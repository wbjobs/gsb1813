// csp-collector.js —— 主线程资源收集器
// 数据来源（四路合一）：
//   1. PerformanceObserver（resource/navigation entry，含传输层资源）
//   2. DOM 全量扫描（<script>/<img>/<link>/<form>/<base> 等，能拿到非网络属性）
//   3. MutationObserver（页面动态新增资源）
//   4. fetch / XMLHttpRequest / WebSocket hook（API 调用资源）
// 收集到的资源按 (type,url) 去重，批量送入 Web Worker 生成策略。
import { PERF_BUDGET } from './csp-core.js';

const INITIATOR_TO_TYPE = {
  script: 'script',
  link: 'style',
  css: 'style',
  img: 'img',
  image: 'img',
  'input-image': 'img',
  font: 'font',
  fetch: 'connect',
  xmlhttprequest: 'connect',
  beacon: 'connect',
  eventsource: 'connect',
  websocket: 'connect',
  iframe: 'frame',
  frame: 'frame',
  video: 'media',
  audio: 'media',
  track: 'media',
  manifest: 'manifest',
  other: guessTypeByExtension
};

const LINK_REL_TO_TYPE = {
  stylesheet: 'style',
  preload: null, // 按 as 属性决定
  modulepreload: 'script',
  prefetch: null,
  icon: 'img',
  'apple-touch-icon': 'img',
  manifest: 'manifest',
  font: 'font',
  preconnect: null
};

const FONT_EXT = /\.(?:woff2?|ttf|otf|eot)(?:[?#]|$)/i;
const IMG_EXT = /\.(?:png|jpe?g|gif|svg|webp|avif|ico)(?:[?#]|$)/i;
const SCRIPT_EXT = /\.m?js(?:[?#]|$)/i;
const STYLE_EXT = /\.css(?:[?#]|$)/i;

function guessTypeByExtension(url) {
  if (FONT_EXT.test(url)) return 'font';
  if (IMG_EXT.test(url)) return 'img';
  if (SCRIPT_EXT.test(url)) return 'script';
  if (STYLE_EXT.test(url)) return 'style';
  return null;
}

function sha256Base64(text) {
  if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
    const bytes = new TextEncoder().encode(text);
    return crypto.subtle.digest('SHA-256', bytes).then((buffer) => {
      const binary = String.fromCharCode(...new Uint8Array(buffer));
      return "'sha256-" + btoa(binary) + "'";
    });
  }
  return Promise.resolve(null);
}

export class CspCollector {
  constructor(options = {}) {
    this.options = Object.assign({
      workerUrl: './src/csp-worker.js',
      flushIntervalMs: 800,
      onUpdate: null,
      onViolation: null,
      onNotice: null,
      onMetrics: null
    }, options);
    this.selfOrigin = (typeof location !== 'undefined') ? location.origin : '';
    this.documentUrl = (typeof location !== 'undefined') ? location.href : '';
    this.resources = [];
    this.seen = new Set();
    this.queue = [];
    this.violations = [];
    this.metrics = { resourceEvents: 0, dropped: 0, domNodes: 0, batchCount: 0, lastBuildMs: 0, workerErrors: 0 };
    this.started = false;
    this._unhandlers = [];
  }

  start() {
    if (this.started || typeof document === 'undefined' || typeof location === 'undefined') return this;
    this.started = true;
    this._startPerformanceObserver();
    this._collectInitial();
    this._startMutationObserver();
    this._installHooks();
    this._listenViolations();
    this._flushTimer = setInterval(() => this.flush(), this.options.flushIntervalMs);
    this._notice('收集已开始：PerformanceObserver + DOM + MutationObserver + fetch/XHR hook', 'info');
    // 首屏资源稍后做一次全量策略构建
    setTimeout(() => this.flush(true), 1200);
    return this;
  }

  stop() {
    this.started = false;
    clearInterval(this._flushTimer);
    for (const un of this._unhandlers) { try { un(); } catch (_) {} }
    this._unhandlers = [];
    if (this._workerPromise) {
      this._workerPromise.then((worker) => { try { worker.terminate && worker.terminate(); } catch (_) {} }).catch(() => {});
      this._workerPromise = null;
    }
    return this;
  }

  // -------- 收集原语 --------
  add(resource, meta = {}) {
    if (!resource) return;
    // 内联脚本/样式/eval 没有 URL；外部资源必须有 URL
    if (!resource.url && !resource.inline && !resource.eval) return;
    const key = resource.eval ? 'eval' : resource.inline ? `inline:${resource.inline}:${resource.hash || ''}` : `${resource.type}:${resource.url}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    const entry = Object.assign({ firstSeenAt: new Date().toISOString() }, resource, meta);
    this.resources.push(entry);
    this.queue.push(entry);
  }

  _notice(message, level = 'warning') {
    if (this.options.onNotice) this.options.onNotice({ message, level, at: new Date().toISOString() });
  }

  // -------- 1) PerformanceObserver --------
  _startPerformanceObserver() {
    if (typeof PerformanceObserver === 'undefined') {
      this._notice('当前环境不支持 PerformanceObserver，已降级为 DOM 扫描', 'warning');
      return;
    }
    try {
      const observer = new PerformanceObserver((list) => {
        for (const entry of list.getEntries()) {
          this.metrics.resourceEvents++;
          this._absorbPerformanceEntry(entry);
        }
      });
      observer.observe({ type: 'resource', buffered: true });
      this._unhandlers.push(() => observer.disconnect());
    } catch (error) {
      this._notice(`PerformanceObserver 启动失败：${error.message}，已降级`, 'error');
    }
  }

  _absorbPerformanceEntry(entry) {
    let type = INITIATOR_TO_TYPE[entry.initiatorType] || null;
    if (typeof type === 'function') type = type(entry.name);
    // css/link 发起的子资源（@font-face 字体、background 图片等）按扩展名修正分类
    if ((entry.initiatorType === 'css' || entry.initiatorType === 'link') && !/\.css(?:[?#]|$)/i.test(entry.name)) {
      const guessed = guessTypeByExtension(entry.name);
      if (guessed) type = guessed;
    }
    if (!type) return;
    this.add({ url: entry.name, type }, { via: 'performance', initiatorType: entry.initiatorType });
  }

  // -------- 2) 初始 DOM 扫描 + Performance buffer 兜底 --------
  _collectInitial() {
    // Performance buffer 中可能已有资源（observer 的 buffered 一般已覆盖，双保险）
    if (performance.getEntriesByType) {
      for (const entry of performance.getEntriesByType('resource')) {
        this._absorbPerformanceEntry(entry);
      }
    }
    this._scanDom(document.documentElement);
  }

  _scanDom(root) {
    let nodes;
    try { nodes = root.querySelectorAll ? root.querySelectorAll('script,link,img,source,video,audio,track,iframe,frame,object,embed,form,base,input,link[rel="manifest"]') : []; }
    catch (_) { nodes = []; }
    this.metrics.domNodes += nodes.length;
    for (const node of nodes) this._absorbDomNode(node);
    // 内联事件处理器 / style 属性检测（全量一次）
    let all;
    try { all = root.querySelectorAll ? root.querySelectorAll('*') : []; } catch (_) { all = []; }
    for (const node of all) this._detectInlineHandler(node);
  }

  _absorbDomNode(node) {
    const tag = node.tagName.toLowerCase();
    const push = (url, type, extra = {}) => { if (url) this.add(Object.assign({ url, type }, extra), { via: 'dom' }); };

    if (tag === 'script') {
      if (node.src) {
        push(node.src, 'script');
      } else {
        const text = node.textContent || '';
        if (text.trim()) this._hashInline(text, 'script');
      }
    } else if (tag === 'link') {
      const rel = (node.rel || '').toLowerCase();
      let type = LINK_REL_TO_TYPE[rel];
      if (rel === 'preload' || rel === 'prefetch') type = node.as === 'style' ? 'style' : node.as === 'font' ? 'font' : node.as === 'script' ? 'script' : node.as === 'image' ? 'img' : guessTypeByExtension(node.href);
      if (type && node.href) push(node.href, type);
    } else if (tag === 'style') {
      const text = node.textContent || '';
      if (text.trim()) this._hashInline(text, 'style');
    } else if (tag === 'img' || tag === 'input' || tag === 'source') {
      if (node.src) push(node.src, 'img');
      if (node.srcset) this._absorbSrcset(node.srcset, 'img');
    } else if (tag === 'video' || tag === 'audio' || tag === 'track') {
      if (node.src) push(node.src, 'media');
    } else if (tag === 'iframe' || tag === 'frame') {
      if (node.src) push(node.src, 'frame');
    } else if (tag === 'object' || tag === 'embed') {
      if (node.data || node.src) push(node.data || node.src, 'object');
    } else if (tag === 'form') {
      if (node.action) push(node.action, 'form');
    } else if (tag === 'base') {
      if (node.href) push(node.href, 'base');
      else this.add({ type: 'base', url: "'self'", inline: null }, { via: 'dom', baseSelf: true });
    }
  }

  _absorbSrcset(srcset, type) {
    for (const chunk of String(srcset).split(',')) {
      const url = chunk.trim().split(/\s+/)[0];
      if (url) this.add({ url, type }, { via: 'srcset' });
    }
  }

  _hashInline(text, kind) {
    // hash 异步计算完成后再入列，避免同一段内联代码出现“无 hash/有 hash”两条记录
    return sha256Base64(text).then((hash) => {
      const resource = { inline: kind, type: kind, url: '' };
      if (hash) resource.hash = hash;
      this.add(resource, { via: 'inline-hash', length: text.length });
    });
  }

  _detectInlineHandler(node) {
    if (!node || node.nodeType !== 1 || !node.attributes) return;
    for (const attr of node.attributes) {
      if (/^on/i.test(attr.name)) {
        this._hasInlineAttr = true;
        this.add({ inline: 'script-attr', type: 'script', url: '' }, { via: 'inline-handler', attribute: attr.name });
        break;
      }
    }
    if (node.style && node.getAttribute && node.getAttribute('style')) {
      this._hasStyleAttr = true;
      this.add({ inline: 'style-attr', type: 'style', url: '' }, { via: 'style-attribute' });
    }
  }

  // -------- 3) MutationObserver --------
  _startMutationObserver() {
    if (typeof MutationObserver === 'undefined') return;
    const observer = new MutationObserver((mutations) => {
      const pending = [];
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType !== 1) continue;
          pending.push(node);
          if (node.querySelectorAll) {
            try { node.querySelectorAll('script,link,img,source,video,audio,iframe,form').forEach((child) => pending.push(child)); } catch (_) {}
          }
        }
        if (mutation.type === 'attributes' && mutation.target.nodeType === 1) {
          pending.push(mutation.target);
        }
      }
      for (const node of pending) { this._absorbDomNode(node); this._detectInlineHandler(node); }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['src', 'href', 'srcset', 'action', 'data'] });
    this._unhandlers.push(() => observer.disconnect());
  }

  // -------- 4) fetch / XHR / WebSocket hook --------
  _installHooks() {
    if (typeof window !== 'undefined' && window.fetch && !window.__cspFetchPatched) {
      const original = window.fetch.bind(window);
      window.fetch = (input, init) => {
        try {
          const url = typeof input === 'string' ? input : (input && input.url) || '';
          if (url) this.add({ url, type: 'connect' }, { via: 'fetch' });
        } catch (_) {}
        return original(input, init);
      };
      window.__cspFetchPatched = true;
      this._unhandlers.push(() => { window.fetch = original; delete window.__cspFetchPatched; });
    }

    if (typeof XMLHttpRequest !== 'undefined' && !XMLHttpRequest.prototype.__cspOpenPatched) {
      const originalOpen = XMLHttpRequest.prototype.open;
      XMLHttpRequest.prototype.open = function (method, url, ...rest) {
        try { window.__cspCollector && url && window.__cspCollector.add({ url, type: 'connect' }, { via: 'xhr' }); } catch (_) {}
        return originalOpen.call(this, method, url, ...rest);
      };
      XMLHttpRequest.prototype.__cspOpenPatched = true;
      if (typeof window !== 'undefined') window.__cspCollector = this;
      this._unhandlers.push(() => { XMLHttpRequest.prototype.open = originalOpen; delete XMLHttpRequest.prototype.__cspOpenPatched; });
    }

    if (typeof WebSocket !== 'undefined' && !WebSocket.__cspPatched) {
      const Original = WebSocket;
      const collector = this;
      // eslint-disable-next-line no-global-assign
      window.WebSocket = function (url, protocols) {
        try { collector.add({ url, type: 'connect' }, { via: 'websocket' }); } catch (_) {}
        return protocols ? new Original(url, protocols) : new Original(url);
      };
      window.WebSocket.prototype = Original.prototype;
      window.WebSocket.__cspPatched = true;
      this._unhandlers.push(() => { window.WebSocket = Original; delete window.WebSocket.__cspPatched; });
    }

    this._detectEval();
  }

  // 通过 Error.stack 快照无法静态确认 eval，这里提供显式探针 API；
  // 同时探测常见动态执行痕迹（构造器 new Function）的实际调用由 markEval 记录。
  _detectEval() {
    this.markEval = (reason = 'manual') => {
      this.add({ eval: true, type: 'script', url: '' }, { via: 'eval', reason });
    };
  }

  // -------- CSP 违规事件（真实浏览器上报 / Report-Only dry-run 通用） --------
  _listenViolations() {
    if (typeof document === 'undefined') return;
    const handler = (event) => {
      const record = {
        at: new Date().toISOString(),
        directive: event.violation ? event.violation.effectiveDirective : event.effectiveDirective,
        policy: event.violation ? event.violation.originalPolicy : event.originalPolicy,
        blockedURI: event.blockedURI || (event.violation && event.violation.blockedURL),
        sourceFile: event.sourceFile,
        lineNumber: event.lineNumber
      };
      this.violations.push(record);
      if (this.options.onViolation) this.options.onViolation(record);
    };
    document.addEventListener('securitypolicyviolation', handler);
    this._unhandlers.push(() => document.removeEventListener('securitypolicyviolation', handler));
  }

  // -------- 批量刷新 -> Worker --------
  flush(force = false) {
    if (!this.queue.length) return Promise.resolve(null);
    this.metrics.batchCount++;
    const run = (worker) => {
      // Worker 首次创建是异步的：拿到 worker 后再截取队列，
      // 避免首批资源在“建 worker 期间”被清空而空跑。
      const batch = this.queue.splice(0, this.queue.length);
      if (!batch.length) return Promise.resolve(null);
      return new Promise((resolve) => {
        const start = performance.now();
        let done = false;
        const timer = setTimeout(() => {
          if (done) return;
          done = true;
          worker.removeEventListener('message', onMessage);
          this._notice('Worker 处理超时（>2s），请减少单次批量', 'error');
          resolve(null);
        }, 2000);
        const onMessage = (event) => {
          if (done) return;
          done = true;
          clearTimeout(timer);
          worker.removeEventListener('message', onMessage);
          if (event.data.type === 'built') {
            this.metrics.lastBuildMs = event.data.timing.batchBuildMs;
            this.lastResult = event.data;
            this._emitMetrics(start, batch.length);
            if (this.options.onUpdate) this.options.onUpdate(event.data);
            resolve(event.data);
          } else if (event.data.type === 'error') {
            this.metrics.workerErrors++;
            this._notice(`策略构建失败：${event.data.error}`, 'error');
            resolve(null);
          } else {
            resolve(null);
          }
        };
        worker.addEventListener('message', onMessage);
        worker.postMessage({
          type: 'build',
          resources: this.snapshot(),
          options: this._context()
        });
      });
    };
    return this._withWorker(run).catch((error) => {
      this._notice(`Worker 不可用：${error.message}，请检查 worker 路径或同源策略`, 'error');
      return null;
    });
  }


  tighten(policyOverride) {
    const policy = policyOverride || (this.lastResult && this.lastResult.policy);
    if (!policy) return Promise.reject(new Error('尚无可用策略，请先收集并生成'));
    return this.request('tighten', { policy, resources: this.snapshot(), options: Object.assign({ detectedInlineAttr: this._hasInlineAttr, detectedStyleAttr: this._hasStyleAttr }, this._context()) });
  }

  evaluate(policy) {
    return this.request('evaluate', { policy, resources: this.snapshot(), options: this._context() });
  }

  request(type, payload) {
    return this._withWorker((worker) => new Promise((resolve, reject) => {
      const onMessage = (event) => {
        worker.removeEventListener('message', onMessage);
        if (event.data.type === 'error') reject(new Error(event.data.error));
        else resolve(event.data);
      };
      worker.addEventListener('message', onMessage);
      worker.postMessage(Object.assign({ type }, payload));
    }));
  }

  _withWorker(fn) {
    if (!this._workerPromise) this._workerPromise = this._createWorker();
    return this._workerPromise.then(fn);
  }


  _createWorker() {
    return new Promise((resolve, reject) => {
      if (typeof Worker === 'undefined') { reject(new Error('当前环境不支持 Web Worker')); return; }
      const worker = new Worker(this.options.workerUrl, { type: 'module' });
      worker.addEventListener('error', (event) => {
        this.metrics.workerErrors++;
        this._notice(`Worker 错误：${event.message || '加载失败'}`, 'error');
      });
      resolve(worker);
    });
  }

  _emitMetrics(start, batchSize) {
    const payload = Object.assign({}, this.metrics, {
      queuePending: this.queue.length,
      resourceTotal: this.resources.length,
      buildOverBudget: this.metrics.lastBuildMs > (batchSize > PERF_BUDGET.bigBatch ? PERF_BUDGET.batchBuildMs : PERF_BUDGET.batchBuildMs),
      violations: this.violations.length
    });
    if (this.options.onMetrics) this.options.onMetrics(payload);
  }

  _context() {
    return {
      selfOrigin: this.selfOrigin,
      documentUrl: this.documentUrl,
      stage: this.stage || 'report',
      collapseWildcard: this.options.collapseWildcard
    };
  }

  setStage(stage) { this.stage = stage; }

  snapshot() {
    return this.resources.slice();
  }
}
