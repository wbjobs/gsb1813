/**
 * index.js — CSPManager：编排 收集 → 生成 → 报告 → 收紧 全流程
 *
 * 生命周期：
 *   const cspm = new CSPManager({ reportEndpoint: '/api/csp-report' });
 *   cspm.start();                        // 开始收集资源 + 监听违规
 *   const { csp } = await cspm.generate();       // Worker 中生成策略（自检不破坏页面）
 *   cspm.applyReportOnly(csp);           // meta 方式灰度（Report-Only）
 *   const t = await cspm.tighten(csp);   // Worker 中收紧
 *   cspm.reporter.export('json');        // 导出报告
 */
import { ResourceCollector } from './collector.js';
import { ViolationReporter } from './reporter.js';

export class CSPManager {
  constructor(options = {}) {
    this.options = options;
    this.selfOrigin = options.selfOrigin || (typeof location !== 'undefined' ? location.origin : '');
    this.collector = new ResourceCollector(options.collector);
    this.reporter = new ViolationReporter({ endpoint: options.reportEndpoint, ...options.reporter });
    this._worker = null;
    this._msgId = 0;
    this._pending = new Map();
    this._workerFailed = false;
  }

  start() {
    const ok = this.collector.start();
    this.reporter.start();
    if (!ok) console.warn('[csp] 资源收集未启动，后续生成将仅基于违规报告');
    return ok;
  }

  _getWorker() {
    if (this._worker || this._workerFailed) return this._worker;
    try {
      const url = this.options.workerUrl || new URL('./worker.js', import.meta.url);
      this._worker = new Worker(url, { type: 'module' });
      this._worker.onmessage = (ev) => {
        const { id, result, error, elapsedMs } = ev.data;
        const p = this._pending.get(id);
        if (!p) return;
        this._pending.delete(id);
        if (error) p.reject(new Error(error));
        else p.resolve({ ...result, workerElapsedMs: elapsedMs });
      };
      this._worker.onerror = (err) => {
        console.warn('[csp] Worker 异常，回退主线程计算:', err.message);
        this._workerFailed = true;
        for (const p of this._pending.values()) p.reject(new Error('worker error'));
        this._pending.clear();
      };
    } catch (err) {
      console.warn('[csp] Worker 创建失败，回退主线程计算:', err.message);
      this._workerFailed = true;
    }
    return this._worker;
  }

  async _run(type, payload) {
    const worker = this._getWorker();
    if (worker) {
      const id = ++this._msgId;
      return new Promise((resolve, reject) => {
        this._pending.set(id, { resolve, reject });
        worker.postMessage({ id, type, payload });
      });
    }
    // 主线程回退（Worker 不可用时仍保证功能可用）
    const { generatePolicy } = await import('./generator.js');
    const { tightenPolicy } = await import('./tightener.js');
    const { verifyPolicy } = await import('./policy.js');
    if (type === 'generate') return generatePolicy(payload.entries, payload.options);
    if (type === 'tighten') return tightenPolicy(payload.currentCsp, payload.entries, payload.options);
    if (type === 'verify') return { violations: verifyPolicy(payload.csp, payload.entries, payload.selfOrigin) };
    throw new Error(`未知任务类型: ${type}`);
  }

  /** 生成 CSP（含自检：safe=false 表示会阻断已观察资源） */
  generate(extraOptions = {}) {
    const snap = this.collector.snapshot();
    return this._run('generate', {
      entries: snap.entries,
      options: { selfOrigin: this.selfOrigin, inline: snap.inline, reportUri: this.options.reportEndpoint, ...extraOptions },
    });
  }

  /** 收紧现有策略 */
  tighten(currentCsp, extraOptions = {}) {
    const snap = this.collector.snapshot();
    return this._run('tighten', {
      currentCsp,
      entries: snap.entries,
      options: { selfOrigin: this.selfOrigin, inline: snap.inline, reportUri: this.options.reportEndpoint, ...extraOptions },
    });
  }

  /** 校验任意策略是否会破坏当前页面 */
  verify(csp) {
    const snap = this.collector.snapshot();
    return this._run('verify', { csp, entries: snap.entries, selfOrigin: this.selfOrigin });
  }

  /** 以 Report-Only meta 方式灰度策略（不真正阻断，只上报） */
  applyReportOnly(csp) {
    if (typeof document === 'undefined') return false;
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy-Report-Only';
    meta.content = csp;
    document.head.appendChild(meta);
    return true;
  }

  /** 性能摘要：采集开销 + 资源耗时 */
  perfStats() { return this.collector.perfStats(); }

  stop() {
    this.collector.stop();
    this.reporter.stop();
    if (this._worker) this._worker.terminate();
  }
}

export { ResourceCollector } from './collector.js';
export { ViolationReporter } from './reporter.js';
export { generatePolicy } from './generator.js';
export { tightenPolicy } from './tightener.js';
export { parsePolicy, serializePolicy, verifyPolicy } from './policy.js';
