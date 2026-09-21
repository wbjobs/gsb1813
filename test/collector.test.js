import { test } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { Worker } from 'node:worker_threads';
import { EventEmitter } from 'node:events';

// 定时器 unref，避免阻止测试进程退出
const realSetInterval = globalThis.setInterval;
globalThis.setInterval = (...args) => { const handle = realSetInterval(...args); handle.unref(); return handle; };
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (...args) => { const handle = realSetTimeout(...args); if (handle.unref) handle.unref(); return handle; };

// ---- 极简 DOM ----
function el(tagName, attrs = {}, text = '') {
  const node = {
    nodeType: 1,
    tagName: tagName.toUpperCase(),
    textContent: text,
    attributes: Object.entries(attrs).map(([name, value]) => ({ name, value })),
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(attrs, name) ? attrs[name] : null; },
    style: attrs.style ? {} : null,
    srcset: attrs.srcset || '',
    querySelectorAll() { return []; }
  };
  // 真实 DOM 元素存在 src/href/action/data 反射属性
  for (const name of ['src', 'href', 'action', 'data', 'rel', 'as']) node[name] = attrs[name] || '';
  return node;
}

const resourceNodes = [
  el('script', { src: 'http://127.0.0.1:8125/cdn/third-party.js' }),
  el('link', { rel: 'stylesheet', href: 'http://127.0.0.1:8125/cdn/cdn-style.css' }),
  el('img', { src: 'http://127.0.0.1:8125/assets/logo.svg' }),
  el('iframe', { src: 'http://127.0.0.1:8125/cdn/frame.html' }),
  el('form', { action: '/submit' }),
  el('script', {}, 'window.inline = 1;')
];

globalThis.document = {
  addEventListener() {},
  removeEventListener() {},
  documentElement: {
    querySelectorAll(selector) {
      // 简化模拟：'*' 与“资源标签选择器”都返回全部节点（含无属性的内联 script）；
      // 收集器内部会自行区分外链/内联。
      return resourceNodes;
    }
  }
};

let observerCallback = null;
globalThis.PerformanceObserver = class {
  constructor(callback) { observerCallback = callback; }
  observe() {}
  disconnect() {}
};
globalThis.performance = performance;
globalThis.performance.getEntriesByType = () => [
  { name: 'http://127.0.0.1:8126/assets/dummy.woff2', initiatorType: 'css' },
  { name: 'http://127.0.0.1:8125/xhr', initiatorType: 'xmlhttprequest' }
];
globalThis.MutationObserver = class { observe() {} disconnect() {} };

const windowStub = {};
globalThis.window = windowStub;
windowStub.location = { origin: 'http://127.0.0.1:8124', href: 'http://127.0.0.1:8124/' };
globalThis.location = windowStub.location;
windowStub.fetch = () => Promise.resolve({ ok: true });
globalThis.XMLHttpRequest = function () {};
XMLHttpRequest.prototype.open = function () {};
globalThis.WebSocket = function () {};

// ---- 用真实 worker_threads 模拟浏览器 Worker ----
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const workerSrc = path.join(__dirname, '../src/csp-worker.js');
class FakeWorker extends EventEmitter {
  constructor() {
    super();
    // 必须在 super() 之后、任何消息产生前定义浏览器风格 API
    this.addEventListener = (name, fn) => this.on(name, fn);
    this.removeEventListener = (name, fn) => this.off(name, fn);
    this.thread = new Worker(`
      import { handleMessage } from ${JSON.stringify('file://' + workerSrc)};
      const { parentPort } = await import('node:worker_threads');
      parentPort.on('message', (msg) => {
        try { parentPort.postMessage(handleMessage(msg)); }
        catch (e) { parentPort.postMessage({ type: 'error', stage: msg.type, error: String((e && e.message) || e) }); }
      });
    `, { eval: true, execArgv: ['--input-type=module'] });
    this.thread.on('message', (data) => this.emit('message', { data }));
  }
  postMessage(msg) { this.thread.postMessage(msg); }
  terminate() { return this.thread.terminate(); }
}
globalThis.Worker = FakeWorker;

const { CspCollector } = await import('../src/csp-collector.js');

test('收集器：DOM/Performance/hook 四路收集 + 内联 hash + Worker 出策略 + 收紧', async () => {
  const collector = new CspCollector({ workerUrl: 'file://fake', flushIntervalMs: 60000 });
  collector.start();

  observerCallback({ getEntries: () => [{ name: 'https://api.example.com/v1/data', initiatorType: 'fetch' }] });
  windowStub.fetch('https://beacon.example.com/ping');
  collector._absorbDomNode(el('script', { src: 'http://127.0.0.1:8125/cdn/late-track.js' }));

  const result = await collector.flush(true);
  assert.equal(result.type, 'built');
  assert.match(result.policy, /script-src-elem/);

  const snapshot = collector.snapshot();
  const urls = snapshot.map((r) => r.url);
  assert.ok(urls.includes('http://127.0.0.1:8125/cdn/third-party.js'));
  assert.ok(urls.includes('http://127.0.0.1:8125/cdn/late-track.js'));
  assert.ok(urls.includes('https://api.example.com/v1/data'));
  assert.ok(urls.includes('https://beacon.example.com/ping'));
  assert.ok(snapshot.some((r) => r.type === 'font' && r.url.includes('dummy.woff2')));
  assert.equal(snapshot.filter((r) => r.url === 'http://127.0.0.1:8125/cdn/third-party.js').length, 1);

  await new Promise((resolve) => realSetTimeout(resolve, 50));
  const inline = collector.snapshot().find((r) => r.inline === 'script');
  assert.ok(inline && /^'sha256-/.test(inline.hash));
  assert.match(result.policy, /script-src[^;]*unsafe-inline/);

  const tight = await collector.tighten(result.policy);
  assert.equal(tight.type, 'tightened');
  assert.deepEqual(tight.violations, []);

  // 终止 worker 线程，避免悬挂事件循环
  const worker = await collector._workerPromise;
  await worker.terminate();
});
