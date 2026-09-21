/**
 * collector.js — 基于 PerformanceObserver 的页面资源收集器
 * 低开销：条目先入缓冲，空闲时批量回调；支持 buffer 上限与去重。
 */
export class ResourceCollector {
  constructor(options = {}) {
    this.maxEntries = options.maxEntries || 2000;
    this.flushInterval = options.flushInterval || 2000;
    this.entries = [];
    this.seen = new Set();
    this.inline = { script: false, style: false };
    this.listeners = new Set();
    this._observer = null;
    this._timer = null;
    this._mutation = null;
  }

  start() {
    if (typeof PerformanceObserver === 'undefined') {
      console.warn('[csp] 当前环境不支持 PerformanceObserver，资源收集不可用');
      return false;
    }
    try {
      this._observer = new PerformanceObserver((list) => {
        for (const e of list.getEntries()) this._add(e);
      });
      this._observer.observe({ type: 'resource', buffered: true });
    } catch (err) {
      console.warn('[csp] PerformanceObserver 启动失败:', err.message);
      return false;
    }
    this._scanInline();
    this._watchInline();
    this._timer = setInterval(() => this._flush(), this.flushInterval);
    return true;
  }

  _add(e) {
    const key = `${e.initiatorType}|${e.name}`;
    if (this.seen.has(key)) return;
    if (this.entries.length >= this.maxEntries) return;
    this.seen.add(key);
    this.entries.push({
      name: e.name,
      initiatorType: e.initiatorType,
      duration: Math.round(e.duration * 100) / 100,
      transferSize: e.transferSize || 0,
    });
  }

  _scanInline() {
    if (typeof document === 'undefined') return;
    if (document.querySelector('script:not([src])')) this.inline.script = true;
    if (document.querySelector('style, [style]')) this.inline.style = true;
  }

  _watchInline() {
    if (typeof MutationObserver === 'undefined' || typeof document === 'undefined') return;
    this._mutation = new MutationObserver(() => this._scanInline());
    this._mutation.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ['style'] });
  }

  onFlush(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); }

  _flush() {
    if (!this.listeners.size) return;
    const snapshot = this.snapshot();
    for (const fn of this.listeners) {
      try { fn(snapshot); } catch (err) { console.warn('[csp] flush 回调异常:', err.message); }
    }
  }

  snapshot() {
    return { entries: this.entries.slice(), inline: { ...this.inline }, collectedAt: Date.now() };
  }

  /** 采集性能摘要，用于“性能可接受”验收 */
  perfStats() {
    const total = this.entries.reduce((s, e) => s + e.duration, 0);
    return { count: this.entries.length, totalResourceTime: Math.round(total), buffered: this.seen.size };
  }

  stop() {
    if (this._observer) this._observer.disconnect();
    if (this._mutation) this._mutation.disconnect();
    if (this._timer) clearInterval(this._timer);
  }
}
