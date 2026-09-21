/**
 * reporter.js — CSP 违规报告：监听 securitypolicyviolation，批量上报，支持导出与本地环形缓冲
 */
export class ViolationReporter {
  constructor(options = {}) {
    this.endpoint = options.endpoint || '/api/csp-report';
    this.batchSize = options.batchSize || 10;
    this.flushInterval = options.flushInterval || 5000;
    this.maxStored = options.maxStored || 500;
    this.reports = [];
    this.queue = [];
    this.errors = [];
    this._timer = null;
    this._listener = null;
  }

  start() {
    if (typeof document === 'undefined') return false;
    this._listener = (ev) => this.record({
      directive: ev.violatedDirective,
      blockedURI: ev.blockedURI,
      documentURI: ev.documentURI,
      effectiveDirective: ev.effectiveDirective,
      originalPolicy: ev.originalPolicy,
      disposition: ev.disposition,
      statusCode: ev.statusCode,
      sourceFile: ev.sourceFile,
      lineNumber: ev.lineNumber,
      ts: Date.now(),
    });
    document.addEventListener('securitypolicyviolation', this._listener);
    this._timer = setInterval(() => this.flush(), this.flushInterval);
    return true;
  }

  record(report) {
    this.reports.push(report);
    if (this.reports.length > this.maxStored) this.reports.shift();
    this.queue.push(report);
    if (this.queue.length >= this.batchSize) this.flush();
  }

  /** 批量上报；失败时保留队列并记录异常提示 */
  async flush() {
    if (!this.queue.length || typeof fetch === 'undefined') return;
    const batch = this.queue.splice(0, this.queue.length);
    try {
      const res = await fetch(this.endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/csp-report' },
        body: JSON.stringify({ reports: batch }),
        keepalive: true,
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      this.queue.unshift(...batch);
      this.errors.push({ message: err.message, ts: Date.now() });
      console.warn(`[csp] 报告上报失败（已保留 ${this.queue.length} 条待重发）:`, err.message);
    }
  }

  /** 导出为 JSON 文件下载（Node 环境返回字符串） */
  export(format = 'json') {
    const data = format === 'csv' ? this._toCsv() : JSON.stringify(this.reports, null, 2);
    if (typeof document === 'undefined') return data;
    const mime = format === 'csv' ? 'text/csv' : 'application/json';
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([data], { type: mime }));
    a.download = `csp-reports-${new Date().toISOString().slice(0, 19)}.${format}`;
    a.click();
    URL.revokeObjectURL(a.href);
    return data;
  }

  _toCsv() {
    const cols = ['ts', 'effectiveDirective', 'blockedURI', 'sourceFile', 'lineNumber', 'disposition'];
    const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
    return [cols.join(','), ...this.reports.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
  }

  stop() {
    if (this._listener) document.removeEventListener('securitypolicyviolation', this._listener);
    if (this._timer) clearInterval(this._timer);
    this.flush();
  }
}
