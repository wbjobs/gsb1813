/**
 * server.js — 零依赖演示服务器
 *   - 静态托管 demo/ 与 src/
 *   - POST /api/csp-report  接收违规报告（内存环形缓冲）
 *   - GET  /api/reports     导出报告（?format=csv 导出 CSV）
 *   - GET  /api/csp         查看当前下发策略
 *   - ?csp=report-only|enforce 控制 CSP 响应头模式
 */
import http from 'node:http';
import { readFile } from 'node:fs/promises';
import { extname, join, normalize } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = fileURLToPath(new URL('.', import.meta.url));
const PORT = process.env.PORT || 8080;
const MAX_REPORTS = 1000;
export const reports = [];
let currentPolicy = null; // 可通过 /api/csp POST 更新（模拟运维下发）

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2', '.ico': 'image/x-icon',
};

function send(res, status, body, headers = {}) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', ...headers });
  res.end(typeof body === 'string' ? body : JSON.stringify(body));
}

export async function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/api/csp-report' && req.method === 'POST') {
    let body = '';
    req.on('data', (c) => { body += c; if (body.length > 1e6) req.destroy(); });
    req.on('end', () => {
      try {
        const parsed = JSON.parse(body || '{}');
        const list = parsed.reports || (parsed['csp-report'] ? [parsed['csp-report']] : [parsed]);
        for (const r of list) {
          reports.push({ ...r, receivedAt: new Date().toISOString() });
          if (reports.length > MAX_REPORTS) reports.shift();
        }
        send(res, 204, '');
      } catch (err) {
        send(res, 400, { error: `报告解析失败: ${err.message}` });
      }
    });
    return;
  }

  if (url.pathname === '/api/reports' && req.method === 'GET') {
    if (url.searchParams.get('format') === 'csv') {
      const cols = ['receivedAt', 'effectiveDirective', 'directive', 'blockedURI', 'sourceFile', 'lineNumber'];
      const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
      const csv = [cols.join(','), ...reports.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
      res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': 'attachment; filename="csp-reports.csv"' });
      res.end(csv);
      return;
    }
    send(res, 200, { count: reports.length, reports });
    return;
  }

  if (url.pathname === '/api/csp') {
    if (req.method === 'GET') return send(res, 200, { policy: currentPolicy });
    if (req.method === 'POST') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', () => {
        try { currentPolicy = JSON.parse(body).policy || null; send(res, 200, { ok: true, policy: currentPolicy }); }
        catch (err) { send(res, 400, { error: err.message }); }
      });
      return;
    }
  }

  // 静态文件
  let filePath = normalize(join(ROOT, url.pathname === '/' ? 'demo/index.html' : url.pathname));
  if (!filePath.startsWith(ROOT)) return send(res, 403, { error: 'forbidden' });
  try {
    const data = await readFile(filePath);
    const headers = { 'Content-Type': MIME[extname(filePath)] || 'application/octet-stream' };
    // CSP 下发模式：?csp=report-only | enforce
    const mode = url.searchParams.get('csp');
    if (currentPolicy && extname(filePath) === '.html') {
      if (mode === 'report-only') headers['Content-Security-Policy-Report-Only'] = currentPolicy;
      if (mode === 'enforce') headers['Content-Security-Policy'] = currentPolicy;
    }
    res.writeHead(200, headers);
    res.end(data);
  } catch {
    send(res, 404, { error: 'not found' });
  }
}

/* c8 ignore next 4 */
if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  http.createServer(handler).listen(PORT, '127.0.0.1', () =>
    console.log(`CSP demo: http://localhost:${PORT}/  (报告端点: POST /api/csp-report)`));
}
