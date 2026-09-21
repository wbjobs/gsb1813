// server.js —— 零依赖演示服务器
// 主源 8124（页面 + API），CDN 源 8125，字体源 8126，恶意源 8127（仅 evil.js）
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(__dirname, 'public');
const ROOT_DIR = __dirname;

const PORTS = { main: 8124, cdn: 8125, font: 8126, evil: 8127 };

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json; charset=utf-8'
};

// 服务端保存当前 CSP 模式（控制台通过 /api/mode 切换）
const mode = { active: 'report', policy: '' };
const reports = []; // 内存中的违规上报（最多保留 200 条）
const sseClients = new Set();

const REPORT_SUFFIX = '; report-uri /csp-report; report-to csp-endpoint';
const REPORT_TO = JSON.stringify({
  group: 'csp-endpoint',
  max_age: 3600,
  endpoints: [{ url: 'http://127.0.0.1:8124/csp-reporting-endpoint' }]
});

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > 1_000_000) { reject(new Error('body too large')); req.destroy(); return; }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function storeReport(body) {
  const record = { at: new Date().toISOString(), body };
  reports.push(record);
  if (reports.length > 200) reports.shift();
  const payload = JSON.stringify([record]);
  for (const res of sseClients) { try { res.write(`data: ${payload}\n\n`); } catch (_) {} }
}

async function handleApi(req, res, url) {
  if (url.pathname === '/api/time' && req.method === 'GET') {
    return sendJson(res, 200, { now: Date.now() });
  }

  if (url.pathname === '/api/mode' && req.method === 'POST') {
    const body = JSON.parse((await readBody(req)) || '{}');
    if (!['report', 'enforce'].includes(body.mode)) return sendJson(res, 400, { error: 'mode 必须是 report 或 enforce' });
    mode.active = body.mode;
    if (typeof body.policy === 'string') mode.policy = body.policy;
    return sendJson(res, 200, { ok: true, mode });
  }

  if (url.pathname === '/api/state' && req.method === 'GET') {
    return sendJson(res, 200, { mode, reportCount: reports.length });
  }

  if (url.pathname === '/api/reports' && req.method === 'GET') {
    return sendJson(res, 200, reports);
  }

  if (url.pathname === '/api/events' && req.method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-cache',
      Connection: 'keep-alive'
    });
    res.write(`data: ${JSON.stringify(reports.slice(-50))}\n\n`);
    sseClients.add(res);
    req.on('close', () => sseClients.delete(res));
    return;
  }

  return false;
}

async function handleReport(req, res, url) {
  if (![ '/csp-report', '/csp-reporting-endpoint' ].includes(url.pathname)) return false;
  const raw = await readBody(req);
  let body;
  try { body = JSON.parse(raw); } catch (_) { body = { raw }; }
  // Reporting API 上报是数组：[{ type:'csp-violation', body: {...} }]
  if (Array.isArray(body)) {
    for (const item of body) storeReport(item.body || item);
  } else {
    storeReport(body['csp-report'] || body);
  }
  res.writeHead(204, { 'Content-Length': '0' });
  res.end();
  return true;
}

function safeResolve(baseDir, urlPath) {
  const decoded = decodeURIComponent(urlPath.split('?')[0]);
  const target = path.normalize(path.join(baseDir, decoded));
  if (!target.startsWith(baseDir)) return null;
  return target;
}

function serveFile(res, filePath, extraHeaders = {}) {
  fs.stat(filePath, (error, stats) => {
    if (error || !stats.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }
    const headers = Object.assign({
      'Content-Type': MIME[path.extname(filePath)] || 'application/octet-stream',
      'Content-Length': stats.size,
      'Cache-Control': 'no-store'
    }, extraHeaders);
    res.writeHead(200, headers);
    fs.createReadStream(filePath).pipe(res);
  });
}

function makeMainHandler() {
  return async (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${PORTS.main}`);
    try {
      if (await handleReport(req, res, url)) return;
      const apiResult = await handleApi(req, res, url);
      if (apiResult !== false) return;

      let urlPath = url.pathname;
      if (urlPath === '/') urlPath = '/index.html';

      // HTML 文档按当前模式注入 CSP 头（报告 / 强制）
      const isHtml = urlPath.endsWith('.html') || urlPath === '/index.html';
      const extra = {};
      if (isHtml && mode.policy) {
        const policyWithReporting = mode.policy + REPORT_SUFFIX;
        if (mode.active === 'enforce') extra['Content-Security-Policy'] = policyWithReporting;
        else extra['Content-Security-Policy-Report-Only'] = policyWithReporting;
        extra['Report-To'] = REPORT_TO;
      }

      // /src/* 模块源码从项目根提供，其余静态资源从 public 提供
      const baseDir = urlPath.startsWith('/src/') ? ROOT_DIR : PUBLIC_DIR;
      const filePath = safeResolve(baseDir, urlPath);
      if (!filePath) { res.writeHead(403); res.end('403'); return; }
      serveFile(res, filePath, extra);
    } catch (error) {
      sendJson(res, 500, { error: error.message });
    }
  };
}

function makeAssetHandler(kind, port) {
  return (req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    // 跨源资源允许任意页面读取，并暴露计时信息给 PerformanceObserver
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Timing-Allow-Origin': '*'
    };
    if (kind === 'evil') {
      if (url.pathname !== '/evil.js') { res.writeHead(404, cors); res.end('not found'); return; }
      return serveFile(res, path.join(PUBLIC_DIR, 'assets/other/evil.js'), cors);
    }
    let pathname = url.pathname;
    if (pathname.startsWith('/cdn/')) pathname = pathname.replace('/cdn/', '/assets/cdn/');
    const filePath = safeResolve(PUBLIC_DIR, pathname);
    if (!filePath) { res.writeHead(403, cors); res.end('403'); return; }
    serveFile(res, filePath, cors);
  };
}


export {
  PORTS, makeMainHandler, makeAssetHandler, mode, reports, REPORT_SUFFIX, MIME, safeResolve, PUBLIC_DIR
};

function listen(port, handler, label) {
  const server = http.createServer(handler);
  server.listen(port, '127.0.0.1', () => {
    console.log(`[csp-lab] ${label} http://127.0.0.1:${port}`);
  });
  server.on('error', (error) => {
    console.error(`[csp-lab] 端口 ${port}（${label}）启动失败：${error.message}`);
  });
  return server;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  listen(PORTS.main, makeMainHandler(), '主源/控制台');
  listen(PORTS.cdn, makeAssetHandler('cdn', PORTS.cdn), 'CDN 源');
  listen(PORTS.font, makeAssetHandler('font', PORTS.font), '字体源');
  listen(PORTS.evil, makeAssetHandler('evil', PORTS.evil), '恶意源（收紧后应被阻止）');
}
