import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { handler, reports } from '../server.js';

function mockReq(method, path, body) {
  const req = new EventEmitter();
  req.method = method;
  req.url = path;
  req.headers = { host: 'localhost' };
  process.nextTick(() => {
    if (body) req.emit('data', Buffer.from(body));
    req.emit('end');
  });
  return req;
}

function mockRes() {
  const res = {
    statusCode: null, headers: {}, body: '',
    writeHead(status, headers = {}) { this.statusCode = status; this.headers = headers; },
    end(data) { this.body = data || ''; this._resolve?.(); },
  };
  res.done = new Promise((r) => { res._resolve = r; });
  return res;
}

async function call(method, path, body) {
  const res = mockRes();
  await handler(mockReq(method, path, body), res);
  await res.done;
  return res;
}

beforeEach(() => { reports.length = 0; });

test('POST /api/csp-report 接收并存储违规报告', async () => {
  const res = await call('POST', '/api/csp-report',
    JSON.stringify({ reports: [{ directive: 'img-src', blockedURI: 'https://evil.com/x.png' }] }));
  assert.equal(res.statusCode, 204);
  assert.equal(reports.length, 1);
  assert.equal(reports[0].directive, 'img-src');
  assert.ok(reports[0].receivedAt);
});

test('POST /api/csp-report 兼容浏览器原生 csp-report 格式', async () => {
  const res = await call('POST', '/api/csp-report',
    JSON.stringify({ 'csp-report': { 'violated-directive': 'script-src', 'blocked-uri': 'inline' } }));
  assert.equal(res.statusCode, 204);
  assert.equal(reports.length, 1);
});

test('GET /api/reports 导出 JSON，?format=csv 导出 CSV', async () => {
  reports.push({ directive: 'img-src', blockedURI: 'https://evil.com/x.png', receivedAt: '2026-09-21' });
  const resJson = await call('GET', '/api/reports');
  const data = JSON.parse(resJson.body);
  assert.equal(data.count, 1);

  const resCsv = await call('GET', '/api/reports?format=csv');
  assert.match(resCsv.headers['Content-Type'], /text\/csv/);
  assert.match(resCsv.body, /img-src/);
});

test('POST /api/csp 更新策略后，HTML 响应携带 Report-Only 头', async () => {
  let res = await call('POST', '/api/csp', JSON.stringify({ policy: "default-src 'self'" }));
  assert.equal(res.statusCode, 200);

  res = await call('GET', '/?csp=report-only');
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['Content-Security-Policy-Report-Only'], "default-src 'self'");

  res = await call('GET', '/?csp=enforce');
  assert.equal(res.headers['Content-Security-Policy'], "default-src 'self'");
});

test('静态模块与 404、路径穿越防护', async () => {
  let res = await call('GET', '/src/index.js');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['Content-Type'], /javascript/);

  res = await call('GET', '/nonexistent.js');
  assert.equal(res.statusCode, 404);

  res = await call('GET', '/../../etc/passwd');
  assert.ok([403, 404].includes(res.statusCode));
});
