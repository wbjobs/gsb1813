import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import { Readable } from 'node:stream';
import { EventEmitter } from 'node:events';
import {
  makeMainHandler, makeAssetHandler, mode, reports
} from '../server.js';

class MockRes extends EventEmitter {
  constructor() {
    super();
    this.statusCode = 200;
    this.headers = {};
    this.chunks = [];
    this.ended = false;
  }
  writeHead(status, headers) {
    this.statusCode = status;
    for (const [key, value] of Object.entries(headers || {})) this.headers[key.toLowerCase()] = value;
  }
  write(chunk) { this.chunks.push(Buffer.from(chunk)); }
  end(chunk) { if (chunk) this.chunks.push(Buffer.from(chunk)); this.ended = true; this.emit('finish'); }
  get body() { return Buffer.concat(this.chunks).toString('utf8'); }
  setHeader(name, value) { this.headers[name] = value; }
}

function mockReq(method, url, body, headers = {}) {
  const req = new Readable({ read() {} });
  req.method = method;
  req.url = url;
  req.headers = headers;
  if (body) req.push(body);
  req.push(null);
  return req;
}

async function callHandler(handler, method, url, body, headers) {
  const req = mockReq(method, url, body, headers);
  const res = new MockRes();
  const done = new Promise((resolve) => res.on('finish', resolve));
  handler(req, res);
  await done;
  return res;
}

beforeEach(() => {
  mode.active = 'report';
  mode.policy = '';
});

test('主源提供首页 HTML', async () => {
  const res = await callHandler(makeMainHandler(), 'GET', '/');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'], /text\/html/);
  assert.match(res.body, /CSP 自动生成控制台/);
});

test('主源提供 /src 下的 ES Module（Worker 源码可加载）', async () => {
  const res = await callHandler(makeMainHandler(), 'GET', '/src/csp-worker.js');
  assert.equal(res.statusCode, 200);
  assert.match(res.headers['content-type'], /javascript/);
  assert.match(res.body, /handleMessage/);
});

test('CDN 源携带 CORS / Timing-Allow-Origin 头', async () => {
  const handler = makeAssetHandler('cdn', 8125);
  const res = await callHandler(handler, 'GET', '/cdn/third-party.js');
  assert.equal(res.statusCode, 200);
  assert.equal(res.headers['access-control-allow-origin'], '*');
  assert.equal(res.headers['timing-allow-origin'], '*');
  assert.match(res.body, /thirdPartyLoaded/);
});

test('字体源提供字体样式；恶意源只放行 /evil.js', async () => {
  const font = await callHandler(makeAssetHandler('font', 8126), 'GET', '/fonts.css');
  assert.equal(font.statusCode, 200);
  assert.match(font.body, /CspDummy/);

  const evil = await callHandler(makeAssetHandler('evil', 8127), 'GET', '/evil.js');
  assert.equal(evil.statusCode, 200);
  assert.match(evil.body, /__evilLoaded/);

  const denied = await callHandler(makeAssetHandler('evil', 8127), 'GET', '/index.html');
  assert.equal(denied.statusCode, 404);
});

test('POST /api/mode 切换模式后 HTML 注入对应 CSP 头', async () => {
  const handler = makeMainHandler();
  const set = await callHandler(handler, 'POST', '/api/mode',
    JSON.stringify({ mode: 'enforce', policy: "default-src 'self'; object-src 'none'" }),
    { 'content-type': 'application/json' });
  assert.equal(set.statusCode, 200);

  const page = await callHandler(handler, 'GET', '/');
  assert.match(page.headers['content-security-policy'], /object-src 'none'/);
  assert.match(page.headers['content-security-policy'], /report-uri \/csp-report/);
  assert.ok(!page.headers['content-security-policy-report-only']);
});

test('Report-Only 模式仅下发 Report-Only 头', async () => {
  const handler = makeMainHandler();
  await callHandler(handler, 'POST', '/api/mode',
    JSON.stringify({ mode: 'report', policy: "default-src 'self'" }),
    { 'content-type': 'application/json' });
  const page = await callHandler(handler, 'GET', '/');
  assert.match(page.headers['content-security-policy-report-only'], /default-src 'self'/);
  assert.ok(!page.headers['content-security-policy']);
});

test('违规上报：report-uri 单条格式可接收并通过 /api/reports 导出', async () => {
  const handler = makeMainHandler();
  const report = await callHandler(handler, 'POST', '/csp-report',
    JSON.stringify({ 'csp-report': { 'effective-directive': 'script-src-elem', 'blocked-uri': 'http://127.0.0.1:8127/evil.js' } }),
    { 'content-type': 'application/csp-report' });
  assert.equal(report.statusCode, 204);

  const list = await callHandler(handler, 'GET', '/api/reports');
  const data = JSON.parse(list.body);
  assert.ok(data.length >= 1);
  assert.ok(data.some((r) => r.body['blocked-uri'].includes('8127')));
});

test('违规上报：Reporting API 批量格式同样可接收', async () => {
  const handler = makeMainHandler();
  const res = await callHandler(handler, 'POST', '/csp-reporting-endpoint',
    JSON.stringify([{ type: 'csp-violation', body: { 'effective-directive': 'img-src', 'blocked-uri': 'https://tracker.example/x.gif' } }]),
    { 'content-type': 'application/reports' });
  assert.equal(res.statusCode, 204);
  const list = JSON.parse((await callHandler(handler, 'GET', '/api/reports')).body);
  assert.ok(list.some((r) => r.body['effective-directive'] === 'img-src'));
});

test('非法模式返回 400 与错误信息（异常有提示）', async () => {
  const res = await callHandler(makeMainHandler(), 'POST', '/api/mode',
    JSON.stringify({ mode: 'nope' }), { 'content-type': 'application/json' });
  assert.equal(res.statusCode, 400);
  assert.match(JSON.parse(res.body).error, /report 或 enforce/);
});

test('路径穿越返回 403', async () => {
  const res = await callHandler(makeMainHandler(), 'GET', '/..%2f..%2f..%2fetc%2fpasswd');
  assert.ok([403, 404].includes(res.statusCode));
});
