import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePolicy } from '../src/generator.js';
import { parsePolicy } from '../src/policy.js';

const SELF = 'https://example.com';
const ENTRIES = [
  { name: 'https://example.com/app.js', initiatorType: 'script' },
  { name: 'https://cdn.libs.com/lib.js', initiatorType: 'script' },
  { name: 'https://example.com/style.css', initiatorType: 'link' },
  { name: 'https://example.com/logo.png', initiatorType: 'img' },
  { name: 'data:image/png;base64,xx', initiatorType: 'img' },
  { name: 'https://api.example.com/v1/data', initiatorType: 'fetch' },
  { name: 'https://fonts.cdn.com/a.woff2', initiatorType: 'other' },
];

test('生成的 CSP 不破坏页面（safe=true，零违规）', () => {
  const r = generatePolicy(ENTRIES, { selfOrigin: SELF });
  assert.equal(r.safe, true);
  assert.equal(r.violations.length, 0);
});

test('生成的 CSP 内容正确', () => {
  const r = generatePolicy(ENTRIES, { selfOrigin: SELF, reportUri: '/api/csp-report' });
  const p = parsePolicy(r.csp);
  assert.deepEqual(p.get('default-src'), ["'self'"]);
  assert.deepEqual(p.get('object-src'), ["'none'"]);
  assert.ok(p.get('script-src').includes("'self'"));
  assert.ok(p.get('script-src').includes('https://cdn.libs.com'));
  assert.ok(p.get('img-src').includes('data:'));
  assert.ok(p.get('connect-src').includes('https://api.example.com'));
  assert.ok(p.get('font-src').includes('https://fonts.cdn.com'));
  assert.deepEqual(p.get('report-uri'), ['/api/csp-report']);
});

test('内联脚本/样式触发 unsafe-inline', () => {
  const r = generatePolicy(ENTRIES, { selfOrigin: SELF, inline: { script: true, style: true } });
  const p = parsePolicy(r.csp);
  assert.ok(p.get('script-src').includes("'unsafe-inline'"));
  assert.ok(p.get('style-src').includes("'unsafe-inline'"));
});

test('空资源集也能生成合法基线策略', () => {
  const r = generatePolicy([], { selfOrigin: SELF });
  assert.equal(r.safe, true);
  assert.ok(r.csp.includes("default-src 'self'"));
});

test('性能：1 万条资源生成耗时 < 500ms', () => {
  const many = Array.from({ length: 10000 }, (_, i) => ({
    name: `https://cdn${i % 50}.com/res/${i}.js`, initiatorType: 'script',
  }));
  const t0 = performance.now();
  const r = generatePolicy(many, { selfOrigin: SELF });
  const elapsed = performance.now() - t0;
  assert.equal(r.safe, true);
  assert.ok(elapsed < 500, `耗时 ${elapsed.toFixed(1)}ms 超过阈值`);
});
