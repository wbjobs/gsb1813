import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  directiveForEntry, sourceForUrl, parsePolicy, serializePolicy,
  sourceMatchesUrl, verifyPolicy,
} from '../src/policy.js';

const SELF = 'https://example.com';

test('资源类型映射到正确的 CSP 指令', () => {
  assert.equal(directiveForEntry({ initiatorType: 'script', name: 'https://a.com/x.js' }), 'script-src');
  assert.equal(directiveForEntry({ initiatorType: 'link', name: 'https://a.com/x.css' }), 'style-src');
  assert.equal(directiveForEntry({ initiatorType: 'link', name: 'https://a.com/x.woff2' }), 'font-src');
  assert.equal(directiveForEntry({ initiatorType: 'img', name: 'https://a.com/x.png' }), 'img-src');
  assert.equal(directiveForEntry({ initiatorType: 'fetch', name: 'https://a.com/api' }), 'connect-src');
  assert.equal(directiveForEntry({ initiatorType: 'xmlhttprequest', name: 'https://a.com/api' }), 'connect-src');
  assert.equal(directiveForEntry({ initiatorType: 'video', name: 'https://a.com/x' }), 'media-src');
  assert.equal(directiveForEntry({ initiatorType: 'iframe', name: 'https://a.com/x' }), 'frame-src');
  assert.equal(directiveForEntry({ initiatorType: 'other', name: 'https://a.com/x.woff' }), 'font-src');
  assert.equal(directiveForEntry({ initiatorType: 'other', name: 'https://a.com/x.mp4' }), 'media-src');
});

test('URL 提取为 CSP 源表达式', () => {
  assert.equal(sourceForUrl('https://example.com/a.js', SELF), "'self'");
  assert.equal(sourceForUrl('https://cdn.other.com/a.js', SELF), 'https://cdn.other.com');
  assert.equal(sourceForUrl('data:image/png;base64,xx', SELF), 'data:');
  assert.equal(sourceForUrl('blob:https://example.com/uuid', SELF), 'blob:');
  assert.equal(sourceForUrl('not a url', ''), null);
});

test('CSP 解析与序列化互逆', () => {
  const csp = "default-src 'self'; script-src 'self' https://cdn.com; img-src data:";
  const map = parsePolicy(csp);
  assert.deepEqual(map.get('script-src'), ["'self'", 'https://cdn.com']);
  const out = serializePolicy(map);
  assert.ok(out.includes("script-src 'self' https://cdn.com"));
  assert.ok(out.indexOf('default-src') < out.indexOf('img-src')); // 排序稳定
});

test('源匹配规则', () => {
  assert.ok(sourceMatchesUrl("'self'", 'https://example.com/a', SELF));
  assert.ok(!sourceMatchesUrl("'self'", 'https://evil.com/a', SELF));
  assert.ok(sourceMatchesUrl('data:', 'data:image/png;base64,x', SELF));
  assert.ok(sourceMatchesUrl('*.cdn.com', 'https://a.cdn.com/x', SELF));
  assert.ok(!sourceMatchesUrl('*.cdn.com', 'https://cdn.com.evil.com/x', SELF));
  assert.ok(sourceMatchesUrl('https://cdn.com', 'https://cdn.com/x.js', SELF));
  assert.ok(!sourceMatchesUrl("'none'", 'https://example.com/a', SELF));
});

test('verifyPolicy 检出不允许的资源', () => {
  const entries = [
    { name: 'https://example.com/a.js', initiatorType: 'script' },
    { name: 'https://evil.com/b.js', initiatorType: 'script' },
  ];
  const violations = verifyPolicy("script-src 'self'", entries, SELF);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].url, 'https://evil.com/b.js');
  assert.equal(violations[0].directive, 'script-src');
});
