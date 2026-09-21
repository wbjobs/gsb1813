import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generatePolicy } from '../src/generator.js';
import { tightenPolicy } from '../src/tightener.js';
import { parsePolicy } from '../src/policy.js';

const SELF = 'https://example.com';
const ENTRIES = [
  { name: 'https://example.com/app.js', initiatorType: 'script' },
  { name: 'https://cdn.libs.com/lib.js', initiatorType: 'script' },
  { name: 'https://example.com/logo.png', initiatorType: 'img' },
];

test('收紧移除未使用的源', () => {
  const loose = "default-src 'self'; script-src 'self' https://cdn.libs.com https://unused.com; img-src 'self' https://old-cdn.com";
  const r = tightenPolicy(loose, ENTRIES, { selfOrigin: SELF });
  const p = parsePolicy(r.csp);
  assert.ok(!p.get('script-src').includes('https://unused.com'));
  assert.ok(!p.get('img-src').includes('https://old-cdn.com'));
  assert.ok(p.get('script-src').includes('https://cdn.libs.com')); // 仍被使用
  assert.equal(r.safe, true); // 收紧后不破坏页面
});

test('收紧移除无内联时的 unsafe-inline', () => {
  const loose = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'";
  const r = tightenPolicy(loose, ENTRIES, { selfOrigin: SELF, inline: { script: false, style: true } });
  const p = parsePolicy(r.csp);
  assert.ok(!p.get('script-src').includes("'unsafe-inline'"));
  assert.ok(p.get('style-src').includes("'unsafe-inline'")); // 仍有内联样式则保留
});

test('通配符收紧为实际观察源', () => {
  const loose = "default-src 'self'; script-src *";
  const r = tightenPolicy(loose, ENTRIES, { selfOrigin: SELF });
  const p = parsePolicy(r.csp);
  assert.ok(!p.get('script-src').includes('*'));
  assert.ok(p.get('script-src').includes('https://cdn.libs.com'));
  assert.equal(r.safe, true);
});

test('未使用的资源指令被移除并回落 default-src', () => {
  const loose = "default-src 'self'; script-src 'self'; media-src 'self' https://media.com";
  const r = tightenPolicy(loose, ENTRIES, { selfOrigin: SELF });
  const p = parsePolicy(r.csp);
  assert.equal(p.get('media-src'), undefined);
  assert.ok(r.removed.some((x) => x.includes('media-src')));
});

test('收紧不引入破坏：观察到的源被补回', () => {
  const tooStrict = "default-src 'none'; script-src 'none'";
  const r = tightenPolicy(tooStrict, ENTRIES, { selfOrigin: SELF });
  assert.equal(r.safe, true); // 防御性补回观察到的源
});

test('生成→收紧 闭环保持 safe', () => {
  const g = generatePolicy(ENTRIES, { selfOrigin: SELF, inline: { script: true } });
  const t = tightenPolicy(g.csp, ENTRIES, { selfOrigin: SELF, inline: { script: true } });
  assert.equal(t.safe, true);
  assert.equal(t.violations.length, 0);
});
