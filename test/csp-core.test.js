import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  toSourceToken, buildDirectives, buildPolicy, parsePolicy,
  evaluatePolicy, tightenPolicy, lintPolicy, buildReport, PERF_BUDGET
} from '../src/csp-core.js';

const CTX = { selfOrigin: 'http://127.0.0.1:8124', documentUrl: 'http://127.0.0.1:8124/' };

test('toSourceToken: 同源 -> self，跨源 -> host/通配，scheme 归类', () => {
  assert.equal(toSourceToken('/app.js', CTX).token, "'self'");
  assert.equal(toSourceToken('http://127.0.0.1:8124/x', CTX).token, "'self'");
  assert.equal(toSourceToken('http://127.0.0.1:8125/cdn/a.js', CTX).token, 'http://127.0.0.1:8125');
  assert.equal(toSourceToken('https://a.b.example.com/x.js', CTX).token, '*.example.com');
  assert.equal(toSourceToken('https://example.com/x.js', CTX).token, 'example.com');
  assert.equal(toSourceToken('data:image/png;base64,AAAA', CTX).token, 'data:');
  assert.equal(toSourceToken('blob:https://x/uuid', CTX).token, 'blob:');
  assert.equal(toSourceToken('javascript:alert(1)', CTX).token, null);
});

test('buildDirectives: 按类型分桶并生成有序指令', () => {
  const resources = [
    { url: 'http://127.0.0.1:8125/cdn/third-party.js', type: 'script' },
    { url: 'http://127.0.0.1:8125/cdn/cdn-style.css', type: 'style' },
    { url: 'http://127.0.0.1:8125/assets/logo.svg', type: 'img' },
    { url: '/api/time', type: 'connect' },
    { url: 'http://127.0.0.1:8125/cdn/frame.html', type: 'frame' }
  ];
  const { directives } = buildDirectives(resources, CTX);
  assert.ok(directives['script-src-elem'].tokens.includes('http://127.0.0.1:8125'));
  assert.ok(directives['img-src'].tokens.includes('http://127.0.0.1:8125'));
  assert.ok(directives['connect-src'].tokens.includes("'self'"));
  assert.deepEqual(directives['object-src'].tokens, ["'none'"]);
  assert.deepEqual(directives['base-uri'].tokens, ["'none'"]);
  const policy = buildPolicy(directives);
  assert.match(policy, /^default-src [^;]+; script-src /);
  // default-src 必须出现在首位
  assert.equal(policy.indexOf('default-src'), 0);
});

test('报告阶段自动包含 unsafe-inline/unsafe-eval，保证不破坏页面', () => {
  const resources = [
    { inline: 'script', type: 'script', hash: "'sha256-abc'" },
    { eval: true, type: 'script' }
  ];
  const { directives } = buildDirectives(resources, { ...CTX, stage: 'report' });
  assert.ok(directives['script-src-elem'].tokens.includes("'unsafe-inline'"));
  assert.ok(directives['script-src-elem'].tokens.includes("'unsafe-eval'"));
});

test('收紧阶段用 hash 放行内联脚本；有内联事件处理器时保留 unsafe-inline 并告警', () => {
  const resources = [
    { url: 'https://cdn.example.com/a.js', type: 'script' },
    { inline: 'script', type: 'script', hash: "'sha256-abc'" },
    { inline: 'script-attr', type: 'script' }
  ];
  const report = buildPolicy(buildDirectives(resources, { ...CTX, stage: 'report' }).directives);
  const result = tightenPolicy(report, { detectedInlineAttr: true });
  // 无精确域时保留通配子域（避免破坏）
  assert.ok(result.warnings.some((w) => /example\.com/.test(w.reason)));
  // 内联事件处理器 -> unsafe-inline 保留
  assert.ok(parsePolicy(result.policy)['script-src-elem'].tokens.includes("'unsafe-inline'"));
});

test('收紧：有 hash 且无内联属性时移除 unsafe-inline；object-src 固定 none', () => {
  const resources = [
    { url: 'https://cdn.example.com/a.js', type: 'script' },
    { inline: 'script', type: 'script', hash: "'sha256-abc'" }
  ];
  const report = buildPolicy(buildDirectives(resources, { ...CTX, stage: 'report' }).directives);
  const result = tightenPolicy(report, { resources });
  const scriptTokens = parsePolicy(result.policy)['script-src-elem'].tokens;
  assert.ok(!scriptTokens.includes("'unsafe-inline'"));
  assert.ok(scriptTokens.includes("'sha256-abc'"));
  assert.deepEqual(parsePolicy(result.policy)['object-src'].tokens, ["'none'"]);
  assert.ok(result.changes.some((c) => c.token === "'unsafe-inline'" && c.action === 'remove'));
});

test('收紧策略对已收集资源 dry-run 零违规（不破坏页面的核心保证）', () => {
  const resources = [
    { url: 'http://127.0.0.1:8125/a.js', type: 'script' },
    { url: 'http://127.0.0.1:8126/assets/dummy.woff2', type: 'font' },
    { url: '/api/time', type: 'connect' },
    { inline: 'script', type: 'script', hash: "'sha256-xyz'" }
  ];
  const report = buildPolicy(buildDirectives(resources, { ...CTX, stage: 'report' }).directives);
  const { policy } = tightenPolicy(report, { resources });
  const violations = evaluatePolicy(policy, resources, CTX);
  assert.deepEqual(violations, []);
});

test('收紧后未授权源必须被评估为违规', () => {
  const resources = [{ url: 'http://127.0.0.1:8125/a.js', type: 'script' }];
  const report = buildPolicy(buildDirectives(resources, { ...CTX, stage: 'report' }).directives);
  const { policy } = tightenPolicy(report);
  const violations = evaluatePolicy(policy, [
    { url: 'http://127.0.0.1:8127/evil.js', type: 'script' }
  ], CTX);
  assert.equal(violations.length, 1);
  assert.equal(violations[0].directive, 'script-src-elem');
});

test('eval 与内联违规检测', () => {
  const resources = [{ url: '/a.js', type: 'script' }];
  const { directives } = buildDirectives(resources, { ...CTX, stage: 'enforce' });
  // 构造一个无 unsafe-eval、无 hash 的严格脚本策略
  const policy = "default-src 'self'; script-src-elem 'self'; style-src-elem 'self'; object-src 'none'; base-uri 'none'";
  const violations = evaluatePolicy(policy, [
    { eval: true, type: 'script' },
    { inline: 'script', type: 'script', hash: "'sha256-zzz'" }
  ], CTX);
  assert.equal(violations.length, 2);
});

test('lintPolicy: none 与其他来源并存时报错', () => {
  const findings = lintPolicy("img-src 'none' https://x; unknown-directive 'self'");
  assert.ok(findings.some((f) => f.level === 'error' && /'none'/.test(f.message)));
  assert.ok(findings.some((f) => f.level === 'warn' && /非标准/.test(f.message)));
});

test('buildReport: 报告结构完整且可序列化', () => {
  const report = buildReport({
    resources: [{ url: '/a.js', type: 'script' }], stage: 'report',
    selfOrigin: CTX.selfOrigin, policy: "default-src 'self'", violations: [], timing: { batchBuildMs: 3 }
  });
  const json = JSON.stringify(report);
  assert.match(json, /"tool":"csp-auto-gen"/);
  assert.equal(report.summary.resources, 1);
});

test('性能：2000 资源构建 + 收紧在阈值内完成', () => {
  const resources = [];
  for (let i = 0; i < PERF_BUDGET.stressResources; i++) {
    resources.push({ url: `https://h${i % 50}.example.net/a/${i}.js`, type: i % 3 === 0 ? 'script' : i % 3 === 1 ? 'img' : 'connect' });
  }
  const t0 = performance.now();
  const { directives } = buildDirectives(resources, CTX);
  const policy = buildPolicy(directives);
  tightenPolicy(policy);
  const elapsed = performance.now() - t0;
  assert.ok(elapsed < PERF_BUDGET.stressBuildMs, `构建耗时 ${elapsed}ms 超过阈值 ${PERF_BUDGET.stressBuildMs}ms`);
  // 资源被去重归并到有限 host
  assert.ok(parsePolicy(policy)['img-src'].tokens.length <= 50);
});
