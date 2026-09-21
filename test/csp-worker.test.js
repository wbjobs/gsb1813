import { test } from 'node:test';
import assert from 'node:assert/strict';
import { Worker } from 'node:worker_threads';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { handleMessage } from '../src/csp-worker.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CTX = { selfOrigin: 'http://127.0.0.1:8124' };

test('Worker handleMessage: build -> tighten 全流程', () => {
  const resources = [
    { url: 'http://127.0.0.1:8125/a.js', type: 'script' },
    { url: 'http://127.0.0.1:8126/f.woff2', type: 'font' },
    { inline: 'script', type: 'script', hash: "'sha256-aaa'" }
  ];
  const built = handleMessage({ type: 'build', resources, options: CTX });
  assert.equal(built.type, 'built');
  assert.match(built.policy, /script-src-elem/);
  assert.equal(built.timing.batchSize, 3);

  const tightened = handleMessage({
    type: 'tighten',
    policy: built.policy,
    resources,
    options: CTX
  });
  assert.equal(tightened.type, 'tightened');
  assert.deepEqual(tightened.violations, []);
  assert.ok(tightened.policy.includes("'sha256-aaa'"));
  assert.ok(!/script-src[^;]*unsafe-inline/.test(tightened.policy));
});

test('Worker handleMessage: 未知消息返回 error（异常提示通道）', () => {
  const result = handleMessage({ type: 'bogus' });
  assert.equal(result.type, 'error');
  assert.match(result.error, /未知的 Worker 消息类型/);
});

test('真实 Worker 线程往返：构建消息能被独立线程处理', async () => {
  const workerCode = `
    import { handleMessage } from ${JSON.stringify(path.join(__dirname, '../src/csp-worker.js').replace(/\\\\/g, '/'))};
    const { parentPort } = await import('node:worker_threads');
    parentPort.on('message', (msg) => {
      try { parentPort.postMessage(handleMessage(msg)); }
      catch (e) { parentPort.postMessage({ type: 'error', error: String(e && e.message || e) }); }
    });
  `;
  const worker = new Worker(workerCode, { eval: true, execArgv: ['--input-type=module'] });
  const reply = await new Promise((resolve, reject) => {
    worker.once('message', resolve);
    worker.once('error', reject);
    worker.postMessage({
      type: 'build',
      resources: [{ url: 'https://cdn.example.com/x.js', type: 'script' }],
      options: CTX
    });
  });
  await worker.terminate();
  assert.equal(reply.type, 'built');
  assert.match(reply.policy, /cdn\.example\.com|\*\.example\.com/);
  assert.ok(reply.timing.batchBuildMs >= 0);
});
