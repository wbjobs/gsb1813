/**
 * worker.js — CSP 计算 Worker：策略生成 / 收紧 / 校验移出主线程，避免阻塞渲染
 * 使用方式：new Worker('worker.js', { type: 'module' })
 * 消息：{ id, type: 'generate'|'tighten'|'verify', payload }
 */
import { generatePolicy } from './generator.js';
import { tightenPolicy } from './tightener.js';
import { verifyPolicy } from './policy.js';

const handlers = {
  generate: ({ entries, options }) => generatePolicy(entries, options),
  tighten: ({ currentCsp, entries, options }) => tightenPolicy(currentCsp, entries, options),
  verify: ({ csp, entries, selfOrigin }) => ({ violations: verifyPolicy(csp, entries, selfOrigin) }),
};

self.onmessage = (ev) => {
  const { id, type, payload } = ev.data || {};
  const handler = handlers[type];
  if (!handler) {
    self.postMessage({ id, error: `未知任务类型: ${type}` });
    return;
  }
  try {
    const started = performance.now();
    const result = handler(payload);
    self.postMessage({ id, result, elapsedMs: Math.round((performance.now() - started) * 100) / 100 });
  } catch (err) {
    self.postMessage({ id, error: err.message || String(err) });
  }
};
