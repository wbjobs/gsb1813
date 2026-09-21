// csp-worker.js —— Web Worker
// 主线程把资源快照批量发送过来，Worker 负责去重、构建策略、dry-run 评估、收紧，
// 避免大批量资源处理阻塞页面渲染。
import {
  buildDirectives, buildPolicy, evaluatePolicy, tightenPolicy, lintPolicy, buildReport
} from './csp-core.js';

// 纯消息处理函数，方便在 Node 中单测；浏览器环境下由 self.onmessage 调用。
export function handleMessage(msg) {
  switch (msg.type) {
    case 'build': {
      const { resources, options } = msg;
      const start = (typeof performance !== 'undefined' ? performance.now() : Date.now());
      const result = buildDirectives(resources, options);
      const policy = buildPolicy(result.directives);
      const violations = evaluatePolicy(policy, resources, options);
      const elapsed = roundMs((typeof performance !== 'undefined' ? performance.now() : Date.now()) - start);
      return {
        type: 'built',
        policy,
        directives: result.directives,
        flags: result.flags,
        ignored: result.ignored,
        violations,
        timing: { batchBuildMs: elapsed, batchSize: resources.length }
      };
    }
    case 'tighten': {
      const { policy, resources, options } = msg;
      const start = (typeof performance !== 'undefined' ? performance.now() : Date.now());
      const tightened = tightenPolicy(policy, Object.assign({ resources }, options || {}));
      const violations = evaluatePolicy(tightened.policy, resources, options || {});
      const lint = lintPolicy(tightened.policy);
      const elapsed = roundMs((typeof performance !== 'undefined' ? performance.now() : Date.now()) - start);
      return { type: 'tightened', ...tightened, violations, lint, timing: { tightenMs: elapsed } };
    }
    case 'evaluate': {
      const { policy, resources, options } = msg;
      return { type: 'evaluated', violations: evaluatePolicy(policy, resources, options), lint: lintPolicy(policy) };
    }
    case 'report':
      return { type: 'report', report: buildReport((msg.payload) || {}) };
    default:
      return { type: 'error', error: `未知的 Worker 消息类型：${msg.type}` };
  }
}

function roundMs(value) { return Math.round(value * 100) / 100; }

if (typeof self !== 'undefined' && typeof self.postMessage === 'function') {
  self.onmessage = (event) => {
    try {
      self.postMessage(handleMessage(event.data || {}));
    } catch (error) {
      self.postMessage({ type: 'error', stage: (event.data || {}).type, error: String((error && error.message) || error) });
    }
  };
}
