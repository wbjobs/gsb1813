/**
 * generator.js — 由收集到的资源条目生成 CSP（纯逻辑，可在 Worker / Node 中运行）
 */
import {
  RESOURCE_DIRECTIVES, directiveForEntry, sourceForUrl,
  parsePolicy, serializePolicy, verifyPolicy,
} from './policy.js';

/**
 * @param {Array} entries 收集到的资源条目 [{name, initiatorType, ...}]
 * @param {object} options
 *   - selfOrigin: 页面源（同源资源折叠为 'self'）
 *   - inline: { script:boolean, style:boolean } 是否观察到内联脚本/样式
 *   - reportUri: 报告接收地址
 *   - extras: { directive: [sources] } 额外合并的源
 *   - baseUri/objectSrc: 非资源指令覆盖
 */
export function generatePolicy(entries, options = {}) {
  const selfOrigin = options.selfOrigin || '';
  const inline = options.inline || {};
  const map = new Map();

  map.set('default-src', ["'self'"]);
  map.set('object-src', options.objectSrc ? [options.objectSrc] : ["'none'"]);
  map.set('base-uri', [options.baseUri || "'self'"]);

  for (const entry of entries) {
    const directive = directiveForEntry(entry);
    const source = sourceForUrl(entry.name, selfOrigin);
    if (!source) continue;
    if (!map.has(directive)) map.set(directive, []);
    const list = map.get(directive);
    if (!list.includes(source)) list.push(source);
  }

  // 保证每个被使用的资源指令至少含 'self'（'none' 指令除外）
  for (const dir of RESOURCE_DIRECTIVES) {
    const list = map.get(dir);
    if (list && !list.includes("'none'") && !list.includes("'self'")) list.unshift("'self'");
  }

  if (inline.script) {
    const list = map.get('script-src') || [];
    if (!list.includes("'unsafe-inline'")) list.push("'unsafe-inline'");
    map.set('script-src', list);
  }
  if (inline.style) {
    const list = map.get('style-src') || [];
    if (!list.includes("'unsafe-inline'")) list.push("'unsafe-inline'");
    map.set('style-src', list);
  }

  if (options.extras) {
    for (const [dir, sources] of Object.entries(options.extras)) {
      const list = map.get(dir) || [];
      for (const s of sources) if (!list.includes(s)) list.push(s);
      map.set(dir, list);
    }
  }
  if (options.reportUri) map.set('report-uri', [options.reportUri]);

  const csp = serializePolicy(map);
  // 自检：生成的策略必须允许全部已观察资源
  const violations = verifyPolicy(csp, entries, selfOrigin);
  return { csp, violations, safe: violations.length === 0 };
}
