/**
 * tightener.js — 策略收紧：移除未使用的源/指令、消除 unsafe-inline、保证不破坏已观察资源
 */
import {
  RESOURCE_DIRECTIVES, directiveForEntry, sourceForUrl,
  parsePolicy, serializePolicy, verifyPolicy,
} from './policy.js';

/**
 * @param {string} currentCsp 当前生效（或生成）的 CSP
 * @param {Array} entries 观察到的资源条目
 * @param {object} options { selfOrigin, inline:{script,style}, keepDirectives:[], reportUri }
 * @returns {{ csp, removed, violations, safe, notes }}
 */
export function tightenPolicy(currentCsp, entries, options = {}) {
  const selfOrigin = options.selfOrigin || '';
  const inline = options.inline || {};
  const policy = parsePolicy(currentCsp);
  const removed = [];
  const notes = [];

  // 每条指令实际需要的源
  const needed = new Map();
  for (const entry of entries) {
    const dir = directiveForEntry(entry);
    const src = sourceForUrl(entry.name, selfOrigin);
    if (!src) continue;
    if (!needed.has(dir)) needed.set(dir, new Set());
    needed.get(dir).add(src);
  }

  const next = new Map();
  for (const [dir, sources] of policy) {
    if (!RESOURCE_DIRECTIVES.includes(dir)) { next.set(dir, sources); continue; }
    const need = needed.get(dir) || new Set();
    const kept = [];
    for (const s of sources) {
      if (s === "'unsafe-inline'") {
        const kind = dir === 'script-src' ? 'script' : dir === 'style-src' ? 'style' : null;
        if (kind && !inline[kind]) {
          removed.push(`${dir} ${s}`);
          notes.push(`${dir}: 未观察到内联${kind === 'script' ? '脚本' : '样式'}，移除 'unsafe-inline'`);
          continue;
        }
        kept.push(s);
        continue;
      }
      if (s === "'unsafe-eval'" || s === "'none'" || s === '*') {
        if (s === '*') { removed.push(`${dir} ${s}`); notes.push(`${dir}: 通配符 * 收紧为实际观察到的源`); continue; }
        kept.push(s);
        continue;
      }
      // 保留仍被需要的源；'self' 在指令被使用时保留
      const neededList = [...need];
      const stillUsed = neededList.includes(s) || (s === "'self'" && neededList.includes("'self'"));
      if (stillUsed || (s === "'self'" && need.size > 0)) kept.push(s);
      else removed.push(`${dir} ${s}`);
    }
    // 补充观察到但原策略没有的源（防御：收紧不应引入破坏）
    for (const src of need) if (!kept.includes(src)) kept.push(src);
    // 'none' 与实际源互斥：补回真实源后移除 'none'
    if (kept.length > 1 && kept.includes("'none'")) {
      kept.splice(kept.indexOf("'none'"), 1);
      removed.push(`${dir} 'none'`);
      notes.push(`${dir}: 观察到实际资源，'none' 替换为真实源`);
    }
    if (!kept.length) {
      removed.push(`${dir} (整指令)`);
      notes.push(`${dir}: 无观察到的使用，指令移除（回落 default-src）`);
      continue;
    }
    next.set(dir, kept);
  }

  // 原策略缺失但已观察到的指令：补建，避免收紧引入破坏
  for (const [dir, sources] of needed) {
    if (!next.has(dir)) {
      next.set(dir, [...sources]);
      notes.push(`${dir}: 原策略缺失，按观察补建`);
    }
  }

  if (options.reportUri) next.set('report-uri', [options.reportUri]);

  const csp = serializePolicy(next);
  const violations = verifyPolicy(csp, entries, selfOrigin);
  if (violations.length) notes.push(`警告：收紧后仍有 ${violations.length} 个已观察资源不被允许`);
  return { csp, removed, violations, safe: violations.length === 0, notes };
}
