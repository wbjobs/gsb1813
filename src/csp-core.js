// csp-core.js
// 纯函数核心：URL 归并 -> 指令构建 -> 策略评估 -> 收紧。
// 同时可运行于浏览器主线程、Web Worker、Node（无 DOM 依赖）。

export const VERSION = '1.0.0';

// 各资源类型对应的 CSP 取数指令（default-src 之外的指令固定输出顺序）
export const DIRECTIVE_ORDER = [
  'default-src',
  'script-src',
  'script-src-elem',
  'style-src',
  'style-src-elem',
  'img-src',
  'font-src',
  'connect-src',
  'worker-src',
  'frame-src',
  'object-src',
  'media-src',
  'manifest-src',
  'base-uri',
  'form-action'
];

const HOST_DIRECTIVES = new Set([
  'default-src', 'script-src', 'script-src-elem', 'style-src', 'style-src-elem',
  'img-src', 'font-src', 'connect-src', 'worker-src', 'frame-src',
  'object-src', 'media-src', 'manifest-src'
]);

export const PERF_BUDGET = {
  batchBuildMs: 50,      // 单次批量构建策略耗时阈值
  bigBatch: 500,         // 超过该资源数视为大批量
  stressResources: 2000, // 压测资源数
  stressBuildMs: 500     // 压测构建耗时阈值
};

function isIpHost(host) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host) || host.startsWith('[');
}

// 将资源 URL 归并为 CSP source token；无法判定时返回 null（并给出原因）
export function toSourceToken(rawUrl, context) {
  const url = String(rawUrl == null ? '' : rawUrl).trim();
  if (!url || url.startsWith('about:') || url.startsWith('javascript:') || url.startsWith('vbscript:')) {
    return { token: null, reason: url ? 'unsupported-scheme' : 'empty-url' };
  }
  if (url === "'self'" || url === "'none'") return { token: url };

  if (/^[a-z][a-z0-9+.-]*:/i.test(url) && !url.startsWith('//')) {
    let parsed = null;
    try { parsed = new URL(url, context && context.selfOrigin); } catch (_) { parsed = null; }
    const scheme = (url.split(':')[0] || '').toLowerCase();
    if (scheme === 'data') return { token: 'data:', kind: 'scheme' };
    if (scheme === 'blob') return { token: 'blob:', kind: 'scheme' };
    if (scheme === 'filesystem') return { token: 'filesystem:', kind: 'scheme' };
    if (scheme === 'http' || scheme === 'https') {
      if (!parsed) return { token: null, reason: 'invalid-url' };
    } else {
      return { token: scheme + ':', kind: 'scheme' };
    }
    if (parsed && (parsed.protocol === 'http:' || parsed.protocol === 'https:')) {
      return hostToken(parsed, context);
    }
    return { token: scheme + ':', kind: 'scheme' };
  }

  let parsed;
  try { parsed = new URL(url, (context && context.documentUrl) || (context && context.selfOrigin) || 'http://x/'); }
  catch (_) { return { token: null, reason: 'invalid-url' }; }
  if (parsed.protocol === 'data:') return { token: 'data:', kind: 'scheme' };
  if (parsed.protocol === 'blob:') return { token: 'blob:', kind: 'scheme' };
  if (parsed.protocol === 'http:' || parsed.protocol === 'https:') return hostToken(parsed, context);
  return { token: parsed.protocol, kind: 'scheme' };
}

function hostToken(parsed, context) {
  const selfOrigin = context && context.selfOrigin ? tryOrigin(context.selfOrigin) : null;
  if (selfOrigin && parsed.origin === selfOrigin) return { token: "'self'", kind: 'self' };
  const host = parsed.hostname;
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  if (isIpHost(host)) {
    return { token: `${parsed.protocol}//${host}:${port}`, kind: 'host' };
  }
  if (context && context.collapseWildcard !== false) {
    const labels = host.split('.');
    if (labels.length >= 3) {
      // 仅折叠“资源型/CDN 型”三级以上域名到 *.example.com，保留二级域名
      return { token: `*.${labels.slice(-2).join('.')}`, kind: 'wildcard' };
    }
  }
  return { token: host, kind: 'host' };
}

function tryOrigin(value) {
  try { return new URL(value).origin; } catch (_) { return null; }
}

const KEYWORD_ORDER = ["'none'", "'self'", "'strict-dynamic'", "'unsafe-inline'", "'unsafe-eval'", 'data:', 'blob:', 'https:'];

function sortTokens(tokens) {
  const set = new Set(tokens.filter(Boolean));
  const kw = [];
  const schemes = [];
  const wildcards = [];
  const hosts = [];
  for (const token of set) {
    if (KEYWORD_ORDER.includes(token)) kw.push(token);
    else if (/^[a-z][a-z0-9+.-]*:$/.test(token)) schemes.push(token);
    else if (token.startsWith('*')) wildcards.push(token);
    else hosts.push(token);
  }
  kw.sort((a, b) => KEYWORD_ORDER.indexOf(a) - KEYWORD_ORDER.indexOf(b));
  const cmp = (a, b) => a.localeCompare(b);
  return [...kw, ...schemes.sort(cmp), ...wildcards.sort(cmp), ...hosts.sort(cmp)];
}

// 从资源集合构建各指令 token
// resources: [{ url, type, inline?:'script'|'style'|'script-attr'|'style-attr', eval?:boolean }]
// options: { selfOrigin, documentUrl, collapseWildcard, stage:'report'|'enforce' }
export function buildDirectives(resources, options = {}) {
  const stage = options.stage || 'report';
  const buckets = new Map();
  const inlineScriptHashes = new Set();
  const inlineStyleHashes = new Set();
  const flags = { evalUsed: false, inlineScriptAttr: false, inlineStyleAttr: false };
  const ignored = [];

  const addToken = (directive, token) => {
    if (!buckets.has(directive)) buckets.set(directive, new Set());
    buckets.get(directive).add(token);
  };

  for (const resource of resources) {
    if (resource.eval) { flags.evalUsed = true; continue; }
    if (resource.inline) {
      if (resource.inline === 'script' && resource.hash) inlineScriptHashes.add(resource.hash);
      if (resource.inline === 'style' && resource.hash) inlineStyleHashes.add(resource.hash);
      if (resource.inline === 'script-attr') flags.inlineScriptAttr = true;
      if (resource.inline === 'style-attr') flags.inlineStyleAttr = true;
      continue;
    }
    const directive = typeToDirective(resource.type);
    if (!directive) { ignored.push({ url: resource.url, reason: 'unknown-type' }); continue; }
    const result = toSourceToken(resource.url, options);
    if (!result.token) { ignored.push({ url: resource.url, reason: result.reason || 'unresolved' }); continue; }
    addToken(directive, result.token);
  }

  const directives = {};
  for (const directive of DIRECTIVE_ORDER) {
    if (directive === 'base-uri' || directive === 'form-action' || directive === 'default-src') continue;
    const set = buckets.get(directive);
    if (!set || set.size === 0) continue;
    directives[directive] = { tokens: sortTokens([...set]), sources: set.size };
  }

  // base-uri：无 <base> 时默认 'none'（由 options.noBase=true 指定）
  const baseSet = buckets.get('base-uri');
  if (baseSet && baseSet.size) directives['base-uri'] = { tokens: sortTokens([...baseSet]) };
  else if (options.noBase !== false) directives['base-uri'] = { tokens: ["'none'"] };

  const formSet = buckets.get('form-action');
  if (formSet && formSet.size) directives['form-action'] = { tokens: sortTokens([...formSet]) };

  // default-src：报告阶段用并集兜底，确保“不破坏页面”
  const union = new Set();
  for (const directive of Object.keys(directives)) {
    if (directive === 'base-uri' || directive === 'form-action') continue;
    for (const token of directives[directive].tokens) {
      if (!token.startsWith('*')) union.add(token);
    }
  }
  union.add("'self'");
  directives['default-src'] = { tokens: sortTokens([...union]) };

  applyInlineAndHardening(directives, { inlineScriptHashes, inlineStyleHashes, flags, stage });

  return { directives, flags: { ...flags, inlineScriptCount: inlineScriptHashes.size, inlineStyleCount: inlineStyleHashes.size }, ignored };
}

function typeToDirective(type) {
  const map = {
    script: 'script-src-elem',
    inlineScript: null,
    style: 'style-src-elem',
    img: 'img-src',
    font: 'font-src',
    connect: 'connect-src',
    worker: 'worker-src',
    frame: 'frame-src',
    object: 'object-src',
    media: 'media-src',
    manifest: 'manifest-src',
    base: 'base-uri',
    form: 'form-action'
  };
  return map[type] || null;
}

function applyInlineAndHardening(directives, ctx) {
  const { stage, flags, inlineScriptHashes, inlineStyleHashes } = ctx;
  const scriptTokens = new Set(directives['script-src-elem'] ? directives['script-src-elem'].tokens : ["'self'"]);
  const styleTokens = new Set(directives['style-src-elem'] ? directives['style-src-elem'].tokens : ["'self'"]);

  if (stage === 'report') {
    // 报告阶段宽松：放行内联与 eval，先保证页面不被破坏
    scriptTokens.add("'unsafe-inline'");
    if (flags.evalUsed) scriptTokens.add("'unsafe-eval'");
    styleTokens.add("'unsafe-inline'");
  } else {
    // 收紧阶段：用 hash 精确放行内联脚本；内联事件处理器无法用 hash 放行 -> 保留并给出告警
    for (const hash of inlineScriptHashes) scriptTokens.add(hash);
    if (inlineScriptHashes.size === 0 || flags.inlineScriptAttr) scriptTokens.add("'unsafe-inline'");
    if (flags.evalUsed) scriptTokens.add("'unsafe-eval'");
    for (const hash of inlineStyleHashes) styleTokens.add(hash);
    // style 属性（element.style）无法用 hash 放行：仅在确实使用过 style 属性时保留
    if (flags.inlineStyleAttr) styleTokens.add("'unsafe-inline'");
  }

  directives['script-src-elem'] = { tokens: sortTokens([...scriptTokens]) };
  directives['style-src-elem'] = { tokens: sortTokens([...styleTokens]) };
  // 回退指令保持一致内容
  directives['script-src'] = { tokens: directives['script-src-elem'].tokens.slice() };
  directives['style-src'] = { tokens: directives['style-src-elem'].tokens.slice() };

  if (!directives['object-src']) directives['object-src'] = { tokens: ["'none'"] };
}

// 按 DIRECTIVE_ORDER 序列化为 CSP 头值
export function buildPolicy(directives) {
  const parts = [];
  for (const directive of DIRECTIVE_ORDER) {
    const entry = directives[directive];
    if (entry && entry.tokens && entry.tokens.length) {
      parts.push(`${directive} ${entry.tokens.join(' ')}`);
    }
  }
  // 任何未登记但存在的指令（如 frame-ancestors）追加在末尾
  for (const directive of Object.keys(directives)) {
    if (!DIRECTIVE_ORDER.includes(directive)) {
      const entry = directives[directive];
      if (entry && entry.tokens && entry.tokens.length) parts.push(`${directive} ${entry.tokens.join(' ')}`);
    }
  }
  return parts.join('; ');
}

export function parsePolicy(policyText) {
  const directives = {};
  for (const chunk of String(policyText || '').split(';')) {
    const tokens = chunk.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    directives[tokens[0]] = { tokens: tokens.slice(1) };
  }
  return directives;
}

function effectiveTokens(directives, directive) {
  if (directives[directive] && directives[directive].tokens.length) return directives[directive].tokens;
  const fallbacks = {
    'script-src-elem': ['script-src', 'default-src'],
    'style-src-elem': ['style-src', 'default-src'],
    'img-src': ['default-src'], 'font-src': ['default-src'],
    'connect-src': ['default-src'], 'worker-src': ['child-src', 'script-src', 'default-src'],
    'frame-src': ['child-src', 'default-src'], 'object-src': ['default-src'],
    'media-src': ['default-src'], 'manifest-src': ['default-src'],
    'base-uri': [], 'form-action': []
  };
  for (const fallback of fallbacks[directive] || []) {
    if (directives[fallback] && directives[fallback].tokens.length) return directives[fallback].tokens;
  }
  return null; // 无指令 = 允许
}

// 判断 token 是否放行 origin（host / scheme / 关键字 / nonce / hash）
function tokenMatches(token, parsed, context) {
  if (token === '*') return true;
  if (token === "'self'") {
    const selfOrigin = context && context.selfOrigin ? tryOrigin(context.selfOrigin) : null;
    return !!selfOrigin && parsed.origin === selfOrigin;
  }
  if (token === 'https:' || token === 'http:') return parsed.protocol === token;
  if (/^[a-z][a-z0-9+.-]*:$/.test(token)) return parsed.protocol === token;
  if (token.startsWith("'")) return false; // hash/nonce/unsafe-* 对 URL 匹配无意义
  // host-source，支持前导通配 *.example.com 与显式端口
  let hostPattern = token;
  let portPattern = '';
  const schemeMatch = token.match(/^(https?):\/\/(.+)$/i);
  if (schemeMatch) {
    hostPattern = schemeMatch[2];
  }
  const colon = hostPattern.indexOf(':');
  if (colon >= 0) {
    portPattern = hostPattern.slice(colon + 1);
    hostPattern = hostPattern.slice(0, colon);
  }
  const host = parsed.hostname;
  const port = parsed.port || (parsed.protocol === 'https:' ? '443' : '80');
  let hostOk;
  if (hostPattern.startsWith('*.')) hostOk = host === hostPattern.slice(2) || host.endsWith(hostPattern.slice(1));
  else if (hostPattern === '*') hostOk = true;
  else hostOk = host === hostPattern;
  if (!hostOk) return false;
  if (portPattern && portPattern !== '*' && portPattern !== port) return false;
  if (schemeMatch && parsed.protocol !== schemeMatch[1].toLowerCase() + ':') return false;
  return true;
}

// 用给定策略回放资源，返回违规列表（用于 Report-Only dry-run 与收紧校验）
export function evaluatePolicy(policyText, resources, context = {}) {
  const directives = parsePolicy(policyText);
  const violations = [];
  for (const resource of resources) {
    if (resource.eval) {
      const tokens = effectiveTokens(directives, 'script-src-elem');
      if (tokens && !tokens.includes("'unsafe-eval'")) {
        violations.push({ type: 'eval', directive: 'script-src', blocked: "eval / new Function", reason: "缺少 'unsafe-eval'" });
      }
      continue;
    }
    if (resource.inline) {
      const directive = resource.inline.startsWith('style') ? 'style-src-elem' : 'script-src-elem';
      const tokens = effectiveTokens(directives, directive);
      if (!tokens) continue;
      const allowed = tokens.includes("'unsafe-inline'") ||
        (resource.hash && tokens.includes(resource.hash)) ||
        (resource.nonce && tokens.includes(`'nonce-${resource.nonce}'`));
      if (!allowed) {
        violations.push({ type: 'inline', inline: resource.inline, directive: directive.replace('-elem', ''), blocked: resource.hash ? resource.hash.slice(0, 18) + '…' : 'inline', reason: '内联未通过 hash/nonce 放行' });
      }
      continue;
    }
    const directive = typeToDirective(resource.type);
    if (!directive) continue;
    const tokens = effectiveTokens(directives, directive);
    if (!tokens) continue;
    if (tokens.includes("'none'")) {
      violations.push({ type: resource.type, directive, blocked: resource.url, reason: "'none'" });
      continue;
    }
    let parsed = null;
    const result = toSourceToken(resource.url, context);
    try { parsed = new URL(/^[a-z][a-z0-9+.-]*:/i.test(resource.url) ? resource.url : new URL(resource.url, context.selfOrigin || context.documentUrl || 'http://x/').href); }
    catch (_) { parsed = null; }
    const special = result.token === 'data:' || result.token === 'blob:' || (result.kind === 'scheme');
    const allowed = tokens.some((token) => {
      if (special) return token === result.token;
      return parsed && tokenMatches(token, parsed, context);
    });
    if (!allowed) {
      violations.push({ type: resource.type, directive, blocked: resource.url, reason: '来源不在允许列表' });
    }
  }
  return violations;
}

// 收紧：v1（宽松） -> v2（严格）
export function tightenPolicy(policyText, options = {}) {
  const directives = parsePolicy(policyText);
  const changes = [];
  const warnings = [];

  // 报告策略用 unsafe-inline 兜底，hash 未出现在策略中；
  // 收紧前根据收集到的内联资源，把 hash 精确补回对应指令。
  if (Array.isArray(options.resources)) {
    for (const resource of options.resources) {
      if (!resource.inline || !resource.hash) continue;
      const names = resource.inline.startsWith('style')
        ? ['style-src-elem', 'style-src']
        : ['script-src-elem', 'script-src'];
      for (const name of names) {
        if (directives[name]) {
          if (!directives[name].tokens.includes(resource.hash)) directives[name].tokens.push(resource.hash);
        } else {
          directives[name] = { tokens: [resource.hash] };
        }
      }
    }
  }

  const removeToken = (directive, token, reason) => {
    const entry = directives[directive];
    if (!entry) return false;
    const next = entry.tokens.filter((item) => item !== token);
    if (next.length === entry.tokens.length) return false;
    entry.tokens = next;
    changes.push({ directive, action: 'remove', token, reason });
    return true;
  };

  const ensureToken = (directive, token, reason) => {
    const entry = directives[directive];
    if (!entry) return;
    if (!entry.tokens.includes(token)) {
      entry.tokens.push(token);
      changes.push({ directive, action: 'add', token, reason });
    }
  };

  // 1) 移除通配符子域，保留精确二级域（若无精确域则给出告警而非盲目删除）
  for (const directive of Object.keys(directives)) {
    const entry = directives[directive];
    if (!HOST_DIRECTIVES.has(directive)) continue;
    const wildcards = entry.tokens.filter((token) => token.startsWith('*.'));
    for (const wildcard of wildcards) {
      const bare = wildcard.slice(2);
      if (entry.tokens.includes(bare)) removeToken(directive, wildcard, '已存在精确域名，移除通配子域');
      else warnings.push({ directive, token: wildcard, reason: `通配子域 ${wildcard} 无对应精确域，保留以避免破坏页面` });
    }
  }

  // 2) script/style：收紧内联。可通过 hash 放行时移除 unsafe-inline
  for (const pair of [['script-src-elem', 'script-src'], ['style-src-elem', 'style-src']]) {
    const [elem, base] = pair;
    const names = [elem, base].filter((name) => directives[name]);
    for (const name of names) {
      const entry = directives[name];
      if (!entry || !entry.tokens.includes("'unsafe-inline'")) continue;
      const hasHash = entry.tokens.some((token) => /^'(sha256|sha384|sha512)-/.test(token));
      const isStyle = name.startsWith('style');
      if (isStyle) {
        if (options.detectedStyleAttr) {
          warnings.push({ directive: name, token: "'unsafe-inline'", reason: '页面使用 style 属性时无法用 hash 放行，保留不安全内联（建议改用 class/nonce）' });
        } else {
          removeToken(name, "'unsafe-inline'", '未检测到内联样式，移除不安全内联');
        }
      } else if (hasHash) {
        removeToken(name, "'unsafe-inline'", '内联脚本已用 hash 精确放行');
      } else if (options.detectedInlineAttr) {
        warnings.push({ directive: name, token: "'unsafe-inline'", reason: '检测到内联事件处理器（onclick 等），需先重构后才能移除' });
      } else {
        removeToken(name, "'unsafe-inline'", '未检测到内联脚本');
      }
    }
  }

  // 3) data:/blob: 只保留在真正需要的指令（img/font/script/style），从 default-src 移除
  for (const token of ['data:', 'blob:']) {
    const entry = directives['default-src'];
    if (!entry || !entry.tokens.includes(token)) continue;
    const needed = ['img-src', 'font-src', 'script-src-elem', 'style-src-elem', 'worker-src'].some((name) => directives[name] && directives[name].tokens.includes(token));
    if (!needed) removeToken('default-src', token, '无指令使用该 scheme');
  }

  // 4) object-src 强制 'none'
  if (directives['object-src']) {
    directives['object-src'].tokens = ["'none'"];
  } else {
    directives['object-src'] = { tokens: ["'none'"] };
    changes.push({ directive: 'object-src', action: 'add', token: "'none'", reason: '默认禁止插件资源' });
  }

  // 5) base-uri 收紧为 'none' 或 'self'
  if (!directives['base-uri']) {
    directives['base-uri'] = { tokens: ["'none'"] };
    changes.push({ directive: 'base-uri', action: 'add', token: "'none'", reason: '未使用 <base>，固定为 none' });
  }

  // 清理空指令，重新排序
  for (const name of Object.keys(directives)) {
    if (!directives[name].tokens.length) delete directives[name];
  }
  for (const name of Object.keys(directives)) {
    directives[name].tokens = sortTokens(directives[name].tokens);
  }
  const policy = buildPolicy(directives);
  return { policy, directives, changes, warnings };
}

// 策略健全性检查（重复/矛盾/无效指令等）
export function lintPolicy(policyText) {
  const findings = [];
  const directives = parsePolicy(policyText);
  for (const [name, entry] of Object.entries(directives)) {
    if (!DIRECTIVE_ORDER.includes(name) && name !== 'frame-ancestors' && name !== 'report-uri' && !name.startsWith('report-')) {
      findings.push({ level: 'warn', directive: name, message: '非标准或已废弃指令' });
    }
    if (entry.tokens.includes("'none'") && entry.tokens.length > 1) {
      findings.push({ level: 'error', directive: name, message: "'none' 与其他来源同时存在，整条指令会被忽略" });
    }
    const dupes = entry.tokens.filter((token, index) => entry.tokens.indexOf(token) !== index);
    if (dupes.length) findings.push({ level: 'warn', directive: name, message: `重复来源：${[...new Set(dupes)].join(' ')}` });
  }
  if (directives['script-src'] && directives['script-src-elem']) {
    findings.push({ level: 'info', directive: 'script-src', message: '同时存在 script-src 与 script-src-elem，后者对 <script> 优先生效' });
  }
  return findings;
}

// 组装可导出报告
export function buildReport({ resources, stage, selfOrigin, policy, mode = 'report', violations = [], timing = {}, collectedAt = new Date().toISOString() }) {
  return {
    tool: 'csp-auto-gen',
    version: VERSION,
    mode,
    stage,
    collectedAt,
    selfOrigin,
    summary: {
      resources: resources.length,
      directives: Object.keys(parsePolicy(policy)).length,
      violations: violations.length
    },
    timing,
    policy,
    violations,
    resources: resources.map(({ url, type, inline, hash, eval: isEval }) => ({ url, type, inline, hash, eval: isEval }))
  };
}
