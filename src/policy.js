/**
 * policy.js — CSP 解析 / 序列化 / 资源分类 / 策略校验（纯逻辑，可在主线程、Worker、Node 中运行）
 */

export const RESOURCE_DIRECTIVES = [
  'script-src', 'style-src', 'img-src', 'font-src', 'connect-src',
  'media-src', 'frame-src', 'worker-src', 'manifest-src', 'object-src',
];

const FONT_EXT = /\.(woff2?|ttf|otf|eot)(\?|#|$)/i;
const MEDIA_EXT = /\.(mp4|webm|ogg|mp3|wav|flac|m4a|mov)(\?|#|$)/i;
const IMG_EXT = /\.(png|jpe?g|gif|webp|avif|svg|ico|bmp)(\?|#|$)/i;

/** 将 PerformanceResourceTiming 条目映射到 CSP 指令 */
export function directiveForEntry(entry) {
  const type = (entry.initiatorType || '').toLowerCase();
  const name = entry.name || '';
  switch (type) {
    case 'script': return 'script-src';
    case 'link':
    case 'css': return FONT_EXT.test(name) ? 'font-src' : 'style-src';
    case 'img': return 'img-src';
    case 'fetch':
    case 'xmlhttprequest':
    case 'beacon':
    case 'ping': return 'connect-src';
    case 'video':
    case 'audio': return 'media-src';
    case 'iframe':
    case 'frame': return 'frame-src';
    case 'worker':
    case 'sharedworker':
    case 'serviceworker': return 'worker-src';
    case 'manifest': return 'manifest-src';
    case 'embed':
    case 'object': return 'object-src';
    case 'other':
    default:
      if (FONT_EXT.test(name)) return 'font-src';
      if (MEDIA_EXT.test(name)) return 'media-src';
      if (IMG_EXT.test(name)) return 'img-src';
      return 'connect-src';
  }
}

/** 从 URL 提取 CSP 源表达式（origin 或 scheme） */
export function sourceForUrl(url, selfOrigin) {
  if (!url) return null;
  if (url.startsWith('data:')) return 'data:';
  if (url.startsWith('blob:')) return 'blob:';
  if (url.startsWith('mediastream:')) return 'mediastream:';
  if (url.startsWith('filesystem:')) return 'filesystem:';
  try {
    const u = new URL(url, selfOrigin);
    if (selfOrigin && u.origin === selfOrigin) return "'self'";
    if (u.protocol === 'http:' || u.protocol === 'https:') return u.origin;
    return u.host ? `${u.protocol}//${u.host}` : u.protocol;
  } catch {
    return null;
  }
}

/** 解析 CSP 字符串为 Map<directive, sources[]> */
export function parsePolicy(csp) {
  const map = new Map();
  if (!csp || typeof csp !== 'string') return map;
  for (const part of csp.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    if (!tokens.length) continue;
    map.set(tokens[0].toLowerCase(), tokens.slice(1));
  }
  return map;
}

/** 将 Map<directive, sources[]> 序列化为 CSP 字符串（指令名排序，源去重） */
export function serializePolicy(map) {
  return [...map.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([dir, sources]) => [dir, ...new Set(sources)].join(' '))
    .join('; ');
}

/** 源表达式是否匹配给定 URL（支持 'self'、scheme、精确 origin、*. 通配） */
export function sourceMatchesUrl(source, url, selfOrigin) {
  if (source === "'none'") return false;
  if (source === '*') return true;
  if (source === "'unsafe-inline'" || source === "'unsafe-eval'" || source === "'strict-dynamic'") return false;
  if (source.startsWith("'") && source.endsWith("'")) {
    if (source === "'self'") {
      try { return new URL(url, selfOrigin).origin === selfOrigin; } catch { return false; }
    }
    return false; // nonce/hash 与 URL 无关
  }
  if (source.endsWith(':')) return url.startsWith(source); // data: blob: https: 等
  try {
    const u = new URL(url, selfOrigin);
    if (source.startsWith('*.')) {
      const host = source.slice(2);
      return u.hostname === host || u.hostname.endsWith('.' + host);
    }
    const s = new URL(source, selfOrigin);
    return u.origin === s.origin;
  } catch {
    return false;
  }
}

/**
 * 校验策略是否允许所有已观察资源 —— “生成的 CSP 不破坏页面”的机器保证。
 * 返回违规列表：[{ url, directive }]
 */
export function verifyPolicy(csp, entries, selfOrigin) {
  const policy = parsePolicy(csp);
  const violations = [];
  for (const entry of entries) {
    const directive = directiveForEntry(entry);
    const sources = policy.get(directive) || policy.get('default-src') || [];
    const allowed = sources.some((s) => sourceMatchesUrl(s, entry.name, selfOrigin));
    if (!allowed) violations.push({ url: entry.name, directive });
  }
  return violations;
}
