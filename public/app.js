// app.js —— 演示控制台：收集 -> 生成报告策略 -> dry-run -> 收紧 -> 强制 -> 导出
import { CspCollector } from '../src/csp-collector.js';
import { PERF_BUDGET } from '../src/csp-core.js';

const $ = (selector) => document.querySelector(selector);
const state = { stage: 'collect', reportPolicy: '', enforcedPolicy: '' };

const collector = new CspCollector({
  workerUrl: new URL('../src/csp-worker.js', location.href),
  flushIntervalMs: 800,
  onUpdate: (result) => {
    state.reportPolicy = result.policy;
    renderPolicy('reportPolicy', result.policy);
    renderDirectives(result.directives);
    renderIgnored(result.ignored);
    renderFlags(result.flags);
    renderViolations(result.violations, 'dryrun');
    setStage('report');
    syncServerMode('report', result.policy);
  },
  onViolation: (record) => {
    renderLiveViolation(record);
  },
  onNotice: (notice) => toast(notice.message, notice.level),
  onMetrics: (metrics) => renderMetrics(metrics)
});

window.__collector = collector;

function setStage(stage) {
  state.stage = stage;
  const index = { collect: 0, report: 1, tighten: 2, enforce: 3 }[stage];
  document.querySelectorAll('.stage-dot').forEach((dot, i) => {
    dot.classList.toggle('active', i <= index);
  });
}

function renderPolicy(targetId, policy) {
  const element = document.getElementById(targetId);
  element.textContent = policy || '（尚未生成）';
}

function renderDirectives(directives) {
  const tbody = $('#directivesTable tbody');
  tbody.innerHTML = '';
  for (const [name, entry] of Object.entries(directives)) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td class="dir-name">${name}</td><td>${entry.tokens.map(escapeHtml).join('<br>')}</td>`;
    tbody.appendChild(tr);
  }
}

function renderIgnored(ignored) {
  const box = $('#ignoredBox');
  if (!ignored || !ignored.length) { box.textContent = '无'; box.className = 'muted'; return; }
  box.className = '';
  box.innerHTML = ignored.slice(0, 20).map((item) => `<div>⚠️ 忽略 <code>${escapeHtml(item.url || '')}</code>：${item.reason}</div>`).join('');
}

function renderFlags(flags) {
  const messages = [];
  if (flags.evalUsed) messages.push('检测到 eval/Function 动态执行（收紧时将保留或告警）');
  if (flags.inlineScriptAttr) messages.push('检测到内联事件处理器（onclick 等），无法用 hash 放行');
  if (flags.inlineStyleCount) messages.push(`内联样式块 ${flags.inlineStyleCount} 段（hash 放行）`);
  if (flags.inlineScriptCount) messages.push(`内联脚本 ${flags.inlineScriptCount} 段（hash 放行）`);
  $('#flagsBox').innerHTML = messages.length ? messages.map((m) => `<div>• ${m}</div>`).join('') : '<div class="muted">未发现内联/eval 风险</div>';
}

function renderViolations(violations, source) {
  const tbody = $('#violationsTable tbody');
  if (source === 'dryrun') tbody.innerHTML = '';
  if (!violations || !violations.length) {
    if (source === 'dryrun') tbody.innerHTML = '<tr><td colspan="4" class="muted">dry-run 无违规：该策略不会破坏已收集的资源</td></tr>';
    return;
  }
  for (const violation of violations) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${source}</td><td>${violation.directive || ''}</td><td>${escapeHtml(violation.blocked || '')}</td><td>${escapeHtml(violation.reason || '')}</td>`;
    tbody.appendChild(tr);
  }
}

function renderLiveViolation(record) {
  const tr = document.createElement('tr');
  tr.innerHTML = `<td>浏览器实际上报</td><td>${escapeHtml(record.directive || '')}</td><td>${escapeHtml(record.blockedURI || '')}</td><td>${escapeHtml(record.sourceFile || '')}:${record.lineNumber || 0}</td>`;
  $('#violationsTable tbody').prepend(tr);
  toast(`CSP 阻止：${record.blockedURI || record.directive}`, 'error');
}

function renderMetrics(metrics) {
  const over = metrics.lastBuildMs > PERF_BUDGET.batchBuildMs;
  $('#metricBuild').textContent = `${metrics.lastBuildMs || 0} ms`;
  $('#metricBuild').classList.toggle('bad', over);
  $('#metricEvents').textContent = metrics.resourceEvents;
  $('#metricTotal').textContent = metrics.resourceTotal;
  $('#metricBatches').textContent = metrics.batchCount;
  $('#metricWorkerErrors').textContent = metrics.workerErrors;
}

function escapeHtml(value) {
  return String(value == null ? '' : value).replace(/[&<>"']/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
}

let toastTimer;
function toast(message, level = 'info') {
  const box = $('#toast');
  const item = document.createElement('div');
  item.className = `toast toast-${level}`;
  item.textContent = message;
  box.appendChild(item);
  setTimeout(() => { item.classList.add('fade'); setTimeout(() => item.remove(), 400); }, 4000);
}

let syncTimer;
function syncServerMode(modeName, policy) {
  clearTimeout(syncTimer);
  syncTimer = setTimeout(async () => {
    try {
      await fetch('/api/mode', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: modeName, policy: policy || state.reportPolicy })
      });
    } catch (error) {
      toast(`同步服务端 CSP 模式失败：${error.message}`, 'warning');
    }
  }, 300);
}

async function download(filename, content, type = 'application/json') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

// -------- 按钮 --------
$('#btnStart').addEventListener('click', () => { collector.start(); });
$('#btnRegen').addEventListener('click', async () => {
  collector.setStage('report');
  const result = await collector.flush(true);
  if (result) toast('已重新生成报告策略（dry-run 同步完成）', 'info');
});

$('#btnTighten').addEventListener('click', async () => {
  try {
    const result = await collector.tighten(state.reportPolicy);
    state.enforcedPolicy = result.policy;
    renderPolicy('tightPolicy', result.policy);
    renderTightenDiff(result);
    renderViolations(result.violations, 'tighten-dryrun');
    const errors = result.lint.filter((item) => item.level === 'error');
    if (errors.length) toast(`收紧后策略存在 ${errors.length} 个错误，请先修正`, 'error');
    else if (result.violations.length) toast(`收紧策略 dry-run 发现 ${result.violations.length} 个违规（可能破坏页面）`, 'warning');
    else toast('收紧完成，dry-run 无违规', 'info');
    setStage('tighten');
  } catch (error) {
    toast(`收紧失败：${error.message}`, 'error');
  }
});

function renderTightenDiff(result) {
  const tbody = $('#diffTable tbody');
  tbody.innerHTML = '';
  for (const change of result.changes) {
    const tr = document.createElement('tr');
    tr.innerHTML = `<td>${change.directive}</td><td class="change-${change.action}">${change.action}</td><td>${escapeHtml(change.token)}</td><td>${escapeHtml(change.reason)}</td>`;
    tbody.appendChild(tr);
  }
  const box = $('#tightenWarnings');
  box.innerHTML = result.warnings.length
    ? result.warnings.map((w) => `<div>⚠️ ${w.directive}：${escapeHtml(w.reason)}</div>`).join('')
    : '<div class="muted">无风险项</div>';
}

$('#btnEnforceMeta').addEventListener('click', () => {
  if (!state.enforcedPolicy) { toast('请先生成并收紧策略', 'warning'); return; }
  // 注入 meta 即时生效：只影响之后新加载的资源（演示无需刷新）
  const existing = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (existing) existing.remove();
  const meta = document.createElement('meta');
  meta.httpEquiv = 'Content-Security-Policy';
  meta.content = state.enforcedPolicy;
  document.head.appendChild(meta);
  toast('已通过 <meta> 收紧并强制生效（对后续新资源立即生效）', 'info');
  setStage('enforce');
});

$('#btnEnforceHeader').addEventListener('click', async () => {
  if (!state.enforcedPolicy) { toast('请先生成并收紧策略', 'warning'); return; }
  try {
    const response = await fetch('/api/mode', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: 'enforce', policy: state.enforcedPolicy })
    });
    if (!response.ok) throw new Error('HTTP ' + response.status);
    toast('服务端已切换为强制头，2 秒后刷新页面以验证…', 'info');
    setTimeout(() => location.reload(), 2000);
  } catch (error) {
    toast(`切换服务端模式失败：${error.message}`, 'error');
  }
});

$('#btnReportOnly').addEventListener('click', async () => {
  try {
    await fetch('/api/mode', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'report' }) });
    toast('已切回 Report-Only 模式', 'info');
  } catch (error) { toast(`切换失败：${error.message}`, 'error'); }
});

$('#btnExportReport').addEventListener('click', async () => {
  const report = {
    tool: 'csp-auto-gen', version: '1.0.0', exportedAt: new Date().toISOString(),
    stage: state.stage,
    selfOrigin: location.origin,
    reportPolicy: state.reportPolicy,
    enforcedPolicy: state.enforcedPolicy,
    metrics: collector.metrics,
    resources: collector.snapshot(),
    violations: collector.violations
  };
  await download(`csp-report-${Date.now()}.json`, JSON.stringify(report, null, 2));
  toast('报告已导出为 JSON', 'info');
});

$('#btnExportCsp').addEventListener('click', () => {
  if (!state.enforcedPolicy) { toast('尚未收紧，无强制策略可导出', 'warning'); return; }
  download(`csp-policy-${Date.now()}.txt`, 'Content-Security-Policy: ' + state.enforcedPolicy + '\n', 'text/plain');
});

$('#btnEvalProbe').addEventListener('click', () => {
  try {
    // 故意触发 eval，供收集器记录动态执行需求
    window.__collector.markEval('eval-probe-button');
    // eslint-disable-next-line no-eval
    (0, eval)('1+1');
    toast('已触发一次 eval（刷新后在 Report-Only 下会产生违规记录）', 'info');
  } catch (error) {
    toast(`eval 已被当前 CSP 阻止：${error.message}`, 'warning');
  }
});

$('#btnBlockProbe').addEventListener('click', async () => {
  // 尝试加载一个不在白名单的源：收紧强制后应被阻止并产生 securitypolicyviolation
  const script = document.createElement('script');
  script.src = `http://127.0.0.1:${window.__EVIL_PORT__ || 8127}/evil.js?t=${Date.now()}`;
  script.onerror = () => toast('恶意脚本加载失败（可能已被 CSP 阻止，见违规表）', 'warning');
  document.head.appendChild(script);
});

$('#btnStress').addEventListener('click', async () => {
  const start = performance.now();
  const synthetic = [];
  for (let i = 0; i < PERF_BUDGET.stressResources; i++) {
    synthetic.push({ url: `https://cdn${i % 20}.example.net/assets/file${i}.js`, type: i % 3 === 0 ? 'script' : i % 3 === 1 ? 'img' : 'connect' });
  }
  const result = await collector.request('build', { resources: synthetic, options: collector._context() });
  const elapsed = performance.now() - start;
  toast(`压测 ${PERF_BUDGET.stressResources} 条资源：Worker 构建 ${result.timing.batchBuildMs}ms，端到端 ${elapsed.toFixed(0)}ms（阈值 ${PERF_BUDGET.stressBuildMs}ms）`, result.timing.batchBuildMs > PERF_BUDGET.stressBuildMs ? 'warning' : 'info');
});

// 实时接收服务端转发的违规上报（Report-Only 头模式）
if (window.EventSource) {
  const events = new EventSource('/api/events');
  events.onmessage = (event) => {
    try {
      const reports = JSON.parse(event.data);
      for (const report of reports) {
        const body = report.body || {};
        renderLiveViolation({
          directive: body['effective-directive'] || body['violated-directive'],
          blockedURI: body['blocked-uri'], sourceFile: (body['source-file'] || ''),
          lineNumber: body['line-number'], policy: '', at: report.at
        });
      }
    } catch (_) {}
  };
  events.onerror = () => { /* SSE 断开静默，演示用 */ };
}

setStage('collect');
toast('控制台就绪：点击「开始收集」', 'info');
