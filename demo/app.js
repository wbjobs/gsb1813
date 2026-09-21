import { CSPManager } from '../src/index.js';

const $ = (id) => document.getElementById(id);
const cspm = new CSPManager({ reportEndpoint: '/api/csp-report' });
const started = cspm.start();

function show(msg, data) {
  $('status').textContent = typeof msg === 'string' ? msg : JSON.stringify(msg, null, 2);
  if (data !== undefined) $('policy').textContent = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
}

let currentCsp = null;

$('btn-generate').onclick = async () => {
  try {
    const r = await cspm.generate();
    currentCsp = r.csp;
    show(`生成完成（Worker 耗时 ${r.workerElapsedMs ?? '-'}ms）safe=${r.safe} 违规=${r.violations.length}`, r.csp);
  } catch (err) { show(`生成失败: ${err.message}`); }
};

$('btn-apply').onclick = () => {
  if (!currentCsp) return show('请先生成策略');
  cspm.applyReportOnly(currentCsp);
  show('已以 Report-Only 方式灰度（违规仅上报不阻断）', currentCsp);
};

$('btn-tighten').onclick = async () => {
  if (!currentCsp) return show('请先生成策略');
  try {
    const r = await cspm.tighten(currentCsp);
    currentCsp = r.csp;
    show(`收紧完成 safe=${r.safe}\n移除:\n${r.removed.join('\n') || '(无)'}\n说明:\n${r.notes.join('\n') || '(无)'}`, r.csp);
  } catch (err) { show(`收紧失败: ${err.message}`); }
};

$('btn-export-json').onclick = () => cspm.reporter.export('json');
$('btn-export-csv').onclick = () => cspm.reporter.export('csv');

// 演示：动态加载一个同源脚本资源 + 一次 fetch，让收集器有内容
fetch('/api/csp').catch(() => {});
const s = document.createElement('script');
s.src = './lazy.js';
document.body.appendChild(s);

show(started ? '收集器已启动，正在收集页面资源…' : '警告：PerformanceObserver 不可用');
setInterval(() => {
  const p = cspm.perfStats();
  $('status').textContent += '';
  document.title = `CSP demo (资源:${p.count})`;
}, 3000);
