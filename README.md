# CSP Auto-Gen · 根据页面资源自动生成 CSP

基于 **PerformanceObserver + CSP + Web Worker** 的内容安全策略自动生成工具，覆盖
「资源收集 → 策略生成 → Report-Only 报告 → dry-run 校验 → 收紧 → 强制」完整闭环。

## 快速开始

```bash
npm start          # 启动演示服务器（无需安装依赖）
# 打开 http://127.0.0.1:8124
npm test           # 运行全部测试（核心 / Worker / 服务器，共 30+ 断言）
```

演示服务器在本机模拟四个源：

| 端口 | 角色 | 说明 |
| --- | --- | --- |
| 8124 | 主源 | 控制台、API、CSP 头下发、违规上报接收 |
| 8125 | CDN 源 | 第三方脚本 / 样式 / 图片 / iframe（允许来源） |
| 8126 | 字体源 | `@import` 的字体样式与 woff2 |
| 8127 | 恶意源 | `evil.js`，收紧强制后必须被阻止 |

## 使用流程（对应页面四个阶段）

1. **开始收集**：PerformanceObserver 抓取网络资源，DOM 扫描补全元素属性，
   MutationObserver 追踪动态节点，fetch/XHR/WebSocket hook 捕获 API 调用；
   内联 `<script>/<style>` 计算 `sha256`，内联事件处理器与 `style` 属性单独标记。
2. **生成报告策略**：资源按 CSP 指令归桶（IP 保留精确 host:port，多级域名折叠为
   `*.example.com`），经 Web Worker 构建策略；报告阶段自动保留 `'unsafe-inline'` /
   `'unsafe-eval'` 与并集 `default-src` 兜底，**保证不破坏页面**。策略自动同步到服务端，
   以 `Content-Security-Policy-Report-Only` 头下发，浏览器真实违规会回传并实时显示。
3. **收紧**：一键把宽松策略收紧——通配子域在无精确域时保留并告警（绝不盲目删除）、
   内联脚本改用 hash 精确放行后移除 `'unsafe-inline'`、`object-src 'none'`、
   `base-uri 'none'`、清理多余 `data:`/`blob:`；收紧后立即 dry-run 回放所有已收集资源，
   有违规或 lint 错误会明确提示。
4. **强制生效**：可选择 `<meta>` 即时强制（只影响后续新资源）或服务端响应头强制
   （刷新整页验证）。点击「加载未授权源脚本」探针，可观察 8127 的 `evil.js` 被拦截并产生
   `securitypolicyviolation` 上报。

## 验收标准对照

- **生成的 CSP 不破坏页面**：报告策略宽松兜底；收紧策略用 `evaluatePolicy` 对全部已收集资源
  dry-run，要求零违规才允许进入强制（核心测试固化此保证）。
- **报告可导出**：控制台「导出报告 JSON」（资源、策略、违规、性能、时间戳）、
  「导出 CSP 头 .txt」；服务端违规记录可经 `GET /api/reports` 获取。
- **收紧正确**：通配域/内联/eval/object/base-uri 规则均有单测；无法安全移除的项只告警不删除。
- **性能可接受**：策略构建在 Worker 线程执行；面板展示批量构建耗时；2000 资源压测
  阈值 500ms（实测约几十 ms），普通批量阈值 50ms；超时会提示。
- **异常有提示**：Worker 加载失败/超时、PerformanceObserver 不可用降级、非法模式、
  lint 错误、浏览器真实拦截事件，统一走右上角 toast + 违规表。

## 目录结构

```
src/csp-core.js       纯函数核心：URL 归并、指令构建、dry-run 评估、收紧、lint、报告组装
src/csp-worker.js     Web Worker：批量 build/tighten/evaluate/report
src/csp-collector.js  主线程收集器：PerformanceObserver/DOM/MutationObserver/hooks + 内联hash
public/app.js         演示控制台逻辑（阶段流转、导出、探针、性能面板）
public/index.html     控制台页面
server.js             零依赖演示服务器（多源模拟 / CSP 模式切换 / 违规收集 / SSE）
test/                 核心、Worker（含真实 worker_threads 往返）、服务器处理器测试
```

## 在自己的页面中接入

```js
import { CspCollector } from './src/csp-collector.js';

const collector = new CspCollector({
  workerUrl: new URL('./src/csp-worker.js', location.href),
  onUpdate({ policy, violations }) { /* 上报或展示策略 */ },
  onViolation(record) { /* 浏览器真实违规 */ },
  onNotice(notice) { /* 异常/降级提示 */ },
  onMetrics(metrics) { /* 性能指标 */ }
}).start();

const result = await collector.flush(true);   // 生成报告策略
const tight = await collector.tighten();      // 收紧（含 dry-run）
if (tight.violations.length === 0) {
  // 发布 tight.policy 到网关响应头 Content-Security-Policy
}
```

## 设计说明与限制

- `frame-ancestors`、`report-uri` 等无法从页面资源推断的指令不自动生成，避免误伤。
- 内联事件处理器（`onclick`）与元素 `style` 属性无法用 hash 放行，收紧时保留
  `'unsafe-inline'` 并告警，正确做法是重构为 `addEventListener` / class 或迁移 nonce。
- 生产环境建议把 `report-uri`/`Report-To` 指向真实收集端，并保留一段 Report-Only 观察期。
