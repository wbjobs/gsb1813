# CSP AutoGen — 页面资源自动生成 CSP

基于 **PerformanceObserver + CSP + Web Worker** 的 CSP 自动化工具链：
收集页面真实加载的资源 → 在 Worker 中生成策略 → 违规报告与导出 → 安全收紧。

## 架构

```
┌─ 主线程 ─────────────────────────────┐   ┌─ Web Worker ──────────┐
│ collector.js  PerformanceObserver    │   │ worker.js             │
│   收集 resource timing + 内联检测     │──▶│  generate / tighten   │
│ reporter.js   securitypolicyviolation │◀──│  verify（纯计算）      │
│ index.js      CSPManager 编排         │   └───────────────────────┘
└──────────────────────────────────────┘
        │ POST /api/csp-report
        ▼
  server.js  报告接收 / 导出 / 策略下发（report-only | enforce）
```

- `src/policy.js` — CSP 解析/序列化、资源→指令映射、源匹配、策略校验（纯逻辑，三端通用）
- `src/generator.js` — 由资源条目生成 CSP，**自检保证不破坏已观察资源**
- `src/tightener.js` — 移除未用源/指令、消除多余 `unsafe-inline`、通配符收紧，防御性补回防破坏
- `src/collector.js` — PerformanceObserver 资源收集（去重、上限、批量 flush、内联监测）
- `src/reporter.js` — 违规批量上报（失败保留重发）、JSON/CSV 导出、环形缓冲
- `src/worker.js` — 生成/收紧/校验移出主线程；Worker 不可用时自动回退主线程
- `server.js` — 零依赖演示服务器（报告端点、报告导出、CSP 头灰度/强制下发）

## 使用

```js
import { CSPManager } from './src/index.js';

const cspm = new CSPManager({ reportEndpoint: '/api/csp-report' });
cspm.start();                                   // 开始收集 + 监听违规

const { csp, safe } = await cspm.generate();    // Worker 中生成（safe=true 即不破坏页面）
cspm.applyReportOnly(csp);                      // Report-Only 灰度

const t = await cspm.tighten(csp);              // 收紧（输出移除项与说明）
cspm.reporter.export('json');                   // 导出报告（支持 'csv'）
```

## 运行

```bash
npm test          # 单元测试（策略/生成/收紧/服务器，含性能用例）
npm start         # 演示服务器 http://localhost:8080/
```

演示页按钮：生成 CSP → Report-Only 灰度 → 收紧 → 导出报告。
服务端导出：`GET /api/reports`（JSON）或 `GET /api/reports?format=csv`。

## 验收标准对照

| 标准 | 实现 |
| --- | --- |
| 生成的 CSP 不破坏页面 | 生成/收紧后自动 `verifyPolicy` 自检，`safe` 标志 + 违规明细；测试覆盖 |
| 报告可导出 | 客户端 `reporter.export('json'/'csv')`；服务端 `/api/reports?format=csv` |
| 收紧正确 | 移除未用源/空指令、消除多余 `unsafe-inline`、通配符→实际源，且防御性补回已观察源 |
| 性能可接受 | 计算在 Worker 中执行并回报耗时；收集器去重+上限+批量 flush；测试：1 万条资源生成 < 500ms |
| 异常有提示 | PerformanceObserver/Worker 不可用时 `console.warn` 降级；上报失败保留队列重发；未知任务类型返回错误 |
