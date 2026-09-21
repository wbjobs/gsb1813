// 模拟第三方分析脚本（来自“CDN 源”）
(function () {
  window.__thirdPartyLoaded = true;
  console.info('[third-party] analytics script loaded from CDN origin');
  fetch('/api/time').catch(function () {});
})();
