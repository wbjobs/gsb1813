// 模拟页面运行 1.5s 后动态插入的追踪脚本
(function () {
  window.__lateTrackLoaded = true;
  console.info('[third-party] late tracker loaded');
})();
