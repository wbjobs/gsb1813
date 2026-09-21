// 模拟不在白名单的源（evil origin: 8127）。收紧强制后该脚本必须无法执行。
(function () {
  window.__evilLoaded = true;
  document.body.setAttribute('data-evil', 'PWNED');
  console.error('[evil] script executed — CSP failed to block it');
})();
