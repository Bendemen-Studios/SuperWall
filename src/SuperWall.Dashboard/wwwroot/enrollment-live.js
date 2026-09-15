// Live enrollment-key list refresh without full-page reload.
// Uses the dashboard's existing loadKeys() AJAX function.
(() => {
  const REFRESH_MS = 5000;
  let timer = null;

  const refreshEnrollmentKeys = async () => {
    if (!window.currentAdmin && typeof currentAdmin !== 'undefined' && !currentAdmin) return;
    const page = document.getElementById('p-enrollment');
    if (!page || !page.classList.contains('active')) return;
    if (typeof loadKeys === 'function') {
      try { await loadKeys(); } catch { /* next interval retries */ }
    }
  };

  const start = () => {
    if (timer) clearInterval(timer);
    timer = setInterval(refreshEnrollmentKeys, REFRESH_MS);
  };

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) refreshEnrollmentKeys();
  });

  start();
})();
