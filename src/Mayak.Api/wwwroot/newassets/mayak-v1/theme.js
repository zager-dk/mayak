(() => {
  const root = document.documentElement;
  const key = 'mayak.ui.theme';
  const readTheme = () => {
    try { const value = localStorage.getItem(key); return value === 'day' || value === 'night' ? value : 'night'; }
    catch { return 'night'; }
  };
  const applyTheme = (theme, save = false) => {
    const value = theme === 'day' ? 'day' : 'night';
    root.setAttribute('data-theme', value);
    document.querySelectorAll('[data-theme-toggle]').forEach(button => {
      button.textContent = value === 'night' ? 'День' : 'Ночь';
      button.setAttribute('aria-label', value === 'night' ? 'Тема: ночь. Переключить на день' : 'Тема: день. Переключить на ночь');
      button.setAttribute('aria-pressed', value === 'day' ? 'true' : 'false');
    });
    if (save) { try { localStorage.setItem(key, value); } catch {} }
  };
  applyTheme(readTheme());
  document.addEventListener('click', event => {
    const button = event.target.closest('[data-theme-toggle]');
    if (button) applyTheme(root.getAttribute('data-theme') === 'night' ? 'day' : 'night', true);
  });
})();
