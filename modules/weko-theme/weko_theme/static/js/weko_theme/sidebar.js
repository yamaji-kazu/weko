document.addEventListener('DOMContentLoaded', function() {
  const btn = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('search_sidebar_container');
  const main = document.getElementById('item-main');

  // サイドバーが存在しないページでは何もしない
  if (!btn || !sidebar || !main) return;

  // sessionStorage のキー
  const STORAGE_KEY = 'weko.sidebar.collapsed';


  // Bootstrapのcol-*クラス抽出ヘルパ
  const isColClass = c => /^col-(xs|sm|md|lg|xl)-\d+$/.test(c);
  const getColClasses = el => Array.from(el.classList).filter(isColClass);

  // 初期クラスを保存（展開時に復元するため）
  const initialSidebarCols = getColClasses(sidebar);
  const initialMainCols    = getColClasses(main);

  const label = btn.dataset.label;

  function updateButtonText(expanded) {
    const isMobile = window.innerWidth < 768;
    if (isMobile) {
      // btn.querySelector('span').textContent = label;
      btn.querySelector('span').textContent = expanded ? label : '';
    } else {
      btn.querySelector('span').textContent = expanded ? label : '';
    }
  }

  function applyCollapsed() {
    // Bootstrapのcol-*を外す（inlineで幅を制御するため）
    initialSidebarCols.forEach(c => sidebar.classList.remove(c));
    initialMainCols.forEach(c => main.classList.remove(c));
    // 折りたたみ用クラス適用
    sidebar.classList.add('sidebar-collapsed');
    main.classList.add('main-collapsed');
    main.classList.remove('main-expanded');

    // アクセシビリティ＆ボタン表示
    btn.setAttribute('aria-expanded', 'false');
    updateButtonText(false);
  }

  function applyExpanded() {
    // 折りたたみ用クラスを外す
    sidebar.classList.remove('sidebar-collapsed');
    main.classList.remove('main-collapsed');
    main.classList.add('main-expanded');

    // 初期のBootstrap col-*を復元
    initialSidebarCols.forEach(c => sidebar.classList.add(c));
    initialMainCols.forEach(c => main.classList.add(c));

    // アクセシビリティ＆ボタン表示
    btn.setAttribute('aria-expanded', 'true');
    updateButtonText(true);
  }

  function toggle() {
    const expanded = btn.getAttribute('aria-expanded') !== 'false';
    if (expanded) {
      applyCollapsed();
      try { localStorage.setItem(STORAGE_KEY, 'true'); } catch (_) {}
    } else {
      applyExpanded();
      try { localStorage.setItem(STORAGE_KEY, 'false'); } catch (_) {}
    }
  }

  // 初期ロード時に localStorage を反映
  let collapsedPref = null;
  try {
    // 値は 'true' or 'false' を期待。未設定なら null。
    const v = localStorage.getItem(STORAGE_KEY);
    collapsedPref = (v === 'true') ? true : (v === 'false') ? false : null;
  } catch (_) {
    // プライベートモード等で例外になる可能性に備えて握りつぶす
    collapsedPref = null;
  }

  if (collapsedPref === true) {
    applyCollapsed();
  } else {
    // 初期状態は展開
    applyExpanded();
  }

  // クリックでトグル
  btn.addEventListener('click', toggle);

  // 画面サイズ変更時にも文言を更新
  window.addEventListener('resize', () => {
    const expanded = btn.getAttribute('aria-expanded') !== 'false';
    updateButtonText(expanded);
  });

  // ---- 幅の変更 (2026-09-17) ----
  // 列の右縁をつまんで横に動かす。決めた幅は --weko-sidebar-width として行に
  // 置き、CSS が Bootstrap の col-* より優先する。ダブルクリックで既定に戻る。
  const resizer = document.getElementById('sidebar-resizer');
  const row = document.getElementById('search_row');
  if (resizer && row) {
    const WIDTH_KEY = 'weko.sidebar.width';
    const MIN = 160;
    const maxWidth = () => Math.max(MIN, Math.floor(row.getBoundingClientRect().width * 0.6));
    const applyWidth = (px) => {
      if (px == null) {
        row.style.removeProperty('--weko-sidebar-width');
        return;
      }
      const w = Math.min(maxWidth(), Math.max(MIN, Math.round(px)));
      row.style.setProperty('--weko-sidebar-width', w + 'px');
    };
    try {
      const saved = parseInt(localStorage.getItem(WIDTH_KEY), 10);
      if (saved > 0) applyWidth(saved);
    } catch (_) {}

    let startX = 0, startW = 0, dragging = false;
    const onMove = (ev) => {
      if (!dragging) return;
      const x = ev.touches ? ev.touches[0].clientX : ev.clientX;
      applyWidth(startW + (x - startX));
      ev.preventDefault();
    };
    const onUp = () => {
      if (!dragging) return;
      dragging = false;
      resizer.classList.remove('is-dragging');
      document.body.classList.remove('sidebar-resizing');
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.removeEventListener('touchmove', onMove);
      document.removeEventListener('touchend', onUp);
      const v = row.style.getPropertyValue('--weko-sidebar-width');
      try {
        if (v) localStorage.setItem(WIDTH_KEY, String(parseInt(v, 10)));
        else localStorage.removeItem(WIDTH_KEY);
      } catch (_) {}
    };
    const onDown = (ev) => {
      if (sidebar.classList.contains('sidebar-collapsed')) return;
      dragging = true;
      startX = ev.touches ? ev.touches[0].clientX : ev.clientX;
      startW = sidebar.getBoundingClientRect().width;
      resizer.classList.add('is-dragging');
      document.body.classList.add('sidebar-resizing');
      document.addEventListener('mousemove', onMove);
      document.addEventListener('mouseup', onUp);
      document.addEventListener('touchmove', onMove, { passive: false });
      document.addEventListener('touchend', onUp);
      ev.preventDefault();
    };
    resizer.addEventListener('mousedown', onDown);
    resizer.addEventListener('touchstart', onDown, { passive: false });
    resizer.addEventListener('dblclick', () => {
      applyWidth(null);
      try { localStorage.removeItem(WIDTH_KEY); } catch (_) {}
    });
  }
});
