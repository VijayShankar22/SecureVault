/**
 * ui.js
 * ---------------------------------------------------------------------------
 * SecureVault — shared UI chrome used by every tab: navigation, theming,
 * toast notifications, modal dialogs (confirm/prompt), the icon set, the
 * dashboard/stats/activity feed, settings persistence, and keyboard
 * shortcuts.
 *
 * Nothing in this file touches cryptography. Feature modules (keyManager,
 * file, folder, text) call into the small API this file exposes
 * (SV.UI.toast, SV.UI.confirm, SV.UI.promptText, SV.UI.icon, SV.UI.stat,
 * SV.UI.logActivity, SV.UI.switchTab) instead of building their own
 * notifications/dialogs, so the whole app looks and behaves consistently.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.UI = (function () {
  'use strict';

  const U = SV.Utils;
  const TAB_IDS = ['dashboard', 'files', 'folder', 'text', 'keys', 'settings', 'about'];
  const SETTINGS_KEY = 'securevault:settings:v1';

  // ---- Icon set --------------------------------------------------------
  // Small, original, hand-drawn line icons (24x24, stroke = currentColor).
  // No icon font or library — keeps the app dependency-free and themeable
  // purely through CSS custom properties.

  const ICONS = {
    lock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    unlock: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.2-2.6"/>',
    shield: '<path d="M12 3.2 19 6v5c0 4.5-3 7.4-7 8.8-4-1.4-7-4.3-7-8.8V6l7-2.8z"/><path d="M9 12l2 2 4-4.2"/>',
    download: '<path d="M12 4v11"/><path d="M7.5 11.5 12 16l4.5-4.5"/><path d="M5 19.5h14"/>',
    upload: '<path d="M12 20V9"/><path d="M7.5 12.5 12 8l4.5 4.5"/><path d="M5 19.5h14"/>',
    close: '<path d="M6 6l12 12"/><path d="M18 6 6 18"/>',
    success: '<circle cx="12" cy="12" r="8.3"/><path d="M8.3 12.3l2.4 2.4 4.7-5.3"/>',
    error: '<circle cx="12" cy="12" r="8.3"/><path d="M12 7.6v5.4"/><circle cx="12" cy="16.3" r="0.95" fill="currentColor" stroke="none"/>',
    warning: '<path d="M12 4.3 21 19.7H3L12 4.3z"/><path d="M12 10v4.2"/><circle cx="12" cy="17" r="0.95" fill="currentColor" stroke="none"/>',
    info: '<circle cx="12" cy="12" r="8.3"/><path d="M12 11v5.3"/><circle cx="12" cy="7.8" r="0.95" fill="currentColor" stroke="none"/>',
    key: '<circle cx="8" cy="15" r="3.4"/><path d="M10.4 12.4 19 3.8"/><path d="M15.6 7.8 18 10.2"/><path d="M13.1 6.4 15.1 8.4"/>',
    folder: '<path d="M4 7.2A1.7 1.7 0 0 1 5.7 5.5h3.7l2 2H18.3A1.7 1.7 0 0 1 20 9.2v7.6a1.7 1.7 0 0 1-1.7 1.7H5.7A1.7 1.7 0 0 1 4 16.8V7.2z"/>',
    text: '<path d="M6 4.8h12"/><path d="M12 4.8V19"/><path d="M9 19h6"/>',
    image: '<rect x="4" y="5" width="16" height="14" rx="2"/><circle cx="9.3" cy="10" r="1.5"/><path d="M4.5 16.8 9 12.5l3 3 3.7-4.6L19.5 15"/>',
    video: '<rect x="4" y="6" width="12" height="12" rx="2"/><path d="M16 10.3 20 7.7v8.6l-4-2.6"/>',
    audio: '<path d="M5 15.5V9l6-2.2v10.2"/><circle cx="4" cy="16.3" r="2"/><circle cx="10" cy="15.8" r="2"/>',
    pdf: '<path d="M6 3.5h7.5l4 4V20a.5.5 0 0 1-.5.5H6.5A.5.5 0 0 1 6 20V4a.5.5 0 0 1 .5-.5z"/><path d="M13.5 3.5V8h4"/><path d="M8 16v-3.2h1c.7 0 1.3.5 1.3 1.4S9.7 15.6 9 15.6H8"/><path d="M12 16v-3.2h1.4c1 0 1.6.7 1.6 1.6s-.6 1.6-1.6 1.6H12"/><path d="M16 16v-3.2h1.8M16 14.4h1.4"/>',
    archive: '<rect x="5" y="4.5" width="14" height="15" rx="1.5"/><path d="M9.3 4.5v15"/><path d="M9.3 7.2h3M9.3 10h3M9.3 12.8h3"/>',
    code: '<path d="M9 8 5 12l4 4"/><path d="M15 8l4 4-4 4"/>',
    encrypted: '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/><circle cx="12" cy="15.2" r="1.1" fill="currentColor" stroke="none"/>',
    generic: '<path d="M7 3.5h6.5l3.5 3.5V20a.5.5 0 0 1-.5.5H7A.5.5 0 0 1 6.5 20V4A.5.5 0 0 1 7 3.5z"/><path d="M13.5 3.5V7H17"/>',
    search: '<circle cx="10.3" cy="10.3" r="6"/><path d="M15 15l4.7 4.7"/>',
    refresh: '<path d="M5 12a7 7 0 0 1 12-4.9L19 9"/><path d="M19 5.2V9h-3.8"/><path d="M19 12a7 7 0 0 1-12 4.9L5 15"/><path d="M5 18.8V15h3.8"/>',
    clipboard: '<rect x="6" y="5.5" width="12" height="15" rx="1.5"/><rect x="9" y="3.5" width="6" height="3" rx="1"/>',
    copy: '<rect x="8.5" y="8.5" width="10.5" height="12" rx="1.5"/><path d="M15 8.5V6a1.5 1.5 0 0 0-1.5-1.5H6A1.5 1.5 0 0 0 4.5 6v10A1.5 1.5 0 0 0 6 17.5h2.5"/>',
    'chevron-down': '<path d="M6 9l6 6 6-6"/>',
    sun: '<circle cx="12" cy="12" r="4"/><path d="M12 3v2.2M12 18.8V21M21 12h-2.2M5.2 12H3M18.4 5.6l-1.6 1.6M7.2 16.8l-1.6 1.6M18.4 18.4l-1.6-1.6M7.2 7.2 5.6 5.6"/>',
    moon: '<path d="M20 14.3A8.4 8.4 0 1 1 9.7 4a6.8 6.8 0 0 0 10.3 10.3z"/>',
    monitor: '<rect x="3.5" y="5" width="17" height="11" rx="1.5"/><path d="M8.5 19.5h7M12 16v3.5"/>',
    menu: '<path d="M4 7h16M4 12h16M4 17h16"/>',
    dashboard: '<rect x="4" y="4" width="7" height="7" rx="1.2"/><rect x="13" y="4" width="7" height="4.5" rx="1.2"/><rect x="13" y="10.5" width="7" height="9" rx="1.2"/><rect x="4" y="13" width="7" height="6.5" rx="1.2"/>',
    settings: '<circle cx="12" cy="12" r="2.6"/><path d="M12 4v2.4M12 17.6V20M20 12h-2.4M6.4 12H4M17 7l-1.7 1.7M8.7 15.3 7 17M17 17l-1.7-1.7M8.7 8.7 7 7"/>',
    plus: '<path d="M12 5v14M5 12h14"/>',
    trash: '<path d="M5 7h14"/><path d="M9 7V5.5A1.5 1.5 0 0 1 10.5 4h3A1.5 1.5 0 0 1 15 5.5V7"/><path d="M7 7l1 12.5a1 1 0 0 0 1 .9h6a1 1 0 0 0 1-.9L17 7"/>',
  };

  function icon(name, opts = {}) {
    const inner = ICONS[name] || ICONS.generic;
    const size = opts.size || 20;
    return `<svg viewBox="0 0 24 24" width="${size}" height="${size}" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false">${inner}</svg>`;
  }

  // ---- Toasts ----------------------------------------------------------

  let toastSeq = 0;

  function toast({ type = 'info', message, duration = 4500 }) {
    const container = document.getElementById('toast-container');
    if (!container || !message) return;

    const el = document.createElement('div');
    el.className = `toast toast-${type}`;
    el.id = `toast-${++toastSeq}`;
    el.setAttribute('role', type === 'error' ? 'alert' : 'status');

    const iconWrap = document.createElement('span');
    iconWrap.className = 'toast-icon';
    iconWrap.innerHTML = icon(type === 'success' ? 'success' : type === 'error' ? 'error' : type === 'warning' ? 'warning' : 'info');
    el.appendChild(iconWrap);

    const msg = document.createElement('span');
    msg.className = 'toast-message';
    msg.textContent = message;
    el.appendChild(msg);

    const closeBtn = document.createElement('button');
    closeBtn.type = 'button';
    closeBtn.className = 'toast-close';
    closeBtn.setAttribute('aria-label', 'Dismiss notification');
    closeBtn.innerHTML = icon('close', { size: 14 });
    el.appendChild(closeBtn);

    let timer = null;
    const remove = () => {
      el.classList.remove('toast-visible');
      setTimeout(() => el.remove(), 220);
    };
    const arm = () => {
      timer = setTimeout(remove, duration);
    };
    const disarm = () => clearTimeout(timer);

    closeBtn.addEventListener('click', remove);
    el.addEventListener('mouseenter', disarm);
    el.addEventListener('mouseleave', arm);

    container.appendChild(el);
    requestAnimationFrame(() => el.classList.add('toast-visible'));
    arm();
  }

  // ---- Modals (confirm / promptText) ------------------------------------
  // Built on demand into #modal-root; focus-trapped, Escape-to-close, and
  // restores focus to whatever triggered the modal on close.

  function openModalBase({ title, bodyNode, buttons, escapeValue, initialFocusSelector }) {
    return new Promise((resolve) => {
      const root = document.getElementById('modal-root');
      if (!root) {
        resolve(escapeValue);
        return;
      }
      root.innerHTML = '';

      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay';

      const modal = document.createElement('div');
      modal.className = 'modal';
      modal.setAttribute('role', 'dialog');
      modal.setAttribute('aria-modal', 'true');
      const titleId = 'modal-title-' + U.uuid();
      modal.setAttribute('aria-labelledby', titleId);

      const h = document.createElement('h2');
      h.className = 'modal-title';
      h.id = titleId;
      h.textContent = title;
      modal.appendChild(h);

      if (bodyNode) modal.appendChild(bodyNode);

      const actionsWrap = document.createElement('div');
      actionsWrap.className = 'modal-actions';
      modal.appendChild(actionsWrap);

      const previouslyFocused = document.activeElement;

      function close(result) {
        document.removeEventListener('keydown', onKeydown, true);
        overlay.classList.remove('modal-visible');
        setTimeout(() => {
          root.innerHTML = '';
        }, 160);
        if (previouslyFocused && typeof previouslyFocused.focus === 'function') previouslyFocused.focus();
        resolve(result);
      }

      function onKeydown(e) {
        if (e.key === 'Escape') {
          e.preventDefault();
          close(escapeValue);
          return;
        }
        if (e.key === 'Tab') {
          const focusables = modal.querySelectorAll('button, input, textarea, select, [tabindex]:not([tabindex="-1"])');
          if (focusables.length === 0) return;
          const first = focusables[0];
          const last = focusables[focusables.length - 1];
          if (e.shiftKey && document.activeElement === first) {
            e.preventDefault();
            last.focus();
          } else if (!e.shiftKey && document.activeElement === last) {
            e.preventDefault();
            first.focus();
          }
        }
      }

      buttons.forEach((def) => {
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.className = `btn ${def.cls || 'btn-secondary'}`;
        btn.textContent = def.label;
        btn.addEventListener('click', () => close(def.value));
        actionsWrap.appendChild(btn);
      });

      overlay.appendChild(modal);
      overlay.addEventListener('mousedown', (e) => {
        if (e.target === overlay) close(escapeValue);
      });
      root.appendChild(overlay);
      document.addEventListener('keydown', onKeydown, true);

      requestAnimationFrame(() => {
        overlay.classList.add('modal-visible');
        const target = (initialFocusSelector && modal.querySelector(initialFocusSelector)) || actionsWrap.querySelector('button');
        if (target) target.focus();
      });
    });
  }

  function confirmDialog({ title, message, confirmLabel = 'Confirm', cancelLabel = 'Cancel', danger = false }) {
    const body = document.createElement('p');
    body.className = 'modal-message';
    body.textContent = message;
    return openModalBase({
      title,
      bodyNode: body,
      escapeValue: false,
      buttons: [
        { label: cancelLabel, value: false, cls: 'btn-secondary' },
        { label: confirmLabel, value: true, cls: danger ? 'btn-danger' : 'btn-primary' },
      ],
    });
  }

  function promptText({ title, message, placeholder = '', confirmLabel = 'OK', cancelLabel = 'Cancel', multiline = true }) {
    const wrap = document.createElement('div');
    if (message) {
      const p = document.createElement('p');
      p.className = 'modal-message';
      p.textContent = message;
      wrap.appendChild(p);
    }
    const input = document.createElement(multiline ? 'textarea' : 'input');
    input.className = 'modal-input';
    if (!multiline) input.type = 'text';
    else input.rows = 4;
    input.placeholder = placeholder;
    input.spellcheck = false;
    wrap.appendChild(input);

    const SENTINEL = '__SV_PROMPT_CONFIRM__';
    return openModalBase({
      title,
      bodyNode: wrap,
      escapeValue: null,
      initialFocusSelector: '.modal-input',
      buttons: [
        { label: cancelLabel, value: null, cls: 'btn-secondary' },
        { label: confirmLabel, value: SENTINEL, cls: 'btn-primary' },
      ],
    }).then((result) => (result === SENTINEL ? input.value : null));
  }

  function showShortcutsModal() {
    const dl = document.createElement('dl');
    dl.className = 'shortcuts-list';
    [
      ['Alt + 1 – 7', 'Switch tabs'],
      ['Ctrl / Cmd + G', 'Generate a new key'],
      ['Ctrl / Cmd + O', 'Browse for files'],
      ['Ctrl / Cmd + D', 'Toggle dark / light theme'],
      ['?', 'Show this list'],
      ['Esc', 'Close a dialog'],
    ].forEach(([keys, desc]) => {
      const dt = document.createElement('dt');
      dt.textContent = keys;
      const dd = document.createElement('dd');
      dd.textContent = desc;
      dl.appendChild(dt);
      dl.appendChild(dd);
    });
    openModalBase({ title: 'Keyboard shortcuts', bodyNode: dl, escapeValue: null, buttons: [{ label: 'Close', value: null, cls: 'btn-primary' }] });
  }

  // ---- Tabs --------------------------------------------------------------

  function switchTab(tabId) {
    if (!TAB_IDS.includes(tabId)) return;

    document.querySelectorAll('.nav-tab').forEach((btn) => {
      const active = btn.dataset.tab === tabId;
      btn.classList.toggle('is-active', active);
      btn.setAttribute('aria-selected', active ? 'true' : 'false');
      btn.tabIndex = active ? 0 : -1;
    });

    document.querySelectorAll('[data-tabpanel]').forEach((panel) => {
      panel.hidden = panel.dataset.tabpanel !== tabId;
    });

    const panel = document.querySelector(`[data-tabpanel="${tabId}"]`);
    const heading = panel && panel.querySelector('h1, h2');
    if (heading) {
      heading.setAttribute('tabindex', '-1');
      heading.focus({ preventScroll: false });
    }

    closeMobileDrawer();
    if (history.replaceState) history.replaceState(null, '', `#${tabId}`);
  }

  function initTabs() {
    document.querySelectorAll('.nav-tab').forEach((btn) => {
      btn.addEventListener('click', () => switchTab(btn.dataset.tab));
    });
    document.querySelectorAll('[data-goto-tab]').forEach((el) => {
      el.addEventListener('click', () => switchTab(el.dataset.gotoTab));
    });
    const initial = (location.hash || '').replace('#', '');
    switchTab(TAB_IDS.includes(initial) ? initial : 'dashboard');
  }

  // ---- Theme --------------------------------------------------------------

  function resolveTheme(pref) {
    if (pref !== 'system') return pref;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function applyTheme(pref) {
    const resolved = resolveTheme(pref);
    document.documentElement.setAttribute('data-theme', resolved);
    document.documentElement.setAttribute('data-theme-pref', pref);
    updateThemeButtons();
  }

  function setTheme(pref) {
    SV.state.settings.theme = pref;
    applyTheme(pref);
    saveSettings();
  }

  function toggleThemeQuick() {
    const current = document.documentElement.getAttribute('data-theme') || 'dark';
    setTheme(current === 'dark' ? 'light' : 'dark');
  }

  function updateThemeButtons() {
    ['dark', 'light', 'system'].forEach((t) => {
      const btn = document.getElementById(`theme-btn-${t}`);
      if (btn) {
        const active = SV.state.settings.theme === t;
        btn.classList.toggle('is-active', active);
        btn.setAttribute('aria-pressed', active ? 'true' : 'false');
      }
    });
    const toggleIcon = document.getElementById('btn-theme-toggle-icon');
    if (toggleIcon) {
      const resolved = document.documentElement.getAttribute('data-theme');
      toggleIcon.innerHTML = icon(resolved === 'dark' ? 'moon' : 'sun', { size: 18 });
    }
  }

  function initThemeControls() {
    applyTheme(SV.state.settings.theme);
    const btnToggle = document.getElementById('btn-theme-toggle');
    if (btnToggle) btnToggle.addEventListener('click', toggleThemeQuick);
    ['dark', 'light', 'system'].forEach((t) => {
      const btn = document.getElementById(`theme-btn-${t}`);
      if (btn) btn.addEventListener('click', () => setTheme(t));
    });
    if (window.matchMedia) {
      const mq = window.matchMedia('(prefers-color-scheme: dark)');
      const onChange = () => {
        if (SV.state.settings.theme === 'system') applyTheme('system');
      };
      if (mq.addEventListener) mq.addEventListener('change', onChange);
      else if (mq.addListener) mq.addListener(onChange);
    }
  }

  // ---- Settings persistence (non-sensitive only — never keys) -----------

  function defaultSettings() {
    return {
      theme: 'system',
      autoDownload: false,
      confirmBeforeOverwrite: true,
      showMetadata: true,
      rememberTheme: true,
      highContrast: false,
      chunkSizeMB: 16,
    };
  }

  function loadSettings() {
    const defaults = defaultSettings();
    try {
      const raw = localStorage.getItem(SETTINGS_KEY);
      if (!raw) return defaults;
      return Object.assign({}, defaults, JSON.parse(raw));
    } catch (err) {
      return defaults;
    }
  }

  function saveSettings() {
    try {
      const s = SV.state.settings;
      const toStore = s.rememberTheme ? s : Object.assign({}, s, { theme: defaultSettings().theme });
      localStorage.setItem(SETTINGS_KEY, JSON.stringify(toStore));
    } catch (err) {
      // localStorage unavailable (private browsing, storage disabled, etc.)
      // Settings just won't persist across reloads — never fatal.
    }
  }

  function initSettingsControls() {
    const bindToggle = (id, key, extra) => {
      const el = document.getElementById(id);
      if (!el) return;
      el.checked = !!SV.state.settings[key];
      el.addEventListener('change', () => {
        SV.state.settings[key] = el.checked;
        saveSettings();
        if (extra) extra(el.checked);
      });
    };

    bindToggle('setting-auto-download', 'autoDownload');
    bindToggle('setting-confirm-overwrite', 'confirmBeforeOverwrite');
    bindToggle('setting-show-metadata', 'showMetadata');
    bindToggle('setting-remember-theme', 'rememberTheme');
    bindToggle('setting-high-contrast', 'highContrast', (checked) => {
      document.documentElement.classList.toggle('high-contrast', checked);
    });
    document.documentElement.classList.toggle('high-contrast', !!SV.state.settings.highContrast);

    const chunkSelect = document.getElementById('setting-chunk-size');
    if (chunkSelect) {
      chunkSelect.value = String(SV.state.settings.chunkSizeMB);
      chunkSelect.addEventListener('change', () => {
        SV.state.settings.chunkSizeMB = parseInt(chunkSelect.value, 10) || 16;
        saveSettings();
      });
    }
  }

  // ---- Dashboard: stats + activity feed -----------------------------------

  function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = String(value);
  }

  function stat(name, delta) {
    SV.state.stats[name] = (SV.state.stats[name] || 0) + delta;
    refreshDashboard();
  }

  function logActivity({ type, label, detail }) {
    SV.state.activity.unshift({ id: U.uuid(), type, label, detail, at: U.nowIso() });
    SV.state.activity = SV.state.activity.slice(0, 40);
    refreshDashboard();
  }

  function activityIconFor(type) {
    if (type === 'key') return 'key';
    if (type.indexOf('folder') === 0) return 'folder';
    if (type.indexOf('text') === 0) return 'text';
    if (type.indexOf('encrypt') !== -1) return 'lock';
    if (type.indexOf('decrypt') !== -1) return 'unlock';
    return 'info';
  }

  function renderActivityItem(item) {
    const li = document.createElement('li');
    li.className = 'activity-item';

    const iconWrap = document.createElement('span');
    iconWrap.className = 'activity-icon';
    iconWrap.innerHTML = icon(activityIconFor(item.type), { size: 16 });
    li.appendChild(iconWrap);

    const main = document.createElement('div');
    main.className = 'activity-main';
    const label = document.createElement('div');
    label.className = 'activity-label';
    label.textContent = item.label;
    main.appendChild(label);
    const meta = document.createElement('div');
    meta.className = 'activity-meta';
    meta.textContent = [item.detail, U.formatRelativeTime(item.at)].filter(Boolean).join(' · ');
    main.appendChild(meta);
    li.appendChild(main);

    return li;
  }

  function refreshDashboard() {
    const s = SV.state.stats;
    setText('stat-files-encrypted', s.filesEncrypted || 0);
    setText('stat-files-decrypted', s.filesDecrypted || 0);
    setText('stat-folders-total', (s.foldersEncrypted || 0) + (s.foldersDecrypted || 0));
    setText('stat-bytes-total', U.formatBytes((s.bytesEncrypted || 0) + (s.bytesDecrypted || 0)));

    const keyStatusEl = document.getElementById('stat-key-status');
    if (keyStatusEl) keyStatusEl.textContent = SV.KeyManager && SV.KeyManager.hasKey() ? 'Active' : 'None loaded';

    const list = document.getElementById('activity-list');
    const empty = document.getElementById('activity-empty');
    if (list) {
      list.innerHTML = '';
      const frag = document.createDocumentFragment();
      for (const item of SV.state.activity.slice(0, 8)) frag.appendChild(renderActivityItem(item));
      list.appendChild(frag);
      list.hidden = SV.state.activity.length === 0;
      if (empty) empty.hidden = SV.state.activity.length > 0;
    }
  }

  // ---- FAQ accordion -------------------------------------------------------

  function initFaq() {
    document.querySelectorAll('.faq-question').forEach((btn) => {
      btn.addEventListener('click', () => {
        const expanded = btn.getAttribute('aria-expanded') === 'true';
        btn.setAttribute('aria-expanded', String(!expanded));
        const panel = document.getElementById(btn.getAttribute('aria-controls'));
        if (panel) panel.hidden = expanded;
      });
    });
  }

  // ---- Mobile sidebar drawer ------------------------------------------------

  function openMobileDrawer() {
    document.body.classList.add('sidebar-open');
    const first = document.querySelector('#sidebar-nav .nav-tab.is-active');
    if (first) first.focus();
  }
  function closeMobileDrawer() {
    document.body.classList.remove('sidebar-open');
  }
  function initMobileDrawer() {
    const menuBtn = document.getElementById('btn-menu-toggle');
    const backdrop = document.getElementById('sidebar-backdrop');
    if (menuBtn) menuBtn.addEventListener('click', openMobileDrawer);
    if (backdrop) backdrop.addEventListener('click', closeMobileDrawer);
  }

  // ---- Keyboard shortcuts ---------------------------------------------------

  function isTypingContext() {
    const t = document.activeElement;
    return !!t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
  }

  function initShortcuts() {
    document.addEventListener('keydown', (e) => {
      const mod = e.ctrlKey || e.metaKey;

      if (mod && e.key.toLowerCase() === 'd') {
        e.preventDefault();
        toggleThemeQuick();
        return;
      }
      if (mod && e.key.toLowerCase() === 'g') {
        e.preventDefault();
        if (SV.KeyManager) SV.KeyManager.generateNewKey();
        return;
      }
      if (mod && e.key.toLowerCase() === 'o') {
        e.preventDefault();
        switchTab('files');
        const input = document.getElementById('input-browse-files');
        if (input) input.click();
        return;
      }
      if (!mod && !isTypingContext()) {
        if (e.key === '?') {
          e.preventDefault();
          showShortcutsModal();
          return;
        }
        if (e.altKey) {
          const map = { 1: 'dashboard', 2: 'files', 3: 'folder', 4: 'text', 5: 'keys', 6: 'settings', 7: 'about' };
          if (map[e.key]) {
            e.preventDefault();
            switchTab(map[e.key]);
          }
        }
      }
    });
  }

  // ---- Web Crypto availability gate --------------------------------------

  function checkWebCryptoSupport() {
    const supported = !!(window.crypto && window.crypto.subtle && typeof window.crypto.subtle.encrypt === 'function' && window.crypto.getRandomValues);
    if (supported) return true;

    document.body.innerHTML = '';
    const wrap = document.createElement('div');
    wrap.className = 'fatal-screen';
    const card = document.createElement('div');
    card.className = 'fatal-card';

    const h1 = document.createElement('h1');
    h1.textContent = "Web Crypto API isn't available";
    card.appendChild(h1);

    const paragraphs = [
      "SecureVault needs the browser's built-in Web Crypto API (crypto.subtle), which this page doesn't currently have access to.",
      'This usually happens when a page is opened directly from disk (file://) in a browser that restricts Web Crypto to secure contexts. Everything in SecureVault still runs entirely on your device — nothing needs to leave it — the page just needs to be served rather than double-clicked.',
      'Fix: open a terminal in this folder and run:',
    ];
    paragraphs.forEach((text) => {
      const p = document.createElement('p');
      p.textContent = text;
      card.appendChild(p);
    });

    const pre = document.createElement('pre');
    pre.textContent = 'python3 -m http.server 8000';
    card.appendChild(pre);

    const p2 = document.createElement('p');
    p2.textContent = 'Then open http://localhost:8000 in your browser. Alternatively, try a recent version of Chrome, Firefox, Edge, or Safari — most support opening SecureVault directly from disk.';
    card.appendChild(p2);

    wrap.appendChild(card);
    document.body.appendChild(wrap);
    return false;
  }

  // ---- Init ------------------------------------------------------------

  function init() {
    SV.state.settings = loadSettings();
    if (!checkWebCryptoSupport()) return false;

    initTabs();
    initThemeControls();
    initSettingsControls();
    initFaq();
    initMobileDrawer();
    initShortcuts();
    refreshDashboard();
    return true;
  }

  return {
    init,
    icon,
    toast,
    confirm: confirmDialog,
    promptText,
    switchTab,
    stat,
    logActivity,
    refreshDashboard,
    saveSettings,
  };
})();
