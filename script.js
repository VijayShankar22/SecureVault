/**
 * script.js
 * ---------------------------------------------------------------------------
 * SecureVault — application entry point.
 *
 * Defines the single shared state object every module reads/writes, then
 * initializes each feature module. This is the only file that runs
 * top-level (non-function-wrapped) code with side effects, and it's kept
 * intentionally small: everything else lives in its own module and is
 * only wired up from here.
 *
 * Load order (see index.html): utils, crypto, keyManager, file, folder,
 * text, ui, script. Every earlier file only *defines* functions on the
 * shared SV namespace — nothing runs until SV.App.init() below fires each
 * module's init(), so definition order matters but init order is explicit
 * and controlled right here.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.App = (function () {
  'use strict';

  const VERSION = '1.0.0';
  const FORMAT_VERSION = 1;

  function createInitialState() {
    return {
      // -- key state (memory only — see keyManager.js for the "why") --
      key: null,
      keyBytes: null,
      keyBase64: '',
      keyHex: '',
      keyFingerprint: '',
      keyCreatedAt: null,

      // -- non-sensitive settings, persisted to localStorage by ui.js --
      settings: null, // populated by SV.UI.init() -> loadSettings()

      // -- session-only usage stats + activity feed, shown on Dashboard --
      stats: {
        filesEncrypted: 0,
        filesDecrypted: 0,
        foldersEncrypted: 0,
        foldersDecrypted: 0,
        bytesEncrypted: 0,
        bytesDecrypted: 0,
        textOps: 0,
      },
      activity: [],

      // -- File Encryption tab's working list --
      files: [],
    };
  }

  function logStartupBanner() {
    // eslint-disable-next-line no-console
    console.log(
      `%cSecureVault v${VERSION}%c — offline AES-256-GCM encryption (container format v${FORMAT_VERSION}). ` +
        'No network requests. No telemetry. Your files and keys never leave this browser tab.',
      'font-weight: 700;',
      'font-weight: 400;'
    );
  }

  function setYearAndVersionLabels() {
    const versionEls = document.querySelectorAll('[data-app-version]');
    versionEls.forEach((el) => {
      el.textContent = `v${VERSION}`;
    });
    const formatEls = document.querySelectorAll('[data-format-version]');
    formatEls.forEach((el) => {
      el.textContent = String(FORMAT_VERSION);
    });
    const yearEls = document.querySelectorAll('[data-current-year]');
    yearEls.forEach((el) => {
      el.textContent = String(new Date().getFullYear());
    });
  }

  function init() {
    SV.state = createInitialState();

    // ui.js sets SV.state.settings and gates the rest of the app on Web
    // Crypto actually being available — if it isn't, init() renders a
    // fatal screen and returns false, and nothing else should try to run.
    const ok = SV.UI.init();
    if (!ok) return;

    SV.KeyManager.init();
    SV.Files.init();
    SV.Folder.init();
    SV.Text.init();

    setYearAndVersionLabels();
    logStartupBanner();
  }

  return { init, VERSION, FORMAT_VERSION };
})();

document.addEventListener('DOMContentLoaded', SV.App.init);
