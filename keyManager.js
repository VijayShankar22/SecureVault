/**
 * keyManager.js
 * ---------------------------------------------------------------------------
 * SecureVault — key lifecycle: generate, display, copy, download, import,
 * clear. Owns SV.state.key and everything derived from it.
 *
 * SECURITY NOTE: the key lives only in `SV.state` (plain JS memory) for the
 * lifetime of the page. It is never written to localStorage, sessionStorage,
 * IndexedDB, or any cookie, and never leaves the device in any network
 * request (SecureVault makes none). Reloading the page or closing the tab
 * discards it completely — this is intentional, not a bug: if SecureVault
 * silently persisted keys, a compromise of the browser profile would be
 * enough to recover them. "Never store keys" is a hard requirement, not a
 * missing feature.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.KeyManager = (function () {
  'use strict';

  const U = SV.Utils;
  const C = SV.Crypto;

  function els() {
    return {
      emptyState: document.getElementById('key-empty-state'),
      loadedState: document.getElementById('key-loaded-state'),
      base64Field: document.getElementById('key-base64-field'),
      hexField: document.getElementById('key-hex-field'),
      fingerprint: document.getElementById('key-fingerprint'),
      createdAt: document.getElementById('key-created-at'),
      headerChip: document.getElementById('header-key-chip'),
      headerChipLabel: document.getElementById('header-key-chip-label'),
      generateBtn: document.getElementById('btn-generate-key'),
      regenerateBtn: document.getElementById('btn-regenerate-key'),
      copyBase64Btn: document.getElementById('btn-copy-key-base64'),
      copyHexBtn: document.getElementById('btn-copy-key-hex'),
      downloadBtn: document.getElementById('btn-download-key'),
      uploadBtn: document.getElementById('btn-upload-key'),
      uploadInput: document.getElementById('input-upload-key'),
      pasteBtn: document.getElementById('btn-paste-key'),
      clearBtn: document.getElementById('btn-clear-key'),
    };
  }

  /** "a1b2c3…" -> "A1B2 C3D4 E5F6 …" for readability / eyeballing. */
  function formatFingerprint(hex) {
    const groups = hex.toUpperCase().match(/.{1,4}/g) || [];
    return groups.join(' ');
  }

  function hasKey() {
    return !!SV.state.key;
  }

  function render() {
    const e = els();
    const loaded = hasKey();

    if (e.emptyState) e.emptyState.hidden = loaded;
    if (e.loadedState) e.loadedState.hidden = !loaded;

    if (loaded) {
      if (e.base64Field) e.base64Field.value = SV.state.keyBase64;
      if (e.hexField) e.hexField.value = SV.state.keyHex;
      if (e.fingerprint) e.fingerprint.textContent = formatFingerprint(SV.state.keyFingerprint);
      if (e.createdAt) {
        e.createdAt.textContent = SV.state.keyCreatedAt ? new Date(SV.state.keyCreatedAt).toLocaleString() : '—';
      }
    }

    if (e.headerChip) {
      e.headerChip.classList.toggle('is-active', loaded);
      e.headerChip.classList.toggle('is-empty', !loaded);
    }
    if (e.headerChipLabel) {
      e.headerChipLabel.textContent = loaded
        ? `Key loaded · ${SV.state.keyFingerprint.slice(0, 8).toUpperCase()}`
        : 'No key loaded';
    }

    if (SV.UI && SV.UI.refreshDashboard) SV.UI.refreshDashboard();
  }

  async function setActiveKey(key, bytes) {
    SV.state.key = key;
    SV.state.keyBytes = bytes;
    SV.state.keyBase64 = U.bytesToBase64(bytes);
    SV.state.keyHex = U.bytesToHex(bytes);
    SV.state.keyFingerprint = await C.fingerprintOf(bytes);
    SV.state.keyCreatedAt = U.nowIso();
    render();
  }

  async function confirmOverwriteIfNeeded() {
    if (!hasKey()) return true;
    if (!SV.state.settings.confirmBeforeOverwrite) return true;
    return SV.UI.confirm({
      title: 'Replace the current key?',
      message:
        "A key is already loaded. Replacing it only changes what's in this browser tab's memory — if you haven't saved a copy of the current key, anything encrypted with it can no longer be decrypted here.",
      confirmLabel: 'Replace key',
      danger: true,
    });
  }

  async function generateNewKey() {
    const proceed = await confirmOverwriteIfNeeded();
    if (!proceed) return;
    const key = await C.generateKey();
    const bytes = await C.exportKeyBytes(key);
    await setActiveKey(key, bytes);
    SV.UI.toast({ type: 'success', message: 'New AES-256 key generated. Save it now — SecureVault never stores it for you.' });
    SV.UI.logActivity({ type: 'key', label: 'Generated a new key', detail: SV.state.keyFingerprint.slice(0, 16).toUpperCase() });
  }

  /**
   * Accepts a .key file's JSON contents, a raw Base64 string, or a raw hex
   * string, and returns the decoded 32-byte key material.
   */
  function detectAndDecode(rawText) {
    const trimmed = String(rawText || '').trim();
    if (!trimmed) throw new Error('That field is empty.');

    if (trimmed.startsWith('{')) {
      let obj;
      try {
        obj = JSON.parse(trimmed);
      } catch (err) {
        throw new Error('This looks like a .key file but the JSON could not be parsed.');
      }
      if (obj.key_base64 || obj.keyBase64) return U.base64ToBytes(obj.key_base64 || obj.keyBase64);
      if (obj.key_hex || obj.keyHex) return U.hexToBytes(obj.key_hex || obj.keyHex);
      throw new Error("This JSON doesn't contain a recognizable SecureVault key field.");
    }

    if (U.looksLikeHexKey(trimmed)) return U.hexToBytes(trimmed);
    return U.base64ToBytes(trimmed);
  }

  async function importFromRawText(rawText) {
    const proceed = await confirmOverwriteIfNeeded();
    if (!proceed) return;

    let bytes;
    try {
      bytes = detectAndDecode(rawText);
    } catch (err) {
      SV.UI.toast({ type: 'error', message: err.message || 'Could not read that key.' });
      return;
    }

    try {
      const key = await C.importKeyBytes(bytes);
      await setActiveKey(key, bytes);
      SV.UI.toast({ type: 'success', message: 'Key imported.' });
      SV.UI.logActivity({ type: 'key', label: 'Imported a key', detail: SV.state.keyFingerprint.slice(0, 16).toUpperCase() });
    } catch (err) {
      SV.UI.toast({ type: 'error', message: err.message || 'That key could not be imported.' });
    }
  }

  async function importFromFile(file) {
    try {
      const text = await file.text();
      await importFromRawText(text);
    } catch (err) {
      SV.UI.toast({ type: 'error', message: 'Could not read that file.' });
    }
  }

  function buildKeyFileContents() {
    return JSON.stringify(
      {
        app: 'SecureVault',
        type: 'SecureVault-Key',
        version: 1,
        algorithm: 'AES-256-GCM',
        key_base64: SV.state.keyBase64,
        key_hex: SV.state.keyHex,
        fingerprint: SV.state.keyFingerprint,
        created: SV.state.keyCreatedAt,
      },
      null,
      2
    );
  }

  function downloadKeyFile() {
    if (!hasKey()) {
      SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
      return;
    }
    const filename = `securevault-key-${SV.state.keyFingerprint.slice(0, 8)}.key`;
    U.downloadBlob(new Blob([buildKeyFileContents()], { type: 'application/json' }), filename);
    SV.UI.toast({ type: 'success', message: `Downloaded ${filename}. Anyone with this file can decrypt your data — store it somewhere safe.` });
    SV.UI.logActivity({ type: 'key', label: 'Downloaded the key file', detail: filename });
  }

  async function copyToClipboard(format) {
    if (!hasKey()) {
      SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
      return;
    }
    const value = format === 'hex' ? SV.state.keyHex : SV.state.keyBase64;
    try {
      await navigator.clipboard.writeText(value);
      SV.UI.toast({ type: 'success', message: `Key copied (${format === 'hex' ? 'hex' : 'Base64'}). Paste it somewhere safe.` });
    } catch (err) {
      SV.UI.toast({ type: 'error', message: 'Could not access the clipboard — you can select the field and copy it manually.' });
    }
  }

  async function clearKey() {
    if (!hasKey()) return;
    const confirmed = await SV.UI.confirm({
      title: 'Clear the key from memory?',
      message: "This removes the key from this tab. SecureVault never stores keys, so this can't be undone here — make sure you've saved a copy first if you'll need it again.",
      confirmLabel: 'Clear key',
      danger: true,
    });
    if (!confirmed) return;

    SV.state.key = null;
    SV.state.keyBytes = null;
    SV.state.keyBase64 = '';
    SV.state.keyHex = '';
    SV.state.keyFingerprint = '';
    SV.state.keyCreatedAt = null;
    render();
    SV.UI.toast({ type: 'info', message: 'Key cleared from memory.' });
  }

  function init() {
    const e = els();
    if (e.generateBtn) e.generateBtn.addEventListener('click', generateNewKey);
    if (e.regenerateBtn) e.regenerateBtn.addEventListener('click', generateNewKey);
    if (e.copyBase64Btn) e.copyBase64Btn.addEventListener('click', () => copyToClipboard('base64'));
    if (e.copyHexBtn) e.copyHexBtn.addEventListener('click', () => copyToClipboard('hex'));
    if (e.downloadBtn) e.downloadBtn.addEventListener('click', downloadKeyFile);
    if (e.clearBtn) e.clearBtn.addEventListener('click', clearKey);

    if (e.uploadBtn && e.uploadInput) {
      e.uploadBtn.addEventListener('click', () => e.uploadInput.click());
      e.uploadInput.addEventListener('change', async () => {
        const file = e.uploadInput.files && e.uploadInput.files[0];
        if (file) await importFromFile(file);
        e.uploadInput.value = '';
      });
    }

    if (e.pasteBtn) {
      e.pasteBtn.addEventListener('click', async () => {
        const text = await SV.UI.promptText({
          title: 'Paste a key',
          message: 'Paste a Base64 key, a 64-character hex key, or the full contents of a .key file.',
          placeholder: 'Paste key material here…',
          confirmLabel: 'Import key',
        });
        if (text != null) await importFromRawText(text);
      });
    }

    render();
  }

  return {
    init,
    hasKey,
    formatFingerprint,
    generateNewKey,
    importFromRawText,
    importFromFile,
    downloadKeyFile,
    copyToClipboard,
    clearKey,
    render,
  };
})();
