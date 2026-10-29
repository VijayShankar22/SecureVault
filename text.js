/**
 * text.js
 * ---------------------------------------------------------------------------
 * SecureVault — Text Encryption tab.
 *
 * Reuses the exact same AES-256-GCM engine as files (crypto.js): plaintext
 * is UTF-8 encoded, wrapped in a normal SecureVault container, and the
 * resulting bytes are shown as Base64 so they're easy to paste into an
 * email, chat message, or text file. Decryption just reverses this.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.Text = (function () {
  'use strict';

  const U = SV.Utils;
  const C = SV.Crypto;

  function els() {
    return {
      input: document.getElementById('text-plain-input'),
      charCount: document.getElementById('text-input-char-count'),
      encryptBtn: document.getElementById('btn-encrypt-text'),
      output: document.getElementById('text-cipher-output'),
      copyOutputBtn: document.getElementById('btn-copy-cipher-output'),
      downloadOutputBtn: document.getElementById('btn-download-cipher-output'),

      cipherInput: document.getElementById('text-cipher-input'),
      decryptBtn: document.getElementById('btn-decrypt-text'),
      plainOutput: document.getElementById('text-plain-output'),
      copyPlainBtn: document.getElementById('btn-copy-plain-output'),
    };
  }

  async function ensureKeyOrRedirect() {
    if (SV.KeyManager.hasKey()) return true;
    SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
    SV.UI.switchTab('keys');
    return false;
  }

  async function encryptText() {
    const e = els();
    if (!(await ensureKeyOrRedirect())) return;

    const text = e.input.value;
    if (!text) {
      SV.UI.toast({ type: 'error', message: 'Type or paste some text first.' });
      return;
    }

    try {
      const bytes = new TextEncoder().encode(text);
      const blob = await C.encryptBytes(SV.state.key, bytes, 'message.txt', 'text/plain', C.ContentType.TEXT);
      const outBytes = new Uint8Array(await blob.arrayBuffer());
      e.output.value = U.bytesToBase64(outBytes);
      SV.UI.stat('textOps', 1);
      SV.UI.stat('bytesEncrypted', bytes.length);
      SV.UI.logActivity({ type: 'text-encrypt', label: 'Encrypted text', detail: `${text.length.toLocaleString()} characters` });
      SV.UI.toast({ type: 'success', message: 'Text encrypted.' });
    } catch (err) {
      SV.UI.toast({ type: 'error', message: err.message || 'Could not encrypt that text.' });
    }
  }

  async function decryptText() {
    const e = els();
    if (!(await ensureKeyOrRedirect())) return;

    const b64 = e.cipherInput.value.trim();
    if (!b64) {
      SV.UI.toast({ type: 'error', message: 'Paste encrypted text first.' });
      return;
    }

    try {
      const bytes = U.base64ToBytes(b64);
      const result = await C.decryptBlob(SV.state.key, new Blob([bytes]));
      const text = await result.blob.text();
      e.plainOutput.value = text;
      SV.UI.stat('textOps', 1);
      SV.UI.stat('bytesDecrypted', result.blob.size);
      SV.UI.logActivity({ type: 'text-decrypt', label: 'Decrypted text', detail: `${text.length.toLocaleString()} characters` });
      SV.UI.toast({ type: 'success', message: 'Text decrypted — integrity verified.' });
    } catch (err) {
      e.plainOutput.value = '';
      SV.UI.toast({ type: 'error', message: err.message || 'Could not decrypt that text.' });
    }
  }

  async function copyField(el, label) {
    if (!el || !el.value) {
      SV.UI.toast({ type: 'error', message: 'Nothing to copy yet.' });
      return;
    }
    try {
      await navigator.clipboard.writeText(el.value);
      SV.UI.toast({ type: 'success', message: `${label} copied to clipboard.` });
    } catch (err) {
      SV.UI.toast({ type: 'error', message: 'Could not access the clipboard — you can select the field and copy it manually.' });
    }
  }

  function downloadCipher() {
    const e = els();
    if (!e.output.value) {
      SV.UI.toast({ type: 'error', message: 'Nothing to download yet.' });
      return;
    }
    U.downloadBlob(new Blob([e.output.value], { type: 'text/plain' }), 'securevault-encrypted-text.txt');
  }

  function init() {
    const e = els();
    if (e.encryptBtn) e.encryptBtn.addEventListener('click', encryptText);
    if (e.decryptBtn) e.decryptBtn.addEventListener('click', decryptText);
    if (e.copyOutputBtn) e.copyOutputBtn.addEventListener('click', () => copyField(e.output, 'Encrypted text'));
    if (e.copyPlainBtn) e.copyPlainBtn.addEventListener('click', () => copyField(e.plainOutput, 'Decrypted text'));
    if (e.downloadOutputBtn) e.downloadOutputBtn.addEventListener('click', downloadCipher);
    if (e.input && e.charCount) {
      const update = () => {
        e.charCount.textContent = `${e.input.value.length.toLocaleString()} characters`;
      };
      e.input.addEventListener('input', update);
      update();
    }
  }

  return { init, encryptText, decryptText };
})();
