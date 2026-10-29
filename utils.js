/**
 * utils.js
 * ---------------------------------------------------------------------------
 * SecureVault — shared, dependency-free utility functions.
 *
 * Nothing in this file touches cryptography and nothing in this file is
 * security-sensitive. It exists purely to keep the rest of the codebase
 * small and readable. Everything here is a pure function unless it says
 * otherwise in a comment.
 *
 * Attached to the shared `SV` namespace so it can be used from plain
 * <script> tags without a bundler or ES module loader (this keeps the app
 * loadable directly from disk via file://, with no local server required).
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.Utils = (function () {
  'use strict';

  // Chunk size used when converting large byte arrays to binary strings for
  // btoa(). btoa/String.fromCharCode choke or blow the call stack on huge
  // arrays if you pass them all at once, so we feed it in bounded pieces.
  const BASE64_STRING_CHUNK = 0x8000; // 32,768 bytes at a time

  /**
   * Encode a Uint8Array as a Base64 string. Safe for large arrays.
   */
  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i += BASE64_STRING_CHUNK) {
      const slice = bytes.subarray(i, i + BASE64_STRING_CHUNK);
      binary += String.fromCharCode.apply(null, slice);
    }
    return btoa(binary);
  }

  /**
   * Decode a Base64 string into a Uint8Array. Throws a plain Error with a
   * user-safe message if the input isn't valid Base64.
   */
  function base64ToBytes(b64) {
    let binary;
    try {
      binary = atob(String(b64).trim().replace(/\s+/g, ''));
    } catch (err) {
      throw new Error('That text is not valid Base64.');
    }
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  /**
   * Encode a Uint8Array as a lowercase hex string.
   */
  function bytesToHex(bytes) {
    let hex = '';
    for (let i = 0; i < bytes.length; i++) {
      hex += bytes[i].toString(16).padStart(2, '0');
    }
    return hex;
  }

  /**
   * Decode a hex string (whitespace-tolerant) into a Uint8Array.
   */
  function hexToBytes(hex) {
    const clean = String(hex).trim().replace(/\s+/g, '');
    if (clean.length === 0 || clean.length % 2 !== 0) {
      throw new Error('Hex key must have an even number of characters.');
    }
    if (!/^[0-9a-fA-F]*$/.test(clean)) {
      throw new Error('Hex key contains characters other than 0-9 and a-f.');
    }
    const bytes = new Uint8Array(clean.length / 2);
    for (let i = 0; i < bytes.length; i++) {
      bytes[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return bytes;
  }

  /**
   * Detects whether a trimmed string looks like a 32-byte (256-bit) hex key.
   */
  function looksLikeHexKey(str) {
    const clean = String(str).trim().replace(/\s+/g, '');
    return /^[0-9a-fA-F]{64}$/.test(clean);
  }

  /**
   * Human-readable byte size, e.g. 1536 -> "1.5 KB".
   */
  function formatBytes(bytes, decimals = 2) {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 Bytes';
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    const value = bytes / Math.pow(k, i);
    return `${parseFloat(value.toFixed(decimals))} ${sizes[i]}`;
  }

  /**
   * Human-readable duration, e.g. 61234 -> "1m 1s".
   */
  function formatDuration(ms) {
    if (!Number.isFinite(ms) || ms < 0) return '0 ms';
    if (ms < 1000) return `${Math.round(ms)} ms`;
    const totalSeconds = ms / 1000;
    if (totalSeconds < 60) return `${totalSeconds.toFixed(1)} s`;
    const minutes = Math.floor(totalSeconds / 60);
    const seconds = Math.round(totalSeconds % 60);
    return `${minutes}m ${seconds}s`;
  }

  /**
   * Relative time for the activity feed, e.g. "just now", "5m ago".
   */
  function formatRelativeTime(isoString) {
    const then = new Date(isoString).getTime();
    const diffMs = Date.now() - then;
    const s = Math.floor(diffMs / 1000);
    if (s < 5) return 'just now';
    if (s < 60) return `${s}s ago`;
    const m = Math.floor(s / 60);
    if (m < 60) return `${m}m ago`;
    const h = Math.floor(m / 60);
    if (h < 24) return `${h}h ago`;
    const d = Math.floor(h / 24);
    return `${d}d ago`;
  }

  /**
   * RFC4122-ish v4 UUID, used only as opaque local IDs for list rows
   * (not security-sensitive).
   */
  function uuid() {
    if (window.crypto && typeof window.crypto.randomUUID === 'function') {
      return window.crypto.randomUUID();
    }
    const bytes = window.crypto.getRandomValues(new Uint8Array(16));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytesToHex(bytes);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  }

  function debounce(fn, wait) {
    let timer = null;
    return function debounced(...args) {
      clearTimeout(timer);
      timer = setTimeout(() => fn.apply(this, args), wait);
    };
  }

  /**
   * Triggers a browser "Save As" for a Blob, without navigating away from
   * the page. Revokes the object URL shortly after to avoid leaking memory.
   */
  function downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename || 'download';
    a.rel = 'noopener';
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 4000);
  }

  /**
   * Strips characters that are illegal (or awkward) in filenames on common
   * operating systems, and caps length.
   */
  function sanitizeFilename(name) {
    const cleaned = String(name == null ? '' : name)
      .replace(/[\/\\?%*:|"<>\x00-\x1f]/g, '_')
      .trim();
    return (cleaned || 'file').slice(0, 255);
  }

  function getExtension(filename) {
    const str = String(filename || '');
    const idx = str.lastIndexOf('.');
    if (idx <= 0 || idx === str.length - 1) return '';
    return str.slice(idx + 1).toLowerCase();
  }

  function stripExtension(filename, ext) {
    const str = String(filename || '');
    const suffix = '.' + ext;
    return str.toLowerCase().endsWith(suffix.toLowerCase()) ? str.slice(0, str.length - suffix.length) : str;
  }

  /**
   * Concatenates a list of Uint8Array (or plain array-of-bytes) values into
   * a single Uint8Array. Used constantly by the binary container format.
   */
  function concatUint8(arrays) {
    let total = 0;
    for (const a of arrays) total += a.length;
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  /**
   * Yields to the event loop / render pipeline. Used between chunk
   * operations so large-file processing never freezes the UI thread for
   * longer than a single chunk's worth of work.
   */
  function yieldToUI() {
    return new Promise((resolve) => setTimeout(resolve, 0));
  }

  function nowIso() {
    return new Date().toISOString();
  }

  function clamp(n, min, max) {
    return Math.min(max, Math.max(min, n));
  }

  return {
    bytesToBase64,
    base64ToBytes,
    bytesToHex,
    hexToBytes,
    looksLikeHexKey,
    formatBytes,
    formatDuration,
    formatRelativeTime,
    uuid,
    debounce,
    downloadBlob,
    sanitizeFilename,
    getExtension,
    stripExtension,
    concatUint8,
    yieldToUI,
    nowIso,
    clamp,
  };
})();
