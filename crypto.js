/**
 * crypto.js
 * ---------------------------------------------------------------------------
 * SecureVault — cryptographic core.
 *
 * SECURITY NOTE FOR MAINTAINERS:
 * This file performs no cryptography of its own. Every encrypt/decrypt
 * operation is delegated directly to the browser's native Web Crypto API
 * (crypto.subtle), which is implemented in native code by the browser
 * vendor and has been through far more scrutiny than anything we could
 * write here. This file's only job is:
 *
 *   1. Ask Web Crypto to generate/import/export AES-256-GCM keys.
 *   2. Split large inputs into fixed-size chunks so multi-gigabyte files
 *      don't require holding the entire plaintext/ciphertext in memory
 *      at once as a single buffer, and so the UI thread gets a chance to
 *      breathe between chunks.
 *   3. Give every chunk a unique IV (nonce) and bind every chunk to the
 *      file's header via Additional Authenticated Data (AAD), so chunks
 *      can never be silently reordered, duplicated, or spliced between
 *      two different encrypted files.
 *   4. Read and write the on-disk container format (magic bytes, version,
 *      filename, mime type, IV material, chunk table, ciphertext).
 *
 * Algorithm choice: AES-256-GCM only. GCM is an AEAD cipher, so every
 * chunk is both encrypted *and* authenticated — a modified ciphertext byte,
 * a modified header byte, a wrong key, a truncated file, or data appended
 * after the end of the file will all cause decryption to fail loudly
 * rather than silently returning corrupted plaintext.
 *
 * Never reused across chunks or files: the IV. Every file gets a fresh
 * random 8-byte base nonce from crypto.getRandomValues(); every chunk
 * within that file gets a unique 12-byte IV built from
 * (base nonce || 4-byte big-endian chunk index) — the same "counter
 * appended to a random base" construction used by streaming AEAD designs
 * such as age and libsodium's secretstream. Because the counter portion
 * strictly increases per chunk and chunk counts never approach 2^32, no
 * two chunks ever share an IV under the same key.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.Crypto = (function () {
  'use strict';

  const U = SV.Utils;

  // ---- Container format constants -----------------------------------------

  const MAGIC = new Uint8Array([0x53, 0x56, 0x4c, 0x54]); // ASCII "SVLT"
  const FORMAT_VERSION = 1;
  const IV_BASE_LEN = 8; // random bytes stored in the header per file
  const IV_FULL_LEN = 12; // bytes required by AES-GCM
  const CHUNK_LEN_FIELD = 4; // bytes used to prefix each chunk's ciphertext length
  const GCM_TAG_BITS = 128;
  const DEFAULT_CHUNK_SIZE = 16 * 1024 * 1024; // 16 MB plaintext per chunk
  const HEADER_PROBE_START = 4096; // initial guess for header length when reading

  const ContentType = Object.freeze({ FILE: 0, TEXT: 1, FOLDER: 2 });

  /**
   * Error type used for everything this module rejects with, so callers can
   * branch on `.code` instead of parsing message strings.
   * Codes: INVALID_KEY_LENGTH, INVALID_FORMAT, UNSUPPORTED_VERSION,
   *        AUTH_FAILED, TAMPERED, EMPTY_INPUT
   */
  class SVError extends Error {
    constructor(code, message) {
      super(message);
      this.name = 'SVError';
      this.code = code;
    }
  }

  // ---- Small binary writer (network byte order / big-endian) --------------
  // Used only for SecureVault's own .enc container header. The unrelated
  // ZIP writer in folder.js uses little-endian, per the ZIP spec — the two
  // formats are independent and intentionally do not share this class.

  class BinaryWriter {
    constructor() {
      this._parts = [];
      this.length = 0;
    }
    writeBytes(bytes) {
      this._parts.push(bytes);
      this.length += bytes.length;
      return this;
    }
    writeUint8(v) {
      return this.writeBytes(Uint8Array.of(v & 0xff));
    }
    writeUint16(v) {
      const b = new Uint8Array(2);
      new DataView(b.buffer).setUint16(0, v, false);
      return this.writeBytes(b);
    }
    writeUint32(v) {
      const b = new Uint8Array(4);
      new DataView(b.buffer).setUint32(0, v, false);
      return this.writeBytes(b);
    }
    writeUint64(v) {
      const b = new Uint8Array(8);
      new DataView(b.buffer).setBigUint64(0, BigInt(v), false);
      return this.writeBytes(b);
    }
    toUint8Array() {
      return U.concatUint8(this._parts);
    }
  }

  function uint32BE(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, false);
    return b;
  }

  // ---- Key management -------------------------------------------------------

  /** Generates a brand-new random AES-256-GCM key. Never derived from a password. */
  async function generateKey() {
    return crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  /** Exports a CryptoKey to raw bytes (32 bytes / 256 bits) for display/download. */
  async function exportKeyBytes(key) {
    const raw = await crypto.subtle.exportKey('raw', key);
    return new Uint8Array(raw);
  }

  /** Imports raw key bytes back into a usable CryptoKey. Validates length first. */
  async function importKeyBytes(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = new Uint8Array(bytes);
    if (bytes.length !== 32) {
      throw new SVError(
        'INVALID_KEY_LENGTH',
        `A SecureVault key must be exactly 256 bits (32 bytes). This one is ${bytes.length * 8} bits.`
      );
    }
    return crypto.subtle.importKey('raw', bytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  }

  /**
   * SHA-256 fingerprint of the raw key, truncated to 16 bytes (32 hex chars).
   * This is purely a convenience "does this look like the key I expect"
   * visual check for the user — it is not a MAC, not a KDF, and it is not
   * itself a security boundary.
   */
  async function fingerprintOf(bytes) {
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return U.bytesToHex(new Uint8Array(digest)).slice(0, 32);
  }

  // ---- Source adapters --------------------------------------------------
  // Lets the same encrypt() function accept either a File/Blob (files,
  // folders-as-zip) or an in-memory Uint8Array (text) without branching
  // throughout the chunk loop.

  function blobSource(blob) {
    return {
      size: blob.size,
      async sliceAsync(start, end) {
        return new Uint8Array(await blob.slice(start, end).arrayBuffer());
      },
    };
  }

  function bytesSource(bytes) {
    return {
      size: bytes.length,
      async sliceAsync(start, end) {
        return bytes.subarray(start, end);
      },
    };
  }

  // ---- Header build/parse ------------------------------------------------

  function buildHeader({ filename, mime, contentType, plaintextLength, chunkSize }) {
    const filenameBytes = new TextEncoder().encode(filename || '');
    const mimeBytes = new TextEncoder().encode(mime || 'application/octet-stream');
    const ivBase = crypto.getRandomValues(new Uint8Array(IV_BASE_LEN));
    const chunkCount = plaintextLength === 0 ? 1 : Math.ceil(plaintextLength / chunkSize);

    const w = new BinaryWriter();
    w.writeBytes(MAGIC);
    w.writeUint8(FORMAT_VERSION);
    w.writeUint8(contentType);
    w.writeUint16(0); // reserved, for future flags
    w.writeUint16(filenameBytes.length);
    w.writeBytes(filenameBytes);
    w.writeUint16(mimeBytes.length);
    w.writeBytes(mimeBytes);
    w.writeBytes(ivBase);
    w.writeUint64(plaintextLength);
    w.writeUint32(chunkSize);
    w.writeUint32(chunkCount);

    return { bytes: w.toUint8Array(), ivBase, chunkCount, chunkSize };
  }

  async function fetchPrefix(blob, len) {
    const n = Math.min(len, blob.size);
    return new Uint8Array(await blob.slice(0, n).arrayBuffer());
  }

  /**
   * Reads and validates the container header from an encrypted Blob/File.
   * Grows its read window as needed to accommodate arbitrarily long
   * filenames/mime strings without ever reading the (potentially huge)
   * ciphertext body.
   */
  async function parseHeader(blob) {
    if (blob.size < 10) {
      throw new SVError('INVALID_FORMAT', "This doesn't look like a SecureVault file (it's too short).");
    }

    let prefix = await fetchPrefix(blob, Math.min(HEADER_PROBE_START, blob.size));
    let dv = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);

    for (let i = 0; i < MAGIC.length; i++) {
      if (prefix[i] !== MAGIC[i]) {
        throw new SVError('INVALID_FORMAT', "This doesn't look like a SecureVault (.enc) file.");
      }
    }
    const version = dv.getUint8(4);
    if (version !== FORMAT_VERSION) {
      throw new SVError(
        'UNSUPPORTED_VERSION',
        `This file uses SecureVault container version ${version}, which this build doesn't support.`
      );
    }
    const contentType = dv.getUint8(5);
    // bytes 6-7 reserved

    const ensure = async (need) => {
      if (prefix.length >= need) return;
      if (blob.size < need) {
        throw new SVError('INVALID_FORMAT', 'This file is truncated or is not a valid SecureVault container.');
      }
      prefix = await fetchPrefix(blob, need);
      dv = new DataView(prefix.buffer, prefix.byteOffset, prefix.byteLength);
    };

    await ensure(10);
    const filenameLen = dv.getUint16(8, false);

    await ensure(10 + filenameLen + 2);
    const filenameBytes = prefix.slice(10, 10 + filenameLen);
    const mimeLenOffset = 10 + filenameLen;
    const mimeLen = dv.getUint16(mimeLenOffset, false);

    const fixedTailLen = IV_BASE_LEN + 8 /*plaintextLength*/ + 4 /*chunkSize*/ + 4; /*chunkCount*/
    const mimeStart = mimeLenOffset + 2;
    const headerLength = mimeStart + mimeLen + fixedTailLen;
    await ensure(headerLength);

    const mimeBytes = prefix.slice(mimeStart, mimeStart + mimeLen);
    let off = mimeStart + mimeLen;
    const ivBase = prefix.slice(off, off + IV_BASE_LEN);
    off += IV_BASE_LEN;
    const plaintextLength = dv.getBigUint64(off, false);
    off += 8;
    const chunkSize = dv.getUint32(off, false);
    off += 4;
    const chunkCount = dv.getUint32(off, false);
    off += 4;

    if (chunkSize === 0 || chunkCount === 0) {
      throw new SVError('INVALID_FORMAT', 'This file has an invalid chunk table and cannot be read.');
    }

    const headerBytes = prefix.slice(0, headerLength);
    const filename = new TextDecoder().decode(filenameBytes);
    const mime = new TextDecoder().decode(mimeBytes) || 'application/octet-stream';

    return { version, contentType, filename, mime, ivBase, plaintextLength, chunkSize, chunkCount, headerLength, headerBytes };
  }

  // ---- Per-chunk AEAD ------------------------------------------------------

  function chunkIv(ivBase, index) {
    return U.concatUint8([ivBase, uint32BE(index)]);
  }

  function chunkAad(headerBytes, index) {
    // Binds every chunk to this exact header (filename, mime, lengths, IV
    // base, chunk table) AND to its position in the sequence. An attacker
    // who edits the stored filename, or who cuts a chunk from file A and
    // splices it into file B, or who reorders chunks within one file,
    // produces an AAD mismatch and GCM rejects the chunk outright.
    return U.concatUint8([headerBytes, uint32BE(index)]);
  }

  async function encryptChunk(key, plaintext, ivBase, index, headerBytes) {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: chunkIv(ivBase, index), additionalData: chunkAad(headerBytes, index), tagLength: GCM_TAG_BITS },
      key,
      plaintext
    );
    return new Uint8Array(ciphertext);
  }

  async function decryptChunk(key, ciphertext, ivBase, index, headerBytes) {
    try {
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: chunkIv(ivBase, index), additionalData: chunkAad(headerBytes, index), tagLength: GCM_TAG_BITS },
        key,
        ciphertext
      );
      return new Uint8Array(plaintext);
    } catch (err) {
      throw new SVError('AUTH_FAILED', 'Decryption failed — wrong key, or this data has been corrupted or tampered with.');
    }
  }

  // ---- Public encrypt/decrypt ----------------------------------------------

  /**
   * Encrypts a `source` (see blobSource/bytesSource) into a single Blob
   * containing the full SecureVault container: header + length-prefixed,
   * independently-authenticated chunks.
   */
  async function encrypt({ key, filename, mime, contentType, source, chunkSize = DEFAULT_CHUNK_SIZE, onProgress }) {
    if (!key) throw new SVError('EMPTY_INPUT', 'No encryption key is loaded.');
    const header = buildHeader({ filename, mime, contentType, plaintextLength: source.size, chunkSize });
    const parts = [header.bytes];

    for (let i = 0; i < header.chunkCount; i++) {
      const start = i * chunkSize;
      const end = Math.min(start + chunkSize, source.size);
      const plaintext = await source.sliceAsync(start, end);
      const ciphertext = await encryptChunk(key, plaintext, header.ivBase, i, header.bytes);
      parts.push(uint32BE(ciphertext.length), ciphertext);

      if (onProgress) onProgress({ processedBytes: end, totalBytes: source.size, chunkIndex: i, chunkCount: header.chunkCount });
      await U.yieldToUI();
    }

    return new Blob(parts, { type: 'application/octet-stream' });
  }

  /**
   * Decrypts a SecureVault container Blob/File back into
   * { blob, filename, mime, contentType }. Verifies every chunk's AEAD
   * tag, verifies total decrypted length matches the header's declared
   * length, and verifies there is no unexpected trailing data — so
   * truncation and appension attacks are caught even though each
   * individual chunk tag might otherwise pass.
   */
  async function decrypt({ key, blob, onProgress }) {
    if (!key) throw new SVError('EMPTY_INPUT', 'No decryption key is loaded.');
    const header = await parseHeader(blob);

    const outputs = [];
    let pos = header.headerLength;
    let totalPlainBytes = 0n;

    for (let i = 0; i < header.chunkCount; i++) {
      if (blob.size < pos + CHUNK_LEN_FIELD) {
        throw new SVError('INVALID_FORMAT', 'This file is truncated or is not a valid SecureVault container.');
      }
      const lenBytes = new Uint8Array(await blob.slice(pos, pos + CHUNK_LEN_FIELD).arrayBuffer());
      const chunkLen = new DataView(lenBytes.buffer).getUint32(0, false);
      pos += CHUNK_LEN_FIELD;

      if (blob.size < pos + chunkLen) {
        throw new SVError('INVALID_FORMAT', 'This file is truncated or is not a valid SecureVault container.');
      }
      const ciphertext = new Uint8Array(await blob.slice(pos, pos + chunkLen).arrayBuffer());
      pos += chunkLen;

      const plaintext = await decryptChunk(key, ciphertext, header.ivBase, i, header.headerBytes);
      outputs.push(plaintext);
      totalPlainBytes += BigInt(plaintext.length);

      if (onProgress) {
        onProgress({ processedBytes: Number(totalPlainBytes), totalBytes: Number(header.plaintextLength), chunkIndex: i, chunkCount: header.chunkCount });
      }
      await U.yieldToUI();
    }

    if (pos !== blob.size) {
      throw new SVError('TAMPERED', 'This file has extra trailing data and may have been tampered with.');
    }
    if (totalPlainBytes !== header.plaintextLength) {
      throw new SVError('TAMPERED', "The decrypted size doesn't match what the file header declares. The file may be truncated.");
    }

    const outBlob = new Blob(outputs, { type: header.mime || 'application/octet-stream' });
    return { blob: outBlob, filename: header.filename, mime: header.mime, contentType: header.contentType };
  }

  // ---- Convenience wrappers used by the feature modules --------------------

  async function encryptBlob(key, blob, filename, mime, contentType, onProgress) {
    return encrypt({ key, filename, mime, contentType, source: blobSource(blob), onProgress });
  }

  async function encryptBytes(key, bytes, filename, mime, contentType, onProgress) {
    return encrypt({ key, filename, mime, contentType, source: bytesSource(bytes), onProgress });
  }

  async function decryptBlob(key, blob, onProgress) {
    return decrypt({ key, blob, onProgress });
  }

  return {
    ContentType,
    SVError,
    DEFAULT_CHUNK_SIZE,
    FORMAT_VERSION,
    generateKey,
    exportKeyBytes,
    importKeyBytes,
    fingerprintOf,
    blobSource,
    bytesSource,
    encrypt,
    decrypt,
    encryptBlob,
    encryptBytes,
    decryptBlob,
    parseHeader,
  };
})();
