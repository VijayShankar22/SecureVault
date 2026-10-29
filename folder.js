/**
 * folder.js
 * ---------------------------------------------------------------------------
 * SecureVault — folder encryption.
 *
 * Folders can't be handed to Web Crypto directly, so this module first
 * packs the selected folder into a standard ZIP archive, then encrypts
 * that ZIP's bytes through the exact same AES-256-GCM engine used for
 * single files (crypto.js). Decryption is the mirror image: decrypt back
 * to the original ZIP bytes and let the user's OS unzip it, which is what
 * actually restores the folder hierarchy — SecureVault does not need (or
 * contain) a ZIP *reader*, only a writer.
 *
 * ZIP compression: entries are stored with compression method 0 ("Store",
 * i.e. uncompressed). This is a deliberate trade-off, not an oversight —
 * see the note above buildZip() below.
 *
 * ZIP byte order: unlike SecureVault's own .enc container (big-endian),
 * the ZIP format itself is little-endian by specification. The two are
 * independent formats and intentionally do not share a binary writer.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.Folder = (function () {
  'use strict';

  const U = SV.Utils;
  const C = SV.Crypto;

  const ZIP_LOCAL_SIG = 0x04034b50;
  const ZIP_CENTRAL_SIG = 0x02014b50;
  const ZIP_EOCD_SIG = 0x06054b50;
  const ZIP_VERSION = 20; // 2.0, enough for Store + UTF-8 filenames
  const ZIP_FLAG_UTF8 = 0x0800; // general purpose bit 11 (language encoding / EFS)
  const ZIP_METHOD_STORE = 0;

  // ---- little-endian primitives (ZIP spec requires LE) --------------------

  function u16le(n) {
    const b = new Uint8Array(2);
    new DataView(b.buffer).setUint16(0, n, true);
    return b;
  }
  function u32le(n) {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n, true);
    return b;
  }

  // ---- CRC-32 (standard zlib/PKZIP polynomial 0xEDB88320) ------------------
  // Used only for the ZIP container's own integrity field, per the ZIP spec.
  // This has nothing to do with SecureVault's actual security: the whole
  // ZIP gets wrapped in authenticated AES-256-GCM afterward, and that GCM
  // tag — not this CRC — is what detects tampering.

  const CRC_TABLE = (() => {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) {
        c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) {
      crc = CRC_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8);
    }
    return (crc ^ 0xffffffff) >>> 0;
  }

  function toDosDateTime(date) {
    const d = date instanceof Date && !isNaN(date) ? date : new Date();
    const dosTime = ((d.getHours() & 0x1f) << 11) | ((d.getMinutes() & 0x3f) << 5) | ((d.getSeconds() >> 1) & 0x1f);
    const year = Math.max(0, d.getFullYear() - 1980) & 0x7f;
    const dosDate = (year << 9) | (((d.getMonth() + 1) & 0xf) << 5) | (d.getDate() & 0x1f);
    return { dosTime, dosDate };
  }

  // ---- ZIP record builders --------------------------------------------------

  function buildLocalHeader({ nameBytes, crc, size, dosTime, dosDate }) {
    return U.concatUint8([
      u32le(ZIP_LOCAL_SIG),
      u16le(ZIP_VERSION),
      u16le(ZIP_FLAG_UTF8),
      u16le(ZIP_METHOD_STORE),
      u16le(dosTime),
      u16le(dosDate),
      u32le(crc),
      u32le(size), // compressed size == size, since Store
      u32le(size), // uncompressed size
      u16le(nameBytes.length),
      u16le(0), // extra field length
    ]);
  }

  function buildCentralHeader({ nameBytes, crc, size, dosTime, dosDate, localOffset }) {
    return U.concatUint8([
      u32le(ZIP_CENTRAL_SIG),
      u16le(ZIP_VERSION), // version made by
      u16le(ZIP_VERSION), // version needed to extract
      u16le(ZIP_FLAG_UTF8),
      u16le(ZIP_METHOD_STORE),
      u16le(dosTime),
      u16le(dosDate),
      u32le(crc),
      u32le(size),
      u32le(size),
      u16le(nameBytes.length),
      u16le(0), // extra length
      u16le(0), // comment length
      u16le(0), // disk number start
      u16le(0), // internal file attributes
      u32le(0), // external file attributes
      u32le(localOffset),
    ]);
  }

  function buildEOCD(entryCount, centralDirSize, centralDirOffset) {
    return U.concatUint8([
      u32le(ZIP_EOCD_SIG),
      u16le(0), // this disk number
      u16le(0), // disk with start of central directory
      u16le(entryCount), // entries on this disk
      u16le(entryCount), // total entries
      u32le(centralDirSize),
      u32le(centralDirOffset),
      u16le(0), // comment length
    ]);
  }

  /**
   * Builds a standard ZIP archive (Blob) from a list of
   * { relativePath, file } entries.
   *
   * Compression: entries are stored uncompressed (method 0 / "Store")
   * rather than DEFLATE-compressed. This is intentional: implementing a
   * correct DEFLATE compressor from scratch is a substantial undertaking
   * in its own right and a poor place to introduce subtle bugs in a
   * security tool, and SecureVault has "no CDN dependencies, everything
   * bundled locally" as a hard requirement, which rules out pulling in a
   * third-party compression library. The trade-off is larger archives for
   * already-compressed content (photos, videos, most documents); the
   * upside is a small, auditable, dependency-free implementation and a
   * resulting .zip that is 100% standards-compliant and opens in any
   * unzip tool. AES-256-GCM is applied to the whole archive afterward
   * regardless, so no confidentiality is lost by skipping compression.
   */
  async function buildZip(entries, onProgress) {
    const localParts = [];
    const centralEntries = [];
    let offset = 0;

    for (let idx = 0; idx < entries.length; idx++) {
      const { relativePath, file } = entries[idx];
      const data = new Uint8Array(await file.arrayBuffer());
      const crc = crc32(data);
      const nameBytes = new TextEncoder().encode(relativePath.replace(/\\/g, '/'));
      const { dosTime, dosDate } = toDosDateTime(new Date(file.lastModified || Date.now()));

      const localHeader = buildLocalHeader({ nameBytes, crc, size: data.length, dosTime, dosDate });
      localParts.push(localHeader, nameBytes, data);

      centralEntries.push(buildCentralHeader({ nameBytes, crc, size: data.length, dosTime, dosDate, localOffset: offset }), nameBytes);

      offset += localHeader.length + nameBytes.length + data.length;

      if (onProgress) onProgress({ processed: idx + 1, total: entries.length, name: relativePath });
      await U.yieldToUI();
    }

    const centralDir = U.concatUint8(centralEntries);
    const eocd = buildEOCD(entries.length, centralDir.length, offset);

    return new Blob([...localParts, centralDir, eocd], { type: 'application/zip' });
  }

  /**
   * Normalizes a FileList from <input webkitdirectory> into
   * { relativePath, file }[], plus a derived folder name and total size.
   * Note: browsers only enumerate *files*; a wholly empty sub-folder never
   * appears in the FileList at all, so it cannot be preserved. That's a
   * limitation of the underlying browser API, not of this ZIP writer.
   */
  function collectEntries(fileList) {
    const entries = [];
    let totalSize = 0;
    let folderName = 'folder';

    for (const file of fileList) {
      const relativePath = file.webkitRelativePath || file.name;
      entries.push({ relativePath, file });
      totalSize += file.size;
      if (!folderName || folderName === 'folder') {
        const firstSegment = relativePath.split('/')[0];
        if (firstSegment) folderName = firstSegment;
      }
    }

    return { entries, totalSize, folderName, fileCount: entries.length };
  }

  /**
   * Zips the given entries and encrypts the resulting archive. Reports
   * combined progress across both phases (0-50% zipping, 50-100%
   * encrypting) via onProgress({ phase, fraction }).
   */
  async function encryptFolder({ key, folderName, entries, chunkSize, onProgress }) {
    const zipBlob = await buildZip(entries, (p) => {
      if (onProgress) onProgress({ phase: 'zipping', fraction: p.processed / p.total, detail: p.name });
    });

    const encBlob = await C.encryptBlob(
      key,
      zipBlob,
      U.sanitizeFilename(folderName) + '.zip',
      'application/zip',
      C.ContentType.FOLDER,
      (p) => {
        if (onProgress) onProgress({ phase: 'encrypting', fraction: p.processedBytes / Math.max(1, p.totalBytes) });
      }
    );

    return { blob: encBlob, filename: U.sanitizeFilename(folderName) + '.zip.enc', zipSize: zipBlob.size };
  }

  /** Decrypts a folder .enc back into its original .zip Blob + filename. */
  async function decryptFolder({ key, blob, onProgress }) {
    const result = await C.decryptBlob(key, blob, (p) => {
      if (onProgress) onProgress({ phase: 'decrypting', fraction: p.processedBytes / Math.max(1, p.totalBytes) });
    });
    return result; // { blob, filename, mime, contentType }
  }

  // ---- DOM wiring for the Folder Encryption tab -----------------------------

  const LARGE_FOLDER_WARN_BYTES = 250 * 1024 * 1024;

  let selectedFolder = null; // { folderName, entries, totalSize, fileCount }
  let pendingEncResult = null; // { blob, filename }
  let pendingDecFile = null; // File chosen for decryption
  let pendingDecResult = null; // { blob, filename, mime, contentType }

  function els() {
    return {
      pickerBtn: document.getElementById('btn-pick-folder'),
      pickerInput: document.getElementById('input-pick-folder'),
      summary: document.getElementById('folder-summary'),
      summaryName: document.getElementById('folder-summary-name'),
      summaryMeta: document.getElementById('folder-summary-meta'),
      encryptBtn: document.getElementById('btn-encrypt-folder'),
      progressWrap: document.getElementById('folder-progress-wrap'),
      progressBar: document.getElementById('folder-progress-bar'),
      progressLabel: document.getElementById('folder-progress-label'),
      resultWrap: document.getElementById('folder-result-wrap'),
      resultLabel: document.getElementById('folder-result-label'),
      downloadBtn: document.getElementById('btn-download-folder-result'),

      decPickerBtn: document.getElementById('btn-pick-folder-enc'),
      decPickerInput: document.getElementById('input-pick-folder-enc'),
      decSummary: document.getElementById('folder-dec-summary'),
      decryptBtn: document.getElementById('btn-decrypt-folder'),
      decProgressWrap: document.getElementById('folder-dec-progress-wrap'),
      decProgressBar: document.getElementById('folder-dec-progress-bar'),
      decProgressLabel: document.getElementById('folder-dec-progress-label'),
      decResultWrap: document.getElementById('folder-dec-result-wrap'),
      decResultLabel: document.getElementById('folder-dec-result-label'),
      decDownloadBtn: document.getElementById('btn-download-folder-dec-result'),
    };
  }

  function onFolderPicked(fileList) {
    const e = els();
    if (!fileList || fileList.length === 0) return;
    selectedFolder = collectEntries(fileList);
    pendingEncResult = null;
    if (e.summary) e.summary.hidden = false;
    if (e.summaryName) e.summaryName.textContent = selectedFolder.folderName;
    if (e.summaryMeta) {
      e.summaryMeta.textContent = `${selectedFolder.fileCount} file${selectedFolder.fileCount === 1 ? '' : 's'} · ${U.formatBytes(selectedFolder.totalSize)}`;
    }
    if (e.resultWrap) e.resultWrap.hidden = true;
    if (e.encryptBtn) e.encryptBtn.disabled = selectedFolder.fileCount === 0;
  }

  async function handleEncryptFolder() {
    const e = els();
    if (!selectedFolder || selectedFolder.entries.length === 0) {
      SV.UI.toast({ type: 'error', message: 'Choose a folder first.' });
      return;
    }
    if (!SV.KeyManager.hasKey()) {
      SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
      SV.UI.switchTab('keys');
      return;
    }
    if (selectedFolder.totalSize > LARGE_FOLDER_WARN_BYTES) {
      const ok = await SV.UI.confirm({
        title: 'Large folder',
        message: `This folder is ${U.formatBytes(selectedFolder.totalSize)} across ${selectedFolder.fileCount} files. This can take a while and use significant memory. Continue?`,
        confirmLabel: 'Continue',
      });
      if (!ok) return;
    }

    if (e.encryptBtn) e.encryptBtn.disabled = true;
    if (e.progressWrap) e.progressWrap.hidden = false;
    if (e.resultWrap) e.resultWrap.hidden = true;
    const t0 = performance.now();
    try {
      const { blob, filename, zipSize } = await encryptFolder({
        key: SV.state.key,
        folderName: selectedFolder.folderName,
        entries: selectedFolder.entries,
        onProgress: (p) => {
          const overall = p.phase === 'zipping' ? p.fraction * 0.5 : 0.5 + p.fraction * 0.5;
          if (e.progressBar) e.progressBar.style.width = `${Math.round(U.clamp(overall, 0, 1) * 100)}%`;
          if (e.progressLabel) {
            e.progressLabel.textContent = p.phase === 'zipping' ? 'Compressing files into an archive…' : 'Encrypting archive…';
          }
        },
      });
      pendingEncResult = { blob, filename };
      if (e.resultWrap) e.resultWrap.hidden = false;
      if (e.resultLabel) e.resultLabel.textContent = `${filename} · ${U.formatBytes(blob.size)}`;
      if (e.progressLabel) e.progressLabel.textContent = 'Done.';
      SV.UI.stat('foldersEncrypted', 1);
      SV.UI.stat('bytesEncrypted', zipSize);
      SV.UI.logActivity({ type: 'folder-encrypt', label: `Encrypted folder "${selectedFolder.folderName}"`, detail: `${selectedFolder.fileCount} files · ${U.formatBytes(zipSize)}` });
      SV.UI.toast({ type: 'success', message: `Folder encrypted in ${U.formatDuration(performance.now() - t0)}.` });
      if (SV.state.settings.autoDownload) U.downloadBlob(blob, filename);
    } catch (err) {
      SV.UI.toast({ type: 'error', message: err.message || 'Could not encrypt this folder.' });
    } finally {
      if (e.encryptBtn) e.encryptBtn.disabled = false;
    }
  }

  function downloadEncResult() {
    if (!pendingEncResult) return;
    U.downloadBlob(pendingEncResult.blob, pendingEncResult.filename);
  }

  function onDecFilePicked(fileList) {
    const e = els();
    const file = fileList && fileList[0];
    if (!file) return;
    pendingDecFile = file;
    pendingDecResult = null;
    if (e.decSummary) {
      e.decSummary.hidden = false;
      e.decSummary.textContent = `${file.name} · ${U.formatBytes(file.size)}`;
    }
    if (e.decResultWrap) e.decResultWrap.hidden = true;
    if (e.decryptBtn) e.decryptBtn.disabled = false;
  }

  async function handleDecryptFolder() {
    const e = els();
    if (!pendingDecFile) {
      SV.UI.toast({ type: 'error', message: 'Choose an encrypted (.enc) file first.' });
      return;
    }
    if (!SV.KeyManager.hasKey()) {
      SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
      SV.UI.switchTab('keys');
      return;
    }

    if (e.decryptBtn) e.decryptBtn.disabled = true;
    if (e.decProgressWrap) e.decProgressWrap.hidden = false;
    if (e.decResultWrap) e.decResultWrap.hidden = true;
    const t0 = performance.now();
    try {
      const result = await decryptFolder({
        key: SV.state.key,
        blob: pendingDecFile,
        onProgress: (p) => {
          if (e.decProgressBar) e.decProgressBar.style.width = `${Math.round(U.clamp(p.fraction, 0, 1) * 100)}%`;
          if (e.decProgressLabel) e.decProgressLabel.textContent = 'Decrypting…';
        },
      });
      pendingDecResult = result;
      if (e.decResultWrap) e.decResultWrap.hidden = false;
      if (e.decResultLabel) e.decResultLabel.textContent = `${result.filename} · ${U.formatBytes(result.blob.size)}`;
      if (e.decProgressLabel) e.decProgressLabel.textContent = 'Done — integrity verified.';
      SV.UI.stat('foldersDecrypted', 1);
      SV.UI.stat('bytesDecrypted', result.blob.size);
      SV.UI.logActivity({ type: 'folder-decrypt', label: 'Decrypted a folder archive', detail: result.filename });
      SV.UI.toast({ type: 'success', message: `Decrypted in ${U.formatDuration(performance.now() - t0)}. Extract the .zip to restore the folder.` });
      if (SV.state.settings.autoDownload) U.downloadBlob(result.blob, result.filename);
    } catch (err) {
      SV.UI.toast({ type: 'error', message: err.message || 'Could not decrypt this file.' });
    } finally {
      if (e.decryptBtn) e.decryptBtn.disabled = false;
    }
  }

  function downloadDecResult() {
    if (!pendingDecResult) return;
    U.downloadBlob(pendingDecResult.blob, pendingDecResult.filename);
  }

  function init() {
    const e = els();
    if (e.pickerBtn && e.pickerInput) {
      e.pickerBtn.addEventListener('click', () => e.pickerInput.click());
      e.pickerInput.addEventListener('change', () => onFolderPicked(e.pickerInput.files));
    }
    if (e.encryptBtn) e.encryptBtn.addEventListener('click', handleEncryptFolder);
    if (e.downloadBtn) e.downloadBtn.addEventListener('click', downloadEncResult);

    if (e.decPickerBtn && e.decPickerInput) {
      e.decPickerBtn.addEventListener('click', () => e.decPickerInput.click());
      e.decPickerInput.addEventListener('change', () => onDecFilePicked(e.decPickerInput.files));
    }
    if (e.decryptBtn) e.decryptBtn.addEventListener('click', handleDecryptFolder);
    if (e.decDownloadBtn) e.decDownloadBtn.addEventListener('click', downloadDecResult);
  }

  return {
    buildZip,
    collectEntries,
    encryptFolder,
    decryptFolder,
    crc32, // exported for tests
    init,
  };
})();
