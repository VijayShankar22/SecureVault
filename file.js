/**
 * file.js
 * ---------------------------------------------------------------------------
 * SecureVault — File Encryption tab.
 *
 * Owns SV.state.files (the working list of rows shown in the UI) and all
 * DOM for that list. Delegates the actual cryptography to crypto.js and
 * shared chrome (toasts, modals, stats, activity log) to ui.js.
 *
 * A note on safe rendering: filenames come from the user's filesystem (or,
 * on decrypt, from inside a file someone else sent them) and are never
 * trusted as markup. Every user-controlled string in this file reaches the
 * DOM exclusively via `.textContent`, never via innerHTML string
 * interpolation — so a maliciously crafted filename cannot inject HTML/JS
 * into the page.
 * ---------------------------------------------------------------------------
 */

window.SV = window.SV || {};

SV.Files = (function () {
  'use strict';

  const U = SV.Utils;
  const C = SV.Crypto;

  const LARGE_FILE_WARN_BYTES = 250 * 1024 * 1024; // 250 MB

  let searchTerm = '';
  let renderQueued = false;

  function els() {
    return {
      dropzone: document.getElementById('file-dropzone'),
      browseBtn: document.getElementById('btn-browse-files'),
      fileInput: document.getElementById('input-browse-files'),
      list: document.getElementById('file-list'),
      emptyState: document.getElementById('file-list-empty'),
      searchInput: document.getElementById('file-search'),
      encryptAllBtn: document.getElementById('btn-encrypt-all'),
      decryptAllBtn: document.getElementById('btn-decrypt-all'),
      clearAllBtn: document.getElementById('btn-clear-files'),
      countLabel: document.getElementById('file-count-label'),
    };
  }

  function categoryForExt(ext) {
    if (['png', 'jpg', 'jpeg', 'gif', 'webp', 'svg', 'bmp', 'heic', 'tiff', 'avif'].includes(ext)) return 'image';
    if (['mp4', 'mov', 'avi', 'mkv', 'webm', 'm4v'].includes(ext)) return 'video';
    if (['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a'].includes(ext)) return 'audio';
    if (ext === 'pdf') return 'pdf';
    if (['zip', 'rar', '7z', 'tar', 'gz', 'iso', 'bz2'].includes(ext)) return 'archive';
    if (['js', 'ts', 'py', 'java', 'c', 'cpp', 'rs', 'go', 'rb', 'php', 'html', 'css', 'json', 'sh', 'jsx', 'tsx'].includes(ext)) return 'code';
    if (ext === 'enc') return 'encrypted';
    return 'generic';
  }

  function guessDirection(filename) {
    return U.getExtension(filename) === 'enc' ? 'decrypt' : 'encrypt';
  }

  function describeError(err) {
    return (err && err.message) || 'Something went wrong processing this file.';
  }

  function addFiles(fileList) {
    const incoming = Array.from(fileList || []);
    for (const file of incoming) {
      SV.state.files.push({
        id: U.uuid(),
        file,
        name: file.name,
        size: file.size,
        mime: file.type || '',
        ext: U.getExtension(file.name),
        direction: guessDirection(file.name),
        status: 'pending', // pending | processing | done | error | verified
        phaseLabel: '',
        etaLabel: '',
        progress: 0,
        resultBlob: null,
        resultFilename: null,
        error: null,
        durationMs: null,
        warnedLarge: false,
      });
    }
    renderList();
  }

  function removeRow(id) {
    SV.state.files = SV.state.files.filter((r) => r.id !== id);
    renderList();
  }

  function clearAll() {
    SV.state.files = [];
    renderList();
  }

  async function ensureKeyOrRedirect() {
    if (SV.KeyManager.hasKey()) return true;
    SV.UI.toast({ type: 'error', message: 'Generate or import a key first.' });
    SV.UI.switchTab('keys');
    return false;
  }

  async function confirmLargeIfNeeded(row) {
    if (row.file.size <= LARGE_FILE_WARN_BYTES || row.warnedLarge) return true;
    const ok = await SV.UI.confirm({
      title: 'Large file',
      message: `${row.name} is ${U.formatBytes(row.file.size)}. Processing large files can take a while and uses meaningful memory. Continue?`,
      confirmLabel: 'Continue',
    });
    if (ok) row.warnedLarge = true;
    return ok;
  }

  function makeProgressHandler(row, t0) {
    return (p) => {
      row.progress = p.processedBytes / Math.max(1, p.totalBytes);
      const elapsed = performance.now() - t0;
      if (row.progress > 0.03 && row.progress < 0.999) {
        const totalEst = elapsed / row.progress;
        row.etaLabel = `~${U.formatDuration(Math.max(0, totalEst - elapsed))} remaining`;
      } else {
        row.etaLabel = '';
      }
      queueRender();
    };
  }

  async function encryptRow(row) {
    if (!(await ensureKeyOrRedirect())) return;
    if (!(await confirmLargeIfNeeded(row))) return;

    row.status = 'processing';
    row.phaseLabel = 'Encrypting…';
    row.progress = 0;
    row.error = null;
    renderList();

    const t0 = performance.now();
    try {
      const chunkSize = (SV.state.settings.chunkSizeMB || 16) * 1024 * 1024;
      const blob = await C.encrypt({
        key: SV.state.key,
        filename: row.name,
        mime: row.mime || 'application/octet-stream',
        contentType: C.ContentType.FILE,
        source: C.blobSource(row.file),
        chunkSize,
        onProgress: makeProgressHandler(row, t0),
      });
      row.resultBlob = blob;
      row.resultFilename = U.sanitizeFilename(row.name) + '.enc';
      row.status = 'done';
      row.durationMs = performance.now() - t0;
      SV.UI.stat('filesEncrypted', 1);
      SV.UI.stat('bytesEncrypted', row.file.size);
      SV.UI.logActivity({ type: 'file-encrypt', label: `Encrypted ${row.name}`, detail: U.formatBytes(row.file.size) });
      SV.UI.toast({ type: 'success', message: `Encrypted ${row.name} in ${U.formatDuration(row.durationMs)}.` });
      if (SV.state.settings.autoDownload) U.downloadBlob(row.resultBlob, row.resultFilename);
    } catch (err) {
      row.status = 'error';
      row.error = describeError(err);
      SV.UI.toast({ type: 'error', message: `${row.name}: ${row.error}` });
    }
    renderList();
  }

  async function decryptRow(row, { verifyOnly = false } = {}) {
    if (!(await ensureKeyOrRedirect())) return;
    if (!(await confirmLargeIfNeeded(row))) return;

    row.status = 'processing';
    row.phaseLabel = verifyOnly ? 'Verifying…' : 'Decrypting…';
    row.progress = 0;
    row.error = null;
    renderList();

    const t0 = performance.now();
    try {
      const result = await C.decryptBlob(SV.state.key, row.file, makeProgressHandler(row, t0));
      row.durationMs = performance.now() - t0;
      row.etaLabel = '';

      if (verifyOnly) {
        row.status = 'verified';
        SV.UI.toast({
          type: 'success',
          message: `${row.name}: integrity verified ✓ — decrypts to "${result.filename}" (${U.formatBytes(result.blob.size)}).`,
        });
        SV.UI.logActivity({ type: 'file-decrypt', label: `Verified ${row.name}`, detail: 'Integrity check passed' });
      } else {
        row.resultBlob = result.blob;
        row.resultFilename = U.sanitizeFilename(result.filename || U.stripExtension(row.name, 'enc') || 'decrypted_file');
        row.status = 'done';
        SV.UI.stat('filesDecrypted', 1);
        SV.UI.stat('bytesDecrypted', result.blob.size);
        SV.UI.logActivity({ type: 'file-decrypt', label: `Decrypted ${row.name}`, detail: row.resultFilename });
        SV.UI.toast({ type: 'success', message: `Decrypted ${row.name} in ${U.formatDuration(row.durationMs)} — integrity verified.` });
        if (SV.state.settings.autoDownload) U.downloadBlob(row.resultBlob, row.resultFilename);
      }
    } catch (err) {
      row.status = 'error';
      row.error = describeError(err);
      SV.UI.toast({ type: 'error', message: `${row.name}: ${row.error}` });
    }
    renderList();
  }

  function downloadRow(row) {
    if (!row.resultBlob) return;
    U.downloadBlob(row.resultBlob, row.resultFilename);
  }

  async function processAll(direction) {
    const rows = SV.state.files.filter((r) => r.direction === direction && r.status !== 'processing' && r.status !== 'done');
    for (const row of rows) {
      if (direction === 'encrypt') await encryptRow(row);
      else await decryptRow(row);
    }
  }

  function queueRender() {
    if (renderQueued) return;
    renderQueued = true;
    requestAnimationFrame(() => {
      renderQueued = false;
      renderList();
    });
  }

  // ---- Rendering -----------------------------------------------------------

  function rowSkeleton() {
    const el = document.createElement('div');
    el.className = 'file-row';
    el.innerHTML =
      '<div class="file-row-icon" aria-hidden="true"></div>' +
      '<div class="file-row-main">' +
      '<div class="file-row-top"><span class="file-row-name"></span><span class="file-row-badge"></span></div>' +
      '<div class="file-row-meta"></div>' +
      '<div class="file-row-progress" hidden><div class="file-row-progress-bar"></div></div>' +
      '<div class="file-row-error" role="alert" hidden></div>' +
      '</div>' +
      '<div class="file-row-actions"></div>';
    return el;
  }

  function makeActionBtn(label, cls, iconName, onClick) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = `btn btn-icon-sm ${cls}`;
    btn.title = label;
    btn.setAttribute('aria-label', label);
    btn.innerHTML = SV.UI.icon(iconName);
    btn.addEventListener('click', onClick);
    return btn;
  }

  function buildActions(row) {
    const wrap = document.createElement('div');
    wrap.className = 'file-row-actions';

    if (row.status === 'processing') {
      const spinner = document.createElement('span');
      spinner.className = 'spinner spinner-sm';
      spinner.setAttribute('role', 'status');
      spinner.setAttribute('aria-label', 'Processing');
      wrap.appendChild(spinner);
      return wrap;
    }

    if (row.status === 'done' && row.resultBlob) {
      wrap.appendChild(makeActionBtn('Download result', 'btn-primary', 'download', () => downloadRow(row)));
    } else if (row.direction === 'encrypt') {
      wrap.appendChild(makeActionBtn('Encrypt', 'btn-primary', 'lock', () => encryptRow(row)));
    } else {
      wrap.appendChild(makeActionBtn('Decrypt', 'btn-primary', 'unlock', () => decryptRow(row)));
      wrap.appendChild(makeActionBtn('Verify integrity only (no download)', 'btn-ghost', 'shield', () => decryptRow(row, { verifyOnly: true })));
    }
    wrap.appendChild(makeActionBtn('Remove from list', 'btn-ghost btn-danger-ghost', 'close', () => removeRow(row.id)));
    return wrap;
  }

  function renderRow(row) {
    const el = rowSkeleton();
    el.dataset.id = row.id;

    el.querySelector('.file-row-icon').innerHTML = SV.UI.icon(categoryForExt(row.ext));
    el.querySelector('.file-row-name').textContent = row.name;

    const badge = el.querySelector('.file-row-badge');
    badge.textContent = row.direction === 'encrypt' ? 'Encrypt' : 'Decrypt';
    badge.classList.add(row.direction === 'encrypt' ? 'badge-encrypt' : 'badge-decrypt');

    const metaBits = [U.formatBytes(row.size)];
    if (SV.state.settings.showMetadata && row.mime) metaBits.push(row.mime);
    if (row.status === 'processing') metaBits.push(row.phaseLabel, row.etaLabel);
    if (row.status === 'done' && row.durationMs != null) metaBits.push(`Done in ${U.formatDuration(row.durationMs)}`);
    if (row.status === 'verified') metaBits.push('Integrity verified ✓');
    el.querySelector('.file-row-meta').textContent = metaBits.filter(Boolean).join(' · ');

    const progressWrap = el.querySelector('.file-row-progress');
    const progressBar = el.querySelector('.file-row-progress-bar');
    if (row.status === 'processing') {
      progressWrap.hidden = false;
      progressBar.style.width = `${Math.round(U.clamp(row.progress, 0, 1) * 100)}%`;
    }

    const errorEl = el.querySelector('.file-row-error');
    if (row.status === 'error' && row.error) {
      errorEl.hidden = false;
      errorEl.textContent = row.error;
    }

    el.classList.toggle('is-error', row.status === 'error');
    el.classList.toggle('is-done', row.status === 'done' || row.status === 'verified');

    el.querySelector('.file-row-actions').replaceWith(buildActions(row));
    return el;
  }

  function renderList() {
    const e = els();
    if (!e.list) return;

    const term = searchTerm.trim().toLowerCase();
    const visible = SV.state.files.filter((r) => !term || r.name.toLowerCase().includes(term));

    e.list.innerHTML = '';
    const frag = document.createDocumentFragment();
    for (const row of visible) frag.appendChild(renderRow(row));
    e.list.appendChild(frag);

    const total = SV.state.files.length;
    if (e.emptyState) e.emptyState.hidden = total > 0;
    e.list.hidden = total === 0;

    if (e.countLabel) {
      e.countLabel.textContent = total ? `${visible.length} of ${total} file${total === 1 ? '' : 's'}` : '';
    }

    const hasEncryptable = SV.state.files.some((r) => r.direction === 'encrypt' && r.status !== 'done');
    const hasDecryptable = SV.state.files.some((r) => r.direction === 'decrypt' && r.status !== 'done');
    if (e.encryptAllBtn) e.encryptAllBtn.hidden = !hasEncryptable;
    if (e.decryptAllBtn) e.decryptAllBtn.hidden = !hasDecryptable;
    if (e.clearAllBtn) e.clearAllBtn.hidden = total === 0;
  }

  function wireDropzone(dropzone) {
    let dragDepth = 0;
    ['dragenter', 'dragover'].forEach((evt) => {
      dropzone.addEventListener(evt, (e) => {
        e.preventDefault();
        e.stopPropagation();
        if (evt === 'dragenter') dragDepth++;
        dropzone.classList.add('is-dragover');
      });
    });
    dropzone.addEventListener('dragleave', (e) => {
      e.preventDefault();
      dragDepth = Math.max(0, dragDepth - 1);
      if (dragDepth === 0) dropzone.classList.remove('is-dragover');
    });
    dropzone.addEventListener('drop', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dragDepth = 0;
      dropzone.classList.remove('is-dragover');
      if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length) {
        addFiles(e.dataTransfer.files);
      }
    });
  }

  function init() {
    const e = els();
    if (e.dropzone) {
      wireDropzone(e.dropzone);
      e.dropzone.addEventListener('click', () => e.fileInput && e.fileInput.click());
      e.dropzone.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter' || ev.key === ' ') {
          ev.preventDefault();
          e.fileInput && e.fileInput.click();
        }
      });
    }
    if (e.browseBtn && e.fileInput) {
      e.browseBtn.addEventListener('click', (ev) => {
        ev.stopPropagation();
        e.fileInput.click();
      });
      e.fileInput.addEventListener('change', () => {
        addFiles(e.fileInput.files);
        e.fileInput.value = '';
      });
    }
    if (e.searchInput) {
      e.searchInput.addEventListener(
        'input',
        U.debounce(() => {
          searchTerm = e.searchInput.value;
          renderList();
        }, 120)
      );
    }
    if (e.encryptAllBtn) e.encryptAllBtn.addEventListener('click', () => processAll('encrypt'));
    if (e.decryptAllBtn) e.decryptAllBtn.addEventListener('click', () => processAll('decrypt'));
    if (e.clearAllBtn) {
      e.clearAllBtn.addEventListener('click', async () => {
        const ok = await SV.UI.confirm({
          title: 'Clear file list?',
          message: 'This removes every file from the list. Any results you have not downloaded yet will be lost.',
          confirmLabel: 'Clear list',
          danger: true,
        });
        if (ok) clearAll();
      });
    }
    renderList();
  }

  return { init, addFiles, renderList };
})();
