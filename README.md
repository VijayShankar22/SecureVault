# SecureVault

**Offline AES-256-GCM file, folder, and text encryption — 100% client-side.**

SecureVault is a single-page web app that encrypts and decrypts files, folders, and text entirely inside your browser using the native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). There is no backend, no server, no API, and no build step. Once the page is loaded, it needs no network connection at all — you can verify this yourself by disconnecting from the internet and using it normally.

- **No servers, no accounts, no telemetry.** Nothing is ever uploaded, tracked, or logged.
- **No CDN dependencies.** Every file needed to run the app is in this folder.
- **No frameworks.** Vanilla HTML5 / CSS3 / ES2023, split into small, single-purpose modules.
- **Keys are never stored.** A key lives only in page memory for as long as the tab is open.

## Quick start

The simplest way to run it: open `index.html` directly in a modern browser (double-click it, or drag it into a browser window).

Some browsers restrict the Web Crypto API on pages opened directly from disk (`file://`). If you see a "Web Crypto API isn't available" screen, serve the folder instead:

```bash
cd securevault
python3 -m http.server 8000
```

Then open `http://localhost:8000` — everything still runs 100% locally; this just satisfies the browser's secure-context requirement.

## What it does

| Tab | What it's for |
|---|---|
| **Dashboard** | Session stats, recent activity, quick links to the other tabs |
| **File Encryption** | Drag-and-drop or browse for any file(s); encrypt to `.enc`, decrypt back, or verify integrity without saving |
| **Folder Encryption** | Pick a folder; it's packed into a `.zip` and the whole archive is encrypted in one `.enc` file |
| **Text Encryption** | Encrypt a message to a Base64 blob you can paste anywhere, or decrypt one back |
| **Key Manager** | Generate a random AES-256 key, view it as Base64/hex, copy/download/import/clear it |
| **Settings** | Theme, auto-download, overwrite confirmation, metadata display, chunk size |
| **About** | How it works, FAQ, privacy notes, keyboard shortcuts |

## How the cryptography works

- **Algorithm:** AES-256-GCM only, via `crypto.subtle` — this app never implements its own cipher. GCM is an [AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption) construction, so every chunk is encrypted *and* authenticated: a wrong key, a flipped bit, a truncated file, or data spliced from another file all cause decryption to fail loudly rather than silently returning garbage.
- **Keys:** a random 256-bit key from `crypto.getRandomValues()` — never derived from a typed password. Export as Base64 or hex; import either format, or a downloaded `.key` file.
- **Large files:** encrypted in independently-authenticated chunks (16 MB by default, configurable in Settings) instead of one giant buffer, so multi-gigabyte files don't need to fit in memory at once and the page never freezes. Each chunk gets a unique nonce (a random 8-byte per-file base + a 4-byte counter — the same "STREAM" technique used by tools like `age`) and is cryptographically bound to the file's header and its position in the sequence via AES-GCM's additional authenticated data (AAD), so chunks can't be silently reordered, duplicated, or moved between two different encrypted files.
- **Container format** (`.enc`): magic bytes, version, content type, filename, MIME type, IV material, a chunk table, then the length-prefixed chunks themselves. See `crypto.js` for the exact byte layout — it's fully commented.
- **Folders:** packed into a standard ZIP archive (Store method — no compression, see the FAQ in the app for why) using a small dependency-free ZIP writer, then the whole archive is encrypted as one file. Decrypting a folder `.enc` gives you back a normal `.zip`; extract it with your OS to restore the folder structure.

## Project structure

```
index.html      Page shell: all 7 tab panels, wired to the exact IDs the JS below expects
style.css       Design system: theming (dark/light/high-contrast), layout, every component
utils.js        Dependency-free helpers (Base64/hex, formatting, DOM helpers) — no crypto, no DOM-unsafe code
crypto.js       The cryptographic core: key generation/import/export, chunked encrypt/decrypt, container format
keyManager.js   Key Manager tab: generate/copy/download/import/clear, owns the in-memory key state
file.js         File Encryption tab: drag & drop, multi-file list, per-file progress/actions, search
folder.js       Folder Encryption tab + the ZIP writer (CRC-32, local/central headers, EOCD)
text.js         Text Encryption tab
ui.js           Shared chrome: tabs, theme, toasts, modals, icon set, dashboard, settings, shortcuts
script.js       Entry point: shared app state + module init order
```

Everything is loaded as classic `<script>` tags (no ES modules, no bundler) sharing one `window.SV` namespace, specifically so the app keeps working when opened directly from disk.

## Security notes

- SecureVault delegates all actual cryptography to the browser's built-in, independently-audited Web Crypto API. The application code itself has **not** been through a formal third-party security audit — for extremely high-stakes secrets, consider pairing this with (or using instead) a long-established, audited tool.
- If you lose your key, your data is **permanently unrecoverable**. There is no backdoor, no password reset, and no recovery mechanism — that's the point of real encryption. Save your key before closing the tab.
- Only non-sensitive settings (theme, UI preferences) are ever written to `localStorage`. Keys are never written to `localStorage`, `sessionStorage`, `IndexedDB`, or a cookie, under any circumstance.
- The page ships a strict `Content-Security-Policy` (`connect-src 'none'`, no external scripts/frames/objects) so that, even inspected line by line, there is no code path capable of making a network request.

## Browser support

Any current version of Chrome, Firefox, Edge, or Safari with Web Crypto API support (all of them, as of any recent release). Mobile browsers work too; very large files may be limited by your device's available memory.

## License

No license restrictions — use, modify, and redistribute freely.
