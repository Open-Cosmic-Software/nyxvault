/* NyxVault — Client-Side E2E Encryption 🔐🦞 */
/* v2: Chunked encryption, reduced Argon2, progressive download */
'use strict';

// ── Crypto Helpers (self-hosted libs: nacl + argon2) ─────
const SALT_BYTES = 16;
const NONCE_BYTES = 24; // XSalsa20-Poly1305 = secretbox
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC2 = new Uint8Array([0x4E, 0x59, 0x58, 0x32]); // "NYX2" (legacy)
const MAGIC3 = new Uint8Array([0x4E, 0x59, 0x58, 0x33]); // "NYX3" (integrity-protected)
const SECRETBOX_OVERHEAD = 16; // Poly1305 tag
const CHUNK_PREFIX_BYTES = 5; // 4-byte index BE + 1-byte is_last flag

// Argon2id key derivation (using hash-wasm) — 16 MB (was 64 MB)
async function deriveKey(passphrase, salt) {
  const key = await hashwasm.argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16MB — still secure (OWASP min: 15MB)
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

function generateSalt() {
  return nacl.randomBytes(SALT_BYTES);
}

function generateNonce() {
  return nacl.randomBytes(NONCE_BYTES);
}

// Check blob format
function isNYX2(data) {
  return data.length >= 4 && data[0] === 0x4E && data[1] === 0x59 && data[2] === 0x58 && data[3] === 0x32;
}
function isNYX3(data) {
  return data.length >= 4 && data[0] === 0x4E && data[1] === 0x59 && data[2] === 0x58 && data[3] === 0x33;
}
function isChunkedFormat(data) {
  return isNYX2(data) || isNYX3(data);
}

// ── HMAC-SHA256 via Web Crypto ─────
async function hmacSHA256(key, data) {
  const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', cryptoKey, data);
  return new Uint8Array(sig);
}

// Derive a separate subkey for HMAC (domain separation from encryption key)
async function deriveHMACKey(encKey) {
  return await hmacSHA256(encKey, new TextEncoder().encode('nyxvault-header-auth'));
}

// ── Chunked Encrypt (NYX3 format — integrity-protected) ─────
// Format: NYX3(4) + salt(16) + header_hmac(32) + num_chunks(4 BE) + [nonce(24) + ciphertext]...
// Each chunk plaintext is prefixed with: chunk_index(4 BE) + is_last(1)
//
// `keyProvider` (optional): async (salt) => Uint8Array(32). When supplied (e.g.
// passkey mode), it derives the key from the per-file salt instead of Argon2id.
// The blob format is byte-identical either way — only the key SOURCE changes.
async function encryptDataChunked(data, passphrase, onProgress, keyProvider) {
  const salt = generateSalt();
  const key = keyProvider ? await keyProvider(salt) : await deriveKey(passphrase, salt);
  const hmacKey = await deriveHMACKey(key);
  const numChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));

  // Build header bytes for HMAC: magic + salt + num_chunks
  const headerForHMAC = new Uint8Array(4 + SALT_BYTES + 4);
  headerForHMAC.set(MAGIC3, 0);
  headerForHMAC.set(salt, 4);
  headerForHMAC[4 + SALT_BYTES] = (numChunks >>> 24) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 1] = (numChunks >>> 16) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 2] = (numChunks >>> 8) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 3] = numChunks & 0xFF;
  const headerHMAC = await hmacSHA256(hmacKey, headerForHMAC);

  // Calculate total size: magic(4) + salt(16) + hmac(32) + num_chunks(4) + chunks
  let totalSize = 4 + SALT_BYTES + 32 + 4;
  for (let i = 0; i < numChunks; i++) {
    const chunkLen = Math.min(CHUNK_SIZE, data.length - i * CHUNK_SIZE);
    // Each chunk plaintext gets 5-byte prefix → encrypted size = prefix + data + overhead
    totalSize += NONCE_BYTES + CHUNK_PREFIX_BYTES + chunkLen + SECRETBOX_OVERHEAD;
  }

  const result = new Uint8Array(totalSize);
  let offset = 0;

  // Write magic
  result.set(MAGIC3, offset); offset += 4;
  // Write salt
  result.set(salt, offset); offset += SALT_BYTES;
  // Write header HMAC
  result.set(headerHMAC, offset); offset += 32;
  // Write num_chunks (big-endian uint32)
  result[offset] = (numChunks >>> 24) & 0xFF;
  result[offset+1] = (numChunks >>> 16) & 0xFF;
  result[offset+2] = (numChunks >>> 8) & 0xFF;
  result[offset+3] = numChunks & 0xFF;
  offset += 4;

  // Encrypt each chunk with index prefix
  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunkData = data.slice(start, end);
    const isLast = (i === numChunks - 1) ? 1 : 0;

    // Prepend 5-byte prefix: chunk_index(4 BE) + is_last(1)
    const prefixedChunk = new Uint8Array(CHUNK_PREFIX_BYTES + chunkData.length);
    prefixedChunk[0] = (i >>> 24) & 0xFF;
    prefixedChunk[1] = (i >>> 16) & 0xFF;
    prefixedChunk[2] = (i >>> 8) & 0xFF;
    prefixedChunk[3] = i & 0xFF;
    prefixedChunk[4] = isLast;
    prefixedChunk.set(chunkData, CHUNK_PREFIX_BYTES);

    const nonce = generateNonce();
    const encrypted = nacl.secretbox(prefixedChunk, nonce, key);
    result.set(nonce, offset); offset += NONCE_BYTES;
    result.set(encrypted, offset); offset += encrypted.length;
    if (onProgress) onProgress(i + 1, numChunks);
  }

  return { blob: result, salt };
}

// ── Chunked Decrypt (NYX3 format — integrity-verified) ─────
async function decryptDataNYX3(data, passphrase, onProgress, keyProvider) {
  let offset = 4; // skip magic
  const salt = data.slice(offset, offset + SALT_BYTES); offset += SALT_BYTES;
  const storedHMAC = data.slice(offset, offset + 32); offset += 32;
  const numChunks = (data[offset] << 24) | (data[offset+1] << 16) | (data[offset+2] << 8) | data[offset+3];
  offset += 4;

  const key = keyProvider ? await keyProvider(salt) : await deriveKey(passphrase, salt);
  const hmacKey = await deriveHMACKey(key);

  // Verify header HMAC
  const headerForHMAC = new Uint8Array(4 + SALT_BYTES + 4);
  headerForHMAC.set(MAGIC3, 0);
  headerForHMAC.set(salt, 4);
  headerForHMAC[4 + SALT_BYTES] = (numChunks >>> 24) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 1] = (numChunks >>> 16) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 2] = (numChunks >>> 8) & 0xFF;
  headerForHMAC[4 + SALT_BYTES + 3] = numChunks & 0xFF;
  const expectedHMAC = await hmacSHA256(hmacKey, headerForHMAC);

  // Constant-time-ish comparison
  let hmacMatch = true;
  for (let j = 0; j < 32; j++) { if (storedHMAC[j] !== expectedHMAC[j]) hmacMatch = false; }
  if (!hmacMatch) throw new Error('Decryption failed – wrong passphrase?');

  const chunks = [];
  let totalDecrypted = 0;

  for (let i = 0; i < numChunks; i++) {
    const nonce = data.slice(offset, offset + NONCE_BYTES); offset += NONCE_BYTES;
    // NYX3 ciphertext includes the 5-byte prefix
    let ciphertextLen;
    if (i < numChunks - 1) {
      ciphertextLen = CHUNK_PREFIX_BYTES + CHUNK_SIZE + SECRETBOX_OVERHEAD;
    } else {
      ciphertextLen = data.length - offset;
    }
    const ciphertext = data.slice(offset, offset + ciphertextLen); offset += ciphertextLen;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) throw new Error('Decryption failed – wrong passphrase?');

    // Verify chunk prefix
    const chunkIdx = (decrypted[0] << 24) | (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
    const isLast = decrypted[4];
    if (chunkIdx !== i) throw new Error('Integrity error: chunk order mismatch');
    if (i === numChunks - 1 && isLast !== 1) throw new Error('Integrity error: missing final chunk marker');
    if (i < numChunks - 1 && isLast !== 0) throw new Error('Integrity error: premature final chunk marker');

    // Strip prefix, keep only actual data
    const actualData = decrypted.slice(CHUNK_PREFIX_BYTES);
    chunks.push(actualData);
    totalDecrypted += actualData.length;
    if (onProgress) onProgress(i + 1, numChunks);
  }

  // Explicit truncation guard: verify we consumed all data and saw exactly one final chunk
  if (offset !== data.length) throw new Error('Integrity error: unexpected trailing data');
  if (chunks.length !== numChunks) throw new Error('Integrity error: chunk count mismatch');

  const result = new Uint8Array(totalDecrypted);
  let pos = 0;
  for (const chunk of chunks) { result.set(chunk, pos); pos += chunk.length; }
  return result;
}



// ── Encrypt (auto-selects chunked for large files, legacy for small strings) ─────
async function encryptData(data, passphrase, onProgress, keyProvider) {
  // Always use chunked format for files
  return encryptDataChunked(data, passphrase, onProgress, keyProvider);
}

// Helper: derive key with specific memory size
async function deriveKeyWithMem(passphrase, salt, memorySize) {
  const key = await hashwasm.argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: memorySize,
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

// ── Decrypt (auto-detects format) ─────
async function decryptData(encryptedBlob, passphrase, onProgress, keyProvider) {
  if (isNYX3(encryptedBlob)) {
    return decryptDataNYX3(encryptedBlob, passphrase, onProgress, keyProvider);
  }
  if (isNYX2(encryptedBlob)) {
    throw new Error('This file uses the legacy NYX2 format without integrity protection. Migrate it to NYX3 first using: node nyx-migrate.js <file> <passphrase>');
  }
  // Legacy format — try 16MB first, then 64MB for old files
  const salt = encryptedBlob.slice(0, SALT_BYTES);
  const nonce = encryptedBlob.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = encryptedBlob.slice(SALT_BYTES + NONCE_BYTES);
  for (const mem of [16384, 65536]) {
    const key = await deriveKeyWithMem(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) return decrypted;
  }
  throw new Error('Decryption failed – wrong passphrase?');
}

// Encrypt a string (uses legacy format for small metadata — simpler).
// `keyProvider` (optional): async (salt) => Uint8Array(32) for passkey mode.
async function encryptString(str, passphrase, keyProvider) {
  const data = nacl.util.decodeUTF8(str);
  const salt = generateSalt();
  const key = keyProvider ? await keyProvider(salt) : await deriveKey(passphrase, salt);
  const nonce = generateNonce();
  const encrypted = nacl.secretbox(data, nonce, key);
  const result = new Uint8Array(salt.length + nonce.length + encrypted.length);
  result.set(salt, 0);
  result.set(nonce, salt.length);
  result.set(encrypted, salt.length + nonce.length);
  return nacl.util.encodeBase64(result);
}

// Decrypt a base64 string (legacy format, with Argon2 fallback).
// `keyProvider` (optional): async (salt) => Uint8Array(32) for passkey mode.
async function decryptString(b64, passphrase, keyProvider) {
  const data = nacl.util.decodeBase64(b64);
  const salt = data.slice(0, SALT_BYTES);
  const nonce = data.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES);
  const ciphertext = data.slice(SALT_BYTES + NONCE_BYTES);
  if (keyProvider) {
    const key = await keyProvider(salt);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) return nacl.util.encodeUTF8(decrypted);
    throw new Error('Decryption failed – wrong passkey?');
  }
  // Try 16MB first, then 64MB for old encrypted strings
  for (const mem of [16384, 65536]) {
    const key = await deriveKeyWithMem(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) return nacl.util.encodeUTF8(decrypted);
  }
  throw new Error('Decryption failed – wrong passphrase?');
}

// ── Progressive fetch with progress ─────
async function fetchWithProgress(url, onProgress) {
  const headers = {};
  if (sessionToken) headers['X-Session-Token'] = sessionToken;
  const response = await fetch(url, { headers });
  if (response.status === 401) { logout(); throw new Error('Session expired'); }
  if (!response.ok) throw new Error('Download failed (' + response.status + ')');
  const contentLength = +response.headers.get('Content-Length');
  if (!response.body || !contentLength) {
    // Fallback: no streaming support
    return new Uint8Array(await response.arrayBuffer());
  }
  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    received += value.length;
    if (onProgress) onProgress(received, contentLength);
  }
  const result = new Uint8Array(received);
  let pos = 0;
  for (const chunk of chunks) {
    result.set(chunk, pos);
    pos += chunk.length;
  }
  return result;
}

// ── State ─────────────────────────────────────────────────
let sessionToken = sessionStorage.getItem('nyxvault_session');
let vaultPassphrase = sessionStorage.getItem('nyxvault_passphrase');
let selectedFile = null;
let vaultPubkey = null;         // vault public key (base64) for envelope encryption
let passkeyRegistered = false;  // at least one passkey exists
let usePassphraseUpload = false; // explicit "use passphrase instead" toggle
let serverMaxFileMB = 100;      // server upload cap (from /api/settings)

// ── DOM refs ──────────────────────────────────────────────
const loginOverlay = document.getElementById('loginOverlay');
const loginForm = document.getElementById('loginForm');
const loginPassword = document.getElementById('loginPassword');
const loginPassphrase = document.getElementById('loginPassphrase');
const loginError = document.getElementById('loginError');
const loginBtn = document.getElementById('loginBtn');
const logoutBtn = document.getElementById('logoutBtn');
const appContent = document.getElementById('appContent');

const dropzone = document.getElementById('dropzone');
const fileInput = document.getElementById('fileInput');
const uploadOptions = document.getElementById('uploadOptions');
const selectedFileName = document.getElementById('selectedFileName');
const selectedFileSize = document.getElementById('selectedFileSize');
const expirySelect = document.getElementById('expirySelect');
const uploadBtn = document.getElementById('uploadBtn');
const cancelBtn = document.getElementById('cancelBtn');

const progressContainer = document.getElementById('progressContainer');
const progressFill = document.getElementById('progressFill');
const progressText = document.getElementById('progressText');

const fileListBody = document.getElementById('fileListBody');
const fileCount = document.getElementById('fileCount');
const emptyState = document.getElementById('emptyState');
const fileTable = document.getElementById('fileTable');

const toastContainer = document.getElementById('toastContainer');

// ── Custom dialogs (CSP-safe replacement for prompt/confirm) ─────
function nyxDialog({ title, message, input, inputType = 'text', inputValue = '', placeholder = '', okLabel = 'OK', cancelLabel = 'Cancel', danger = false }) {
  return new Promise((resolve) => {
    const root = document.getElementById('nyxModalRoot');
    const overlay = document.createElement('div');
    overlay.className = 'nyx-dialog-overlay';
    const box = document.createElement('div');
    box.className = 'nyx-dialog';

    const h = document.createElement('h3');
    h.textContent = title;
    box.appendChild(h);
    if (message) {
      const p = document.createElement('p');
      p.textContent = message;
      box.appendChild(p);
    }
    let inputEl = null;
    if (input) {
      inputEl = document.createElement('input');
      inputEl.type = inputType;
      inputEl.value = inputValue;
      inputEl.placeholder = placeholder;
      inputEl.autocomplete = 'off';
      box.appendChild(inputEl);
    }
    const actions = document.createElement('div');
    actions.className = 'nyx-dialog-actions';
    const cancelBtn = document.createElement('button');
    cancelBtn.className = 'btn-cancel';
    cancelBtn.type = 'button';
    cancelBtn.textContent = cancelLabel;
    const okBtn = document.createElement('button');
    okBtn.className = danger ? 'btn-danger' : 'btn-primary';
    okBtn.type = 'button';
    okBtn.textContent = okLabel;
    actions.append(cancelBtn, okBtn);
    box.appendChild(actions);
    overlay.appendChild(box);
    root.appendChild(overlay);

    function close(result) {
      overlay.remove();
      document.removeEventListener('keydown', onKey);
      resolve(result);
    }
    function ok() { close(input ? inputEl.value : true); }
    function cancel() { close(input ? null : false); }
    function onKey(e) {
      if (e.key === 'Escape') cancel();
      else if (e.key === 'Enter' && (input ? document.activeElement === inputEl : true)) ok();
    }
    okBtn.addEventListener('click', ok);
    cancelBtn.addEventListener('click', cancel);
    overlay.addEventListener('click', (e) => { if (e.target === overlay) cancel(); });
    document.addEventListener('keydown', onKey);
    if (inputEl) inputEl.focus(); else okBtn.focus();
  });
}
function nyxConfirm(title, message, opts = {}) {
  return nyxDialog({ title, message, okLabel: opts.okLabel || 'Confirm', danger: !!opts.danger });
}
function nyxPrompt(title, message, opts = {}) {
  return nyxDialog({ title, message, input: true, inputType: opts.type || 'text', inputValue: opts.value || '', placeholder: opts.placeholder || '', okLabel: opts.okLabel || 'OK' });
}

// ── Toast ─────────────────────────────────────────────────
function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.textContent = message;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Format helpers ────────────────────────────────────────
function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDate(dateStr) {
  const d = new Date(dateStr + 'Z');
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: '2-digit' }) +
    ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
}

// ── Auth ──────────────────────────────────────────────────
function showLogin() {
  loginOverlay.style.display = 'flex';
  appContent.style.display = 'none';
}

function showApp() {
  loginOverlay.style.display = 'none';
  appContent.style.display = 'block';
  loadFiles();
  loadPasskeySettings();
}

// ── Passkey settings + admin UI ───────────────────────────
async function loadPasskeySettings() {
  try {
    const s = await (await fetch('/api/settings')).json();
    vaultPubkey = s.vault_pubkey || null;
    passkeyRegistered = !!s.passkey_registered;
    if (s.max_file_size_mb) {
      serverMaxFileMB = s.max_file_size_mb;
      const hint = document.getElementById('dropzoneHint');
      if (hint) hint.textContent = 'Click to browse. Encryption happens locally before anything leaves your device. Max ' + (serverMaxFileMB >= 1024 ? (serverMaxFileMB / 1024).toFixed(0) + ' GB' : serverMaxFileMB + ' MB') + '.';
    }
    renderPasskeyUI();
    loadPasskeyList();
  } catch { /* settings are optional; ignore */ }
}

// Passkey mode is now the DEFAULT whenever a vault public key exists. There is
// no global on/off toggle any more — a file only becomes passphrase-only when
// the user EXPLICITLY chooses "use passphrase instead" at upload time.
function passkeyModeActive() {
  return !!vaultPubkey && !usePassphraseUpload;
}

function renderPasskeyUI() {
  const status = document.getElementById('passkeyStatus');
  const supportWarn = document.getElementById('passkeyUnsupported');
  const supported = window.NyxPasskey && window.NyxPasskey.supported();

  if (status) {
    status.textContent = passkeyRegistered
      ? '🔑 Passkey encryption is ON by default — every upload is decryptable with all your registered passkeys.'
      : 'No passkey registered yet — uploads use a passphrase. Register a passkey to enable passkey encryption.';
  }
  if (supportWarn) supportWarn.style.display = supported ? 'none' : 'block';
  renderUploadModeUI();
}

// Toggle the upload passphrase field depending on mode.
function renderUploadModeUI() {
  const pkActive = passkeyModeActive();
  const upPwRow = document.getElementById('uploadPassphraseRow');
  const upPwLabel = document.getElementById('uploadPassphraseLabel');
  const upPw = document.getElementById('uploadPassphrase');
  const pkNote = document.getElementById('passkeyUploadNote');
  const passphraseToggleRow = document.getElementById('usePassphraseRow');

  // Show the "use passphrase instead" toggle only when a passkey vault exists.
  if (passphraseToggleRow) passphraseToggleRow.style.display = (passkeyRegistered && vaultPubkey) ? 'flex' : 'none';

  const showPw = !pkActive; // passphrase field visible only in passphrase mode
  if (upPwRow) upPwRow.style.display = showPw ? 'flex' : 'none';
  if (upPwLabel) upPwLabel.style.display = showPw ? 'block' : 'none';
  if (upPw) upPw.required = showPw;
  if (pkNote) pkNote.style.display = pkActive ? 'block' : 'none';
}

// ── Passkey management table ──────────────────────────────
async function loadPasskeyList() {
  const wrap = document.getElementById('passkeyListWrap');
  if (!wrap) return;
  try {
    const res = await api('/api/passkeys');
    const data = await res.json();
    renderPasskeyList(data.passkeys || [], data.count || 0);
  } catch { /* ignore */ }
}

function renderPasskeyList(passkeys, count) {
  const wrap = document.getElementById('passkeyListWrap');
  const body = document.getElementById('passkeyListBody');
  if (!wrap || !body) return;
  if (!passkeys.length) { wrap.style.display = 'none'; return; }
  wrap.style.display = 'block';
  body.innerHTML = '';
  for (const pk of passkeys) {
    const tr = document.createElement('tr');
    tr.dataset.id = pk.id;

    const nameTd = document.createElement('td');
    const nameSpan = document.createElement('span');
    nameSpan.className = 'pk-name';
    nameSpan.textContent = '🔑 ' + (pk.label || 'Passkey');
    const chip = document.createElement('span');
    chip.className = 'pk-chip';
    chip.textContent = pk.cred_id_short + '…';
    chip.title = 'Credential ID (truncated)';
    nameTd.append(nameSpan, ' ', chip);

    const createdTd = document.createElement('td'); createdTd.className = 'meta';
    createdTd.textContent = pk.created_at ? formatDate(pk.created_at) : '—';
    const usedTd = document.createElement('td'); usedTd.className = 'meta';
    usedTd.textContent = pk.last_used ? formatDate(pk.last_used) : 'never';

    const actTd = document.createElement('td'); actTd.className = 'actions';
    actTd.innerHTML =
      '<button class="btn-icon" data-pk-act="rename" title="Rename">✏️</button>' +
      '<button class="btn-icon delete" data-pk-act="delete" title="Delete">🗑️</button>';

    tr.append(nameTd, createdTd, usedTd, actTd);
    body.appendChild(tr);
  }
}

async function renamePasskey(id) {
  const name = await nyxPrompt('Rename passkey', 'Choose a new name for this passkey.', { placeholder: 'e.g. iPhone, Laptop', okLabel: 'Rename' });
  if (!name || !name.trim()) return;
  try {
    const res = await api('/api/passkeys/' + id, {
      method: 'PATCH', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ label: name.trim() })
    });
    if (!res.ok) throw new Error((await res.json()).error || 'Rename failed');
    toast('Passkey renamed', 'success');
    loadPasskeyList();
  } catch (err) { toast(err.message, 'error'); }
}

async function deletePasskey(id) {
  try {
    let res = await api('/api/passkeys/' + id, { method: 'DELETE' });
    if (res.status === 409) {
      const info = await res.json();
      if (info.error === 'last_passkey') {
        const ok = await nyxConfirm('⚠️ Delete your LAST passkey?',
          'This will make ' + (info.affected_files ?? 'all') + ' passkey-encrypted file(s) permanently UNRECOVERABLE. The vault key cannot be unwrapped without a passkey.\n\nThis cannot be undone.',
          { okLabel: 'Delete forever', danger: true });
        if (!ok) return;
        res = await api('/api/passkeys/' + id + '?confirm=1', { method: 'DELETE' });
      }
    }
    if (!res.ok) throw new Error((await res.json()).error || 'Delete failed');
    toast('Passkey deleted', 'success');
    await loadPasskeySettings();
  } catch (err) { toast(err.message, 'error'); }
}

async function registerPasskey() {
  const btn = document.getElementById('registerPasskeyBtn');
  if (!window.NyxPasskey || !window.NyxPasskey.supported()) {
    toast('Passkeys are not supported by this browser', 'error');
    return;
  }
  if (btn) { btn.disabled = true; btn.textContent = 'Waiting for passkey…'; }
  // Registration may prompt the passkey up to THREE times: (optionally) an
  // existing passkey to unwrap the vault key, once to create the new passkey,
  // and once to verify its PRF and wrap the vault key. Warn the user.
  toast('You may be prompted a few times: to verify an existing passkey (if any), create the new one, and confirm encryption support.', 'info');
  try {
    const label = await nyxPrompt('Name this passkey', 'Pick a name so you can recognise this passkey later.', { value: navigator.platform || 'Passkey', placeholder: 'e.g. iPhone, Laptop', okLabel: 'Continue' });
    if (label === null) { return; }
    const res = await window.NyxPasskey.register(sessionToken, (label && label.trim()) || 'Passkey');
    toast(res.first ? 'First passkey registered — passkey encryption is now active! 🔑' : 'Passkey registered! 🔑', 'success');
    passkeyRegistered = true;
    await loadPasskeySettings();
  } catch (err) {
    toast('Passkey registration failed: ' + err.message, 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = '＋ Register Passkey'; }
  }
}

async function login() {
  const password = loginPassword.value.trim();
  const passphrase = loginPassphrase.value.trim();

  if (!password || !passphrase) {
    loginError.textContent = 'Both fields required';
    loginError.style.display = 'block';
    return;
  }

  loginBtn.disabled = true;
  loginBtn.textContent = 'Authenticating...';
  loginError.style.display = 'none';

  try {
    const res = await fetch('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });

    const data = await res.json();
    if (!res.ok) throw new Error(data.error || 'Login failed');

    sessionToken = data.token;
    vaultPassphrase = passphrase;
    sessionStorage.setItem('nyxvault_session', sessionToken);
    sessionStorage.setItem('nyxvault_passphrase', passphrase);

    toast('Logged in! 🔐', 'success');
    showApp();
  } catch (err) {
    loginError.textContent = err.message;
    loginError.style.display = 'block';
  } finally {
    loginBtn.disabled = false;
    loginBtn.textContent = 'Unlock Vault';
  }
}

function logout() {
  fetch('/auth/logout', {
    method: 'POST',
    headers: { 'X-Session-Token': sessionToken }
  }).catch(() => {});
  sessionToken = null;
  vaultPassphrase = null;
  sessionStorage.removeItem('nyxvault_session');
  sessionStorage.removeItem('nyxvault_passphrase');
  loginPassword.value = '';
  loginPassphrase.value = '';
  showLogin();
}

// ── API helper ────────────────────────────────────────────
async function api(path, options = {}) {
  const headers = { ...options.headers };
  if (sessionToken) headers['X-Session-Token'] = sessionToken;
  const res = await fetch(path, { ...options, headers });
  if (res.status === 401) {
    logout();
    throw new Error('Session expired');
  }
  return res;
}

// ── File List ─────────────────────────────────────────────
let currentPage = 1;
let totalPages = 1;
let filenameDecryptToken = 0; // cancels in-flight background decrypts on reload

async function loadFiles(page = currentPage) {
  try {
    const res = await api(`/api/files?page=${page}&limit=25`);
    const data = await res.json();
    currentPage = data.page || 1;
    totalPages = data.totalPages || 1;
    renderFiles(data.files, data.total);
    updatePagination(data.total);
  } catch (err) {
    if (err.message !== 'Session expired') {
      toast('Failed to load files', 'error');
    }
  }
}

function updatePagination(total) {
  const pag = document.getElementById('pagination');
  if (!pag) return;
  if (totalPages <= 1) { pag.style.display = 'none'; return; }
  pag.style.display = 'flex';
  document.getElementById('pageInfo').textContent = `Page ${currentPage} / ${totalPages} · ${total} files`;
  document.getElementById('prevPage').disabled = currentPage <= 1;
  document.getElementById('nextPage').disabled = currentPage >= totalPages;
}

// Render rows INSTANTLY (no Argon2 blocking). Filenames are decrypted lazily
// in the background — one at a time — and patched into each row as they resolve,
// so opening the admin page no longer waits on hundreds of key derivations.
function renderFiles(files, total) {
  fileListBody.innerHTML = '';
  fileCount.textContent = `${total != null ? total : files.length} file${(total != null ? total : files.length) !== 1 ? 's' : ''}`;

  if (files.length === 0) {
    emptyState.style.display = 'block';
    fileTable.style.display = 'none';
    return;
  }
  emptyState.style.display = 'none';
  fileTable.style.display = 'table';

  const myToken = ++filenameDecryptToken;
  const rows = [];

  for (const f of files) {
    const placeholder = (f.original_name && f.original_name !== 'redacted') ? f.original_name : '🔒 encrypted';
    const tr = document.createElement('tr');
    tr.dataset.id = f.id;
    tr.dataset.token = f.download_token;
    tr.dataset.filenameEnc = f.filename_enc || '';
    tr.dataset.originalName = (f.original_name && f.original_name !== 'redacted') ? f.original_name : 'encrypted_file';

    const nameTd = document.createElement('td');
    nameTd.className = 'filename enc-placeholder';
    nameTd.title = placeholder;
    nameTd.textContent = '📄 ' + placeholder;

    const sizeTd = document.createElement('td'); sizeTd.className = 'meta'; sizeTd.textContent = formatBytes(f.size_bytes);
    const dateTd = document.createElement('td'); dateTd.className = 'meta'; dateTd.textContent = formatDate(f.upload_date);
    const fromTd = document.createElement('td'); fromTd.className = 'meta'; fromTd.textContent = f.uploader;

    const actTd = document.createElement('td');
    actTd.className = 'actions';
    actTd.innerHTML =
      '<button class="btn-icon copy" data-act="copy" title="Copy shareable link">📋 Link</button>' +
      '<button class="btn-icon" data-act="download" title="Download & decrypt">⬇️</button>' +
      '<button class="btn-icon delete" data-act="delete" title="Delete">🗑️</button>';

    tr.append(nameTd, sizeTd, dateTd, fromTd, actTd);
    fileListBody.appendChild(tr);
    rows.push({ f, nameTd });
  }

  // Background filename decryption (non-blocking, cancellable).
  if (vaultPassphrase) {
    (async () => {
      for (const { f, nameTd } of rows) {
        if (myToken !== filenameDecryptToken) return; // a newer render started
        if (!f.filename_enc) continue;
        try {
          const name = await decryptString(f.filename_enc, vaultPassphrase);
          if (myToken !== filenameDecryptToken) return;
          nameTd.title = name;
          nameTd.textContent = '📄 ' + name;
          nameTd.classList.remove('enc-placeholder');
        } catch { /* keep placeholder */ }
        // Yield to the UI thread between heavy Argon2 derivations.
        await new Promise(r => setTimeout(r, 0));
      }
    })();
  }
}

// Event delegation for row action buttons (CSP-safe — no inline onclick).
fileListBody.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-act]');
  if (!btn) return;
  const tr = btn.closest('tr');
  if (!tr) return;
  const id = parseInt(tr.dataset.id);
  const token = tr.dataset.token;
  const act = btn.dataset.act;
  if (act === 'copy') copyLink(token);
  else if (act === 'download') downloadFile(id);
  else if (act === 'delete') deleteFile(id);
});

// ── Upload ────────────────────────────────────────────────
function handleFileDrop(e) {
  e.preventDefault();
  dropzone.classList.remove('dragover');
  const files = e.dataTransfer?.files || e.target?.files;
  if (files && files.length > 0) {
    selectFile(files[0]);
  }
}

function selectFile(file) {
  // Encrypted blob is slightly larger than the plaintext (~0.002%) — a small
  // margin keeps the client check honest against the server-side cap.
  if (file.size > serverMaxFileMB * 1024 * 1024 * 0.99) {
    toast('File too large — this server accepts up to ' + serverMaxFileMB + ' MB.', 'error');
    return;
  }
  selectedFile = file;
  selectedFileName.textContent = file.name;
  selectedFileSize.textContent = formatBytes(file.size);
  uploadOptions.classList.add('show');
  // Pre-fill upload passphrase with vault passphrase (user can change it)
  const upPw = document.getElementById('uploadPassphrase');
  if (upPw && vaultPassphrase && !upPw.value) upPw.value = vaultPassphrase;
}

function cancelUpload() {
  selectedFile = null;
  uploadOptions.classList.remove('show');
  fileInput.value = '';
  const upPw = document.getElementById('uploadPassphrase');
  if (upPw) upPw.value = '';
}

async function uploadFile() {
  const uploadPw = (document.getElementById('uploadPassphrase')?.value || '').trim();
  if (!selectedFile) return;

  // ENVELOPE ENCRYPTION (default when a passkey vault exists):
  //   • Generate a random file key (FEK) and encrypt the file/metadata with it
  //     (standard NYX3 blob). NO WebAuthn ceremony at upload time.
  //   • Seal the FEK to the vault public key → wrapped_fek. Any registered
  //     passkey can later unseal it on the download page.
  // PASSPHRASE MODE (explicit): only when no passkey vault exists, or the user
  //   ticked "use passphrase instead". Argon2id, passkeys CANNOT open it.
  const pkActive = passkeyModeActive();
  let keyProvider = null;
  let wrappedFekB64 = null;
  if (pkActive) {
    if (!vaultPubkey) {
      toast('No vault key found — register a passkey first, or use a passphrase.', 'error');
      return;
    }
    const { fek, wrappedFekB64: wf } = window.NyxPasskey.sealFEK(vaultPubkey);
    wrappedFekB64 = wf;
    keyProvider = window.NyxPasskey.fekKeyProvider(fek);
    fek.fill(0);
  } else if (!uploadPw) {
    toast('Please set a passphrase for this file', 'error');
    document.getElementById('uploadPassphrase')?.focus();
    return;
  }

  uploadBtn.disabled = true;
  uploadBtn.textContent = 'Encrypting...';
  progressContainer.classList.add('show');
  progressFill.style.width = '10%';
  progressText.textContent = 'Encrypting file...';

  try {

    // Read file
    const arrayBuffer = await selectedFile.arrayBuffer();
    const fileData = new Uint8Array(arrayBuffer);

    progressFill.style.width = '20%';
    progressText.textContent = 'Deriving key & encrypting...';

    // Encrypt file content (chunked with progress)
    const { blob: encryptedData } = await encryptData(fileData, uploadPw, (done, total) => {
      const pct = 20 + (done / total) * 30;
      progressFill.style.width = pct + '%';
      progressText.textContent = `Encrypting chunk ${done}/${total}...`;
    }, keyProvider);

    progressFill.style.width = '50%';
    progressText.textContent = 'Encrypting metadata...';

    // Encrypt filename and content type
    const filenameEnc = await encryptString(selectedFile.name, uploadPw, keyProvider);
    const contentTypeEnc = await encryptString(selectedFile.type || 'application/octet-stream', uploadPw, keyProvider);

    // Calculate expiry
    let expiresAt = null;
    const expiryVal = expirySelect.value;
    if (expiryVal !== 'never') {
      const hours = parseInt(expiryVal);
      expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
    }

    progressFill.style.width = '60%';
    progressText.textContent = 'Uploading...';

    // Build form data
    const formData = new FormData();
    formData.append('file', new Blob([encryptedData]), 'encrypted');
    formData.append('filename_enc', filenameEnc);
    formData.append('content_type_enc', contentTypeEnc);
    // NOTE: the plaintext filename is deliberately NOT sent — zero-knowledge
    // means the server never sees it, not even in transit.
    if (pkActive) {
      formData.append('key_mode', 'passkey');
      formData.append('wrapped_fek', wrappedFekB64);
    }
    if (expiresAt) formData.append('expires_at', expiresAt);
    const burnEl = document.getElementById('burnCheckbox');
    if (burnEl && burnEl.checked) formData.append('burn_after_read', '1');

    // Upload with progress
    const xhr = new XMLHttpRequest();
    const uploadPromise = new Promise((resolve, reject) => {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const pct = 60 + (e.loaded / e.total) * 35;
          progressFill.style.width = pct + '%';
          progressText.textContent = `Uploading... ${Math.round(e.loaded / e.total * 100)}%`;
        }
      });
      xhr.addEventListener('load', () => {
        let body = null;
        try { body = JSON.parse(xhr.responseText); } catch { /* non-JSON (proxy error page) */ }
        if (xhr.status >= 200 && xhr.status < 300 && body) {
          resolve(body);
        } else {
          reject(new Error((body && body.error) || 'Upload failed (HTTP ' + xhr.status + ')'));
        }
      });
      xhr.addEventListener('error', () => reject(new Error('Network error')));
    });

    xhr.open('POST', '/api/upload');
    xhr.setRequestHeader('X-Session-Token', sessionToken);
    xhr.send(formData);

    const result = await uploadPromise;

    progressFill.style.width = '100%';
    progressText.textContent = 'Done!';

    toast(`Uploaded ${selectedFile.name} 🔐`, 'success');

    // Reset
    cancelUpload();
    loadFiles(1); // newest file appears on page 1

  } catch (err) {
    toast(`Upload failed: ${err.message}`, 'error');
  } finally {
    uploadBtn.disabled = false;
    uploadBtn.textContent = '🔐 Encrypt & Upload';
    setTimeout(() => {
      progressContainer.classList.remove('show');
      progressFill.style.width = '0%';
    }, 2000);
  }
}

// ── Download (authenticated) ──────────────────────────────
async function downloadFile(id) {
  // Passkey-encrypted files need the WebAuthn ceremony, which lives on the
  // shareable download page. Detect them and open that page in a new tab.
  const rowEl = document.querySelector(`#fileListBody tr[data-id="${id}"]`);
  const tok = rowEl && rowEl.dataset.token;
  if (tok) {
    try {
      const meta = await (await fetch('/api/dl/' + tok + '/meta')).json();
      if (meta && meta.key_mode === 'passkey') {
        toast('Passkey file — opening the passkey download page…', 'info');
        window.open('/dl/' + tok, '_blank', 'noopener');
        return;
      }
    } catch { /* fall through to passphrase download */ }
  }

  toast('Downloading…', 'info');

  let encryptedData;
  try {
    encryptedData = await fetchWithProgress(`/api/download/${id}`, (received, total) => {
      const pct = Math.round(received / total * 100);
      toast(`Downloading… ${pct}%`, 'info');
    });
  } catch (err) {
    toast(`Download failed: ${err.message}`, 'error');
    return;
  }

  // Try vault passphrase first; on failure prompt for the correct one
  // (the file may have been uploaded with a custom passphrase).
  let pw = vaultPassphrase || null;
  let decrypted = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (!pw) {
      pw = await nyxPrompt('Decrypt file', attempt === 0
        ? 'Enter the passphrase for this file.'
        : 'Wrong passphrase — try again.', { type: 'password', placeholder: 'Passphrase', okLabel: 'Decrypt' });
      if (!pw) { toast('Cancelled', 'info'); return; }
    }
    try {
      toast('Decrypting…', 'info');
      decrypted = await decryptData(encryptedData, pw, (done, total) => {
        if (total > 1) toast(`Decrypting chunk ${done}/${total}…`, 'info');
      });
      break;
    } catch {
      pw = null; // wrong passphrase, ask again
    }
  }
  if (!decrypted) {
    toast('Decryption failed — wrong passphrase?', 'error');
    return;
  }

  // Get filename
  const row = document.querySelector(`#fileListBody tr[data-id="${id}"]`);
  let filename = 'decrypted_file';
  if (row) {
    const enc = row.dataset.filenameEnc;
    if (enc && pw) {
      try { filename = await decryptString(enc, pw); }
      catch { filename = row.dataset.originalName || 'decrypted_file'; }
    } else {
      filename = row.dataset.originalName || 'decrypted_file';
    }
  }

  try {
    const blob = new Blob([decrypted]);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    toast(`Decrypted: ${filename}`, 'success');
  } catch (err) {
    toast(`Failed: ${err.message}`, 'error');
  }
}

// ── Delete ────────────────────────────────────────────────
async function deleteFile(id) {
  if (!(await nyxConfirm('Delete file?', 'This permanently deletes the encrypted file from the server. Existing share links will stop working.', { okLabel: 'Delete', danger: true }))) return;

  try {
    const res = await api(`/api/files/${id}`, { method: 'DELETE' });
    if (!res.ok) throw new Error('Delete failed');
    toast('File deleted', 'success');
    loadFiles();
  } catch (err) {
    toast(`Delete failed: ${err.message}`, 'error');
  }
}

// ── Copy Link ─────────────────────────────────────────────
function copyLink(token) {
  const url = `${window.location.origin}/dl/${token}`;
  navigator.clipboard.writeText(url).then(() => {
    toast('Link copied! 📋', 'success');
  }).catch(() => {
    // Fallback
    const input = document.createElement('input');
    input.value = url;
    document.body.appendChild(input);
    input.select();
    document.execCommand('copy');
    document.body.removeChild(input);
    toast('Link copied! 📋', 'success');
  });
}

// ── Event Listeners ───────────────────────────────────────
loginForm.addEventListener('submit', (e) => { e.preventDefault(); login(); });
logoutBtn.addEventListener('click', logout);

dropzone.addEventListener('dragover', (e) => { e.preventDefault(); dropzone.classList.add('dragover'); });
dropzone.addEventListener('dragleave', () => dropzone.classList.remove('dragover'));
dropzone.addEventListener('drop', handleFileDrop);
dropzone.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', handleFileDrop);

uploadBtn.addEventListener('click', uploadFile);
cancelBtn.addEventListener('click', cancelUpload);

// Passkey admin controls
const registerPasskeyBtn = document.getElementById('registerPasskeyBtn');
if (registerPasskeyBtn) registerPasskeyBtn.addEventListener('click', registerPasskey);

// "Use passphrase instead" toggle (makes a single upload passphrase-only).
const usePassphraseToggle = document.getElementById('usePassphraseToggle');
if (usePassphraseToggle) usePassphraseToggle.addEventListener('change', (e) => {
  usePassphraseUpload = !!e.target.checked;
  renderUploadModeUI();
  if (usePassphraseUpload) {
    const upPw = document.getElementById('uploadPassphrase');
    if (upPw && vaultPassphrase && !upPw.value) upPw.value = vaultPassphrase;
  }
});

// Passkey management table (rename / delete) — event delegation.
const passkeyListBody = document.getElementById('passkeyListBody');
if (passkeyListBody) passkeyListBody.addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-pk-act]');
  if (!btn) return;
  const tr = btn.closest('tr');
  if (!tr) return;
  const id = parseInt(tr.dataset.id);
  if (btn.dataset.pkAct === 'rename') renamePasskey(id);
  else if (btn.dataset.pkAct === 'delete') deletePasskey(id);
});

// Upload passphrase show/hide toggle
const toggleUploadPw = document.getElementById('toggleUploadPw');
const uploadPassphraseEl = document.getElementById('uploadPassphrase');
if (toggleUploadPw && uploadPassphraseEl) {
  toggleUploadPw.addEventListener('click', () => {
    const show = uploadPassphraseEl.type === 'password';
    uploadPassphraseEl.type = show ? 'text' : 'password';
    toggleUploadPw.textContent = show ? '🙈' : '👁️';
  });
}

// Pagination controls
const prevPageBtn = document.getElementById('prevPage');
const nextPageBtn = document.getElementById('nextPage');
if (prevPageBtn) prevPageBtn.addEventListener('click', () => { if (currentPage > 1) loadFiles(currentPage - 1); });
if (nextPageBtn) nextPageBtn.addEventListener('click', () => { if (currentPage < totalPages) loadFiles(currentPage + 1); });

// ── Init ──────────────────────────────────────────────────
if (sessionToken && vaultPassphrase) {
  // Validate session
  api('/api/files').then(res => {
    if (res.ok) showApp();
    else showLogin();
  }).catch(() => showLogin());
} else {
  showLogin();
}
