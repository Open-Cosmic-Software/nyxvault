#!/usr/bin/env node
'use strict';

require('dotenv').config({ path: __dirname + '/.env' });

const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const rateLimit = require('express-rate-limit');
const argon2 = require('argon2');
const nacl = require('tweetnacl');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

const VERSION = (() => {
  try { return require('./package.json').version; } catch { return 'unknown'; }
})();

// Security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
const PORT = parseInt(process.env.PORT) || 3870;
const API_KEY = process.env.API_KEY;
const WEB_PASSWORD = process.env.WEB_PASSWORD;
const MAX_FILE_SIZE_MB = parseInt(process.env.MAX_FILE_SIZE_MB) || 100;
const MAX_FILE_SIZE = MAX_FILE_SIZE_MB * 1024 * 1024;

// Fail fast on missing critical config — a vault without auth is not a vault.
if (!API_KEY || !WEB_PASSWORD) {
  console.error('FATAL: API_KEY and WEB_PASSWORD must be set (see .env.example).');
  process.exit(1);
}
const VT_API_KEY = process.env.VT_API_KEY || '';
// WebAuthn / passkey configuration. RP ID + origin must match the public
// hostname (Caddy) — never localhost, or the browser rejects the ceremony.
const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID || 'nyxvault.org';
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || 'NyxVault';
const WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN || 'https://nyxvault.org';
// Accept both the apex and www origins: Caddy serves the app on both, and a
// ceremony started on www.nyxvault.org is valid for rpID nyxvault.org — but
// clientDataJSON.origin then reads https://www.nyxvault.org, which a single
// expectedOrigin string would reject. (This broke passkeys on every Chromium
// browser for anyone who opened the www URL.)
const WEBAUTHN_ORIGINS = (() => {
  const set = new Set([WEBAUTHN_ORIGIN]);
  try {
    const u = new URL(WEBAUTHN_ORIGIN);
    if (u.hostname.startsWith('www.')) set.add(u.protocol + '//' + u.hostname.slice(4));
    else set.add(u.protocol + '//www.' + u.hostname);
  } catch { /* keep single origin */ }
  return [...set];
})();

const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

// Cache the download page HTML (with cachebust injected)
const DL_PAGE_HTML = (() => {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'dl-page.html'), 'utf8');
    return html.replace(/__CACHEBUST__/g, String(Date.now()));
  } catch { return null; }
})();

// Simple in-memory cache for VirusTotal hash lookups (1h TTL, bounded)
const vtCache = new Map();
const VT_CACHE_MAX = 500;
function vtCacheSet(hash, entry) {
  if (vtCache.size >= VT_CACHE_MAX) {
    // Evict the oldest entry (Map preserves insertion order).
    const oldest = vtCache.keys().next().value;
    if (oldest !== undefined) vtCache.delete(oldest);
  }
  vtCache.set(hash, entry);
}

// Defensive JSON parse for the passkey transports column (corrupt rows must
// never turn into a 500 on an otherwise healthy endpoint).
function parseTransports(raw) {
  if (!raw) return undefined;
  try { const t = JSON.parse(raw); return Array.isArray(t) ? t : undefined; }
  catch { return undefined; }
}

// Parse a human duration like "30m", "1h", "24h", "7d", "30d" into milliseconds.
function parseDuration(str) {
  const m = String(str).trim().match(/^(\d+)\s*(m|h|d)$/i);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  const unit = m[2].toLowerCase();
  const mult = unit === 'm' ? 60e3 : unit === 'h' ? 3600e3 : 86400e3;
  return n * mult;
}

// ── Database ──────────────────────────────────────────────
// NYXVAULT_DB / NYXVAULT_STORAGE / NYXVAULT_RECOVERY_KEY are overridable via
// env so a test instance can run against throwaway paths without ever touching
// the production database.
const DB_PATH = process.env.NYXVAULT_DB || path.join(__dirname, 'data', 'vault.db');
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename_enc TEXT NOT NULL,
    upload_date TEXT NOT NULL DEFAULT (datetime('now')),
    uploader TEXT NOT NULL DEFAULT 'unknown',
    size_bytes INTEGER NOT NULL DEFAULT 0,
    download_token TEXT NOT NULL UNIQUE,
    content_type_enc TEXT,
    expires_at TEXT,
    nonce TEXT,
    original_name TEXT,
    burn_after_read INTEGER NOT NULL DEFAULT 0,
    downloaded_at TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_download_token ON files(download_token);
`);

// Idempotent migration for databases created before burn-after-reading existed.
// (CREATE TABLE IF NOT EXISTS won't add columns to an already-existing table.)
(() => {
  const cols = db.prepare(`PRAGMA table_info(files)`).all().map(c => c.name);
  if (!cols.includes('burn_after_read')) {
    db.exec(`ALTER TABLE files ADD COLUMN burn_after_read INTEGER NOT NULL DEFAULT 0`);
    console.log('[MIGRATE] added column burn_after_read');
  }
  if (!cols.includes('downloaded_at')) {
    db.exec(`ALTER TABLE files ADD COLUMN downloaded_at TEXT`);
    console.log('[MIGRATE] added column downloaded_at');
  }
  // Per-file key mode: 'passphrase' (default, Argon2id) or 'passkey' (envelope).
  // Old files have no column → default to 'passphrase' so nothing breaks.
  if (!cols.includes('key_mode')) {
    db.exec(`ALTER TABLE files ADD COLUMN key_mode TEXT NOT NULL DEFAULT 'passphrase'`);
    console.log('[MIGRATE] added column key_mode');
  }
  // v2.2.0 envelope encryption: passkey-mode files store the file-encryption
  // key (FEK) sealed to the vault public key (anonymous sealed box). The blob
  // itself is a standard NYX3 blob whose key IS the FEK. NULL for passphrase
  // files and legacy passkey files (which no longer exist after the v2.2 wipe).
  if (!cols.includes('wrapped_fek')) {
    db.exec(`ALTER TABLE files ADD COLUMN wrapped_fek TEXT`);
    console.log('[MIGRATE] added column wrapped_fek');
  }
})();

// ── Settings table (global key/value config) ──────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);
const stmtGetSetting = db.prepare(`SELECT value FROM settings WHERE key = ?`);
const stmtSetSetting = db.prepare(`INSERT INTO settings (key, value) VALUES (?, ?)
  ON CONFLICT(key) DO UPDATE SET value = excluded.value`);
function getSetting(key, fallback = null) {
  const row = stmtGetSetting.get(key);
  return row ? row.value : fallback;
}
function setSetting(key, value) { stmtSetSetting.run(key, String(value)); }

if (!getSetting('passkey_mode')) setSetting('passkey_mode', 'off');

// ── Passkeys table (WebAuthn credentials + envelope key wrapping) ───────
// v2.2.0 architecture (envelope encryption):
//   • A single vault X25519 keypair is created client-side when the FIRST
//     passkey is registered. The PUBLIC key is stored in settings; the PRIVATE
//     key is never stored in plaintext.
//   • Every passkey row stores its OWN random `prf_salt` (per-credential PRF
//     output is a per-credential HMAC — salts are NOT interchangeable) plus a
//     `wrapped_privkey`: the vault private key encrypted (nacl.secretbox) under
//     a KEK derived (HKDF) from THAT passkey's PRF output. So every registered
//     passkey can independently unwrap the same vault private key.
//   • Files sealed to the vault public key can therefore be opened by ANY
//     registered passkey.
db.exec(`
  CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    label TEXT,
    prf_salt TEXT,
    wrapped_privkey TEXT,
    last_used TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
// Idempotent migration for pre-2.2 passkeys tables.
(() => {
  const pcols = db.prepare(`PRAGMA table_info(passkeys)`).all().map(c => c.name);
  if (!pcols.includes('prf_salt')) {
    db.exec(`ALTER TABLE passkeys ADD COLUMN prf_salt TEXT`);
    console.log('[MIGRATE] added column passkeys.prf_salt');
  }
  if (!pcols.includes('wrapped_privkey')) {
    db.exec(`ALTER TABLE passkeys ADD COLUMN wrapped_privkey TEXT`);
    console.log('[MIGRATE] added column passkeys.wrapped_privkey');
  }
  if (!pcols.includes('last_used')) {
    db.exec(`ALTER TABLE passkeys ADD COLUMN last_used TEXT`);
    console.log('[MIGRATE] added column passkeys.last_used');
  }
  // The old v2.1.x global PRF salt is obsolete under envelope encryption.
  // Pre-2.2 passkeys WITHOUT wrapping data are cryptographically incompatible
  // (they wrongly assumed one shared global PRF salt). Wipe them so the user
  // re-registers cleanly. Rows created by v2.2 always have prf_salt +
  // wrapped_privkey set, so this only ever fires once on upgrade.
  const legacy = db.prepare(`SELECT COUNT(*) AS c FROM passkeys WHERE prf_salt IS NULL OR wrapped_privkey IS NULL`).get().c;
  if (legacy > 0) {
    db.prepare(`DELETE FROM passkeys WHERE prf_salt IS NULL OR wrapped_privkey IS NULL`).run();
    console.log('[MIGRATE] removed ' + legacy + ' incompatible pre-2.2 passkey(s) — re-registration required');
    // Drop the now-orphaned vault pubkey + old global prf salt so the next
    // registration regenerates a fresh vault keypair.
    db.prepare(`DELETE FROM settings WHERE key IN ('vault_pubkey','prf_salt')`).run();
    setSetting('passkey_mode', 'off');
  }
})();
// ── Additional per-passkey vault-key wraps (v2.4) ────────────────────────────
// The SAME passkey can yield DIFFERENT PRF outputs across transports
// (a confirmed iOS Safari bug: a passkey used over hybrid/QR returns a
// different PRF value than the same passkey used on-device). The primary wrap
// lives in passkeys.wrapped_privkey; this table holds ADDITIONAL wraps of the
// same vault private key under other KEKs derived from other PRF contexts, so
// one passkey can decrypt regardless of which transport produced its PRF.
// prf_context is an OPAQUE label ('hybrid'/'platform'/custom) — it never
// encodes the PRF value itself. Each wrap uses its own fresh secretbox nonce.
db.exec(`
  CREATE TABLE IF NOT EXISTS passkey_wraps (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    passkey_id INTEGER NOT NULL,
    prf_context TEXT,
    wrapped_privkey TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(passkey_id, prf_context),
    FOREIGN KEY(passkey_id) REFERENCES passkeys(id) ON DELETE CASCADE
  );
`);
const stmtGetWrapsForPasskey = db.prepare(`SELECT prf_context, wrapped_privkey FROM passkey_wraps WHERE passkey_id = ? ORDER BY id ASC`);
const stmtInsertWrap = db.prepare(`INSERT OR REPLACE INTO passkey_wraps (passkey_id, prf_context, wrapped_privkey) VALUES (?, ?, ?)`);
const stmtGetPasskeyByCredIdRow = db.prepare(`SELECT id FROM passkeys WHERE cred_id = ?`);

// Build the client-facing view of a passkey: its primary wrap plus EVERY
// additional per-context wrap. `wraps` is the full list the client trial-
// decrypts against (secretbox is authenticated → only the matching KEK opens
// one; a wrong KEK fails cleanly). Keeps `wrapped_privkey` for old clients.
function passkeyForClient(p) {
  const extra = stmtGetWrapsForPasskey.all(p.id);
  const wraps = [];
  if (p.wrapped_privkey) wraps.push({ prf_context: 'primary', wrapped_privkey: p.wrapped_privkey });
  for (const w of extra) wraps.push({ prf_context: w.prf_context, wrapped_privkey: w.wrapped_privkey });
  return {
    cred_id: p.cred_id,
    prf_salt: p.prf_salt,
    wrapped_privkey: p.wrapped_privkey, // legacy single-wrap field (back-compat)
    wraps,                              // v2.4: all wraps to try
    transports: parseTransports(p.transports)
  };
}

const stmtInsertPasskey = db.prepare(`INSERT INTO passkeys (cred_id, public_key, counter, transports, label, prf_salt, wrapped_privkey) VALUES (?, ?, ?, ?, ?, ?, ?)`);
const stmtGetAllPasskeys = db.prepare(`SELECT * FROM passkeys ORDER BY created_at ASC`);
const stmtGetPasskeyByCredId = db.prepare(`SELECT * FROM passkeys WHERE cred_id = ?`);
const stmtUpdatePasskeyCounter = db.prepare(`UPDATE passkeys SET counter = ?, last_used = datetime('now') WHERE cred_id = ?`);
const stmtDeletePasskey = db.prepare(`DELETE FROM passkeys WHERE id = ?`);
const stmtCountPasskeys = db.prepare(`SELECT COUNT(*) AS c FROM passkeys`);
const stmtRenamePasskey = db.prepare(`UPDATE passkeys SET label = ? WHERE id = ?`);
const stmtGetPasskeyById = db.prepare(`SELECT * FROM passkeys WHERE id = ?`);

// ── Recovery keys table (agent access to passkey-mode files) ────────────────
// A recovery key is a SOFTWARE X25519 keypair. The private key lives in a
// chmod-600 JSON file on the server host (outside git), controlled by the
// operator/agent. Its row stores:
//   • pubkey           — the recovery public key (base64)
//   • wrapped_privkey  — the VAULT private key sealed to the recovery public
//                        key (anonymous sealed box, same format as wrapped_fek)
// The wrap can only be produced in a browser after a passkey ceremony (only a
// passkey can unwrap the vault private key) — hence the init/finalize split.
// ⚠️ Trade-off (opt-in, explicit): with a finalized recovery key the server
// HOST can decrypt passkey-mode files. Passphrase files stay zero-knowledge.
db.exec(`
  CREATE TABLE IF NOT EXISTS recovery_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    label TEXT,
    pubkey TEXT NOT NULL,
    wrapped_privkey TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
const stmtInsertRecovery = db.prepare(`INSERT INTO recovery_keys (label, pubkey) VALUES (?, ?)`);
const stmtGetRecoveryById = db.prepare(`SELECT * FROM recovery_keys WHERE id = ?`);
const stmtFinalizeRecovery = db.prepare(`UPDATE recovery_keys SET wrapped_privkey = ? WHERE id = ?`);
const stmtGetAllRecovery = db.prepare(`SELECT * FROM recovery_keys ORDER BY created_at ASC`);
const stmtDeleteRecovery = db.prepare(`DELETE FROM recovery_keys WHERE id = ?`);
const stmtDeleteAllRecovery = db.prepare(`DELETE FROM recovery_keys`);
// Where the recovery PRIVATE key file lives (never in git, chmod 600).
const RECOVERY_KEY_PATH = process.env.NYXVAULT_RECOVERY_KEY || path.join(__dirname, 'data', 'recovery-key.json');

// Prepared statements
const stmtInsert = db.prepare(`
  INSERT INTO files (filename_enc, uploader, size_bytes, download_token, content_type_enc, expires_at, nonce, original_name, burn_after_read, key_mode, wrapped_fek)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtMarkDownloaded = db.prepare(`UPDATE files SET downloaded_at = datetime('now') WHERE id = ?`);
// Atomic single-use lock for burn-after-reading blobs: only the request that
// actually flips downloaded_at from NULL wins.
const stmtClaimBurnRead = db.prepare(`UPDATE files SET downloaded_at = datetime('now') WHERE id = ? AND downloaded_at IS NULL`);
// Pagination + lazy-expiry helpers (treat NULL expires_at as never-expiring).
const stmtGetExpired = db.prepare(`SELECT id, download_token FROM files WHERE expires_at IS NOT NULL AND expires_at < ?`);
const stmtCountActive = db.prepare(`SELECT COUNT(*) AS c FROM files WHERE expires_at IS NULL OR expires_at >= ?`);
const stmtGetPage = db.prepare(`SELECT * FROM files WHERE expires_at IS NULL OR expires_at >= ? ORDER BY upload_date DESC LIMIT ? OFFSET ?`);
const stmtGetById = db.prepare(`SELECT * FROM files WHERE id = ?`);
const stmtGetByToken = db.prepare(`SELECT * FROM files WHERE download_token = ?`);
const stmtDelete = db.prepare(`DELETE FROM files WHERE id = ?`);

// ── Storage ───────────────────────────────────────────────
const STORAGE_DIR = process.env.NYXVAULT_STORAGE || path.join(__dirname, 'storage');
if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

// Best-effort secure delete: overwrite the file with random bytes before
// unlinking, so a casual disk-undelete can't trivially recover the ciphertext.
// (On copy-on-write / SSD filesystems in-place overwrite isn't guaranteed;
//  this is defense-in-depth on top of the data already being encrypted.)
function secureDelete(filePath) {
  try {
    if (!fs.existsSync(filePath)) return;
    const size = fs.statSync(filePath).size;
    if (size > 0) {
      const fd = fs.openSync(filePath, 'r+');
      try {
        const CHUNK = 1 << 20; // 1 MiB
        let written = 0;
        while (written < size) {
          const n = Math.min(CHUNK, size - written);
          fs.writeSync(fd, crypto.randomBytes(n), 0, n, written);
          written += n;
        }
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
    }
    fs.unlinkSync(filePath);
  } catch (e) {
    try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch {}
  }
}

const upload = multer({
  dest: STORAGE_DIR,
  limits: { fileSize: MAX_FILE_SIZE }
});

// ── Middleware ─────────────────────────────────────────────
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting on uploads
const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  message: { error: 'Too many uploads, slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting on login (anti brute-force)
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many login attempts, try again later.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Rate limiting on download (anti brute-force passphrase attempts)
const downloadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 30,
  message: { error: 'Too many download attempts, slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// Session tokens (in-memory, simple)
const sessions = new Map();

function generateSessionToken() {
  return crypto.randomBytes(48).toString('hex');
}

// ── Auth Middleware ────────────────────────────────────────
function authApi(req, res, next) {
  const key = req.headers['x-api-key'];
  if (key && key === API_KEY) {
    req.uploader = 'nyx-api';
    return next();
  }
  return res.status(401).json({ error: 'Invalid API key' });
}

function authWeb(req, res, next) {
  const token = req.headers['x-session-token'];
  if (token && sessions.has(token)) {
    const session = sessions.get(token);
    if (session.expires > Date.now()) {
      req.uploader = 'web-ui';
      return next();
    }
    sessions.delete(token);
  }
  return res.status(401).json({ error: 'Not authenticated' });
}

function authAny(req, res, next) {
  // Try API key first
  const key = req.headers['x-api-key'];
  if (key && key === API_KEY) {
    req.uploader = 'nyx-api';
    return next();
  }
  // Then session
  const token = req.headers['x-session-token'];
  if (token && sessions.has(token)) {
    const session = sessions.get(token);
    if (session.expires > Date.now()) {
      req.uploader = 'web-ui';
      return next();
    }
    sessions.delete(token);
  }
  return res.status(401).json({ error: 'Not authenticated' });
}

// ── Static Files ──────────────────────────────────────────
app.use((req, res, next) => { if (req.path.startsWith("/dl/")) return next(); express.static(path.join(__dirname, "public"), {
  index: false
  })(req, res, next); });

// ── Landing / Upload UI ───────────────────────────────────
app.get('/', (req, res) => {
  // Serve landing.html if it exists, otherwise the upload UI
  const landing = path.join(__dirname, 'public', 'landing.html');
  // dotfiles:'allow' is required because the install path contains a dot-dir
  // (~/.ocplatform/...); express 5 / send rejects such paths with 404 otherwise.
  if (fs.existsSync(landing)) return res.sendFile(landing, { dotfiles: 'allow' });
  res.sendFile(path.join(__dirname, 'public', 'index.html'), { dotfiles: 'allow' });
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'), { dotfiles: 'allow' });
});

// ── Web Auth ──────────────────────────────────────────────
app.post('/auth/login', loginLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    if (!password) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    // Support both hashed (argon2) and plaintext passwords for backward compat
    let valid = false;
    if (WEB_PASSWORD.startsWith('$argon2')) {
      valid = await argon2.verify(WEB_PASSWORD, password);
    } else {
      valid = password === WEB_PASSWORD;
    }
    if (!valid) {
      return res.status(401).json({ error: 'Wrong password' });
    }
    const token = generateSessionToken();
    sessions.set(token, {
      created: Date.now(),
      expires: Date.now() + 24 * 60 * 60 * 1000 // 24h
    });
    return res.json({ token, expires_in: 86400 });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/auth/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  return res.json({ ok: true });
});

// ── API: Upload ───────────────────────────────────────────
app.post('/api/upload', uploadLimiter, authAny, upload.single('file'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const downloadToken = crypto.randomBytes(32).toString('hex');
    const filenameEnc = req.body.filename_enc || '';
    const contentTypeEnc = req.body.content_type_enc || '';
    // Expiry: accept either an absolute ISO timestamp (expires_at) or a
    // relative duration (expires_in: e.g. "1h", "24h", "7d", "30d", "90m").
    let expiresAt = req.body.expires_at || null;
    if (!expiresAt && req.body.expires_in) {
      const ms = parseDuration(req.body.expires_in);
      if (ms) expiresAt = new Date(Date.now() + ms).toISOString();
    }
    const nonce = req.body.nonce || '';
    const burnAfterRead = (req.body.burn_after_read === '1' || req.body.burn_after_read === 'true' || req.body.burn_after_read === true) ? 1 : 0;
    // Per-file key mode: 'passkey' (envelope/sealed-box FEK) or 'passphrase'.
    const keyMode = (req.body.key_mode === 'passkey') ? 'passkey' : 'passphrase';
    // For passkey mode, the client uploads the FEK sealed to the vault public
    // key (base64). The server stores it opaquely — it can never open it.
    let wrappedFek = null;
    if (keyMode === 'passkey') {
      wrappedFek = (typeof req.body.wrapped_fek === 'string' && req.body.wrapped_fek.length > 0)
        ? req.body.wrapped_fek.slice(0, 4096) : null;
      if (!wrappedFek) {
        // Clean up the just-uploaded temp file before bailing.
        if (req.file && req.file.path && fs.existsSync(req.file.path)) {
          try { fs.unlinkSync(req.file.path); } catch {}
        }
        return res.status(400).json({ error: 'passkey mode requires wrapped_fek' });
      }
    }
    // Don't store original filename (privacy: zero-knowledge)
    const originalName = 'redacted';

    // Rename uploaded file to download token for easy lookup
    const newPath = path.join(STORAGE_DIR, downloadToken);
    fs.renameSync(req.file.path, newPath);

    const fileSize = req.file.size;

    const result = stmtInsert.run(
      filenameEnc,
      req.uploader,
      fileSize,
      downloadToken,
      contentTypeEnc,
      expiresAt,
      nonce,
      originalName,
      burnAfterRead,
      keyMode,
      wrappedFek
    );

    const file = stmtGetById.get(result.lastInsertRowid);

    console.log(`[UPLOAD] ${(fileSize / 1024).toFixed(1)}KB by ${req.uploader} → token:${downloadToken.slice(0, 8)}...`);

    return res.json({
      id: file.id,
      download_token: downloadToken,
      download_url: `/dl/${downloadToken}`,
      size_bytes: fileSize,
      upload_date: file.upload_date,
      expires_at: file.expires_at || null,
      burn_after_read: !!file.burn_after_read,
      key_mode: file.key_mode || 'passphrase'
    });
  } catch (err) {
    console.error('Upload error:', err);
    // Clean up temp file if exists
    if (req.file && req.file.path && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    return res.status(500).json({ error: 'Upload failed' });
  }
});

// ── API: List Files ───────────────────────────────────────
app.get('/api/files', authAny, (req, res) => {
  try {
    // Lazily purge expired files (cheap: indexed scan of just the expired ones).
    const now = new Date().toISOString();
    const expired = stmtGetExpired.all(now);
    for (const f of expired) {
      secureDelete(path.join(STORAGE_DIR, f.download_token));
      stmtDelete.run(f.id);
    }

    // Pagination: avoid shipping (and rendering) hundreds of rows at once.
    const limit = Math.min(Math.max(parseInt(req.query.limit) || 25, 1), 100);
    const page = Math.max(parseInt(req.query.page) || 1, 0);
    const offset = page > 0 ? (page - 1) * limit : 0;

    const total = stmtCountActive.get(now).c;
    const files = stmtGetPage.all(now, limit, offset);

    return res.json({
      files,
      count: files.length,
      total,
      page,
      limit,
      totalPages: Math.max(Math.ceil(total / limit), 1)
    });
  } catch (err) {
    console.error('List error:', err);
    return res.status(500).json({ error: 'Failed to list files' });
  }
});

// ── API: Download by ID (authenticated) ───────────────────
app.get('/api/download/:id', authAny, (req, res) => {
  try {
    const file = stmtGetById.get(parseInt(req.params.id));
    if (!file) return res.status(404).json({ error: 'File not found' });

    // Check expiry
    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      return res.status(410).json({ error: 'File has expired' });
    }

    const filePath = path.join(STORAGE_DIR, file.download_token);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File data missing' });
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', file.size_bytes);
    res.setHeader('Content-Disposition', `attachment; filename="encrypted_${file.id}"`);
    return fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    console.error('Download error:', err);
    return res.status(500).json({ error: 'Download failed' });
  }
});

// ── API: Delete File ──────────────────────────────────────
app.delete('/api/files/:id', authAny, (req, res) => {
  try {
    const file = stmtGetById.get(parseInt(req.params.id));
    if (!file) return res.status(404).json({ error: 'File not found' });

    const filePath = path.join(STORAGE_DIR, file.download_token);
    secureDelete(filePath);
    stmtDelete.run(file.id);

    console.log(`[DELETE] File #${file.id} (token:${file.download_token.slice(0, 8)}...)`);
    return res.json({ ok: true, deleted: file.id });
  } catch (err) {
    console.error('Delete error:', err);
    return res.status(500).json({ error: 'Delete failed' });
  }
});

// ── Public: Shareable Download ────────────────────────────
app.get('/dl/:token', (req, res) => {
  if (!/^[a-f0-9]{64}$/.test(req.params.token)) {
    return res.status(400).send('Invalid token');
  }
  if (DL_PAGE_HTML) {
    res.type('html').send(DL_PAGE_HTML);
  } else {
    res.sendFile(path.join(__dirname, 'dl-page.html'), { dotfiles: 'allow' });
  }
});

// ── Public: VirusTotal hash lookup (privacy-preserving) ──────
// Only the SHA-256 hash is sent to VirusTotal – never the file itself.
// Zero-knowledge is preserved: the server only proxies a hash query.
const vtLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 60,
  message: { error: 'Too many scan requests, slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

app.get('/api/vt/:hash', vtLimiter, async (req, res) => {
  try {
    const hash = (req.params.hash || '').toLowerCase();
    if (!/^[a-f0-9]{64}$/.test(hash)) {
      return res.status(400).json({ error: 'Invalid hash format' });
    }
    if (!VT_API_KEY) {
      return res.json({ disabled: true });
    }
    // Cache hit?
    const cached = vtCache.get(hash);
    if (cached && cached.expires > Date.now()) {
      return res.json(cached.data);
    }

    const vtRes = await fetch('https://www.virustotal.com/api/v3/files/' + hash, {
      headers: { 'x-apikey': VT_API_KEY }
    });

    if (vtRes.status === 404) {
      const data = { not_found: true };
      vtCacheSet(hash, { data, expires: Date.now() + 60 * 60 * 1000 });
      return res.json(data);
    }
    if (vtRes.status === 401 || vtRes.status === 403) {
      return res.json({ error: 'VirusTotal API key invalid or quota exceeded.' });
    }
    if (vtRes.status === 429) {
      return res.json({ error: 'VirusTotal rate limit reached. Try again later.' });
    }
    if (!vtRes.ok) {
      return res.json({ error: 'VirusTotal returned ' + vtRes.status });
    }

    const json = await vtRes.json();
    const stats = (json.data && json.data.attributes && json.data.attributes.last_analysis_stats) || {};
    const data = {
      malicious: stats.malicious || 0,
      suspicious: stats.suspicious || 0,
      harmless: stats.harmless || 0,
      undetected: stats.undetected || 0,
      total: (stats.malicious||0) + (stats.suspicious||0) + (stats.harmless||0) + (stats.undetected||0) + (stats.timeout||0),
      permalink: 'https://www.virustotal.com/gui/file/' + hash
    };
    vtCacheSet(hash, { data, expires: Date.now() + 60 * 60 * 1000 });
    return res.json(data);
  } catch (err) {
    console.error('VT lookup error:', err.message);
    return res.json({ error: 'Could not reach VirusTotal.' });
  }
});

// ── Public: Get file metadata for download page ───────────
app.get('/api/dl/:token/meta', downloadLimiter, (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/.test(req.params.token)) {
      return res.status(400).json({ error: 'Invalid token format' });
    }
    const file = stmtGetByToken.get(req.params.token);
    if (!file) return res.status(404).json({ error: 'File not found' });

    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      return res.status(410).json({ error: 'File has expired' });
    }

    return res.json({
      id: file.id,
      filename_enc: file.filename_enc,
      content_type_enc: file.content_type_enc,
      size_bytes: file.size_bytes,
      upload_date: file.upload_date,
      uploader: file.uploader,
      nonce: file.nonce,
      burn_after_read: !!file.burn_after_read,
      key_mode: file.key_mode || 'passphrase',
      // Envelope encryption (passkey mode): the download page needs the FEK
      // sealed to the vault public key, plus the vault public key itself is NOT
      // needed to DECRYPT (only the private key is), but we include the list of
      // registered passkeys' PRF salts so the client can run the ceremony that
      // unwraps the vault private key. wrapped_fek is opaque to the server.
      wrapped_fek: (file.key_mode === 'passkey') ? (file.wrapped_fek || undefined) : undefined,
      passkeys: (file.key_mode === 'passkey') ? stmtGetAllPasskeys.all().map(passkeyForClient) : undefined
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── Public: Download raw encrypted blob ───────────────────
app.get('/api/dl/:token/blob', downloadLimiter, (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/.test(req.params.token)) {
      return res.status(400).json({ error: 'Invalid token format' });
    }
    const file = stmtGetByToken.get(req.params.token);
    if (!file) return res.status(404).json({ error: 'File not found' });

    if (file.expires_at && new Date(file.expires_at) < new Date()) {
      return res.status(410).json({ error: 'File has expired' });
    }

    const filePath = path.join(STORAGE_DIR, file.download_token);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File data missing' });
    }

    // Single-use lock for burn-after-reading: once the ciphertext has been
    // served once, refuse further blob fetches. This closes the window where
    // the blob could be pulled multiple times before the /burn confirmation.
    // (Defense-in-depth; the actual destruction still happens on /burn after a
    //  verified client-side decrypt, so a failed/aborted fetch isn't punished
    //  beyond a single retry being blocked.)
    if (file.burn_after_read) {
      const claimed = stmtClaimBurnRead.run(file.id);
      if (claimed.changes === 0) {
        return res.status(410).json({ error: 'This burn-after-reading file has already been retrieved.' });
      }
    }

    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Length', file.size_bytes);
    return fs.createReadStream(filePath).pipe(res);
  } catch (err) {
    return res.status(500).json({ error: 'Download failed' });
  }
});

// ── Public: Burn after reading ────────────────────────────
// Called by the download page ONLY after a successful client-side decryption,
// so a wrong passphrase never destroys the file. Zero-knowledge preserved:
// the server learns nothing about the content, only that it may now self-destruct.
app.post('/api/dl/:token/burn', downloadLimiter, (req, res) => {
  try {
    if (!/^[a-f0-9]{64}$/.test(req.params.token)) {
      return res.status(400).json({ error: 'Invalid token format' });
    }
    const file = stmtGetByToken.get(req.params.token);
    if (!file) return res.json({ burned: true, already: true });
    if (!file.burn_after_read) {
      return res.json({ burned: false, reason: 'not a burn-after-read file' });
    }
    const filePath = path.join(STORAGE_DIR, file.download_token);
    secureDelete(filePath);
    stmtDelete.run(file.id);
    console.log(`[BURN] File #${file.id} self-destructed after read (token:${file.download_token.slice(0,8)}...)`);
    return res.json({ burned: true });
  } catch (err) {
    console.error('Burn error:', err.message);
    return res.status(500).json({ error: 'Burn failed' });
  }
});

// ── Settings ──────────────────────────────────────────────
// Public GET: exposes only what the download/upload page needs — whether
// passkey mode is on and whether at least one passkey exists. The PRF salt is
// not secret and is included so the client can derive keys.
app.get('/api/settings', (req, res) => {
  try {
    const passkeyMode = getSetting('passkey_mode', 'off');
    const passkeyCount = stmtCountPasskeys.get().c;
    return res.json({
      passkey_mode: passkeyMode,
      passkey_registered: passkeyCount > 0,
      passkey_count: passkeyCount,
      max_file_size_mb: MAX_FILE_SIZE_MB,
      // Vault public key (base64) for envelope encryption. Anyone (web UI, CLI,
      // agent API) can seal a FEK to it; only a registered passkey can unseal.
      vault_pubkey: getSetting('vault_pubkey') || null
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Authenticated POST: toggle passkey_mode. Refuses to turn it ON if no passkey
// is registered yet (would make the upload UI unusable).
app.post('/api/settings', authWeb, (req, res) => {
  try {
    const { passkey_mode } = req.body || {};
    if (passkey_mode !== undefined) {
      const val = (passkey_mode === 'on' || passkey_mode === true || passkey_mode === '1') ? 'on' : 'off';
      if (val === 'on' && stmtCountPasskeys.get().c === 0) {
        return res.status(400).json({ error: 'Register a passkey before enabling passkey mode.' });
      }
      setSetting('passkey_mode', val);
    }
    const passkeyCount = stmtCountPasskeys.get().c;
    return res.json({
      ok: true,
      passkey_mode: getSetting('passkey_mode', 'off'),
      passkey_registered: passkeyCount > 0,
      passkey_count: passkeyCount
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── WebAuthn / Passkeys ───────────────────────────────────
// Ceremony challenges are short-lived, kept in memory keyed by session token
// (registration is admin-only) or a random flow id (public authentication).
const webauthnChallenges = new Map();
function putChallenge(id, challenge) {
  webauthnChallenges.set(id, { challenge, expires: Date.now() + 5 * 60 * 1000 });
}
function takeChallenge(id) {
  const c = webauthnChallenges.get(id);
  webauthnChallenges.delete(id);
  if (!c || c.expires < Date.now()) return null;
  return c.challenge;
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of webauthnChallenges) if (v.expires < now) webauthnChallenges.delete(k);
}, 5 * 60 * 1000);

// List registered passkeys (admin only). Returns management metadata only —
// never the wrapped private key material.
app.get('/api/passkeys', authWeb, (req, res) => {
  try {
    const rows = stmtGetAllPasskeys.all().map(p => ({
      id: p.id, label: p.label, created_at: p.created_at,
      last_used: p.last_used || null,
      cred_id_short: p.cred_id.slice(0, 12)
    }));
    return res.json({
      passkeys: rows,
      has_vault: !!getSetting('vault_pubkey'),
      count: rows.length
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Rename a passkey (admin only).
app.patch('/api/passkeys/:id', authWeb, (req, res) => {
  try {
    const { label } = req.body || {};
    if (!label || !String(label).trim()) return res.status(400).json({ error: 'A name is required' });
    const row = stmtGetPasskeyById.get(parseInt(req.params.id));
    if (!row) return res.status(404).json({ error: 'Passkey not found' });
    stmtRenamePasskey.run(String(label).trim().slice(0, 64), row.id);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Delete a passkey (admin only). Deleting the LAST passkey makes every
// passkey-encrypted file permanently unrecoverable (the vault private key can
// no longer be unwrapped) — the client must confirm via ?confirm=1.
app.delete('/api/passkeys/:id', authWeb, (req, res) => {
  try {
    const row = stmtGetPasskeyById.get(parseInt(req.params.id));
    if (!row) return res.status(404).json({ error: 'Passkey not found' });
    const total = stmtCountPasskeys.get().c;
    const isLast = total <= 1;
    const passkeyFiles = db.prepare(`SELECT COUNT(*) AS c FROM files WHERE key_mode = 'passkey'`).get().c;
    if (isLast && req.query.confirm !== '1') {
      return res.status(409).json({
        error: 'last_passkey',
        message: 'This is your LAST passkey. Deleting it will make ' + passkeyFiles +
          ' passkey-encrypted file(s) permanently UNRECOVERABLE. Re-send the request with ?confirm=1 to proceed.',
        affected_files: passkeyFiles
      });
    }
    stmtDeletePasskey.run(row.id);
    if (stmtCountPasskeys.get().c === 0) {
      setSetting('passkey_mode', 'off');
      // The vault keypair is now useless (no passkey can unwrap it). Drop the
      // pubkey so a future registration starts a clean new vault.
      db.prepare(`DELETE FROM settings WHERE key = 'vault_pubkey'`).run();
      console.log('[PASSKEY] last passkey removed — vault pubkey cleared');
      // Recovery keys wrap the (now dead) vault private key — useless, drop them.
      stmtDeleteAllRecovery.run();
    }
    return res.json({ ok: true, was_last: isLast });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Registration phase 1: generate options (admin only). Also mints a fresh
// per-credential PRF salt for the new passkey and tells the client whether a
// vault keypair already exists (if so, an existing passkey must unwrap the
// vault private key so it can be re-wrapped for the new one).
app.post('/api/webauthn/register/options', authWeb, async (req, res) => {
  try {
    const existing = stmtGetAllPasskeys.all();
    const options = await generateRegistrationOptions({
      rpName: WEBAUTHN_RP_NAME,
      rpID: WEBAUTHN_RP_ID,
      userName: 'nyxvault-owner',
      userDisplayName: 'NyxVault Owner',
      attestationType: 'none',
      excludeCredentials: existing.map(p => ({
        id: p.cred_id,
        transports: parseTransports(p.transports)
      })),
      authenticatorSelection: {
        // 'preferred' (not 'required') for broad platform-authenticator
        // compatibility — Windows Hello / some iCloud versions reject required
        // resident keys. Passkeys stay discoverable where the platform supports it.
        residentKey: 'preferred',
        requireResidentKey: false,
        userVerification: 'preferred'
      },
      extensions: { prf: {} }
    });
    const token = req.headers['x-session-token'];
    // Fresh 32-byte PRF salt for THIS new credential.
    const newPrfSalt = crypto.randomBytes(32).toString('base64');
    putChallenge('reg:' + token, { challenge: options.challenge, prfSalt: newPrfSalt });
    const hasVault = !!getSetting('vault_pubkey');
    return res.json({
      ...options,
      prf_salt: newPrfSalt,
      has_vault: hasVault,
      // For re-wrapping: the client authenticates with an EXISTING passkey to
      // unwrap the vault private key, then wraps it under the new passkey's KEK.
      existing_passkeys: hasVault ? existing.map(passkeyForClient) : []
    });
  } catch (err) {
    console.error('Register options error:', err);
    return res.status(500).json({ error: 'Could not generate registration options' });
  }
});

// Registration phase 2: verify response (admin only) and persist the credential
// together with its wrapped copy of the vault private key. On the FIRST-ever
// registration the client also supplies the freshly generated vault_pubkey.
app.post('/api/webauthn/register/verify', authWeb, async (req, res) => {
  try {
    const token = req.headers['x-session-token'];
    const stored = takeChallenge('reg:' + token);
    if (!stored) return res.status(400).json({ error: 'Challenge expired — try again.' });
    const expectedChallenge = stored.challenge;
    const expectedPrfSalt = stored.prfSalt;
    const { credential, label, wrapped_privkey, vault_pubkey } = req.body || {};
    if (!credential) return res.status(400).json({ error: 'Missing credential' });
    if (!wrapped_privkey || typeof wrapped_privkey !== 'string') {
      return res.status(400).json({ error: 'Missing wrapped private key' });
    }

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: WEBAUTHN_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: false
    });
    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'Passkey verification failed' });
    }
    const cred = verification.registrationInfo.credential;
    const credId = cred.id;
    const publicKeyB64 = Buffer.from(cred.publicKey).toString('base64');
    const counter = cred.counter || 0;
    const transports = credential.response && credential.response.transports
      ? JSON.stringify(credential.response.transports) : null;

    if (stmtGetPasskeyByCredId.get(credId)) {
      return res.status(409).json({ error: 'This passkey is already registered.' });
    }

    const hasVault = !!getSetting('vault_pubkey');
    if (!hasVault) {
      // First passkey ever — the client generated the vault keypair. Persist
      // its public key. (The private key only ever exists wrapped.)
      if (!vault_pubkey || typeof vault_pubkey !== 'string') {
        return res.status(400).json({ error: 'First registration must include vault_pubkey' });
      }
      setSetting('vault_pubkey', vault_pubkey.slice(0, 128));
      console.log('[VAULT] initialised vault public key');
    }

    // Persist the credential + its per-credential prf salt + wrapped privkey.
    stmtInsertPasskey.run(credId, publicKeyB64, counter, transports,
      (label && String(label).slice(0, 64)) || 'Passkey',
      expectedPrfSalt, wrapped_privkey.slice(0, 4096));
    console.log('[PASSKEY] registered ' + credId.slice(0, 12) + '… (envelope-wrapped)');
    return res.json({ ok: true, cred_id_short: credId.slice(0, 12), vault_pubkey: getSetting('vault_pubkey') });
  } catch (err) {
    console.error('Register verify error:', err);
    return res.status(500).json({ error: 'Passkey registration failed: ' + err.message });
  }
});

app.post('/api/webauthn/auth/options', downloadLimiter, async (req, res) => {
  try {
    const passkeys = stmtGetAllPasskeys.all();
    const options = await generateAuthenticationOptions({
      rpID: WEBAUTHN_RP_ID,
      userVerification: 'preferred',
      allowCredentials: passkeys.map(p => ({
        id: p.cred_id,
        transports: parseTransports(p.transports)
      }))
    });
    const flowId = crypto.randomBytes(16).toString('hex');
    putChallenge('auth:' + flowId, options.challenge);
    return res.json({ ...options, flowId });
  } catch (err) {
    console.error('Auth options error:', err);
    return res.status(500).json({ error: 'Could not generate authentication options' });
  }
});

// Authentication: verify response (public). Bumps the counter (anti-replay).
// The decryption key comes from the client-side PRF result — never the server.
app.post('/api/webauthn/auth/verify', downloadLimiter, async (req, res) => {
  try {
    const { credential, flowId } = req.body || {};
    if (!credential || !flowId) return res.status(400).json({ error: 'Missing credential' });
    const expectedChallenge = takeChallenge('auth:' + flowId);
    if (!expectedChallenge) return res.status(400).json({ error: 'Challenge expired — try again.' });

    const dbCred = stmtGetPasskeyByCredId.get(credential.id);
    if (!dbCred) return res.status(404).json({ error: 'Unknown passkey' });

    const verification = await verifyAuthenticationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: WEBAUTHN_ORIGINS,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: false,
      credential: {
        id: dbCred.cred_id,
        publicKey: new Uint8Array(Buffer.from(dbCred.public_key, 'base64')),
        counter: dbCred.counter,
        transports: parseTransports(dbCred.transports)
      }
    });
    if (!verification.verified) return res.status(400).json({ error: 'Passkey authentication failed' });
    stmtUpdatePasskeyCounter.run(verification.authenticationInfo.newCounter, dbCred.cred_id);
    return res.json({ ok: true });
  } catch (err) {
    console.error('Auth verify error:', err);
    return res.status(500).json({ error: 'Passkey authentication failed: ' + err.message });
  }
});

// Add an ADDITIONAL vault-key wrap for a passkey under a new PRF context (v2.4).
// Fixes the iOS Safari hybrid-vs-on-device PRF discrepancy: after the client
// unwraps the vault private key via a WORKING channel (its existing wrap, or the
// passphrase/recovery bootstrap) and re-wraps it under the KEK derived from the
// CURRENT (e.g. on-device) PRF output, it posts that new wrap here. Thereafter
// this passkey decrypts directly in the current context. The server only stores
// opaque ciphertext + an opaque context label — it never sees the vault key or
// the PRF value. Public endpoint (no admin): adding a wrap requires already
// possessing a valid wrap ciphertext, which itself required a passkey ceremony.
app.post('/api/webauthn/add-wrap', downloadLimiter, (req, res) => {
  try {
    const { cred_id, prf_context, wrapped_privkey } = req.body || {};
    if (!cred_id || typeof cred_id !== 'string') return res.status(400).json({ error: 'Missing cred_id' });
    if (!wrapped_privkey || typeof wrapped_privkey !== 'string' || wrapped_privkey.length > 4096) {
      return res.status(400).json({ error: 'Missing or invalid wrapped_privkey' });
    }
    // Opaque, bounded label; default to 'platform' (the on-device context).
    let ctx = (typeof prf_context === 'string' && prf_context) ? prf_context : 'platform';
    ctx = ctx.replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 32) || 'platform';
    const row = stmtGetPasskeyByCredIdRow.get(cred_id);
    if (!row) return res.status(404).json({ error: 'Unknown passkey' });
    stmtInsertWrap.run(row.id, ctx, wrapped_privkey);
    console.log('[WRAP] added “' + ctx + '” vault-key wrap for passkey #' + row.id);
    return res.json({ ok: true });
  } catch (err) {
    console.error('Add-wrap error:', err);
    return res.status(500).json({ error: 'Could not store the wrap' });
  }
});

// Open a tweetnacl SEALED box: layout ephPub(32) || nonce(24) || box_ct.
// Mirror of nyx-decrypt.js sealOpen(); returns Uint8Array | null.
function serverSealOpen(sealed, recipPub, recipSec) {
  const eph = sealed.subarray(0, 32);
  const nonce = sealed.subarray(32, 56);
  const ct = sealed.subarray(56);
  return nacl.box.open(new Uint8Array(ct), new Uint8Array(nonce), new Uint8Array(eph), recipSec);
}

// GENERIC device-calibration bootstrap (v2.4). When a passkey returns a
// DIFFERENT PRF value on-device than the one it was registered with (the iOS/
// WebKit hybrid-vs-on-device bug), the browser can't unwrap the vault key in
// the current context and has no working channel ON THE DEVICE ITSELF. Any
// self-hoster who has set up a recovery key (Admin → “Add recovery key”) can
// use it as that channel: after an ADMIN login, the server opens the recovery
// wrap with its recovery private-key FILE, returns the vault private key to the
// browser, and the browser re-wraps it under the current on-device PRF KEK via
// /api/webauthn/add-wrap. This works for EVERYONE, needs no second device, and
// stays gated behind the admin password + a finalized recovery key.
// ⚠️ This intentionally hands the vault private key to an authenticated admin
// browser — exactly the same trust boundary the recovery key already implies.
app.post('/api/webauthn/recovery-bootstrap', authWeb, (req, res) => {
  try {
    if (!getSetting('vault_pubkey')) {
      return res.status(400).json({ error: 'No passkey vault exists yet' });
    }
    // Need the recovery private-key file on disk.
    let keyFile;
    try {
      keyFile = JSON.parse(fs.readFileSync(RECOVERY_KEY_PATH, 'utf8'));
    } catch {
      return res.status(409).json({ error: 'No recovery key is set up on this server. Add one in Admin → Passkeys → “Add recovery key” first.' });
    }
    const rows = stmtGetAllRecovery.all().filter(r => r.wrapped_privkey);
    // Match the DB row whose pubkey belongs to the on-disk private key.
    const recPub = new Uint8Array(Buffer.from(keyFile.publicKey, 'base64'));
    const recPriv = new Uint8Array(Buffer.from(keyFile.privateKey, 'base64'));
    const row = rows.find(r => r.pubkey === keyFile.publicKey);
    if (!row) {
      return res.status(409).json({ error: 'The recovery key on disk has not been finalized. Redo “Add recovery key” in the admin UI.' });
    }
    const vaultPriv = serverSealOpen(Buffer.from(row.wrapped_privkey, 'base64'), recPub, recPriv);
    if (!vaultPriv) {
      return res.status(500).json({ error: 'Recovery unwrap failed (key mismatch).' });
    }
    const out = Buffer.from(vaultPriv).toString('base64');
    vaultPriv.fill(0);
    console.log('[BOOTSTRAP] served vault key via recovery key for on-device calibration');
    return res.json({ ok: true, vault_privkey: out });
  } catch (err) {
    console.error('Recovery-bootstrap error:', err);
    return res.status(500).json({ error: 'Bootstrap failed' });
  }
});

// ── Recovery key (agent decryption) ──────────────────────────────────────────
// Lets the server operator's agent decrypt PASSKEY-mode files without a
// biometric authenticator. Flow:
//   1. POST /api/recovery/init (admin): server generates an X25519 keypair,
//      writes the PRIVATE key to RECOVERY_KEY_PATH (chmod 600, outside git)
//      and returns the PUBLIC key + the registered passkeys' wrapping data.
//   2. The BROWSER runs one passkey ceremony, unwraps the vault private key
//      locally and seals it to the recovery public key (sealed box — the
//      server never sees the vault private key in plaintext at any point).
//   3. POST /api/recovery/finalize (admin) stores that wrap.
// Afterwards the CLI (nyx-decrypt.js --recovery, on the server host) can open
// the wrap with the recovery private key file and decrypt passkey-mode files.
app.get('/api/recovery', authWeb, (req, res) => {
  try {
    const rows = stmtGetAllRecovery.all().map(r => ({
      id: r.id,
      label: r.label,
      created_at: r.created_at,
      finalized: !!r.wrapped_privkey,
      pubkey_short: (r.pubkey || '').slice(0, 12)
    }));
    return res.json({ recovery_keys: rows, count: rows.length });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/recovery/init', authWeb, (req, res) => {
  try {
    if (!getSetting('vault_pubkey')) {
      return res.status(400).json({ error: 'No passkey vault exists yet — register a passkey first.' });
    }
    const label = (req.body && req.body.label ? String(req.body.label) : 'Agent recovery key').trim().slice(0, 64) || 'Agent recovery key';
    // Generate the recovery keypair server-side: the whole point is that the
    // PRIVATE key ends up in a file the agent on this host can read.
    const kp = nacl.box.keyPair();
    const pubB64 = Buffer.from(kp.publicKey).toString('base64');
    const result = stmtInsertRecovery.run(label, pubB64);
    const recoveryId = result.lastInsertRowid;
    const keyFile = {
      id: recoveryId,
      label,
      publicKey: pubB64,
      privateKey: Buffer.from(kp.secretKey).toString('base64'),
      created: new Date().toISOString(),
      note: 'NyxVault recovery private key. Anyone with this file + DB access can decrypt passkey-mode files. chmod 600, never commit.'
    };
    fs.mkdirSync(path.dirname(RECOVERY_KEY_PATH), { recursive: true });
    fs.writeFileSync(RECOVERY_KEY_PATH, JSON.stringify(keyFile, null, 2) + '\n', { mode: 0o600 });
    try { fs.chmodSync(RECOVERY_KEY_PATH, 0o600); } catch {}
    kp.secretKey.fill(0);
    console.log('[RECOVERY] generated recovery keypair #' + recoveryId + ' → ' + RECOVERY_KEY_PATH);
    // The browser needs the passkeys' wrapping data to run the unwrap ceremony.
    const passkeys = stmtGetAllPasskeys.all().map(passkeyForClient);
    return res.json({ recovery_id: recoveryId, recovery_pubkey: pubB64, passkeys });
  } catch (err) {
    console.error('Recovery init error:', err);
    return res.status(500).json({ error: 'Could not create recovery key' });
  }
});

app.post('/api/recovery/finalize', authWeb, (req, res) => {
  try {
    const { recovery_id, wrapped_privkey } = req.body || {};
    const row = stmtGetRecoveryById.get(parseInt(recovery_id));
    if (!row) return res.status(404).json({ error: 'Unknown recovery key' });
    if (row.wrapped_privkey) return res.status(409).json({ error: 'This recovery key is already finalized' });
    if (!wrapped_privkey || typeof wrapped_privkey !== 'string' || wrapped_privkey.length > 4096) {
      return res.status(400).json({ error: 'Missing or invalid wrapped_privkey' });
    }
    stmtFinalizeRecovery.run(wrapped_privkey, row.id);
    console.log('[RECOVERY] finalized recovery key #' + row.id + ' — agent decryption is now possible');
    return res.json({ ok: true, recovery_id: row.id });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/recovery/:id', authWeb, (req, res) => {
  try {
    const row = stmtGetRecoveryById.get(parseInt(req.params.id));
    if (!row) return res.status(404).json({ error: 'Recovery key not found' });
    stmtDeleteRecovery.run(row.id);
    // Best-effort: remove the private key file if it belongs to this entry.
    try {
      const kf = JSON.parse(fs.readFileSync(RECOVERY_KEY_PATH, 'utf8'));
      if (kf && kf.id === row.id) fs.unlinkSync(RECOVERY_KEY_PATH);
    } catch {}
    console.log('[RECOVERY] deleted recovery key #' + row.id);
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── Health ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'nyxvault', version: VERSION, uptime: process.uptime() });
});

// ── Session cleanup (every 30min) ─────────────────────────
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of sessions) {
    if (session.expires < now) sessions.delete(token);
  }
}, 30 * 60 * 1000);

// ── Expired files cleanup (every 30min) ───────────────────
setInterval(() => {
  try {
    const now = new Date().toISOString();
    const expired = stmtGetExpired.all(now);
    for (const f of expired) {
      secureDelete(path.join(STORAGE_DIR, f.download_token));
      stmtDelete.run(f.id);
    }
    if (expired.length > 0) console.log(`[CLEANUP] Removed ${expired.length} expired file(s)`);

    // Orphaned multer temp files: aborted uploads leave random-named temp files
    // (32 hex chars) in the storage dir. Real blobs are 64-hex download tokens.
    // Remove any non-token file older than 24h.
    const cutoff = Date.now() - 24 * 60 * 60 * 1000;
    for (const name of fs.readdirSync(STORAGE_DIR)) {
      if (/^[a-f0-9]{64}$/.test(name)) continue; // real encrypted blob
      const p = path.join(STORAGE_DIR, name);
      try {
        const st = fs.statSync(p);
        if (st.isFile() && st.mtimeMs < cutoff) {
          fs.unlinkSync(p);
          console.log(`[CLEANUP] Removed orphaned temp file ${name}`);
        }
      } catch { /* ignore races */ }
    }
  } catch (err) {
    console.error('Cleanup error:', err);
  }
}, 30 * 60 * 1000);

// ── Start ─────────────────────────────────────────────────
const httpServer = app.listen(PORT, '127.0.0.1', () => {
  console.log(`🔐 NyxVault running on http://127.0.0.1:${PORT}`);
  console.log(`   Storage: ${STORAGE_DIR}`);
  console.log(`   Database: ${DB_PATH}`);
});
// Allow long uploads (large encrypted backups) without aborting mid-transfer
httpServer.requestTimeout = 0;          // no overall request timeout
httpServer.headersTimeout = 5 * 60 * 1000;
httpServer.keepAliveTimeout = 10 * 60 * 1000;
httpServer.timeout = 0;                 // disable socket inactivity timeout
