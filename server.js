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
const { v4: uuidv4 } = require('uuid');

const app = express();
app.disable('x-powered-by');
app.set('trust proxy', 1);

// Security headers
app.use((req, res, next) => {
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'");
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
});
app.disable('x-powered-by');
const PORT = parseInt(process.env.PORT) || 3870;
const API_KEY = process.env.API_KEY;
const WEB_PASSWORD = process.env.WEB_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;
const MAX_FILE_SIZE = (parseInt(process.env.MAX_FILE_SIZE_MB) || 100) * 1024 * 1024;
const VT_API_KEY = process.env.VT_API_KEY || '';
// WebAuthn / passkey configuration. RP ID + origin must match the public
// hostname (Caddy) — never localhost, or the browser rejects the ceremony.
const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID || 'nyxvault.org';
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || 'NyxVault';
const WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN || 'https://nyxvault.org';

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

// Simple in-memory cache for VirusTotal hash lookups (1h TTL)
const vtCache = new Map();

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
const DB_PATH = path.join(__dirname, 'data', 'vault.db');
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
  // Per-file key mode: 'passphrase' (default, Argon2id) or 'passkey' (WebAuthn PRF).
  // Old files have no column → default to 'passphrase' so nothing breaks.
  if (!cols.includes('key_mode')) {
    db.exec(`ALTER TABLE files ADD COLUMN key_mode TEXT NOT NULL DEFAULT 'passphrase'`);
    console.log('[MIGRATE] added column key_mode');
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

// One global PRF salt, shared across every registered passkey so that ANY of
// Fabian's devices (iPhone + Laptop, iCloud-synced or not) can decrypt ANY
// passkey-encrypted file. The salt is not secret — it's a domain-separation
// nonce for the PRF evaluation — so it's safe to expose to the download page.
// Generated exactly once on first boot.
if (!getSetting('prf_salt')) {
  setSetting('prf_salt', crypto.randomBytes(32).toString('base64'));
  console.log('[INIT] generated global PRF salt');
}
if (!getSetting('passkey_mode')) setSetting('passkey_mode', 'off');

// ── Passkeys table (WebAuthn credentials) ─────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS passkeys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    cred_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    label TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);
const stmtInsertPasskey = db.prepare(`INSERT INTO passkeys (cred_id, public_key, counter, transports, label) VALUES (?, ?, ?, ?, ?)`);
const stmtGetAllPasskeys = db.prepare(`SELECT * FROM passkeys ORDER BY created_at ASC`);
const stmtGetPasskeyByCredId = db.prepare(`SELECT * FROM passkeys WHERE cred_id = ?`);
const stmtUpdatePasskeyCounter = db.prepare(`UPDATE passkeys SET counter = ? WHERE cred_id = ?`);
const stmtDeletePasskey = db.prepare(`DELETE FROM passkeys WHERE id = ?`);
const stmtCountPasskeys = db.prepare(`SELECT COUNT(*) AS c FROM passkeys`);

// Prepared statements
const stmtInsert = db.prepare(`
  INSERT INTO files (filename_enc, uploader, size_bytes, download_token, content_type_enc, expires_at, nonce, original_name, burn_after_read, key_mode)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtMarkDownloaded = db.prepare(`UPDATE files SET downloaded_at = datetime('now') WHERE id = ?`);
const stmtGetAll = db.prepare(`SELECT * FROM files ORDER BY upload_date DESC`);
// Pagination + lazy-expiry helpers (treat NULL expires_at as never-expiring).
const stmtGetExpired = db.prepare(`SELECT id, download_token FROM files WHERE expires_at IS NOT NULL AND expires_at < ?`);
const stmtCountActive = db.prepare(`SELECT COUNT(*) AS c FROM files WHERE expires_at IS NULL OR expires_at >= ?`);
const stmtGetPage = db.prepare(`SELECT * FROM files WHERE expires_at IS NULL OR expires_at >= ? ORDER BY upload_date DESC LIMIT ? OFFSET ?`);
const stmtGetById = db.prepare(`SELECT * FROM files WHERE id = ?`);
const stmtGetByToken = db.prepare(`SELECT * FROM files WHERE download_token = ?`);
const stmtDelete = db.prepare(`DELETE FROM files WHERE id = ?`);

// ── Storage ───────────────────────────────────────────────
const STORAGE_DIR = path.join(__dirname, 'storage');
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
    // Per-file key mode: 'passkey' (WebAuthn PRF) or 'passphrase' (default).
    const keyMode = (req.body.key_mode === 'passkey') ? 'passkey' : 'passphrase';
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
      keyMode
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
      const filePath = path.join(STORAGE_DIR, f.download_token);
      if (fs.existsSync(filePath)) { try { fs.unlinkSync(filePath); } catch {} }
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
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
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
      vtCache.set(hash, { data, expires: Date.now() + 60 * 60 * 1000 });
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
    vtCache.set(hash, { data, expires: Date.now() + 60 * 60 * 1000 });
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
      // The PRF salt is a non-secret domain-separation nonce; the download page
      // needs it to re-derive the same key from the visitor's passkey.
      prf_salt: (file.key_mode === 'passkey') ? getSetting('prf_salt') : undefined
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
      if (file.downloaded_at) {
        return res.status(410).json({ error: 'This burn-after-reading file has already been retrieved.' });
      }
      stmtMarkDownloaded.run(file.id);
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
      prf_salt: getSetting('prf_salt')
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

// List registered passkeys (admin only)
app.get('/api/passkeys', authWeb, (req, res) => {
  try {
    const rows = stmtGetAllPasskeys.all().map(p => ({
      id: p.id, label: p.label, created_at: p.created_at,
      cred_id_short: p.cred_id.slice(0, 12)
    }));
    return res.json({ passkeys: rows });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Delete a passkey (admin only). If it was the last one, auto-disable passkey mode.
app.delete('/api/passkeys/:id', authWeb, (req, res) => {
  try {
    stmtDeletePasskey.run(parseInt(req.params.id));
    if (stmtCountPasskeys.get().c === 0) setSetting('passkey_mode', 'off');
    return res.json({ ok: true });
  } catch (err) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// Registration: generate options (admin only). Requests the PRF extension so
// the credential can later produce a stable secret for key derivation.
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
        transports: p.transports ? JSON.parse(p.transports) : undefined
      })),
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'preferred'
      },
      extensions: { prf: {} }
    });
    const token = req.headers['x-session-token'];
    putChallenge('reg:' + token, options.challenge);
    return res.json(options);
  } catch (err) {
    console.error('Register options error:', err);
    return res.status(500).json({ error: 'Could not generate registration options' });
  }
});

// Registration: verify response (admin only) and persist the credential.
app.post('/api/webauthn/register/verify', authWeb, async (req, res) => {
  try {
    const token = req.headers['x-session-token'];
    const expectedChallenge = takeChallenge('reg:' + token);
    if (!expectedChallenge) return res.status(400).json({ error: 'Challenge expired — try again.' });
    const { credential, label } = req.body || {};
    if (!credential) return res.status(400).json({ error: 'Missing credential' });

    const verification = await verifyRegistrationResponse({
      response: credential,
      expectedChallenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
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
    const prfEnabled = !!(credential.clientExtensionResults &&
      credential.clientExtensionResults.prf &&
      credential.clientExtensionResults.prf.enabled);

    stmtInsertPasskey.run(credId, publicKeyB64, counter, transports,
      (label && String(label).slice(0, 64)) || 'Passkey');
    console.log('[PASSKEY] registered ' + credId.slice(0, 12) + '… (prf=' + prfEnabled + ')');
    return res.json({ ok: true, prf_enabled: prfEnabled, cred_id_short: credId.slice(0, 12) });
  } catch (err) {
    console.error('Register verify error:', err);
    return res.status(500).json({ error: 'Passkey registration failed: ' + err.message });
  }
});

// Authentication: generate options (public).
app.post('/api/webauthn/auth/options', downloadLimiter, async (req, res) => {
  try {
    const passkeys = stmtGetAllPasskeys.all();
    const options = await generateAuthenticationOptions({
      rpID: WEBAUTHN_RP_ID,
      userVerification: 'preferred',
      allowCredentials: passkeys.map(p => ({
        id: p.cred_id,
        transports: p.transports ? JSON.parse(p.transports) : undefined
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
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: false,
      credential: {
        id: dbCred.cred_id,
        publicKey: new Uint8Array(Buffer.from(dbCred.public_key, 'base64')),
        counter: dbCred.counter,
        transports: dbCred.transports ? JSON.parse(dbCred.transports) : undefined
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

// ── Health ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'nyxvault', version: '2.1.0', uptime: process.uptime() });
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
    const files = stmtGetAll.all();
    const now = new Date().toISOString();
    let cleaned = 0;
    for (const f of files) {
      if (f.expires_at && f.expires_at < now) {
        const filePath = path.join(STORAGE_DIR, f.download_token);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        stmtDelete.run(f.id);
        cleaned++;
      }
    }
    if (cleaned > 0) console.log(`[CLEANUP] Removed ${cleaned} expired file(s)`);
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
