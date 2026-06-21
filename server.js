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
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; frame-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'");
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

// Cache the download page HTML (with cachebust injected)
const DL_PAGE_HTML = (() => {
  try {
    const html = fs.readFileSync(path.join(__dirname, 'dl-page.html'), 'utf8');
    return html.replace(/__CACHEBUST__/g, String(Date.now()));
  } catch { return null; }
})();

// Simple in-memory cache for VirusTotal hash lookups (1h TTL)
const vtCache = new Map();

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
    original_name TEXT
  );
  CREATE INDEX IF NOT EXISTS idx_download_token ON files(download_token);
`);

// Prepared statements
const stmtInsert = db.prepare(`
  INSERT INTO files (filename_enc, uploader, size_bytes, download_token, content_type_enc, expires_at, nonce, original_name, burn_after_read)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const stmtMarkDownloaded = db.prepare(`UPDATE files SET downloaded_at = datetime('now') WHERE id = ?`);
const stmtGetAll = db.prepare(`SELECT * FROM files ORDER BY upload_date DESC`);
const stmtGetById = db.prepare(`SELECT * FROM files WHERE id = ?`);
const stmtGetByToken = db.prepare(`SELECT * FROM files WHERE download_token = ?`);
const stmtDelete = db.prepare(`DELETE FROM files WHERE id = ?`);

// ── Storage ───────────────────────────────────────────────
const STORAGE_DIR = path.join(__dirname, 'storage');
if (!fs.existsSync(STORAGE_DIR)) fs.mkdirSync(STORAGE_DIR, { recursive: true });

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
  if (fs.existsSync(landing)) return res.sendFile(landing);
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
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
    const expiresAt = req.body.expires_at || null;
    const nonce = req.body.nonce || '';
    const burnAfterRead = (req.body.burn_after_read === '1' || req.body.burn_after_read === 'true' || req.body.burn_after_read === true) ? 1 : 0;
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
      burnAfterRead
    );

    const file = stmtGetById.get(result.lastInsertRowid);

    console.log(`[UPLOAD] ${(fileSize / 1024).toFixed(1)}KB by ${req.uploader} → token:${downloadToken.slice(0, 8)}...`);

    return res.json({
      id: file.id,
      download_token: downloadToken,
      download_url: `/dl/${downloadToken}`,
      size_bytes: fileSize,
      upload_date: file.upload_date
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
    const files = stmtGetAll.all();
    // Check and clean expired files
    const now = new Date().toISOString();
    const active = [];
    for (const f of files) {
      if (f.expires_at && f.expires_at < now) {
        // Delete expired file
        const filePath = path.join(STORAGE_DIR, f.download_token);
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
        stmtDelete.run(f.id);
        continue;
      }
      active.push(f);
    }
    return res.json({ files: active, count: active.length });
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
    res.sendFile(path.join(__dirname, 'dl-page.html'));
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
      burn_after_read: !!file.burn_after_read
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
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);
    stmtDelete.run(file.id);
    console.log(`[BURN] File #${file.id} self-destructed after read (token:${file.download_token.slice(0,8)}...)`);
    return res.json({ burned: true });
  } catch (err) {
    console.error('Burn error:', err.message);
    return res.status(500).json({ error: 'Burn failed' });
  }
});

// ── Health ────────────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'nyxvault', version: '1.0.0', uptime: process.uptime() });
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
app.listen(PORT, '127.0.0.1', () => {
  console.log(`🔐 NyxVault running on http://127.0.0.1:${PORT}`);
  console.log(`   Storage: ${STORAGE_DIR}`);
  console.log(`   Database: ${DB_PATH}`);
});
