#!/usr/bin/env node
'use strict';

// ─────────────────────────────────────────────────────────────────────────────
// NyxVault — Upload CLI
//
// Encrypts a file CLIENT-SIDE (Argon2id + XSalsa20-Poly1305 via TweetNaCl) and
// uploads only the ciphertext. The server NEVER sees your passphrase or content.
//
// Configuration (environment variables):
//   NYXVAULT_API_KEY     (required)  API key for your NyxVault instance
//   NYXVAULT_URL         (optional)  Base URL, default https://nyxvault.org
//   NYXVAULT_PASSPHRASE  (optional)  Encryption passphrase (or pass as arg 4)
//   NYXVAULT_BURN        (optional)  "1" → burn-after-reading (or pass "burn" as arg 5)
//
// Usage:
//   node nyx-upload.js <file> [expires_in] [passphrase] [burn]
//     <file>        Path to the file to upload
//     [expires_in]  1h | 24h | 7d | 30d | 90m  (optional, default: never)
//     [passphrase]  Encryption passphrase (optional if NYXVAULT_PASSPHRASE set)
//     [burn]        literal "burn" to enable burn-after-reading
//
// Example:
//   NYXVAULT_API_KEY=xxx node nyx-upload.js secret.pdf 24h 'my passphrase' burn
// ─────────────────────────────────────────────────────────────────────────────

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const API_KEY = process.env.NYXVAULT_API_KEY || '';
const BASE_URL = process.env.NYXVAULT_URL || 'https://nyxvault.org';
// Passphrase is now OPTIONAL. If omitted AND the server has a vault public key,
// we upload in PASSKEY mode (envelope: random FEK sealed to the vault pubkey).
// If a passphrase IS supplied, we keep the classic passphrase mode.
const PASSPHRASE = process.argv[4] || process.env.NYXVAULT_PASSPHRASE || '';
const PASSPHRASE_EXPLICIT = !!(process.argv[4] || process.env.NYXVAULT_PASSPHRASE);

const crypto = require('crypto');

const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC3 = Buffer.from('NYX3');  // integrity-protected format
const CHUNK_PREFIX_BYTES = 5; // 4-byte index BE + 1-byte is_last

async function deriveKey(passphrase, salt) {
  const key = await argon2id({
    password: passphrase,
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16 MB
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

// Chunked encryption: NYX3(4) + salt(16) + header_hmac(32) + num_chunks(4 BE) + [nonce(24) + ciphertext]...
// Each chunk plaintext is prefixed with: chunk_index(4 BE) + is_last(1)
async function encryptDataChunked(data, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const numChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));

  // Derive HMAC subkey (domain separation)
  const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();

  // Build header for HMAC: magic + salt + num_chunks
  const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC3.copy(headerForHMAC, 0);
  Buffer.from(salt).copy(headerForHMAC, 4);
  headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  const headerHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();

  const buffers = [];
  // Header: magic(4) + salt(16) + hmac(32) + num_chunks(4)
  const header = Buffer.alloc(4 + SALT_BYTES + 32 + 4);
  MAGIC3.copy(header, 0);
  Buffer.from(salt).copy(header, 4);
  headerHMAC.copy(header, 4 + SALT_BYTES);
  header.writeUInt32BE(numChunks, 4 + SALT_BYTES + 32);
  buffers.push(header);

  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunkData = data.slice(start, end);
    const isLast = (i === numChunks - 1) ? 1 : 0;

    // Prepend 5-byte prefix: chunk_index(4 BE) + is_last(1)
    const prefixed = Buffer.alloc(CHUNK_PREFIX_BYTES + chunkData.length);
    prefixed.writeUInt32BE(i, 0);
    prefixed[4] = isLast;
    chunkData.copy(prefixed, CHUNK_PREFIX_BYTES);

    const nonce = nacl.randomBytes(NONCE_BYTES);
    const enc = nacl.secretbox(new Uint8Array(prefixed), nonce, key);
    buffers.push(Buffer.from(nonce));
    buffers.push(Buffer.from(enc));
    process.stdout.write(`\r  Encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(buffers);
}

// Encrypt a short string (filename / content-type) — single-block legacy format
async function encryptString(str, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const key = await deriveKey(passphrase, salt);
  const enc = nacl.secretbox(new TextEncoder().encode(str), nonce, key);
  return Buffer.concat([Buffer.from(salt), Buffer.from(nonce), Buffer.from(enc)]).toString('base64');
}

// ── Sealed box (anonymous X25519) via tweetnacl ───────────
// seal(msg, recipPub) → eph_pub(32) || nonce(24) || box(msg, nonce, recipPub, eph_sec)
// Matches public/lib/passkey.js so the browser can unseal it with the vault
// private key (unwrapped via any registered passkey).
function sealTo(message, recipPubB64) {
  const recipPub = new Uint8Array(Buffer.from(recipPubB64, 'base64'));
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const ct = nacl.box(message, nonce, recipPub, eph.secretKey);
  const out = Buffer.concat([Buffer.from(eph.publicKey), Buffer.from(nonce), Buffer.from(ct)]);
  eph.secretKey.fill(0);
  return out; // Buffer
}

// Encrypt a file with a raw 32-byte key (FEK) instead of an Argon2 passphrase.
// Produces the SAME NYX3 blob format — only the key SOURCE differs.
async function encryptDataChunkedWithKey(data, key) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const numChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));
  const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();
  const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC3.copy(headerForHMAC, 0);
  Buffer.from(salt).copy(headerForHMAC, 4);
  headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  const headerHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();
  const buffers = [];
  const header = Buffer.alloc(4 + SALT_BYTES + 32 + 4);
  MAGIC3.copy(header, 0);
  Buffer.from(salt).copy(header, 4);
  headerHMAC.copy(header, 4 + SALT_BYTES);
  header.writeUInt32BE(numChunks, 4 + SALT_BYTES + 32);
  buffers.push(header);
  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunkData = data.slice(start, end);
    const isLast = (i === numChunks - 1) ? 1 : 0;
    const prefixed = Buffer.alloc(CHUNK_PREFIX_BYTES + chunkData.length);
    prefixed.writeUInt32BE(i, 0);
    prefixed[4] = isLast;
    chunkData.copy(prefixed, CHUNK_PREFIX_BYTES);
    const nonce = nacl.randomBytes(NONCE_BYTES);
    const enc = nacl.secretbox(new Uint8Array(prefixed), nonce, key);
    buffers.push(Buffer.from(nonce));
    buffers.push(Buffer.from(enc));
    process.stdout.write(`\r  Encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(buffers);
}

// Encrypt a short string (filename / type) with a raw FEK.
function encryptStringWithKey(str, key) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const enc = nacl.secretbox(new TextEncoder().encode(str), nonce, key);
  return Buffer.concat([Buffer.from(salt), Buffer.from(nonce), Buffer.from(enc)]).toString('base64');
}

// Fetch server settings (vault public key + key-mode default).
function getJSON(urlStr, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const transport = parsed.protocol === 'http:' ? http : https;
    const req = transport.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path: parsed.pathname + (parsed.search || ''),
      method: 'GET',
      headers: headers || {}
    }, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => { try { resolve(JSON.parse(body)); } catch { reject(new Error('Bad settings response: ' + body.slice(0,120))); } });
    });
    req.on('error', reject);
    req.end();
  });
}

function postForm(urlStr, form, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(urlStr);
    const transport = parsed.protocol === 'http:' ? http : https;
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'http:' ? 80 : 443),
      path: parsed.pathname,
      method: 'POST',
      headers: { ...form.getHeaders(), ...headers }
    };
    const req = transport.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); }
        catch { reject(new Error(`Non-JSON response (${res.statusCode}): ${body.slice(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    form.pipe(req);
  });
}

async function upload(filePath, expiresIn, burn) {
  if (!API_KEY) {
    console.error('❌ NYXVAULT_API_KEY is not set. Export it before uploading.');
    process.exit(1);
  }

  const fileName = path.basename(filePath);
  const fileData = fs.readFileSync(filePath);

  // Decide mode: explicit passphrase → passphrase mode. Otherwise, if the
  // server has a vault public key → passkey mode (envelope). Otherwise error.
  let mode = 'passphrase';
  let vaultPubkey = null;
  if (!PASSPHRASE_EXPLICIT) {
    try {
      const settings = await getJSON(`${BASE_URL}/api/settings`);
      vaultPubkey = settings && settings.vault_pubkey;
    } catch (e) { /* fall through to the error below */ }
    if (vaultPubkey) {
      mode = 'passkey';
    } else {
      console.error('❌ No passphrase given and the server has no passkey vault.');
      console.error('   Either pass a passphrase (arg 4 / NYXVAULT_PASSPHRASE),');
      console.error('   or register a passkey in the web admin to enable passkey encryption.');
      process.exit(1);
    }
  }

  let encryptedData, encryptedNameB64, encryptedTypeB64, wrappedFekB64 = null;
  if (mode === 'passkey') {
    console.log(`🔑 Passkey mode — sealing a file key to the vault public key.`);
    const fek = nacl.randomBytes(32);
    console.log(`🔐 Encrypting ${fileName} (${fileData.length} bytes)...`);
    encryptedData = await encryptDataChunkedWithKey(fileData, fek);
    encryptedNameB64 = encryptStringWithKey(fileName, fek);
    encryptedTypeB64 = encryptStringWithKey('application/octet-stream', fek);
    wrappedFekB64 = sealTo(fek, vaultPubkey).toString('base64');
    fek.fill(0);
  } else {
    console.log(`🔐 Encrypting ${fileName} (${fileData.length} bytes)...`);
    encryptedData = await encryptDataChunked(fileData, PASSPHRASE);
    encryptedNameB64 = await encryptString(fileName, PASSPHRASE);
    encryptedTypeB64 = await encryptString('application/octet-stream', PASSPHRASE);
  }

  console.log(`📤 Uploading encrypted blob (${encryptedData.length} bytes)...`);

  const form = new FormData();
  form.append('file', encryptedData, { filename: 'encrypted.bin', contentType: 'application/octet-stream' });
  form.append('uploader', 'cli');
  form.append('filename_enc', encryptedNameB64);
  form.append('content_type_enc', encryptedTypeB64);
  if (mode === 'passkey') {
    form.append('key_mode', 'passkey');
    form.append('wrapped_fek', wrappedFekB64);
  }
  if (expiresIn) form.append('expires_in', expiresIn);
  if (burn) {
    form.append('burn_after_read', '1');
    console.log('🔥 Burn-after-reading enabled — file self-destructs after first decrypt.');
  }

  const result = await postForm(`${BASE_URL}/api/upload`, form, { 'X-Api-Key': API_KEY });

  if (result.download_token) {
    console.log(`\n✅ Upload successful!`);
    if (result.key_mode === 'passkey') console.log(`🔑 Encrypted for your passkeys — open the link in a browser with a registered passkey.`);
    console.log(`📎 Download link: ${BASE_URL}/dl/${result.download_token}`);
    if (result.expires_at) console.log(`⏳ Expires at: ${result.expires_at}`);
    if (result.burn_after_read) console.log(`🔥 Self-destructs after first read.`);
    return `${BASE_URL}/dl/${result.download_token}`;
  }
  console.error('❌ Upload failed:', result);
  process.exit(1);
}

const filePath = process.argv[2];
const expiresIn = process.argv[3] && /^\d+\s*[mhd]$/i.test(process.argv[3]) ? process.argv[3] : null;
const burn = process.env.NYXVAULT_BURN === '1' || process.argv[5] === 'burn';

if (!filePath) {
  console.log('NyxVault Upload CLI');
  console.log('Usage: node nyx-upload.js <file> [expires_in: 1h|24h|7d|30d] [passphrase] [burn]');
  console.log('Env:   NYXVAULT_API_KEY (required), NYXVAULT_URL, NYXVAULT_PASSPHRASE, NYXVAULT_BURN');
  console.log('');
  console.log('Modes:');
  console.log('  • No passphrase given → PASSKEY mode (default). The file key is sealed to');
  console.log('    the vault public key; decrypt in a browser with any registered passkey.');
  console.log('  • Passphrase given    → passphrase mode (Argon2id). Passkeys cannot open it.');
  process.exit(1);
}
upload(filePath, expiresIn, burn).catch(e => { console.error('❌', e.message); process.exit(1); });
