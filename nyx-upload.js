#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');
const FormData = require('form-data');
const https = require('https');
const { URL } = require('url');

const API_KEY = process.env.NYXVAULT_API_KEY || '';
const BASE_URL = process.env.NYXVAULT_URL || 'https://nyxvault.org';
const DEFAULT_PASSPHRASE = process.env.NYXVAULT_PASSPHRASE || 'KosmischerLobster!2026';
const PASSPHRASE = process.argv[4] || DEFAULT_PASSPHRASE;
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024; // 4 MB
const MAGIC = Buffer.from('NYX2'); // chunked format magic

async function deriveKey(passphrase, salt) {
  const key = await argon2id({
    password: passphrase,
    salt: salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 16384, // 16MB (was 64MB)
    hashLength: 32,
    outputType: 'binary'
  });
  return new Uint8Array(key);
}

// Chunked encryption: NYX2(4) + salt(16) + num_chunks(4 BE) + [nonce(24) + ciphertext]...
async function encryptDataChunked(data, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt);
  const numChunks = Math.ceil(data.length / CHUNK_SIZE);

  const chunkBuffers = [];

  // Header: magic + salt + num_chunks
  const header = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC.copy(header, 0);
  Buffer.from(salt).copy(header, 4);
  header.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  chunkBuffers.push(header);

  for (let i = 0; i < numChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, data.length);
    const chunk = data.slice(start, end);
    const nonce = nacl.randomBytes(NONCE_BYTES);
    const encrypted = nacl.secretbox(new Uint8Array(chunk), nonce, key);
    chunkBuffers.push(Buffer.from(nonce));
    chunkBuffers.push(Buffer.from(encrypted));
    process.stdout.write(`\r  Encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');

  return Buffer.concat(chunkBuffers);
}

// Legacy string encryption (for metadata like filename)
async function encryptString(str, passphrase) {
  const salt = nacl.randomBytes(SALT_BYTES);
  const nonce = nacl.randomBytes(NONCE_BYTES);
  const key = await deriveKey(passphrase, salt);
  const encrypted = nacl.secretbox(new TextEncoder().encode(str), nonce, key);
  const result = Buffer.concat([Buffer.from(salt), Buffer.from(nonce), Buffer.from(encrypted)]);
  return result.toString('base64');
}

function postForm(url, form, headers) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.pathname,
      method: 'POST',
      headers: { ...form.getHeaders(), ...headers }
    };
    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } 
        catch(e) { reject(new Error(`Non-JSON response: ${body.substring(0, 200)}`)); }
      });
    });
    req.on('error', reject);
    form.pipe(req);
  });
}

async function upload(filePath, expiresIn) {
  const fileName = path.basename(filePath);
  const fileData = fs.readFileSync(filePath);
  
  console.log(`🔐 Encrypting ${fileName} (${fileData.length} bytes)...`);
  
  const encryptedData = await encryptDataChunked(fileData, PASSPHRASE);
  
  console.log(`📤 Uploading encrypted blob (${encryptedData.length} bytes)...`);
  
  const encryptedNameB64 = await encryptString(fileName, PASSPHRASE);
  const encryptedTypeB64 = await encryptString('application/octet-stream', PASSPHRASE);
  
  const form = new FormData();
  form.append('file', encryptedData, { filename: 'encrypted.bin', contentType: 'application/octet-stream' });
  form.append('uploader', 'nyx');
  form.append('filename_enc', encryptedNameB64);
  form.append('content_type_enc', encryptedTypeB64);
  if (expiresIn) form.append('expires_in', expiresIn);
  const burn = process.env.NYXVAULT_BURN === '1' || process.argv[5] === 'burn';
  if (burn) { form.append('burn_after_read', '1'); console.log('🔥 Burn-after-reading enabled — file self-destructs after first decrypt.'); }
  
  const result = await postForm(`${BASE_URL}/api/upload`, form, { 'X-Api-Key': API_KEY });
  
  if (result.download_token) {
    console.log(`\n✅ Upload erfolgreich!`);
    console.log(`📎 Download link: ${BASE_URL}/dl/${result.download_token}`);
    return `${BASE_URL}/dl/${result.download_token}`;
  } else {
    console.error('❌ Upload failed:', result);
    return null;
  }
}

const filePath = process.argv[2];
const expiresIn = process.argv[3];
// argv[4] = custom passphrase (optional)
if (!filePath) {
  console.log('Usage: node nyx-upload.js <file> [expires_in: 1h|24h|7d|30d]');
  process.exit(1);
}
upload(filePath, expiresIn).catch(console.error);
