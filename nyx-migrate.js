#!/usr/bin/env node
/**
 * nyx-migrate.js — Migrate NYX2 blobs to NYX3 (integrity-protected) format.
 *
 * Usage:
 *   node nyx-migrate.js <encrypted-file> <passphrase> [output-file]
 *   node nyx-migrate.js --server <passphrase>     # re-encrypt all NYX2 files on a NyxVault server
 *
 * The tool decrypts using the legacy NYX2 path, then re-encrypts as NYX3.
 * The passphrase must be the same one used to encrypt the file originally.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');

const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024;
const SECRETBOX_OVERHEAD = 16;
const CHUNK_PREFIX_BYTES = 5;
const MAGIC2 = Buffer.from('NYX2');
const MAGIC3 = Buffer.from('NYX3');
const MAGIC4 = Buffer.from('NYX4'); // current format: NYX3 layout, 21 MB Argon2id
const ARGON2_MEM_NYX4 = 21504;

async function deriveKey(passphrase, salt, memorySize = 16384) {
  return new Uint8Array(await argon2id({
    password: passphrase, salt, parallelism: 1, iterations: 3,
    memorySize, hashLength: 32, outputType: 'binary'
  }));
}

// ── NYX2 Decrypt (legacy) ────────────────────────────────
function isNYX2(data) { return data.length >= 4 && data.slice(0, 4).equals(MAGIC2); }
function isNYX3(data) { return data.length >= 4 && (data.slice(0, 4).equals(MAGIC3) || data.slice(0, 4).equals(MAGIC4)); }

async function decryptNYX2(data, passphrase) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const numChunks = data.readUInt32BE(offset); offset += 4;
  const key = await deriveKey(passphrase, salt);
  const chunks = [];
  let total = 0;
  for (let i = 0; i < numChunks; i++) {
    const nonce = new Uint8Array(data.slice(offset, offset + NONCE_BYTES)); offset += NONCE_BYTES;
    const ctLen = (i < numChunks - 1) ? CHUNK_SIZE + SECRETBOX_OVERHEAD : data.length - offset;
    const ct = new Uint8Array(data.slice(offset, offset + ctLen)); offset += ctLen;
    const dec = nacl.secretbox.open(ct, nonce, key);
    if (!dec) throw new Error('Decryption failed — wrong passphrase?');
    chunks.push(Buffer.from(dec));
    total += dec.length;
    process.stdout.write(`\r  Decrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(chunks, total);
}

// ── NYX3 Encrypt ─────────────────────────────────────────
async function encryptNYX3(data, passphrase) { // emits NYX4 (current format)
  const salt = nacl.randomBytes(SALT_BYTES);
  const key = await deriveKey(passphrase, salt, ARGON2_MEM_NYX4);
  const numChunks = Math.max(1, Math.ceil(data.length / CHUNK_SIZE));

  const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();
  const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC4.copy(headerForHMAC, 0);
  Buffer.from(salt).copy(headerForHMAC, 4);
  headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  const headerHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();

  const buffers = [];
  const header = Buffer.alloc(4 + SALT_BYTES + 32 + 4);
  MAGIC4.copy(header, 0);
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
    process.stdout.write(`\r  Re-encrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(buffers);
}

// ── Server mode: migrate all NYX2 blobs in storage/ ──────
async function migrateServer(passphrase) {
  const storageDir = path.join(__dirname, 'storage');
  if (!fs.existsSync(storageDir)) {
    console.error('❌ No storage/ directory found. Run from NyxVault root.');
    process.exit(1);
  }

  const files = fs.readdirSync(storageDir);
  let migrated = 0, skipped = 0, failed = 0;

  for (const file of files) {
    const filePath = path.join(storageDir, file);
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) continue;

    const data = fs.readFileSync(filePath);
    if (isNYX3(data)) {
      skipped++;
      continue;
    }
    if (!isNYX2(data)) {
      console.log(`  ⚠️  ${file}: not NYX2/NYX3, skipping`);
      skipped++;
      continue;
    }

    console.log(`\n📦 Migrating ${file} (${(data.length / 1024).toFixed(1)} KB)...`);
    try {
      const plaintext = await decryptNYX2(data, passphrase);
      const nyx3Blob = await encryptNYX3(plaintext, passphrase);

      // Backup original
      fs.writeFileSync(filePath + '.nyx2bak', data);
      // Write NYX3
      fs.writeFileSync(filePath, nyx3Blob);
      console.log(`  ✅ Migrated! (${data.length} → ${nyx3Blob.length} bytes)`);
      migrated++;
    } catch (err) {
      console.log(`  ❌ Failed: ${err.message}`);
      failed++;
    }
  }

  console.log(`\n🏁 Migration complete: ${migrated} migrated, ${skipped} skipped, ${failed} failed`);
  if (failed > 0) {
    console.log('   Failed files may use a different passphrase. Re-run with the correct one.');
  }
}

// ── Single file mode ─────────────────────────────────────
async function migrateSingleFile(inputPath, passphrase, outputPath) {
  const data = fs.readFileSync(inputPath);

  if (isNYX3(data)) {
    console.log('✅ Already NYX3 format — nothing to do.');
    process.exit(0);
  }
  if (!isNYX2(data)) {
    console.error('❌ Not a NYX2 file.');
    process.exit(1);
  }

  console.log(`📦 Migrating ${path.basename(inputPath)} (${(data.length / 1024).toFixed(1)} KB)...`);
  const plaintext = await decryptNYX2(data, passphrase);
  const nyx3Blob = await encryptNYX3(plaintext, passphrase);

  const out = outputPath || inputPath;
  if (out === inputPath) {
    fs.writeFileSync(inputPath + '.nyx2bak', data);
    console.log(`  💾 Backup: ${inputPath}.nyx2bak`);
  }
  fs.writeFileSync(out, nyx3Blob);
  console.log(`  ✅ Migrated! Saved to: ${out} (${data.length} → ${nyx3Blob.length} bytes)`);
}

// ── Main ─────────────────────────────────────────────────
(async () => {
  const args = process.argv.slice(2);

  if (args.length === 0 || args[0] === '--help' || args[0] === '-h') {
    console.log(`
nyx-migrate.js — Migrate NYX2 → NYX3

Usage:
  node nyx-migrate.js <file> <passphrase> [output]   Migrate a single blob
  node nyx-migrate.js --server <passphrase>           Migrate all blobs in storage/

NYX3 adds chunk integrity (index + is_last prefix) and header HMAC.
Original NYX2 files are backed up as *.nyx2bak before overwriting.
`);
    process.exit(0);
  }

  if (args[0] === '--server') {
    const pw = args[1] || process.env.NYXVAULT_PASSPHRASE;
    if (!pw) { console.error('❌ Passphrase required: --server <passphrase>'); process.exit(1); }
    await migrateServer(pw);
  } else {
    const inputPath = args[0];
    const pw = args[1] || process.env.NYXVAULT_PASSPHRASE;
    if (!pw) { console.error('❌ Passphrase required.'); process.exit(1); }
    if (!fs.existsSync(inputPath)) { console.error(`❌ File not found: ${inputPath}`); process.exit(1); }
    await migrateSingleFile(inputPath, pw, args[2]);
  }
})();
