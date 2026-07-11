#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');

const crypto = require('crypto');

const PASSPHRASE = process.argv[3] || process.env.NYXVAULT_PASSPHRASE || '';
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024;
const SECRETBOX_OVERHEAD = 16;
const CHUNK_PREFIX_BYTES = 5; // 4-byte index BE + 1-byte is_last
const MAGIC2 = Buffer.from('NYX2');
const MAGIC3 = Buffer.from('NYX3');

async function deriveKey(passphrase, salt, memorySize = 16384) {
  const key = await argon2id({
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

function isNYX2(data) {
  return data.length >= 4 && data.slice(0, 4).equals(MAGIC2);
}
function isNYX3(data) {
  return data.length >= 4 && data.slice(0, 4).equals(MAGIC3);
}
function isChunkedFormat(data) {
  return isNYX2(data) || isNYX3(data);
}

async function decryptDataNYX3(data, passphrase) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const storedHMAC = data.slice(offset, offset + 32); offset += 32;
  const numChunks = data.readUInt32BE(offset); offset += 4;

  console.log(`  NYX3 format (integrity-protected): ${numChunks} chunks`);
  const key = await deriveKey(passphrase, salt, 16384);

  // Derive HMAC subkey and verify header
  const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();
  const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
  MAGIC3.copy(headerForHMAC, 0);
  Buffer.from(salt).copy(headerForHMAC, 4);
  headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  const expectedHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();

  if (!crypto.timingSafeEqual(storedHMAC, expectedHMAC)) {
    throw new Error('Decryption failed! Wrong passphrase or header tampered.\n' +
      '   Note: if this file was uploaded in PASSKEY mode (no passphrase), it cannot be\n' +
      '   decrypted here. Open its /dl/ link in a browser with a registered passkey.');
  }
  console.log('  ✓ Header HMAC verified');

  const chunks = [];
  let totalDecrypted = 0;

  for (let i = 0; i < numChunks; i++) {
    const nonce = new Uint8Array(data.slice(offset, offset + NONCE_BYTES)); offset += NONCE_BYTES;
    let ciphertextLen = (i < numChunks - 1) ? CHUNK_PREFIX_BYTES + CHUNK_SIZE + SECRETBOX_OVERHEAD : data.length - offset;
    const ciphertext = new Uint8Array(data.slice(offset, offset + ciphertextLen)); offset += ciphertextLen;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) throw new Error('Decryption failed! Wrong passphrase?');

    // Verify chunk prefix
    const chunkIdx = (decrypted[0] << 24) | (decrypted[1] << 16) | (decrypted[2] << 8) | decrypted[3];
    const isLast = decrypted[4];
    if (chunkIdx !== i) throw new Error(`Integrity error: chunk ${i} has index ${chunkIdx}`);
    if (i === numChunks - 1 && isLast !== 1) throw new Error('Integrity error: missing final chunk marker');
    if (i < numChunks - 1 && isLast !== 0) throw new Error('Integrity error: premature final chunk marker');

    const actualData = Buffer.from(decrypted.slice(CHUNK_PREFIX_BYTES));
    chunks.push(actualData);
    totalDecrypted += actualData.length;
    process.stdout.write(`\r  Decrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  // Explicit truncation guard
  if (offset !== data.length) throw new Error('Integrity error: unexpected trailing data');
  if (chunks.length !== numChunks) throw new Error('Integrity error: chunk count mismatch');
  return Buffer.concat(chunks, totalDecrypted);
}

async function decryptDataNYX2(data, passphrase) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const numChunks = data.readUInt32BE(offset); offset += 4;

  console.log(`  NYX2 format (legacy): ${numChunks} chunks`);
  const key = await deriveKey(passphrase, salt, 16384);

  const chunks = [];
  let totalDecrypted = 0;

  for (let i = 0; i < numChunks; i++) {
    const nonce = new Uint8Array(data.slice(offset, offset + NONCE_BYTES)); offset += NONCE_BYTES;
    let ciphertextLen = (i < numChunks - 1) ? CHUNK_SIZE + SECRETBOX_OVERHEAD : data.length - offset;
    const ciphertext = new Uint8Array(data.slice(offset, offset + ciphertextLen)); offset += ciphertextLen;
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (!decrypted) throw new Error('Decryption failed! Wrong passphrase?');
    chunks.push(Buffer.from(decrypted));
    totalDecrypted += decrypted.length;
    process.stdout.write(`\r  Decrypting chunk ${i + 1}/${numChunks}...`);
  }
  console.log(' done!');
  return Buffer.concat(chunks, totalDecrypted);
}

async function decryptDataLegacy(data, passphrase) {
  console.log('  Legacy format (single block)');
  const salt = new Uint8Array(data.slice(0, SALT_BYTES));
  const nonce = new Uint8Array(data.slice(SALT_BYTES, SALT_BYTES + NONCE_BYTES));
  const ciphertext = new Uint8Array(data.slice(SALT_BYTES + NONCE_BYTES));

  // Try 16MB first (new), then 64MB (old) for backward compatibility
  for (const mem of [16384, 65536]) {
    console.log(`  Trying Argon2id with ${mem / 1024}MB...`);
    const key = await deriveKey(passphrase, salt, mem);
    const decrypted = nacl.secretbox.open(ciphertext, nonce, key);
    if (decrypted) {
      console.log(`  ✓ Success with ${mem / 1024}MB Argon2id`);
      return Buffer.from(decrypted);
    }
  }
  throw new Error('Decryption failed! Wrong passphrase?');
}

async function main() {
  const inputFile = process.argv[2];
  const outputFile = process.argv[4] || null;

  const allowLegacy = process.argv.includes('--allow-legacy');

  if (!inputFile || inputFile === '--help' || inputFile === '-h') {
    console.log('NyxVault Decrypt CLI');
    console.log('Usage: node nyx-decrypt.js <encrypted-file> [passphrase] [output-file] [--allow-legacy]');
    console.log('Env:   NYXVAULT_PASSPHRASE (used if passphrase arg omitted)');
    console.log('');
    console.log('  --allow-legacy   Allow decryption of NYX2 files (no integrity protection).');
    console.log('                   Use nyx-migrate.js to upgrade NYX2 → NYX3 instead.');
    process.exit(1);
  }
  if (!PASSPHRASE) {
    console.error('\u274c No passphrase. Set NYXVAULT_PASSPHRASE or pass it as argument 2.');
    process.exit(1);
  }

  const encData = fs.readFileSync(inputFile);
  console.log(`🔐 Decrypting ${inputFile} (${encData.length} bytes)...`);

  let decrypted;
  if (isNYX3(encData)) {
    decrypted = await decryptDataNYX3(encData, PASSPHRASE);
  } else if (isNYX2(encData)) {
    if (!allowLegacy) {
      console.error('❌ This file uses the legacy NYX2 format without integrity protection.');
      console.error('   To migrate it to NYX3: node nyx-migrate.js ' + inputFile + ' <passphrase>');
      console.error('   To decrypt anyway (UNSAFE): add --allow-legacy flag');
      process.exit(1);
    }
    console.warn('  ⚠️  WARNING: Decrypting NYX2 file without integrity checks (--allow-legacy)');
    decrypted = await decryptDataNYX2(encData, PASSPHRASE);
  } else {
    decrypted = await decryptDataLegacy(encData, PASSPHRASE);
  }

  const outPath = outputFile || inputFile.replace('.bin', '-decrypted');
  fs.writeFileSync(outPath, decrypted);
  console.log(`✅ Decrypted! Saved to: ${outPath} (${decrypted.length} bytes)`);
}

main().catch(e => console.error('❌', e.message));
