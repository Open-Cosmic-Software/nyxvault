#!/usr/bin/env node
'use strict';

const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const fs = require('fs');
const path = require('path');

const crypto = require('crypto');

function tokenArgValue() {
  const i = process.argv.indexOf('--token');
  return (i !== -1 && process.argv[i + 1]) ? process.argv[i + 1] : null;
}
const SALT_BYTES = 16;
const NONCE_BYTES = 24;
const CHUNK_SIZE = 4 * 1024 * 1024;
const SECRETBOX_OVERHEAD = 16;
const CHUNK_PREFIX_BYTES = 5; // 4-byte index BE + 1-byte is_last
const MAGIC2 = Buffer.from('NYX2');
const MAGIC3 = Buffer.from('NYX3');
const MAGIC4 = Buffer.from('NYX4'); // same layout as NYX3, 21 MB Argon2id memory
const ARGON2_MEM_NYX3 = 16384; // KiB
const ARGON2_MEM_NYX4 = 21504; // KiB (21 MB)

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
function isNYX4(data) {
  return data.length >= 4 && data.slice(0, 4).equals(MAGIC4);
}
function isChunkedFormat(data) {
  return isNYX2(data) || isNYX3(data) || isNYX4(data);
}

// Verify the NYX3/NYX4 header HMAC for a raw 32-byte key WITHOUT decrypting.
// Used by recovery mode to match a blob to the right wrapped FEK.
function headerHMACMatches(data, key) {
  try {
    let offset = 4;
    const salt = data.slice(offset, offset + SALT_BYTES); offset += SALT_BYTES;
    const storedHMAC = data.slice(offset, offset + 32); offset += 32;
    const numChunks = data.readUInt32BE(offset);
    const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();
    const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
    data.copy(headerForHMAC, 0, 0, 4);
    salt.copy(headerForHMAC, 4);
    headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
    const expectedHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();
    return crypto.timingSafeEqual(storedHMAC, expectedHMAC);
  } catch { return false; }
}

// Core chunked decrypt with a raw 32-byte key (passphrase-derived OR a FEK).
async function decryptChunkedWithKey(data, key) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const storedHMAC = data.slice(offset, offset + 32); offset += 32;
  const numChunks = data.readUInt32BE(offset); offset += 4;

  console.log(`  ${isNYX4(data) ? 'NYX4' : 'NYX3'} format (integrity-protected): ${numChunks} chunks`);

  // Derive HMAC subkey and verify header
  const hmacSubKey = crypto.createHmac('sha256', Buffer.from(key)).update('nyxvault-header-auth').digest();
  // HMAC is computed over the ACTUAL magic — binds the format version
  const headerForHMAC = Buffer.alloc(4 + SALT_BYTES + 4);
  data.copy(headerForHMAC, 0, 0, 4);
  Buffer.from(salt).copy(headerForHMAC, 4);
  headerForHMAC.writeUInt32BE(numChunks, 4 + SALT_BYTES);
  const expectedHMAC = crypto.createHmac('sha256', hmacSubKey).update(headerForHMAC).digest();

  if (!crypto.timingSafeEqual(storedHMAC, expectedHMAC)) {
    throw new Error('Decryption failed! Wrong key/passphrase or header tampered.\n' +
      '   Note: if this file was uploaded in PASSKEY mode (no passphrase), decrypt it\n' +
      '   with --recovery (agent recovery key) or open its /dl/ link in a browser\n' +
      '   with a registered passkey.');
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

async function decryptDataNYX3(data, passphrase) {
  const kdfMem = isNYX4(data) ? ARGON2_MEM_NYX4 : ARGON2_MEM_NYX3;
  const salt = new Uint8Array(data.slice(4, 4 + SALT_BYTES));
  const key = await deriveKey(passphrase, salt, kdfMem);
  return decryptChunkedWithKey(data, key);
}

async function decryptDataNYX2(data, passphrase) {
  let offset = 4;
  const salt = new Uint8Array(data.slice(offset, offset + SALT_BYTES)); offset += SALT_BYTES;
  const numChunks = data.readUInt32BE(offset); offset += 4;

  console.log(`  NYX2 format (legacy): ${numChunks} chunks`);
  const key = await deriveKey(passphrase, salt, ARGON2_MEM_NYX3);

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
  for (const mem of [ARGON2_MEM_NYX4, ARGON2_MEM_NYX3, 65536]) {
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

// ── Recovery-key decryption (agent access to passkey-mode files) ─────────────
// Passkey-mode blobs are NYX3/NYX4 encrypted with a random FEK; the FEK is
// sealed to the vault public key (wrapped_fek, stored in the DB). Normally
// only a passkey can unwrap the vault private key — but if an "agent recovery
// key" was set up in the admin UI, the vault private key is ALSO sealed to a
// software recovery keypair whose private key lives in data/recovery-key.json
// on this host. Chain: recovery privkey → vault privkey → FEK → file.
//
// Sealed box format (matches public/lib/passkey.js + nyx-upload.js):
//   eph_pub(32) || nonce(24) || nacl.box(msg, nonce, recipPub, eph_sec)
function sealOpen(sealed, recipPub, recipSec) {
  const eph = sealed.slice(0, 32);
  const nonce = sealed.slice(32, 32 + NONCE_BYTES);
  const ct = sealed.slice(32 + NONCE_BYTES);
  return nacl.box.open(new Uint8Array(ct), new Uint8Array(nonce), new Uint8Array(eph), recipSec); // Uint8Array | null
}

const RECOVERY_KEY_PATH = process.env.NYXVAULT_RECOVERY_KEY || path.join(__dirname, 'data', 'recovery-key.json');
const DB_PATH = process.env.NYXVAULT_DB || path.join(__dirname, 'data', 'vault.db');

async function decryptWithRecovery(encData, tokenHint) {
  if (!fs.existsSync(RECOVERY_KEY_PATH)) {
    throw new Error('No recovery key file at ' + RECOVERY_KEY_PATH + '.\n' +
      '   Set one up in the web admin: Passkeys card → "Add recovery key" (one passkey tap).');
  }
  const keyFile = JSON.parse(fs.readFileSync(RECOVERY_KEY_PATH, 'utf8'));
  const recPriv = new Uint8Array(Buffer.from(keyFile.privateKey, 'base64'));

  const Database = require('better-sqlite3');
  const db = new Database(DB_PATH, { readonly: true });
  try {
    const row = db.prepare('SELECT * FROM recovery_keys WHERE id = ?').get(keyFile.id)
      || db.prepare('SELECT * FROM recovery_keys WHERE pubkey = ?').get(keyFile.publicKey);
    if (!row) throw new Error('Recovery key #' + keyFile.id + ' not found in the database (was it removed in the admin UI?).');
    if (!row.wrapped_privkey) throw new Error('Recovery key #' + row.id + ' was never finalized — redo "Add recovery key" in the admin UI.');

    // 1) recovery privkey opens the sealed vault privkey
    const recPub = nacl.box.keyPair.fromSecretKey(recPriv).publicKey;
    const vaultPriv = sealOpen(Buffer.from(row.wrapped_privkey, 'base64'), recPub, recPriv);
    if (!vaultPriv) throw new Error('Could not open the wrapped vault key — recovery key file does not match the database entry.');
    console.log('  ✓ Vault private key unwrapped via recovery key #' + row.id);

    // 2) vault privkey opens the file's sealed FEK. If a token is given, use
    //    that exact row; otherwise identify the blob by its header HMAC.
    const vaultPub = nacl.box.keyPair.fromSecretKey(vaultPriv).publicKey;
    let fek = null;
    const candidates = tokenHint
      ? db.prepare("SELECT * FROM files WHERE download_token = ?").all(tokenHint)
      : db.prepare("SELECT * FROM files WHERE key_mode = 'passkey' AND wrapped_fek IS NOT NULL ORDER BY id DESC").all();
    for (const f of candidates) {
      if (!f.wrapped_fek) continue;
      const candidate = sealOpen(Buffer.from(f.wrapped_fek, 'base64'), vaultPub, vaultPriv);
      if (!candidate) continue;
      if (headerHMACMatches(encData, candidate)) {
        fek = candidate;
        console.log('  ✓ Matched file #' + f.id + ' (token ' + f.download_token.slice(0, 8) + '…) — FEK unsealed');
        break;
      }
      candidate.fill(0);
    }
    vaultPriv.fill(0);
    if (!fek) {
      throw new Error(tokenHint
        ? 'The FEK for that token does not decrypt this blob (wrong file?).'
        : 'No passkey-mode DB entry matches this blob. Pass --token <download_token> if the file was already deleted from the list.');
    }

    // 3) FEK decrypts the chunked blob
    const out = await decryptChunkedWithKey(encData, fek);
    fek.fill(0);
    return out;
  } finally {
    recPriv.fill(0);
    db.close();
  }
}

async function main() {
  const flags = process.argv.slice(2).filter(a => a.startsWith('--'));
  const positional = process.argv.slice(2).filter(a => !a.startsWith('--') && a !== tokenArgValue());
  const inputFile = positional[0];

  const allowLegacy = flags.includes('--allow-legacy');
  const recoveryFlag = flags.includes('--recovery');
  // Positional layout stays backward compatible:
  //   passphrase mode: <file> [passphrase] [output]
  //   recovery mode:   <file> --recovery [output] [--token <hex>]
  const passphrase = recoveryFlag ? '' : (positional[1] || process.env.NYXVAULT_PASSPHRASE || '');
  const outputFile = (recoveryFlag ? positional[1] : positional[2]) || null;
  const tokenHint = tokenArgValue();

  if (!inputFile || inputFile === '-h') {
    console.log('NyxVault Decrypt CLI');
    console.log('Usage: node nyx-decrypt.js <encrypted-file> [passphrase] [output-file] [--allow-legacy]');
    console.log('       node nyx-decrypt.js <encrypted-file> --recovery [output-file] [--token <download_token>]');
    console.log('Env:   NYXVAULT_PASSPHRASE (used if passphrase arg omitted)');
    console.log('       NYXVAULT_DB, NYXVAULT_RECOVERY_KEY (recovery mode paths)');
    console.log('');
    console.log('  --recovery       Decrypt a PASSKEY-mode file using the agent recovery key');
    console.log('                   (data/recovery-key.json, set up in the web admin).');
    console.log('  --token <hex>    Recovery mode: pick the exact DB row by download token.');
    console.log('  --allow-legacy   Allow decryption of NYX2 files (no integrity protection).');
    console.log('                   Use nyx-migrate.js to upgrade NYX2 → NYX3 instead.');
    process.exit(1);
  }

  const encData = fs.readFileSync(inputFile);
  console.log(`🔐 Decrypting ${inputFile} (${encData.length} bytes)...`);

  // Auto-detect: no passphrase given but a recovery key file exists → try
  // recovery mode for chunked blobs (passkey-mode files have no passphrase).
  const useRecovery = recoveryFlag ||
    (!passphrase && fs.existsSync(RECOVERY_KEY_PATH) && (isNYX3(encData) || isNYX4(encData)));

  if (!useRecovery && !passphrase) {
    console.error('\u274c No passphrase. Set NYXVAULT_PASSPHRASE or pass it as argument 2.');
    console.error('   For passkey-mode files, use --recovery (requires an agent recovery key).');
    process.exit(1);
  }

  let decrypted;
  if (useRecovery) {
    if (!isNYX3(encData) && !isNYX4(encData)) {
      console.error('\u274c Recovery mode only supports NYX3/NYX4 blobs.');
      process.exit(1);
    }
    console.log('  🦞 Recovery mode — using the agent recovery key');
    decrypted = await decryptWithRecovery(encData, tokenHint);
  } else if (isNYX3(encData) || isNYX4(encData)) {
    decrypted = await decryptDataNYX3(encData, passphrase);
  } else if (isNYX2(encData)) {
    if (!allowLegacy) {
      console.error('❌ This file uses the legacy NYX2 format without integrity protection.');
      console.error('   To migrate it to NYX3: node nyx-migrate.js ' + inputFile + ' <passphrase>');
      console.error('   To decrypt anyway (UNSAFE): add --allow-legacy flag');
      process.exit(1);
    }
    console.warn('  ⚠️  WARNING: Decrypting NYX2 file without integrity checks (--allow-legacy)');
    decrypted = await decryptDataNYX2(encData, passphrase);
  } else {
    decrypted = await decryptDataLegacy(encData, passphrase);
  }

  const outPath = outputFile || inputFile.replace('.bin', '-decrypted');
  fs.writeFileSync(outPath, decrypted);
  console.log(`✅ Decrypted! Saved to: ${outPath} (${decrypted.length} bytes)`);
}

main().catch(e => console.error('❌', e.message));
