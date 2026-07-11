/* NyxVault — WebAuthn Passkey key-derivation helpers 🔑🦞
 *
 * Zero-knowledge design: the file-encryption key never leaves the browser and
 * is never sent to the server. It is derived entirely on the client from the
 * WebAuthn PRF extension output.
 *
 * Flow:
 *   1. navigator.credentials.get() with extensions.prf.eval.first = GLOBAL prf_salt
 *      → the authenticator returns 32 secret bytes (prfOutput), stable across
 *        every ceremony for the same (credential, salt) pair.
 *   2. HKDF-SHA256(prfOutput, salt = per-file blobSalt, info = 'nyxvault-passkey-v1')
 *      → the 32-byte secretbox key.
 *
 * Because the per-file blob salt (16 random bytes, stored inside the NYX3 blob)
 * feeds the HKDF, every file gets a unique key even though the PRF secret is the
 * same. The blob format is IDENTICAL to the passphrase path — only the key
 * source differs — so all the existing NYX3 chunk/HMAC machinery is reused.
 */
'use strict';

// One global, non-secret domain-separation salt for the PRF evaluation.
// (Fetched from /api/settings or /api/dl/:token/meta and passed in as base64.)
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64url(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
}

// HKDF-SHA256(prfOutput, salt, info) → 32-byte key, via Web Crypto.
async function hkdfKey(prfOutput, saltBytes, infoStr) {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: saltBytes,
      info: new TextEncoder().encode(infoStr)
    },
    baseKey,
    256 // 32 bytes
  );
  return new Uint8Array(bits);
}

// Whether this browser exposes WebAuthn at all.
function passkeySupported() {
  return typeof window !== 'undefined' &&
    window.PublicKeyCredential !== undefined &&
    typeof navigator !== 'undefined' &&
    navigator.credentials && navigator.credentials.get;
}

// ── Registration (admin) ──────────────────────────────────
// Runs the create() ceremony. `sessionToken` authorizes the server endpoints.
async function passkeyRegister(sessionToken, label) {
  if (!passkeySupported()) throw new Error('Dieser Browser unterstützt keine Passkeys.');

  const optRes = await fetch('/api/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionToken }
  });
  if (!optRes.ok) throw new Error((await optRes.json()).error || 'Konnte Optionen nicht laden');
  const options = await optRes.json();

  // Convert server JSON (base64url) → ArrayBuffers for navigator.credentials.create
  const publicKey = {
    ...options,
    challenge: b64urlToBytes(options.challenge),
    user: { ...options.user, id: b64urlToBytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map(c => ({
      ...c, id: b64urlToBytes(c.id)
    }))
  };
  // Request the PRF extension (empty eval at registration; we only need enablement)
  publicKey.extensions = Object.assign({}, options.extensions, { prf: {} });

  const cred = await navigator.credentials.create({ publicKey });
  if (!cred) throw new Error('Passkey-Erstellung abgebrochen');

  const clientExt = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  const att = cred.response;
  const payload = {
    id: cred.id,
    rawId: bytesToB64url(new Uint8Array(cred.rawId)),
    type: cred.type,
    response: {
      clientDataJSON: bytesToB64url(new Uint8Array(att.clientDataJSON)),
      attestationObject: bytesToB64url(new Uint8Array(att.attestationObject)),
      transports: att.getTransports ? att.getTransports() : undefined
    },
    clientExtensionResults: clientExt
  };

  const verRes = await fetch('/api/webauthn/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionToken },
    body: JSON.stringify({ credential: payload, label: label || 'Passkey' })
  });
  const verJson = await verRes.json();
  if (!verRes.ok || !verJson.ok) throw new Error(verJson.error || 'Passkey-Registrierung fehlgeschlagen');
  return verJson; // { ok, prf_enabled, cred_id_short }
}

// ── Key derivation via authentication ─────────────────────
// Runs the get() ceremony with PRF eval = prf_salt, verifies with the server
// (anti-replay counter bump), and returns the 32-byte PRF secret.
// `blobSalt` (per-file) is then HKDF'd on top by the caller via passkeyDeriveKey.
async function passkeyGetPRF(prfSaltB64) {
  if (!passkeySupported()) throw new Error('Dieser Browser unterstützt keine Passkeys.');
  const prfSalt = b64ToBytes(prfSaltB64);

  const optRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
  if (!optRes.ok) throw new Error((await optRes.json()).error || 'Konnte Passkey-Optionen nicht laden');
  const options = await optRes.json();
  const flowId = options.flowId;

  const publicKey = {
    ...options,
    challenge: b64urlToBytes(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(c => ({
      ...c, id: b64urlToBytes(c.id)
    })),
    extensions: { prf: { eval: { first: prfSalt } } }
  };
  delete publicKey.flowId;

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey });
  } catch (e) {
    throw new Error('Kein passender Passkey auf diesem Gerät gefunden oder Vorgang abgebrochen.');
  }
  if (!assertion) throw new Error('Passkey-Authentifizierung abgebrochen');

  const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
    throw new Error('Dieser Passkey unterstützt die PRF-Erweiterung nicht — auf einem kompatiblen Gerät/Browser erneut versuchen.');
  }
  const prfOutput = new Uint8Array(ext.prf.results.first); // 32 bytes

  // Verify assertion with the server (counter bump). Non-fatal for key
  // derivation, but we surface a clear error if the passkey is unknown.
  const resp = assertion.response;
  const payload = {
    flowId,
    credential: {
      id: assertion.id,
      rawId: bytesToB64url(new Uint8Array(assertion.rawId)),
      type: assertion.type,
      response: {
        clientDataJSON: bytesToB64url(new Uint8Array(resp.clientDataJSON)),
        authenticatorData: bytesToB64url(new Uint8Array(resp.authenticatorData)),
        signature: bytesToB64url(new Uint8Array(resp.signature)),
        userHandle: resp.userHandle ? bytesToB64url(new Uint8Array(resp.userHandle)) : undefined
      },
      clientExtensionResults: {} // don't leak PRF output to the server
    }
  };
  const verRes = await fetch('/api/webauthn/auth/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  if (!verRes.ok) {
    const j = await verRes.json().catch(() => ({}));
    throw new Error(j.error || 'Passkey-Verifizierung fehlgeschlagen');
  }

  return prfOutput;
}

// Derive the 32-byte file key from a passkey PRF secret + the per-file blob salt.
async function passkeyDeriveKey(prfOutput, blobSalt) {
  return await hkdfKey(prfOutput, blobSalt, 'nyxvault-passkey-v1');
}

// Expose on window for the non-module scripts.
window.NyxPasskey = {
  supported: passkeySupported,
  register: passkeyRegister,
  getPRF: passkeyGetPRF,
  deriveKey: passkeyDeriveKey,
  _b64ToBytes: b64ToBytes
};
