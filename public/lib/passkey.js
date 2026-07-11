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
 *
 * PRF SUPPORT DETECTION: create()'s clientExtensionResults.prf.enabled is
 * unreliable — many platform authenticators (Windows Hello, some iCloud
 * versions) do NOT report it at registration even though PRF works fine during
 * get(). So we never hard-fail on the create() result; instead we run a real
 * follow-up get() with prf.eval and check whether an output is actually
 * produced. That is the ground truth.
 */
'use strict';

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
// Runs the create() ceremony, then does a REAL follow-up get() with prf.eval to
// verify PRF actually works on this authenticator (create() results lie).
// `sessionToken` authorizes the server endpoints.
// Returns { ok, prf_enabled, cred_id_short } where prf_enabled reflects the
// ground-truth follow-up test, not the create() extension result.
async function passkeyRegister(sessionToken, label) {
  if (!passkeySupported()) throw new Error('This browser does not support passkeys.');

  const optRes = await fetch('/api/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionToken }
  });
  if (!optRes.ok) throw new Error((await optRes.json()).error || 'Could not load registration options');
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

  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (e) {
    throw new Error('Passkey creation was cancelled or failed on this device.');
  }
  if (!cred) throw new Error('Passkey creation was cancelled.');

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
  if (!verRes.ok || !verJson.ok) throw new Error(verJson.error || 'Passkey registration failed');

  // Ground-truth PRF check: try an actual PRF evaluation via get(). This is the
  // only reliable way to know PRF works, since create() often under-reports.
  let prfWorks = false;
  try {
    // Use a throwaway 32-byte salt just to probe PRF output presence.
    const probeSalt = new Uint8Array(32).fill(0x2a);
    const settingsRes = await fetch('/api/settings');
    const settings = settingsRes.ok ? await settingsRes.json() : null;
    const realSalt = settings && settings.prf_salt ? b64ToBytes(settings.prf_salt) : probeSalt;
    const out = await passkeyGetPRF(settings && settings.prf_salt ? settings.prf_salt : null, realSalt);
    prfWorks = !!(out && out.length === 32);
  } catch (probeErr) {
    // The probe failing (e.g. user dismissed the second prompt) does NOT mean
    // PRF is unsupported — fall back to the create()-time hint from the server.
    prfWorks = !!verJson.prf_enabled;
  }

  return { ok: true, prf_enabled: prfWorks, cred_id_short: verJson.cred_id_short };
}

// ── Key derivation via authentication ─────────────────────
// Runs the get() ceremony with PRF eval = prf_salt, verifies with the server
// (anti-replay counter bump), and returns the 32-byte PRF secret.
// Accepts either a base64 prf_salt string or (for internal probing) a raw
// Uint8Array override.
async function passkeyGetPRF(prfSaltB64, prfSaltBytesOverride) {
  if (!passkeySupported()) throw new Error('This browser does not support passkeys.');
  const prfSalt = prfSaltBytesOverride || b64ToBytes(prfSaltB64);

  const optRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
  if (!optRes.ok) throw new Error((await optRes.json()).error || 'Could not load passkey options');
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
    throw new Error('No matching passkey found on this device, or the request was cancelled.');
  }
  if (!assertion) throw new Error('Passkey authentication was cancelled.');

  const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
    throw new Error('This passkey does not support the PRF extension. Try the latest Chrome or Edge, or an iPhone/iPad passkey.');
  }
  const prfOutput = new Uint8Array(ext.prf.results.first); // 32 bytes

  // Verify assertion with the server (counter bump). We deliberately do NOT
  // send the PRF output to the server — it must never leave the browser.
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
    throw new Error(j.error || 'Passkey verification failed');
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
