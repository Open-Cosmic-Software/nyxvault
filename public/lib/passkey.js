/* NyxVault — WebAuthn Passkey ENVELOPE encryption 🔑🦞  (v2.2.0)
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHY ENVELOPE ENCRYPTION?
 * The v2.1.x design assumed one shared global PRF salt would give the SAME PRF
 * output across every passkey. That is cryptographically WRONG: the WebAuthn PRF
 * output is a per-credential HMAC, so each passkey yields a DIFFERENT secret for
 * the same salt. Multi-passkey therefore requires KEY WRAPPING.
 *
 * ARCHITECTURE
 *   • Vault keypair (X25519, via tweetnacl nacl.box) is generated in the browser
 *     when the FIRST passkey is registered. Only the PUBLIC key is stored on the
 *     server. The PRIVATE key is never stored in plaintext.
 *   • Each passkey gets its OWN random 32-byte PRF salt (stored server-side).
 *     From that passkey's PRF output we derive a KEK = HKDF-SHA256(prfOutput).
 *     We then store wrapped_privkey = secretbox(vault_privkey, KEK) for THAT
 *     passkey. Every registered passkey can independently unwrap the same vault
 *     private key.
 *   • File encryption (default, passkey mode): a random 32-byte FEK encrypts the
 *     file as a normal NYX3 blob. The FEK is sealed to the vault public key
 *     (anonymous sealed box) → wrapped_fek. NO WebAuthn ceremony needed to
 *     UPLOAD — anyone with the public key can seal.
 *   • Decrypt: run get() with allowCredentials = all passkeys and per-credential
 *     PRF salts (prf.evalByCredential) → whichever passkey the user picks gives
 *     its PRF output → KEK → unwrap vault privkey → open sealed FEK → decrypt.
 *
 * SEALED BOX (anonymous public-key encryption) with tweetnacl:
 *   seal(msg, recipPub):
 *     eph = nacl.box.keyPair(); nonce = random(24)
 *     ct  = nacl.box(msg, nonce, recipPub, eph.secretKey)
 *     return eph.publicKey(32) || nonce(24) || ct
 *   open(sealed, recipPub, recipSec):
 *     eph = sealed[0..32]; nonce = sealed[32..56]; ct = sealed[56..]
 *     return nacl.box.open(ct, nonce, eph, recipSec)
 * Only the holder of recipSec (the vault private key) can open it.
 * ─────────────────────────────────────────────────────────────────────────────
 */
'use strict';

// ── base64 helpers ────────────────────────────────────────
function b64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function bytesToB64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}
function bytesToB64url(bytes) {
  return bytesToB64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64urlToBytes(b64url) {
  let b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  return b64ToBytes(b64);
}

// ── HKDF-SHA256 → 32-byte KEK from a PRF output ───────────
async function hkdfKey(prfOutput, saltBytes, infoStr) {
  const baseKey = await crypto.subtle.importKey('raw', prfOutput, 'HKDF', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'HKDF', hash: 'SHA-256', salt: saltBytes, info: new TextEncoder().encode(infoStr) },
    baseKey, 256
  );
  return new Uint8Array(bits);
}

// KEK for wrapping the vault private key under a passkey's PRF output.
// salt is fixed-domain here (the per-credential randomness already lives in the
// PRF salt used during get()); info separates it from file-key derivation.
async function kekFromPRF(prfOutput) {
  const zeroSalt = new Uint8Array(32); // domain-separation via info string
  return await hkdfKey(prfOutput, zeroSalt, 'nyxvault-privkey-wrap-v2');
}

// ── Sealed box (anonymous X25519) via tweetnacl ───────────
const SEAL_NONCE = 24;
function sealTo(message, recipPubB64) {
  const recipPub = b64ToBytes(recipPubB64);
  const eph = nacl.box.keyPair();
  const nonce = nacl.randomBytes(SEAL_NONCE);
  const ct = nacl.box(message, nonce, recipPub, eph.secretKey);
  const out = new Uint8Array(eph.publicKey.length + nonce.length + ct.length);
  out.set(eph.publicKey, 0);
  out.set(nonce, eph.publicKey.length);
  out.set(ct, eph.publicKey.length + nonce.length);
  // wipe ephemeral secret
  eph.secretKey.fill(0);
  return out;
}
function sealOpen(sealed, recipPub, recipSec) {
  const eph = sealed.slice(0, 32);
  const nonce = sealed.slice(32, 32 + SEAL_NONCE);
  const ct = sealed.slice(32 + SEAL_NONCE);
  return nacl.box.open(ct, nonce, eph, recipSec); // Uint8Array | null
}

// ── secretbox wrap/unwrap (privkey under KEK) ─────────────
// Format: nonce(24) || secretbox(privkey, nonce, kek)
function wrapWithKEK(plaintext, kek) {
  const nonce = nacl.randomBytes(24);
  const ct = nacl.secretbox(plaintext, nonce, kek);
  const out = new Uint8Array(nonce.length + ct.length);
  out.set(nonce, 0);
  out.set(ct, nonce.length);
  return out;
}
function unwrapWithKEK(wrapped, kek) {
  const nonce = wrapped.slice(0, 24);
  const ct = wrapped.slice(24);
  return nacl.secretbox.open(ct, nonce, kek); // Uint8Array | null
}

// ── Capability checks ─────────────────────────────────────
function passkeySupported() {
  return typeof window !== 'undefined' &&
    window.PublicKeyCredential !== undefined &&
    typeof navigator !== 'undefined' &&
    navigator.credentials && navigator.credentials.get;
}

// Turn a DOMException into a readable, actionable error message.
function friendlyWebAuthnError(e, phase) {
  const name = (e && e.name) || '';
  if (name === 'NotAllowedError') {
    return phase + ' was cancelled or timed out. Please try again and approve the passkey prompt.';
  }
  if (name === 'InvalidStateError') {
    return 'This passkey already exists on this device.';
  }
  if (name === 'SecurityError') {
    return 'Security error — the page origin does not match the passkey configuration (' + (e.message || '') + ').';
  }
  return phase + ' failed: ' + (name ? name + ': ' : '') + (e && e.message ? e.message : String(e));
}

// Low-level: run create() and return the raw credential payload for the server.
// `prfSaltBytes` (optional): request a PRF evaluation during creation — modern
// Chromium returns prf.results.first right away, saving a whole extra ceremony.
async function doCreate(options, prfSaltBytes) {
  const publicKey = {
    ...options,
    challenge: b64urlToBytes(options.challenge),
    user: { ...options.user, id: b64urlToBytes(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map(c => ({ ...c, id: b64urlToBytes(c.id) }))
  };
  const prfReq = prfSaltBytes ? { eval: { first: prfSaltBytes } } : {};
  publicKey.extensions = Object.assign({}, options.extensions, { prf: prfReq });
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey });
  } catch (e) {
    throw new Error(friendlyWebAuthnError(e, 'Passkey creation'));
  }
  if (!cred) throw new Error('Passkey creation was cancelled.');
  const att = cred.response;
  const ext = cred.getClientExtensionResults ? cred.getClientExtensionResults() : {};
  // PRF capability check: if the authenticator explicitly reports no PRF
  // support, fail NOW with a clear message instead of a confusing one later.
  if (ext.prf && ext.prf.enabled === false) {
    throw new Error('This authenticator does not support the PRF (hmac-secret) extension required for encryption. Try a different device — e.g. an iPhone/iPad or Android phone passkey (via QR code), or a security key.');
  }
  const prfFromCreate = (ext.prf && ext.prf.results && ext.prf.results.first)
    ? new Uint8Array(ext.prf.results.first) : null;
  return {
    prfFromCreate,
    payload: {
      id: cred.id,
      rawId: bytesToB64url(new Uint8Array(cred.rawId)),
      type: cred.type,
      response: {
        clientDataJSON: bytesToB64url(new Uint8Array(att.clientDataJSON)),
        attestationObject: bytesToB64url(new Uint8Array(att.attestationObject)),
        transports: att.getTransports ? att.getTransports() : undefined
      },
      clientExtensionResults: {} // never leak PRF output to the server
    }
  };
}

// Low-level: run get() with a PRF eval and return { prfOutput, assertionPayload }.
// `allowCreds`: array of { cred_id, prf_salt, transports }.
// If `evalByCredential` is true, each credential gets its OWN salt (needed for
// decryption where multiple different passkeys may answer). Otherwise a single
// `firstSalt` is used (for a freshly created passkey whose id we already know).
async function doGetPRF(options, allowCreds, opts) {
  opts = opts || {};
  const allowCredentials = allowCreds.map(c => ({
    id: b64urlToBytes(c.cred_id),
    type: 'public-key',
    transports: c.transports || undefined
  }));

  const prfExt = {};
  if (opts.evalByCredential) {
    // Per-credential salts: the authenticator applies the salt matching whichever
    // credential actually signs. This is REQUIRED for multi-passkey decryption.
    const map = {};
    for (const c of allowCreds) {
      map[c.cred_id] = { first: b64ToBytes(c.prf_salt) };
    }
    prfExt.evalByCredential = map;
    // Some browsers still want a top-level eval as a fallback; use the first salt.
    if (allowCreds.length) prfExt.eval = { first: b64ToBytes(allowCreds[0].prf_salt) };
  } else {
    prfExt.eval = { first: opts.firstSalt };
  }

  const publicKey = {
    ...options,
    challenge: b64urlToBytes(options.challenge),
    allowCredentials,
    extensions: { prf: prfExt }
  };
  delete publicKey.flowId;

  let assertion;
  try {
    assertion = await navigator.credentials.get({ publicKey });
  } catch (e) {
    throw new Error(friendlyWebAuthnError(e, 'Passkey authentication'));
  }
  if (!assertion) throw new Error('Passkey authentication was cancelled.');

  const ext = assertion.getClientExtensionResults ? assertion.getClientExtensionResults() : {};
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
    throw new Error('This passkey does not support the PRF extension. Try the latest Chrome/Edge, or an iPhone/iPad passkey.');
  }
  const prfOutput = new Uint8Array(ext.prf.results.first); // 32 bytes
  const resp = assertion.response;
  const assertionPayload = {
    id: assertion.id,
    rawId: bytesToB64url(new Uint8Array(assertion.rawId)),
    type: assertion.type,
    response: {
      clientDataJSON: bytesToB64url(new Uint8Array(resp.clientDataJSON)),
      authenticatorData: bytesToB64url(new Uint8Array(resp.authenticatorData)),
      signature: bytesToB64url(new Uint8Array(resp.signature)),
      userHandle: resp.userHandle ? bytesToB64url(new Uint8Array(resp.userHandle)) : undefined
    },
    clientExtensionResults: {} // never leak PRF output to the server
  };
  return { prfOutput, usedCredId: assertion.id, assertionPayload };
}

// Verify an assertion server-side (counter bump). Best-effort — a failure here
// does not compromise the client-side key material.
async function verifyAssertion(flowId, assertionPayload) {
  try {
    await fetch('/api/webauthn/auth/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ flowId, credential: assertionPayload })
    });
  } catch { /* non-fatal */ }
}

// ── Registration (admin) ──────────────────────────────────
// Envelope-aware registration:
//   1. GET options (server mints a fresh per-credential PRF salt + tells us
//      whether a vault keypair already exists).
//   2. If a vault exists → authenticate with an EXISTING passkey to UNWRAP the
//      vault private key (so we can re-wrap it for the new passkey).
//      If not → generate a brand-new vault keypair now (first passkey ever).
//   3. create() the new passkey.
//   4. get() the new passkey with its fresh salt → PRF output → KEK → wrap the
//      vault private key for it.
//   5. verify: send credential + wrapped_privkey (+ vault_pubkey on first reg).
// Returns { ok, cred_id_short, first }.
async function passkeyRegister(sessionToken, label) {
  if (!passkeySupported()) throw new Error('This browser does not support passkeys.');

  const optRes = await fetch('/api/webauthn/register/options', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionToken }
  });
  if (!optRes.ok) throw new Error((await optRes.json()).error || 'Could not load registration options');
  const options = await optRes.json();
  const newPrfSaltB64 = options.prf_salt;
  const newPrfSalt = b64ToBytes(newPrfSaltB64);
  const hasVault = !!options.has_vault;

  // Step 2: obtain the vault private key (unwrap via existing passkey, or make new).
  let vaultPriv, vaultPubB64;
  if (hasVault && options.existing_passkeys && options.existing_passkeys.length) {
    const authOptRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
    if (!authOptRes.ok) throw new Error('Could not start existing-passkey verification');
    const authOpts = await authOptRes.json();
    const { prfOutput, usedCredId, assertionPayload } = await doGetPRF(
      authOpts, options.existing_passkeys, { evalByCredential: true }
    );
    await verifyAssertion(authOpts.flowId, assertionPayload);
    const match = options.existing_passkeys.find(p => p.cred_id === usedCredId);
    if (!match) throw new Error('The passkey you used is not registered.');
    const kek = await kekFromPRF(prfOutput);
    prfOutput.fill(0);
    vaultPriv = unwrapWithKEK(b64ToBytes(match.wrapped_privkey), kek);
    kek.fill(0);
    if (!vaultPriv) throw new Error('Could not unwrap the vault key with that passkey. Try a different one.');
    vaultPubB64 = null; // already known server-side
  } else {
    // First passkey ever → generate the vault keypair here.
    const kp = nacl.box.keyPair();
    vaultPriv = kp.secretKey;
    vaultPubB64 = bytesToB64(kp.publicKey);
  }

  // Step 3: create the new passkey — requesting a PRF evaluation with the new
  // salt right away. Modern Chromium returns prf.results at creation, which
  // saves the extra authentication ceremony entirely.
  const { prfFromCreate, payload: createPayload } = await doCreate(options, newPrfSalt);

  // Step 4: obtain the new passkey's PRF output → KEK → wrap the vault privkey.
  let wrappedPrivB64;
  try {
    let newPrf = prfFromCreate;
    if (!newPrf) {
      // Authenticator didn't evaluate PRF at creation — run a get() ceremony.
      // NOTE: no server-side assertion verify here; the new credential isn't
      // persisted server-side yet (that happens in step 5).
      const authOptRes2 = await fetch('/api/webauthn/auth/options', { method: 'POST' });
      if (!authOptRes2.ok) throw new Error('Could not verify PRF on the new passkey');
      const authOpts2 = await authOptRes2.json();
      const r = await doGetPRF(
        authOpts2, [{ cred_id: createPayload.id, prf_salt: newPrfSaltB64,
          transports: createPayload.response.transports }],
        { evalByCredential: false, firstSalt: newPrfSalt }
      );
      newPrf = r.prfOutput;
    }
    const kek = await kekFromPRF(newPrf);
    newPrf.fill(0);
    const wrapped = wrapWithKEK(vaultPriv, kek);
    kek.fill(0);
    wrappedPrivB64 = bytesToB64(wrapped);
  } catch (e) {
    vaultPriv.fill(0);
    throw new Error('Could not verify encryption (PRF) support on the new passkey. ' + (e.message || ''));
  }
  vaultPriv.fill(0);

  // Step 5: verify + persist.
  const body = { credential: createPayload, label: label || 'Passkey', wrapped_privkey: wrappedPrivB64 };
  if (vaultPubB64) body.vault_pubkey = vaultPubB64;
  const verRes = await fetch('/api/webauthn/register/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Session-Token': sessionToken },
    body: JSON.stringify(body)
  });
  const verJson = await verRes.json();
  if (!verRes.ok || !verJson.ok) throw new Error(verJson.error || 'Passkey registration failed');
  return { ok: true, cred_id_short: verJson.cred_id_short, first: !hasVault };
}

// ── Upload: seal a fresh FEK to the vault public key ──────
// Returns { fek: Uint8Array(32), wrappedFekB64 }. NO ceremony needed.
function sealFEK(vaultPubB64) {
  const fek = nacl.randomBytes(32);
  const sealed = sealTo(fek, vaultPubB64);
  return { fek, wrappedFekB64: bytesToB64(sealed) };
}

// ── Download: unwrap the FEK via any registered passkey ───
// `passkeys`: [{ cred_id, prf_salt, wrapped_privkey, transports }] (from meta).
// `wrappedFekB64`: the sealed FEK. Returns Uint8Array(32) FEK.
async function unsealFEK(passkeys, wrappedFekB64) {
  if (!passkeySupported()) throw new Error('This browser does not support passkeys.');
  if (!passkeys || !passkeys.length) throw new Error('No passkeys are registered for this file.');

  const authOptRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
  if (!authOptRes.ok) throw new Error((await authOptRes.json()).error || 'Could not load passkey options');
  const authOpts = await authOptRes.json();

  const { prfOutput, usedCredId, assertionPayload } = await doGetPRF(
    authOpts, passkeys, { evalByCredential: true }
  );
  await verifyAssertion(authOpts.flowId, assertionPayload);

  const match = passkeys.find(p => p.cred_id === usedCredId);
  if (!match) throw new Error('The passkey you used is not authorised for this file.');

  const kek = await kekFromPRF(prfOutput);
  prfOutput.fill(0);

  // v2.4: a passkey may carry MULTIPLE wraps of the vault key (e.g. one from the
  // hybrid/QR PRF value, one from the on-device PRF value — iOS Safari returns
  // different PRF outputs per transport). Try every wrap with this KEK; secretbox
  // is authenticated, so only the wrap matching THIS context opens — the rest
  // fail cleanly. Fall back to the legacy single field for old servers.
  const wrapList = (match.wraps && match.wraps.length)
    ? match.wraps.map(w => w.wrapped_privkey)
    : (match.wrapped_privkey ? [match.wrapped_privkey] : []);
  let vaultPriv = null;
  for (const w of wrapList) {
    const attempt = unwrapWithKEK(b64ToBytes(w), kek);
    if (attempt) { vaultPriv = attempt; break; }
  }
  kek.fill(0);
  if (!vaultPriv) {
    // This passkey verified, but none of its stored wraps match the PRF value
    // this context produced. Signal the caller so it can offer to “enable this
    // device” (bootstrap a new wrap via a working channel).
    const err = new Error('This device produced a passkey value that none of the stored keys match yet. Enable this device (one-time) to decrypt directly here.');
    err.code = 'NEEDS_DEVICE_WRAP';
    err.credId = usedCredId;
    throw err;
  }

  // Recover the vault public key from the private key so we can open the box.
  const vaultPubForOpen = nacl.box.keyPair.fromSecretKey(vaultPriv).publicKey;
  const fek = sealOpen(b64ToBytes(wrappedFekB64), vaultPubForOpen, vaultPriv);
  vaultPriv.fill(0);
  if (!fek) throw new Error('Could not decrypt the file key — the file may be corrupted.');
  return fek; // Uint8Array(32)
}

// ── Enable-this-device (v2.4) ─────────────────────────────
// Bootstraps an on-device wrap for a passkey whose only stored wrap came from a
// DIFFERENT PRF context (the iOS Safari hybrid-vs-on-device case). The vault
// private key is obtained via a WORKING channel (a passphrase-derived vault key
// the caller already recovered, OR any wrap that DOES open here), then re-wrapped
// under the CURRENT on-device PRF KEK and posted to the server. Never sends the
// vault key in the clear.
//   vaultPriv: Uint8Array(32) — the vault private key, already recovered locally.
//   passkeys, credIdHint: to run the on-device ceremony with the same passkey.
async function enableThisDevice(passkeys, vaultPriv, prfContext) {
  if (!vaultPriv || vaultPriv.length !== 32) throw new Error('Missing vault key for device enablement.');
  const authOptRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
  if (!authOptRes.ok) throw new Error((await authOptRes.json()).error || 'Could not load passkey options');
  const authOpts = await authOptRes.json();
  const { prfOutput, usedCredId, assertionPayload } = await doGetPRF(
    authOpts, passkeys, { evalByCredential: true }
  );
  await verifyAssertion(authOpts.flowId, assertionPayload);
  const kek = await kekFromPRF(prfOutput);
  prfOutput.fill(0);
  const wrapped = wrapWithKEK(vaultPriv, kek); // fresh random nonce inside
  kek.fill(0);
  const res = await fetch('/api/webauthn/add-wrap', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      cred_id: usedCredId,
      prf_context: prfContext || 'platform',
      wrapped_privkey: bytesToB64(wrapped)
    })
  });
  if (!res.ok) throw new Error((await res.json()).error || 'Could not save the device key.');
  return { ok: true, credId: usedCredId };
}

// ── Recovery-assisted device calibration (v2.4, GENERIC) ──────────────────
// The fully generic fix for the iOS/WebKit hybrid-vs-on-device PRF bug that
// works for ANY self-hoster on the device ITSELF (no second device needed).
// Requires: (1) an admin session token, (2) a finalized recovery key on the
// server. The server opens the recovery wrap with its recovery private-key
// file and returns the vault private key to this authenticated admin browser;
// we then re-wrap it under the CURRENT on-device PRF KEK. Thereafter the
// passkey decrypts directly in this context, forever.
//   adminToken: X-Session-Token from POST /auth/login.
async function bootstrapViaRecovery(passkeys, adminToken, prfContext) {
  if (!adminToken) throw new Error('Admin login is required to calibrate this device.');
  const res = await fetch('/api/webauthn/recovery-bootstrap', {
    method: 'POST',
    headers: { 'X-Session-Token': adminToken }
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || 'Could not fetch the vault key from the recovery channel.');
  const vaultPriv = b64ToBytes(data.vault_privkey);
  try {
    return await enableThisDevice(passkeys, vaultPriv, prfContext || 'platform');
  } finally {
    vaultPriv.fill(0);
  }
}

// ── Recovery key setup: wrap the vault private key for a recovery pubkey ────
// Runs ONE passkey ceremony to unwrap the vault private key locally, then
// seals it to the given recovery PUBLIC key (server-generated software key).
// The vault private key never leaves this function unencrypted.
// `passkeys`: [{ cred_id, prf_salt, wrapped_privkey, transports }]
// Returns the wrap as base64 (to be sent to /api/recovery/finalize).
async function wrapVaultKeyForRecovery(passkeys, recoveryPubB64) {
  if (!passkeySupported()) throw new Error('This browser does not support passkeys.');
  if (!passkeys || !passkeys.length) throw new Error('No passkeys are registered.');
  if (!recoveryPubB64) throw new Error('Missing recovery public key.');

  const authOptRes = await fetch('/api/webauthn/auth/options', { method: 'POST' });
  if (!authOptRes.ok) throw new Error((await authOptRes.json()).error || 'Could not load passkey options');
  const authOpts = await authOptRes.json();

  const { prfOutput, usedCredId, assertionPayload } = await doGetPRF(
    authOpts, passkeys, { evalByCredential: true }
  );
  await verifyAssertion(authOpts.flowId, assertionPayload);

  const match = passkeys.find(p => p.cred_id === usedCredId);
  if (!match) throw new Error('The passkey you used is not registered.');

  const kek = await kekFromPRF(prfOutput);
  prfOutput.fill(0);
  const vaultPriv = unwrapWithKEK(b64ToBytes(match.wrapped_privkey), kek);
  kek.fill(0);
  if (!vaultPriv) throw new Error('Could not unwrap the vault key with that passkey.');

  const wrapped = sealTo(vaultPriv, recoveryPubB64);
  vaultPriv.fill(0);
  return bytesToB64(wrapped);
}

// A keyProvider (salt => 32-byte key) that IGNORES the per-file salt and always
// returns the fixed FEK. The NYX3 blob was encrypted directly with the FEK, so
// every chunk/metadata call must return the same key regardless of salt.
function fekKeyProvider(fek) {
  const copy = fek.slice(0);
  return async () => copy;
}

// ── Expose ────────────────────────────────────────────────
window.NyxPasskey = {
  supported: passkeySupported,
  register: passkeyRegister,
  wrapVaultKeyForRecovery,
  sealFEK,
  unsealFEK,
  enableThisDevice,
  bootstrapViaRecovery,
  fekKeyProvider,
  _b64ToBytes: b64ToBytes,
  _bytesToB64: bytesToB64,
  _sealOpen: sealOpen
};
