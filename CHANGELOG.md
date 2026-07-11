# Changelog

All notable changes to NyxVault are documented here.

## [2.3.0] — 2026-07-11

### 🔑 Passkey encryption — the headline feature

- **Passkey (WebAuthn PRF) encryption is now the DEFAULT for new uploads.**
  Unlock your files with Face ID, Touch ID, Windows Hello or a hardware key —
  no passphrase to remember, nothing the server could ever read.
- **Envelope architecture:** the vault has an X25519 keypair; the private key
  is wrapped separately for every registered passkey using a key derived from
  the WebAuthn **PRF extension** secret. Each file is encrypted with a random
  file key (FEK) that is sealed to the vault public key (libsodium sealed box).
  Result: **any of your passkeys decrypts every passkey-mode file**, and adding
  a passkey never requires re-encrypting anything.
- **Passphrase mode is still there** — an explicit "use passphrase instead"
  option at upload time (and the CLI takes a passphrase argument).
- **Zero-knowledge, end to end:** the server stores only wrapped keys and
  ciphertext; it can never decrypt files, filenames or content types.
- **Passkey management UI:** register, rename and delete passkeys, with
  credential-ID chips, created/last-used timestamps and live count.

### 🦞 Agent recovery key — CLI decryption for passkey-mode files

- **New: an opt-in software recovery key lets the server host's agent (Nyx)
  decrypt passkey-mode files from the command line** — no biometric
  authenticator required. Until now, passkey-mode files could only be opened
  in a browser with a registered passkey; the agent could upload (sealing to
  the vault public key) but never decrypt.
- **How it works:** the server generates an X25519 recovery keypair; the
  private key is written to `data/recovery-key.json` (chmod 600, git-ignored,
  never leaves the host). The browser then runs **one passkey ceremony**,
  unwraps the vault private key locally and seals it to the recovery public
  key (anonymous sealed box) — the vault private key never travels in
  plaintext. The wrap is stored in a new `recovery_keys` table.
- **Admin UI:** the Passkeys card gains an "Add recovery key" button with a
  clear warning that this key allows the server operator to decrypt all
  passkey-mode files, plus status display and one-click removal (revocation).
- **CLI:** `node nyx-decrypt.js <blob> --recovery [output] [--token <hex>]`
  opens the chain recovery key → vault private key → file key (FEK) → file.
  Without `--token`, the right DB entry is identified automatically by the
  blob's authenticated header HMAC. Auto-detects recovery mode when no
  passphrase is given and a recovery key file exists.
- **New endpoints (admin-only):** `GET /api/recovery`,
  `POST /api/recovery/init`, `POST /api/recovery/finalize`,
  `DELETE /api/recovery/:id`. Removing the last passkey also purges recovery
  keys (they wrap a vault key that no longer exists).
- **Scope of the trade-off (explicit + opt-in):** a finalized recovery key
  reduces zero-knowledge **for passkey-mode files only**. Passphrase-mode
  files remain fully zero-knowledge — the server still cannot decrypt them,
  recovery key or not.
- `NYXVAULT_DB`, `NYXVAULT_STORAGE` and `NYXVAULT_RECOVERY_KEY` environment
  overrides so test instances can run against throwaway paths.
- Verified end to end: recovery-decrypt of a passkey-mode upload on an
  isolated test instance (byte-identical output), passphrase CLI round-trip
  unchanged.

### 🛡️ Passkey-loss safety UX

- **Persistent backup note** in the Passkeys admin card: passkeys are the ONLY
  way to decrypt passkey-mode files (zero-knowledge, no password reset), with a
  strong recommendation to register at least TWO passkeys on different devices.
  An extra alert appears while only one passkey is registered.
- **Hardened last-passkey deletion**: deleting the final passkey now requires
  an explicit warning modal AND typing `DELETE` to confirm — it spells out that
  all passkey-encrypted files become permanently unrecoverable.
- **One-time briefings**: an acknowledgement dialog after registering the first
  passkey, and a one-time hint after the first passkey-mode upload ("keep at
  least one passkey safe — there is no password recovery").
- `nyxDialog` supports acknowledgement-only mode (no cancel button); typed
  prompts can be styled as destructive.
- Verified: 21 MB browser passkey E2E, browser passphrase round-trip (NYX4),
  CLI NYX4 round-trip, **and a real 16 MB-era NYX3 file decrypting in both the
  browser and the CLI** — all byte-identical.

### ✨ Admin UI redesign (cosmic lobster, but tidier)

- The admin page is now organised into three clean glass cards — **Upload**,
  **Passkeys**, **Your Files** — with consistent headers, icons, subtitles,
  hover glow and mobile-friendly spacing (tables scroll horizontally on small
  screens instead of breaking the layout).
- **Native `prompt()`/`confirm()` are gone.** Renaming a passkey, naming a new
  one, deleting files and the scary “delete your LAST passkey” confirmation all
  use a proper cosmic-styled dialog (keyboard: Enter/Escape, click-outside to
  cancel, danger-styled destructive buttons).
- Passkey rows show a monospace credential-ID chip next to the name.
- The passphrase prompt when downloading a foreign-passphrase file from the
  admin list is a real password dialog now.
- Download page: entrance animation, hash-line wrapping, minor polish.
- All dates render in English locale formatting.

### 🔒 Hardening & fixes

- Burn-after-reading single-use lock is now an atomic
  `UPDATE … WHERE downloaded_at IS NULL` claim (no double-serve window).
- `secureDelete` (random overwrite before unlink) is now used on **every**
  deletion path — manual delete, lazy expiry purge and the periodic cleanup —
  not just burn.
- Periodic cleanup now uses the indexed expiry query and also removes orphaned
  multer temp files (aborted uploads) older than 24 h.
- Corrupt `transports` JSON in a passkey row can no longer 500 an endpoint
  (defensive parsing everywhere).
- VirusTotal cache is bounded (500 entries, FIFO eviction).
- Server fails fast at startup when `API_KEY` / `WEB_PASSWORD` are missing.
- `/health` reports the real version from `package.json`.
- Upload XHR no longer hangs the UI on a non-JSON error response (proxy error
  pages), and reports the HTTP status.
- The plaintext filename is no longer sent (and ignored) as a form field on
  web uploads — it never even transits the wire now.
- Removed dead code: unused `SESSION_SECRET` config, duplicate
  `x-powered-by` disable, unused SELECT-all statement, unused `escapeHtml`.

### 🔐 Argon2id memory raised: 16 MB → 21 MB (new NYX4 format)

- New passphrase encryptions use **21 MB (21504 KiB) Argon2id memory** instead
  of 16 MB — a stronger work factor against GPU/ASIC brute force.
- Introduced the **NYX4 format magic**: byte-layout identical to NYX3, but the
  magic tells the decryptor which KDF parameters to use (NYX4 → 21 MB,
  NYX3 → 16 MB). **Every existing file keeps decrypting exactly as before** —
  KDF params are now versioned by the format, never guessed.
- The header HMAC is computed over the *actual* magic bytes, so the format
  version itself is authenticated (a tampered NYX4→NYX3 downgrade fails).
- Applied consistently across the web app, download page, `nyx-upload.js`,
  `nyx-decrypt.js` and `nyx-migrate.js` (migration now emits NYX4). Encrypted
  metadata strings (filenames/content types) also use 21 MB for new uploads,
  with 21 → 16 → 64 MB fallback on decrypt.
- Passkey-mode files are unaffected (they use a random file key, not Argon2).

### 💪 Upload size

- The web UI now reads the server’s real `MAX_FILE_SIZE_MB` from
  `GET /api/settings` and rejects oversized files **before** encrypting, with a
  clear message (previously the failure surfaced only after upload).

### 📚 Docs

- README rewritten: passkey envelope architecture diagram, systemd + Caddy
  examples, updated env reference, testing notes.
- API.md: documented `/api/settings`, passkey management, WebAuthn ceremony
  endpoints, `key_mode` / `wrapped_fek` fields.

## [2.2.1] — 2026-07-11

### 🐛 Passkey fixes (verified end-to-end with a CDP virtual authenticator)

- **Fixed: www origin broke every passkey ceremony.** `www.nyxvault.org` served
  the app directly, but the server only accepted `https://nyxvault.org` as the
  WebAuthn origin. A ceremony started on the www URL passes in the browser
  (rpID suffix rule) and then **always fails server-side verification** — on
  every Chromium browser (Edge, Opera, Chrome …). The server now accepts both
  apex and www origins, and Caddy 301-redirects www → apex so there is a single
  canonical origin.
- **PRF is now evaluated during `create()`.** Modern Chromium returns
  `prf.results` at registration time, which removes one whole extra passkey
  prompt. The separate `get()` ceremony remains as a fallback for
  authenticators that only evaluate PRF on assertion.
- **Early, clear PRF-capability error.** If the authenticator reports
  `prf.enabled === false` at creation (e.g. some Windows Hello setups),
  registration now fails immediately with an actionable message (use a phone
  passkey via QR code or a security key) instead of a confusing late failure.
- **Real error messages.** `create()`/`get()` exceptions are no longer swallowed
  into a generic “cancelled” message — DOMException names (`SecurityError`,
  `InvalidStateError`, …) are surfaced so failures are diagnosable.
- **No more bogus 404 during registration.** The fallback PRF `get()` on a
  freshly created (not yet persisted) credential no longer calls
  `/api/webauthn/auth/verify`, which could only ever answer 404.

Verified: full register → upload → download → decrypt flow, including a second
passkey (unwrap-with-existing + re-wrap) and multi-credential
`prf.evalByCredential` decryption, via Chromium's virtual authenticator
(`hasPrf: true`), plus passphrase-mode CLI regression (nyx-upload/nyx-decrypt).

## [2.2.0] — 2026-07-11

### 🔑 Passkey encryption, redesigned (envelope encryption)

The v2.1.x passkey design was cryptographically broken for multi-passkey use: it
assumed one shared global PRF salt would yield the SAME PRF output across every
passkey. It does not — WebAuthn PRF output is a **per-credential HMAC**, so each
passkey produces a different secret. v2.2.0 replaces this with proper **envelope
encryption** so that **every** registered passkey can decrypt **every**
passkey-encrypted file.

#### New architecture
- **Vault keypair (X25519).** A single vault keypair is generated in the browser
  when the **first** passkey is registered. Only the **public** key is stored on
  the server (`settings.vault_pubkey`). The private key is never stored in
  plaintext.
- **Per-passkey key wrapping.** Each passkey gets its **own** random 32-byte PRF
  salt. From that passkey's PRF output we derive `KEK = HKDF-SHA256(prfOutput)`
  and store `wrapped_privkey = secretbox(vault_privkey, KEK)` in the passkey row.
  So **any** registered passkey can independently unwrap the same vault private
  key.
- **Adding a passkey later** unwraps the vault private key via an existing
  passkey, then re-wraps it for the new one (the UI runs the needed ceremonies).
- **File encryption (passkey mode — now the DEFAULT).** A random file key (FEK)
  encrypts the file as a normal NYX3 blob; the FEK is sealed to the vault public
  key (anonymous sealed box) and stored as `wrapped_fek`. **No WebAuthn ceremony
  is needed to upload** — anyone with the public key can seal (web UI, CLI, agent
  API). `key_mode='passkey'`.
- **Decrypt (download page).** `credentials.get()` with `allowCredentials` = all
  registered passkeys and **per-credential PRF salts** (`prf.evalByCredential`).
  Whichever passkey the user picks yields its PRF output → KEK → unwrap vault
  privkey → open the sealed FEK → decrypt the blob. Key material is wiped from
  memory after use.
- **Passphrase mode (explicit only).** A file becomes passphrase-only (Argon2id,
  passkeys cannot open it) **only** when a passphrase is explicitly set — via the
  new "Use a passphrase instead" toggle in the web UI, or by passing a passphrase
  to the CLI. `key_mode='passphrase'`.

#### Passkey management (admin UI)
- New table listing every registered passkey: **name (editable)**, created date,
  last used, and **rename / delete** actions.
- Registration now prompts for a **nickname**.
- Deleting the **last** passkey is hard-gated: it warns that all
  passkey-encrypted files become permanently unrecoverable and requires explicit
  confirmation (`?confirm=1`).
- New endpoints: `GET/PATCH/DELETE /api/passkeys`, and the vault public key is
  exposed via `GET /api/settings` (`vault_pubkey`).

#### CLI / agent API (`nyx-upload.js`)
- **Default is now passkey mode.** With no passphrase argument, the CLI fetches
  the vault public key from `GET /api/settings` and seals a FEK to it — the file
  is decryptable by any registered passkey in a browser.
- Passing a passphrase (arg 4 / `NYXVAULT_PASSPHRASE`) keeps the classic
  passphrase mode. Argument order is unchanged (backward compatible).
- `nyx-decrypt.js` still decrypts passphrase files; for passkey files it prints a
  clear message that a browser + passkey is required.

#### Migration & compatibility
- **Existing passphrase-encrypted files keep working** unchanged (Argon2id path,
  CLI included). The blob format (NYX3) is byte-identical across both modes.
- Idempotent DB migrations add `files.wrapped_fek` and
  `passkeys.prf_salt / wrapped_privkey / last_used`.
- **Pre-2.2 passkeys are wiped on upgrade** (they used the broken global-salt
  scheme). Fabian must **re-register** his passkeys — the old vault pubkey is
  cleared so a fresh vault keypair is created on first re-registration.
- Zero-knowledge preserved: the server only ever stores the vault **public** key,
  **wrapped** private keys, **sealed** FEKs, and non-secret salts.

---

## [2.1.1] — 2026-07-11

### 🔑 Passkey polish (post-first-test feedback)

#### Fixed
- **All user-facing strings are now English** (buttons, toasts, error messages,
  status lines, HTML labels) — previously some passkey UI text was German.
- **Reliable PRF-support detection.** `create()`'s
  `clientExtensionResults.prf.enabled` is unreliable — many authenticators
  (Windows Hello, some iCloud versions) don't report it even though PRF works
  fine during `get()`. Registration no longer hard-fails on the `create()`
  result: after saving the credential it runs a **real follow-up
  `navigator.credentials.get()` with `prf.eval`** and only reports PRF as
  unsupported if that probe genuinely produces no output. The user is told they
  may be prompted twice (create + verify). When PRF is truly unavailable, the
  English message suggests trying the latest Chrome/Edge or an iPhone/iPad passkey.
- **Broader platform-authenticator compatibility:** registration now uses
  `residentKey: 'preferred'` + `requireResidentKey: false` (was `'required'`),
  which Windows Hello and some iCloud versions require.

---

## [2.1.0] — 2026-07-11

### 🔑 Passkey Encryption (WebAuthn PRF)

Files can now optionally be encrypted with a **passkey** instead of a passphrase.
Zero-knowledge is fully preserved — the encryption key is derived entirely in the
browser from the WebAuthn PRF extension and never touches the server.

#### How it works
- **Key derivation:** `navigator.credentials.get()` requests the PRF extension
  with `eval.first = <global prf_salt>`. The authenticator returns 32 secret
  bytes, which are run through **HKDF-SHA256** (salt = the per-file blob salt,
  info = `nyxvault-passkey-v1`) to produce the 32-byte XChaCha20-Poly1305 key.
- **Same blob format:** passkey files use the exact same **NYX3** on-disk format
  as passphrase files — only the key *source* differs. All chunk/HMAC integrity
  protection is reused unchanged.
- **One global PRF salt** (non-secret, stored in the new `settings` table) is
  shared across all registered passkeys, so any of the owner's devices
  (iPhone + Laptop, iCloud-synced) can decrypt any passkey-encrypted file.

#### Added
- **Global setting `passkey_mode`** (on/off) — toggled in the admin UI.
  `GET /api/settings` (public) exposes `passkey_mode`, whether a passkey is
  registered, and the non-secret `prf_salt`. `POST /api/settings` (admin only)
  toggles the mode (refuses to enable it with no passkey registered).
- **Passkey registration** in the admin UI ("🔑 Passkey registrieren"), backed by
  `POST /api/webauthn/register/{options,verify}`. Supports **multiple** passkeys.
  Credentials are stored in the new `passkeys` table.
- **WebAuthn authentication ceremony** endpoints
  `POST /api/webauthn/auth/{options,verify}` (public) for the download page,
  with server-side counter tracking (anti-replay).
- **Per-file `key_mode`** column (`passphrase` | `passkey`), returned in
  `/api/dl/:token/meta`. The download page shows a *"Mit Passkey entschlüsseln"*
  button for passkey files and keeps the passphrase input for passphrase files.
- Configurable RP via env: `WEBAUTHN_RP_ID` (default `nyxvault.org`),
  `WEBAUTHN_RP_NAME`, `WEBAUTHN_ORIGIN` (default `https://nyxvault.org`).
- Dependency: `@simplewebauthn/server` for correct ceremony verification.

#### Unchanged / compatibility
- The **passphrase path is 100% intact** — API/CLI uploads (`nyx-upload.js`) stay
  passphrase-based, all existing files decrypt exactly as before, and the NYX3
  encryption format for passphrase files is byte-for-byte unchanged.
- No CDN scripts added — `passkey.js` is served locally, so the strict CSP
  (`script-src 'self'`) is untouched.

---

## [2.0.2] — 2026-06-27

### 🔒 Security: dependency updates

- **multer** `2.1.1 → 2.2.0` — patches 2 high-severity advisories.
- **form-data** `→ 4.0.6` — patches CRLF injection (GHSA-hmw2-7cc7-3qxx).
- `npm audit`: **0 vulnerabilities**.

---

## [2.0.1] — 2026-06-22

### 🛡️ Anti-Downgrade: NYX2 Legacy Path Removed from Browser

Addresses a downgrade attack vector identified post-release: an attacker who can modify a blob (compromised server, MitM) could overwrite the magic bytes from `NYX3` to `NYX2`, causing the client to silently use the legacy code path without integrity checks — bypassing all NYX3 protections.

#### Fixed
- **Browser (app.js, dl-page.js):** NYX2 blobs are now **rejected** with a clear error message instead of silently decrypted. This eliminates the downgrade attack surface entirely.
- **CLI (nyx-decrypt.js):** NYX2 decryption is **blocked by default**. Use `--allow-legacy` flag to explicitly opt in (needed for migration).

#### Added
- **`nyx-migrate.js`** — CLI tool to migrate NYX2 blobs to NYX3 format.
  - Single file: `node nyx-migrate.js <file> <passphrase> [output]`
  - Server-wide: `node nyx-migrate.js --server <passphrase>` (re-encrypts all NYX2 blobs in `storage/`, creates `.nyx2bak` backups)

#### Migration Guide
1. Run `node nyx-migrate.js --server '<passphrase>'` for each passphrase in use.
2. Verify migrated files work: `node nyx-decrypt.js <file> <passphrase>`.
3. After confirming, delete `.nyx2bak` backup files.

---

## [2.0.0] — 2026-06-22

### 🔐 Security — NYX3 Encryption Format

Major cryptographic integrity upgrade. **New files are encrypted with the NYX3 format; existing NYX2 files remain fully readable (backward compatible).**

#### Fixed
- **Chunk reordering/truncation vulnerability** — Each chunk's plaintext now includes a 5-byte prefix (`chunk_index` as 4-byte big-endian + `is_last` flag). After decryption, the prefix is verified: wrong order → `Integrity error: chunk order mismatch`; missing final marker → `Integrity error: missing final chunk marker`; premature final marker → `Integrity error: premature final chunk marker`. An attacker with blob access can no longer silently reorder, duplicate, or truncate chunks.
- **Unauthenticated header** — A 32-byte HMAC-SHA256 of the header (magic + salt + num_chunks) is stored between the salt and the chunk count. The HMAC key is derived via domain separation (`HMAC-SHA256(derived_key, "nyxvault-header-auth")`), so tampering with `num_chunks` is detected before any chunk decryption begins.
- **Incorrect cipher label on landing page** — The landing page and index previously stated "XChaCha20-Poly1305"; the actual cipher used by TweetNaCl's `secretbox` is **XSalsa20-Poly1305**. Corrected everywhere.

#### Format

```
NYX3 on-disk layout:
  "NYX3"            4 bytes   magic
  salt              16 bytes  Argon2id salt
  header_hmac       32 bytes  HMAC-SHA256(hmac_subkey, magic ‖ salt ‖ num_chunks)
  num_chunks        4 bytes   uint32 big-endian
  repeated num_chunks times:
    nonce           24 bytes
    ciphertext      encrypted(chunk_index‖is_last‖data) + 16 bytes Poly1305 tag

  hmac_subkey = HMAC-SHA256(derived_key, "nyxvault-header-auth")
  chunk plaintext prefix: index(4 BE) + is_last(1 byte: 0x00 or 0x01)
```

#### Changed
- `app.js` (browser encrypt) — writes NYX3 format with chunk prefix + header HMAC
- `dl-page.js` (browser decrypt) — detects NYX3 vs NYX2, verifies HMAC + chunk integrity
- `nyx-upload.js` (CLI encrypt) — writes NYX3 format
- `nyx-decrypt.js` (CLI decrypt) — detects NYX3 vs NYX2, uses `crypto.timingSafeEqual` for HMAC comparison
- `package.json` — version bumped to 2.0.0
- `server.js` — health endpoint reports version 2.0.0

#### Backward Compatibility
- NYX2 files are auto-detected by magic bytes and decrypted using the original code path (no integrity checks, since those didn't exist in NYX2).
- Legacy single-block format (used for `filename_enc` / `content_type_enc` metadata strings) is unchanged.
- Argon2id parameters are unchanged (16 MB, 3 iterations, 32-byte key).

---

## [1.2.2] — 2026-06-22

- New premium landing page; removed "Open Vault" links (instance is private).

## [1.2.1] — 2026-06-22

- Admin download: try vault passphrase first, prompt on failure for custom ones.

## [1.2.0] — 2026-06-22

- Fix admin download button; require passphrase on upload.
- Fast admin dashboard: paginated file list (25/page) with non-blocking filename decryption.

## [1.1.3] — 2026-06-21

- Fix 404 on `/` and `/admin` when install path contains a dot-dir.

## [1.1.2] — 2026-06-21

- Audit v3 fixes (Tyto 🦉): schema migration, CSP hardening, burn single-use + secure delete.
- Make VirusTotal scan strictly opt-in (privacy).

## [1.0.0] — 2026-06-21

- Initial production release.
- E2E encrypted file sharing with Argon2id + XSalsa20-Poly1305.
- Burn after reading, expiring links, QR code sharing.
- VirusTotal opt-in hash scan, in-browser preview (image/video/audio/PDF/text).
- CLI tools (`nyx-upload.js`, `nyx-decrypt.js`).
- Cosmic lobster theme 🦞.
