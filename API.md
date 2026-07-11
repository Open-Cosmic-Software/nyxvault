# NyxVault — API & CLI Reference

Technical reference for programmatic use (CLI, HTTP API, and the on-disk encryption format). Written to be machine-readable and unambiguous — suitable for AI agents and developers integrating NyxVault.

- Base URL: your instance, e.g. `https://nyxvault.org`
- All responses are JSON unless noted.
- Auth: `X-Api-Key: <API_KEY>` header for upload/admin endpoints. Public download endpoints need no auth (the token is the capability).

---

## Core principle: zero-knowledge

The server **never** receives plaintext or passphrases. Encryption and decryption happen entirely client-side. Any integration MUST encrypt before upload and decrypt after download using the format described in [Encryption format](#encryption-format). The server is a dumb ciphertext store with metadata.

---

## Authentication

| Auth type | Header | Used for |
|---|---|---|
| API key | `X-Api-Key: <key>` | `/api/upload`, `/api/files`, `/api/download/:id`, `DELETE /api/files/:id` |
| Web session | `X-Session-Token: <token>` | same endpoints, after `POST /auth/login` |
| None | — | `/api/dl/:token/*`, `/api/vt/:hash`, `/dl/:token`, `/health` |

`POST /auth/login` body `{ "password": "<WEB_PASSWORD>" }` → `{ "token": "...", "expires_in": 86400 }`.

---

## HTTP API

### `POST /api/upload`
Upload an already-encrypted blob. **Auth required.** `multipart/form-data`.

| Field | Type | Required | Description |
|---|---|---|---|
| `file` | file | yes | The **ciphertext** blob (see [Encryption format](#encryption-format)). |
| `filename_enc` | string (base64) | no | Encrypted original filename (single-block format). |
| `content_type_enc` | string (base64) | no | Encrypted content type. |
| `expires_in` | string | no | Relative TTL: `30m`, `1h`, `24h`, `7d`, `30d`. |
| `expires_at` | string (ISO 8601) | no | Absolute expiry. Takes precedence over `expires_in`. |
| `burn_after_read` | `"1"`/`"true"` | no | Enable self-destruct on first successful decrypt. |
| `uploader` | string | no | Free-text label for logs. |

**Response 200:**
```json
{
  "id": 123,
  "download_token": "<64-hex>",
  "download_url": "/dl/<64-hex>",
  "size_bytes": 10485760,
  "upload_date": "2026-06-21 20:00:00",
  "expires_at": "2026-06-22T20:00:00.000Z",
  "burn_after_read": false
}
```

### `GET /api/files`
List non-expired files (metadata only). **Auth required.** Expired files are purged on access.

**Pagination** (query params): `page` (default `1`), `limit` (default `25`, max `100`).

Response: `{ "files": [ { id, size_bytes, upload_date, uploader, expires_at, download_token, ... } ], "count": N, "total": T, "page": P, "limit": L, "totalPages": TP }`.

`count` is the number of rows in this page; `total` is the full non-expired count. Filenames stay encrypted (`filename_enc`) — decrypt them client-side.

### `GET /api/download/:id`
Download the raw ciphertext blob by numeric id. **Auth required.** Returns `application/octet-stream`.

### `DELETE /api/files/:id`
Delete a file (DB row + blob). **Auth required.** Response: `{ "ok": true, "deleted": <id> }`.

### `GET /api/dl/:token/meta`
**Public.** Metadata for a download page. `:token` must match `^[a-f0-9]{64}$`.
```json
{
  "id": 123,
  "filename_enc": "<base64>",
  "content_type_enc": "<base64>",
  "size_bytes": 10485760,
  "upload_date": "2026-06-21 20:00:00",
  "uploader": "cli",
  "nonce": "",
  "burn_after_read": true
}
```
`404` if not found, `410` if expired.

### `GET /api/dl/:token/blob`
**Public.** Streams the raw ciphertext (`application/octet-stream`). This does **not** trigger burn-after-reading — only `/burn` does.

### `POST /api/dl/:token/burn`
**Public.** Destroys a burn-after-reading file. Call this **only after a successful client-side decryption**. No-op (returns `{ "burned": false }`) for non-burn files; idempotent for already-gone files.
```json
{ "burned": true }
```

### `GET /api/vt/:hash`
**Public. Opt-in.** VirusTotal lookup by SHA-256 hex hash (computed client-side from the *decrypted* bytes). The web UI never calls this automatically — only on explicit user action — because even a hash query reveals to VirusTotal that a file with that exact fingerprint exists. Integrators should treat it the same way. Rate-limited, 1h in-memory cache.
Possible responses:
- `{ "disabled": true }` — no `VT_API_KEY` configured.
- `{ "not_found": true }` — hash unknown to VirusTotal.
- `{ "malicious": N, "suspicious": N, "harmless": N, "undetected": N, "total": N, "permalink": "..." }`
- `{ "error": "..." }`

### `GET /health`
**Public.** `{ "status": "ok", "service": "nyxvault", "version": "2.0.0", "uptime": <seconds> }`.

---

## CLI

Both CLIs read configuration from environment variables. **No secrets are hardcoded; there is no default passphrase.**

### Environment
| Variable | Required | Default | Used by |
|---|---|---|---|
| `NYXVAULT_API_KEY` | upload | — | `nyx-upload.js` |
| `NYXVAULT_URL` | no | `https://nyxvault.org` | `nyx-upload.js` |
| `NYXVAULT_PASSPHRASE` | yes* | — | both (*or pass as arg) |
| `NYXVAULT_BURN` | no | — | `nyx-upload.js` (`1` = burn) |

### `nyx-upload.js`
```
node nyx-upload.js <file> [expires_in] [passphrase] [burn]
```
- `<file>` — path to upload.
- `[expires_in]` — `1h` `24h` `7d` `30d` `90m` (matches `^\d+[mhd]$`). Optional.
- `[passphrase]` — overrides `NYXVAULT_PASSPHRASE`. Optional.
- `[burn]` — literal `burn` enables burn-after-reading.

**Encryption mode (since 2.2.0):**
- **No passphrase given → passkey mode (default).** The CLI fetches the vault
  public key from `GET /api/settings` and seals a random file key (FEK) to it
  (anonymous X25519 sealed box). The file is decryptable in a browser with any
  registered passkey. Requires a passkey to have been registered first.
- **Passphrase given → passphrase mode.** Classic Argon2id key derivation;
  passkeys cannot open the file.

Example (passkey mode — no passphrase):
```bash
export NYXVAULT_API_KEY="..."
node nyx-upload.js report.pdf 24h
# → sealed to the vault pubkey; open the /dl/<token> link with a passkey
```
Example (passphrase mode):
```bash
node nyx-upload.js report.pdf 24h 'correct horse battery staple' burn
# → prints the /dl/<token> link
```

### `nyx-decrypt.js`
```
node nyx-decrypt.js <encrypted-file> [passphrase] [output-file]
```
Decrypts a downloaded blob. Auto-detects NYX3 (integrity-protected), NYX2 (legacy chunked), and legacy single-block format. Output defaults to `<input>-decrypted`.

### Programmatic download (no CLI)
```bash
# 1. fetch ciphertext
curl -s "https://host/api/dl/<token>/blob" -o encrypted.bin
# 2. decrypt locally
NYXVAULT_PASSPHRASE='...' node nyx-decrypt.js encrypted.bin
# 3. (if burn-after-reading) confirm destruction
curl -s -X POST "https://host/api/dl/<token>/burn"
```

---

## Encryption format

All encryption uses **Argon2id** for key derivation and **`nacl.secretbox`** (XSalsa20-Poly1305) for authenticated encryption.

**Argon2id parameters (fixed):**
`parallelism=1, iterations=3, memorySize=16384 KiB (16 MB), hashLength=32`.

### Chunked format (files) — magic `NYX3` (current) / `NYX2` (legacy)

#### NYX3 (v2.0+, integrity-protected)
Used by the CLI and web UI since v2.0. Layout:
```
"NYX3"            4 bytes   magic
salt              16 bytes  Argon2id salt
header_hmac       32 bytes  HMAC-SHA256(hmac_subkey, magic ‖ salt ‖ num_chunks)
num_chunks        4 bytes   uint32 big-endian
repeated num_chunks times:
  nonce           24 bytes
  ciphertext      encrypted(prefix ‖ data) + 16 bytes Poly1305 tag

hmac_subkey = HMAC-SHA256(derived_key, "nyxvault-header-auth")
chunk prefix (5 bytes): chunk_index(4 BE) + is_last(1 byte: 0x00 or 0x01)
```
Each chunk plaintext is `prefix ‖ data`, where `prefix` is 5 bytes (chunk index as uint32 BE + is_last flag). On decrypt, the HMAC is verified first (wrong passphrase or tampered header → immediate failure), then each chunk's prefix is checked against expected position and final-chunk status.

#### NYX2 (legacy, still readable)
Older files use the NYX2 format without integrity protection:
```
"NYX2"            4 bytes  magic
salt              16 bytes Argon2id salt
num_chunks        4 bytes  uint32 big-endian
repeated num_chunks times:
  nonce           24 bytes
  ciphertext      (chunk plaintext up to 4 MB) + 16 bytes Poly1305 tag
```
Each chunk is `nacl.secretbox(plaintextChunk, nonce, key)`. No chunk index or HMAC. The last chunk may be shorter. Chunk plaintext size is `CHUNK_SIZE = 4 MiB`.

Decryptors MUST auto-detect the format by reading the first 4 bytes (magic). NYX3 files start with `0x4E 0x59 0x58 0x33`; NYX2 files start with `0x4E 0x59 0x58 0x32`.

### Single-block format (metadata) — legacy
Used for short strings like `filename_enc` / `content_type_enc`, base64-encoded:
```
salt              16 bytes
nonce             24 bytes
ciphertext        plaintext + 16 bytes tag
```
Decryption tries `memorySize` 16384 then 65536 for backward compatibility.

### Reference pseudocode (decrypt)
```js
key = argon2id(passphrase, salt, {parallelism:1, iterations:3, memorySize:16384, hashLength:32})
plaintext = nacl.secretbox.open(ciphertext, nonce, key)  // null ⇒ wrong passphrase
```

---

## Integration checklist for agents

1. **Encrypt client-side** using the format above. Never send plaintext or the passphrase to the server.
2. Upload via `POST /api/upload` with `X-Api-Key`. Add `expires_in` and/or `burn_after_read` as needed.
3. Share `download_url` and the passphrase **out of band** (different channel than the link).
4. To consume: `GET /api/dl/:token/meta` → `GET /api/dl/:token/blob` → decrypt → (optional) `POST /api/dl/:token/burn`.
5. Optional integrity/safety: SHA-256 the decrypted bytes, query `GET /api/vt/:hash`.
6. Respect rate limits (HTTP 429). Back off and retry.

---

## Error codes
| Code | Meaning |
|---|---|
| `400` | Invalid token format / missing file |
| `401` | Bad/missing API key or session |
| `404` | File not found |
| `410` | File expired |
| `429` | Rate limited |
| `500` | Server error |
