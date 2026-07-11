<div align="center">

<img src="public/assets/nyx-logo-256.png" alt="NyxVault" width="140" />

# NyxVault

**End-to-end encrypted, zero-knowledge file sharing.**

Encrypt in your browser. Share a link. The server never sees your data.

[Features](#-features) · [Quick Start](#-quick-start) · [Security Model](#-security-model) · [API & CLI](API.md)

</div>

---

## ✨ Features

- 🔐 **End-to-end encryption** — files are encrypted in the browser/CLI with Argon2id + XSalsa20-Poly1305 (TweetNaCl). The server only ever stores ciphertext.
- 🔑 **Passkey encryption (WebAuthn PRF)** — register a passkey (Face ID / Touch ID / security key) once and every upload is encrypted *to your passkeys*: no passphrase to remember, no passphrase to leak. Envelope encryption means every registered passkey can open every passkey-encrypted file. See [Passkey architecture](#-passkey-architecture-envelope-encryption).
- 🛡️ **Integrity-protected chunks (NYX3)** — every chunk embeds its index and a final-chunk marker; the header is authenticated with HMAC-SHA256. Reordering, truncating, or tampering with chunks is detected immediately.
- 🧠 **Zero-knowledge** — your passphrase and the plaintext never leave your device. Not the filename, not the content type, nothing.
- 🖼️ **In-browser preview** — images, video, audio, PDF and text are previewed right after decryption, before you download.
- 🔥 **Burn after reading** — optional self-destruct: the file is permanently deleted from the server the moment it's first successfully decrypted.
- ⏳ **Expiring links** — 1 hour, 24 hours, 7 days, 30 days, or never. Expired files are purged automatically.
- 🛡️ **VirusTotal scan (opt-in)** — never runs automatically. The SHA-256 hash is computed client-side and shown to you; only if you click *Scan* is the hash sent to VirusTotal — never the file itself. (Even sending a hash reveals that a file with that exact fingerprint exists, so it's strictly your choice.)
- ▦ **QR code sharing** — open any download link on your phone by scanning a QR code.
- ⚡ **Fast admin dashboard** — paginated file list (25/page) that renders instantly; encrypted filenames are decrypted lazily in the background instead of blocking on hundreds of key derivations.
- 📦 **Large files** — chunked streaming encryption handles big files without eating all your RAM.
- 🌌 **It looks like Nyx** — a cosmic lobster theme, because why should encryption be boring.

## 🚀 Quick Start

### Requirements
- Node.js 18+

### Install

```bash
git clone https://github.com/Open-Cosmic-Software/nyxvault.git
cd nyxvault
npm install
cp .env.example .env
```

### Configure

Edit `.env` and set **your own** values:

```ini
PORT=3870
API_KEY=<generate a long random string>
WEB_PASSWORD=<your web UI password, or an argon2 hash starting with $argon2>
MAX_FILE_SIZE_MB=100
VT_API_KEY=              # optional, enables VirusTotal scanning

# Passkeys (WebAuthn) — must match the public hostname you serve the app on
WEBAUTHN_RP_ID=vault.example.com
WEBAUTHN_RP_NAME=NyxVault
WEBAUTHN_ORIGIN=https://vault.example.com
```

Generate random secrets quickly:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

> ⚠️ **There is no default passphrase.** Every file is protected by a passphrase **you** choose at upload time. Choose a strong, unique one — it is the only thing standing between an attacker and your data. NyxVault cannot recover it for you.

### Run

```bash
node server.js
# 🔐 NyxVault running on http://127.0.0.1:3870
```

The server binds to `127.0.0.1` — put a reverse proxy (Caddy, nginx, Traefik) with TLS in front of it for public access.

### systemd example

```ini
[Unit]
Description=NyxVault - E2E Encrypted File Sharing
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/nyxvault
ExecStart=/usr/bin/node /opt/nyxvault/server.js
Restart=on-failure
RestartSec=5
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
```

### Caddy example

```caddyfile
www.vault.example.com {
	# WebAuthn rpID/origin should be ONE canonical origin — redirect www to apex.
	redir https://vault.example.com{uri} permanent
}

vault.example.com {
	request_body {
		max_size 2GB
	}
	reverse_proxy 127.0.0.1:3870
}
```

## 📖 Usage

### Web UI

1. Open `http://your-host/admin` and log in with `WEB_PASSWORD`.
2. Drag & drop a file, pick an expiry, optionally tick **🔥 Burn after reading**.
3. Enter an encryption passphrase → **Encrypt & Upload**.
4. Share the generated `/dl/<token>` link **and the passphrase** (over a separate channel!).

### Download

Anyone with the link opens it, enters the passphrase, and the file is decrypted **in their browser**. They get a preview, an optional VirusTotal scan (opt-in, see below), and a download button. If the file was set to *burn after reading*, it's destroyed on the server the moment it's decrypted.

### CLI

```bash
export NYXVAULT_API_KEY="your-api-key"
export NYXVAULT_URL="https://your-host"      # optional, defaults to https://nyxvault.org

# Upload (expiry + passphrase + burn are all optional)
node nyx-upload.js secret.pdf 24h 'my strong passphrase' burn

# Decrypt a downloaded blob
node nyx-decrypt.js encrypted.bin 'my strong passphrase' output.pdf
```

Full CLI and HTTP API reference: **[API.md](API.md)**.

## 🔑 Passkey architecture (envelope encryption)

Since v2.2, NyxVault can encrypt files *to your passkeys* using the WebAuthn
PRF (`hmac-secret`) extension — no passphrase involved. The design is classic
envelope encryption:

```
            REGISTRATION (once per passkey, in the browser)
┌─────────────────────────────────────────────────────────────┐
│ first passkey ever:  browser generates vault X25519 keypair    │
│   • vault PUBLIC key  → stored on the server (not secret)      │
│   • vault PRIVATE key → wrapped per passkey (below), never     │
│     stored in plaintext anywhere                                │
│                                                                 │
│ per passkey: PRF(salt_i) → KEK_i = HKDF(prf_output)             │
│   wrapped_privkey_i = secretbox(vault_priv, KEK_i)              │
└─────────────────────────────────────────────────────────────┘

            UPLOAD (no passkey prompt needed!)
┌─────────────────────────────────────────────────────────────┐
│ random FEK (32 B) encrypts the file as a normal NYX3 blob      │
│ wrapped_fek = sealed_box(FEK → vault public key)               │
│ server stores blob + wrapped_fek — can open neither            │
└─────────────────────────────────────────────────────────────┘

            DOWNLOAD (any registered passkey)
┌─────────────────────────────────────────────────────────────┐
│ passkey ceremony → PRF output → KEK_i → unwrap vault priv key  │
│ open sealed box → FEK → decrypt NYX3 blob. All client-side.    │
└─────────────────────────────────────────────────────────────┘
```

Key properties:

- **Every passkey opens every passkey-file** — the vault private key is wrapped
  once per passkey, so passkeys are interchangeable at decrypt time.
- **Uploads never prompt** — sealing to a public key needs no ceremony. The CLI
  and API can upload passkey-encrypted files too (`key_mode=passkey`).
- **The server is blind** — it stores the vault *public* key, per-passkey PRF
  salts, wrapped private keys, and sealed FEKs. None of these reveal plaintext.
- **Deleting the last passkey** permanently orphans all passkey-encrypted files
  (the UI warns loudly and requires explicit confirmation).
- Files can still be made **passphrase-only** per upload (“use a passphrase
  instead”), and passphrase files work exactly as before.

## 🔒 Security Model

| Property | How |
|---|---|
| **Encryption** | Argon2id (16 MB, 3 iterations) derives a key from your passphrase; XSalsa20-Poly1305 (`nacl.secretbox`) encrypts the data. Since v2.0 (NYX3 format), each chunk includes an authenticated index prefix and the header is HMAC-protected. |
| **Where** | 100% client-side — browser or CLI. The server receives only ciphertext. |
| **Filename privacy** | The original filename and content type are themselves encrypted; the server stores `redacted`. |
| **Passphrase** | Never transmitted. Not stored. Not recoverable. |
| **Passkeys** | WebAuthn PRF output never leaves the browser (client extension results are stripped before anything is sent). The vault private key exists only wrapped under per-passkey KEKs; file keys only sealed to the vault public key. |
| **VirusTotal** | **Opt-in only** — never automatic. The SHA-256 hash is computed client-side and shown locally; it's sent to VirusTotal only on explicit user click. The file is never uploaded to VT. A clear privacy note warns that even a hash query reveals the file's existence — so users can skip it for sensitive, unique files. |
| **Burn after reading** | The server only deletes the file after the client confirms a *successful* decryption, so a wrong passphrase can never destroy a file. The ciphertext blob is single-use (a server-side lock refuses a second fetch) and is overwritten with random bytes before unlink (best-effort secure delete). |
| **Transport** | Bind to localhost + TLS-terminating reverse proxy. Strict CSP (`script-src 'self' 'wasm-unsafe-eval'` — no inline scripts; plus `object-src 'none'`, `base-uri 'self'`, `form-action 'self'`), `X-Frame-Options: DENY`. PDF previews run in a sandboxed iframe. |
| **Rate limiting** | Upload, login and download endpoints are rate-limited against brute force. |

### What the server *can* see
The ciphertext, the file size, the upload time, and (optionally) an expiry timestamp. That's it.

### What the server *cannot* see
The plaintext, the filename, the content type, or your passphrase.

> NyxVault is built to minimize trust in the server. But you still trust the code that runs in your browser. Self-host it, read the source, and serve it over HTTPS.

## 🛠️ Tech

Node.js · Express · better-sqlite3 · TweetNaCl · hash-wasm (Argon2id) · multer · qrcode-generator. No build step, no framework — just open `server.js`.

See [CHANGELOG.md](CHANGELOG.md) for version history.

## 🧪 Testing

The passkey path is end-to-end tested with Playwright + the Chrome DevTools
`WebAuthn.addVirtualAuthenticator` API (CTAP2, internal transport, PRF
enabled): register → upload (21 MB) → download → decrypt → byte-for-byte hash
comparison, plus a passphrase-mode UI regression.

## 📄 License

MIT — see [LICENSE](LICENSE).

---

<div align="center">
<sub>Built with 🦞 by <b>Nyx</b> & Fabian · cosmic lobster approved</sub>
</div>
