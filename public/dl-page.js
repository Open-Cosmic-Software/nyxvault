  const SALT_BYTES = 16, NONCE_BYTES = 24, CHUNK_SIZE = 4 * 1024 * 1024, SECRETBOX_OVERHEAD = 16;
  const CHUNK_PREFIX_BYTES = 5; // 4-byte index BE + 1-byte is_last
  const MAGIC3 = new Uint8Array([0x4E, 0x59, 0x58, 0x33]); // "NYX3"

  async function deriveKey(passphrase, salt) {
    return new Uint8Array(await hashwasm.argon2id({
      password: passphrase, salt, parallelism: 1, iterations: 3,
      memorySize: 16384, hashLength: 32, outputType: 'binary'
    }));
  }
  function isNYX2(d){ return d.length>=4 && d[0]===0x4E && d[1]===0x59 && d[2]===0x58 && d[3]===0x32; }
  function isNYX3(d){ return d.length>=4 && d[0]===0x4E && d[1]===0x59 && d[2]===0x58 && d[3]===0x33; }
  function isChunkedFormat(d){ return isNYX2(d) || isNYX3(d); }

  // HMAC-SHA256 via Web Crypto
  async function hmacSHA256(key, data) {
    const ck = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    return new Uint8Array(await crypto.subtle.sign('HMAC', ck, data));
  }
  async function deriveHMACKey(encKey) {
    return await hmacSHA256(encKey, new TextEncoder().encode('nyxvault-header-auth'));
  }

  // NYX3 decrypt (integrity-verified)
  async function decryptDataNYX3(data, passphrase, onProgress, keyProvider) {
    let offset = 4;
    const salt = data.slice(offset, offset+SALT_BYTES); offset += SALT_BYTES;
    const storedHMAC = data.slice(offset, offset+32); offset += 32;
    const numChunks = (data[offset]<<24)|(data[offset+1]<<16)|(data[offset+2]<<8)|data[offset+3]; offset += 4;
    const key = keyProvider ? await keyProvider(salt) : await deriveKey(passphrase, salt);
    const hmacKey = await deriveHMACKey(key);
    // Verify header HMAC
    const hdr = new Uint8Array(4+SALT_BYTES+4);
    hdr.set(MAGIC3,0); hdr.set(salt,4);
    hdr[4+SALT_BYTES]=(numChunks>>>24)&0xFF; hdr[4+SALT_BYTES+1]=(numChunks>>>16)&0xFF;
    hdr[4+SALT_BYTES+2]=(numChunks>>>8)&0xFF; hdr[4+SALT_BYTES+3]=numChunks&0xFF;
    const expectedHMAC = await hmacSHA256(hmacKey, hdr);
    let hmacOk = true;
    for (let j=0;j<32;j++) if(storedHMAC[j]!==expectedHMAC[j]) hmacOk=false;
    if (!hmacOk) throw new Error('Decryption failed \u2013 wrong passphrase?');
    const chunks = []; let total = 0;
    for (let i=0; i<numChunks; i++) {
      const nonce = data.slice(offset, offset+NONCE_BYTES); offset += NONCE_BYTES;
      const ctLen = (i<numChunks-1) ? CHUNK_PREFIX_BYTES+CHUNK_SIZE+SECRETBOX_OVERHEAD : data.length-offset;
      const ct = data.slice(offset, offset+ctLen); offset += ctLen;
      const dec = nacl.secretbox.open(ct, nonce, key);
      if (!dec) throw new Error('Decryption failed \u2013 wrong passphrase?');
      const idx=(dec[0]<<24)|(dec[1]<<16)|(dec[2]<<8)|dec[3];
      if (idx!==i) throw new Error('Integrity error: chunk order mismatch');
      if (i===numChunks-1 && dec[4]!==1) throw new Error('Integrity error: missing final chunk marker');
      if (i<numChunks-1 && dec[4]!==0) throw new Error('Integrity error: premature final chunk marker');
      const actual = dec.slice(CHUNK_PREFIX_BYTES);
      chunks.push(actual); total += actual.length;
      if (onProgress) onProgress(i+1, numChunks);
    }
    // Explicit truncation guard
    if (offset !== data.length) throw new Error('Integrity error: unexpected trailing data');
    if (chunks.length !== numChunks) throw new Error('Integrity error: chunk count mismatch');
    const result = new Uint8Array(total); let pos = 0;
    for (const c of chunks){ result.set(c, pos); pos += c.length; }
    return result;
  }

  async function decryptData(blob, passphrase, onProgress, keyProvider) {
    if (isNYX3(blob)) return decryptDataNYX3(blob, passphrase, onProgress, keyProvider);
    if (isNYX2(blob)) throw new Error('This file uses the legacy NYX2 format without integrity protection. Ask the uploader to migrate it using: node nyx-migrate.js');
    const salt = blob.slice(0, SALT_BYTES);
    const nonce = blob.slice(SALT_BYTES, SALT_BYTES+NONCE_BYTES);
    const ct = blob.slice(SALT_BYTES+NONCE_BYTES);
    for (const mem of [16384, 65536]) {
      const key = new Uint8Array(await hashwasm.argon2id({
        password: passphrase, salt, parallelism: 1, iterations: 3,
        memorySize: mem, hashLength: 32, outputType: 'binary'
      }));
      const dec = nacl.secretbox.open(ct, nonce, key);
      if (dec) return dec;
    }
    throw new Error('Decryption failed \u2013 wrong passphrase?');
  }
  async function decryptString(b64, passphrase, keyProvider) {
    // Metadata strings use the legacy salt+nonce+ciphertext format (not NYX3).
    const data = nacl.util.decodeBase64(b64);
    const salt = data.slice(0, SALT_BYTES);
    const nonce = data.slice(SALT_BYTES, SALT_BYTES+NONCE_BYTES);
    const ct = data.slice(SALT_BYTES+NONCE_BYTES);
    if (keyProvider) {
      const key = await keyProvider(salt);
      const dec = nacl.secretbox.open(ct, nonce, key);
      if (dec) return nacl.util.encodeUTF8(dec);
      throw new Error('Decryption failed \u2013 wrong passkey?');
    }
    for (const mem of [16384, 65536]) {
      const key = new Uint8Array(await hashwasm.argon2id({
        password: passphrase, salt, parallelism: 1, iterations: 3,
        memorySize: mem, hashLength: 32, outputType: 'binary'
      }));
      const dec = nacl.secretbox.open(ct, nonce, key);
      if (dec) return nacl.util.encodeUTF8(dec);
    }
    throw new Error('Decryption failed \u2013 wrong passphrase?');
  }
  async function fetchWithProgress(url, onProgress) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('Download failed');
    const len = +r.headers.get('Content-Length');
    if (!r.body || !len) return new Uint8Array(await r.arrayBuffer());
    const reader = r.body.getReader(); const chunks = []; let received = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value); received += value.length;
      if (onProgress) onProgress(received, len);
    }
    const out = new Uint8Array(received); let pos = 0;
    for (const c of chunks){ out.set(c, pos); pos += c.length; }
    return out;
  }
  function toast(msg, type) {
    const t = document.createElement('div');
    t.className = 'toast ' + (type||'info'); t.textContent = msg;
    document.getElementById('toast-container').appendChild(t);
    setTimeout(()=>t.remove(), 4000);
  }
  function fmtSize(size){
    const k=1024, s=['B','KB','MB','GB'];
    const i = size>0 ? Math.floor(Math.log(size)/Math.log(k)) : 0;
    return parseFloat((size/Math.pow(k,i)).toFixed(1)) + ' ' + s[i];
  }
  function iconForType(ct, name){
    ct = ct || ''; name = (name||'').toLowerCase();
    if (ct.startsWith('image/')) return '🖼️';
    if (ct.startsWith('video/')) return '🎬';
    if (ct.startsWith('audio/')) return '🎵';
    if (ct === 'application/pdf' || name.endsWith('.pdf')) return '📕';
    if (ct.startsWith('text/') || /\.(txt|md|json|csv|log|xml|js|ts|py|css|html)$/.test(name)) return '📝';
    if (/\.(zip|rar|7z|tar|gz)$/.test(name)) return '🗜️';
    return '📄';
  }
  async function sha256Hex(bytes){
    const buf = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  const token = window.location.pathname.split('/').pop();
  let fileMeta = null;
  let decryptedBlobUrl = null, decryptedFilename = 'file', decryptedContentType = 'application/octet-stream';

  const $ = id => document.getElementById(id);
  function show(id){ $(id).style.display = 'block'; }
  function hide(id){ $(id).style.display = 'none'; }

  // QR code: render the current download URL so it can be opened on a phone.
  let qrRendered = false;
  function renderQR() {
    if (qrRendered) return;
    try {
      const qr = qrcode(0, 'M');
      qr.addData(window.location.href);
      qr.make();
      $('qrCanvas').innerHTML = qr.createSvgTag({ cellSize: 5, margin: 2, scalable: true });
      qrRendered = true;
    } catch (e) {
      $('qrCanvas').textContent = 'Could not render QR code.';
    }
  }
  $('qrToggle').addEventListener('click', () => {
    const panel = $('qrPanel');
    if (panel.style.display === 'none') {
      renderQR();
      panel.style.display = 'block';
      $('qrToggle').textContent = '× Hide QR';
    } else {
      panel.style.display = 'none';
      $('qrToggle').textContent = '▦ Open on phone';
    }
  });

  // Load metadata
  fetch('/api/dl/' + token + '/meta').then(r=>r.json()).then(meta => {
    if (meta.error) {
      hide('loadingState'); show('errorState');
      $('errorMessage').textContent = meta.error; return;
    }
    fileMeta = meta;
    $('dlFileName').textContent = meta.original_name || 'Encrypted File';
    $('dlFileMeta').textContent = fmtSize(meta.size_bytes) + ' · ' + new Date(meta.upload_date).toLocaleDateString();
    if (meta.burn_after_read) { $('burnWarn').style.display = 'flex'; }
    // Passkey-encrypted file: swap the passphrase form for a passkey button.
    if (meta.key_mode === 'passkey') {
      const pf = $('passphraseForm'); if (pf) pf.style.display = 'none';
      const pb = $('passkeyDecryptWrap'); if (pb) pb.style.display = 'block';
      if (!window.NyxPasskey || !window.NyxPasskey.supported()) {
        const pn = $('passkeyNote');
        if (pn) { pn.textContent = '⚠️ Dieser Browser unterstützt keine Passkeys. Öffne den Link in einem Browser/Gerät mit Passkey-Unterstützung.'; pn.style.color = '#ffb4b4'; }
        const btn = $('passkeyDecryptBtn'); if (btn) btn.disabled = true;
      }
    } else {
      const pf = $('passphraseForm'); if (pf) pf.style.display = 'block';
      const pb = $('passkeyDecryptWrap'); if (pb) pb.style.display = 'none';
    }
    hide('loadingState'); show('fileState');
  }).catch(()=>{ hide('loadingState'); show('errorState'); });

  // Shared decrypt routine. Either `passphrase` (passphrase mode) or
  // `keyProvider` (passkey mode: async (salt)=>Uint8Array(32)) is supplied.
  async function runDecrypt(passphrase, keyProvider) {
    $('dlError').style.display = 'none';
    hide('fileState'); show('decryptingState');
    try {
      $('decryptStatus').textContent = 'Downloading encrypted file…';
      $('dlProgress').style.width = '5%';
      const encryptedData = await fetchWithProgress('/api/dl/' + token + '/blob', (rec, total) => {
        $('dlProgress').style.width = Math.round(rec/total*50) + '%';
        $('decryptStatus').textContent = 'Downloading… ' + Math.round(rec/total*100) + '%';
      });
      $('decryptStatus').textContent = 'Deriving key & decrypting…';
      $('dlProgress').style.width = '55%';
      const decrypted = await decryptData(encryptedData, passphrase, (done, total) => {
        $('dlProgress').style.width = (55 + Math.round(done/total*30)) + '%';
        $('decryptStatus').textContent = 'Decrypting chunk ' + done + '/' + total + '…';
      }, keyProvider);
      // Filename + content type
      $('decryptStatus').textContent = 'Finalizing…';
      $('dlProgress').style.width = '92%';
      decryptedFilename = 'decrypted_file';
      if (fileMeta.filename_enc) {
        try { decryptedFilename = await decryptString(fileMeta.filename_enc, passphrase, keyProvider); }
        catch { decryptedFilename = fileMeta.original_name || 'decrypted_file'; }
      }
      decryptedContentType = 'application/octet-stream';
      if (fileMeta.content_type_enc) {
        try { decryptedContentType = await decryptString(fileMeta.content_type_enc, passphrase, keyProvider); } catch {}
      }
      $('dlProgress').style.width = '100%';

      const blob = new Blob([decrypted], { type: decryptedContentType });
      decryptedBlobUrl = URL.createObjectURL(blob);

      // Render result
      hide('decryptingState');
      renderResult(decrypted, decryptedContentType, decryptedFilename);
      show('resultState');
      toast('Decrypted: ' + decryptedFilename, 'success');

      // Burn after reading: now that decryption succeeded, tell the server to destroy it.
      if (fileMeta && fileMeta.burn_after_read) {
        $('burnedBanner').style.display = 'block';
        fetch('/api/dl/' + token + '/burn', { method: 'POST' })
          .then(()=>toast('File destroyed — save it now 🔥', 'info'))
          .catch(()=>{});
      }

      prepareHash(decrypted);
    } catch (err) {
      hide('decryptingState'); show('fileState');
      $('dlError').textContent = err.message; $('dlError').style.display = 'block';
      toast('Decryption failed', 'error');
    }
  }

  // Passphrase form
  $('decryptForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    const passphrase = $('dlPassphrase').value.trim();
    if (!passphrase) return;
    await runDecrypt(passphrase, null);
  });

  // Passkey button: run the WebAuthn PRF ceremony → HKDF per-file key → decrypt.
  const passkeyDecryptBtn = $('passkeyDecryptBtn');
  if (passkeyDecryptBtn) {
    passkeyDecryptBtn.addEventListener('click', async () => {
      if (!window.NyxPasskey || !window.NyxPasskey.supported()) {
        $('dlError').textContent = 'Dieser Browser unterstützt keine Passkeys.';
        $('dlError').style.display = 'block';
        return;
      }
      const prfSalt = fileMeta && fileMeta.prf_salt;
      if (!prfSalt) {
        $('dlError').textContent = 'Für diese Datei fehlt der Passkey-Salt (Server-Konfiguration).';
        $('dlError').style.display = 'block';
        return;
      }
      passkeyDecryptBtn.disabled = true;
      const origText = passkeyDecryptBtn.textContent;
      passkeyDecryptBtn.textContent = 'Warte auf Passkey…';
      try {
        const prfOutput = await window.NyxPasskey.getPRF(prfSalt);
        const keyProvider = (salt) => window.NyxPasskey.deriveKey(prfOutput, salt);
        await runDecrypt(null, keyProvider);
      } catch (err) {
        $('dlError').textContent = err.message || 'Passkey-Entschlüsselung fehlgeschlagen';
        $('dlError').style.display = 'block';
        toast('Passkey fehlgeschlagen', 'error');
      } finally {
        passkeyDecryptBtn.disabled = false;
        passkeyDecryptBtn.textContent = origText;
      }
    });
  }

  // Map file extensions to MIME types (fallback when content-type is octet-stream)
  const EXT_MIME = {
    png:'image/png', jpg:'image/jpeg', jpeg:'image/jpeg', gif:'image/gif', webp:'image/webp',
    svg:'image/svg+xml', bmp:'image/bmp', avif:'image/avif', ico:'image/x-icon',
    mp4:'video/mp4', webm:'video/webm', mov:'video/quicktime', mkv:'video/x-matroska', m4v:'video/mp4',
    mp3:'audio/mpeg', wav:'audio/wav', ogg:'audio/ogg', m4a:'audio/mp4', flac:'audio/flac', aac:'audio/aac',
    pdf:'application/pdf'
  };
  function effectiveType(ct, name) {
    // If server gave a real, specific type, trust it
    if (ct && ct !== 'application/octet-stream' && ct !== '') return ct;
    const ext = (name.split('.').pop() || '').toLowerCase();
    return EXT_MIME[ext] || ct || 'application/octet-stream';
  }

  function renderResult(bytes, ctRaw, name) {
    const lname = name.toLowerCase();
    const ct = effectiveType(ctRaw, name);
    $('resultName').textContent = name;
    $('resultMeta').textContent = fmtSize(bytes.length) + ' · ' + (ct || 'unknown type');

    // Rebuild blob URL with the effective type so previews/players work
    if (ct && ct !== decryptedContentType) {
      try {
        URL.revokeObjectURL(decryptedBlobUrl);
        decryptedBlobUrl = URL.createObjectURL(new Blob([bytes], { type: ct }));
      } catch {}
    }

    if (ct.startsWith('image/')) {
      $('previewImgEl').src = decryptedBlobUrl; show('previewImage');
    } else if (ct.startsWith('video/')) {
      $('previewVideoEl').src = decryptedBlobUrl; show('previewVideo');
    } else if (ct.startsWith('audio/')) {
      $('previewAudioEl').src = decryptedBlobUrl; show('previewAudio');
    } else if (ct === 'application/pdf' || lname.endsWith('.pdf')) {
      $('previewPdfEl').src = decryptedBlobUrl; show('previewPdf');
    } else if (ct.startsWith('text/') || /\.(txt|md|json|csv|log|xml|js|ts|py|css|html|yml|yaml|ini|conf)$/.test(lname)) {
      try {
        let txt = new TextDecoder().decode(bytes);
        if (txt.length > 20000) txt = txt.slice(0, 20000) + '\n\n… (truncated, download for full file)';
        $('previewTextEl').textContent = txt; show('previewText');
      } catch { showNoPreview(ct, name); }
    } else {
      showNoPreview(ct, name);
    }
  }
  function showNoPreview(ct, name){
    show('previewNone');
  }

  // Download button
  $('downloadBtn').addEventListener('click', () => {
    const a = document.createElement('a');
    a.href = decryptedBlobUrl; a.download = decryptedFilename;
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
    toast('Saving ' + decryptedFilename, 'info');
  });

  // VirusTotal
  // Compute + display the hash locally (no network). Wire up Copy + opt-in Scan.
  let currentHash = null;
  async function prepareHash(bytes) {
    currentHash = await sha256Hex(bytes);
    $('hashLine').textContent = 'SHA-256: ' + currentHash;
    $('copyHashBtn').onclick = () => {
      navigator.clipboard.writeText(currentHash).then(()=>toast('Hash copied', 'success'));
    };
    const btn = $('vtScanBtn');
    if (btn) btn.onclick = () => runVirusTotal();
  }

  async function runVirusTotal() {
    if (!currentHash) return;
    const statusEl = $('vtStatus'), bodyEl = $('vtBody'), box = $('vtBox');
    statusEl.textContent = 'checking…';
    statusEl.className = 'dl-vt-status neutral';
    bodyEl.innerHTML = '<span class="spinner small"></span> Looking up file hash…';
    try {
      const r = await fetch('/api/vt/' + currentHash);
      const data = await r.json();

      if (data.disabled) {
        statusEl.textContent = 'off';
        statusEl.className = 'dl-vt-status neutral';
        bodyEl.innerHTML = 'VirusTotal scan is not configured on this server.';
        return;
      }
      if (data.not_found) {
        statusEl.textContent = 'unknown';
        statusEl.className = 'dl-vt-status neutral';
        bodyEl.innerHTML = 'This file is not in the VirusTotal database (never scanned before). The hash was checked — the file itself was never uploaded.';
        return;
      }
      if (data.error) {
        statusEl.textContent = 'error';
        statusEl.className = 'dl-vt-status neutral';
        bodyEl.textContent = data.error;
        return;
      }
      const mal = data.malicious || 0, susp = data.suspicious || 0;
      const total = data.total || 0, harmless = data.harmless || 0;
      if (mal > 0 || susp > 0) {
        box.classList.add('danger');
        statusEl.textContent = '⚠️ ' + (mal+susp) + ' flagged';
        statusEl.className = 'dl-vt-status danger';
        bodyEl.innerHTML = '<strong>' + mal + '</strong> engines flagged this as malicious, <strong>' + susp + '</strong> as suspicious (of ' + total + '). Be careful before opening this file.';
      } else {
        box.classList.add('clean');
        statusEl.textContent = '✓ clean';
        statusEl.className = 'dl-vt-status clean';
        bodyEl.innerHTML = '<strong>' + harmless + '/' + total + '</strong> security engines report this file as clean. ✅';
      }
      if (data.permalink) {
        bodyEl.innerHTML += ' <a href="' + data.permalink + '" target="_blank" rel="noopener" class="dl-vt-link">Full report →</a>';
      }
    } catch (err) {
      $('vtStatus').textContent = 'error';
      $('vtStatus').className = 'dl-vt-status neutral';
      $('vtBody').textContent = 'Could not reach VirusTotal.';
    }
  }
