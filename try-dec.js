const nacl = require('tweetnacl');
const { argon2id } = require('hash-wasm');
const crypto = require('crypto');
const fs = require('fs');
const data = fs.readFileSync('/tmp/checkout.har.enc');
const SALT_BYTES=16;
async function tryOne(pass, mem) {
  let off=4;
  const salt=new Uint8Array(data.slice(off,off+SALT_BYTES)); off+=SALT_BYTES;
  const storedHMAC=data.slice(off,off+32); off+=32;
  const numChunks=data.readUInt32BE(off);
  const key=await argon2id({password:pass,salt,parallelism:1,iterations:3,memorySize:mem,hashLength:32,outputType:'binary'});
  const hmacSub=crypto.createHmac('sha256',Buffer.from(key)).update('nyxvault-header-auth').digest();
  const hdr=Buffer.alloc(4+SALT_BYTES+4);
  Buffer.from('NYX3').copy(hdr,0); Buffer.from(salt).copy(hdr,4); hdr.writeUInt32BE(numChunks,20);
  const exp=crypto.createHmac('sha256',hmacSub).update(hdr).digest();
  return crypto.timingSafeEqual(storedHMAC,exp);
}
(async()=>{
  const variants=['KosmischerLobster!2026','KosmischerLobster!2026 ',' KosmischerLobster!2026','KosmischerLobster!2026\n','kosmischerLobster!2026','KosmischerLobster!2026.','KosmischerLobster2026!','changeme'];
  for (const mem of [16384,65536]) {
    for (const p of variants) {
      const ok=await tryOne(p,mem);
      console.log(mem, JSON.stringify(p), ok?'✅ MATCH':'no');
      if(ok) process.exit(0);
    }
  }
  console.log('none matched');
})();
