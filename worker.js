/**
 * worker.js – CPU SHA256d mining worker (runs in Web Worker thread)
 * Each worker independently mines a nonce range and reports back.
 */

// ─── SHA-256 constants ────────────────────────────────────────────────────
const K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const W = new Uint32Array(64);

function rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function bswap32(x) {
  return ((x << 24) | ((x << 8) & 0x00FF0000) | ((x >>> 8) & 0x0000FF00) | (x >>> 24)) >>> 0;
}

/**
 * SHA-256 hash of arbitrary bytes → Uint32Array(8) in big-endian
 * Optimized: reuses W array, avoids allocations in hot path.
 */
function sha256(data) {
  const len    = data.length;
  const bitLen = len * 8;
  const blocks = Math.ceil((len + 9) / 64);
  const padLen = blocks * 64;
  const padded = new Uint8Array(padLen);
  padded.set(data);
  padded[len] = 0x80;
  // big-endian bit-length at end
  const dv = new DataView(padded.buffer);
  dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
  dv.setUint32(padLen - 4, bitLen >>> 0, false);

  let h0=0x6a09e667, h1=0xbb67ae85, h2=0x3c6ef372, h3=0xa54ff53a;
  let h4=0x510e527f, h5=0x9b05688c, h6=0x1f83d9ab, h7=0x5be0cd19;

  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4, false);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i-15],7)  ^ rotr(W[i-15],18) ^ (W[i-15]>>>3);
      const s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >>>10);
      W[i] = (W[i-16] + s0 + W[i-7] + s1) >>> 0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i = 0; i < 64; i++) {
      const S1   = rotr(e,6)  ^ rotr(e,11)  ^ rotr(e,25);
      const ch   = (e & f) ^ (~e & g);
      const t1   = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0   = rotr(a,2)  ^ rotr(a,13)  ^ rotr(a,22);
      const maj  = (a & b) ^ (a & c) ^ (b & c);
      const t2   = (S0 + maj) >>> 0;
      h=g; g=f; f=e; e=(d+t1)>>>0;
      d=c; c=b; b=a; a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0; h1=(h1+b)>>>0; h2=(h2+c)>>>0; h3=(h3+d)>>>0;
    h4=(h4+e)>>>0; h5=(h5+f)>>>0; h6=(h6+g)>>>0; h7=(h7+h)>>>0;
  }
  return new Uint32Array([h0,h1,h2,h3,h4,h5,h6,h7]);
}

function sha256d(data) {
  const first  = sha256(data);
  const bytes  = new Uint8Array(32);
  const dv     = new DataView(bytes.buffer);
  for (let i = 0; i < 8; i++) dv.setUint32(i*4, first[i], false);
  return sha256(bytes);
}

// ─── Hot mining loop ──────────────────────────────────────────────────────

/**
 * Compress one 64-byte block already loaded into W[0..15], starting from
 * state s (Uint32Array(8), mutated in place). Message schedule + 64 rounds.
 */
function compressW(s) {
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(W[i-15],7)  ^ rotr(W[i-15],18) ^ (W[i-15]>>>3);
    const s1 = rotr(W[i-2], 17) ^ rotr(W[i-2], 19) ^ (W[i-2] >>>10);
    W[i] = (W[i-16] + s0 + W[i-7] + s1) >>> 0;
  }
  let a=s[0],b=s[1],c=s[2],d=s[3],e=s[4],f=s[5],g=s[6],h=s[7];
  for (let i = 0; i < 64; i++) {
    const S1  = rotr(e,6)  ^ rotr(e,11)  ^ rotr(e,25);
    const ch  = (e & f) ^ (~e & g);
    const t1  = (h + S1 + ch + K[i] + W[i]) >>> 0;
    const S0  = rotr(a,2)  ^ rotr(a,13)  ^ rotr(a,22);
    const maj = (a & b) ^ (a & c) ^ (b & c);
    const t2  = (S0 + maj) >>> 0;
    h=g; g=f; f=e; e=(d+t1)>>>0;
    d=c; c=b; b=a; a=(t1+t2)>>>0;
  }
  s[0]=(s[0]+a)>>>0; s[1]=(s[1]+b)>>>0; s[2]=(s[2]+c)>>>0; s[3]=(s[3]+d)>>>0;
  s[4]=(s[4]+e)>>>0; s[5]=(s[5]+f)>>>0; s[6]=(s[6]+g)>>>0; s[7]=(s[7]+h)>>>0;
}

// Preallocated state buffers for the hot loop (no per-nonce allocation)
const _mid = new Uint32Array(8); // midstate after header block 1
const _s1  = new Uint32Array(8); // pass-1 running state
const _s2  = new Uint32Array(8); // pass-2 running state
const IV = new Uint32Array([
  0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
  0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19,
]);

/**
 * Mine a batch of nonces — midstate-optimized SHA256d:
 *   • Header bytes 0-63 are nonce-independent → compress ONCE into _mid,
 *     then each nonce only compresses block 2 + the 32-byte pass-2 block
 *     (2 compressions instead of 3 → ~33% less work than the generic path).
 *   • All buffers preallocated; zero allocation per nonce.
 * @param {Uint8Array} header76  - First 76 bytes of block header (no nonce)
 * @param {Uint32Array} target   - 8 u32 big-endian target
 * @param {number} nonceStart
 * @param {number} batchSize
 * @returns {{ nonces: number[], hashes: number }}
 */
function mineBatch(header76, target, nonceStart, batchSize) {
  const hdv = new DataView(header76.buffer, header76.byteOffset, 76);
  const nonces = [];

  // Midstate: compress header block 1 (bytes 0-63) once for the whole batch
  _mid.set(IV);
  for (let i = 0; i < 16; i++) W[i] = hdv.getUint32(i * 4, false);
  compressW(_mid);

  // Header tail (bytes 64-75) — constant words of block 2
  const t0 = hdv.getUint32(64, false);
  const t1 = hdv.getUint32(68, false);
  const t2 = hdv.getUint32(72, false);

  for (let i = 0; i < batchSize; i++) {
    const nonce = (nonceStart + i) >>> 0;

    // Pass 1, block 2: tail + nonce (LE bytes = bswap of the u32) + padding
    _s1.set(_mid);
    W[0] = t0; W[1] = t1; W[2] = t2;
    W[3] = bswap32(nonce);
    W[4] = 0x80000000;
    W[5]=0; W[6]=0; W[7]=0; W[8]=0; W[9]=0; W[10]=0;
    W[11]=0; W[12]=0; W[13]=0; W[14]=0;
    W[15] = 640; // 80 * 8 bits
    compressW(_s1);

    // Pass 2: hash the 32-byte digest
    _s2.set(IV);
    W[0]=_s1[0]; W[1]=_s1[1]; W[2]=_s1[2]; W[3]=_s1[3];
    W[4]=_s1[4]; W[5]=_s1[5]; W[6]=_s1[6]; W[7]=_s1[7];
    W[8] = 0x80000000;
    W[9]=0; W[10]=0; W[11]=0; W[12]=0; W[13]=0; W[14]=0;
    W[15] = 256; // 32 * 8 bits
    compressW(_s2);

    // Bitcoin compares the digest as a LITTLE-ENDIAN uint256: the most
    // significant word is _s2[7] (trailing digest bytes), byte-swapped to
    // match the target's big-endian words. A big-endian compare finds
    // "leading-zero" hashes the pool rejects as "Above target".
    let valid = false;
    for (let j = 0; j < 8; j++) {
      const h = bswap32(_s2[7 - j]);
      if (h < target[j]) { valid = true; break; }
      if (h > target[j]) { valid = false; break; }
      if (j === 7) valid = true; // all equal
    }
    // Keep scanning after a hit: a batch can contain several shares, and the
    // next batch skips ahead — returning early would leave a coverage gap
    if (valid) nonces.push(nonce);
  }
  return { nonces, hashes: batchSize };
}

// ─── Worker message handler ───────────────────────────────────────────────

self.onmessage = function(e) {
  const { header76, target, nonceStart, batchSize } = e.data;
  const h76 = new Uint8Array(header76);
  const tgt = new Uint32Array(target);
  const result = mineBatch(h76, tgt, nonceStart, batchSize);
  self.postMessage(result);
};
