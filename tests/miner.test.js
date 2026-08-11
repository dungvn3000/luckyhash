/**
 * Unit tests for LuckyHash miner.
 *
 * Covers the pure mining math of miner.js + worker.js:
 *   - SHA-256/SHA-256d vs Node crypto + known vectors
 *   - sha256Midstate (GPU midstate optimization)
 *   - merkle root, header76 layout, diff → target
 *   - the little-endian share comparison (the pool-compat fix)
 *   - the WGSL shader's dataflow (input layout replica)
 *
 * Real-world fixture: Bitcoin GENESIS BLOCK (known header + hash).
 *
 * Run:  node --test tests/
 */
'use strict';

const { test } = require('node:test');
const assert   = require('node:assert/strict');
const crypto   = require('node:crypto');
const fs       = require('fs');
const path     = require('path');

const ROOT = path.join(__dirname, '..');

// ─── Load production sources with browser stubs ──────────────────────────────
// miner.js ends with browser bootstrap (window/document/navigator) — stub
// them, run the whole file, and pull out the pure functions to test.
function loadMiner() {
  const src = fs.readFileSync(path.join(ROOT, 'miner.js'), 'utf8');
  const windowStub   = {};
  const documentStub = { addEventListener() {}, getElementById() { return null; } };
  const navigatorStub = { hardwareConcurrency: 8 };
  const factory = new Function('window', 'document', 'navigator', src + `
    return { hexToBytes, bytesToHex, reverseHex, sha256, sha256d, sha256Midstate,
             buildMerkleRoot, buildHeader76, diffToTarget, targetToU32,
             sha256dBuf, fmtHS, fmtUptime, hashToDiff, fmtDiff,
             MIN_SHARE_DIFF, SHA256_WGSL };
  `);
  return factory(windowStub, documentStub, navigatorStub);
}

function loadWorker() {
  const src = fs.readFileSync(path.join(ROOT, 'worker.js'), 'utf8');
  const selfStub = { onmessage: null, posted: [], postMessage(m) { this.posted.push(m); } };
  const factory = new Function('self', src + `
    return { mineBatch, sha256, sha256d, bswap32 };
  `);
  return factory(selfStub);
}

const M = loadMiner();
const W = loadWorker();

// ─── Helpers for this suite ──────────────────────────────────────────────────
const cSha256  = (b) => crypto.createHash('sha256').update(b).digest();
const cSha256d = (b) => cSha256(cSha256(b));
const hex      = (buf) => Buffer.from(buf).toString('hex');
const DIFF1    = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');

function bswap32(x) {
  return ((x << 24) | ((x << 8) & 0x00FF0000) | ((x >>> 8) & 0x0000FF00) | (x >>> 24)) >>> 0;
}
const SHA_K_T = (() => {
  const Ksrc = fs.readFileSync(path.join(ROOT, 'miner.js'), 'utf8')
    .match(/const SHA_K = new Uint32Array\(\[[\s\S]*?\]\);/)[0];
  return new Function(Ksrc + '\nreturn SHA_K;')();
})();
/** Compress exactly one 64-byte block with an explicit 8-word IV. */
function compressBlock(block64, iv) {
  const dv = new DataView(block64.buffer, block64.byteOffset, 64);
  const w = new Uint32Array(64);
  for (let i = 0; i < 16; i++) w[i] = dv.getUint32(i * 4, false);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  const SHA_K = SHA_K_T;
  for (let i = 16; i < 64; i++) {
    const s0 = rotr(w[i-15],7) ^ rotr(w[i-15],18) ^ (w[i-15]>>>3);
    const s1 = rotr(w[i-2],17) ^ rotr(w[i-2],19) ^ (w[i-2]>>>10);
    w[i] = (w[i-16] + s0 + w[i-7] + s1) >>> 0;
  }
  let [a,b,c,d,e,f,g,h] = iv;
  for (let i = 0; i < 64; i++) {
    const S1 = rotr(e,6)^rotr(e,11)^rotr(e,25);
    const ch = (e&f)^(~e&g);
    const t1 = (h+S1+ch+SHA_K[i]+w[i])>>>0;
    const S0 = rotr(a,2)^rotr(a,13)^rotr(a,22);
    const maj = (a&b)^(a&c)^(b&c);
    const t2 = (S0+maj)>>>0;
    h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [(a+iv[0])>>>0,(b+iv[1])>>>0,(c+iv[2])>>>0,(d+iv[3])>>>0,
   (e+iv[4])>>>0,(f+iv[5])>>>0,(g+iv[6])>>>0,(h+iv[7])>>>0]
    .forEach((v,i) => odv.setUint32(i*4,v,false));
  return out;
}
const IV_WORDS = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];

// ─── Genesis block fixture (byte-exact, hash is public knowledge) ───────────
const GENESIS = {
  version: 1,
  prevHash: '0'.repeat(64),
  // internal byte order of the (single-tx) merkle root
  merkleRoot: '3ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a',
  nTime:  1231006505,
  nBits:  0x1d00ffff,
  nonce:  2083236893,
  displayHash: '000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f',
  coinbase:
    '01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff' +
    '4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72' +
    '206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73' +
    'ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a679' +
    '62e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac' +
    '00000000',
};
function genesisHeader80() {
  const h = new Uint8Array(80);
  const dv = new DataView(h.buffer);
  dv.setUint32(0, GENESIS.version, true);
  h.set(M.hexToBytes(GENESIS.prevHash), 4);
  h.set(M.hexToBytes(GENESIS.merkleRoot), 36);
  dv.setUint32(68, GENESIS.nTime, true);
  dv.setUint32(72, GENESIS.nBits, true);
  dv.setUint32(76, GENESIS.nonce, true);
  return h;
}

// ═══ 1. SHA-256 core ═══════════════════════════════════════════════════════
test('sha256 matches Node crypto on random inputs and known vector', () => {
  assert.equal(hex(M.sha256(new Uint8Array(0))),
    'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  assert.equal(hex(M.sha256(new TextEncoder().encode('abc'))),
    'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  for (let i = 0; i < 100; i++) {
    const data = crypto.randomBytes(1 + Math.floor(Math.random() * 256));
    assert.equal(hex(M.sha256(data)), cSha256(data).toString('hex'));
    assert.equal(hex(M.sha256d(data)), cSha256d(data).toString('hex'));
  }
});

test('worker.js sha256d matches miner.js / crypto', () => {
  for (let i = 0; i < 20; i++) {
    const data = crypto.randomBytes(80);
    const ref  = cSha256d(data).toString('hex');
    const wd   = W.sha256d(data); // Uint32Array(8) of big-endian state words
    const out  = new Uint8Array(32);
    const odv  = new DataView(out.buffer);
    for (let j = 0; j < 8; j++) odv.setUint32(j * 4, wd[j], false);
    assert.equal(hex(out), ref);
    assert.equal(hex(M.sha256d(data)), ref);
  }
});

// ═══ 2. sha256Midstate (GPU optimization) ══════════════════════════════════
test('sha256Midstate: midstate + block2 === full sha256 (random headers)', () => {
  for (let i = 0; i < 200; i++) {
    const hdr = crypto.randomBytes(80);
    // reference
    const ref = cSha256(hdr);
    // midstate path: block1 → mid; block2 = tail16 + 0x80 … + 640-bit length
    const mid = M.sha256Midstate(hdr.subarray(0, 64));
    assert.ok(mid instanceof Uint32Array && mid.length === 8);
    const b2 = new Uint8Array(64);
    b2.set(hdr.subarray(64, 80), 0);
    b2[16] = 0x80;
    new DataView(b2.buffer).setUint32(60, 640, false);
    assert.deepEqual(hex(compressBlock(b2, mid)), ref.toString('hex'));
  }
});

// ═══ 3. Merkle root ════════════════════════════════════════════════════════
test('buildMerkleRoot: genesis coinbase (no branches) → internal merkle root', () => {
  const job = { coinb1: GENESIS.coinbase, coinb2: '', merkleBranch: [] };
  assert.equal(M.buildMerkleRoot(job, '', ''), GENESIS.merkleRoot);
});

test('buildMerkleRoot with branches matches independent folding', () => {
  for (let t = 0; t < 20; t++) {
    const branches = Array.from({ length: 1 + Math.floor(Math.random() * 12) },
      () => crypto.randomBytes(32).toString('hex'));
    const job = {
      coinb1: crypto.randomBytes(40).toString('hex'),
      coinb2: crypto.randomBytes(40).toString('hex'),
      merkleBranch: branches,
    };
    const en1 = crypto.randomBytes(4).toString('hex');
    const en2 = crypto.randomBytes(8).toString('hex');
    let h = cSha256d(Buffer.from(job.coinb1 + en1 + en2 + job.coinb2, 'hex'));
    for (const b of branches) h = cSha256d(Buffer.concat([h, Buffer.from(b, 'hex')]));
    assert.equal(M.buildMerkleRoot(job, en1, en2), h.toString('hex'));
  }
});

// ═══ 4. Header layout (buildHeader76) ══════════════════════════════════════
test('buildHeader76: field offsets and little-endian encoding (genesis)', () => {
  const job = {
    version: GENESIS.version, nTime: GENESIS.nTime, nBits: GENESIS.nBits,
    prevHash: GENESIS.prevHash, merkleRoot: GENESIS.merkleRoot,
  };
  const h76 = M.buildHeader76(job);
  assert.equal(h76.length, 76);
  const full = new Uint8Array(80);
  full.set(h76, 0);
  new DataView(full.buffer).setUint32(76, GENESIS.nonce, true);
  const fh = hex(full);
  assert.equal(fh.slice(0, 8),       '01000000');          // version LE (bytes 0-3)
  assert.equal(fh.slice(8, 72),      '0'.repeat(64));      // prevhash (bytes 4-35)
  assert.equal(fh.slice(72, 136),    GENESIS.merkleRoot);  // merkle (bytes 36-67)
  assert.equal(fh.slice(136, 144),   '29ab5f49');          // nTime LE (bytes 68-71)
  assert.equal(fh.slice(144, 152),   'ffff001d');          // nBits LE (bytes 72-75)
  assert.equal(fh.slice(152, 160),   '1dac2b7c');          // nonce LE (bytes 76-79)
});

test('genesis header → known block hash (full sha256d + display convention)', () => {
  const digest = M.sha256d(genesisHeader80());
  assert.equal(M.reverseHex(hex(digest)), GENESIS.displayHash);
});

// ═══ 5. diff → target ══════════════════════════════════════════════════════
test('diffToTarget: diff=1 → diff1 target; fractional; monotonic', () => {
  assert.equal(hex(M.diffToTarget(1)), DIFF1.toString(16).padStart(64, '0'));
  const t1000   = BigInt('0x' + hex(M.diffToTarget(1000)));
  const t1      = BigInt('0x' + hex(M.diffToTarget(1)));
  const tFract  = BigInt('0x' + hex(M.diffToTarget(0.001)));
  assert.ok(t1000 < t1, 'higher diff → smaller target');
  assert.ok(tFract > t1, 'fractional diff → larger target');
  // integer math: diff1 * 1e6 / round(diff*1e6) (floored)
  const expect = DIFF1 * 1_000_000n / 1000n;
  assert.equal(BigInt('0x' + hex(M.diffToTarget(0.001))), expect);
});

test('targetToU32 gives big-endian words', () => {
  const t = M.diffToTarget(1);
  const w = M.targetToU32(t);
  const tBE = BigInt('0x' + hex(t));
  for (let i = 0; i < 8; i++) {
    const shift = BigInt((7 - i) * 32);
    assert.equal(w[i], Number((tBE >> shift) & 0xFFFFFFFFn));
  }
});

// ═══ 6. THE LITTLE-ENDIAN SHARE COMPARISON (pool-compat fix) ═══════════════
test('worker mineBatch: finds genesis nonce under diff=1 target (LE check)', () => {
  const job = {
    version: GENESIS.version, nTime: GENESIS.nTime, nBits: GENESIS.nBits,
    prevHash: GENESIS.prevHash, merkleRoot: GENESIS.merkleRoot,
  };
  const h76 = M.buildHeader76(job);
  const tgt = M.targetToU32(M.diffToTarget(1));     // LE(genesisHash) < diff1
  const res = W.mineBatch(h76, tgt, GENESIS.nonce - 1000, 2001);
  assert.deepEqual(res.nonces, [GENESIS.nonce]);
  assert.equal(res.hashes, 2001);
});

test('worker mineBatch: LE semantics — boundary at the hash\'s true difficulty', () => {
  // Genesis hash LE value = diff1 / 2536.43… → passes diff=2000, fails diff=3000
  const job = {
    version: GENESIS.version, nTime: GENESIS.nTime, nBits: GENESIS.nBits,
    prevHash: GENESIS.prevHash, merkleRoot: GENESIS.merkleRoot,
  };
  const h76 = M.buildHeader76(job);
  const pass = W.mineBatch(h76, M.targetToU32(M.diffToTarget(2000)), GENESIS.nonce - 1000, 2001);
  assert.deepEqual(pass.nonces, [GENESIS.nonce]);
  const fail = W.mineBatch(h76, M.targetToU32(M.diffToTarget(3000)), GENESIS.nonce - 1000, 2001);
  assert.deepEqual(fail.nonces, []);
});

test('worker bswap32 byte swap', () => {
  assert.equal(W.bswap32(0x00871a81), 0x811a8700);
  assert.equal(W.bswap32(0xdeadbeef), 0xefbeadde);
  assert.equal(W.bswap32(0), 0);
});

// ═══ 7. WGSL shader dataflow (input layout + math replica) ════════════════
test('WGSL: shader source uses midstate load + LE compare + atomic pre-filter', () => {
  assert.match(M.SHA256_WGSL, /s1\[i\] = inp\[30u \+ i\]/,    'midstate from inp[30..37]');
  assert.match(M.SHA256_WGSL, /bswap32\(s2\[7u - i\]\)/,      'little-endian target compare');
  assert.match(M.SHA256_WGSL, /atomicLoad\(&out_buf\[5\]\)/,  'atomicMin pre-filter');
  assert.match(M.SHA256_WGSL, /workgroup_size\(256\)/);
});

test('WGSL dataflow replica: runBatch input layout reproduces crypto sha256d', () => {
  // Build the exact input buffer GPUEngine.runBatch would send
  const hdr80 = genesisHeader80();
  const target = M.diffToTarget(1);
  const mid    = M.sha256Midstate(hdr80.slice(0, 64));
  const data = new Uint32Array(38);
  {
    const hdv = new DataView(hdr80.buffer, hdr80.byteOffset, 80);
    for (let i = 0; i < 20; i++) data[i] = hdv.getUint32(i * 4, false);
    const tdv = new DataView(target.buffer, target.byteOffset, 32);
    for (let i = 0; i < 8;  i++) data[20+i] = tdv.getUint32(i * 4, false);
    data[28] = GENESIS.nonce >>> 0;
    data[29] = 1;
    data.set(mid, 30);
  }
  // Simulate one shader thread (gid.x=0) following the WGSL steps
  const nonce_le = bswap32(data[28]);
  // pass1 block2: w2 = [inp16, inp17, inp18, nonce_le, 0x80000000 …, 640]
  const b2 = new Uint8Array(64);
  const b2dv = new DataView(b2.buffer);
  b2dv.setUint32(0,  data[16], false);
  b2dv.setUint32(4,  data[17], false);
  b2dv.setUint32(8,  data[18], false);
  b2dv.setUint32(12, nonce_le, false);
  b2[16] = 0x80;
  b2dv.setUint32(60, 640, false);
  const s1d = compressBlock(b2, Array.from(data.slice(30, 38)));
  // pass2: w3 = [s1d words, 0x80000000 …, 256]
  const b3 = new Uint8Array(64);
  b3.set(s1d, 0);
  b3[32] = 0x80;
  new DataView(b3.buffer).setUint32(60, 256, false);
  const digest = compressBlock(b3, IV_WORDS);
  // identical to crypto sha256d of the full header
  assert.equal(hex(digest), cSha256d(hdr80).toString('hex'));
  // …and its LE value is below the diff=1 target (share is valid)
  const leVal = BigInt('0x' + M.reverseHex(hex(digest)));
  assert.ok(leVal < DIFF1);
  // LE compare loop, word by word, as the shader does
  const dv = new DataView(digest.buffer);
  let below = false;
  for (let i = 0; i < 8; i++) {
    const hw = bswap32(dv.getUint32((7 - i) * 4, false));
    if (hw < data[20 + i]) { below = true;  break; }
    if (hw > data[20 + i]) { below = false; break; }
    if (i === 7) below = true;
  }
  assert.ok(below, 'shader LE compare marks genesis nonce as a share');
});

// ═══ 8. Small helpers / settings ═══════════════════════════════════════════
test('hex/bytes helpers round-trip', () => {
  const h = '0123456789abcdef';
  assert.equal(M.bytesToHex(M.hexToBytes(h)), h);
  assert.equal(M.reverseHex('aabbccdd'), 'ddccbbaa');
  assert.deepEqual(Array.from(M.hexToBytes('')), []);
  assert.deepEqual(Array.from(M.hexToBytes('abc')), []); // odd length → empty
});

test('hashToDiff ≈ 2536 for the genesis block', () => {
  const d = M.hashToDiff(GENESIS.displayHash);
  assert.ok(d > 2500 && d < 2600, `expected ~2536, got ${d}`);
});

test('fmtHS / fmtUptime / fmtDiff basics', () => {
  assert.equal(M.fmtHS(0), '0 H/s');
  assert.equal(M.fmtHS(2500), '2.50 KH/s');
  assert.equal(M.fmtHS(3.5e9), '3.50 GH/s');
  assert.equal(M.fmtUptime(3661), '01:01:01');
  assert.equal(M.fmtUptime(0), '00:00:00');
  assert.equal(M.fmtDiff(0), '—');
  assert.equal(M.fmtDiff(1.23e12), '1.23 T');
});

test('MIN_SHARE_DIFF floor is 100 (anti pool-spam)', () => {
  assert.equal(M.MIN_SHARE_DIFF, 100);
});
