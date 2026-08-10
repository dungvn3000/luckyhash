/**
 * miner.js – LuckyHash Solo BTC Miner
 *   • Primary:  WebGPU compute shader (SHA256d on GPU, millions of hashes/sec)
 *   • Fallback: CPU Web Workers (SHA256d in multiple threads)
 *
 * Protocol: Stratum JSON-RPC over WebSocket → luckyhash_proxy
 *
 * Bitcoin block header (80 bytes):
 *   version      4 bytes  LE
 *   prev_hash   32 bytes  LE (per stratum byte-swap)
 *   merkle_root 32 bytes  LE (computed from coinbase + branches)
 *   time         4 bytes  LE
 *   bits         4 bytes  LE
 *   nonce        4 bytes  LE  ← iterated by GPU/CPU
 */

'use strict';

// ═══════════════════════════════════════════════════════════════
// Utilities
// ═══════════════════════════════════════════════════════════════

function hexToBytes(hex) {
  if (!hex || hex.length % 2) return new Uint8Array(0);
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2)
    out[i >> 1] = parseInt(hex.slice(i, i + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function reverseHex(hex) {
  return hex.match(/../g).reverse().join('');
}

// ═══════════════════════════════════════════════════════════════
// CPU SHA-256 (used for Merkle root; workers handle mining hot path)
// ═══════════════════════════════════════════════════════════════

const SHA_K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
  0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
  0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
  0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
  0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
  0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
  0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
  0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
  0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
]);

function _rotr(x, n) { return (x >>> n) | (x << (32 - n)); }

function sha256(data) {
  const len    = data.length;
  const bitLen = len * 8;
  const padded = new Uint8Array(Math.ceil((len + 9) / 64) * 64);
  padded.set(data);
  padded[len] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setUint32(padded.length - 8, Math.floor(bitLen / 2 ** 32), false);
  dv.setUint32(padded.length - 4, bitLen >>> 0, false);
  let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a;
  let h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
  const w = new Uint32Array(64);
  for (let off = 0; off < padded.length; off += 64) {
    for (let i=0;i<16;i++) w[i] = dv.getUint32(off+i*4,false);
    for (let i=16;i<64;i++) {
      const s0=_rotr(w[i-15],7)^_rotr(w[i-15],18)^(w[i-15]>>>3);
      const s1=_rotr(w[i-2],17)^_rotr(w[i-2], 19)^(w[i-2] >>>10);
      w[i]=(w[i-16]+s0+w[i-7]+s1)>>>0;
    }
    let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
    for (let i=0;i<64;i++) {
      const S1=((_rotr(e,6)^_rotr(e,11)^_rotr(e,25)));
      const ch=(e&f)^(~e&g);
      const t1=(h+S1+ch+SHA_K[i]+w[i])>>>0;
      const S0=((_rotr(a,2)^_rotr(a,13)^_rotr(a,22)));
      const maj=(a&b)^(a&c)^(b&c);
      const t2=(S0+maj)>>>0;
      h=g;g=f;f=e;e=(d+t1)>>>0;d=c;c=b;b=a;a=(t1+t2)>>>0;
    }
    h0=(h0+a)>>>0;h1=(h1+b)>>>0;h2=(h2+c)>>>0;h3=(h3+d)>>>0;
    h4=(h4+e)>>>0;h5=(h5+f)>>>0;h6=(h6+g)>>>0;h7=(h7+h)>>>0;
  }
  const out = new Uint8Array(32);
  const odv = new DataView(out.buffer);
  [h0,h1,h2,h3,h4,h5,h6,h7].forEach((v,i) => odv.setUint32(i*4,v,false));
  return out;
}

function sha256d(data) { return sha256(sha256(data)); }

// ═══════════════════════════════════════════════════════════════
// Bitcoin helpers
// ═══════════════════════════════════════════════════════════════

function buildMerkleRoot(job, en1, en2) {
  const coinbase = job.coinb1 + en1 + en2 + job.coinb2;
  let hash = sha256d(hexToBytes(coinbase));
  for (const branch of job.merkleBranch) {
    const combined = new Uint8Array(64);
    combined.set(hash, 0);
    combined.set(hexToBytes(branch), 32);
    hash = sha256d(combined);
  }
  return bytesToHex(hash);
}

/** 76-byte header prefix (no nonce) — nonce is appended during mining */
function buildHeader76(job) {
  const buf = new Uint8Array(76);
  const dv  = new DataView(buf.buffer);
  dv.setUint32(0,  job.version, true);
  buf.set(hexToBytes(job.prevHash), 4);
  buf.set(hexToBytes(job.merkleRoot), 36);
  dv.setUint32(68, job.nTime, true);
  dv.setUint32(72, job.nBits, true);
  return buf;
}

/** Difficulty → 32-byte big-endian target */
function diffToTarget(diff) {
  const diff1 = BigInt('0x00000000FFFF0000000000000000000000000000000000000000000000000000');
  const t = diff1 / BigInt(Math.max(1, Math.floor(diff)));
  const hex = t.toString(16).padStart(64, '0');
  return hexToBytes(hex);
}

/** Convert 32-byte target to Uint32Array(8) big-endian for workers */
function targetToU32(target32) {
  const dv  = new DataView(target32.buffer, target32.byteOffset, 32);
  const u32 = new Uint32Array(8);
  for (let i = 0; i < 8; i++) u32[i] = dv.getUint32(i * 4, false);
  return u32;
}

// ═══════════════════════════════════════════════════════════════
// WebGPU engine
// ═══════════════════════════════════════════════════════════════

const SHA256_WGSL = /* wgsl */`
const K = array<u32, 64>(
  0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
  0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
  0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
  0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
  0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
  0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
  0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
  0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
  0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
  0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
  0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
  0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
  0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
  0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
  0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
  0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
);
fn rotr32(x: u32, n: u32) -> u32 { return (x >> n) | (x << (32u - n)); }
fn compress(w: ptr<function, array<u32, 64>>, s: ptr<function, array<u32, 8>>) {
  for (var i = 16u; i < 64u; i++) {
    let s0 = rotr32((*w)[i-15u],  7u) ^ rotr32((*w)[i-15u], 18u) ^ ((*w)[i-15u] >>  3u);
    let s1 = rotr32((*w)[i- 2u], 17u) ^ rotr32((*w)[i- 2u], 19u) ^ ((*w)[i- 2u] >> 10u);
    (*w)[i] = (*w)[i-16u] + s0 + (*w)[i-7u] + s1;
  }
  var a=(*s)[0]; var b=(*s)[1]; var c=(*s)[2]; var d=(*s)[3];
  var e=(*s)[4]; var f=(*s)[5]; var g=(*s)[6]; var h=(*s)[7];
  for (var i = 0u; i < 64u; i++) {
    let S1  = rotr32(e, 6u) ^ rotr32(e, 11u) ^ rotr32(e, 25u);
    let ch  = (e & f) ^ (~e & g);
    let t1  = h + S1 + ch + K[i] + (*w)[i];
    let S0  = rotr32(a, 2u) ^ rotr32(a, 13u) ^ rotr32(a, 22u);
    let maj = (a & b) ^ (a & c) ^ (b & c);
    let t2  = S0 + maj;
    h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
  }
  (*s)[0]+=a; (*s)[1]+=b; (*s)[2]+=c; (*s)[3]+=d;
  (*s)[4]+=e; (*s)[5]+=f; (*s)[6]+=g; (*s)[7]+=h;
}
@group(0) @binding(0) var<storage, read>       inp:     array<u32>;
@group(0) @binding(1) var<storage, read_write> out_buf: array<atomic<u32>>;
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let nonce    = inp[28] + gid.x;
  let nonce_le = (nonce << 24u)
               | ((nonce <<  8u) & 0x00FF0000u)
               | ((nonce >>  8u) & 0x0000FF00u)
               |  (nonce >> 24u);
  var s1: array<u32, 8>;
  s1[0]=0x6a09e667u; s1[1]=0xbb67ae85u; s1[2]=0x3c6ef372u; s1[3]=0xa54ff53au;
  s1[4]=0x510e527fu; s1[5]=0x9b05688cu; s1[6]=0x1f83d9abu; s1[7]=0x5be0cd19u;
  var w1: array<u32, 64>;
  for (var i = 0u; i < 16u; i++) { w1[i] = inp[i]; }
  compress(&w1, &s1);
  var w2: array<u32, 64>;
  w2[0]=inp[16]; w2[1]=inp[17]; w2[2]=inp[18]; w2[3]=nonce_le;
  w2[4]=0x80000000u; w2[15]=640u; // padding bit + 80*8 bit-length
  compress(&w2, &s1);

  // ── SHA256 pass 2: double-hash the 32-byte result ──────────────
  var s2: array<u32, 8>;
  s2[0]=0x6a09e667u; s2[1]=0xbb67ae85u; s2[2]=0x3c6ef372u; s2[3]=0xa54ff53au;
  s2[4]=0x510e527fu; s2[5]=0x9b05688cu; s2[6]=0x1f83d9abu; s2[7]=0x5be0cd19u;

  var w3: array<u32, 64>;
  for (var i = 0u; i < 8u; i++) { w3[i] = s1[i]; }
  w3[8]=0x80000000u;
  w3[15]=256u; // 32 * 8 bits
  compress(&w3, &s2);

  // ── Compare final hash vs target (big-endian, MSW first) ───────
  var below = false;
  for (var i = 0u; i < 8u; i++) {
    if (s2[i] < inp[20u + i]) { below = true;  break; }
    if (s2[i] > inp[20u + i]) { below = false; break; }
    if (i == 7u)               { below = true; }
  }

  if (below) {
    atomicStore(&out_buf[0], 1u);
    atomicStore(&out_buf[1], nonce);
  }
  // Track minimum hash[0] across all threads for realtime best-hash display
  // slot[2] = min hash[0] seen, slot[3] = nonce for that min
  let prev = atomicMin(&out_buf[2], s2[0]);
  if (s2[0] < prev) {
    atomicStore(&out_buf[3], nonce);
  }
}
`;

class GPUEngine {
  constructor() {
    this.device    = null;
    this.pipeline  = null;
    this.inputBuf  = null;
    this.resultBuf = null;
    this.readBuf   = null;
    this.bindGroup = null;
    this.ready     = false;
  }

  async init() {
    if (!navigator.gpu) throw new Error('WebGPU not available');
    const adapter = await navigator.gpu.requestAdapter({ powerPreference: 'high-performance' });
    if (!adapter) throw new Error('No WebGPU adapter found');
    this.device = await adapter.requestDevice();

    // 29 u32 = 116 bytes; pad to 256 for alignment
    this.inputBuf  = this.device.createBuffer({ size: 256, usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_DST });
    this.resultBuf = this.device.createBuffer({ size: 16,  usage: GPUBufferUsage.STORAGE | GPUBufferUsage.COPY_SRC | GPUBufferUsage.COPY_DST });
    this.readBuf   = this.device.createBuffer({ size: 16,  usage: GPUBufferUsage.MAP_READ | GPUBufferUsage.COPY_DST });

    // Capture shader compile errors explicitly
    this.device.pushErrorScope('validation');
    const module = this.device.createShaderModule({ code: SHA256_WGSL });
    const shaderErr = await this.device.popErrorScope();
    if (shaderErr) throw new Error('Shader: ' + shaderErr.message);

    this.pipeline = await this.device.createComputePipelineAsync({
      layout: 'auto',
      compute: { module, entryPoint: 'main' },
    });

    this.bindGroup = this.device.createBindGroup({
      layout: this.pipeline.getBindGroupLayout(0),
      entries: [
        { binding: 0, resource: { buffer: this.inputBuf  } },
        { binding: 1, resource: { buffer: this.resultBuf } },
      ],
    });
    this.ready = true;
  }

  async runBatch(header80, target32, nonceStart, batchSize) {
    // Flat layout: [header x20][target x8][nonce_start]
    const data = new Uint32Array(29);
    const hdv  = new DataView(header80.buffer, header80.byteOffset, 80);
    for (let i = 0; i < 20; i++) data[i]    = hdv.getUint32(i * 4, false);
    const tdv  = new DataView(target32.buffer, target32.byteOffset, 32);
    for (let i = 0; i < 8;  i++) data[20+i] = tdv.getUint32(i * 4, false);
    data[28] = nonceStart >>> 0;

    this.device.queue.writeBuffer(this.inputBuf,  0, data);
    // Reset: found=0, nonce=0, minHash0=0xFFFFFFFF, minNonce=0
    this.device.queue.writeBuffer(this.resultBuf, 0, new Uint32Array([0, 0, 0xFFFFFFFF, 0]));

    const enc  = this.device.createCommandEncoder();
    const pass = enc.beginComputePass();
    pass.setPipeline(this.pipeline);
    pass.setBindGroup(0, this.bindGroup);
    pass.dispatchWorkgroups(Math.ceil(batchSize / 256));
    pass.end();
    enc.copyBufferToBuffer(this.resultBuf, 0, this.readBuf, 0, 16);
    this.device.queue.submit([enc.finish()]);
    await this.readBuf.mapAsync(GPUMapMode.READ);
    const v     = new Uint32Array(this.readBuf.getMappedRange().slice(0));
    this.readBuf.unmap();
    return {
      nonce:    v[0] ? v[1] : null,
      minHash0: v[2],          // best hash[0] in this batch
      minNonce: v[3],          // nonce that produced it
    };
  }
  destroy() {
    this.uniformBuf?.destroy(); this.resultBuf?.destroy(); this.readBuf?.destroy();
    this.device?.destroy(); this.ready = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// CPU engine  (Web Workers)
// ═══════════════════════════════════════════════════════════════

class CPUEngine {
  constructor() {
    this.workers   = [];
    this.ready     = false;
    this.numWorkers = Math.max(1, Math.min(navigator.hardwareConcurrency || 4, 8));
  }
  async init() {
    for (let i = 0; i < this.numWorkers; i++) {
      this.workers.push(new Worker('worker.js'));
    }
    this.ready = true;
  }
  /**
   * Split batchSize across workers, each gets a slice of the nonce range.
   * Returns null or winning nonce.
   */
  async runBatch(header76, target32u, nonceStart, batchSize) {
    const sliceSize = Math.ceil(batchSize / this.numWorkers);

    const promises = this.workers.map((w, i) => {
      const start = (nonceStart + i * sliceSize) >>> 0;
      const count = Math.min(sliceSize, batchSize - i * sliceSize);
      if (count <= 0) return Promise.resolve({ nonce: null, hashes: 0 });

      // Each worker gets its OWN copy — transferring the same buffer to multiple
      // workers detaches it after the first transfer causing "already detached".
      const h76copy  = header76.buffer.slice(header76.byteOffset, header76.byteOffset + 76);
      const tgtcopy  = target32u.buffer.slice(0, 32);

      return new Promise((resolve) => {
        w.onmessage = (e) => resolve(e.data);
        // Transfer ownership of the *copies* — zero-copy to worker, no shared state
        w.postMessage(
          { header76: h76copy, target: tgtcopy, nonceStart: start, batchSize: count },
          [h76copy, tgtcopy],
        );
      });
    });

    const results = await Promise.all(promises);
    const totalHashes = results.reduce((a, r) => a + r.hashes, 0);
    const found = results.find(r => r.nonce !== null);
    return { nonce: found ? found.nonce : null, hashes: totalHashes };
  }
  destroy() {
    this.workers.forEach(w => w.terminate());
    this.workers = []; this.ready = false;
  }
}

// ═══════════════════════════════════════════════════════════════
// Stratum client
// ═══════════════════════════════════════════════════════════════

class StratumClient {
  constructor(url, onMsg, onOpen, onClose, onError) {
    this.url=url; this.ws=null; this._id=1;
    this.onMsg=onMsg; this.onOpen=onOpen; this.onClose=onClose; this.onError=onError;
  }
  connect() {
    this.ws = new WebSocket(this.url);
    this.ws.onopen    = () => this.onOpen();
    this.ws.onclose   = (e) => this.onClose(e);
    this.ws.onerror   = (e) => this.onError(e);
    this.ws.onmessage = (ev) => {
      for (const line of ev.data.split('\n')) {
        const t = line.trim();
        if (!t) continue;
        try { this.onMsg(JSON.parse(t)); } catch {}
      }
    };
  }
  send(method, params) {
    const id  = this._id++;
    const msg = JSON.stringify({ id, method, params }) + '\n';
    if (this.ws?.readyState === WebSocket.OPEN) this.ws.send(msg);
    return id;
  }
  close() { if (this.ws) { this.ws.onclose=null; this.ws.close(); this.ws=null; } }
}

// ═══════════════════════════════════════════════════════════════
// Hashrate chart
// ═══════════════════════════════════════════════════════════════

class HashrateChart {
  constructor(id) {
    this.canvas  = document.getElementById(id);
    this.ctx     = this.canvas.getContext('2d');
    this.samples = [];
    this.MAX     = 60;
    this._resize();
    window.addEventListener('resize', () => this._resize());
  }
  _resize() {
    // Bug 6 fix: wrap in rAF so layout is complete before reading dimensions
    requestAnimationFrame(() => {
      const r = this.canvas.parentElement.getBoundingClientRect();
      this.canvas.width  = r.width  || 500;
      this.canvas.height = r.height || 180;
    });
  }
  push(hs) {
    this.samples.push(hs);
    if (this.samples.length > this.MAX) this.samples.shift();
    this._draw();
  }
  _draw() {
    const { canvas: c, ctx, samples: s } = this;
    const W=c.width, H=c.height;
    ctx.clearRect(0,0,W,H);
    if (s.length < 2) return;
    const maxV = Math.max(...s) * 1.2 || 1;
    const pts  = s.map((v,i) => ({
      x: (i/(s.length-1))*W,
      y: H - (v/maxV)*(H*0.82) - H*0.05,
    }));
    // fill
    const grad = ctx.createLinearGradient(0,0,0,H);
    grad.addColorStop(0,'rgba(34,211,163,0.28)');
    grad.addColorStop(1,'rgba(34,211,163,0)');
    ctx.beginPath();
    ctx.moveTo(pts[0].x, H);
    ctx.lineTo(pts[0].x, pts[0].y);
    for (let i=1;i<pts.length;i++) {
      const cx = pts[i-1].x + (pts[i].x-pts[i-1].x)*0.5;
      ctx.bezierCurveTo(cx,pts[i-1].y,cx,pts[i].y,pts[i].x,pts[i].y);
    }
    ctx.lineTo(pts[pts.length-1].x, H);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();
    // line
    ctx.beginPath();
    ctx.moveTo(pts[0].x, pts[0].y);
    for (let i=1;i<pts.length;i++) {
      const cx = pts[i-1].x + (pts[i].x-pts[i-1].x)*0.5;
      ctx.bezierCurveTo(cx,pts[i-1].y,cx,pts[i].y,pts[i].x,pts[i].y);
    }
    ctx.strokeStyle='#22d3a3'; ctx.lineWidth=2.5;
    ctx.shadowColor='#22d3a3'; ctx.shadowBlur=10;
    ctx.stroke(); ctx.shadowBlur=0;
    const last = pts[pts.length-1];
    ctx.beginPath(); ctx.arc(last.x,last.y,4,0,Math.PI*2);
    ctx.fillStyle='#22d3a3'; ctx.shadowColor='#22d3a3'; ctx.shadowBlur=14;
    ctx.fill(); ctx.shadowBlur=0;
  }
}

// ═══════════════════════════════════════════════════════════════
// Format helpers
// ═══════════════════════════════════════════════════════════════

function fmtHS(hs) {
  if (hs>=1e12) return (hs/1e12).toFixed(2)+' TH/s';
  if (hs>=1e9)  return (hs/1e9).toFixed(2) +' GH/s';
  if (hs>=1e6)  return (hs/1e6).toFixed(2) +' MH/s';
  if (hs>=1e3)  return (hs/1e3).toFixed(2) +' KH/s';
  return hs.toFixed(0)+' H/s';
}
function fmtUptime(sec) {
  const h=Math.floor(sec/3600), m=Math.floor((sec%3600)/60), s=sec%60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

// SHA256d via SubtleCrypto (async, main thread)
async function sha256dBuf(bytes) {
  const h1 = await crypto.subtle.digest('SHA-256', bytes);
  const h2 = await crypto.subtle.digest('SHA-256', h1);
  return Array.from(new Uint8Array(h2)).map(b => b.toString(16).padStart(2,'0')).join('');
}

// Format hash HTML: leading zeros dim, rest bright, mid truncated for display
function fmtHashHtml(hex) {
  if (!hex || hex === '—') return '—';
  let z = 0;
  while (z < hex.length && hex[z] === '0') z++;
  const zeros = hex.slice(0, z);
  const rest  = hex.slice(z);
  return `<span class="lh-hash-zeros">${zeros}</span><span class="lh-hash-rest">${rest}</span>`;
}

// ═══════════════════════════════════════════════════════════════
// Main Miner Controller
// ═══════════════════════════════════════════════════════════════

class LuckyHashMiner {
  constructor() {
    this.gpu        = new GPUEngine();
    this.cpu        = new CPUEngine();
    this.engine     = null;
    this.chart      = null;
    this.stratum    = null;
    this.running    = false;
    this._authorized = false;

    this.extranonce1 = '';
    this.extranonce2Size = 4;
    this.difficulty  = 10000;
    this.currentJob  = null;
    this._en2Counter = 0;
    this.pendingSubmits = new Map();

    this.accepted = 0; this.rejected = 0;
    this.startTime = 0; this.totalHashes = 0;
    this.hashWindow = [];

    this._miningActive = false;
    this._jobChanged   = false;
    this._uptimeTmr    = null;
    this._chartTmr     = null;
  }

  // ── Helpers to update Alpine UI state ────────────────────────

  get _ui() { return window.uiState; }

  log(msg, type = 'info') {
    this._ui?.pushLog(msg, type);
  }

  _setStatus(cls, text) {
    if (!this._ui) return;
    this._ui.statusClass = cls;
    this._ui.statusText  = text;
  }

  _updateEngine(mode) {
    if (!this._ui) return;
    if (mode === 'gpu') {
      this._ui.engineLabel = 'WebGPU';
      this._ui.engineClass = 'lh-badge-gpu';
      this._ui.engineIcon  = 'bi-gpu-card';
    } else {
      this._ui.engineLabel = `CPU ×${this.cpu.numWorkers}`;
      this._ui.engineClass = 'lh-badge-cpu';
      this._ui.engineIcon  = 'bi-cpu-fill';
    }
  }

  // ── Start ─────────────────────────────────────────────────────

  async start() {
    const s      = this._ui?.settings || {};
    const url    = s.proxyUrl  || document.getElementById('proxy-url').value.trim();
    const addr   = s.address   || document.getElementById('btc-address').value.trim();
    const worker = s.worker    || document.getElementById('worker-name').value.trim() || 'webgpu01';

    if (!addr) { this.log('❌ Please enter your BTC address', 'error'); return; }
    if (!url)  { this.log('❌ Please enter the proxy WebSocket URL', 'error'); return; }

    if (navigator.gpu) {
      this.log('🖥️ Initializing WebGPU...', 'info');
      try {
        await this.gpu.init();
        this.engine = 'gpu';
        this.log('✅ WebGPU ready — full GPU acceleration enabled!', 'success');
        this._updateEngine('gpu');
      } catch (e) {
        this.log(`⚠️ WebGPU init failed: ${e.message}`, 'warn');
        this.log('🔄 Falling back to CPU miners...', 'info');
        this.engine = 'cpu';
      }
    } else {
      this.log('⚠️ WebGPU not available — using CPU fallback.', 'warn');
      this.engine = 'cpu';
    }

    if (this.engine === 'cpu') {
      await this.cpu.init();
      this._updateEngine('cpu');
      this.log(`✅ CPU mining with ${this.cpu.numWorkers} threads`, 'success');
    }

    this.running     = true;
    this._authorized = false;
    this.startTime   = Date.now();
    this.accepted    = this.rejected = 0;
    this.totalHashes = 0;
    this.hashWindow  = [];
    this._en2Counter = 0;

    if (this._ui) {
      this._ui.running  = true;
      this._ui.accepted = 0;
      this._ui.rejected = 0;
      this._ui.uptime   = '00:00:00';
      this._ui.totalGH  = '0';
      this._ui.hashrate = '0 H/s';
      this._ui.bestHash = '—';
      this._ui.bestBlockHash     = '—';
      this._ui.bestBlockHashNonce = '—';
      this._ui.bestBlockHashHtml  = '—';
    }
    this._bestHS = 0;
    this._bestBlockHashHex = 'f'.repeat(64);
    this._bestHash0        = 0xFFFFFFFF; // fast uint32 pre-check
    this.chart = new HashrateChart('hashrate-chart');

    this._uptimeTmr = setInterval(() => {
      const sec = Math.floor((Date.now() - this.startTime) / 1000);
      if (this._ui) this._ui.uptime = fmtUptime(sec);
    }, 1000);

    this._chartTmr = setInterval(() => {
      const hs = this._calcHS();
      if (this._ui) {
        this._ui.hashrate = fmtHS(hs);
        this._ui.totalGH  = (this.totalHashes / 1e9).toFixed(3);
        // Update best hash (peak hashrate)
        if (hs > this._bestHS) {
          this._bestHS = hs;
          this._ui.bestHash = fmtHS(hs);
        }
      }
      this.chart.push(hs);
    }, 2000);

    this.log(`🔗 Connecting to ${url}…`, 'info');
    this.stratum = new StratumClient(
      url,
      (m) => this._onMsg(m, addr, worker),
      ()  => this._onOpen(addr, worker),
      (e) => this._onClose(e),
      (e) => this._onErr(e),
    );
    this.stratum.connect();
  }

  // ── Stop ──────────────────────────────────────────────────────

  stop() {
    this.running = false;
    this._miningActive = false;
    this.stratum?.close(); this.stratum = null;
    clearInterval(this._uptimeTmr); this._uptimeTmr = null;
    clearInterval(this._chartTmr);  this._chartTmr  = null;
    if (this.engine === 'gpu') this.gpu.destroy();
    else if (this.engine === 'cpu') this.cpu.destroy();
    this.engine = null; this.currentJob = null;
    this._setStatus('', 'Disconnected');
    if (this._ui) this._ui.running = false;
    this.log('⏹️ Mining stopped.', 'warn');
  }

  // ── WebSocket events ──────────────────────────────────────────

  _onOpen(addr, worker) {
    this.log('🔗 Connected! Subscribing…', 'success');
    this._setStatus('connected', 'Connected');
    this.stratum.send('mining.subscribe', ['LuckyHashWebGPU/1.0', null]);
  }

  _onClose(e) {
    if (!this.running) return;
    this.log(`⚠️ Closed (${e.code}). Reconnecting in 5s…`, 'warn');
    this._setStatus('error', 'Reconnecting…');
    this._miningActive = false; this.currentJob = null;
    setTimeout(() => { if (this.running && this.stratum) this.stratum.connect(); }, 5000);
  }

  _onErr() {
    this.log('❌ WebSocket error — check proxy URL.', 'error');
    this._setStatus('error', 'Error');
  }

  // ── Stratum messages ──────────────────────────────────────────

  _onMsg(msg, addr, worker) {
    if (msg.method === 'mining.notify') { this._onNotify(msg.params); return; }
    if (msg.method === 'mining.set_difficulty') {
      // Cap difficulty at 10000 so target stays reachable in-browser
      this.difficulty = Math.min(msg.params[0], 10000);
      if (this._ui) this._ui.pool.difficulty = this.difficulty.toLocaleString();
      this.log(`📊 Difficulty → ${this.difficulty} (pool sent ${msg.params[0]})`, 'info'); return;
    }
    if (msg.id == null) return;

    // Subscribe response
    if (Array.isArray(msg.result) && msg.result.length === 3 && typeof msg.result[1] === 'string') {
      this.extranonce1     = msg.result[1];
      this.extranonce2Size = msg.result[2];
      if (this._ui) {
        this._ui.pool.extranonce = this.extranonce1;
        this._ui.pool.en2size    = this.extranonce2Size + ' bytes';
      }
      this.log(`✅ Subscribed. EN1=${this.extranonce1}`, 'success');
      const username = `${addr}.${worker}`;
      this.stratum.send('mining.authorize', [username, 'x']);
      this.log(`🔑 Authorizing as ${username}`, 'info');
      return;
    }

    // Authorize
    if (msg.result === true && !this._authorized) {
      this._authorized = true;
      this._setStatus('mining', `Mining (${this.engine === 'gpu' ? 'WebGPU' : 'CPU ×'+this.cpu.numWorkers})`);
      this.log('✅ Authorized! Waiting for first job…', 'success'); return;
    }

    // Share response
    if (this.pendingSubmits.has(msg.id)) {
      const jobId = this.pendingSubmits.get(msg.id);
      this.pendingSubmits.delete(msg.id);
      if (msg.result === true) {
        this.accepted++;
        if (this._ui) this._ui.accepted = this.accepted;
        this.log(`🏆 Share ACCEPTED (job ${jobId})`, 'success');
      } else {
        this.rejected++;
        if (this._ui) this._ui.rejected = this.rejected;
        const reason = msg.error?.[1] ?? 'unknown';
        this.log(`❌ Share rejected: ${reason}`, 'error');
      }
    }
    if (msg.error) this.log(`⚠️ Stratum: ${JSON.stringify(msg.error)}`, 'warn');
  }

  // ── mining.notify ─────────────────────────────────────────────

  _onNotify(params) {
    const [jobId, prevHash, coinb1, coinb2, merkleBranch,
           versionHex, nBitsHex, nTimeHex, cleanJobs] = params;

    const prevHashLE = prevHash.match(/.{8}/g).map(x => reverseHex(x)).join('');
    this.currentJob = {
      jobId, coinb1, coinb2, merkleBranch,
      version:  parseInt(versionHex, 16),
      nBits:    parseInt(nBitsHex,   16),
      nTime:    parseInt(nTimeHex,   16),
      prevHash: prevHashLE,
    };

    if (this._ui) {
      this._ui.pool.jobId      = jobId;
      this._ui.pool.targetBits = nBitsHex;
      this._ui.pool.cleanJobs  = cleanJobs ? 'Yes' : 'No';
    }

    this.log(`📦 Job ${jobId}${cleanJobs ? ' (clean)' : ''}`, 'info');
    this._jobChanged = true;

    if (!this._miningActive) {
      this._miningActive = true;
      this._loop();
    }
  }

  // ── Mining loop ───────────────────────────────────────────────

  async _loop() {
    const s     = this._ui?.settings || {};
    const BATCH = parseInt(s.batchSize) || parseInt(document.getElementById('batch-size')?.value) || 4194304;
    let nonceStart = 0;

    while (this._miningActive && this.running) {
      if (!this.currentJob) { await new Promise(r => setTimeout(r, 200)); continue; }

      if (this._jobChanged) {
        this._jobChanged = false;
        nonceStart = 0;
        this._en2Counter++;
      }

      const job = this.currentJob;
      const en2 = this._en2Counter.toString(16).padStart(this.extranonce2Size * 2, '0');
      job.merkleRoot = buildMerkleRoot(job, this.extranonce1, en2);

      const target32 = diffToTarget(this.difficulty);
      let nonce = null, hashes = 0;

      try {
        if (this.engine === 'gpu') {
          const h80 = new Uint8Array(80);
          h80.set(buildHeader76(job));
          const res  = await this.gpu.runBatch(h80, target32, nonceStart >>> 0, BATCH);
          nonce      = res.nonce;
          hashes     = BATCH;
          // Realtime best hash: GPU tracked the minimum hash[0] of this batch
          if (res.minHash0 < this._bestHash0) {
            this._bestHash0 = res.minHash0;
            this._checkBestHash(h80, res.minNonce); // async, non-blocking
          }
        } else {
          const h76 = buildHeader76(job);
          const tgt = targetToU32(target32);
          const res = await this.cpu.runBatch(h76, tgt, nonceStart >>> 0, BATCH);
          nonce  = res.nonce;
          hashes = res.hashes;
        }
      } catch (e) {
        this.log(`⚠️ Engine error: ${e.message}`, 'error');
        await new Promise(r => setTimeout(r, 500));
        continue;
      }

      this.totalHashes += hashes;
      this.hashWindow.push({ t: Date.now(), count: hashes });

      if (nonce !== null) {
        this.log(`⚡ NONCE FOUND! 0x${nonce.toString(16).padStart(8,'0')} — submitting…`, 'share');
        this._submit(job, en2, nonce);
        // Compute actual SHA256d hash for Best Block Hash display
        this._checkBestHash(
          this.engine === 'gpu' ? h80 : buildHeader76(job),
          nonce
        );
      }

      nonceStart = (nonceStart + BATCH) >>> 0;
      await new Promise(r => setTimeout(r, 0));
    }
    this._miningActive = false;
  }

  // ── Best Block Hash ───────────────────────────────────────────

  async _checkBestHash(headerBytes, nonce) {
    try {
      // Build full 80-byte header with this nonce (LE at bytes 76-79)
      const h80 = new Uint8Array(80);
      const src = headerBytes instanceof Uint8Array ? headerBytes : new Uint8Array(headerBytes.buffer || headerBytes);
      h80.set(src.slice(0, 76));
      const dv = new DataView(h80.buffer);
      dv.setUint32(76, nonce, true); // little-endian nonce
      const hashHex = await sha256dBuf(h80);
      // Lower hex = better (more leading zeros)
      if (hashHex < this._bestBlockHashHex) {
        this._bestBlockHashHex = hashHex;
        if (this._ui) {
          this._ui.bestBlockHash      = hashHex;
          this._ui.bestBlockHashNonce = '0x' + nonce.toString(16).padStart(8,'0');
          this._ui.bestBlockHashHtml  = fmtHashHtml(hashHex);
        }
        this.log(`🏆 New best hash: ${hashHex.slice(0,20)}…`, 'info');
      }
    } catch(e) { /* ignore */ }
  }

  // ── Submit share ──────────────────────────────────────────────

  _submit(job, en2, nonce) {
    if (!this.stratum) return;
    const s     = this._ui?.settings || {};
    const addr  = s.address || document.getElementById('btc-address').value.trim();
    const wname = s.worker  || document.getElementById('worker-name').value.trim() || 'webgpu01';
    const id    = this.stratum.send('mining.submit', [
      `${addr}.${wname}`,
      job.jobId, en2,
      job.nTime.toString(16).padStart(8,'0'),
      nonce.toString(16).padStart(8,'0'),
    ]);
    this.pendingSubmits.set(id, job.jobId);
    this.log(`📤 Share submitted (nonce: ${nonce.toString(16).padStart(8,'0')})`, 'share');
  }

  // ── Hashrate ──────────────────────────────────────────────────

  _calcHS() {
    const now = Date.now(), win = 10000;
    this.hashWindow = this.hashWindow.filter(s => now - s.t <= win);
    if (!this.hashWindow.length) return 0;
    const total   = this.hashWindow.reduce((a,s) => a + s.count, 0);
    const elapsed = (now - this.hashWindow[0].t) / 1000 || 1;
    return total / elapsed;
  }
}

// ═══════════════════════════════════════════════════════════════
// Bootstrap — wait for Alpine to init window.uiState
// ═══════════════════════════════════════════════════════════════

const miner = new LuckyHashMiner();
window.miner = miner;

// Log initial state after Alpine initialises uiState
document.addEventListener('alpine:initialized', () => {
  if (!navigator.gpu) {
    miner.log('⚠️ WebGPU not available — CPU multi-thread mode will be used.', 'warn');
    miner.log(`🔧 ${navigator.hardwareConcurrency || 4} CPU core(s) detected.`, 'info');
    miner._updateEngine('cpu');
  } else {
    miner.log('✅ WebGPU detected — GPU acceleration ready!', 'success');
  }

  const savedAddr = localStorage.getItem('lh_btc_address');
  if (savedAddr) miner.log(`💾 Wallet loaded: ${savedAddr.slice(0,12)}…`, 'success');
  miner.log('📋 Configure your wallet address and click Start Mining.', 'info');
});


