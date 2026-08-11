# ⚡ LuckyHash — Solo Bitcoin Miner in the Browser

> Mine Bitcoin solo directly in your browser using **WebGPU compute shaders** — no install, no native app. Falls back to CPU Web Workers automatically.

![LuckyHash](https://img.shields.io/badge/Bitcoin-Solo%20Miner-orange?logo=bitcoin&logoColor=white)
![WebGPU](https://img.shields.io/badge/WebGPU-Compute%20Shader-4f8fff?logo=googlechrome&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952b3?logo=bootstrap&logoColor=white)
![Alpine.js](https://img.shields.io/badge/Alpine.js-3.x-8bc0d0?logo=alpine.js&logoColor=white)
![License](https://img.shields.io/badge/license-Apache%202.0-22d3a3)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🖥️ **WebGPU Compute** | WGSL SHA256d shader — millions of nonces per batch; **SHA-256 midstate** (block-1 precomputed on CPU) makes it ~40% faster |
| 🧵 **CPU Fallback** | Multi-threaded Web Workers kick in automatically when WebGPU isn't available |
| 🔗 **Stratum Protocol** | Full Stratum JSON-RPC flow: subscribe → authorize → notify → submit |
| ✅ **Bitcoin-correct compare** | Hash is checked as a **little-endian uint256** (Bitcoin's convention) — shares are accepted by ckpool-family pools, verified live |
| 🛡️ **Pre-submit verification** | Every found nonce is re-hashed locally against the *current* difficulty — shares that would be rejected ("Above target") are dropped instead of submitted |
| ⏱️ **Mining Duration** | Auto-stop timer (5 min default, up to 8 h, or unlimited) with live countdown |
| 🚦 **Anti-spam clamp** | Share difficulty floor of 100 — ignores pools broadcasting absurdly low difficulties |
| 📈 **Wallet stats** | One-click link to your pool stats page on Helios Pool |
| 🔄 **No stale cache** | Local JS is loaded with a random `?v=` token per page load |
| 🧪 **Unit tests** | 18 tests (`node:test`, no deps) covering hashes, midstate, merkle, LE compare |
| 📊 **Live Hashrate Chart** | Real-time animated chart with 60-sample history |
| 💾 **Persistent Settings** | Wallet address, worker name, proxy URL saved to `localStorage` |
| 🎨 **Bootstrap 5 + Alpine.js** | Dark-mode glassmorphism UI with reactive bindings |
| 📖 **About Page** | Architecture diagram, step-by-step flow, FAQ, Glossary, Disclaimer |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────┐
│                      BROWSER                        │
│                                                     │
│  ┌─────────────┐    Stratum/WS   ┌─────────────┐   │
│  │  miner.js   │ ◄────────────► │  Proxy WS   │   │
│  │             │                 │   :3030      │   │
│  │  ┌────────┐ │                 └──────┬───────┘   │
│  │  │WebGPU  │ │                        │ TCP        │
│  │  │Compute │ │                 ┌──────▼───────┐   │
│  │  │SHA256d │ │                 │ Bitcoin Pool │   │
│  │  └────────┘ │                 │   :3333      │   │
│  │  ┌────────┐ │                 └──────────────┘   │
│  │  │  CPU   │ │  (fallback when no GPU)             │
│  │  │Workers │ │                                     │
│  │  └────────┘ │                                     │
│  └─────────────┘                                     │
└──────────────────────────────────────────────────────┘
```

The proxy ([luckyhash_proxy](https://github.com/dungvn3000/luckyhash_proxy)) bridges the browser WebSocket to the pool's raw TCP Stratum connection — because browsers can't open TCP sockets directly.

---

## 🚀 Quick Start

### 1. Start the proxy

```bash
git clone https://github.com/dungvn3000/luckyhash_proxy
cd luckyhash_proxy
# follow proxy README to connect to your pool
```

### 2. Serve the miner

```bash
git clone https://github.com/dungvn3000/luckyhash
cd luckyhash
python3 -m http.server 8080
```

Then open **http://localhost:8080** in Chrome 113+ or Edge 113+.

### 2b. Run unit tests (optional, no deps)

```bash
node --test tests/miner.test.js
```

### 3. Configure & mine

1. Enter your **BTC address** (bc1q… or 1…)
2. Set **Worker name** (optional, default: `luckyhash01`)
3. Set **Proxy URL** (default: `wss://ws.luckyhash.dev`, upstream: [Helios Pool](https://heliospool.com/))
4. Pick a **Mining Duration** if you want an auto-stop timer (default: 5 minutes)
5. Click **Start Mining** 🚀
6. Track accepted shares anytime via the **Check wallet stats** link shown under the BTC address field

---

## 🖥️ Browser Requirements

| Browser | WebGPU | CPU Mode |
|---------|--------|----------|
| Chrome / Edge 113+ (desktop) | ✅ Full | ✅ |
| Chrome 121+ (Android) | ✅ ¹ | ✅ |
| Opera 99+ | ✅ Full | ✅ |
| Safari 26+ (macOS / iOS) | ✅ Full | ✅ |
| Firefox | ❌ | ✅ fallback |
| Any other | ❌ | ✅ fallback |

> ¹ **Mobile note:** the OS can revoke the GPU device mid-mining (watchdog
> timeout, thermal/memory pressure, or a backgrounded tab). The miner detects
> this and automatically falls back to CPU workers, so mining continues —
> mobile sessions also default to the lighter 1M batch to keep dispatches short.

---

## ⚙️ Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| Proxy URL | `wss://ws.luckyhash.dev` | WebSocket address of luckyhash_proxy |
| BTC Address | — | Your Bitcoin receiving address |
| Worker | `luckyhash01` | Worker name shown in pool dashboard |
| Workgroup | `64K (Light)` | GPU dispatch size — higher = more hashes/batch |
| Batch Size | `4M nonces` (`1M` on mobile) | Nonces processed per mining cycle |
| Mining Duration | `5 minutes` | Auto-stop timer — miner stops after the chosen time (5 min → 8 h, or unlimited), with an on-screen countdown |

All settings persist across sessions via `localStorage`.

---

## 🔬 How It Works

### SHA256d on the GPU (WGSL)

Each GPU thread receives a unique nonce offset and independently computes the double SHA256 of the 80-byte block header. The first 64 bytes of the header are identical for every thread of every batch, so JavaScript precomputes their **midstate** once per job — the GPU only runs 2 of the 3 SHA-256 compressions per hash:

```wgsl
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let nonce = inp[28] + gid.x;          // unique nonce per thread

  // SHA256 pass 1 — block-2 only; block-1 midstate comes from the CPU
  var s1: array<u32, 8>;
  for (var i = 0u; i < 8u; i++) { s1[i] = inp[30u + i]; }   // midstate
  compress(&w2, &s1);                    // bytes 64–79 + nonce + padding

  // SHA256 pass 2 — double hash
  var s2: array<u32, 8> = IV;
  compress(&w3, &s2);

  // Bitcoin compares the digest as a LITTLE-ENDIAN uint256
  // (valid shares have trailing zero bytes, not leading ones)
  if (le_hash_below_target) {
    let idx = atomicAdd(&out_buf[0], 1u);  // up to 4 nonces per batch
    if (idx < 4u) { atomicStore(&out_buf[1u + idx], nonce); }
  }
}
```

### Mining Loop

```
Job received → Merkle root + header (76B) + midstate (cached per en2)
→ Dispatch GPU/CPU batch → Read result buffer
→ Nonce found? → Re-hash locally vs CURRENT difficulty → Submit share
→ Increment nonce range → Repeat
```

### Stratum Flow

```
Client                          Pool (via proxy)
  │── mining.subscribe ─────────────────────►│
  │◄── [subscriptionId, extranonce1, en2size]─│
  │── mining.authorize ────────────────────►│
  │◄── true ──────────────────────────────── │
  │◄── mining.notify (job params) ─────────  │
  │── mining.submit (nonce found) ─────────►│
  │◄── true / error ───────────────────────  │
```

---

## 📁 File Structure

```
luckyhash/
├── index.html      # Main miner UI (Bootstrap 5 + Alpine.js)
├── about.html      # How it works page (architecture, FAQ, disclaimer)
├── style.css       # Custom styles on top of Bootstrap dark theme
├── miner.js        # Core logic: Stratum, GPUEngine, CPUEngine, UI state
├── worker.js       # CPU Web Worker — standalone SHA256d implementation
├── bg.js           # Animated particle background canvas
└── tests/
    └── miner.test.js  # Unit tests (node:test, no deps)
```

---

## ⚠️ Disclaimer

- **Extremely low probability** — mining a Bitcoin block with consumer hardware could statistically take thousands of years.
- **Not a financial tool** — this is an educational/experimental project. No guaranteed returns.
- **Power consumption** — continuous GPU mining increases device temperature and power draw. Ensure adequate cooling.
- **Legal compliance** — users are responsible for complying with local laws regarding cryptocurrency mining.
- Provided **"as is"** without warranty of any kind.

---

## 🤝 Related

- [luckyhash_proxy](https://github.com/dungvn3000/luckyhash_proxy) — WebSocket↔Stratum TCP bridge (required)
- [Helios Pool](https://heliospool.com/) — solo pool (ckpool fork); wallet stats at `stats-btc.heliospool.com/users/<your-address>`
- [tadu.cloud](https://tadu.cloud) — Developed & maintained by the Tadu team

---

## 📄 License

Copyright 2026 [tadu.cloud](https://tadu.cloud)

Licensed under the **Apache License, Version 2.0**. See [LICENSE](LICENSE) for details.
