# ⚡ LuckyHash — Solo Bitcoin Miner in the Browser

> Mine Bitcoin solo directly in your browser using **WebGPU compute shaders** — no install, no native app. Falls back to CPU Web Workers automatically.

![LuckyHash](https://img.shields.io/badge/Bitcoin-Solo%20Miner-orange?logo=bitcoin&logoColor=white)
![WebGPU](https://img.shields.io/badge/WebGPU-Compute%20Shader-4f8fff?logo=googlechrome&logoColor=white)
![Bootstrap](https://img.shields.io/badge/Bootstrap-5.3-7952b3?logo=bootstrap&logoColor=white)
![Alpine.js](https://img.shields.io/badge/Alpine.js-3.x-8bc0d0?logo=alpine.js&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-22d3a3)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🖥️ **WebGPU Compute** | WGSL SHA256d shader — processes millions of nonces per batch on the GPU |
| 🧵 **CPU Fallback** | Multi-threaded Web Workers kick in automatically when WebGPU isn't available |
| 🔗 **Stratum Protocol** | Full Stratum JSON-RPC flow: subscribe → authorize → notify → submit |
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

### 3. Configure & mine

1. Enter your **BTC address** (bc1q… or 1…)
2. Set **Worker name** (optional, default: `webgpu01`)
3. Set **Proxy URL** (default: `wss://ws.luckyhash.dev`)
4. Click **Start Mining** 🚀

---

## 🖥️ Browser Requirements

| Browser | WebGPU | CPU Mode |
|---------|--------|----------|
| Chrome 113+ | ✅ Full | ✅ |
| Edge 113+ | ✅ Full | ✅ |
| Opera 99+ | ✅ Full | ✅ |
| Safari 18+ (macOS 14+) | ✅ Full | ✅ |
| Firefox | ❌ | ✅ fallback |
| Any other | ❌ | ✅ fallback |

---

## ⚙️ Configuration Options

| Setting | Default | Description |
|---------|---------|-------------|
| Proxy URL | `wss://ws.luckyhash.dev` | WebSocket address of luckyhash_proxy |
| BTC Address | — | Your Bitcoin receiving address |
| Worker | `webgpu01` | Worker name shown in pool dashboard |
| Workgroup | `64K (Light)` | GPU dispatch size — higher = more hashes/batch |
| Batch Size | `4M nonces` | Nonces processed per mining cycle |

All settings persist across sessions via `localStorage`.

---

## 🔬 How It Works

### SHA256d on the GPU (WGSL)

Each GPU thread receives a unique nonce offset and independently computes the double SHA256 of the 80-byte block header:

```wgsl
@compute @workgroup_size(256)
fn main(@builtin(global_invocation_id) gid: vec3<u32>) {
  let nonce = inp[28] + gid.x;          // unique nonce per thread

  // SHA256 pass 1 — 80-byte header (2 blocks)
  var s1: array<u32, 8> = IV;
  compress(&w1, &s1);                    // bytes 0–63
  compress(&w2, &s1);                    // bytes 64–79 + padding

  // SHA256 pass 2 — double hash
  var s2: array<u32, 8> = IV;
  compress(&w3, &s2);

  if (hash_below_target) {
    atomicStore(&out_buf[0], 1u);        // signal found
    atomicStore(&out_buf[1], nonce);
  }
}
```

### Mining Loop

```
Job received → Build header (76B) → Dispatch GPU/CPU batch
→ Read result buffer → Nonce found? → Submit share
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
└── bg.js           # Animated particle background canvas
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

---

## 📄 License

MIT © [dungvn3000](https://github.com/dungvn3000)
