# BetterDoS

**Network resilience research and testing framework — 47 attack methods, 12 commands, GUI + CLI.**

All the methods and tools of MHDDoS, automated, optimized, augmented, with corrected counts, Cloudflare detection and evasion, and improved docs/UI. Conducts a competition between methods to find ideal attack vectors for any site.

## Screenshot

![BetterDoS GUI](docs/screenshots/gui1.png)

## To Do

  - Give the project actual DDoS (not just DoS) via swarm management over SSH.

## Important Note

I am not a maintainer. After the initial improvements there will be no further updates (this point has not yet been reached and the project is under active development).

## What's New

| Feature | Description |
|---|---|
| **GUI** | Tkinter desktop interface — tabbed Attack / Advise / Auto / CFIP modes, live output pane |
| **ADVISE** | Fingerprints a target (HTTP headers, ports, CDN detection) and recommends the best attack methods |
| **AUTO** | Probes every candidate method with bounded trials, ranks results by PPS/BPS, recommends the winner |
| **Cloudflare Protection** | Full IPv4 + IPv6 range detection; L4 attacks against CF IPs are automatically blocked |
| **CFIP Tool** | Discovers origin IPs behind Cloudflare via subdomain enumeration, MX, and SPF/TXT parsing |
| **Modular Architecture** | Monolithic 2100-line script split into 9 focused modules under `betterdos/` |
| **Pretty Output** | Unicode box-drawing tables, color-coded results, live progress bar with PPS/BPS counters |
| **Run Tracking** | Every session gets a unique `RUN_ID`; optional `MHD_LOG_FILE` and `MHD_DEBUG` env vars |
| **Performance** | O(1) method dispatch (dict lookup replaces O(n) if/elif chains), cached Apache range header |

---

## Quick Start

**Requirements:** Python 3.11+ recommended (3.9+ minimum). Docker is **not** required — install dependencies directly and run.

```bash
git clone <this-repo>
cd BetterDoS
pip install -r requirements.txt
```

**Optional — Docker** (if you prefer a containerized environment):

```bash
docker compose build
docker compose run -it --entrypoint /bin/bash betterdos
```

---

## GUI (Recommended)

The easiest way to use BetterDoS. Launch from the project root:

```bash
python3 -m betterdos.gui
```

The GUI has four tabs:

| Tab | What it does |
|---|---|
| **Attack** | Select method, target, threads, duration, proxy settings. Start/stop with live PPS/BPS output. |
| **Advise** | Fingerprint a target and see recommended methods — no attack traffic sent. |
| **Auto** | Benchmark all candidate methods and rank by throughput. |
| **CFIP** | Enter a domain — discovers origin IPs hidden behind Cloudflare. |

All output streams into the built-in output pane. No terminal needed.

---

## CLI Usage

```bash
python3 start.py HELP          # show full usage with all methods
python3 start.py TOOLS         # interactive tools console
python3 start.py TOOLS CFIP    # jump straight into the CFIP tool
```

### ADVISE — Discover What Works

Fingerprints the target and recommends candidate methods without sending attack traffic:

```
python3 start.py ADVISE https://fakeurl.com
```

```
┌─── ADVISE Results ────────────────────────────┐
│ Target   : fakeurl.com:443
│ TCP      : open
│ HTTP     : 200
│
│ L7 Candidates (17):
│   GET, HEAD, POST, PPS, EVEN, OVH, STRESS, ...
│
│ L4 Candidates (4):
│   TCP, UDP, SYN, CPS
│
│ Rationale:
│   • TCP port 443 open — all L4 base methods apply
│   • HTTP 200 — full L7 suite applies
└───────────────────────────────────────────────┘
```

### AUTO — Benchmark Every Method

Probes each candidate with bounded traffic, measures PPS/BPS, ranks results:

```
python3 start.py AUTO https://fakeurl.com 50 10 100 1 proxies.txt
#                      threads  probe_sec rpc socks_type proxy_file
```

```
╔══════════════════════════════════════════════════════════════╗
║                     AUTO RESULTS                             ║
╠══════════════╤════════╤════════════╤══════════════╤══════════╣
║ Method       │ Layer  │        PPS │          BPS │ Status   ║
╠══════════════╪════════╪════════════╪══════════════╪══════════╣
║ GET          │ L7     │      1.2K  │      4.8 MB  │ #1       ║
║ POST         │ L7     │        980 │      3.2 MB  │ #2       ║
║ STRESS       │ L7     │        450 │      1.1 MB  │ #3       ║
║ SLOW         │ L7     │          0 │        0  B  │ FAILED   ║
╚══════════════╧════════╧════════════╧══════════════╧══════════╝

RECOMMENDATION: Use method GET (L7) — highest throughput at 1.2K pps / 4.8 MB
```

### Layer 7 Attack

```
python3 start.py <method> <url> <socks_type> <threads> <proxy_file> <rpc> <duration>
python3 start.py GET https://fakeurl.com 1 100 proxies.txt 100 120
```

### Layer 4 Attack

```
python3 start.py <method> <ip:port> <threads> <duration>
python3 start.py TCP 1.2.3.4:80 100 120
```

**With proxies:**

```
python3 start.py TCP 1.2.3.4:80 100 120 <socks_type> <proxy_file>
```

**Amplification methods (MEM, NTP, DNS, CHAR, CLDAP, ARD, RDP):**

```
python3 start.py NTP 1.2.3.4:80 100 120 reflectors.txt
```

**Proxy types:** `0` = all from config, `1` = HTTP, `4` = SOCKS4, `5` = SOCKS5, `6` = random

---

## Cloudflare: Built-in Bypass Methods vs. Infrastructure Detection

BetterDoS handles Cloudflare at **two distinct levels** — it's important to understand the difference:

### 1. Bypass Methods (inherited from MHDDoS)

These are **L7 attack methods** that attempt to push traffic through Cloudflare's reverse proxy:

| Method | Strategy |
|---|---|
| **CFB** | Uses `cloudscraper` to solve Cloudflare's JS challenge, then floods with the obtained cookies/tokens. |
| **CFBUAM** | Same approach but specifically targets "Under Attack Mode" — waits out the 5-second delay, then attacks. |
| **BYPASS** | Generic anti-DDoS bypass that works against multiple providers including CF. |

These methods send traffic *through* Cloudflare and try to overwhelm the origin anyway. They work, but Cloudflare's rate limiting and bot detection can throttle them.

### 2. Infrastructure Detection (added by BetterDoS)

This is a completely different approach — instead of punching through Cloudflare, **find the origin server's real IP and bypass Cloudflare entirely**:

- **CFIP tool** — Probes subdomains (mail, ftp, cpanel, dev, etc.), MX records, and SPF/TXT entries to find IPs that aren't behind CF.
- **IP range detection** — All 22 official Cloudflare CIDR ranges (15 IPv4 + 7 IPv6) are checked automatically.
- **L4 blocking** — If the resolved IP belongs to Cloudflare, L4 attacks are **blocked** (both CLI and GUI) since L4 packets hit Cloudflare's edge, not the origin. You'll see a message directing you to use CFIP or switch to L7.
- **L7 warning** — L7 attacks show a notice but proceed, since they go through proxies.
- **ADVISE integration** — Detects CF by both HTTP headers and IP range, recommends the CFIP tool.

**The recommended workflow for Cloudflare targets:**
1. Run `ADVISE` or `AUTO` — the system detects CF automatically.
2. Run `TOOLS CFIP fakeurl.com` — discover the origin IP.
3. Attack the origin IP directly (L4) or use CFB/CFBUAM methods (L7) through the CF proxy.

**Covered ranges (22 total — 15 IPv4 + 7 IPv6):**

| IPv4 | IPv6 |
|---|---|
| 173.245.48.0/20 | 2400:cb00::/32 |
| 103.21.244.0/22 | 2606:4700::/32 |
| 103.22.200.0/22 | 2803:f800::/32 |
| 103.31.4.0/22 | 2405:b500::/32 |
| 141.101.64.0/18 | 2405:8100::/32 |
| 108.162.192.0/18 | 2a06:98c0::/29 |
| 190.93.240.0/20 | 2c0f:f248::/32 |
| 188.114.96.0/20 | |
| 197.234.240.0/22 | |
| 198.41.128.0/17 | |
| 162.158.0.0/15 | |
| 104.16.0.0/13 | |
| 104.24.0.0/14 | |
| 172.64.0.0/13 | |
| 131.0.72.0/22 | |

---

## Methods

### Layer 7 — 26 Methods

| Method | Description |
|---|---|
| GET | GET flood |
| POST | POST flood |
| HEAD | HEAD request flood |
| PPS | Minimal `GET / HTTP/1.1\r\n\r\n` |
| EVEN | GET with extended headers |
| OVH | OVH bypass |
| STRESS | High-byte HTTP packet |
| COOKIE | Random cookie flood (PHP `isset($_COOKIE)`) |
| NULL | Null User-Agent |
| DYN | Random subdomain generation |
| RHEX | Random hex payload |
| STOMP | chk_captcha bypass |
| DOWNLOADER | Slow data read |
| SLOW | Slowloris |
| BOT | Search engine bot impersonation |
| GSB | Google Project Shield bypass |
| DGB | DDoS-Guard bypass |
| AVB | ArvanCloud bypass |
| CFB | Cloudflare bypass |
| CFBUAM | Cloudflare Under-Attack-Mode bypass |
| BYPASS | Generic anti-DDoS bypass |
| APACHE | Apache range header exploit |
| XMLRPC | WordPress XML-RPC exploit |
| BOMB | Bombardier-based bypass |
| KILLER | High thread count flood |
| TOR | Onion site bypass via tor2web |

### Layer 4 — 21 Methods

| Method | Description |
|---|---|
| TCP | TCP flood |
| UDP | UDP flood |
| SYN | SYN flood |
| OVH-UDP | OVH/WAF bypass UDP flood |
| CPS | Connection-per-second (open/close with proxy) |
| ICMP | ICMP echo request flood |
| CONNECTION | Keep-alive connection flood with proxy |
| VSE | Valve Source Engine protocol |
| TS3 | TeamSpeak 3 status ping |
| FIVEM | FiveM status ping |
| FIVEM-TOKEN | FiveM token flood |
| MINECRAFT | Minecraft status ping |
| MCPE | Minecraft PE status ping |
| MCBOT | Minecraft bot attack |
| MEM | Memcached amplification |
| NTP | NTP amplification |
| DNS | DNS amplification |
| CHAR | Chargen amplification |
| CLDAP | CLDAP amplification |
| ARD | Apple Remote Desktop amplification |
| RDP | RDP amplification |

### Tools — 7 Commands

Tools are **reconnaissance utilities** — they don't send attack traffic. Run them three ways:

```bash
# 1. Interactive console (type tool names at the prompt)
python3 start.py TOOLS

# 2. Jump straight to a tool
python3 start.py TOOLS CFIP

# 3. One-shot with argument (no prompts)
python3 start.py TOOLS CFIP fakeurl.com
```

Inside the interactive console, each tool prompts for a domain/IP. Type **BACK** to return to the main prompt, or **EXIT** to quit.

| Tool | Description |
|---|---|
| CFIP | Find real IP behind Cloudflare (subdomain enum, MX, SPF parsing) |
| DNS | DNS record lookup (A, AAAA, CNAME, MX, NS, TXT, SOA) |
| INFO | IP/domain WHOIS-style info (country, city, ISP, org) |
| CHECK | HTTP status check — is the target online? |
| PING | ICMP ping (5 packets) |
| TSSRV | TeamSpeak SRV record resolver |
| DSTAT | Live network I/O + CPU/memory monitor (Ctrl-C to stop) |

### Utility Commands — 5

| Command | Description |
|---|---|
| HELP | Show full usage |
| TOOLS | Open interactive tools console |
| STOP | Stop all running attacks |
| ADVISE | Fingerprint target and recommend methods |
| AUTO | Benchmark methods and rank by throughput |

---

## Project Structure

```
betterdos/
├── __init__.py       # Package marker
├── core.py           # Shared state, constants, Methods registry, Tools utilities
├── layer7.py         # HttpFlood (26 methods) — Thread subclass
├── layer4.py         # Layer4 (21 methods) — Thread subclass
├── advisor.py        # MethodAdvisor — ADVISE and AUTO logic
├── proxy.py          # ProxyManager — download, check, load
├── console.py        # ToolsConsole — interactive tools REPL + CloudflareScanner
├── minecraft.py      # Minecraft protocol helpers
├── output.py         # Pretty output — banner, tables, progress bars
└── gui.py            # Tkinter desktop GUI
start.py              # Thin CLI entrypoint
config.json           # MCBOT prefix, protocol version, proxy providers
```

---

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MHD_DEBUG` | `0` | Set to `1` for DEBUG-level logging |
| `MHD_LOG_FILE` | *(none)* | Path to write log output to a file |

---

## Upstream Credit

This is a research fork of **[MHDDoS](https://github.com/MatrixTM/MHDDoS)** by [MatrixTM](https://github.com/MatrixTM).
Original project licensed under the [MIT License](LICENSE).

---

## Disclaimer

**For authorized testing and research only.**
Do not use against any system without explicit written permission from the owner.
Unauthorized use is illegal and unethical.
