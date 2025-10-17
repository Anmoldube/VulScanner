# 🔍 VulnScannerFull

**VulnScannerFull** is a modular vulnerability scanning suite that combines a **C++ backend**, **Lua scripting engine**, and a **Qt-based frontend GUI** for interactive vulnerability detection and reporting.

It’s designed for educational and authorized security testing — providing an extendable environment where users can write **Lua scripts** to perform network scans, capture packets, and fetch vulnerability data from NVD (CVE database).

---

## 🧩 Architecture Overview

### 1. Backend (`/backend`)
The backend is written in modern **C++17** and powered by:
- **Boost.Asio** — for asynchronous TCP/UDP scanning.
- **libpcap** — for packet sniffing.
- **libcurl** — for NVD (CVE) API integration.
- **Lua 5.3** — for script execution and extending functionality.

#### Core Features:
- Asynchronous **TCP port scanner**.
- **UDP probe and sniffer** using libpcap.
- **Lua bindings** for scripting and automation.
- **NVD API stub** for vulnerability lookups.
- **Scanner Runner** CLI (`scanner_runner`) to execute Lua scripts.

### 2. Lua Scripting (`/scripts`)
Lua scripts define how scans are performed and how results are handled.  
They can:
- Launch scans via `scanner.tcp_scan()` or `scanner.udp_probe()`.
- Register callbacks to process results.
- Perform **banner analysis** and **CVE lookups** via `nvd.lookup()`.

Example script usage:
```bash
./backend/scanner_runner ../scripts/example_scan.lua 127.0.0.1
