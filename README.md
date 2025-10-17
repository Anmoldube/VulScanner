VulnScanner Full Bundle (C/C++ backend + Lua scripting + Qt frontend)

Features:
- Async TCP scanner using Boost.Asio
- UDP probe + pcap sniffer skeleton (requires libpcap and elevated privileges)
- NVD API integration stub via libcurl and local JSON cache
- Lua bindings exposing scanning and CVE lookup functions
- Scanner runner (runs Lua scripts embedding the scanner)
- Qt frontend (simple) that runs Lua scripts and shows output
- Example Lua scripts in scripts/

Build prerequisites (Linux/Debian/Kali):
  sudo apt update
  sudo apt install -y build-essential cmake libboost-all-dev qtbase5-dev libpcap-dev libcurl4-openssl-dev liblua5.3-dev lua5.3

Build:
  mkdir build && cd build
  cmake ..
  cmake --build . --parallel

Run controller (example):
  ./backend/scanner_runner ../scripts/example_scan.lua 127.0.0.1

Run GUI (example):
  ./frontend/vuln_gui   # from build/frontend or adjust path

Notes:
- pcap/sniffing requires elevated privileges (sudo) on Linux/macOS; on Windows, run as Administrator and install NPCAP.
- NVD integration requires an API key for live queries; the code includes a stub that can be extended.
- Use only on authorized targets.
