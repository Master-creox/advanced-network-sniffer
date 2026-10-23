![Python](https://img.shields.io/badge/Python-3.10+-blue)
![License](https://img.shields.io/badge/License-MIT-green)
![Version](https://img.shields.io/badge/Version-2.0-orange)
![Tests](https://img.shields.io/badge/Tests-14%20passing-success)
![Dependencies](https://img.shields.io/badge/Core%20dependencies-ZERO-brightgreen)

# 🚀 Advanced Network Packet Sniffer & Analyzer — v2.0

A real network analysis engine in **pure Python** — no Scapy needed for analysis.
v2 parses raw bytes itself (Ethernet → IPv4/IPv6 → TCP/UDP/ICMP/ARP → DNS, DHCP,
HTTP, **TLS SNI**), tracks flows, and runs **IDS-style threat detection** over
live traffic or any `.pcap` file from Wireshark/tcpdump.

> **What changed in v2?** v1 printed packets with Scapy. v2 is a ground-up engine:
> its own PCAP reader/writer, its own protocol dissectors, flow tracking, and
> seven explainable threat detectors — all standard library, all tested.

---

## ✨ Features

- 🔬 **Deep dissection** — Ethernet, IPv4, IPv6, ARP, TCP (flags), UDP, ICMP,
  DNS (queries + answers, compression pointers), DHCP, HTTP (method/host/path),
  **TLS ClientHello SNI extraction**
- 🌊 **Flow tracking** — bidirectional 5-tuple flows with bytes, duration, TCP state
- 🛡️ **Threat detection** (every alert explains itself):
  | Detector | Catches |
  |---|---|
  | Port scan / network scan | one host probing many ports/hosts |
  | SYN flood | SYN bursts with no completed handshakes |
  | ARP spoofing | one IP claimed by multiple MACs (MITM) |
  | DNS tunneling | long / high-entropy query labels (exfiltration) |
  | Ping sweep | ICMP echo across many hosts |
  | Beaconing | machine-regular connection intervals (C2 pattern) |
  | Suspicious ports | 4444, 1337, 31337, 6667, 23, exposed DB ports… |
- 📊 **Reports** — protocol distribution, top talkers, top flows, DNS & TLS
  summaries, security findings; text + **JSON export**
- 📡 **Live capture** — Scapy as a frame source only; frames feed the same engine
- 🧪 **14 pytest tests**, all offline, no root, no Scapy

## 🚀 Quickstart

```bash
git clone https://github.com/Master-creox/advanced-network-sniffer.git
cd advanced-network-sniffer

# 1) Instant demo - generates sample traffic with 5 attacks and detects them
python main.py demo

# 2) Analyze any capture (Wireshark/tcpdump export)
python main.py analyze capture.pcap
python main.py analyze capture.pcap --json report.json

# 3) Make your own sample capture
python tools/make_sample_pcap.py sample.pcap

# 4) Live capture (needs: pip install scapy, and admin/root)
sudo python main.py live -c 200        # Linux/macOS
python main.py live                    # Windows (admin terminal + Npcap)
```

**Demo output (excerpt):**
```
[HIGH] PORT_SCAN:     192.168.1.66 sent SYNs to 20 different ports on 192.168.1.10
[HIGH] SYN_FLOOD:     45 SYNs to 192.168.1.20:80 with almost no completed handshakes
[HIGH] ARP_SPOOF:     IP 192.168.1.1 is claimed by 2 different MAC addresses
[HIGH] DNS_TUNNELING: DNS query with a 51-char label (entropy 4.6): aGVsbG8...evil-c2.com
[MED]  BEACONING:     connected to 185.220.101.5:4444 8 times every ~10s (CV 0.00)
```

## 📁 Project Structure

```
advanced-network-sniffer/
├── main.py                  # CLI: analyze | demo | live
├── sniffer.py               # live capture (Scapy frame source)
├── analyzer/
│   ├── pcap.py              # PCAP reader/writer (zero deps)
│   ├── dissect.py           # Ethernet/IP/TCP/UDP/ICMP/ARP/DNS/DHCP/HTTP/TLS-SNI
│   ├── flows.py             # flow tracking, top talkers, protocol stats
│   ├── detect.py            # 7 threat detectors, explainable findings
│   └── report.py            # text + JSON reports
├── tools/
│   ├── packet_builder.py    # packet crafting (used by generator + tests)
│   └── make_sample_pcap.py  # sample capture: normal traffic + 5 attacks
└── tests/test_sniffer.py    # 14 tests
```

## 🧪 Tests

```bash
pip install pytest
pytest -v        # 14 passed - dissectors, detectors, flows, pcap round-trip
```

## 🗺️ Roadmap
- IPv6 extension-header walking · TCP stream reassembly
- JA3-style TLS fingerprinting · GeoIP enrichment
- Optional Isolation-Forest anomaly layer over flow features

## ⚖️ Ethics
Use only on networks you own or are authorized to test. Packet capture can
expose sensitive data — handle captures responsibly.

## 📄 License
MIT — © Akash Kumar (Master Creox) · Cybersecurity student · CreoX Tech Labs
