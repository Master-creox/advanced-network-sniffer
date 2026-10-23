"""Live capture for Advanced Network Sniffer v2.

Uses Scapy only as a frame source; every frame is fed as raw bytes into the
same pure-Python engine that powers PCAP analysis - so live mode and offline
mode always agree. Requires admin/root (Windows: Npcap + admin terminal).
"""
import time
from datetime import datetime

from analyzer import detect, dissect, report


def start_sniffer(count=0):
    try:
        from scapy.all import sniff
    except ImportError:
        print("Live capture needs Scapy:  pip install scapy")
        print("Offline analysis works without it:  python main.py analyze capture.pcap")
        return
    packets = []

    def _cb(pkt):
        try:
            raw = bytes(pkt)
        except Exception:
            return
        p = dissect.dissect(time.time(), raw)
        packets.append(p)
        extra = ""
        if p.dns and p.dns.get("qr") == 0:
            extra = f"  DNS query: {p.dns.get('qname', '')}"
        elif p.tls_sni:
            extra = f"  TLS SNI: {p.tls_sni}"
        elif p.http:
            extra = f"  HTTP {p.http.get('method', '')} {p.http.get('host', '')}{p.http.get('path', '')}"
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {p.app_protocol:<5} "
              f"{p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}  {p.length}B{extra}")

    print("Starting Advanced Network Sniffer v2 (live) - Ctrl+C to stop")
    try:
        sniff(prn=_cb, store=False, count=count)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        print("\nPermission denied: live capture needs admin/root privileges.")
        return
    if packets:
        print("\n" + report.build_report(packets, detect.run_all(packets)))


if __name__ == "__main__":
    start_sniffer()
