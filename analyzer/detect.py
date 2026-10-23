"""Threat detection over dissected packets.

Each detector returns Finding objects with a plain-language explanation -
the same philosophy as a real IDS: an alert you cannot explain is noise.
"""
import math
import statistics
from collections import defaultdict
from dataclasses import dataclass


@dataclass
class Finding:
    severity: str   # HIGH / MEDIUM / LOW
    kind: str
    subject: str
    detail: str


SUSPICIOUS_PORTS = {4444: "Metasploit default listener", 1337: "common backdoor port",
                    31337: "Back Orifice / 'elite' trojan port", 6667: "IRC (botnet C2 classic)",
                    5555: "Android ADB exposed", 23: "Telnet (cleartext, legacy)",
                    2323: "Telnet alternate (IoT botnets)", 6379: "Redis (often unauthenticated)",
                    27017: "MongoDB (often unauthenticated)"}


def detect_port_scan(packets, port_threshold=15, host_threshold=15):
    out = []
    ports = defaultdict(set)
    hosts = defaultdict(set)
    for p in packets:
        if p.protocol == "TCP" and "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags:
            ports[(p.src_ip, p.dst_ip)].add(p.dst_port)
            hosts[p.src_ip].add(p.dst_ip)
    for (src, dst), ps in ports.items():
        if len(ps) >= port_threshold:
            out.append(Finding("HIGH", "PORT_SCAN", src,
                               f"{src} sent SYNs to {len(ps)} different ports on {dst} - classic port scan"))
    for src, hs in hosts.items():
        if len(hs) >= host_threshold:
            out.append(Finding("HIGH", "NETWORK_SCAN", src,
                               f"{src} probed {len(hs)} different hosts - network discovery scan"))
    return out


def detect_syn_flood(packets, ratio=4.0, min_syns=40):
    syns = defaultdict(int)
    synacks = defaultdict(int)
    for p in packets:
        if p.protocol != "TCP":
            continue
        if "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags:
            syns[(p.dst_ip, p.dst_port)] += 1
        if "SYN" in p.tcp_flags and "ACK" in p.tcp_flags:
            synacks[(p.src_ip, p.src_port)] += 1
    out = []
    for (ip, port), n in syns.items():
        if n >= min_syns and n > ratio * max(1, synacks.get((ip, port), 0)):
            out.append(Finding("HIGH", "SYN_FLOOD", ip,
                               f"{n} SYNs to {ip}:{port} with almost no completed handshakes - possible SYN flood / spoofed sources"))
    return out


def detect_arp_spoof(packets):
    claims = defaultdict(set)
    gratuitous = defaultdict(int)
    for p in packets:
        if p.protocol == "ARP" and p.arp:
            claims[p.arp["sender_ip"]].add(p.arp["sender_mac"])
            if p.arp["sender_ip"] == p.arp["target_ip"]:
                gratuitous[p.arp["sender_ip"]] += 1
    out = []
    for ip, macs in claims.items():
        if len(macs) > 1:
            out.append(Finding("HIGH", "ARP_SPOOF", ip,
                               f"IP {ip} is claimed by {len(macs)} different MAC addresses ({', '.join(sorted(macs))}) - ARP spoofing / MITM indicator"))
    for ip, n in gratuitous.items():
        if n >= 5:
            out.append(Finding("MEDIUM", "ARP_GRATUITOUS", ip,
                               f"{n} gratuitous ARPs for {ip} - can indicate spoofing or a misconfigured host"))
    return out


def _entropy(s):
    if not s:
        return 0.0
    freq = defaultdict(int)
    for c in s:
        freq[c] += 1
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in freq.values())


def detect_dns_tunneling(packets, len_threshold=40):
    out = []
    seen = set()
    for p in packets:
        if not p.dns or p.dns.get("qr") != 0:
            continue
        qname = p.dns.get("qname", "")
        labels = qname.split(".")
        longest = max((len(l) for l in labels), default=0)
        ent = _entropy(labels[0]) if labels else 0.0
        key = (p.src_ip, qname)
        if key in seen:
            continue
        if longest >= len_threshold or (longest >= 25 and ent >= 4.2):
            seen.add(key)
            out.append(Finding("HIGH", "DNS_TUNNELING", p.src_ip,
                               f"DNS query with a {longest}-char label (entropy {ent:.1f}): {qname[:70]} - data exfiltration via DNS indicator"))
    return out


def detect_ping_sweep(packets, host_threshold=10):
    targets = defaultdict(set)
    for p in packets:
        if p.protocol == "ICMP" and p.icmp_type == 8:
            targets[p.src_ip].add(p.dst_ip)
    return [Finding("MEDIUM", "PING_SWEEP", src,
                    f"{src} sent ICMP echo requests to {len(hs)} different hosts - ping sweep")
            for src, hs in targets.items() if len(hs) >= host_threshold]


def detect_suspicious_ports(packets):
    seen = {}
    for p in packets:
        for port in (p.dst_port, p.src_port):
            if port in SUSPICIOUS_PORTS:
                seen.setdefault((p.src_ip, p.dst_ip, port), SUSPICIOUS_PORTS[port])
    return [Finding("MEDIUM", "SUSPICIOUS_PORT", f"{s}->{d}",
                    f"traffic on port {port} ({why}) between {s} and {d}")
            for (s, d, port), why in seen.items()]


def detect_beaconing(packets, min_contacts=6, cv_threshold=0.15):
    """Regular-interval connections to the same host:port = C2 beacon pattern."""
    times = defaultdict(list)
    for p in packets:
        if p.protocol == "TCP" and "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags:
            times[(p.src_ip, p.dst_ip, p.dst_port)].append(p.ts)
    out = []
    for (src, dst, port), ts in times.items():
        if len(ts) < min_contacts:
            continue
        ts.sort()
        intervals = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0]
        if len(intervals) < min_contacts - 1:
            continue
        mean = statistics.mean(intervals)
        if mean <= 0:
            continue
        cv = statistics.pstdev(intervals) / mean
        if cv < cv_threshold:
            out.append(Finding("MEDIUM", "BEACONING", src,
                               f"{src} connected to {dst}:{port} {len(ts)} times every ~{mean:.0f}s with very regular timing (CV {cv:.2f}) - C2 beaconing pattern"))
    return out


ALL_DETECTORS = [detect_port_scan, detect_syn_flood, detect_arp_spoof,
                 detect_dns_tunneling, detect_ping_sweep,
                 detect_suspicious_ports, detect_beaconing]


def run_all(packets):
    findings = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(packets))
    order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    return sorted(findings, key=lambda f: order.get(f.severity, 3))
