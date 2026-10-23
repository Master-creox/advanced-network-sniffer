"""v2 test-suite: dissectors, detectors, flows, pcap round-trip.
All packets are crafted in-memory (tools/packet_builder) - no root, no Scapy.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools"))

import packet_builder as pb  # noqa: E402
from analyzer import detect, dissect, flows, pcap  # noqa: E402

C = "192.168.1.10"
CMAC = "aa:bb:cc:dd:ee:01"


def d(frame, ts=1000.0):
    return dissect.dissect(ts, frame)


def tcp_pkt(sport=12345, dport=80, src=C, dst="8.8.8.8", flags=0x02, payload=b"", ts=1000.0):
    return d(pb.eth(pb.ipv4(pb.tcp(payload, sport, dport, src, dst, flags=flags), 6, src, dst), src=CMAC), ts)


# ---------- dissectors ----------
def test_tcp_flags_and_ports():
    p = tcp_pkt(sport=4433, dport=443, flags=0x12)
    assert p.protocol == "TCP" and p.src_port == 4433 and p.dst_port == 443
    assert p.tcp_flags == frozenset({"SYN", "ACK"})


def test_dns_query_and_response():
    q = d(pb.eth(pb.ipv4(pb.udp(pb.dns_query("example.com"), 53000, 53, C, "8.8.8.8"), 17, C, "8.8.8.8"), src=CMAC))
    assert q.app_protocol == "DNS" and q.dns["qname"] == "example.com" and q.dns["qr"] == 0
    r = d(pb.eth(pb.ipv4(pb.udp(pb.dns_query("example.com", qr=1, answers=["1.2.3.4"]), 53, 53000, "8.8.8.8", C), 17, "8.8.8.8", C), src=CMAC))
    assert r.dns["qr"] == 1 and r.dns["answers"] == ["1.2.3.4"]


def test_tls_sni():
    p = tcp_pkt(dport=443, dst="142.250.72.4", payload=pb.tls_client_hello("www.google.com"))
    assert p.tls_sni == "www.google.com" and p.app_protocol == "TLS"


def test_http_parse():
    p = tcp_pkt(dport=80, payload=pb.http_get("example.com", "/a"))
    assert p.http["method"] == "GET" and p.http["host"] == "example.com" and p.http["path"] == "/a"


def test_arp_parse():
    p = d(pb.eth(pb.arp(2, "192.168.1.1", "aa:bb:cc:dd:ee:02", C, CMAC), 0x0806, src="aa:bb:cc:dd:ee:02"))
    assert p.protocol == "ARP" and p.arp["sender_ip"] == "192.168.1.1" and p.arp["op"] == 2


def test_icmp_parse():
    p = d(pb.eth(pb.ipv4(pb.icmp(b"x", 8, C, "8.8.8.8"), 1, C, "8.8.8.8"), src=CMAC))
    assert p.protocol == "ICMP" and p.icmp_type == 8


# ---------- flows ----------
def test_flow_aggregation():
    pkts = [tcp_pkt(sport=1000, dport=80, flags=0x02, ts=1.0),
            tcp_pkt(sport=80, dport=1000, src="8.8.8.8", dst=C, flags=0x12, ts=1.5)]
    fs = flows.build_flows(pkts)
    assert len(fs) == 1 and fs[0].packets == 2 and fs[0].syn == 1 and fs[0].syn_ack == 1


def test_pcap_roundtrip(tmp_path):
    path = str(tmp_path / "t.pcap")
    frame = pb.eth(pb.ipv4(pb.tcp(b"", 1, 2, C, "8.8.8.8"), 6, C, "8.8.8.8"), src=CMAC)
    pcap.write_pcap(path, [(123.5, frame)])
    got = list(pcap.read_pcap(path))
    assert len(got) == 1 and got[0].data == frame and abs(got[0].ts - 123.5) < 0.001


# ---------- detectors ----------
def test_port_scan_detected_and_benign_ignored():
    scan = [tcp_pkt(sport=40000 + i, dport=1000 + i, src="10.0.0.9", ts=1000 + i * 0.01) for i in range(20)]
    assert any(f.kind == "PORT_SCAN" for f in detect.detect_port_scan(scan))
    benign = [tcp_pkt(sport=40000 + i, dport=443, ts=1000 + i) for i in range(3)]
    assert detect.detect_port_scan(benign) == []


def test_syn_flood():
    flood = [tcp_pkt(sport=30000 + i, dport=80, src=f"203.0.113.{i % 30}", dst="192.168.1.20", ts=1000 + i * 0.01) for i in range(45)]
    assert any(f.kind == "SYN_FLOOD" for f in detect.detect_syn_flood(flood))


def test_arp_spoof():
    pkts = [d(pb.eth(pb.arp(2, "192.168.1.1", "aa:bb:cc:dd:ee:02", C, CMAC), 0x0806)),
            d(pb.eth(pb.arp(2, "192.168.1.1", "aa:bb:cc:dd:ee:66", C, CMAC), 0x0806))]
    assert any(f.kind == "ARP_SPOOF" for f in detect.detect_arp_spoof(pkts))


def test_dns_tunneling():
    name = "aGVsbG8tdGhpcyBpcyBzZWNyZXQgZGF0YSBleGZpbA.data.evil.com"
    pkts = [d(pb.eth(pb.ipv4(pb.udp(pb.dns_query(name), 53100, 53, C, "8.8.8.8"), 17, C, "8.8.8.8"), src=CMAC))]
    assert any(f.kind == "DNS_TUNNELING" for f in detect.detect_dns_tunneling(pkts))
    benign = [d(pb.eth(pb.ipv4(pb.udp(pb.dns_query("www.google.com"), 53100, 53, C, "8.8.8.8"), 17, C, "8.8.8.8"), src=CMAC))]
    assert detect.detect_dns_tunneling(benign) == []


def test_beaconing():
    pkts = [tcp_pkt(sport=45000, dport=8443, dst="185.220.101.5", ts=1000 + i * 30) for i in range(8)]
    assert any(f.kind == "BEACONING" for f in detect.detect_beaconing(pkts))
    jitter = [tcp_pkt(sport=45000, dport=8443, dst="185.220.101.5", ts=1000 + i * i * 7) for i in range(8)]
    assert detect.detect_beaconing(jitter) == []


def test_ping_sweep():
    pkts = [d(pb.eth(pb.ipv4(pb.icmp(b"", 8, "10.0.0.9", f"10.0.0.{i}"), 1, "10.0.0.9", f"10.0.0.{i}"), src=CMAC)) for i in range(1, 13)]
    assert any(f.kind == "PING_SWEEP" for f in detect.detect_ping_sweep(pkts))
