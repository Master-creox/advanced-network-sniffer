"""Generate sample.pcap: normal traffic + five attacks, for demo & testing.

    python tools/make_sample_pcap.py [output.pcap]
    python main.py analyze sample.pcap
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from analyzer.pcap import write_pcap  # noqa: E402
import packet_builder as pb  # noqa: E402

CLIENT = "192.168.1.10"
GATEWAY = "192.168.1.1"
DNS_SRV = "8.8.8.8"
ATTACKER = "192.168.1.66"
CMAC = "aa:bb:cc:dd:ee:01"


def run(path="sample.pcap"):
    frames = []
    t = 1_700_000_000.0

    def add(frame, dt=0.05):
        nonlocal t
        t += dt
        frames.append((t, frame))

    # ---- normal traffic ----
    q = pb.eth(pb.ipv4(pb.udp(pb.dns_query("www.google.com"), 53000, 53, CLIENT, DNS_SRV), 17, CLIENT, DNS_SRV), src=CMAC)
    add(q)
    r = pb.eth(pb.ipv4(pb.udp(pb.dns_query("www.google.com", qr=1, answers=["142.250.72.4"]), 53, 53000, DNS_SRV, CLIENT), 17, DNS_SRV, CLIENT), src="aa:bb:cc:dd:ee:02", dst=CMAC)
    add(r)
    add(pb.eth(pb.ipv4(pb.tcp(pb.tls_client_hello("www.google.com"), 44000, 443, CLIENT, "142.250.72.4"), 6, CLIENT, "142.250.72.4"), src=CMAC))                     # TLS SNI
    add(pb.eth(pb.ipv4(pb.tcp(pb.http_get("example.com"), 44001, 80, CLIENT, "93.184.216.34"), 6, CLIENT, "93.184.216.34"), src=CMAC))                                            # HTTP GET
    add(pb.eth(pb.ipv4(pb.icmp(b"ping", 8, CLIENT, GATEWAY), 1, CLIENT, GATEWAY), src=CMAC))                                                                                     # ping req
    add(pb.eth(pb.ipv4(pb.icmp(b"pong", 0, GATEWAY, CLIENT), 1, GATEWAY, CLIENT), src="aa:bb:cc:dd:ee:02", dst=CMAC))                                                             # ping reply
    add(pb.eth(pb.arp(1, GATEWAY, "aa:bb:cc:dd:ee:02", CLIENT), 0x0806, src="aa:bb:cc:dd:ee:02"))                                                                                 # ARP request

    # ---- attack 1: port scan (20 ports) ----
    for i, port in enumerate(range(20, 40)):
        add(pb.eth(pb.ipv4(pb.tcp(b"", 40000 + i, port, ATTACKER, CLIENT, flags=0x02), 6, ATTACKER, CLIENT),
                   src="aa:bb:cc:dd:ee:66"), 0.01)

    # ---- attack 2: ARP spoof (gateway IP claimed by attacker MAC) ----
    for _ in range(2):
        add(pb.eth(pb.arp(2, GATEWAY, "aa:bb:cc:dd:ee:66", CLIENT, CMAC), 0x0806, src="aa:bb:cc:dd:ee:66"), 0.02)

    # ---- attack 3: DNS tunneling ----
    tunnel = "aGVsbG8tdGhpcyBpcyBzZWNyZXQgZGF0YSBleGZpbHRyYXRpb24.data.evil-c2.com"
    add(pb.eth(pb.ipv4(pb.udp(pb.dns_query(tunnel), 53100, 53, CLIENT, DNS_SRV), 17, CLIENT, DNS_SRV), src=CMAC), 0.02)

    # ---- attack 4: SYN flood (45 SYNs, no handshakes) ----
    for i in range(45):
        add(pb.eth(pb.ipv4(pb.tcp(b"", 30000 + i, 80, f"203.0.113.{i % 40 + 1}", "192.168.1.20", flags=0x02),
                           6, f"203.0.113.{i % 40 + 1}", "192.168.1.20"), src="aa:bb:cc:dd:ee:77"), 0.005)

    # ---- attack 5: beaconing (8 SYNs, exactly every 10s) ----
    for i in range(8):
        frames.append((t + 1 + i * 10, pb.eth(pb.ipv4(pb.tcp(b"", 45000, 4444, CLIENT, "185.220.101.5", flags=0x02),
                                                       6, CLIENT, "185.220.101.5"), src=CMAC)))

    write_pcap(path, frames)
    print(f"wrote {path}: {len(frames)} packets (normal traffic + port scan, ARP spoof, DNS tunneling, SYN flood, beaconing)")


if __name__ == "__main__":
    run(sys.argv[1] if len(sys.argv) > 1 else "sample.pcap")
