"""Protocol dissectors: Ethernet, IPv4/IPv6, ARP, TCP, UDP, ICMP,
DNS, DHCP, HTTP and TLS (ClientHello SNI) - all with struct, zero deps.
"""
import socket
import struct
from dataclasses import dataclass, field

TCP_FLAG_BITS = [(0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
                 (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR")]


@dataclass
class Packet:
    ts: float
    length: int
    src_mac: str = ""
    dst_mac: str = ""
    ethertype: int = 0
    protocol: str = "OTHER"          # TCP / UDP / ICMP / ARP / IGMP / IPv6 / OTHER
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    tcp_flags: frozenset = frozenset()
    icmp_type: int = -1
    payload: bytes = b""
    # layer-7 details
    dns: dict = field(default_factory=dict)      # {qr, qname, answers[], qtype}
    arp: dict = field(default_factory=dict)      # {op, sender_ip, sender_mac, target_ip}
    http: dict = field(default_factory=dict)     # {method, host, path}
    tls_sni: str = ""
    dhcp: dict = field(default_factory=dict)     # {msg_type}

    @property
    def app_protocol(self):
        if self.dns:
            return "DNS"
        if self.tls_sni:
            return "TLS"
        if self.http:
            return "HTTP"
        if self.dhcp:
            return "DHCP"
        if self.protocol == "ARP":
            return "ARP"
        return self.protocol


def _mac(raw):
    return ":".join(f"{b:02x}" for b in raw)


def dissect(ts, frame):
    """Turn one raw Ethernet frame into a Packet (best-effort, never raises)."""
    p = Packet(ts=ts, length=len(frame))
    if len(frame) < 14:
        return p
    p.dst_mac = _mac(frame[0:6])
    p.src_mac = _mac(frame[6:12])
    p.ethertype = struct.unpack("!H", frame[12:14])[0]
    body = frame[14:]
    try:
        if p.ethertype == 0x0806:
            _dissect_arp(p, body)
        elif p.ethertype == 0x0800:
            _dissect_ipv4(p, body)
        elif p.ethertype == 0x86DD:
            _dissect_ipv6(p, body)
    except Exception:
        pass  # malformed packet - keep whatever was parsed
    return p


def _dissect_arp(p, body):
    p.protocol = "ARP"
    if len(body) < 28:
        return
    _ht, _pt, _hl, _pl, op = struct.unpack("!HHBBH", body[:8])
    p.arp = {
        "op": op,  # 1=request, 2=reply
        "sender_mac": _mac(body[8:14]),
        "sender_ip": socket.inet_ntoa(body[14:18]),
        "target_mac": _mac(body[18:24]),
        "target_ip": socket.inet_ntoa(body[24:28]),
    }
    p.src_ip = p.arp["sender_ip"]
    p.dst_ip = p.arp["target_ip"]


def _dissect_ipv4(p, body):
    if len(body) < 20:
        return
    ihl = (body[0] & 0x0F) * 4
    proto = body[9]
    p.src_ip = socket.inet_ntoa(body[12:16])
    p.dst_ip = socket.inet_ntoa(body[16:20])
    payload = body[ihl:]
    _dissect_l4(p, proto, payload)


def _dissect_ipv6(p, body):
    if len(body) < 40:
        return
    nxt = body[6]
    p.src_ip = socket.inet_ntop(socket.AF_INET6, body[8:24])
    p.dst_ip = socket.inet_ntop(socket.AF_INET6, body[24:40])
    _dissect_l4(p, nxt, body[40:])


def _dissect_l4(p, proto, payload):
    if proto == 6 and len(payload) >= 20:  # TCP
        p.protocol = "TCP"
        p.src_port, p.dst_port = struct.unpack("!HH", payload[:4])
        data_off = (payload[12] >> 4) * 4
        flags = payload[13]
        p.tcp_flags = frozenset(name for bit, name in TCP_FLAG_BITS if flags & bit)
        p.payload = payload[data_off:]
        _dissect_app(p)
    elif proto == 17 and len(payload) >= 8:  # UDP
        p.protocol = "UDP"
        p.src_port, p.dst_port, _len = struct.unpack("!HHH", payload[:6])
        p.payload = payload[8:]
        _dissect_app(p)
    elif proto == 1 and len(payload) >= 2:  # ICMP
        p.protocol = "ICMP"
        p.icmp_type = payload[0]
    elif proto == 2:
        p.protocol = "IGMP"
    else:
        p.protocol = f"IP-PROTO-{proto}"


def _dissect_app(p):
    if 53 in (p.src_port, p.dst_port) and p.payload:
        p.dns = parse_dns(p.payload)
    elif p.protocol == "UDP" and (p.src_port == 68 or p.dst_port == 67) and p.payload:
        p.dhcp = parse_dhcp(p.payload)
    elif p.protocol == "TCP" and p.payload:
        if p.dst_port == 443 or p.src_port == 443 or (p.payload and p.payload[0] == 0x16):
            p.tls_sni = parse_tls_sni(p.payload)
        if p.dst_port == 80 or p.src_port == 80:
            p.http = parse_http(p.payload)


# ---------------- DNS ----------------

def _dns_name(msg, off):
    labels, jumped, seen = [], False, 0
    start = off
    while off < len(msg):
        ln = msg[off]
        if ln == 0:
            off += 1
            break
        if ln & 0xC0 == 0xC0:  # compression pointer
            if off + 1 >= len(msg):
                break
            off = ((ln & 0x3F) << 8) | msg[off + 1]
            if not jumped:
                start = off + 2 - (off - start)  # keep simple: return position after pointer below
                jumped = True
                start = None
            seen += 1
            if seen > 10:
                break
            continue
        off += 1
        labels.append(msg[off:off + ln].decode("utf-8", "replace"))
        off += ln
    return ".".join(labels)


def parse_dns(msg):
    """Parse a DNS message into {qr, qname, qtype, answers}."""
    out = {}
    if len(msg) < 12:
        return out
    _id, flags, qd, an, _ns, _ar = struct.unpack("!HHHHHH", msg[:12])
    out["qr"] = (flags >> 15) & 1
    off = 12
    if qd >= 1:
        out["qname"] = _dns_name(msg, off)
        # skip name (uncompressed walk) + qtype/qclass
        while off < len(msg) and msg[off] != 0:
            off += 1 + msg[off]
        off += 1
        if off + 4 <= len(msg):
            out["qtype"] = struct.unpack("!H", msg[off:off + 2])[0]
        off += 4
    answers = []
    for _ in range(an):
        if off >= len(msg):
            break
        if msg[off] & 0xC0 == 0xC0:
            off += 2
        else:
            while off < len(msg) and msg[off] != 0:
                off += 1 + msg[off]
            off += 1
        if off + 10 > len(msg):
            break
        rtype, _cls, _ttl, rdlen = struct.unpack("!HHIH", msg[off:off + 10])
        off += 10
        rdata = msg[off:off + rdlen]
        if rtype == 1 and rdlen == 4:  # A record
            answers.append(socket.inet_ntoa(rdata))
        off += rdlen
    out["answers"] = answers
    return out


# ---------------- DHCP ----------------

DHCP_TYPES = {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
              5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM"}


def parse_dhcp(msg):
    out = {}
    if len(msg) < 240:
        return out
    cookie = struct.unpack("!I", msg[236:240])[0]
    if cookie != 0x63825363:
        return out
    off = 240
    while off < len(msg):
        code = msg[off]
        if code == 255:
            break
        if code == 0:
            off += 1
            continue
        ln = msg[off + 1]
        if code == 53 and ln >= 1:
            out["msg_type"] = DHCP_TYPES.get(msg[off + 2], f"TYPE-{msg[off + 2]}")
        off += 2 + ln
    return out


# ---------------- HTTP ----------------

HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")


def parse_http(payload):
    out = {}
    first = payload[:8]
    if not any(first.startswith(m) for m in HTTP_METHODS):
        if payload.startswith(b"HTTP/"):
            out["response"] = True
        return out
    try:
        head = payload.split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
        lines = head.split("\r\n")
        parts = lines[0].split(" ")
        out["method"] = parts[0]
        out["path"] = parts[1] if len(parts) > 1 else ""
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                out["host"] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return out


# ---------------- TLS SNI ----------------

def parse_tls_sni(payload):
    """Extract the Server Name Indication from a TLS ClientHello."""
    try:
        if len(payload) < 9 or payload[0] != 0x16:  # handshake record
            return ""
        # TLS record: type(1) ver(2) len(2) | handshake: type(1) len(3) ver(2) random(32)
        off = 5
        if payload[off] != 0x01:  # ClientHello
            return ""
        off += 4 + 2 + 32
        sess_len = payload[off]
        off += 1 + sess_len
        cs_len = struct.unpack("!H", payload[off:off + 2])[0]
        off += 2 + cs_len
        comp_len = payload[off]
        off += 1 + comp_len
        ext_total = struct.unpack("!H", payload[off:off + 2])[0]
        off += 2
        end = min(len(payload), off + ext_total)
        while off + 4 <= end:
            etype, elen = struct.unpack("!HH", payload[off:off + 4])
            ext = payload[off + 4:off + 4 + elen]
            if etype == 0 and len(ext) >= 5:  # server_name
                name_len = struct.unpack("!H", ext[3:5])[0]
                return ext[5:5 + name_len].decode("utf-8", "replace")
            off += 4 + elen
    except Exception:
        return ""
    return ""
