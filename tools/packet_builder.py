"""Packet crafting helpers (pure struct) - used by the sample-traffic
generator and by the test-suite, so everything runs without Scapy/root.
"""
import socket
import struct


def _checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) + data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_bytes(mac):
    return bytes(int(x, 16) for x in mac.split(":"))


def eth(payload, ethertype=0x0800, src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02"):
    return _mac_bytes(dst) + _mac_bytes(src) + struct.pack("!H", ethertype) + payload


def ipv4(payload, proto, src="192.168.1.10", dst="8.8.8.8", ident=1):
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0, 64, proto, 0)
    hdr += socket.inet_aton(src) + socket.inet_aton(dst)
    csum = _checksum(hdr)
    hdr = struct.pack("!BBHHHBBH", 0x45, 0, total, ident, 0, 64, proto, csum)
    hdr += socket.inet_aton(src) + socket.inet_aton(dst)
    return hdr + payload


def tcp(payload=b"", sport=12345, dport=80, src="192.168.1.10", dst="8.8.8.8",
        flags=0x18, seq=1, ack=1):
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(hdr) + len(payload))
    csum = _checksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 65535, csum, 0)
    return hdr + payload


def udp(payload=b"", sport=12345, dport=53, src="192.168.1.10", dst="8.8.8.8"):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, length)
    csum = _checksum(pseudo + hdr + payload)
    return struct.pack("!HHHH", sport, dport, length, csum) + payload


def icmp(payload=b"", itype=8, src="192.168.1.10", dst="8.8.8.8"):
    hdr = struct.pack("!BBHHH", itype, 0, 0, 1, 1)
    csum = _checksum(hdr + payload)
    return struct.pack("!BBHHH", itype, 0, csum, 1, 1) + payload


def dns_query(qname="example.com", qtype=1, qr=0, answers=()):
    def enc(name):
        out = b""
        for label in name.split("."):
            out += bytes([len(label)]) + label.encode()
        return out + b"\x00"
    flags = 0x8180 if qr else 0x0100
    msg = struct.pack("!HHHHHH", 0x1234, flags, 1, len(answers), 0, 0)
    msg += enc(qname) + struct.pack("!HH", qtype, 1)
    for ip in answers:
        msg += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 300, 4) + socket.inet_aton(ip)
    return msg


def arp(op=1, sender_ip="192.168.1.1", sender_mac="aa:bb:cc:dd:ee:01",
        target_ip="192.168.1.10", target_mac="00:00:00:00:00:00"):
    body = struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
    body += _mac_bytes(sender_mac) + socket.inet_aton(sender_ip)
    body += _mac_bytes(target_mac) + socket.inet_aton(target_ip)
    return body


def http_get(host="example.com", path="/index.html"):
    return (f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\n\r\n").encode()


def tls_client_hello(sni="www.google.com"):
    # server_name extension
    name = sni.encode()
    sni_entry = b"\x00" + struct.pack("!H", len(name)) + name
    sni_list = struct.pack("!H", len(sni_entry)) + sni_entry
    ext = struct.pack("!HH", 0, len(sni_list)) + sni_list
    ext_block = struct.pack("!H", len(ext)) + ext
    body = b"\x03\x03" + b"\x11" * 32          # version + random
    body += b"\x00"                             # session id len
    body += struct.pack("!H", 2) + b"\x13\x01"  # cipher suites
    body += b"\x01\x00"                         # compression
    body += ext_block
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake
    return record
