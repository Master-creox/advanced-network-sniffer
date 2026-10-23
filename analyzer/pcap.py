"""Minimal PCAP reader/writer (libpcap format, Ethernet linktype).

Pure standard library - lets the analyzer work on any capture file
(Wireshark/tcpdump exports) with zero third-party dependencies.
"""
import struct
from dataclasses import dataclass

PCAP_MAGIC = 0xA1B2C3D4


@dataclass
class RawPacket:
    ts: float          # epoch seconds (float)
    data: bytes        # full Ethernet frame


def read_pcap(path):
    """Yield RawPacket objects from a .pcap file."""
    with open(path, "rb") as f:
        blob = f.read()
    if len(blob) < 24:
        raise ValueError("file too small to be a pcap")
    magic = struct.unpack("<I", blob[:4])[0]
    if magic == PCAP_MAGIC:
        endian = "<"
    elif struct.unpack(">I", blob[:4])[0] == PCAP_MAGIC:
        endian = ">"
    else:
        raise ValueError("not a pcap file (bad magic)")
    # global header: magic, ver_major, ver_minor, thiszone, sigfigs, snaplen, network
    off = 24
    while off + 16 <= len(blob):
        ts_sec, ts_usec, incl, _orig = struct.unpack(endian + "IIII", blob[off:off + 16])
        off += 16
        frame = blob[off:off + incl]
        off += incl
        if len(frame) < incl:
            break
        yield RawPacket(ts=ts_sec + ts_usec / 1e6, data=frame)


def write_pcap(path, packets):
    """Write an iterable of (ts, frame_bytes) to a pcap file."""
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, 65535, 1))  # LINKTYPE_ETHERNET
        for ts, frame in packets:
            sec = int(ts)
            usec = int((ts - sec) * 1e6)
            f.write(struct.pack("<IIII", sec, usec, len(frame), len(frame)))
            f.write(frame)
