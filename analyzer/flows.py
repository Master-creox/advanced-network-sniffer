"""Flow tracking: aggregate packets into bidirectional 5-tuple flows."""
from collections import defaultdict
from dataclasses import dataclass, field


@dataclass
class Flow:
    proto: str
    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn: int = 0
    syn_ack: int = 0
    rst: int = 0
    fin: int = 0

    @property
    def duration(self):
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def key(self):
        return (self.proto, self.a_ip, self.a_port, self.b_ip, self.b_port)


def _canon(p):
    a = (p.src_ip, p.src_port)
    b = (p.dst_ip, p.dst_port)
    return (a, b) if a <= b else (b, a)


def build_flows(packets):
    flows = {}
    for p in packets:
        if p.protocol not in ("TCP", "UDP") or not p.src_ip:
            continue
        (a_ip, a_port), (b_ip, b_port) = _canon(p)
        key = (p.protocol, a_ip, a_port, b_ip, b_port)
        f = flows.get(key)
        if f is None:
            f = Flow(proto=p.protocol, a_ip=a_ip, a_port=a_port, b_ip=b_ip, b_port=b_port,
                     first_ts=p.ts, last_ts=p.ts)
            flows[key] = f
        f.packets += 1
        f.bytes += p.length
        f.first_ts = min(f.first_ts, p.ts)
        f.last_ts = max(f.last_ts, p.ts)
        if "SYN" in p.tcp_flags and "ACK" not in p.tcp_flags:
            f.syn += 1
        if "SYN" in p.tcp_flags and "ACK" in p.tcp_flags:
            f.syn_ack += 1
        if "RST" in p.tcp_flags:
            f.rst += 1
        if "FIN" in p.tcp_flags:
            f.fin += 1
    return sorted(flows.values(), key=lambda f: f.bytes, reverse=True)


def top_talkers(packets, n=10):
    sent = defaultdict(int)
    recv = defaultdict(int)
    for p in packets:
        if p.src_ip:
            sent[p.src_ip] += p.length
        if p.dst_ip:
            recv[p.dst_ip] += p.length
    total = {ip: sent[ip] + recv[ip] for ip in set(sent) | set(recv)}
    return sorted(total.items(), key=lambda kv: kv[1], reverse=True)[:n]


def protocol_distribution(packets):
    dist = defaultdict(int)
    for p in packets:
        dist[p.app_protocol] += 1
    return sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
