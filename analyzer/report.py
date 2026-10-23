"""Human + machine readable analysis reports."""
import json
from collections import Counter

from .flows import build_flows, protocol_distribution, top_talkers


def summarize(packets):
    duration = 0.0
    if packets:
        duration = max(p.ts for p in packets) - min(p.ts for p in packets)
    dns_queries = [p.dns.get("qname", "") for p in packets if p.dns and p.dns.get("qr") == 0]
    tls_hosts = sorted({p.tls_sni for p in packets if p.tls_sni})
    return {
        "packets": len(packets),
        "bytes": sum(p.length for p in packets),
        "duration_sec": round(duration, 2),
        "protocols": protocol_distribution(packets),
        "top_talkers": top_talkers(packets),
        "top_dns_queries": Counter(dns_queries).most_common(10),
        "tls_sni_hosts": tls_hosts,
        "flow_count": len(build_flows(packets)),
    }


def build_report(packets, findings):
    s = summarize(packets)
    flows = build_flows(packets)
    lines = []
    lines.append("=" * 68)
    lines.append("ADVANCED NETWORK SNIFFER v2 - ANALYSIS REPORT")
    lines.append("=" * 68)
    lines.append(f"Packets: {s['packets']}   Bytes: {s['bytes']}   Duration: {s['duration_sec']}s   Flows: {s['flow_count']}")
    lines.append("")
    lines.append("-- Protocol distribution --")
    for proto, n in s["protocols"]:
        lines.append(f"  {proto:<10} {n}")
    lines.append("")
    lines.append("-- Top talkers (by bytes) --")
    for ip, b in s["top_talkers"][:5]:
        lines.append(f"  {ip:<16} {b} bytes")
    if s["top_dns_queries"]:
        lines.append("")
        lines.append("-- Top DNS queries --")
        for name, n in s["top_dns_queries"][:5]:
            lines.append(f"  {name}  x{n}")
    if s["tls_sni_hosts"]:
        lines.append("")
        lines.append("-- TLS hosts (SNI) --")
        for h in s["tls_sni_hosts"][:10]:
            lines.append(f"  {h}")
    lines.append("")
    lines.append("-- Top flows --")
    for f in flows[:5]:
        lines.append(f"  {f.proto} {f.a_ip}:{f.a_port} <-> {f.b_ip}:{f.b_port}  {f.packets} pkts, {f.bytes} bytes")
    lines.append("")
    lines.append(f"-- Security findings ({len(findings)}) --")
    if findings:
        for f in findings:
            lines.append(f"  [{f.severity}] {f.kind}: {f.detail}")
    else:
        lines.append("  No threats detected.")
    return "\n".join(lines)


def to_json(packets, findings):
    s = summarize(packets)
    flows = build_flows(packets)
    return json.dumps({
        "summary": {k: (dict(v) if k == "protocols" else v) for k, v in s.items()},
        "flows": [{"proto": f.proto, "a": f"{f.a_ip}:{f.a_port}", "b": f"{f.b_ip}:{f.b_port}",
                   "packets": f.packets, "bytes": f.bytes, "duration_sec": round(f.duration, 2)}
                  for f in flows[:50]],
        "findings": [{"severity": f.severity, "kind": f.kind, "subject": f.subject, "detail": f.detail}
                     for f in findings],
    }, indent=2)
