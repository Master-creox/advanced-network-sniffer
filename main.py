#!/usr/bin/env python3
"""Advanced Network Sniffer v2 - CLI

  python main.py analyze capture.pcap [--json report.json]
  python main.py demo                      (generates sample traffic & analyzes it)
  python main.py live [-c COUNT]           (live capture - needs scapy + privileges)
"""
import argparse
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from analyzer import detect, dissect, pcap, report  # noqa: E402


def load_packets(path):
    return [dissect.dissect(rp.ts, rp.data) for rp in pcap.read_pcap(path)]


def cmd_analyze(args):
    packets = load_packets(args.file)
    findings = detect.run_all(packets)
    print(report.build_report(packets, findings))
    if args.json:
        with open(args.json, "w") as f:
            f.write(report.to_json(packets, findings))
        print(f"\nJSON report written to {args.json}")
    return 0


def cmd_demo(args):
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools"))
    from tools.make_sample_pcap import run as make_sample
    tmp = os.path.join(tempfile.gettempdir(), "ans_sample.pcap")
    make_sample(tmp)
    args.file = tmp
    args.json = None
    print()
    return cmd_analyze(args)


def cmd_live(args):
    import sniffer
    sniffer.start_sniffer(count=args.count)
    return 0


def main():
    ap = argparse.ArgumentParser(prog="advanced-network-sniffer", description="Advanced Network Sniffer v2")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("analyze", help="analyze a .pcap file")
    a.add_argument("file")
    a.add_argument("--json", help="also write a JSON report to this path")
    a.set_defaults(fn=cmd_analyze)
    d = sub.add_parser("demo", help="generate sample traffic (with attacks) and analyze it")
    d.set_defaults(fn=cmd_demo)
    l = sub.add_parser("live", help="live capture (requires scapy + admin/root)")
    l.add_argument("-c", "--count", type=int, default=0, help="packets to capture (0 = until Ctrl+C)")
    l.set_defaults(fn=cmd_live)
    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
