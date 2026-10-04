#!/usr/bin/env python3
"""
pcap_analyzer.py - PCAP Threat Hunter
Author: Rakesh Rajbali

Parses a packet capture and flags common indicators of malicious activity:
  * TCP SYN port scans                       (MITRE ATT&CK T1046)
  * ICMP host sweeps                         (T1018)
  * DNS tunneling / exfiltration             (T1071.004, T1048)
  * Cleartext credentials (FTP, HTTP Basic,  (T1040, T1552)
    HTTP form POSTs)

Usage:
    python pcap_analyzer.py attack_sample.pcap
    python pcap_analyzer.py capture.pcap --json findings.json --report report.md
"""
import argparse
import base64
import json
import math
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass, field

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, Raw, rdpcap

# --- Detection thresholds (tune for your environment) ---------------------
PORT_SCAN_THRESHOLD = 25        # distinct dst ports from one src -> one dst
ICMP_SWEEP_THRESHOLD = 10       # distinct hosts pinged by one src
DNS_LABEL_LEN_THRESHOLD = 40    # longest subdomain label length
DNS_ENTROPY_THRESHOLD = 3.5     # Shannon entropy of the subdomain
DNS_TUNNEL_MIN_QUERIES = 10     # suspicious queries to one base domain

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


@dataclass
class Finding:
    severity: str
    category: str
    mitre: str
    source: str
    target: str
    summary: str
    evidence: list = field(default_factory=list)


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    return -sum((c / len(s)) * math.log2(c / len(s)) for c in counts.values())


def mask(secret: str) -> str:
    """Redact a credential for reporting (keep first/last char)."""
    if len(secret) <= 2:
        return "*" * len(secret)
    return secret[0] + "*" * (len(secret) - 2) + secret[-1]


# --- Detectors ------------------------------------------------------------
def detect_port_scans(packets):
    syns = defaultdict(set)
    for p in packets:
        if IP in p and TCP in p and p[TCP].flags == "S":
            syns[(p[IP].src, p[IP].dst)].add(p[TCP].dport)
    findings = []
    for (src, dst), ports in syns.items():
        if len(ports) >= PORT_SCAN_THRESHOLD:
            open_ports = sorted({
                p[TCP].sport for p in packets
                if IP in p and TCP in p and p[IP].src == dst and p[IP].dst == src
                and p[TCP].flags == "SA"
            })
            findings.append(Finding(
                "HIGH", "Port Scan", "T1046 Network Service Discovery", src, dst,
                f"{src} sent SYNs to {len(ports)} distinct ports on {dst}",
                [f"Port range: {min(ports)}-{max(ports)}",
                 f"Ports that answered SYN/ACK (open): {open_ports or 'none'}"],
            ))
    return findings


def detect_icmp_sweeps(packets):
    pings = defaultdict(set)
    for p in packets:
        if IP in p and ICMP in p and p[ICMP].type == 8:
            pings[p[IP].src].add(p[IP].dst)
    return [
        Finding("MEDIUM", "ICMP Sweep", "T1018 Remote System Discovery", src,
                f"{len(hosts)} hosts", f"{src} sent echo requests to {len(hosts)} hosts",
                [f"Sample targets: {sorted(hosts)[:5]}"])
        for src, hosts in pings.items() if len(hosts) >= ICMP_SWEEP_THRESHOLD
    ]


def detect_dns_tunneling(packets):
    suspicious = defaultdict(list)
    for p in packets:
        if IP in p and p.haslayer(DNS) and p[DNS].qr == 0 and p.haslayer(DNSQR):
            qname = p[DNSQR].qname.decode(errors="ignore").rstrip(".")
            parts = qname.split(".")
            if len(parts) < 3:
                continue
            base = ".".join(parts[-2:])
            sub = ".".join(parts[:-2])
            longest = max(len(x) for x in parts[:-2])
            if longest >= DNS_LABEL_LEN_THRESHOLD or shannon_entropy(sub) >= DNS_ENTROPY_THRESHOLD:
                suspicious[(p[IP].src, base)].append((qname, longest, shannon_entropy(sub)))
    findings = []
    for (src, base), qs in suspicious.items():
        if len(qs) >= DNS_TUNNEL_MIN_QUERIES:
            avg_len = sum(q[1] for q in qs) / len(qs)
            avg_ent = sum(q[2] for q in qs) / len(qs)
            findings.append(Finding(
                "HIGH", "DNS Tunneling", "T1071.004 Application Layer Protocol: DNS", src, base,
                f"{len(qs)} long/high-entropy queries from {src} to *.{base}",
                [f"Avg label length: {avg_len:.1f}, avg entropy: {avg_ent:.2f}",
                 f"Example: {qs[0][0][:70]}..."],
            ))
    return findings


def detect_cleartext_creds(packets):
    findings = []
    ftp_users = {}
    for p in packets:
        if not (IP in p and TCP in p and Raw in p):
            continue
        payload = bytes(p[Raw].load).decode(errors="ignore")
        src, dst, dport = p[IP].src, p[IP].dst, p[TCP].dport

        # FTP
        if dport == 21:
            m = re.match(r"USER (\S+)", payload)
            if m:
                ftp_users[(src, dst)] = m.group(1)
            m = re.match(r"PASS (\S+)", payload)
            if m:
                user = ftp_users.get((src, dst), "?")
                findings.append(Finding(
                    "CRITICAL", "Cleartext Credentials", "T1040 Network Sniffing", src, f"{dst}:21",
                    "FTP login captured in cleartext",
                    [f"user={user} pass={mask(m.group(1))}"]))

        # HTTP Basic Auth
        m = re.search(r"Authorization: Basic ([A-Za-z0-9+/=]+)", payload)
        if m:
            try:
                user, pw = base64.b64decode(m.group(1)).decode().split(":", 1)
                findings.append(Finding(
                    "CRITICAL", "Cleartext Credentials", "T1040 Network Sniffing", src, f"{dst}:{dport}",
                    "HTTP Basic Auth header sent over unencrypted HTTP",
                    [f"user={user} pass={mask(pw)}"]))
            except Exception:
                pass

        # HTTP form POST
        if payload.startswith("POST"):
            m = re.search(r"(?:user(?:name)?|login|email)=([^&\s]+).*?(?:pass(?:word)?|pwd)=([^&\s]+)",
                          payload, re.I | re.S)
            if m:
                findings.append(Finding(
                    "CRITICAL", "Cleartext Credentials", "T1040 Network Sniffing", src, f"{dst}:{dport}",
                    "Login form submitted over unencrypted HTTP",
                    [f"user={m.group(1)} pass={mask(m.group(2))}"]))
    return findings


# --- Reporting ------------------------------------------------------------
def summarize(packets):
    protos = Counter()
    talkers = Counter()
    for p in packets:
        if IP in p:
            talkers[p[IP].src] += 1
            protos["TCP" if TCP in p else "ICMP" if ICMP in p else "DNS" if p.haslayer(DNS) else "Other IP"] += 1
        else:
            protos["Non-IP"] += 1
    return {"total_packets": len(packets), "protocols": dict(protos),
            "top_talkers": talkers.most_common(5)}


def analyze(path):
    packets = rdpcap(path)
    findings = (detect_cleartext_creds(packets) + detect_port_scans(packets)
                + detect_dns_tunneling(packets) + detect_icmp_sweeps(packets))
    findings.sort(key=lambda f: SEVERITY_ORDER[f.severity])
    return summarize(packets), findings


def to_markdown(path, stats, findings):
    lines = [f"# PCAP Analysis Report: `{path}`", "",
             f"**Packets analyzed:** {stats['total_packets']}  ",
             f"**Findings:** {len(findings)}", "", "## Traffic Summary", "",
             "| Protocol | Packets |", "|---|---|"]
    lines += [f"| {k} | {v} |" for k, v in stats["protocols"].items()]
    lines += ["", "**Top talkers:** " + ", ".join(f"{ip} ({n})" for ip, n in stats["top_talkers"]), "",
              "## Findings", "", "| # | Severity | Category | MITRE ATT&CK | Source | Target |",
              "|---|---|---|---|---|---|"]
    lines += [f"| {i} | {f.severity} | {f.category} | {f.mitre} | {f.source} | {f.target} |"
              for i, f in enumerate(findings, 1)]
    for i, f in enumerate(findings, 1):
        lines += ["", f"### {i}. {f.category} ({f.severity})", "", f.summary, ""]
        lines += [f"- {e}" for e in f.evidence]
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser(description="Hunt for threats in a PCAP file.")
    ap.add_argument("pcap")
    ap.add_argument("--json", help="write findings as JSON")
    ap.add_argument("--report", help="write a Markdown report")
    args = ap.parse_args()

    stats, findings = analyze(args.pcap)

    colors = {"CRITICAL": "\033[91m", "HIGH": "\033[93m", "MEDIUM": "\033[96m", "LOW": "\033[0m"}
    print(f"\n[*] {stats['total_packets']} packets analyzed from {args.pcap}")
    print(f"[*] Protocols: {stats['protocols']}\n")
    for f in findings:
        print(f"{colors[f.severity]}[{f.severity}]\033[0m {f.category}: {f.summary}  ({f.mitre})")
        for e in f.evidence:
            print(f"      - {e}")
    print(f"\n[+] {len(findings)} findings")

    if args.json:
        with open(args.json, "w") as fh:
            json.dump({"stats": stats, "findings": [asdict(f) for f in findings]}, fh, indent=2)
    if args.report:
        with open(args.report, "w") as fh:
            fh.write(to_markdown(args.pcap, stats, findings))
    return 0 if not findings else 1


if __name__ == "__main__":
    sys.exit(main())
