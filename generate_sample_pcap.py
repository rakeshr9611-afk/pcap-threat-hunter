#!/usr/bin/env python3
"""
generate_sample_pcap.py
Builds a synthetic PCAP containing benign traffic mixed with simulated attack
activity so the analyzer can be tested safely and reproducibly.

Simulated scenarios:
  1. TCP SYN port scan        (10.0.0.66 -> 10.0.0.10, ports 1-1024)
  2. DNS tunneling / exfil    (long, high-entropy subdomains to evil-tunnel.xyz)
  3. Cleartext credentials    (FTP USER/PASS and HTTP Basic Auth)
  4. ICMP sweep               (10.0.0.66 pinging 10.0.0.1-30)
  5. Benign background        (normal DNS lookups + HTTPS handshakes)

No real hosts or real credentials are used.
"""
import base64
import random
import string

from scapy.all import DNS, DNSQR, ICMP, IP, TCP, UDP, Raw, wrpcap

random.seed(1337)

ATTACKER = "10.0.0.66"
VICTIM = "10.0.0.10"
WORKSTATION = "10.0.0.25"
DNS_SERVER = "10.0.0.2"

packets = []
t = 1_700_000_000.0  # fixed base timestamp for reproducible output


def add(pkt, gap=0.01):
    global t
    t += gap
    pkt.time = t
    packets.append(pkt)


# --- 5. Benign background traffic -----------------------------------------
for domain in ["google.com", "github.com", "stjohns.edu", "microsoft.com", "cloudflare.com"]:
    add(IP(src=WORKSTATION, dst=DNS_SERVER) / UDP(sport=random.randint(40000, 60000), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=domain)), gap=0.5)
    add(IP(src=WORKSTATION, dst="142.250.80.46") / TCP(sport=random.randint(40000, 60000), dport=443, flags="S"))

# --- 1. SYN port scan ----------------------------------------------------
for port in range(1, 1025):
    add(IP(src=ATTACKER, dst=VICTIM) / TCP(sport=54321, dport=port, flags="S"), gap=0.002)
    if port in (21, 22, 80, 443):
        add(IP(src=VICTIM, dst=ATTACKER) / TCP(sport=port, dport=54321, flags="SA"), gap=0.001)
    else:
        add(IP(src=VICTIM, dst=ATTACKER) / TCP(sport=port, dport=54321, flags="RA"), gap=0.001)

# --- 4. ICMP sweep -------------------------------------------------------
for host in range(1, 31):
    add(IP(src=ATTACKER, dst=f"10.0.0.{host}") / ICMP(type=8), gap=0.005)

# --- 3. Cleartext credentials -------------------------------------------
ftp = IP(src=WORKSTATION, dst=VICTIM) / TCP(sport=50111, dport=21, flags="PA")
add(ftp / Raw(load=b"USER labadmin\r\n"), gap=0.2)
add(ftp / Raw(load=b"PASS Summer2024!\r\n"), gap=0.2)

basic = base64.b64encode(b"jdoe:P@ssw0rd123").decode()
http_req = (
    "GET /admin HTTP/1.1\r\n"
    "Host: intranet.lab.local\r\n"
    f"Authorization: Basic {basic}\r\n"
    "User-Agent: Mozilla/5.0\r\n\r\n"
).encode()
add(IP(src=WORKSTATION, dst=VICTIM) / TCP(sport=50222, dport=80, flags="PA") / Raw(load=http_req), gap=0.3)

http_post = (
    "POST /login HTTP/1.1\r\nHost: intranet.lab.local\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n\r\n"
    "username=mrivera&password=Winter2025"
).encode()
add(IP(src=WORKSTATION, dst=VICTIM) / TCP(sport=50223, dport=80, flags="PA") / Raw(load=http_post), gap=0.3)

# --- 2. DNS tunneling ----------------------------------------------------
for _ in range(40):
    chunk = "".join(random.choices(string.ascii_lowercase + string.digits, k=random.randint(45, 60)))
    add(IP(src=WORKSTATION, dst=DNS_SERVER) / UDP(sport=random.randint(40000, 60000), dport=53)
        / DNS(rd=1, qd=DNSQR(qname=f"{chunk}.evil-tunnel.xyz", qtype="TXT")), gap=0.05)

if __name__ == "__main__":
    out = "attack_sample.pcap"
    wrpcap(out, packets)
    print(f"[+] Wrote {len(packets)} packets to {out}")
