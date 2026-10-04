# PCAP Threat Hunter 🔍

A Python network traffic analysis tool that parses packet captures and flags indicators of malicious activity, mapped to **MITRE ATT&CK**. Built as a hands-on SOC / blue-team lab.

![Python](https://img.shields.io/badge/Python-3.9+-blue) ![Scapy](https://img.shields.io/badge/Scapy-2.5+-green) ![Tests](https://img.shields.io/badge/tests-8%20passing-brightgreen)

## What it detects

| Detection | How | MITRE ATT&CK |
|---|---|---|
| **TCP SYN port scan** | One source sends SYNs to ≥25 distinct ports on a host; correlates SYN/ACK replies to list open ports | T1046 Network Service Discovery |
| **ICMP host sweep** | One source pings ≥10 distinct hosts | T1018 Remote System Discovery |
| **DNS tunneling / exfil** | Long subdomain labels (≥40 chars) or high Shannon entropy (≥3.5) repeated to one base domain | T1071.004 Application Layer Protocol: DNS |
| **Cleartext credentials** | FTP `USER`/`PASS`, HTTP Basic Auth headers, HTTP login form POSTs (passwords masked in output) | T1040 Network Sniffing |

## Lab scenario

`generate_sample_pcap.py` builds a reproducible synthetic capture (2,132 packets) of a small network where:

- **10.0.0.66** (attacker) runs a SYN scan of ports 1–1024 against **10.0.0.10** and an ICMP sweep of 10.0.0.1–30
- **10.0.0.25** (compromised workstation) leaks credentials over FTP/HTTP and exfiltrates data through DNS TXT queries to `evil-tunnel.xyz`
- Normal DNS lookups and HTTPS handshakes are mixed in as benign noise (and are **not** flagged)

No real hosts or credentials are used.

## Quick start

```bash
pip install -r requirements.txt
python generate_sample_pcap.py                 # creates attack_sample.pcap (deterministic, seed 1337)
python pcap_analyzer.py attack_sample.pcap --report report.md --json findings.json
pytest -q                                      # 8 tests
```

Works on any `.pcap` — e.g. captures from Wireshark/tcpdump or [Malware-Traffic-Analysis.net](https://www.malware-traffic-analysis.net/).

## Results

```
[*] 2132 packets analyzed from attack_sample.pcap
[CRITICAL] Cleartext Credentials: FTP login captured in cleartext  (T1040)
      - user=labadmin pass=S*********!
[CRITICAL] Cleartext Credentials: HTTP Basic Auth header sent over unencrypted HTTP  (T1040)
[CRITICAL] Cleartext Credentials: Login form submitted over unencrypted HTTP  (T1040)
[HIGH] Port Scan: 10.0.0.66 sent SYNs to 1024 distinct ports on 10.0.0.10  (T1046)
      - Ports that answered SYN/ACK (open): [21, 22, 80, 443]
[HIGH] DNS Tunneling: 40 long/high-entropy queries from 10.0.0.25 to *.evil-tunnel.xyz  (T1071.004)
      - Avg label length: 51.6, avg entropy: 4.58
[MEDIUM] ICMP Sweep: 10.0.0.66 sent echo requests to 30 hosts  (T1018)
[+] 6 findings
```

Full output: [`sample_output.txt`](sample_output.txt) — add `--report`/`--json` to also get a Markdown report and JSON findings.

## Analyst takeaways & recommendations

1. **Contain 10.0.0.66** — reconnaissance (scan + sweep) is typically the precursor to exploitation. Block at the firewall and investigate the host.
2. **Treat 10.0.0.25 as compromised** — DNS exfil means data is leaving. Isolate, image, and review processes making DNS requests.
3. **Rotate leaked credentials** (`labadmin`, `jdoe`, `mrivera`) and **retire FTP/HTTP** in favor of SFTP/HTTPS.
4. **Reduce attack surface on 10.0.0.10** — close unneeded services on 21/22/80.
5. **Detection engineering** — alert on DNS queries with labels > 40 chars, and enforce DNS only through internal resolvers.

## Skills demonstrated

Packet analysis · Python (Scapy) · threat detection logic · Shannon entropy · MITRE ATT&CK mapping · incident reporting · unit testing

## Roadmap

- [ ] Beaconing detection (periodic C2 callbacks)
- [ ] Threat intel enrichment (AbuseIPDB / VirusTotal lookups)
- [ ] Export to Splunk / ELK-friendly JSON lines

---
**Author:** Rakesh Rajbali · Cybersecurity, St. John's University
