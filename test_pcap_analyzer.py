import subprocess
import sys
from pathlib import Path

import pytest

import pcap_analyzer as pa

HERE = Path(__file__).parent
PCAP = HERE / "attack_sample.pcap"


@pytest.fixture(scope="session", autouse=True)
def sample_pcap():
    if not PCAP.exists():
        subprocess.run([sys.executable, "generate_sample_pcap.py"], cwd=HERE, check=True)


@pytest.fixture(scope="session")
def findings():
    return pa.analyze(str(PCAP))[1]


def categories(findings):
    return [f.category for f in findings]


def test_detects_port_scan(findings):
    scan = [f for f in findings if f.category == "Port Scan"]
    assert len(scan) == 1
    assert scan[0].source == "10.0.0.66"
    assert "[21, 22, 80, 443]" in scan[0].evidence[1]


def test_detects_dns_tunneling(findings):
    dns = [f for f in findings if f.category == "DNS Tunneling"]
    assert len(dns) == 1 and dns[0].target == "evil-tunnel.xyz"


def test_benign_dns_not_flagged(findings):
    assert not any("google.com" in f.target for f in findings)


def test_detects_all_cleartext_creds(findings):
    assert categories(findings).count("Cleartext Credentials") == 3


def test_passwords_are_masked(findings):
    blob = str([f.evidence for f in findings])
    assert "Summer2024!" not in blob and "P@ssw0rd123" not in blob


def test_detects_icmp_sweep(findings):
    assert "ICMP Sweep" in categories(findings)


def test_sorted_by_severity(findings):
    order = [pa.SEVERITY_ORDER[f.severity] for f in findings]
    assert order == sorted(order)


def test_entropy():
    assert pa.shannon_entropy("aaaa") == 0
    assert pa.shannon_entropy("a8f3k2m9x7q1") > 3.5
