"""Test scan_server's decisions without a network, by replacing run_s_client
with a fake that returns saved outputs. This checks the hybrid probe logic
for OpenSSL 3.5+ on any machine, whatever OpenSSL version it has."""

import os

from qscan import tls_scan


def load(name):
    with open(os.path.join(os.path.dirname(__file__), "fixtures", name)) as f:
        return f.read()


CLASSIC = load("s_client_tls13_x25519.txt")
FAILED = "New, (NONE), Cipher is (NONE)\n"


def fake(replies):
    """replies maps a probe flag (or "normal") to the text it should return."""
    def run(openssl, host, port, extra_args=(), timeout=10):
        key = next((a for a in extra_args if a in replies), "normal")
        text = replies[key]
        return tls_scan.handshake_worked(text), text
    return run


TARGET = {"host": "example.org", "port": 443, "years_secret": 10, "criticality": 3}


def by_usage(findings):
    return {f.usage: f for f in findings}


def test_server_that_accepts_hybrid(monkeypatch):
    monkeypatch.setattr(tls_scan, "run_s_client",
                        fake({"normal": CLASSIC, "-groups": CLASSIC, "-tls1": FAILED, "-tls1_1": FAILED}))
    fs = by_usage(tls_scan.scan_server(TARGET, "openssl", (3, 5)))
    assert fs["key exchange"].algorithm == "X25519MLKEM768"
    assert "accepts X25519MLKEM768" in fs["key exchange"].detail
    assert "protocol" not in fs          # no old TLS accepted


def test_server_without_hybrid(monkeypatch):
    monkeypatch.setattr(tls_scan, "run_s_client",
                        fake({"normal": CLASSIC, "-groups": FAILED, "-tls1": FAILED, "-tls1_1": FAILED}))
    fs = by_usage(tls_scan.scan_server(TARGET, "openssl", (3, 5)))
    assert fs["key exchange"].algorithm == "X25519"
    assert "does NOT accept" in fs["key exchange"].detail


def test_old_openssl_cannot_test_hybrid(monkeypatch):
    monkeypatch.setattr(tls_scan, "run_s_client",
                        fake({"normal": CLASSIC, "-tls1": FAILED, "-tls1_1": FAILED}))
    fs = by_usage(tls_scan.scan_server(TARGET, "openssl", (3, 0)))
    assert "not tested" in fs["key exchange"].detail


def test_server_accepting_tls10(monkeypatch):
    monkeypatch.setattr(tls_scan, "run_s_client",
                        fake({"normal": CLASSIC, "-groups": FAILED, "-tls1": CLASSIC, "-tls1_1": FAILED}))
    fs = tls_scan.scan_server(TARGET, "openssl", (3, 5))
    assert [f.algorithm for f in fs if f.usage == "protocol"] == ["TLS1.0"]


def test_unreachable(monkeypatch):
    monkeypatch.setattr(tls_scan, "run_s_client",
                        fake({"normal": "connect:errno=111 Connection refused"}))
    fs = tls_scan.scan_server(TARGET, "openssl", (3, 5))
    assert len(fs) == 1 and fs[0].algorithm == "UNREACHABLE"
    assert fs[0].detail == "Connection refused"
