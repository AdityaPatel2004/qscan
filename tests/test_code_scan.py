"""The code scanner must find every planted weak call with the right file and line."""

import os

from qscan import code_scan

SAMPLES = os.path.join(os.path.dirname(__file__), "..", "samples")


def found():
    return {(os.path.basename(f.location.rsplit(":", 1)[0]), int(f.location.rsplit(":", 1)[1]),
             f.algorithm) for f in code_scan.scan_folder(SAMPLES)}


def test_python_planted_calls():
    hits = found()
    assert ("weak_python.py", 9, "MD5") in hits
    assert ("weak_python.py", 13, "RSA") in hits
    assert ("weak_python.py", 17, "AES-ECB") in hits


def test_c_planted_calls():
    hits = found()
    assert ("weak_c.c", 6, "SHA-1") in hits
    assert ("weak_c.c", 10, "AES-ECB") in hits
    assert ("weak_c.c", 14, "EC") in hits


def test_java_planted_calls():
    hits = found()
    assert ("Weak.java", 8, "AES-ECB") in hits
    assert ("Weak.java", 9, "RSA") in hits


def test_safe_calls_not_reported():
    algos = {a for _, _, a in found()}
    assert "SHA-256" not in algos


def test_known_limits_behave_as_documented():
    hits = {(n, line) for n, line, _ in found() if n == "known_limits.py"}
    assert ("known_limits.py", 7) not in hits    # the alias is missed
    assert ("known_limits.py", 12) in hits       # the printed text is a false alarm
