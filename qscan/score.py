"""
score.py - decide what to fix first.

Plain picture: Mosca's rule asks "are we already late?"
    X = years the data must stay secret      (per target, from targets.json)
    Y = years the migration will take        (setting, default 3)
    Z = years until a quantum computer       (setting, default 10 - an ASSUMPTION)
If X + Y > Z, recorded traffic will still matter when it can be broken,
so the key exchange protecting it is already late.

Priority rule (small enough to check by hand):
    1  Broken today, or vulnerable key exchange with X + Y > Z
    2  Vulnerable key exchange with X + Y <= Z,
       or vulnerable signature on a criticality-3 system
    3  Other vulnerable signatures, Weakened (AES-128), Unknown
    4  Quantum-safe, no action
    0  Unreachable (not scored)
Inside one priority, higher criticality comes first.
"""

from . import rules

DEFAULT_Y = 3
DEFAULT_Z = 10


def priority_of(finding, y=DEFAULT_Y, z=DEFAULT_Z):
    label = finding.label
    late = finding.years_secret + y > z

    if label == rules.BROKEN:
        return 1
    if label == rules.QV_KEX:
        return 1 if late else 2
    if label == rules.QV_SIG:
        return 2 if finding.criticality >= 3 else 3
    if label in (rules.WEAKENED, rules.UNKNOWN):
        return 3
    if label == rules.SAFE:
        return 4
    return 0  # Unreachable


def sort_key(f):
    """Priority 1 first (0 = unreachable goes last), then most critical first,
    then servers before code, then by place (line 6 before line 10)."""
    place, _, line = f.location.rpartition(":")
    line = int(line) if line.isdigit() else 0
    return (f.priority or 99, -f.criticality, f.source != "tls", place, line)


def score_all(findings, y=DEFAULT_Y, z=DEFAULT_Z):
    for f in findings:
        f.priority = priority_of(f, y, z)
    findings.sort(key=sort_key)
    return findings
