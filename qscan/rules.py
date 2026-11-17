"""
rules.py - give every finding a label.

Plain picture: a lookup table on the wall. "If you saw THIS lock used
for THIS job, write THIS label on the sticky note."

The whole table is in this one file, so changing a rule never means
touching scanner code. Each row says why, so the report can explain it.
"""

BROKEN = "Broken today"
QV_KEX = "Quantum-vulnerable (key exchange)"
QV_SIG = "Quantum-vulnerable (signature)"
WEAKENED = "Weakened"
SAFE = "Quantum-safe"
UNKNOWN = "Unknown"
UNREACHABLE = "Unreachable"

# Public-key families that Shor's algorithm breaks.
SHOR_KEX = {"RSA", "DH", "ECDH", "EC", "X25519", "X448", "P-256", "P-384", "P-521"}
SHOR_SIG = {"RSA", "ECDSA", "EC", "Ed25519", "Ed448", "DSA"}

# Each row: (set of algorithms, label, why, migrate to)
TABLE = [
    ({"MD5", "SHA-1"},
     BROKEN, "Collisions can be made today, no quantum computer needed", "SHA-256 or SHA-3"),

    ({"DES", "3DES", "RC4"},
     BROKEN, "Weak cipher, breakable today", "AES-256-GCM or ChaCha20-Poly1305"),

    ({"AES-ECB"},
     BROKEN, "ECB mode leaks patterns in the data (same input block -> same output block)",
     "AES-256-GCM"),

    ({"TLS1.0", "TLS1.1"},
     BROKEN, "Old TLS version with known attacks, deprecated by RFC 8996",
     "Disable; allow only TLS 1.2 and 1.3"),

    ({"AES-128"},
     WEAKENED, "Grover's algorithm halves effective key bits; NIST still accepts "
               "AES-128, NSA CNSA 2.0 requires AES-256 (policy-dependent)",
     "AES-256"),

    ({"X25519MLKEM768", "SecP256r1MLKEM768", "SecP384r1MLKEM1024",
      "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "MLKEM768", "MLKEM1024",
      "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
      "AES-256", "CHACHA20", "SHA-256", "SHA-384", "SHA-512", "SHA-3"},
     SAFE, "No known quantum attack that matters", "Keep; monitor"),
]


def classify(finding):
    """Write label, why and migrate_to onto one finding."""
    algo, usage = finding.algorithm, finding.usage

    if algo == "UNREACHABLE":
        finding.label, finding.why, finding.migrate_to = UNREACHABLE, finding.detail, "Re-scan"
        return finding

    # 1. fixed rows first (broken / weakened / safe)
    for algorithms, label, why, migrate_to in TABLE:
        if algo in algorithms:
            finding.label, finding.why, finding.migrate_to = label, why, migrate_to
            return finding

    # 2. public-key crypto: the label depends on the JOB it does
    if usage == "key exchange" and algo in SHOR_KEX:
        finding.label = QV_KEX
        finding.why = "Shor's algorithm; harvest-now-decrypt-later applies"
        finding.migrate_to = "Hybrid X25519MLKEM768, then ML-KEM"
    elif usage == "signature" and algo in SHOR_SIG:
        finding.label = QV_SIG
        finding.why = "Shor's algorithm; only matters once a quantum computer exists"
        finding.migrate_to = "ML-DSA (hybrid or composite during transition)"
    elif usage == "public key" and algo in SHOR_KEX | SHOR_SIG:
        # From one line of code we cannot tell if this key encrypts or signs.
        # Assume the worse case (key exchange: harvest-now-decrypt-later).
        finding.label = QV_KEX
        finding.why = ("Shor's algorithm; use (key exchange or signature) unclear from "
                       "code, treated as key exchange to be safe")
        finding.migrate_to = "ML-KEM for key exchange / ML-DSA for signatures"
    else:
        finding.label = UNKNOWN
        finding.why = "Not in qscan's rule table"
        finding.migrate_to = "Check by hand"
    return finding


def classify_all(findings):
    return [classify(f) for f in findings]
