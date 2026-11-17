"""
finding.py - the one record every part of qscan passes around.

Plain picture: a "finding" is one sticky note that says
"at THIS place, I saw THIS crypto, used for THIS job".
The scanners write the sticky notes. rules.py adds a label,
score.py adds a priority, report.py prints them all.
"""

from dataclasses import dataclass, asdict


@dataclass
class Finding:
    # --- filled in by a scanner (tls_scan.py or code_scan.py) ---
    source: str          # "tls" or "code"
    location: str        # "cloudflare.com:443" or "samples/weak.py:12"
    usage: str           # what the crypto is doing, one of:
                         #   "key exchange", "signature", "cipher",
                         #   "hash", "protocol", "public key", "connection"
    algorithm: str       # short name, e.g. "X25519", "RSA", "AES-128", "TLS1.0"
    detail: str = ""     # extra words for a human, e.g. "2048 bits, expires in 80 days"

    # --- copied from targets.json so score.py can use them ---
    years_secret: int = 5    # X in Mosca's rule
    criticality: int = 2     # 1 = low, 3 = high

    # --- filled in by rules.py ---
    label: str = ""
    why: str = ""
    migrate_to: str = ""

    # --- filled in by score.py ---
    priority: int = 0        # 1 = fix first ... 4 = no action, 0 = not scored

    def to_dict(self):
        return asdict(self)
