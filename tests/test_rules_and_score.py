"""One test per label, and one per priority band (the done criteria)."""

from qscan import rules, score
from qscan.finding import Finding


def make(algorithm, usage, years_secret=5, criticality=2):
    f = Finding(source="tls", location="example:443", usage=usage, algorithm=algorithm,
                years_secret=years_secret, criticality=criticality)
    rules.classify(f)
    f.priority = score.priority_of(f, y=3, z=10)
    return f


# ---------------- labels ----------------

def test_label_broken():
    assert make("MD5", "hash").label == rules.BROKEN
    assert make("TLS1.0", "protocol").label == rules.BROKEN


def test_label_quantum_vulnerable_key_exchange():
    assert make("X25519", "key exchange").label == rules.QV_KEX
    assert make("RSA", "key exchange").label == rules.QV_KEX


def test_label_quantum_vulnerable_signature():
    assert make("ECDSA", "signature").label == rules.QV_SIG
    assert make("RSA", "signature").label == rules.QV_SIG


def test_same_algorithm_different_job_gets_different_label():
    # RSA doing key exchange and RSA doing signatures are different risks
    assert make("RSA", "key exchange").label != make("RSA", "signature").label


def test_label_public_key_from_code_treated_as_key_exchange():
    assert make("RSA", "public key").label == rules.QV_KEX


def test_label_weakened():
    assert make("AES-128", "cipher").label == rules.WEAKENED


def test_label_safe():
    assert make("X25519MLKEM768", "key exchange").label == rules.SAFE
    assert make("AES-256", "cipher").label == rules.SAFE


def test_label_unknown_and_unreachable():
    assert make("FOO-CIPHER", "cipher").label == rules.UNKNOWN
    assert make("UNREACHABLE", "connection").label == rules.UNREACHABLE


# ---------------- priorities ----------------

def test_priority_1_broken():
    assert make("RC4", "cipher").priority == 1


def test_priority_1_key_exchange_when_late():
    # X + Y > Z  ->  10 + 3 > 10  ->  already late
    assert make("X25519", "key exchange", years_secret=10).priority == 1


def test_priority_2_key_exchange_when_not_late():
    # 5 + 3 = 8 <= 10
    assert make("X25519", "key exchange", years_secret=5).priority == 2


def test_priority_2_signature_on_critical_system():
    assert make("RSA", "signature", criticality=3).priority == 2


def test_priority_3_other_signatures_and_weakened():
    assert make("RSA", "signature", criticality=2).priority == 3
    assert make("AES-128", "cipher").priority == 3


def test_priority_4_safe():
    assert make("AES-256", "cipher").priority == 4


def test_priority_0_unreachable():
    assert make("UNREACHABLE", "connection").priority == 0


def test_sort_order():
    fs = [make("AES-256", "cipher"), make("UNREACHABLE", "connection"),
          make("RSA", "signature", criticality=1), make("MD5", "hash")]
    score.score_all(fs)
    assert [f.priority for f in fs] == [1, 3, 4, 0]
