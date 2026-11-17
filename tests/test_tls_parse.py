"""Parser tests on saved `openssl s_client` outputs (tests/fixtures/).

The x25519, tls10 and rsa_kex files are real outputs from OpenSSL 3.0 against
local test servers. The hybrid file is the x25519 file with its group line
changed to what OpenSSL 3.5+ prints, so it is marked "synthetic".
"""

import os

from qscan import tls_scan

HERE = os.path.join(os.path.dirname(__file__), "fixtures")


def load(name):
    with open(os.path.join(HERE, name)) as f:
        return f.read()


def test_tls13_x25519():
    text = load("s_client_tls13_x25519.txt")
    assert tls_scan.handshake_worked(text)
    hs = tls_scan.parse_handshake(text)
    assert hs == {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "group": "X25519"}


def test_tls13_hybrid_line_from_newer_openssl():
    hs = tls_scan.parse_handshake(load("s_client_tls13_hybrid_synthetic.txt"))
    assert hs["group"] == "X25519MLKEM768"


def test_tls10_server():
    hs = tls_scan.parse_handshake(load("s_client_tls10.txt"))
    assert hs["protocol"] == "TLSv1"
    assert hs["cipher"] == "ECDHE-RSA-AES256-SHA"


def test_tls12_rsa_key_transport():
    # "New, SSLv3, ..." is misleading; the Protocol line says TLSv1.2
    hs = tls_scan.parse_handshake(load("s_client_tls12_rsa_kex.txt"))
    assert hs["protocol"] == "TLSv1.2"
    assert hs["group"] == "RSA"


def test_failed_handshake_detected():
    assert not tls_scan.handshake_worked("New, (NONE), Cipher is (NONE)")
    assert not tls_scan.handshake_worked("connect:errno=111")


def test_tls12_ecdh_temp_key():
    hs = tls_scan.parse_handshake("Server Temp Key: ECDH, prime256v1, 256 bits\n"
                                  "New, TLSv1.2, Cipher is ECDHE-RSA-AES128-GCM-SHA256\n")
    assert hs["group"] == "P-256"


def test_cipher_names():
    assert tls_scan.cipher_to_algorithm("TLS_AES_128_GCM_SHA256") == "AES-128"
    assert tls_scan.cipher_to_algorithm("TLS_CHACHA20_POLY1305_SHA256") == "CHACHA20"
    assert tls_scan.cipher_to_algorithm("DES-CBC3-SHA") == "3DES"


def test_certificate_read():
    pem = tls_scan.find_certificate_pem(load("s_client_tls13_x25519.txt"))
    c = tls_scan.read_certificate(pem)
    assert c["key"] == "RSA" and c["key_detail"] == "2048 bits"
    assert "sha256" in c["signed_with"].lower()
