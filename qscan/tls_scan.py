"""
tls_scan.py - ask live servers which crypto they use.

Plain picture: we knock on a server's door the way a browser does
(a TLS "handshake"), write down what the server agreed to use, and
look at the ID card (certificate) it showed us.

How: we run the real `openssl s_client` program and read its text
output. We knock several times, each time asking slightly differently:

  1. "normal"  : a normal handshake -> TLS version, cipher, key-exchange
                 group, and the server's certificate.
  2. "hybrid"  : offer ONLY the post-quantum hybrid group X25519MLKEM768.
                 If the handshake still works, the server supports it.
  3. "tls1.0"  : offer ONLY the old TLS 1.0. If it works, that is bad.
  4. "tls1.1"  : same for TLS 1.1.

Every raw output is saved to out/raw/ so you can read what openssl said.
"""

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from .finding import Finding

HYBRID_GROUP = "X25519MLKEM768"

# "Turn security level down to 0" so openssl is willing to TRY old,
# weak settings. We only do this to test whether the server accepts them.
LEGACY_CIPHERS = ["-cipher", "DEFAULT:@SECLEVEL=0"]

# Post-quantum signature algorithms are new, so older libraries may not
# have names for them. These are their official ID numbers (OIDs).
PQ_KEY_OIDS = {
    "2.16.840.1.101.3.4.3.17": "ML-DSA-44",
    "2.16.840.1.101.3.4.3.18": "ML-DSA-65",
    "2.16.840.1.101.3.4.3.19": "ML-DSA-87",
}

# Different programs spell the same curve differently. Use one name.
CURVE_NAMES = {
    "prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256",
    "secp384r1": "P-384", "p-384": "P-384",
    "secp521r1": "P-521", "p-521": "P-521",
    "x25519": "X25519", "x448": "X448",
}


# ----------------------------------------------------------------------
# Step 0: find a modern openssl
# ----------------------------------------------------------------------

def find_openssl():
    """The Mac's built-in `openssl` is really LibreSSL, which does not know
    post-quantum groups. Prefer Homebrew's OpenSSL 3."""
    if os.environ.get("QSCAN_OPENSSL"):
        return os.environ["QSCAN_OPENSSL"]
    for path in ("/opt/homebrew/opt/openssl@3/bin/openssl",   # Apple-silicon Mac
                 "/usr/local/opt/openssl@3/bin/openssl"):     # Intel Mac
        if os.path.exists(path):
            return path
    return shutil.which("openssl") or "openssl"


def openssl_version(openssl):
    """Return ((major, minor), full_text), e.g. ((3, 5), "OpenSSL 3.5.4 ...")."""
    text = subprocess.run([openssl, "version"], capture_output=True, text=True).stdout.strip()
    m = re.match(r"OpenSSL (\d+)\.(\d+)", text)
    return ((int(m[1]), int(m[2])) if m else (0, 0)), text


# ----------------------------------------------------------------------
# Step 1: knock on the door (run s_client once)
# ----------------------------------------------------------------------

def run_s_client(openssl, host, port, extra_args=(), timeout=10):
    """Run one handshake. Returns (worked: bool, output_text: str)."""
    cmd = [openssl, "s_client", "-connect", f"{host}:{port}", "-servername", host, *extra_args]
    try:
        # input="" means "send nothing and hang up right after the handshake"
        result = subprocess.run(cmd, input="", capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"TIMEOUT after {timeout} s"
    text = result.stdout + result.stderr
    return handshake_worked(text), text


def handshake_worked(text):
    """openssl prints 'Cipher is TLS_AES_...' on success and
    'Cipher is (NONE)' when the handshake failed."""
    m = re.search(r"Cipher is (\S+)", text)
    return bool(m) and m.group(1) not in ("(NONE)", "0000")


# ----------------------------------------------------------------------
# Step 2: read what openssl printed
# ----------------------------------------------------------------------

def parse_handshake(text):
    """Pull TLS version, cipher suite and key-exchange group out of the text.

    The lines we look for (open a file in out/raw/ to see them yourself):
        New, TLSv1.3, Cipher is TLS_AES_256_GCM_SHA384
        Protocol  : TLSv1.3
        Negotiated TLS1.3 group: X25519MLKEM768      (OpenSSL 3.2+)
        Server Temp Key: X25519, 253 bits            (OpenSSL 3.0-3.4)
        Peer Temp Key: X25519, 253 bits              (OpenSSL 3.5+, same meaning)
    """
    info = {"protocol": "unknown", "cipher": "unknown", "group": "unknown"}

    m = re.search(r"New, (\S+), Cipher is (\S+)", text)
    if m:
        info["protocol"], info["cipher"] = m.group(1), m.group(2)
    m = re.search(r"^\s*Protocol\s*:\s*(\S+)", text, re.M)
    if m:
        info["protocol"] = m.group(1)

    m = re.search(r"Negotiated TLS1\.3 group:\s*(\S+)", text)
    if m:
        info["group"] = normalise_group(m.group(1))
    else:
        m = re.search(r"(?:Server|Peer) Temp Key:\s*([^\n]+)", text)
        if m:
            parts = [p.strip() for p in m.group(1).split(",")]
            # "X25519, 253 bits" -> X25519 ; "ECDH, prime256v1, 256 bits" -> P-256
            # "DH, 2048 bits" -> DH
            if parts[0] in ("ECDH",) and len(parts) > 1:
                info["group"] = normalise_group(parts[1])
            else:
                info["group"] = normalise_group(parts[0])
        elif info["cipher"] != "unknown" and not re.match(r"(TLS_|ECDHE|DHE)", info["cipher"]):
            # TLS 1.2 suite such as AES256-SHA: no temporary key at all,
            # the browser encrypts the secret with the server's RSA key.
            info["group"] = "RSA"
    return info


def normalise_group(name):
    return CURVE_NAMES.get(name.lower(), name)


def cipher_to_algorithm(cipher):
    """Turn a cipher-suite name into the symmetric algorithm it uses."""
    c = cipher.upper()
    if "CHACHA20" in c:
        return "CHACHA20"
    if "AES_256" in c or "AES256" in c:
        return "AES-256"
    if "AES_128" in c or "AES128" in c:
        return "AES-128"
    if "3DES" in c or "DES-CBC3" in c or "DES_EDE" in c:
        return "3DES"
    if "RC4" in c:
        return "RC4"
    if "DES" in c:
        return "DES"
    return cipher


def find_certificate_pem(text):
    """s_client prints the server's certificate between BEGIN/END lines."""
    m = re.search(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)
    return m.group(0) if m else None


def read_certificate(pem):
    """Read the server's ID card. Returns a dict with:
    key (e.g. "RSA"), key_detail ("2048 bits"), signed_with, days_left."""
    cert = x509.load_pem_x509_certificate(pem.encode())

    key, key_detail = "unknown", ""
    try:
        pk = cert.public_key()
        if isinstance(pk, rsa.RSAPublicKey):
            key, key_detail = "RSA", f"{pk.key_size} bits"
        elif isinstance(pk, ec.EllipticCurvePublicKey):
            key, key_detail = "ECDSA", normalise_group(pk.curve.name)
        elif isinstance(pk, ed25519.Ed25519PublicKey):
            key = "Ed25519"
        elif isinstance(pk, ed448.Ed448PublicKey):
            key = "Ed448"
        elif isinstance(pk, dsa.DSAPublicKey):
            key, key_detail = "DSA", f"{pk.key_size} bits"
    except Exception:
        pass  # key type this library does not know - fall back to its OID below
    if key == "unknown":
        oid = cert.public_key_algorithm_oid.dotted_string
        key = PQ_KEY_OIDS.get(oid, f"unknown key (OID {oid})")

    oid = cert.signature_algorithm_oid
    signed_with = PQ_KEY_OIDS.get(oid.dotted_string, getattr(oid, "_name", oid.dotted_string))

    days_left = (cert.not_valid_after_utc - datetime.now(timezone.utc)).days
    return {"key": key, "key_detail": key_detail, "signed_with": signed_with, "days_left": days_left}


# ----------------------------------------------------------------------
# Step 3: put it together for one server
# ----------------------------------------------------------------------

def save_raw(raw_dir, host, port, probe, text):
    if raw_dir:
        os.makedirs(raw_dir, exist_ok=True)
        with open(os.path.join(raw_dir, f"{host}_{port}_{probe}.txt"), "w") as f:
            f.write(text)


def first_error_line(text):
    """A short reason for the report, e.g. 'Connection refused'."""
    for words, reason in (("TIMEOUT", "Timed out"), ("Connection refused", "Connection refused"),
                          ("getaddrinfo", "Host name not found")):
        if words in text:
            return reason
    for line in text.splitlines():
        if any(w in line.lower() for w in ("timeout", "refused", "errno", "error", "alert", "getaddrinfo")):
            return line.strip()[:120]
    return "handshake failed"


def scan_server(target, openssl, version, raw_dir=None):
    """Scan one server from targets.json. Returns a list of Findings."""
    host, port = target["host"], int(target.get("port", 443))
    where = f"{host}:{port}"
    common = dict(source="tls", location=where,
                  years_secret=int(target.get("years_secret", 5)),
                  criticality=int(target.get("criticality", 2)))
    findings = []

    # --- knock 1: normal handshake (retry allowing old settings if it fails) ---
    ok, text = run_s_client(openssl, host, port)
    save_raw(raw_dir, host, port, "normal", text)
    no_answer = any(w in text for w in ("TIMEOUT", "errno=", "getaddrinfo", "Connection refused"))
    if not ok and not no_answer:   # it answered but refused us: maybe it only speaks old TLS
        ok, text = run_s_client(openssl, host, port, LEGACY_CIPHERS)
        save_raw(raw_dir, host, port, "normal-legacy", text)
    if not ok:
        return [Finding(usage="connection", algorithm="UNREACHABLE",
                        detail=first_error_line(text), **common)]

    hs = parse_handshake(text)

    # --- knock 2: does it accept the post-quantum hybrid group? ---
    if hs["group"] == HYBRID_GROUP:
        hybrid = True
    elif version >= (3, 5):
        hybrid, htext = run_s_client(openssl, host, port, ["-groups", HYBRID_GROUP])
        save_raw(raw_dir, host, port, "hybrid", htext)
    else:
        hybrid = None  # our openssl is too old to even ask

    kex_detail = f"{hs['protocol']}, negotiated {hs['group']}"
    if hybrid and hs["group"] != HYBRID_GROUP:
        kex_detail += f"; accepts {HYBRID_GROUP} when offered"
    if hybrid is False:
        kex_detail += f"; does NOT accept {HYBRID_GROUP}"
    if hybrid is None:
        kex_detail += f"; {HYBRID_GROUP} not tested (needs OpenSSL 3.5+)"
    findings.append(Finding(usage="key exchange",
                            algorithm=HYBRID_GROUP if hybrid else hs["group"],
                            detail=kex_detail, **common))

    # --- the bulk cipher (symmetric encryption of the actual data) ---
    findings.append(Finding(usage="cipher", algorithm=cipher_to_algorithm(hs["cipher"]),
                            detail=f"{hs['protocol']}, suite {hs['cipher']}", **common))

    # --- the certificate (the server's ID card) ---
    pem = find_certificate_pem(text)
    if pem:
        c = read_certificate(pem)
        expiry = f"EXPIRED {-c['days_left']} days ago" if c["days_left"] < 0 \
            else f"expires in {c['days_left']} days"
        detail = ", ".join(x for x in (c["key_detail"], f"signed with {c['signed_with']}", expiry) if x)
        findings.append(Finding(usage="signature", algorithm=c["key"], detail=detail, **common))
        # an old hash inside the certificate signature is broken even today
        for weak in ("md5", "sha1"):
            if weak in c["signed_with"].lower().replace("-", ""):
                findings.append(Finding(usage="hash", algorithm="MD5" if weak == "md5" else "SHA-1",
                                        detail=f"used in certificate signature ({c['signed_with']})",
                                        **common))

    # --- knocks 3 and 4: does it still accept old TLS versions? ---
    for flag, name in (("-tls1", "TLS1.0"), ("-tls1_1", "TLS1.1")):
        old_ok, otext = run_s_client(openssl, host, port, [flag, *LEGACY_CIPHERS])
        save_raw(raw_dir, host, port, name, otext)
        if old_ok:
            findings.append(Finding(usage="protocol", algorithm=name,
                                    detail=f"server still accepts {name}", **common))
    return findings


def scan_servers(servers, raw_dir=None):
    openssl = find_openssl()
    version, vtext = openssl_version(openssl)
    print(f"[qscan] using {openssl} ({vtext or 'unknown version'})", file=sys.stderr)
    if version < (3, 5):
        print("[qscan] warning: OpenSSL older than 3.5, hybrid post-quantum support "
              "cannot be tested", file=sys.stderr)
    findings = []
    for target in servers:
        print(f"[qscan] scanning {target['host']}:{target.get('port', 443)} ...", file=sys.stderr)
        findings += scan_server(target, openssl, version, raw_dir)
    return findings
