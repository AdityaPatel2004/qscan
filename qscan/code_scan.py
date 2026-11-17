"""
code_scan.py - find crypto calls in source code.

Plain picture: like pressing Ctrl+F in every file for words such as
"md5" or "RSA", and writing down the file and line of every hit.

How: each PATTERN below is a regular expression (a search pattern)
plus the algorithm it means and what it is used for. We read every
.py, .c, .h and .java file line by line and test every pattern.

Honest limits (also in the README):
  * a wrapper function (def make_key(): return RSA.generate(...)) is
    found once, but every place that calls make_key() is not;
  * an alias (from hashlib import md5 as h; h(...)) is missed;
  * crypto inside compiled libraries is invisible.
"""

import os
import re

from .finding import Finding

FILE_TYPES = (".py", ".c", ".h", ".java")

# (search pattern, algorithm, usage)
# "public key" = RSA or EC key whose job (key exchange or signature)
# cannot be told from this line alone.
PATTERNS = [
    # ---------- Python (hashlib, cryptography, PyCryptodome) ----------
    (r"hashlib\.md5\b|\bMD5\.new\(", "MD5", "hash"),
    (r"hashlib\.sha1\b|\bSHA1\.new\(|hashes\.SHA1\(", "SHA-1", "hash"),
    (r"\bRSA\.generate\(|rsa\.generate_private_key\(", "RSA", "public key"),
    (r"ec\.generate_private_key\(|\bECC\.generate\(", "EC", "public key"),
    (r"\bec\.ECDH\(|x25519\.X25519PrivateKey", "ECDH", "key exchange"),
    (r"dsa\.generate_private_key\(|\bDSA\.generate\(", "DSA", "signature"),
    (r"\bdh\.generate_parameters\(", "DH", "key exchange"),
    (r"\bDES3\.new\(|algorithms\.TripleDES\(", "3DES", "cipher"),
    (r"\bDES\.new\(", "DES", "cipher"),
    (r"\bARC4\.new\(|algorithms\.ARC4\(", "RC4", "cipher"),
    (r"AES\.MODE_ECB|modes\.ECB\(", "AES-ECB", "cipher"),

    # ---------- C (OpenSSL) ----------
    (r"\bMD5_Init\b|\bMD5\(|EVP_md5\(", "MD5", "hash"),
    (r"\bSHA1_Init\b|\bSHA1\(|EVP_sha1\(", "SHA-1", "hash"),
    (r"\bRSA_generate_key(_ex)?\(|EVP_PKEY_RSA\b", "RSA", "public key"),
    (r"\bEC_KEY_new_by_curve_name\(|EVP_PKEY_EC\b", "EC", "public key"),
    (r"\bECDSA_sign\(", "ECDSA", "signature"),
    (r"\bDH_generate_key\(", "DH", "key exchange"),
    (r"\bDES_ecb_encrypt\(|EVP_des_(?!ede)", "DES", "cipher"),
    (r"EVP_des_ede3", "3DES", "cipher"),
    (r"\bRC4\(|EVP_rc4\(", "RC4", "cipher"),
    (r"EVP_aes_\d+_ecb\(", "AES-ECB", "cipher"),

    # ---------- Java (JCA) ----------
    (r'MessageDigest\.getInstance\("MD5"\)', "MD5", "hash"),
    (r'MessageDigest\.getInstance\("SHA-?1"\)', "SHA-1", "hash"),
    (r'KeyPairGenerator\.getInstance\("RSA"\)', "RSA", "public key"),
    (r'KeyPairGenerator\.getInstance\("EC"\)', "EC", "public key"),
    (r'KeyPairGenerator\.getInstance\("DSA"\)', "DSA", "signature"),
    (r'KeyAgreement\.getInstance\("(ECDH|DH)"\)', "DH", "key exchange"),
    (r'Signature\.getInstance\("\w*withECDSA"\)', "ECDSA", "signature"),
    (r'Signature\.getInstance\("\w*withRSA"\)', "RSA", "signature"),
    (r'Cipher\.getInstance\("AES/ECB', "AES-ECB", "cipher"),
    (r'Cipher\.getInstance\("AES"\)', "AES-ECB", "cipher"),   # Java's default mode is ECB!
    (r'Cipher\.getInstance\("DESede', "3DES", "cipher"),
    (r'Cipher\.getInstance\("DES[/"]', "DES", "cipher"),
    (r'Cipher\.getInstance\("(RC4|ARCFOUR)', "RC4", "cipher"),
]

COMPILED = [(re.compile(p), algo, usage) for p, algo, usage in PATTERNS]


def is_comment(line):
    """Skip lines that are only comments, so '# never use md5' is not a hit."""
    s = line.strip()
    return s.startswith(("#", "//", "/*", "*"))


def scan_file(path, display_path, common):
    findings = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line_no, line in enumerate(f, start=1):
            if is_comment(line):
                continue
            seen = set()   # report each algorithm at most once per line
            for regex, algo, usage in COMPILED:
                if algo not in seen and regex.search(line):
                    seen.add(algo)
                    findings.append(Finding(source="code", location=f"{display_path}:{line_no}",
                                            usage=usage, algorithm=algo,
                                            detail=" ".join(line.split())[:100], **common))
    return findings


def scan_folder(folder, years_secret=5, criticality=2):
    """Walk a folder and scan every source file in it."""
    common = dict(years_secret=int(years_secret), criticality=int(criticality))
    findings = []
    for root, _dirs, files in os.walk(folder):
        for name in sorted(files):
            if name.endswith(FILE_TYPES):
                path = os.path.join(root, name)
                findings += scan_file(path, os.path.relpath(path), common)
    return findings
