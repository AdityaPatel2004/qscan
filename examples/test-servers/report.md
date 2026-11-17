# qscan report

Generated 2026-11-17 03:33 by qscan 0.1.0. Settings: migration time Y = 3 years, assumed years to a quantum computer Z = 10 years (an assumption, not a prediction).

## Summary

| Priority | Findings |
| --- | --- |
| 1 - fix first | 8 |
| 2 | 6 |
| 3 | 2 |
| 4 - no action | 3 |
| unreachable | 1 |

## Findings

| # | Priority | Location | Used for | Algorithm | Label | Migrate to | Detail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | localhost:4433 | key exchange | X25519 | Quantum-vulnerable (key exchange) | Hybrid X25519MLKEM768, then ML-KEM | TLSv1.3, negotiated X25519; X25519MLKEM768 not tested (needs OpenSSL 3.5+) |
| 2 | 1 | samples/Weak.java:8 | cipher | AES-ECB | Broken today | AES-256-GCM | Cipher c = Cipher.getInstance("AES"); // Java default is AES/ECB: broken |
| 3 | 1 | samples/known_limits.py:12 | hash | MD5 | Broken today | SHA-256 or SHA-3 | print("We removed hashlib.md5 from this project last year") |
| 4 | 1 | samples/weak_c.c:6 | hash | SHA-1 | Broken today | SHA-256 or SHA-3 | SHA1(d, n, out); /* SHA-1: broken today */ |
| 5 | 1 | samples/weak_c.c:10 | cipher | AES-ECB | Broken today | AES-256-GCM | return EVP_aes_128_ecb(); /* AES-ECB: broken today */ |
| 6 | 1 | samples/weak_python.py:9 | hash | MD5 | Broken today | SHA-256 or SHA-3 | return hashlib.md5(data).hexdigest() # MD5: broken today |
| 7 | 1 | samples/weak_python.py:17 | cipher | AES-ECB | Broken today | AES-256-GCM | return AES.new(key, AES.MODE_ECB).encrypt(block) # AES-ECB: broken today |
| 8 | 1 | localhost:4434 | protocol | TLS1.0 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.0 |
| 9 | 2 | localhost:4433 | signature | RSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | 2048 bits, signed with sha256WithRSAEncryption, expires in 89 days |
| 10 | 2 | localhost:4435 | key exchange | RSA | Quantum-vulnerable (key exchange) | Hybrid X25519MLKEM768, then ML-KEM | TLSv1.2, negotiated RSA; X25519MLKEM768 not tested (needs OpenSSL 3.5+) |
| 11 | 2 | samples/Weak.java:9 | public key | RSA | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); // RSA: quantum-vulnerable |
| 12 | 2 | samples/weak_c.c:14 | public key | EC | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | return EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); /* EC: quantum-vulnerable */ |
| 13 | 2 | samples/weak_python.py:13 | public key | RSA | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | return RSA.generate(2048) # RSA: quantum-vulnerable |
| 14 | 2 | localhost:4434 | key exchange | X25519 | Quantum-vulnerable (key exchange) | Hybrid X25519MLKEM768, then ML-KEM | TLSv1, negotiated X25519; X25519MLKEM768 not tested (needs OpenSSL 3.5+) |
| 15 | 3 | localhost:4435 | signature | RSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | 2048 bits, signed with sha256WithRSAEncryption, expires in 89 days |
| 16 | 3 | localhost:4434 | signature | RSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | 2048 bits, signed with sha256WithRSAEncryption, expires in 89 days |
| 17 | 4 | localhost:4433 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1.3, suite TLS_AES_256_GCM_SHA384 |
| 18 | 4 | localhost:4435 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1.2, suite AES256-SHA |
| 19 | 4 | localhost:4434 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1, suite ECDHE-RSA-AES256-SHA |

## Migration plan

### Priority 1 - fix first

- **X25519** (key exchange) -> Hybrid X25519MLKEM768, then ML-KEM. Found at: localhost:4433
- **AES-ECB** (cipher) -> AES-256-GCM. Found at: samples/Weak.java:8, samples/weak_c.c:10, samples/weak_python.py:17
- **MD5** (hash) -> SHA-256 or SHA-3. Found at: samples/known_limits.py:12, samples/weak_python.py:9
- **SHA-1** (hash) -> SHA-256 or SHA-3. Found at: samples/weak_c.c:6
- **TLS1.0** (protocol) -> Disable; allow only TLS 1.2 and 1.3. Found at: localhost:4434

### Priority 2

- **RSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: localhost:4433
- **RSA** (key exchange) -> Hybrid X25519MLKEM768, then ML-KEM. Found at: localhost:4435
- **RSA** (public key) -> ML-KEM for key exchange / ML-DSA for signatures. Found at: samples/Weak.java:9, samples/weak_python.py:13
- **EC** (public key) -> ML-KEM for key exchange / ML-DSA for signatures. Found at: samples/weak_c.c:14
- **X25519** (key exchange) -> Hybrid X25519MLKEM768, then ML-KEM. Found at: localhost:4434

### Priority 3

- **RSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: localhost:4435, localhost:4434

## Unreachable targets

- localhost:9: Connection refused

## What this scan cannot see

- Crypto inside compiled binaries and third-party libraries.
- Crypto outside HTTPS: SSH, VPN/IPsec, databases, message queues, Java key stores.
- Keys in HSMs, cloud KMS and vaults; certificates in internal stores.
- What the data is worth: years-secret and criticality come from a person, not the scan.
