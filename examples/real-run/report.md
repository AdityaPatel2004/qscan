# qscan report

Generated 2026-11-17 11:39 by qscan 0.1.0. Settings: migration time Y = 3 years, assumed years to a quantum computer Z = 10 years (an assumption, not a prediction).

## Summary

| Priority | Findings |
| --- | --- |
| 1 - fix first | 12 |
| 2 | 6 |
| 3 | 3 |
| 4 - no action | 5 |
| unreachable | 1 |

## Findings

| # | Priority | Location | Used for | Algorithm | Label | Migrate to | Detail |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 1 | 1 | cloudflare.com:443 | protocol | TLS1.0 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.0 |
| 2 | 1 | cloudflare.com:443 | protocol | TLS1.1 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.1 |
| 3 | 1 | www.onlinesbi.sbi:443 | key exchange | X25519 | Quantum-vulnerable (key exchange) | Hybrid X25519MLKEM768, then ML-KEM | TLSv1.3, negotiated X25519; does NOT accept X25519MLKEM768 |
| 4 | 1 | google.com:443 | protocol | TLS1.0 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.0 |
| 5 | 1 | google.com:443 | protocol | TLS1.1 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.1 |
| 6 | 1 | samples/Weak.java:8 | cipher | AES-ECB | Broken today | AES-256-GCM | Cipher c = Cipher.getInstance("AES"); // Java default is AES/ECB: broken |
| 7 | 1 | samples/known_limits.py:12 | hash | MD5 | Broken today | SHA-256 or SHA-3 | print("We removed hashlib.md5 from this project last year") |
| 8 | 1 | samples/weak_c.c:6 | hash | SHA-1 | Broken today | SHA-256 or SHA-3 | SHA1(d, n, out); /* SHA-1: broken today */ |
| 9 | 1 | samples/weak_c.c:10 | cipher | AES-ECB | Broken today | AES-256-GCM | return EVP_aes_128_ecb(); /* AES-ECB: broken today */ |
| 10 | 1 | samples/weak_python.py:9 | hash | MD5 | Broken today | SHA-256 or SHA-3 | return hashlib.md5(data).hexdigest() # MD5: broken today |
| 11 | 1 | samples/weak_python.py:17 | cipher | AES-ECB | Broken today | AES-256-GCM | return AES.new(key, AES.MODE_ECB).encrypt(block) # AES-ECB: broken today |
| 12 | 1 | tls-v1-0.badssl.com:1010 | protocol | TLS1.0 | Broken today | Disable; allow only TLS 1.2 and 1.3 | server still accepts TLS1.0 |
| 13 | 2 | cloudflare.com:443 | signature | ECDSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | P-256, signed with ecdsa-with-SHA256, expires in 76 days |
| 14 | 2 | www.onlinesbi.sbi:443 | signature | RSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | 2048 bits, signed with sha256WithRSAEncryption, expires in 193 days |
| 15 | 2 | samples/Weak.java:9 | public key | RSA | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | KeyPairGenerator g = KeyPairGenerator.getInstance("RSA"); // RSA: quantum-vulnerable |
| 16 | 2 | samples/weak_c.c:14 | public key | EC | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | return EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL); /* EC: quantum-vulnerable */ |
| 17 | 2 | samples/weak_python.py:13 | public key | RSA | Quantum-vulnerable (key exchange) | ML-KEM for key exchange / ML-DSA for signatures | return RSA.generate(2048) # RSA: quantum-vulnerable |
| 18 | 2 | tls-v1-0.badssl.com:1010 | key exchange | P-256 | Quantum-vulnerable (key exchange) | Hybrid X25519MLKEM768, then ML-KEM | TLSv1, negotiated P-256; does NOT accept X25519MLKEM768 |
| 19 | 3 | www.onlinesbi.sbi:443 | cipher | AES-128 | Weakened | AES-256 | TLSv1.3, suite TLS_AES_128_GCM_SHA256 |
| 20 | 3 | google.com:443 | signature | ECDSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | P-256, signed with ecdsa-with-SHA256, expires in 70 days |
| 21 | 3 | tls-v1-0.badssl.com:1010 | signature | RSA | Quantum-vulnerable (signature) | ML-DSA (hybrid or composite during transition) | 2048 bits, signed with sha256WithRSAEncryption, expires in 41 days |
| 22 | 4 | cloudflare.com:443 | key exchange | X25519MLKEM768 | Quantum-safe | Keep; monitor | TLSv1.3, negotiated X25519MLKEM768 |
| 23 | 4 | cloudflare.com:443 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1.3, suite TLS_AES_256_GCM_SHA384 |
| 24 | 4 | google.com:443 | key exchange | X25519MLKEM768 | Quantum-safe | Keep; monitor | TLSv1.3, negotiated X25519MLKEM768 |
| 25 | 4 | google.com:443 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1.3, suite TLS_AES_256_GCM_SHA384 |
| 26 | 4 | tls-v1-0.badssl.com:1010 | cipher | AES-256 | Quantum-safe | Keep; monitor | TLSv1, suite ECDHE-RSA-AES256-SHA |

## Migration plan

### Priority 1 - fix first

- **TLS1.0** (protocol) -> Disable; allow only TLS 1.2 and 1.3. Found at: cloudflare.com:443, google.com:443, tls-v1-0.badssl.com:1010
- **TLS1.1** (protocol) -> Disable; allow only TLS 1.2 and 1.3. Found at: cloudflare.com:443, google.com:443
- **X25519** (key exchange) -> Hybrid X25519MLKEM768, then ML-KEM. Found at: www.onlinesbi.sbi:443
- **AES-ECB** (cipher) -> AES-256-GCM. Found at: samples/Weak.java:8, samples/weak_c.c:10, samples/weak_python.py:17
- **MD5** (hash) -> SHA-256 or SHA-3. Found at: samples/known_limits.py:12, samples/weak_python.py:9
- **SHA-1** (hash) -> SHA-256 or SHA-3. Found at: samples/weak_c.c:6

### Priority 2

- **ECDSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: cloudflare.com:443
- **RSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: www.onlinesbi.sbi:443
- **RSA** (public key) -> ML-KEM for key exchange / ML-DSA for signatures. Found at: samples/Weak.java:9, samples/weak_python.py:13
- **EC** (public key) -> ML-KEM for key exchange / ML-DSA for signatures. Found at: samples/weak_c.c:14
- **P-256** (key exchange) -> Hybrid X25519MLKEM768, then ML-KEM. Found at: tls-v1-0.badssl.com:1010

### Priority 3

- **AES-128** (cipher) -> AES-256. Found at: www.onlinesbi.sbi:443
- **ECDSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: google.com:443
- **RSA** (signature) -> ML-DSA (hybrid or composite during transition). Found at: tls-v1-0.badssl.com:1010

## Unreachable targets

- localhost:9: Connection refused

## What this scan cannot see

- Crypto inside compiled binaries and third-party libraries.
- Crypto outside HTTPS: SSH, VPN/IPsec, databases, message queues, Java key stores.
- Keys in HSMs, cloud KMS and vaults; certificates in internal stores.
- What the data is worth: years-secret and criticality come from a person, not the scan.
