# qscan: Quantum-Readiness Scanner

qscan finds the cryptography a system uses, flags what a large quantum computer would break, and ranks what to migrate first. It scans **live TLS servers** and **source code**, then writes a **CycloneDX 1.6 CBOM** (Cryptography Bill of Materials) and a **migration report**.

It covers the first two steps of a post-quantum migration programme: **discover and inventory** the crypto, then **assess** its quantum risk.

---

## Why this matters

- **Shor's algorithm** breaks all of today's public-key crypto: RSA, Diffie-Hellman, and elliptic curves (ECDH, ECDSA, EdDSA).
- **Grover's algorithm** only weakens symmetric crypto. AES-128 drops to about 64-bit strength; AES-256 stays safe.
- **Harvest now, decrypt later:** traffic recorded today can be decrypted once a quantum computer exists. So key exchange protecting long-lived secrets is urgent now.
- NIST's replacements are **ML-KEM** (FIPS 203) for key exchange and **ML-DSA** (FIPS 204) for signatures. During the transition, TLS uses the **hybrid** group `X25519MLKEM768` (X25519 + ML-KEM-768).
- You cannot migrate what you have not found. The first step is a crypto inventory.

---

## What qscan does

1. **Discovers** crypto in two places.
   - TLS servers: TLS version, cipher suite, key-exchange group, certificate key and signature algorithm, days to expiry, support for hybrid `X25519MLKEM768`, and whether TLS 1.0 / 1.1 are still accepted.
   - Source code (Python, C, Java): calls to RSA, EC, DSA, DH, MD5, SHA-1, DES, 3DES, RC4 and AES-ECB, with file and line.
2. **Classifies** each finding as *Broken today*, *Quantum-vulnerable (key exchange)*, *Quantum-vulnerable (signature)*, *Weakened* or *Quantum-safe*.
3. **Scores** migration priority from 1 (fix first) to 4 (no action) using **Mosca's rule**.
4. **Reports** a CycloneDX 1.6 CBOM (`cbom.json`) and a Markdown migration plan (`report.md`).

---

## Results

### Scan of public sites (17 Nov 2026)

Run on macOS with Homebrew OpenSSL 3.5+ against the targets in [`targets.json`](targets.json). Full output: [`examples/real-run/report.md`](examples/real-run/report.md) and [`cbom.json`](examples/real-run/cbom.json) (validates against the CycloneDX 1.6 schema).

| Site | Key exchange | Certificate | Cipher | Old TLS accepted | Top priority |
| --- | --- | --- | --- | --- | --- |
| cloudflare.com | `X25519MLKEM768` (hybrid PQ): **quantum-safe** | ECDSA P-256: quantum-vulnerable | AES-256-GCM | TLS 1.0 and 1.1 | 1 (old TLS) |
| google.com | `X25519MLKEM768` (hybrid PQ): **quantum-safe** | ECDSA P-256: quantum-vulnerable | AES-256-GCM | TLS 1.0 and 1.1 | 1 (old TLS) |
| www.onlinesbi.sbi | X25519 only, refuses the hybrid group: **quantum-vulnerable** | RSA-2048: quantum-vulnerable | AES-128-GCM (weakened) | none | 1 (key exchange, 10 + 3 > 10) |
| tls-v1-0.badssl.com:1010 (deliberately weak test site) | ECDHE P-256: quantum-vulnerable | RSA-2048: quantum-vulnerable | AES-256-CBC with SHA-1 | TLS 1.0 | 1 (TLS 1.0) |
| localhost:9 (closed port) | unreachable, scan continued | | | | |

### What went well

- **Hybrid post-quantum detection works on real servers.** Cloudflare and Google both negotiate `X25519MLKEM768`; a bank site that only offers classical X25519 was correctly flagged as priority 1 because its data must stay secret for 10 years (harvest-now-decrypt-later).
- **It shows that hybrid key exchange alone is not "quantum-safe".** Every site, including the two with hybrid key exchange, still authenticates with a classical certificate (ECDSA or RSA), so all four get a quantum-vulnerable signature finding.
- **Legacy TLS detection works.** The deliberately weak test site was flagged for TLS 1.0, and the scan also found that cloudflare.com and google.com still accept TLS 1.0 and 1.1 (confirmed in the raw openssl output).
- **Saved raw output made debugging fast.** The bug below was found and fixed within minutes by reading `out/raw/`.

### What went wrong, and what was done about it

| Issue | Effect | Status |
| --- | --- | --- |
| OpenSSL 3.5 prints `Peer Temp Key:` where older versions print `Server Temp Key:` | On the first real run, the key exchange of the two servers without hybrid support was reported as "unknown" | **Fixed**: the parser accepts both spellings; a test was added. Lesson: parsing human-readable tool output is fragile, so every probe's raw output is kept |
| The cipher label looks only at the AES key size | badssl's `ECDHE-RSA-AES256-SHA` (CBC mode, SHA-1 MAC, over TLS 1.0) is shown as "AES-256, quantum-safe" | Open. The server is still priority 1 because of its TLS 1.0 finding, but the cipher row alone is misleading. Next step: judge mode and MAC, not just key size |
| "Broken today" for TLS 1.0/1.1 on Cloudflare and Google | Correct by the rule, but these operators keep old versions on purpose for legacy clients while modern clients get TLS 1.3 + hybrid | By design: qscan reports facts; whether a legacy fallback is acceptable is a policy decision for a person |
| Non-standard port blocked by the local network | On one run, `tls-v1-0.badssl.com:1010` timed out | Handled: recorded as unreachable and the scan continued; it succeeded on the next run |
| Pattern-based code scanning | One known miss (import alias) and one known false alarm (a string mentioning `hashlib.md5`) in [`samples/known_limits.py`](samples/known_limits.py) | Documented limit; a real tool would parse the code or trace it at run time |

### Test suite

35 unit tests pass: one per label, one per priority band, parser tests on recorded `openssl s_client` output (including the OpenSSL 3.5 format above), scanner-logic tests (hybrid support, legacy TLS, unreachable hosts), and code-scanner tests on planted samples.

### Run against controlled TLS servers

Four local servers with known configurations (OpenSSL 3.0, so the hybrid probe was reported as "not tested"). Full output: [`examples/test-servers/report.md`](examples/test-servers/report.md).

| Server configuration | qscan verdict |
| --- | --- |
| TLS 1.3, X25519 key exchange, RSA-2048 certificate, data secret 10 years, criticality 3 | Key exchange X25519: quantum-vulnerable, **priority 1** (10 + 3 > 10). Certificate RSA: vulnerable signature, **priority 2**. AES-256: safe |
| Accepts only TLS 1.0 | TLS 1.0: broken today, **priority 1** |
| TLS 1.2 with RSA key transport (`AES256-SHA`) | Key exchange RSA: quantum-vulnerable, **priority 2** (5 + 3 <= 10) |
| Closed port | Recorded as unreachable; scan continued |

### Run on source code

All 8 planted weak calls in [`samples/`](samples/) were found with the correct file and line, across Python, C and Java, including Java's `Cipher.getInstance("AES")`, which silently defaults to ECB mode.

---

## Quick start

Requirements: Python 3.10+, and OpenSSL 3.5+ to test hybrid post-quantum key exchange (on macOS: `brew install openssl@3`; qscan finds Homebrew's OpenSSL automatically, or set `QSCAN_OPENSSL=/path/to/openssl`).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python -m pytest -q                              # run the tests
python -m qscan scan targets.json --out out      # full scan -> out/report.md, out/cbom.json
python -m qscan tls targets.json                 # servers only, table in the terminal
python -m qscan code samples                     # one code folder only
```

`targets.json` lists servers and code folders. For each one you set how many years its data must stay secret (`years_secret`) and how critical it is (`criticality`, 1 to 3):

```json
{
  "settings": {"migration_years": 3, "quantum_years": 10},
  "servers": [{"host": "example.com", "port": 443, "years_secret": 10, "criticality": 3}],
  "code_folders": [{"path": "samples", "years_secret": 5, "criticality": 2}]
}
```

Raw `openssl s_client` output for every probe is saved in `out/raw/` so each verdict can be checked by hand.

---

## How it works

```
targets.json ──> tls_scan.py ──┐
                               ├──> findings ──> rules.py ──> score.py ──> report.py ──> cbom.json
code folder  ──> code_scan.py ─┘                 (label)      (priority)               report.md
```

| File | Role |
| --- | --- |
| `qscan/finding.py` | The `Finding` record passed through the pipeline |
| `qscan/tls_scan.py` | Runs up to four `openssl s_client` handshakes per server (normal, hybrid-only, TLS 1.0-only, TLS 1.1-only) and parses the output; reads the certificate with `cryptography` |
| `qscan/code_scan.py` | Regular-expression patterns for Python, C (OpenSSL) and Java (JCA) crypto calls |
| `qscan/rules.py` | The classification table; the label depends on both the algorithm and its job (key exchange vs signature) |
| `qscan/score.py` | Mosca-based priority and sorting |
| `qscan/report.py` | CBOM and Markdown report |
| `qscan/__main__.py` | Command-line interface |

### Scoring

Mosca's rule: with **X** = years the data must stay secret, **Y** = years the migration takes, and **Z** = years until a cryptographically relevant quantum computer, if X + Y > Z the migration is already late. Z is unknown, so it is a setting (default 10), printed on every report.

| Priority | Rule |
| --- | --- |
| 1 | Broken today, or quantum-vulnerable key exchange with X + Y > Z |
| 2 | Quantum-vulnerable key exchange with X + Y <= Z, or vulnerable signature on a criticality-3 system |
| 3 | Other vulnerable signatures, Weakened (AES-128), Unknown |
| 4 | Quantum-safe |

Key exchange ranks above signatures because of harvest-now-decrypt-later: a recorded key exchange can be broken later, while a signature only needs to resist forgery at the moment it is checked. A public key found in code without a clear job is treated as key exchange, the more urgent case.

---

## Limitations

- **Visibility:** only TLS endpoints and source code. Crypto in compiled binaries and libraries, SSH, VPN/IPsec, databases, message queues, key stores, HSMs and cloud KMS is not seen.
- **Code scanning is pattern-based:** aliases and wrapper functions can be missed; strings and dead code can raise false alarms.
- **TLS:** cipher labels look only at key size (not mode or MAC); only the leaf certificate is read; only `X25519MLKEM768` is probed among hybrid groups; an OpenSSL build without TLS 1.0 cannot detect TLS 1.0 support.
- **Business context is manual:** `years_secret` and `criticality` come from the user.
- **Priorities are a ranking, not a prediction**, because Z is an assumption.

---

## Project layout

```
qscan/            the scanner (7 modules)
tests/            pytest suite + recorded s_client outputs
samples/          planted weak crypto in Python, C and Java
examples/         reports and CBOMs from the public-site and controlled-server runs
targets.json      example targets
```

---

## References

- NIST FIPS 203 (ML-KEM) and FIPS 204 (ML-DSA), August 2024
- M. Mosca, "Cybersecurity in an era with quantum computers: will we be ready?", IEEE Security & Privacy, 2018
- IETF draft-ietf-tls-ecdhe-mlkem (hybrid ECDHE-MLKEM key agreement for TLS 1.3)
- CycloneDX 1.6 specification, Cryptography Bill of Materials (CBOM)
- RFC 8996, Deprecating TLS 1.0 and TLS 1.1
