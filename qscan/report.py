"""
report.py - write the results down, twice.

  cbom.json : for machines. A CycloneDX 1.6 "Cryptography Bill of
              Materials": one entry per algorithm found, with every
              place it was found. Other tools can read this file.
  report.md : for people. A findings table sorted by priority and a
              short migration plan.
"""

import json
import os
import uuid
from collections import OrderedDict
from datetime import datetime, timezone

from . import __version__, rules

# CycloneDX names for "what kind of crypto is this"
PRIMITIVE = {
    "key exchange": "key-agree",
    "signature": "signature",
    "cipher": "block-cipher",
    "hash": "hash",
    "public key": "unknown",
}

# NIST post-quantum security category (0 = broken by a quantum computer).
QUANTUM_LEVEL = {
    "X25519MLKEM768": 3, "ML-KEM-512": 1, "ML-KEM-768": 3, "ML-KEM-1024": 5,
    "ML-DSA-44": 2, "ML-DSA-65": 3, "ML-DSA-87": 5,
    "AES-128": 1, "AES-256": 5, "CHACHA20": 5,
    "SHA-256": 2, "SHA-384": 4, "SHA-512": 5,
}

PRIORITY_NAMES = {1: "1 - fix first", 2: "2", 3: "3", 4: "4 - no action"}


# ----------------------------------------------------------------------
# CBOM (machine-readable)
# ----------------------------------------------------------------------

def occurrence(f):
    """One place where an algorithm was seen."""
    occ = {"location": f.location, "additionalContext": f.detail}
    if f.source == "code":
        path, _, line = f.location.rpartition(":")
        occ["location"], occ["line"] = path, int(line)
    return occ


def make_component(f):
    """The CBOM entry for one (algorithm, usage) pair."""
    if f.usage == "protocol":      # TLS1.0 / TLS1.1
        crypto = {"assetType": "protocol",
                  "protocolProperties": {"type": "tls", "version": f.algorithm.replace("TLS", "")}}
    else:
        primitive = PRIMITIVE.get(f.usage, "unknown")
        if f.usage == "key exchange" and "MLKEM" in f.algorithm.replace("-", ""):
            primitive = "kem"
        if f.algorithm in ("CHACHA20", "RC4"):
            primitive = "stream-cipher"
        props = {"primitive": primitive}
        if f.label in (rules.BROKEN, rules.QV_KEX, rules.QV_SIG):
            props["nistQuantumSecurityLevel"] = 0
        elif f.algorithm in QUANTUM_LEVEL:
            props["nistQuantumSecurityLevel"] = QUANTUM_LEVEL[f.algorithm]
        crypto = {"assetType": "algorithm", "algorithmProperties": props}

    slug = f"{f.algorithm}-{f.usage}".lower().replace(" ", "-")
    return {
        "type": "cryptographic-asset",
        "bom-ref": f"crypto/{slug}",
        "name": f.algorithm,
        "cryptoProperties": crypto,
        "evidence": {"occurrences": []},
        "properties": [
            {"name": "qscan:usage", "value": f.usage},
            {"name": "qscan:label", "value": f.label},
            {"name": "qscan:priority", "value": str(f.priority)},
            {"name": "qscan:migrateTo", "value": f.migrate_to},
        ],
    }


def build_cbom(findings):
    components = OrderedDict()
    for f in findings:
        if f.label == rules.UNREACHABLE:
            continue
        key = (f.algorithm, f.usage)
        if key not in components:
            components[key] = make_component(f)
        comp = components[key]
        comp["evidence"]["occurrences"].append(occurrence(f))
        # if the same algorithm got different priorities, keep the most urgent
        old = int(comp["properties"][2]["value"])
        if f.priority and f.priority < old:
            comp["properties"][2]["value"] = str(f.priority)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application", "name": "qscan",
                                      "version": __version__}]},
        },
        "components": list(components.values()),
    }


# ----------------------------------------------------------------------
# Markdown report (human-readable)
# ----------------------------------------------------------------------

def cell(text):
    return str(text).replace("|", "\\|").replace("\n", " ")


def build_markdown(findings, y, z):
    scored = [f for f in findings if f.priority]
    unreachable = [f for f in findings if not f.priority]
    now = datetime.now().strftime("%Y-%m-%d %H:%M")

    out = [f"# qscan report", "",
           f"Generated {now} by qscan {__version__}. "
           f"Settings: migration time Y = {y} years, assumed years to a quantum "
           f"computer Z = {z} years (an assumption, not a prediction).", ""]

    # summary
    out += ["## Summary", "", "| Priority | Findings |", "| --- | --- |"]
    for p in (1, 2, 3, 4):
        out.append(f"| {PRIORITY_NAMES[p]} | {sum(1 for f in scored if f.priority == p)} |")
    out.append(f"| unreachable | {len(unreachable)} |")
    out.append("")

    # findings table
    out += ["## Findings", "",
            "| # | Priority | Location | Used for | Algorithm | Label | Migrate to | Detail |",
            "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for i, f in enumerate(scored, 1):
        out.append("| " + " | ".join(cell(x) for x in (
            i, f.priority, f.location, f.usage, f.algorithm, f.label, f.migrate_to, f.detail)) + " |")
    out.append("")

    # migration plan, one block per priority band
    out += ["## Migration plan", ""]
    for p in (1, 2, 3):
        band = [f for f in scored if f.priority == p]
        if not band:
            continue
        out += [f"### Priority {PRIORITY_NAMES[p]}", ""]
        actions = OrderedDict()
        for f in band:
            actions.setdefault((f.algorithm, f.usage, f.migrate_to), []).append(f.location)
        for (algo, usage, to), places in actions.items():
            out.append(f"- **{algo}** ({usage}) -> {to}. Found at: {', '.join(places)}")
        out.append("")
    if not any(f.priority in (1, 2, 3) for f in scored):
        out += ["Nothing to migrate.", ""]

    if unreachable:
        out += ["## Unreachable targets", ""]
        out += [f"- {f.location}: {f.detail}" for f in unreachable]
        out.append("")

    out += ["## What this scan cannot see", "",
            "- Crypto inside compiled binaries and third-party libraries.",
            "- Crypto outside HTTPS: SSH, VPN/IPsec, databases, message queues, Java key stores.",
            "- Keys in HSMs, cloud KMS and vaults; certificates in internal stores.",
            "- What the data is worth: years-secret and criticality come from a person, not the scan.",
            ""]
    return "\n".join(out)


def write_reports(findings, out_dir, y, z):
    os.makedirs(out_dir, exist_ok=True)
    cbom_path = os.path.join(out_dir, "cbom.json")
    md_path = os.path.join(out_dir, "report.md")
    with open(cbom_path, "w") as f:
        json.dump(build_cbom(findings), f, indent=2)
    with open(md_path, "w") as f:
        f.write(build_markdown(findings, y, z))
    return cbom_path, md_path
