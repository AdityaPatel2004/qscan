"""
__main__.py - the front door. `python -m qscan ...` starts here.

The whole program is a straight line:

    targets.json -> tls_scan + code_scan -> findings
                 -> rules.classify_all   (add labels)
                 -> score.score_all      (add priorities, sort)
                 -> report.write_reports (cbom.json + report.md)

Commands:
    python -m qscan scan targets.json --out out    # everything
    python -m qscan tls  targets.json              # servers only, print a table
    python -m qscan code samples                   # one code folder, print a table
"""

import argparse
import json
import os
import sys

from . import code_scan, report, rules, score, tls_scan


def load_targets(path):
    with open(path) as f:
        cfg = json.load(f)
    settings = cfg.get("settings", {})
    y = int(settings.get("migration_years", score.DEFAULT_Y))
    z = int(settings.get("quantum_years", score.DEFAULT_Z))
    return cfg, y, z


def print_table(findings):
    """A quick table for the terminal."""
    print(f"{'P':<2} {'LOCATION':<32} {'USED FOR':<13} {'ALGORITHM':<16} LABEL")
    for f in findings:
        print(f"{f.priority or '-':<2} {f.location[:32]:<32} {f.usage:<13} "
              f"{f.algorithm[:16]:<16} {f.label}")


def main(argv=None):
    parser = argparse.ArgumentParser(prog="qscan", description="Quantum-readiness scanner")
    sub = parser.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="scan servers and code folders, write reports")
    p_scan.add_argument("targets", help="path to targets.json")
    p_scan.add_argument("--out", default="out", help="output folder (default: out)")

    p_tls = sub.add_parser("tls", help="scan only the servers in targets.json")
    p_tls.add_argument("targets")

    p_code = sub.add_parser("code", help="scan one code folder")
    p_code.add_argument("folder")

    args = parser.parse_args(argv)
    y, z = score.DEFAULT_Y, score.DEFAULT_Z
    findings = []

    if args.command in ("scan", "tls"):
        cfg, y, z = load_targets(args.targets)
        raw_dir = os.path.join(args.out, "raw") if args.command == "scan" else None
        if raw_dir and os.path.isdir(raw_dir):      # remove last run's raw files
            for name in os.listdir(raw_dir):
                if name.endswith(".txt"):
                    os.remove(os.path.join(raw_dir, name))
        findings += tls_scan.scan_servers(cfg.get("servers", []), raw_dir)
        if args.command == "scan":
            for folder in cfg.get("code_folders", []):
                findings += code_scan.scan_folder(folder["path"],
                                                  folder.get("years_secret", 5),
                                                  folder.get("criticality", 2))
    else:
        findings += code_scan.scan_folder(args.folder)

    rules.classify_all(findings)
    score.score_all(findings, y, z)
    print_table(findings)

    if args.command == "scan":
        cbom_path, md_path = report.write_reports(findings, args.out, y, z)
        print(f"\nWrote {cbom_path} and {md_path}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
