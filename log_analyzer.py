#!/usr/bin/env python3
"""
log_analyzer.py  --  Sensitive Data Exposure scanner for log files (VAPT)
========================================================================

Scans application / API log files for sensitive data that must never be logged
(CWE-532) -- auth tokens, OTPs, phone numbers, PAN, Aadhaar, payment cards,
passwords, etc. -- and produces a professional PDF report with a severity-rated
index, masked evidence keyed by file/location/timestamp, impact and mitigation.

Runs on Windows, macOS and Linux (pure Python).

USAGE
-----
    python log_analyzer.py -i <file_or_folder> [more...] [options]

EXAMPLES
--------
    python log_analyzer.py -i .\\logs -o api_log_report.pdf --client "ACME Bank"
    python log_analyzer.py -i app.log api_dump.json export.xlsx --tester "XYZ Security"

OPTIONS
-------
    -i, --input        One or more files or folders (folders scanned recursively)
    -o, --output       Output PDF path           (default: log_sensitive_report.pdf)
        --client       Client name for the report
        --tester       Your name / VAPT firm
        --target       Scope description
        --json         Also write machine-readable findings to this JSON path
        --no-mask      Show full sensitive values in the report (NOT recommended)
        --max-evidence Max evidence rows shown per finding (default 25)
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from datetime import datetime

from detectors import DETECTORS, SEVERITY_ORDER, mask_value
from parsers import gather_files, parse_file

TOOL_NAME = "LogScan"
SUPPORTED = (".log", ".txt", ".out", ".json", ".jsonl", ".ndjson",
             ".csv", ".tsv", ".xlsx", ".xlsm", ".xls")


def scan(files: list[str], mask: bool = True):
    """Return (findings, stats). findings are grouped per detector."""
    # grouped[detector_id] = list of instance dicts
    grouped: dict[str, list[dict]] = defaultdict(list)
    files_for: dict[str, set] = defaultdict(set)
    total_records = 0

    det_by_id = {d.id: d for d in DETECTORS}

    for path in files:
        for rec in parse_file(path):
            total_records += 1
            for det in DETECTORS:
                for m, value in det.finditer(rec.text):
                    ts = rec.timestamp or ""
                    evidence = value if not mask else mask_value(value)
                    grouped[det.id].append({
                        "file": rec.file,
                        "location": rec.location,
                        "timestamp": ts,
                        "evidence": evidence,
                    })
                    files_for[det.id].add(rec.file)

    # Build sorted, ID-stamped findings
    findings = []
    ordered_ids = sorted(
        grouped.keys(),
        key=lambda did: (SEVERITY_ORDER.get(det_by_id[did].severity, 9),
                         -len(grouped[did]))
    )
    for n, did in enumerate(ordered_ids, 1):
        det = det_by_id[did]
        instances = grouped[did]
        findings.append({
            "id": f"VAPT-LOG-{n:03d}",
            "detector_id": did,
            "name": det.name,
            "severity": det.severity,
            "references": det.references,
            "impact": det.impact,
            "recommendation": det.recommendation,
            "count": len(instances),
            "files": sorted(files_for[did]),
            "instances": instances,
        })

    stats = {"total_files": len(files), "total_records": total_records}
    return findings, stats


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Scan log files for sensitive data exposure (VAPT) and "
                    "produce a PDF report.")
    p.add_argument("-i", "--input", nargs="+", required=True,
                   help="Files or folders to scan (folders are recursive).")
    p.add_argument("-o", "--output", default="log_sensitive_report.pdf",
                   help="Output PDF path.")
    p.add_argument("--client", default="Client")
    p.add_argument("--tester", default="VAPT Team")
    p.add_argument("--target", default="Mobile & Web Application API logs")
    p.add_argument("--title", default="Log File Sensitive Data Exposure Assessment")
    p.add_argument("--json", dest="json_out", default=None,
                   help="Also write findings as JSON to this path.")
    p.add_argument("--no-mask", action="store_true",
                   help="Show full sensitive values (NOT recommended).")
    p.add_argument("--max-evidence", type=int, default=25,
                   help="Max evidence rows per finding in the PDF.")
    args = p.parse_args(argv)

    files = gather_files(args.input)
    if not files:
        print("[!] No files found for the given input.", file=sys.stderr)
        return 2

    scannable = [f for f in files if os.path.splitext(f)[1].lower() in SUPPORTED]
    skipped = [f for f in files if f not in scannable]
    if skipped:
        print(f"[i] Skipping {len(skipped)} unsupported file(s); "
              f"treating only known log types. Use a supported extension "
              f"({', '.join(SUPPORTED)}) if these are logs.")

    print(f"[i] Scanning {len(scannable)} file(s)...")
    findings, stats = scan(scannable or files, mask=not args.no_mask)

    crit = sum(1 for f in findings if f["severity"] == "Critical")
    high = sum(1 for f in findings if f["severity"] == "High")
    print(f"[i] Records scanned : {stats['total_records']}")
    print(f"[i] Findings        : {len(findings)} type(s), "
          f"{sum(f['count'] for f in findings)} instance(s) "
          f"(Critical={crit}, High={high})")

    meta = {
        "report_title": args.title,
        "client": args.client,
        "tester": args.tester,
        "target": args.target,
        "date": datetime.now().strftime("%d %b %Y"),
        "total_files": stats["total_files"],
        "total_records": stats["total_records"],
        "tool_name": TOOL_NAME,
    }

    from reporter import build_report
    out = build_report(findings, meta, args.output,
                        max_evidence_rows=args.max_evidence)
    print(f"[+] PDF report written: {out}")

    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump({"meta": meta, "findings": findings}, fh,
                      ensure_ascii=False, indent=2)
        print(f"[+] JSON findings written: {args.json_out}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
