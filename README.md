<p align="center">
  <img src="assets/logo.png" alt="LogSentinel Logo" width="350">
</p>

<h1 align="center">LogSentinel</h1>

<p align="center">
  Sensitive Data Exposure Scanner for Log Files
</p>

<p align="center">
  Detect • Analyze • Protect
</p>

A self-contained Python tool for **VAPT log reviews**. It scans application /
API log files supplied by a client, finds **sensitive data that should never be
written to logs** (CWE-532), and generates a **professional PDF report** with a
severity-rated index, masked evidence keyed by file / location / timestamp,
impact and mitigation for every finding.

Designed to run on **Windows** (also works on macOS / Linux). Pure Python — no
external services, nothing leaves your machine.

---

## What it detects

| Severity | Detected data |
|----------|---------------|
| Critical | Private keys, plaintext passwords/secrets, payment card numbers (Luhn-checked), CVV, cloud access keys (AWS), JWT / auth tokens |
| High     | Bearer / API tokens, Aadhaar (Verhoeff-checked), PAN, OTP, bank account numbers, session IDs |
| Medium   | Phone numbers, email addresses, IFSC codes, date of birth |
| Low      | IPv4 addresses (octet-validated) |

To reduce false positives the tool applies structural validators — **Luhn** for
cards, the **Verhoeff** checksum for Aadhaar, **PAN structure**, and IPv4 octet
range checks. You can add, remove or tune detectors in `detectors.py`.

## Supported input formats

`.log` `.txt` `.out` · `.json` · `.jsonl` / `.ndjson` · `.csv` · `.tsv` ·
`.xlsx` / `.xlsm` / `.xls`

Point it at individual files or at a folder (folders are scanned recursively).

---

## Install (Windows)

1. Install Python 3.9+ from <https://www.python.org/downloads/> (tick
   *"Add Python to PATH"* during setup).
2. Open **Command Prompt** or **PowerShell** in the tool folder and run:

```bat
pip install -r requirements.txt
```

## Usage

```bat
python log_analyzer.py -i <file_or_folder> [more...] -o report.pdf [options]
```

### Examples

```bat
:: Scan a whole folder of client logs
python log_analyzer.py -i .\client_logs -o ACME_log_report.pdf --client "ACME Bank" --tester "XYZ Security"

:: Scan specific mixed-format files
python log_analyzer.py -i app.log api_dump.json txns.xlsx -o report.pdf

:: Also emit machine-readable findings
python log_analyzer.py -i .\logs -o report.pdf --json findings.json
```

### Options

| Option | Description |
|--------|-------------|
| `-i, --input` | One or more files or folders (folders are recursive). **Required.** |
| `-o, --output` | Output PDF path (default `log_sensitive_report.pdf`). |
| `--client` | Client name shown on the report. |
| `--tester` | Your name / VAPT firm. |
| `--target` | Scope description. |
| `--title` | Report title. |
| `--json PATH` | Also write findings as JSON (for re-use / ticketing). |
| `--no-mask` | Show full sensitive values in the report. **Not recommended** — the report would itself contain live secrets. |
| `--max-evidence N` | Max evidence rows shown per finding (default 25). |

---

## The PDF report contains

1. **Cover page** — client, scope, tester, date, severity summary.
2. **Index of findings** — severity classification table + a findings index
   (ID, vulnerability, severity, instance count).
3. **Executive summary** + methodology.
4. **Severity classification** legend.
5. **Detailed findings**, ordered Critical → Info. Each finding has:
   - a unique ID (`VAPT-LOG-001`, …) used as the primary key,
   - vulnerability name + severity + CWE/OWASP/PCI references,
   - an **evidence table**: file, location (line / row / sheet!row),
     **timestamp** (the per-record primary key) and the **masked** value,
   - **impact** description,
   - **recommendation / mitigation**.
6. **Appendix** — detector coverage and scope/disclaimer.

> **Evidence is masked by default** (e.g. `41************11`) so the report can be
> shared without leaking the very data you're reporting on.

---

## Project layout

```
logscan/
├── log_analyzer.py   # CLI entry point (run this)
├── detectors.py      # detection rules + validators (edit to tune/extend)
├── parsers.py        # multi-format log loaders
├── reporter.py       # PDF report builder
├── requirements.txt
└── README.md
```

## Extending

Add a new detector by appending a `Detector(...)` to the `DETECTORS` list in
`detectors.py`. For labelled key/value patterns set `value_group=2` and capture
the value in the second group; add a `validator=` callback to suppress false
positives.

## Notes & limitations

- Pattern matching produces false positives and false negatives; **validate
  findings against the source data** before remediation sign-off.
- 12-digit numbers that coincidentally pass the Verhoeff check (e.g. a phone
  number with country code) may surface under Aadhaar — confirm in context.
- This is a point-in-time review limited to the supplied samples and configured
  detectors.
