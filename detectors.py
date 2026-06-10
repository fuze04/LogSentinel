"""
detectors.py
------------
Sensitive-data detection rules for the log analyzer.

Each Detector describes ONE class of sensitive data that should never appear
in application/API logs (CWE-532: Insertion of Sensitive Information into Log
File). A detector carries everything the PDF report needs: a human-readable
vulnerability name, severity, references, impact text and a recommendation.

To reduce false positives, many detectors carry a `validator` callback
(e.g. Luhn for payment cards, the Verhoeff checksum for Aadhaar numbers, octet
range checks for IPv4). A match is only kept if the validator returns True.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


# --------------------------------------------------------------------------- #
# Validators (used to cut down false positives)
# --------------------------------------------------------------------------- #

def luhn_valid(number: str) -> bool:
    """Luhn checksum used by all major payment-card networks."""
    digits = [int(d) for d in re.sub(r"\D", "", number)]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# Verhoeff tables (used by UIDAI to validate Aadhaar numbers)
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]
_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def verhoeff_valid(number: str) -> bool:
    """Verhoeff checksum validation for 12-digit Aadhaar numbers."""
    digits = re.sub(r"\D", "", number)
    if len(digits) != 12:
        return False
    if digits[0] in ("0", "1"):  # UIDAI: Aadhaar never starts with 0 or 1
        return False
    c = 0
    for i, item in enumerate(reversed(digits)):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][int(item)]]
    return c == 0


def ipv4_valid(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def pan_valid(value: str) -> bool:
    """Indian PAN: AAAAA9999A. 4th char is holder-type, restricted set."""
    value = value.upper()
    if not re.fullmatch(r"[A-Z]{5}[0-9]{4}[A-Z]", value):
        return False
    # 4th character = holder type (P,C,H,F,A,T,B,L,J,G)
    return value[3] in "PCHFATBLJG"


def not_already_masked(value: str) -> bool:
    """Skip values that are already redacted (e.g. ****, ••••, xxxx)."""
    stripped = value.strip()
    if not stripped:
        return False
    masking_chars = set("*•xX.#")
    return not all(ch in masking_chars for ch in stripped)


# --------------------------------------------------------------------------- #
# Detector definition
# --------------------------------------------------------------------------- #

@dataclass
class Detector:
    id: str                       # short stable code, e.g. "JWT"
    name: str                     # vulnerability name shown in the report
    severity: str                 # Critical | High | Medium | Low | Info
    pattern: str                  # regex
    impact: str                   # impact description (report)
    recommendation: str           # mitigation / recommendation (report)
    references: str = ""          # CWE / OWASP references
    value_group: int = 0          # which regex group holds the value to report
    flags: int = 0
    validator: Optional[Callable[[str], bool]] = None
    _compiled: re.Pattern = field(init=False, repr=False, default=None)

    def __post_init__(self):
        self._compiled = re.compile(self.pattern, self.flags)

    def finditer(self, text: str):
        for m in self._compiled.finditer(text):
            value = m.group(self.value_group) if self.value_group else m.group(0)
            if value is None:
                continue
            if self.validator and not self.validator(value):
                continue
            yield m, value


# --------------------------------------------------------------------------- #
# The detector catalogue
# --------------------------------------------------------------------------- #
# Order roughly follows severity; the engine sorts properly later.

_LABEL = r'''["']?\s*[:=]\s*["']?'''   # generic key/value separator

DETECTORS: list[Detector] = [

    # ----------------------------- CRITICAL ------------------------------- #
    Detector(
        id="PRIVATE_KEY",
        name="Private Cryptographic Key Disclosed in Logs",
        severity="Critical",
        pattern=r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
        references="CWE-532, CWE-312, OWASP A02:2021 (Cryptographic Failures)",
        impact=(
            "A private key written to logs allows an attacker who can read the "
            "log file to impersonate the server/user, decrypt intercepted "
            "traffic, or forge signatures. This is a full compromise of the "
            "associated cryptographic trust."
        ),
        recommendation=(
            "Never log key material. Rotate the exposed key immediately, purge "
            "it from all log storage and backups, and store keys only in a "
            "secrets manager / HSM."
        ),
    ),
    Detector(
        id="PASSWORD",
        name="Plaintext Password / Credential in Logs",
        severity="Critical",
        pattern=r'(?i)\b(pass(?:word|wd)?|pwd|secret|credential)\b' + _LABEL + r'([^\s"\',&}{]{3,80})',
        value_group=2,
        validator=not_already_masked,
        references="CWE-532, CWE-256, OWASP A04:2021, A09:2021",
        impact=(
            "Plaintext credentials in logs let anyone with log access (ops "
            "staff, SIEM operators, attackers who exfiltrate logs) authenticate "
            "as the affected user or service and pivot further into the system."
        ),
        recommendation=(
            "Strip credential fields before logging. Mask request bodies on "
            "auth endpoints, rotate any exposed credentials, and add log "
            "scrubbing/redaction middleware."
        ),
    ),
    Detector(
        id="CARD_PAN",
        name="Payment Card Number (PAN) in Logs",
        severity="Critical",
        pattern=r"(?<![\d.])\d(?:[ -]?\d){12,18}(?![\d.])",
        validator=luhn_valid,
        references="CWE-532, PCI-DSS Req. 3.4, OWASP A09:2021",
        impact=(
            "Storing a Primary Account Number in logs is a direct PCI-DSS "
            "violation and enables payment fraud. Logs are typically retained "
            "and widely accessible, multiplying the breach exposure."
        ),
        recommendation=(
            "Never log full card numbers. If display is required, mask to the "
            "last 4 digits. Tokenize card data and keep it out of application "
            "logs entirely."
        ),
    ),
    Detector(
        id="CVV",
        name="Card Verification Value (CVV/CVC) in Logs",
        severity="Critical",
        pattern=r"(?i)\b(cvv2?|cvc2?|cid|card[\s_-]?verification)\b" + _LABEL + r"(\d{3,4})\b",
        value_group=2,
        references="CWE-532, PCI-DSS Req. 3.2 (CVV must never be stored)",
        impact=(
            "CVV must never be stored after authorization under PCI-DSS. Its "
            "presence in logs enables card-not-present fraud and is a serious "
            "compliance failure."
        ),
        recommendation=(
            "Remove CVV from all logging immediately and purge historical logs. "
            "CVV must only ever be held transiently in memory during the "
            "authorization request."
        ),
    ),
    Detector(
        id="AWS_KEY",
        name="Cloud Access Key (AWS) in Logs",
        severity="Critical",
        pattern=r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b",
        references="CWE-532, CWE-798, OWASP A07:2021",
        impact=(
            "A leaked cloud access key may grant programmatic access to cloud "
            "infrastructure, data stores and billing. Attackers actively scrape "
            "logs and repos for such keys."
        ),
        recommendation=(
            "Revoke and rotate the key immediately, review CloudTrail/activity "
            "for misuse, and use short-lived role-based credentials instead of "
            "static keys."
        ),
    ),
    Detector(
        id="JWT",
        name="JSON Web Token (JWT) / Auth Token in Logs",
        severity="Critical",
        pattern=r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b",
        references="CWE-532, OWASP A09:2021, OWASP API2:2023 (Broken Authn)",
        impact=(
            "A JWT in logs can be replayed until expiry to fully impersonate the "
            "user/session. The token payload also commonly leaks PII (user id, "
            "email, roles)."
        ),
        recommendation=(
            "Never log Authorization headers or tokens. Redact bearer tokens in "
            "request logging, shorten token lifetimes, and support server-side "
            "revocation."
        ),
    ),

    # ------------------------------- HIGH --------------------------------- #
    Detector(
        id="BEARER",
        name="Bearer / Authorization Token in Logs",
        severity="High",
        pattern=r"(?i)\b(?:authorization|bearer|x-api-key|api[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token)\b"
                + r'["\']?\s*[:=]?\s*(?:bearer\s+)?["\']?([A-Za-z0-9._\-]{12,})',
        value_group=1,
        validator=not_already_masked,
        references="CWE-532, OWASP A09:2021, OWASP API2:2023",
        impact=(
            "Authorization tokens / API keys in logs allow session or API "
            "impersonation. Anyone with log read access can reuse them within "
            "their validity window."
        ),
        recommendation=(
            "Redact Authorization headers and token query parameters before "
            "logging. Treat API keys as secrets and rotate any that appear in "
            "logs."
        ),
    ),
    Detector(
        id="AADHAAR",
        name="Aadhaar Number (India National ID) in Logs",
        severity="High",
        pattern=r"(?<!\d)[2-9]\d{3}\s?\d{4}\s?\d{4}(?!\d)",
        validator=verhoeff_valid,
        references="CWE-532, India DPDP Act 2023, Aadhaar Act 2016",
        impact=(
            "Aadhaar is a sensitive national identifier. Its exposure in logs "
            "breaches the DPDP Act and the Aadhaar Act, enables identity theft "
            "and KYC fraud, and carries regulatory penalties."
        ),
        recommendation=(
            "Do not log Aadhaar. Where reference is unavoidable, store only a "
            "masked form (last 4 digits) or a one-way reference token, and "
            "encrypt at rest."
        ),
    ),
    Detector(
        id="PAN_INDIA",
        name="PAN (India Permanent Account Number) in Logs",
        severity="High",
        pattern=r"(?<![A-Za-z0-9])[A-Z]{5}[0-9]{4}[A-Z](?![A-Za-z0-9])",
        validator=pan_valid,
        references="CWE-532, India DPDP Act 2023, Income Tax Act",
        impact=(
            "A PAN is a financial/tax identifier and sensitive personal data. "
            "Exposure enables identity and financial fraud and breaches Indian "
            "data-protection obligations."
        ),
        recommendation=(
            "Avoid logging PAN. If display is required, mask all but the last 4 "
            "characters and encrypt stored values."
        ),
    ),
    Detector(
        id="OTP",
        name="One-Time Password (OTP) in Logs",
        severity="High",
        pattern=r"(?i)\b(otp|one[\s_-]?time[\s_-]?(?:password|code|pin)|verification[\s_-]?code|auth[\s_-]?code|2fa|mfa|security[\s_-]?code)\b"
                + r'["\']?\s*[:=]?\s*["\']?(\d{4,8})\b',
        value_group=2,
        references="CWE-532, OWASP A09:2021, OWASP API2:2023",
        impact=(
            "OTPs in logs defeat two-factor authentication. An insider or "
            "attacker reading logs in near-real-time can complete logins or "
            "transactions on behalf of the user."
        ),
        recommendation=(
            "Never log OTP values. Log only an opaque event ('OTP sent') with no "
            "code, keep OTP lifetimes short, and invalidate on use."
        ),
    ),
    Detector(
        id="BANK_ACCOUNT",
        name="Bank Account Number in Logs",
        severity="High",
        pattern=r"(?i)\b(account[\s_-]?(?:number|no|num)|a/?c[\s_-]?no|acct)\b" + _LABEL + r"(\d{9,18})\b",
        value_group=2,
        references="CWE-532, India DPDP Act 2023, RBI guidelines",
        impact=(
            "Bank account numbers in logs facilitate financial fraud and "
            "unauthorized debit attempts, and constitute sensitive financial "
            "personal data."
        ),
        recommendation=(
            "Mask account numbers in logs (last 4 digits only) and encrypt any "
            "stored financial identifiers."
        ),
    ),
    Detector(
        id="SESSION_ID",
        name="Session Identifier in Logs",
        severity="High",
        pattern=r"(?i)\b(jsessionid|phpsessid|sessionid|session[_-]?id|sid|connect\.sid)\b" + _LABEL + r"([A-Za-z0-9._%\-]{10,})",
        value_group=2,
        validator=not_already_masked,
        references="CWE-532, CWE-384, OWASP A07:2021",
        impact=(
            "A session identifier in logs allows session hijacking: an attacker "
            "can replay the session cookie to take over the authenticated user "
            "session."
        ),
        recommendation=(
            "Do not log session identifiers or Set-Cookie headers. Rotate "
            "session IDs on privilege change and bind sessions to additional "
            "context."
        ),
    ),

    # ------------------------------ MEDIUM -------------------------------- #
    Detector(
        id="PHONE_IN",
        name="Phone Number (PII) in Logs",
        severity="Medium",
        pattern=r"(?<![\d])(?:\+91[\-\s]?|0)?[6-9]\d{9}(?![\d])",
        references="CWE-532, CWE-359, India DPDP Act 2023",
        impact=(
            "Phone numbers are personal data. In logs they enable user tracking, "
            "correlation across systems, SIM-swap / smishing targeting and "
            "breach the data-minimisation principle."
        ),
        recommendation=(
            "Avoid logging full phone numbers. Mask to the last 2-4 digits where "
            "a reference is needed, and apply log retention limits."
        ),
    ),
    Detector(
        id="EMAIL",
        name="Email Address (PII) in Logs",
        severity="Medium",
        pattern=r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
        references="CWE-532, CWE-359, OWASP A09:2021",
        impact=(
            "Email addresses are personal data useful for phishing and account "
            "correlation. Mass exposure via logs increases breach impact and "
            "regulatory exposure."
        ),
        recommendation=(
            "Minimise logging of email addresses; use internal user IDs instead. "
            "If logged, mask the local part and enforce retention limits."
        ),
    ),
    Detector(
        id="IFSC",
        name="IFSC Bank Code in Logs",
        severity="Medium",
        pattern=r"(?<![A-Za-z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Za-z0-9])",
        references="CWE-532, India DPDP Act 2023",
        impact=(
            "An IFSC code combined with an account number (often nearby in the "
            "same log) is enough to initiate transfers and aids financial fraud."
        ),
        recommendation=(
            "Avoid logging full banking coordinates; where required, separate "
            "and mask financial fields."
        ),
    ),
    Detector(
        id="DOB",
        name="Date of Birth (PII) in Logs",
        severity="Medium",
        pattern=r"(?i)\b(dob|date[\s_-]?of[\s_-]?birth|birth[\s_-]?date)\b" + _LABEL + r"(\d{1,4}[-/]\d{1,2}[-/]\d{1,4})",
        value_group=2,
        references="CWE-532, CWE-359, India DPDP Act 2023",
        impact=(
            "Date of birth is sensitive personal data widely used for identity "
            "verification; its exposure aids identity theft and account-recovery "
            "abuse."
        ),
        recommendation=(
            "Do not log date of birth. Where age checks are needed, log only a "
            "derived boolean (e.g. 'is_adult')."
        ),
    ),

    # ------------------------------- LOW / INFO --------------------------- #
    Detector(
        id="IPV4",
        name="Internal/Client IP Address in Logs",
        severity="Low",
        pattern=r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])",
        validator=ipv4_valid,
        references="CWE-532, CWE-359 (IP can be PII under GDPR/DPDP)",
        impact=(
            "IP addresses can be personal data and may reveal internal network "
            "topology. Useful to an attacker for reconnaissance and user "
            "geolocation/correlation."
        ),
        recommendation=(
            "Treat IPs as personal data: limit retention, restrict access, and "
            "consider truncating the last octet for analytics use cases."
        ),
    ),
]


SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


def mask_value(value: str, keep: int = 2) -> str:
    """Mask the middle of a sensitive value so the report is not itself a leak."""
    value = str(value)
    n = len(value)
    if n <= 2:
        return "*" * n
    if n <= keep * 2:
        return value[0] + "*" * (n - 1)
    return value[:keep] + "*" * (n - keep * 2) + value[-keep:]
