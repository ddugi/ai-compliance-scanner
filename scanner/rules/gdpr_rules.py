"""GDPR compliance rules."""

import re
from pathlib import Path
from typing import Any


class GDPRRules:
    def __init__(self, base_path: Path, file_contents: dict[str, str]):
        self.base_path = base_path
        self.files = file_contents
        self.findings: list[dict[str, Any]] = []

    def check(self) -> list[dict[str, Any]]:
        self._check_personal_data_handling()
        self._check_privacy_policy()
        self._check_data_retention()
        self._check_consent_mechanism()
        self._check_encryption()
        self._check_logging_pii()
        self._check_data_export_deletion()
        self._check_env_secrets()
        return self.findings

    def _add(self, rule_id: str, risk: str, title: str, description: str, recommendation: str, file: str = ""):
        self.findings.append({
            "category": "GDPR",
            "rule_id": rule_id,
            "risk": risk,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "file": file,
        })

    def _check_personal_data_handling(self):
        pii_patterns = re.compile(
            r"\b(email|password|ssn|social.security|date.of.birth|dob|phone.number|"
            r"credit.card|passport|national.id|ip.address|biometric)\b",
            re.IGNORECASE,
        )
        found_in = []
        for fname, content in self.files.items():
            if pii_patterns.search(content):
                found_in.append(fname)

        if found_in:
            self._add(
                "GDPR-001", "HIGH",
                "Personal Data Detected",
                f"Potential personal data fields found in: {', '.join(found_in[:3])}{'...' if len(found_in) > 3 else ''}",
                "Ensure all personal data is documented in a ROPA (Records of Processing Activities). "
                "Apply data minimization and pseudonymization where possible.",
                found_in[0] if found_in else "",
            )

    def _check_privacy_policy(self):
        policy_files = {"privacy", "privacy_policy", "datenschutz", "gdpr"}
        found = any(
            any(p in Path(f).stem.lower() for p in policy_files)
            for f in self.files
        )
        if not found:
            self._add(
                "GDPR-002", "HIGH",
                "No Privacy Policy Found",
                "No privacy policy document was detected in the project.",
                "Add a PRIVACY.md or link to a privacy policy. Required under GDPR Art. 13/14 "
                "for any system processing personal data.",
            )

    def _check_data_retention(self):
        retention_pattern = re.compile(r"retention|data.expir|delete.after|ttl|time.to.live", re.IGNORECASE)
        found = any(retention_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "GDPR-003", "MEDIUM",
                "No Data Retention Policy Detected",
                "No retention period or data expiry logic was found.",
                "Define and implement data retention periods. Personal data must not be kept longer "
                "than necessary (GDPR Art. 5(1)(e)).",
            )

    def _check_consent_mechanism(self):
        consent_pattern = re.compile(r"consent|opt.in|opt.out|accept.*terms|cookie.*consent", re.IGNORECASE)
        found = any(consent_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "GDPR-004", "MEDIUM",
                "No Consent Mechanism Found",
                "No consent collection or opt-in/opt-out logic detected.",
                "Implement explicit consent mechanisms before collecting personal data (GDPR Art. 7). "
                "Consent must be freely given, specific, informed, and unambiguous.",
            )

    def _check_encryption(self):
        encrypt_pattern = re.compile(r"encrypt|aes|rsa|bcrypt|argon2|sha256|tls|ssl|https", re.IGNORECASE)
        found = any(encrypt_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "GDPR-005", "HIGH",
                "No Encryption Implementation Found",
                "No encryption libraries or patterns were detected in the codebase.",
                "Encrypt personal data at rest and in transit (GDPR Art. 32). "
                "Use TLS for all network communication and strong hashing for passwords.",
            )

    def _check_logging_pii(self):
        log_pii_pattern = re.compile(
            r"(log|print|console\.log|logger)\s*[\.\(].*?(email|password|ssn|phone|token|secret)",
            re.IGNORECASE,
        )
        found_in = [f for f, c in self.files.items() if log_pii_pattern.search(c)]
        if found_in:
            self._add(
                "GDPR-006", "HIGH",
                "Potential PII Logging Detected",
                f"Possible personal data being logged in: {', '.join(found_in[:3])}",
                "Never log personal data or secrets. Mask or redact sensitive fields before logging. "
                "Review all log statements for PII exposure.",
                found_in[0],
            )

    def _check_data_export_deletion(self):
        export_pattern = re.compile(r"export.*data|download.*data|right.to.erasure|delete.*user|forget.*user", re.IGNORECASE)
        found = any(export_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "GDPR-007", "MEDIUM",
                "No Data Export / Deletion Mechanism Found",
                "No data portability or right-to-erasure functionality detected.",
                "Implement data export (Art. 20) and deletion endpoints (Art. 17 — Right to Erasure). "
                "Users must be able to request their data and request deletion.",
            )

    def _check_env_secrets(self):
        secret_pattern = re.compile(r"(api_key|secret|password|token)\s*=\s*['\"]?.{8,}", re.IGNORECASE)
        found_in = []
        for fname, content in self.files.items():
            if ".env.example" in fname:
                continue
            if secret_pattern.search(content) and ".env" not in fname:
                found_in.append(fname)
        if found_in:
            self._add(
                "GDPR-008", "HIGH",
                "Hardcoded Secrets Detected",
                f"API keys or secrets may be hardcoded in: {', '.join(found_in[:3])}",
                "Never hardcode secrets. Use environment variables or a secrets manager. "
                "Rotate any exposed credentials immediately.",
                found_in[0],
            )
