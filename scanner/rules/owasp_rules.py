"""
OWASP Top 10 compliance rules for the AI Compliance Scanner.
Checks for common web application security vulnerabilities.
Author: DUGI
"""

import re
from pathlib import Path
from typing import List, Dict, Any


def check_injection(files: List[Path]) -> Dict[str, Any]:
    """OWASP-001: SQL/Command Injection — detect unsafe query construction."""
    patterns = [
        r'execute\s*\(\s*f["\']',
        r'cursor\.execute\s*\(\s*".*\+',
        r'cursor\.execute\s*\(\s*\'.*\+',
        r'query\s*=\s*["\'].*\+\s*\w',
        r'query\s*=\s*f["\'].*\{',
        r'os\.system\s*\(\s*f["\']',
        r'os\.system\s*\(\s*.*\+',
        r'subprocess\.\w+\s*\(\s*.*shell\s*=\s*True.*\+',
        r'subprocess\.\w+\s*\(\s*f["\'].*shell\s*=\s*True',
    ]
    for path in files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            if re.search(pattern, text):
                return {
                    "rule_id": "OWASP-001",
                    "title": "Injection Vulnerability Detected",
                    "risk": "HIGH",
                    "description": "Unsafe query or command construction found. User input may be passed directly to SQL or shell.",
                    "recommendation": "Use parameterized queries for SQL. Never pass unsanitized input to os.system or subprocess with shell=True.",
                }
    return None


def check_broken_auth(files: List[Path]) -> Dict[str, Any]:
    """OWASP-002: Broken Authentication — detect weak session or auth patterns."""
    patterns = [
        r'SECRET_KEY\s*=\s*["\'][a-zA-Z0-9]{1,12}["\']',
        r'session\[.token.\]\s*=\s*str\(uuid',
        r'jwt\.encode\(.*algorithm\s*=\s*["\']none["\']',
        r'jwt\.decode\(.*verify\s*=\s*False',
        r'verify\s*=\s*False',
        r'check_password_hash\s*\(\s*\)',
        r'password\s*==\s*["\']',
    ]
    for path in files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return {
                    "rule_id": "OWASP-002",
                    "title": "Broken Authentication Pattern",
                    "risk": "HIGH",
                    "description": "Weak or insecure authentication pattern detected. This may allow attackers to bypass login or hijack sessions.",
                    "recommendation": "Use strong random SECRET_KEY. Use proper JWT verification. Never compare passwords as plain strings.",
                }
    return None


def check_sensitive_data_exposure(files: List[Path]) -> Dict[str, Any]:
    """OWASP-003: Sensitive Data Exposure — plain text passwords or keys in source."""
    patterns = [
        r'password\s*=\s*["\'][^"\']{3,}["\']',
        r'passwd\s*=\s*["\'][^"\']{3,}["\']',
        r'db_password\s*=\s*["\']',
        r'api_key\s*=\s*["\'][^"\']{8,}["\']',
        r'secret\s*=\s*["\'][^"\']{8,}["\']',
        r'token\s*=\s*["\'][^"\']{16,}["\']',
    ]
    for path in files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        lower = text.lower()
        for pattern in patterns:
            if re.search(pattern, lower):
                return {
                    "rule_id": "OWASP-003",
                    "title": "Sensitive Data Exposed in Source",
                    "risk": "HIGH",
                    "description": "Passwords, tokens, or API keys appear to be hardcoded in source code.",
                    "recommendation": "Store secrets in environment variables or a secrets manager. Never commit credentials to source control.",
                }
    return None


def check_xxe(files: List[Path]) -> Dict[str, Any]:
    """OWASP-004: XML External Entities (XXE) — unsafe XML parsing."""
    patterns = [
        r'etree\.parse\s*\(',
        r'xml\.etree',
        r'minidom\.parse',
        r'lxml\.etree',
        r'defusedxml',
    ]
    dangerous = [r'etree\.parse', r'minidom\.parse', r'xml\.etree']
    safe = [r'defusedxml']
    for path in files:
        if path.suffix not in (".py", ".js", ".ts", ".java"):
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        has_dangerous = any(re.search(p, text) for p in dangerous)
        has_safe = any(re.search(p, text) for p in safe)
        if has_dangerous and not has_safe:
            return {
                "rule_id": "OWASP-004",
                "title": "Unsafe XML Parsing (XXE Risk)",
                "risk": "MEDIUM",
                "description": "XML parsing without XXE protection detected. Attackers can use malicious XML to read local files or make server-side requests.",
                "recommendation": "Use defusedxml instead of the standard xml library for parsing untrusted XML input.",
            }
    return None


def check_broken_access_control(files: List[Path]) -> Dict[str, Any]:
    """OWASP-005: Broken Access Control — missing auth decorators on routes."""
    route_pattern = re.compile(r'@app\.route\s*\(|@router\.(get|post|put|delete|patch)\s*\(')
    auth_pattern = re.compile(r'@login_required|@require_permission|@jwt_required|@auth\.login_required|requires_auth|verify_token|check_permission')
    for path in files:
        if path.suffix not in (".py", ".js", ".ts"):
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        routes = route_pattern.findall(text)
        if len(routes) > 2 and not auth_pattern.search(text):
            return {
                "rule_id": "OWASP-005",
                "title": "Missing Access Control on Routes",
                "risk": "HIGH",
                "description": "Web routes found without access control decorators. Users may access unauthorized resources.",
                "recommendation": "Add authentication and authorization checks to all routes that expose sensitive data or actions.",
            }
    return None


def check_security_misconfiguration(files: List[Path]) -> Dict[str, Any]:
    """OWASP-006: Security Misconfiguration — debug mode on, default credentials."""
    patterns = [
        r'DEBUG\s*=\s*True',
        r'app\.run\(.*debug\s*=\s*True',
        r'TESTING\s*=\s*True',
        r'username\s*=\s*["\']admin["\']',
        r'password\s*=\s*["\']admin["\']',
        r'password\s*=\s*["\']password["\']',
        r'password\s*=\s*["\']1234',
    ]
    for path in files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return {
                    "rule_id": "OWASP-006",
                    "title": "Security Misconfiguration",
                    "risk": "MEDIUM",
                    "description": "Debug mode enabled or default credentials detected. This exposes detailed error messages and may allow unauthorized access.",
                    "recommendation": "Disable debug mode in production. Change all default passwords. Use environment-specific configuration.",
                }
    return None


def check_xss(files: List[Path]) -> Dict[str, Any]:
    """OWASP-007: Cross-Site Scripting (XSS) — unsafe output rendering."""
    patterns = [
        r'render_template_string\s*\(',
        r'Markup\s*\(\s*request\.',
        r'innerHTML\s*=\s*.*\+',
        r'document\.write\s*\(',
        r'\|\s*safe',
    ]
    for path in files:
        if path.suffix not in (".py", ".js", ".ts", ".html"):
            continue
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            if re.search(pattern, text):
                return {
                    "rule_id": "OWASP-007",
                    "title": "Cross-Site Scripting (XSS) Risk",
                    "risk": "HIGH",
                    "description": "Potentially unsafe HTML rendering detected. User input may be rendered as HTML without sanitization.",
                    "recommendation": "Always escape user input before rendering. Avoid render_template_string with user data. Use Content Security Policy headers.",
                }
    return None


def check_insecure_deserialization(files: List[Path]) -> Dict[str, Any]:
    """OWASP-008: Insecure Deserialization — pickle or unsafe YAML load."""
    patterns = [
        r'pickle\.loads\s*\(',
        r'pickle\.load\s*\(',
        r'yaml\.load\s*\([^,)]+\)',
        r'marshal\.loads\s*\(',
        r'jsonpickle\.decode\s*\(',
    ]
    safe_yaml = re.compile(r'yaml\.safe_load\s*\(')
    for path in files:
        try:
            text = path.read_text(errors="ignore")
        except Exception:
            continue
        for pattern in patterns:
            if re.search(pattern, text):
                if "yaml.load" in pattern and safe_yaml.search(text):
                    continue
                return {
                    "rule_id": "OWASP-008",
                    "title": "Insecure Deserialization",
                    "risk": "HIGH",
                    "description": "Unsafe deserialization detected (pickle, unsafe yaml.load, or marshal). Deserializing untrusted data can lead to remote code execution.",
                    "recommendation": "Never deserialize untrusted data with pickle or marshal. Use yaml.safe_load instead of yaml.load.",
                }
    return None


def check_known_vulnerabilities(files: List[Path]) -> Dict[str, Any]:
    """OWASP-009: Using Components with Known Vulnerabilities."""
    req_files = [p for p in files if p.name in ("requirements.txt", "package.json", "Pipfile")]
    known_vulnerable = {
        "django": "2.",
        "flask": "0.",
        "requests": "2.18",
        "urllib3": "1.2",
        "pyyaml": "5.",
    }
    for path in req_files:
        try:
            text = path.read_text(errors="ignore").lower()
        except Exception:
            continue
        for lib, old_version in known_vulnerable.items():
            if lib in text and old_version in text:
                return {
                    "rule_id": "OWASP-009",
                    "title": "Potentially Outdated Dependency",
                    "risk": "MEDIUM",
                    "description": f"Dependency '{lib}' may be pinned to an old version with known vulnerabilities.",
                    "recommendation": "Run 'pip install --upgrade <package>' and audit dependencies regularly. Use 'pip-audit' or 'safety check'.",
                }
    return None


def check_insufficient_logging(files: List[Path]) -> Dict[str, Any]:
    """OWASP-010: Insufficient Logging and Monitoring."""
    has_logging = False
    has_audit_log = False
    log_patterns = [r'import logging', r'logger\s*=', r'logging\.get']
    audit_patterns = [r'audit', r'security_log', r'access_log', r'event_log']
    for path in files:
        if path.suffix not in (".py", ".js", ".ts"):
            continue
        try:
            text = path.read_text(errors="ignore").lower()
        except Exception:
            continue
        if any(re.search(p, text) for p in log_patterns):
            has_logging = True
        if any(p in text for p in audit_patterns):
            has_audit_log = True
    if not has_logging:
        return {
            "rule_id": "OWASP-010",
            "title": "Insufficient Logging",
            "risk": "MEDIUM",
            "description": "No logging framework detected. Without logs, security incidents are difficult to detect and investigate.",
            "recommendation": "Add structured logging for authentication, authorization failures, and critical operations. Use a centralized log management system.",
        }
    if has_logging and not has_audit_log:
        return {
            "rule_id": "OWASP-010",
            "title": "No Security Audit Logging",
            "risk": "LOW",
            "description": "Basic logging found but no security audit trail detected.",
            "recommendation": "Add dedicated audit logging for login attempts, access control decisions, and data changes.",
        }
    return None


OWASP_RULES = [
    check_injection,
    check_broken_auth,
    check_sensitive_data_exposure,
    check_xxe,
    check_broken_access_control,
    check_security_misconfiguration,
    check_xss,
    check_insecure_deserialization,
    check_known_vulnerabilities,
    check_insufficient_logging,
]
