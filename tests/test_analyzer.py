"""Tests for the compliance analyzer."""

import pytest
from pathlib import Path
from unittest.mock import patch
import tempfile
import os

from scanner.analyzer import Analyzer
from scanner.rules.gdpr_rules import GDPRRules
from scanner.rules.ai_act_rules import AIActRules
from scanner.rules.owasp_rules import (
    check_injection,
    check_broken_auth,
    check_sensitive_data_exposure,
    check_security_misconfiguration,
    check_xss,
    check_insecure_deserialization,
    check_insufficient_logging,
)


@pytest.fixture
def temp_project(tmp_path):
    """Create a minimal fake project for testing."""
    (tmp_path / "main.py").write_text("email = user.email\nprint(email)\n")
    (tmp_path / "config.yaml").write_text("api_key: supersecret123\n")
    return tmp_path


@pytest.fixture
def clean_project(tmp_path):
    """Create a project with good compliance practices."""
    (tmp_path / "PRIVACY.md").write_text("# Privacy Policy\nThis app collects minimal data.\n")
    (tmp_path / "main.py").write_text(
        "# AI Disclosure: This system uses AI.\n"
        "# human oversight: manual review required\n"
        "# data retention: 30 days\n"
        "# consent: opt-in required\n"
        "import ssl  # encryption\n"
    )
    return tmp_path


class TestGDPRRules:
    def test_detects_pii(self, temp_project):
        contents = {"main.py": (temp_project / "main.py").read_text()}
        rules = GDPRRules(temp_project, contents)
        findings = rules.check()
        rule_ids = [f["rule_id"] for f in findings]
        assert "GDPR-001" in rule_ids

    def test_detects_missing_privacy_policy(self, temp_project):
        contents = {"main.py": "print('hello')"}
        rules = GDPRRules(temp_project, contents)
        findings = rules.check()
        rule_ids = [f["rule_id"] for f in findings]
        assert "GDPR-002" in rule_ids

    def test_detects_hardcoded_secrets(self, temp_project):
        contents = {"config.py": "AWS_SECRET_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE'\npassword = 'hunter2'\n"}
        rules = GDPRRules(temp_project, contents)
        findings = rules.check()
        rule_ids = [f["rule_id"] for f in findings]
        assert "GDPR-008" in rule_ids

    def test_no_false_positives_on_clean_project(self, clean_project):
        contents = {f: (clean_project / f).read_text() for f in ["PRIVACY.md", "main.py"]}
        rules = GDPRRules(clean_project, contents)
        findings = rules.check()
        # Privacy policy should not trigger GDPR-002
        assert "GDPR-002" not in [f["rule_id"] for f in findings]


class TestAIActRules:
    def test_detects_missing_risk_classification(self, temp_project):
        contents = {"main.py": "print('no risk docs here')"}
        rules = AIActRules(temp_project, contents)
        findings = rules.check()
        rule_ids = [f["rule_id"] for f in findings]
        assert "AIACT-001" in rule_ids

    def test_detects_missing_human_oversight(self, temp_project):
        contents = {"main.py": "result = model.predict(x)"}
        rules = AIActRules(temp_project, contents)
        findings = rules.check()
        rule_ids = [f["rule_id"] for f in findings]
        assert "AIACT-002" in rule_ids

    def test_all_findings_have_required_fields(self, temp_project):
        contents = {"main.py": "print('test')"}
        rules = AIActRules(temp_project, contents)
        findings = rules.check()
        for finding in findings:
            assert "rule_id" in finding
            assert "risk" in finding
            assert finding["risk"] in ("HIGH", "MEDIUM", "LOW")
            assert "title" in finding
            assert "recommendation" in finding


class TestOWASPRules:
    def test_detects_injection(self, tmp_path):
        (tmp_path / "db.py").write_text('cursor.execute("SELECT * FROM users WHERE id=" + user_id)\n')
        finding = check_injection(list(tmp_path.iterdir()))
        assert finding is not None
        assert finding["rule_id"] == "OWASP-001"

    def test_detects_debug_mode(self, tmp_path):
        (tmp_path / "app.py").write_text("DEBUG = True\napp.run()\n")
        finding = check_security_misconfiguration(list(tmp_path.iterdir()))
        assert finding is not None
        assert finding["rule_id"] == "OWASP-006"

    def test_detects_pickle(self, tmp_path):
        (tmp_path / "model.py").write_text("import pickle\ndata = pickle.loads(raw)\n")
        finding = check_insecure_deserialization(list(tmp_path.iterdir()))
        assert finding is not None
        assert finding["rule_id"] == "OWASP-008"

    def test_detects_missing_logging(self, tmp_path):
        (tmp_path / "main.py").write_text("print('no logging here')\n")
        finding = check_insufficient_logging(list(tmp_path.iterdir()))
        assert finding is not None
        assert finding["rule_id"] == "OWASP-010"

    def test_no_injection_on_safe_code(self, tmp_path):
        (tmp_path / "db.py").write_text('cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))\n')
        finding = check_injection(list(tmp_path.iterdir()))
        assert finding is None

    def test_owasp_included_in_analyzer(self, temp_project):
        analyzer = Analyzer(temp_project)
        results = analyzer.run()
        assert "owasp" in results


class TestAnalyzer:
    def test_run_returns_expected_keys(self, temp_project):
        analyzer = Analyzer(temp_project)
        results = analyzer.run()
        assert "gdpr" in results
        assert "ai_act" in results
        assert "owasp" in results
        assert "summary" in results
        assert "scanned_files" in results

    def test_summary_counts_match(self, temp_project):
        analyzer = Analyzer(temp_project)
        results = analyzer.run()
        s = results["summary"]
        assert s["total"] == s["high"] + s["medium"] + s["low"]

    def test_skips_hidden_dirs(self, tmp_path):
        (tmp_path / ".git").mkdir()
        (tmp_path / ".git" / "config").write_text("secret stuff")
        (tmp_path / "main.py").write_text("print('hello')")
        analyzer = Analyzer(tmp_path)
        analyzer.collect_files()
        assert not any(".git" in str(f) for f in analyzer.files)
