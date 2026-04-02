"""Core analyzer — scans project files and applies compliance rules."""

import os
from pathlib import Path
from typing import Any

from .rules.gdpr_rules import GDPRRules
from .rules.ai_act_rules import AIActRules
from .rules.owasp_rules import OWASP_RULES


SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".env", "dist", "build"}
SCAN_EXTENSIONS = {".py", ".js", ".ts", ".yaml", ".yml", ".json", ".md", ".txt", ".env.example", ".cfg", ".toml"}


class Analyzer:
    def __init__(self, path: Path, verbose: bool = False):
        self.path = path
        self.verbose = verbose
        self.files: list[Path] = []
        self.results: dict[str, Any] = {
            "gdpr": [],
            "ai_act": [],
            "owasp": [],
            "summary": {},
            "scanned_files": [],
        }

    def collect_files(self):
        for root, dirs, files in os.walk(self.path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for f in files:
                fp = Path(root) / f
                if fp.suffix in SCAN_EXTENSIONS or fp.name in {".env.example", "Dockerfile", "docker-compose.yml"}:
                    self.files.append(fp)

    def run(self) -> dict[str, Any]:
        self.collect_files()
        self.results["scanned_files"] = [str(f.relative_to(self.path)) for f in self.files]

        file_contents: dict[str, str] = {}
        for fp in self.files:
            try:
                file_contents[str(fp.relative_to(self.path))] = fp.read_text(errors="ignore")
            except Exception:
                pass

        gdpr = GDPRRules(self.path, file_contents)
        self.results["gdpr"] = gdpr.check()

        ai_act = AIActRules(self.path, file_contents)
        self.results["ai_act"] = ai_act.check()

        owasp_findings = []
        for rule_fn in OWASP_RULES:
            finding = rule_fn(self.files)
            if finding:
                owasp_findings.append(finding)
        self.results["owasp"] = owasp_findings

        self._build_summary()
        return self.results

    def _build_summary(self):
        all_findings = self.results["gdpr"] + self.results["ai_act"] + self.results.get("owasp", [])
        self.results["summary"] = {
            "total": len(all_findings),
            "high": sum(1 for f in all_findings if f["risk"] == "HIGH"),
            "medium": sum(1 for f in all_findings if f["risk"] == "MEDIUM"),
            "low": sum(1 for f in all_findings if f["risk"] == "LOW"),
            "files_scanned": len(self.files),
        }
