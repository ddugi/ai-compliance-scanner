"""EU AI Act compliance rules."""

import re
from pathlib import Path
from typing import Any


class AIActRules:
    def __init__(self, base_path: Path, file_contents: dict[str, str]):
        self.base_path = base_path
        self.files = file_contents
        self.findings: list[dict[str, Any]] = []

    def check(self) -> list[dict[str, Any]]:
        self._check_risk_classification()
        self._check_human_oversight()
        self._check_transparency()
        self._check_technical_documentation()
        self._check_bias_testing()
        self._check_model_card()
        self._check_prohibited_use_cases()
        self._check_accuracy_metrics()
        self._check_incident_logging()
        return self.findings

    def _add(self, rule_id: str, risk: str, title: str, description: str, recommendation: str, file: str = ""):
        self.findings.append({
            "category": "EU AI Act",
            "rule_id": rule_id,
            "risk": risk,
            "title": title,
            "description": description,
            "recommendation": recommendation,
            "file": file,
        })

    def _check_risk_classification(self):
        risk_pattern = re.compile(r"risk.classif|high.risk|limited.risk|minimal.risk|unacceptable.risk", re.IGNORECASE)
        found = any(risk_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-001", "HIGH",
                "No Risk Classification Documentation",
                "No AI risk classification documentation detected in the project.",
                "Document your system's risk classification under the EU AI Act (Annex III). "
                "High-risk systems require conformity assessments before deployment.",
            )

    def _check_human_oversight(self):
        oversight_pattern = re.compile(
            r"human.oversight|human.review|manual.review|human.in.the.loop|hitl|override|escalat",
            re.IGNORECASE,
        )
        found = any(oversight_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-002", "HIGH",
                "No Human Oversight Mechanism Found",
                "No human-in-the-loop or override mechanism detected.",
                "Implement human oversight controls (EU AI Act Art. 14). High-risk AI systems must "
                "allow humans to monitor, override, or shut down the system.",
            )

    def _check_transparency(self):
        transparency_pattern = re.compile(
            r"transparency|explainab|interpretab|ai.disclosure|generated.by.ai|this.is.an.ai",
            re.IGNORECASE,
        )
        found = any(transparency_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-003", "MEDIUM",
                "No AI Transparency Disclosure Found",
                "No transparency or AI-disclosure text detected in the project.",
                "Disclose AI involvement to users (EU AI Act Art. 13 & 52). "
                "Systems interacting with humans must identify themselves as AI.",
            )

    def _check_technical_documentation(self):
        doc_files = {"technical", "architecture", "system_design", "model_card", "datasheet"}
        found = any(
            any(d in Path(f).stem.lower() for d in doc_files)
            for f in self.files
        )
        if not found:
            self._add(
                "AIACT-004", "MEDIUM",
                "Missing Technical Documentation",
                "No technical documentation file (architecture, system design, model card) found.",
                "Create technical documentation describing the AI system's purpose, design, "
                "training data, and limitations (EU AI Act Art. 11 & Annex IV).",
            )

    def _check_bias_testing(self):
        bias_pattern = re.compile(
            r"bias|fairness|discriminat|demographic|equity|debiasing|protected.attribute",
            re.IGNORECASE,
        )
        found = any(bias_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-005", "MEDIUM",
                "No Bias or Fairness Testing Detected",
                "No bias evaluation or fairness testing logic found.",
                "Implement bias and fairness testing across demographic groups (EU AI Act Art. 9 & 10). "
                "Document testing methodology and results.",
            )

    def _check_model_card(self):
        model_card_pattern = re.compile(r"model.card|model_card|MODEL_CARD", re.IGNORECASE)
        found = any(
            model_card_pattern.search(c) or "model_card" in f.lower()
            for f, c in self.files.items()
        )
        if not found:
            self._add(
                "AIACT-006", "LOW",
                "No Model Card Found",
                "No model card document was detected.",
                "Create a model card documenting: intended use, training data, evaluation results, "
                "limitations, and ethical considerations. See modelcards.info for templates.",
            )

    def _check_prohibited_use_cases(self):
        prohibited_pattern = re.compile(
            r"social.scor|emotion.recogni|real.time.biometric|mass.surveil|subliminal|"
            r"manipulat.behav|exploit.vulnerabilit",
            re.IGNORECASE,
        )
        found_in = [f for f, c in self.files.items() if prohibited_pattern.search(c)]
        if found_in:
            self._add(
                "AIACT-007", "HIGH",
                "Potential Prohibited Use Case Detected",
                f"Code patterns matching prohibited AI practices found in: {', '.join(found_in[:3])}",
                "Review against EU AI Act Art. 5 prohibited practices. "
                "Systems involving real-time biometric surveillance, social scoring, or subliminal "
                "manipulation are prohibited in the EU.",
                found_in[0],
            )

    def _check_accuracy_metrics(self):
        accuracy_pattern = re.compile(
            r"accuracy|precision|recall|f1.score|auc|roc|confusion.matrix|benchmark|eval",
            re.IGNORECASE,
        )
        found = any(accuracy_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-008", "MEDIUM",
                "No Accuracy or Performance Metrics Found",
                "No model evaluation or performance metrics detected.",
                "Document accuracy, robustness, and performance metrics (EU AI Act Art. 9). "
                "High-risk systems must meet accuracy thresholds and be continuously monitored.",
            )

    def _check_incident_logging(self):
        incident_pattern = re.compile(
            r"incident|anomaly|alert|monitor|audit.log|post.market|serious.incident",
            re.IGNORECASE,
        )
        found = any(incident_pattern.search(c) for c in self.files.values())
        if not found:
            self._add(
                "AIACT-009", "LOW",
                "No Incident Logging / Post-Market Monitoring",
                "No incident reporting or post-market monitoring logic detected.",
                "Implement incident logging and post-market monitoring (EU AI Act Art. 61 & 62). "
                "High-risk AI providers must report serious incidents to national authorities.",
            )
