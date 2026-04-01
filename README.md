# AI Compliance Scanner

**Know your risks before regulators do.**

An open-source CLI tool that scans AI projects for EU AI Act and GDPR compliance gaps. Built for developers and teams who want to ship AI products responsibly — without hiring a compliance consultant.

Point it at any project folder and get a clear report: what is at risk, why it matters, and exactly what to fix. Runs in seconds, works offline, and integrates directly into your GitHub workflow.

---

## Features

- GDPR checks — PII handling, privacy policy, consent, encryption, data retention, logging, secrets
- EU AI Act checks — Risk classification, human oversight, transparency, bias testing, model cards, prohibited use cases
- Rich terminal output with color-coded risk levels
- Markdown & JSON report export
- Zero config — just point it at a folder
- GitHub Action — auto-scan on every Pull Request, blocks merges on HIGH risk findings

---

## Installation

```bash
git clone https://github.com/ddugi/ai-compliance-scanner.git
cd ai-compliance-scanner
pip install -r requirements.txt
pip install -e .
```

---

## Usage

```bash
# Scan current directory
ai-compliance-scanner scan

# Scan a specific project
ai-compliance-scanner scan ./my-ai-project

# Quick summary only
ai-compliance-scanner quick ./my-ai-project

# Export as JSON
ai-compliance-scanner scan ./my-ai-project --format json --output report.json

# Export as Markdown
ai-compliance-scanner scan ./my-ai-project --format markdown --output report.md

# Verbose mode
ai-compliance-scanner scan ./my-ai-project --verbose

---

## Sample Compliance Report Output

```
╭─────────────────────────────────────────────────────╮
│          AI Compliance Scanner Report               │
│  Project: my-ai-project                             │
│  Files scanned: 24                                  │
│  🔴 HIGH risk: 3  🟡 MEDIUM: 4  🟢 LOW: 2           │
╰─────────────────────────────────────────────────────╯

GDPR Findings
─────────────────────────────────────────────────────
Risk     Rule ID     Title                    Recommendation
🔴 HIGH  GDPR-001    Personal Data Detected   Ensure all personal data is documented in a ROPA...
🔴 HIGH  GDPR-002    No Privacy Policy Found  Add a PRIVACY.md or link to a privacy policy...
🟡 MED   GDPR-003    No Data Retention Policy Define and implement data retention periods...

EU AI Act Findings
─────────────────────────────────────────────────────
Risk     Rule ID     Title                          Recommendation
🔴 HIGH  AIACT-001   No Risk Classification Docs    Document your system's risk classification...
🔴 HIGH  AIACT-002   No Human Oversight Mechanism   Implement human oversight controls (Art. 14)...
🟡 MED   AIACT-005   No Bias Testing Detected       Implement bias and fairness testing...
🟢 LOW   AIACT-006   No Model Card Found            Create a model card documenting intended use...

Report saved to: compliance_report.md
```

---

## GDPR Rules Checked

| Rule ID  | Risk   | Check                         |
|----------|--------|-------------------------------|
| GDPR-001 | HIGH   | Personal data in code         |
| GDPR-002 | HIGH   | Privacy policy missing        |
| GDPR-003 | MEDIUM | No data retention policy      |
| GDPR-004 | MEDIUM | No consent mechanism          |
| GDPR-005 | HIGH   | No encryption found           |
| GDPR-006 | HIGH   | PII in logs                   |
| GDPR-007 | MEDIUM | No data export/deletion       |
| GDPR-008 | HIGH   | Hardcoded secrets             |

## EU AI Act Rules Checked

| Rule ID   | Risk   | Check                         |
|-----------|--------|-------------------------------|
| AIACT-001 | HIGH   | No risk classification docs   |
| AIACT-002 | HIGH   | No human oversight            |
| AIACT-003 | MEDIUM | No AI transparency disclosure |
| AIACT-004 | MEDIUM | No technical documentation    |
| AIACT-005 | MEDIUM | No bias/fairness testing      |
| AIACT-006 | LOW    | No model card                 |
| AIACT-007 | HIGH   | Prohibited use case patterns  |
| AIACT-008 | MEDIUM | No accuracy metrics           |
| AIACT-009 | LOW    | No incident logging           |

---

## Run Tests

```bash
pytest tests/
```

---

## License

MIT License — Copyright (c) 2026 DUGI

---

## Pre-commit Hook

Blocks any `git commit` that has HIGH risk compliance issues before the code reaches GitHub.

**Install in one command:**

```bash
python install_hooks.py
```

Or manually:

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

From that point on, every commit is scanned automatically. If HIGH risk issues are found the commit is blocked with a clear message telling you what to fix.

---

## Slack Alerts

Get a Slack message after every scan with the compliance score, risk counts, and top HIGH risk issues.

**Setup:**

1. Create a Slack incoming webhook at `api.slack.com/apps` — New App, Incoming Webhooks, copy the URL
2. Run the scanner with the webhook:

```bash
ai-compliance-scanner scan ./my-project --slack-webhook https://hooks.slack.com/services/xxx/yyy/zzz
```

Or set it as an environment variable so you never need to pass it manually:

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
ai-compliance-scanner scan ./my-project
```

**GitHub Action:** Add `SLACK_WEBHOOK_URL` as a repository secret in GitHub (`Settings → Secrets → Actions`) and the Action will send alerts automatically on every PR scan.

---

## GitHub Action

Automatically scans every Pull Request and blocks merges if HIGH risk issues are found.

The workflow is already included in `.github/workflows/compliance-scan.yml`. Once pushed to GitHub, it will:

1. Run on every PR to `main`
2. Post a comment on the PR with the full compliance report
3. Block the merge if any HIGH risk findings exist
4. Upload the report as a downloadable artifact

No configuration needed — it works out of the box.

---

## Author

**DUGI** — [https://github.com/ddugi](https://github.com/ddugi)
