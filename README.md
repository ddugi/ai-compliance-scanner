<div align="center">

# 🛡️ AI Compliance Scanner

**Know your risks before regulators do.**

Scan any AI project for **EU AI Act**, **GDPR** and **OWASP Top 10** gaps — in seconds, offline, right from your terminal or CI pipeline.

[![Compliance Scan](https://github.com/ddugi/ai-compliance-scanner/actions/workflows/compliance-scan.yml/badge.svg)](https://github.com/ddugi/ai-compliance-scanner/actions/workflows/compliance-scan.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/license-MIT-green)
![Rules](https://img.shields.io/badge/rules-27-blueviolet)
![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-ready-003399)
![GDPR](https://img.shields.io/badge/GDPR-checks-003399)
![OWASP](https://img.shields.io/badge/OWASP-Top%2010-000000)

[Quick start](#-quick-start) · [Features](#-features) · [Integrations](#-integrations) · [Rules](#-rules) · [Contributing](#-contributing)

</div>

---

## Why?

The EU AI Act and GDPR put real obligations on teams that build AI products — risk classification, human oversight, transparency, data protection. Most teams find out what they're missing during an audit.

**AI Compliance Scanner** shifts that left. Point it at a project folder and get a clear report: **what is at risk, why it matters, and exactly what to fix** — before the code is merged.

<!-- Tip: add a screenshot of the web UI here, e.g. docs/screenshot.png -->

## ✨ Features

| | |
|---|---|
| 🇪🇺 **EU AI Act** | Risk classification, human oversight, transparency, bias testing, model cards, prohibited use cases |
| 🔐 **GDPR** | PII handling, privacy policy, consent, encryption, data retention, PII in logs, hardcoded secrets |
| 🧱 **OWASP Top 10** | Injection, broken auth, XSS, XXE, insecure deserialization, misconfiguration and more |
| 🖥️ **Rich CLI** | Color-coded risk levels, summary mode, Markdown & JSON export |
| 📊 **Web dashboard** | Compliance score and charts in your browser |
| 🤖 **GitHub Action** | Scans every PR, comments the report and blocks merges on HIGH risk |
| 🪝 **Pre-commit hook** | Stops HIGH risk issues before they ever leave your machine |
| 💬 **Slack alerts** | Score, risk counts and top issues posted to your channel |
| ⚡ **Zero config** | No accounts, no API keys, runs fully offline |

## 🚀 Quick start

```bash
git clone https://github.com/ddugi/ai-compliance-scanner.git
cd ai-compliance-scanner
pip install -r requirements.txt
pip install -e .

ai-compliance-scanner scan ./my-ai-project
```

**Requirements:** Python 3.9+

## 📖 Usage

```bash
# Scan current directory
ai-compliance-scanner scan

# Scan a specific project
ai-compliance-scanner scan ./my-ai-project

# Quick summary only
ai-compliance-scanner quick ./my-ai-project

# Export as JSON or Markdown
ai-compliance-scanner scan ./my-ai-project --format json --output report.json
ai-compliance-scanner scan ./my-ai-project --format markdown --output report.md

# Verbose mode
ai-compliance-scanner scan ./my-ai-project --verbose

# Launch the web dashboard (http://localhost:5050)
ai-compliance-scanner ui --port 5050
```

<details>
<summary><b>Example output</b></summary>

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

</details>

## 🔌 Integrations

### GitHub Action

The workflow ships in [`.github/workflows/compliance-scan.yml`](.github/workflows/compliance-scan.yml). On every push and pull request to `main` it will:

1. Run the full compliance scan
2. Comment the report on the PR
3. Block the merge if any HIGH risk findings exist
4. Upload the report as a downloadable artifact

No configuration needed.

### Pre-commit hook

Block commits that introduce HIGH risk issues:

```bash
python install_hooks.py
```

<details>
<summary>Manual install</summary>

```bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
```

</details>

### Slack alerts

1. Create an [incoming webhook](https://api.slack.com/messaging/webhooks) in Slack
2. Pass it to the scanner — or set it once as an environment variable:

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx/yyy/zzz
ai-compliance-scanner scan ./my-project
```

In GitHub Actions, add `SLACK_WEBHOOK_URL` as a repository secret (**Settings → Secrets and variables → Actions**).

## 📋 Rules

27 rules across three frameworks.

<details open>
<summary><b>🇪🇺 EU AI Act (9)</b></summary>

| Rule ID   | Risk   | Check                         |
|-----------|--------|-------------------------------|
| AIACT-001 | 🔴 HIGH   | No risk classification docs   |
| AIACT-002 | 🔴 HIGH   | No human oversight            |
| AIACT-003 | 🟡 MEDIUM | No AI transparency disclosure |
| AIACT-004 | 🟡 MEDIUM | No technical documentation    |
| AIACT-005 | 🟡 MEDIUM | No bias/fairness testing      |
| AIACT-006 | 🟢 LOW    | No model card                 |
| AIACT-007 | 🔴 HIGH   | Prohibited use case patterns  |
| AIACT-008 | 🟡 MEDIUM | No accuracy metrics           |
| AIACT-009 | 🟢 LOW    | No incident logging           |

</details>

<details>
<summary><b>🔐 GDPR (8)</b></summary>

| Rule ID  | Risk   | Check                         |
|----------|--------|-------------------------------|
| GDPR-001 | 🔴 HIGH   | Personal data in code         |
| GDPR-002 | 🔴 HIGH   | Privacy policy missing        |
| GDPR-003 | 🟡 MEDIUM | No data retention policy      |
| GDPR-004 | 🟡 MEDIUM | No consent mechanism          |
| GDPR-005 | 🔴 HIGH   | No encryption found           |
| GDPR-006 | 🔴 HIGH   | PII in logs                   |
| GDPR-007 | 🟡 MEDIUM | No data export/deletion       |
| GDPR-008 | 🔴 HIGH   | Hardcoded secrets             |

</details>

<details>
<summary><b>🧱 OWASP Top 10 (10)</b></summary>

| Rule ID   | Risk   | Check                            |
|-----------|--------|----------------------------------|
| OWASP-001 | 🔴 HIGH   | Injection vulnerability          |
| OWASP-002 | 🔴 HIGH   | Broken authentication pattern    |
| OWASP-003 | 🔴 HIGH   | Sensitive data exposed in source |
| OWASP-004 | 🟡 MEDIUM | Unsafe XML parsing (XXE)         |
| OWASP-005 | 🔴 HIGH   | Missing access control on routes |
| OWASP-006 | 🟡 MEDIUM | Security misconfiguration        |
| OWASP-007 | 🔴 HIGH   | Cross-site scripting (XSS)       |
| OWASP-008 | 🔴 HIGH   | Insecure deserialization         |
| OWASP-009 | 🟡 MEDIUM | Potentially outdated dependency  |
| OWASP-010 | 🟡 MEDIUM / 🟢 LOW | Insufficient / no audit logging |

</details>

## 🏗️ Project structure

```
scanner/
├── cli.py          # Click-based CLI (scan, quick, ui)
├── analyzer.py     # Runs all rule sets against a project
├── reporter.py     # Rich, Markdown and JSON reports
├── notifier.py     # Slack integration
├── rules/          # gdpr_rules.py · ai_act_rules.py · owasp_rules.py
└── web/            # Flask dashboard
hooks/pre-commit    # Git pre-commit hook
tests/              # pytest suite
```

## 🤝 Contributing

Contributions are welcome — new rules, framework support or bug fixes.

1. Fork the repo and create a branch: `git checkout -b feat/my-rule`
2. Add your rule in `scanner/rules/` and a test in `tests/`
3. Run the tests: `pytest tests/`
4. Open a pull request

## ⚠️ Disclaimer

This tool helps you find common compliance gaps through static analysis. It is **not legal advice** and does not replace a formal compliance assessment.

## 📄 License

[MIT](LICENSE) © 2026 Dugi Selmanaj

---

<div align="center">

Built by **[Dugi Selmanaj](https://github.com/ddugi)** · [DVS Konsult](https://dvskonsult.se)

If this project helps you, consider giving it a ⭐

</div>
