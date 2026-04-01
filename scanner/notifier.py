"""Slack notifier — sends compliance scan results to a Slack channel."""

import json
import urllib.request
import urllib.error
from typing import Any


def _color(summary: dict) -> str:
    if summary.get("high", 0) > 0:
        return "#ef4444"
    if summary.get("medium", 0) > 0:
        return "#f59e0b"
    return "#22c55e"


def _status_text(summary: dict) -> str:
    if summary.get("high", 0) > 0:
        return f"FAILED — {summary['high']} HIGH risk issue(s) found"
    if summary.get("medium", 0) > 0:
        return f"WARNING — {summary['medium']} MEDIUM risk issue(s) found"
    return "PASSED — No HIGH or MEDIUM risk issues"


def _score_label(score: int) -> str:
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "Poor"
    return "Critical"


def compute_score(summary: dict) -> int:
    score = 100
    score -= summary.get("high", 0) * 15
    score -= summary.get("medium", 0) * 7
    score -= summary.get("low", 0) * 3
    return max(0, score)


def build_slack_payload(results: dict[str, Any], project_name: str) -> dict:
    s = results["summary"]
    score = compute_score(s)
    label = _score_label(score)

    findings_gdpr = results.get("gdpr", [])
    findings_ai = results.get("ai_act", [])

    high_findings = [
        f for f in findings_gdpr + findings_ai if f["risk"] == "HIGH"
    ]

    top_issues = "\n".join(
        f"  • [{f['rule_id']}] {f['title']}" for f in high_findings[:5]
    ) or "  None"

    payload = {
        "text": f"*AI Compliance Scan — {project_name}*",
        "attachments": [
            {
                "color": _color(s),
                "blocks": [
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*Status*\n{_status_text(s)}"},
                            {"type": "mrkdwn", "text": f"*Compliance Score*\n{score}/100 — {label}"},
                        ],
                    },
                    {
                        "type": "section",
                        "fields": [
                            {"type": "mrkdwn", "text": f"*HIGH*\n{s.get('high', 0)}"},
                            {"type": "mrkdwn", "text": f"*MEDIUM*\n{s.get('medium', 0)}"},
                            {"type": "mrkdwn", "text": f"*LOW*\n{s.get('low', 0)}"},
                            {"type": "mrkdwn", "text": f"*Files Scanned*\n{s.get('files_scanned', 0)}"},
                        ],
                    },
                    {
                        "type": "section",
                        "text": {
                            "type": "mrkdwn",
                            "text": f"*Top HIGH Risk Issues*\n{top_issues}",
                        },
                    },
                    {"type": "divider"},
                    {
                        "type": "context",
                        "elements": [
                            {
                                "type": "mrkdwn",
                                "text": "AI Compliance Scanner by *DUGI* — github.com/ddugi/ai-compliance-scanner",
                            }
                        ],
                    },
                ],
            }
        ],
    }
    return payload


def send_slack_alert(webhook_url: str, results: dict[str, Any], project_name: str) -> bool:
    """Send compliance scan results to Slack via webhook. Returns True on success."""
    payload = build_slack_payload(results, project_name)
    data = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except urllib.error.URLError as e:
        raise ConnectionError(f"Failed to send Slack alert: {e}")
