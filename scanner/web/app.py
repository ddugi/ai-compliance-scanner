"""Flask web UI for AI Compliance Scanner."""

from flask import Flask, render_template, request, jsonify, send_file
from pathlib import Path
import json
import io

from ..analyzer import Analyzer
from ..reporter import Reporter

app = Flask(__name__)


def compute_score(summary: dict) -> int:
    score = 100
    score -= summary.get("high", 0) * 15
    score -= summary.get("medium", 0) * 7
    score -= summary.get("low", 0) * 3
    return max(0, score)


def score_label(score: int) -> str:
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Moderate"
    elif score >= 40:
        return "Poor"
    return "Critical"


def score_color(score: int) -> str:
    if score >= 80:
        return "#22c55e"
    elif score >= 60:
        return "#f59e0b"
    elif score >= 40:
        return "#f97316"
    return "#ef4444"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    path = data.get("path", "").strip()

    if not path:
        return jsonify({"error": "No path provided"}), 400

    target = Path(path).expanduser().resolve()
    if not target.exists():
        return jsonify({"error": f"Path does not exist: {target}"}), 400
    if not target.is_dir():
        return jsonify({"error": "Path must be a directory"}), 400

    try:
        analyzer = Analyzer(target)
        results = analyzer.run()

        score = compute_score(results["summary"])
        results["score"] = score
        results["score_label"] = score_label(score)
        results["score_color"] = score_color(score)
        results["project_name"] = target.name

        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/export/json", methods=["POST"])
def export_json():
    data = request.get_json()
    results = data.get("results", {})
    buf = io.BytesIO(json.dumps(results, indent=2).encode())
    buf.seek(0)
    return send_file(buf, mimetype="application/json", as_attachment=True, download_name="compliance_report.json")


@app.route("/api/export/markdown", methods=["POST"])
def export_markdown():
    data = request.get_json()
    results = data.get("results", {})
    path = data.get("path", ".")
    target = Path(path).expanduser().resolve()

    reporter = Reporter(results, target)
    tmp = Path("/tmp/compliance_report.md")
    reporter._save_markdown(str(tmp))

    return send_file(str(tmp), mimetype="text/markdown", as_attachment=True, download_name="compliance_report.md")


def main():
    print("AI Compliance Scanner — Web UI")
    print("Open http://localhost:5050 in your browser")
    app.run(host="0.0.0.0", port=5050, debug=False)


if __name__ == "__main__":
    main()
