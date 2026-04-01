let currentResults = null;
let currentPath = null;
let allFindings = [];
let riskChart = null;
let categoryChart = null;
let scoreChart = null;

async function runScan() {
  const path = document.getElementById("pathInput").value.trim();
  if (!path) return;

  currentPath = path;

  show("loadingState");
  hide("emptyState");
  hide("results");
  hide("errorState");
  document.getElementById("scanBtn").disabled = true;

  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
    });
    const data = await res.json();

    if (!res.ok || data.error) {
      showError(data.error || "Scan failed");
      return;
    }

    currentResults = data;
    renderResults(data);
  } catch (e) {
    showError("Could not connect to the scanner server.");
  } finally {
    document.getElementById("scanBtn").disabled = false;
    hide("loadingState");
  }
}

function renderResults(data) {
  const s = data.summary;

  document.getElementById("projectName").textContent = data.project_name;
  document.getElementById("fileCount").textContent = `${s.files_scanned} files scanned`;
  document.getElementById("highCount").textContent = s.high;
  document.getElementById("mediumCount").textContent = s.medium;
  document.getElementById("lowCount").textContent = s.low;
  document.getElementById("totalCount").textContent = s.total;

  const scoreEl = document.getElementById("scoreNumber");
  scoreEl.textContent = data.score;
  scoreEl.style.color = data.score_color;
  document.getElementById("scoreLabel").textContent = data.score_label;
  document.getElementById("gaugeLabel").textContent = data.score_label;

  allFindings = [...(data.gdpr || []), ...(data.ai_act || [])];
  renderFindings(allFindings);
  renderCharts(s, data.score, data.score_color);

  show("results");
  show("exportButtons");

  // Reset filter tabs
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  document.querySelector(".tab").classList.add("active");
}

function renderFindings(findings) {
  const tbody = document.getElementById("findingsBody");
  const noFindings = document.getElementById("noFindings");

  if (!findings.length) {
    tbody.innerHTML = "";
    noFindings.style.display = "block";
    return;
  }

  noFindings.style.display = "none";
  const sorted = [...findings].sort((a, b) =>
    ["HIGH", "MEDIUM", "LOW"].indexOf(a.risk) - ["HIGH", "MEDIUM", "LOW"].indexOf(b.risk)
  );

  tbody.innerHTML = sorted.map(f => `
    <tr>
      <td><span class="badge badge-${f.risk.toLowerCase()}">${f.risk}</span></td>
      <td><span class="rule-id">${f.rule_id}</span></td>
      <td>${f.category}</td>
      <td>${f.title}</td>
      <td>${f.recommendation}</td>
    </tr>
  `).join("");
}

function filterFindings(filter, btn) {
  document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
  btn.classList.add("active");

  if (filter === "all") {
    renderFindings(allFindings);
    return;
  }

  const filtered = allFindings.filter(f =>
    f.risk === filter || f.category === filter
  );
  renderFindings(filtered);
}

function renderCharts(s, score, scoreColor) {
  if (riskChart) riskChart.destroy();
  if (categoryChart) categoryChart.destroy();
  if (scoreChart) scoreChart.destroy();

  const chartDefaults = {
    plugins: { legend: { labels: { color: "#8892a4", font: { size: 12 } } } }
  };

  // Risk breakdown doughnut
  riskChart = new Chart(document.getElementById("riskChart"), {
    type: "doughnut",
    data: {
      labels: ["HIGH", "MEDIUM", "LOW"],
      datasets: [{
        data: [s.high, s.medium, s.low],
        backgroundColor: ["#ef4444", "#f59e0b", "#22c55e"],
        borderWidth: 0,
      }]
    },
    options: {
      ...chartDefaults,
      cutout: "65%",
    }
  });

  // Category breakdown bar
  const gdprCount = (currentResults.gdpr || []).length;
  const aiActCount = (currentResults.ai_act || []).length;

  categoryChart = new Chart(document.getElementById("categoryChart"), {
    type: "bar",
    data: {
      labels: ["GDPR", "EU AI Act"],
      datasets: [{
        label: "Findings",
        data: [gdprCount, aiActCount],
        backgroundColor: ["#3b82f6", "#8b5cf6"],
        borderRadius: 6,
        borderWidth: 0,
      }]
    },
    options: {
      ...chartDefaults,
      scales: {
        x: { ticks: { color: "#8892a4" }, grid: { color: "#2a3044" } },
        y: { ticks: { color: "#8892a4", stepSize: 1 }, grid: { color: "#2a3044" } }
      },
      plugins: { legend: { display: false } }
    }
  });

  // Score gauge doughnut
  scoreChart = new Chart(document.getElementById("scoreChart"), {
    type: "doughnut",
    data: {
      labels: ["Score", ""],
      datasets: [{
        data: [score, 100 - score],
        backgroundColor: [scoreColor, "#2a3044"],
        borderWidth: 0,
      }]
    },
    options: {
      cutout: "72%",
      plugins: { legend: { display: false }, tooltip: { enabled: false } },
    }
  });
}

async function exportJSON() {
  if (!currentResults) return;
  const res = await fetch("/api/export/json", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ results: currentResults }),
  });
  downloadBlob(await res.blob(), "compliance_report.json");
}

async function exportMarkdown() {
  if (!currentResults || !currentPath) return;
  const res = await fetch("/api/export/markdown", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ results: currentResults, path: currentPath }),
  });
  downloadBlob(await res.blob(), "compliance_report.md");
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function show(id) { document.getElementById(id).style.display = ""; }
function hide(id) { document.getElementById(id).style.display = "none"; }

function showError(msg) {
  document.getElementById("errorMsg").textContent = msg;
  show("errorState");
  hide("loadingState");
  hide("results");
}

document.getElementById("pathInput").addEventListener("keydown", e => {
  if (e.key === "Enter") runScan();
});
