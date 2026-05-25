const form = document.querySelector("#connection-form");
const testBtn = document.querySelector("#test-btn");
const scanBtn = document.querySelector("#scan-btn");
const statusBox = document.querySelector("#connection-status");
const health = document.querySelector("#health");
const filterInput = document.querySelector("#filter");
const resultsBody = document.querySelector("#results-body");
const riskRulesBody = document.querySelector("#risk-rules-body");
const scanMeta = document.querySelector("#scan-meta");
const tabs = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");
const themeToggle = document.querySelector("#theme-toggle");
const addAssetBtn = document.querySelector("#add-asset-btn");
const saveAssetsBtn = document.querySelector("#save-assets-btn");
const assetPattern = document.querySelector("#asset-pattern");
const assetLevel = document.querySelector("#asset-level");
const assetReason = document.querySelector("#asset-reason");
const assetRuleList = document.querySelector("#asset-rule-list");
const assetSaveStatus = document.querySelector("#asset-save-status");
const reportPreview = document.querySelector("#report-preview");
const exportCsvBtn = document.querySelector("#export-csv-btn");
const exportWordBtn = document.querySelector("#export-word-btn");
const exportPdfBtn = document.querySelector("#export-pdf-btn");

const DEFAULT_ASSETS = [
  { pattern: "password", level: "CRITICAL", reason: "Credential files are crown-jewel assets" },
  { pattern: "finance", level: "HIGH", reason: "Finance folders carry regulated business data" },
];

let latestFiles = [];
let latestReport = null;
let rowOverrides = loadRowOverrides();
let assetRules = loadAssetRules();
let editingAssetIndex = null;

async function api(path, payload) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }

  return response.json();
}

function readPayload() {
  const data = new FormData(form);
  return {
    server: data.get("server") || "",
    domain: data.get("domain") || "WORKGROUP",
    username: data.get("username") || "",
    password: data.get("password") || "",
    local_path: data.get("local_path") || "test_data",
    max_depth: Number(data.get("max_depth") || 4),
    asset_overrides: assetRules,
  };
}

function setBusy(isBusy) {
  testBtn.disabled = isBusy;
  scanBtn.disabled = isBusy;
}

function setStatus(message, tone = "muted") {
  statusBox.className = `status ${tone}`;
  statusBox.textContent = message;
}

function updateSummary(summary = {}) {
  document.querySelector("#critical-count").textContent = summary.critical || 0;
  document.querySelector("#high-count").textContent = summary.high || 0;
  document.querySelector("#medium-count").textContent = summary.medium || 0;
  document.querySelector("#low-count").textContent = summary.low || 0;
  document.querySelector("#total-count").textContent = summary.total_files || 0;
}

function updateSummaryFromFiles(files = []) {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  files.forEach((file) => {
    const effective = getEffectiveRisk(file).level;
    counts[effective] = (counts[effective] || 0) + 1;
  });

  updateSummary({
    total_files: files.length,
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
  });

  renderReportPreview();
}

function list(items) {
  if (!items || items.length === 0) {
    return '<span class="subtext">None</span>';
  }

  return `<ul class="list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function renderRows(files) {
  const query = filterInput.value.trim().toLowerCase();
  const visible = files.filter((file) => JSON.stringify(file).toLowerCase().includes(query));

  if (visible.length === 0) {
    resultsBody.innerHTML = '<tr><td colspan="7" class="empty">No matching files.</td></tr>';
    return;
  }

  resultsBody.innerHTML = visible
    .map((file) => {
      const findings = (file.findings || []).map((finding) => `${finding.type}: ${finding.count}`);
      const recommendations = file.risk?.dlp_recommendations || [];
      const reasons = file.risk?.reasons || [];
      const effectiveRisk = getEffectiveRisk(file);
      const level = effectiveRisk.level;
      const score = effectiveRisk.score;
      const key = fileKey(file);
      const preview = renderPreview(file.preview);

      return `
        <tr data-file-key="${escapeHtml(key)}">
          <td>
            <div class="file-title">
              <button type="button" class="preview-toggle" data-preview="${escapeHtml(key)}" title="Show file preview">v</button>
              <span class="file-path">${escapeHtml(file.name || file.path)}</span>
            </div>
            <div class="subtext">${escapeHtml(file.path || "")}</div>
            ${preview}
          </td>
          <td>
            ${escapeHtml(file.source || "unknown")}
            <div class="subtext">${escapeHtml(file.share || "")}</div>
          </td>
          <td>${list(findings)}</td>
          <td><span class="badge ${level}">${level} ${score}</span></td>
          <td>
            <select class="risk-select" data-override="${escapeHtml(key)}">
              ${riskOption("", "Auto", rowOverrides[key] || "")}
              ${riskOption("CRITICAL", "Critical", rowOverrides[key] || "")}
              ${riskOption("HIGH", "High", rowOverrides[key] || "")}
              ${riskOption("MEDIUM", "Medium", rowOverrides[key] || "")}
              ${riskOption("LOW", "Low", rowOverrides[key] || "")}
            </select>
          </td>
          <td>${list(reasons)}</td>
          <td>${list(recommendations)}</td>
        </tr>
      `;
    })
    .join("");
}

function switchTab(tabName) {
  tabs.forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === tabName));
  tabPanels.forEach((panel) => panel.classList.toggle("active", panel.id === `tab-${tabName}`));
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeToggle.textContent = theme === "dark" ? "Light mode" : "Dark mode";
  safeStorageSet("dspm-theme", theme);
}

function renderPreview(preview) {
  if (!preview?.available) {
    return '<div class="preview-panel hidden"><span class="subtext">Preview unavailable for this file type.</span></div>';
  }

  const lines = (preview.lines || []).map((line, index) => {
    return `<code><span>${index + 1}</span>${escapeHtml(line || " ")}</code>`;
  });
  const truncated = preview.truncated ? '<div class="subtext">Preview truncated for safe display.</div>' : "";

  return `<div class="preview-panel hidden">${lines.join("")}${truncated}</div>`;
}

function riskOption(value, label, selected) {
  return `<option value="${value}" ${value === selected ? "selected" : ""}>${label}</option>`;
}

function getEffectiveRisk(file) {
  const level = rowOverrides[fileKey(file)];
  if (!level) {
    return file.risk || { level: "LOW", score: 0 };
  }

  return {
    level,
    score: scoreForLevel(level),
  };
}

function scoreForLevel(level) {
  return {
    CRITICAL: 95,
    HIGH: 80,
    MEDIUM: 55,
    LOW: 20,
  }[level] || 0;
}

function fileKey(file) {
  return `${file.source || "unknown"}|${file.share || ""}|${file.path || file.name || ""}`;
}

function renderRiskRules(rules) {
  if (!rules || rules.length === 0) {
    riskRulesBody.innerHTML = '<tr><td colspan="5" class="empty">No risk logic configured.</td></tr>';
    return;
  }

  riskRulesBody.innerHTML = rules
    .map(
      (rule) => `
        <tr>
          <td class="file-path">${escapeHtml(rule.signal)}</td>
          <td><span class="badge ${riskBadgeClass(rule.base_risk)}">${escapeHtml(rule.base_risk)}</span></td>
          <td>${escapeHtml(rule.score)}</td>
          <td>${escapeHtml(rule.reason)}</td>
          <td>${escapeHtml(rule.dlp_action)}</td>
        </tr>
      `
    )
    .join("");
}

function riskBadgeClass(value) {
  if (value.includes("HIGH")) {
    return "HIGH";
  }
  if (value.includes("MEDIUM")) {
    return "MEDIUM";
  }
  return "LOW";
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function renderAssetRules() {
  if (!assetRules.length) {
    assetRuleList.innerHTML = '<div class="empty asset-empty">No customer asset rules saved yet.</div>';
    return;
  }

  assetRuleList.innerHTML = assetRules
    .map(
      (item, index) => `
        <article class="asset-card ${editingAssetIndex === index ? "editing" : ""}">
          <div>
            <span class="badge ${item.level}">${escapeHtml(item.level)}</span>
            <h4>${escapeHtml(item.pattern)}</h4>
            <p>${escapeHtml(item.reason || "No business reason provided")}</p>
          </div>
          <div class="asset-card-actions">
            <button type="button" class="secondary-btn" data-edit-asset="${index}">Edit</button>
            <button type="button" class="danger-btn" data-remove-asset="${index}">Remove</button>
          </div>
        </article>
      `
    )
    .join("");
}

function saveAssetRules(message = "Asset rules saved.") {
  safeStorageSet("dspm-asset-rules", JSON.stringify(assetRules));
  assetSaveStatus.textContent = message;
  renderAssetRules();
}

function upsertAssetRule() {
  const pattern = assetPattern.value.trim();
  if (!pattern) {
    assetSaveStatus.textContent = "Add a pattern before saving.";
    assetPattern.focus();
    return;
  }

  const item = {
    pattern,
    level: assetLevel.value,
    reason: assetReason.value.trim(),
  };
  const existingIndex =
    editingAssetIndex !== null
      ? editingAssetIndex
      : assetRules.findIndex((rule) => rule.pattern.toLowerCase() === pattern.toLowerCase());

  if (existingIndex >= 0) {
    assetRules[existingIndex] = item;
  } else {
    assetRules.push(item);
  }

  resetAssetForm();
  saveAssetRules("Saved. These rules will be applied to the next scan.");
}

function saveAssetEditor() {
  if (assetPattern.value.trim()) {
    upsertAssetRule();
    return;
  }

  saveAssetRules("Asset rules saved. They will be included in scans.");
}

function resetAssetForm() {
  editingAssetIndex = null;
  assetPattern.value = "";
  assetLevel.value = "HIGH";
  assetReason.value = "";
  addAssetBtn.textContent = "Add asset";
}

function loadAssetRules() {
  try {
    const saved = JSON.parse(safeStorageGet("dspm-asset-rules") || "null");
    return Array.isArray(saved) ? saved : DEFAULT_ASSETS;
  } catch {
    return DEFAULT_ASSETS;
  }
}

function loadRowOverrides() {
  try {
    return JSON.parse(safeStorageGet("dspm-row-risk-overrides") || "{}");
  } catch {
    return {};
  }
}

function saveRowOverrides() {
  safeStorageSet("dspm-row-risk-overrides", JSON.stringify(rowOverrides));
}

function safeStorageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeStorageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    return false;
  }
  return true;
}

function renderReportPreview() {
  const summary = buildCurrentSummary();
  const topFiles = [...latestFiles]
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 5);
  const distribution = buildRiskDistribution(summary);
  const findingStats = buildFindingStats();

  if (!latestFiles.length) {
    reportPreview.innerHTML = `
      <div class="report-empty">
        <h4>No report data yet</h4>
        <p>Run a scan first. The report center will then prepare executive summary, risk table, and export files.</p>
      </div>
    `;
    return;
  }

  reportPreview.innerHTML = `
    <div class="report-document">
      <div class="report-title">
        <div>
          <span>DSPM assessment report</span>
          <h4>${escapeHtml(readPayload().server || "Local sample scan")}</h4>
        </div>
        <strong>${new Date().toLocaleString()}</strong>
      </div>
      <div class="report-kpis">
        <div><span>Critical</span><strong>${summary.critical}</strong></div>
        <div><span>High</span><strong>${summary.high}</strong></div>
        <div><span>Medium</span><strong>${summary.medium}</strong></div>
        <div><span>Low</span><strong>${summary.low}</strong></div>
        <div><span>Total files</span><strong>${summary.total_files}</strong></div>
      </div>
      <div class="report-visual-grid">
        <div class="chart-panel">
          <h5>Risk distribution</h5>
          ${buildDonutSvg(distribution)}
          <div class="chart-legend">${distribution.map((item) => `<span><i class="${item.level}"></i>${item.label}: ${item.count}</span>`).join("")}</div>
        </div>
        <div class="chart-panel">
          <h5>Detection signals</h5>
          ${renderFindingBars(findingStats)}
        </div>
      </div>
      <h5>Top risky files</h5>
      ${topFiles
        .map((file) => {
          const risk = getEffectiveRisk(file);
          return `
            <div class="report-row">
              <div>
                <strong>${escapeHtml(file.name || file.path)}</strong>
                <span>${escapeHtml(file.path || "")}</span>
              </div>
              <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

function buildRiskDistribution(summary) {
  return [
    { level: "CRITICAL", label: "Critical", count: summary.critical, color: "#9f1239" },
    { level: "HIGH", label: "High", count: summary.high, color: "#c2410c" },
    { level: "MEDIUM", label: "Medium", count: summary.medium, color: "#b7791f" },
    { level: "LOW", label: "Low", count: summary.low, color: "#2f855a" },
  ];
}

function buildFindingStats() {
  const counts = {};
  latestFiles.forEach((file) => {
    (file.findings || []).forEach((finding) => {
      counts[finding.type] = (counts[finding.type] || 0) + Number(finding.count || 1);
    });
  });

  return Object.entries(counts)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 6);
}

function buildDonutSvg(distribution) {
  const total = distribution.reduce((sum, item) => sum + item.count, 0) || 1;
  let offset = 25;
  const rings = distribution
    .map((item) => {
      const value = (item.count / total) * 100;
      const circle = `<circle r="15.9" cx="18" cy="18" fill="transparent" stroke="${item.color}" stroke-width="7" stroke-dasharray="${value} ${100 - value}" stroke-dashoffset="${offset}" />`;
      offset -= value;
      return circle;
    })
    .join("");

  return `
    <svg class="donut-chart" viewBox="0 0 36 36" aria-label="Risk distribution chart">
      <circle r="15.9" cx="18" cy="18" fill="transparent" stroke="#d9dee7" stroke-width="7" />
      ${rings}
      <text x="18" y="18.5" text-anchor="middle">${total}</text>
      <text x="18" y="23" text-anchor="middle">files</text>
    </svg>
  `;
}

function renderFindingBars(items) {
  if (!items.length) {
    return '<p class="subtext">No sensitive detection signals were found.</p>';
  }

  const max = Math.max(...items.map((item) => item.count), 1);
  return `
    <div class="signal-bars">
      ${items
        .map(
          (item) => `
            <div class="signal-bar">
              <div><span>${escapeHtml(item.type)}</span><strong>${item.count}</strong></div>
              <progress max="${max}" value="${item.count}"></progress>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildCurrentSummary() {
  const counts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
  latestFiles.forEach((file) => {
    const level = getEffectiveRisk(file).level;
    counts[level] = (counts[level] || 0) + 1;
  });

  return {
    total_files: latestFiles.length,
    critical: counts.CRITICAL,
    high: counts.HIGH,
    medium: counts.MEDIUM,
    low: counts.LOW,
  };
}

function exportCsv() {
  if (!latestFiles.length) {
    setStatus("Run a scan before exporting CSV.");
    return;
  }

  const summary = buildCurrentSummary();
  const rows = [
    ["DSPM Assessment Report"],
    ["Generated", new Date().toLocaleString()],
    ["Critical", summary.critical, "High", summary.high, "Medium", summary.medium, "Low", summary.low, "Total", summary.total_files],
    [],
    ["file", "path", "source", "share", "risk_level", "risk_score", "findings", "reasons", "recommendations"],
    ...latestFiles.map((file) => {
      const risk = getEffectiveRisk(file);
      return [
        file.name || "",
        file.path || "",
        file.source || "",
        file.share || "",
        risk.level,
        risk.score,
        (file.findings || []).map((finding) => `${finding.type}:${finding.count}`).join("; "),
        (file.risk?.reasons || []).join("; "),
        (file.risk?.dlp_recommendations || []).join("; "),
      ];
    }),
  ];

  downloadFile("dspm-report.csv", rows.map((row) => row.map(csvCell).join(",")).join("\n"), "text/csv");
}

function exportWord() {
  if (!latestFiles.length) {
    setStatus("Run a scan before exporting Word report.");
    return;
  }

  downloadFile("dspm-report.doc", buildReportHtml(), "application/msword");
}

function exportPdf() {
  if (!latestFiles.length) {
    setStatus("Run a scan before printing PDF report.");
    return;
  }

  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(buildReportHtml());
  reportWindow.document.close();
  reportWindow.focus();
  reportWindow.print();
}

function buildReportHtml() {
  const summary = buildCurrentSummary();
  const distribution = buildRiskDistribution(summary);
  const findingStats = buildFindingStats();
  const topFiles = [...latestFiles]
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 5);
  const rows = latestFiles
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <tr>
          <td>${escapeHtml(file.name || "")}</td>
          <td>${escapeHtml(file.path || "")}</td>
          <td>${escapeHtml(file.source || "")}</td>
          <td>${escapeHtml(risk.level)} ${escapeHtml(risk.score)}</td>
          <td>${escapeHtml((file.findings || []).map((finding) => `${finding.type}: ${finding.count}`).join(", ") || "None")}</td>
          <td>${escapeHtml((file.risk?.dlp_recommendations || []).join("; "))}</td>
        </tr>
      `;
    })
    .join("");
  const topRows = topFiles
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <tr>
          <td>${escapeHtml(file.name || file.path || "")}</td>
          <td>${escapeHtml(file.path || "")}</td>
          <td><span class="pill ${risk.level}">${escapeHtml(risk.level)} ${escapeHtml(risk.score)}</span></td>
        </tr>
      `;
    })
    .join("");

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>DSPM Assessment Report</title>
        <style>
          body { font-family: Arial, sans-serif; color: #17202a; margin: 0; background: #eef2f7; }
          .page { margin: 28px; background: #fff; border: 1px solid #d9dee7; }
          .cover { background: #0f766e; color: #fff; padding: 28px; }
          .cover p { color: #ccfbf1; margin: 6px 0 0; }
          .content { padding: 24px; }
          h1 { margin: 0; font-size: 30px; }
          h2 { margin-top: 28px; }
          .muted { color: #687382; }
          .kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 22px 0; }
          .kpis div, .panel { border: 1px solid #d9dee7; padding: 14px; border-radius: 8px; background: #f9fafb; }
          .kpis span { display: block; color: #687382; font-size: 12px; text-transform: uppercase; }
          .kpis strong { display: block; margin-top: 8px; font-size: 28px; }
          .grid { display: grid; grid-template-columns: 0.8fr 1.2fr; gap: 14px; }
          .donut-chart { width: 210px; height: 210px; display: block; margin: 0 auto; }
          .donut-chart text:first-of-type { font-size: 7px; font-weight: 800; fill: #17202a; }
          .donut-chart text:last-of-type { font-size: 3px; fill: #687382; }
          .legend { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin-top: 10px; }
          .legend span { font-size: 12px; }
          .legend i { display: inline-block; width: 10px; height: 10px; border-radius: 999px; margin-right: 6px; }
          .bar { margin-bottom: 10px; }
          .bar div { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }
          .bar span.track { display: block; height: 9px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
          .bar b { display: block; height: 100%; background: #0f766e; }
          table { width: 100%; border-collapse: collapse; font-size: 12px; }
          th, td { border: 1px solid #d9dee7; padding: 9px; text-align: left; vertical-align: top; }
          th { background: #f1f5f9; }
          .pill { display: inline-block; padding: 4px 8px; border-radius: 999px; color: #fff; font-weight: 700; }
          .CRITICAL { background: #9f1239; } .HIGH { background: #c2410c; } .MEDIUM { background: #b7791f; } .LOW { background: #2f855a; }
        </style>
      </head>
      <body>
        <div class="page">
          <div class="cover">
            <h1>DSPM Assessment Report</h1>
            <p>Generated ${escapeHtml(new Date().toLocaleString())} for ${escapeHtml(readPayload().server || "Local sample scan")}</p>
          </div>
          <div class="content">
            <div class="kpis">
              <div><span>Critical</span><strong>${summary.critical}</strong></div>
              <div><span>High</span><strong>${summary.high}</strong></div>
              <div><span>Medium</span><strong>${summary.medium}</strong></div>
              <div><span>Low</span><strong>${summary.low}</strong></div>
              <div><span>Total</span><strong>${summary.total_files}</strong></div>
            </div>
            <div class="grid">
              <div class="panel">
                <h2>Risk Distribution</h2>
                ${buildDonutSvg(distribution)}
                <div class="legend">${distribution.map((item) => `<span><i class="${item.level}"></i>${item.label}: ${item.count}</span>`).join("")}</div>
              </div>
              <div class="panel">
                <h2>Detection Signals</h2>
                ${findingStats.length ? findingStats.map((item) => `<div class="bar"><div><span>${escapeHtml(item.type)}</span><strong>${item.count}</strong></div><span class="track"><b style="width:${Math.max(8, (item.count / Math.max(...findingStats.map((stat) => stat.count))) * 100)}%"></b></span></div>`).join("") : '<p class="muted">No sensitive detection signals were found.</p>'}
              </div>
            </div>
            <h2>Top Risky Files</h2>
            <table>
              <thead><tr><th>File</th><th>Path</th><th>Risk</th></tr></thead>
              <tbody>${topRows}</tbody>
            </table>
            <h2>File Risk Register</h2>
            <table>
              <thead><tr><th>File</th><th>Path</th><th>Source</th><th>Risk</th><th>Findings</th><th>Recommendations</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
  `;
}

function csvCell(value) {
  return `"${String(value).replaceAll('"', '""')}"`;
}

function downloadFile(filename, content, type) {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

testBtn.addEventListener("click", async () => {
  setBusy(true);
  setStatus("Testing connection...");
  try {
    const result = await api("/api/test-connection", readPayload());
    const shareText = result.shares?.length ? ` Shares: ${result.shares.join(", ")}` : "";
    setStatus(`${result.message}.${shareText}`, result.connected ? "" : "muted");
  } catch (error) {
    setStatus(`Connection test failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  setStatus("Fetching and assessing data...");
  try {
    const report = await api("/api/scan", { ...readPayload(), save_report: true });
    latestReport = report;
    latestFiles = report.files || [];
    updateSummaryFromFiles(latestFiles);
    renderRows(latestFiles);
    scanMeta.textContent = `${latestFiles.length} files scanned from ${report.source} at ${report.timestamp}`;
    setStatus("Scan completed and report.json updated.");
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

filterInput.addEventListener("input", () => renderRows(latestFiles));

document.addEventListener("click", (event) => {
  const tabButton = event.target.closest(".tab[data-tab]");
  if (!tabButton) {
    return;
  }
  switchTab(tabButton.dataset.tab);
});

themeToggle.addEventListener("click", () => {
  const current = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  applyTheme(current);
});

addAssetBtn.addEventListener("click", upsertAssetRule);
saveAssetsBtn.addEventListener("click", saveAssetEditor);

assetRuleList.addEventListener("click", (event) => {
  const edit = event.target.closest("[data-edit-asset]");
  const remove = event.target.closest("[data-remove-asset]");

  if (edit) {
    const item = assetRules[Number(edit.dataset.editAsset)];
    assetPattern.value = item.pattern;
    assetLevel.value = item.level;
    assetReason.value = item.reason || "";
    editingAssetIndex = Number(edit.dataset.editAsset);
    addAssetBtn.textContent = "Update asset";
    assetPattern.focus();
    assetSaveStatus.textContent = "Editing selected rule. Save to update it.";
    renderAssetRules();
  }

  if (remove) {
    assetRules.splice(Number(remove.dataset.removeAsset), 1);
    resetAssetForm();
    saveAssetRules("Asset rule removed.");
  }
});

resultsBody.addEventListener("click", (event) => {
  const button = event.target.closest(".preview-toggle");
  if (!button) {
    return;
  }

  const panel = button.closest("td").querySelector(".preview-panel");
  if (!panel) {
    return;
  }

  const isHidden = panel.classList.toggle("hidden");
  button.textContent = isHidden ? "v" : "^";
});

resultsBody.addEventListener("change", (event) => {
  const select = event.target.closest("[data-override]");
  if (!select) {
    return;
  }

  const key = select.dataset.override;
  if (select.value) {
    rowOverrides[key] = select.value;
  } else {
    delete rowOverrides[key];
  }

  saveRowOverrides();
  updateSummaryFromFiles(latestFiles);
  renderRows(latestFiles);
});

exportCsvBtn.addEventListener("click", exportCsv);
exportWordBtn.addEventListener("click", exportWord);
exportPdfBtn.addEventListener("click", exportPdf);

applyTheme(safeStorageGet("dspm-theme") || "light");
renderAssetRules();
renderReportPreview();

fetch("/api/health")
  .then((response) => response.json())
  .then((data) => {
    health.textContent = data.status === "ok" ? "API online" : "API unavailable";
  })
  .catch(() => {
    health.textContent = "API unavailable";
  });

fetch("/api/risk-rules")
  .then((response) => response.json())
  .then((data) => renderRiskRules(data.rules))
  .catch(() => {
    riskRulesBody.innerHTML = '<tr><td colspan="5" class="empty">Risk logic could not be loaded.</td></tr>';
  });
