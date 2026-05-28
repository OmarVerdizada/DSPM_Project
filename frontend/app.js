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
const authForm = document.querySelector("#auth-form");
const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");
const authStatus = document.querySelector("#auth-status");
const logoutBtn = document.querySelector("#logout-btn");
const refreshHistoryBtn = document.querySelector("#refresh-history-btn");
const historyBody = document.querySelector("#history-body");
const executiveSummary = document.querySelector("#executive-summary");
const overviewInsights = document.querySelector("#overview-insights");
const refreshExecutiveBtn = document.querySelector("#refresh-executive-btn");
const executiveHero = document.querySelector("#executive-hero");
const riskDistribution = document.querySelector("#risk-distribution");
const riskTotalLabel = document.querySelector("#risk-total-label");
const riskHeatmap = document.querySelector("#risk-heatmap");
const signalMatrix = document.querySelector("#signal-matrix");
const riskTopology = document.querySelector("#risk-topology");
const executiveTopFiles = document.querySelector("#executive-top-files");
const createApiKeyBtn = document.querySelector("#create-api-key-btn");
const apiKeyLabel = document.querySelector("#api-key-label");
const apiKeyOutput = document.querySelector("#api-key-output");
const exportDlpPolicyBtn = document.querySelector("#export-dlp-policy-btn");
const dlpPolicyOutput = document.querySelector("#dlp-policy-output");
const refreshAuditBtn = document.querySelector("#refresh-audit-btn");
const auditBody = document.querySelector("#audit-body");
const integrationGrid = document.querySelector("#integration-grid");
const integrationDiagram = document.querySelector("#integration-diagram");

const DEFAULT_ASSETS = [
  { pattern: "password", level: "CRITICAL", reason: "Credential files are crown-jewel assets" },
  { pattern: "finance", level: "HIGH", reason: "Finance folders carry regulated business data" },
];

let latestFiles = [];
let latestReport = null;
let rowOverrides = loadRowOverrides();
let assetRules = loadAssetRules();
let editingAssetIndex = null;
let accessToken = safeStorageGet("dspm-access-token") || "";
let currentTenant = safeStorageGet("dspm-tenant-id") || "default";
let latestDashboard = null;

async function api(path, payload, method = "POST") {
  const response = await fetch(path, {
    method,
    headers: authHeaders(),
    body: payload ? JSON.stringify(payload) : undefined,
  });

  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `Request failed with ${response.status}`);
  }

  return response.json();
}

function authHeaders() {
  const headers = { "Content-Type": "application/json", "X-Tenant-ID": currentTenant };
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  return headers;
}

function readPayload() {
  const data = new FormData(form);
  return {
    server: data.get("server") || "",
    domain: data.get("domain") || "WORKGROUP",
    username: data.get("username") || "",
    password: data.get("password") || "",
    credential_ref: data.get("credential_ref") || "",
    local_path: data.get("local_path") || "test_data",
    max_depth: Number(data.get("max_depth") || 4),
    async_scan: Boolean(data.get("async_scan")),
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

function setAuthState(isAuthenticated) {
  document.body.classList.toggle("auth-locked", !isAuthenticated);
  document.body.classList.toggle("auth-ready", isAuthenticated);
  setBusy(!isAuthenticated);
  const onLoginPage = window.location.pathname === "/login";
  if (!isAuthenticated && !onLoginPage) {
    window.history.replaceState({}, "", "/login");
  }
  if (isAuthenticated && onLoginPage) {
    window.history.replaceState({}, "", "/");
  }
}

async function performLogin(username, password) {
  const result = await api("/api/auth/login", { username, password }, "POST");
  accessToken = result.access_token;
  currentTenant = result.tenant_id || "default";
  safeStorageSet("dspm-access-token", accessToken);
  safeStorageSet("dspm-tenant-id", currentTenant);
  setAuthState(true);
  authStatus.textContent = `Signed in as ${result.role} for tenant ${currentTenant}.`;
  if (loginStatus) {
    loginStatus.textContent = "Signed in successfully.";
  }
  await loadProtectedMetadata();
  await loadHistory();
  await loadAudit();
}

function logout() {
  accessToken = "";
  latestDashboard = null;
  safeStorageSet("dspm-access-token", "");
  safeStorageSet("dspm-tenant-id", "default");
  setAuthState(false);
  authStatus.textContent = "Signed out.";
  if (loginStatus) {
    loginStatus.textContent = "Signed out. Sign in to continue.";
  }
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
  renderExecutiveExperience();
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
  const activePanel = document.querySelector(`#tab-${tabName}`);
  if (activePanel) {
    activePanel.animate(
      [
        { opacity: 0, transform: "translateY(8px)" },
        { opacity: 1, transform: "translateY(0)" },
      ],
      { duration: 180, easing: "ease-out" }
    );
  }
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

function escapeSvg(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;");
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
          ${buildDistributionBars(distribution)}
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

function renderExecutiveExperience() {
  const summary = buildCurrentSummary();
  const score = latestDashboard?.risk_posture_score ?? calculatePostureScore(summary);
  const distribution = buildRiskDistribution(summary);
  const topFiles = [...latestFiles].sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score).slice(0, 6);
  const criticalCount = summary.critical || 0;

  overviewInsights.innerHTML = `
    <div class="insight-card posture">
      <span>Posture score</span>
      <strong>${score}</strong>
      <p>${score >= 80 ? "Healthy exposure profile" : score >= 55 ? "Watch active risk concentration" : "Immediate remediation recommended"}</p>
    </div>
    <div class="insight-card">
      <span>Critical alerts</span>
      <strong>${criticalCount}</strong>
      <p>${criticalCount ? "Threshold alert will be generated after scan save." : "No critical exposure in current view."}</p>
    </div>
    <div class="insight-card">
      <span>Sensitive files</span>
      <strong>${latestReport?.summary?.sensitive_files || countSensitiveFiles(latestFiles)}</strong>
      <p>Files with PII, secrets, PCI, PHI, or ML context signals.</p>
    </div>
    <div class="insight-card">
      <span>Tenant</span>
      <strong>${escapeHtml(currentTenant)}</strong>
      <p>History, audit, and vault data are isolated by tenant.</p>
    </div>
  `;

  executiveHero.innerHTML = `
    <div class="score-ring" style="--score:${score}">
      <strong>${score}</strong>
      <span>Risk posture</span>
    </div>
    <div>
      <p class="eyebrow">Latest assessment</p>
      <h3>${summary.total_files ? `${summary.total_files} files analyzed` : "No scan has been run yet"}</h3>
      <p>${summary.critical || summary.high ? "Prioritize critical and high exposure before broad cleanup." : "The current scan does not show urgent high-risk exposure."}</p>
      <div class="hero-actions">
        <button type="button" class="secondary-btn" data-tab-jump="overview">Review files</button>
        <button type="button" data-tab-jump="security">Export controls</button>
      </div>
    </div>
  `;

  riskTotalLabel.textContent = `${summary.total_files || 0} files`;
  riskDistribution.innerHTML = buildDistributionBars(distribution);
  riskHeatmap.innerHTML = buildHeatmap(topFiles.length ? latestFiles : []);
  signalMatrix.innerHTML = buildSignalMatrix();
  riskTopology.innerHTML = buildRiskTopology(summary);
  executiveTopFiles.innerHTML = renderTopFiles(topFiles);
}

function calculatePostureScore(summary) {
  return Math.max(0, 100 - summary.critical * 20 - summary.high * 8 - summary.medium * 3);
}

function countSensitiveFiles(files) {
  return files.filter((file) => (file.findings || []).length > 0).length;
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

function buildDistributionBars(distribution) {
  const total = distribution.reduce((sum, item) => sum + item.count, 0) || 1;
  const stack = distribution
    .map((item) => `<span class="${item.level}" style="width:${(item.count / total) * 100}%"></span>`)
    .join("");
  return `
    <div class="risk-stack">${stack}</div>
    <div class="risk-breakdown">
      ${distribution
        .map(
          (item) => `
            <div class="risk-breakdown-row">
              <span><i class="${item.level}"></i>${item.label}</span>
              <strong>${item.count}</strong>
              <progress max="${total}" value="${item.count}"></progress>
            </div>
          `
        )
        .join("")}
    </div>
  `;
}

function buildHeatmap(files) {
  if (!files.length) {
    return '<div class="empty compact">Run a scan to generate path heatmap.</div>';
  }
  const groups = {};
  files.forEach((file) => {
    const path = file.path || file.name || "unknown";
    const group = file.share || path.split(/[\\\\/]/).filter(Boolean).slice(-2, -1)[0] || file.source || "local";
    const risk = getEffectiveRisk(file);
    groups[group] = groups[group] || { label: group, score: 0, files: 0, critical: 0 };
    groups[group].score += risk.score;
    groups[group].files += 1;
    groups[group].critical += risk.level === "CRITICAL" ? 1 : 0;
  });
  return `
    <div class="heatmap-grid">
      ${Object.values(groups)
        .sort((a, b) => b.score - a.score)
        .slice(0, 12)
        .map((item) => {
          const intensity = Math.min(0.32, Math.max(0.06, item.score / Math.max(item.files * 95, 1) * 0.32));
          return `
            <div class="heat-tile" style="--heat-alpha:${intensity}">
              <strong>${escapeHtml(item.label)}</strong>
              <span>${item.files} files</span>
              <small>${item.critical} critical</small>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

function renderTopFiles(files) {
  if (!files.length) {
    return '<div class="empty compact">Top risky files will appear after a scan.</div>';
  }
  return files
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <article class="top-file-card">
          <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
          <h4>${escapeHtml(file.name || file.path)}</h4>
          <p>${escapeHtml(file.path || "")}</p>
          <div>${(file.findings || []).slice(0, 3).map((finding) => `<small>${escapeHtml(finding.type)}</small>`).join("") || "<small>No finding labels</small>"}</div>
        </article>
      `;
    })
    .join("");
}

function buildSignalMatrix() {
  const stats = buildFindingStats();
  if (!stats.length) {
    return '<div class="empty compact">Detection signal matrix appears after a scan.</div>';
  }
  const max = Math.max(...stats.map((item) => item.count), 1);
  return `
    <div class="signal-matrix">
      ${stats
        .map((item, index) => {
          const size = 56 + Math.round((item.count / max) * 42);
          return `
            <div class="signal-bubble b${index % 4}" style="--bubble:${size}px">
              <strong>${item.count}</strong>
              <span>${escapeHtml(item.type)}</span>
            </div>
          `;
        })
        .join("")}
    </div>
  `;
}

function buildRiskTopology(summary) {
  const source = latestReport?.source || "source";
  const critical = summary.critical || 0;
  const high = summary.high || 0;
  const sensitive = latestReport?.summary?.sensitive_files || countSensitiveFiles(latestFiles);
  return `
    <svg viewBox="0 0 760 230" class="topology-svg" role="img" aria-label="Risk topology diagram">
      <defs>
        <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z"></path>
        </marker>
      </defs>
      <path class="topology-line" d="M125 116 C225 38 284 38 382 112" marker-end="url(#arrow)"></path>
      <path class="topology-line" d="M125 116 C226 188 288 190 382 124" marker-end="url(#arrow)"></path>
      <path class="topology-line danger" d="M492 116 C575 64 620 64 690 92" marker-end="url(#arrow)"></path>
      <path class="topology-line warn" d="M492 116 C575 168 620 166 690 140" marker-end="url(#arrow)"></path>
      <g class="topology-node"><rect x="34" y="78" width="120" height="76" rx="10"></rect><text x="94" y="109">Data source</text><text x="94" y="130">${escapeSvg(source)}</text></g>
      <g class="topology-node"><rect x="348" y="76" width="158" height="82" rx="10"></rect><text x="427" y="108">Detection engine</text><text x="427" y="131">${sensitive} sensitive files</text></g>
      <g class="topology-node critical"><rect x="630" y="54" width="104" height="56" rx="10"></rect><text x="682" y="78">Critical</text><text x="682" y="96">${critical}</text></g>
      <g class="topology-node high"><rect x="630" y="124" width="104" height="56" rx="10"></rect><text x="682" y="148">High</text><text x="682" y="166">${high}</text></g>
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
    setStatus("Run a scan before exporting Excel.");
    return;
  }

  downloadFile("dspm-assessment.xls", buildExcelWorkbookHtml(), "application/vnd.ms-excel");
}

function exportWord() {
  if (!latestFiles.length) {
    setStatus("Run a scan before exporting Word report.");
    return;
  }

  downloadFile("dspm-assessment.doc", buildReportHtml("word"), "application/msword");
}

function exportPdf() {
  if (!latestFiles.length) {
    setStatus("Run a scan before printing PDF report.");
    return;
  }

  const reportWindow = window.open("", "_blank");
  reportWindow.document.write(buildReportHtml("pdf"));
  reportWindow.document.close();
  reportWindow.focus();
  reportWindow.print();
}

function buildReportHtml(mode = "word") {
  const summary = buildCurrentSummary();
  const distribution = buildRiskDistribution(summary);
  const findingStats = buildFindingStats();
  const score = latestDashboard?.risk_posture_score ?? calculatePostureScore(summary);
  const topFiles = [...latestFiles]
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 8);
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
          <td>${escapeHtml((file.risk?.reasons || []).join("; "))}</td>
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

  const distributionRows = distribution
    .map((item) => {
      const total = Math.max(summary.total_files, 1);
      return `<div class="bar"><div><span>${item.label}</span><strong>${item.count}</strong></div><span class="track"><b class="${item.level}" style="width:${(item.count / total) * 100}%"></b></span></div>`;
    })
    .join("");

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>DSPM Assessment Report</title>
        <style>
          @page { margin: 18mm; }
          body { font-family: Arial, sans-serif; color: #17202a; margin: 0; background: ${mode === "pdf" ? "#fff" : "#eef2f7"}; }
          .page { margin: ${mode === "pdf" ? "0" : "28px"}; background: #fff; border: 1px solid #d9dee7; }
          .cover { background: #0f766e; color: #fff; padding: 34px; }
          .cover p { color: #ccfbf1; margin: 8px 0 0; }
          .brandline { display: flex; justify-content: space-between; gap: 18px; align-items: center; }
          .logo { width: 54px; height: 54px; border-radius: 12px; background: #fff; color: #0f766e; display: grid; place-items: center; font-weight: 900; font-size: 24px; }
          .content { padding: 26px; }
          h1 { margin: 0; font-size: 34px; }
          h2 { margin: 28px 0 12px; }
          .muted { color: #687382; }
          .kpis { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin: 22px 0; }
          .kpis div, .panel { border: 1px solid #d9dee7; padding: 14px; border-radius: 8px; background: #f9fafb; }
          .kpis span { display: block; color: #687382; font-size: 12px; text-transform: uppercase; }
          .kpis strong { display: block; margin-top: 8px; font-size: 28px; }
          .score { display: grid; grid-template-columns: 150px 1fr; gap: 18px; align-items: center; margin-top: 22px; }
          .score-ring { width: 138px; height: 138px; border-radius: 999px; background: conic-gradient(#0f766e ${score}%, #d9dee7 0); display: grid; place-items: center; }
          .score-ring span { width: 92px; height: 92px; border-radius: 999px; background: #fff; display: grid; place-items: center; font-size: 30px; font-weight: 900; color: #0f766e; }
          .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
          .bar { margin-bottom: 10px; }
          .bar div { display: flex; justify-content: space-between; font-size: 12px; margin-bottom: 4px; }
          .bar span.track { display: block; height: 9px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
          .bar b { display: block; height: 100%; background: #0f766e; }
          .bar b.CRITICAL { background: #9f1239; } .bar b.HIGH { background: #c2410c; } .bar b.MEDIUM { background: #b7791f; } .bar b.LOW { background: #2f855a; }
          table { width: 100%; border-collapse: collapse; font-size: 12px; }
          th, td { border: 1px solid #d9dee7; padding: 9px; text-align: left; vertical-align: top; }
          th { background: #f1f5f9; }
          .pill { display: inline-block; padding: 4px 8px; border-radius: 999px; color: #fff; font-weight: 700; }
          .CRITICAL { background: #9f1239; } .HIGH { background: #c2410c; } .MEDIUM { background: #b7791f; } .LOW { background: #2f855a; }
          .two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
          .top-card { border: 1px solid #d9dee7; border-radius: 8px; padding: 12px; margin-bottom: 8px; }
          @media print { .page { border: 0; } .cover { print-color-adjust: exact; -webkit-print-color-adjust: exact; } }
        </style>
      </head>
      <body>
        <div class="page">
          <div class="cover">
            <div class="brandline">
              <div>
                <h1>DSPM Assessment Report</h1>
                <p>Generated ${escapeHtml(new Date().toLocaleString())} for ${escapeHtml(readPayload().server || "Local sample scan")}</p>
              </div>
              <div class="logo">D</div>
            </div>
          </div>
          <div class="content">
            <div class="score">
              <div class="score-ring"><span>${score}</span></div>
              <div>
                <h2>Executive Summary</h2>
                <p class="muted">${summary.critical || summary.high ? "Sensitive data exposure requires prioritized remediation." : "Current exposure remains within a manageable posture."}</p>
              </div>
            </div>
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
                ${distributionRows}
              </div>
              <div class="panel">
                <h2>Detection Signals</h2>
                ${findingStats.length ? findingStats.map((item) => `<div class="bar"><div><span>${escapeHtml(item.type)}</span><strong>${item.count}</strong></div><span class="track"><b style="width:${Math.max(8, (item.count / Math.max(...findingStats.map((stat) => stat.count))) * 100)}%"></b></span></div>`).join("") : '<p class="muted">No sensitive detection signals were found.</p>'}
              </div>
            </div>
            <h2>Top Risky Files</h2>
            <div class="two-col">${topFiles
              .map((file) => {
                const risk = getEffectiveRisk(file);
                return `<div class="top-card"><span class="pill ${risk.level}">${risk.level} ${risk.score}</span><strong> ${escapeHtml(file.name || file.path || "")}</strong><p class="muted">${escapeHtml(file.path || "")}</p></div>`;
              })
              .join("")}</div>
            <h2>File Risk Register</h2>
            <table>
              <thead><tr><th>File</th><th>Path</th><th>Source</th><th>Risk</th><th>Findings</th><th>Reasons</th><th>Recommendations</th></tr></thead>
              <tbody>${rows}</tbody>
            </table>
          </div>
        </div>
      </body>
    </html>
  `;
}

function buildExcelWorkbookHtml() {
  const summary = buildCurrentSummary();
  const distribution = buildRiskDistribution(summary);
  const findingStats = buildFindingStats();
  const rows = latestFiles
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <tr>
          <td>${escapeHtml(file.name || "")}</td>
          <td>${escapeHtml(file.path || "")}</td>
          <td>${escapeHtml(file.source || "")}</td>
          <td>${escapeHtml(file.share || "")}</td>
          <td class="${risk.level}">${escapeHtml(risk.level)}</td>
          <td>${escapeHtml(risk.score)}</td>
          <td>${escapeHtml((file.findings || []).map((finding) => `${finding.type}:${finding.count}`).join("; "))}</td>
          <td>${escapeHtml((file.risk?.reasons || []).join("; "))}</td>
          <td>${escapeHtml((file.risk?.dlp_recommendations || []).join("; "))}</td>
        </tr>
      `;
    })
    .join("");

  return `
    <html>
      <head>
        <meta charset="utf-8" />
        <style>
          body { font-family: Arial, sans-serif; color: #17202a; }
          h1 { color: #0f766e; }
          table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
          th { background: #0f766e; color: white; }
          th, td { border: 1px solid #d9dee7; padding: 8px; vertical-align: top; }
          .kpi th { background: #f1f5f9; color: #17202a; }
          .CRITICAL { background: #fce7f3; color: #9f1239; font-weight: bold; }
          .HIGH { background: #ffedd5; color: #c2410c; font-weight: bold; }
          .MEDIUM { background: #fef9c3; color: #b7791f; font-weight: bold; }
          .LOW { background: #dcfce7; color: #2f855a; font-weight: bold; }
        </style>
      </head>
      <body>
        <h1>DSPM Assessment Workbook</h1>
        <p>Generated ${escapeHtml(new Date().toLocaleString())} for tenant ${escapeHtml(currentTenant)}</p>
        <table class="kpi">
          <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total files</th><th>Posture score</th></tr>
          <tr><td class="CRITICAL">${summary.critical}</td><td class="HIGH">${summary.high}</td><td class="MEDIUM">${summary.medium}</td><td class="LOW">${summary.low}</td><td>${summary.total_files}</td><td>${latestDashboard?.risk_posture_score ?? calculatePostureScore(summary)}</td></tr>
        </table>
        <h2>Risk Distribution</h2>
        <table><tr><th>Level</th><th>Files</th></tr>${distribution.map((item) => `<tr><td class="${item.level}">${item.label}</td><td>${item.count}</td></tr>`).join("")}</table>
        <h2>Detection Signals</h2>
        <table><tr><th>Signal</th><th>Count</th></tr>${findingStats.map((item) => `<tr><td>${escapeHtml(item.type)}</td><td>${item.count}</td></tr>`).join("") || '<tr><td colspan="2">No sensitive detection signals</td></tr>'}</table>
        <h2>Risk Register</h2>
        <table>
          <tr><th>File</th><th>Path</th><th>Source</th><th>Share</th><th>Risk</th><th>Score</th><th>Findings</th><th>Reasons</th><th>Recommendations</th></tr>
          ${rows}
        </table>
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

function requireAuth() {
  if (!accessToken) {
    throw new Error("Sign in first. Default local admin is admin / admin123 unless DSPM_ADMIN_PASSWORD is set.");
  }
}

async function ensureCredential(payload) {
  if (!payload.server || payload.credential_ref || !payload.password) {
    return payload;
  }

  const secret = await api("/api/credentials", {
    username: payload.username,
    password: payload.password,
    domain: payload.domain,
  });
  document.querySelector("#credential_ref").value = secret.credential_ref;
  document.querySelector("#password").value = "";
  return { ...payload, credential_ref: secret.credential_ref, password: "" };
}

async function runQueuedScan(payload) {
  const job = await api("/api/scan", { ...payload, async_scan: true, save_report: true });
  setStatus(`Scan queued: ${job.id}`);
  return pollScan(job.id);
}

async function pollScan(jobId) {
  while (true) {
    const job = await api(`/api/scans/${jobId}`, null, "GET");
    setStatus(`${job.message} (${job.progress || 0}%)`);
    if (job.status === "completed") {
      return job.result;
    }
    if (job.status === "failed" || job.status === "cancelled") {
      throw new Error(job.error || job.message || `Scan ${job.status}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 1200));
  }
}

async function loadHistory() {
  if (!accessToken) {
    return;
  }
  const [history, dashboard] = await Promise.all([
    api("/api/history", null, "GET"),
    api("/api/executive-dashboard", null, "GET"),
  ]);
  latestDashboard = dashboard;
  renderHistory(history.history || []);
  renderExecutiveDashboard(dashboard);
  renderExecutiveExperience();
}

function renderHistory(items) {
  if (!items.length) {
    historyBody.innerHTML = '<tr><td colspan="6" class="empty">No scans saved for this tenant yet.</td></tr>';
    return;
  }
  historyBody.innerHTML = items
    .slice()
    .reverse()
    .map((item) => {
      const summary = item.summary || {};
      return `
        <tr>
          <td>${escapeHtml(item.timestamp || "")}</td>
          <td class="file-path">${escapeHtml(item.scan_id || "")}</td>
          <td>${summary.critical || 0}</td>
          <td>${summary.high || 0}</td>
          <td>${summary.medium || 0}</td>
          <td>${summary.low || 0}</td>
        </tr>
      `;
    })
    .join("");
}

function renderExecutiveDashboard(data) {
  const latest = data.latest?.summary || {};
  executiveSummary.innerHTML = `
    <div class="history-card"><span>Posture score</span><strong>${escapeHtml(data.risk_posture_score ?? 100)}</strong></div>
    <div class="history-card"><span>Tenant</span><strong>${escapeHtml(data.tenant_id || currentTenant)}</strong></div>
    <div class="history-card"><span>Reports</span><strong>${escapeHtml(data.retention?.report_count || 0)}</strong></div>
    <div class="history-card"><span>Open critical</span><strong>${escapeHtml(latest.critical || 0)}</strong></div>
  `;
}

async function loadAudit() {
  if (!accessToken) {
    return;
  }
  try {
    const data = await api("/api/audit", null, "GET");
    renderAudit(data.events || []);
  } catch (error) {
    auditBody.innerHTML = `<tr><td colspan="4" class="empty">Audit unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function renderAudit(events) {
  if (!events.length) {
    auditBody.innerHTML = '<tr><td colspan="4" class="empty">No audit events for this tenant yet.</td></tr>';
    return;
  }
  auditBody.innerHTML = events
    .slice()
    .reverse()
    .map(
      (event) => `
        <tr>
          <td>${escapeHtml(event.timestamp || "")}</td>
          <td>${escapeHtml(event.actor || "")}</td>
          <td class="file-path">${escapeHtml(event.action || "")}</td>
          <td><code>${escapeHtml(JSON.stringify(event.detail || {}))}</code></td>
        </tr>
      `
    )
    .join("");
}

async function createApiKey() {
  requireAuth();
  apiKeyOutput.textContent = "Creating key...";
  const result = await api("/api/api-keys", { label: apiKeyLabel.value.trim() || "automation" });
  apiKeyOutput.textContent = JSON.stringify(result, null, 2);
  await loadAudit();
}

async function exportDlpPolicy() {
  requireAuth();
  const result = await api("/api/dlp-policy", readPayload());
  dlpPolicyOutput.textContent = JSON.stringify(result, null, 2);
}

function renderIntegrations() {
  const items = [
    ["SMB / file server", "Active", "Vault-backed scan connector with share traversal."],
    ["Local folder", "Active", "Offline evidence review, demos, and local path scans."],
    ["Credential vault", "Active", "Encrypted local vault now; Vault/AWS adapter can replace it."],
    ["Async queue", "Active", "In-process jobs today; Celery + Redis slot is ready."],
    ["Alerts", "Adapter", "Webhook-ready threshold alerting for critical exposure."],
    ["DLP export", "Active", "Policy skeleton export from customer asset rules."],
    ["SharePoint / OneDrive", "Planned", "Graph API connector space reserved."],
    ["AWS S3 / Azure Blob", "Planned", "Object storage collector slot reserved."],
    ["Google Drive", "Planned", "Workspace connector slot reserved."],
    ["Jira / ServiceNow", "Planned", "Remediation ticket workflow slot reserved."],
    ["Slack / Teams", "Planned", "Notification connector slot reserved."],
    ["SIEM export", "Planned", "Splunk/QRadar audit export slot reserved."],
  ];
  integrationDiagram.innerHTML = `
    <svg viewBox="0 0 820 430" class="architecture-svg" role="img" aria-label="DSPM reference architecture">
      <defs>
        <marker id="arch-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M 0 0 L 10 5 L 0 10 z"></path>
        </marker>
      </defs>
      <path class="arch-lane" d="M150 104 H318" marker-end="url(#arch-arrow)"></path>
      <path class="arch-lane" d="M150 214 H318" marker-end="url(#arch-arrow)"></path>
      <path class="arch-lane" d="M150 324 H318" marker-end="url(#arch-arrow)"></path>
      <path class="arch-lane" d="M470 214 H640" marker-end="url(#arch-arrow)"></path>
      <path class="arch-lane soft" d="M394 144 V96 H640" marker-end="url(#arch-arrow)"></path>
      <path class="arch-lane soft" d="M394 284 V334 H640" marker-end="url(#arch-arrow)"></path>

      <g class="arch-box source"><rect x="30" y="64" width="130" height="80" rx="10"></rect><text x="95" y="98">File shares</text><text x="95" y="119">SMB / Local</text></g>
      <g class="arch-box source"><rect x="30" y="174" width="130" height="80" rx="10"></rect><text x="95" y="208">Cloud stores</text><text x="95" y="229">S3 / Drive</text></g>
      <g class="arch-box source"><rect x="30" y="284" width="130" height="80" rx="10"></rect><text x="95" y="318">SaaS apps</text><text x="95" y="339">Graph API</text></g>

      <g class="arch-box core"><rect x="318" y="144" width="168" height="140" rx="14"></rect><text x="402" y="196">DSPM Engine</text><text x="402" y="221">Queue + Detection</text><text x="402" y="244">Risk scoring</text></g>

      <g class="arch-box side"><rect x="640" y="56" width="140" height="80" rx="10"></rect><text x="710" y="91">Vault</text><text x="710" y="112">Secrets</text></g>
      <g class="arch-box side"><rect x="640" y="174" width="140" height="80" rx="10"></rect><text x="710" y="209">Tenant store</text><text x="710" y="230">History / Audit</text></g>
      <g class="arch-box side"><rect x="640" y="294" width="140" height="80" rx="10"></rect><text x="710" y="329">Outputs</text><text x="710" y="350">Reports / Alerts</text></g>
    </svg>
  `;
  integrationGrid.innerHTML = items
    .map(
      ([name, status, description]) => `
        <article class="integration-card ${status.toLowerCase()}">
          <span>${escapeHtml(status)}</span>
          <h4>${escapeHtml(name)}</h4>
          <p>${escapeHtml(description)}</p>
          <button type="button" class="secondary-btn mini-btn">Configure</button>
        </article>
      `
    )
    .join("");
}

authForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  authStatus.textContent = "Signing in...";
  try {
    const data = new FormData(authForm);
    await performLogin(data.get("auth_username") || "", data.get("auth_password") || "");
  } catch (error) {
    authStatus.textContent = `Sign-in failed: ${error.message}`;
  }
});

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginStatus.textContent = "Signing in...";
  try {
    const data = new FormData(loginForm);
    await performLogin(data.get("username") || "", data.get("password") || "");
  } catch (error) {
    loginStatus.textContent = `Sign-in failed: ${error.message}`;
  }
});

testBtn.addEventListener("click", async () => {
  setBusy(true);
  setStatus("Testing connection...");
  try {
    requireAuth();
    const result = await api("/api/test-connection", await ensureCredential(readPayload()));
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
    requireAuth();
    const payload = await ensureCredential(readPayload());
    const report = payload.async_scan ? await runQueuedScan(payload) : await api("/api/scan", { ...payload, save_report: true });
    latestReport = report;
    latestFiles = report.files || [];
    updateSummaryFromFiles(latestFiles);
    renderRows(latestFiles);
    scanMeta.textContent = `${latestFiles.length} files scanned from ${report.source} at ${report.timestamp}`;
    setStatus("Scan completed and report.json updated.");
    await loadHistory();
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`);
  } finally {
    setBusy(false);
  }
});

filterInput.addEventListener("input", () => renderRows(latestFiles));

document.addEventListener("click", (event) => {
  const tabButton = event.target.closest(".tab[data-tab]");
  const tabJump = event.target.closest("[data-tab-jump]");
  if (tabButton) {
    switchTab(tabButton.dataset.tab);
    return;
  }
  if (tabJump) {
    switchTab(tabJump.dataset.tabJump);
  }
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
refreshHistoryBtn.addEventListener("click", () => {
  loadHistory().catch((error) => setStatus(`History failed: ${error.message}`));
});
refreshExecutiveBtn.addEventListener("click", () => {
  loadHistory().catch((error) => setStatus(`Executive dashboard failed: ${error.message}`));
});
refreshAuditBtn.addEventListener("click", () => {
  loadAudit().catch((error) => setStatus(`Audit failed: ${error.message}`));
});
createApiKeyBtn.addEventListener("click", () => {
  createApiKey().catch((error) => {
    apiKeyOutput.textContent = error.message;
  });
});
exportDlpPolicyBtn.addEventListener("click", () => {
  exportDlpPolicy().catch((error) => {
    dlpPolicyOutput.textContent = error.message;
  });
});
logoutBtn.addEventListener("click", logout);

applyTheme(safeStorageGet("dspm-theme") || "light");
setAuthState(Boolean(accessToken));
renderAssetRules();
renderReportPreview();
renderExecutiveExperience();
renderIntegrations();

fetch("/api/health")
  .then((response) => response.json())
  .then((data) => {
    health.textContent = data.status === "ok" ? "API online" : "API unavailable";
  })
  .catch(() => {
    health.textContent = "API unavailable";
  });

async function loadProtectedMetadata() {
  if (!accessToken) {
    riskRulesBody.innerHTML = '<tr><td colspan="5" class="empty">Sign in to load risk logic.</td></tr>';
    return;
  }
  try {
    const data = await api("/api/risk-rules", null, "GET");
    renderRiskRules(data.rules);
  } catch {
    riskRulesBody.innerHTML = '<tr><td colspan="5" class="empty">Risk logic could not be loaded.</td></tr>';
  }
}

if (accessToken) {
  authStatus.textContent = `Token loaded for tenant ${currentTenant}.`;
  loadProtectedMetadata();
  loadHistory().catch(() => {});
  loadAudit().catch(() => {});
} else {
  loadProtectedMetadata();
}
