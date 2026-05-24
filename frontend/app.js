const form = document.querySelector("#connection-form");
const testBtn = document.querySelector("#test-btn");
const scanBtn = document.querySelector("#scan-btn");
const statusBox = document.querySelector("#connection-status");
const health = document.querySelector("#health");
const filterInput = document.querySelector("#filter");
const resultsBody = document.querySelector("#results-body");
const riskRulesBody = document.querySelector("#risk-rules-body");
const scanMeta = document.querySelector("#scan-meta");

let latestFiles = [];

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
    resultsBody.innerHTML = '<tr><td colspan="6" class="empty">No matching files.</td></tr>';
    return;
  }

  resultsBody.innerHTML = visible
    .map((file) => {
      const findings = (file.findings || []).map((finding) => `${finding.type}: ${finding.count}`);
      const recommendations = file.risk?.dlp_recommendations || [];
      const reasons = file.risk?.reasons || [];
      const level = file.risk?.level || "LOW";
      const score = file.risk?.score || 0;

      return `
        <tr>
          <td>
            <div class="file-path">${escapeHtml(file.name || file.path)}</div>
            <div class="subtext">${escapeHtml(file.path || "")}</div>
          </td>
          <td>
            ${escapeHtml(file.source || "unknown")}
            <div class="subtext">${escapeHtml(file.share || "")}</div>
          </td>
          <td>${list(findings)}</td>
          <td><span class="badge ${level}">${level} ${score}</span></td>
          <td>${list(reasons)}</td>
          <td>${list(recommendations)}</td>
        </tr>
      `;
    })
    .join("");
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
    latestFiles = report.files || [];
    updateSummary(report.summary);
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
