const form = document.querySelector("#connection-form");
const testBtn = document.querySelector("#test-btn");
const scanBtn = document.querySelector("#scan-btn");
const generateDemoDataBtn = document.querySelector("#generate-demo-data-btn");
const demoDataTitle = document.querySelector("#demo-data-title");
const demoDataStatus = document.querySelector("#demo-data-status");
const statusBox = document.querySelector("#connection-status");
const scanProgress = document.querySelector("#scan-progress");
const scanProgressLabel = document.querySelector("#scan-progress-label");
const scanProgressBar = document.querySelector("#scan-progress-bar");
const allowedExtensionsList = document.querySelector("#allowed_extensions");
const extensionSearch = document.querySelector("#extension-search");
const endpointAllowedExtensionsList = document.querySelector("#endpoint_allowed_extensions");
const endpointExtensionSearch = document.querySelector("#endpoint-extension-search");
const customExtensionInput = document.querySelector("#custom-extension-input");
const addCustomExtensionBtn = document.querySelector("#add-custom-extension-btn");
const endpointCustomExtensionInput = document.querySelector("#endpoint-custom-extension-input");
const endpointAddCustomExtensionBtn = document.querySelector("#endpoint-add-custom-extension-btn");
const toastHost = document.querySelector("#toast-host");
const sidebarToggle = document.querySelector("#sidebar-toggle");
const menuOpenToggle = document.querySelector("#menu-open-toggle");
const protectedCount = document.querySelector("#protected-count");
const health = document.querySelector("#health");
const filterInput = document.querySelector("#filter");
const inventoryRiskFilters = document.querySelectorAll("[data-risk-filter]");
const inventorySourceFilter = document.querySelector("#inventory-source-filter");
const inventoryFindingFilter = document.querySelector("#inventory-finding-filter");
const inventoryClearFiltersBtn = document.querySelector("#clear-inventory-filters");
const inventoryContextMetrics = document.querySelector("#inventory-context-metrics");
const resultsBody = document.querySelector("#results-body");
const riskRulesBody = document.querySelector("#risk-rules-body");
const scanMeta = document.querySelector("#scan-meta");
const tabs = document.querySelectorAll(".tab");
const tabPanels = document.querySelectorAll(".tab-panel");
const themeToggle = document.querySelector("#theme-toggle");
const tenantSwitcher = document.querySelector("#tenant-switcher");
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
const logoutBtn = document.querySelector("#logout-btn");
const profileToggle = document.querySelector("#profile-toggle");
const profileName = document.querySelector("#profile-name");
const profileTenant = document.querySelector("#profile-tenant");
const profileRole = document.querySelector("#profile-role");
const profilePanelName = document.querySelector("#profile-panel-name");
const profilePanelTenant = document.querySelector("#profile-panel-tenant");
const refreshHistoryBtn = document.querySelector("#refresh-history-btn");
const historyRange = document.querySelector("#history-range");
const historyFrom = document.querySelector("#history-from");
const historyTo = document.querySelector("#history-to");
const historyBody = document.querySelector("#history-body");
const executiveSummary = document.querySelector("#executive-summary");
const overviewInsights = document.querySelector("#overview-insights");
const fileServerContext = document.querySelector("#file-server-context");
const endpointContext = document.querySelector("#endpoint-context");
const findingsSignalSummary = document.querySelector("#findings-signal-summary");
const findingsPrioritySummary = document.querySelector("#findings-priority-summary");
const exposurePermissionsSummary = document.querySelector("#exposure-permissions-summary");
const exposureCoverageSummary = document.querySelector("#exposure-coverage-summary");
const refreshExecutiveBtn = document.querySelector("#refresh-executive-btn");
const executiveHero = document.querySelector("#executive-hero");
const riskDistribution = document.querySelector("#risk-distribution");
const riskTotalLabel = document.querySelector("#risk-total-label");
const riskHeatmap = document.querySelector("#risk-heatmap");
const signalMatrix = document.querySelector("#signal-matrix");
const riskTopology = document.querySelector("#risk-topology");
const executiveTopFiles = document.querySelector("#executive-top-files");
const priorityRiskFiles = document.querySelector("#priority-risk-files");
const departmentRisk = document.querySelector("#department-risk");
const scanComparison = document.querySelector("#scan-comparison");
const topRiskyFolders = document.querySelector("#top-risky-folders");
const postureTrend = document.querySelector("#posture-trend");
const remediationWorkflow = document.querySelector("#remediation-workflow");
const msspPortfolio = document.querySelector("#mssp-portfolio");
const createApiKeyBtn = document.querySelector("#create-api-key-btn");
const apiKeyLabel = document.querySelector("#api-key-label");
const apiKeyOutput = document.querySelector("#api-key-output");
const exportDlpPolicyBtn = document.querySelector("#export-dlp-policy-btn");
const dlpPolicyOutput = document.querySelector("#dlp-policy-output");
const refreshAuditBtn = document.querySelector("#refresh-audit-btn");
const auditRange = document.querySelector("#audit-range");
const auditFrom = document.querySelector("#audit-from");
const auditTo = document.querySelector("#audit-to");
const auditBody = document.querySelector("#audit-body");
const createUserBtn = document.querySelector("#create-user-btn");
const refreshUsersBtn = document.querySelector("#refresh-users-btn");
const usersBody = document.querySelector("#users-body");
const userManagementStatus = document.querySelector("#user-management-status");
const newUserUsername = document.querySelector("#new-user-username");
const newUserRole = document.querySelector("#new-user-role");
const newUserTenant = document.querySelector("#new-user-tenant");
const newUserFullName = document.querySelector("#new-user-full-name");
const newUserPassword = document.querySelector("#new-user-password");
const createTenantBtn = document.querySelector("#create-tenant-btn");
const refreshTenantsBtn = document.querySelector("#refresh-tenants-btn");
const tenantsBody = document.querySelector("#tenants-body");
const tenantManagementStatus = document.querySelector("#tenant-management-status");
const newTenantId = document.querySelector("#new-tenant-id");
const newTenantName = document.querySelector("#new-tenant-name");
const integrationGrid = document.querySelector("#integration-grid");
const integrationDiagram = document.querySelector("#integration-diagram");
const localWinrmActivateBtn = document.querySelector("#local-winrm-activate-btn");
const localWinrmStatus = document.querySelector("#local-winrm-status");
const endpointActivateBtn = document.querySelector("#endpoint-activate-btn");
const endpointTestBtn = document.querySelector("#endpoint-test-btn");
const endpointScanBtn = document.querySelector("#endpoint-scan-btn");
const endpointCancelBtn = document.querySelector("#endpoint-cancel-btn");
const endpointViewOverviewBtn = document.querySelector("#endpoint-view-overview-btn");
const endpointStatus = document.querySelector("#endpoint-status");
const winrmActivateStatus = document.querySelector("#winrm-activate-status");
const endpointPathScope = document.querySelector("#endpoint-path-scope");
const endpointCustomPaths = document.querySelector("#endpoint-custom-paths");
const endpointScanProgress = document.querySelector("#endpoint-scan-progress");
const endpointScanProgressLabel = document.querySelector("#endpoint-scan-progress-label");
const endpointScanProgressBar = document.querySelector("#endpoint-scan-progress-bar");
const detailDrawer = document.querySelector("#detail-drawer");
const detailDrawerEyebrow = detailDrawer.querySelector("#detail-drawer-eyebrow");
const detailDrawerTitle = detailDrawer.querySelector("#detail-drawer-title");
const detailDrawerMeta = detailDrawer.querySelector("#detail-drawer-meta");
const detailDrawerBody = detailDrawer.querySelector("#detail-drawer-body");

const DEFAULT_ASSETS = [
  { pattern: "password", level: "CRITICAL", reason: "Credential files are crown-jewel assets" },
  { pattern: "finance", level: "HIGH", reason: "Finance folders carry regulated business data" },
];

const RISK_SCORE_BANDS = [
  {
    level: "LOW",
    range: "0-39",
    title: "Low exposure",
    description: "No regulated data, secrets, broad access, or risky business context was found. Monitor and keep normal retention controls in place.",
  },
  {
    level: "MEDIUM",
    range: "40-69",
    title: "Review needed",
    description: "Personal data, confidential labels, risky paths, or file types indicate business-sensitive data that should be owned and classified.",
  },
  {
    level: "HIGH",
    range: "70-89",
    title: "Controlled data",
    description: "Credentials, payment data, finance records, payroll, customer exports, or broad writable access require restrictive handling.",
  },
  {
    level: "CRITICAL",
    range: "90-100",
    title: "Immediate action",
    description: "Private keys, cloud tokens, secrets, or crown-jewel assets can create direct compromise and should be quarantined or remediated first.",
  },
];

const FILE_EXTENSION_OPTIONS = [
  ["__hidden__", "Hidden files"],
  ["__system__", "System files"],
  [".txt", "Text document"],
  [".log", "Log file"],
  [".csv", "CSV export"],
  [".tsv", "TSV export"],
  [".json", "JSON data"],
  [".xml", "XML data"],
  [".yaml", "YAML config"],
  [".yml", "YML config"],
  [".toml", "TOML config"],
  [".ini", "INI config"],
  [".cfg", "CFG config"],
  [".conf", "CONF config"],
  [".config", "App config"],
  [".properties", "Properties config"],
  [".env", "Environment secrets"],
  [".pem", "PEM key/cert"],
  [".key", "Key file"],
  [".crt", "Certificate"],
  [".cer", "Certificate"],
  [".pfx", "PFX certificate"],
  [".p12", "PKCS12 certificate"],
  [".kdbx", "KeePass database"],
  [".sql", "SQL dump"],
  [".dump", "Database dump"],
  [".bak", "Backup"],
  [".backup", "Backup"],
  [".db", "Database"],
  [".sqlite", "SQLite database"],
  [".sqlite3", "SQLite database"],
  [".mdb", "Access database"],
  [".accdb", "Access database"],
  [".pst", "Outlook archive"],
  [".ost", "Outlook cache"],
  [".msg", "Outlook message"],
  [".eml", "Email message"],
  [".mbox", "Mailbox archive"],
  [".ics", "Calendar data"],
  [".doc", "Word legacy"],
  [".docx", "Word document"],
  [".docm", "Word macro document"],
  [".dotx", "Word template"],
  [".dotm", "Word macro template"],
  [".rtf", "Rich text"],
  [".odt", "OpenDocument text"],
  [".ott", "OpenDocument template"],
  [".pages", "Apple Pages"],
  [".xls", "Excel legacy"],
  [".xlsx", "Excel workbook"],
  [".xlsm", "Excel macro workbook"],
  [".xlsb", "Excel binary workbook"],
  [".ods", "OpenDocument sheet"],
  [".ots", "OpenDocument sheet template"],
  [".numbers", "Apple Numbers"],
  [".ppt", "PowerPoint legacy"],
  [".pptx", "PowerPoint deck"],
  [".pptm", "PowerPoint macro deck"],
  [".odp", "OpenDocument deck"],
  [".otp", "OpenDocument deck template"],
  [".keynote", "Apple Keynote"],
  [".pdf", "PDF document"],
  [".one", "OneNote notebook"],
  [".pub", "Publisher document"],
  [".vsd", "Visio legacy"],
  [".vsdx", "Visio drawing"],
  [".dwg", "AutoCAD drawing"],
  [".dxf", "CAD exchange"],
  [".zip", "ZIP archive"],
  [".7z", "7-Zip archive"],
  [".rar", "RAR archive"],
  [".tar", "TAR archive"],
  [".gz", "GZip archive"],
  [".tgz", "TAR GZip archive"],
  [".bz2", "BZip archive"],
  [".xz", "XZ archive"],
  [".cab", "Cabinet archive"],
  [".jar", "Java archive"],
  [".ps1", "PowerShell script"],
  [".psm1", "PowerShell module"],
  [".psd1", "PowerShell data"],
  [".bat", "Batch script"],
  [".cmd", "Command script"],
  [".sh", "Shell script"],
  [".py", "Python code"],
  [".js", "JavaScript code"],
  [".ts", "TypeScript code"],
  [".tsx", "TSX code"],
  [".jsx", "JSX code"],
  [".html", "HTML file"],
  [".htm", "HTML file"],
  [".css", "CSS file"],
  [".scss", "SCSS file"],
  [".java", "Java code"],
  [".cs", "C# code"],
  [".go", "Go code"],
  [".rb", "Ruby code"],
  [".php", "PHP code"],
  [".c", "C source"],
  [".cpp", "C++ source"],
  [".h", "Header file"],
  [".hpp", "C++ header"],
  [".md", "Markdown"],
  [".adoc", "AsciiDoc"],
  [".rst", "reStructuredText"],
  [".yara", "YARA rule"],
  [".reg", "Registry export"],
  [".rdp", "Remote Desktop profile"],
  [".ovpn", "VPN profile"],
  [".pcf", "VPN profile"],
  [".mobileconfig", "Mobile config"],
  [".tf", "Terraform config"],
  [".tfvars", "Terraform variables"],
  [".hcl", "HCL config"],
  [".dockerfile", "Dockerfile"],
  [".tfstate", "Terraform state"],
  [".npmrc", "NPM config"],
  [".pypirc", "Python package config"],
  [".netrc", "Network credential file"],
  [".aws", "AWS config"],
  [".gpg", "GPG encrypted file"],
  [".pgp", "PGP encrypted file"],
  [".sys", "System driver"],
  [".dll", "Windows library"],
  [".exe", "Executable"],
  [".msi", "Windows installer"],
  [".lnk", "Windows shortcut"],
  [".tmp", "Temporary file"],
  [".temp", "Temporary file"],
  [".old", "Old copy"],
  [".swp", "Swap file"],
  [".dat", "Data file"],
  [".bin", "Binary data"],
  [".iso", "Disk image"],
  [".vhd", "Virtual disk"],
  [".vhdx", "Virtual disk"],
  [".jpg", "JPEG image"],
  [".jpeg", "JPEG image"],
  [".png", "PNG image"],
  [".gif", "GIF image"],
  [".bmp", "Bitmap image"],
  [".tif", "TIFF image"],
  [".tiff", "TIFF image"],
  [".heic", "HEIC image"],
  [".svg", "SVG image"],
  [".mp3", "Audio file"],
  [".wav", "Audio file"],
  [".mp4", "Video file"],
  [".mov", "Video file"],
  [".avi", "Video file"],
  [".mkv", "Video file"],
];

const EXTENSION_PRESETS = {
  all: FILE_EXTENSION_OPTIONS.filter(([extension]) => extension.startsWith(".")).map(([extension]) => extension),
  clear: [],
};

const SIMPLE_EXTENSION_MEDIA_EXCLUSIONS = new Set([".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".svg", ".mp3", ".wav", ".mp4", ".mov", ".avi", ".mkv"]);
const SIMPLE_EXTENSION_PRESETS = {
  secrets: [".env", ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".kdbx", ".npmrc", ".pypirc", ".netrc", ".aws", ".ovpn", ".pcf", ".mobileconfig", ".rdp", ".tfvars", ".tfstate", ".kubeconfig"],
  recommended: [".env", ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".kdbx", ".npmrc", ".pypirc", ".netrc", ".aws", ".ovpn", ".pcf", ".mobileconfig", ".rdp", ".tfvars", ".tfstate", ".kubeconfig", ".doc", ".docx", ".docm", ".pdf", ".xls", ".xlsx", ".xlsm", ".ppt", ".pptx", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".sql", ".db", ".sqlite", ".sqlite3", ".bak", ".dump", ".backup", ".msg", ".eml", ".pst", ".ost"],
  broad: EXTENSION_PRESETS.all.filter((extension) => !SIMPLE_EXTENSION_MEDIA_EXCLUSIONS.has(extension)),
  all: EXTENSION_PRESETS.all,
};

const EXTENSION_GROUP_ORDER = [
  "Scope",
  "Secrets & config",
  "Documents",
  "Data & exports",
  "Source code",
  "Archives",
  "System & binaries",
  "Media",
  "Custom",
  "Other",
];

let accessToken = safeSessionGet("dspm-access-token") || "";
let currentTenant = safeSessionGet("dspm-tenant-id") || "default";
let currentUser = safeSessionGet("dspm-user") || "admin";
let currentRole = safeSessionGet("dspm-role") || "admin";
let customExtensions = loadCustomExtensions();
let latestFiles = [];
let latestReport = null;
let latestScanKind = "";
let latestHistoryItems = [];
let latestAuditEvents = [];
let rowOverrides = loadRowOverrides();
let assetRules = loadAssetRules();
let editingAssetIndex = null;
let latestDashboard = null;
let tenantPortfolio = [];
let latestRiskRules = [];
let lastRenderedFileKeys = new Set();
let hasRenderedScanRows = false;
let renderedRowsLimit = 200;
let activeEndpointJobId = "";
let inventoryRiskFilter = "ALL";
let inventorySourceFacet = "ALL";
let inventoryFindingFacet = "ALL";
let fileSearchIndex = new WeakMap();

const ROW_PAGE_SIZE = 200;
const ARCHIVE_EXTENSIONS = new Set([".7z", ".bz2", ".cab", ".gz", ".jar", ".rar", ".tar", ".tgz", ".xz", ".zip"]);

async function api(path, payload, method = "POST") {
  const response = await fetch(path, {
    method,
    headers: authHeaders(),
    body: payload ? JSON.stringify(payload) : undefined,
  });

  if (!response.ok) {
    const message = await readErrorMessage(response);
    if (response.status === 401) {
      accessToken = "";
      safeSessionSet("dspm-access-token", "");
      showToast("Session expired", "Please sign in again.", "danger");
      window.setTimeout(() => window.location.replace("/login"), 900);
    }
    throw new Error(`${response.status}: ${message}`);
  }

  return response.json();
}

async function readErrorMessage(response) {
  const message = await response.text();
  if (!message) {
    return `Request failed with ${response.status}`;
  }
  try {
    const data = JSON.parse(message);
    return typeof data.detail === "string" ? data.detail : "Request failed.";
  } catch {
    return "Request failed.";
  }
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
  const selectedExtensions = readSelectedExtensions();
  const searchedExtension = readSearchExtension(extensionSearch);
  if (searchedExtension && !selectedExtensions.includes(searchedExtension)) {
    selectedExtensions.push(searchedExtension);
  }
  const selectedFileExtensions = selectedExtensions.filter((item) => item.startsWith("."));
  return {
    server: data.get("server") || "",
    domain: data.get("domain") || "WORKGROUP",
    username: data.get("username") || "",
    password: data.get("password") || "",
    credential_ref: data.get("credential_ref") || "",
    local_path: data.get("local_path") || "enterprise_test_data",
    max_depth: Number(data.get("max_depth") || 4),
    allowed_extensions: selectedFileExtensions,
    extension_filter_enabled: selectedFileExtensions.length > 0,
    include_hidden: selectedExtensions.includes("__hidden__"),
    include_system: selectedExtensions.includes("__system__"),
    hidden_filter_enabled: selectedExtensions.includes("__hidden__"),
    system_filter_enabled: selectedExtensions.includes("__system__"),
    include_admin_shares: Boolean(data.get("include_admin_shares")),
    inspect_archives: Boolean(data.get("inspect_archives")),
    async_scan: Boolean(data.get("async_scan")),
    asset_overrides: assetRules,
  };
}

function readSelectedExtensions(list = allowedExtensionsList) {
  if (!list) return [];
  return [...list.querySelectorAll("input[type='checkbox']:checked")].map((input) => input.value);
}

function readSearchExtension(search) {
  const value = search?.value?.trim().toLowerCase() || "";
  return normalizeExtension(value);
}

function renderExtensionFilter(list = allowedExtensionsList, search = extensionSearch) {
  if (!list) return;
  const selectedBefore = new Set(readSelectedExtensions(list));
  const options = [
    ...FILE_EXTENSION_OPTIONS.filter(([value]) => !value.startsWith(".")).map(([extension, label]) => [extension, label, "Scope"]),
    ...getExtensionOptions().map(([extension, label]) => [extension, label, extensionGroupFor(extension)]),
  ];
  const groups = new Map();
  options.forEach(([extension, label, group]) => {
    const bucket = groups.get(group) || [];
    bucket.push([extension, label]);
    groups.set(group, bucket);
  });
  list.innerHTML = EXTENSION_GROUP_ORDER
    .filter((group) => groups.has(group))
    .map((group) => {
      const rows = groups.get(group).sort(([first], [second]) => first.localeCompare(second)).map(
        ([extension, label]) => `
        <label class="extension-option" data-extension-group="${escapeHtml(group.toLowerCase())}" data-extension-label="${escapeHtml(`${extension} ${label} ${group}`.toLowerCase())}">
        <input type="checkbox" value="${extension}" />
        <span>${extension.startsWith(".") ? `${escapeHtml(extension)} - ` : ""}${escapeHtml(label)}</span>
      </label>
    `
      ).join("");
      return `<div class="extension-group" data-extension-group-wrap="${escapeHtml(group.toLowerCase())}">
        <div class="extension-group-heading">${escapeHtml(group)}</div>
        ${rows}
      </div>`;
    }).join("");
  [...list.querySelectorAll("input[type='checkbox']")].forEach((input) => {
    input.checked = selectedBefore.has(input.value);
  });
  reorderExtensionOptions(list);
  filterExtensionList(list, search);
  updateExtensionSummary(list);
}

function getExtensionOptions() {
  const seen = new Set();
  const options = [];
  FILE_EXTENSION_OPTIONS
    .filter(([value]) => value.startsWith("."))
    .forEach(([value, label]) => {
      const normalized = normalizeExtension(value);
      if (!normalized || seen.has(normalized)) return;
      seen.add(normalized);
      options.push([normalized, label]);
    });
  customExtensions.forEach((extension) => {
    if (seen.has(extension)) return;
    seen.add(extension);
    options.push([extension, "Custom extension"]);
  });
  return options;
}

function normalizeExtension(value) {
  const raw = String(value || "").trim().toLowerCase();
  if (!raw || raw.includes(" ") || raw.includes(",") || raw.includes("/") || raw.includes("\\")) return "";
  const extension = raw.startsWith(".") ? raw : `.${raw}`;
  if (!/^\.[a-z0-9][a-z0-9._+-]{0,40}$/.test(extension)) return "";
  return extension;
}

function extensionGroupFor(extension) {
  if (customExtensions.includes(extension)) return "Custom";
  if ([".env", ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".kdbx", ".npmrc", ".pypirc", ".netrc", ".aws", ".ovpn", ".pcf", ".mobileconfig", ".rdp"].includes(extension)) {
    return "Secrets & config";
  }
  if ([".doc", ".docx", ".docm", ".dotx", ".dotm", ".rtf", ".odt", ".ott", ".pages", ".pdf", ".ppt", ".pptx", ".pptm", ".odp", ".otp", ".keynote", ".one", ".pub", ".vsd", ".vsdx", ".dwg", ".dxf"].includes(extension)) {
    return "Documents";
  }
  if ([".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".sql", ".dump", ".backup", ".bak", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ods", ".ots", ".numbers", ".pst", ".ost", ".msg", ".eml", ".mbox", ".ics", ".dat"].includes(extension)) {
    return "Data & exports";
  }
  if ([".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".sh", ".py", ".js", ".ts", ".tsx", ".jsx", ".html", ".htm", ".css", ".scss", ".java", ".cs", ".go", ".rb", ".php", ".c", ".cpp", ".h", ".hpp", ".md", ".adoc", ".rst", ".yara", ".reg", ".tf", ".tfvars", ".tfstate", ".hcl", ".dockerfile"].includes(extension)) {
    return "Source code";
  }
  if ([".zip", ".7z", ".rar", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".cab", ".jar", ".iso", ".vhd", ".vhdx"].includes(extension)) {
    return "Archives";
  }
  if ([".sys", ".dll", ".exe", ".msi", ".lnk", ".tmp", ".temp", ".old", ".swp", ".bin", ".gpg", ".pgp"].includes(extension)) {
    return "System & binaries";
  }
  if ([".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tif", ".tiff", ".heic", ".svg", ".mp3", ".wav", ".mp4", ".mov", ".avi", ".mkv"].includes(extension)) {
    return "Media";
  }
  return "Other";
}

function applyExtensionPreset(name, list = allowedExtensionsList, search = extensionSearch) {
  if (!list) return;
  const selected = new Set(name === "all" ? getExtensionOptions().map(([extension]) => extension) : EXTENSION_PRESETS[name] || []);
  [...list.querySelectorAll("input[type='checkbox']")].forEach((input) => {
    input.checked = selected.has(input.value);
  });
  reorderExtensionOptions(list);
  filterExtensionList(list, search);
  updateExtensionSummary(list);
}

function applySimpleExtensionPolicy(name, list = allowedExtensionsList, search = extensionSearch) {
  if (!list) return;
  const selected = new Set(SIMPLE_EXTENSION_PRESETS[name] || SIMPLE_EXTENSION_PRESETS.secrets);
  [...list.querySelectorAll("input[type='checkbox']")].forEach((input) => {
    input.checked = selected.has(input.value);
  });
  reorderExtensionOptions(list);
  filterExtensionList(list, search);
  updateExtensionSummary(list);
  if (list === endpointAllowedExtensionsList) {
    tuneEndpointScanDefaults();
  }
}

function toggleExtensionPolicyMode(simpleId, advancedId, buttonId) {
  const simple = document.querySelector(`#${simpleId}`);
  const advanced = document.querySelector(`#${advancedId}`);
  const button = document.querySelector(`#${buttonId}`);
  if (!simple || !advanced || !button) return;
  const nextAdvanced = advanced.classList.contains("hidden");
  simple.classList.toggle("hidden", nextAdvanced);
  advanced.classList.toggle("hidden", !nextAdvanced);
  button.textContent = nextAdvanced ? "Simple" : "Advanced";
}

function initSimpleExtensionPolicies() {
  document.querySelectorAll("input[name='ext-preset']").forEach((radio) => {
    radio.addEventListener("change", () => {
      if (radio.checked) applySimpleExtensionPolicy(radio.value, allowedExtensionsList, extensionSearch);
    });
  });
  document.querySelectorAll("input[name='endpoint-ext-preset']").forEach((radio) => {
    radio.addEventListener("change", () => {
      if (radio.checked) applySimpleExtensionPolicy(radio.value, endpointAllowedExtensionsList, endpointExtensionSearch);
    });
  });
  document.querySelector("#ext-mode-toggle")?.addEventListener("click", () => toggleExtensionPolicyMode("ext-simple-mode", "ext-advanced-mode", "ext-mode-toggle"));
  document.querySelector("#endpoint-ext-mode-toggle")?.addEventListener("click", () => toggleExtensionPolicyMode("endpoint-ext-simple-mode", "endpoint-ext-advanced-mode", "endpoint-ext-mode-toggle"));
}

function applyDefaultSimpleExtensionPolicies() {
  const fileServerPreset = document.querySelector("input[name='ext-preset']:checked")?.value || "secrets";
  const endpointPreset = document.querySelector("input[name='endpoint-ext-preset']:checked")?.value || "secrets";
  applySimpleExtensionPolicy(fileServerPreset, allowedExtensionsList, extensionSearch);
  applySimpleExtensionPolicy(endpointPreset, endpointAllowedExtensionsList, endpointExtensionSearch);
}

function filterExtensionList(list = allowedExtensionsList, search = extensionSearch) {
  if (!list || !search) return;
  const query = search.value.trim().toLowerCase();
  list.querySelectorAll(".extension-option").forEach((option) => {
    const matchesQuery = !query || option.dataset.extensionLabel.includes(query);
    option.classList.toggle("hidden", Boolean(query && !matchesQuery));
  });
  list.querySelectorAll(".extension-group").forEach((group) => {
    const visibleRows = [...group.querySelectorAll(".extension-option")].some((option) => !option.classList.contains("hidden"));
    group.classList.toggle("hidden", !visibleRows);
  });
  updateExtensionSummary(list);
}

function reorderExtensionOptions(list = allowedExtensionsList) {
  if (!list) return;
  list.querySelectorAll(".extension-group").forEach((group) => {
    [...group.querySelectorAll(".extension-option")]
      .sort((first, second) => {
        const firstInput = first.querySelector("input");
        const secondInput = second.querySelector("input");
        const checkedDiff = Number(secondInput.checked) - Number(firstInput.checked);
        if (checkedDiff) return checkedDiff;
        return firstInput.value.localeCompare(secondInput.value);
      })
      .forEach((option) => group.appendChild(option));
  });
}

function updateExtensionSummary(list = allowedExtensionsList) {
  const selected = readSelectedExtensions(list);
  const host = list === endpointAllowedExtensionsList
    ? document.querySelector('[data-extension-selected-for="endpoint"]')
    : document.querySelector('[data-extension-selected-for="file-server"]');
  if (!host) return;
  if (!selected.length) {
    host.innerHTML = '<span class="extension-selected-empty">No extension filter selected</span>';
    return;
  }
  host.innerHTML = selected
    .map((extension) => `<button type="button" class="extension-chip" data-remove-extension="${escapeHtml(extension)}">${escapeHtml(extension)}<span aria-hidden="true">x</span></button>`)
    .join("");
}

function removeSelectedExtension(list, extension) {
  const input = [...(list?.querySelectorAll("input[type='checkbox']") || [])].find((item) => item.value === extension);
  if (!input) return;
  input.checked = false;
  reorderExtensionOptions(list);
  filterExtensionList(list, list === endpointAllowedExtensionsList ? endpointExtensionSearch : extensionSearch);
}

function addCustomExtensionFromInput(input, list, search) {
  const extension = normalizeExtension(input?.value);
  if (!extension) {
    setStatus("Custom extension format is invalid.");
    return;
  }
  if (!customExtensions.includes(extension) && !FILE_EXTENSION_OPTIONS.some(([value]) => normalizeExtension(value) === extension)) {
    customExtensions = [...customExtensions, extension].sort();
    saveCustomExtensions();
  }
  if (input) input.value = "";
  if (search) search.value = extension;
  renderExtensionFilter(allowedExtensionsList, extensionSearch);
  renderExtensionFilter(endpointAllowedExtensionsList, endpointExtensionSearch);
  [allowedExtensionsList, endpointAllowedExtensionsList].forEach((targetList) => {
    [...targetList.querySelectorAll("input[type='checkbox']")].forEach((checkbox) => {
      checkbox.checked = checkbox.checked || checkbox.value === extension;
    });
    reorderExtensionOptions(targetList);
  });
  filterExtensionList(allowedExtensionsList, extensionSearch);
  filterExtensionList(endpointAllowedExtensionsList, endpointExtensionSearch);
  setStatus(`Custom extension saved: ${extension}`);
}

function readEndpointPayload() {
  const selectedExtensions = readSelectedExtensions(endpointAllowedExtensionsList);
  const searchedExtension = readSearchExtension(endpointExtensionSearch);
  if (searchedExtension && !selectedExtensions.includes(searchedExtension)) {
    selectedExtensions.push(searchedExtension);
  }
  const selectedFileExtensions = selectedExtensions.filter((item) => item.startsWith("."));
  const archiveOnlyFilter = selectedFileExtensions.length > 0 && selectedFileExtensions.every((extension) => ARCHIVE_EXTENSIONS.has(extension));
  const scope = endpointPathScope.value;
  const customPaths = endpointCustomPaths.value
    .split(";")
    .map((item) => item.trim())
    .filter(Boolean);
  const pathsByScope = {
    default: ["desktop", "documents", "downloads"],
    desktop: ["desktop"],
    documents: ["documents"],
    downloads: ["downloads"],
    all: ["all"],
    c_drive: ["c_drive"],
    all_fixed_drives: ["all_fixed_drives"],
    custom: customPaths,
  };
  return {
    host: document.querySelector("#endpoint-host").value.trim(),
    target_username: document.querySelector("#endpoint-target-username").value.trim(),
    domain: document.querySelector("#endpoint-domain").value.trim() || "WORKGROUP",
    username: document.querySelector("#endpoint-username").value.trim(),
    password: document.querySelector("#endpoint-password").value,
    credential_ref: document.querySelector("#endpoint-credential-ref").value.trim(),
    paths: pathsByScope[scope] || pathsByScope.default,
    max_depth: Number(document.querySelector("#endpoint-max-depth").value || 12),
    read_content: document.querySelector("#endpoint-read-content").checked && !archiveOnlyFilter,
    read_acl: document.querySelector("#endpoint-read-acl")?.checked || false,
    inspect_archives: document.querySelector("#endpoint-inspect-archives")?.checked || false,
    async_scan: document.querySelector("#endpoint-async-scan")?.checked || false,
    allowed_extensions: selectedFileExtensions,
    extension_filter_enabled: selectedFileExtensions.length > 0,
    include_hidden: selectedExtensions.includes("__hidden__"),
    include_system: selectedExtensions.includes("__system__"),
    hidden_filter_enabled: selectedExtensions.includes("__hidden__"),
    system_filter_enabled: selectedExtensions.includes("__system__"),
    save_report: true,
    asset_overrides: assetRules,
  };
}

function readWinrmActivationPayload() {
  return {
    host: document.querySelector("#winrm-activate-host").value.trim(),
    target_username: document.querySelector("#winrm-target-username").value.trim(),
    domain: document.querySelector("#winrm-activate-domain").value.trim() || "WORKGROUP",
    username: document.querySelector("#winrm-activate-username").value.trim(),
    password: document.querySelector("#winrm-activate-password").value,
    credential_ref: "",
    paths: ["desktop", "documents", "downloads"],
    max_depth: 1,
    read_content: false,
    save_report: false,
    asset_overrides: [],
  };
}

function readLocalWinrmPayload() {
  return {
    domain: document.querySelector("#local-winrm-domain").value.trim() || "WORKGROUP",
    username: document.querySelector("#local-winrm-username").value.trim(),
    password: document.querySelector("#local-winrm-password").value,
  };
}

function syncEndpointScanCredentials(payload) {
  document.querySelector("#endpoint-host").value = payload.host || "";
  document.querySelector("#endpoint-target-username").value = payload.target_username || "";
  document.querySelector("#endpoint-domain").value = payload.domain || "WORKGROUP";
  document.querySelector("#endpoint-username").value = payload.username || "";
  document.querySelector("#endpoint-password").value = payload.password || "";
  document.querySelector("#endpoint-credential-ref").value = "";
}

async function ensureEndpointCredential(payload) {
  if (!payload.host || payload.credential_ref || !payload.password) {
    return payload;
  }
  const secret = await api("/api/credentials", {
    username: payload.username,
    password: payload.password,
    domain: payload.domain,
  });
  document.querySelector("#endpoint-credential-ref").value = secret.credential_ref;
  document.querySelector("#endpoint-password").value = "";
  return { ...payload, credential_ref: secret.credential_ref, password: "" };
}

function setBusy(isBusy) {
  testBtn.disabled = isBusy;
  scanBtn.disabled = isBusy;
  generateDemoDataBtn.disabled = isBusy;
  if (localWinrmActivateBtn) localWinrmActivateBtn.disabled = isBusy;
  if (endpointActivateBtn) endpointActivateBtn.disabled = isBusy;
  if (endpointTestBtn) endpointTestBtn.disabled = isBusy;
  if (endpointScanBtn) endpointScanBtn.disabled = isBusy;
  if (endpointCancelBtn) endpointCancelBtn.disabled = !activeEndpointJobId;
  if (endpointViewOverviewBtn) endpointViewOverviewBtn.disabled = isBusy;
  updateEndpointCustomPathState(isBusy);
}

function setStatus(message, tone = "muted") {
  statusBox.className = `status ${tone}`;
  statusBox.textContent = message;
}

function animateNumber(element, target) {
  if (!element) {
    return;
  }
  const end = Number(target || 0);
  const start = Number(element.dataset.value || element.textContent || 0) || 0;
  element.dataset.value = String(end);
  if (start === end) {
    element.textContent = String(end);
    return;
  }
  const duration = 720;
  const started = performance.now();
  const step = (now) => {
    const progress = Math.min((now - started) / duration, 1);
    const eased = 1 - Math.pow(1 - progress, 3);
    element.textContent = String(Math.round(start + (end - start) * eased));
    if (progress < 1) {
      requestAnimationFrame(step);
    }
  };
  requestAnimationFrame(step);
}

function setScanProgress(active, progress = 0, label = "Scanning...") {
  scanProgress.classList.toggle("hidden", !active);
  scanProgress.classList.toggle("active", active);
  scanProgressLabel.textContent = label;
  scanProgressBar.style.width = `${Math.max(4, Math.min(100, Number(progress) || 0))}%`;
}

function setEndpointScanProgress(active, progress = 0, label = "Scanning endpoint...") {
  if (!endpointScanProgress || !endpointScanProgressLabel || !endpointScanProgressBar) return;
  endpointScanProgress.classList.toggle("hidden", !active);
  endpointScanProgress.classList.toggle("active", active);
  endpointScanProgressLabel.textContent = label;
  endpointScanProgressBar.style.width = `${Math.max(4, Math.min(100, Number(progress) || 0))}%`;
}

function clearResultsFilter() {
  if (filterInput) {
    filterInput.value = "";
  }
  inventoryRiskFilter = "ALL";
  inventorySourceFacet = "ALL";
  inventoryFindingFacet = "ALL";
  if (inventorySourceFilter) inventorySourceFilter.value = "ALL";
  if (inventoryFindingFilter) inventoryFindingFilter.value = "ALL";
}

function summarizeExtensions(files = [], backendCounts = null) {
  const counts = backendCounts || {};
  if (!backendCounts) {
    files.forEach((file) => {
      const extension = String(file.extension || "no extension").toLowerCase();
      counts[extension] = (counts[extension] || 0) + 1;
    });
  }
  const top = Object.entries(counts)
    .filter(([extension]) => extension !== "no extension")
    .sort(([, firstCount], [, secondCount]) => secondCount - firstCount)
    .slice(0, 8)
    .map(([extension, count]) => `${extension}: ${count}`)
    .join(", ");
  return top ? `Extensions: ${top}.` : "";
}

function summarizeEndpointDiagnostics(endpoint = {}) {
  const diagnostics = endpoint.scan_diagnostics || {};
  const visited = Number(diagnostics.visited_files || 0);
  const matched = Number(diagnostics.matched_files || 0);
  const archiveFiles = Number(diagnostics.archive_files || 0);
  const archiveEntries = Number(diagnostics.archive_entries || 0);
  const skippedDirs = Number(diagnostics.skipped_dirs || 0);
  const resolved = (diagnostics.resolved_roots || []).slice(0, 3).join("; ");
  const missing = (diagnostics.missing_roots || []).slice(0, 3).join("; ");
  const archiveErrors = (diagnostics.archive_errors || []).slice(0, 2).join("; ");
  const allowed = (diagnostics.allowed_extensions || endpoint.allowed_extensions || []).join(", ");
  const parts = [`Visited: ${visited}`, `Matched: ${matched}`];
  if (skippedDirs) parts.push(`Skipped dirs: ${skippedDirs}`);
  if (archiveFiles || archiveEntries) parts.push(`Archives: ${archiveFiles}`, `Archive entries: ${archiveEntries}`);
  if (allowed) parts.push(`Allowed: ${allowed}`);
  if (resolved) parts.push(`Roots: ${resolved}`);
  if (missing) parts.push(`Missing: ${missing}`);
  if (archiveErrors) parts.push(`Archive errors: ${archiveErrors}`);
  return parts.join(". ");
}

function showToast(title, message = "", tone = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.innerHTML = `<strong>${escapeHtml(title)}</strong>${message ? `<span>${escapeHtml(message)}</span>` : ""}`;
  toastHost.appendChild(toast);
  window.setTimeout(() => toast.classList.add("leaving"), 4200);
  window.setTimeout(() => toast.remove(), 4800);
}

function updateEndpointCustomPathState(isBusy = false) {
  if (!endpointPathScope || !endpointCustomPaths) {
    return;
  }
  const customSelected = endpointPathScope.value === "custom";
  endpointCustomPaths.disabled = isBusy || !customSelected;
  endpointCustomPaths.required = customSelected;
  if (!customSelected) {
    endpointCustomPaths.value = "";
  }
}

function tuneEndpointScanDefaults() {
  const depthInput = document.querySelector("#endpoint-max-depth");
  const readContent = document.querySelector("#endpoint-read-content");
  if (depthInput && ["c_drive", "all_fixed_drives"].includes(endpointPathScope?.value) && Number(depthInput.value || 0) > 4) {
    depthInput.value = "4";
  }
  const selectedExtensions = readSelectedExtensions(endpointAllowedExtensionsList).filter((item) => item.startsWith("."));
  const searchedExtension = readSearchExtension(endpointExtensionSearch);
  if (searchedExtension && !selectedExtensions.includes(searchedExtension)) {
    selectedExtensions.push(searchedExtension);
  }
  const archiveOnlyFilter = selectedExtensions.length > 0 && selectedExtensions.every((extension) => ARCHIVE_EXTENSIONS.has(extension));
  if (readContent && archiveOnlyFilter) {
    readContent.checked = false;
  }
}

function renderSkeletonRows(count = 6) {
  resultsBody.innerHTML = Array.from({ length: count })
    .map(
      () => `
        <tr class="skeleton-row">
          <td><span class="skeleton-block wide"></span><span class="skeleton-block"></span></td>
          <td><span class="skeleton-block"></span></td>
          <td><span class="skeleton-block short"></span></td>
          <td><span class="skeleton-pill"></span></td>
          <td><span class="skeleton-block short"></span></td>
          <td><span class="skeleton-block"></span></td>
          <td><span class="skeleton-block wide"></span></td>
        </tr>
      `
    )
    .join("");
}

function setAuthState(isAuthenticated) {
  document.body.classList.toggle("auth-locked", !isAuthenticated);
  document.body.classList.toggle("auth-ready", isAuthenticated);
  setBusy(!isAuthenticated);
  if (!isAuthenticated) {
    window.location.replace("/login");
  }
}

async function logout() {
  const tokenToRevoke = accessToken;
  try {
    if (tokenToRevoke) {
      await fetch("/api/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenToRevoke}` },
      });
    }
  } catch {
    // Client-side logout still proceeds; token expiry/revocation is best-effort if the network is unavailable.
  }
  accessToken = "";
  latestDashboard = null;
  safeSessionSet("dspm-access-token", "");
  safeSessionSet("dspm-tenant-id", "default");
  safeSessionSet("dspm-role", "");
  safeSessionSet("dspm-user", "");
  setAuthState(false);
}


function isProtectedFile(file = {}) {
  const status = String(file.content_status || file.scan_error || file.protection_type || "").toLowerCase();
  const extension = String(file.extension || "").toLowerCase();
  return Boolean(file.protected)
    || /protected|password|encrypted|locked|unreadable|unsupported_archive|bad_archive/.test(status)
    || [".gpg", ".pgp", ".kdbx", ".p12", ".pfx"].includes(extension);
}

function getProtectionLabel(file = {}) {
  if (file.protection_type) return String(file.protection_type).replaceAll("_", " ");
  const status = String(file.content_status || "").replaceAll("_", " ");
  if (status) return status;
  return "content locked";
}

function getFriendlyTimestamp(value) {
  if (!value) return "";
  const parsed = Date.parse(value);
  if (Number.isNaN(parsed)) return value;
  return new Date(parsed).toLocaleString();
}

function renderProfile() {
  profileName.textContent = currentUser || "User";
  profileTenant.textContent = `${currentTenant || "default"} tenant`;
  profileRole.textContent = currentRole || "viewer";
  profilePanelName.textContent = currentUser || "User";
  profilePanelTenant.textContent = currentTenant || "default";
  tenantSwitcher.value = currentTenant;
  const initial = (currentUser || "U").trim().charAt(0).toUpperCase();
  document.querySelectorAll(".profile-avatar").forEach((item) => {
    item.textContent = initial || "U";
  });
}

function updateSummary(summary = {}) {
  animateNumber(document.querySelector("#critical-count"), summary.critical || 0);
  animateNumber(document.querySelector("#high-count"), summary.high || 0);
  animateNumber(document.querySelector("#medium-count"), summary.medium || 0);
  animateNumber(document.querySelector("#low-count"), summary.low || 0);
  animateNumber(protectedCount, summary.protected_files || 0);
  animateNumber(document.querySelector("#total-count"), summary.total_files || 0);
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
    protected_files: files.filter(isProtectedFile).length,
  });

  renderReportPreview();
  renderExecutiveExperience();
  renderScanContextPanels();
  renderFindingsWorkspace();
  renderExposureWorkspace();
}

function applyScanReport(report, scanKind = "file-server") {
  latestReport = report;
  latestFiles = report.files || [];
  latestScanKind = scanKind;
  fileSearchIndex = new WeakMap();
  renderedRowsLimit = ROW_PAGE_SIZE;
  updateSummaryFromFiles(latestFiles);
  hasRenderedScanRows = true;
  renderRows(latestFiles);
  scanMeta.textContent = buildScanMetaText(report, scanKind);
}

function buildScanMetaText(report = latestReport, scanKind = latestScanKind) {
  if (!report) return "No scan has been run yet.";
  const source = scanKind === "endpoint"
    ? report.endpoint?.host || report.source || "endpoint"
    : report.source || readPayload().server || "file server";
  const label = scanKind === "endpoint" ? "endpoint files" : "files";
  return `${latestFiles.length} ${label} scanned from ${source} at ${report.timestamp || "latest run"}`;
}

function getScanKindLabel() {
  return latestScanKind === "endpoint" ? "Endpoint scan" : latestScanKind === "file-server" ? "File-server scan" : "No scan";
}

function renderScanContextPanels() {
  const summary = buildCurrentSummary();
  const source = latestScanKind === "endpoint"
    ? latestReport?.endpoint?.host || latestReport?.source || "endpoint"
    : latestReport?.source || readPayload().server || "file server";
  const hasData = summary.total_files > 0;
  const title = hasData ? `${getScanKindLabel()} - ${summary.total_files} files` : "No scan loaded";
  const protectedFiles = latestFiles.filter(isProtectedFile).length;
  const body = hasData
    ? `${summary.critical || 0} critical, ${summary.high || 0} high, ${countSensitiveFiles(latestFiles)} sensitive, ${protectedFiles} protected/locked files from ${source}.`
    : "Run a file-server or endpoint scan to populate the shared workspace.";
  const contextHtml = `
    <div>
      <span>Latest workspace data</span>
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(body)}</p>
    </div>
    <div class="context-actions">
      <button type="button" class="secondary-btn" data-tab-jump="inventory">Open inventory</button>
      <button type="button" class="secondary-btn" data-tab-jump="risk">Open risk</button>
    </div>
  `;
  if (fileServerContext) fileServerContext.innerHTML = contextHtml;
  if (endpointContext) endpointContext.innerHTML = contextHtml;
}

function renderScanRunningContext(scanKind, message) {
  latestScanKind = scanKind;
  const title = scanKind === "endpoint" ? "Endpoint scan running" : "File-server scan running";
  const contextHtml = `
    <div>
      <span>Latest workspace data</span>
      <strong>${escapeHtml(title)}</strong>
      <p>${escapeHtml(message)}</p>
    </div>
    <div class="context-actions">
      <button type="button" class="secondary-btn" data-tab-jump="inventory">Open inventory</button>
      <button type="button" class="secondary-btn" data-tab-jump="${scanKind === "endpoint" ? "endpoint" : "file-servers"}">Open scan</button>
    </div>
  `;
  if (fileServerContext) fileServerContext.innerHTML = contextHtml;
  if (endpointContext) endpointContext.innerHTML = contextHtml;
}

function renderFindingsWorkspace() {
  if (!findingsSignalSummary || !findingsPrioritySummary) return;
  const stats = buildFindingStats(Number.POSITIVE_INFINITY);
  if (!latestFiles.length) {
    findingsSignalSummary.className = "summary-list";
    findingsPrioritySummary.className = "summary-list";
    findingsSignalSummary.innerHTML = `
      <div class="finding-kpi-grid">
        <div class="finding-kpi critical"><span>Sensitive files</span><strong>0</strong></div>
        <div class="finding-kpi high"><span>Secret signals</span><strong>0</strong></div>
        <div class="finding-kpi medium"><span>Regulated data</span><strong>0</strong></div>
      </div>
      <div class="summary-row finding-signal-row"><span>Scan status</span><strong>Ready</strong></div>
      <div class="summary-row finding-signal-row"><span>Finding categories</span><strong>Secrets / PII / PCI</strong></div>
    `;
    findingsPrioritySummary.innerHTML = `
      <div class="summary-row finding-file-card HIGH"><span><b>No scan loaded</b><small>Run a file-server or endpoint scan to fill this queue.</small></span><strong class="badge HIGH">READY</strong></div>
      <div class="summary-row finding-file-card MEDIUM"><span><b>Priority queue</b><small>Critical and high-risk files will appear here first.</small></span><strong class="badge MEDIUM">0</strong></div>
      <div class="summary-row finding-file-card LOW"><span><b>Inventory link</b><small>Use Data Inventory after scan to inspect every matched file.</small></span><strong class="badge LOW">OPEN</strong></div>
    `;
    return;
  }
  findingsSignalSummary.className = "summary-list";
  findingsPrioritySummary.className = "summary-list";
  const sensitiveFiles = latestFiles.filter((file) => (file.findings || []).length);
  const regulatedFiles = latestFiles.filter((file) => (file.findings || []).some((finding) => /pii|personal|gdpr|hipaa|pci|card|passport|ssn|iban/i.test(finding.type || finding.label || finding.pattern || "")));
  const secretFiles = latestFiles.filter((file) => (file.findings || []).some((finding) => /secret|password|token|key|credential|private/i.test(finding.type || finding.label || finding.pattern || "")));
  findingsSignalSummary.innerHTML = stats.length
    ? `
      <div class="finding-kpi-grid">
        <div class="finding-kpi critical"><span>Sensitive files</span><strong>${sensitiveFiles.length}</strong></div>
        <div class="finding-kpi high"><span>Secret signals</span><strong>${secretFiles.length}</strong></div>
        <div class="finding-kpi medium"><span>Regulated data</span><strong>${regulatedFiles.length}</strong></div>
      </div>
      ${renderFindingBars(stats, "finding-signal-bars")}
    `
    : '<div class="empty compact">No sensitive findings were detected in the latest scan.</div>';
  const priorityFiles = latestFiles
    .filter((file) => (file.findings || []).length || ["CRITICAL", "HIGH"].includes(getEffectiveRisk(file).level))
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 10);
  findingsPrioritySummary.innerHTML = priorityFiles.length
    ? priorityFiles.map((file) => {
        const risk = getEffectiveRisk(file);
        const findingCount = (file.findings || []).length;
        const source = file.source || file.share || "workspace";
        return `
          <div class="summary-row finding-file-card ${risk.level}">
            <span>
              <b>${escapeHtml(file.name || file.path || "Unknown file")}</b>
              <small>${escapeHtml(source)} &middot; ${findingCount} finding${findingCount === 1 ? "" : "s"}</small>
            </span>
            <strong class="badge ${risk.level}">${risk.level}</strong>
          </div>
        `;
      }).join("")
    : '<div class="empty compact">No priority finding queue for the latest scan.</div>';
}

function renderExposureWorkspace() {
  if (!exposurePermissionsSummary || !exposureCoverageSummary) return;
  exposurePermissionsSummary.className = "summary-list exposure-summary-list";
  exposureCoverageSummary.className = "summary-list coverage-summary-list";

  if (!latestFiles.length) {
    exposurePermissionsSummary.innerHTML = `
      <div class="exposure-kpi-grid">
        <div class="exposure-kpi high"><span>Broad access</span><strong>0</strong><small>ACL signals</small></div>
        <div class="exposure-kpi medium"><span>Hidden files</span><strong>0</strong><small>discovery scope</small></div>
        <div class="exposure-kpi low"><span>Sources</span><strong>0</strong><small>active connectors</small></div>
      </div>
      <div class="summary-row exposure-row"><span><b>ACL posture</b><small>Enable endpoint ACL reading or SMB permission enrichment.</small></span><strong>READY</strong></div>
      <div class="summary-row exposure-row"><span><b>Share exposure</b><small>Writable, broad, hidden, and admin-share signals will be grouped here.</small></span><strong>0</strong></div>
    `;
    exposureCoverageSummary.innerHTML = `
      <div class="coverage-overview-card">
        <div><span>Scan coverage</span><strong>0%</strong><small>No file content has been previewed yet.</small></div>
        <div class="coverage-meter" aria-hidden="true"><span style="width:4%"></span></div>
      </div>
      ${renderCoverageBars([
        ["Content previewed", 0, "low"],
        ["Metadata-only files", 0, "medium"],
        ["Archive entries", 0, "high"],
        ["Total files", 0, "neutral"],
      ], 1)}
    `;
    return;
  }

  const broad = latestFiles.filter((file) => file.risk?.reasons?.some((reason) => /everyone|authenticated users|broad|writable|permission|acl/i.test(reason))).length;
  const hidden = latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length;
  const protectedFiles = latestFiles.filter(isProtectedFile);
  const metadataOnly = latestFiles.filter((file) => file.content_status === "metadata_only" || file.content_scannable === false).length;
  const archiveEntries = latestFiles.filter((file) => file.scan_mode === "archive_entry" || String(file.path || "").includes("!")).length;
  const previewable = latestFiles.filter((file) => file.preview?.available).length;
  const previewPercent = Math.max(4, Math.min(100, Math.round((previewable / Math.max(1, latestFiles.length)) * 100)));
  const sources = new Set(latestFiles.map((file) => file.source || file.share || "unknown")).size;

  const riskyFolders = Array.from(
    latestFiles.reduce((map, file) => {
      const path = String(file.path || file.name || "Unknown");
      const folder = path.includes("\\") ? path.split("\\").slice(0, -1).join("\\") : path.split("/").slice(0, -1).join("/") || file.source || "Workspace";
      const existing = map.get(folder) || { folder, count: 0, risk: 0, critical: 0 };
      const effective = getEffectiveRisk(file);
      existing.count += 1;
      existing.risk += effective.score;
      existing.critical += effective.level === "CRITICAL" ? 1 : 0;
      map.set(folder, existing);
      return map;
    }, new Map()).values()
  ).sort((a, b) => b.risk - a.risk).slice(0, 6);

  exposurePermissionsSummary.innerHTML = `
    <div class="exposure-kpi-grid">
      <div class="exposure-kpi high"><span>Broad access</span><strong>${broad}</strong><small>permission signals</small></div>
      <div class="exposure-kpi medium"><span>Hidden files</span><strong>${hidden}</strong><small>in scan scope</small></div>
      <div class="exposure-kpi low"><span>Sources</span><strong>${sources}</strong><small>active sources</small></div>
    </div>
    <div class="scroll-card-list exposure-folder-list">
      ${riskyFolders.map((item) => `
        <div class="summary-row exposure-row">
          <span>
            <b>${escapeHtml(item.folder || "Workspace")}</b>
            <small>${item.count} file${item.count === 1 ? "" : "s"} &middot; ${item.critical} critical &middot; exposure score ${Math.round(item.risk)}</small>
          </span>
          <strong>${item.count}</strong>
        </div>
      `).join("")}
    </div>
  `;

  const coverageRows = [
    ["Content previewed", previewable, "low"],
    ["Metadata-only files", metadataOnly, "medium"],
    ["Archive entries", archiveEntries, "high"],
    ["Protected / locked", protectedFiles.length, "critical"],
    ["Total files", latestFiles.length, "neutral"],
  ];

  exposureCoverageSummary.innerHTML = `
    <div class="coverage-overview-card">
      <div>
        <span>Preview coverage</span>
        <strong>${previewPercent}%</strong>
        <small>${previewable} of ${latestFiles.length} files have readable preview content.</small>
      </div>
      <div class="coverage-meter" aria-hidden="true"><span style="width:${previewPercent}%"></span></div>
    </div>
    ${renderCoverageBars(coverageRows, latestFiles.length)}
    ${protectedFiles.length ? `<div class="protected-file-stack coverage-scroll-list">${protectedFiles.slice(0, 12).map((file) => `<div class="summary-row coverage-row critical protected-file-row"><span><b>${escapeHtml(file.name || file.path || "Protected file")}</b><small>${escapeHtml(getProtectionLabel(file))} &middot; ${escapeHtml(file.path || "")}</small></span><strong>LOCKED</strong></div>`).join("")}</div>` : ""}
  `;
}

function renderCoverageBars(rows, total) {
  const max = Math.max(Number(total) || 0, ...rows.map(([, value]) => Number(value) || 0), 1);
  return `
    <div class="coverage-grid coverage-bar-list">
      ${rows.map(([label, value, tone]) => `
        <div class="summary-row coverage-row ${tone}">
          <span>${escapeHtml(label)}</span>
          <strong>${value}</strong>
          <progress max="${max}" value="${Number(value) || 0}"></progress>
        </div>
      `).join("")}
    </div>
  `;
}


function list(items) {
  if (!items || items.length === 0) {
    return '<span class="subtext">None</span>';
  }

  return `<ul class="list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function detailButton(items, file, type, label, emptyText) {
  if (!items || items.length === 0) {
    return `<span class="subtext">${escapeHtml(emptyText)}</span>`;
  }

  return `
    <button type="button" class="detail-toggle" data-detail-type="${escapeHtml(type)}" data-detail-key="${escapeHtml(fileKey(file))}" title="${escapeHtml(label)}">
        <span class="detail-chevron" aria-hidden="true"></span>
        <span class="detail-toggle-label">${escapeHtml(label)}</span>
        <span class="detail-count">${items.length}</span>
    </button>
  `;
}

function renderRows(files) {
  const visible = getVisibleInventoryFiles(files);
  const page = visible.slice(0, renderedRowsLimit);
  const currentKeys = new Set(page.map((file) => fileKey(file)));
  renderInventoryControlState(files, visible);

  if (visible.length === 0) {
    const hasAnyFiles = Boolean(files?.length);
    resultsBody.innerHTML = `<tr><td colspan="7" class="empty inventory-empty-state">
      <strong>${hasAnyFiles ? "No files match the current filters." : "Run a scan to see file risk assessment."}</strong>
      <span>${hasAnyFiles ? "Try clearing risk, source, finding, or search filters." : "File-server and endpoint results will appear here with findings, risk, reasons, and DLP actions."}</span>
    </td></tr>`;
    lastRenderedFileKeys = currentKeys;
    hasRenderedScanRows = true;
    return;
  }

  const rows = page
    .map((file) => {
      const rawFindings = file.findings || [];
      const findingLabels = rawFindings.map((finding) => `${finding.type || finding.label || "Signal"}: ${finding.count || 1}`);
      const recommendations = file.risk?.dlp_recommendations || [];
      const reasons = file.risk?.reasons || [];
      const effectiveRisk = getEffectiveRisk(file);
      const level = effectiveRisk.level;
      const score = effectiveRisk.score;
      const key = fileKey(file);
      const preview = renderPreview(file.preview);
      const flash = hasRenderedScanRows && !lastRenderedFileKeys.has(key) ? " row-flash" : "";
      const fileFlags = [
        file.is_hidden ? "Hidden" : "",
        file.is_system ? "System" : "",
        file.scan_mode === "archive_entry" || String(file.path || "").includes("::") ? "Archive" : "",
        file.content_status === "metadata_only" ? "Metadata only" : "",
        isProtectedFile(file) ? "Protected / locked" : "",
      ].filter(Boolean);
      const riskLabel = buildRiskLabel(level, score);
      const findingChips = rawFindings.length
        ? rawFindings.slice(0, 4).map((finding) => `<span class="finding-chip">${escapeHtml(finding.type || finding.label || "Signal")} <b>${escapeHtml(finding.count || 1)}</b></span>`).join("")
        : '<span class="subtext">No sensitive signals</span>';
      const moreFindings = rawFindings.length > 4 ? `<span class="finding-chip muted-chip">+${rawFindings.length - 4}</span>` : "";
      const sourceName = file.source || file.share || "workspace";
      const path = file.path || file.name || "";
      const owner = inferDepartment(file);

      return `
        <tr class="${flash} severity-row ${level}" data-file-key="${escapeHtml(key)}">
          <td>
            <div class="file-title polished-file-title">
              <button type="button" class="preview-toggle" data-preview="${escapeHtml(key)}" title="Show file preview" aria-label="Show file preview"><span class="preview-toggle-icon" aria-hidden="true"></span></button>
              <span class="file-path">${escapeHtml(file.name || file.path || "Unknown file")}</span>
            </div>
            <div class="file-meta-line">
              ${file.extension ? `<span>${escapeHtml(file.extension)}</span>` : ""}
              <span>${escapeHtml(formatBytes(file.size))}</span>
              <span>${escapeHtml(owner)}</span>
            </div>
            ${fileFlags.length ? `<div class="file-flags polished-flags">${fileFlags.map((flag) => `<span>${escapeHtml(flag)}</span>`).join("")}</div>` : ""}
            <div class="subtext path-subtext">${escapeHtml(path)}</div>
            ${preview}
          </td>
          <td>
            <div class="source-pill">${escapeHtml(sourceName)}</div>
            <div class="subtext">${escapeHtml(file.share || file.content_status || "scanned")}</div>
          </td>
          <td><div class="finding-chip-wrap">${findingChips}${moreFindings}</div></td>
          <td>
            <span class="badge ${level}">${escapeHtml(level)} ${escapeHtml(score)}</span>
            <div class="risk-mini-meter" style="--risk-score:${Math.max(0, Math.min(100, Number(score) || 0))}%"><span></span></div>
            <div class="subtext">${escapeHtml(riskLabel)}</div>
          </td>
          <td>
            <select class="risk-select" data-override="${escapeHtml(key)}" aria-label="Manual risk override for ${escapeHtml(file.name || file.path || "file")}">
              ${riskOption("", "Auto", rowOverrides[key] || "")}
              ${riskOption("CRITICAL", "Critical", rowOverrides[key] || "")}
              ${riskOption("HIGH", "High", rowOverrides[key] || "")}
              ${riskOption("MEDIUM", "Medium", rowOverrides[key] || "")}
              ${riskOption("LOW", "Low", rowOverrides[key] || "")}
            </select>
          </td>
          <td>${detailButton(reasons, file, "reasons", "Reasons", "No reasons")}</td>
          <td>${detailButton(recommendations, file, "recommendations", "DLP actions", "No actions")}</td>
        </tr>
      `;
    })
    .join("");
  const moreRow = visible.length > page.length
    ? `<tr><td colspan="7" class="empty"><button type="button" class="secondary-btn mini-btn" id="load-more-results">Load ${Math.min(ROW_PAGE_SIZE, visible.length - page.length)} more of ${visible.length}</button></td></tr>`
    : "";
  resultsBody.innerHTML = rows + moreRow;
  lastRenderedFileKeys = currentKeys;
  hasRenderedScanRows = true;
}

function getVisibleInventoryFiles(files = latestFiles) {
  const query = filterInput?.value?.trim().toLowerCase() || "";
  return (files || []).filter((file) => {
    const risk = getEffectiveRisk(file).level;
    if (inventoryRiskFilter === "PROTECTED" && !isProtectedFile(file)) return false;
    if (!["ALL", "PROTECTED"].includes(inventoryRiskFilter) && risk !== inventoryRiskFilter) return false;
    const source = getInventorySourceValue(file);
    if (inventorySourceFacet !== "ALL" && source !== inventorySourceFacet) return false;
    if (inventoryFindingFacet !== "ALL" && !getFileFindingTypes(file).includes(inventoryFindingFacet)) return false;
    return !query || getFileSearchText(file).includes(query);
  });
}

function renderInventoryControlState(files = latestFiles, visible = getVisibleInventoryFiles(files)) {
  updateInventoryFilterOptions(files || []);
  inventoryRiskFilters.forEach((button) => {
    const risk = button.dataset.riskFilter || "ALL";
    button.classList.toggle("active", risk === inventoryRiskFilter);
    const count = risk === "ALL"
      ? (files || []).length
      : risk === "PROTECTED"
        ? (files || []).filter(isProtectedFile).length
        : (files || []).filter((file) => getEffectiveRisk(file).level === risk).length;
    button.dataset.count = String(count);
  });
  if (inventoryContextMetrics) {
    const sensitive = visible.filter((file) => (file.findings || []).length).length;
    const avgRisk = visible.length
      ? Math.round(visible.reduce((sum, file) => sum + (Number(getEffectiveRisk(file).score) || 0), 0) / visible.length)
      : 0;
    const topSource = visible.length ? getTopFacet(visible.map(getInventorySourceValue)) : "none";
    inventoryContextMetrics.innerHTML = `
      <div><span>Visible</span><strong>${visible.length}</strong><small>of ${(files || []).length} files</small></div>
      <div><span>Sensitive</span><strong>${sensitive}</strong><small>${Math.round((sensitive / Math.max(1, visible.length)) * 100)}% in view</small></div>
      <div><span>Avg risk</span><strong>${avgRisk}</strong><small>/100</small></div>
      <div><span>Top source</span><strong>${escapeHtml(topSource)}</strong><small>current filter</small></div>
    `;
  }
}

function updateInventoryFilterOptions(files = latestFiles) {
  if (inventorySourceFilter) {
    const sources = [...new Set(files.map(getInventorySourceValue).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const current = sources.includes(inventorySourceFacet) ? inventorySourceFacet : "ALL";
    inventorySourceFacet = current;
    inventorySourceFilter.innerHTML = ["ALL", ...sources]
      .map((value) => `<option value="${escapeHtml(value)}" ${value === current ? "selected" : ""}>${escapeHtml(value === "ALL" ? "All sources" : value)}</option>`)
      .join("");
  }
  if (inventoryFindingFilter) {
    const findings = [...new Set(files.flatMap(getFileFindingTypes))].sort((a, b) => a.localeCompare(b));
    const current = findings.includes(inventoryFindingFacet) ? inventoryFindingFacet : "ALL";
    inventoryFindingFacet = current;
    inventoryFindingFilter.innerHTML = ["ALL", ...findings]
      .map((value) => `<option value="${escapeHtml(value)}" ${value === current ? "selected" : ""}>${escapeHtml(value === "ALL" ? "All finding types" : value)}</option>`)
      .join("");
  }
}

function getInventorySourceValue(file) {
  return String(file.source || file.share || "workspace").trim() || "workspace";
}

function getFileFindingTypes(file) {
  const findings = (file.findings || [])
    .map((finding) => String(finding.type || finding.label || finding.pattern || "Signal").trim())
    .filter(Boolean);
  if (isProtectedFile(file)) {
    findings.push("Protected / locked");
  }
  return findings;
}

function getTopFacet(values) {
  const counts = values.reduce((map, item) => {
    map[item] = (map[item] || 0) + 1;
    return map;
  }, {});
  const top = Object.entries(counts).sort((a, b) => b[1] - a[1])[0];
  return top ? top[0] : "none";
}

function buildRiskLabel(level, score) {
  if (level === "CRITICAL") return "Immediate remediation";
  if (level === "HIGH") return "Restrict and review";
  if (level === "MEDIUM") return "Owner review";
  if (Number(score) > 0) return "Monitor";
  return "No action";
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  const amount = bytes / 1024 ** index;
  return `${amount >= 10 || index === 0 ? Math.round(amount) : amount.toFixed(1)} ${units[index]}`;
}

function getFileSearchText(file) {
  const cached = fileSearchIndex.get(file);
  if (cached) return cached;
  const text = [
    file.name,
    file.path,
    file.source,
    file.share,
    file.extension,
    file.risk?.level,
    file.risk?.score,
    ...(file.findings || []).map((finding) => `${finding.type} ${finding.description || ""}`),
  ]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();
  fileSearchIndex.set(file, text);
  return text;
}

function resolveTabName(tabName) {
  const aliases = { inventory: "overview" };
  return aliases[tabName] || tabName || "overview";
}

function hydrateNavigation() {
  const icons = {
    overview: "DB",
    risk: "RM",
    "file-servers": "FS",
    endpoint: "EP",
    findings: "FN",
    exposure: "EX",
    reports: "RP",
    history: "HS",
    security: "SO",
    admin: "AD",
    settings: "AR",
    integrations: "IN",
    logic: "LG",
  };
  tabs.forEach((tab) => {
    const key = tab.dataset.tab;
    tab.dataset.navIcon = tab.dataset.navIcon || icons[key] || (key || "DSPM").slice(0, 2).toUpperCase();
    tab.title = tab.querySelector("span")?.textContent?.trim() || key || "Navigate";
    tab.setAttribute("aria-current", tab.classList.contains("active") ? "page" : "false");
  });
}

function switchTab(tabName) {
  const requestedTab = tabName;
  const resolvedTab = resolveTabName(tabName);
  const activePanel = document.getElementById(`tab-${resolvedTab}`);
  if (!activePanel) return;

  tabs.forEach((tab) => {
    const isActive = tab.dataset.tab === resolvedTab;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-current", isActive ? "page" : "false");
  });
  tabPanels.forEach((panel) => panel.classList.toggle("active", panel === activePanel));

  activePanel.animate(
    [
      { opacity: 0, transform: "translateY(8px)" },
      { opacity: 1, transform: "translateY(0)" },
    ],
    { duration: 180, easing: "ease-out" }
  );

  if (requestedTab === "inventory") {
    document.querySelector("#inventory-workspace")?.scrollIntoView({ behavior: "smooth", block: "start" });
  } else if (window.matchMedia("(max-width: 860px)").matches) {
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const icon = themeToggle.querySelector(".theme-icon");
  const nextLabel = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  if (icon) {
    icon.textContent = theme === "dark" ? "☀" : "☾";
  }
  themeToggle.setAttribute("aria-label", nextLabel);
  themeToggle.title = nextLabel;
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

function openDetailDrawer(key, type) {
  const file = latestFiles.find((item) => fileKey(item) === key);
  const isRecommendation = type === "recommendations";
  const items = isRecommendation ? file?.risk?.dlp_recommendations || [] : file?.risk?.reasons || [];
  detailDrawerEyebrow.textContent = isRecommendation ? "DLP recommendations" : "Risk context";
  detailDrawerTitle.textContent = file?.name || (isRecommendation ? "DLP recommendations" : "Reasons");
  detailDrawerMeta.textContent = file?.path || "";
  detailDrawerBody.innerHTML = items.length
    ? `
      <ol class="detail-list ${isRecommendation ? "recommendations" : "reasons"}">
        ${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ol>
    `
    : `<p class="subtext">No ${isRecommendation ? "DLP recommendations" : "risk reasons"} were generated for this file.</p>`;
  detailDrawer.classList.remove("hidden");
  detailDrawer.getBoundingClientRect();
  detailDrawer.classList.add("open");
}

function closeDetailDrawer() {
  detailDrawer.classList.remove("open");
  window.setTimeout(() => {
    if (!detailDrawer.classList.contains("open")) {
      detailDrawer.classList.add("hidden");
    }
  }, 180);
}

function renderRiskRules(rules) {
  latestRiskRules = rules || [];
  if (!rules || rules.length === 0) {
    riskRulesBody.innerHTML = '<div class="empty compact">No risk logic configured.</div>';
    return;
  }

  const formulaCards = [
    ["Detection weights", "Critical findings add 45 points and force at least 90. High findings add 35 and force at least 70. Medium findings add 20. Low findings add 5."],
    ["Context boosters", "Sensitive filenames or paths add 15 points. Risky extensions add 10-25. SMB exposure adds 5. Broad or writable permissions can add 15-40."],
    ["Customer assets", "Analyst asset rules can force LOW, MEDIUM, HIGH, or CRITICAL when a path matches a customer-specific pattern."],
    ["Posture score", "File risk scores are averaged as exposure. Posture is 100 minus that exposure, so it moves with every scan and manual override."],
  ];

  riskRulesBody.innerHTML = `
    <div class="logic-hero">
      <div>
        <span class="eyebrow">Risk scoring model</span>
        <h4>Every file receives a 0-100 risk score from content, path, extension, permissions, share exposure, and customer asset context.</h4>
      </div>
      <div class="logic-score-meter">
        <strong>100</strong>
        <span>maximum file risk</span>
      </div>
    </div>

    <section class="logic-section">
      <div class="logic-section-title">
        <span>Severity ranges</span>
        <strong>0-100 scale</strong>
      </div>
      <div class="logic-band-grid">
        ${RISK_SCORE_BANDS.map(
          (band) => `
            <article class="logic-band ${band.level}">
              <span>${band.range}</span>
              <h4>${escapeHtml(band.level)} - ${escapeHtml(band.title)}</h4>
              <p>${escapeHtml(band.description)}</p>
            </article>
          `
        ).join("")}
      </div>
    </section>

    <section class="logic-section">
      <div class="logic-section-title">
        <span>How the score is built</span>
        <strong>Signals are additive, manual context can override</strong>
      </div>
      <div class="logic-card-grid">
        ${formulaCards.map(
          ([title, description]) => `
            <article class="logic-card">
              <h4>${escapeHtml(title)}</h4>
              <p>${escapeHtml(description)}</p>
            </article>
          `
        ).join("")}
      </div>
    </section>

    <section class="logic-section">
      <div class="logic-section-title">
        <span>Detection and control rules</span>
        <strong>${rules.length} signals</strong>
      </div>
      <div class="logic-signal-grid">
        ${rules.map(renderLogicRuleCard).join("")}
      </div>
    </section>

    <section class="logic-section">
      <div class="logic-section-title">
        <span>Customer asset context</span>
        <strong>${assetRules.length} active overrides</strong>
      </div>
      <div class="logic-assets-grid">
        ${assetRules.map(
          (asset) => `
            <article class="logic-asset">
              <span class="badge ${asset.level}">${escapeHtml(asset.level)}</span>
              <h4>${escapeHtml(asset.pattern)}</h4>
              <p>${escapeHtml(asset.reason || "Matching files inherit this customer-specific risk context.")}</p>
            </article>
          `
        ).join("")}
      </div>
    </section>
  `;
}

function renderRiskRulesCache() {
  if (latestRiskRules.length) {
    renderRiskRules(latestRiskRules);
  }
}

function renderLogicRuleCard(rule) {
  return `
    <article class="logic-signal-card">
      <div class="logic-signal-head">
        <span class="badge ${riskBadgeClass(rule.base_risk)}">${escapeHtml(rule.base_risk)}</span>
        <strong>${escapeHtml(rule.score)}</strong>
      </div>
      <h4>${escapeHtml(rule.signal)}</h4>
      <p>${escapeHtml(rule.reason)}</p>
      ${renderLogicRuleList("Findings", rule.findings)}
      ${renderLogicRuleList("Keywords", rule.keywords)}
      <div class="logic-action">
        <span>DLP action</span>
        <p>${escapeHtml(rule.dlp_action)}</p>
      </div>
      ${rule.control ? `
        <div class="logic-action logic-control">
          <span>Control guidance</span>
          <p>${escapeHtml(rule.control)}</p>
        </div>
      ` : ""}
    </article>
  `;
}

function renderLogicRuleList(label, items = []) {
  if (!Array.isArray(items) || !items.length) {
    return "";
  }
  return `
    <div class="logic-rule-tags">
      <span>${escapeHtml(label)}</span>
      <div>
        ${items.map((item) => `<code>${escapeHtml(item)}</code>`).join("")}
      </div>
    </div>
  `;
}

function riskBadgeClass(value) {
  const normalized = String(value || "").toUpperCase();
  if (normalized.includes("CRITICAL")) {
    return "CRITICAL";
  }
  if (normalized.includes("HIGH")) {
    return "HIGH";
  }
  if (normalized.includes("MEDIUM") || normalized.includes("MANUAL")) {
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
  safeStorageSet(tenantStorageKey("asset-rules"), JSON.stringify(assetRules));
  assetSaveStatus.textContent = message;
  renderAssetRules();
  renderRiskRulesCache();
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
    const saved = JSON.parse(safeStorageGet(tenantStorageKey("asset-rules")) || "null");
    return Array.isArray(saved) ? saved : DEFAULT_ASSETS;
  } catch {
    return DEFAULT_ASSETS;
  }
}

function loadRowOverrides() {
  try {
    return JSON.parse(safeStorageGet(tenantStorageKey("row-risk-overrides")) || "{}");
  } catch {
    return {};
  }
}

function loadCustomExtensions() {
  try {
    const saved = JSON.parse(safeStorageGet(tenantStorageKey("custom-extensions")) || "[]");
    if (!Array.isArray(saved)) return [];
    return [...new Set(saved.map(normalizeExtension).filter(Boolean))].sort();
  } catch {
    return [];
  }
}

function saveCustomExtensions() {
  safeStorageSet(tenantStorageKey("custom-extensions"), JSON.stringify(customExtensions));
}

function saveRowOverrides() {
  safeStorageSet(tenantStorageKey("row-risk-overrides"), JSON.stringify(rowOverrides));
}

function tenantStorageKey(key) {
  return `dspm-${currentTenant || "default"}-${key}`;
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

function safeSessionGet(key) {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return null;
  }
}

function safeSessionSet(key, value) {
  try {
    if (value) {
      window.sessionStorage.setItem(key, value);
    } else {
      window.sessionStorage.removeItem(key);
    }
  } catch {
    return false;
  }
  return true;
}

function renderReportPreview() {
  if (!latestFiles.length) {
    reportPreview.innerHTML = `
      <div class="report-empty product-report-empty">
        <span class="report-empty-icon">↗</span>
        <h4>No report data yet</h4>
        <p>Run a scan first. The report center will prepare a board-ready summary, evidence register, and export package.</p>
      </div>
    `;
    return;
  }

  const report = buildReportModel();
  const hiddenCount = latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length;
  const protectedCount = latestReport?.summary?.protected_files ?? latestFiles.filter(isProtectedFile).length;
  const topFiles = report.priorityFiles.slice(0, 10);
  const fullRegisterRows = buildReportRegisterRows(report.priorityFiles, { compact: true });
  const executiveTone = report.summary.critical || report.summary.high
    ? "Immediate remediation focus: critical/high files, sensitive signals, and broad access paths."
    : "Current scan is stable, but continue ownership validation and retention cleanup.";

  reportPreview.innerHTML = `
    <div class="report-document premium-report-preview product-report-preview">
      <div class="report-cover-strip product-report-cover">
        <div>
          <span>DSPM executive evidence package</span>
          <h4>${escapeHtml(report.title)}</h4>
          <p>${escapeHtml(report.generatedAt)} · tenant ${escapeHtml(currentTenant)} · ${report.summary.total_files} files analyzed</p>
        </div>
        <strong>${report.score}</strong>
      </div>

      <div class="report-narrative-card">
        <p class="eyebrow">Board summary</p>
        <h5>${escapeHtml(executiveTone)}</h5>
        <p>Exports now separate the executive story from the full evidence register. The full dataset is available below through the expandable evidence drawer instead of forcing every row into the first page.</p>
      </div>

      <div class="report-kpis product-report-kpis">
        <div class="critical"><span>Critical</span><strong>${report.summary.critical}</strong></div>
        <div class="high"><span>High</span><strong>${report.summary.high}</strong></div>
        <div class="medium"><span>Medium</span><strong>${report.summary.medium}</strong></div>
        <div class="low"><span>Low</span><strong>${report.summary.low}</strong></div>
        <div><span>Hidden</span><strong>${hiddenCount}</strong></div>
        <div><span>Protected</span><strong>${protectedCount}</strong></div>
      </div>

      <div class="report-visual-grid report-distribution-grid">
        <div class="chart-panel report-card-scroll report-risk-card product-panel">
          <h5>Risk distribution</h5>
          ${buildDistributionBars(report.distribution)}
        </div>
        <div class="chart-panel report-card-scroll report-signal-card product-panel">
          <h5>Detection signals</h5>
          ${renderFindingBars(report.findingStats.slice(0, 10), "product-signal-bars")}
        </div>
      </div>

      <div class="report-visual-grid">
        <div class="chart-panel report-card-scroll report-priority-card product-panel">
          <h5>Priority queue</h5>
          ${renderReportFileList(topFiles)}
        </div>
        <div class="chart-panel report-card-scroll report-folder-card product-panel">
          <h5>Top risky folders</h5>
          ${renderReportFolderList(report.folders.slice(0, 10))}
        </div>
      </div>

      <details class="report-data-drawer">
        <summary>
          <span>
            <strong>Show full evidence register</strong>
            <small>All scanned files are available here; no hidden “additional files” placeholder.</small>
          </span>
          <b>${report.priorityFiles.length} rows</b>
        </summary>
        <div class="report-register-wrap">
          <table class="report-register-table">
            <thead>
              <tr><th>File</th><th>Source</th><th>Risk</th><th>Findings</th><th>Action</th></tr>
            </thead>
            <tbody>${fullRegisterRows}</tbody>
          </table>
        </div>
      </details>
    </div>
  `;
}


function buildReportModel() {
  const summary = buildCurrentSummary();
  const priorityFiles = [...latestFiles].sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score);
  return {
    title: readPayload().server || "Local sample scan",
    generatedAt: new Date().toLocaleString(),
    summary,
    score: getCurrentPostureScore(summary),
    distribution: buildRiskDistribution(summary),
    findingStats: buildFindingStats(Number.POSITIVE_INFINITY),
    priorityFiles,
    departments: groupFilesByDepartment(latestFiles),
    folders: groupFilesByFolder(latestFiles),
    comparison: buildReportComparisonRows(),
  };
}

function renderReportFileList(files) {
  if (!files.length) {
    return '<p class="subtext">No priority files.</p>';
  }
  return files
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <div class="report-row">
          <div>
            <strong>${escapeHtml(file.name || file.path || "")}</strong>
            <span>${escapeHtml(file.path || "")}</span>
          </div>
          <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
        </div>
      `;
    })
    .join("");
}

function renderReportFolderList(folders) {
  if (!folders.length) {
    return '<p class="subtext">No folder risk concentration yet.</p>';
  }
  return folders
    .map(
      (folder) => `
        <div class="report-row">
          <div>
            <strong>${escapeHtml(folder.folder)}</strong>
            <span>${folder.files} files · ${folder.critical} critical · avg ${Math.round(folder.score / Math.max(folder.files, 1))}</span>
          </div>
        </div>
      `
    )
    .join("");
}

function buildReportComparisonRows() {
  const trend = latestDashboard?.trend || [];
  if (trend.length < 2) {
    return [];
  }
  const previous = trend[trend.length - 2].summary || {};
  const latest = trend[trend.length - 1].summary || {};
  return [
    ["Critical", latest.critical || 0, previous.critical || 0],
    ["High", latest.high || 0, previous.high || 0],
    ["Medium", latest.medium || 0, previous.medium || 0],
    ["Low", latest.low || 0, previous.low || 0],
    ["Total files", latest.total_files || 0, previous.total_files || 0],
  ].map(([label, current, prior]) => ({ label, current, prior, delta: Number(current) - Number(prior) }));
}

function renderExecutiveExperience() {
  const currentSummary = buildCurrentSummary();
  const dashboardSummary = latestDashboard?.latest?.summary || {};
  const summary = currentSummary.total_files ? currentSummary : dashboardSummary.total_files ? dashboardSummary : currentSummary;
  const score = getCurrentPostureScore(summary);
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
      <span>Hidden files</span>
      <strong>${latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length}</strong>
      <p>Hidden local and SMB entries are included in discovery scope.</p>
    </div>
    <div class="insight-card protected">
      <span>Protected / locked</span>
      <strong>${latestReport?.summary?.protected_files ?? latestFiles.filter(isProtectedFile).length}</strong>
      <p>Password-protected archives, encrypted vaults, and unreadable files needing owner review.</p>
    </div>
    <div class="insight-card">
      <span>Tenant</span>
      <strong>${escapeHtml(currentTenant)}</strong>
      <p>History, audit, and vault data are isolated by tenant.</p>
    </div>
  `;

  executiveHero.innerHTML = `
    <div class="posture-meter" style="--meter:${score}; --needle:${-90 + score * 1.8}deg">
      <div class="meter-arc"></div>
      <div class="meter-needle"></div>
      <strong>${score}</strong>
      <span>Posture: ${score} - ${score >= 80 ? "Low risk" : score >= 55 ? "High risk" : "Critical risk"}</span>
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
  riskDistribution.innerHTML = `<div class="distribution-visual">${buildDonutSvg(distribution)}${buildDistributionBars(distribution)}</div>`;
  riskHeatmap.innerHTML = buildHeatmap(topFiles.length ? latestFiles : []);
  signalMatrix.innerHTML = buildSignalMatrix();
  riskTopology.innerHTML = buildRiskTopology(summary);
  postureTrend.innerHTML = buildPostureTrend();
  remediationWorkflow.innerHTML = buildRemediationWorkflow();
  msspPortfolio.innerHTML = buildMsspPortfolio();
  priorityRiskFiles.innerHTML = buildPriorityRiskFiles();
  departmentRisk.innerHTML = buildDepartmentRisk();
  scanComparison.innerHTML = buildScanComparison();
  topRiskyFolders.innerHTML = buildTopRiskyFolders();
  // Duplicate loose priority cards were intentionally hidden; the structured priority queue above is the source of truth.
  executiveTopFiles.innerHTML = "";
}

function getCurrentPostureScore(summary = buildCurrentSummary()) {
  if (latestFiles.length) {
    return calculatePostureScore(summary, latestFiles);
  }
  const dashboardSummary = latestDashboard?.latest?.summary;
  if (dashboardSummary?.total_files) {
    return calculatePostureScore(dashboardSummary);
  }
  return latestDashboard?.risk_posture_score ?? calculatePostureScore(summary);
}

function calculatePostureScore(summary, files = []) {
  if (files.length) {
    const exposure = files.reduce((sum, file) => sum + (Number(getEffectiveRisk(file).score) || 0), 0) / files.length;
    return clampScore(100 - Math.round(exposure));
  }

  const total = Number(summary.total_files || 0);
  if (!total) {
    return 100;
  }

  const exposure =
    ((summary.critical || 0) * 95 + (summary.high || 0) * 80 + (summary.medium || 0) * 55 + (summary.low || 0) * 20) / total;
  return clampScore(100 - Math.round(exposure));
}

function clampScore(value) {
  return Math.max(0, Math.min(100, Number(value) || 0));
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

function buildFindingStats(limit = 6) {
  const counts = {};
  latestFiles.forEach((file) => {
    (file.findings || []).forEach((finding) => {
      counts[finding.type] = (counts[finding.type] || 0) + Number(finding.count || 1);
    });
  });

  return Object.entries(counts)
    .map(([type, count]) => ({ type, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, limit);
}

function buildPostureTrend() {
  const trend = latestDashboard?.trend || [];
  if (!trend.length) {
    return '<div class="empty compact">Scan history will draw a posture trend after the first saved assessment.</div>';
  }

  const points = trend.slice(-8).map((item) => {
    const summary = item.summary || {};
    return {
      label: (item.timestamp || "").slice(5, 10) || "scan",
      score: calculatePostureScore(summary),
      critical: summary.critical || 0,
      high: summary.high || 0,
    };
  });

  const maxScore = Math.max(35, ...points.map((item) => item.score));
  return `
    <div class="trend-bars">
      ${points.map((item) => `
        <div class="trend-bar" title="${escapeHtml(item.label)}: ${item.score}">
          <span style="height:${Math.max(8, (item.score / maxScore) * 100)}%"></span>
          <strong>${item.score}</strong>
          <small>${escapeHtml(item.label)}</small>
        </div>
      `).join("")}
    </div>
    <div class="trend-caption">${points.at(-1)?.critical || 0} critical and ${points.at(-1)?.high || 0} high files in latest saved scan.</div>
  `;
}


function buildRemediationWorkflow() {
  const items = latestFiles
    .filter((file) => ["CRITICAL", "HIGH", "MEDIUM"].includes(getEffectiveRisk(file).level) || isProtectedFile(file))
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 18);

  if (!items.length) {
    return '<div class="empty compact">No active remediation queue yet. Critical, high, protected, and medium-risk files will appear here after a scan.</div>';
  }

  return `
    <div class="scroll-card-list remediation-list remediation-kanban">
      ${items.map((file, index) => {
        const risk = getEffectiveRisk(file);
        const remediation = file.risk?.remediation || {};
        const actions = remediation.actions || ["Validate business ownership"];
        const findingCount = (file.findings || []).length;
        const owner = remediation.owner || inferDepartment(file) || "Data owner";
        const ticket = remediation.ticket || `DSPM-${String(index + 1).padStart(4, "0")}`;
        const sla = remediation.sla || (risk.level === "CRITICAL" ? "24 hours" : risk.level === "HIGH" ? "3 business days" : "14 days");
        return `
          <article class="remediation-item compact-risk-card ${risk.level}">
            <div class="remediation-head">
              <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
              <span class="remediation-ticket">${escapeHtml(ticket)}</span>
            </div>
            <div class="remediation-body">
              <h4>${escapeHtml(file.name || file.path || "Unknown file")}</h4>
              <p title="${escapeHtml(file.path || "")}">${escapeHtml(file.path || file.source || "Workspace")}</p>
              <div class="remediation-meta">
                <span>${findingCount} finding${findingCount === 1 ? "" : "s"}</span>
                <span>${escapeHtml(owner)}</span>
                <span>SLA ${escapeHtml(sla)}</span>
              </div>
              <small>${escapeHtml(actions[0])}</small>
            </div>
          </article>
        `;
      }).join("")}
    </div>
  `;
}

function buildMsspPortfolio() {
  const tenants = tenantPortfolio.length
    ? tenantPortfolio
    : [{ tenant_id: currentTenant, scan_count: latestDashboard?.trend?.length || 0, latest: latestDashboard?.latest || { summary: buildCurrentSummary() } }];

  const totalCustomers = tenants.length;
  const activeTenant = tenants.find((tenant) => tenant.tenant_id === currentTenant) || tenants[0];
  const activeSummary = activeTenant.latest?.summary || buildCurrentSummary();
  const openCritical = tenants.reduce((sum, tenant) => sum + Number(tenant.latest?.summary?.critical || 0), 0);

  return `
    <article class="mssp-summary-card">
      <span>Managed customers</span>
      <strong>${totalCustomers}</strong>
      <p>Active customer: ${escapeHtml(currentTenant)} · ${activeSummary.total_files || 0} files in scope</p>
    </article>
    <article class="mssp-summary-card">
      <span>Open critical exposure</span>
      <strong>${openCritical}</strong>
      <p>Aggregated across tenant-isolated customer workspaces.</p>
    </article>
    ${tenants.slice(0, 4).map((tenant) => {
      const summary = tenant.latest?.summary || {};
      const score = calculatePostureScore(summary);
      const isActive = tenant.tenant_id === currentTenant;
      return `
        <article class="portfolio-card ${isActive ? "active" : ""}" data-tenant-jump="${escapeHtml(tenant.tenant_id)}">
          <span>${escapeHtml(tenant.tenant_id)}</span>
          <strong>${score}</strong>
          <p>${summary.total_files || 0} files · ${summary.critical || 0} critical · ${tenant.scan_count || 0} scans</p>
        </article>
      `;
    }).join("")}
  `;
}


function buildDonutSvg(distribution) {
  const total = distribution.reduce((sum, item) => sum + item.count, 0) || 1;
  let offset = 25;
  const rings = distribution
    .map((item) => {
      const value = (item.count / total) * 100;
      const circle = `<circle class="donut-segment" r="15.9" cx="18" cy="18" fill="transparent" stroke="${item.color}" stroke-width="7" stroke-dasharray="${value} ${100 - value}" stroke-dashoffset="${offset}" />`;
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

function buildDepartmentRisk() {
  const groups = groupFilesByDepartment(latestFiles);
  if (!groups.length) {
    return '<div class="empty compact">Department or team risk appears after a scan.</div>';
  }

  const maxScore = Math.max(...groups.map((item) => item.score), 1);
  return `
    <div class="department-risk-list">
      ${groups.map((item) => `
        <div class="department-risk-row">
          <div>
            <strong>${escapeHtml(item.department)}</strong>
            <span>${item.files} files · ${item.critical} critical · ${item.high} high</span>
          </div>
          <progress max="${maxScore}" value="${item.score}"></progress>
        </div>
      `).join("")}
    </div>
  `;
}

function buildPriorityRiskFiles() {
  const items = latestFiles
    .filter((file) => ["CRITICAL", "HIGH"].includes(getEffectiveRisk(file).level) || isProtectedFile(file))
    .sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score)
    .slice(0, 16);

  if (!items.length) {
    return '<div class="empty compact">Critical, high, and protected files will appear after a risky scan.</div>';
  }

  return `
    <div class="scroll-card-list priority-file-list">
      ${items.map((file) => {
        const risk = getEffectiveRisk(file);
        const findings = (file.findings || []).map((finding) => finding.type).slice(0, 3).join(", ") || "Risk context";
        return `
          <article class="priority-file compact-risk-card ${risk.level}" title="${escapeHtml(file.path || file.name || "")}">
            <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
            <div>
              <strong>${escapeHtml(file.name || file.path || "Unknown file")}</strong>
              <p>${escapeHtml(file.path || "")}</p>
              <small>${escapeHtml(file.source || file.share || "workspace")} &middot; ${escapeHtml(isProtectedFile(file) ? getProtectionLabel(file) : findings)}</small>
            </div>
          </article>
        `;
      }).join("")}
    </div>
  `;
}


function groupFilesByDepartment(files) {
  const groups = {};
  files.forEach((file) => {
    const department = inferDepartment(file);
    const risk = getEffectiveRisk(file);
    groups[department] = groups[department] || { department, files: 0, critical: 0, high: 0, score: 0 };
    groups[department].files += 1;
    groups[department].critical += risk.level === "CRITICAL" ? 1 : 0;
    groups[department].high += risk.level === "HIGH" ? 1 : 0;
    groups[department].score += risk.score;
  });
  return Object.values(groups).sort((a, b) => b.score - a.score);
}

function inferDepartment(file) {
  const parts = String(file.path || file.name || "")
    .split(/[\\\\/]/)
    .filter(Boolean);
  const known = ["Finance", "HR", "Legal", "Engineering", "IT", "Sales", "Marketing", "Identity", "Cloud", "Database", "Backups"];
  const match = parts.find((part) => known.some((name) => part.toLowerCase().includes(name.toLowerCase())));
  if (match) {
    return match.replaceAll("_", " ");
  }
  return file.share || parts.slice(-3, -2)[0] || file.source || "Unassigned";
}

function buildScanComparison() {
  const trend = latestDashboard?.trend || [];
  if (trend.length < 2) {
    return '<div class="empty compact">Save at least two scans to compare posture changes.</div>';
  }

  const previous = trend[trend.length - 2];
  const latest = trend[trend.length - 1];
  const previousSummary = previous.summary || {};
  const latestSummary = latest.summary || {};
  const rows = [
    ["Critical", latestSummary.critical || 0, previousSummary.critical || 0],
    ["High", latestSummary.high || 0, previousSummary.high || 0],
    ["Medium", latestSummary.medium || 0, previousSummary.medium || 0],
    ["Low", latestSummary.low || 0, previousSummary.low || 0],
    ["Total", latestSummary.total_files || 0, previousSummary.total_files || 0],
  ];

  return `
    <div class="scan-comparison-list">
      ${rows.map(([label, current, prior]) => {
        const delta = Number(current) - Number(prior);
        const sign = delta > 0 ? "+" : "";
        return `
          <div class="scan-comparison-row">
            <span>${escapeHtml(label)}</span>
            <strong>${current}</strong>
            <small class="${delta > 0 ? "worse" : delta < 0 ? "better" : ""}">${sign}${delta}</small>
          </div>
        `;
      }).join("")}
    </div>
  `;
}

function buildTopRiskyFolders() {
  const folders = groupFilesByFolder(latestFiles);
  if (!folders.length) {
    return '<div class="empty compact">Top risky folders appear after a scan.</div>';
  }

  return `
    <div class="folder-risk-list compact-folder-list">
      ${folders.slice(0, 6).map((item) => `
        <article class="folder-risk-row">
          <strong>${escapeHtml(item.folder)}</strong>
          <span>${item.files} files · avg ${Math.round(item.score / Math.max(item.files, 1))} · ${item.critical} critical</span>
        </article>
      `).join("")}
    </div>
  `;
}

function groupFilesByFolder(files) {
  const groups = {};
  files.forEach((file) => {
    const folder = inferFolder(file);
    const risk = getEffectiveRisk(file);
    groups[folder] = groups[folder] || { folder, files: 0, score: 0, critical: 0 };
    groups[folder].files += 1;
    groups[folder].score += risk.score;
    groups[folder].critical += risk.level === "CRITICAL" ? 1 : 0;
  });
  return Object.values(groups).sort((a, b) => b.score - a.score);
}

function inferFolder(file) {
  const parts = String(file.path || "")
    .split(/[\\\\/]/)
    .filter(Boolean);
  if (file.share && parts.length) {
    return `${file.share}/${parts.slice(0, -1).slice(-2).join("/") || "root"}`;
  }
  return parts.slice(0, -1).slice(-2).join("/") || file.share || file.source || "local";
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
          const size = 96 + Math.round((item.count / max) * 70);
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

function renderFindingBars(items, extraClass = "") {
  if (!items.length) {
    return '<p class="subtext">No sensitive detection signals were found.</p>';
  }

  const max = Math.max(...items.map((item) => item.count), 1);
  return `
    <div class="signal-bars ${extraClass}">
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
    protected_files: latestFiles.filter(isProtectedFile).length,
  };
}

function reportTimestampSlug() {
  return new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
}

function reportSourceSlug(value = "dspm") {
  return String(value || "dspm")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 44) || "dspm";
}

function reportFileName(extension) {
  const source = reportSourceSlug(buildReportModel().title || "assessment");
  return `dspm-${source}-${reportTimestampSlug()}.${extension}`;
}

function reportText(value, fallback = "—") {
  if (Array.isArray(value)) {
    const joined = value.filter(Boolean).join("; ");
    return joined || fallback;
  }
  const text = String(value ?? "").trim();
  return text || fallback;
}

function reportFindingsText(file) {
  const findings = file.findings || [];
  if (!findings.length) return "No sensitive finding labels";
  return findings
    .slice(0, 8)
    .map((finding) => `${finding.type || finding.label || finding.pattern || "Finding"}${finding.count ? `: ${finding.count}` : ""}`)
    .join("; ");
}

function reportReasonsText(file) {
  return reportText(file.risk?.reasons || file.risk?.explanations || file.reasons, "Risk generated from score, sensitivity, extension, hidden/protected status, and findings.");
}

function reportActionsText(file) {
  return reportText(
    file.risk?.remediation?.actions || file.risk?.dlp_recommendations || file.risk?.recommendations,
    "Validate owner, reduce broad access, apply retention policy, and monitor recurring exposure."
  );
}

function reportDlpText(file) {
  return reportText(file.risk?.dlp_recommendations || file.risk?.remediation?.controls, "Classify, restrict sharing, and add DLP monitoring rule.");
}

function reportOwnerText(file) {
  return reportText(file.owner || file.created_by || file.modified_by || file.account || file.user || file.principal, "Unassigned");
}

function reportPathText(file) {
  return reportText(file.path || file.full_path || file.name, "Unknown path");
}

function reportSourceText(file) {
  return reportText(file.source || file.share || file.host || file.server, "workspace");
}

function buildReportRegisterRows(files, options = {}) {
  const compact = options.compact !== false;
  const limit = options.limit || files.length;
  return files.slice(0, limit).map((file) => {
    const risk = getEffectiveRisk(file);
    const name = reportText(file.name || file.filename || file.path, "Unknown file");
    const path = reportPathText(file);
    const source = reportSourceText(file);
    const hidden = file.is_hidden ? "Hidden" : "Visible";
    const protectedLabel = isProtectedFile(file) ? getProtectionLabel(file) : "Readable";
    const riskCell = `<span class="risk ${risk.level}">${escapeHtml(risk.level)} ${escapeHtml(risk.score)}</span>`;
    if (compact) {
      return `
        <tr>
          <td><strong>${escapeHtml(name)}</strong><br><span>${escapeHtml(path)}</span></td>
          <td>${escapeHtml(source)}<br><span>${escapeHtml(hidden)} · ${escapeHtml(protectedLabel)}</span></td>
          <td>${riskCell}</td>
          <td>${escapeHtml(reportFindingsText(file))}</td>
          <td>${escapeHtml(reportActionsText(file))}</td>
        </tr>
      `;
    }
    return `
      <tr>
        <td><strong>${escapeHtml(name)}</strong><br><span>${escapeHtml(path)}</span></td>
        <td>${escapeHtml(source)}</td>
        <td>${escapeHtml(reportOwnerText(file))}</td>
        <td>${file.is_hidden ? "Yes" : "No"}</td>
        <td>${isProtectedFile(file) ? escapeHtml(getProtectionLabel(file)) : "No"}</td>
        <td>${riskCell}</td>
        <td>${escapeHtml(reportFindingsText(file))}</td>
        <td>${escapeHtml(reportReasonsText(file))}</td>
        <td>${escapeHtml(reportDlpText(file))}</td>
        <td>${escapeHtml(reportActionsText(file))}</td>
      </tr>
    `;
  }).join("");
}

function exportCsv() {
  if (!latestFiles.length) {
    setStatus("Run a scan before exporting Excel workbook.");
    return;
  }

  downloadFile(reportFileName("xls"), buildPolishedExcelWorkbookHtml(), "application/vnd.ms-excel;charset=utf-8");
  setStatus("Excel workbook exported with full evidence register and remediation sheets.");
}

function exportWord() {
  if (!latestFiles.length) {
    setStatus("Run a scan before exporting Word report.");
    return;
  }

  downloadFile(reportFileName("doc"), buildExecutiveReportHtml("word"), "application/msword;charset=utf-8");
  setStatus("Word board pack exported with executive summary and full appendix.");
}

function exportPdf() {
  if (!latestFiles.length) {
    setStatus("Run a scan before opening the PDF composer.");
    return;
  }

  const reportWindow = window.open("", "_blank");
  if (!reportWindow) {
    setStatus("Popup blocked. Allow popups to open the PDF composer.");
    return;
  }
  reportWindow.document.write(buildExecutiveReportHtml("pdf"));
  reportWindow.document.close();
  reportWindow.focus();
  setStatus("PDF composer opened. Use Show full data register before printing if you want the appendix included.");
}






function reportColor(level) {
  return {
    CRITICAL: "#9f1239",
    HIGH: "#c2410c",
    MEDIUM: "#b7791f",
    LOW: "#2f855a",
  }[level] || "#0f766e";
}

function buildReportDonutSvg(distribution, total) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  let offset = 0;
  const rings = distribution
    .map((item) => {
      const length = total ? (item.count / total) * circumference : 0;
      const circle = `<circle cx="80" cy="80" r="${radius}" fill="none" stroke="${reportColor(item.level)}" stroke-width="18" stroke-dasharray="${length} ${circumference - length}" stroke-dashoffset="${-offset}" />`;
      offset += length;
      return circle;
    })
    .join("");
  return `
    <svg class="report-svg" viewBox="0 0 160 160" role="img" aria-label="Risk distribution donut">
      <circle cx="80" cy="80" r="${radius}" fill="none" stroke="#e5e7eb" stroke-width="18" />
      ${rings}
      <circle cx="80" cy="80" r="38" fill="#fff" />
      <text x="80" y="76" text-anchor="middle" class="svg-number">${total}</text>
      <text x="80" y="96" text-anchor="middle" class="svg-label">files</text>
    </svg>
  `;
}

function buildReportRiskBarsSvg(distribution, total) {
  const rows = distribution
    .map((item, index) => {
      const y = 28 + index * 34;
      const width = Math.max(6, total ? (item.count / total) * 250 : 0);
      return `
        <text x="0" y="${y + 9}" class="svg-axis">${escapeSvg(item.label)}</text>
        <rect x="76" y="${y}" width="250" height="14" rx="7" fill="#e5e7eb"></rect>
        <rect x="76" y="${y}" width="${width}" height="14" rx="7" fill="${reportColor(item.level)}"></rect>
        <text x="340" y="${y + 11}" class="svg-value">${item.count}</text>
      `;
    })
    .join("");
  return `<svg class="report-svg wide" viewBox="0 0 390 170" role="img" aria-label="Risk bar chart">${rows}</svg>`;
}

function buildReportSignalSvg(stats) {
  if (!stats.length) {
    return '<p class="muted">No detection signals.</p>';
  }
  const max = Math.max(...stats.map((item) => item.count), 1);
  const rows = stats.slice(0, 7)
    .map((item, index) => {
      const y = 24 + index * 28;
      const label = item.type.length > 22 ? `${item.type.slice(0, 21)}...` : item.type;
      const width = Math.max(8, (item.count / max) * 220);
      return `
        <text x="0" y="${y + 9}" class="svg-axis">${escapeSvg(label)}</text>
        <rect x="142" y="${y}" width="220" height="12" rx="6" fill="#e5e7eb"></rect>
        <rect x="142" y="${y}" width="${width}" height="12" rx="6" fill="#0f766e"></rect>
        <text x="374" y="${y + 10}" class="svg-value">${item.count}</text>
      `;
    })
    .join("");
  return `<svg class="report-svg wide" viewBox="0 0 420 232" role="img" aria-label="Detection signal chart">${rows}</svg>`;
}

function buildReportTrendSvg() {
  const trend = (latestDashboard?.trend || []).slice(-8);
  if (trend.length < 2) {
    return '<p class="muted">Save at least two scans to draw a trend line.</p>';
  }
  const points = trend.map((item, index) => {
    const score = calculatePostureScore(item.summary || {});
    const x = 24 + index * (300 / Math.max(trend.length - 1, 1));
    const y = 138 - score * 1.08;
    return { x, y, score, label: (item.timestamp || "").slice(5, 10) || `scan ${index + 1}` };
  });
  const polyline = points.map((item) => `${item.x},${item.y}`).join(" ");
  const dots = points.map((item) => `<circle cx="${item.x}" cy="${item.y}" r="4" fill="#0f766e"></circle><text x="${item.x}" y="158" text-anchor="middle" class="svg-tick">${escapeSvg(item.label)}</text>`).join("");
  return `
    <svg class="report-svg wide" viewBox="0 0 360 170" role="img" aria-label="Risk trend">
      <line x1="24" y1="138" x2="340" y2="138" stroke="#cbd5e1"></line>
      <line x1="24" y1="30" x2="24" y2="138" stroke="#cbd5e1"></line>
      <polyline points="${polyline}" fill="none" stroke="#0f766e" stroke-width="3"></polyline>
      ${dots}
      <text x="28" y="24" class="svg-label">Posture score</text>
    </svg>
  `;
}

function buildReportFolderHeatmapSvg(folders) {
  if (!folders.length) {
    return '<p class="muted">No folder concentration data.</p>';
  }
  const max = Math.max(...folders.map((item) => item.score), 1);
  return `
    <svg class="report-svg wide" viewBox="0 0 420 190" role="img" aria-label="Top folder heatmap">
      ${folders.slice(0, 8).map((item, index) => {
        const col = index % 4;
        const row = Math.floor(index / 4);
        const x = 8 + col * 102;
        const y = 16 + row * 82;
        const alpha = Math.max(0.16, item.score / max);
        const label = item.folder.length > 15 ? `${item.folder.slice(0, 14)}...` : item.folder;
        return `
          <rect x="${x}" y="${y}" width="94" height="70" rx="8" fill="#0f766e" opacity="${alpha}"></rect>
          <text x="${x + 9}" y="${y + 24}" class="svg-heat-title">${escapeSvg(label)}</text>
          <text x="${x + 9}" y="${y + 44}" class="svg-heat-meta">${item.files} files</text>
          <text x="${x + 9}" y="${y + 60}" class="svg-heat-meta">${item.critical} critical</text>
        `;
      }).join("")}
    </svg>
  `;
}

function buildPolishedReportHtml(mode = "word") {
  const report = buildReportModel();
  const maxSignal = Math.max(...report.findingStats.map((item) => item.count), 1);
  const sourceLabel = escapeHtml(report.title);
  const registerRows = report.priorityFiles
    .map((file) => {
      const risk = getEffectiveRisk(file);
      return `
        <tr>
          <td><strong>${escapeHtml(file.name || "")}</strong><br><span>${escapeHtml(file.path || "")}</span></td>
          <td>${escapeHtml(file.source || "")}</td>
          <td>${file.is_hidden ? "Yes" : "No"}</td>
          <td><span class="risk ${risk.level}">${escapeHtml(risk.level)} ${escapeHtml(risk.score)}</span></td>
          <td>${escapeHtml((file.findings || []).map((finding) => `${finding.type}: ${finding.count}`).join("; ") || "None")}</td>
          <td>${escapeHtml((file.risk?.remediation?.actions || []).slice(0, 3).join("; ") || "Review ownership and access")}</td>
        </tr>
      `;
    })
    .join("");
  const comparisonRows = report.comparison.length
    ? report.comparison.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td>${item.current}</td><td>${item.prior}</td><td class="${item.delta > 0 ? "worse" : item.delta < 0 ? "better" : ""}">${item.delta > 0 ? "+" : ""}${item.delta}</td></tr>`).join("")
    : '<tr><td colspan="4">Run and save at least two scans to populate comparison.</td></tr>';

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>DSPM Assessment Report</title>
        <style>
          @page { size: A4; margin: 14mm; }
          * { box-sizing: border-box; }
          body { margin: 0; background: ${mode === "pdf" ? "#fff" : "#eef2f7"}; color: #17202a; font-family: Arial, Helvetica, sans-serif; line-height: 1.35; }
          .page { max-width: 1120px; margin: ${mode === "pdf" ? "0" : "28px auto"}; background: #fff; border: 1px solid #d8dee8; }
          .cover { padding: 34px; color: #fff; background: #0f766e; }
          .cover-top { display: table; width: 100%; }
          .cover-copy { display: table-cell; vertical-align: top; }
          .logo { display: table-cell; vertical-align: middle; text-align: right; }
          .logo span { display: inline-block; width: 64px; height: 64px; border-radius: 12px; background: #fff; color: #0f766e; line-height: 64px; text-align: center; font-size: 28px; font-weight: 900; }
          h1, h2, h3, p { margin-top: 0; }
          h1 { font-size: 34px; margin-bottom: 8px; }
          h2 { font-size: 19px; margin: 28px 0 12px; }
          h3 { font-size: 14px; margin-bottom: 8px; }
          .muted, td span { color: #667085; }
          .content { padding: 28px; }
          .summary { display: table; width: 100%; margin-bottom: 18px; }
          .score { display: table-cell; width: 170px; vertical-align: middle; }
          .score-ring { width: 138px; height: 138px; border-radius: 999px; background: conic-gradient(#0f766e ${report.score}%, #e5e7eb 0); display: table; }
          .score-ring span { display: table-cell; vertical-align: middle; text-align: center; font-size: 34px; font-weight: 900; color: #0f766e; }
          .summary-text { display: table-cell; vertical-align: middle; }
          .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 10px; margin: 18px 0 24px; }
          .kpi { border: 1px solid #d8dee8; border-radius: 8px; padding: 12px; background: #f8fafc; }
          .kpi span { display: block; color: #667085; font-size: 11px; font-weight: 700; text-transform: uppercase; }
          .kpi strong { display: block; margin-top: 7px; font-size: 25px; }
          .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
          .panel { border: 1px solid #d8dee8; border-radius: 8px; padding: 14px; background: #fff; }
          .bar { margin-bottom: 10px; }
          .bar-label { display: table; width: 100%; font-size: 12px; margin-bottom: 4px; }
          .bar-label span { display: table-cell; }
          .bar-label strong { display: table-cell; text-align: right; }
          .track { display: block; height: 9px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
          .track b { display: block; height: 100%; background: #0f766e; }
          .track b.CRITICAL { background: #9f1239; } .track b.HIGH { background: #c2410c; } .track b.MEDIUM { background: #b7791f; } .track b.LOW { background: #2f855a; }
          .list-card { border: 1px solid #d8dee8; border-radius: 8px; padding: 10px; margin-bottom: 8px; background: #f8fafc; }
          .list-card strong { display: block; word-break: break-word; }
          .list-card span { font-size: 12px; }
          table { width: 100%; border-collapse: collapse; font-size: 11px; margin-top: 8px; }
          th, td { border: 1px solid #d8dee8; padding: 8px; text-align: left; vertical-align: top; }
          th { background: #f1f5f9; color: #334155; }
          .risk { display: inline-block; border-radius: 999px; padding: 4px 8px; color: #fff; font-weight: 700; white-space: nowrap; }
          .CRITICAL { background: #9f1239; } .HIGH { background: #c2410c; } .MEDIUM { background: #b7791f; } .LOW { background: #2f855a; }
          .better { color: #15803d; font-weight: 700; }
          .worse { color: #9f1239; font-weight: 700; }
          @media print { body { background: #fff; } .page { border: 0; margin: 0; } .cover { print-color-adjust: exact; -webkit-print-color-adjust: exact; } }
        </style>
      </head>
      <body>
        <div class="page">
          <section class="cover">
            <div class="cover-top">
              <div class="cover-copy">
                <h1>DSPM Assessment Report</h1>
                <p>${sourceLabel}</p>
                <p>Generated ${escapeHtml(report.generatedAt)} · tenant ${escapeHtml(currentTenant)}</p>
              </div>
              <div class="logo"><span>D</span></div>
            </div>
          </section>
          <main class="content">
            <section class="summary">
              <div class="score"><div class="score-ring"><span>${report.score}</span></div></div>
              <div class="summary-text">
                <h2>Executive summary</h2>
                <p class="muted">${report.summary.critical || report.summary.high ? "Critical or high exposure exists. Prioritize credential rotation, ownership validation, and access reduction." : "No urgent high-risk exposure is present in the current scan."}</p>
              </div>
            </section>
            <section class="kpis">
              <div class="kpi"><span>Critical</span><strong>${report.summary.critical}</strong></div>
              <div class="kpi"><span>High</span><strong>${report.summary.high}</strong></div>
              <div class="kpi"><span>Medium</span><strong>${report.summary.medium}</strong></div>
              <div class="kpi"><span>Low</span><strong>${report.summary.low}</strong></div>
              <div class="kpi"><span>Hidden</span><strong>${latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length}</strong></div>
              <div class="kpi"><span>Total</span><strong>${report.summary.total_files}</strong></div>
            </section>
            <section class="grid">
              <div class="panel">
                <h2>Risk distribution</h2>
                ${report.distribution.map((item) => `<div class="bar"><div class="bar-label"><span>${item.label}</span><strong>${item.count}</strong></div><span class="track"><b class="${item.level}" style="width:${(item.count / Math.max(report.summary.total_files, 1)) * 100}%"></b></span></div>`).join("")}
              </div>
              <div class="panel">
                <h2>Detection signals</h2>
                ${report.findingStats.length ? report.findingStats.map((item) => `<div class="bar"><div class="bar-label"><span>${escapeHtml(item.type)}</span><strong>${item.count}</strong></div><span class="track"><b style="width:${Math.max(8, (item.count / maxSignal) * 100)}%"></b></span></div>`).join("") : '<p class="muted">No detection signals.</p>'}
              </div>
            </section>
            <section class="grid">
              <div class="panel">
                <h2>Department risk</h2>
                ${report.departments.slice(0, 7).map((item) => `<div class="list-card"><strong>${escapeHtml(item.department)}</strong><span>${item.files} files · ${item.critical} critical · ${item.high} high</span></div>`).join("") || '<p class="muted">No department data.</p>'}
              </div>
              <div class="panel">
                <h2>Top risky folders</h2>
                ${report.folders.slice(0, 7).map((item) => `<div class="list-card"><strong>${escapeHtml(item.folder)}</strong><span>${item.files} files · ${item.critical} critical · avg ${Math.round(item.score / Math.max(item.files, 1))}</span></div>`).join("") || '<p class="muted">No folder data.</p>'}
              </div>
            </section>
            <h2>Scan comparison</h2>
            <table><thead><tr><th>Metric</th><th>Latest</th><th>Previous</th><th>Delta</th></tr></thead><tbody>${comparisonRows}</tbody></table>
            <h2>Priority file queue</h2>
            <table>
              <thead><tr><th>File</th><th>Source</th><th>Hidden</th><th>Risk</th><th>Findings</th><th>Recommended action</th></tr></thead>
              <tbody>${registerRows}</tbody>
            </table>
          </main>
        </div>
      </body>
    </html>
  `;
}

function buildExecutiveReportHtml(mode = "word") {
  const report = buildReportModel();
  const hiddenCount = latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length;
  const protectedCount = latestReport?.summary?.protected_files ?? latestFiles.filter(isProtectedFile).length;
  const criticalHighCount = (report.summary.critical || 0) + (report.summary.high || 0);
  const statusText = criticalHighCount ? "Action required" : "Controlled";
  const statusTone = criticalHighCount ? "Critical and high exposure exists. Prioritize owner review, access reduction, and DLP controls." : "No critical/high concentration is visible in the latest assessment.";
  const maxSignal = Math.max(...report.findingStats.map((item) => item.count), 1);
  const fullRows = buildReportRegisterRows(report.priorityFiles, { compact: false });
  const priorityRows = buildReportRegisterRows(report.priorityFiles, { compact: true, limit: 12 });
  const comparisonRows = report.comparison.length
    ? report.comparison.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td>${item.current}</td><td>${item.prior}</td><td class="${item.delta > 0 ? "worse" : item.delta < 0 ? "better" : ""}">${item.delta > 0 ? "+" : ""}${item.delta}</td></tr>`).join("")
    : '<tr><td colspan="4">Run and save at least two scans to populate comparison.</td></tr>';
  const actionCards = report.priorityFiles.slice(0, 4).map((file, index) => {
    const risk = getEffectiveRisk(file);
    return `
      <div class="action-card ${risk.level}">
        <span>${String(index + 1).padStart(2, "0")}</span>
        <strong>${escapeHtml(file.name || file.path || "Unknown file")}</strong>
        <p>${escapeHtml(reportActionsText(file))}</p>
      </div>
    `;
  }).join("") || '<p class="muted">No priority action required from the current scan.</p>';
  const pdfToolbar = mode === "pdf" ? `
    <div class="report-composer-toolbar no-print">
      <div>
        <strong>PDF Composer</strong>
        <span>Default view is executive-only. Click the button to reveal all rows before printing.</span>
      </div>
      <button type="button" onclick="toggleRegister()" id="toggle-register-btn">Show full data register</button>
      <button type="button" class="primary" onclick="window.print()">Print / Save PDF</button>
    </div>
  ` : "";

  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>DSPM Assessment Report</title>
        <style>
          @page { size: A4 landscape; margin: 9mm; }
          * { box-sizing: border-box; }
          body { margin: 0; background: ${mode === "pdf" ? "#f3f7fb" : "#eef2f7"}; color: #17202a; font-family: "Segoe UI", Arial, Helvetica, sans-serif; font-size: 10.8px; line-height: 1.42; }
          .page { width: 100%; max-width: 1180px; margin: ${mode === "pdf" ? "76px auto 24px" : "24px auto"}; background: #fff; border: 1px solid #d8dee8; box-shadow: 0 24px 70px rgba(15, 23, 42, .12); }
          .report-composer-toolbar { position: fixed; z-index: 50; left: 18px; right: 18px; top: 14px; display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 16px; background: rgba(255,255,255,.95); box-shadow: 0 16px 42px rgba(15, 23, 42, .16); backdrop-filter: blur(12px); }
          .report-composer-toolbar div { display: grid; gap: 2px; }
          .report-composer-toolbar strong { font-size: 13px; }
          .report-composer-toolbar span { color: #64748b; }
          .report-composer-toolbar button { border: 1px solid #cbd5e1; border-radius: 999px; background: #fff; color: #0f172a; padding: 9px 13px; font-weight: 800; cursor: pointer; }
          .report-composer-toolbar button.primary { background: #0f766e; border-color: #0f766e; color: #fff; }
          .cover { padding: 24px 28px; color: #fff; background: linear-gradient(135deg, #0f766e, #115e59 48%, #0f172a); }
          .cover-top { display: table; width: 100%; table-layout: fixed; }
          .cover-copy { display: table-cell; vertical-align: top; }
          .logo { display: table-cell; vertical-align: middle; text-align: right; }
          .logo span { display: inline-block; width: 58px; height: 58px; border-radius: 16px; background: #ecfeff; color: #0f766e; line-height: 58px; text-align: center; font-size: 26px; font-weight: 900; box-shadow: inset 0 0 0 1px rgba(15,118,110,.18); }
          h1, h2, h3, p { margin-top: 0; }
          h1 { font-size: 28px; margin-bottom: 6px; letter-spacing: -.03em; }
          h2 { font-size: 15px; margin: 18px 0 8px; color: #0f172a; }
          h3 { font-size: 12px; margin: 0 0 6px; color: #0f172a; }
          .muted, td span { color: #64748b; }
          .cover p { color: #ccfbf1; margin: 4px 0 0; }
          .content { padding: 20px 22px 24px; }
          .meta-strip { display: grid; grid-template-columns: 1.2fr .8fr .8fr; gap: 10px; align-items: stretch; margin-bottom: 12px; }
          .executive-box, .status-box, .metric-box, .panel, .action-card { border: 1px solid #d8dee8; border-radius: 14px; padding: 12px; background: #fff; break-inside: avoid; page-break-inside: avoid; }
          .executive-box { background: #f8fafc; }
          .status-box { background: #ecfdf5; border-color: #99f6e4; color: #134e4a; }
          .status-box.warning { background: #fff7ed; border-color: #fed7aa; color: #9a3412; }
          .status-box strong { display: block; font-size: 30px; margin: 2px 0; letter-spacing: -.05em; }
          .metric-box span, .status-box span, .kpi span { display: block; color: #64748b; font-size: 9px; font-weight: 800; text-transform: uppercase; letter-spacing: .06em; }
          .metric-box strong { display: block; font-size: 22px; margin-top: 6px; }
          .kpis { display: grid; grid-template-columns: repeat(6, 1fr); gap: 8px; margin: 12px 0 14px; }
          .kpi { border: 1px solid #d8dee8; border-radius: 12px; padding: 9px 10px; background: #fff; }
          .kpi strong { display: block; margin-top: 4px; font-size: 22px; }
          .kpi.critical { background: #fff1f2; border-color: #fecdd3; } .kpi.high { background: #fff7ed; border-color: #fed7aa; } .kpi.medium { background: #fefce8; border-color: #fde68a; } .kpi.low { background: #f0fdf4; border-color: #bbf7d0; }
          .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 10px; }
          .tri-grid { display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 10px; margin-bottom: 10px; }
          .panel.visual-panel { min-height: 172px; }
          .report-svg { width: 100%; height: auto; display: block; }
          .report-svg.wide { min-height: 136px; }
          .svg-number { font-size: 25px; font-weight: 900; fill: #17202a; }
          .svg-label, .svg-axis, .svg-value, .svg-tick { font-size: 9px; fill: #64748b; }
          .svg-value { font-weight: 900; fill: #0f172a; }
          .svg-heat-title { font-size: 8px; font-weight: 900; fill: #fff; }
          .svg-heat-meta { font-size: 7px; fill: #ecfeff; }
          .signal-list .bar { margin-bottom: 8px; }
          .bar-label { display: flex; justify-content: space-between; gap: 10px; margin-bottom: 3px; font-size: 10px; }
          .track { display: block; height: 8px; background: #e5e7eb; border-radius: 999px; overflow: hidden; }
          .track b { display: block; height: 100%; background: #0f766e; }
          .action-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 8px; }
          .action-card span { display: inline-grid; place-items: center; width: 24px; height: 24px; border-radius: 50%; background: #f1f5f9; font-weight: 900; color: #334155; margin-bottom: 8px; }
          .action-card strong { display: block; word-break: break-word; }
          .action-card p { margin: 5px 0 0; color: #64748b; font-size: 9.6px; }
          .register-intro { display: flex; align-items: center; justify-content: space-between; gap: 12px; padding: 12px; border-radius: 14px; background: #f8fafc; border: 1px dashed #cbd5e1; margin: 14px 0 8px; }
          .register-intro strong { display: block; }
          .register-intro span { color: #64748b; }
          .register-intro .fake-button { border-radius: 999px; padding: 8px 12px; background: #0f766e; color: #fff; font-weight: 900; white-space: nowrap; }
          table { width: 100%; border-collapse: collapse; font-size: 9.2px; margin-top: 8px; table-layout: fixed; }
          th, td { border: 1px solid #d8dee8; padding: 5px 6px; text-align: left; vertical-align: top; overflow-wrap: anywhere; }
          th { background: #f1f5f9; color: #334155; font-size: 8.5px; text-transform: uppercase; letter-spacing: .04em; }
          .priority-table th:nth-child(1) { width: 30%; } .priority-table th:nth-child(2) { width: 18%; } .priority-table th:nth-child(3) { width: 10%; } .priority-table th:nth-child(4) { width: 20%; } .priority-table th:nth-child(5) { width: 22%; }
          .full-register-table th:nth-child(1) { width: 21%; } .full-register-table th:nth-child(2) { width: 10%; } .full-register-table th:nth-child(3) { width: 9%; } .full-register-table th:nth-child(4) { width: 6%; } .full-register-table th:nth-child(5) { width: 8%; } .full-register-table th:nth-child(6) { width: 8%; } .full-register-table th:nth-child(7) { width: 13%; } .full-register-table th:nth-child(8) { width: 13%; } .full-register-table th:nth-child(9) { width: 12%; }
          .risk { display: inline-block; border-radius: 999px; padding: 3px 7px; color: #fff; font-weight: 900; white-space: nowrap; font-size: 8.6px; }
          .CRITICAL { background: #9f1239; } .HIGH { background: #c2410c; } .MEDIUM { background: #b7791f; } .LOW { background: #15803d; }
          .better { color: #15803d; font-weight: 900; } .worse { color: #9f1239; font-weight: 900; }
          .page-break { break-before: page; page-break-before: always; }
          .full-register-section { display: ${mode === "word" ? "block" : "none"}; }
          body.include-register .full-register-section { display: block; }
          body.include-register #toggle-register-btn::before { content: "Hide"; }
          body.include-register #toggle-register-btn { font-size: 0; }
          body.include-register #toggle-register-btn::before { font-size: 13px; }
          @media print { body { background: #fff; } .no-print { display: none !important; } .page { border: 0; box-shadow: none; margin: 0; max-width: none; } body:not(.include-register) .full-register-section { display: none !important; } .cover, .status-box, .kpi, .panel, .metric-box, .action-card, .register-intro { print-color-adjust: exact; -webkit-print-color-adjust: exact; } }
        </style>
        <script>
          function toggleRegister() {
            document.body.classList.toggle("include-register");
          }
        </script>
      </head>
      <body class="${mode === "word" ? "include-register" : ""}">
        ${pdfToolbar}
        <div class="page">
          <section class="cover">
            <div class="cover-top">
              <div class="cover-copy">
                <h1>DSPM Assessment Report</h1>
                <p>${escapeHtml(report.title)}</p>
                <p>Generated ${escapeHtml(report.generatedAt)} &middot; tenant ${escapeHtml(currentTenant)} &middot; ${report.summary.total_files} files analyzed</p>
              </div>
              <div class="logo"><span>D</span></div>
            </div>
          </section>
          <main class="content">
            <section class="meta-strip">
              <div class="executive-box">
                <h2>Executive summary</h2>
                <p class="muted">${escapeHtml(statusTone)} This pack is structured for customer, audit, and remediation review: first the decision summary, then the evidence appendix only when requested.</p>
              </div>
              <div class="status-box ${criticalHighCount ? "warning" : ""}">
                <span>Risk posture</span>
                <strong>${report.score}</strong>
                <span>${escapeHtml(statusText)}</span>
              </div>
              <div class="metric-box">
                <span>Priority exposure</span>
                <strong>${criticalHighCount}</strong>
                <p class="muted">Critical + high files requiring owner validation.</p>
              </div>
            </section>

            <section class="kpis">
              <div class="kpi critical"><span>Critical</span><strong>${report.summary.critical}</strong></div>
              <div class="kpi high"><span>High</span><strong>${report.summary.high}</strong></div>
              <div class="kpi medium"><span>Medium</span><strong>${report.summary.medium}</strong></div>
              <div class="kpi low"><span>Low</span><strong>${report.summary.low}</strong></div>
              <div class="kpi"><span>Hidden</span><strong>${hiddenCount}</strong></div>
              <div class="kpi"><span>Protected</span><strong>${protectedCount}</strong></div>
            </section>

            <section class="grid">
              <div class="panel visual-panel">
                <h2>Risk distribution</h2>
                ${buildReportDonutSvg(report.distribution, report.summary.total_files)}
              </div>
              <div class="panel visual-panel">
                <h2>Risk bars</h2>
                ${buildReportRiskBarsSvg(report.distribution, report.summary.total_files)}
              </div>
            </section>

            <section class="grid">
              <div class="panel visual-panel signal-list">
                <h2>Detection signals</h2>
                ${report.findingStats.length ? report.findingStats.slice(0, 8).map((item) => `<div class="bar"><div class="bar-label"><span>${escapeHtml(item.type)}</span><strong>${item.count}</strong></div><span class="track"><b style="width:${Math.max(8, (item.count / maxSignal) * 100)}%"></b></span></div>`).join("") : '<p class="muted">No detection signals.</p>'}
              </div>
              <div class="panel visual-panel">
                <h2>Posture trend</h2>
                ${buildReportTrendSvg()}
              </div>
            </section>

            <section class="grid">
              <div class="panel">
                <h2>Department risk</h2>
                ${report.departments.slice(0, 7).map((item) => `<div class="bar"><div class="bar-label"><span>${escapeHtml(item.department)}</span><strong>${item.files}</strong></div><span class="track"><b style="width:${Math.min(100, (item.score / Math.max(...report.departments.map((dep) => dep.score), 1)) * 100)}%"></b></span></div>`).join("") || '<p class="muted">No department data.</p>'}
              </div>
              <div class="panel visual-panel">
                <h2>Top risky folders</h2>
                ${buildReportFolderHeatmapSvg(report.folders)}
              </div>
            </section>

            <section class="panel">
              <h2>Recommended remediation plan</h2>
              <div class="action-grid">${actionCards}</div>
            </section>

            <section class="grid">
              <div class="panel">
                <h2>Scan comparison</h2>
                <table><thead><tr><th>Metric</th><th>Latest</th><th>Previous</th><th>Delta</th></tr></thead><tbody>${comparisonRows}</tbody></table>
              </div>
              <div class="panel">
                <h2>Priority file queue</h2>
                <table class="priority-table">
                  <thead><tr><th>File</th><th>Source</th><th>Risk</th><th>Findings</th><th>Action</th></tr></thead>
                  <tbody>${priorityRows || '<tr><td colspan="5">No priority files.</td></tr>'}</tbody>
                </table>
              </div>
            </section>

            <section class="register-intro ${mode === "pdf" ? "no-print" : ""}">
              <div>
                <strong>Full evidence register is separated from the executive story.</strong>
                <span>${mode === "pdf" ? "Click “Show full data register” in the composer before printing if the PDF must include every row." : "Word export includes the full appendix below, so auditors can review every row without changing the executive summary layout."}</span>
              </div>
              <div class="fake-button">${mode === "pdf" ? "Show data from toolbar" : `${report.priorityFiles.length} rows included`}</div>
            </section>

            <section class="full-register-section page-break">
              <h2>Appendix A — Full evidence register</h2>
              <p class="muted">All scanned files sorted by effective risk score. This replaces the old “additional files” placeholder and keeps every row available when requested.</p>
              <table class="full-register-table">
                <thead><tr><th>File</th><th>Source</th><th>Owner</th><th>Hidden</th><th>Protected</th><th>Risk</th><th>Findings</th><th>Reasons</th><th>DLP / action</th></tr></thead>
                <tbody>${fullRows || '<tr><td colspan="9">No file evidence rows available.</td></tr>'}</tbody>
              </table>
            </section>
          </main>
        </div>
      </body>
    </html>
  `;
}


function buildReportHtml(mode = "word") {
  const summary = buildCurrentSummary();
  const distribution = buildRiskDistribution(summary);
  const findingStats = buildFindingStats();
  const score = getCurrentPostureScore(summary);
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

function buildPolishedExcelWorkbookHtml() {
  const report = buildReportModel();
  const hiddenCount = latestReport?.summary?.hidden_files || latestFiles.filter((file) => file.is_hidden).length;
  const protectedCount = latestReport?.summary?.protected_files ?? latestFiles.filter(isProtectedFile).length;
  const criticalHighCount = (report.summary.critical || 0) + (report.summary.high || 0);
  const riskRows = report.priorityFiles
    .map((file, index) => {
      const risk = getEffectiveRisk(file);
      return `
        <tr>
          <td>${index + 1}</td>
          <td>${escapeHtml(file.name || file.filename || file.path || "")}</td>
          <td>${escapeHtml(reportPathText(file))}</td>
          <td>${escapeHtml(reportSourceText(file))}</td>
          <td>${escapeHtml(file.share || "")}</td>
          <td>${escapeHtml(reportOwnerText(file))}</td>
          <td>${file.is_hidden ? "Yes" : "No"}</td>
          <td>${isProtectedFile(file) ? escapeHtml(getProtectionLabel(file)) : "No"}</td>
          <td class="${risk.level}">${escapeHtml(risk.level)}</td>
          <td>${escapeHtml(risk.score)}</td>
          <td>${escapeHtml(reportFindingsText(file))}</td>
          <td>${escapeHtml(reportReasonsText(file))}</td>
          <td>${escapeHtml(reportDlpText(file))}</td>
          <td>${escapeHtml(reportActionsText(file))}</td>
        </tr>
      `;
    })
    .join("");
  const departmentRows = report.departments
    .map((item) => `<tr><td>${escapeHtml(item.department)}</td><td>${item.files}</td><td>${item.critical}</td><td>${item.high}</td><td>${item.score}</td><td>${Math.round(item.score / Math.max(item.files, 1))}</td></tr>`)
    .join("");
  const folderRows = report.folders
    .map((item) => `<tr><td>${escapeHtml(item.folder)}</td><td>${item.files}</td><td>${item.critical}</td><td>${item.score}</td><td>${Math.round(item.score / Math.max(item.files, 1))}</td></tr>`)
    .join("");
  const signalRows = report.findingStats
    .map((item) => `<tr><td>${escapeHtml(item.type)}</td><td>${item.count}</td><td>${Math.round((item.count / Math.max(report.summary.total_files, 1)) * 100)}%</td></tr>`)
    .join("");
  const comparisonRows = report.comparison.length
    ? report.comparison.map((item) => `<tr><td>${escapeHtml(item.label)}</td><td>${item.current}</td><td>${item.prior}</td><td class="${item.delta > 0 ? "worse" : item.delta < 0 ? "better" : ""}">${item.delta}</td></tr>`).join("")
    : '<tr><td colspan="4">No previous saved scan</td></tr>';
  const remediationRows = report.priorityFiles.slice(0, 50)
    .map((file, index) => {
      const risk = getEffectiveRisk(file);
      const sla = risk.level === "CRITICAL" ? "24 hours" : risk.level === "HIGH" ? "3 days" : risk.level === "MEDIUM" ? "14 days" : "30 days";
      return `<tr><td>${index + 1}</td><td>${escapeHtml(file.name || file.path || "")}</td><td class="${risk.level}">${risk.level}</td><td>${risk.score}</td><td>${escapeHtml(reportOwnerText(file))}</td><td>${sla}</td><td>${escapeHtml(reportActionsText(file))}</td></tr>`;
    })
    .join("");

  return `
    <html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
      <head>
        <meta charset="utf-8" />
        <!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets>
          <x:ExcelWorksheet><x:Name>Executive Summary</x:Name><x:WorksheetOptions><x:DisplayGridlines/><x:FreezePanes/><x:FrozenNoSplit/><x:SplitHorizontal>1</x:SplitHorizontal><x:TopRowBottomPane>1</x:TopRowBottomPane></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Risk Register</x:Name><x:WorksheetOptions><x:DisplayGridlines/><x:FreezePanes/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Remediation Plan</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Departments</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Folders</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Signals</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Comparison</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
        </x:ExcelWorksheets></x:ExcelWorkbook></xml><![endif]-->
        <style>
          body { font-family: "Segoe UI", Arial, sans-serif; color: #17202a; }
          h1 { color: #0f766e; font-size: 24px; margin-bottom: 6px; }
          h2 { color: #0f172a; font-size: 18px; margin-top: 24px; border-bottom: 2px solid #0f766e; padding-bottom: 6px; }
          .muted { color: #64748b; }
          table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
          th { background: #0f766e; color: #fff; font-weight: bold; text-align: left; }
          th, td { border: 1px solid #cbd5e1; padding: 8px; vertical-align: top; mso-number-format:"\\@"; }
          .meta th { background: #f1f5f9; color: #334155; width: 18%; }
          .score-card td { border: 0; padding: 12px; }
          .score { background: #0f766e; color: #fff; font-size: 30px; font-weight: bold; text-align: center; }
          .summary-copy { background: #f8fafc; color: #334155; }
          .kpi th { background: #1f2937; color: #fff; }
          .kpi td { font-size: 18px; font-weight: bold; text-align: center; }
          .CRITICAL { background: #ffe4e6; color: #9f1239; font-weight: bold; }
          .HIGH { background: #ffedd5; color: #c2410c; font-weight: bold; }
          .MEDIUM { background: #fef9c3; color: #a16207; font-weight: bold; }
          .LOW { background: #dcfce7; color: #15803d; font-weight: bold; }
          .better { background: #dcfce7; color: #15803d; font-weight: bold; }
          .worse { background: #ffe4e6; color: #9f1239; font-weight: bold; }
          .section-break { page-break-before: always; }
        </style>
      </head>
      <body>
        <h1>DSPM Assessment Workbook</h1>
        <p class="muted">Executive summary, full risk register, remediation plan, department/folder concentration, detection signals, and scan comparison.</p>
        <table class="meta">
          <tr><th>Generated</th><td>${escapeHtml(report.generatedAt)}</td><th>Tenant</th><td>${escapeHtml(currentTenant)}</td></tr>
          <tr><th>Source</th><td>${escapeHtml(report.title)}</td><th>Posture score</th><td>${report.score}</td></tr>
          <tr><th>Total files</th><td>${report.summary.total_files}</td><th>Priority exposure</th><td>${criticalHighCount}</td></tr>
        </table>
        <table class="score-card">
          <tr><td class="score">${report.score}</td><td class="summary-copy">${criticalHighCount ? "Critical or high exposure exists. Prioritize owners, broad-access reduction, credential rotation, and DLP controls." : "Current exposure profile is controlled. Continue periodic scans and retention cleanup."}</td></tr>
        </table>
        <table class="kpi">
          <tr><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Hidden</th><th>Protected</th><th>Total files</th></tr>
          <tr><td class="CRITICAL">${report.summary.critical}</td><td class="HIGH">${report.summary.high}</td><td class="MEDIUM">${report.summary.medium}</td><td class="LOW">${report.summary.low}</td><td>${hiddenCount}</td><td>${protectedCount}</td><td>${report.summary.total_files}</td></tr>
        </table>

        <h2>Risk Distribution</h2>
        <table><tr><th>Level</th><th>Files</th><th>Percent of scan</th></tr>${report.distribution.map((item) => `<tr><td class="${item.level}">${item.label}</td><td>${item.count}</td><td>${Math.round((item.count / Math.max(report.summary.total_files, 1)) * 100)}%</td></tr>`).join("")}</table>

        <h2 class="section-break">Risk Register — All Files</h2>
        <table>
          <tr><th>#</th><th>File</th><th>Path</th><th>Source</th><th>Share</th><th>Owner</th><th>Hidden</th><th>Protected</th><th>Risk</th><th>Score</th><th>Findings</th><th>Reasons</th><th>DLP Recommendation</th><th>Remediation Action</th></tr>
          ${riskRows || '<tr><td colspan="14">No risk rows available</td></tr>'}
        </table>

        <h2 class="section-break">Remediation Plan</h2>
        <table><tr><th>#</th><th>File</th><th>Risk</th><th>Score</th><th>Owner</th><th>SLA</th><th>Action</th></tr>${remediationRows || '<tr><td colspan="7">No remediation actions required</td></tr>'}</table>

        <h2 class="section-break">Departments</h2>
        <table><tr><th>Department</th><th>Files</th><th>Critical</th><th>High</th><th>Total risk score</th><th>Average risk</th></tr>${departmentRows || '<tr><td colspan="6">No department data</td></tr>'}</table>

        <h2>Folders</h2>
        <table><tr><th>Folder</th><th>Files</th><th>Critical</th><th>Total risk score</th><th>Average risk</th></tr>${folderRows || '<tr><td colspan="5">No folder data</td></tr>'}</table>

        <h2>Detection Signals</h2>
        <table><tr><th>Signal</th><th>Count</th><th>Percent of files</th></tr>${signalRows || '<tr><td colspan="3">No sensitive detection signals</td></tr>'}</table>

        <h2>Scan Comparison</h2>
        <table><tr><th>Metric</th><th>Latest</th><th>Previous</th><th>Delta</th></tr>${comparisonRows}</table>
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
          <tr><td class="CRITICAL">${summary.critical}</td><td class="HIGH">${summary.high}</td><td class="MEDIUM">${summary.medium}</td><td class="LOW">${summary.low}</td><td>${summary.total_files}</td><td>${getCurrentPostureScore(summary)}</td></tr>
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
  setScanProgress(true, job.progress || 5, "Scan queued...");
  return pollScan(job.id);
}

async function runQueuedEndpointScan(payload) {
  const job = await api("/api/endpoint/scan", { ...payload, async_scan: true, save_report: true });
  activeEndpointJobId = job.id;
  if (endpointCancelBtn) {
    endpointCancelBtn.classList.remove("hidden");
    endpointCancelBtn.disabled = false;
  }
  endpointStatus.textContent = `Endpoint scan queued: ${job.id}`;
  setEndpointScanProgress(true, job.progress || 5, "Endpoint scan queued...");
  try {
    return await pollScan(job.id, (polledJob) => {
      endpointStatus.textContent = `${polledJob.message} (${polledJob.progress || 0}%)`;
      setEndpointScanProgress(true, polledJob.progress || 0, polledJob.message || "Scanning endpoint...");
    });
  } finally {
    activeEndpointJobId = "";
    if (endpointCancelBtn) {
      endpointCancelBtn.classList.add("hidden");
      endpointCancelBtn.disabled = true;
    }
  }
}

async function generateDemoData() {
  requireAuth();
  const output = document.querySelector("#local_path").value.trim() || "enterprise_test_data";
  demoDataTitle.textContent = "Generating...";
  demoDataStatus.textContent = "Rebuilding local demo dataset.";
  setStatus("Generating enterprise demo data...");
  const result = await api("/api/demo-data/generate", { output, files_per_share: 10 });
  document.querySelector("#local_path").value = result.local_path || output;
  demoDataTitle.textContent = result.local_path || "enterprise_test_data";
  demoDataStatus.textContent = `${result.file_count || 0} sample files ready for scan.`;
  setStatus(`Demo data generated: ${result.file_count || 0} files at ${result.local_path}.`);
  showToast("Demo data ready", `${result.file_count || 0} files generated`, "success");
  await loadAudit().catch(() => {});
}

async function pollScan(jobId, onProgress = null) {
  while (true) {
    const job = await api(`/api/scans/${jobId}`, null, "GET");
    if (onProgress) {
      onProgress(job);
    } else {
      setStatus(`${job.message} (${job.progress || 0}%)`);
      setScanProgress(true, job.progress || 0, job.message || "Scanning...");
    }
    if (job.status === "completed") {
      if (onProgress) {
        onProgress({ ...job, progress: 100, message: "Completed" });
      } else {
        setScanProgress(true, 100, "Scan completed");
      }
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
  await restoreLatestSavedReport(history.history || []);
  renderExecutiveExperience();
  loadTenants().catch(() => {});
}

async function restoreLatestSavedReport(historyItems = latestHistoryItems) {
  if (latestFiles.length || !Array.isArray(historyItems) || !historyItems.length) {
    return;
  }
  const latest = historyItems[historyItems.length - 1];
  const scanId = latest?.scan_id;
  if (!scanId) {
    return;
  }
  try {
    const data = await api(`/api/history/${encodeURIComponent(scanId)}/report`, null, "GET");
    const report = data.report || {};
    if (!Array.isArray(report.files) || !report.files.length) {
      return;
    }
    const scanKind = report.endpoint ? "endpoint" : "file-server";
    applyScanReport(report, scanKind);
    scanMeta.textContent = `Restored ${report.files.length} files from saved scan ${scanId}.`;
  } catch (error) {
    setStatus(`Saved scan restore failed: ${error.message}`);
  }
}

async function loadTenants() {
  if (!accessToken || currentRole !== "admin") {
    tenantSwitcher.classList.add("hidden");
    tenantPortfolio = [{ tenant_id: currentTenant, scan_count: latestDashboard?.trend?.length || 0, latest: latestDashboard?.latest || { summary: {} } }];
    renderTenantOptions();
    renderTenantsTable([]);
    renderExecutiveExperience();
    return;
  }

  const data = await api("/api/tenants", null, "GET");
  tenantPortfolio = data.tenants || [];
  renderTenantOptions();
  renderTenantsTable(tenantPortfolio);
  const tenantIds = new Set([currentTenant, ...tenantPortfolio.map((item) => item.tenant_id)]);
  tenantSwitcher.innerHTML = [...tenantIds]
    .map((tenantId) => `<option value="${escapeHtml(tenantId)}">${escapeHtml(tenantId)}</option>`)
    .join("");
  tenantSwitcher.value = currentTenant;
  tenantSwitcher.classList.remove("hidden");
  tenantManagementStatus.textContent = "Tenants loaded from SQLite.";
  renderExecutiveExperience();
}

function renderTenantOptions() {
  const tenants = tenantPortfolio.length ? tenantPortfolio : [{ tenant_id: currentTenant || "default", display_name: currentTenant || "default" }];
  newUserTenant.innerHTML = tenants
    .map((tenant) => `<option value="${escapeHtml(tenant.tenant_id)}">${escapeHtml(tenant.display_name || tenant.tenant_id)}</option>`)
    .join("");
  if (tenants.some((tenant) => tenant.tenant_id === currentTenant)) {
    newUserTenant.value = currentTenant;
  }
}

function renderTenantsTable(tenants) {
  if (!accessToken || currentRole !== "admin") {
    tenantsBody.innerHTML = '<tr><td colspan="6" class="empty">Admin role is required to manage tenants.</td></tr>';
    tenantManagementStatus.textContent = "Admin role is required.";
    return;
  }
  if (!tenants.length) {
    tenantsBody.innerHTML = '<tr><td colspan="6" class="empty">No tenants found.</td></tr>';
    return;
  }
  tenantsBody.innerHTML = tenants
    .map((tenant) => {
      const retention = tenant.retention || {};
      const disabled = tenant.tenant_id === "default" ? "disabled" : "";
      const registrationCode = tenant.registration_code || "";
      return `
        <tr>
          <td>
            <strong>${escapeHtml(tenant.display_name || tenant.tenant_id)}</strong>
            <div class="subtext">${escapeHtml(tenant.tenant_id)}</div>
          </td>
          <td>
            <div class="inline-control tenant-code-control">
              <input class="table-input tenant-code-input" value="${escapeHtml(registrationCode || "Refresh tenants")}" readonly />
              <button type="button" class="secondary-btn" data-copy-code="${escapeHtml(registrationCode)}" ${registrationCode ? "" : "disabled"}>Copy</button>
              <button type="button" class="secondary-btn" data-regenerate-code="${escapeHtml(tenant.tenant_id)}">Generate</button>
            </div>
          </td>
          <td>${escapeHtml(retention.report_count || 0)}</td>
          <td>${escapeHtml(retention.audit_events || 0)}</td>
          <td>${escapeHtml(retention.alert_events || 0)}</td>
          <td><button type="button" class="secondary-btn" data-delete-tenant="${escapeHtml(tenant.tenant_id)}" ${disabled}>Remove</button></td>
        </tr>
      `;
    })
    .join("");
}

function renderHistory(items) {
  latestHistoryItems = items || [];
  const visibleItems = filterHistoryItems(latestHistoryItems);
  updateRangeStatus(historyRange, visibleItems.length, latestHistoryItems.length);
  renderExecutiveDashboard(latestDashboard, visibleItems);
  if (!latestHistoryItems.length) {
    historyBody.innerHTML = '<tr><td colspan="6" class="empty">No scans saved for this tenant yet.</td></tr>';
    return;
  }
  if (!visibleItems.length) {
    historyBody.innerHTML = '<tr><td colspan="6" class="empty">No scans match the selected date range.</td></tr>';
    return;
  }
  historyBody.innerHTML = visibleItems
    .slice()
    .reverse()
    .map((item) => {
      const summary = item.summary || {};
      const timestamp = getItemTimestampValue(item);
      return `
        <tr>
          <td><span class="timestamp-cell">${escapeHtml(getFriendlyTimestamp(timestamp))}</span><small>${escapeHtml(timestamp)}</small></td>
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

function parseHistoryTime(item) {
  const value = getItemTimestampValue(item);
  if (typeof value === "number") return value;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
}

function getItemTimestampValue(item) {
  if (!item) return "";
  return item.timestamp
    || item.created_at
    || item.createdAt
    || item.time
    || item.date
    || item.event_time
    || item.scan_time
    || item.detail?.timestamp
    || item.detail?.created_at
    || "";
}

function filterHistoryItems(items) {
  return filterTimedItems(items, historyRange, historyFrom, historyTo);
}

function updateHistoryFilterControls() {
  const custom = historyRange?.value === "custom";
  historyFrom?.classList.toggle("hidden", !custom);
  historyTo?.classList.toggle("hidden", !custom);
}

function renderExecutiveDashboard(data = {}, visibleHistoryItems = filterHistoryItems(latestHistoryItems)) {
  data = data || {};
  const filteredItems = Array.isArray(visibleHistoryItems) ? visibleHistoryItems : [];
  const latestVisible = filteredItems.at(-1);
  const latest = latestVisible?.summary || data.latest?.summary || {};
  const reports = filteredItems.length || (latestHistoryItems.length ? 0 : data.retention?.report_count || 0);
  const score = latest.total_files ? calculatePostureScore(latest) : filteredItems.length ? 100 : data.risk_posture_score ?? 100;
  executiveSummary.innerHTML = `
    <div class="history-card"><span>Posture score</span><strong>${escapeHtml(score)}</strong></div>
    <div class="history-card"><span>Tenant</span><strong>${escapeHtml(data.tenant_id || currentTenant)}</strong></div>
    <div class="history-card"><span>Reports</span><strong>${escapeHtml(reports)}</strong></div>
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
  latestAuditEvents = events || [];
  const visibleEvents = filterTimedItems(latestAuditEvents, auditRange, auditFrom, auditTo);
  updateRangeStatus(auditRange, visibleEvents.length, latestAuditEvents.length);
  if (!latestAuditEvents.length) {
    auditBody.innerHTML = '<tr><td colspan="4" class="empty">No audit events for this tenant yet.</td></tr>';
    return;
  }
  if (!visibleEvents.length) {
    auditBody.innerHTML = '<tr><td colspan="4" class="empty">No audit events match the selected date range.</td></tr>';
    return;
  }
  auditBody.innerHTML = visibleEvents
    .slice()
    .reverse()
    .map(
      (event) => `
        <tr>
          <td><span class="timestamp-cell">${escapeHtml(getFriendlyTimestamp(getItemTimestampValue(event)))}</span><small>${escapeHtml(getItemTimestampValue(event))}</small></td>
          <td>${escapeHtml(event.actor || "")}</td>
          <td class="file-path">${escapeHtml(event.action || "")}</td>
          <td><code>${escapeHtml(JSON.stringify(event.detail || {}))}</code></td>
        </tr>
      `
    )
    .join("");
}

function filterTimedItems(items, rangeSelect, fromInput, toInput) {
  const range = rangeSelect?.value || "all";
  if (range === "all") return items;
  const now = Date.now();
  if (range !== "custom") {
    const days = Number(range);
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    const cutoff = days === 1 ? now - 24 * 60 * 60 * 1000 : today.getTime() - (days - 1) * 24 * 60 * 60 * 1000;
    return items.filter((item) => {
      const time = parseHistoryTime(item);
      return time !== null && time >= cutoff;
    });
  }
  const fromTime = fromInput?.value ? new Date(`${fromInput.value}T00:00:00`).getTime() : null;
  const toTime = toInput?.value ? new Date(`${toInput.value}T23:59:59`).getTime() : null;
  return items.filter((item) => {
    const time = parseHistoryTime(item);
    if (time === null) return false;
    if (fromTime !== null && time < fromTime) return false;
    if (toTime !== null && time > toTime) return false;
    return true;
  });
}

function updateRangeStatus(rangeSelect, visible, total) {
  if (!rangeSelect) return;
  const controls = rangeSelect.closest(".history-controls");
  if (!controls) return;
  let status = controls.querySelector(".range-filter-status");
  if (!status) {
    status = document.createElement("span");
    status.className = "range-filter-status";
    controls.appendChild(status);
  }
  const selected = rangeSelect.options[rangeSelect.selectedIndex]?.textContent || "Selected range";
  status.textContent = `${selected}: ${visible} of ${total}`;
  rangeSelect.title = `${selected}: showing ${visible} of ${total}`;
}

function updateAuditFilterControls() {
  const custom = auditRange?.value === "custom";
  auditFrom?.classList.toggle("hidden", !custom);
  auditTo?.classList.toggle("hidden", !custom);
}

async function loadUsers() {
  if (!accessToken || currentRole !== "admin") {
    usersBody.innerHTML = '<tr><td colspan="6" class="empty">Admin role is required to manage users.</td></tr>';
    userManagementStatus.textContent = "Admin role is required.";
    return;
  }
  const data = await api("/api/users", null, "GET");
  renderUsers(data.users || []);
  userManagementStatus.textContent = "Users loaded from SQLite.";
}

function renderUsers(users) {
  if (!users.length) {
    usersBody.innerHTML = '<tr><td colspan="6" class="empty">No users found.</td></tr>';
    return;
  }
  usersBody.innerHTML = users
    .map(
      (user) => `
        <tr data-user-row="${escapeHtml(user.username)}">
          <td>
            <strong>${escapeHtml(user.username)}</strong>
            <div class="subtext">${escapeHtml(user.full_name || "No full name")}</div>
          </td>
          <td><input class="table-input" data-user-tenant="${escapeHtml(user.username)}" value="${escapeHtml(user.tenant_id || "default")}" /></td>
          <td>
            <select class="table-input" data-user-role="${escapeHtml(user.username)}">
              ${["viewer", "analyst", "admin"]
                .map((role) => `<option value="${role}" ${user.role === role ? "selected" : ""}>${role}</option>`)
                .join("")}
            </select>
          </td>
          <td>${escapeHtml(user.last_login_at || "Never")}</td>
          <td>
            <div class="inline-control">
              <input class="table-input" data-user-password="${escapeHtml(user.username)}" type="password" placeholder="New password" />
              <button type="button" class="secondary-btn" data-reset-user="${escapeHtml(user.username)}">Reset</button>
            </div>
          </td>
          <td><button type="button" class="danger-btn" data-delete-user="${escapeHtml(user.username)}">Delete</button></td>
        </tr>
      `
    )
    .join("");
}

async function createUser() {
  requireAuth();
  const payload = {
    username: newUserUsername.value.trim(),
    password: newUserPassword.value,
    full_name: newUserFullName.value.trim(),
    tenant_id: newUserTenant.value.trim() || "default",
    role: newUserRole.value || "viewer",
  };
  if (!payload.username || !payload.password) {
    throw new Error("Username and password are required.");
  }
  userManagementStatus.textContent = "Creating user...";
  await api("/api/users", payload);
  newUserUsername.value = "";
  newUserPassword.value = "";
  newUserFullName.value = "";
  userManagementStatus.textContent = `Created ${payload.username}.`;
  await Promise.all([loadUsers(), loadAudit(), loadTenants().catch(() => {})]);
}

async function updateUserRole(username, role, tenantId) {
  userManagementStatus.textContent = `Updating ${username}...`;
  await api(`/api/users/${encodeURIComponent(username)}/role`, { role, tenant_id: tenantId || "default" }, "PUT");
  userManagementStatus.textContent = `Updated ${username}.`;
  await Promise.all([loadUsers(), loadAudit(), loadTenants().catch(() => {})]);
}

async function resetUserPassword(username, password) {
  if (!password) {
    throw new Error("Enter a new password first.");
  }
  userManagementStatus.textContent = `Resetting password for ${username}...`;
  await api(`/api/users/${encodeURIComponent(username)}/reset-password`, { password });
  userManagementStatus.textContent = `Password reset for ${username}.`;
  await Promise.all([loadUsers(), loadAudit()]);
}

async function deleteUser(username) {
  requireAuth();
  userManagementStatus.textContent = `Deleting ${username}...`;
  await api(`/api/users/${encodeURIComponent(username)}/delete`, {});
  userManagementStatus.textContent = `Deleted ${username}.`;
  await Promise.all([loadUsers(), loadAudit(), loadTenants().catch(() => {})]);
}

async function createTenant() {
  requireAuth();
  const payload = {
    tenant_id: newTenantId.value.trim(),
    display_name: newTenantName.value.trim(),
  };
  if (!payload.tenant_id) {
    throw new Error("Tenant id is required.");
  }
  tenantManagementStatus.textContent = "Creating tenant...";
  await api("/api/tenants", payload);
  newTenantId.value = "";
  newTenantName.value = "";
  tenantManagementStatus.textContent = `Created ${payload.tenant_id}. Registration code generated.`;
  await Promise.all([loadTenants(), loadAudit()]);
}

async function deleteTenant(tenantId) {
  requireAuth();
  tenantManagementStatus.textContent = `Removing ${tenantId}...`;
  await api(`/api/tenants/${encodeURIComponent(tenantId)}`, null, "DELETE");
  if (currentTenant === tenantId) {
    currentTenant = "default";
    safeSessionSet("dspm-tenant-id", currentTenant);
    renderProfile();
  }
  tenantManagementStatus.textContent = `Removed ${tenantId}.`;
  await Promise.all([loadTenants(), loadAudit()]);
}

async function regenerateTenantCode(tenantId) {
  requireAuth();
  tenantManagementStatus.textContent = `Generating code for ${tenantId}...`;
  const result = await api(`/api/tenants/${encodeURIComponent(tenantId)}/regenerate-registration-code`, {});
  tenantManagementStatus.textContent = `Registration code generated for ${tenantId}.`;
  await loadTenants();
  return result.registration_code;
}

async function copyText(value) {
  if (!value) {
    throw new Error("No registration code to copy.");
  }
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const input = document.createElement("textarea");
  input.value = value;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  document.body.appendChild(input);
  input.select();
  document.execCommand("copy");
  input.remove();
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

document.querySelectorAll("[data-extension-preset]").forEach((button) => {
  button.addEventListener("click", () => applyExtensionPreset(button.dataset.extensionPreset, allowedExtensionsList, extensionSearch));
});
document.querySelectorAll("[data-endpoint-extension-preset]").forEach((button) => {
  button.addEventListener("click", () => applyExtensionPreset(button.dataset.endpointExtensionPreset, endpointAllowedExtensionsList, endpointExtensionSearch));
});
addCustomExtensionBtn?.addEventListener("click", () => addCustomExtensionFromInput(customExtensionInput, allowedExtensionsList, extensionSearch));
customExtensionInput?.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  addCustomExtensionFromInput(customExtensionInput, allowedExtensionsList, extensionSearch);
});
endpointAddCustomExtensionBtn?.addEventListener("click", () => addCustomExtensionFromInput(endpointCustomExtensionInput, endpointAllowedExtensionsList, endpointExtensionSearch));
endpointCustomExtensionInput?.addEventListener("keydown", (event) => {
  if (event.key !== "Enter") return;
  event.preventDefault();
  addCustomExtensionFromInput(endpointCustomExtensionInput, endpointAllowedExtensionsList, endpointExtensionSearch);
});
extensionSearch?.addEventListener("input", () => filterExtensionList(allowedExtensionsList, extensionSearch));
endpointExtensionSearch?.addEventListener("input", () => {
  filterExtensionList(endpointAllowedExtensionsList, endpointExtensionSearch);
  tuneEndpointScanDefaults();
});
allowedExtensionsList?.addEventListener("change", (event) => {
  if (!event.target.matches("input[type='checkbox']")) return;
  reorderExtensionOptions(allowedExtensionsList);
  filterExtensionList(allowedExtensionsList, extensionSearch);
});
endpointAllowedExtensionsList?.addEventListener("change", (event) => {
  if (!event.target.matches("input[type='checkbox']")) return;
  reorderExtensionOptions(endpointAllowedExtensionsList);
  filterExtensionList(endpointAllowedExtensionsList, endpointExtensionSearch);
  tuneEndpointScanDefaults();
});
document.querySelectorAll("[data-extension-selected-for]").forEach((host) => {
  host.addEventListener("click", (event) => {
    const chip = event.target.closest("[data-remove-extension]");
    if (!chip) return;
    const isEndpoint = host.dataset.extensionSelectedFor === "endpoint";
    removeSelectedExtension(isEndpoint ? endpointAllowedExtensionsList : allowedExtensionsList, chip.dataset.removeExtension);
    if (isEndpoint) tuneEndpointScanDefaults();
  });
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

generateDemoDataBtn.addEventListener("click", async () => {
  setBusy(true);
  try {
    await generateDemoData();
  } catch (error) {
    demoDataTitle.textContent = "Generation failed";
    demoDataStatus.textContent = error.message;
    setStatus(`Demo data failed: ${error.message}`);
    showToast("Demo data failed", error.message, "danger");
  } finally {
    setBusy(false);
  }
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  setBusy(true);
  setStatus("Fetching and assessing data...");
  clearResultsFilter();
  renderSkeletonRows();
  renderScanRunningContext("file-server", "Scanning file-server or local dataset. Results will update across Overview, Inventory, Findings, Exposure, Risk, and Endpoint context.");
  setScanProgress(true, 8, "Preparing scan...");
  let simulatedProgress = 8;
  const progressTimer = window.setInterval(() => {
    simulatedProgress = Math.min(92, simulatedProgress + Math.max(2, Math.round((92 - simulatedProgress) * 0.16)));
    setScanProgress(true, simulatedProgress, "Scanning...");
  }, 700);
  try {
    requireAuth();
    const payload = await ensureCredential(readPayload());
    const report = payload.async_scan ? await runQueuedScan(payload) : await api("/api/scan", { ...payload, save_report: true });
    applyScanReport(report, "file-server");
    setStatus("Scan completed and report.json updated.");
    setScanProgress(true, 100, "Scan completed");
    showToast("Scan completed", `${latestFiles.length} files found`, latestReport.summary?.critical ? "danger" : "success");
    if (latestReport.summary?.critical) {
      showToast("Critical exposure", `${latestReport.summary.critical} critical files found`, "danger");
    }
    await loadHistory();
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`);
    showToast("Scan failed", error.message, "danger");
  } finally {
    window.clearInterval(progressTimer);
    window.setTimeout(() => setScanProgress(false), 700);
    setBusy(false);
  }
});

localWinrmActivateBtn.addEventListener("click", async () => {
  setBusy(true);
  localWinrmStatus.textContent = "Preparing WinRM on this backend host only...";
  try {
    requireAuth();
    const result = await api("/api/endpoint/activate-local-winrm", readLocalWinrmPayload());
    localWinrmStatus.textContent = result.activated
      ? `Local backend WinRM is active on ${result.host || "this host"}. Continue with target local-admin credentials below.`
      : `Local backend readiness needs review: ${result.message}`;
    showToast(result.activated ? "Local backend WinRM ready" : "Local backend readiness needs review", result.message || result.host || "", result.activated ? "success" : "danger");
  } catch (error) {
    localWinrmStatus.textContent = `Local backend WinRM preparation failed: ${error.message}`;
    showToast("Local backend WinRM failed", error.message, "danger");
  } finally {
    setBusy(false);
  }
});

endpointActivateBtn.addEventListener("click", async () => {
  setBusy(true);
  winrmActivateStatus.textContent = "Preparing target WinRM, firewall, and verification...";
  try {
    requireAuth();
    const payload = readWinrmActivationPayload();
    const result = await api("/api/endpoint/repair-winrm", payload);
    if (result.connected) {
      syncEndpointScanCredentials(payload);
    }
    winrmActivateStatus.textContent = result.activated
      ? `Target WinRM ready on ${result.computer || result.host}. ${result.skipped_wmi_activation ? "Existing WinRM connection verified." : result.connected ? "Connection verified." : result.message || ""}`
      : `Target preparation needs review: ${result.connection_message || result.message}`;
    showToast(result.activated ? "Target WinRM ready" : "Target WinRM needs review", result.connection_message || result.message || result.host, result.activated ? "success" : "danger");
  } catch (error) {
    winrmActivateStatus.textContent = `Target WinRM preparation failed: ${error.message}`;
    showToast("Target WinRM preparation failed", error.message, "danger");
  } finally {
    setBusy(false);
  }
});

if (endpointTestBtn) endpointTestBtn.addEventListener("click", async () => {
  setBusy(true);
  endpointStatus.textContent = "Testing WinRM connection...";
  try {
    requireAuth();
    const payload = await ensureEndpointCredential(readEndpointPayload());
    const result = await api("/api/endpoint/test-connection", payload);
    endpointStatus.textContent = result.connected
      ? `Connected to ${result.computer || result.host} as ${result.user || "remote user"}.`
      : `Connection failed: ${result.message}`;
    showToast(result.connected ? "Endpoint connected" : "Endpoint test failed", result.message || result.host, result.connected ? "success" : "danger");
  } catch (error) {
    endpointStatus.textContent = `Endpoint test failed: ${error.message}`;
    showToast("Endpoint test failed", error.message, "danger");
  } finally {
    setBusy(false);
  }
});

if (endpointCancelBtn) endpointCancelBtn.addEventListener("click", async () => {
  if (!activeEndpointJobId) return;
  endpointCancelBtn.disabled = true;
  try {
    await api(`/api/scans/${activeEndpointJobId}/cancel`, {}, "POST");
    endpointStatus.textContent = "Endpoint scan cancellation requested.";
    setEndpointScanProgress(false);
  } catch (error) {
    endpointStatus.textContent = `Endpoint scan cancel failed: ${error.message}`;
  }
});

endpointScanBtn.addEventListener("click", async () => {
  setBusy(true);
  setStatus("Scanning endpoint through WinRM...");
  endpointStatus.textContent = "Scanning endpoint profile...";
  if (endpointViewOverviewBtn) endpointViewOverviewBtn.classList.add("hidden");
  clearResultsFilter();
  renderSkeletonRows();
  renderScanRunningContext("endpoint", "Scanning endpoint paths through WinRM. Results will update across Overview, Inventory, Findings, Exposure, Risk, and File Server context.");
  setEndpointScanProgress(true, 8, "Preparing endpoint scan...");
  const endpointProgressTimer = window.setInterval(() => {
    const current = Number.parseFloat(endpointScanProgressBar?.style.width || "8") || 8;
    setEndpointScanProgress(true, Math.min(current + 7, 88), "Searching endpoint paths...");
  }, 900);
  try {
    requireAuth();
    const payload = await ensureEndpointCredential(readEndpointPayload());
    if (payload.async_scan) {
      window.clearInterval(endpointProgressTimer);
    }
    const report = payload.async_scan ? await runQueuedEndpointScan(payload) : await api("/api/endpoint/scan", payload);
    applyScanReport(report, "endpoint");
    const extensionCounts = summarizeExtensions(latestFiles, report.endpoint?.extension_counts);
    const diagnostics = summarizeEndpointDiagnostics(report.endpoint);
    endpointStatus.textContent = `Endpoint scan completed. ${latestFiles.length} files analyzed. ${extensionCounts} ${diagnostics}`;
    if (endpointViewOverviewBtn) endpointViewOverviewBtn.classList.remove("hidden");
    setStatus("Endpoint scan completed and report.json updated.");
    setEndpointScanProgress(true, 100, "Endpoint scan completed");
    showToast("Endpoint scan completed", `${latestFiles.length} files found`, latestReport.summary?.critical ? "danger" : "success");
    await loadHistory();
  } catch (error) {
    endpointStatus.textContent = `Endpoint scan failed: ${error.message}`;
    setStatus(`Endpoint scan failed: ${error.message}`);
    showToast("Endpoint scan failed", error.message, "danger");
  } finally {
    window.clearInterval(endpointProgressTimer);
    window.setTimeout(() => setEndpointScanProgress(false), 700);
    setBusy(false);
  }
});

endpointPathScope.addEventListener("change", () => {
  updateEndpointCustomPathState();
  tuneEndpointScanDefaults();
});

filterInput.addEventListener("input", () => {
  renderedRowsLimit = ROW_PAGE_SIZE;
  renderRows(latestFiles);
});

inventoryRiskFilters.forEach((button) => {
  button.addEventListener("click", () => {
    inventoryRiskFilter = button.dataset.riskFilter || "ALL";
    renderedRowsLimit = ROW_PAGE_SIZE;
    renderRows(latestFiles);
  });
});

inventorySourceFilter?.addEventListener("change", () => {
  inventorySourceFacet = inventorySourceFilter.value || "ALL";
  renderedRowsLimit = ROW_PAGE_SIZE;
  renderRows(latestFiles);
});

inventoryFindingFilter?.addEventListener("change", () => {
  inventoryFindingFacet = inventoryFindingFilter.value || "ALL";
  renderedRowsLimit = ROW_PAGE_SIZE;
  renderRows(latestFiles);
});

inventoryClearFiltersBtn?.addEventListener("click", () => {
  inventoryRiskFilter = "ALL";
  inventorySourceFacet = "ALL";
  inventoryFindingFacet = "ALL";
  if (filterInput) filterInput.value = "";
  renderedRowsLimit = ROW_PAGE_SIZE;
  renderRows(latestFiles);
});

document.addEventListener("click", (event) => {
  if (event.target.closest("#load-more-results")) {
    renderedRowsLimit += ROW_PAGE_SIZE;
    renderRows(latestFiles);
    return;
  }
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
  const detailButton = event.target.closest(".detail-toggle");
  if (detailButton) {
    openDetailDrawer(detailButton.dataset.detailKey || "", detailButton.dataset.detailType || "reasons");
    return;
  }

  const button = event.target.closest(".preview-toggle");
  if (!button) {
    return;
  }

  const panel = button.closest("td").querySelector(".preview-panel");
  if (!panel) {
    return;
  }

  const isHidden = panel.classList.toggle("hidden");
  button.classList.toggle("preview-open", !isHidden);
  button.setAttribute("aria-label", isHidden ? "Show file preview" : "Hide file preview");
});

detailDrawer.addEventListener("click", (event) => {
  if (event.target.closest("[data-close-detail]")) {
    closeDetailDrawer();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    closeDetailDrawer();
  }
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
historyRange?.addEventListener("change", () => {
  updateHistoryFilterControls();
  renderHistory(latestHistoryItems);
});
historyFrom?.addEventListener("change", () => renderHistory(latestHistoryItems));
historyTo?.addEventListener("change", () => renderHistory(latestHistoryItems));
historyFrom?.addEventListener("input", () => renderHistory(latestHistoryItems));
historyTo?.addEventListener("input", () => renderHistory(latestHistoryItems));
auditRange?.addEventListener("change", () => {
  updateAuditFilterControls();
  renderAudit(latestAuditEvents);
});
auditFrom?.addEventListener("change", () => renderAudit(latestAuditEvents));
auditTo?.addEventListener("change", () => renderAudit(latestAuditEvents));
auditFrom?.addEventListener("input", () => renderAudit(latestAuditEvents));
auditTo?.addEventListener("input", () => renderAudit(latestAuditEvents));
function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle("sidebar-collapsed", collapsed);
  sidebarToggle?.setAttribute("aria-expanded", String(!collapsed));
  menuOpenToggle?.setAttribute("aria-expanded", String(!collapsed));
  if (sidebarToggle) {
    sidebarToggle.title = collapsed ? "Expand navigation" : "Collapse navigation";
  }
  safeSessionSet("dspm-sidebar-collapsed", collapsed ? "1" : "");
}

sidebarToggle?.addEventListener("click", () => {
  setSidebarCollapsed(!document.body.classList.contains("sidebar-collapsed"));
});
menuOpenToggle?.addEventListener("click", () => setSidebarCollapsed(false));
refreshExecutiveBtn.addEventListener("click", () => {
  loadHistory().catch((error) => setStatus(`Executive dashboard failed: ${error.message}`));
});
refreshAuditBtn.addEventListener("click", () => {
  loadAudit().catch((error) => setStatus(`Audit failed: ${error.message}`));
});
refreshUsersBtn.addEventListener("click", () => {
  loadUsers().catch((error) => {
    userManagementStatus.textContent = `Users failed: ${error.message}`;
  });
});
refreshTenantsBtn.addEventListener("click", () => {
  loadTenants().catch((error) => {
    tenantManagementStatus.textContent = `Tenants failed: ${error.message}`;
  });
});
createUserBtn.addEventListener("click", () => {
  createUser().catch((error) => {
    userManagementStatus.textContent = `Create failed: ${error.message}`;
  });
});
createTenantBtn.addEventListener("click", () => {
  createTenant().catch((error) => {
    tenantManagementStatus.textContent = `Create failed: ${error.message}`;
  });
});
tenantsBody.addEventListener("click", (event) => {
  const regenerateButton = event.target.closest("[data-regenerate-code]");
  if (regenerateButton) {
    regenerateTenantCode(regenerateButton.dataset.regenerateCode).then((code) => {
      if (!code) {
        return;
      }
      copyText(code).then(() => {
          tenantManagementStatus.textContent = "New registration code generated and copied.";
      }).catch(() => {
        tenantManagementStatus.textContent = "New registration code generated. Copy it from the table.";
      });
    }).catch((error) => {
      tenantManagementStatus.textContent = `Generate failed: ${error.message}`;
    });
    return;
  }

  const copyButton = event.target.closest("[data-copy-code]");
  if (copyButton) {
    copyText(copyButton.dataset.copyCode).then(() => {
      tenantManagementStatus.textContent = "Registration code copied.";
    }).catch((error) => {
      tenantManagementStatus.textContent = `Copy failed: ${error.message}`;
    });
    return;
  }

  const button = event.target.closest("[data-delete-tenant]");
  if (!button) {
    return;
  }
  const tenantId = button.dataset.deleteTenant;
  deleteTenant(tenantId).catch((error) => {
    tenantManagementStatus.textContent = `Remove failed: ${error.message}`;
  });
});
usersBody.addEventListener("change", (event) => {
  const roleSelect = event.target.closest("[data-user-role]");
  const tenantInput = event.target.closest("[data-user-tenant]");
  if (!roleSelect && !tenantInput) {
    return;
  }
  const username = roleSelect?.dataset.userRole || tenantInput?.dataset.userTenant;
  const roleInput = usersBody.querySelector(`[data-user-role="${CSS.escape(username)}"]`);
  const tenantValue = tenantInput?.value || usersBody.querySelector(`[data-user-tenant="${CSS.escape(username)}"]`)?.value || "default";
  updateUserRole(username, roleInput?.value || "viewer", tenantValue).catch((error) => {
    userManagementStatus.textContent = `Update failed: ${error.message}`;
  });
});
usersBody.addEventListener("click", (event) => {
  const deleteButton = event.target.closest("[data-delete-user]");
  if (deleteButton) {
    const username = deleteButton.dataset.deleteUser;
    const confirmed = window.confirm(`Delete user ${username}?`);
    if (confirmed) {
      deleteUser(username).catch((error) => {
        userManagementStatus.textContent = `Delete failed: ${error.message}`;
      });
    }
    return;
  }

  const button = event.target.closest("[data-reset-user]");
  if (!button) {
    return;
  }
  const username = button.dataset.resetUser;
  const input = usersBody.querySelector(`[data-user-password="${CSS.escape(username)}"]`);
  resetUserPassword(username, input?.value || "").catch((error) => {
    userManagementStatus.textContent = `Reset failed: ${error.message}`;
  });
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
profileToggle.addEventListener("click", (event) => {
  event.preventDefault();
  event.stopPropagation();
  const menu = document.querySelector(".profile-menu");
  const isOpen = menu.classList.toggle("open");
  profileToggle.setAttribute("aria-expanded", String(isOpen));
  if (!isOpen) {
    profileToggle.blur();
  }
});
document.addEventListener("click", (event) => {
  const menu = event.target.closest(".profile-menu");
  if (!menu) {
    document.querySelector(".profile-menu")?.classList.remove("open");
    profileToggle.setAttribute("aria-expanded", "false");
  }
});
tenantSwitcher.addEventListener("change", async () => {
  currentTenant = tenantSwitcher.value || "default";
  safeSessionSet("dspm-tenant-id", currentTenant);
  latestFiles = [];
  fileSearchIndex = new WeakMap();
  latestReport = null;
  latestScanKind = "";
  latestDashboard = null;
  rowOverrides = loadRowOverrides();
  assetRules = loadAssetRules();
  customExtensions = loadCustomExtensions();
  renderProfile();
  renderExtensionFilter(allowedExtensionsList, extensionSearch);
  renderExtensionFilter(endpointAllowedExtensionsList, endpointExtensionSearch);
  applyDefaultSimpleExtensionPolicies();
  renderAssetRules();
  renderRows([]);
  updateSummaryFromFiles([]);
  scanMeta.textContent = "No scan has been run yet.";
  setStatus(`Switched MSSP customer to ${currentTenant}.`);
  await loadHistory().catch((error) => setStatus(`Tenant switch failed: ${error.message}`));
});

msspPortfolio.addEventListener("click", async (event) => {
  const card = event.target.closest("[data-tenant-jump]");
  if (!card) {
    return;
  }
  tenantSwitcher.value = card.dataset.tenantJump || currentTenant;
  tenantSwitcher.dispatchEvent(new Event("change"));
});

hydrateNavigation();
applyTheme(safeStorageGet("dspm-theme") || "light");
setAuthState(Boolean(accessToken));
renderExtensionFilter(allowedExtensionsList, extensionSearch);
renderExtensionFilter(endpointAllowedExtensionsList, endpointExtensionSearch);
initSimpleExtensionPolicies();
applyDefaultSimpleExtensionPolicies();
renderProfile();
renderAssetRules();
renderReportPreview();
renderExecutiveExperience();
renderScanContextPanels();
renderFindingsWorkspace();
renderExposureWorkspace();
renderIntegrations();
if (safeSessionGet("dspm-sidebar-collapsed") === "1") {
  setSidebarCollapsed(true);
}
updateHistoryFilterControls();
updateAuditFilterControls();
updateEndpointCustomPathState();

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
    riskRulesBody.innerHTML = '<div class="empty compact">Sign in to load risk logic.</div>';
    return;
  }
  try {
    const data = await api("/api/risk-rules", null, "GET");
    renderRiskRules(data.rules);
  } catch {
    riskRulesBody.innerHTML = '<div class="empty compact">Risk logic could not be loaded.</div>';
  }
}

if (accessToken) {
  loadProtectedMetadata();
  loadHistory().catch(() => {});
  loadAudit().catch(() => {});
  loadUsers().catch(() => {});
} else {
  loadProtectedMetadata();
}


/* DSPM_V4_PRODUCT_PATCH: small UX helpers added by UI rebuild */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  document.querySelector(".profile-menu")?.classList.remove("open");
  profileToggle?.setAttribute("aria-expanded", "false");
  document.querySelector("#detail-drawer")?.classList.add("hidden");
});

window.addEventListener("storage", (event) => {
  if (event.key === "dspm-theme" && event.newValue) {
    document.documentElement.dataset.theme = event.newValue;
    const toggle = document.querySelector("#theme-toggle");
    const icon = toggle?.querySelector(".theme-icon");
    if (icon) icon.textContent = event.newValue === "dark" ? "☀" : "☾";
    if (toggle) {
      const nextLabel = event.newValue === "dark" ? "Switch to light mode" : "Switch to dark mode";
      toggle.setAttribute("aria-label", nextLabel);
      toggle.title = nextLabel;
    }
  }
});
