const form = document.querySelector("#connection-form");
const testBtn = document.querySelector("#test-btn");
const scanBtn = document.querySelector("#scan-btn");
const scanCancelBtn = document.querySelector("#scan-cancel-btn");
const generateDemoDataBtn = document.querySelector("#generate-demo-data-btn");
const demoDataTitle = document.querySelector("#demo-data-title");
const demoDataStatus = document.querySelector("#demo-data-status");
const statusBox = document.querySelector("#connection-status");
const scanProgress = document.querySelector("#scan-progress");
const scanProgressLabel = document.querySelector("#scan-progress-label");
const scanProgressBar = document.querySelector("#scan-progress-bar");
const scanProgressPercent = document.querySelector("#scan-progress-percent");
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
const protectedCount = document.querySelector("#protected-count");
const health = document.querySelector("#health");
const filterInput = document.querySelector("#filter");
const inventoryRiskFilters = document.querySelectorAll("[data-risk-filter]");
const inventorySourceFilter = document.querySelector("#inventory-source-filter");
const inventoryFindingFilter = document.querySelector("#inventory-finding-filter");
const inventoryFrameworkFilter = document.querySelector("#inventory-framework-filter");
const inventoryClearFiltersBtn = document.querySelector("#clear-inventory-filters");
const inventoryExportCsvBtn = document.querySelector("#inventory-export-csv");
const inventoryExportNdjsonBtn = document.querySelector("#inventory-export-ndjson");
const inventoryExportStatus = document.querySelector("#inventory-export-status");
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
const endpointScanProgressPercent = document.querySelector("#endpoint-scan-progress-percent");
const complianceEnabledInput = document.querySelector("#compliance-enabled");
const endpointComplianceEnabledInput = document.querySelector("#endpoint-compliance-enabled");
const complianceFrameworkHosts = document.querySelectorAll("[data-compliance-frameworks]");

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
  [".msix", "MSIX package"],
  [".msixbundle", "MSIX bundle"],
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
  recommended: [".txt", ".log", ".md", ".adoc", ".rst", ".rtf", ".csv", ".tsv", ".json", ".xml", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".config", ".properties", ".tf", ".tfvars", ".tfstate", ".hcl", ".npmrc", ".pypirc", ".netrc", ".aws", ".reg", ".env", ".pem", ".key", ".crt", ".cer", ".pfx", ".p12", ".kdbx", ".ovpn", ".pcf", ".mobileconfig", ".rdp", ".gpg", ".pgp", ".sql", ".dump", ".bak", ".backup", ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb", ".pst", ".ost", ".msg", ".eml", ".mbox", ".ics", ".doc", ".docx", ".docm", ".dotx", ".dotm", ".odt", ".ott", ".pages", ".xls", ".xlsx", ".xlsm", ".xlsb", ".ods", ".ots", ".numbers", ".ppt", ".pptx", ".pptm", ".odp", ".otp", ".keynote", ".pdf", ".one", ".pub", ".vsd", ".vsdx"],
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

const COMPLIANCE_FRAMEWORKS = [
  { id: "gdpr", name: "GDPR", desc: "Personal data, IDs, health, biometric, HR and customer records." },
  { id: "pci_dss", name: "PCI DSS", desc: "CHD and SAD rules: PAN, cardholder name, expiry, service code, track data, CVV, PIN and PIN block." },
  { id: "nist_sp800_60_enterprise", name: "NIST", desc: "Information types, CIA impact, PII, CUI-aware handling, and catalog health." },
];
const COMPLIANCE_LOGIC = [
  {
    id: "gdpr",
    name: "GDPR",
    scope: "EU personal data protection and special-category data exposure",
    summary: "Maps files to GDPR when scan evidence contains personal data, identity records, health data, biometrics, online identifiers, employee records, customer data, financial records, or credential material tied to a person or regulated process.",
    scoring: [
      "Risk score contributes up to 35% of the compliance score so normal DSPM severity influences GDPR priority without forcing every file to 100.",
      "Data type criticality adds the strongest weight: health data, special-category data, biometric/genetic data, government IDs, credentials, financial records, HR records, customer data, and online identifiers are scored differently.",
      "Finding evidence adds weight from finding severity and count, so one low-confidence name match scores lower than repeated health or identity findings.",
      "Exposure adds limited weight for broad access, writable access, and permission score.",
      "Location adds smaller context weight for exports, desktop/downloads, backups, shares, and high-density file types such as CSV, XLSX, ZIP, SQL, DB, JSON, and PST.",
      "Protection can reduce score when a file is encrypted or protected."
    ],
    dataTypes: [
      "Personal data",
      "Government IDs",
      "Health Data / Special Category",
      "Biometric data",
      "Genetic and special-category data",
      "Financial records",
      "Customer data",
      "HR / employee data",
      "Online and device identifiers",
      "Location and behavioral data",
      "Credentials / identity access"
    ],
    evidence: [
      "Regex and GDPR rule findings such as full name, email, phone, passport, national ID, health record, biometric, salary, employee, customer, and credential signals.",
      "Matched keywords and redacted samples from GDPR classifier output.",
      "Path, filename, share, and extension keywords such as customer, employee, payroll, finance, health, legal, export, backup, secret, and credential.",
      "Permission context such as broad access and writable exposure."
    ],
    output: [
      "Adds a GDPR compliance chip to matching files.",
      "Adds framework mapping, data categories, reason details, matched keyword/sample evidence, score parts, and remediation text.",
      "Appears in reports under Compliance mapping and Framework mapping."
    ]
  },
  {
    id: "pci_dss",
    name: "PCI DSS",
    scope: "PCI DSS account data split into Cardholder Data (CHD) and Sensitive Authentication Data (SAD)",
    summary: "Maps files to PCI DSS using the supplied rule set: PAN anchors CHD, name/expiry/service code become CHD when linked to PAN, and track data, CVV, PIN, and PIN block are SAD.",
    scoring: [
      "PCI-CHD-PAN receives the strongest CHD priority because readable full PAN anchors PCI DSS scope for the storage location and connected systems.",
      "Protection state changes severity: masked and truncated PAN score lower, while tokenized, hashed, and encrypted PAN still require validation of reversibility, key separation, and scope.",
      "Payment-domain context, field names, path names, Luhn validation, and negative-context suppression are combined so generic numbers do not become PCI findings by keyword alone.",
      "Exposure, risky locations, backups, exports, logs, and broad access raise priority when cardholder data is present.",
      "PCI-SAD-TRACK, PCI-SAD-CVV, and PCI-SAD-PIN always map to SAD and raise retention/exception workflow evidence.",
      "Report evidence uses masked previews and secure fingerprints only; full PAN, CVV, PIN, and track payloads are not returned to the UI."
    ],
    dataTypes: [
      "PCI-CHD-PAN: Primary Account Number",
      "PCI-CHD-NAME: Cardholder name with PAN",
      "PCI-CHD-EXP: Expiration date with PAN",
      "PCI-CHD-SVC: Service code with PAN",
      "PCI-SAD-TRACK: Full track data / chip equivalent",
      "PCI-SAD-CVV: CAV2, CVC2, CVN2, CVV2, CID",
      "PCI-SAD-PIN: PIN and PIN block",
      "Masked PAN",
      "Truncated PAN",
      "Tokenized PAN",
      "Hashed PAN",
      "Encrypted PAN",
      "PCI Cardholder Data (CHD)",
      "PCI Sensitive Authentication Data (SAD)",
      "PCI scope evidence"
    ],
    evidence: [
      "PAN candidates validated through structure, Luhn, field/path context, and payment-domain keywords.",
      "Cardholder name evidence from explicit name-on-card fields or correlation with PAN-bearing payment records.",
      "Expiration date evidence from explicit card-expiry fields, MM/YY variants, month/year pairs, or correlation with PAN-bearing records.",
      "Service code evidence from explicit service-code fields or correlation with PAN-bearing payment records.",
      "Track data evidence from structural Track 1, Track 2, EMV Track 2 equivalent, encrypted-track fields, parser components, and secure fingerprints.",
      "CVV-family evidence from explicit CVV/CVC/CID fields, payment-card context, PAN correlation, and value-length-only masked output.",
      "PIN/PIN-block evidence from explicit card/ATM/payment PIN fields, ISO PIN block/HSM/key context, PAN correlation, and length-only masked output.",
      "Protection-state terms such as masked, truncated, tokenized, hashed, encrypted, vault, and fingerprint.",
      "Negative context such as invoice, order, tracking, serial, phone, IBAN, SKU, UUID, sample, and placeholder terms.",
      "Permission context, storage location, archive/export/log context, and file risk score."
    ],
    output: [
      "Adds a PCI DSS compliance chip to matching files.",
      "Adds PAN protection state, confidence, PCI CHD/SAD category, requirement mapping, masked evidence, and remediation text.",
      "Appears in reports under Compliance mapping, Framework mapping, and pci_scope_summary without exposing raw PCI secrets."
    ]
  },
  {
    id: "nist_sp800_60_enterprise",
    name: "NIST",
    scope: "Information-type discovery with FIPS 199 CIA impact categorization",
    summary: "Maps files to NIST information types while preserving nested catalog metadata such as source kind, handling tier, CIA impact, scoring, governance, mappings, remediation, and evidence policy.",
    scoring: [
      "Rule-specific score_model thresholds classify matches as confirmed, high, medium, low, or rejected.",
      "Positive signals include markings, schema fields, path/object context, Azerbaijani/local terms, regex patterns, and supporting context.",
      "Negative public, training, template, synthetic, placeholder, and decontrol context reduces confidence.",
      "CIA impact remains separate from DSPM product severity and operational risk modifiers."
    ],
    dataTypes: [
      "CUI-aware information types",
      "NIST PII",
      "FIPS 199 impact-derived non-CUI records",
      "Credentials, security artifacts, source code, finance, HR, legal, health, customer, and IP records"
    ],
    evidence: [
      "Top-level catalog rules with primary aliases, schema fields, Azerbaijani terms, supporting context, negative context, and regex patterns.",
      "Catalog version/hash/status, source kind, source version, handling tier, CIA impact, and risk factor breakdown.",
      "Masked previews and non-reversible fingerprints only."
    ],
    output: [
      "Adds NIST framework chips to matching files.",
      "Adds catalog health, category coverage, rule coverage, CIA distribution, review queue, and remediation priorities.",
      "Keeps nist_csf separate from this information-type classifier."
    ]
  },
];
let latestHistoryItems = [];
let latestAuditEvents = [];
let rowOverrides = loadRowOverrides();
let assetRules = loadAssetRules();
let editingAssetIndex = null;
let latestDashboard = null;
let latestHashComparison = null;
let tenantPortfolio = [];
let latestRiskRules = [];
let latestComplianceKeywordLibrary = null;
let latestComplianceKeywordLibraries = {};
let lastRenderedFileKeys = new Set();
let hasRenderedScanRows = false;
let renderedRowsLimit = 200;
let inventoryPageWindow = createInventoryPageWindow();
let inventoryPageRequest = 0;
let inventoryPageAbortController = null;
let inventoryFacets = null;
// Estate-wide summary aggregated server-side across ALL scan sources (file
// server + endpoint + local). The dashboard tiles must describe the whole
// indexed inventory - the same data Data Inventory shows - not whichever
// single scan happened to run last.
let estateSummary = null;
let inventoryFacetRequest = 0;
const expandedInventoryKeys = new Set();
// Inventory details use the authenticated on-demand asset endpoint.
const inventoryDetailRequests = new Map();
let activeScanJobId = "";
let activeEndpointJobId = "";
let scanProgressValue = 0;
let endpointProgressValue = 0;
let scanStartedAt = 0;
let endpointScanStartedAt = 0;
let lastScanElapsedSeconds = 0;
let lastEndpointElapsedSeconds = 0;
let endpointScopePolicyTuning = false;
let inventoryRiskFilter = "ALL";
let inventorySourceFacet = "ALL";
let inventoryFindingFacet = "ALL";
let inventoryFrameworkFacets = new Set();
let fileSearchIndex = new WeakMap();

const ROW_PAGE_SIZE = 200;
const INVENTORY_SERVER_PAGE_SIZE = 100;
const INVENTORY_MAX_CACHED_PAGES = 3;

function createInventoryPageWindow(active = false) {
  return {
    active,
    loading: false,
    pageIndex: 0,
    pageStarts: [""],
    pages: new Map(),
    error: "",
  };
}

// Debounce: coalesce rapid-fire events (every keystroke in a search box) into a
// single trailing call, so the expensive re-filter + full table re-render runs
// ONCE when the user pauses instead of on every keystroke. The <input> value
// updates instantly (the browser owns that); only the heavy work is deferred, so
// typing stays smooth on large result sets. .flush()/.cancel() let callers force
// or drop a pending run.
function debounce(fn, wait = 160) {
  let timer = null;
  function debounced(...args) {
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      fn.apply(this, args);
    }, wait);
  }
  debounced.cancel = () => {
    if (timer) clearTimeout(timer);
    timer = null;
  };
  debounced.flush = function flush(...args) {
    if (timer) clearTimeout(timer);
    timer = null;
    fn.apply(this, args);
  };
  return debounced;
}
const ARCHIVE_EXTENSIONS = new Set([".7z", ".bz2", ".cab", ".gz", ".jar", ".rar", ".tar", ".tgz", ".xz", ".zip"]);

async function api(path, payload, method = "POST", options = {}) {
  const response = await fetch(path, {
    method,
    headers: authHeaders(),
    body: payload ? JSON.stringify(payload) : undefined,
    signal: options.signal,
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
    if (typeof data.detail === "string") return data.detail;
    if (data.detail && typeof data.detail === "object") {
      return [data.detail.message, data.detail.hint].filter(Boolean).join(" — ");
    }
    return "Request failed.";
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

// The scan currently running from a deck card. Its name is stamped on the
// report so every asset it produces is filterable by that scan in Data
// Inventory. Declared with `var` on purpose: app.js is assembled by appending
// modules, readPayload() runs during boot, and a `let` here would sit in its
// temporal dead zone and throw.
var activeScanLabel = "";

function readPayload() {
  const data = new FormData(form);
  const selectedExtensions = readSelectedExtensions();
  const searchedExtension = readSearchExtension(extensionSearch);
  const selectedComplianceFrameworks = complianceEnabledInput?.checked
    ? readSelectedComplianceFrameworks("file-server")
    : [];
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
    include_hidden: true,
    include_system: selectedExtensions.includes("__system__"),
    hidden_filter_enabled: selectedExtensions.includes("__hidden__"),
    system_filter_enabled: selectedExtensions.includes("__system__"),
    include_admin_shares: Boolean(data.get("include_admin_shares")),
    inspect_archives: Boolean(data.get("inspect_archives")),
    async_scan: Boolean(data.get("async_scan")),
    incremental_enabled: Boolean(data.get("incremental_enabled")),
    asset_overrides: assetRules,
    compliance_enabled: selectedComplianceFrameworks.length > 0,
    compliance_frameworks: selectedComplianceFrameworks,
    scan_label: activeScanLabel || "",
  };
}

function readSelectedComplianceFrameworks(scope) {
  return [...document.querySelectorAll(`[data-compliance-frameworks="${scope}"] input[type='checkbox']:checked`)].map((input) => input.value);
}

function renderComplianceSelectors() {
  complianceFrameworkHosts.forEach((host) => {
    const scope = host.dataset.complianceFrameworks;
    host.innerHTML = COMPLIANCE_FRAMEWORKS.map((framework) => `
      <label class="compliance-framework-card">
        <input type="checkbox" value="${escapeHtml(framework.id)}" />
        <span class="compliance-framework-copy">
          <strong>${escapeHtml(framework.name)}</strong>
          <small>${escapeHtml(framework.desc)}</small>
        </span>
        <span class="compliance-framework-check" aria-hidden="true"></span>
      </label>
    `).join("");
    const toggle = scope === "endpoint" ? endpointComplianceEnabledInput : complianceEnabledInput;
    const refresh = () => {
      const enabled = Boolean(toggle?.checked);
      host.classList.toggle("disabled", !enabled);
      host.querySelectorAll("input[type='checkbox']").forEach((input) => {
        input.disabled = !enabled;
        if (!enabled) input.checked = false;
      });
    };
    toggle?.addEventListener("change", refresh);
    host.addEventListener("change", () => {
      if (readSelectedComplianceFrameworks(scope).length && toggle) toggle.checked = true;
      refresh();
    });
    refresh();
  });
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
  const selected = new Set(name === "all" ? getExtensionOptions().map(([extension]) => extension) : SIMPLE_EXTENSION_PRESETS[name] || SIMPLE_EXTENSION_PRESETS.secrets);
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
  const selectedFileExtensions = selected.filter((extension) => extension.startsWith("."));
  const allFileExtensions = getExtensionOptions().map(([extension]) => extension);
  if (selectedFileExtensions.length >= allFileExtensions.length && allFileExtensions.every((extension) => selectedFileExtensions.includes(extension))) {
    host.innerHTML = '<span class="extension-selected-empty">All listed extensions selected</span>';
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
  [...list.querySelectorAll("input[type='checkbox']")].forEach((checkbox) => {
    checkbox.checked = checkbox.checked || checkbox.value === extension;
  });
  reorderExtensionOptions(list);
  filterExtensionList(allowedExtensionsList, extensionSearch);
  filterExtensionList(endpointAllowedExtensionsList, endpointExtensionSearch);
  updateExtensionSummary(allowedExtensionsList);
  updateExtensionSummary(endpointAllowedExtensionsList);
  setStatus(`Custom extension saved: ${extension}`);
}

function getEndpointScopeConfig(scope = endpointPathScope?.value || "default") {
  const configs = {
    default: { paths: ["desktop", "documents", "downloads"], depth: 5, label: "User profile quick scan" },
    desktop: { paths: ["desktop"], depth: 3, label: "Desktop only" },
    documents: { paths: ["documents"], depth: 4, label: "Documents only" },
    downloads: { paths: ["downloads"], depth: 3, label: "Downloads only" },
    onedrive: { paths: ["onedrive"], depth: 5, label: "OneDrive only" },
    all: { paths: ["all"], depth: 5, label: "Target profile data" },
    all_profiles: { paths: ["all_profiles"], depth: 5, label: "All user profiles" },
    c_drive: { paths: ["c_drive"], depth: 5, label: "C drive data scan" },
    all_fixed_drives: { paths: ["all_fixed_drives"], depth: 5, label: "All fixed drives" },
    custom: { paths: readEndpointCustomPaths(), depth: 4, label: "Custom paths" },
  };
  return configs[scope] || configs.default;
}

function readEndpointCustomPaths() {
  return endpointCustomPaths.value
    .split(/[\n;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function clampEndpointDepth(value, scope = endpointPathScope?.value || "default") {
  const number = Number(value || getEndpointScopeConfig(scope).depth);
  const maxByScope = scope === "c_drive" || scope === "all_fixed_drives" ? 8 : ["all", "all_profiles"].includes(scope) ? 8 : 12;
  return Math.max(1, Math.min(maxByScope, Number.isFinite(number) ? Math.round(number) : getEndpointScopeConfig(scope).depth));
}

function readEndpointPayload() {
  const selectedExtensions = readSelectedExtensions(endpointAllowedExtensionsList);
  const searchedExtension = readSearchExtension(endpointExtensionSearch);
  if (searchedExtension && !selectedExtensions.includes(searchedExtension)) {
    selectedExtensions.push(searchedExtension);
  }
  const selectedFileExtensions = selectedExtensions.filter((item) => item.startsWith("."));
  const allKnownFileExtensions = getExtensionOptions().map(([extension]) => extension);
  const allExtensionsSelected = selectedFileExtensions.length >= allKnownFileExtensions.length
    && allKnownFileExtensions.every((extension) => selectedFileExtensions.includes(extension));
  const effectiveAllowedExtensions = allExtensionsSelected ? [] : selectedFileExtensions;
  const archiveOnlyFilter = selectedFileExtensions.length > 0 && selectedFileExtensions.every((extension) => ARCHIVE_EXTENSIONS.has(extension));
  const scope = endpointPathScope.value;
  const scopeConfig = getEndpointScopeConfig(scope);
  const targetUsername = document.querySelector("#endpoint-target-username").value.trim();
  const selectedComplianceFrameworks = endpointComplianceEnabledInput?.checked
    ? readSelectedComplianceFrameworks("endpoint")
    : [];
  if (scope === "custom" && !scopeConfig.paths.length) {
    throw new Error("Enter at least one custom endpoint path.");
  }
  if (["default", "desktop", "documents", "downloads", "onedrive", "all"].includes(scope) && !targetUsername) {
    throw new Error("Enter Target Windows user for single-profile scopes, or choose All user profiles / C drive / All fixed drives / Custom paths.");
  }
  return {
    host: document.querySelector("#endpoint-host").value.trim(),
    target_username: targetUsername,
    domain: document.querySelector("#endpoint-domain").value.trim() || "WORKGROUP",
    username: document.querySelector("#endpoint-username").value.trim(),
    password: document.querySelector("#endpoint-password").value,
    credential_ref: document.querySelector("#endpoint-credential-ref").value.trim(),
    paths: scopeConfig.paths,
    max_depth: clampEndpointDepth(document.querySelector("#endpoint-max-depth").value, scope),
    read_content: document.querySelector("#endpoint-read-content").checked && !archiveOnlyFilter,
    read_acl: document.querySelector("#endpoint-read-acl")?.checked || false,
    inspect_archives: document.querySelector("#endpoint-inspect-archives")?.checked || false,
    async_scan: document.querySelector("#endpoint-async-scan")?.checked || false,
    incremental_enabled: document.querySelector("#endpoint-incremental-enabled")?.checked ?? true,
    allowed_extensions: effectiveAllowedExtensions,
    extension_filter_enabled: effectiveAllowedExtensions.length > 0,
    include_hidden: true,
    include_system: selectedExtensions.includes("__system__"),
    hidden_filter_enabled: selectedExtensions.includes("__hidden__"),
    system_filter_enabled: selectedExtensions.includes("__system__"),
    save_report: true,
    asset_overrides: assetRules,
    compliance_enabled: selectedComplianceFrameworks.length > 0,
    compliance_frameworks: selectedComplianceFrameworks,
    scan_label: activeScanLabel || "",
  };
}

function readEndpointConnectionPayload() {
  return {
    host: document.querySelector("#endpoint-host").value.trim(),
    target_username: document.querySelector("#endpoint-target-username").value.trim(),
    domain: document.querySelector("#endpoint-domain").value.trim() || "WORKGROUP",
    username: document.querySelector("#endpoint-username").value.trim(),
    password: document.querySelector("#endpoint-password").value,
    credential_ref: document.querySelector("#endpoint-credential-ref").value.trim(),
    paths: ["desktop"],
    max_depth: 1,
    read_content: false,
    read_acl: false,
    inspect_archives: false,
    async_scan: false,
    allowed_extensions: [],
    extension_filter_enabled: false,
    include_hidden: true,
    include_system: false,
    hidden_filter_enabled: false,
    system_filter_enabled: false,
    save_report: false,
    asset_overrides: [],
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
  if (!payload.host || !payload.password) {
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
  if (scanCancelBtn) scanCancelBtn.disabled = !activeScanJobId;
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
  // Hidden tabs throttle requestAnimationFrame to zero, which would freeze the
  // count-up mid-flight and show a stale number until the next repaint. The
  // value itself must never depend on animation: set it when the page is
  // hidden, animate only when someone can watch.
  if (start === end || document.hidden) {
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

function normalizeProgress(progress, previous = 0, minimum = 0) {
  const value = Math.round(Math.max(minimum, Math.min(100, Number(progress) || 0)));
  return Math.max(previous, value);
}

function smoothProgress(progress, previous = 0, minimum = 0) {
  const requested = normalizeProgress(progress, previous, minimum);
  if (requested >= 100) return 100;
  if (requested <= previous) return previous;
  const step = previous < 30 ? 4 : previous < 70 ? 3 : 2;
  return Math.min(requested, previous + step);
}

function nextLiveProgress(current, serverProgress = 0, cap = 92) {
  const floor = normalizeProgress(serverProgress, current, 5);
  if (floor >= cap) return Math.min(99, floor);
  const step = floor < 30 ? 4 : floor < 65 ? 3 : 1;
  return Math.min(cap, Math.max(floor, current + step));
}

function formatElapsedTime(seconds = 0) {
  const total = Math.max(0, Math.round(Number(seconds) || 0));
  const minutes = Math.floor(total / 60);
  const remainingSeconds = total % 60;
  if (minutes <= 0) return `${remainingSeconds}s`;
  return `${minutes}m ${remainingSeconds}s`;
}

function scanElapsedSeconds(startedAt = 0, fallback = 0) {
  if (Number(fallback) > 0) return Number(fallback);
  return startedAt ? (performance.now() - startedAt) / 1000 : 0;
}

function estimatedProgress(startedAt = 0, current = 0, cap = 88) {
  const elapsed = scanElapsedSeconds(startedAt);
  const target = Math.min(cap, 8 + Math.floor((1 - Math.exp(-elapsed / 18)) * (cap - 8)));
  return Math.max(current, target);
}

function setScanProgress(active, progress = 0, label = "Scanning...", elapsedSeconds = 0) {
  scanProgress.classList.toggle("hidden", !active);
  scanProgress.classList.toggle("active", active);
  if (!active) {
    scanProgressValue = 0;
    scanStartedAt = 0;
    if (scanProgressPercent) scanProgressPercent.textContent = "0%";
    scanProgressBar.style.width = "0%";
    return;
  }
  if (!scanStartedAt) scanStartedAt = performance.now();
  scanProgressValue = smoothProgress(progress, scanProgressValue, 0);
  scanProgressLabel.textContent = label;
  scanProgressBar.style.width = `${scanProgressValue}%`;
  scanProgressBar.parentElement?.setAttribute("aria-valuemin", "0");
  scanProgressBar.parentElement?.setAttribute("aria-valuemax", "100");
  scanProgressBar.parentElement?.setAttribute("aria-valuenow", String(scanProgressValue));
  if (scanProgressPercent) scanProgressPercent.textContent = `${scanProgressValue}% · ${formatElapsedTime(scanElapsedSeconds(scanStartedAt, elapsedSeconds))}`;
}

function setEndpointScanProgress(active, progress = 0, label = "Scanning endpoint...", elapsedSeconds = 0) {
  if (!endpointScanProgress || !endpointScanProgressLabel || !endpointScanProgressBar) return;
  endpointScanProgress.classList.toggle("hidden", !active);
  endpointScanProgress.classList.toggle("active", active);
  if (!active) {
    endpointProgressValue = 0;
    endpointScanStartedAt = 0;
    if (endpointScanProgressPercent) endpointScanProgressPercent.textContent = "0%";
    endpointScanProgressBar.style.width = "0%";
    return;
  }
  if (!endpointScanStartedAt) endpointScanStartedAt = performance.now();
  endpointProgressValue = smoothProgress(progress, endpointProgressValue, 0);
  endpointScanProgressLabel.textContent = label;
  endpointScanProgressBar.style.width = `${endpointProgressValue}%`;
  endpointScanProgressBar.parentElement?.setAttribute("aria-valuemin", "0");
  endpointScanProgressBar.parentElement?.setAttribute("aria-valuemax", "100");
  endpointScanProgressBar.parentElement?.setAttribute("aria-valuenow", String(endpointProgressValue));
  if (endpointScanProgressPercent) endpointScanProgressPercent.textContent = `${endpointProgressValue}% · ${formatElapsedTime(scanElapsedSeconds(endpointScanStartedAt, elapsedSeconds))}`;
}

function clearResultsFilter() {
  if (filterInput) {
    filterInput.value = "";
  }
  inventoryRiskFilter = "ALL";
  inventorySourceFacet = "ALL";
  inventoryFindingFacet = "ALL";
  inventoryFrameworkFacets = new Set();
  if (inventorySourceFilter) inventorySourceFilter.value = "ALL";
  if (inventoryFindingFilter) inventoryFindingFilter.value = "ALL";
  renderInventoryFrameworkFilter();
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
  const filtered = Math.max(0, visited - matched);
  const archiveFiles = Number(diagnostics.archive_files || 0);
  const archiveEntries = Number(diagnostics.archive_entries || 0);
  const skippedDirs = Number(diagnostics.skipped_dirs || 0);
  const filteredWrongProfile = Number(diagnostics.filtered_wrong_profile || 0);
  const resolved = (diagnostics.resolved_roots || []).slice(0, 8).join("; ");
  const missing = (diagnostics.missing_roots || []).slice(0, 8).join("; ");
  const archiveErrors = (diagnostics.archive_errors || []).slice(0, 2).join("; ");
  const unreadable = (diagnostics.unreadable_dirs || []).slice(0, 3).join("; ");
  const allowed = (diagnostics.allowed_extensions || endpoint.allowed_extensions || []).join(", ");
  const parts = [`Visited: ${visited}`, `Matched: ${matched}`, `Filtered: ${filtered}`];
  const incremental = diagnostics.incremental || {};
  if (incremental.enabled) {
    parts.push(`Delta: ${Number(incremental.unchanged_objects || 0)} reused, ${Number(incremental.content_reads || 0)} read`);
    if (Number(incremental.deleted_objects || 0)) parts.push(`Deleted: ${Number(incremental.deleted_objects)}`);
  }
  if (skippedDirs) parts.push(`Skipped dirs: ${skippedDirs}`);
  if (filteredWrongProfile) parts.push(`Wrong-profile files ignored: ${filteredWrongProfile}`);
  if (archiveFiles || archiveEntries) parts.push(`Archives: ${archiveFiles}`, `Archive entries: ${archiveEntries}`);
  if (allowed) parts.push(`Allowed: ${allowed}`);
  if (resolved) parts.push(`Roots: ${resolved}`);
  if (missing) parts.push(`Missing: ${missing}`);
  if (unreadable) parts.push(`Unreadable: ${unreadable}`);
  if (archiveErrors) parts.push(`Archive errors: ${archiveErrors}`);
  return parts.join(". ");
}

function summarizeFileServerDiagnostics(report = {}) {
  const diagnostics = report.scan_diagnostics || {};
  const parts = [];
  const incremental = diagnostics.incremental || {};
  if (incremental.enabled) {
    parts.push(`Delta: ${Number(incremental.unchanged_objects || 0)} reused, ${Number(incremental.content_reads || 0)} read`);
    if (Number(incremental.deleted_objects || 0)) parts.push(`Deleted: ${Number(incremental.deleted_objects)}`);
  }
  if (Number.isFinite(Number(diagnostics.records))) parts.push(`Records: ${Number(diagnostics.records)}`);
  if (Number.isFinite(Number(diagnostics.owner_resolved))) parts.push(`Owners: ${Number(diagnostics.owner_resolved)} resolved`);
  if (Number.isFinite(Number(diagnostics.owner_missing)) && Number(diagnostics.owner_missing)) parts.push(`${Number(diagnostics.owner_missing)} owner missing`);
  if (Number.isFinite(Number(diagnostics.owner_read_failed)) && Number(diagnostics.owner_read_failed)) parts.push(`${Number(diagnostics.owner_read_failed)} ACL reads failed`);
  if (Array.isArray(diagnostics.list_errors) && diagnostics.list_errors.length) {
    const shares = diagnostics.list_errors.slice(0, 3).map((item) => `${item.share || "share"}:${item.path || "/"}`).join(", ");
    parts.push(`Unreadable paths: ${shares}`);
  }
  if (diagnostics.local_path) parts.push(`Local path: ${diagnostics.local_path}`);
  if (Array.isArray(diagnostics.allowed_extensions) && diagnostics.allowed_extensions.length) {
    parts.push(`Allowed: ${diagnostics.allowed_extensions.slice(0, 12).join(", ")}`);
  }
  return parts.join(". ");
}

function showToast(title, message = "", tone = "info") {
  const toast = document.createElement("div");
  toast.className = `toast ${tone}`;
  toast.innerHTML = `<button type="button" class="toast-close" aria-label="Dismiss notification"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button><strong>${escapeHtml(title)}</strong>${message ? `<span>${escapeHtml(message)}</span>` : ""}`;
  toast.querySelector(".toast-close").addEventListener("click", () => {
    toast.classList.add("leaving");
    window.setTimeout(() => toast.remove(), 260);
  });
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
  if (endpointStatus && !isBusy) {
    const scope = endpointPathScope.value;
    const targetUser = document.querySelector("#endpoint-target-username")?.value.trim();
    if (["default", "desktop", "documents", "downloads", "onedrive", "all"].includes(scope) && !targetUser) {
      endpointStatus.textContent = "Enter Target Windows user for single-profile scopes. Use All user profiles, C drive, All fixed drives, or Custom paths without a profile user.";
    } else if (scope === "default") {
      endpointStatus.textContent = "Quick scan checks the target user's Desktop, Documents, Downloads, and OneDrive equivalents.";
    } else if (["desktop", "documents", "downloads"].includes(scope)) {
      endpointStatus.textContent = "Selected profile folder scan uses the target user's real C:\\Users profile and OneDrive equivalents.";
    } else if (scope === "onedrive") {
      endpointStatus.textContent = "OneDrive scan checks OneDrive and OneDrive - tenant folders under the target user's profile.";
    } else if (scope === "all") {
      endpointStatus.textContent = "Target profile data scans the target user's C:\\Users profile while skipping AppData, OS cache, and project folders. Use Custom paths for an exact deep folder.";
    } else if (scope === "all_profiles") {
      endpointStatus.textContent = "All user profiles scans real C:\\Users profiles and skips Default/Public/system profile folders.";
    } else if (scope === "c_drive") {
      endpointStatus.textContent = "C drive data scan checks C:\\ while skipping OS, browser cache, temp, and project folders. Use Custom paths for exact deep locations.";
    } else if (scope === "all_fixed_drives") {
      endpointStatus.textContent = "All fixed drives can be long-running. Keep depth low first, then expand after validating results.";
    } else {
      endpointStatus.textContent = "Fill the endpoint scan details after WinRM is active on the workstation.";
    }
  }
}

function isWideEndpointScope(scope = endpointPathScope?.value || "default") {
  if (["all_profiles", "c_drive", "all_fixed_drives"].includes(scope)) return true;
  if (scope !== "custom") return false;
  return readEndpointCustomPaths().some((path) => /^[A-Za-z]:\\?$/.test(path.trim()));
}

function tuneEndpointScopeExtensionPolicy() {
  if (endpointScopePolicyTuning || !isWideEndpointScope()) return;
  const checkedPreset = document.querySelector("input[name='endpoint-ext-preset']:checked");
  if (!checkedPreset || checkedPreset.value !== "recommended") return;
  const broadPreset = document.querySelector("input[name='endpoint-ext-preset'][value='broad']");
  if (!broadPreset) return;
  endpointScopePolicyTuning = true;
  broadPreset.checked = true;
  applySimpleExtensionPolicy("broad", endpointAllowedExtensionsList, endpointExtensionSearch);
  endpointScopePolicyTuning = false;
}

function tuneEndpointScanDefaults() {
  const depthInput = document.querySelector("#endpoint-max-depth");
  const readContent = document.querySelector("#endpoint-read-content");
  const asyncScan = document.querySelector("#endpoint-async-scan");
  const scope = endpointPathScope?.value || "default";
  if (asyncScan && isWideEndpointScope(scope)) {
    asyncScan.checked = true;
  }
  if (depthInput) {
    const config = getEndpointScopeConfig(scope);
    const current = Number(depthInput.value || 0);
    if (!depthInput.dataset.touched || !current) {
      depthInput.value = String(config.depth);
    } else {
      depthInput.value = String(clampEndpointDepth(current, scope));
    }
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
  return Boolean(file.protected || file.is_protected)
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

function fileDateMeta(value) {
  return getFriendlyTimestamp(value) || "-";
}

function filePropertyOwner(file = {}) {
  return reportText(
    file.owner
      || file.owner_name
      || file.file_owner
      || file.acl?.owner
      || file.security_owner
      || file.metadata?.owner,
    ""
  );
}

function filePropertyAttributes(file = {}) {
  const attributes = String(file.attributes || "").trim();
  if (attributes) return attributes;
  const flags = [
    file.is_hidden ? "Hidden" : "",
    file.is_system ? "System" : "",
    isProtectedFile(file) ? "Protected" : "",
  ].filter(Boolean);
  return flags.join(", ") || "Normal";
}

function fileHashValue(file = {}) {
  return String(file.sha256 || file.file_hash || "").trim().toLowerCase();
}

function shortHash(hash = "") {
  const value = String(hash || "").trim();
  if (!value) return "-";
  return value.length > 18 ? `${value.slice(0, 12)}...${value.slice(-8)}` : value;
}

function hasHashChanged(file = {}) {
  return changedHashKeys().has(hashComparisonKey(file));
}

function duplicateHashKeys() {
  const keys = (latestHashComparison?.duplicate_hash_paths || [])
    .flatMap((item) => Array.isArray(item.keys) ? item.keys : [])
    .map((key) => String(key || "").toLowerCase())
    .filter(Boolean);
  return new Set(keys);
}

function hasDuplicateHashPath(file = {}) {
  return duplicateHashKeys().has(hashComparisonKey(file));
}

function firstFileValue(file = {}, keys = []) {
  for (const key of keys) {
    const value = key.split(".").reduce((current, part) => current?.[part], file);
    if (value !== undefined && value !== null && String(value).trim() !== "") return value;
  }
  return "";
}

function renderFilePropertyRows(file = {}, sha256 = fileHashValue(file), hashChanged = hasHashChanged(file), duplicateHashPath = hasDuplicateHashPath(file)) {
  const owner = filePropertyOwner(file);
  const displayValue = (value) => {
    const text = String(value ?? "").trim();
    return text && text !== "Unknown" && text !== "Not available" ? text : "-";
  };
  const rows = [
    { label: "Owner", value: owner, required: true },
    { label: "Author", value: firstFileValue(file, ["author", "metadata.author", "document_author", "documentAuthor"]), required: true },
    { label: "Created by", value: firstFileValue(file, ["created_by", "creator", "metadata.creator"]) },
    { label: "Modified by", value: firstFileValue(file, ["modified_by", "last_modified_by", "metadata.last_modified_by"]) },
    { label: "Date created", value: fileDateMeta(firstFileValue(file, ["created_at", "createdAt", "created", "creation_time"])), required: true },
    { label: "Date modified", value: fileDateMeta(firstFileValue(file, ["modified_at", "modifiedAt", "last_modified", "mtime"])), required: true },
    { label: "Date accessed", value: fileDateMeta(firstFileValue(file, ["accessed_at", "accessedAt", "last_accessed", "atime"])) },
    { label: "Attributes", value: filePropertyAttributes(file), required: true },
    { label: "Size", value: formatBytes(file.size), required: true },
    { label: "Extension", value: file.extension || "-" },
    { label: "Source", value: file.source || file.share || "workspace" },
    { label: "Share", value: file.share || file.host || file.server || "" },
    { label: "Content status", value: file.content_status || file.scan_error || "" },
    { label: "Scan mode", value: file.scan_mode || "" },
    { label: "SHA-256", value: sha256 ? `<span title="${escapeHtml(sha256)}">${escapeHtml(shortHash(sha256))}</span>` : "-", html: Boolean(sha256), required: true },
    { label: "Hash status", value: hashChanged ? "Hash changed since previous scan" : "" },
    { label: "Duplicate hash", value: duplicateHashPath ? "Same SHA-256 appears at another path" : "" },
    { label: "Path", value: file.path || file.full_path || "", required: true },
  ];

  return rows
    .filter((row) => row.required || (row.value !== undefined && row.value !== null && String(row.value).trim() !== "" && String(row.value).trim() !== "Unknown" && String(row.value).trim() !== "-"))
    .map((row) => `<div><dt>${escapeHtml(row.label)}</dt><dd>${row.html ? row.value : escapeHtml(displayValue(row.value))}</dd></div>`)
    .join("");
}

function hashComparisonKey(file = {}) {
  const path = String(file.path || file.full_path || file.name || "");
  const source = String(file.source || "");
  const share = String(file.share || file.host || file.server || "");
  return `${source}|${share}|${path}`.toLowerCase();
}

function changedHashKeys() {
  return new Set((latestHashComparison?.changed || []).map((item) => String(item.key || "").toLowerCase()).filter(Boolean));
}

function renderProfile() {
  profileName.textContent = currentUser || "User";
  profileTenant.textContent = `${currentTenant || "default"} tenant`;
  // The dock panel is actions-only now; these render only if the elements exist.
  if (profileRole) profileRole.textContent = currentRole || "viewer";
  if (profilePanelName) profilePanelName.textContent = currentUser || "User";
  if (profilePanelTenant) profilePanelTenant.textContent = currentTenant || "default";
  tenantSwitcher.value = currentTenant;
  const initial = (currentUser || "U").trim().charAt(0).toUpperCase();
  const avatarImage = safeStorageGet(profileAvatarStorageKey());
  document.querySelectorAll(".profile-avatar").forEach((item) => {
    applyProfileAvatarElement(item, avatarImage, initial || "U");
  });
}

function displaySummary(summary = {}) {
  // The dashboard shows the whole indexed estate (every source), exactly like
  // Data Inventory. A single scan's summary only wins while it covers MORE
  // than the persisted inventory - e.g. a scan that has not been saved yet.
  if (estateSummary && estateSummary.total_files > Number(summary.total_files || 0)) {
    return estateSummary;
  }
  return summary;
}

function updateSummary(summary = {}) {
  const view = displaySummary(summary);
  animateNumber(document.querySelector("#critical-count"), view.critical || 0);
  animateNumber(document.querySelector("#high-count"), view.high || 0);
  animateNumber(document.querySelector("#medium-count"), view.medium || 0);
  animateNumber(document.querySelector("#low-count"), view.low || 0);
  animateNumber(protectedCount, view.protected_files || 0);
  animateNumber(document.querySelector("#total-count"), view.total_files || 0);
}

function facetsToEstateSummary(facets = {}) {
  const risk = facets.risk_counts || {};
  const total = Number(facets.total || 0);
  if (!total) return null;
  return {
    total_files: total,
    critical: Number(risk.CRITICAL || 0),
    high: Number(risk.HIGH || 0),
    medium: Number(risk.MEDIUM || 0),
    low: Number(risk.LOW || 0),
    protected_files: Number(facets.protected || 0),
    sensitive_files: Number(facets.sensitive || 0),
    hidden_files: Number(facets.hidden || 0),
    posture_score: clampScore(100 - Math.round(Number(facets.avg_risk_score || 0))),
  };
}

async function refreshEstateSummary() {
  if (!accessToken) return;
  try {
    const facets = await api("/api/inventory/facets", null, "GET");
    estateSummary = facetsToEstateSummary(facets);
  } catch {
    estateSummary = null;
  }
  // Repaint the dashboard-facing views now that the estate numbers are known.
  updateSummary(latestReport?.summary || buildCurrentSummary());
  renderExecutiveExperience();
  renderFindingsWorkspace();
}

function updateSummaryFromFiles(files = []) {
  // Compact reports (files_omitted) keep the full file list server-side; the
  // client array is either empty or a bounded top-risk workspace slice.
  // Counting it would misreport the tiles, so the report summary stays the
  // authority for the numbers while the renderers use whatever slice we hold.
  if (latestReport?.files_omitted && latestReport?.summary) {
    updateSummary(latestReport.summary);
    renderReportPreview();
    renderExecutiveExperience();
    renderScanContextPanels();
    renderFindingsWorkspace();
    return;
  }
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
}

function isSampleDataPath(value = "") {
  return /(^|[\\/])enterprise_test_data([\\/]|$)|(^|[\\/])README_enterprise_dataset\.md$|(^|[\\/])_manifest\.json$/i.test(String(value || ""));
}

function isDemoSampleReport(report = {}) {
  if (report.is_demo_sample !== undefined) return Boolean(report.is_demo_sample);
  const files = Array.isArray(report.files) ? report.files : [];
  if (!files.length) return false;
  const sampleCount = files.filter((file) => isSampleDataPath(file.path || file.full_path || file.name || "")).length;
  return sampleCount > 0 && sampleCount / files.length >= 0.5;
}

function clearActiveScanReport(message = "No scan loaded") {
  resetInventoryPageWindow();
  inventoryFacetRequest += 1;
  inventoryFacets = null;
  latestReport = null;
  latestFiles = [];
  latestScanKind = "none";
  fileSearchIndex = new WeakMap();
  renderedRowsLimit = ROW_PAGE_SIZE;
  lastRenderedFileKeys = new Set();
  updateSummaryFromFiles([]);
  renderRows([]);
  scanMeta.textContent = message;
}

function applyScanReport(report, scanKind = "file-server") {
  if (scanKind === "endpoint" && !report?.endpoint) {
    clearActiveScanReport("Endpoint scan did not return endpoint data.");
    return;
  }
  latestReport = report;
  latestFiles = report.files || [];
  latestScanKind = scanKind;
  inventoryFacetRequest += 1;
  inventoryFacets = null;
  fileSearchIndex = new WeakMap();
  renderedRowsLimit = ROW_PAGE_SIZE;
  resetInventoryPageWindow();
  if (report.files_omitted) {
    updateSummary(report.summary || {});
    renderReportPreview();
    renderExecutiveExperience();
    renderScanContextPanels();
    renderFindingsWorkspace();
  } else {
    updateSummaryFromFiles(latestFiles);
  }
  hasRenderedScanRows = true;
  renderRows(latestFiles);
  // The scan just persisted new assets server-side; pull the fresh estate
  // totals so the dashboard reflects every source, not only this scan.
  refreshEstateSummary().catch(() => {});
  scanMeta.textContent = buildScanMetaText(report, scanKind);
  refreshInventoryPageWindow();
  hydrateWorkspaceSlice();
}

// P4: compact reports (files_omitted) deliberately ship no file array, which
// left every latestFiles-driven workspace (remediation queue, findings queue,
// priority files, exposure insights) empty. Hydrate a bounded top-risk slice
// from the inventory API (server-sorted by risk_score) and re-render those
// workspaces from it. Tiles keep using the report summary (see
// updateSummaryFromFiles), so the slice never skews the numbers.
let workspaceSliceRequest = 0;
async function hydrateWorkspaceSlice() {
  if (!latestReport?.files_omitted) return;
  const requestId = ++workspaceSliceRequest;
  const resultsBody = document.getElementById("results-body");
  if (resultsBody && resultsBody.querySelector("td.empty")) {
    // Table-shaped skeleton: one shimmer per column so the load state looks
    // like the data it becomes, not a banner over an empty-state CTA.
    const widths = [86, 62, 48, 40, 46, 78, 78];
    resultsBody.innerHTML = Array.from({ length: 6 }, () =>
      "<tr class=\"skl-tr\">" + widths.map((w) =>
        `<td><div class="skl" style="height:12px;width:${w}%"></div></td>`).join("") + "</tr>").join("");
  }
  try {
    const data = await api("/api/inventory?sort=risk_score&limit=200", null, "GET");
    if (requestId !== workspaceSliceRequest || !latestReport?.files_omitted) return;
    const items = (data?.items || []).map((item) => hydrateInventoryPageItem(item));
    if (!items.length) return;
    latestFiles = items;
    fileSearchIndex = new WeakMap();
    renderReportPreview();
    renderExecutiveExperience();
    renderScanContextPanels();
    renderFindingsWorkspace();
  } catch (_) {
    // Workspaces stay on the summary-only view; the inventory table is
    // unaffected (it reads its own page window).
  }
}

function buildScanMetaText(report = latestReport, scanKind = latestScanKind) {
  if (!report) return "No scan has been run yet.";
  const source = scanKind === "endpoint"
    ? report.endpoint?.host || report.source || "endpoint"
    : report.source || readPayload().server || "file server";
  const label = scanKind === "endpoint" ? "endpoint files" : "files";
  const incremental = report.scan_diagnostics?.incremental || report.endpoint?.scan_diagnostics?.incremental || {};
  const delta = incremental.enabled
    ? ` Â· ${Number(incremental.unchanged_objects || 0)} unchanged reused Â· ${Number(incremental.content_reads || 0)} content reads`
    : " Â· full scan";
  return `${activeReportFileCount()} ${label} scanned from ${source} at ${report.timestamp || "latest run"}${delta}`;
}

function activeReportFileCount() {
  return Number(latestReport?.file_count || latestReport?.result_file_count || latestReport?.summary?.total_files || latestFiles.length || 0);
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
  const protectedFiles = Number(summary.protected_files || latestFiles.filter(isProtectedFile).length || 0);
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
    const summary = displaySummary(buildCurrentSummary());
    if (summary.total_files) {
      findingsSignalSummary.className = "summary-list";
      findingsPrioritySummary.className = "summary-list";
      findingsSignalSummary.innerHTML = `
        <div class="finding-kpi-grid">
          <div class="finding-kpi critical"><span>Critical files</span><strong>${escapeHtml(summary.critical || 0)}</strong></div>
          <div class="finding-kpi high"><span>High-risk files</span><strong>${escapeHtml(summary.high || 0)}</strong></div>
          <div class="finding-kpi medium"><span>Protected / locked</span><strong>${escapeHtml(summary.protected_files || 0)}</strong></div>
        </div>
        <div class="summary-row finding-signal-row"><span>Inventory mode</span><strong>Windowed</strong></div>
      `;
      findingsPrioritySummary.innerHTML = `
        <div class="summary-row finding-file-card HIGH"><span><b>${escapeHtml(summary.total_files)} assets indexed</b><small>Open Data Inventory to query bounded pages and load evidence on demand.</small></span><strong class="badge HIGH">LIVE</strong></div>
      `;
      return;
    }
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
  const findingRows = buildFindingQueueRows();
  const regulatedFiles = latestFiles.filter((file) => (file.findings || []).some(isRegulatedFinding));
  const secretFiles = latestFiles.filter((file) => (file.findings || []).some(isSecretFinding));
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
  findingsPrioritySummary.innerHTML = findingRows.length
    ? renderFindingQueueTable(findingRows.slice(0, 25))
    : '<div class="empty compact">No priority finding queue for the latest scan.</div>';
}

function buildFindingQueueRows() {
  const rows = [];
  latestFiles.forEach((file) => {
    primaryFindingsForFile(file).forEach((finding) => {
      // Inventory-hydrated slices summarize findings without per-finding risk;
      // fall back to the file's effective level so the queue still triages.
      const level = String(finding.risk || finding.severity || getEffectiveRisk(file).level || "LOW").toUpperCase();
      rows.push({
        file,
        finding,
        severity: level,
        score: severityScore(level),
        confidence: findingConfidenceLabel(finding),
        framework: findingFrameworkText(finding),
        dataElement: finding.data_element || finding.data_category || finding.personal_data_type || finding.category || "",
        asset: file.asset_id || file.host_id || file.name || file.path || "Unknown asset",
        location: findingLocationText(file, finding),
        exposure: findingExposureText(file, finding),
        occurrences: findingOccurrenceCount(finding),
        uniqueRecords: findingUniqueRecordCount(finding),
        status: finding.review_status || finding.workflow_status || finding.status || "Open",
        owner: finding.data_owner || file.owner || file.department || "Unassigned",
        sla: finding.sla || file.risk?.remediation?.sla || slaForSeverity(level),
        lastSeen: finding.last_seen || file.last_scanned_at || file.modified || "",
      });
    });
  });
  return rows.sort((a, b) => b.score - a.score || b.occurrences - a.occurrences);
}

function severityScore(level = "LOW") {
  const normalized = String(level || "LOW").toUpperCase();
  return { CRITICAL: 95, HIGH: 80, MEDIUM: 55, LOW: 20 }[normalized] || 0;
}

// U-C: the queue shows 8 primary columns an operator scans at a glance; the
// remaining 7 fields (confidence, protection state, exposure, occurrences,
// unique records, owner, last seen) are demoted into a per-row expander so the
// table stays legible without losing any data.
// P4: every primary column is click-sortable (severity by score, the rest as
// text); the active column carries aria-sort and re-renders the workspace.
let findingQueueSort = { key: "score", dir: -1 };

const FINDING_QUEUE_SORT_KEYS = {
  score: (row) => row.score,
  finding: (row) => findingDisplayName(row.finding) || "",
  framework: (row) => row.framework || "",
  dataElement: (row) => row.dataElement || "",
  asset: (row) => row.asset || "",
  location: (row) => row.location || "",
  status: (row) => row.status || "",
  sla: (row) => row.sla || "",
};

function sortFindingQueueRows(rows) {
  const pick = FINDING_QUEUE_SORT_KEYS[findingQueueSort.key] || FINDING_QUEUE_SORT_KEYS.score;
  const dir = findingQueueSort.dir;
  return [...rows].sort((a, b) => {
    const left = pick(a);
    const right = pick(b);
    if (typeof left === "number" && typeof right === "number") return (left - right) * dir;
    return String(left).localeCompare(String(right)) * dir;
  });
}

function findingQueueHeader(label, key, extraClass = "") {
  const active = findingQueueSort.key === key;
  const ariaSort = active ? (findingQueueSort.dir === 1 ? "ascending" : "descending") : "none";
  return `<th data-sort="${key}" aria-sort="${ariaSort}"${extraClass ? ` class="${extraClass}"` : ""}>${label}</th>`;
}

function renderFindingQueueTable(rows) {
  rows = sortFindingQueueRows(rows);
  return `
    <div class="report-register-wrap finding-queue-wrap">
      <table class="report-register-table finding-queue-table">
        <thead>
          <tr>${findingQueueHeader("Severity", "score")}${findingQueueHeader("Finding", "finding")}${findingQueueHeader("Framework", "framework")}${findingQueueHeader("Data Element", "dataElement")}${findingQueueHeader("Asset", "asset")}${findingQueueHeader("Exact Location", "location")}${findingQueueHeader("Status", "status")}${findingQueueHeader("SLA", "sla")}<th class="finding-expand-col" aria-label="More detail"></th></tr>
        </thead>
        <tbody>
          ${rows.map(({ file, finding, severity, confidence, framework, dataElement, asset, location, exposure, occurrences, uniqueRecords, status, owner, sla, lastSeen }) => {
            const fileKeyValue = fileKey(file);
            const identity = findingIdentity(finding);
            return `
            <tr class="finding-summary-row">
              <td><span class="badge ${escapeHtml(severity)}">${escapeHtml(severity)}</span></td>
              <td class="fq-name" title="${escapeHtml(findingDisplayName(finding))}"><strong>${escapeHtml(findingDisplayName(finding))}</strong></td>
              <td><div class="framework-pill-row fq-frameworks">${findingFrameworkBadges(finding)}</div></td>
              <td class="fq-clip" title="${escapeHtml(dataElement)}">${escapeHtml(dataElement)}</td>
              <td class="fq-clip" title="${escapeHtml(asset)}">${escapeHtml(asset)}</td>
              <td class="fq-clip fq-mono" title="${escapeHtml(location)}">${escapeHtml(location)}</td>
              <td>${escapeHtml(status)}</td>
              <td class="fq-clip">${escapeHtml(sla)}</td>
              <td class="finding-expand-col"><button type="button" class="finding-open-btn" data-finding-file-key="${escapeHtml(fileKeyValue)}" data-finding-identity="${escapeHtml(identity)}" aria-haspopup="dialog" aria-label="Open finding evidence for ${escapeHtml(findingDisplayName(finding))}" title="Open finding evidence"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6"></path><path d="M20 4 11.5 12.5"></path><path d="M10 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-4"></path></svg></button></td>
            </tr>
          `}).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function findingIdentity(finding = {}) {
  return [
    finding.rule_id,
    finding.type,
    finding.display_name,
    finding.label,
    finding.data_element,
    finding.category_id || finding.category,
  ].map((value) => String(value || "").trim().toLowerCase()).join("|");
}

function findInventoryFileByKey(key) {
  return latestFiles.find((item) => fileKey(item) === key)
    || currentInventoryPage()?.items.find((item) => fileKey(item) === key)
    || null;
}

function findFindingByIdentity(file, identity, fallback = null) {
  const findings = primaryFindingsForFile(file);
  return findings.find((item) => findingIdentity(item) === identity)
    || findings.find((item) => findingDisplayName(item).toLowerCase() === findingDisplayName(fallback || {}).toLowerCase())
    || fallback
    || findings[0]
    || {};
}

// A queue row opens the same pop-up as the Data inventory, landed on the
// Findings tab (the dossier that holds this finding's group).
document.addEventListener("click", (event) => {
  const btn = event.target.closest(".finding-open-btn");
  if (!btn) return;
  openAssetDetailModal(btn.dataset.findingFileKey || "", "findings");
});

// P4: delegated sort for the finding-queue headers. Clicking the active column
// flips direction; a new column starts descending (worst first).
document.addEventListener("click", (event) => {
  const th = event.target.closest(".finding-queue-table th[data-sort]");
  if (!th) return;
  const key = th.dataset.sort;
  if (findingQueueSort.key === key) {
    findingQueueSort.dir *= -1;
  } else {
    findingQueueSort = { key, dir: -1 };
  }
  renderFindingsWorkspace();
});

function primaryFindingsForFile(file) {
  return (file?.findings || []).filter((finding) => String(finding.display_state || "").toLowerCase() !== "child_evidence");
}

function childFindingsFor(file, parent) {
  const parentType = String(parent?.type || "");
  const parentRule = String(parent?.rule_id || "");
  return (file?.findings || []).filter((finding) => {
    if (String(finding.display_state || "").toLowerCase() !== "child_evidence") return false;
    const suppressedBy = String(finding.suppressed_by || "");
    return suppressedBy === parentType || suppressedBy === parentRule || (parent.child_finding_types || []).includes(finding.type);
  });
}

function isRegulatedFinding(finding = {}) {
  const frameworks = findingFrameworks(finding);
  const domain = String(finding.classification_domain || "").toLowerCase();
  const category = String(finding.data_category || finding.category || "").toLowerCase();
  return frameworks.some((item) => ["gdpr", "pci_dss", "hipaa", "nist_sp800_60_enterprise"].includes(item)) || domain.startsWith("regulated") || domain.startsWith("privacy") || domain.startsWith("nist") || category.startsWith("pci_") || category.startsWith("nist_");
}

function isSecretFinding(finding = {}) {
  const domain = String(finding.classification_domain || "").toLowerCase();
  const category = String(finding.data_category || finding.category || finding.finding_category || "").toLowerCase();
  return domain === "secrets" || category.includes("credential") || category.includes("secret");
}

function selectedFrameworkScope() {
  const complianceSummary = latestReport?.compliance_summary;
  if (complianceSummary && complianceSummary.enabled === false) return [];
  const fromReport = complianceSummary?.selected_frameworks || complianceSummary?.selected_framework_ids || [];
  if (fromReport.length) {
    return [...new Set(fromReport.map(normalizeFrameworkId).filter((item) => item && item !== "generic"))];
  }
  const fromPayload = readPayload().compliance_frameworks || [];
  return [...new Set(fromPayload.map(normalizeFrameworkId).filter((item) => item && item !== "generic"))];
}

function normalizeFrameworkId(value = "") {
  const normalized = String(value || "").trim().toLowerCase().replace(/[-\s]+/g, "_");
  const compact = normalized.replace(/[^a-z0-9]/g, "");
  if (normalized === "pci" || normalized === "pci_dss") return "pci_dss";
  if (["nist", "nist_sp800_60", "nist_sp800_60_enterprise"].includes(normalized) || ["nistsp80060", "nistsp80060enterprise"].includes(compact)) return "nist_sp800_60_enterprise";
  if (normalized === "gdpr") return "gdpr";
  return normalized || "generic";
}

function frameworkClass(value = "") {
  const framework = normalizeFrameworkId(value);
  if (framework === "nist_sp800_60_enterprise") return "framework-nist nist_sp800_60_enterprise";
  if (framework === "pci_dss") return "framework-pci pci_dss";
  if (framework === "gdpr") return "framework-gdpr gdpr";
  return "framework-generic generic";
}

function allFindingFrameworks(finding = {}) {
  const frameworks = Array.isArray(finding.frameworks) ? [...finding.frameworks] : [];
  if (Array.isArray(finding.mapped_frameworks)) frameworks.push(...finding.mapped_frameworks);
  if (Array.isArray(finding.framework_mappings)) {
    finding.framework_mappings.forEach((item) => {
      if (typeof item === "string") frameworks.push(item);
      else frameworks.push(item.framework || item.framework_id || item.name || "");
    });
  }
  if (Array.isArray(finding.requirement_mappings)) {
    finding.requirement_mappings.forEach((item) => frameworks.push(item.framework || item.framework_id || ""));
  }
  if (finding.framework) frameworks.push(finding.framework);
  return [...new Set(frameworks.map(normalizeFrameworkId).filter(Boolean))];
}

function findingFrameworks(finding = {}, { scoped = true } = {}) {
  if (latestReport?.compliance_summary?.enabled === false) return [];
  const frameworks = allFindingFrameworks(finding);
  if (!scoped) return frameworks;
  const selected = selectedFrameworkScope();
  if (!selected.length) return frameworks;
  const primary = normalizeFrameworkId(finding.framework);
  const scopedFrameworks = frameworks.filter((framework) => {
    if (framework === primary && framework !== "generic") return true;
    return selected.includes(framework);
  });
  if (scopedFrameworks.length) return [...new Set(scopedFrameworks)];
  return primary && primary !== "generic" ? [primary] : frameworks.filter((framework) => framework !== "gdpr");
}

function findingVisualFramework(finding = {}) {
  const primary = normalizeFrameworkId(finding.framework);
  if (["nist_sp800_60_enterprise", "pci_dss", "gdpr"].includes(primary)) return primary;
  const selected = selectedFrameworkScope();
  const frameworks = allFindingFrameworks(finding);
  for (const framework of selected) {
    if (frameworks.includes(framework)) return framework;
  }
  return frameworks.find((framework) => framework !== "generic") || primary || "generic";
}

function findingFrameworkText(finding = {}) {
  const frameworks = findingFrameworks(finding);
  if (frameworks.length) return frameworks.map(frameworkLabel).join(", ");
  return "Unmapped";
}

function isNistFinding(finding = {}) {
  return findingFrameworks(finding, { scoped: false }).includes("nist_sp800_60_enterprise")
    || String(finding.type || finding.rule_id || "").toLowerCase().startsWith("nist_");
}

function frameworkLabel(framework = "") {
  const normalized = normalizeFrameworkId(framework || "standard_scan");
  if (normalized === "pci_dss") return "PCI DSS";
  if (normalized === "nist_sp800_60_enterprise") return "NIST";
  if (normalized === "gdpr") return "GDPR";
  if (normalized === "hipaa") return "HIPAA";
  return "Standard scan";
}

function findingFrameworkBadges(finding = {}, options = {}) {
  const frameworks = findingFrameworks(finding, options);
  const values = frameworks.length ? frameworks : ["standard_scan"];
  return values.map((framework) => {
    const normalized = normalizeFrameworkId(framework || "standard_scan");
    const label = frameworkLabel(normalized);
    return `<span class="framework-pill ${escapeHtml(frameworkClass(normalized))}">${escapeHtml(label)}</span>`;
  }).join("");
}

function findingFrameworkStrip(findings = []) {
  const values = new Set();
  findings.forEach((finding) => {
    const frameworks = findingFrameworks(finding);
    (frameworks.length ? frameworks : ["standard_scan"]).forEach((framework) => {
      const normalized = normalizeFrameworkId(framework || "standard_scan");
      values.add(normalized);
    });
  });
  return [...values].map((framework) => {
    const normalized = normalizeFrameworkId(framework);
    const label = frameworkLabel(normalized);
    return `<span class="framework-pill ${escapeHtml(frameworkClass(normalized))}">${escapeHtml(label)}</span>`;
  }).join("");
}

function findingConfidenceLabel(finding = {}) {
  const value = finding.detection_confidence ?? finding.confidence ?? finding.mapping_confidence;
  if (typeof value === "number") {
    if (value >= 85) return "High";
    if (value >= 60) return "Medium";
    return "Low";
  }
  const normalized = String(value || "").trim();
  return normalized ? normalized.charAt(0).toUpperCase() + normalized.slice(1) : "Unknown";
}

function findingOccurrenceCount(finding = {}) {
  return Number(finding.occurrence_count || finding.count || 1);
}

function findingUniqueRecordCount(finding = {}) {
  if (finding.unique_value_count !== undefined) return Number(finding.unique_value_count || 0);
  const fingerprints = finding.secure_value_fingerprints || finding.secure_fingerprints || [];
  if (Array.isArray(fingerprints) && fingerprints.length) return new Set(fingerprints.map(String)).size;
  const samples = finding.samples || [];
  if (Array.isArray(samples) && samples.length) return new Set(samples.map(String)).size;
  return 1;
}

function findingLocationText(file = {}, finding = {}) {
  const occurrence = Array.isArray(finding.occurrences) ? finding.occurrences[0] || {} : {};
  const parts = [
    occurrence.file || file.path || file.name,
    occurrence.line ? `line ${occurrence.line}` : "",
    occurrence.page ? `page ${occurrence.page}` : "",
    occurrence.sheet ? `sheet ${occurrence.sheet}` : "",
    occurrence.row ? `row ${occurrence.row}` : "",
    occurrence.column ? `column ${occurrence.column}` : "",
    occurrence.JSONPath || occurrence.json_path || "",
    occurrence.XPath || occurrence.xpath || "",
    occurrence.table ? `${occurrence.schema || ""}.${occurrence.table}.${occurrence.column || ""}`.replace(/^\./, "") : "",
  ].filter(Boolean);
  return parts.join(" / ") || file.path || file.name || "unknown";
}

function findingExposureText(file = {}, finding = {}) {
  const permissions = file.permissions || {};
  if (finding.exposure_state) return finding.exposure_state;
  if (permissions.public || permissions.wide_access) return "Broad access";
  if (permissions.writable) return "Writable share";
  if (file.source === "smb") return "SMB share";
  return "Limited or unknown";
}

function slaForSeverity(level = "LOW") {
  return level === "CRITICAL" ? "24 hours" : level === "HIGH" ? "3 business days" : level === "MEDIUM" ? "14 days" : "30 days";
}

function list(items) {
  if (!items || items.length === 0) {
    return '<span class="subtext">None</span>';
  }

  return `<ul class="list">${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

const DETAIL_CELL_META = {
  reasons: {
    icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 16v-4M12 8h.01"/></svg>',
    noun: "reason",
    plural: "reasons",
    title: "Why this file is risky - opens the Reasons tab",
  },
  recommendations: {
    icon: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M14.7 6.3a4.5 4.5 0 0 0-6 6L3 18l3 3 5.7-5.7a4.5 4.5 0 0 0 6-6l-2.8 2.8-2.2-2.2z"/></svg>',
    noun: "fix",
    plural: "fixes",
    title: "Recommended fixes - opens the Actions tab",
  },
};

function detailCellMarkup(count, file, type) {
  const meta = DETAIL_CELL_META[type] || DETAIL_CELL_META.reasons;
  if (!count) return `<span class="subtext">No ${escapeHtml(meta.plural)} yet</span>`;
  return `
    <button type="button" class="detail-toggle detail-cell-btn" data-detail-type="${escapeHtml(type)}" data-detail-key="${escapeHtml(fileKey(file))}" title="${escapeHtml(meta.title)}">
        <span class="detail-cell-ico" aria-hidden="true">${meta.icon}</span>
        <span class="detail-toggle-label">${escapeHtml(count)} ${escapeHtml(count === 1 ? meta.noun : meta.plural)}</span>
    </button>
  `;
}

function countDetailButton(count, file, type, label, emptyText) {
  return detailCellMarkup(count, file, type);
}

function lazyDetailButton(file, type, label) {
  const meta = DETAIL_CELL_META[type] || DETAIL_CELL_META.reasons;
  return `
    <button type="button" class="detail-toggle detail-cell-btn detail-toggle-lazy" data-detail-type="${escapeHtml(type)}" data-detail-key="${escapeHtml(fileKey(file))}" title="${escapeHtml(meta.title)}">
        <span class="detail-cell-ico" aria-hidden="true">${meta.icon}</span>
        <span class="detail-toggle-label">&hellip;</span>
    </button>
  `;
}

function refreshInventorySummaryCells(file) {
  const row = resultsBody?.querySelector(`tr[data-file-key="${CSS.escape(fileKey(file))}"]`);
  if (!row) return;
  const cells = row.querySelectorAll("td");
  if (cells.length < 7) return;
  const loaded = !file.__inventory_page_item || file.__inventory_detail_loaded;
  cells[5].innerHTML = loaded
    ? detailButton(file.risk?.reasons || [], file, "reasons", "Reasons", "No reasons")
    : detailCellMarkup(file.reason_count || 0, file, "reasons");
  cells[6].innerHTML = loaded
    ? detailButton(file.risk?.dlp_recommendations || [], file, "recommendations", "DLP actions", "No actions")
    : detailCellMarkup(file.dlp_count || 0, file, "recommendations");
}

function detailButton(items, file, type, label, emptyText) {
  if (DETAIL_CELL_META[type]) return detailCellMarkup((items || []).length, file, type);
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

function currentInventoryPage() {
  return inventoryPageWindow.pages.get(inventoryPageWindow.pageIndex) || null;
}

function resetInventoryPageWindow(active = false) {
  inventoryPageAbortController?.abort();
  inventoryPageAbortController = null;
  inventoryPageRequest += 1;
  inventoryPageWindow = createInventoryPageWindow(active);
  resultsBody?.setAttribute("aria-busy", "false");
}

function renderInventoryRiskSelection() {
  inventoryRiskFilters.forEach((button) => {
    const active = (button.dataset.riskFilter || "ALL") === inventoryRiskFilter;
    button.classList.toggle("active", active);
    button.setAttribute("aria-pressed", String(active));
  });
}

function canUseInventoryPageWindow() {
  // S-E.2 represents every inventory facet on the server. Browser-local risk
  // overrides may still change a displayed row, but they never force the
  // browser to hydrate the unbounded saved report.
  return Boolean(accessToken && latestReport?.scan_id);
}

function inventoryDetailKey(file = {}) {
  return `${String(file.path || "").toLowerCase()}|${String(file.name || "").toLowerCase()}`;
}

function summarizedInventoryFindings(item = {}) {
  const count = Number(item.finding_count || 0);
  if (!count) return [];
  const frameworks = String(item.top_frameworks || "")
    .split(",")
    .map((framework) => normalizeFrameworkId(framework.trim()))
    .filter(Boolean);
  const types = parseInventoryListField(item.finding_types);
  return (types.length ? types : ["Indexed findings"]).map((type, index) => ({
    type,
    count: index === 0 ? count : 1,
    framework: frameworks[0] || "standard_scan",
    frameworks,
    description: "Summary from the normalized inventory index. Open this row to load full finding evidence.",
  }));
}

function parseInventoryListField(value) {
  if (Array.isArray(value)) return value.map(String).filter(Boolean);
  try {
    const parsed = JSON.parse(String(value || "[]"));
    return Array.isArray(parsed) ? parsed.map(String).filter(Boolean) : [];
  } catch {
    return [];
  }
}

function hydrateInventoryPageItem(item = {}) {
  const detailKey = inventoryDetailKey(item);
  const detail = latestFiles.find((file) => inventoryDetailKey(file) === detailKey);
  return {
    ...(detail || {}),
    ...item,
    protected: detail?.protected ?? Boolean(item.is_protected),
    risk: detail?.risk || {
      level: String(item.risk_level || "LOW").toUpperCase(),
      score: Number(item.risk_score || 0),
      reasons: [],
      dlp_recommendations: [],
    },
    findings: detail?.findings || summarizedInventoryFindings(item),
    __inventory_page_item: true,
  };
}

function inventoryFilterParams() {
  const params = new URLSearchParams();
  const query = filterInput?.value?.trim() || "";
  if (!["ALL", "PROTECTED"].includes(inventoryRiskFilter)) params.set("risk", inventoryRiskFilter);
  if (inventoryRiskFilter === "PROTECTED") params.set("protected", "true");
  if (inventorySourceFacet !== "ALL") params.set("source", inventorySourceFacet);
  if (inventoryFindingFacet === "Protected / locked") params.set("protected", "true");
  else if (inventoryFindingFacet !== "ALL") params.set("finding_type", inventoryFindingFacet);
  if (inventoryFrameworkFacets.size) params.set("framework", [...inventoryFrameworkFacets].join(","));
  if (query) params.set("q", query);
  return params;
}

// Sorting is a SERVER concern: the API orders the whole inventory and returns
// one keyset page, so clicking a column sorts every file in the tenant - not
// just the rows already loaded in the browser.
let inventorySortKey = "risk_score";

function inventoryPageQuery(cursor = "") {
  const params = inventoryFilterParams();
  params.set("sort", inventorySortKey);
  params.set("limit", String(INVENTORY_SERVER_PAGE_SIZE));
  if (cursor) params.set("after", cursor);
  return params.toString();
}

function inventoryExportQuery(format) {
  const params = inventoryFilterParams();
  params.set("format", format);
  return params.toString();
}

async function streamInventoryExport(format) {
  requireAuth();
  if (typeof window.showSaveFilePicker !== "function" || typeof WritableStream === "undefined") {
    throw new Error("This browser cannot stream authenticated downloads to disk. Use current Chrome or Edge, or call /api/inventory/export with an API client.");
  }

  const extension = format === "csv" ? "csv" : "ndjson";
  [inventoryExportCsvBtn, inventoryExportNdjsonBtn].forEach((button) => {
    if (button) button.disabled = true;
  });
  if (inventoryExportStatus) inventoryExportStatus.textContent = `Preparing ${extension.toUpperCase()} export.`;
  try {
    const picker = await window.showSaveFilePicker({
      suggestedName: `sentro-inventory-${new Date().toISOString().slice(0, 10)}.${extension}`,
      types: [{
        description: format === "csv" ? "CSV inventory" : "NDJSON inventory",
        accept: { [format === "csv" ? "text/csv" : "application/x-ndjson"]: [`.${extension}`] },
      }],
    });
    const writable = await picker.createWritable();
    const response = await fetch(`/api/inventory/export?${inventoryExportQuery(format)}`, {
      method: "GET",
      headers: authHeaders(),
    });
    try {
      if (!response.ok) throw new Error(`${response.status}: ${await readErrorMessage(response)}`);
      if (!response.body) throw new Error("The browser did not expose the export response stream.");
      if (inventoryExportStatus) inventoryExportStatus.textContent = `Streaming ${extension.toUpperCase()} directly to disk.`;
      await response.body.pipeTo(writable);
    } catch (error) {
      try { await writable.abort(); } catch { /* already closed or aborted */ }
      throw error;
    }
    if (inventoryExportStatus) inventoryExportStatus.textContent = `${extension.toUpperCase()} inventory export complete.`;
    showToast("Inventory export complete", `${extension.toUpperCase()} was streamed directly to disk.`, "success");
  } catch (error) {
    if (inventoryExportStatus) {
      inventoryExportStatus.textContent = error?.name === "AbortError" ? "Inventory export cancelled." : "Inventory export failed.";
    }
    throw error;
  } finally {
    [inventoryExportCsvBtn, inventoryExportNdjsonBtn].forEach((button) => {
      if (button) button.disabled = false;
    });
  }
}

async function refreshInventoryFacets() {
  if (!canUseInventoryPageWindow()) return;
  const scanId = latestReport?.scan_id;
  const requestId = ++inventoryFacetRequest;
  try {
    const facets = await api("/api/inventory/facets", null, "GET");
    if (requestId !== inventoryFacetRequest || latestReport?.scan_id !== scanId) return;
    inventoryFacets = facets;
    const page = currentInventoryPage();
    if (page) renderRows(page.items, { serverPage: page });
  } catch (error) {
    if (requestId === inventoryFacetRequest) {
      inventoryFacets = null;
      setStatus(`Inventory facets unavailable: ${error.message}`);
    }
  }
}

function trimInventoryPageCache() {
  while (inventoryPageWindow.pages.size > INVENTORY_MAX_CACHED_PAGES) {
    const candidates = [...inventoryPageWindow.pages.keys()]
      .filter((index) => index !== inventoryPageWindow.pageIndex)
      .sort((a, b) => Math.abs(b - inventoryPageWindow.pageIndex) - Math.abs(a - inventoryPageWindow.pageIndex));
    if (!candidates.length) break;
    inventoryPageWindow.pages.delete(candidates[0]);
  }
}

function renderInventoryPageLoading() {
  resultsBody.setAttribute("aria-busy", "true");
  resultsBody.innerHTML = `<tr><td colspan="7" class="empty inventory-window-status">
    <strong>Loading inventory page...</strong>
    <span>The browser keeps only a bounded page window while the database filters and sorts.</span>
  </td></tr>`;
}

async function loadInventoryWindowPage(pageIndex = 0) {
  if (!inventoryPageWindow.active) return;
  inventoryPageAbortController?.abort();
  inventoryPageAbortController = null;
  const requestId = ++inventoryPageRequest;
  const cached = inventoryPageWindow.pages.get(pageIndex);
  inventoryPageWindow.pageIndex = pageIndex;
  if (cached) {
    resultsBody.setAttribute("aria-busy", "false");
    renderRows(cached.items, { serverPage: cached });
    return;
  }

  const cursor = inventoryPageWindow.pageStarts[pageIndex];
  if (cursor === undefined) return;
  const controller = new AbortController();
  inventoryPageAbortController = controller;
  inventoryPageWindow.loading = true;
  renderInventoryPageLoading();
  try {
    const data = await api(`/api/inventory?${inventoryPageQuery(cursor)}`, null, "GET", { signal: controller.signal });
    if (requestId !== inventoryPageRequest || !inventoryPageWindow.active) return;
    const page = {
      items: (data.items || []).map(hydrateInventoryPageItem),
      nextCursor: data.next_cursor || "",
      hasMore: Boolean(data.has_more),
      total: Number(data.total || 0),
      totalIsEstimate: Boolean(data.total_is_estimate),
      source: String(data.source || "database"),
    };
    inventoryPageWindow.pages.set(pageIndex, page);
    if (page.hasMore && page.nextCursor) inventoryPageWindow.pageStarts[pageIndex + 1] = page.nextCursor;
    inventoryPageWindow.loading = false;
    resultsBody.setAttribute("aria-busy", "false");
    trimInventoryPageCache();
    renderRows(page.items, { serverPage: page });
  } catch (error) {
    if (error?.name === "AbortError" || requestId !== inventoryPageRequest) return;
    inventoryPageWindow.loading = false;
    resultsBody.setAttribute("aria-busy", "false");
    inventoryPageWindow.error = error.message;
    inventoryPageWindow.active = false;
    renderedRowsLimit = ROW_PAGE_SIZE;
    renderRows(latestFiles);
    setStatus(latestFiles.length
      ? `Windowed inventory unavailable; using the bounded local preview: ${error.message}`
      : `Windowed inventory unavailable; no report blob was loaded: ${error.message}`);
  } finally {
    if (inventoryPageAbortController === controller) inventoryPageAbortController = null;
  }
}

function refreshInventoryPageWindow() {
  if (!canUseInventoryPageWindow()) {
    resetInventoryPageWindow();
    renderedRowsLimit = ROW_PAGE_SIZE;
    renderRows(latestFiles);
    return;
  }
  resetInventoryPageWindow(true);
  if (!inventoryFacets) refreshInventoryFacets();
  loadInventoryWindowPage(0);
}

function inventoryWindowControls(page) {
  const pageIndex = inventoryPageWindow.pageIndex;
  const start = page.total ? (pageIndex * INVENTORY_SERVER_PAGE_SIZE) + 1 : 0;
  const end = start ? start + page.items.length - 1 : 0;
  const totalLabel = `${page.total}${page.totalIsEstimate ? "+" : ""}`;
  return `<tr class="inventory-window-row"><td colspan="7">
    <div class="inventory-window-controls" aria-label="Inventory page controls" role="status" aria-live="polite">
      <button type="button" class="secondary-btn mini-btn" data-inventory-page="previous" ${pageIndex === 0 ? "disabled" : ""}>Previous page</button>
      <span><strong>${start}-${end}</strong> of ${totalLabel} files · page ${pageIndex + 1} · ${escapeHtml(page.source)} source</span>
      <button type="button" class="secondary-btn mini-btn" data-inventory-page="next" ${!page.hasMore ? "disabled" : ""}>Next page</button>
    </div>
  </td></tr>`;
}

function renderRows(files, options = {}) {
  if (!options.serverPage && inventoryPageWindow.active && currentInventoryPage()) {
    const current = currentInventoryPage();
    renderRows(current.items, { serverPage: current });
    return;
  }
  const serverPage = options.serverPage || null;
  const visible = serverPage ? (files || []) : getVisibleInventoryFiles(files);
  const page = serverPage ? visible : visible.slice(0, renderedRowsLimit);
  const currentKeys = new Set(page.map((file) => fileKey(file)));
  const hashChangedKeys = changedHashKeys();
  const duplicateHashPathKeys = duplicateHashKeys();
  renderInventoryControlState(serverPage ? latestFiles : files, visible, serverPage);

  if (visible.length === 0) {
    const hasAnyFiles = Boolean(serverPage ? latestFiles.length || serverPage.total : files?.length);
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
      const rawFindings = primaryFindingsForFile(file);
      const recommendations = file.risk?.dlp_recommendations || [];
      const reasons = file.risk?.reasons || [];
      // Windowed page items carry no reasons/actions until the on-demand
      // detail loads - the collapsed cell must say "view", never "none".
      const lazyDetail = Boolean(file.__inventory_page_item && !file.__inventory_detail_loaded && file.id);
      const effectiveRisk = getEffectiveRisk(file);
      const level = effectiveRisk.level;
      const score = effectiveRisk.score;
      const key = fileKey(file);
      const hashChanged = hashChangedKeys.has(hashComparisonKey(file));
      const duplicateHashPath = duplicateHashPathKeys.has(hashComparisonKey(file));
      const flash = !serverPage && hasRenderedScanRows && !lastRenderedFileKeys.has(key) ? " row-flash" : "";
      const fileFlags = [
        file.is_hidden ? "Hidden" : "",
        file.is_system ? "System" : "",
        file.scan_mode === "archive_entry" || String(file.path || "").includes("::") ? "Archive" : "",
        file.content_status === "metadata_only" ? "Metadata only" : "",
        isProtectedFile(file) ? "Protected / locked" : "",
      ].filter(Boolean);
      const riskLabel = buildRiskLabel(level, score);
      const integrityFindings = [
        hashChanged ? { type: "Hash changed", count: 1 } : null,
        duplicateHashPath ? { type: "Duplicate hash path", count: 1 } : null,
      ].filter(Boolean);
      const displayFindings = integrityFindings.length ? [...rawFindings, ...integrityFindings] : rawFindings;
      const visibleFindingChips = displayFindings.filter((finding) => !isNistFinding(finding));
      const findingChips = visibleFindingChips.length
        ? visibleFindingChips.map((finding) => `<span class="finding-chip ${escapeHtml(frameworkClass(findingVisualFramework(finding)))}">${escapeHtml(findingDisplayName(finding))} <b>${escapeHtml(finding.count || 1)}</b></span>`).join("")
        : displayFindings.length ? "" : '<span class="subtext">No sensitive signals</span>';
      const frameworkStrip = displayFindings.length ? `<div class="finding-framework-strip">${findingFrameworkStrip(displayFindings)}</div>` : "";
      const hiddenFindingCount = Math.max(0, displayFindings.length - Math.min(visibleFindingChips.length, 4));
      const moreFindings = hiddenFindingCount > 0
        ? `<button type="button" class="detail-toggle finding-chip muted-chip" data-detail-type="findings" data-detail-key="${escapeHtml(key)}" title="Show all findings and matched keywords">+${hiddenFindingCount}</button>`
        : "";
      // The scan a customer named, falling back to the collector protocol.
      const sourceName = getInventorySourceValue(file);
      const path = file.path || file.name || "";
      const sha256 = fileHashValue(file);

      const rowFrameworkClass = "";
      const copyPathButton = path
        ? `<button type="button" class="icon-mini-btn copy-path-btn" data-copy-text="${escapeHtml(path)}" title="Copy full path" aria-label="Copy full file path"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"></rect><path d="M15 9V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v7a2 2 0 0 0 2 2h3"></path></svg><span>Copy path</span></button>`
        : "";

      return `
        <tr class="${flash} severity-row ${level} ${escapeHtml(rowFrameworkClass)}" data-file-key="${escapeHtml(key)}">
          <td>
            <div class="file-title polished-file-title">
              <button type="button" class="preview-toggle inventory-row-expand" data-inventory-expand="${escapeHtml(key)}" title="Open asset &amp; scan detail" aria-label="Open asset and scan detail for ${escapeHtml(file.name || file.path || "file")}" aria-haspopup="dialog"><svg class="preview-toggle-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M14 4h6v6"></path><path d="M20 4 11.5 12.5"></path><path d="M10 5H6a2 2 0 0 0-2 2v11a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2v-4"></path></svg></button>
              <button type="button" class="file-info-toggle" data-inventory-expand="${escapeHtml(key)}" aria-haspopup="dialog" title="Open asset &amp; scan detail">
                <span class="file-path">${escapeHtml(file.name || file.path || "Unknown file")}</span>
              </button>
            </div>
            <div class="file-meta-line">
              ${file.extension ? `<span>${escapeHtml(file.extension)}</span>` : ""}
              <span>${escapeHtml(formatBytes(file.size))}</span>
              <span>${escapeHtml(sourceName)}</span>
              ${hashChanged ? '<span class="hash-change-chip">Hash changed</span>' : ""}
              ${duplicateHashPath ? '<span class="hash-change-chip duplicate-hash-chip">Duplicate hash path</span>' : ""}
            </div>
            ${fileFlags.length ? `<div class="file-flags polished-flags">${fileFlags.map((flag) => `<span>${escapeHtml(flag)}</span>`).join("")}</div>` : ""}
            <div class="subtext path-subtext"><span>${escapeHtml(path)}</span>${copyPathButton}</div>
          </td>
          <td>
            <div class="source-pill">${escapeHtml(sourceName)}</div>
            <div class="subtext">${escapeHtml(file.share || file.content_status || "scanned")}</div>
          </td>
          <td><div class="finding-chip-wrap"><div class="finding-chip-set">${findingChips}</div>${moreFindings}</div>${frameworkStrip}</td>
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
          <td>${!lazyDetail ? detailButton(reasons, file, "reasons", "Reasons", "No reasons")
            : Number.isInteger(file.reason_count) ? countDetailButton(file.reason_count, file, "reasons", "Reasons", "No reasons")
            : lazyDetailButton(file, "reasons", "Reasons")}</td>
          <td>${!lazyDetail ? detailButton(recommendations, file, "recommendations", "DLP actions", "No actions")
            : Number.isInteger(file.dlp_count) ? countDetailButton(file.dlp_count, file, "recommendations", "DLP actions", "No actions")
            : lazyDetailButton(file, "recommendations", "DLP actions")}</td>
        </tr>
      `;
    })
    .join("");
  const moreRow = serverPage
    ? inventoryWindowControls(serverPage)
    : visible.length > page.length
      ? `<tr><td colspan="7" class="empty"><button type="button" class="secondary-btn mini-btn" id="load-more-results">Load ${Math.min(ROW_PAGE_SIZE, visible.length - page.length)} more of ${visible.length}</button></td></tr>`
      : "";
  resultsBody.innerHTML = rows + moreRow;
  resolveLazyDetailCounts(page);
  lastRenderedFileKeys = currentKeys;
  hasRenderedScanRows = true;
}

// Backstop: if a rendered row is still waiting on reason/fix counts (a data
// path without the per-page attachment), one batched request fills them all
// in - the cells never sit on an ellipsis.
function resolveLazyDetailCounts(files = []) {
  const pendingByKey = new Map();
  files.forEach((file) => {
    if (file?.__inventory_page_item && !file.__inventory_detail_loaded && file.id
        && !(Number.isInteger(file.reason_count) && Number.isInteger(file.dlp_count))) {
      pendingByKey.set(fileKey(file), file);
    }
  });
  // Trust the DOM over the data flags: any lazy button still on screen names
  // a row that owes the operator numbers.
  resultsBody?.querySelectorAll(".detail-toggle-lazy[data-detail-key]").forEach((button) => {
    const key = button.dataset.detailKey || "";
    if (!pendingByKey.has(key)) {
      const file = findInventoryFileByKey(key);
      if (file?.id) pendingByKey.set(key, file);
    }
  });
  const pending = [...pendingByKey.values()];
  if (!pending.length) return;
  const ids = [...new Set(pending.map((file) => String(file.id)))].slice(0, 500);
  api(`/api/inventory-detail-counts?ids=${encodeURIComponent(ids.join(","))}`, null, "GET")
    .then((data) => {
      const counts = data?.counts || {};
      let unpatched = 0;
      pending.forEach((file) => {
        const pair = counts[String(file.id)];
        if (!pair) return;
        file.reason_count = pair.reasons;
        file.dlp_count = pair.fixes;
        const row = resultsBody?.querySelector(`tr[data-file-key="${CSS.escape(fileKey(file))}"]`);
        if (row) refreshInventorySummaryCells(file);
        else unpatched += 1;
      });
      // A row the patcher could not find still renders right on the next
      // paint because the counts now live on the items.
      if (unpatched && !resultsBody?.querySelector(".detail-toggle-lazy")) return;
      if (resultsBody?.querySelector(".detail-toggle-lazy")) renderFindingsWorkspace?.();
    })
    .catch(() => { /* the on-open refresh still corrects the cells */ });
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
    if (inventoryFrameworkFacets.size) {
      const frameworks = getFileFrameworks(file);
      if (![...inventoryFrameworkFacets].some((framework) => frameworks.includes(framework))) return false;
    }
    return !query || getFileSearchText(file).includes(query);
  });
}

function renderInventoryControlState(files = latestFiles, visible = getVisibleInventoryFiles(files), serverPage = null) {
  updateInventoryFilterOptions(files || []);
  renderInventoryRiskSelection();
  inventoryRiskFilters.forEach((button) => {
    const risk = button.dataset.riskFilter || "ALL";
    const serverCounts = serverPage && inventoryFacets ? inventoryFacets.risk_counts || {} : null;
    const count = serverCounts
      ? risk === "ALL"
        ? Number(inventoryFacets.total || 0)
        : risk === "PROTECTED"
          ? Number(inventoryFacets.protected || 0)
          : Number(serverCounts[risk] || 0)
      : risk === "ALL"
        ? (files || []).length
        : risk === "PROTECTED"
          ? (files || []).filter(isProtectedFile).length
          : (files || []).filter((file) => getEffectiveRisk(file).level === risk).length;
    button.dataset.count = String(count);
  });
  if (inventoryContextMetrics) {
    const sensitive = serverPage
      ? visible.filter((file) => Number(file.finding_count || (file.findings || []).length) > 0).length
      : visible.filter((file) => (file.findings || []).length).length;
    const avgRisk = visible.length
      ? Math.round(visible.reduce((sum, file) => sum + (Number(getEffectiveRisk(file).score) || 0), 0) / visible.length)
      : 0;
    const topSource = visible.length ? getTopFacet(visible.map(getInventorySourceValue)) : "none";
    const inventoryTotal = serverPage ? `${serverPage.total}${serverPage.totalIsEstimate ? "+" : ""}` : (files || []).length;
    inventoryContextMetrics.innerHTML = `
      <div><span>Visible</span><strong>${visible.length}</strong><small>of ${inventoryTotal} files</small></div>
      <div><span>Sensitive</span><strong>${sensitive}</strong><small>${Math.round((sensitive / Math.max(1, visible.length)) * 100)}% in view</small></div>
      <div><span>Avg risk</span><strong>${avgRisk}</strong><small>/100</small></div>
      <div><span>Top source</span><strong>${escapeHtml(topSource)}</strong><small>current filter</small></div>
    `;
  }
}

const INVENTORY_SORT_LABELS = {
  name: "file name",
  scan_label: "scan",
  finding_count: "finding count",
  risk_score: "risk score",
};

function syncInventorySortHeaders() {
  document.querySelectorAll(".inventory-table th[data-inventory-sort]").forEach((th) => {
    const active = th.dataset.inventorySort === inventorySortKey;
    th.classList.toggle("is-sorted", active);
    // Each key has one meaningful direction server-side (risk high-first,
    // names A-Z), so the header reports that rather than a toggle.
    th.setAttribute("aria-sort", active
      ? (["name", "scan_label"].includes(inventorySortKey) ? "ascending" : "descending")
      : "none");
  });
}

async function applyInventorySort(key) {
  if (!INVENTORY_SORT_LABELS[key] || key === inventorySortKey) return;
  inventorySortKey = key;
  syncInventorySortHeaders();
  setStatus(`Sorting all files by ${INVENTORY_SORT_LABELS[key]}...`);
  try {
    resetInventoryPageWindow();
    await refreshInventoryPageWindow();
    setStatus(`Sorted every file by ${INVENTORY_SORT_LABELS[key]}.`);
  } catch (error) {
    setStatus(`Sort failed: ${error.message}`);
  }
}

document.addEventListener("click", (event) => {
  const th = event.target.closest(".inventory-table th[data-inventory-sort]");
  if (th) applyInventorySort(th.dataset.inventorySort);
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const th = event.target.closest?.(".inventory-table th[data-inventory-sort]");
  if (!th) return;
  event.preventDefault();
  applyInventorySort(th.dataset.inventorySort);
});

function updateInventoryFilterOptions(files = latestFiles) {
  if (inventorySourceFilter) {
    // Prefer the scans a customer actually configured ("HR file share") over
    // collector protocols ("smb"); protocols remain as the fallback for assets
    // captured before scans carried a name.
    const scanNames = (inventoryFacets?.scans || []).map((item) => String(item.value || "")).filter(Boolean);
    const sources = scanNames.length
      ? scanNames
      : inventoryFacets
        ? (inventoryFacets.sources || []).map((item) => String(item.value || "")).filter(Boolean)
        : [...new Set(files.map(getInventorySourceValue).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    const current = sources.includes(inventorySourceFacet) ? inventorySourceFacet : "ALL";
    inventorySourceFacet = current;
    inventorySourceFilter.innerHTML = ["ALL", ...sources]
      .map((value) => `<option value="${escapeHtml(value)}" ${value === current ? "selected" : ""}>${escapeHtml(value === "ALL" ? "All scans" : value)}</option>`)
      .join("");
  }
  if (inventoryFindingFilter) {
    const findings = inventoryFacets
      ? (inventoryFacets.finding_types || []).map((item) => String(item.value || "")).filter(Boolean)
      : [...new Set(files.flatMap(getFileFindingTypes))].sort((a, b) => a.localeCompare(b));
    const current = findings.includes(inventoryFindingFacet) ? inventoryFindingFacet : "ALL";
    inventoryFindingFacet = current;
    inventoryFindingFilter.innerHTML = ["ALL", ...findings]
      .map((value) => `<option value="${escapeHtml(value)}" ${value === current ? "selected" : ""}>${escapeHtml(value === "ALL" ? "All finding types" : value)}</option>`)
      .join("");
  }
  renderInventoryFrameworkFilter(files);
}

function getInventorySourceValue(file) {
  // The Source column names the scan a customer configured ("HR file share").
  // Assets captured before scans carried a name fall back to the collector
  // protocol so the column is never blank.
  return String(file.scan_label || file.source || file.share || "workspace").trim() || "workspace";
}

function inventoryFrameworkOptions(files = latestFiles) {
  const allOptions = [
    ["standard_scan", "Standard scan"],
    ["gdpr", "GDPR"],
    ["pci_dss", "PCI DSS"],
    ["nist_sp800_60_enterprise", "NIST"],
  ];
  const counts = new Map(allOptions.map(([id]) => [id, 0]));
  if (inventoryFacets) {
    (inventoryFacets.frameworks || []).forEach((item) => counts.set(String(item.value || ""), Number(item.count || 0)));
  } else {
    (files || []).forEach((file) => {
      getFileFrameworks(file).forEach((framework) => {
        counts.set(framework, (counts.get(framework) || 0) + 1);
      });
    });
  }
  return allOptions.map(([id, label]) => ({ id, label, count: counts.get(id) || 0 }));
}

function renderInventoryFrameworkFilter(files = latestFiles) {
  if (!inventoryFrameworkFilter) return;
  const options = inventoryFrameworkOptions(files);
  inventoryFrameworkFilter.innerHTML = options.map(({ id, label, count }) => {
    const checked = !inventoryFrameworkFacets.size || inventoryFrameworkFacets.has(id);
    return `
      <label class="inventory-framework-option ${checked ? "active" : ""}">
        <input type="checkbox" value="${escapeHtml(id)}" ${checked ? "checked" : ""} />
        <span>${escapeHtml(label)}</span>
        <b>${escapeHtml(count)}</b>
      </label>
    `;
  }).join("");
}
// Without these a fresh install shows an empty framework filter and count-less
// risk pills until the first scan: only clearResultsFilter() and the scan-data
// pipeline call the renderers, and the pill ovals read counts from data-count.
renderInventoryFrameworkFilter();
renderInventoryControlState();

function getFileFrameworks(file = {}) {
  const frameworks = new Set();
  primaryFindingsForFile(file).forEach((finding) => {
    const findingFrameworkValues = findingFrameworks(finding, { scoped: false });
    if (findingFrameworkValues.length) {
      findingFrameworkValues.forEach((framework) => frameworks.add(framework));
    } else {
      frameworks.add("standard_scan");
    }
  });
  if (!frameworks.size && file.top_frameworks) {
    String(file.top_frameworks)
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean)
      .forEach((framework) => frameworks.add(normalizeFrameworkId(framework)));
  }
  if (!frameworks.size) frameworks.add("standard_scan");
  return [...frameworks];
}

function getFileFindingTypes(file) {
  const findings = primaryFindingsForFile(file)
    .map((finding) => String(findingDisplayName(finding) || finding.pattern || "Signal").trim())
    .filter(Boolean);
  if (isProtectedFile(file)) {
    findings.push("Protected / locked");
  }
  if (hasHashChanged(file)) {
    findings.push("Hash changed");
  }
  if (hasDuplicateHashPath(file)) {
    findings.push("Duplicate hash path");
  }
  return findings;
}

function findingDisplayName(finding = {}, language = "en") {
  const framework = normalizeFrameworkId(finding.framework);
  if (framework === "nist_sp800_60_enterprise" || String(finding.type || "").startsWith("nist_")) {
    const category = normalizeKeywordCategory("nist_sp800_60_enterprise", finding.category_id || finding.category || "custom");
    return keywordFindingTypeLabel(finding, "nist_sp800_60_enterprise", category);
  }
  if (language.startsWith("az") && finding.display_name_az) return cleanGeneratedTypeName(finding.display_name_az);
  return cleanGeneratedTypeName(
    finding.display_name
      || finding.label
      || finding.data_type
      || finding.service
      || finding.type
      || finding.rule_id
      || "Unnamed rule"
  );
}

function cleanGeneratedTypeName(value = "") {
  const text = String(value || "").replace(/_/g, " ").replace(/\bType\s+\d+\b/gi, "").replace(/\s+/g, " ").trim();
  return text || "Unnamed rule";
}

function findingTechnicalType(finding = {}) {
  return finding.technical_type || finding.type || finding.rule_id || "";
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
    filePropertyOwner(file),
    firstFileValue(file, ["author", "metadata.author", "document_author", "created_by"]),
    firstFileValue(file, ["modified_by", "last_modified_by", "metadata.last_modified_by"]),
    file.created_at,
    file.modified_at,
    file.accessed_at,
    file.attributes,
    fileHashValue(file),
    hasHashChanged(file) ? "hash changed" : "",
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
  const aliases = { inventory: "findings" };
  return aliases[tabName] || tabName || "overview";
}

// Redesign P3: the sidebar shows 6 destinations while the tab panels keep their
// original names (old data-tab-jump deep links stay valid). Merged destinations
// own several member panels; navDestination() maps any panel to the sidebar
// button that should light up for it. Sidebar .nav-sub groups switch between
// members via the existing data-tab-jump wiring.
const NAV_DESTINATIONS = {
  overview: "overview",
  "file-servers": "file-servers",
  endpoint: "file-servers",
  findings: "findings",
  risk: "risk",
  reports: "reports",
  history: "reports",
  security: "security",
  admin: "security",
  settings: "security",
  logic: "security",
};

function navDestination(tabName) {
  return NAV_DESTINATIONS[resolveTabName(tabName)] || "overview";
}

// Every destination is a real path (reload keeps you on the page); member
// panels of merged destinations deep-link with a #hash on that path.
const DESTINATION_PATHS = {
  overview: "/dashboard",
  findings: "/findings",
  risk: "/remediation",
  "file-servers": "/scan",
  reports: "/evidence",
  security: "/administration",
};
const PATH_DEFAULT_TAB = {
  "/dashboard": "overview",
  "/findings": "findings",
  "/remediation": "risk",
  "/scan": "file-servers",
  "/evidence": "reports",
  "/administration": "security",
};

function tabUrl(resolvedTab) {
  const destination = navDestination(resolvedTab);
  const base = DESTINATION_PATHS[destination] || "/dashboard";
  // Members of a multi-member destination ALWAYS carry their #member, so the
  // default member is addressable too (/scan#file-servers, not a bare /scan).
  const memberCount = document.querySelectorAll(`.nav-sub[data-nav-sub="${destination}"] .nav-sub-link`).length;
  if (memberCount > 1 || resolvedTab !== PATH_DEFAULT_TAB[base]) {
    return `${base}#${resolvedTab}`;
  }
  return base;
}

function tabFromLocation() {
  const base = PATH_DEFAULT_TAB[location.pathname];
  if (!base) return null;
  const member = resolveTabName(location.hash.slice(1));
  if (member && document.getElementById(`tab-${member}`) && navDestination(member) === navDestination(base)) {
    return member;
  }
  return base;
}

window.addEventListener("popstate", () => {
  // Leaving a setup URL (back button) closes the wizard; a setup hash never
  // OPENS one - resolveTabName does not know it, so direct entry lands on
  // the deck. The temporary URL dies with the flow.
  if (!String(location.hash).endsWith("-setup")) {
    closeAnyOpenScanWizard();
  }
  const tab = tabFromLocation();
  if (tab) switchTab(tab);
});

// Sidebar groups: the caret is a pure expand/collapse toggle (no navigation);
// clicking the destination name/icon navigates and auto-opens its group.
// Open state is independent of the active page, so an operator can peek into
// another destination's members without leaving the current one.
const navOpenGroups = new Set();
// Groups the user opened with the caret stay open across navigation until the
// caret closes them; groups that auto-opened on entry close again on leaving.
const navPinnedGroups = new Set();
let currentNavTab = "overview";

function syncNavGroups() {
  document.querySelectorAll(".side-nav .nav-sub").forEach((group) => {
    const open = navOpenGroups.has(group.dataset.navSub);
    group.classList.toggle("open", open);
    group.setAttribute("aria-hidden", open ? "false" : "true");
    group.querySelectorAll(".nav-sub-link").forEach((link) => {
      const isCurrent = open && resolveTabName(link.dataset.tabJump) === currentNavTab;
      link.classList.toggle("active", isCurrent);
      link.setAttribute("aria-current", isCurrent ? "page" : "false");
      link.tabIndex = open ? 0 : -1;
    });
  });
  document.querySelectorAll(".side-nav .tab").forEach((tab) => {
    tab.classList.toggle("expanded", navOpenGroups.has(tab.dataset.tab));
  });
}

// Capture phase so the caret wins before the tab's own navigation handler.
document.addEventListener("click", (event) => {
  const caret = event.target.closest(".nav-caret");
  if (!caret) return;
  event.preventDefault();
  event.stopPropagation();
  const dest = caret.closest(".tab")?.dataset.tab;
  if (!dest) return;
  if (navOpenGroups.has(dest)) {
    navOpenGroups.delete(dest);
    navPinnedGroups.delete(dest);
  } else {
    navOpenGroups.add(dest);
    navPinnedGroups.add(dest);
  }
  syncNavGroups();
}, true);

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

  // A setup wizard lives INSIDE its scan panel, so navigating to that panel
  // (or away from it) must dismiss it - otherwise the sidebar changes the URL
  // to /scan#file-servers while the setup view stays on screen.
  closeAnyOpenScanWizard();

  const destination = navDestination(resolvedTab);
  tabs.forEach((tab) => {
    // The sidebar button owning this panel's destination lights up, so merged
    // destinations (Scan, Evidence, Administration) stay active for members.
    const isActive = tab.dataset.tab === destination;
    tab.classList.toggle("active", isActive);
    tab.setAttribute("aria-current", isActive ? "page" : "false");
  });
  // Auto-expanded groups follow the active section: entering a section
  // opens its group, leaving closes it again - but groups the user opened
  // with the caret are pinned and stay open until the caret closes them.
  navOpenGroups.clear();
  navPinnedGroups.forEach((group) => navOpenGroups.add(group));
  navOpenGroups.add(destination);
  currentNavTab = resolvedTab;
  syncNavGroups();
  const targetUrl = tabUrl(resolvedTab);
  if (location.pathname + location.hash !== targetUrl && PATH_DEFAULT_TAB[location.pathname]) {
    history.pushState({ tab: resolvedTab }, "", targetUrl);
  }
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
  } else {
    // A new page starts at its top - carrying the old scroll position over
    // meant landing mid-page after every switch.
    window.scrollTo({ top: 0, behavior: "auto" });
  }
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  const icon = themeToggle.querySelector(".theme-icon");
  const nextLabel = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
  if (icon) {
    icon.innerHTML = theme === "dark" ? "&#9728;" : "&#9790;";
  }
  themeToggle.setAttribute("aria-label", nextLabel);
  themeToggle.title = nextLabel;
  safeStorageSet("dspm-theme", theme);
}

function renderPreview(preview) {
  if (!preview?.available) {
    return "";
  }

  const lines = (preview.lines || []).map((line) => `<code>${escapeHtml(line || " ")}</code>`);
  const truncated = preview.truncated ? '<div class="subtext">Preview truncated for safe display.</div>' : "";

  return `<div class="essential-preview" aria-label="Sanitized content preview">${lines.join("")}${truncated}</div>`;
}

function riskOption(value, label, selected) {
  return `<option value="${value}" ${value === selected ? "selected" : ""}>${label}</option>`;
}

function getEffectiveRisk(file) {
  const level = rowOverrides[fileKey(file)];
  if (!level) {
    return file.risk || {
      level: String(file.risk_level || "LOW").toUpperCase(),
      score: Number(file.risk_score || 0),
    };
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

function hashString(value) {
  let hash = 0;
  for (let index = 0; index < String(value || "").length; index += 1) {
    hash = ((hash << 5) - hash + String(value).charCodeAt(index)) | 0;
  }
  return hash;
}

async function ensureInventoryAssetDetail(file) {
  if (!file?.__inventory_page_item || file.__inventory_detail_loaded || !file.id) return file;
  const requestKey = String(file.id);
  if (!inventoryDetailRequests.has(requestKey)) {
    const request = api(`/api/inventory/${encodeURIComponent(file.id)}`, null, "GET")
      .then((data) => {
        const asset = data.asset || {};
        const cachedItems = [...inventoryPageWindow.pages.values()].flatMap((page) => page.items || []);
        const targets = [...new Set([file, ...latestFiles, ...cachedItems])]
          .filter((item) => item && (item === file || String(item.id || "") === requestKey || fileKey(item) === fileKey(file)));
        targets.forEach((item) => Object.assign(item, asset, {
          __inventory_page_item: true,
          __inventory_detail_loaded: true,
        }));
        refreshInventorySummaryCells(file);
        return file;
      })
      .finally(() => inventoryDetailRequests.delete(requestKey));
    inventoryDetailRequests.set(requestKey, request);
  }
  return inventoryDetailRequests.get(requestKey);
}

function renderInventoryDetailLoading(message = "Loading asset and scan detail...") {
  return `<div class="inventory-detail-state" role="status"><span class="inventory-detail-spinner" aria-hidden="true"></span><strong>${escapeHtml(message)}</strong><small>File properties, permissions, document metadata, and scan diagnostics are loaded on demand.</small></div>`;
}

function renderInventoryDetailError(message) {
  return `<div class="inventory-detail-state error" role="alert"><strong>Complete detail could not be loaded.</strong><small>${escapeHtml(message || "The inventory detail endpoint is temporarily unavailable.")}</small></div>`;
}

function renderInventoryRecommendations(file) {
  const recommendations = file?.risk?.dlp_recommendations || [];
  return recommendations.length
    ? `<ol class="detail-list recommendations inventory-recommendation-list">${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>`
    : '<p class="inventory-detail-empty">No DLP recommendations were generated for this asset.</p>';
}

function humanizeDetailKey(key) {
  return String(key || "")
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replaceAll("_", " ")
    .replace(/\b\w/g, (letter) => letter.toUpperCase());
}

const ESSENTIAL_UNSAFE_FIELD = /(?:^|_)(?:raw|unmasked|secret_value|full_value|fingerprint|sample|preview|file_content|content_body|search_text|detail_json|response_json)(?:$|_)/i;

const ESSENTIAL_DISCLOSURE_ICONS = {
  identity: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 6.5h16v11H4z"></path><path d="M8 10h4M8 14h7"></path></svg>',
  exposure: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3 5 6v5c0 4.6 2.8 8 7 10 4.2-2 7-5.4 7-10V6z"></path><path d="M9 12h6M12 9v6"></path></svg>',
  protection: '<svg viewBox="0 0 24 24" aria-hidden="true"><rect x="5" y="10" width="14" height="10" rx="2"></rect><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v2"></path></svg>',
  document: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M6 3h8l4 4v14H6z"></path><path d="M14 3v5h5M9 12h6M9 16h6"></path></svg>',
  scan: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 8V4h4M16 4h4v4M20 16v4h-4M8 20H4v-4"></path><path d="M7 12h2l1.5-3 3 6 1.5-3h2"></path></svg>',
  preview: '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"></path><circle cx="12" cy="12" r="2.5"></circle></svg>',
};

function essentialBoolean(value, positive, negative) {
  if (value === undefined || value === null || value === "") return "";
  const enabled = typeof value === "string"
    ? ["1", "true", "yes", "enabled"].includes(value.trim().toLowerCase())
    : Boolean(value);
  return enabled ? positive : negative;
}

function safeEssentialEntries(value = {}, excluded = new Set()) {
  if (!value || typeof value !== "object" || Array.isArray(value)) return [];
  return Object.entries(value).filter(([key, item]) => {
    const normalized = String(key || "").toLowerCase();
    return !normalized.startsWith("__")
      && !excluded.has(normalized)
      && !ESSENTIAL_UNSAFE_FIELD.test(normalized)
      && hasDisplayValue(item);
  });
}

function formatEssentialValue(value, depth = 0) {
  if (typeof value === "boolean") return value ? "Yes" : "No";
  if (Array.isArray(value)) {
    const formatted = value.map((item) => formatEssentialValue(item, depth + 1)).filter(Boolean);
    const visible = formatted.slice(0, 8);
    return `${visible.join(" • ")}${formatted.length > visible.length ? ` • ${formatted.length - visible.length} more` : ""}`;
  }
  if (value && typeof value === "object") {
    if (depth > 1) return "Structured value available";
    return safeEssentialEntries(value)
      .slice(0, 8)
      .map(([key, item]) => `${humanizeDetailKey(key)}: ${formatEssentialValue(item, depth + 1)}`)
      .filter(Boolean)
      .join(" • ");
  }
  return String(value ?? "").trim();
}

function renderEssentialRows(rows = []) {
  const visible = rows.filter((row) => hasDisplayValue(row.value));
  if (!visible.length) return "";
  return `
    <dl class="essential-data-grid">
      ${visible.map((row) => `
        <div class="${escapeHtml(row.className || "")}">
          <dt>${escapeHtml(row.label)}</dt>
          <dd>${escapeHtml(row.display || formatEssentialValue(row.value))}</dd>
        </div>
      `).join("")}
    </dl>
  `;
}

function renderEssentialDisclosure({ id, icon, eyebrow, title, summary, rows = [], content = "", open = false, count = null, countLabel = "" }) {
  const visibleRows = rows.filter((row) => hasDisplayValue(row.value));
  if (!visibleRows.length && !content) return "";
  const numericCount = Number(count);
  const hasCount = count !== null && count !== "" && Number.isFinite(numericCount) && numericCount >= 0;
  return `
    <details class="essential-disclosure" data-essential-section="${escapeHtml(id)}" ${open ? "open" : ""}>
      <summary>
        <span class="essential-disclosure-icon">${ESSENTIAL_DISCLOSURE_ICONS[icon] || ESSENTIAL_DISCLOSURE_ICONS.document}</span>
        <span class="essential-disclosure-copy">
          <span>${escapeHtml(eyebrow)}</span>
          <strong>${escapeHtml(title)}</strong>
          <small>${escapeHtml(summary)}</small>
        </span>
        ${hasCount ? `<span class="essential-disclosure-metric"><strong>${escapeHtml(numericCount)}</strong><small>${escapeHtml(countLabel)}</small></span>` : ""}
        <svg class="essential-disclosure-caret" viewBox="0 0 24 24" aria-hidden="true"><path d="m7 10 5 5 5-5"></path></svg>
      </summary>
      <div class="essential-disclosure-body">
        ${renderEssentialRows(visibleRows)}
        ${content}
      </div>
    </details>
  `;
}

function essentialObjectRows(value = {}, excluded = []) {
  const excludedKeys = new Set(excluded.map((key) => String(key).toLowerCase()));
  return safeEssentialEntries(value, excludedKeys).map(([key, item]) => ({
    label: humanizeDetailKey(key),
    value: item,
  }));
}

function collectionSize(value) {
  if (Array.isArray(value)) return value.length;
  if (value && typeof value === "object") return Object.keys(value).length;
  return hasDisplayValue(value) ? 1 : 0;
}

function renderInventoryExpandedDetails(file) {
  const permissions = file?.permissions && typeof file.permissions === "object" ? file.permissions : {};
  const acl = file?.acl && typeof file.acl === "object" ? file.acl : {};
  const owner = filePropertyOwner(file);
  const aclOwner = String(acl.owner || "").trim();
  const principals = acl.principals || permissions.principals || [];
  const permissionGrants = acl.permissions || permissions.grants || [];
  const accessIssues = permissions.issues || acl.issues || [];
  const principalCount = collectionSize(principals);
  const grantCount = collectionSize(permissionGrants);
  const broadAccess = Boolean(permissions.public || permissions.wide_access);
  const writable = Boolean(permissions.writable);
  const privileged = Boolean(permissions.privileged_access);
  const exposureAttention = broadAccess || writable || privileged || collectionSize(accessIssues) > 0;
  const accessPosture = broadAccess
    ? "Broad access reported"
    : writable
      ? "Writable access reported"
      : privileged
        ? "Privileged access reported"
        : principalCount || grantCount
          ? "Explicit access controls available"
          : "Access details not reported";

  const hash = fileHashValue(file);
  const contentHash = String(file.content_hash || "").trim().toLowerCase();
  const hashChanged = hasHashChanged(file);
  const duplicateHashPath = hasDuplicateHashPath(file);
  const protectedAsset = isProtectedFile(file);
  const protectionAttention = protectedAsset || file.content_scannable === false || hashChanged || duplicateHashPath;
  const protectionSummary = protectedAsset
    ? `Protected: ${getProtectionLabel(file)}`
    : file.content_scannable === false
      ? "Content could not be fully inspected"
      : "No protection barrier reported";

  const detectorMetrics = file?.detector_metrics && typeof file.detector_metrics === "object" ? file.detector_metrics : {};
  const detectorCount = collectionSize(detectorMetrics.detectors);
  const slowDetectorCount = collectionSize(detectorMetrics.slow_detectors);
  const bytesScanned = Number(file.bytes_scanned);
  const totalBytes = Number(file.total_bytes);
  const coverage = Number.isFinite(bytesScanned) && bytesScanned >= 0
    ? `${formatBytes(bytesScanned)} analyzed${Number.isFinite(totalBytes) && totalBytes > 0 ? ` of ${formatBytes(totalBytes)}` : ""}`
    : "";
  const elapsedMs = Number(file.detector_elapsed_ms ?? detectorMetrics.elapsed_ms);
  const timeoutSeconds = Number(detectorMetrics.detector_timeout_seconds);
  const scanAttention = Boolean(file.scan_error || file.truncated || detectorMetrics.slow_detector_degraded_mode || file.compliance_degraded_mode)
    || String(file.scan_completeness || "").toLowerCase() === "partial";

  const identityRows = [
    { label: "Owner", value: owner || "Unassigned" },
    { label: "Author", value: firstFileValue(file, ["author", "metadata.author", "document_author", "documentAuthor"]) },
    { label: "Created by", value: firstFileValue(file, ["created_by", "creator", "metadata.creator"]) },
    { label: "Modified by", value: firstFileValue(file, ["modified_by", "last_modified_by", "metadata.last_modified_by"]) },
    { label: "Asset type", value: file.is_dir ? "Directory" : file.extension || "File" },
    { label: "Size", value: file.is_dir ? "" : formatBytes(file.size) },
    { label: "Source", value: file.source || "workspace" },
    { label: "Share or host", value: file.share || file.host || file.server || "" },
    { label: "Created", value: getFriendlyTimestamp(firstFileValue(file, ["created_at", "createdAt", "created", "creation_time"])) },
    { label: "Modified", value: getFriendlyTimestamp(firstFileValue(file, ["modified_at", "modifiedAt", "last_modified", "mtime"])) },
    { label: "Last accessed", value: getFriendlyTimestamp(firstFileValue(file, ["accessed_at", "accessedAt", "last_accessed", "atime"])) },
  ];
  const exposureRows = [
    { label: "Access posture", value: accessPosture },
    { label: "Write access", value: essentialBoolean(permissions.writable, "Allowed", "Not reported") },
    { label: "Privileged access", value: essentialBoolean(permissions.privileged_access, "Detected", "Not reported") },
    { label: "ACL owner", value: aclOwner && aclOwner !== owner ? aclOwner : "" },
    { label: "Principals", value: principals },
    { label: "Permission grants", value: permissionGrants },
    { label: "Observed access issues", value: accessIssues },
  ];
  const protectionRows = [
    { label: "Protection state", value: protectedAsset ? getProtectionLabel(file) : "No protection signal reported" },
    { label: "Content inspection", value: essentialBoolean(file.content_scannable, "Scannable", "Not scannable") },
    { label: "Content status", value: file.content_status || file.scan_error || "" },
    { label: "Protection type", value: file.protection_type },
    { label: "File attributes", value: filePropertyAttributes(file) },
    { label: "SHA-256", value: hash ? shortHash(hash) : "" },
    { label: "Content hash", value: contentHash && contentHash !== hash ? shortHash(contentHash) : "" },
    { label: "Integrity change", value: hashChanged ? "Hash changed since the previous scan" : "" },
    { label: "Duplicate content", value: duplicateHashPath ? "The same SHA-256 exists at another path" : "" },
  ];
  const documentRows = essentialObjectRows(file.metadata, [
    "owner", "author", "creator", "created_by", "modified_by", "last_modified_by",
    "path", "full_path", "name", "size", "source", "share", "host", "server",
  ]);
  const scanRows = [
    { label: "Collection completeness", value: file.scan_completeness },
    { label: "Coverage", value: coverage },
    { label: "Scan mode", value: file.scan_mode },
    { label: "Last scanned", value: getFriendlyTimestamp(file.last_scanned_at) },
    { label: "Truncation", value: essentialBoolean(file.truncated, "Partial content", "Not truncated") },
    { label: "Incremental reuse", value: essentialBoolean(file.incremental_reused, "Reused unchanged result", "Fresh analysis") },
    { label: "Incremental decision", value: file.incremental_scan_reason },
    { label: "Detector cache", value: essentialBoolean(file.cache_reused ?? detectorMetrics.cache_hit, "Cache hit", "Cache miss") },
    { label: "Baseline result", value: file.baseline_result },
    { label: "Detector version", value: file.detector_version },
    { label: "Rule catalog", value: file.rule_catalog_version },
    { label: "Keyword catalog", value: file.keyword_catalog_status },
    { label: "Detection route", value: detectorMetrics.triage_route },
    { label: "Detection duration", value: Number.isFinite(elapsedMs) && elapsedMs >= 0 ? `${Math.round(elapsedMs)} ms` : "" },
    { label: "Detector timeout", value: Number.isFinite(timeoutSeconds) && timeoutSeconds > 0 ? `${timeoutSeconds} seconds` : "" },
    { label: "Slow detectors", value: slowDetectorCount ? detectorMetrics.slow_detectors : "" },
    { label: "Degraded detector mode", value: essentialBoolean(detectorMetrics.slow_detector_degraded_mode, "Enabled", "Not active") },
    { label: "Compliance mapping mode", value: essentialBoolean(file.compliance_degraded_mode, "Degraded", "Standard") },
    { label: "Scan error", value: file.scan_error },
  ];
  const preview = renderPreview(file.preview);
  const previewLineCount = Array.isArray(file?.preview?.lines) ? file.preview.lines.length : 0;

  return `
    <div class="inventory-expanded-panel">
      <div class="essential-scope-note">
        <span aria-hidden="true">i</span>
        <p><strong>Asset context only.</strong> Detection evidence, scoring rationale, and remediation stay in Findings, Reasons, and Actions.</p>
      </div>
      <div class="essential-stack">
        ${renderEssentialDisclosure({
          id: "identity", icon: "identity", eyebrow: "Asset context", title: "Identity and location",
          summary: "Ownership, origin, format, and lifecycle timestamps", rows: identityRows, open: true,
        })}
        ${renderEssentialDisclosure({
          id: "exposure", icon: "exposure", eyebrow: "Access control", title: "Exposure context",
          summary: accessPosture, rows: exposureRows, open: exposureAttention,
          count: principalCount || grantCount || null, countLabel: principalCount ? `principal${principalCount === 1 ? "" : "s"}` : `grant${grantCount === 1 ? "" : "s"}`,
        })}
        ${renderEssentialDisclosure({
          id: "protection", icon: "protection", eyebrow: "Data handling", title: "Protection and integrity",
          summary: protectionSummary, rows: protectionRows, open: protectionAttention,
        })}
        ${renderEssentialDisclosure({
          id: "document", icon: "document", eyebrow: "Extracted properties", title: "Document metadata",
          summary: "Non-sensitive format and document properties", rows: documentRows,
        })}
        ${renderEssentialDisclosure({
          id: "scan", icon: "scan", eyebrow: "Collection quality", title: "Scan coverage and provenance",
          summary: "Completeness, reuse decisions, detector health, and catalog versions", rows: scanRows, open: scanAttention,
          count: detectorCount || null, countLabel: `detector${detectorCount === 1 ? "" : "s"}`,
        })}
        ${renderEssentialDisclosure({
          id: "preview", icon: "preview", eyebrow: "Sanitized content only", title: "Content preview",
          summary: "Redacted collector output; open only when needed", content: preview,
          count: previewLineCount || null, countLabel: `line${previewLineCount === 1 ? "" : "s"}`,
        })}
      </div>
    </div>
  `;
}

let assetModalFile = null;
let assetModalTab = "essential";
let assetModalReturnFocus = null;

const ASSET_MODAL_TABS = {
  essential: (file) => renderInventoryExpandedDetails(file),
  findings: (file) => renderFindingDrawerGroups(file),
  reasons: (file) => `
    <section class="inventory-detail-section asset-tab-single">
      <div class="inventory-detail-section-head"><div><span>Why this file is scored</span><h5>Risk reasons</h5></div><b>${escapeHtml((file?.risk?.reasons || []).length)}</b></div>
      ${renderReasonDetailList(file)}
    </section>`,
  actions: (file) => `
    <section class="inventory-detail-section asset-tab-single">
      <div class="inventory-detail-section-head"><div><span>Recommended response</span><h5>Fixes</h5></div><b>${escapeHtml((file?.risk?.dlp_recommendations || []).length)}</b></div>
      ${renderInventoryRecommendations(file)}
    </section>`,
};

function setAssetModalTab(tab) {
  assetModalTab = ASSET_MODAL_TABS[tab] ? tab : "essential";
  let activeButton = null;
  document.querySelectorAll("#asset-detail-modal .asset-tab").forEach((button) => {
    const active = button.dataset.assetTab === assetModalTab;
    button.classList.toggle("active", active);
    button.setAttribute("aria-selected", String(active));
    button.tabIndex = active ? 0 : -1;
    if (active) activeButton = button;
  });
  const body = document.getElementById("asset-modal-body");
  if (activeButton?.id) body.setAttribute("aria-labelledby", activeButton.id);
  if (assetModalFile) {
    body.innerHTML = ASSET_MODAL_TABS[assetModalTab](assetModalFile);
    body.scrollTop = 0;
  }
}

async function openAssetDetailModal(keyOrControl, tab = "essential") {
  const key = typeof keyOrControl === "string"
    ? keyOrControl
    : keyOrControl.dataset.inventoryExpand || keyOrControl.closest("tr")?.dataset.fileKey || "";
  let file = findInventoryFileByKey(key);
  if (!file) return;
  const modal = document.getElementById("asset-detail-modal");
  if (!modal) return;
  assetModalReturnFocus = keyOrControl instanceof Element ? keyOrControl : document.activeElement;
  assetModalFile = null;
  document.getElementById("asset-modal-title").textContent = file.name || file.path || "Asset";
  document.getElementById("asset-modal-path").textContent = file.path || "";
  const body = document.getElementById("asset-modal-body");
  body.innerHTML = renderInventoryDetailLoading();
  modal.classList.remove("hidden");
  modal.getBoundingClientRect();
  modal.classList.add("open");
  setAssetModalTab(tab);
  requestAnimationFrame(() => modal.querySelector(".asset-tab.active")?.focus());
  try {
    file = await ensureInventoryAssetDetail(file);
    if (modal.classList.contains("hidden")) return;
    assetModalFile = file;
    setAssetModalTab(tab);
  } catch (error) {
    body.innerHTML = renderInventoryDetailError(error.message);
  }
}

document.addEventListener("click", (event) => {
  const tabButton = event.target.closest("#asset-detail-modal .asset-tab");
  if (tabButton) setAssetModalTab(tabButton.dataset.assetTab);
});

document.addEventListener("keydown", (event) => {
  const tabButton = event.target.closest("#asset-detail-modal .asset-tab");
  if (!tabButton || !["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) return;
  const tabs = [...tabButton.closest("[role='tablist']").querySelectorAll(".asset-tab")];
  const current = tabs.indexOf(tabButton);
  const next = event.key === "Home"
    ? 0
    : event.key === "End"
      ? tabs.length - 1
      : (current + (event.key === "ArrowRight" ? 1 : -1) + tabs.length) % tabs.length;
  event.preventDefault();
  setAssetModalTab(tabs[next].dataset.assetTab);
  tabs[next].focus();
});

function closeAssetDetailModal() {
  const modal = document.getElementById("asset-detail-modal");
  if (!modal || modal.classList.contains("hidden")) return;
  modal.classList.remove("open");
  modal.classList.add("hidden");
  if (assetModalReturnFocus?.isConnected) assetModalReturnFocus.focus();
  assetModalReturnFocus = null;
}

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-close-asset-modal]")) closeAssetDetailModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeAssetDetailModal();
});

const DRAWER_SEVERITY_ORDER = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };

// The +N chip opens the evidence dossier: one collapsible group per finding
// type, every group closed at first so the reader scans the index and opens
// only what they came for. The row expansion stays the flat "everything at
// once" view; this drawer is the organized deep-dive.
function renderFindingDrawerGroups(file) {
  const findings = primaryFindingsForFile(file);
  if (!findings.length) {
    return '<p class="subtext">No findings were generated for this file.</p>';
  }
  const groups = findings
    .map((finding) => ({
      finding,
      level: String(finding.risk || finding.severity || "LOW").toUpperCase(),
      occurrences: findingOccurrenceCount(finding),
      supporting: childFindingsFor(file, finding).length,
    }))
    .sort((a, b) =>
      (DRAWER_SEVERITY_ORDER[a.level] ?? 9) - (DRAWER_SEVERITY_ORDER[b.level] ?? 9)
      || b.occurrences - a.occurrences);
  const totalOccurrences = groups.reduce((sum, group) => sum + group.occurrences, 0);
  const effectiveRisk = getEffectiveRisk(file);
  return `
    <div class="drawer-summary-strip">
      <span class="badge ${escapeHtml(effectiveRisk.level)}">${escapeHtml(effectiveRisk.level)} ${escapeHtml(effectiveRisk.score)}</span>
      <span>${escapeHtml(groups.length)} finding type${groups.length === 1 ? "" : "s"}</span>
      <i aria-hidden="true"></i>
      <span>${escapeHtml(totalOccurrences)} occurrence${totalOccurrences === 1 ? "" : "s"}</span>
    </div>
    ${groups.map(({ finding, level, occurrences, supporting }) => `
      <details class="drawer-group">
        <summary>
          <span class="drawer-group-sev ${escapeHtml(level)}" aria-hidden="true"></span>
          <span class="drawer-group-name">${escapeHtml(findingDisplayName(finding))}</span>
          <span class="drawer-group-count">${escapeHtml(occurrences)}${supporting ? ` <small>+${escapeHtml(supporting)} supporting</small>` : ""}</span>
          <svg class="drawer-group-caret" viewBox="0 0 24 24" aria-hidden="true"><path d="m7 10 5 5 5-5"/></svg>
        </summary>
        <div class="drawer-group-body">
          <ol class="detail-list findings">${renderFindingDetails(file, finding)}</ol>
        </div>
      </details>
    `).join("")}
  `;
}

function renderFindingDetailList(file) {
  const findings = primaryFindingsForFile(file);
  if (!findings.length) {
    return '<p class="subtext">No findings were generated for this file.</p>';
  }
  return `
    <ol class="detail-list findings">
      ${findings.map((finding) => {
        return renderFindingDetails(file, finding);
      }).join("")}
    </ol>
  `;
}

function complianceFindingDetailsForFile(file = {}) {
  return [];
}
function renderFindingDetails(file, finding) {
  return renderGenericFindingDetails(file, finding);
}

function renderGenericFindingDetails(file, finding) {
  const dataTypes = dataTypesForFinding(finding);
  const children = childFindingsFor(file, finding);
  return `
    <li class="${escapeHtml(frameworkClass(findingVisualFramework(finding)))}">
      <strong>${escapeHtml(findingDisplayName(finding))}</strong>
      <span class="detail-meta-line">${escapeHtml(finding.risk || "Signal")} &middot; ${escapeHtml(findingConfidenceLabel(finding))} confidence &middot; ${escapeHtml(findingOccurrenceCount(finding))} occurrence${findingOccurrenceCount(finding) === 1 ? "" : "s"}</span>
      <div class="framework-pill-row detail-framework-row">${findingFrameworkBadges(finding)}</div>
      ${dataTypes.length ? `<div class="detail-chip-row">${dataTypes.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>` : ""}
      ${renderFindingMetadataGrid(file, finding)}
      ${finding.description ? `<p>${escapeHtml(finding.description)}</p>` : ""}
      ${renderFindingEvidenceSections(finding)}
      ${finding.severity_rationale ? `<div class="detail-evidence"><span>Severity rationale</span><code>${escapeHtml(finding.severity_rationale)}</code></div>` : ""}
      ${finding.remediation ? `<div class="detail-evidence"><span>Remediation</span><code>${escapeHtml(finding.remediation)}</code></div>` : ""}
      ${renderChildFindingEvidence(file, children)}
    </li>
  `;
}

function renderChildFindingEvidence(file, children = []) {
  if (!children.length) return "";
  return `
    <div class="child-finding-evidence">
      <span>Supporting detections (${escapeHtml(children.length)})</span>
      ${children.map((child) => `
        <article>
          <strong>${escapeHtml(findingDisplayName(child))}</strong>
          <small>${escapeHtml(child.risk || child.severity || "Signal")} &middot; ${escapeHtml(findingConfidenceLabel(child))} confidence &middot; ${escapeHtml(findingOccurrenceCount(child))} occurrence${findingOccurrenceCount(child) === 1 ? "" : "s"}</small>
          <div class="framework-pill-row detail-framework-row">${findingFrameworkBadges(child)}</div>
          ${renderFindingMetadataGrid(file, child)}
          ${child.description ? `<p>${escapeHtml(child.description)}</p>` : ""}
          ${renderFindingEvidenceSections(child)}
        </article>
      `).join("")}
    </div>
  `;
}

function renderDetailSection(title, rows = {}) {
  const entries = Object.entries(rows).filter(([, value]) => hasDisplayValue(value));
  if (!entries.length) return "";
  return `<div class="detail-evidence detail-section"><span>${escapeHtml(title)}</span><dl>${entries.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd>${escapeHtml(formatDetailValue(value))}</dd></div>`).join("")}</dl></div>`;
}

function hasDisplayValue(value) {
  if (value === undefined || value === null) return false;
  if (Array.isArray(value)) return value.length > 0;
  if (typeof value === "object") return Object.keys(value).length > 0;
  const text = String(value).trim();
  return text !== "" && text.toUpperCase() !== "UNKNOWN";
}

function formatDetailValue(value) {
  if (Array.isArray(value)) return value.filter(hasDisplayValue).map(formatDetailValue).join(", ");
  if (typeof value === "object" && value !== null) return formatObject(value);
  return String(value);
}

function formatObject(value) {
  if (!value || typeof value !== "object") return "";
  if (Array.isArray(value)) return value.map(formatDetailValue).filter(Boolean).join("; ");
  return Object.entries(value).filter(([, item]) => hasDisplayValue(item)).map(([key, item]) => `${key}: ${formatDetailValue(item)}`).join("; ");
}

function formatList(value) {
  return Array.isArray(value) ? value.filter(hasDisplayValue).join(", ") : value || "";
}

function formatSignals(value) {
  if (!Array.isArray(value)) return "";
  return value.map((item) => typeof item === "object" ? formatObject(item) : String(item)).filter(Boolean).join("; ");
}

function protectionSectionRows(finding = {}) {
  const rows = {
    "Protection state": finding.protection_state,
    "Claimed protection": finding.claimed_protection_state,
    "Verified protection": finding.verified_protection_state,
    "Algorithm": finding.encryption_algorithm || finding.hash_algorithm,
    "Tokenization": finding.token_provider,
    "Masking": finding.masking_format,
  };
  return Object.values(rows).some((value) => hasDisplayValue(value)) ? rows : {};
}

function renderFindingMetadataGrid(file, finding) {
  const requirementMappings = finding.requirement_mappings || [];
  const pciRequirements = requirementMappings.length
    ? requirementMappings.map((item) => `${item.framework || "PCI DSS"} ${item.framework_version || ""} ${item.requirement_id || ""}`.trim())
    : finding.pci_requirements || [];
  const rows = [
    ["Rule ID", finding.rule_id],
    ["Framework", findingFrameworkText(finding)],
    ["PCI requirement", Array.isArray(pciRequirements) ? pciRequirements.join(", ") : pciRequirements],
    ["NIST catalog", finding.catalog_version],
    ["NIST catalog hash", finding.catalog_hash],
    ["CIA impact", [finding.confidentiality_impact, finding.integrity_impact, finding.availability_impact].filter(Boolean).join(" / ")],
    ["Overall impact", finding.overall_impact],
    ["Handling tier", finding.handling_tier],
    ["CHD/SAD", finding.pci_category],
    ["Data element", finding.data_element || finding.data_category || finding.category],
    ["Finding category", finding.finding_category],
    ["Protection state", finding.protection_state || finding.encryption_state],
    ["Storage state", finding.storage_state],
    ["Authorization state", finding.authorization_state],
    ["Entity role", finding.entity_role],
    ["Environment", finding.environment],
    ["Scope impact", finding.scope_impact || finding.logical_boundary],
    ["Display state", finding.display_state],
    ["Suppressed by", finding.suppressed_by],
    ["Review status", finding.review_status || finding.status],
    ["Exception status", finding.exception_status || (finding.exception_required ? "required" : "")],
    ["Owner", finding.data_owner || file?.owner || file?.department],
    ["Exact location", findingLocationText(file, finding)],
  ].filter(([, value]) => value !== undefined && value !== null && String(value).trim() !== "");
  if (!rows.length) return "";
  return `<div class="detail-chip-row finding-metadata-grid">${rows.map(([label, value]) => `<span><b>${escapeHtml(label)}:</b> ${escapeHtml(value)}</span>`).join("")}</div>`;
}

function renderFindingEvidenceSections(finding) {
  const sections = [
    ["Matched schema/context keywords", finding.matched_keywords || finding.keywords || []],
    ["Redacted value samples", finding.samples || []],
    ["Exact occurrence locations", (Array.isArray(finding.occurrences) ? finding.occurrences : []).map((occurrence) => formatObject(occurrence))],
    ["Framework and control mappings", compactEvidence([
      formatSignals(finding.framework_mappings),
      formatSignals(finding.requirement_mappings),
      formatSignals(finding.compliance_mappings),
      formatSignals(finding.mapped_controls),
    ])],
    ["Structural evidence", compactEvidence([
      finding.validation_status && `Validation: ${finding.validation_status}`,
      finding.luhn_valid !== undefined && `Luhn: ${finding.luhn_valid}`,
      finding.card_brand && `Brand: ${finding.card_brand}`,
      finding.emv_tag && `EMV tag: ${finding.emv_tag}`,
      finding.pin_block_format && `PIN block: ${finding.pin_block_format}`,
    ])],
    ["Detection quality", compactEvidence([
      finding.confidence_basis && `Confidence basis: ${formatDetailValue(finding.confidence_basis)}`,
      finding.scan_completeness && `Scan completeness: ${formatDetailValue(finding.scan_completeness)}`,
      finding.truncated !== undefined && `Truncated: ${finding.truncated}`,
      finding.partial !== undefined && `Partial: ${finding.partial}`,
    ])],
    ["Correlation evidence", compactEvidence([
      ...(finding.correlated_elements || []),
      finding.logical_boundary && `Boundary: ${finding.logical_boundary}`,
      finding.parent_finding_type && `Parent: ${finding.parent_finding_type}`,
      finding.child_finding_types?.length && `Children: ${finding.child_finding_types.join(", ")}`,
    ])],
    ["NIST detection evidence", compactEvidence([
      ...(finding.matched_signal_groups || []),
      finding.detection_mode && `Detection mode: ${finding.detection_mode}`,
      formatSignals(finding.contributing_signals),
      formatSignals(finding.negative_signals),
      finding.threshold && `Threshold: ${formatObject(finding.threshold)}`,
    ])],
    ["NIST classification context", compactEvidence([
      finding.impact_basis && `Impact basis: ${finding.impact_basis}`,
      finding.official_definition_en,
      finding.source_kind && `Source kind: ${finding.source_kind}`,
      finding.source_status && `Source status: ${finding.source_status}`,
      finding.governance_status && `Governance: ${finding.governance_status}`,
    ])],
    ["Protection state", compactEvidence([
      finding.claimed_protection_state && `Claimed: ${finding.claimed_protection_state}`,
      finding.verified_protection_state && `Verified: ${finding.verified_protection_state}`,
      finding.encryption_algorithm && `Algorithm: ${finding.encryption_algorithm}`,
      finding.key_id && `Key ID: ${finding.key_id}`,
      finding.token_provider && `Token provider: ${finding.token_provider}`,
      finding.hash_algorithm && `Hash: ${finding.hash_algorithm}`,
    ])],
  ];
  return sections
    .filter(([, values]) => Array.isArray(values) ? values.length : values)
    .map(([label, values]) => {
      const listValues = Array.isArray(values) ? values : [values];
      return `<div class="detail-evidence"><span>${escapeHtml(label)}</span><code>${escapeHtml(listValues.join(", "))}</code></div>`;
    })
    .join("");
}

function compactEvidence(values) {
  return values.filter(Boolean).map(String);
}

function renderReasonDetailList(file) {
  const complianceDetails = file?.compliance?.reason_details || [];
  const reasons = file?.risk?.reasons || [];
  const findingReasonRows = (file?.findings || []).map((finding) => ({
    category: dataTypesForFinding(finding).join(", ") || "Sensitive signal",
    reason: finding.description || `${findingDisplayName(finding)} detected`,
  }));
  const rows = [
    ...complianceDetails.map((item) => ({
      category: item.category || "Framework match",
      dataTypes: item.data_types || [],
      reason: item.reason || "",
    })),
    ...findingReasonRows,
    ...reasons.map((reason) => ({ category: inferReasonCategory(reason), dataTypes: [], reason })),
  ].filter((item) => item.reason);

  if (!rows.length) {
    return '<p class="subtext">No risk reasons were generated for this file.</p>';
  }

  return `
    <ol class="detail-list reasons">
      ${rows.map((item) => `
        <li>
          <strong>${escapeHtml(item.category || "Risk context")}</strong>
          ${item.dataTypes?.length ? `<div class="detail-chip-row">${item.dataTypes.map((type) => `<span>${escapeHtml(type)}</span>`).join("")}</div>` : ""}
          <p>${escapeHtml(item.reason)}</p>
        </li>
      `).join("")}
    </ol>
  `;
}

function dataTypesForFinding(finding = {}) {
  const category = String(finding.data_category || finding.category || "").toLowerCase();
  const pciCategory = String(finding.pci_category || "").toUpperCase();
  const visualFramework = findingVisualFramework(finding);
  if (visualFramework === "pci_dss" || pciCategory) {
    const labels = [];
    if (category === "pci_cardholder_data" || pciCategory === "CHD") labels.push("PCI Cardholder Data (CHD)");
    if (category === "pci_sensitive_authentication_data" || pciCategory === "SAD") labels.push("PCI Sensitive Authentication Data (SAD)");
    if (category === "pci_scope_context" || pciCategory === "CONTEXT") labels.push("PCI Scope Context");
    if (finding.data_element) labels.push(String(finding.data_element));
    if (finding.finding_category) labels.push(String(finding.finding_category));
    return [...new Set(labels)];
  }
  const categoryLabels = {
    pii: "Personal data",
    personal_data: "Personal data",
    government_ids: "Government ID",
    health_data: "Health Data / Special Category",
    biometric_data: "Biometric data",
    genetic_data: "Special-category data",
    special_category_context: "Special-category data",
    financial_records: "Financial records",
    hr_documents: "HR / employee data",
    credentials_secrets: "Credentials / secrets",
    credentials: "Credentials / secrets",
    legal_documents: "Legal documents",
    security_operations: "Security operations",
  };
  const labels = [
    categoryLabels[category],
    finding.personal_data_type && keywordCategoryLabel(finding.personal_data_type),
    finding.finding_category,
  ].filter((label) => label && !/compliance mapping/i.test(String(label)));
  return [...new Set(labels.map(String))];
}

function inferReasonCategory(reason = "") {
  const text = String(reason).toLowerCase();
  if (/hr|employee|payroll|salary|full name|personal|email|phone/.test(text)) return "Personal / HR data";
  if (/passport|national|ssn|fin|government/.test(text)) return "Government ID";
  if (/health|medical|patient|phi/.test(text)) return "Health Data / Special Category";
  if (/password|secret|token|key|credential/.test(text)) return "Credentials / secrets";
  if (/permission|broad|writable|everyone|access/.test(text)) return "Access exposure";
  if (/location|path|extension|archive|export/.test(text)) return "File context";
  return "Risk context";
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

    <section class="logic-section compliance-logic-section">
      <div class="logic-section-title">
        <span>Compliance mapping</span>
        <strong>${COMPLIANCE_LOGIC.length} framework${COMPLIANCE_LOGIC.length === 1 ? "" : "s"}</strong>
      </div>
      <div class="compliance-logic-list">
        ${COMPLIANCE_LOGIC.map(renderComplianceLogicItem).join("")}
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

function renderComplianceLogicItem(item) {
  return `
    <details class="compliance-logic-item">
      <summary>
        <span>
          <strong>${escapeHtml(item.name)}</strong>
          <small>${escapeHtml(item.scope)}</small>
        </span>
        <b>${escapeHtml(item.dataTypes.length)} data types</b>
      </summary>
      <div class="compliance-logic-body">
        <div class="compliance-logic-hero">
          <div>
            <span>Framework mapping model</span>
            <strong>${escapeHtml(item.name)} evidence pipeline</strong>
            <p>Signals are normalized into data types, weighted by exposure, then surfaced as file chips and report evidence.</p>
          </div>
          <div class="compliance-logic-score">
            <b>0-100</b>
            <span>compliance priority</span>
          </div>
        </div>
        <div class="compliance-logic-visual">
          <div>
            <em>01</em>
            <span>Evidence</span>
            <strong>Findings + keywords</strong>
          </div>
          <div>
            <em>02</em>
            <span>Mapping</span>
            <strong>${escapeHtml(item.name)} controls</strong>
          </div>
          <div>
            <em>03</em>
            <span>Score</span>
            <strong>Risk weighted</strong>
          </div>
          <div>
            <em>04</em>
            <span>Output</span>
            <strong>Report evidence</strong>
          </div>
        </div>
        <div class="compliance-logic-summary">
          <p>${escapeHtml(item.summary)}</p>
          <div class="compliance-logic-stats">
            <span><b>35%</b> risk component cap</span>
            <span><b>${escapeHtml(item.dataTypes.length)}</b> mapped data types</span>
            <span><b>4</b> evidence layers</span>
          </div>
        </div>
        <div class="logic-card-grid compliance-logic-grid">
          ${renderComplianceLogicBlock("Scoring model", item.scoring)}
          ${renderComplianceLogicBlock("Mapped data types", item.dataTypes)}
          ${renderComplianceLogicBlock("Evidence used", item.evidence)}
          ${renderComplianceLogicBlock("Output in scan/report", item.output)}
        </div>
        ${renderComplianceKeywordLibraryPanel(item)}
      </div>
    </details>
  `;
}

function renderComplianceLogicBlock(title, items = []) {
  return `
    <article class="logic-card compliance-logic-card">
      <div class="compliance-logic-card-head">
        <span>${escapeHtml(title.slice(0, 2).toUpperCase())}</span>
        <h4>${escapeHtml(title)}</h4>
      </div>
      <ul>
        ${items.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}
      </ul>
    </article>
  `;
}

function renderComplianceKeywordLibraryPanel(item) {
  const library = latestComplianceKeywordLibraries[item.id] || (latestComplianceKeywordLibrary?.framework === item.id ? latestComplianceKeywordLibrary : {});
  const groups = library.groups || [];
  const customGroups = groups.filter((group) => group.source === "custom");
  const totalTerms = library.total_terms || 0;
  const customTerms = library.custom_terms || 0;
  const typeOptions = keywordFindingTypeOptions(groups, item.id);
  const categoryOptions = keywordCategoryOptions(typeOptions);
  return `
    <section class="keyword-library-panel" data-keyword-framework="${escapeHtml(item.id)}">
      <div class="keyword-library-head">
        <div>
          <span>Keyword library</span>
          <strong>Import / export detection terms</strong>
          <p>Maintain tenant-specific ${escapeHtml(item.name)} dictionaries without replacing the built-in detection layer.</p>
        </div>
        <div class="keyword-library-metrics">
          <span><b>${escapeHtml(totalTerms)}</b>Total terms</span>
          <span><b>${escapeHtml(customTerms)}</b>Custom terms</span>
          <span><b>${escapeHtml(customGroups.length)}</b>Custom groups</span>
        </div>
      </div>
      <div class="keyword-library-actions">
        <label>
          <span>Category</span>
          <select data-keyword-category-select>
            ${categoryOptions.map(([value, label]) => `<option value="${escapeHtml(value)}">${escapeHtml(label)}</option>`).join("")}
            <option value="__custom__">Custom category...</option>
          </select>
        </label>
        <label>
          <span>Finding type</span>
          <select data-keyword-type>
            <option value="all" data-keyword-option-category="all">All finding types</option>
            ${typeOptions.map((option) => `<option value="${escapeHtml(option.type)}" title="${escapeHtml(option.meta)}" data-keyword-option-category="${escapeHtml(option.category)}" data-keyword-option-label="${escapeHtml(option.label)}" data-keyword-option-risk="${escapeHtml(option.risk)}">${escapeHtml(option.label)}</option>`).join("")}
            <option value="__custom__" data-keyword-option-category="__custom__" hidden>Custom finding type...</option>
          </select>
        </label>
        <label>
          <span>Import mode</span>
          <select data-keyword-mode>
            <option value="merge">Add only new terms</option>
            <option value="replace_type">Replace matching finding types</option>
            <option value="replace_category">Replace matching data categories</option>
            <option value="replace_framework">Replace all custom ${escapeHtml(item.name)} terms</option>
          </select>
        </label>
        <label class="keyword-file-picker">
          <span>Import file</span>
          <input type="file" data-keyword-file accept=".json,.csv,.txt,text/plain,application/json,text/csv" />
        </label>
      </div>
      <div class="keyword-custom-grid">
        <label>
          <span>Custom category</span>
          <input type="text" data-keyword-category placeholder="custom, legal, finance" disabled />
        </label>
        <label>
          <span>Custom finding</span>
          <input type="text" data-keyword-custom-type placeholder="custom_sensitive_marker" disabled />
        </label>
        <label>
          <span>Display label</span>
          <input type="text" data-keyword-label placeholder="Sensitive marker" disabled />
        </label>
        <label>
          <span>Risk</span>
          <select data-keyword-risk disabled>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
            <option value="HIGH">High</option>
            <option value="CRITICAL">Critical</option>
          </select>
        </label>
      </div>
      <div class="keyword-library-buttons">
        <button type="button" class="secondary-btn mini-btn" data-keyword-action="validate">Preview import</button>
        <button type="button" class="secondary-btn mini-btn" data-keyword-action="import">Import keywords</button>
        <button type="button" class="secondary-btn mini-btn" data-keyword-action="export-json">Export JSON</button>
        <button type="button" class="secondary-btn mini-btn" data-keyword-action="export-csv">Export CSV</button>
        <button type="button" class="secondary-btn mini-btn" data-keyword-action="template">Download template</button>
      </div>
      <div class="keyword-import-status" data-keyword-import-status>${library.framework ? "Ready for import/export." : "Keyword library will load after sign-in."}</div>
      <div class="keyword-import-preview hidden" data-keyword-import-preview></div>
      <div class="keyword-import-guide">
        <div>
          <strong>TXT import</strong>
          <span>Choose a category, then pick a finding type. Select Custom category to enable custom category, finding, label, and risk fields.</span>
          <code>employee legal name, customer full name, beneficiary name</code>
        </div>
        <div>
          <strong>CSV / JSON import</strong>
          <span>Use CSV/JSON for multiple finding types. Include category, label, and risk when adding custom findings.</span>
          <code>keyword,type,category,label,risk</code>
        </div>
        <div>
          <strong>Mode policy</strong>
          <span>Add only is safest for production. Replace modes affect only the custom layer, never built-in detections.</span>
          <code>preview before import</code>
        </div>
        <div>
          <strong>Match quality</strong>
          <span>Imported phrases are matched case-insensitively with word boundaries to reduce accidental hits.</span>
          <code>clinical diagnosis != misdiagnosis</code>
        </div>
      </div>
    </section>
  `;
}

const NIST_RULE_NAME_TAXONOMY = {
  nist_identity_management: ["User Identity Records", "Account Registry Records", "Access Entitlement Records", "Privileged Access Records", "Authentication Event Records", "Identity Proofing Records", "Directory Synchronization Records"],
  nist_privacy_pii: ["Sensitive Personally Identifiable Information", "General Privacy Information", "Contact Information", "Government Identifier Records", "Demographic Records", "Biometric Identifier Records", "Online Identifier Records", "Location Privacy Records", "Household and Family Records", "Financial Privacy Records", "Education Privacy Records", "Employment Privacy Records", "Health Privacy Records", "Behavioral Privacy Records", "Consent and Preference Records", "Privacy Case Records"],
  nist_financial: ["Financial Account Records", "Payment Card and Transaction Records", "Bank Routing and Transfer Records", "Invoice and Billing Records", "Payroll Financial Records", "Treasury and Cash Management Records", "Audit-Ready Financial Statements"],
  nist_health: ["Health Information", "Clinical Encounter Records", "Medication and Prescription Records", "Insurance and Benefits Records", "Genetic Information", "Mental Health and Substance Use Records", "Medical Device and Laboratory Records"],
  nist_legal: ["Legal Matter Records", "Contract Records", "Law Enforcement Records", "Litigation Hold Records", "Case Investigation Records", "Regulatory Filing Records", "Evidence and Discovery Records"],
  nist_hr: ["Personnel Records", "Military Personnel Records", "Employee Benefits Records", "Recruiting and Applicant Records", "Performance Review Records", "Workforce Investigation Records", "Training and Certification Records"],
  nist_customer: ["Customer Records", "CRM Account Records", "Customer Support Records", "Sales Opportunity Records", "Customer Contract Records", "Customer Billing Records", "Customer Communications Records"],
  nist_research: ["Research Data", "Experiment Results", "Clinical Research Records", "Product Design Records", "Prototype Evaluation Records", "Grant and Sponsored Research Records", "Research Collaboration Records"],
  nist_security_operations: ["Sensitive Security Information", "Vulnerability Scans and Penetration Test Reports", "Incident Response Records", "Threat Intelligence Records", "Security Monitoring Logs", "Security Architecture Review Records", "Security Exception Records"],
  nist_credentials_secrets: ["API Keys, Access Tokens and OAuth Secrets", "Private Keys and Certificates", "Service Account Credentials", "Database Connection Secrets", "Cloud Access Credentials", "Encryption Key Material", "Password and Recovery Secrets"],
  nist_source_code: ["Source Code and Algorithms", "Build Pipeline Records", "Repository Metadata", "Software Bill of Materials", "Release and Deployment Records", "Code Review Records", "Package Signing Records"],
  nist_infrastructure: ["Network Diagrams and Architecture", "System Architecture Records", "Firewall and Routing Configurations", "Cloud Infrastructure Inventory", "Endpoint and Server Inventory", "Privileged Infrastructure Access Records", "Backup and Recovery Architecture"],
  nist_procurement: ["Procurement Records", "Vendor Due Diligence Records", "Purchase Order Records", "Supplier Contract Records", "Third-Party Risk Records", "Solicitation and Bid Records", "Vendor Performance Records"],
  nist_export_control: ["Controlled Technical Information", "Export Controlled Research Records", "ITAR Technical Data", "EAR Controlled Technology Records", "Sanctions Screening Records", "Foreign National Access Records"],
  nist_tax: ["Federal Taxpayer Information", "Tax Return Records", "Tax Account Transcripts", "Withholding and Payroll Tax Records", "Treasury Reporting Records", "Tax Audit Records"],
  nist_audit: ["Audit and Compliance Evidence", "Control Test Evidence", "Policy Exception Records", "Risk Assessment Records", "Compliance Attestation Records", "Internal Audit Workpapers"],
  nist_education: ["Student Records", "Academic Transcript Records", "Enrollment and Registration Records", "Financial Aid Records", "Student Conduct Records", "Education Accommodation Records"],
  nist_public_safety: ["Public Safety Information", "Emergency Response Records", "Dispatch and Incident Records", "Critical Infrastructure Safety Records", "Responder Credential Records", "Public Warning Records"],
  nist_geospatial: ["Geospatial and Facility Information", "Facility Floor Plans", "Critical Site Coordinates", "Utility and Infrastructure Maps", "Asset Location Records", "Restricted Area Mapping Records"],
  nist_intellectual_property: ["Trade Secrets and Intellectual Property", "Patent Draft Records", "Invention Disclosure Records", "Product Roadmap Records", "Competitive Strategy Records", "Confidential Design Records"],
  nist_public_context: ["Approved Public Release Context", "Publication Review Records", "Press Release Approval Records", "Public Dataset Release Records", "Disclosure Review Records", "Communication Clearance Records"],
  nist_records_management: ["Records Retention Metadata", "Legal Hold Metadata", "Disposition Schedule Records", "Archive Inventory Records", "Records Classification Metadata", "Retention Exception Records"],
};

function keywordFindingTypeOptions(groups = [], framework = "gdpr") {
  const fallback = keywordFallbackOptions(framework);
  const source = groups.length ? groups : fallback;
  const seen = new Set();
  const options = [];
  source.forEach((group) => {
    const type = group.type || "";
    if (!type || seen.has(type)) return;
    seen.add(type);
    const category = normalizeKeywordCategory(framework, group.category || group.category_id || "custom");
    const label = keywordFindingTypeLabel(group, framework, category);
    const risk = group.risk || "MEDIUM";
    const tier = group.handling_tier || "";
    const meta = [frameworkLabel(framework), keywordCategoryLabel(category), tier, risk].filter(Boolean).join(" · ");
    options.push({ type, label, category, risk, meta });
  });
  return options.sort((a, b) => severitySortRank(a.risk) - severitySortRank(b.risk) || a.label.localeCompare(b.label));
}

function keywordFindingTypeLabel(group = {}, framework = "gdpr", category = "") {
  if (framework === "nist_sp800_60_enterprise") {
    const candidate = [group.display_name, group.official_name, group.service, group.label, group.data_type]
      .map((value) => cleanGeneratedTypeName(value))
      .find((value) => value && !isGeneratedTypeLabel(value) && !isCategoryOnlyNistLabel(value, category));
    if (candidate) return candidate;
    return nistTaxonomyName(group, category) || cleanGeneratedTypeName(group.rule_id || group.type || "Unnamed NIST finding");
  }
  return cleanGeneratedTypeName(group.display_name || group.label || group.data_type || group.service || group.type || "Unnamed finding");
}

function nistTaxonomyName(group = {}, category = "") {
  const taxonomy = NIST_RULE_NAME_TAXONOMY[category] || [];
  const ordinal = nistRuleOrdinal(group);
  return taxonomy.length && ordinal >= 1 ? taxonomy[(ordinal - 1) % taxonomy.length] : "";
}

function nistRuleOrdinal(group = {}) {
  const text = [group.type, group.rule_id, group.label, group.data_type].filter(Boolean).join(" ");
  const match = text.match(/(?:type[_\s-]?|[-_])0*(\d{1,3})\b/i);
  return match ? Math.max(1, Number(match[1]) || 1) : 1;
}

function isGeneratedTypeLabel(value = "") {
  return /\bType\s+\d+\b/i.test(String(value || "")) || /_type_0*\d+\b/i.test(String(value || ""));
}

function isCategoryOnlyNistLabel(value = "", category = "") {
  const normalizedValue = cleanGeneratedTypeName(value).toLowerCase();
  const normalizedCategory = keywordCategoryLabel(category).replace(/^NIST\s+/i, "").toLowerCase();
  return normalizedValue === normalizedCategory || normalizedValue === normalizedCategory.replace(/\s+information$/, "");
}

function severitySortRank(value = "") {
  return { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }[String(value || "").toUpperCase()] ?? 9;
}

function keywordFallbackOptions(framework = "gdpr") {
  if (framework === "pci_dss") {
    return [
      { type: "pci_chd_pan", label: "PCI-CHD-PAN - Primary Account Number", category: "pci_cardholder_data", risk: "CRITICAL" },
      { type: "pci_chd_cardholder_name", label: "PCI-CHD-NAME - Cardholder Name", category: "pci_cardholder_data", risk: "HIGH" },
      { type: "pci_chd_expiration_date", label: "PCI-CHD-EXP - Expiration Date", category: "pci_cardholder_data", risk: "HIGH" },
      { type: "pci_chd_service_code", label: "PCI-CHD-SVC - Service Code", category: "pci_cardholder_data", risk: "HIGH" },
      { type: "pci_enriched_chd_record", label: "PCI-CHD-COMPLETE - Complete CHD Record", category: "pci_cardholder_data", risk: "CRITICAL" },
      { type: "pci_sad_track_data", label: "PCI-SAD-TRACK - Full Track Data", category: "pci_sensitive_authentication_data", risk: "CRITICAL" },
      { type: "pci_sad_cvv", label: "PCI-SAD-CVV - CAV2 / CVC2 / CVV2 / CID", category: "pci_sensitive_authentication_data", risk: "CRITICAL" },
      { type: "pci_sad_pin", label: "PCI-SAD-PIN - PIN", category: "pci_sensitive_authentication_data", risk: "CRITICAL" },
      { type: "pci_sad_pin_block", label: "PCI-SAD-PIN-BLOCK - PIN Block", category: "pci_sensitive_authentication_data", risk: "CRITICAL" },
      { type: "pci_composite_sad", label: "PCI-SAD-COMPOSITE - PAN + SAD", category: "pci_sensitive_authentication_data", risk: "CRITICAL" },
      { type: "pci_payment_context", label: "PCI-CTX - Payment Scope Context", category: "pci_scope_context", risk: "MEDIUM" },
    ];
  }
  if (framework === "nist_sp800_60_enterprise") {
    return [
      { type: "nist_privacy_pii_type_01", label: "NIST PII overlay", category: "nist_privacy_pii", risk: "HIGH" },
      { type: "nist_credentials_secrets_type_01", label: "NIST credential overlay", category: "nist_credentials_secrets", risk: "CRITICAL" },
      { type: "nist_security_operations_type_01", label: "NIST security operations overlay", category: "nist_security_operations", risk: "HIGH" },
      { type: "nist_financial_type_01", label: "NIST financial records overlay", category: "nist_financial", risk: "HIGH" },
    ];
  }
  return [
    { type: "gdpr_full_name", label: "Full name", category: "pii" },
    { type: "gdpr_email_address", label: "Email address", category: "contact" },
    { type: "gdpr_phone_number", label: "Phone number", category: "contact" },
    { type: "gdpr_passport_number", label: "Passport number", category: "government_ids" },
    { type: "gdpr_national_id", label: "National ID", category: "government_ids" },
    { type: "gdpr_health_medical_record", label: "Health / medical", category: "health" },
    { type: "gdpr_salary_compensation", label: "Salary / compensation", category: "hr" },
    { type: "gdpr_hr_employee_file", label: "HR employee file", category: "hr" },
    { type: "gdpr_invoice_billing_transaction_log", label: "Customer / invoice", category: "financial" },
    { type: "gdpr_password_secret", label: "Password / secret", category: "credentials" },
  ];
}

function keywordCategoryOptions(typeOptions = []) {
  const counts = typeOptions.reduce((map, option) => {
    if (option.category) map[option.category] = (map[option.category] || 0) + 1;
    return map;
  }, {});
  const categories = Object.keys(counts).sort((a, b) => keywordCategoryLabel(a).localeCompare(keywordCategoryLabel(b)));
  return [["all", "All categories"], ...categories.map((category) => [category, `${keywordCategoryLabel(category)} (${counts[category]})`])];
}

function normalizeKeywordCategory(framework, category) {
  const normalized = String(category || "custom").trim().toLowerCase().replaceAll("-", "_").replaceAll(" ", "_");
  if (framework === "nist_sp800_60_enterprise") return normalized.startsWith("nist_") || normalized === "custom" ? normalized : `nist_${normalized}`;
  if (framework !== "pci_dss") return normalized;
  const aliases = {
    pci: "pci_scope_context",
    pci_payment: "pci_scope_context",
    payment: "pci_scope_context",
    cardholder_data: "pci_cardholder_data",
    chd: "pci_cardholder_data",
    sensitive_authentication_data: "pci_sensitive_authentication_data",
    sad: "pci_sensitive_authentication_data",
  };
  return aliases[normalized] || (normalized.startsWith("pci_") ? normalized : `pci_${normalized}`);
}

function keywordCategoryLabel(category) {
  const labels = {
    pci_cardholder_data: "PCI Cardholder Data (CHD)",
    pci_sensitive_authentication_data: "PCI Sensitive Authentication Data (SAD)",
    pci_scope_context: "PCI Scope Context",
    pci_payment_secret: "PCI Payment Secret",
    nist_privacy_pii: "NIST PII",
    nist_credentials_secrets: "NIST credentials and secrets",
    nist_security_operations: "NIST security operations",
    nist_financial: "NIST financial records",
    nist_health: "NIST health information",
    nist_legal: "NIST legal information",
    nist_hr: "NIST human resources",
    nist_customer: "NIST customer records",
    nist_compliance_mapping: "Mapped data",
    nist_audit: "NIST audit",
    nist_education: "NIST education",
    nist_export_control: "NIST export control",
    nist_geospatial: "NIST geospatial",
    nist_identity_management: "NIST identity management",
    nist_infrastructure: "NIST infrastructure",
    nist_intellectual_property: "NIST intellectual property",
    nist_procurement: "NIST procurement",
    nist_public_context: "NIST public context",
    nist_public_safety: "NIST public safety",
    nist_records_management: "NIST records management",
    nist_research: "NIST research",
    nist_source_code: "NIST source code",
    nist_tax: "NIST tax and treasury",
    pii: "Personal data",
    government_ids: "Government IDs",
    financial: "Financial",
    credentials: "Credentials",
    health: "Health",
    hr: "HR",
  };
  return labels[category] || String(category || "").replaceAll("_", " ");
}

function frameworkExportName(framework = "") {
  const normalized = normalizeFrameworkId(framework);
  if (normalized === "nist_sp800_60_enterprise") return "NIST";
  if (normalized === "pci_dss") return "PCI_DSS";
  if (normalized === "gdpr") return "GDPR";
  return String(framework || "framework").replace(/[^a-z0-9_-]+/gi, "_");
}

function keywordLibraryExportView(library = {}, framework = "") {
  const displayName = frameworkExportName(library.framework || framework);
  return {
    ...library,
    framework: displayName,
    catalog_status: library.catalog_status && typeof library.catalog_status === "object"
      ? { ...library.catalog_status, framework: displayName }
      : library.catalog_status,
    groups: (library.groups || []).map((group) => ({
      ...group,
      framework: group.framework ? frameworkExportName(group.framework) : displayName,
    })),
  };
}

function updateKeywordCustomState(panel) {
  if (!panel) return;
  const categorySelect = panel.querySelector("[data-keyword-category-select]");
  const typeSelect = panel.querySelector("[data-keyword-type]");
  const isCustom = categorySelect?.value === "__custom__";
  if (isCustom && typeSelect) {
    typeSelect.value = "__custom__";
    typeSelect.disabled = true;
  } else if (typeSelect) {
    typeSelect.disabled = false;
  }
  panel.querySelectorAll("[data-keyword-category], [data-keyword-custom-type], [data-keyword-label], [data-keyword-risk]").forEach((field) => {
    field.disabled = !isCustom;
    field.closest("label")?.classList.toggle("disabled", !isCustom);
  });
}

function updateKeywordTypeOptions(panel) {
  if (!panel) return;
  const category = panel.querySelector("[data-keyword-category-select]")?.value || "all";
  const typeSelect = panel.querySelector("[data-keyword-type]");
  if (!typeSelect) return;
  [...typeSelect.options].forEach((option) => {
    const optionCategory = option.dataset.keywordOptionCategory || "";
    option.hidden = optionCategory === "__custom__"
      ? category !== "__custom__"
      : category !== "all" && category !== "__custom__" && !["all", category].includes(optionCategory);
  });
  const selected = typeSelect.selectedOptions[0];
  if (category !== "__custom__" && selected?.hidden) {
    typeSelect.value = "all";
  }
  updateKeywordCustomState(panel);
}

function renderRiskRulesCache() {
  if (latestRiskRules.length) {
    renderRiskRules(latestRiskRules);
  }
}

async function loadComplianceKeywordLibrary(framework = "gdpr") {
  if (!accessToken) return;
  try {
    latestComplianceKeywordLibrary = await api(`/api/compliance-keywords?framework=${encodeURIComponent(framework)}`, null, "GET");
    latestComplianceKeywordLibraries[framework] = latestComplianceKeywordLibrary;
    renderRiskRulesCache();
  } catch (error) {
    try {
      if (framework !== "gdpr") throw error;
      const response = await fetch("/static/compliance_keywords_gdpr_builtin.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`Static fallback failed: ${response.status}`);
      latestComplianceKeywordLibrary = await response.json();
      latestComplianceKeywordLibraries[framework] = latestComplianceKeywordLibrary;
      renderRiskRulesCache();
      setKeywordImportStatus("Showing built-in GDPR keywords from static fallback. Restart backend to enable import/preview API.", "warning");
    } catch {
      setKeywordImportStatus(`Keyword library failed: ${error.message}`, "danger");
    }
  }
}

async function loadAllComplianceKeywordLibraries() {
  for (const item of COMPLIANCE_LOGIC) {
    await loadComplianceKeywordLibrary(item.id);
  }
}

async function reloadComplianceKeywordLibraryInPlace(framework = "gdpr") {
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;
  latestComplianceKeywordLibrary = await api(`/api/compliance-keywords?framework=${encodeURIComponent(framework)}`, null, "GET");
  latestComplianceKeywordLibraries[framework] = latestComplianceKeywordLibrary;
  window.requestAnimationFrame(() => {
    window.scrollTo(scrollX, scrollY);
    window.requestAnimationFrame(() => window.scrollTo(scrollX, scrollY));
  });
}

function setKeywordImportStatus(message, tone = "", panel = document) {
  const status = panel?.querySelector("[data-keyword-import-status]") || document.querySelector("[data-keyword-import-status]");
  if (!status) return;
  status.textContent = message;
  status.className = `keyword-import-status ${tone}`.trim();
}

function keywordPanelPayload(panel) {
  const selectedCategory = panel?.querySelector("[data-keyword-category-select]")?.value || "all";
  const selectedType = panel?.querySelector("[data-keyword-type]")?.value || "all";
  const selectedOption = panel?.querySelector("[data-keyword-type]")?.selectedOptions?.[0];
  const isCustom = selectedCategory === "__custom__";
  const customType = cleanKeywordToken(panel?.querySelector("[data-keyword-custom-type]")?.value || "");
  const category = isCustom
    ? cleanKeywordToken(panel?.querySelector("[data-keyword-category]")?.value || "custom") || "custom"
    : (selectedCategory === "all" ? (selectedOption?.dataset.keywordOptionCategory || "") : selectedCategory);
  const label = isCustom
    ? (panel?.querySelector("[data-keyword-label]")?.value || "").trim()
    : (selectedOption?.dataset.keywordOptionLabel || "");
  const risk = isCustom
    ? (panel?.querySelector("[data-keyword-risk]")?.value || "MEDIUM").toUpperCase()
    : (selectedOption?.dataset.keywordOptionRisk || "MEDIUM").toUpperCase();
  return {
    framework: panel?.dataset.keywordFramework || "gdpr",
    language: "custom",
    mode: panel?.querySelector("[data-keyword-mode]")?.value || "merge",
    type: isCustom || selectedType === "__custom__" ? customType : selectedType,
    category,
    label,
    risk,
    isCustomType: isCustom,
  };
}

function cleanKeywordToken(value) {
  return String(value || "").trim().toLowerCase().replace(/-/g, "_").replace(/[^a-z0-9_]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 80);
}

async function readKeywordImportPayload(panel) {
  const settings = keywordPanelPayload(panel);
  const file = panel?.querySelector("[data-keyword-file]")?.files?.[0];
  if (!file) throw new Error("Choose a JSON, CSV, or TXT keyword file first.");
  const text = await file.text();
  const extension = file.name.toLowerCase().split(".").pop();
  if (extension === "json") {
    const parsed = JSON.parse(text);
    const nistRuleOverlays = Array.isArray(parsed.rules)
      ? parsed.rules.map((rule) => {
          const groups = rule.detection?.keyword_groups || {};
          return {
            framework: settings.framework,
            language: parsed.language || settings.language,
            category: rule.category_id || rule.category || settings.category,
            type: rule.type,
            label: rule.label || rule.type,
            risk: rule.classification?.product_severity || "MEDIUM",
            terms: [
              ...(groups.primary_and_aliases || []),
              ...(groups.schema_and_field_names || []),
              ...(groups.azerbaijani_terms || []),
            ],
            negative_keywords: groups.negative_and_exclusion_context || [],
            structured_field_names: groups.schema_and_field_names || [],
          };
        }).filter((group) => group.type)
      : [];
    return {
      framework: settings.framework,
      language: parsed.language || settings.language,
      mode: parsed.mode || settings.mode || "merge",
      keywords: parsed.keywords || parsed.groups || nistRuleOverlays,
    };
  }
  if (extension === "csv") {
    return {
      framework: settings.framework,
      language: settings.language,
      mode: settings.mode,
      keywords: parseKeywordCsv(text, settings),
    };
  }
  if (!settings.type || settings.type === "all") {
    throw new Error("TXT import needs one specific finding type. Use JSON or CSV when importing multiple finding types.");
  }
  const terms = parseKeywordText(text);
  return {
    framework: settings.framework,
    language: settings.language,
    mode: settings.mode,
    keywords: [{
      framework: settings.framework,
      language: settings.language,
      category: settings.category,
      type: settings.type,
      label: settings.label || settings.type.replaceAll("_", " "),
      risk: settings.risk,
      terms,
    }],
  };
}

function parseKeywordText(text) {
  return text
    .split(/\r?\n/)
    .flatMap((line) => line.split(/[,\t;|]+/))
    .map((item) => item.trim().replace(/^["']|["']$/g, ""))
    .filter((item) => item && !item.startsWith("#"));
}

function parseKeywordCsv(text, settings) {
  const rows = text.split(/\r?\n/).filter((line) => line.trim());
  if (!rows.length) return [];
  const headers = splitCsvRow(rows[0]).map((item) => item.trim().toLowerCase());
  const hasHeader = headers.includes("keyword") || headers.includes("term") || headers.includes("type");
  const dataRows = hasHeader ? rows.slice(1) : rows;
  const buckets = new Map();
  dataRows.forEach((row) => {
    const cells = splitCsvRow(row);
    const get = (name, fallback = "") => {
      const index = headers.indexOf(name);
      return index >= 0 ? cells[index] || fallback : fallback;
    };
    const keyword = hasHeader ? get("keyword", get("term", "")) : cells[0];
    const type = hasHeader ? get("type", settings.type === "all" ? "" : settings.type) : (settings.type === "all" ? "" : settings.type);
    const language = hasHeader ? get("language", settings.language) : settings.language;
    const category = hasHeader ? get("category", settings.category) : settings.category;
    const label = hasHeader ? get("label", settings.label) : settings.label;
    const risk = (hasHeader ? get("risk", settings.risk) : settings.risk || "MEDIUM").toUpperCase();
    const keywords = parseKeywordText(keyword);
    if (!keywords.length || !type) return;
    const key = `${language}|${category}|${type}|${label}|${risk}`;
    if (!buckets.has(key)) {
      buckets.set(key, { framework: settings.framework, language, category, type, label, risk, terms: [] });
    }
    buckets.get(key).terms.push(...keywords);
  });
  return [...buckets.values()];
}

function splitCsvRow(row) {
  const cells = [];
  let current = "";
  let quoted = false;
  for (let index = 0; index < row.length; index += 1) {
    const char = row[index];
    if (char === '"' && row[index + 1] === '"') {
      current += '"';
      index += 1;
    } else if (char === '"') {
      quoted = !quoted;
    } else if (char === "," && !quoted) {
      cells.push(current.trim());
      current = "";
    } else {
      current += char;
    }
  }
  cells.push(current.trim());
  return cells;
}

async function handleKeywordAction(action, panel) {
  if (!panel) return;
  try {
    if (action === "validate" || action === "import") {
      const payload = await readKeywordImportPayload(panel);
      const result = await api(`/api/compliance-keywords/${action === "validate" ? "validate" : "import"}`, payload);
      const unknown = (result.unknown_types || []).length ? ` Unknown types: ${result.unknown_types.join(", ")}.` : "";
      const summary = `${result.new_terms || 0} new, ${result.duplicates || 0} duplicates, ${result.group_count || 0} groups.${unknown}`;
      if (action === "import") {
        await reloadComplianceKeywordLibraryInPlace(payload.framework || "gdpr");
        showToast(unknown ? "Keyword import needs review" : "Keywords imported", summary, unknown ? "warning" : "success");
      } else {
        setKeywordImportStatus(`Preview: ${summary}`, unknown ? "warning" : "", panel);
      }
      renderKeywordImportPreview(result, panel);
      return;
    }
    if (action === "template") {
      const settings = keywordPanelPayload(panel);
      let template;
      try {
        template = await api(`/api/compliance-keywords/template?framework=${encodeURIComponent(settings.framework)}&language=custom`, null, "GET");
      } catch {
        template = buildKeywordTemplate(settings.framework);
      }
      downloadFile(`${frameworkExportName(settings.framework)}_keyword_template.json`, JSON.stringify(template, null, 2), "application/json;charset=utf-8");
      setKeywordImportStatus("Template downloaded.", "", panel);
      renderKeywordImportPreview({ groups: template.keywords || [], new_terms: (template.keywords || []).reduce((total, group) => total + (group.terms || []).length, 0) }, panel);
      return;
    }
    if (action === "export-json" || action === "export-csv") {
      const settings = keywordPanelPayload(panel);
      const format = action === "export-csv" ? "csv" : "json";
      await exportComplianceKeywords(settings.framework, "", format);
      setKeywordImportStatus(`Exported ${format.toUpperCase()}.`, "", panel);
    }
  } catch (error) {
    setKeywordImportStatus(error.message, "danger", panel);
    renderKeywordImportPreview(null, panel);
  }
}

function renderKeywordImportPreview(result, panel = document) {
  const preview = panel?.querySelector("[data-keyword-import-preview]") || document.querySelector("[data-keyword-import-preview]");
  if (!preview) return;
  const groups = result?.groups || [];
  if (!groups.length) {
    preview.classList.add("hidden");
    preview.innerHTML = "";
    return;
  }
  preview.classList.remove("hidden");
  preview.innerHTML = `
    <div class="keyword-preview-head">
      <strong>Import preview</strong>
      <span>${escapeHtml(result.new_terms || 0)} new terms &middot; ${escapeHtml(result.duplicates || 0)} duplicates</span>
    </div>
    <div class="keyword-preview-grid">
      ${groups.map((group) => `
        <article class="keyword-preview-card">
          <div class="keyword-preview-card-head">
            <span class="badge ${escapeHtml(group.risk || "MEDIUM")}">${escapeHtml(group.risk || "MEDIUM")}</span>
            <strong>${escapeHtml(group.label || group.type || "Custom finding")}</strong>
          </div>
          <dl>
            <div><dt>Category</dt><dd>${escapeHtml(keywordCategoryLabel(group.category || "custom"))}</dd></div>
            <div><dt>Type</dt><dd>${escapeHtml(group.type || "")}</dd></div>
            <div><dt>Language</dt><dd>${escapeHtml(group.language || "custom")}</dd></div>
          </dl>
          <div class="keyword-preview-terms">
            ${(group.terms || []).slice(0, 8).map((term) => `<span>${escapeHtml(term)}</span>`).join("")}
            ${(group.terms || []).length > 8 ? `<span>+${escapeHtml((group.terms || []).length - 8)} more</span>` : ""}
          </div>
        </article>
      `).join("")}
    </div>
  `;
}

function buildKeywordTemplate(framework = "gdpr") {
  if (framework === "pci_dss") {
    return {
      framework,
      mode: "merge",
      keywords: [
        {
          framework,
          language: "custom",
          category: "pci_cardholder_data",
          type: "pci_chd_pan",
          label: "Primary Account Number",
          risk: "CRITICAL",
          terms: ["primary account number", "card number", "full pan"]
        },
        {
          framework,
          language: "custom",
          category: "pci_sensitive_authentication_data",
          type: "pci_sad_cvv",
          label: "Card Verification Code / Value",
          risk: "CRITICAL",
          terms: ["cvv", "cvc2", "card security code"]
        },
        {
          framework,
          language: "custom",
          category: "pci_scope_context",
          type: "pci_payment_context",
          label: "Payment Scope Context",
          risk: "MEDIUM",
          terms: ["payment gateway", "cardholder data environment", "processor export"]
        }
      ],
      notes: [
        "PCI DSS categories should stay under pci_cardholder_data, pci_sensitive_authentication_data, or pci_scope_context.",
        "Custom PCI context terms are triage evidence; CHD/SAD confirmation still depends on structural PCI detectors.",
        "Raw PAN, CVV, PIN, and track values are not stored in findings."
      ]
    };
  }
  return {
    framework,
    mode: "merge",
    keywords: [
      {
        framework,
        language: "custom",
        category: "pii",
        type: "gdpr_full_name",
        label: "Full name",
        risk: "LOW",
        terms: ["employee legal name", "customer full name", "beneficiary name"]
      },
      {
        framework,
        language: "custom",
        category: "government_ids",
        type: "gdpr_passport_number",
        label: "Passport number",
        risk: "HIGH",
        terms: ["passport number", "passport document number", "travel document identifier"]
      },
      {
        framework,
        language: "custom",
        category: "health",
        type: "gdpr_health_medical_record",
        label: "Health / medical",
        risk: "HIGH",
        terms: ["medical record number", "clinical diagnosis", "patient treatment plan"]
      },
      {
        framework,
        language: "custom",
        category: "custom",
        type: "custom_sensitive_marker",
        label: "Custom sensitive marker",
        risk: "MEDIUM",
        terms: ["custom approval marker", "restricted project codename"]
      }
    ],
    notes: [
      "JSON supports framework, language, category, type, label, risk, and terms.",
      "CSV supports keyword,type,category,label,risk columns.",
      "TXT uses the selected finding type or custom fields in the UI."
    ]
  };
}

async function exportComplianceKeywords(framework, language, format) {
  const response = await fetch(`/api/compliance-keywords/export?framework=${encodeURIComponent(framework)}&language=${encodeURIComponent(language)}&format=${encodeURIComponent(format)}`, {
    method: "GET",
    headers: authHeaders(),
  });
  if (!response.ok) {
    if (latestComplianceKeywordLibraries[framework] || latestComplianceKeywordLibrary) {
      exportComplianceKeywordsFromClient(framework, language, format);
      return;
    }
    throw new Error(await readErrorMessage(response));
  }
  const blob = await response.blob();
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="([^"]+)"/);
  const filename = match?.[1] || `${frameworkExportName(framework)}_keywords.${format}`;
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function exportComplianceKeywordsFromClient(framework, language, format) {
  const library = latestComplianceKeywordLibraries[framework] || latestComplianceKeywordLibrary || { groups: [] };
  const exportLibrary = keywordLibraryExportView(library, framework);
  const groups = (exportLibrary.groups || []).filter((group) => !language || group.language === language || group.language === "built-in");
  const filename = `${frameworkExportName(framework)}_keywords_${language || "all"}.${format}`;
  if (format === "csv") {
    const rows = [["framework", "language", "category", "type", "label", "source", "keyword"]];
    groups.forEach((group) => {
      (group.terms || []).forEach((term) => {
        rows.push([group.framework, group.language, group.category, group.type, group.label || "", group.source || "", term]);
      });
    });
    const csv = `\uFEFF${rows.map((row) => row.map((cell) => `"${String(cell ?? "").replaceAll('"', '""')}"`).join(",")).join("\n")}`;
    downloadFile(filename, csv, "text/csv;charset=utf-8");
    return;
  }
  downloadFile(filename, JSON.stringify({ ...exportLibrary, groups }, null, 2), "application/json;charset=utf-8");
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

function profileAvatarStorageKey(username = currentUser, tenant = currentTenant) {
  return `dspm-avatar-${String(tenant || "default").toLowerCase()}-${String(username || "user").toLowerCase()}`;
}

function applyProfileAvatarElement(element, imageData, fallbackInitial) {
  if (!element) return;
  if (imageData) {
    element.textContent = "";
    element.style.backgroundImage = `url("${imageData}")`;
    element.classList.add("has-image");
  } else {
    element.style.backgroundImage = "";
    element.textContent = fallbackInitial || "U";
    element.classList.remove("has-image");
  }
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
  if (!activeReportFileCount()) {
    reportPreview.innerHTML = `
      <div class="report-empty product-report-empty">
        <span class="report-empty-icon">&nearr;</span>
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
  const executiveTone = report.summary.critical || report.summary.high
    ? "Immediate remediation focus: critical/high files, sensitive signals, and broad access paths."
    : "Current scan is stable, but continue ownership validation and retention cleanup.";

  reportPreview.innerHTML = `
    <div class="report-document premium-report-preview product-report-preview">
      <div class="report-cover-strip product-report-cover">
        <div>
          <span>DSPM executive evidence package</span>
          <h4>${escapeHtml(report.title)}</h4>
          <p>${escapeHtml(report.generatedAt)} &middot; tenant ${escapeHtml(currentTenant)} &middot; ${report.summary.total_files} files analyzed</p>
        </div>
        <strong>${report.score}</strong>
      </div>

      <div class="report-narrative-card">
        <p class="eyebrow">Board summary</p>
        <h5>${escapeHtml(executiveTone)}</h5>
        <p>Exports keep the executive story focused while preserving the full evidence register in generated report packs.</p>
      </div>

      <div class="report-kpis product-report-kpis">
        <div class="critical"><span>Critical</span><strong>${report.summary.critical}</strong></div>
        <div class="high"><span>High</span><strong>${report.summary.high}</strong></div>
        <div class="medium"><span>Medium</span><strong>${report.summary.medium}</strong></div>
        <div class="low"><span>Low</span><strong>${report.summary.low}</strong></div>
        <div class="report-hidden"><span>Hidden</span><strong>${hiddenCount}</strong></div>
        <div class="report-protected"><span>Protected</span><strong>${protectedCount}</strong></div>
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
        ${renderComplianceSummaryPanel(report.compliance)}
        <div class="chart-panel report-card-scroll product-panel">
          <h5>Framework mapping</h5>
          ${renderComplianceMappingList(report.compliance)}
        </div>
      </div>

      <div class="report-visual-grid">
        ${renderPciScopeSummaryPanel(report.pciScope)}
        ${renderGdprReportPanel(report.gdprReport)}
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
            <small>All scanned files are available here; no hidden "additional files" placeholder.</small>
          </span>
          <b>${report.priorityFiles.length} rows</b>
        </summary>
        <div class="report-register-wrap">
          <table class="report-register-table">
            <thead>
              <tr><th>File</th><th>Source</th><th>Risk</th><th>Findings</th><th>Action</th></tr>
            </thead>
            <tbody></tbody>
          </table>
        </div>
      </details>
    </div>
  `;
  reportPreview.querySelector(".report-data-drawer")?.remove();
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
    compliance: latestReport?.compliance_summary || { enabled: false, total_compliance_findings: 0 },
    pciScope: latestReport?.pci_scope_summary || { enabled: false },
    gdprReport: latestReport?.gdpr_report || { enabled: false },
  };
}

function renderComplianceSummaryPanel(compliance = latestReport?.compliance_summary || {}) {
  if (!compliance.enabled) {
    return `
      <div class="chart-panel report-card-scroll product-panel compliance-report-panel">
        <h5>Compliance mapping</h5>
        <p class="subtext">Compliance mapping was not enabled for this scan.</p>
      </div>
    `;
  }
  const frameworks = compliance.selected_framework_names || compliance.selected_frameworks || [];
  const topFiles = compliance.top_risky_files || [];
  const categories = compliance.top_violated_categories || [];
  return `
    <div class="chart-panel report-card-scroll product-panel compliance-report-panel">
      <h5>Compliance mapping</h5>
      <div class="compliance-score-row">
        <div><span>Assets</span><strong>${escapeHtml(compliance.affected_asset_count || 0)}</strong></div>
        <div><span>Files</span><strong>${escapeHtml(compliance.affected_file_count || compliance.files_with_compliance_matches || 0)}</strong></div>
        <div><span>Finding groups</span><strong>${escapeHtml(compliance.finding_group_count || compliance.total_compliance_findings || 0)}</strong></div>
        <div><span>Occurrences</span><strong>${escapeHtml(compliance.occurrence_count || 0)}</strong></div>
        <div><span>Unique values</span><strong>${escapeHtml(compliance.unique_sensitive_value_count || 0)}</strong></div>
        <div class="critical"><span>Critical findings</span><strong>${escapeHtml(compliance.critical || 0)}</strong></div>
        <div class="high"><span>High findings</span><strong>${escapeHtml(compliance.high || 0)}</strong></div>
      </div>
      <div class="compliance-badge-row">${frameworks.map((item) => `<span>${escapeHtml(item)}</span>`).join("")}</div>
      <h6>Top categories</h6>
      ${categories.length ? categories.slice(0, 5).map((item) => `<div class="report-row"><div><strong>${escapeHtml(keywordCategoryLabel(item.category))}</strong><span>${escapeHtml(item.count)} finding groups</span></div></div>`).join("") : '<p class="subtext">No category mapping.</p>'}
      <h6>Top compliance files</h6>
      ${topFiles.length ? topFiles.slice(0, 5).map((item) => `<div class="report-row"><div><strong>${escapeHtml(item.file)}</strong><span>${escapeHtml((item.frameworks || []).join(", "))}</span></div><span class="badge ${escapeHtml(item.severity)}">${escapeHtml(item.severity)} ${escapeHtml(item.score)}</span></div>`).join("") : '<p class="subtext">No compliance findings.</p>'}
    </div>
  `;
}

function renderPciScopeSummaryPanel(summary = latestReport?.pci_scope_summary || {}) {
  if (!summary.enabled) return "";
  const categoryCounts = summary.category_finding_group_counts || summary.category_counts || {};
  const protectionCounts = summary.protection_state_finding_group_counts || summary.protection_state_counts || {};
  const candidateRows = summary.scope_candidates || [];
  const sections = [
    ["CHD", categoryCounts.CHD || 0],
    ["SAD", categoryCounts.SAD || 0],
    ["Unprotected PAN", protectionCounts.READABLE_FULL || protectionCounts.readable_full || 0],
    ["Prohibited Storage", summary.sad_retention_candidate_count || 0],
    ["Scope Candidates", summary.cde_candidate_count || 0],
    ["Protection States", Object.keys(protectionCounts).length],
    ["Exposure", Object.keys(summary.environment_finding_group_counts || summary.environment_counts || {}).length],
    ["Retention", (summary.authorization_state_finding_group_counts || summary.authorization_state_counts || {}).POST_AUTH_CONFIRMED || 0],
  ];
  return `
    <div class="chart-panel report-card-scroll product-panel compliance-report-panel">
      <h5>PCI DSS</h5>
      <div class="compliance-score-row">
        <div><span>Overview</span><strong>${escapeHtml(summary.cde_candidate_count || 0)}</strong></div>
        ${sections.map(([label, value]) => `<div><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("")}
      </div>
      <h6>Scope candidates</h6>
      ${candidateRows.slice(0, 5).map((item) => `<div class="report-row"><div><strong>${escapeHtml(item.file)}</strong><span>${escapeHtml(item.reason || "")}</span></div><span class="badge ${escapeHtml(item.severity || "LOW")}">${escapeHtml(item.severity || "LOW")}</span></div>`).join("") || '<p class="subtext">No PCI scope candidates.</p>'}
    </div>
  `;
}

function renderGdprReportPanel(report = latestReport?.gdpr_report || {}) {
  if (!report.enabled) return "";
  const categories = report.personal_data_by_category || [];
  const special = report.special_category_data || [];
  const owners = report.departments_business_owners || [];
  const queueCount = (report.lawful_basis_review_queue || []).length;
  const dpiaCount = (report.dpia_candidates || []).length;
  const minimizationCount = (report.data_minimization_candidates || []).length;
  return `
    <div class="chart-panel report-card-scroll product-panel compliance-report-panel">
      <h5>GDPR report</h5>
      <div class="compliance-score-row">
        <div><span>Personal data</span><strong>${escapeHtml(categories.reduce((sum, item) => sum + Number(item.count || 0), 0))}</strong></div>
        <div><span>Special category</span><strong>${escapeHtml(special.reduce((sum, item) => sum + Number(item.count || 0), 0))}</strong></div>
        <div><span>Owners</span><strong>${escapeHtml(owners.length)}</strong></div>
        <div><span>Retention</span><strong>${escapeHtml((report.retention_violations || []).length)}</strong></div>
        <div><span>Public exposure</span><strong>${escapeHtml((report.public_exposure || []).length)}</strong></div>
        <div><span>Cross-border</span><strong>${escapeHtml((report.cross_border_locations || []).length)}</strong></div>
        <div><span>Non-production</span><strong>${escapeHtml((report.non_production_copies || []).length)}</strong></div>
        <div><span>Lawful basis</span><strong>${escapeHtml(queueCount)}</strong></div>
        <div><span>DPIA</span><strong>${escapeHtml(dpiaCount)}</strong></div>
        <div><span>Minimization</span><strong>${escapeHtml(minimizationCount)}</strong></div>
        <div><span>DSR search</span><strong>${escapeHtml((report.data_subject_request_search || []).length)}</strong></div>
      </div>
      <h6>Personal data by category</h6>
      ${categories.slice(0, 5).map((item) => `<div class="report-row"><div><strong>${escapeHtml(keywordCategoryLabel(item.category))}</strong><span>${escapeHtml(item.count)} occurrences</span></div></div>`).join("") || '<p class="subtext">No GDPR personal data categories.</p>'}
    </div>
  `;
}

function renderComplianceMappingList(compliance = latestReport?.compliance_summary || {}) {
  if (!compliance.enabled) return '<p class="subtext">Run a scan with Compliance enabled to populate framework mappings.</p>';
  const priorities = compliance.remediation_priorities || [];
  const topFiles = compliance.top_risky_files || [];
  const items = priorities.length
    ? priorities.map((item) => ({ label: item.control, detail: `${item.count} files` }))
    : topFiles.map((item) => ({ label: (item.frameworks || []).join(", "), detail: item.remediation || item.path }));
  return items.slice(0, 8).map((item) => `
    <div class="report-row">
      <div>
        <strong>${escapeHtml(item.label || "Compliance mapping")}</strong>
        <span>${escapeHtml(item.detail || "Review mapped control and remediation priority.")}</span>
      </div>
    </div>
  `).join("") || '<p class="subtext">No compliance mappings found.</p>';
}

function reportComplianceText(file) {
  const compliance = file.compliance || {};
  if (!compliance.matched_frameworks?.length) return "No compliance mapping";
  return `${(compliance.matched_framework_names || compliance.matched_frameworks).join(", ")}; ${compliance.compliance_severity} ${compliance.compliance_score}; ${(compliance.data_categories || []).map(keywordCategoryLabel).join(", ")}`;
}

function buildComplianceRows(report) {
  const summary = report.compliance || {};
  const topFiles = summary.top_risky_files || [];
  return topFiles.map((item, index) => `
    <tr>
      <td>${index + 1}</td>
      <td>${escapeHtml(item.file || "")}</td>
      <td>${escapeHtml(item.path || "")}</td>
      <td class="${escapeHtml(item.severity || "LOW")}">${escapeHtml(item.severity || "LOW")}</td>
      <td>${escapeHtml(item.score || 0)}</td>
      <td>${escapeHtml((item.frameworks || []).join("; "))}</td>
      <td>${escapeHtml((item.categories || []).map(keywordCategoryLabel).join("; "))}</td>
      <td>${escapeHtml(item.remediation || "")}</td>
    </tr>
  `).join("");
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
            <span>${folder.files} files &middot; ${folder.critical} critical &middot; avg ${Math.round(folder.score / Math.max(folder.files, 1))}</span>
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
  const currentSummary = displaySummary(buildCurrentSummary());
  const dashboardSummary = latestDashboard?.latest?.summary || {};
  const summary = currentSummary.total_files ? currentSummary : dashboardSummary.total_files ? dashboardSummary : currentSummary;
  const score = getCurrentPostureScore(summary);
  const distribution = buildRiskDistribution(summary);
  const topFiles = [...latestFiles].sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score).slice(0, 6);
  const criticalCount = summary.critical || 0;
  const highCount = summary.high || 0;
  const queueCount = latestFiles.length
    ? latestFiles.filter((file) => ["CRITICAL", "HIGH", "MEDIUM"].includes(getEffectiveRisk(file).level) || isProtectedFile(file)).length
    : Number(summary.critical || 0) + Number(summary.high || 0) + Number(summary.medium || 0);
  const postureLabel = score >= 80 ? "Low risk" : score >= 55 ? "Elevated risk" : "Critical risk";

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
    <div class="insight-card" title="Files with PII, secrets, PCI, health data, or ML context signals.">
      <span>Sensitive files</span>
      <strong>${summary.sensitive_files ?? latestReport?.summary?.sensitive_files ?? countSensitiveFiles(latestFiles)}</strong>
    </div>
    <div class="insight-card" title="Hidden local and SMB entries are included in discovery scope.">
      <span>Hidden files</span>
      <strong>${summary.hidden_files ?? latestReport?.summary?.hidden_files ?? latestFiles.filter((file) => file.is_hidden).length}</strong>
    </div>
    <div class="insight-card protected" title="Password-protected archives, encrypted vaults, and unreadable files needing owner review.">
      <span>Protected / locked</span>
      <strong>${summary.protected_files ?? latestReport?.summary?.protected_files ?? latestFiles.filter(isProtectedFile).length}</strong>
    </div>
    <div class="insight-card" title="History, audit, and vault data are isolated by tenant.">
      <span>Tenant</span>
      <strong>${escapeHtml(currentTenant)}</strong>
    </div>
  `;

  executiveHero.innerHTML = `
    <div class="remediation-score" aria-label="Posture score ${score} out of 100">
      <strong>${score}</strong>
      <span>/100</span>
      <small>${postureLabel}</small>
    </div>
    <div class="remediation-summary-copy">
      <span>Latest assessment</span>
      <h3>${queueCount ? `${queueCount} items need review` : "No active remediation work"}</h3>
      <p>${criticalCount || highCount ? `${criticalCount} critical and ${highCount} high-risk files are at the front of the queue.` : "No urgent exposure is present in the current workspace."}</p>
    </div>
    <div class="remediation-summary-actions">
      <button type="button" class="secondary-btn" data-tab-jump="overview">Open inventory</button>
      <button type="button" data-tab-jump="security">Export controls</button>
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
  // An estate-wide summary carries its own posture, computed from the mean
  // risk score of every indexed asset across all sources.
  if (summary?.posture_score !== undefined && summary?.posture_score !== null) {
    return clampScore(summary.posture_score);
  }
  if (latestFiles.length || latestReport?.files_omitted) {
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
    primaryFindingsForFile(file).forEach((finding) => {
      const name = findingDisplayName(finding);
      counts[name] = (counts[name] || 0) + Number(finding.count || 1);
    });
    if (hasHashChanged(file)) {
      counts["Hash changed"] = (counts["Hash changed"] || 0) + 1;
    }
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
    .slice(0, 12);

  if (!items.length) {
    return '<div class="empty compact">No active remediation queue yet.</div>';
  }

  return `
    <div class="scroll-card-list remediation-list remediation-queue">
      ${items.map((file, index) => {
        const risk = getEffectiveRisk(file);
        const remediation = file.risk?.remediation || {};
        const actions = remediation.actions || ["Validate business ownership"];
        const findingCount = (file.findings || []).length;
        const owner = remediation.owner || inferDepartment(file) || "Data owner";
        const ticket = remediation.ticket || `DSPM-${String(index + 1).padStart(4, "0")}`;
        const sla = remediation.sla || (risk.level === "CRITICAL" ? "24 hours" : risk.level === "HIGH" ? "3 business days" : "14 days");
        return `
          <article class="remediation-item remediation-row compact-risk-card ${risk.level}">
            <span class="badge ${risk.level}">${risk.level} ${risk.score}</span>
            <div class="remediation-file">
              <strong>${escapeHtml(file.name || file.path || "Unknown file")}</strong>
              <span title="${escapeHtml(file.path || "")}">${escapeHtml(file.path || file.source || "Workspace")}</span>
              <small>${escapeHtml(ticket)} &middot; ${findingCount} finding${findingCount === 1 ? "" : "s"}</small>
            </div>
            <div class="remediation-assignment">
              <span>${escapeHtml(owner)}</span>
              <small>SLA ${escapeHtml(sla)}</small>
              <strong>${escapeHtml(actions[0])}</strong>
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

  const activeTenant = tenants.find((tenant) => tenant.tenant_id === currentTenant) || tenants[0];
  const activeSummary = activeTenant.latest?.summary || buildCurrentSummary();
  const urgentCount = Number(activeSummary.critical || 0) + Number(activeSummary.high || 0);

  return `
    <div class="workspace-status-item workspace-name">
      <span>Workspace</span>
      <strong>${escapeHtml(currentTenant)}</strong>
    </div>
    <div class="workspace-status-item">
      <span>Saved scans</span>
      <strong>${activeTenant.scan_count || 0}</strong>
    </div>
    <div class="workspace-status-item">
      <span>Files in scope</span>
      <strong>${activeSummary.total_files || 0}</strong>
    </div>
    <div class="workspace-status-item ${urgentCount ? "needs-attention" : ""}">
      <span>Urgent items</span>
      <strong>${urgentCount}</strong>
    </div>
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
            <span>${item.files} files &middot; ${item.critical} critical &middot; ${item.high} high</span>
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
    .slice(0, 10);

  if (!items.length) {
    return '<div class="empty compact">Critical, high, and protected files will appear after a risky scan.</div>';
  }

  return `
    <div class="scroll-card-list priority-file-list dense-risk-list">
      ${items.map((file) => {
        const risk = getEffectiveRisk(file);
        const findings = (file.findings || []).map((finding) => finding.type).slice(0, 3).join(", ") || "Risk context";
        return `
          <article class="priority-file priority-file-row compact-risk-card ${risk.level}" title="${escapeHtml(file.path || file.name || "")}">
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
  return file.share || parts.slice(-3, -2)[0] || file.source || "-";
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
  const hashChanges = latestHashComparison?.changed || [];
  const duplicateHashPaths = latestHashComparison?.duplicate_hash_paths || [];
  const hashSummary = latestHashComparison
    ? `
      <details class="scan-advanced hash-comparison-details">
        <summary>Integrity comparison &mdash; SHA-256 changes &amp; duplicates</summary>
      <div class="hash-comparison-card">
        <div>
          <span>Integrity comparison</span>
          <strong>${escapeHtml(latestHashComparison.algorithm || "SHA-256")}</strong>
          <small>${escapeHtml(latestHashComparison.changed_count || 0)} changed &middot; ${escapeHtml(latestHashComparison.added_count || 0)} added &middot; ${escapeHtml(latestHashComparison.removed_count || 0)} removed &middot; ${escapeHtml(latestHashComparison.duplicate_hash_path_count || 0)} duplicate hash groups</small>
        </div>
        ${hashChanges.length ? `
          <div class="hash-change-list">
            ${hashChanges.slice(0, 5).map((item) => `
              <div class="hash-change-row">
                <strong>${escapeHtml(item.name || "Changed file")}</strong>
                <span>${escapeHtml(item.path || item.source || "")}</span>
                <code title="${escapeHtml(item.current_hash || "")}">${escapeHtml(shortHash(item.current_hash || ""))}</code>
              </div>
            `).join("")}
          </div>
        ` : '<p class="subtext">No SHA-256 changes detected between the latest two saved scans.</p>'}
        ${duplicateHashPaths.length ? `
          <div class="hash-change-list">
            ${duplicateHashPaths.slice(0, 5).map((item) => `
              <div class="hash-change-row duplicate-hash-row">
                <strong>${escapeHtml(item.name || "Duplicate content")}</strong>
                <span>${escapeHtml((item.paths || []).slice(0, 2).map((path) => path.path || path.name || "").filter(Boolean).join(" | "))}</span>
                <code title="${escapeHtml(item.hash || "")}">${escapeHtml(shortHash(item.hash || ""))}</code>
              </div>
            `).join("")}
          </div>
        ` : '<p class="subtext">No identical SHA-256 values found across different paths in the latest scan.</p>'}
      </div>
      </details>
    `
    : "";

  return `
    <div class="scan-comparison-list">
      <p class="subtext scan-comparison-hint">Change vs previous scan (latest − previous). A minus value means fewer than last scan.</p>
      ${rows.map(([label, current, prior]) => {
        const delta = Number(current) - Number(prior);
        const sign = delta > 0 ? "+" : "";
        const deltaTitle = delta === 0
          ? `${label}: no change vs previous scan`
          : `${label}: ${Math.abs(delta)} ${delta < 0 ? "fewer" : "more"} than previous scan (latest ${current} − previous ${prior})`;
        return `
          <div class="scan-comparison-row">
            <span>${escapeHtml(label)}</span>
            <strong>${current}</strong>
            <small class="${delta > 0 ? "worse" : delta < 0 ? "better" : ""}" title="${escapeHtml(deltaTitle)}" aria-label="${escapeHtml(deltaTitle)}">${sign}${delta}</small>
          </div>
        `;
      }).join("")}
    </div>
    ${hashSummary}
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
          <span>${item.files} files &middot; avg ${Math.round(item.score / Math.max(item.files, 1))} &middot; ${item.critical} critical</span>
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
  if (latestReport?.files_omitted) {
    return {
      total_files: activeReportFileCount(),
      critical: Number(latestReport.summary?.critical || 0),
      high: Number(latestReport.summary?.high || 0),
      medium: Number(latestReport.summary?.medium || 0),
      low: Number(latestReport.summary?.low || 0),
      protected_files: Number(latestReport.summary?.protected_files || 0),
    };
  }
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

function reportText(value, fallback = "-") {
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
  return reportText(file.owner || file.owner_name || file.file_owner || file.acl?.owner || file.security_owner || file.metadata?.owner, "-");
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
          <td>${escapeHtml(source)}<br><span>${escapeHtml(hidden)} &middot; ${escapeHtml(protectedLabel)}</span></td>
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

  downloadFile(reportFileName("doc"), buildWordReportHtml(), "application/msword;charset=utf-8");
  setStatus("Word board pack exported with executive summary and full appendix.");
}

const UNIFIED_PDF_TEMPLATE_ID = "sentro-dspm-unified-v1";

async function exportPdf() {
  if (!latestFiles.length) {
    setStatus("Run a scan before opening the PDF composer.");
    return;
  }

  const popupWidth = Math.min(1280, Math.max(980, Math.round(window.screen?.availWidth * 0.82 || 1100)));
  const popupHeight = Math.min(920, Math.max(720, Math.round(window.screen?.availHeight * 0.86 || 820)));
  const popupLeft = Math.max(0, Math.round(((window.screen?.availWidth || popupWidth) - popupWidth) / 2));
  const popupTop = Math.max(0, Math.round(((window.screen?.availHeight || popupHeight) - popupHeight) / 2));
  const reportWindow = window.open("", "_blank", `width=${popupWidth},height=${popupHeight},left=${popupLeft},top=${popupTop},resizable=yes,scrollbars=yes`);
  if (!reportWindow) {
    setStatus("Popup blocked. Allow popups to open the PDF composer.");
    return;
  }
  reportWindow.document.write(`
    <!doctype html>
    <html><head><meta charset="utf-8"><title>SENTRO PDF Composer</title>
    <style>
      * { box-sizing: border-box; }
      body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #07112b; color: #e8edff; font-family: "Segoe UI", Arial, sans-serif; }
      main { width: min(520px, calc(100% - 40px)); padding: 30px; border: 1px solid #263b78; border-radius: 20px; background: linear-gradient(145deg, #0b1739, #102a56); box-shadow: 0 24px 80px rgba(0,0,0,.36); }
      strong { display: block; margin-bottom: 8px; font-size: 20px; } p { margin: 0; color: #c7d2fe; line-height: 1.55; }
      .accent { width: 72px; height: 4px; margin-bottom: 18px; border-radius: 99px; background: linear-gradient(90deg, #2563eb, #4f46e5, #7c3aed); }
    </style></head><body><main><div class="accent"></div><strong>Preparing unified SENTRO report</strong><p id="composer-status">Building the visual PDF and signed preview&hellip;</p></main></body></html>
  `);
  reportWindow.document.close();
  reportWindow.focus();
  setStatus("Preparing the unified SENTRO PDF report...");
  try {
    const response = await fetch("/api/v1/reports", {
      method: "POST",
      headers: authHeaders(),
      body: JSON.stringify({ scan_id: latestReport?.scan_id || null }),
    });
    if (!response.ok) {
      throw new Error(await readErrorMessage(response));
    }
    const artifact = await response.json();
    if (artifact.template_id !== UNIFIED_PDF_TEMPLATE_ID || !artifact.preview_url) {
      throw new Error("The report service returned an unsupported template.");
    }
    reportWindow.location.replace(artifact.preview_url);
    setStatus("PDF composer opened with the unified SENTRO report. Use the PDF viewer to print or save it.");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to create the PDF report.";
    const status = reportWindow.document.getElementById("composer-status");
    if (status) status.textContent = message;
    setStatus(message);
  }
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
                <p>Generated ${escapeHtml(report.generatedAt)} &middot; tenant ${escapeHtml(currentTenant)}</p>
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
                ${report.departments.slice(0, 7).map((item) => `<div class="list-card"><strong>${escapeHtml(item.department)}</strong><span>${item.files} files &middot; ${item.critical} critical &middot; ${item.high} high</span></div>`).join("") || '<p class="muted">No department data.</p>'}
              </div>
              <div class="panel">
                <h2>Top risky folders</h2>
                ${report.folders.slice(0, 7).map((item) => `<div class="list-card"><strong>${escapeHtml(item.folder)}</strong><span>${item.files} files &middot; ${item.critical} critical &middot; avg ${Math.round(item.score / Math.max(item.files, 1))}</span></div>`).join("") || '<p class="muted">No folder data.</p>'}
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

function buildWordReportHtml() {
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
  const compliance = report.compliance || {};
  const complianceRows = buildComplianceRows(report);
  const complianceFrameworks = compliance.selected_framework_names || compliance.selected_frameworks || [];
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
  return `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <title>DSPM Assessment Report</title>
        <style>
          @page { size: A4 landscape; margin: 9mm; }
          * { box-sizing: border-box; }
          body { margin: 0; background: #eef2f7; color: #17202a; font-family: "Segoe UI", Arial, Helvetica, sans-serif; font-size: 10.8px; line-height: 1.42; }
          .page { width: 100%; max-width: 1180px; margin: 24px auto; background: #fff; border: 1px solid #d8dee8; box-shadow: 0 24px 70px rgba(15, 23, 42, .12); }
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
          .full-register-section { display: block; }
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
      <body class="include-register">
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
                <h2>Compliance executive summary</h2>
                <table>
                  <thead><tr><th>Enabled</th><th>Frameworks</th><th>Files</th><th>Finding groups</th><th>Occurrences</th><th>Unique values</th><th>Critical findings</th><th>High findings</th><th>Medium findings</th><th>Low findings</th></tr></thead>
                  <tbody><tr><td>${compliance.enabled ? "Yes" : "No"}</td><td>${escapeHtml(complianceFrameworks.join("; "))}</td><td>${escapeHtml(compliance.affected_file_count || 0)}</td><td>${escapeHtml(compliance.finding_group_count || compliance.total_compliance_findings || 0)}</td><td>${escapeHtml(compliance.occurrence_count || 0)}</td><td>${escapeHtml(compliance.unique_sensitive_value_count || 0)}</td><td>${escapeHtml(compliance.critical || 0)}</td><td>${escapeHtml(compliance.high || 0)}</td><td>${escapeHtml(compliance.medium || 0)}</td><td>${escapeHtml(compliance.low || 0)}</td></tr></tbody>
                </table>
              </div>
              <div class="panel">
                <h2>Framework mapping</h2>
                ${renderComplianceMappingList(compliance)}
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

            <section class="register-intro">
              <div>
                <strong>Full evidence register is separated from the executive story.</strong>
                <span>Word export includes the full appendix below, so auditors can review every row without changing the executive summary layout.</span>
              </div>
              <div class="fake-button">${report.priorityFiles.length} rows included</div>
            </section>

            <section class="full-register-section page-break">
              <h2>Appendix A - Full evidence register</h2>
              <p class="muted">All scanned files sorted by effective risk score. This replaces the old "additional files" placeholder and keeps every row available when requested.</p>
              <table class="full-register-table">
                <thead><tr><th>File</th><th>Source</th><th>Owner</th><th>Hidden</th><th>Protected</th><th>Risk</th><th>Findings</th><th>Reasons</th><th>DLP / action</th></tr></thead>
                <tbody>${fullRows || '<tr><td colspan="9">No file evidence rows available.</td></tr>'}</tbody>
              </table>
            </section>
            <section class="full-register-section page-break">
              <h2>Appendix B - Compliance findings</h2>
              <p class="muted">Evidence-based compliance exposure mapping. This is not a legal compliance certification.</p>
              <table>
                <thead><tr><th>#</th><th>File</th><th>Path</th><th>Severity</th><th>Score</th><th>Frameworks</th><th>Categories</th><th>Remediation</th></tr></thead>
                <tbody>${complianceRows || '<tr><td colspan="8">No compliance findings.</td></tr>'}</tbody>
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
          <td>${escapeHtml(reportComplianceText(file))}</td>
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
  const complianceRows = buildComplianceRows(report);
  const compliance = report.compliance || {};
  const frameworkRows = compliance.enabled
    ? (compliance.selected_framework_names || compliance.selected_frameworks || []).map((item) => `<tr><td>${escapeHtml(item)}</td><td>${escapeHtml(compliance.affected_file_count || 0)}</td><td>${escapeHtml(compliance.finding_group_count || compliance.total_compliance_findings || 0)}</td><td>${escapeHtml(compliance.occurrence_count || 0)}</td><td>${escapeHtml(compliance.critical || 0)}</td><td>${escapeHtml(compliance.high || 0)}</td></tr>`).join("")
    : '<tr><td colspan="6">Compliance mapping was not enabled for this scan.</td></tr>';
  const complianceRemediationRows = compliance.enabled
    ? (compliance.remediation_priorities || []).map((item) => `<tr><td>${escapeHtml(item.control)}</td><td>${escapeHtml(item.count)}</td><td>Review owner, reduce broad access, encrypt sensitive data, and validate retention.</td></tr>`).join("")
    : '<tr><td colspan="3">No compliance remediation priorities.</td></tr>';

  return `
    <html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:x="urn:schemas-microsoft-com:office:excel">
      <head>
        <meta charset="utf-8" />
        <!--[if gte mso 9]><xml><x:ExcelWorkbook><x:ExcelWorksheets>
          <x:ExcelWorksheet><x:Name>Executive Summary</x:Name><x:WorksheetOptions><x:DisplayGridlines/><x:FreezePanes/><x:FrozenNoSplit/><x:SplitHorizontal>1</x:SplitHorizontal><x:TopRowBottomPane>1</x:TopRowBottomPane></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Compliance Summary</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Risk Register</x:Name><x:WorksheetOptions><x:DisplayGridlines/><x:FreezePanes/></x:WorksheetOptions></x:ExcelWorksheet>
          <x:ExcelWorksheet><x:Name>Framework Mapping</x:Name><x:WorksheetOptions><x:DisplayGridlines/></x:WorksheetOptions></x:ExcelWorksheet>
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

        <h2 class="section-break">Compliance Summary</h2>
        <table class="kpi">
          <tr><th>Enabled</th><th>Frameworks</th><th>Files</th><th>Finding groups</th><th>Occurrences</th><th>Unique values</th><th>Critical findings</th><th>High findings</th><th>Medium findings</th><th>Low findings</th></tr>
          <tr><td>${compliance.enabled ? "Yes" : "No"}</td><td>${escapeHtml((compliance.selected_framework_names || compliance.selected_frameworks || []).join("; "))}</td><td>${escapeHtml(compliance.affected_file_count || 0)}</td><td>${escapeHtml(compliance.finding_group_count || compliance.total_compliance_findings || 0)}</td><td>${escapeHtml(compliance.occurrence_count || 0)}</td><td>${escapeHtml(compliance.unique_sensitive_value_count || 0)}</td><td class="CRITICAL">${escapeHtml(compliance.critical || 0)}</td><td class="HIGH">${escapeHtml(compliance.high || 0)}</td><td class="MEDIUM">${escapeHtml(compliance.medium || 0)}</td><td class="LOW">${escapeHtml(compliance.low || 0)}</td></tr>
        </table>
        <table><tr><th>#</th><th>File</th><th>Path</th><th>Severity</th><th>Score</th><th>Frameworks</th><th>Categories</th><th>Remediation</th></tr>${complianceRows || '<tr><td colspan="8">No compliance findings</td></tr>'}</table>

        <h2>Risk Distribution</h2>
        <table><tr><th>Level</th><th>Files</th><th>Percent of scan</th></tr>${report.distribution.map((item) => `<tr><td class="${item.level}">${item.label}</td><td>${item.count}</td><td>${Math.round((item.count / Math.max(report.summary.total_files, 1)) * 100)}%</td></tr>`).join("")}</table>

        <h2 class="section-break">Risk Register - All Files</h2>
        <table>
          <tr><th>#</th><th>File</th><th>Path</th><th>Source</th><th>Share</th><th>Owner</th><th>Hidden</th><th>Protected</th><th>Risk</th><th>Score</th><th>Findings</th><th>Compliance</th><th>Reasons</th><th>DLP Recommendation</th><th>Remediation Action</th></tr>
          ${riskRows || '<tr><td colspan="15">No risk rows available</td></tr>'}
        </table>

        <h2 class="section-break">Framework Mapping</h2>
        <table><tr><th>Framework</th><th>Files</th><th>Finding groups</th><th>Occurrences</th><th>Critical findings</th><th>High findings</th></tr>${frameworkRows}</table>

        <h2 class="section-break">Remediation Plan</h2>
        <table><tr><th>#</th><th>File</th><th>Risk</th><th>Score</th><th>Owner</th><th>SLA</th><th>Action</th></tr>${remediationRows || '<tr><td colspan="7">No remediation actions required</td></tr>'}</table>

        <h2>Compliance Remediation</h2>
        <table><tr><th>Mapped control/category</th><th>Files</th><th>Priority action</th></tr>${complianceRemediationRows}</table>

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
    throw new Error("Sign in first.");
  }
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function ensureCredential(payload) {
  if (!payload.server || !payload.password) {
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
  const job = await api("/api/scan", { ...payload, async_scan: true, save_report: true, compact_result: true });
  activeScanJobId = job.id;
  scanStartedAt = performance.now();
  if (scanCancelBtn) {
    scanCancelBtn.classList.remove("hidden");
    scanCancelBtn.disabled = false;
  }
  setStatus(`Scan queued: ${job.id}`);
  setScanProgress(true, job.progress || 5, "Scan queued...", job.elapsed_seconds || 0);
  try {
    return await pollScan(job.id);
  } finally {
    activeScanJobId = "";
    if (scanCancelBtn) {
      scanCancelBtn.classList.add("hidden");
      scanCancelBtn.disabled = true;
    }
  }
}

async function runQueuedEndpointScan(payload) {
  const job = await api("/api/endpoint/scan", { ...payload, async_scan: true, save_report: true, compact_result: true });
  activeEndpointJobId = job.id;
  endpointScanStartedAt = performance.now();
  if (endpointCancelBtn) {
    endpointCancelBtn.classList.remove("hidden");
    endpointCancelBtn.disabled = false;
  }
  endpointStatus.textContent = `Endpoint scan queued: ${job.id}`;
  setEndpointScanProgress(true, job.progress || 5, "Endpoint scan queued...", job.elapsed_seconds || 0);
  try {
    return await pollScan(job.id, (polledJob) => {
      const displayedProgress = smoothProgress(polledJob.progress || 0, endpointProgressValue, 5);
      endpointStatus.textContent = `${polledJob.message} (${displayedProgress}%)`;
      setEndpointScanProgress(
        true,
        displayedProgress,
        polledJob.message || "Scanning endpoint...",
        polledJob.elapsed_seconds || 0
      );
    });
  } finally {
    activeEndpointJobId = "";
    if (endpointCancelBtn) {
      endpointCancelBtn.classList.add("hidden");
      endpointCancelBtn.disabled = true;
    }
  }
}

async function loadSavedReportById(scanId, retries = 3, delayMs = 350, includeFiles = false) {
  if (!scanId) return null;
  for (let attempt = 0; attempt <= retries; attempt += 1) {
    try {
      const data = await api(`/api/history/${encodeURIComponent(scanId)}/report?include_files=${includeFiles ? "true" : "false"}`, null, "GET");
      if (data.report) return data.report;
    } catch (error) {
      if (attempt >= retries) return null;
    }
    await sleep(delayMs);
  }
  return null;
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
  const MAX_POLL_ERRORS = 5;
  let consecutiveErrors = 0;
  while (true) {
    let job;
    try {
      job = await api(`/api/scans/${jobId}`, null, "GET");
      consecutiveErrors = 0;
    } catch (err) {
      // A single transient poll error (network blip, 5xx, brief 401) must not
      // abandon a scan that is still running/completing on the backend. Keep
      // polling; only surface a failure after several consecutive errors.
      consecutiveErrors += 1;
      if (consecutiveErrors >= MAX_POLL_ERRORS) {
        throw err;
      }
      await new Promise((resolve) => setTimeout(resolve, 1200));
      continue;
    }
    if (onProgress) {
      onProgress(job);
    } else {
      const displayedProgress = smoothProgress(job.progress || 0, scanProgressValue, 5);
      setStatus(`${job.message} (${displayedProgress}%)`);
      setScanProgress(true, displayedProgress, job.message || "Scanning...", job.elapsed_seconds || 0);
    }
    if (job.status === "completed") {
      const elapsedSeconds = job.elapsed_seconds || scanElapsedSeconds(onProgress ? endpointScanStartedAt : scanStartedAt);
      if (onProgress) {
        onProgress({ ...job, progress: 100, message: "Completed", elapsed_seconds: elapsedSeconds });
      } else {
        setScanProgress(true, 100, "Scan completed", elapsedSeconds);
      }
      if (job.result && typeof job.result === "object") {
        job.result.__job_elapsed_seconds = elapsedSeconds;
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
  const [history, dashboard, hashComparison, estateFacets] = await Promise.all([
    api("/api/history", null, "GET"),
    api("/api/executive-dashboard", null, "GET"),
    loadHashComparison(),
    api("/api/inventory/facets", null, "GET").catch(() => null),
  ]);
  loadScanProfiles().catch(() => {});
  latestDashboard = dashboard;
  latestHashComparison = hashComparison;
  estateSummary = estateFacets ? facetsToEstateSummary(estateFacets) : null;
  renderHistory(history.history || []);
  await restoreLatestSavedReport(history.history || []);
  renderExecutiveExperience();
  loadTenants().catch(() => {});
}

async function loadHashComparison() {
  try {
    return await api("/api/history/hash-changes", null, "GET");
  } catch {
    return null;
  }
}

async function refreshHashComparison() {
  const [dashboard, hashComparison] = await Promise.all([
    api("/api/executive-dashboard", null, "GET").catch(() => latestDashboard),
    loadHashComparison(),
  ]);
  latestDashboard = dashboard;
  latestHashComparison = hashComparison;
  if (latestFiles.length || currentInventoryPage()) {
    const page = currentInventoryPage();
    if (page) renderRows(page.items, { serverPage: page });
    else renderRows(latestFiles);
    renderFindingsWorkspace();
  }
  renderExecutiveExperience();
}

async function restoreLatestSavedReport(historyItems = latestHistoryItems) {
  if (latestReport?.scan_id || !Array.isArray(historyItems) || !historyItems.length) {
    return;
  }
  const candidates = [...historyItems].reverse();
  for (const item of candidates) {
    const scanId = item?.scan_id;
    if (!scanId) continue;
    try {
      const report = await loadSavedReportById(scanId) || {};
      if (!activeCompactReportCount(report) || isDemoSampleReport(report)) {
        continue;
      }
      const scanKind = report.endpoint ? "endpoint" : "file-server";
      applyScanReport(report, scanKind);
      scanMeta.textContent = `Restored ${activeCompactReportCount(report)} indexed files from saved scan ${scanId}.`;
      return;
    } catch (error) {
      setStatus(`Saved scan restore failed: ${error.message}`);
      return;
    }
  }
  clearActiveScanReport("No non-demo saved scan loaded. Run an endpoint or real file-server scan.");
}

function activeCompactReportCount(report = {}) {
  return Number(report.file_count || report.result_file_count || report.summary?.total_files || report.files?.length || 0);
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
          <td class="file-path"><span class="audit-action" data-action="${escapeHtml(event.action || "")}">${escapeHtml(event.action || "")}</span></td>
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
extensionSearch?.addEventListener("input", debounce(() => filterExtensionList(allowedExtensionsList, extensionSearch)));
endpointExtensionSearch?.addEventListener("input", debounce(() => {
  filterExtensionList(endpointAllowedExtensionsList, endpointExtensionSearch);
  tuneEndpointScanDefaults();
}));
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

if (scanCancelBtn) scanCancelBtn.addEventListener("click", async () => {
  if (!activeScanJobId) return;
  scanCancelBtn.disabled = true;
  try {
    await api(`/api/scans/${activeScanJobId}/cancel`, {}, "POST");
    setStatus("File scan cancellation requested.");
    setScanProgress(false);
  } catch (error) {
    setStatus(`File scan cancel failed: ${error.message}`);
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
  scanStartedAt = performance.now();
  const progressTimer = window.setInterval(() => {
    setScanProgress(true, estimatedProgress(scanStartedAt, scanProgressValue, 88), "Collecting and analyzing files...");
  }, 700);
  try {
    requireAuth();
    const payload = await ensureCredential(readPayload());
    if (payload.async_scan) {
      window.clearInterval(progressTimer);
    }
    const report = payload.async_scan
      ? await runQueuedScan(payload)
      : await api("/api/scan", { ...payload, save_report: true, compact_result: true });
    applyScanReport(report, "file-server");
    await refreshHashComparison();
    const diagnostics = summarizeFileServerDiagnostics(report);
    lastScanElapsedSeconds = report.__job_elapsed_seconds || scanElapsedSeconds(scanStartedAt);
    setStatus(`Scan completed in ${formatElapsedTime(lastScanElapsedSeconds)} and report.json updated.${diagnostics ? ` ${diagnostics}` : ""}`);
    setScanProgress(true, 100, "Scan completed", lastScanElapsedSeconds);
    showToast("Scan completed", `${activeReportFileCount()} files found · ${formatElapsedTime(lastScanElapsedSeconds)}`, latestReport.summary?.critical ? "danger" : "success");
    if (latestReport.summary?.critical) {
      showToast("Critical exposure", `${latestReport.summary.critical} critical files found`, "danger");
    }
    await loadHistory();
  } catch (error) {
    setStatus(`Scan failed: ${error.message}`);
    showToast("Scan failed", error.message, "danger");
  } finally {
    window.clearInterval(progressTimer);
    if (scanProgressValue >= 100) {
      await sleep(500);
    }
    setScanProgress(false);
    setBusy(false);
  }
});

localWinrmActivateBtn.addEventListener("click", async () => {
  setBusy(true);
  localWinrmStatus.textContent = "Checking backend-host WinRM readiness only. Target machine credentials are entered below.";
  try {
    requireAuth();
    const result = await api("/api/endpoint/activate-local-winrm", readLocalWinrmPayload());
    localWinrmStatus.textContent = result.activated
      ? "Backend host WinRM readiness is complete. Enter the target machine local-admin credential in the Target machine WinRM or Endpoint scan section below."
      : `Local backend readiness needs review: ${result.message}`;
    showToast(result.activated ? "Backend WinRM readiness complete" : "Local backend readiness needs review", result.message || "", result.activated ? "success" : "danger");
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
    const payload = await ensureEndpointCredential(readEndpointConnectionPayload());
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
  clearActiveScanReport("Endpoint scan running. Previous SMB/demo results cleared.");
  renderSkeletonRows();
  renderScanRunningContext("endpoint", "Scanning endpoint paths through WinRM. Results will update across Overview, Inventory, Findings, Exposure, Risk, and File Server context.");
  setEndpointScanProgress(true, 8, "Preparing endpoint scan...");
  endpointScanStartedAt = performance.now();
  const endpointProgressTimer = window.setInterval(() => {
    setEndpointScanProgress(true, estimatedProgress(endpointScanStartedAt, endpointProgressValue, 88), "Collecting endpoint files...");
  }, 900);
  try {
    requireAuth();
    const payload = await ensureEndpointCredential(readEndpointPayload());
    if (payload.async_scan) {
      window.clearInterval(endpointProgressTimer);
    }
    const report = payload.async_scan
      ? await runQueuedEndpointScan(payload)
      : await api("/api/endpoint/scan", { ...payload, compact_result: true });
    if (!report?.endpoint) {
      throw new Error("Endpoint scan returned non-endpoint data. Previous SMB/demo report was not displayed.");
    }
    applyScanReport(report, "endpoint");
    await refreshHashComparison();
    const extensionCounts = summarizeExtensions(latestFiles, report.endpoint?.extension_counts);
    const diagnostics = summarizeEndpointDiagnostics(report.endpoint);
    lastEndpointElapsedSeconds = report.__job_elapsed_seconds || scanElapsedSeconds(endpointScanStartedAt);
    endpointStatus.textContent = `Endpoint scan completed in ${formatElapsedTime(lastEndpointElapsedSeconds)}. ${activeReportFileCount()} files analyzed. ${extensionCounts} ${diagnostics}`;
    if (endpointViewOverviewBtn) endpointViewOverviewBtn.classList.remove("hidden");
    setStatus(`Endpoint scan completed in ${formatElapsedTime(lastEndpointElapsedSeconds)} and report.json updated.`);
    setEndpointScanProgress(true, 100, "Endpoint scan completed", lastEndpointElapsedSeconds);
    showToast("Endpoint scan completed", `${activeReportFileCount()} files found · ${formatElapsedTime(lastEndpointElapsedSeconds)}`, latestReport.summary?.critical ? "danger" : "success");
    await loadHistory();
  } catch (error) {
    endpointStatus.textContent = `Endpoint scan failed: ${error.message}`;
    setStatus(`Endpoint scan failed: ${error.message}`);
    showToast("Endpoint scan failed", error.message, "danger");
  } finally {
    window.clearInterval(endpointProgressTimer);
    if (endpointProgressValue >= 100) {
      await sleep(500);
    }
    setEndpointScanProgress(false);
    setBusy(false);
  }
});

endpointPathScope.addEventListener("change", () => {
  document.querySelector("#endpoint-max-depth")?.removeAttribute("data-touched");
  updateEndpointCustomPathState();
  tuneEndpointScopeExtensionPolicy();
  tuneEndpointScanDefaults();
});

endpointCustomPaths?.addEventListener("input", () => {
  tuneEndpointScopeExtensionPolicy();
  tuneEndpointScanDefaults();
});

document.querySelector("#endpoint-max-depth")?.addEventListener("input", (event) => {
  event.target.dataset.touched = "1";
});

document.querySelector("#endpoint-max-depth")?.addEventListener("change", (event) => {
  event.target.dataset.touched = "1";
  event.target.value = String(clampEndpointDepth(event.target.value));
});

document.querySelector("#endpoint-target-username")?.addEventListener("input", () => {
  updateEndpointCustomPathState();
});

// Risk-summary tiles are drill-downs: clicking one opens Findings, scrolls to
// the Data inventory and applies the matching risk filter (Total -> All).
const METRIC_FILTERS = { critical: "CRITICAL", high: "HIGH", medium: "MEDIUM", low: "LOW", protected: "PROTECTED", total: "ALL" };
document.addEventListener("click", (event) => {
  const tile = event.target.closest("#tab-overview .metrics .metric");
  if (!tile) return;
  const key = Object.keys(METRIC_FILTERS).find((k) => tile.classList.contains(k));
  if (!key) return;
  switchTab("inventory");
  document.querySelector(`[data-risk-filter="${METRIC_FILTERS[key]}"]`)?.click();
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const tile = event.target.closest?.("#tab-overview .metrics .metric");
  if (!tile) return;
  event.preventDefault();
  tile.click();
});
const armMetricTiles = () => {
  document.querySelectorAll("#tab-overview .metrics .metric").forEach((tile) => {
    tile.setAttribute("role", "button");
    tile.tabIndex = 0;
  });
};
if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", armMetricTiles);
else armMetricTiles();

let lastInventoryQuery = "";
filterInput.addEventListener("input", debounce(() => {
  const next = filterInput.value.trim();
  if (next === lastInventoryQuery) return;   // identical query - no refetch
  lastInventoryQuery = next;
  renderedRowsLimit = ROW_PAGE_SIZE;
  refreshInventoryPageWindow();
}, 300));
filterInput.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && filterInput.value) {
    filterInput.value = "";
    lastInventoryQuery = "";
    renderedRowsLimit = ROW_PAGE_SIZE;
    refreshInventoryPageWindow();
  }
});

inventoryRiskFilters.forEach((button) => {
  button.addEventListener("click", () => {
    inventoryRiskFilter = button.dataset.riskFilter || "ALL";
    renderInventoryRiskSelection();
    renderedRowsLimit = ROW_PAGE_SIZE;
    refreshInventoryPageWindow();
  });
});

inventorySourceFilter?.addEventListener("change", () => {
  inventorySourceFacet = inventorySourceFilter.value || "ALL";
  renderedRowsLimit = ROW_PAGE_SIZE;
  refreshInventoryPageWindow();
});

inventoryFindingFilter?.addEventListener("change", () => {
  inventoryFindingFacet = inventoryFindingFilter.value || "ALL";
  renderedRowsLimit = ROW_PAGE_SIZE;
  refreshInventoryPageWindow();
});

inventoryFrameworkFilter?.addEventListener("change", () => {
  const checked = [...inventoryFrameworkFilter.querySelectorAll("input[type='checkbox']:checked")].map((input) => input.value);
  const allValues = inventoryFrameworkOptions(latestFiles).map((item) => item.id);
  inventoryFrameworkFacets = checked.length && checked.length < allValues.length ? new Set(checked) : new Set();
  renderedRowsLimit = ROW_PAGE_SIZE;
  refreshInventoryPageWindow();
});

inventoryClearFiltersBtn?.addEventListener("click", () => {
  inventoryRiskFilter = "ALL";
  inventorySourceFacet = "ALL";
  inventoryFindingFacet = "ALL";
  inventoryFrameworkFacets = new Set();
  if (filterInput) filterInput.value = "";
  renderedRowsLimit = ROW_PAGE_SIZE;
  refreshInventoryPageWindow();
  renderFindingsWorkspace();
});

document.addEventListener("click", (event) => {
  const pageAction = event.target.closest("[data-inventory-page]");
  if (pageAction && !pageAction.disabled) {
    const nextIndex = inventoryPageWindow.pageIndex + (pageAction.dataset.inventoryPage === "next" ? 1 : -1);
    loadInventoryWindowPage(Math.max(0, nextIndex));
    return;
  }
  if (event.target.closest("#load-more-results")) {
    renderedRowsLimit += ROW_PAGE_SIZE;
    renderRows(latestFiles);
    return;
  }
  const copyAction = event.target.closest("[data-copy-text]");
  if (copyAction) {
    copyText(copyAction.dataset.copyText || "")
      .then(() => showToast("Copied", "Path copied to clipboard.", "success"))
      .catch((error) => showToast("Copy failed", error.message, "danger"));
    return;
  }
  const keywordAction = event.target.closest("[data-keyword-action]");
  if (keywordAction) {
    handleKeywordAction(keywordAction.dataset.keywordAction, keywordAction.closest(".keyword-library-panel"));
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

document.addEventListener("change", (event) => {
  const keywordCategory = event.target.closest("[data-keyword-category-select]");
  if (keywordCategory) {
    updateKeywordTypeOptions(keywordCategory.closest(".keyword-library-panel"));
    return;
  }
  const keywordType = event.target.closest("[data-keyword-type]");
  if (keywordType) {
    updateKeywordCustomState(keywordType.closest(".keyword-library-panel"));
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
  const expandControl = event.target.closest("[data-inventory-expand]");
  if (expandControl) {
    openAssetDetailModal(expandControl);
    return;
  }

  const detailButton = event.target.closest(".detail-toggle");
  if (detailButton) {
    const tab = { findings: "findings", recommendations: "actions" }[detailButton.dataset.detailType] || "reasons";
    openAssetDetailModal(detailButton.dataset.detailKey || "", tab);
    return;
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
  const currentPage = currentInventoryPage();
  if (inventoryPageWindow.active && currentPage) {
    renderRows(currentPage.items, { serverPage: currentPage });
  } else {
    renderRows(latestFiles);
  }
});

exportCsvBtn.addEventListener("click", exportCsv);
exportWordBtn.addEventListener("click", exportWord);
exportPdfBtn.addEventListener("click", exportPdf);
inventoryExportCsvBtn?.addEventListener("click", () => {
  streamInventoryExport("csv").catch((error) => {
    if (error?.name !== "AbortError") showToast("Inventory export failed", error.message, "danger");
  });
});
inventoryExportNdjsonBtn?.addEventListener("click", () => {
  streamInventoryExport("ndjson").catch((error) => {
    if (error?.name !== "AbortError") showToast("Inventory export failed", error.message, "danger");
  });
});
refreshHistoryBtn.addEventListener("click", () => {
  loadHistory().catch((error) => setStatus(`History failed: ${error.message}`));
});
historyRange?.addEventListener("change", () => {
  updateHistoryFilterControls();
  renderHistory(latestHistoryItems);
});
historyFrom?.addEventListener("change", () => renderHistory(latestHistoryItems));
historyTo?.addEventListener("change", () => renderHistory(latestHistoryItems));
historyFrom?.addEventListener("input", debounce(() => renderHistory(latestHistoryItems)));
historyTo?.addEventListener("input", debounce(() => renderHistory(latestHistoryItems)));
auditRange?.addEventListener("change", () => {
  updateAuditFilterControls();
  renderAudit(latestAuditEvents);
});
auditFrom?.addEventListener("change", () => renderAudit(latestAuditEvents));
auditTo?.addEventListener("change", () => renderAudit(latestAuditEvents));
auditFrom?.addEventListener("input", debounce(() => renderAudit(latestAuditEvents)));
auditTo?.addEventListener("input", debounce(() => renderAudit(latestAuditEvents)));
// The collapse control lives at the bottom of the sidebar (desktop icon-rail
// collapse); the topbar hamburger stays as the small-screen off-canvas opener.
// Both carry [data-sidebar-toggle] and share this handler.
const sidebarToggles = document.querySelectorAll("[data-sidebar-toggle]");
function setSidebarCollapsed(collapsed) {
  document.body.classList.toggle("sidebar-collapsed", collapsed);
  sidebarToggles.forEach((btn) => {
    btn.setAttribute("aria-expanded", String(!collapsed));
    btn.title = collapsed ? "Expand navigation" : "Collapse navigation";
  });
  safeSessionSet("dspm-sidebar-collapsed", collapsed ? "1" : "");
}

sidebarToggles.forEach((btn) => {
  btn.addEventListener("click", () => {
    setSidebarCollapsed(!document.body.classList.contains("sidebar-collapsed"));
  });
});
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
  resetInventoryPageWindow();
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
  await loadAllComplianceKeywordLibraries().catch(() => {});
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
renderComplianceSelectors();
initSimpleExtensionPolicies();
applyDefaultSimpleExtensionPolicies();
// When an Exposure-insights category swaps in taller content, keep the panel
// where the user is looking instead of letting the page appear to jump.
document.addEventListener("change", (event) => {
  if (!event.target.matches?.(".insight-tab-radio")) return;
  // Bring the freshly expanded category into view - its content grows
  // downward, so anchor the panel's head at the top of the viewport. The
  // scroll runs after the swapped-in panel has laid out, instantly, so a
  // competing render can't cancel it mid-glide.
  setTimeout(() => {
    document.querySelector(".exposure-insights")?.scrollIntoView({ block: "start" });
  }, 120);
});

// The inventory results height is user-adjustable (native vertical resize);
// remember the chosen height per browser and restore it on load.
{
  const invWrap = document.querySelector("#inventory-workspace .inventory-table-wrap");
  if (invWrap) {
    invWrap.title = "Drag the bottom-right corner to resize the results area";
    const savedHeight = safeStorageGet("dspm-inventory-height");
    if (savedHeight) invWrap.style.height = savedHeight;
    const saveInventoryHeight = () => {
      if (invWrap.style.height) safeStorageSet("dspm-inventory-height", invWrap.style.height);
    };
    let resizeSaveTimer = 0;
    new ResizeObserver(() => {
      clearTimeout(resizeSaveTimer);
      resizeSaveTimer = setTimeout(saveInventoryHeight, 250);
    }).observe(invWrap);
    // The drag ends with a pointerup on the wrap - save immediately, frames
    // or not.
    invWrap.addEventListener("pointerup", saveInventoryHeight);
  }
}

renderProfile();
{
  const bootTab = tabFromLocation();
  if (bootTab && resolveTabName(bootTab) !== "overview") switchTab(bootTab);
}
// The avatar's source of truth is the account record; localStorage is only a
// per-browser cache for instant paint. Pull the server copy once per load.
(async function syncProfileFromServer() {
  try {
    const response = await fetch("/api/profile", { headers: authHeaders() });
    if (!response.ok) return;
    const data = await response.json();
    const serverAvatar = String(data.avatar || "");
    const key = profileAvatarStorageKey();
    if (serverAvatar) safeStorageSet(key, serverAvatar);
    else if (safeStorageGet(key)) safeStorageSet(key, "");
    renderProfile();
  } catch {
    /* offline or API unavailable - the cached avatar still paints */
  }
})();
renderAssetRules();
renderReportPreview();
renderExecutiveExperience();
renderScanContextPanels();
renderFindingsWorkspace();
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
    await loadAllComplianceKeywordLibraries();
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
    if (icon) icon.innerHTML = event.newValue === "dark" ? "&#9728;" : "&#9790;";
    if (toggle) {
      const nextLabel = event.newValue === "dark" ? "Switch to light mode" : "Switch to dark mode";
      toggle.setAttribute("aria-label", nextLabel);
      toggle.title = nextLabel;
    }
  }
  if (event.key === profileAvatarStorageKey()) {
    renderProfile();
  }
});

// ============================================================
// Scan profile decks & wizards
// A saved scan is a named, editable configuration card. The
// wizard re-houses the existing form widgets in three steps,
// so every field id and behavior below it is unchanged.
// ============================================================

const SCAN_WIZARD_KINDS = {
  "file-server": {
    deck: "#fs-scan-deck", grid: "#fs-profile-grid", wizard: "#fs-wizard",
    heading: "#fs-wizard-heading", stepper: '[data-stepper="file-server"]',
    back: "#fs-wizard-back", next: "#fs-wizard-next", save: "#fs-wizard-save",
    close: "#fs-wizard-close", del: "#fs-wizard-delete", hint: "#fs-wizard-hint",
    mirror: "#fs-wizard-status", statusSource: "#connection-status",
    newTitle: "New file server scan", icon: "li-server",
  },
  endpoint: {
    deck: "#endpoint-scan-deck", grid: "#endpoint-profile-grid", wizard: "#endpoint-wizard",
    heading: "#endpoint-wizard-heading", stepper: '[data-stepper="endpoint"]',
    back: "#endpoint-wizard-back", next: "#endpoint-wizard-next", save: "#endpoint-wizard-save",
    close: "#endpoint-wizard-close", del: "#endpoint-wizard-delete", hint: "#endpoint-wizard-hint",
    mirror: "#endpoint-wizard-status", statusSource: "#endpoint-status",
    newTitle: "New endpoint scan", icon: "li-monitor-cog",
  },
};

let scanProfilesState = [];
const scanWizardState = {
  "file-server": { step: 1, editingId: "" },
  endpoint: { step: 1, editingId: "" },
};
let activeProfileRun = null;
let fsLaunchArmed = false;

function wizardEl(kind, key) {
  return document.querySelector(SCAN_WIZARD_KINDS[kind][key]);
}

async function loadScanProfiles() {
  if (!accessToken) return;
  try {
    const data = await api("/api/scan-profiles", null, "GET");
    scanProfilesState = Array.isArray(data.profiles) ? data.profiles : [];
  } catch {
    scanProfilesState = [];
  }
  renderScanDecks();
}

function profilesOf(kind) {
  return scanProfilesState.filter((profile) => profile.kind === kind);
}

const EXT_PRESET_LABELS = { secrets: "Secrets", recommended: "Recommended", broad: "Broad", all: "All types" };
const ENDPOINT_SCOPE_LABELS = {
  default: "Profile quick scan", desktop: "Desktop", documents: "Documents", downloads: "Downloads",
  onedrive: "OneDrive", all: "Profile data", all_profiles: "All profiles", c_drive: "C: drive",
  all_fixed_drives: "All drives", custom: "Custom paths",
};

function profileTargetLine(profile) {
  const config = profile.config || {};
  if (profile.kind === "endpoint") {
    const user = config.target_username ? ` · ${config.target_username}` : "";
    return `${config.host || "no host"}${user}`;
  }
  return config.server ? `\\\\${config.server}` : `Local: ${config.local_path || "enterprise_test_data"}`;
}

function profileChips(profile) {
  const config = profile.config || {};
  const ui = config.ui || {};
  const chips = [];
  if (profile.kind === "endpoint") {
    chips.push({ label: ENDPOINT_SCOPE_LABELS[ui.path_scope] || "Scope", on: true });
    chips.push({ label: `Depth ${config.max_depth ?? 6}` });
    if (config.read_acl) chips.push({ label: "ACL", on: true });
    if (config.incremental_enabled) chips.push({ label: "Incremental", on: true });
  } else {
    chips.push({ label: EXT_PRESET_LABELS[ui.ext_preset] || "Custom types", on: true });
    chips.push({ label: `Depth ${config.max_depth ?? 4}` });
    if (config.incremental_enabled) chips.push({ label: "Incremental", on: true });
    if (config.inspect_archives) chips.push({ label: "ZIP" });
  }
  if (config.compliance_enabled && (config.compliance_frameworks || []).length) {
    chips.push({ label: `Compliance ${(config.compliance_frameworks || []).length}`, on: true });
  }
  return chips;
}

function scanProfileCardMarkup(profile) {
  const meta = SCAN_WIZARD_KINDS[profile.kind];
  const running = activeProfileRun && activeProfileRun.id === profile.profile_id;
  // Three chips maximum keeps every card exactly one chip-row tall, so the
  // File server and Endpoint decks match. The rest are summarised as "+N".
  const allChips = profileChips(profile);
  const shownChips = allChips.slice(0, 3);
  const hiddenChips = allChips.slice(3);
  const chips = shownChips
    .map((chip) => `<span class="spc-chip${chip.on ? " on" : ""}">${escapeHtml(chip.label)}</span>`)
    .join("") + (hiddenChips.length
      ? `<span class="spc-chip spc-chip-more" title="${escapeHtml(hiddenChips.map((chip) => chip.label).join(", "))}">+${hiddenChips.length}</span>`
      : "");
  const saved = String(profile.updated_at || "").slice(0, 10);
  const stateLabel = running ? "Running" : "Ready";
  return `
    <article class="scan-profile-card${running ? " is-running" : ""}" data-profile-id="${escapeHtml(profile.profile_id)}">
      <span class="spc-rail" aria-hidden="true"><svg class="f-ico"><use href="#${meta.icon}"/></svg></span>
      <div class="spc-body">
        <div class="spc-top">
          <span class="spc-name" title="${escapeHtml(profile.name)}">${escapeHtml(profile.name)}</span>
          <span class="spc-live ${running ? "is-running" : "is-ready"}" role="status">${stateLabel}</span>
        </div>
        <span class="spc-target" title="${escapeHtml(profileTargetLine(profile))}">${escapeHtml(profileTargetLine(profile))}</span>
        <div class="spc-chips">${chips}</div>
        <div class="spc-foot">
          <span class="spc-run-note">${profile.kind === "endpoint" ? "Endpoint" : "File server"} · saved ${escapeHtml(saved)}</span>
          <span class="spc-icon-actions">
            <button type="button" class="spc-icon-btn spc-start" data-profile-start="${escapeHtml(profile.profile_id)}"
              title="${running ? "Scan in progress" : "Start scan"}" aria-label="${running ? "Scan in progress" : `Start ${escapeHtml(profile.name)}`}">
              ${running
                ? '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9" class="spc-spin"/></svg>'
                : '<svg viewBox="0 0 24 24"><path d="M8 5.5v13l11-6.5z"/></svg>'}
            </button>
            <button type="button" class="spc-icon-btn" data-profile-edit="${escapeHtml(profile.profile_id)}"
              title="Edit scan" aria-label="Edit ${escapeHtml(profile.name)}">
              <svg viewBox="0 0 24 24"><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/></svg>
            </button>
          </span>
        </div>
      </div>
    </article>`;
}

function renderScanDecks() {
  Object.keys(SCAN_WIZARD_KINDS).forEach((kind) => {
    const grid = wizardEl(kind, "grid");
    if (!grid) return;
    const profiles = profilesOf(kind);
    if (!profiles.length) {
      grid.innerHTML = `
        <button type="button" class="scan-socket scan-socket-hero" data-open-scan-wizard="${kind}">
          <span class="socket-plus" aria-hidden="true">+</span>
          <strong>Set up your first ${kind === "endpoint" ? "endpoint" : "file server"} scan</strong>
          <small>${kind === "endpoint" ? "Choose a workstation and profile once. Run it whenever you need to." : "Define the connection once. Run it whenever you need to."}</small>
        </button>`;
      return;
    }
    grid.innerHTML = profiles.map(scanProfileCardMarkup).join("") + `
      <button type="button" class="scan-socket" data-open-scan-wizard="${kind}">
        <span class="socket-plus" aria-hidden="true">+</span>
        <strong>New scan</strong>
      </button>`;
  });
  refreshDeckBusyState();
}

function refreshDeckBusyState() {
  const busy = Boolean(activeProfileRun);
  document.querySelectorAll("[data-profile-start]").forEach((button) => {
    button.disabled = busy;
  });
}

// ---- Wizard open/close/steps ----------------------------------------------

function setWizardStep(kind, step) {
  const state = scanWizardState[kind];
  state.step = step;
  const wizard = wizardEl(kind, "wizard");
  wizard.querySelectorAll("[data-wizard-step]").forEach((panel) => {
    panel.classList.toggle("hidden", Number(panel.dataset.wizardStep) !== step);
  });
  document.querySelectorAll(`${SCAN_WIZARD_KINDS[kind].stepper} .stepper-node`).forEach((node) => {
    const nodeStep = Number(node.dataset.stepNode);
    node.classList.toggle("is-current", nodeStep === step);
    node.classList.toggle("is-done", nodeStep < step);
    const dot = node.querySelector(".stepper-dot");
    if (dot) dot.textContent = nodeStep < step ? "✓" : String(nodeStep);
  });
  wizardEl(kind, "back").disabled = step === 1;
  wizardEl(kind, "next").classList.toggle("hidden", step === 3);
  wizardEl(kind, "save").classList.toggle("hidden", step !== 3);
  setWizardHint(kind, "");
  if (kind === "endpoint" && step === 3) {
    syncWinrmActivationFields();
    renderEndpointReview();
  }
  const visiblePanel = wizard.querySelector(".wizard-step:not(.hidden)");
  if (visiblePanel) visiblePanel.scrollTop = 0;
}

function setWizardHint(kind, message) {
  const hint = wizardEl(kind, "hint");
  if (hint) hint.textContent = message || "";
}

const WIZARD_TAB_NAMES = { "file-server": "file-servers", endpoint: "endpoint" };

function wizardContextStrip(kind) {
  return document.querySelector(kind === "file-server" ? "#file-server-context" : "#endpoint-context");
}

function openScanWizard(kind, profileId = "") {
  const state = scanWizardState[kind];
  state.editingId = profileId;
  const profile = profileId ? scanProfilesState.find((p) => p.profile_id === profileId) : null;
  if (kind === "file-server") applyFileServerProfile(profile);
  else applyEndpointProfile(profile);
  wizardEl(kind, "heading").textContent = profile ? `Edit — ${profile.name}` : SCAN_WIZARD_KINDS[kind].newTitle;
  wizardEl(kind, "del").classList.toggle("hidden", !profile);
  wizardEl(kind, "deck").classList.add("hidden");
  wizardContextStrip(kind)?.classList.add("hidden");
  wizardEl(kind, "wizard").classList.remove("hidden");
  // A temporary setup URL: back button leaves the wizard, and entering the
  // URL directly lands on the deck (the router does not know the -setup hash).
  if (!String(location.hash).endsWith("-setup")) {
    history.pushState({ scanWizard: kind }, "", `/scan#${WIZARD_TAB_NAMES[kind]}-setup`);
  }
  setWizardStep(kind, 1);
  window.setTimeout(() => {
    document.querySelector(kind === "file-server" ? "#fs-profile-name" : "#endpoint-profile-name")?.focus({ preventScroll: true });
  }, 60);
}

// Safe from anywhere, including before this module's consts initialize and on
// pages with no wizard. The router calls this during boot, when
// SCAN_WIZARD_KINDS is still in its temporal dead zone - `typeof` does NOT
// guard a const there, it throws, so the access itself must be caught.
function closeAnyOpenScanWizard() {
  let kinds;
  try {
    kinds = SCAN_WIZARD_KINDS;
  } catch {
    return;
  }
  Object.keys(kinds || {}).forEach((kind) => {
    const wizard = document.querySelector(kinds[kind].wizard);
    if (wizard && !wizard.classList.contains("hidden")) {
      closeScanWizard(kind, { skipUrl: true });
    }
  });
}

function closeScanWizard(kind, options = {}) {
  wizardEl(kind, "wizard").classList.add("hidden");
  wizardEl(kind, "deck").classList.remove("hidden");
  wizardContextStrip(kind)?.classList.remove("hidden");
  scanWizardState[kind].editingId = "";
  if (!options.skipUrl && String(location.hash).endsWith("-setup")) {
    history.replaceState({ tab: WIZARD_TAB_NAMES[kind] }, "", `/scan#${WIZARD_TAB_NAMES[kind]}`);
  }
}

function validateWizardStep(kind, step) {
  if (step === 1) {
    if (kind === "file-server") {
      const name = document.querySelector("#fs-profile-name").value.trim();
      if (!name) return "Give this scan a name.";
      const server = document.querySelector("#server").value.trim();
      const hasCred = document.querySelector("#username").value.trim()
        || document.querySelector("#password").value
        || document.querySelector("#credential_ref").value.trim();
      if (server && !hasCred) return "SMB targets need a username + password, or a credential ref.";
    } else {
      if (!document.querySelector("#endpoint-profile-name").value.trim()) return "Give this scan a name.";
      if (!document.querySelector("#endpoint-host").value.trim()) return "Enter the endpoint host or IP.";
      const hasCred = document.querySelector("#endpoint-password").value
        || document.querySelector("#endpoint-credential-ref").value.trim();
      if (!document.querySelector("#endpoint-username").value.trim() || !hasCred) {
        return "Enter the admin username and a password (or credential ref).";
      }
    }
  }
  if (step === 2 && kind === "endpoint") {
    try {
      readEndpointPayload();
    } catch (error) {
      return error.message;
    }
  }
  return "";
}

function wizardNext(kind) {
  const state = scanWizardState[kind];
  const problem = validateWizardStep(kind, state.step);
  if (problem) {
    setWizardHint(kind, problem);
    return;
  }
  if (state.step < 3) setWizardStep(kind, state.step + 1);
}

function wizardBack(kind) {
  const state = scanWizardState[kind];
  if (state.step > 1) setWizardStep(kind, state.step - 1);
}

// ---- Collect & apply -------------------------------------------------------

function collectUiState(scope) {
  const isEndpoint = scope === "endpoint";
  const presetInput = document.querySelector(
    isEndpoint ? "input[name='endpoint-ext-preset']:checked" : "input[name='ext-preset']:checked"
  );
  const advancedVisible = !document
    .querySelector(isEndpoint ? "#endpoint-ext-advanced-mode" : "#ext-advanced-mode")
    ?.classList.contains("hidden");
  const list = isEndpoint ? endpointAllowedExtensionsList : allowedExtensionsList;
  return {
    ext_preset: advancedVisible ? "" : presetInput?.value || "",
    extensions: readSelectedExtensions(list),
    path_scope: isEndpoint ? document.querySelector("#endpoint-path-scope").value : undefined,
    custom_paths: isEndpoint ? document.querySelector("#endpoint-custom-paths").value : undefined,
  };
}

function applyExtensionUiState(scope, ui) {
  const isEndpoint = scope === "endpoint";
  const list = isEndpoint ? endpointAllowedExtensionsList : allowedExtensionsList;
  const search = isEndpoint ? endpointExtensionSearch : extensionSearch;
  const radios = document.querySelectorAll(
    isEndpoint ? "input[name='endpoint-ext-preset']" : "input[name='ext-preset']"
  );
  if (ui.ext_preset && EXT_PRESET_LABELS[ui.ext_preset]) {
    radios.forEach((radio) => { radio.checked = radio.value === ui.ext_preset; });
    applySimpleExtensionPolicy(ui.ext_preset, list, search);
    return;
  }
  const selected = new Set(ui.extensions || []);
  [...list.querySelectorAll("input[type='checkbox']")].forEach((input) => {
    input.checked = selected.has(input.value);
  });
  reorderExtensionOptions(list);
  filterExtensionList(list, search);
  updateExtensionSummary(list);
}

function applyComplianceState(scope, enabled, frameworks) {
  const toggle = scope === "endpoint" ? endpointComplianceEnabledInput : complianceEnabledInput;
  if (!toggle) return;
  toggle.checked = Boolean(enabled);
  toggle.dispatchEvent(new Event("change"));
  const wanted = new Set(frameworks || []);
  document
    .querySelectorAll(`[data-compliance-frameworks="${scope}"] input[type='checkbox']`)
    .forEach((input) => { input.checked = wanted.has(input.value); });
}

function collectFileServerProfile() {
  const payload = readPayload();
  delete payload.password;
  delete payload.asset_overrides;
  delete payload.scan_label;
  payload.ui = collectUiState("file-server");
  return {
    profile_id: scanWizardState["file-server"].editingId,
    kind: "file-server",
    name: document.querySelector("#fs-profile-name").value.trim(),
    config: payload,
  };
}

function collectEndpointProfile() {
  const payload = readEndpointPayload();
  delete payload.password;
  delete payload.asset_overrides;
  delete payload.scan_label;
  payload.ui = collectUiState("endpoint");
  return {
    profile_id: scanWizardState.endpoint.editingId,
    kind: "endpoint",
    name: document.querySelector("#endpoint-profile-name").value.trim(),
    config: payload,
  };
}

function applyFileServerProfile(profile) {
  const config = profile?.config || {};
  const ui = config.ui || {};
  document.querySelector("#fs-profile-name").value = profile?.name || "";
  document.querySelector("#server").value = config.server || "";
  document.querySelector("#domain").value = config.domain || "WORKGROUP";
  document.querySelector("#username").value = config.username || "";
  document.querySelector("#password").value = "";
  document.querySelector("#credential_ref").value = config.credential_ref || "";
  document.querySelector("#local_path").value = config.local_path || "enterprise_test_data";
  document.querySelector("#max_depth").value = config.max_depth ?? 4;
  document.querySelector("#async_scan").checked = config.async_scan ?? true;
  document.querySelector("#incremental_enabled").checked = config.incremental_enabled ?? true;
  document.querySelector("#inspect_archives").checked = Boolean(config.inspect_archives);
  document.querySelector("#include_admin_shares").checked = Boolean(config.include_admin_shares);
  applyExtensionUiState("file-server", profile ? ui : { ext_preset: "recommended" });
  applyComplianceState("file-server", config.compliance_enabled, config.compliance_frameworks);
  document.dispatchEvent(new Event("scan-form-updated"));
}

function applyEndpointProfile(profile) {
  const config = profile?.config || {};
  const ui = config.ui || {};
  document.querySelector("#endpoint-profile-name").value = profile?.name || "";
  document.querySelector("#endpoint-host").value = config.host || "";
  document.querySelector("#endpoint-target-username").value = config.target_username || "";
  document.querySelector("#endpoint-domain").value = config.domain || "WORKGROUP";
  document.querySelector("#endpoint-username").value = config.username || "";
  document.querySelector("#endpoint-password").value = "";
  document.querySelector("#endpoint-credential-ref").value = config.credential_ref || "";
  const scope = ui.path_scope || "default";
  endpointPathScope.value = scope;
  endpointPathScope.dispatchEvent(new Event("change"));
  document.querySelector("#endpoint-custom-paths").value = ui.custom_paths || "";
  document.querySelector("#endpoint-max-depth").value = config.max_depth ?? 6;
  document.querySelector("#endpoint-read-content").checked = config.read_content ?? true;
  document.querySelector("#endpoint-read-acl").checked = config.read_acl ?? true;
  document.querySelector("#endpoint-inspect-archives").checked = Boolean(config.inspect_archives);
  document.querySelector("#endpoint-async-scan").checked = config.async_scan ?? true;
  document.querySelector("#endpoint-incremental-enabled").checked = config.incremental_enabled ?? true;
  applyExtensionUiState("endpoint", profile ? ui : { ext_preset: "all" });
  applyComplianceState("endpoint", config.compliance_enabled, config.compliance_frameworks);
}

function syncWinrmActivationFields() {
  document.querySelector("#winrm-activate-host").value = document.querySelector("#endpoint-host").value.trim();
  document.querySelector("#winrm-target-username").value = document.querySelector("#endpoint-target-username").value.trim();
  document.querySelector("#winrm-activate-domain").value = document.querySelector("#endpoint-domain").value.trim() || "WORKGROUP";
  document.querySelector("#winrm-activate-username").value = document.querySelector("#endpoint-username").value.trim();
  document.querySelector("#winrm-activate-password").value = document.querySelector("#endpoint-password").value;
}

// ---- Save / delete / start -------------------------------------------------

async function saveScanProfileFromWizard(kind) {
  const problem = validateWizardStep(kind, 1) || validateWizardStep(kind, 2);
  if (problem) {
    setWizardHint(kind, problem);
    return;
  }
  const saveBtn = wizardEl(kind, "save");
  saveBtn.disabled = true;
  try {
    requireAuth();
    if (kind === "file-server") {
      await ensureCredential(readPayload());
    } else {
      await ensureEndpointCredential(readEndpointPayload());
    }
    const profile = kind === "file-server" ? collectFileServerProfile() : collectEndpointProfile();
    const saved = await api("/api/scan-profiles", profile);
    const index = scanProfilesState.findIndex((p) => p.profile_id === saved.profile_id);
    if (index >= 0) scanProfilesState[index] = saved;
    else scanProfilesState.push(saved);
    renderScanDecks();
    closeScanWizard(kind);
    showToast("Scan saved", `"${saved.name}" is ready to run.`, "info");
  } catch (error) {
    setWizardHint(kind, `Save failed: ${error.message}`);
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteScanProfileFromWizard(kind) {
  const state = scanWizardState[kind];
  if (!state.editingId) return;
  const profile = scanProfilesState.find((p) => p.profile_id === state.editingId);
  if (!window.confirm(`Delete "${profile?.name || "this scan"}"? Its results stay in the tenant.`)) return;
  try {
    await api(`/api/scan-profiles/${encodeURIComponent(state.editingId)}`, null, "DELETE");
    scanProfilesState = scanProfilesState.filter((p) => p.profile_id !== state.editingId);
    renderScanDecks();
    closeScanWizard(kind);
    showToast("Scan deleted", "", "info");
  } catch (error) {
    setWizardHint(kind, `Delete failed: ${error.message}`);
  }
}

async function startProfileScan(kind, profileId) {
  const profile = scanProfilesState.find((p) => p.profile_id === profileId);
  if (!profile || activeProfileRun) return;
  activeProfileRun = { kind, id: profileId };
  activeScanLabel = String(profile.name || "");
  renderScanDecks();
  try {
    if (kind === "file-server") {
      applyFileServerProfile(profile);
      fsLaunchArmed = true;
      form.requestSubmit(scanBtn);
    } else {
      applyEndpointProfile(profile);
      endpointScanBtn.click();
    }
  } catch (error) {
    activeProfileRun = null;
    renderScanDecks();
    setStatus(`Scan start failed: ${error.message}`);
  }
}

function watchScanRunState() {
  const clearWhenIdle = (progressEl) => {
    if (!progressEl) return;
    new MutationObserver(() => {
      if (progressEl.classList.contains("hidden") && activeProfileRun) {
        activeProfileRun = null;
        activeScanLabel = "";
        renderScanDecks();
      }
    }).observe(progressEl, { attributes: true, attributeFilter: ["class"] });
  };
  clearWhenIdle(document.querySelector("#scan-progress"));
  clearWhenIdle(document.querySelector("#endpoint-scan-progress"));
}

function mirrorWizardStatus() {
  Object.keys(SCAN_WIZARD_KINDS).forEach((kind) => {
    const source = document.querySelector(SCAN_WIZARD_KINDS[kind].statusSource);
    const mirror = wizardEl(kind, "mirror");
    if (!source || !mirror) return;
    new MutationObserver(() => {
      mirror.textContent = source.textContent;
    }).observe(source, { childList: true, characterData: true, subtree: true });
  });
}

function renderEndpointReview() {
  const host = document.querySelector("#endpoint-review-rows");
  if (!host) return;
  const scope = document.querySelector("#endpoint-path-scope");
  const scopeLabel = scope?.selectedOptions?.[0]?.textContent || "User profile quick scan";
  const target = document.querySelector("#endpoint-host").value.trim() || "no host";
  const user = document.querySelector("#endpoint-target-username").value.trim();
  const admin = document.querySelector("#endpoint-username").value.trim();
  const depth = document.querySelector("#endpoint-max-depth").value || "6";
  const flags = [
    ["Content preview", document.querySelector("#endpoint-read-content").checked],
    ["ACL", document.querySelector("#endpoint-read-acl").checked],
    ["Archives", document.querySelector("#endpoint-inspect-archives").checked],
    ["Cancellable job", document.querySelector("#endpoint-async-scan").checked],
    ["Incremental", document.querySelector("#endpoint-incremental-enabled").checked],
  ];
  host.innerHTML = `
    <button type="button" class="review-row" data-wizard-goto="1">
      <span class="review-label">Target</span>
      <span class="review-value"><b>${escapeHtml(target)}</b><small>${escapeHtml(user ? `profile ${user}` : "no profile user")} · admin ${escapeHtml(admin || "—")}</small></span>
      <span class="review-edit" aria-hidden="true">Edit</span>
    </button>
    <button type="button" class="review-row" data-wizard-goto="2">
      <span class="review-label">Scope</span>
      <span class="review-value"><b>${escapeHtml(scopeLabel)}</b><small>depth ${escapeHtml(depth)}</small></span>
      <span class="review-edit" aria-hidden="true">Edit</span>
    </button>
    <div class="review-row review-row-static">
      <span class="review-label">Options</span>
      <ul class="review-option-chips">${flags.map(([label, on]) => `<li class="${on ? "on" : ""}">${escapeHtml(label)}</li>`).join("")}</ul>
    </div>`;
}

// Idle boilerplate ("Ready", boot hints) has no value on the deck; the strip
// appears only when a scan or test actually says something.
const IDLE_STATUS_TEXTS = new Set([
  "Ready",
  "Ready. Saved endpoint scans start from their card.",
  "Fill the endpoint scan details after WinRM is active on the workstation.",
]);

function hideIdleDeckStatus() {
  [document.querySelector("#connection-status"), document.querySelector("#endpoint-status")].forEach((node) => {
    if (!node) return;
    const refresh = () => {
      const text = node.textContent.trim();
      node.classList.toggle("idle-hidden", !text || IDLE_STATUS_TEXTS.has(text) || text.startsWith("Enter Target Windows user"));
    };
    refresh();
    new MutationObserver(refresh).observe(node, { childList: true, characterData: true, subtree: true });
  });
}

function initScanProfileDecks() {
  document.addEventListener("click", (event) => {
    const opener = event.target.closest("[data-open-scan-wizard]");
    if (opener) {
      openScanWizard(opener.dataset.openScanWizard);
      return;
    }
    const startBtn = event.target.closest("[data-profile-start]");
    if (startBtn) {
      const kind = startBtn.closest("#fs-profile-grid") ? "file-server" : "endpoint";
      startProfileScan(kind, startBtn.dataset.profileStart);
      return;
    }
    const editBtn = event.target.closest("[data-profile-edit]");
    if (editBtn) {
      const kind = editBtn.closest("#fs-profile-grid") ? "file-server" : "endpoint";
      openScanWizard(kind, editBtn.dataset.profileEdit);
    }
  });

  document.addEventListener("click", (event) => {
    const gotoBtn = event.target.closest("[data-wizard-goto]");
    if (!gotoBtn) return;
    const kind = gotoBtn.closest("#fs-wizard") ? "file-server" : "endpoint";
    setWizardStep(kind, Number(gotoBtn.dataset.wizardGoto) || 1);
  });

  Object.keys(SCAN_WIZARD_KINDS).forEach((kind) => {
    wizardEl(kind, "next")?.addEventListener("click", () => wizardNext(kind));
    wizardEl(kind, "back")?.addEventListener("click", () => wizardBack(kind));
    wizardEl(kind, "close")?.addEventListener("click", () => closeScanWizard(kind));
    wizardEl(kind, "save")?.addEventListener("click", () => saveScanProfileFromWizard(kind));
    wizardEl(kind, "del")?.addEventListener("click", () => deleteScanProfileFromWizard(kind));
  });

  // Enter inside the wizard advances a step; only an armed programmatic
  // submit (a card's Start button) may launch the scan.
  form.addEventListener("submit", (event) => {
    if (fsLaunchArmed) {
      fsLaunchArmed = false;
      return;
    }
    event.preventDefault();
    event.stopImmediatePropagation();
    wizardNext("file-server");
  }, true);

  document.querySelector("#endpoint-activate-btn")?.addEventListener("click", () => {
    syncWinrmActivationFields();
  }, true);

  watchScanRunState();
  mirrorWizardStatus();
  hideIdleDeckStatus();
  syncInventorySortHeaders();
  renderScanDecks();
}

initScanProfileDecks();
