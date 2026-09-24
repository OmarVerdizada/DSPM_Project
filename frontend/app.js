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
const noticeHost = document.querySelector("#notice-host");
const sidebarToggle = document.querySelector("#sidebar-toggle");
const protectedCount = document.querySelector("#protected-count");
const health = document.querySelector("#health");
const filterInput = document.querySelector("#filter");
const inventoryRiskSelect = document.querySelector("#inventory-risk-filter");
const inventoryFrameworkSelect = document.querySelector("#inventory-framework-select");
const inventoryFolderSelect = document.querySelector("#inventory-folder-filter");
const inventorySourceFilter = document.querySelector("#inventory-source-filter");
const inventoryFindingFilter = document.querySelector("#inventory-finding-filter");
const inventoryClearFiltersBtn = document.querySelector("#clear-inventory-filters");
const inventoryApplyFiltersBtn = document.querySelector("#inventory-apply-filters");
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
const reportComposer = document.querySelector("#report-composer");
const reportTypeList = document.querySelector("#report-type-list");
const reportSectionList = document.querySelector("#report-sections");
const reportFormatList = document.querySelector("#report-format");
const reportFormatNote = document.querySelector("#report-format-note");
const reportBuildLine = document.querySelector("#report-build-line");
const reportCoverageSelect = document.querySelector("#report-coverage");
const reportSeveritySelect = document.querySelector("#report-severity");
const reportStatusSelect = document.querySelector("#report-status");
const reportDepthSelect = document.querySelector("#report-depth");
const reportDetailCountSelect = document.querySelector("#report-detail-count");
const reportOrderSelect = document.querySelector("#report-order");
const reportSectionExplainer = document.querySelector("#report-section-explainer");
const reportScopeSummary = document.querySelector("#report-scope-summary");
const reportSectionsSummary = document.querySelector("#report-sections-summary");
const reportSeamChip = document.querySelector("#report-seam-chip");
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
const historyContext = document.querySelector("#history-context");
const historyHead = document.querySelector("#history-head");
const auditHead = document.querySelector("#audit-head");
const auditSection = document.querySelector("#audit-section");
const fileServerContext = document.querySelector("#file-server-context");
const endpointContext = document.querySelector("#endpoint-context");
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
const topRiskyFolders = document.querySelector("#top-risky-folders");
const remediationWorkflow = document.querySelector("#remediation-workflow");
const remediationDrawerToggle = document.querySelector("#remediation-drawer-toggle");
const remediationDrawerBody = document.querySelector("#remediation-drawer-body");
const remediationFilters = document.querySelector("#remediation-filters");
const remediationApplyFiltersBtn = document.querySelector("#remediation-apply-filters");
const remediationSearch = document.querySelector("#remediation-search");
const remediationScopeFilter = document.querySelector("#remediation-scope-filter");
const remediationSeverityFilter = document.querySelector("#remediation-severity-filter");
const remediationCategoryFilter = document.querySelector("#remediation-category-filter");
const remediationStatusFilter = document.querySelector("#remediation-status-filter");
const remediationOwnerFilter = document.querySelector("#remediation-owner-filter");
const remediationFrameworkFilter = document.querySelector("#remediation-framework-filter");
const remediationDataFilter = document.querySelector("#remediation-data-filter");
const remediationAssetFilter = document.querySelector("#remediation-asset-filter");
const remediationSlaFilter = document.querySelector("#remediation-sla-filter");
const remediationResultCount = document.querySelector("#remediation-result-count");
const remediationScopeSummary = document.querySelector("#remediation-scope-summary");
const remediationError = document.querySelector("#remediation-error");
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
const endpointAccessBtn = document.querySelector("#endpoint-access-btn");
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

// The shell is hidden by <body class="auth-locked"> until something removes it
// (`.auth-locked .app-shell { display: none }`), and index.html has no login
// screen to fall back to - so while that class is on, the page is blank.
//
// That used to be decided 8,500 lines below, after every widget on every page
// had wired itself up, which made "one dead element reference" and "the whole
// console is a white screen" the same bug. Whether to show the shell depends
// on one thing: is there a token. Decide it here, so a failure further down
// costs the widget that failed and not the session.
//
// setAuthState() still runs later and stays the single entry point for login
// and logout; this is the same two class toggles, early and without the
// setBusy() call, which reads state that is not declared yet.
if (accessToken) {
  document.body.classList.remove("auth-locked");
  document.body.classList.add("auth-ready");
} else {
  window.location.replace("/login");
}
let currentTenant = safeSessionGet("dspm-tenant-id") || "default";
// Every asynchronous tenant-owned render captures this generation. Switching
// tenant increments it, so a slower response from the old tenant can never
// repopulate a dashboard, chart, inventory page, profile deck, or audit table.
let tenantContextVersion = 0;
let currentUser = safeSessionGet("dspm-user") || "admin";
let currentRole = safeSessionGet("dspm-role") || "admin";
let customExtensions = loadCustomExtensions();
// Panels that owe a render because they were hidden when their data changed.
const pendingPanelRenders = new Map();

function panelIsVisible(panelId) {
  const panel = document.getElementById(panelId);
  return Boolean(panel && panel.classList.contains("active"));
}

/**
 * True when the caller should skip its work. The render is remembered against
 * the panel and replayed by `flushPanelRenders` when the panel is shown.
 */
function deferWhileHidden(panelId, key, replay) {
  if (panelIsVisible(panelId)) return false;
  pendingPanelRenders.set(`${panelId}:${key}`, { panelId, replay });
  return true;
}

function flushPanelRenders(panelId) {
  for (const [key, entry] of [...pendingPanelRenders]) {
    if (entry.panelId !== panelId) continue;
    pendingPanelRenders.delete(key);
    try {
      entry.replay();
    } catch (error) {
      console.warn("deferred render failed", key, error);
    }
  }
}

// Work a tab needs the first time it is opened, rather than at boot.
const tabFirstOpened = new Set();

function onFirstTabOpen(tabName, run) {
  if (tabFirstOpened.has(tabName)) return;
  tabFirstOpened.add(tabName);
  try {
    run();
  } catch (error) {
    console.warn("tab first-open work failed", tabName, error);
  }
}

let latestFiles = [];
let latestReport = null;
let latestScanKind = "";
let remediationFindings = [];
let remediationSummary = null;
let remediationFacets = {};
const REMEDIATION_PAGE_SIZE = 50;
// Sort lives on the column header, as it does on the inventory.
let remediationSortKey = "risk_score";
let remediationSortDirection = "desc";
let remediationPage = { total: 0, hasMore: false, nextCursor: "", pageIndex: 0, pageStarts: [""] };
let remediationLoaded = false;
let remediationLoading = Boolean(accessToken);
let remediationLoadError = "";
let selectedRemediationFindingId = "";
let selectedRemediationFinding = null;
let remediationDetailRequest = 0;
let remediationListRequest = 0;
let remediationListAbortController = null;
let remediationPendingAction = null;

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
let scanProfilesState = [];
// Estate-wide summary aggregated server-side across ALL scan sources (file
// server + endpoint + local). The dashboard tiles must describe the whole
// indexed inventory - the same data Data Inventory shows - not whichever
// single scan happened to run last.
let estateSummary = null;
let estateFacets = null;
let estateFacetsRequestPromise = null;
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
// Each facet holds a set now, and the single-value globals above are the
// first answer in it - kept for the browser-local filters that predate the
// server-side inventory and still read one value.
let inventoryRiskFacets = new Set();
let inventorySourceFacets = new Set();
let inventoryFindingFacets = new Set();
let inventoryFacetSourceKey = "";
// Not a facet: no control offers it, and it exists only so a dashboard card
// that counted "critical and not locked" can open the same set. Cleared with
// the facets.
let inventoryProtectedFacet = null;

// ---- Facets that take more than one answer -------------------------------
// Every filter on Findings and the queue was a <select>: one question, one
// answer. The question an operator actually asks is "critical AND high", or
// three owners at once, so each becomes a checkbox menu.
//
// The <select> stays where it is. It is where a dozen renderers write their
// option lists, it draws the control - leading glyph, caret, ellipsis, and
// the width rules pinned across four layers of styles.css - and it displays
// the current answer through a synthetic first option. Only its input is
// taken away: a transparent trigger covers it, and one menu shared by every
// facet on the page holds the checkboxes.
const FACET_SUMMARY_VALUE = "__facet_summary__";
// Scope is exclusive by nature. Folder has no parameter of its own - it
// drives the free-text search, which takes one string. Both stay single.
const FACET_SINGLE_IDS = new Set(["inventory-folder-filter", "remediation-scope-filter"]);
const FACET_GROUPS = {
  findings: ["inventory-risk-filter", "inventory-source-filter", "inventory-finding-filter",
    "inventory-framework-select"],
  risk: ["remediation-severity-filter", "remediation-category-filter", "remediation-status-filter",
    "remediation-owner-filter", "remediation-framework-filter", "remediation-data-filter",
    "remediation-asset-filter", "remediation-sla-filter"],
};
// Pending is what the menus show; applied is what the last search asked for.
// Nothing between the two reaches the server, which is the point: narrowing
// by three facets used to cost three round trips and two thrown-away renders.
const facetPending = new Map();
const facetApplied = new Map();
let facetMenuOwner = null;
let facetMenuElement = null;
let fileSearchIndex = new WeakMap();

function captureTenantContext() {
  return { tenantId: currentTenant, version: tenantContextVersion };
}

function isCurrentTenantContext(context, payload = null) {
  if (!context || context.version !== tenantContextVersion || context.tenantId !== currentTenant) {
    return false;
  }
  // Tenant-owned API responses echo the effective backend scope. Keep the
  // generation check for endpoints without an echo, and fail closed if an
  // echoed scope ever disagrees with the request context.
  const responseTenant = payload && typeof payload === "object" ? String(payload.tenant_id || "") : "";
  return !responseTenant || responseTenant === context.tenantId;
}

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

  if (response.status === 401 && !options.isRetry && await refreshAccessToken()) {
    // C1: the access token is bounded (half an hour), and the session is carried by a
    // single-use refresh cookie. A 401 is therefore the NORMAL end of an access token,
    // not the end of the session - retry once with the new one, and only give up if
    // the refresh itself fails.
    return api(path, payload, method, { ...options, isRetry: true });
  }

  if (!response.ok) {
    const message = await readErrorMessage(response);
    if (response.status === 401) {
      endSession("Session expired", "Please sign in again.");
    }
    throw new Error(`${response.status}: ${message}`);
  }

  return response.json();
}

// One refresh at a time. Twenty panels loading at once produce twenty 401s, and each
// exchanging the cookie would retire the token the others are about to present - which
// the server reads as a replay and answers by ending the whole family.
let refreshInFlight = null;

async function refreshAccessToken() {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await fetch("/api/auth/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
        });
        if (!response.ok) {
          return false;
        }
        const data = await response.json();
        if (!data.access_token) {
          return false;
        }
        accessToken = data.access_token;
        safeSessionSet("dspm-access-token", accessToken);
        return true;
      } catch {
        return false;   // offline, or the endpoint is not there: treat as signed out
      } finally {
        window.setTimeout(() => { refreshInFlight = null; }, 0);
      }
    })();
  }
  return refreshInFlight;
}

function endSession(title, message) {
  accessToken = "";
  safeSessionSet("dspm-access-token", "");
  showToast(title, message, "danger");
  window.setTimeout(() => window.location.replace("/login"), 900);
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
    showFieldError(input, "Use a file extension like .docx — letters and digits only.");
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
    ...readEndpointTransport(),
    asset_overrides: assetRules,
    compliance_enabled: selectedComplianceFrameworks.length > 0,
    compliance_frameworks: selectedComplianceFrameworks,
    scan_label: activeScanLabel || "",
  };
}

// C0.1: the transport block the API now accepts. Preflight and the scan send the
// same one, so "test connection" proves the transport the scan will actually use.
function readEndpointTransport() {
  const useSsl = (document.querySelector("#endpoint-transport")?.value || "http") === "https";
  const trust = useSsl ? (document.querySelector("#endpoint-cert-trust")?.value || "system") : "system";
  const port = parseInt(document.querySelector("#endpoint-port")?.value || "", 10);
  return {
    use_ssl: useSsl,
    port: Number.isFinite(port) && port > 0 ? port : null,
    cert_trust: trust,
    ca_bundle: trust === "ca_bundle" ? (document.querySelector("#endpoint-ca-bundle")?.value || "").trim() : "",
    cert_thumbprint: trust === "thumbprint" ? (document.querySelector("#endpoint-cert-thumbprint")?.value || "").trim() : "",
    kerberos: document.querySelector("#endpoint-kerberos")?.value || "",
  };
}

// How a preflight or a scan was actually carried, for the line an operator reads.
// "Connected" alone says nothing about whether the channel was TLS or whether the
// certificate was checked, which is the whole point of the choice they just made.
function describeEndpointTransport(transport) {
  if (!transport) {
    return "";
  }
  const where = `${transport.scheme || "http"}:${transport.port || ""}`;
  if (!transport.ssl) {
    return `${where}, encrypted at the message layer`;
  }
  const trust = {
    thumbprint: "pinned certificate",
    ca_bundle: "certificate checked against your CA bundle",
    system: "certificate checked",
    insecure: "CERTIFICATE NOT CHECKED",
  }[transport.certificate_trust] || "certificate checked";
  return `${where}, ${trust}`;
}

function syncEndpointTransportFields() {
  const transport = document.querySelector("#endpoint-transport");
  const trust = document.querySelector("#endpoint-cert-trust");
  if (!transport || !trust) {
    return;
  }
  const useSsl = transport.value === "https";
  trust.disabled = !useSsl;
  // The API refuses a certificate trust choice on a connection that is not TLS,
  // so the form cannot offer one that would come back as a validation error.
  if (!useSsl) {
    trust.value = "system";
  }
  document.querySelector("#endpoint-ca-bundle-field")?.classList.toggle("hidden", !useSsl || trust.value !== "ca_bundle");
  document.querySelector("#endpoint-thumbprint-field")?.classList.toggle("hidden", !useSsl || trust.value !== "thumbprint");
  const port = document.querySelector("#endpoint-port");
  if (port) {
    port.placeholder = useSsl ? "5986" : "5985";
  }
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
    ...readEndpointTransport(),
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
  // A scan request captures one tenant for its entire lifecycle. Do not let a
  // manual switch retarget polling/rendering while that operation is active.
  if (tenantSwitcher) tenantSwitcher.disabled = isBusy;
  if (scanCancelBtn) scanCancelBtn.disabled = !activeScanJobId;
  if (localWinrmActivateBtn) localWinrmActivateBtn.disabled = isBusy;
  if (endpointActivateBtn) endpointActivateBtn.disabled = isBusy;
  if (endpointTestBtn) endpointTestBtn.disabled = isBusy;
  if (endpointScanBtn) endpointScanBtn.disabled = isBusy;
  if (endpointCancelBtn) endpointCancelBtn.disabled = !activeEndpointJobId;
  if (endpointViewOverviewBtn) endpointViewOverviewBtn.disabled = isBusy;
  updateEndpointCustomPathState(isBusy);
}

// `facts` turns a finished scan's diagnostics into figures instead of a
// paragraph. Without it this behaves exactly as it always has.
function setStatus(message, tone = "muted", facts = []) {
  statusBox.className = `status ${tone}`;
  if (facts.length) {
    statusBox.innerHTML = `<span class="status-headline">${escapeHtml(message)}</span>
      <span class="status-facts">${facts
        .map(([label, value]) => `<span class="status-fact"><b>${escapeHtml(String(value))}</b>${escapeHtml(label)}</span>`)
        .join("")}</span>`;
    return;
  }
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
  clearFindingsFacetState();
  renderInventoryFrameworkFilter();
}

// Both the Clear button and a change of tenant unset every Findings facet.
function clearFindingsFacetState() {
  inventoryRiskFilter = "ALL";
  inventorySourceFacet = "ALL";
  inventoryFindingFacet = "ALL";
  inventoryRiskFacets = new Set();
  inventorySourceFacets = new Set();
  inventoryFindingFacets = new Set();
  inventoryFrameworkFacets = new Set();
  inventoryProtectedFacet = null;
  FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));
  commitFacetGroup("findings");
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

// One figure per diagnostic, and only the ones that carry news: a zero
// unreadable-path count is not worth a chip. The allowed-extension list and
// the local path are settings the scan was run WITH, not results, and they
// belong on the profile rather than in the completion line.
function summarizeFileServerDiagnostics(report = {}) {
  const diagnostics = report.scan_diagnostics || {};
  const incremental = diagnostics.incremental || {};
  const facts = [];
  const number = (value) => Number.isFinite(Number(value)) ? Number(value) : null;
  const add = (label, value, { always = false } = {}) => {
    if (value === null || (!always && !value)) return;
    facts.push([label, value.toLocaleString()]);
  };
  add("records", number(diagnostics.records), { always: true });
  if (incremental.enabled) {
    add("reused", number(incremental.unchanged_objects), { always: true });
    add("read", number(incremental.content_reads), { always: true });
    add("deleted", number(incremental.deleted_objects));
  }
  add("owners", number(diagnostics.owner_resolved), { always: true });
  add("owners missing", number(diagnostics.owner_missing));
  add("ACL reads failed", number(diagnostics.owner_read_failed));
  if (Array.isArray(diagnostics.list_errors) && diagnostics.list_errors.length) {
    add("unreadable paths", diagnostics.list_errors.length, { always: true });
  }
  return facts;
}

/* How long a notice stays up, by tone. A confirmation has been read by the
   time it finishes appearing; a failure carries the sentence that says what
   went wrong, and taking that away after four seconds is how an operator ends
   up re-running a scan to find out why the first one failed. */
const NOTICE_LIFETIMES = { info: 5000, success: 5000, warning: 8000, danger: 12000 };
const NOTICE_LIMIT = 4;
const NOTICE_EXIT_MS = 200;

function dismissNotice(notice) {
  if (!notice || notice.dataset.leaving === "1") return;
  notice.dataset.leaving = "1";
  window.clearTimeout(Number(notice.dataset.timer || 0));
  notice.classList.add("leaving");
  window.setTimeout(() => notice.remove(), NOTICE_EXIT_MS);
}

function armNoticeTimer(notice) {
  window.clearTimeout(Number(notice.dataset.timer || 0));
  const life = Number(notice.dataset.life || 0);
  if (!life || notice.dataset.paused === "1") return;
  notice.dataset.timer = String(window.setTimeout(() => dismissNotice(notice), life));
}

/* Pause while the pointer or the keyboard is inside it. Without this a notice
   can expire between reading its first line and reaching for its close
   button, which reads as the notice refusing to be dismissed. */
function holdNotice(notice, paused) {
  notice.dataset.paused = paused ? "1" : "0";
  if (paused) {
    window.clearTimeout(Number(notice.dataset.timer || 0));
    return;
  }
  armNoticeTimer(notice);
}

function showToast(title, message = "", tone = "info") {
  if (!noticeHost) return null;

  const notice = document.createElement("div");
  notice.className = `notice ${tone}`;
  // Failures interrupt a screen reader; confirmations wait their turn.
  notice.setAttribute("role", tone === "danger" ? "alert" : "status");
  const life = NOTICE_LIFETIMES[tone] ?? NOTICE_LIFETIMES.info;
  notice.dataset.life = String(life);
  notice.style.setProperty("--notice-life", `${life}ms`);
  notice.innerHTML = `<button type="button" class="notice-close plain-btn" aria-label="Dismiss notification"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button><strong class="notice-title">${escapeHtml(title)}</strong>${message ? `<span class="notice-body">${escapeHtml(message)}</span>` : ""}<span class="notice-life" aria-hidden="true"></span>`;

  notice.querySelector(".notice-close").addEventListener("click", () => dismissNotice(notice));
  notice.addEventListener("mouseenter", () => holdNotice(notice, true));
  notice.addEventListener("mouseleave", () => holdNotice(notice, false));
  notice.addEventListener("focusin", () => holdNotice(notice, true));
  notice.addEventListener("focusout", () => holdNotice(notice, false));

  noticeHost.appendChild(notice);
  armNoticeTimer(notice);

  // A burst of notices - a scan finishing on several hosts - must not grow
  // into a column that covers the page it is reporting on.
  const live = Array.from(noticeHost.children).filter((item) => item.dataset.leaving !== "1");
  live.slice(0, Math.max(0, live.length - NOTICE_LIMIT)).forEach(dismissNotice);
  return notice;
}

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || !noticeHost) return;
  const live = Array.from(noticeHost.children).filter((item) => item.dataset.leaving !== "1");
  // Newest first: Escape walks the stack back the way it was built. It does
  // not preventDefault - a modal or a menu still gets the same keypress.
  if (live.length) dismissNotice(live[live.length - 1]);
});

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

const ADMIN_ONLY_TABS = new Set(["security", "admin"]);

function isAdminRole() {
  return currentRole === "admin";
}

function applyRoleVisibility() {
  const isAdmin = isAdminRole();
  document.body.classList.toggle("role-admin", isAdmin);
  document.querySelectorAll("[data-admin-only]").forEach((element) => {
    element.setAttribute("aria-hidden", String(!isAdmin));
    if (element.matches("button, input, select, textarea")) element.tabIndex = isAdmin ? 0 : -1;
  });
  syncNavGroups();
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
  // The Dashboard and Data Inventory share the normalized current-estate
  // aggregation. A scan report is a scoped snapshot, never the global source.
  return estateSummary || summary;
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
  };
}

async function refreshEstateSummary() {
  if (!accessToken) return;
  if (estateFacets) return estateFacets;
  if (estateFacetsRequestPromise) return estateFacetsRequestPromise;
  const context = captureTenantContext();
  const request = (async () => {
    try {
      const facets = await api("/api/inventory/facets", null, "GET");
      if (!isCurrentTenantContext(context, facets)) return null;
      estateFacets = facets;
      estateSummary = facetsToEstateSummary(facets);
      refreshRiskCategoryCounts().catch(() => {});
    } catch {
      if (!isCurrentTenantContext(context)) return null;
      estateFacets = null;
      estateSummary = null;
    }
    if (!isCurrentTenantContext(context)) return null;
    // Repaint the dashboard-facing views now that the estate numbers are known.
    updateSummary(latestReport?.summary || buildCurrentSummary());
    renderExecutiveExperience();
    renderFindingsWorkspace();
    return estateFacets;
  })();
  estateFacetsRequestPromise = request;
  try {
    return await request;
  } finally {
    if (estateFacetsRequestPromise === request) estateFacetsRequestPromise = null;
  }
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

function applyScanReport(report, scanKind = "file-server", { refreshEstate = true } = {}) {
  if (scanKind === "endpoint" && !report?.endpoint) {
    clearActiveScanReport("Endpoint scan did not return endpoint data.");
    return;
  }
  latestReport = report;
  latestFiles = report.files || [];
  latestScanKind = scanKind;
  inventoryFacetRequest += 1;
  inventoryFacets = null;
  if (refreshEstate) {
    estateFacets = null;
    estateSummary = null;
  }
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
  if (refreshEstate) refreshEstateSummary().catch(() => {});
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
let workspaceSliceInFlight = null;
let workspaceSliceScanId = "";
async function hydrateWorkspaceSlice({ force = false } = {}) {
  if (!latestReport?.files_omitted) return;
  const scanId = String(latestReport?.scan_id || "");
  // Already hydrated for this report, or a fetch for it is on its way.
  if (scanId && scanId === workspaceSliceScanId && latestFiles.length) return;
  if (workspaceSliceInFlight) return workspaceSliceInFlight;
  workspaceSliceInFlight = hydrateWorkspaceSliceNow({ force, scanId }).finally(() => {
    workspaceSliceInFlight = null;
  });
  return workspaceSliceInFlight;
}

async function hydrateWorkspaceSliceNow({ force = false, scanId = "" } = {}) {
  // 200 rows for the Findings workspace. Fetching them while nothing on screen
  // needs them bought 203KB and 9,685 nodes nobody had asked to see. `force`
  // is the dashboard saying it does need them: its top-risk list counts per
  // file, so without this slice that card has nothing to count.
  if (!force && deferWhileHidden("tab-findings", "slice", () => hydrateWorkspaceSlice())) return;
  const context = captureTenantContext();
  const requestId = ++workspaceSliceRequest;
  const resultsBody = document.getElementById("results-body");
  if (resultsBody && resultsBody.querySelector(".inventory-empty-cell")) {
    // Table-shaped skeleton: one shimmer per column so the load state looks
    // like the data it becomes, not a banner over an empty-state CTA.
    const widths = [86, 62, 48, 40, 46, 78, 78];
    resultsBody.innerHTML = Array.from({ length: 6 }, () =>
      "<tr class=\"skl-tr\">" + widths.map((w) =>
        `<td><div class="skl" style="height:12px;width:${w}%"></div></td>`).join("") + "</tr>").join("");
  }
  try {
    const data = await api("/api/inventory?sort=risk_score&limit=200", null, "GET");
    if (!isCurrentTenantContext(context, data) || requestId !== workspaceSliceRequest || !latestReport?.files_omitted) return;
    const items = (data?.items || []).map((item) => hydrateInventoryPageItem(item));
    if (!items.length) return;
    latestFiles = items;
    workspaceSliceScanId = scanId;
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

// The Findings page is the Data inventory now: the detection-signal panel and
// the priority queue above it restated the dashboard's severity band and the
// table's own first rows, so both panels are gone. What is left is the one
// thing this function still owns - the page's first-run state.
function renderFindingsWorkspace() {
  if (deferWhileHidden("tab-findings", "workspace", renderFindingsWorkspace)) return;
  document.querySelector("#tab-findings")
    ?.classList.toggle("findings-pristine", !hasCompletedInventoryScan());
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

// The names the detectors give a credential, generic and framework alike.
// Matched as whole names rather than by substring so "Password" cannot be
// found inside an unrelated label.
const SECRET_FINDING_NAMES = new Set([
  "api key", "aws access key", "github token", "password", "private key",
  "connection string", "jwt", "session token",
  "api key, access token, oauth secret, or service token",
  "password, passphrase, or password hash",
  "private key, certificate secret, ssh key, or keystore material",
  "session token, jwt, refresh token, or auth cookie",
  "database connection string or database uri",
]);

function isSecretFinding(finding = {}) {
  const domain = String(finding.classification_domain || "").toLowerCase();
  const category = String(finding.data_category || finding.category || finding.finding_category || "").toLowerCase();
  if (domain === "secrets" || category.includes("credential") || category.includes("secret")) return true;
  // An inventory page's findings carry a name and nothing else, so the name
  // has to be enough on its own.
  return SECRET_FINDING_NAMES.has(String(findingDisplayName(finding) || "").trim().toLowerCase());
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

function applyInventoryRisk(level) {
  const value = String(level || "ALL").toUpperCase();
  // Every caller is a dashboard figure saying "show me these files", so the
  // page starts clean. Setting only the severity left whatever an earlier jump
  // had put in the other facets, and the list then contradicted the number
  // that was clicked - most visibly on "All files", which prints the estate
  // total and opened a filtered page.
  FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));
  if (filterInput) {
    filterInput.value = "";
    lastInventoryQuery = "";
  }
  if (value !== "ALL") setFacetSelection("inventory-risk-filter", [value]);
  inventoryProtectedFacet = null;
  applyFindingsFacets();
}

function renderInventoryRiskSelection() {
  syncFacetSummary(inventoryRiskSelect);
}

function canUseInventoryPageWindow() {
  // S-E.2 represents every inventory facet on the server. Browser-local risk
  // overrides may still change a displayed row, but they never force the
  // browser to hydrate the unbounded saved report.
  return Boolean(accessToken && hasCompletedInventoryScan());
}

function hasCompletedInventoryScan() {
  return Boolean(
    latestReport?.scan_id
    || latestHistoryItems.length
    || Number(inventoryFacets?.total || 0)
    || Number(estateSummary?.total_files || 0)
  );
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
  return (types.length ? types : ["Finding"]).map((type, index) => ({
    type,
    count: index === 0 ? count : 1,
    framework: frameworks[0] || "standard_scan",
    frameworks,
    description: "Summary only \u2014 open the row for the full evidence.",
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
  // A named-scan page can intentionally show an older snapshot. Never merge
  // its rows with similarly-pathed assets from the currently loaded report.
  const itemScanId = String(item.scan_id || "");
  const detail = (!itemScanId || itemScanId === String(latestReport?.scan_id || ""))
    ? latestFiles.find((file) => inventoryDetailKey(file) === detailKey)
    : null;
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
  // "Protected" in the Severity list and "Protected / locked" in the Finding
  // type list are the same stored flag, and the server knows to OR each of
  // them into the facet it was ticked in - so both travel as ordinary values.
  if (inventoryRiskFacets.size) params.set("risk", [...inventoryRiskFacets].join(","));
  if (inventorySourceFacets.size) params.set("source", [...inventorySourceFacets].join(","));
  if (inventoryFindingFacets.size) params.set("finding_type", [...inventoryFindingFacets].join(","));
  if (inventoryFrameworkFacets.size) params.set("framework", [...inventoryFrameworkFacets].join(","));
  if (inventoryProtectedFacet !== null) params.set("protected", inventoryProtectedFacet);
  if (query) params.set("q", query);
  return params;
}

// Sorting is a SERVER concern: the API orders the whole inventory and returns
// one keyset page, so clicking a column sorts every file in the tenant - not
// just the rows already loaded in the browser.
let inventorySortKey = "risk_score";
const INVENTORY_SORT_DEFAULT_DIRECTIONS = {
  risk_score: "desc",
  finding_count: "desc",
  name: "asc",
  scan_label: "asc",
};
let inventorySortDirection = INVENTORY_SORT_DEFAULT_DIRECTIONS[inventorySortKey];

function inventoryPageQuery(cursor = "") {
  const params = inventoryFilterParams();
  params.set("sort", inventorySortKey);
  params.set("direction", inventorySortDirection);
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
    throw new Error("This browser can't save a streaming download. Open Sentro in Chrome or Edge to export from here.");
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

function inventoryFacetSource() {
  const sources = [...inventorySourceFacets];
  return sources.length === 1 ? sources[0] : "ALL";
}

async function refreshInventoryFacets() {
  if (!canUseInventoryPageWindow()) return;
  const context = captureTenantContext();
  const selectedSource = inventoryFacetSource();
  const requestId = ++inventoryFacetRequest;
  try {
    if (selectedSource === "ALL") {
      const canonical = estateFacets || await refreshEstateSummary();
      if (!canonical || !isCurrentTenantContext(context, canonical) || requestId !== inventoryFacetRequest || inventoryFacetSource() !== selectedSource) return;
      inventoryFacets = canonical;
      const page = currentInventoryPage();
      if (page) renderRows(page.items, { serverPage: page });
      return;
    }
    const params = new URLSearchParams();
    if (selectedSource !== "ALL") params.set("source", selectedSource);
    const facets = await api(`/api/inventory/facets${params.size ? `?${params}` : ""}`, null, "GET");
    if (!isCurrentTenantContext(context, facets) || requestId !== inventoryFacetRequest || inventoryFacetSource() !== selectedSource) return;
    inventoryFacets = facets;
    const page = currentInventoryPage();
    if (page) renderRows(page.items, { serverPage: page });
  } catch (error) {
    if (isCurrentTenantContext(context) && requestId === inventoryFacetRequest) {
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
  resultsBody.innerHTML = `<tr><td colspan="6" class="inventory-window-status">
    <strong>Loading the next page\u2026</strong>
  </td></tr>`;
}

async function loadInventoryWindowPage(pageIndex = 0) {
  if (!inventoryPageWindow.active) return;
  const context = captureTenantContext();
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
    if (!isCurrentTenantContext(context, data) || requestId !== inventoryPageRequest || !inventoryPageWindow.active) return;
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
    if (error?.name === "AbortError" || !isCurrentTenantContext(context) || requestId !== inventoryPageRequest) return;
    inventoryPageWindow.loading = false;
    resultsBody.setAttribute("aria-busy", "false");
    inventoryPageWindow.error = error.message;
    inventoryPageWindow.active = false;
    renderedRowsLimit = ROW_PAGE_SIZE;
    renderRows(latestFiles);
    setStatus(latestFiles.length
      ? `Couldn't load that page. Showing the results already open. ${error.message}`
      : `Couldn't load that page, and nothing is open yet. ${error.message}`);
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
  return loadInventoryWindowPage(0);
}

function inventoryWindowControls(page) {
  const pageIndex = inventoryPageWindow.pageIndex;
  const start = page.total ? (pageIndex * INVENTORY_SERVER_PAGE_SIZE) + 1 : 0;
  const end = start ? start + page.items.length - 1 : 0;
  const totalLabel = `${page.total}${page.totalIsEstimate ? "+" : ""}`;
  return `<tr class="inventory-window-row"><td colspan="6">
    <div class="inventory-window-controls" aria-label="Inventory page controls" role="status" aria-live="polite">
      <button type="button" class="secondary-btn mini-btn" data-inventory-page="previous" ${pageIndex === 0 ? "disabled" : ""}>Previous page</button>
      <span><strong>${start}-${end}</strong> of ${totalLabel} files · page ${pageIndex + 1} · ${escapeHtml(page.source)} source</span>
      <button type="button" class="secondary-btn mini-btn" data-inventory-page="next" ${!page.hasMore ? "disabled" : ""}>Next page</button>
    </div>
  </td></tr>`;
}

// Three facts fit the column at every width the table is used at; the rest
// become one +N chip whose title lists them. A fixed cap rather than a
// measured one, because measuring a hundred rows to hide a chip costs a
// reflow per row and the answer would still be three.
const FILE_META_VISIBLE = 3;

// Four is what the cell fits, and what the +N beside it has always counted
// against. Rendering all of them cost 54 nodes a row to draw two that fit
// behind a fade.
const FINDING_CHIPS_SHOWN = 4;

function fileMetaLine({ extension, size, source, hashChanged, duplicateHashPath, flags = [] }) {
  const parts = [
    ...(extension ? [{ text: extension }] : []),
    { text: size },
    { text: source },
    ...(hashChanged ? [{ text: "Hash changed", className: "hash-change-chip" }] : []),
    ...(duplicateHashPath ? [{ text: "Duplicate hash path", className: "hash-change-chip duplicate-hash-chip" }] : []),
    ...flags.map((flag) => ({ text: flag })),
  ];
  const shown = parts.slice(0, FILE_META_VISIBLE);
  const hidden = parts.slice(FILE_META_VISIBLE);
  return `<div class="file-meta-line">${
    shown.map((part) => `<span${part.className ? ` class="${part.className}"` : ""}>${escapeHtml(part.text)}</span>`).join("")
  }${
    hidden.length
      ? `<span class="file-meta-more" title="${escapeHtml(hidden.map((part) => part.text).join(", "))}">+${hidden.length}</span>`
      : ""
  }</div>`;
}

function renderRows(files, options = {}) {
  if (deferWhileHidden("tab-findings", "rows", () => renderRows(files, options))) return;
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
    const hasCompletedScan = hasCompletedInventoryScan();
    document.querySelector("#tab-findings")?.classList.toggle("findings-pristine", !hasCompletedScan);
    resultsBody.innerHTML = hasCompletedScan
      ? `<tr><td colspan="6" class="inventory-empty-cell"><div class="inventory-empty-panel is-filtered" role="status"><strong>No findings found</strong></div></td></tr>`
      : `<tr><td colspan="6" class="inventory-empty-cell"><div class="inventory-empty-panel is-pristine">
          <span class="inventory-empty-icon" aria-hidden="true"></span>
          <strong>See your sensitive data clearly</strong>
          <p>Run a file-server or endpoint scan to build a readable inventory of findings, risk reasons, and recommended actions.</p>
          <button type="button" class="mc-empty-cta" data-tab-jump="file-servers">Start your first scan</button>
        </div></td></tr>`;
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
      const manualLevel = rowOverrides[key] || "";
      const integrityFindings = [
        hashChanged ? { type: "Hash changed", count: 1 } : null,
        duplicateHashPath ? { type: "Duplicate hash path", count: 1 } : null,
      ].filter(Boolean);
      const displayFindings = integrityFindings.length ? [...rawFindings, ...integrityFindings] : rawFindings;
      const visibleFindingChips = displayFindings.filter((finding) => !isNistFinding(finding));
      const shownFindingChips = visibleFindingChips.slice(0, FINDING_CHIPS_SHOWN);
      const findingChips = shownFindingChips.length
        ? shownFindingChips.map((finding) => `<span class="finding-chip ${escapeHtml(frameworkClass(findingVisualFramework(finding)))}">${escapeHtml(findingDisplayName(finding))} <b>${escapeHtml(finding.count || 1)}</b></span>`).join("")
        : displayFindings.length ? "" : '<span class="subtext">No sensitive signals</span>';
      const frameworkStrip = displayFindings.length ? `<div class="finding-framework-strip">${findingFrameworkStrip(displayFindings)}</div>` : "";
      const hiddenFindingCount = Math.max(0, displayFindings.length - shownFindingChips.length);
      const moreFindings = hiddenFindingCount > 0
        ? `<button type="button" class="detail-toggle finding-chip muted-chip" data-detail-type="findings" data-detail-key="${escapeHtml(key)}" title="Show all findings and matched keywords">+${hiddenFindingCount}</button>`
        : "";
      // The scan a customer named, falling back to the collector protocol.
      const sourceName = getInventorySourceValue(file);
      const path = file.path || file.name || "";
      const sha256 = fileHashValue(file);

      const rowFrameworkClass = "";
      const copyPathButton = path
        ? `<button type="button" class="icon-mini-btn copy-path-btn" data-copy-text="${escapeHtml(path)}" title="Copy full path" aria-label="Copy full path"><svg class="f-ico" aria-hidden="true"><use href="#inv-copy"/></svg><span>Copy path</span></button>`
        : "";

      return `
        <tr class="${flash} severity-row ${level} ${escapeHtml(rowFrameworkClass)}" data-file-key="${escapeHtml(key)}">
          <td>
            <div class="file-title polished-file-title">
              <button type="button" class="preview-toggle inventory-row-expand" data-inventory-expand="${escapeHtml(key)}" title="Open asset &amp; scan detail" aria-label="Open asset and scan detail" aria-haspopup="dialog"><svg class="preview-toggle-icon f-ico" aria-hidden="true"><use href="#inv-open"/></svg></button>
              <button type="button" class="file-info-toggle" data-inventory-expand="${escapeHtml(key)}" aria-haspopup="dialog" title="Open asset &amp; scan detail">
                <span class="file-path">${escapeHtml(file.name || file.path || "Unknown file")}</span>
              </button>
            </div>
            ${fileMetaLine({
              extension: file.extension,
              size: formatBytes(file.size),
              source: sourceName,
              hashChanged,
              duplicateHashPath,
              flags: fileFlags,
            })}
            <div class="subtext path-subtext"><span>${escapeHtml(path)}</span>${copyPathButton}</div>
          </td>
          <td>
            <div class="source-pill">${escapeHtml(sourceName)}</div>
            <div class="subtext">${escapeHtml(file.share || file.content_status || "scanned")}</div>
          </td>
          <td><div class="finding-chip-wrap"><div class="finding-chip-set">${findingChips}</div>${moreFindings}</div>${frameworkStrip}</td>
          <td>
            <div class="risk-cell${manualLevel ? " is-manual" : ""}">
              ${riskBadge(level, score)}
              <span class="risk-override" title="${manualLevel ? "Set manually - change or return to Auto" : "Set the risk manually"}">
                <svg class="f-ico" aria-hidden="true"><use href="#li-chevron-down"/></svg>
                <select class="risk-override-select" data-override="${escapeHtml(key)}" aria-label="Manual risk">
                  ${riskOption("", "Auto", manualLevel)}
                  ${riskOption("CRITICAL", "Critical", manualLevel)}
                  ${riskOption("HIGH", "High", manualLevel)}
                  ${riskOption("MEDIUM", "Medium", manualLevel)}
                  ${riskOption("LOW", "Low", manualLevel)}
                </select>
              </span>
            </div>
            <div class="subtext risk-note">${manualLevel ? "Set manually" : escapeHtml(riskLabel)}</div>
          </td>
          <td>${!lazyDetail ? detailButton(reasons, file, "reasons", "Reasons", "No reasons")
            : Number.isInteger(file.reason_count) ? countDetailButton(file.reason_count, file, "reasons", "Reasons", "No reasons")
            : lazyDetailButton(file, "reasons", "Reasons")}</td>
          <td>${!lazyDetail ? detailButton(recommendations, file, "recommendations", "DLP actions", "No actions")
            : Number.isInteger(file.dlp_count) ? countDetailButton(file.dlp_count, file, "recommendations", "DLP actions", "No actions")
            : lazyDetailButton(file, "recommendations", "DLP actions")}</td>
        </tr>
      `;
    });
  const moreRow = serverPage
    ? inventoryWindowControls(serverPage)
    : visible.length > page.length
      ? `<tr><td colspan="6" class="empty"><button type="button" class="secondary-btn mini-btn" id="load-more-results">Load ${Math.min(ROW_PAGE_SIZE, visible.length - page.length)} more of ${visible.length}</button></td></tr>`
      : "";
  writeRowsInChunks(rows, moreRow, () => resolveLazyDetailCounts(page));
  lastRenderedFileKeys = currentKeys;
  hasRenderedScanRows = true;
}

// One frame's worth of rows. At ~0.6ms a row this keeps each write inside the
// frame budget, and the number is small enough that a re-render started
// mid-flight discards little work.
const ROW_CHUNK_SIZE = 25;
let rowChunkToken = 0;

// requestAnimationFrame stops being called when the document is hidden, so a
// render that began before the operator switched away would stall part-drawn
// and stay that way. Yielding through a timeout instead keeps the remaining
// chunks arriving; both let the browser answer input between them, which is
// the whole point.
function scheduleRowChunk(step) {
  if (document.hidden) setTimeout(step, 0);
  else requestAnimationFrame(step);
}

function writeRowsInChunks(rowsHtml, tailHtml, whenDone = () => {}) {
  const token = ++rowChunkToken;
  if (rowsHtml.length <= ROW_CHUNK_SIZE) {
    resultsBody.innerHTML = rowsHtml.join("") + tailHtml;
    whenDone();
    return;
  }
  // The first chunk is synchronous: the operator sees the table in the same
  // frame as before, and only the rows below the fold are deferred.
  resultsBody.innerHTML = rowsHtml.slice(0, ROW_CHUNK_SIZE).join("");
  let next = ROW_CHUNK_SIZE;
  const step = () => {
    // A newer render owns the table now; this one stops where it is.
    if (token !== rowChunkToken) return;
    if (next >= rowsHtml.length) {
      resultsBody.insertAdjacentHTML("beforeend", tailHtml);
      whenDone();
      return;
    }
    resultsBody.insertAdjacentHTML("beforeend", rowsHtml.slice(next, next + ROW_CHUNK_SIZE).join(""));
    next += ROW_CHUNK_SIZE;
    scheduleRowChunk(step);
  };
  scheduleRowChunk(step);
}

// Backstop: if a rendered row is still waiting on reason/fix counts (a data
// path without the per-page attachment), one batched request fills them all
// in - the cells never sit on an ellipsis.
function resolveLazyDetailCounts(files = []) {
  const context = captureTenantContext();
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
      if (!isCurrentTenantContext(context, data)) return;
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
    if (inventoryRiskFacets.size
      && !(inventoryRiskFacets.has(risk) || (inventoryRiskFacets.has("PROTECTED") && isProtectedFile(file)))) return false;
    if (inventorySourceFacets.size
      && ![...inventorySourceFacets].some((source) => inventorySourceMatches(file, source))) return false;
    if (inventoryFindingFacets.size) {
      const types = getFileFindingTypes(file);
      const matched = [...inventoryFindingFacets].some((type) => {
        // Three of the options in this facet are coverage states, not classes.
        if (type === "Protected / locked") return isProtectedFile(file);
        if (type === "Classified") return getFileFindingTypes(file).length > 0;
        if (type === "Clear") return !isProtectedFile(file) && getFileFindingTypes(file).length === 0;
        return types.includes(type);
      });
      if (!matched) return false;
    }
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
  facetRealOptions(inventoryRiskSelect).forEach((option) => {
    const risk = option.value || "ALL";
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
    const label = option.dataset.label || (option.dataset.label = option.textContent);
    option.textContent = `${label} (${count.toLocaleString()})`;
  });
  if (inventoryContextMetrics) {
    const sensitive = serverPage
      ? visible.filter((file) => Number(file.finding_count || (file.findings || []).length) > 0).length
      : visible.filter((file) => (file.findings || []).length).length;
    const avgRisk = visible.length
      ? Math.round(visible.reduce((sum, file) => sum + (Number(getEffectiveRisk(file).score) || 0), 0) / visible.length)
      : 0;
    const inventoryTotal = serverPage ? `${serverPage.total}${serverPage.totalIsEstimate ? "+" : ""}` : (files || []).length;
    inventoryContextMetrics.innerHTML = `
      <div><span>Visible</span><strong>${visible.length}</strong><small>of ${inventoryTotal} files</small></div>
      <div><span>Sensitive</span><strong>${sensitive}</strong><small>${Math.round((sensitive / Math.max(1, visible.length)) * 100)}% in view</small></div>
      <div><span>Avg risk</span><strong>${avgRisk}</strong><small>/100</small></div>
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
    th.setAttribute("aria-sort", active ? (inventorySortDirection === "asc" ? "ascending" : "descending") : "none");
  });
}

function announceInventorySort(message) {
  const region = document.querySelector("#inventory-sort-status");
  if (region) region.textContent = message;
}

async function applyInventorySort(key) {
  if (!INVENTORY_SORT_LABELS[key]) return;
  if (key === inventorySortKey) {
    inventorySortDirection = inventorySortDirection === "asc" ? "desc" : "asc";
  } else {
    inventorySortKey = key;
    inventorySortDirection = INVENTORY_SORT_DEFAULT_DIRECTIONS[key] || "asc";
  }
  // "lowest first" is what a score does; a file name goes A to Z.
  const isText = ["name", "scan_label"].includes(key);
  const directionLabel = isText
    ? (inventorySortDirection === "desc" ? "Z to A" : "A to Z")
    : (inventorySortDirection === "desc" ? "highest first" : "lowest first");
  syncInventorySortHeaders();
  // setStatus() writes to #connection-status, which is the File Server scan
  // page's result box - so sorting the inventory printed "Sorted every file by
  // risk score, lowest first." over the last scan's outcome, on a different
  // page. The sort is already visible in the column header; the announcement
  // is for screen readers and belongs to Findings.
  announceInventorySort(`Sorting all files by ${INVENTORY_SORT_LABELS[key]}, ${directionLabel}…`);
  try {
    resetInventoryPageWindow();
    await refreshInventoryPageWindow();
    announceInventorySort(`Sorted every file by ${INVENTORY_SORT_LABELS[key]}, ${directionLabel}.`);
  } catch (error) {
    announceInventorySort(`Sort failed: ${error.message}`);
  }
}

document.addEventListener("click", (event) => {
  const th = event.target.closest(".inventory-table th[data-inventory-sort]");
  if (th) applyInventorySort(th.dataset.inventorySort);
});

// A row is one file, and the detail is what a row is for. The two buttons on
// the name still work; the rest of the row now does the same thing, except
// over the controls that mean something else - the manual-risk select, the
// reason and action counts, and the copy-path button.
function openInventoryRowDetail(row) {
  const control = row?.querySelector("[data-inventory-expand]");
  if (control) openAssetDetailModal(control);
}

document.addEventListener("click", (event) => {
  const row = event.target.closest("#results-body tr[data-file-key]");
  if (!row) return;
  if (event.target.closest("button, select, a, input, label, [data-detail-type], .risk-override")) return;
  openInventoryRowDetail(row);
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const th = event.target.closest?.(".inventory-table th[data-inventory-sort]");
  if (!th) return;
  event.preventDefault();
  applyInventorySort(th.dataset.inventorySort);
});

function completedInventoryScanNames() {
  // A tenant's configured profiles and persisted named runs are the only
  // entries in the customer-facing Scans group. Collector protocols are
  // covered by the two common scan kinds below.
  const candidates = [
    ...latestHistoryItems.map((item) => item?.scan_label),
    ...(inventoryFacets?.scans || []).map((item) => item?.value),
    ...scanProfilesState.map((profile) => profile?.name),
  ];
  const unique = new Map();
  candidates.forEach((candidate) => {
    const value = String(candidate || "").trim().slice(0, 80);
    if (value && !unique.has(value.toLocaleLowerCase())) unique.set(value.toLocaleLowerCase(), value);
  });
  return [...unique.values()].sort((a, b) => a.localeCompare(b));
}

const COMMON_INVENTORY_SCAN_SOURCES = [
  { value: "scan-kind:file-server", label: "File Server Scans" },
  { value: "scan-kind:endpoint", label: "Endpoint Scans" },
];

function isCommonInventoryScanSource(value) {
  return COMMON_INVENTORY_SCAN_SOURCES.some((source) => source.value === value);
}

function renderInventoryScanOptions() {
  if (inventorySourceFilter) {
    const scanNames = completedInventoryScanNames();
    const savedScans = scanNames.length
      ? `<optgroup label="Scans">${scanNames.map((name) => `<option value="${escapeHtml(name)}">${escapeHtml(name)}</option>`).join("")}</optgroup>`
      : "";
    const commonSources = COMMON_INVENTORY_SCAN_SOURCES
      .map((source) => `<option value="${source.value}">${source.label}</option>`)
      .join("");
    inventorySourceFilter.innerHTML = `
      <option value="ALL">All scans</option>
      ${savedScans}
      <optgroup label="Common scan sources">${commonSources}</optgroup>
    `;
    facetKeepChosen(inventorySourceFilter, [...scanNames, ...COMMON_INVENTORY_SCAN_SOURCES.map((source) => source.value)]);
  }
}

function updateInventoryFilterOptions(files = latestFiles) {
  renderInventoryScanOptions();
  if (inventoryFindingFilter) {
    const findings = inventoryFacets
      ? (inventoryFacets.finding_types || []).map((item) => String(item.value || "")).filter(Boolean)
      : [...new Set(files.flatMap(getFileFindingTypes))].sort((a, b) => a.localeCompare(b));
    inventoryFindingFilter.innerHTML = ["ALL", ...findings]
      .map((value) => `<option value="${escapeHtml(value)}">${escapeHtml(value === "ALL" ? "All finding types" : value)}</option>`)
      .join("");
    facetKeepChosen(inventoryFindingFilter, findings);
  }
  renderInventoryFrameworkFilter(files);
}

function getInventorySourceValue(file) {
  // The Source column names the scan a customer configured ("HR file share").
  // Assets captured before scans carried a name fall back to the collector
  // protocol so the column is never blank.
  return String(file.scan_label || file.source || file.share || "workspace").trim() || "workspace";
}

function inventorySourceMatches(file, sourceFacet) {
  if (sourceFacet === "scan-kind:file-server") return ["local", "smb"].includes(String(file.source || "").toLowerCase());
  if (sourceFacet === "scan-kind:endpoint") return ["endpoint", "endpoint-local", "endpoint-winrm"].includes(String(file.source || "").toLowerCase());
  return getInventorySourceValue(file) === sourceFacet;
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
    (inventoryFacets.frameworks || []).forEach((item) => counts.set(String(item.value || ""), Number(item.file_count ?? item.count ?? 0)));
  }
  return allOptions.map(([id, label]) => ({ id, label, count: counts.get(id) || 0 }));
}

function renderInventoryFrameworkFilter(files = latestFiles) {
  if (inventoryFrameworkSelect) {
    const selected = inventoryFrameworkFacets.size ? [...inventoryFrameworkFacets][0] : "ALL";
    const options = inventoryFrameworkOptions(files);
    inventoryFrameworkSelect.innerHTML = `<option value="ALL">All frameworks</option>${
      options.map(({ id, label, count }) =>
        `<option value="${escapeHtml(id)}">${escapeHtml(label)} (${Number(count).toLocaleString()})</option>`).join("")}`;
    syncFacetSummary(inventoryFrameworkSelect);
  }
  // The folder list is the dashboard's own location tree, so the two pages
  // name the same places the same way.
  if (inventoryFolderSelect) {
    const current = inventoryFolderSelect.value || "ALL";
    const places = (estateFacets?.locations || []).filter((item) => item.label);
    inventoryFolderSelect.innerHTML = `<option value="ALL">Anywhere</option>${
      places.map((item) => `<option value="${escapeHtml(item.label)}">${"  ".repeat(Number(item.depth) || 0)}${escapeHtml(item.label)} (${Number(item.file_count || 0).toLocaleString()})</option>`).join("")}`;
    inventoryFolderSelect.value = [...inventoryFolderSelect.options].some((option) => option.value === current) ? current : "ALL";
  }
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

function permittedTabName(tabName) {
  const resolved = resolveTabName(tabName);
  return !isAdminRole() && ADMIN_ONLY_TABS.has(resolved) ? "settings" : resolved;
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
      link.tabIndex = open && (!link.hasAttribute("data-admin-only") || isAdminRole()) ? 0 : -1;
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
  const resolvedTab = permittedTabName(tabName);
  const activePanel = document.getElementById(`tab-${resolvedTab}`);
  if (!activePanel) return;

  // The facet menu is positioned against a control on the page being left,
  // and it lives on the body so that no card can clip it - which also means
  // nothing hides it when that page does.
  closeFacetMenu();

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
  // Which page is open, where a stylesheet can read it. switchTab is the only
  // thing that toggles .active on a panel, and the popstate handler routes
  // through here too, so this covers every way the console navigates.
  document.body.dataset.tab = resolvedTab;
  syncNavGroups();
  const targetUrl = tabUrl(resolvedTab);
  if (location.pathname + location.hash !== targetUrl && PATH_DEFAULT_TAB[location.pathname]) {
    history.pushState({ tab: resolvedTab }, "", targetUrl);
  }
  tabPanels.forEach((panel) => panel.classList.toggle("active", panel === activePanel));

  flushPanelRenders(`tab-${resolvedTab}`);

  if (resolvedTab === "risk" && !remediationLoaded) {
    loadRemediationFindings().catch(() => {});
  }
  // The 200-row workspace slice used to be fetched at boot for a tab that was
  // not on screen: 203KB and 9,685 nodes nobody had asked for.
  if (resolvedTab === "findings") {
    onFirstTabOpen("findings", () => {
      hydrateWorkspaceSlice();
      loadHashFlagsForFindings();
    });
  }
  if (resolvedTab === "logic") {
    onFirstTabOpen("logic", () => { if (accessToken) loadProtectedMetadata(); });
  }
  if (resolvedTab === "security") {
    onFirstTabOpen("security", () => {
      if (!accessToken) return;
      loadAudit().catch(() => {});
      loadUsers().catch(() => {});
    });
  }

  // One transition for a page change. The console used to run three at once
  // (this animate, a CSS dspmFade, and a 450ms stagger on every child); the
  // other two are deleted from styles.css. Duration and distance come from
  // the motion tokens, so reduced-motion collapses them in one place.
  const motion = getComputedStyle(document.documentElement);
  const duration = parseFloat(motion.getPropertyValue("--motion-base")) || 200;
  const rise = motion.getPropertyValue("--motion-rise").trim() || "6px";
  activePanel.animate(
    [
      { opacity: 0, transform: `translateY(${rise})` },
      { opacity: 1, transform: "translateY(0)" },
    ],
    { duration, easing: "cubic-bezier(.2,.7,.3,1)" }
  );

  if (requestedTab === "inventory") {
    document.querySelector("#inventory-workspace")?.scrollIntoView({ behavior: "smooth", block: "start" });
  } else {
    // A new page starts at its top - carrying the old scroll position over
    // meant landing mid-page after every switch.
    window.scrollTo({ top: 0, behavior: "auto" });
  }
}


function applyTheme(theme, { animate = false } = {}) {
  // A whole screen inverting in one frame reads as a glitch. The class is
  // added only for a deliberate toggle, never on first paint.
  if (animate) {
    document.body.classList.add("theme-animating");
    const slow = parseFloat(
      getComputedStyle(document.documentElement).getPropertyValue("--motion-slow")
    ) || 320;
    window.setTimeout(() => document.body.classList.remove("theme-animating"), slow + 60);
  }
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
  const context = captureTenantContext();
  const scanId = String(file.scan_id || "");
  const requestKey = `${context.tenantId}|${scanId}|${String(file.id)}`;
  if (!inventoryDetailRequests.has(requestKey)) {
    const scanQuery = scanId ? `?scan_id=${encodeURIComponent(scanId)}` : "";
    const request = api(`/api/inventory/${encodeURIComponent(file.id)}${scanQuery}`, null, "GET")
      .then((data) => {
        if (!isCurrentTenantContext(context, data)) return null;
        const asset = data.asset || {};
        const cachedItems = [...inventoryPageWindow.pages.values()].flatMap((page) => page.items || []);
        const targets = [...new Set([file, ...latestFiles, ...cachedItems])]
          .filter((item) => item && (
            item === file
            || (String(item.id || "") === String(file.id) && String(item.scan_id || "") === scanId)
            || (fileKey(item) === fileKey(file) && String(item.scan_id || "") === scanId)
          ));
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

function renderEssentialDisclosure({ id, icon, eyebrow, title, summary, rows = [], content = "", count = null, countLabel = "" }) {
  const visibleRows = rows.filter((row) => hasDisplayValue(row.value));
  if (!visibleRows.length && !content) return "";
  const numericCount = Number(count);
  const hasCount = count !== null && count !== "" && Number.isFinite(numericCount) && numericCount >= 0;
  return `
    <details class="essential-disclosure" data-essential-section="${escapeHtml(id)}">
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
          summary: "Ownership, origin, format, and lifecycle timestamps", rows: identityRows,
        })}
        ${renderEssentialDisclosure({
          id: "exposure", icon: "exposure", eyebrow: "Access control", title: "Exposure context",
          summary: accessPosture, rows: exposureRows,
          count: principalCount || grantCount || null, countLabel: principalCount ? `principal${principalCount === 1 ? "" : "s"}` : `grant${grantCount === 1 ? "" : "s"}`,
        })}
        ${renderEssentialDisclosure({
          id: "protection", icon: "protection", eyebrow: "Data handling", title: "Protection and integrity",
          summary: protectionSummary, rows: protectionRows,
        })}
        ${renderEssentialDisclosure({
          id: "document", icon: "document", eyebrow: "Extracted properties", title: "Document metadata",
          summary: "Non-sensitive format and document properties", rows: documentRows,
        })}
        ${renderEssentialDisclosure({
          id: "scan", icon: "scan", eyebrow: "Collection quality", title: "Scan coverage and provenance",
          summary: "Completeness, reuse decisions, detector health, and catalog versions", rows: scanRows,
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
  const context = captureTenantContext();
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
    if (!file || !isCurrentTenantContext(context) || modal.classList.contains("hidden")) return;
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
      ${riskBadge(effectiveRisk.level, effectiveRisk.score)}
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
    ["Matched field and context keywords", finding.matched_keywords || finding.keywords || []],
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
    personal_data: "Personal data",
    government_ids: "Government IDs",
    official_identifier: "Official identifier",
    credentials_secrets: "Credentials and secrets",
    financial_records: "Financial records",
    hr_documents: "HR and workforce records",
    biometric_data: "Biometric data",
    online_identifiers: "Online identifiers",
    legal_contracts: "Legal and contractual records",
    intellectual_property: "Intellectual property",
    financial: "Financial",
    credentials: "Credentials",
    health: "Health",
    hr: "HR",
  };
  // A report is a printed document: "hr documents" and "credentials secrets"
  // read as raw column values, not as the names of things. Sentence-case the
  // fallback so an unmapped category still prints like a label.
  const known = labels[category];
  if (known) return known;
  const words = String(category || "").replaceAll("_", " ").trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : "";
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

async function loadComplianceKeywordLibrary(framework = "gdpr", context = captureTenantContext()) {
  if (!accessToken) return;
  try {
    const library = await api(`/api/compliance-keywords?framework=${encodeURIComponent(framework)}`, null, "GET");
    if (!isCurrentTenantContext(context, library)) return;
    latestComplianceKeywordLibrary = library;
    latestComplianceKeywordLibraries[framework] = library;
    renderRiskRulesCache();
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    try {
      if (framework !== "gdpr") throw error;
      const response = await fetch("/static/compliance_keywords_gdpr_builtin.json", { cache: "no-store" });
      if (!response.ok) throw new Error(`Built-in GDPR keyword list unavailable (${response.status})`);
      const library = await response.json();
      if (!isCurrentTenantContext(context)) return;
      latestComplianceKeywordLibrary = library;
      latestComplianceKeywordLibraries[framework] = library;
      renderRiskRulesCache();
      setKeywordImportStatus("Import is unavailable until the service restarts. Showing the built-in GDPR keyword list.", "warning");
    } catch {
      setKeywordImportStatus(`Couldn't load the keyword library. ${error.message}`, "danger");
    }
  }
}

async function loadAllComplianceKeywordLibraries() {
  const context = captureTenantContext();
  for (const item of COMPLIANCE_LOGIC) {
    if (!isCurrentTenantContext(context)) return;
    await loadComplianceKeywordLibrary(item.id, context);
  }
}

async function reloadComplianceKeywordLibraryInPlace(framework = "gdpr") {
  const context = captureTenantContext();
  const scrollX = window.scrollX;
  const scrollY = window.scrollY;
  const library = await api(`/api/compliance-keywords?framework=${encodeURIComponent(framework)}`, null, "GET");
  if (!isCurrentTenantContext(context, library)) return;
  latestComplianceKeywordLibrary = library;
  latestComplianceKeywordLibraries[framework] = library;
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

// ---- Reports -------------------------------------------------------------
// A report is a sentence: prepare THIS report, for THIS scope, as THIS format.
// The rail asks it in that order, the preview answers it, and the build line
// above the button says exactly what will come out - so nobody exports and
// hopes.
//
// Four documents, because four different people ask for one: a board wants the
// posture, a security team wants the register, a data owner wants to know what
// is held and where, an auditor wants the framework mapping.
const REPORT_TYPES = [
  {
    id: "executive",
    label: "Executive summary",
    audience: "Board",
    blurb: "Posture, the risks that matter, what moved.",
    // What the posture is, what was looked at, how much was found, then the
    // findings themselves. The first section to state a measure keeps it, so
    // this order decides who owns "448 files" - and coverage should.
    sections: ["posture", "coverage", "scale", "top_risks", "detailed_findings", "estate", "funnel", "trend", "assurance"],
  },
  {
    id: "register",
    label: "Risk register",
    audience: "Security team",
    blurb: "Every finding, its status and its fix.",
    sections: ["severity_split", "funnel", "lifecycle", "sla", "register", "detailed_findings", "remediation", "owners", "appendix"],
  },
  {
    id: "inventory",
    label: "Data inventory",
    audience: "Data owners",
    blurb: "What data the estate holds, and where.",
    sections: ["estate", "classes_by_file", "data_classes", "places", "locations", "assets", "provenance", "detailed_findings", "appendix"],
  },
  {
    id: "compliance",
    label: "Compliance pack",
    audience: "Auditor",
    blurb: "Framework coverage and mapped evidence.",
    sections: ["frameworks", "framework_findings", "pci_scope", "detailed_findings", "remediation", "provenance", "assurance", "appendix"],
  },
];

// `pages` is what this section adds to the page count: a number for a fixed
// summary, or a function of the rows it will print.
const REPORT_SECTIONS = {
  posture: { label: "Posture summary", hint: "Score, files and severity split", pages: () => 1 },
  top_risks: { label: "Top risks", hint: "The highest-scoring findings", pages: () => 1 },
  coverage: { label: "Assessment coverage", hint: "Classified, clear and unreadable", pages: () => 1 },
  trend: { label: "Change since last scan", hint: "What moved since the last scan", pages: () => 1 },
  severity_split: { label: "Severity breakdown", hint: "Counts and share per severity", pages: () => 1 },
  register: { label: "Finding register", hint: "Status, reason and fix per finding", pages: (rows) => Math.max(1, Math.ceil(rows / 24)) },
  remediation: { label: "Remediation guidance", hint: "Actions, by how often they apply", pages: () => 1 },
  owners: { label: "Owners", hint: "Who holds the affected assets", pages: () => 1 },
  data_classes: { label: "Data classes", hint: "Every class found, with counts", pages: () => 2 },
  locations: { label: "Locations", hint: "Folders holding sensitive data", pages: () => 1 },
  assets: { label: "Affected assets", hint: "One row per affected file", pages: (rows) => Math.max(1, Math.ceil(rows / 34)) },
  frameworks: { label: "Framework coverage", hint: "GDPR, PCI DSS and NIST coverage", pages: () => 1 },
  framework_findings: { label: "Mapped findings", hint: "Findings by the framework they touch", pages: (rows) => Math.max(1, Math.ceil(rows / 28)) },
  pci_scope: { label: "PCI scope", hint: "Cardholder data and scope candidates", pages: () => 1 },
  appendix: { label: "Evidence appendix", hint: "Full register with paths and evidence", pages: (rows) => Math.max(1, Math.ceil(rows / 40)), off: true },

  // Added once the page went wide enough to offer them. Every one is backed by
  // a field the scan already returns; nothing here needs new backend work, and
  // nothing degenerate got in - `exposure` is one repeated value on an SMB
  // estate and `confidence` is 0 for every non-PCI finding, so neither is here.
  detailed_findings: { label: "Findings in full", hint: "Each one written out with its reason and fix", pages: (rows, count) => Math.max(1, Math.ceil((count || 10) / 3)) },
  scale: { label: "Scale of exposure", hint: "Findings, values and files in one line", pages: () => 1 },
  funnel: { label: "Remediation funnel", hint: "Open through resolved, with exceptions", pages: () => 1 },
  lifecycle: { label: "Status detail", hint: "Every lifecycle status, not the five groups", pages: () => 1 },
  sla: { label: "SLA position", hint: "Overdue, due soon, and the earliest dates", pages: () => 1 },
  estate: { label: "Estate profile", hint: "Every file by risk, not only the flagged", pages: () => 1 },
  places: { label: "Where the risk lives", hint: "Shares and folders, severity-weighted", pages: () => 1 },
  classes_by_file: { label: "Data classes by file", hint: "Unique files per class, with severity", pages: () => 2 },
  provenance: { label: "Scan provenance", hint: "What was scanned, by what, and when", pages: () => 1 },
  assurance: { label: "Scan assurance", hint: "Coverage, access denials and truncation", pages: () => 1, off: true },
};

// `has` answers "can this scan build the section at all". A section without one
// is always buildable.
const REPORT_SECTION_AVAILABILITY = {
  trend: () => (buildReportComparisonRows() || []).length > 0,
  pci_scope: () => Boolean(latestReport?.pci_scope_summary?.enabled),
  assurance: () => Object.keys(latestReport?.scan_diagnostics || {}).length > 0,
  frameworks: () => Boolean(reportRows.facets?.frameworks?.length),
  places: () => Boolean(estateFacets?.locations?.length),
  estate: () => Boolean(estateFacets?.risk_counts),
  classes_by_file: () => Boolean(estateFacets?.finding_types?.length),
  provenance: () => Boolean(estateFacets?.scans?.length || latestReport?.source),
};

function reportSectionIsAvailable(id) {
  const test = REPORT_SECTION_AVAILABILITY[id];
  if (!test) return true;
  try {
    return Boolean(test());
  } catch (_) {
    return false;
  }
}

const REPORT_FORMATS = [
  { id: "pdf", label: "PDF", note: "Filed on the server as evidence, on the standard template. Scope applies; sections are fixed." },
  { id: "word", label: "Word", note: "An editable document of the sections ticked above." },
  { id: "excel", label: "Excel", note: "Every section as a table, ready to filter and pivot." },
];

let reportState = { type: "executive", format: "word", sections: null };

// A report is evidence, so it covers the estate the server holds - not the 200
// rows the Findings workspace happens to have loaded. Every row comes from
// /api/findings, which filters, sorts and counts server-side; `total` is the
// real number of findings in scope even when only a page of them is in memory.
const REPORT_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
const REPORT_PREVIEW_ROWS = 200;
const REPORT_PAGE_SIZE = 200;
// A filed document is not a database dump. Past this, the report says so and
// prints the highest-scoring findings rather than growing without a bound.
const REPORT_ROW_CEILING = 5000;
let reportRows = { key: "", rows: [], total: 0, complete: false, summary: null, facets: null };
let reportRowsInFlight = null;

function reportType() {
  return REPORT_TYPES.find((item) => item.id === reportState.type) || REPORT_TYPES[0];
}

function reportDefaultSections(type, depth = reportDepth()) {
  return new Set(type.sections.filter((id) => depth.optional || !REPORT_SECTIONS[id]?.off));
}

function reportSections() {
  if (!reportState.sections) reportState.sections = reportDefaultSections(reportType());
  return reportState.sections;
}

function reportSeverities() {
  const raw = reportSeveritySelect?.value || "ALL";
  return raw === "ALL" ? null : new Set(raw.split(","));
}

// Depth is the one control that changes the SHAPE of the document rather than
// its scope: how many rows a table prints, and whether the sections a reader
// only sometimes wants come on by default.
const REPORT_DEPTHS = {
  brief: { label: "Brief", tableRows: 10, previewRows: 6, optional: false },
  standard: { label: "Standard", tableRows: 60, previewRows: 12, optional: false },
  full: { label: "Full", tableRows: Number.POSITIVE_INFINITY, previewRows: 20, optional: true },
};

function reportDepth() {
  return REPORT_DEPTHS[reportDepthSelect?.value || "standard"] || REPORT_DEPTHS.standard;
}

function reportDetailCount() {
  return Math.min(20, Math.max(0, Number(reportDetailCountSelect?.value) || 0));
}

function reportScopeParams() {
  const params = new URLSearchParams();
  params.set("scope", reportCoverageSelect?.value || "current");
  params.set("status", reportStatusSelect?.value || "active");
  const severities = reportSeverities();
  if (severities) params.set("severity", [...severities].join(","));
  params.set("sort", reportOrderSelect?.value || "risk_score");
  params.set("direction", (reportOrderSelect?.value || "risk_score") === "finding_name" ? "asc" : "desc");
  return params;
}

function reportScopeKey() {
  return reportScopeParams().toString();
}

function fieldLabel(select, fallback) {
  return select?.selectedOptions?.[0]?.textContent?.trim() || fallback;
}

function reportScopeLabel() {
  return [
    fieldLabel(reportCoverageSelect, "This scan"),
    fieldLabel(reportSeveritySelect, "All severities"),
    fieldLabel(reportStatusSelect, "Every status"),
    `${reportDepth().label} detail`,
  ].join(" · ");
}

// The document's cover prints the full sentence; the carrier sits under the six
// controls that set it, so it only names the two that are easy to forget.
function reportCarrierScopeLabel() {
  const severities = reportSeverities();
  return [
    fieldLabel(reportCoverageSelect, "This scan"),
    severities ? [...severities].map(severityLabel).join(" and ") : "all severities",
  ].join(" · ");
}

function severityLabel(level) {
  const value = String(level || "").toUpperCase();
  // A file with no signal is not a severity. It is inventory, and "None 0"
  // reads as a broken cell rather than as a clean file.
  if (value === "NONE" || !value) return "Clear";
  return value.charAt(0) + value.slice(1).toLowerCase();
}

// The badge every risk cell draws. One place decides how a level is spelled, so
// the inventory row, the detail drawer and the asset modal cannot disagree.
function riskBadge(level, score) {
  const value = String(level || "NONE").toUpperCase();
  const text = value === "NONE" ? "Clear" : `${escapeHtml(value)} ${escapeHtml(score)}`;
  return `<span class="badge ${escapeHtml(value)}">${text}</span>`;
}

// ---- The rows every section is drawn from --------------------------------
// One page for the preview, every page for the file. The cache is keyed on the
// scope, so changing a control invalidates it and nothing stale is printed.
async function loadReportRows({ complete = false } = {}) {
  const key = reportScopeKey();
  if (reportRows.key === key && (reportRows.complete || !complete) && reportRows.rows.length) return reportRows;
  if (reportRowsInFlight) await reportRowsInFlight.catch(() => {});
  if (reportRows.key === key && (reportRows.complete || !complete) && reportRows.rows.length) return reportRows;
  reportRowsInFlight = loadReportRowsNow(key, complete).finally(() => { reportRowsInFlight = null; });
  return reportRowsInFlight;
}

async function loadReportRowsNow(key, complete) {
  const ceiling = complete ? REPORT_ROW_CEILING : REPORT_PREVIEW_ROWS;
  const rows = [];
  let cursor = "";
  let total = 0;
  let summary = null;
  let facets = null;
  do {
    const params = new URLSearchParams(key);
    params.set("limit", String(Math.min(REPORT_PAGE_SIZE, ceiling - rows.length)));
    if (cursor) params.set("after", cursor);
    const page = await api(`/api/findings?${params.toString()}`, null, "GET");
    if (reportScopeKey() !== key) return reportRows;
    rows.push(...(page.items || []));
    total = Number(page.total || rows.length);
    summary = page.summary || summary;
    facets = page.facets || facets;
    cursor = page.has_more ? String(page.next_cursor || "") : "";
  } while (cursor && rows.length < ceiling);
  reportRows = {
    key, rows, total, summary, facets,
    complete: complete && (rows.length >= total || rows.length >= REPORT_ROW_CEILING),
  };
  return reportRows;
}

// The server counts the whole scan; a page of rows counts only itself. So an
// aggregate uses the server's own tally when nothing narrows the scope, and
// falls back to the carried rows - saying so - when something does.
function reportScopeIsWhole() {
  return !reportSeverities() && reportStatusIsWhole();
}

function reportFacetCounts(name) {
  if (!reportScopeIsWhole()) return null;
  const facet = reportRows.facets?.[name];
  if (!facet?.length) return null;
  return facet
    .map((item) => [String(item.value || ""), Number(item.count || 0)])
    .filter(([value]) => value)
    .sort((a, b) => b[1] - a[1]);
}

// Printed under an aggregate the report could only build from what it carries.
function reportSampleNote() {
  return reportRows.total > reportRows.rows.length
    ? `<p class="report-note">Counted across the ${reportRows.rows.length.toLocaleString()} highest-scoring of ${reportRows.total.toLocaleString()} findings in scope.</p>`
    : "";
}

function reportRegisterRows() {
  return reportRows.rows.map((item) => {
    const file = item.file || {};
    return {
      severity: String(item.severity || "LOW").toUpperCase(),
      score: Number(item.risk_score || 0),
      finding: String(item.display_name || item.type || "Sensitive content"),
      dataClass: String(item.data_type || item.finding_category || "Unclassified"),
      frameworks: item.frameworks || [],
      asset: String(item.affected_asset || file.source || ""),
      path: String(file.path || file.name || ""),
      name: String(file.name || ""),
      owner: String(item.owner || ""),
      status: remediationStatusLabel(item.status),
      due: String(item.sla_due || ""),
      lastSeen: String(item.last_seen || ""),
      occurrences: Number(item.occurrence_count || 0),
      confidence: Number(item.confidence || 0),
      exposure: String(item.exposure || ""),
      reason: String(item.reason || ""),
      recommendation: String(item.recommendation || ""),
    };
  });
}

// ---- Generating ----------------------------------------------------------
function reportFileStem() {
  const type = reportType().id;
  const stamp = new Date().toISOString().slice(0, 10);
  return `sentro_${type}_${stamp}`;
}

function reportDocumentTitle() {
  return `${reportType().label} — ${reportScopeLabel()}`;
}

// A filed document says what it covers. When the scope is larger than one
// document should carry, it says that too, rather than looking complete.
function reportCoverageLine(blocks) {
  const total = reportRows.total;
  const printed = reportPrintedRows(blocks);
  const counted = `${total.toLocaleString()} findings in scope`;
  const depth = reportDepth();
  if (Number.isFinite(depth.tableRows)) {
    return `${counted} · ${depth.label.toLowerCase()} detail prints ${printed.toLocaleString()} rows, longest table ${depth.tableRows}`;
  }
  return reportRows.rows.length < total
    ? `${counted} · this document carries the ${reportRows.rows.length.toLocaleString()} highest-scoring of them`
    : counted;
}

// Excel, LibreOffice and Numbers all EXECUTE a cell that begins with =, +, -
// or @. Every cell below is built from scanned content - file names, owners,
// share names - so a file called `=HYPERLINK("http://x","x").txt` on the share
// being scanned becomes a live formula in the customer's report. The backend
// CSV export has guarded this since Track S; these three builders did not.
//
// A leading apostrophe is the portable "treat this as text" marker. Numbers are
// exempt: the report prints counts and percentages, and quoting those would
// turn a spreadsheet of figures into a spreadsheet of strings.
// The four characters a spreadsheet treats as the start of a formula, plus
// the two whitespace characters Excel strips before deciding.
const FORMULA_LEAD = /^[=+\-@\t\r]/;
const NUMERIC_CELL = /^[-+]?\d[\d,. ]*%?$/;

// The artifact bytes, as a URL a window can be pointed at.
//
// C8: the download token is spent on first use and bound to this session, and it
// travels only in a header - never in a URL, because a URL is written to every
// proxy and access log on the way. So there is exactly one fetch, and if it fails
// the operator is told why rather than sent to a link that cannot work.
async function artifactBlobUrl(artifact) {
  const path = artifact.artifact_path;
  const token = artifact.download_token;
  if (!path || !token) {
    throw new Error("The report was filed, but the service did not return a way to open it.");
  }
  const response = await fetch(`${path}?inline=1`, { headers: { "X-Artifact-Token": token } });
  if (!response.ok) {
    throw new Error(response.status === 401
      ? "The report link has already been used or has expired. File the report again to open it."
      : `The report could not be opened (${response.status}).`);
  }
  return URL.createObjectURL(await response.blob());
}

function reportCell(value) {
  const text = String(value ?? "");
  if (!text || !FORMULA_LEAD.test(text)) return escapeHtml(text);
  // A figure is not a formula. The report prints counts, percentages and
  // deltas like "-12", and quoting those turns a sheet of numbers into a
  // sheet of strings.
  if (NUMERIC_CELL.test(text)) return escapeHtml(text);
  return escapeHtml("'" + text);
}

function buildReportDocumentHtml() {
  const blocks = reportSectionBlocks();
  const body = blocks.map((block, index) => `
    <h2>${index + 1}. ${escapeHtml(block.label)}</h2>
    ${block.detail ? reportDetailWordHtml(block.detail) : block.table ? `<table border="1" cellspacing="0" cellpadding="6">
      <thead><tr>${block.table.headers.map((head) => `<th align="left">${escapeHtml(head)}</th>`).join("")}</tr></thead>
      <tbody>${block.table.rows.map((row) => `<tr>${row.map((cell) => `<td>${reportCell(cell)}</td>`).join("")}</tr>`).join("")}</tbody>
    </table>${reportDroppedNote(block.table)}${block.note || ""}` : (block.html || "")}`).join("");
  return `<!doctype html><html><head><meta charset="utf-8"><title>${escapeHtml(reportDocumentTitle())}</title>
    <style>
      body { font-family: Calibri, Arial, sans-serif; font-size: 11pt; color: #111827; }
      h1 { font-size: 20pt; margin: 0 0 4pt; }
      h2 { font-size: 13pt; margin: 18pt 0 6pt; border-bottom: 1px solid #d1d5db; padding-bottom: 3pt; }
      p.scope { color: #4b5563; margin: 0 0 18pt; }
      table { border-collapse: collapse; width: 100%; font-size: 10pt; }
      th { background: #eef2ff; }
    </style></head><body>
    <h1>${escapeHtml(reportType().label)}</h1>
    <p class="scope">${escapeHtml(reportScopeLabel())} &middot; tenant ${escapeHtml(currentTenant)} &middot; ${escapeHtml(new Date().toLocaleString())}<br/>${escapeHtml(reportCoverageLine(blocks))}</p>
    ${body}
  </body></html>`;
}

function buildReportWorkbookHtml() {
  const blocks = reportSectionBlocks();
  const tables = blocks.map((block) => {
    // A spreadsheet holds long text happily, so the detail blocks travel as a
    // wide sheet rather than as prose.
    if (block.detail) return reportDetailWorkbookHtml(block);
    if (!block.table) return "";
    return `<table border="1" cellspacing="0" cellpadding="4">
      <tr><td colspan="${block.table.headers.length}"><b>${escapeHtml(block.label)}</b></td></tr>
      <tr>${block.table.headers.map((head) => `<th>${escapeHtml(head)}</th>`).join("")}</tr>
      ${block.table.rows.map((row) => `<tr>${row.map((cell) => `<td>${reportCell(cell)}</td>`).join("")}</tr>`).join("")}
      ${reportDroppedText(block.table) ? `<tr><td colspan="${block.table.headers.length}">${escapeHtml(reportDroppedText(block.table))}</td></tr>` : ""}
    </table><br/>`;
  }).join("");
  return `<!doctype html><html><head><meta charset="utf-8"></head><body>
    <table><tr><td><b>${escapeHtml(reportDocumentTitle())}</b></td></tr>
    <tr><td>tenant ${escapeHtml(currentTenant)} &middot; ${escapeHtml(new Date().toLocaleString())}</td></tr>
    <tr><td>${escapeHtml(reportCoverageLine(blocks))}</td></tr></table><br/>
    ${tables}</body></html>`;
}

function reportDetailWordHtml(entries) {
  return entries.map((entry, index) => `
    <h3>${index + 1}. ${escapeHtml(entry.finding)} &mdash; ${escapeHtml(severityLabel(entry.severity))}</h3>
    <p><i>${escapeHtml(entry.path || entry.name)}</i></p>
    <p>${reportDetailFacts(entry).map(([term, value]) =>
      `<b>${escapeHtml(term)}:</b> ${escapeHtml(value)}`).join(" &nbsp;&middot;&nbsp; ")}</p>
    ${entry.reason ? `<p><b>Why it is a risk.</b> ${escapeHtml(entry.reason)}</p>` : ""}
    ${entry.recommendation ? `<p><b>Recommended action.</b> ${escapeHtml(entry.recommendation)}</p>` : ""}`).join("");
}

function reportDetailWorkbookHtml(block) {
  const headers = ["#", "Finding", "Severity", "Status", "File", "Data class", "Owner", "Why it is a risk", "Recommended action"];
  return `<table border="1" cellspacing="0" cellpadding="4">
    <tr><td colspan="${headers.length}"><b>${escapeHtml(block.label)}</b></td></tr>
    <tr>${headers.map((head) => `<th>${escapeHtml(head)}</th>`).join("")}</tr>
    ${block.detail.map((entry, index) => `<tr>${[
      String(index + 1), entry.finding, severityLabel(entry.severity), entry.status,
      entry.path || entry.name, keywordCategoryLabel(entry.dataClass), entry.owner,
      entry.reason, entry.recommendation,
    ].map((cell) => `<td>${reportCell(cell)}</td>`).join("")}</tr>`).join("")}
  </table><br/>`;
}

async function generateReport(event) {
  event?.preventDefault?.();
  if (!activeReportFileCount()) {
    showToast("Nothing to report on", "Run a scan first.", "warning");
    return;
  }
  const button = document.querySelector("#report-generate");
  const format = reportState.format;
  if (format !== "pdf" && !reportSections().size) {
    showToast("No sections selected", "Tick at least one section to build a report.", "warning");
    return;
  }
  if (button) button.disabled = true;
  const label = document.querySelector("#report-generate-label");
  const buttonLabel = label?.textContent;
  try {
    if (format !== "pdf") {
      // The preview holds one page of findings. The file holds every one in
      // scope, so it is fetched now rather than exported short.
      if (label) label.textContent = "Collecting findings…";
      await loadReportRows({ complete: true });
    }
    if (format === "word") {
      downloadFile(`${reportFileStem()}.doc`, buildReportDocumentHtml(), "application/msword;charset=utf-8");
      showToast("Report generated", `${reportType().label} saved as Word.`, "success");
    } else if (format === "excel") {
      downloadFile(`${reportFileStem()}.xls`, buildReportWorkbookHtml(), "application/vnd.ms-excel;charset=utf-8");
      showToast("Report generated", `${reportType().label} saved as Excel.`, "success");
    } else {
      await exportPdf();
    }
  } catch (error) {
    showToast("Report failed", error.message || "The report could not be generated.", "danger");
  } finally {
    if (button) {
      button.disabled = false;
      if (label && buttonLabel) label.textContent = buttonLabel;
    }
  }
}

reportTypeList?.addEventListener("click", (event) => {
  const choice = event.target.closest("[data-report-type]");
  if (!choice) return;
  reportState.type = choice.dataset.reportType;
  // Each report has its own sections, so switching document starts from that
  // document's defaults rather than carrying the last one's ticks across.
  reportState.sections = reportDefaultSections(reportType());
  renderReportPreview();
});

// Fifteen hint lines cost 300px of rail and are read once. One line that
// answers for whichever row you are on costs 32px and is read every time it
// changes - and it doubles as the thing that teaches the list.
function reportSectionExplain(id) {
  if (!reportSectionExplainer) return;
  const section = id && REPORT_SECTIONS[id];
  if (!section) {
    reportSectionExplainer.textContent = reportSectionDefaultHint();
    return;
  }
  reportSectionExplainer.textContent = reportSectionIsAvailable(id)
    ? section.hint
    : `${section.label} is not part of this scan.`;
}

function reportSectionDefaultHint() {
  const listed = reportType().sections;
  const chosen = [...reportSections()].filter((id) => listed.includes(id)).length;
  return `${chosen} of ${listed.length} sections. Point at one to see what it holds.`;
}

// Pointing at a row lights the section it makes. The mapping between the list
// and the document is what a first-time reader has to learn, so the page shows
// it rather than describing it.
function reportLinkSection(id) {
  reportPreview?.querySelectorAll(".report-section-block.is-linked")
    .forEach((block) => block.classList.remove("is-linked"));
  if (!id) return;
  document.querySelector(`#report-section-${id}`)?.classList.add("is-linked");
}

function reportRowFrom(event) {
  return event.target.closest?.("[data-report-row]") || null;
}

reportSectionList?.addEventListener("pointerover", (event) => {
  const row = reportRowFrom(event);
  if (!row) return;
  reportSectionExplain(row.dataset.reportRow);
  reportLinkSection(row.dataset.reportRow);
});

reportSectionList?.addEventListener("focusin", (event) => {
  const row = reportRowFrom(event);
  if (!row) return;
  reportSectionExplain(row.dataset.reportRow);
  reportLinkSection(row.dataset.reportRow);
});

reportSectionList?.addEventListener("pointerleave", () => {
  reportSectionExplain(null);
  reportLinkSection(null);
});

// Ticking a box and then watching that section appear where the list said it
// would is the half of the connection you can use.
reportSectionList?.addEventListener("click", (event) => {
  const jump = event.target.closest("[data-report-jump]");
  if (!jump) return;
  document.querySelector(`#report-section-${jump.dataset.reportJump}`)
    ?.scrollIntoView({ block: "start", behavior: "smooth" });
});

reportSectionList?.addEventListener("change", (event) => {
  const box = event.target.closest("[data-report-section]");
  if (!box) return;
  const chosen = reportSections();
  if (box.checked) chosen.add(box.dataset.reportSection);
  else chosen.delete(box.dataset.reportSection);
  renderReportPreview();
});

reportFormatList?.addEventListener("click", (event) => {
  const choice = event.target.closest("[data-report-format]");
  if (!choice) return;
  reportState.format = choice.dataset.reportFormat;
  renderReportPreview();
});

// Changing scope invalidates the rows, so the preview refetches rather than
// re-rendering a document built from the previous answer.
[reportCoverageSelect, reportSeveritySelect, reportStatusSelect, reportOrderSelect].forEach((select) => {
  select?.addEventListener("change", () => renderReportPreview());
});

// Depth changes which sections a document offers, so it restarts from that
// document's defaults at the new depth rather than keeping a tick that the
// previous depth put there.
reportDepthSelect?.addEventListener("change", () => {
  reportState.sections = reportDefaultSections(reportType());
  renderReportPreview();
});

reportDetailCountSelect?.addEventListener("change", () => renderReportPreview());
reportComposer?.addEventListener("submit", generateReport);

function renderReportComposer() {
  if (!reportTypeList) return;
  const type = reportType();
  reportTypeList.innerHTML = REPORT_TYPES.map((item) => `
    <button type="button" class="report-type plain-btn" role="radio" data-report-type="${item.id}"
            aria-checked="${item.id === type.id ? "true" : "false"}">
      <span class="report-type-mark" aria-hidden="true"></span>
      <span class="report-type-head">
        <span class="report-type-name">${escapeHtml(item.label)}</span>
        <span class="report-type-audience">${escapeHtml(item.audience)}</span>
      </span>
      <span class="report-type-blurb"><span>${escapeHtml(item.blurb)}</span></span>
    </button>`).join("");

  const chosen = reportSections();
  reportSectionList.innerHTML = type.sections.map((id) => {
    const section = REPORT_SECTIONS[id];
    if (!section) return "";
    const available = reportSectionIsAvailable(id);
    return `
      <label class="report-section-row" data-report-row="${id}" ${available ? "" : 'data-unavailable="true"'}
             title="${escapeHtml(available ? section.hint : "Not part of this scan.")}">
        <input type="checkbox" data-report-section="${id}" ${chosen.has(id) && available ? "checked" : ""}
               ${available ? "" : "disabled"} />
        <span class="report-section-name">${escapeHtml(section.label)}</span>
        ${chosen.has(id) && available ? `<button type="button" class="report-section-jump plain-btn" data-report-jump="${id}"
                aria-label="Go to ${escapeHtml(section.label)} in the document">&rarr;</button>` : "<span></span>"}
      </label>`;
  }).join("");

  reportFormatList.innerHTML = REPORT_FORMATS.map((item) => `
    <button type="button" class="report-format-option plain-btn" role="radio" data-report-format="${item.id}"
            aria-checked="${item.id === reportState.format ? "true" : "false"}">${escapeHtml(item.label)}</button>`).join("");
  const format = REPORT_FORMATS.find((item) => item.id === reportState.format) || REPORT_FORMATS[0];
  reportFormatNote.textContent = format.note;
  // The filed PDF is one fixed template on purpose - an auditor wants the same
  // shape every time - so the section list says so rather than being ignored.
  const fixed = reportState.format === "pdf";
  reportSectionList.classList.toggle("is-inert", fixed);
  // Two reasons a tick is refused: the filed PDF ignores the list, or this
  // scan cannot build that section. Clearing the flag for the first reason
  // used to re-enable the second.
  reportSectionList.querySelectorAll("input").forEach((input) => {
    input.disabled = fixed || !reportSectionIsAvailable(input.dataset.reportSection);
  });
  document.querySelector("#composer-options")?.classList.toggle("is-template", fixed);
  [reportDepthSelect, reportDetailCountSelect, reportOrderSelect].forEach((select) => {
    if (select) select.disabled = fixed;
  });

  renderReportBuildLine();
  renderComposerSummaries();
  reportSectionExplain(null);
}

// A drawer that is shut still answers its own question. Six selects and nine
// checkboxes shown at once gave the rail no first move - every group looked
// equally like the place to start - so the two that are usually left alone are
// one line each until somebody wants them.
function renderComposerSummaries() {
  if (reportScopeSummary) reportScopeSummary.textContent = reportCarrierScopeLabel();
  if (reportSectionsSummary) {
    const listed = reportType().sections;
    const chosen = [...reportSections()].filter((id) => listed.includes(id)).length;
    reportSectionsSummary.textContent = reportState.format === "pdf"
      ? "fixed by the PDF template"
      : `${chosen} of ${listed.length}`;
  }
}

function toggleComposerDrawer(toggle, body) {
  if (!toggle || !body) return;
  const open = toggle.getAttribute("aria-expanded") === "true";
  toggle.setAttribute("aria-expanded", open ? "false" : "true");
  body.hidden = open;
}

document.querySelector("#report-scope-toggle")?.addEventListener("click", (event) => {
  toggleComposerDrawer(event.currentTarget, document.querySelector("#report-scope-fields"));
});

document.querySelector("#report-sections-toggle")?.addEventListener("click", (event) => {
  toggleComposerDrawer(event.currentTarget, document.querySelector("#report-sections-body"));
});

// The joint between the instrument and the page it makes. It carries the same
// sentence the document's own cover prints, so the connection is made of
// content rather than of pixels - change any control and the strip and the
// cover move in the same frame. Once the band is docked and the document's
// cover has scrolled away, this is the only thing still saying which report
// and which scope you are reading.
// The jump target has to land below the band, and the band has two heights.


function reportPrintedRows(blocks = reportSectionBlocks()) {
  return blocks.reduce((total, block) =>
    total + (block.table ? block.table.rows.length : block.detail ? block.detail.length : 0), 0);
}

function reportBuildStats() {
  const blocks = reportSectionBlocks();
  const rows = reportPrintedRows(blocks);
  const pages = blocks.reduce((total, block) =>
    total + (REPORT_SECTIONS[block.id]?.pages(block.table ? block.table.rows.length : 0) || 1), 1);
  return {
    pages,
    rows,
    sections: blocks.length,
    findings: reportRows.total,
    files: Number(reportRows.summary?.affected_files || estateFacets?.sensitive || 0),
  };
}

function renderReportBuildLine() {
  if (!reportBuildLine) return;
  if (!activeReportFileCount()) {
    reportBuildLine.textContent = "Run a scan to build a report.";
    return;
  }
  if (!reportRows.rows.length && reportRows.key !== reportScopeKey()) {
    reportBuildLine.textContent = "Counting the findings in scope…";
    return;
  }
  const stats = reportBuildStats();
  const format = (REPORT_FORMATS.find((item) => item.id === reportState.format) || REPORT_FORMATS[0]).label;
  const parts = reportState.format === "pdf"
    ? [`${stats.files.toLocaleString()} files`, `${stats.findings.toLocaleString()} findings`]
    : [`~${stats.pages} pages`, `${stats.sections} sections`, `${stats.rows.toLocaleString()} rows`];
  reportBuildLine.textContent = `${parts.join(" · ")} · ${format}`;
}

// ---- The document --------------------------------------------------------
// One builder, three destinations. What the preview shows is what Word and
// Excel contain, which is the only way the build line above the button can be
// trusted.
// The Executive summary printed the same three figures between two and four
// times each: 6,831 as "Findings in scope", "Findings" and "Open"; 448 as
// "Files with findings", "Files carrying them" and "Classified". Sections
// overlap because each looks at the estate from its own angle, so the first
// section to state a measure keeps it and the rest go quiet - which is also
// why the section order below is the order a reader should meet them in.
function dropRepeatedFacts(blocks) {
  const stated = new Set();
  return blocks.map((block) => {
    if (!block.table?.keys) return block;
    const keep = block.table.keys.map((key) => {
      if (!key) return true;
      if (stated.has(key)) return false;
      stated.add(key);
      return true;
    });
    return {
      ...block,
      table: {
        ...block.table,
        rows: block.table.rows.filter((_, index) => keep[index]),
        keys: block.table.keys.filter((_, index) => keep[index]),
      },
    };
  }).filter((block) => block.html || block.detail?.length || block.table?.rows.length);
}

function reportSectionBlocks() {
  const model = buildReportModel();
  const rows = reportRegisterRows();
  const cap = reportDepth().tableRows;
  const blocks = [...reportSections()]
    .filter((id) => reportType().sections.includes(id) && reportSectionIsAvailable(id))
    .sort((a, b) => reportType().sections.indexOf(a) - reportType().sections.indexOf(b))
    .map((id) => ({ id, label: REPORT_SECTIONS[id].label, ...reportSectionContent(id, model, rows) }))
    .map((block) => (block.table && Number.isFinite(cap) && block.table.rows.length > cap
      ? { ...block, table: { ...block.table, rows: block.table.rows.slice(0, cap) }, capped: true }
      : block))
    .filter((block) => block.html || block.table || block.detail?.length);
  return dropRepeatedFacts(blocks);
}

// "none" and "unknown" are ANSWERS in a security report - "Owner: unknown"
// is a finding, not a gap - so a column of them is a column that said
// something. Only a genuine blank counts.
const REPORT_EMPTY_CELLS = new Set(["", "-", "—", "–", "n/a"]);

function reportCellIsEmpty(cell) {
  return REPORT_EMPTY_CELLS.has(String(cell ?? "").trim().toLowerCase());
}

// A column every row left blank is noise in a printed document: it costs width
// the columns that DID answer needed, and it reads as missing data rather than
// as a question this scan could not answer. Drop it, keeping at least one.
// A fact may name what it MEASURES, not just what it is called. "Files
// analysed" and "Files in the estate" are two names for one number; "Expiration
// Date" and "PCI Account Data" are two data classes that happen to share a
// count. Only a key can tell those apart, so de-duplication reads the key and
// never the value.
function reportFacts(rows, keys) {
  return { ...reportTable(["Measure", "Value"], rows), keys };
}

function reportTable(headers, bodyRows) {
  const keep = headers.map((_, index) =>
    !bodyRows.length || bodyRows.some((row) => !reportCellIsEmpty(row[index])));
  // The first column is the row's identity - Finding, File, Framework,
  // Measure - and a table that lost it cannot be read at all.
  keep[0] = true;
  if (keep.every(Boolean)) return { headers, rows: bodyRows };
  return {
    headers: headers.filter((_, index) => keep[index]),
    rows: bodyRows.map((row) => row.filter((_, index) => keep[index])),
    dropped: headers.filter((_, index) => !keep[index]),
  };
}

function reportTally(rows, pick) {
  const counts = new Map();
  rows.forEach((row) => {
    const key = pick(row);
    if (!key) return;
    counts.set(key, (counts.get(key) || 0) + 1);
  });
  return [...counts.entries()].sort((a, b) => b[1] - a[1]);
}

// Severities come from the facet the same query produced, so they always
// describe the scope the report is actually built from.
function reportStatusIsWhole() {
  return (reportStatusSelect?.value || "all") === "all";
}

function reportSeverityCountsAreWhole() {
  return reportStatusIsWhole() && Boolean(reportRows.facets?.severities?.length);
}

function reportSeverityCounts() {
  const wanted = reportSeverities();
  if (reportSeverityCountsAreWhole()) {
    // Narrowing to Critical does not change how many Critical findings there
    // are, so the scan-wide facet still answers exactly. A narrowed status
    // does change it, which is why that case falls through.
    const counts = {};
    reportRows.facets.severities.forEach((item) => {
      const level = String(item.value || "").toUpperCase();
      if (wanted && !wanted.has(level)) return;
      counts[level] = Number(item.count || 0);
    });
    return counts;
  }
  const counts = {};
  reportRows.rows.forEach((item) => {
    const level = String(item.severity || "").toUpperCase();
    counts[level] = (counts[level] || 0) + 1;
  });
  return counts;
}

function reportWorstSeverity(rows) {
  return rows.reduce((worst, row) => worstSeverity(worst, row.severity), "LOW");
}

function reportFolder(path) {
  const parts = String(path || "").split(/[\\/]+/).filter(Boolean);
  return parts.length > 1 ? parts.slice(0, -1).join("/") : "(root)";
}

function reportSectionContent(id, model, rows) {
  const summary = reportRows.summary || {};
  const estateTotal = Number(estateFacets?.total || model.summary?.total_files || 0);
  switch (id) {
    case "posture": {
      // The headline only. It used to print the file counts, the finding total
      // and the estate size as well, which is every other section's subject.
      const bySeverity = reportSeverityCounts();
      return {
        table: reportFacts([
          ["Posture score", `${model.score} / 100`],
          ...REPORT_SEVERITY_ORDER.map((level) => [severityLabel(level), Number(bySeverity[level] || 0).toLocaleString()]),
          ["Past its SLA", Number(summary.overdue || 0).toLocaleString()],
        ], ["posture.score", ...REPORT_SEVERITY_ORDER.map((level) => `findings.${level.toLowerCase()}`), "findings.overdue"]),
        note: reportSeverityCountsAreWhole() ? "" : reportSampleNote(),
      };
    }
    case "severity_split": {
      const bySeverity = reportSeverityCounts();
      const total = REPORT_SEVERITY_ORDER.reduce((sum, level) => sum + Number(bySeverity[level] || 0), 0) || 1;
      return { table: reportTable(["Severity", "Findings", "Share"], REPORT_SEVERITY_ORDER
        .filter((level) => bySeverity[level])
        .map((level) => [severityLabel(level), Number(bySeverity[level]).toLocaleString(),
          `${Math.round((Number(bySeverity[level]) / total) * 100)}%`])),
        note: reportSeverityCountsAreWhole() ? "" : reportSampleNote() };
    }
    case "top_risks":
      return { table: reportTable(["Finding", "File", "Severity", "Why it is a risk"], rows.slice(0, 12)
        .map((row) => [row.finding, row.name || row.path, severityLabel(row.severity), row.reason || "—"])) };
    case "coverage": {
      const classified = Number(estateFacets?.sensitive || summary.affected_files || 0);
      const locked = Number(estateFacets?.protected || 0);
      return { table: reportFacts([
        ["Classified", classified.toLocaleString()],
        ["Clear", Math.max(0, estateTotal - classified - locked).toLocaleString()],
        ["Unreadable", locked.toLocaleString()],
      ], ["files.sensitive", "files.clear", "files.locked"]) };
    }
    case "trend": {
      const comparison = model.comparison || [];
      if (!comparison.length) return { html: '<p class="report-note">No earlier scan covers comparable ground, so there is nothing to compare against.</p>' };
      return { table: reportTable(["Measure", "Previous", "Now", "Change"], comparison
        .map((item) => [item.label, String(item.previous ?? "—"), String(item.current ?? "—"), String(item.delta ?? "—")])) };
    }
    case "register":
      return { table: reportTable(["Severity", "Finding", "File", "Status", "Why it is a risk", "Recommended action"], rows
        .map((row) => [severityLabel(row.severity), row.finding, row.name || row.path, row.status || "—",
          row.reason || "—", row.recommendation || "—"])) };
    case "remediation": {
      const tally = reportTally(rows, (row) => row.recommendation);
      if (!tally.length) return { html: '<p class="report-note">No recommended actions were produced for this scope.</p>' };
      return {
        table: reportTable(["Recommended action", "Findings"], tally
          .map(([action, count]) => [action, count.toLocaleString()])),
        note: reportSampleNote(),
      };
    }
    case "owners": {
      const tally = reportFacetCounts("owners") || reportTally(rows, (row) => row.owner || "Unassigned");
      return {
        table: reportTable(["Owner", "Findings"], tally.slice(0, 25)
          .map(([owner, count]) => [owner || "Unassigned", count.toLocaleString()])),
        note: reportFacetCounts("owners") ? "" : reportSampleNote(),
      };
    }
    case "data_classes": {
      const counted = reportFacetCounts("data_types");
      const tally = counted || reportTally(rows, (row) => row.dataClass);
      if (!tally.length) return { html: '<p class="report-note">No data classes were found in this scope.</p>' };
      return {
        table: reportTable(["Data class", "Findings"], tally
          .map(([name, count]) => [keywordCategoryLabel(name), count.toLocaleString()])),
        note: counted ? "" : reportSampleNote(),
      };
    }
    case "locations": {
      const tally = reportTally(rows, (row) => reportFolder(row.path));
      if (!tally.length) return { html: '<p class="report-note">No folder grouping is available for this scope.</p>' };
      return {
        table: reportTable(["Location", "Findings", "Highest severity"], tally.slice(0, 25)
          .map(([place, count]) => [place, count.toLocaleString(),
            severityLabel(reportWorstSeverity(rows.filter((row) => reportFolder(row.path) === place)))])),
        note: reportSampleNote(),
      };
    }
    case "assets": {
      const byFile = new Map();
      rows.forEach((row) => {
        const key = row.path || row.name;
        const held = byFile.get(key);
        if (!held) {
          byFile.set(key, { name: row.name || key, place: reportFolder(row.path), severity: row.severity, count: 1 });
          return;
        }
        held.count += 1;
        held.severity = worstSeverity(held.severity, row.severity);
      });
      return {
        table: reportTable(["File", "Location", "Severity", "Findings"], [...byFile.values()]
          .map((file) => [file.name, file.place, severityLabel(file.severity), String(file.count)])),
        note: reportSampleNote(),
      };
    }
    case "frameworks": {
      const counted = reportFacetCounts("frameworks");
      const tally = counted || reportTally(rows, (row) => (row.frameworks[0] || "standard_scan"));
      if (!tally.length) return { html: '<p class="report-note">Compliance mapping was not enabled for this scan.</p>' };
      return {
        table: reportTable(["Framework", "Findings"], tally
          .map(([key, count]) => [frameworkLabel(key), count.toLocaleString()])),
        note: counted ? "" : reportSampleNote(),
      };
    }
    case "framework_findings":
      return { table: reportTable(["Framework", "Finding", "File", "Severity", "Status"], rows
        .flatMap((row) => (row.frameworks.length ? row.frameworks : ["standard_scan"])
          .map((framework) => [frameworkLabel(framework), row.finding, row.name || row.path,
            severityLabel(row.severity), row.status || "—"]))) };
    case "pci_scope": {
      const scope = latestReport?.pci_scope_summary || {};
      if (!scope.enabled) return { html: '<p class="report-note">PCI DSS was not part of this scan.</p>' };
      const categories = scope.category_finding_group_counts || scope.category_counts || {};
      return { table: reportTable(["Measure", "Count"], [
        ["Cardholder data (CHD)", String(categories.CHD || 0)],
        ["Sensitive authentication data (SAD)", String(categories.SAD || 0)],
        ["Scope candidates", String(scope.cde_candidate_count || 0)],
      ]) };
    }
    case "detailed_findings": {
      const count = reportDetailCount();
      if (!count) return { html: '<p class="report-note">Set &ldquo;Findings written out in full&rdquo; above to include this section.</p>' };
      return { detail: rows.slice(0, count) };
    }
    case "scale": {
      const findings = Number(summary.total_findings || reportRows.total || 0);
      const values = Number(summary.total_occurrences || 0);
      const files = Number(summary.affected_files || 0);
      return { table: reportFacts([
        ["Findings", findings.toLocaleString()],
        ["Matched values behind them", values.toLocaleString()],
        ["Files carrying them", files.toLocaleString()],
        ["Values per affected file", files ? (values / files).toFixed(1) : "—"],
      ], ["findings.total", "values.total", "files.sensitive", "values.perFile"]) };
    }
    case "funnel": {
      const stages = [
        ["Open", summary.open], ["In progress", summary.in_progress],
        ["Awaiting validation", summary.pending_validation], ["Resolved", summary.resolved],
        ["Risk accepted", summary.risk_accepted], ["Suppressed", summary.suppressed],
        ["False positive", summary.false_positive],
      ].filter(([, value]) => Number(value || 0) > 0);
      // One stage is not a funnel: it restates the total under another name,
      // which is how "Open" came to print 6,831 for the third time.
      if (stages.length < 2) return {};
      return { table: reportFacts(stages
        .map(([label, value]) => [label, Number(value || 0).toLocaleString()]),
        stages.map(([label]) => `status.${label.toLowerCase().replace(/ /g, "_")}`)) };
    }
    case "lifecycle": {
      const byStatus = Object.entries(summary.findings_by_status || {});
      if (!byStatus.length) return { html: '<p class="report-note">No statuses were recorded for this scope.</p>' };
      return { table: reportTable(["Status", "Findings"], byStatus
        .sort((a, b) => Number(b[1] || 0) - Number(a[1] || 0))
        .map(([status, count]) => [remediationStatusLabel(status), Number(count || 0).toLocaleString()])) };
    }
    case "sla": {
      const overdue = Number(summary.overdue || 0);
      const dated = rows.filter((row) => row.due).sort((a, b) => a.due.localeCompare(b.due));
      if (!overdue && !dated.length) return { html: '<p class="report-note">No SLA dates are set on the findings in this scope.</p>' };
      return {
        table: reportTable(["Finding", "File", "Severity", "Due"], dated.slice(0, 25)
          .map((row) => [row.finding, row.name || row.path, severityLabel(row.severity), formatReportDate(row.due)])),
        note: `<p class="report-note">${overdue.toLocaleString()} of ${Number(summary.total_findings || reportRows.total || 0).toLocaleString()} findings in this scope are past their SLA.</p>`,
      };
    }
    case "estate": {
      const counts = estateFacets?.risk_counts || {};
      // Named for what they count. Bare "Critical" already appears in the
      // posture summary against a finding count, and the same word twice over
      // two different numbers reads as a contradiction rather than as two
      // measures.
      const rowsOut = REPORT_SEVERITY_ORDER
        .filter((level) => Number(counts[level] || 0))
        .map((level) => [`${severityLabel(level)} files`, Number(counts[level]).toLocaleString()]);
      if (!rowsOut.length) return { html: '<p class="report-note">The estate summary is not available for this scan.</p>' };
      const average = Number(estateFacets?.avg_risk_score || 0);
      // These severities count FILES; the posture summary's count findings, so
      // they are different measures and both are stated.
      return { table: reportFacts([
        ["Files in the estate", estateTotal.toLocaleString()],
        ...rowsOut,
        ["Unreadable", Number(estateFacets?.protected || 0).toLocaleString()],
        ["Average risk score", average ? average.toFixed(1) : ""],
      ], ["files.total", ...REPORT_SEVERITY_ORDER.filter((level) => Number(counts[level] || 0)).map((level) => `files.${level.toLowerCase()}`), "files.locked", "risk.average"]) };
    }
    case "places": {
      const places = estateFacets?.locations || [];
      if (!places.length) return { html: '<p class="report-note">No location breakdown is available for this scan.</p>' };
      return { table: reportTable(["Location", "Files", "Critical", "High"], places
        .slice(0, 25)
        .map((place) => [
          `${"\u00a0\u00a0".repeat(Number(place.depth || 0))}${place.label || place.value}`,
          Number(place.file_count ?? place.count ?? 0).toLocaleString(),
          Number(place.severity_file_counts?.CRITICAL || 0).toLocaleString(),
          Number(place.severity_file_counts?.HIGH || 0).toLocaleString(),
        ])) };
    }
    case "classes_by_file": {
      const classes = (estateFacets?.finding_types || []).filter((item) => isDataClass(item.value));
      if (!classes.length) return { html: '<p class="report-note">No data classes were found in this scan.</p>' };
      return { table: reportTable(["Data class", "Files", "Critical", "High"], classes
        .slice(0, 40)
        .map((item) => [
          keywordCategoryLabel(item.value),
          Number(item.file_count ?? item.count ?? 0).toLocaleString(),
          Number(item.severity_file_counts?.CRITICAL || 0).toLocaleString(),
          Number(item.severity_file_counts?.HIGH || 0).toLocaleString(),
        ])) };
    }
    case "provenance": {
      const scans = (estateFacets?.scans || []).map((item) => String(item.value)).filter(Boolean);
      const sources = (estateFacets?.sources || []).map((item) => String(item.value)).filter(Boolean);
      // The file count is keyed, so where a report also carries Estate profile
      // this row goes quiet rather than printing "Files in the estate" twice.
      return { table: reportFacts([
        ["Scan", scans.join(", ")],
        ["Collector", sources.join(", ")],
        ["Server", String(latestReport?.source || readPayload().server || "")],
        ["Run at", latestReport?.timestamp ? formatReportDate(latestReport.timestamp) : ""],
        ["Files in the estate", estateTotal.toLocaleString()],
      ], ["scan.label", "scan.collector", "scan.server", "scan.at", "files.total"]) };
    }
    case "assurance": {
      const diagnostics = latestReport?.scan_diagnostics || {};
      const shares = Number(diagnostics.shares_scanned || 0);
      const facts = [
        ["Files discovered", diagnostics.files_discovered],
        ["Shares scanned", shares],
        ["Shares access denied", diagnostics.shares_access_denied],
        ["Shares skipped", diagnostics.shares_skipped],
        ["Directories that could not be listed", (diagnostics.list_errors || []).length || 0],
        ["Result truncated", diagnostics.scan_truncated ? "Yes" : ""],
      ].filter(([, value]) => value !== undefined && value !== null && Number(value) !== 0 || typeof value === "string" && value);
      if (!facts.length) return { html: '<p class="report-note">This scan recorded no coverage exceptions.</p>' };
      return { table: reportTable(["Measure", "Value"], facts
        .map(([label, value]) => [label, typeof value === "number" ? value.toLocaleString() : String(value)])) };
    }
    case "appendix":
      return { table: reportTable(["Finding", "Path", "Severity", "Data class", "Owner", "Status", "Recommended action"], rows
        .map((row) => [row.finding, row.path, severityLabel(row.severity), row.dataClass,
          row.owner || "—", row.status || "—", row.recommendation || "—"])) };
    default:
      return {};
  }
}

// A reason runs to 162 characters and an action to 101. In a six-column table
// on a 760px page that is four wrapped lines of 90px column, which is why the
// two fields the brief cares most about were the two nobody could read. These
// findings get a block each instead, with the sentences at full width.
function reportDetailMarkup(entries) {
  if (!entries.length) return '<p class="report-note">No finding in this scope carries a written reason yet.</p>';
  return `<ol class="report-detail-list">${entries.map((entry) => `
    <li class="report-detail" data-severity="${escapeHtml(entry.severity)}">
      <div class="report-detail-head">
        <span class="report-detail-name">${escapeHtml(entry.finding)}</span>
        <span class="report-sev" data-severity="${escapeHtml(entry.severity)}">${escapeHtml(severityLabel(entry.severity))}</span>
      </div>
      <p class="report-detail-path">${escapeHtml(entry.path || entry.name)}</p>
      <dl class="report-detail-facts">
        ${reportDetailFacts(entry).map(([term, value]) => `
          <div><dt>${escapeHtml(term)}</dt><dd>${escapeHtml(value)}</dd></div>`).join("")}
      </dl>
      ${entry.reason ? `<div class="report-detail-prose">
        <p class="report-detail-term">Why it is a risk</p>
        <p>${escapeHtml(entry.reason)}</p></div>` : ""}
      ${entry.recommendation ? `<div class="report-detail-prose">
        <p class="report-detail-term">Recommended action</p>
        <p>${escapeHtml(entry.recommendation)}</p></div>` : ""}
    </li>`).join("")}</ol>`;
}

// Only the facts this finding actually carries - the same rule the tables now
// follow, applied one row at a time.
function reportDetailFacts(entry) {
  return [
    ["Status", entry.status],
    ["Data class", keywordCategoryLabel(entry.dataClass)],
    ["Framework", (entry.frameworks || []).map(frameworkLabel).join(", ")],
    ["Owner", entry.owner],
    ["Score", entry.score ? String(entry.score) : ""],
    ["Occurrences", entry.occurrences > 1 ? String(entry.occurrences) : ""],
    ["Due", entry.due ? formatReportDate(entry.due) : ""],
  ].filter(([, value]) => !reportCellIsEmpty(value));
}

function formatReportDate(value) {
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? "" : parsed.toLocaleDateString();
}

function reportDroppedText(table) {
  if (!table?.dropped?.length) return "";
  const names = table.dropped.join(", ");
  const column = table.dropped.length === 1 ? "that column is" : "those columns are";
  return `No row in this scope carried ${names}, so ${column} not printed.`;
}

function reportDroppedNote(table) {
  const text = reportDroppedText(table);
  return text ? `<p class="report-note">${escapeHtml(text)}</p>` : "";
}

// `table-layout: fixed` divides the width equally, which gave an eight-
// character Severity column the same 259px as a 144-character sentence: the
// sentence wrapped to eight lines and the row stood 127px tall, while a
// quarter of every row was blank. A column is sized by what it holds instead.
// The kind is read off the header because every header string is written here.
const REPORT_COLUMN_KINDS = {
  sev: ["severity", "highest severity"],
  num: ["value", "count", "counts", "files", "findings", "occurrences", "share", "score", "pages", "applies to"],
  prose: ["why it is a risk", "recommended action", "reason"],
  when: ["due", "last seen", "run at", "change"],
  path: ["path", "location", "file", "asset", "owner"],
};

function reportColumnKind(header) {
  const name = String(header || "").trim().toLowerCase();
  const found = Object.entries(REPORT_COLUMN_KINDS).find(([, names]) => names.includes(name));
  return found ? found[0] : "name";
}

// A two-column table whose second column is a number is a list of facts, not a
// grid. As a table it ran the full width of the page to print "9 / 100" beside
// "Posture score" - the widest dead space in the document.
function reportTableIsFacts(table) {
  return table.headers.length === 2 && reportColumnKind(table.headers[1]) === "num";
}

function reportFactsMarkup(table, limit) {
  const shown = table.rows.slice(0, limit);
  if (!shown.length) return '<p class="report-note">Nothing to show for this scope.</p>';
  return `
    <dl class="report-facts">
      ${shown.map(([label, value]) => `
        <div><dt>${escapeHtml(String(label ?? ""))}</dt><dd>${escapeHtml(String(value ?? ""))}</dd></div>`).join("")}
    </dl>
    ${reportDroppedNote(table)}
    ${table.rows.length > shown.length ? `<p class="report-note">Preview shows ${shown.length} of ${table.rows.length.toLocaleString()} rows.</p>` : ""}`;
}

function reportTableMarkup(table, limit = reportDepth().previewRows) {
  const shown = table.rows.slice(0, limit);
  if (!shown.length) return '<p class="report-note">Nothing to show for this scope.</p>';
  const kinds = table.headers.map(reportColumnKind);
  return `
    <table class="report-table">
      <colgroup>${kinds.map((kind) => `<col class="col-${kind}" />`).join("")}</colgroup>
      <thead><tr>${table.headers.map((head, index) => `<th class="col-${kinds[index]}">${escapeHtml(head)}</th>`).join("")}</tr></thead>
      <tbody>${shown.map((row) => `<tr>${row.map((cell, index) => `<td class="col-${kinds[index]}">${escapeHtml(String(cell ?? ""))}</td>`).join("")}</tr>`).join("")}</tbody>
    </table>
    ${reportDroppedNote(table)}
    ${table.rows.length > shown.length ? `<p class="report-note">Preview shows ${shown.length} of ${table.rows.length.toLocaleString()} rows.</p>` : ""}`;
}

function reportBlockMarkup(block) {
  if (block.detail) return reportDetailMarkup(block.detail) + (block.note || "");
  if (!block.table) return block.html || "";
  const limit = reportDepth().previewRows;
  const markup = reportTableIsFacts(block.table)
    ? reportFactsMarkup(block.table, Math.max(limit, 12))
    : reportTableMarkup(block.table, limit);
  return markup + (block.note || "");
}

async function renderReportPreview() {
  if (deferWhileHidden("tab-reports", "preview", renderReportPreview)) return;
  if (!reportPreview) return;
  renderReportComposer();
  if (!activeReportFileCount()) {
    reportPreview.innerHTML = `
      <div class="report-empty">
        <h4>No scan to report on yet</h4>
        <p>Run a scan from the Scan page. Every report here is built from the findings that scan produced.</p>
      </div>`;
    return;
  }
  // Changing the scope means asking the server again, which takes long enough
  // to see. Without this the document that is about to be wrong sits there
  // looking current, and is then replaced between two frames - which reads as
  // a glitch rather than as an answer. It steps back while the count is being
  // taken, and the new one arrives.
  reportPreview.classList.add("is-loading");
  try {
    await loadReportRows();
  } catch (_) {
    reportPreview.classList.remove("is-loading");
    reportPreview.innerHTML = `
      <div class="report-empty">
        <h4>The findings could not be read</h4>
        <p>Reload the page, or narrow the scope, and the preview will rebuild.</p>
      </div>`;
    return;
  }
  reportPreview.classList.remove("is-loading");
  renderReportBuildLine();
  const type = reportType();
  const blocks = reportSectionBlocks();
  reportPreview.innerHTML = `
    <article class="report-document">
      <header class="report-cover">
        <p class="eyebrow">Sentro DSPM</p>
        <h3>${escapeHtml(type.label)}</h3>
        <p class="report-cover-scope">${escapeHtml(reportScopeLabel())} · tenant ${escapeHtml(currentTenant)} · ${new Date().toLocaleDateString()}</p>
        <p class="report-cover-scope">${escapeHtml(reportCoverageLine(blocks))}</p>
      </header>
      ${blocks.length ? blocks.map((block, index) => `
        <section class="report-section-block" id="report-section-${escapeHtml(block.id)}">
          <h4><span class="report-section-index">${index + 1}</span>${escapeHtml(block.label)}</h4>
          ${reportBlockMarkup(block)}
        </section>`).join("") : '<p class="report-note">Tick at least one section to build a report.</p>'}
    </article>`;
}


function buildReportModel() {
  const summary = buildCurrentSummary();
  const priorityFiles = [...latestFiles].sort((a, b) => getEffectiveRisk(b).score - getEffectiveRisk(a).score);
  return {
    title: readPayload().server || "Local sample scan",
    generatedAt: new Date().toLocaleString(),
    summary,
    score: getCurrentPostureScore(),
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
  if (deferWhileHidden("tab-overview", "dashboard", renderExecutiveExperience)) return;
  // Top risks are per-file, and a restored report carries no files.
  if (latestReport?.files_omitted && !latestFiles.length) hydrateWorkspaceSlice({ force: true });
  const currentSummary = displaySummary(buildCurrentSummary());
  const dashboardSummary = latestDashboard?.latest?.summary || {};
  const summary = currentSummary.total_files ? currentSummary : dashboardSummary.total_files ? dashboardSummary : currentSummary;
  const score = getCurrentPostureScore();

  renderPostureCard(summary, score);
  renderDataClassesCard();
  renderCoverageCard();
  renderStaleCard();
  renderLocationsCard();
  // The lists were just rendered at last frame's capacity; if the window
  // has changed since, this re-renders the two that adapt.
  refitDashboardLists();
  renderFrameworksCard();
  renderRemediationLoad(summary);

  // The Remediation page keeps only the queue and the folders it points at.
  // Everything else this function used to fill - the hero, the workspace
  // status card, the distribution donut, the posture trend, the scan
  // comparison, the heatmap, the signal bubbles and the topology - restated
  // what the dashboard now says once, so the panels are gone and these writes
  // are guarded rather than removed: the elements come back if a page needs
  // them again, and nothing throws while they do not exist.
  renderRemediationWorkspace();
  setPanelHtml(topRiskyFolders, buildTopRiskyFolders());
  setPanelHtml(riskDistribution, () => `<div class="distribution-visual">${buildDonutSvg(buildRiskDistribution(summary))}${buildDistributionBars(buildRiskDistribution(summary))}</div>`);
  setPanelHtml(msspPortfolio, buildMsspPortfolio);
  setPanelHtml(priorityRiskFiles, buildPriorityRiskFiles);
  setPanelHtml(departmentRisk, buildDepartmentRisk);
  setPanelHtml(signalMatrix, buildSignalMatrix);
  setPanelHtml(riskHeatmap, () => buildHeatmap(latestFiles));
  setPanelHtml(riskTopology, () => buildRiskTopology(summary));
  setPanelHtml(executiveHero, "");
  setPanelHtml(executiveTopFiles, "");
  if (riskTotalLabel) riskTotalLabel.textContent = `${summary.total_files || 0} files`;
}

// A panel that is not on the page is not an error; it is a panel this release
// does not show. Builders are passed as functions so a removed panel costs
// nothing to skip.
function setPanelHtml(element, source) {
  if (!element) return;
  element.innerHTML = typeof source === "function" ? source() : source;
}

// ---- Dashboard cards ------------------------------------------------------
// Three panels, one row, and every row inside them is a way into the page that
// can act on it. The dashboard's job is to be read in one look and left
// immediately.
//
// Every row opens with a glyph in a tinted coin, so a list is recognisable
// before it is read: a risk's coin takes its severity, a data class's coin
// takes the worst level it has been found at, a framework's takes its own
// mark. That is the one place this page spends colour on the row itself.

const POSTURE_BANDS = [
  { floor: 80, key: "low", label: "Low risk", note: "Exposure is under control." },
  { floor: 55, key: "elevated", label: "Elevated risk", note: "Work the queue before the next scan." },
  { floor: 0, key: "critical", label: "Critical risk", note: "Start with the critical files." },
];

function postureBand(score) {
  return POSTURE_BANDS.find((band) => score >= band.floor) || POSTURE_BANDS.at(-1);
}

function posturePoints() {
  return (latestDashboard?.trend || [])
    .slice(-12)
    .map((item) => ({
      label: String(item.timestamp || "").slice(5, 10),
      score: Number(item.posture_score ?? 0),
      files: Number((item.summary || {}).total_files || 0),
    }));
}

// A posture score is the mean risk of whatever that scan covered. Two scans
// only compare if they covered comparable ground: a 539-file estate sweep
// against a 2-file spot check reads as "+68, improving" when nothing improved
// at all - the second scan simply looked somewhere smaller and cleaner. Below
// this ratio the honest answer is to say nothing rather than a number that is
// wrong in the flattering direction.
const POSTURE_COMPARABLE_RATIO = 0.6;

function comparablePosturePoints(points) {
  if (points.length < 2) return null;
  const latest = points.at(-1);
  if (!latest.files) return null;
  // The most recent earlier scan that covered comparable ground.
  for (let index = points.length - 2; index >= 0; index -= 1) {
    const earlier = points[index];
    if (!earlier.files) continue;
    const ratio = Math.min(earlier.files, latest.files) / Math.max(earlier.files, latest.files);
    if (ratio >= POSTURE_COMPARABLE_RATIO) return { earlier, latest, span: points.length - index };
  }
  return null;
}

function glyph(id, extraClass = "") {
  return `<svg class="f-ico${extraClass ? ` ${extraClass}` : ""}" aria-hidden="true"><use href="#${id}"/></svg>`;
}

function coin(id, cat) {
  return `<span class="coin" data-cat="${escapeHtml(cat)}" aria-hidden="true">${glyph(id)}</span>`;
}

// A sparkline, not a chart: the shape of the last dozen scans, no axes, no
// legend, no gridlines. The question it answers is "better or worse than last
// time", and that is the whole of it.
// A wave, not a chart. Straight segments between eight points make a posture
// history look like a saw; a Catmull-Rom spline converted to cubic beziers
// gives the same data one continuous curve, which is what "the shape of the
// last few scans" actually means. Tension 0.5 is the standard centripetal
// value - lower overshoots, higher flattens back toward the polyline.
function smoothPath(points, tension = 0.5) {
  if (points.length < 2) return "";
  const at = (index) => points[Math.max(0, Math.min(points.length - 1, index))];
  let path = `M${points[0].x.toFixed(2)},${points[0].y.toFixed(2)}`;
  for (let index = 0; index < points.length - 1; index += 1) {
    const previous = at(index - 1);
    const current = at(index);
    const next = at(index + 1);
    const after = at(index + 2);
    const c1x = current.x + ((next.x - previous.x) / 6) * tension * 2;
    const c1y = current.y + ((next.y - previous.y) / 6) * tension * 2;
    const c2x = next.x - ((after.x - current.x) / 6) * tension * 2;
    const c2y = next.y - ((after.y - current.y) / 6) * tension * 2;
    path += ` C${c1x.toFixed(2)},${c1y.toFixed(2)} ${c2x.toFixed(2)},${c2y.toFixed(2)} ${next.x.toFixed(2)},${next.y.toFixed(2)}`;
  }
  return path;
}

function buildPostureSparkline(points) {
  if (points.length < 2) return "";
  const width = 260;
  const height = 96;
  // Asymmetric: a Catmull-Rom curve overshoots its control points, so the
  // crest needs more clearance than the trough. Six was not enough and the
  // top of the wave was clipped.
  const padTop = 14;
  const padBottom = 8;
  const scores = points.map((point) => point.score);
  const low = Math.min(...scores);
  // A flat history should read as flat, not as noise amplified to fill the
  // box, so the band never shrinks below ten points of score.
  const span = Math.max(10, Math.max(...scores) - low);
  const mid = (low + Math.max(...scores)) / 2;
  const plotted = points.map((point, index) => ({
    x: 6 + (index / (points.length - 1)) * (width - 12),
    y: padTop + (1 - (point.score - (mid - span / 2)) / span) * (height - padTop - padBottom),
  }));
  const line = smoothPath(plotted);
  const area = `${line} L${plotted.at(-1).x.toFixed(2)},${height} L${plotted[0].x.toFixed(2)},${height} Z`;
  const now = plotted.at(-1);
  return `
    <svg class="posture-wave" viewBox="0 0 ${width} ${height}" preserveAspectRatio="none"
         role="img" aria-label="Posture score across the last ${points.length} saved scans">
      <defs>
        <linearGradient id="posture-wave-fill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--indigo)" stop-opacity=".28" />
          <stop offset="100%" stop-color="var(--indigo)" stop-opacity="0" />
        </linearGradient>
      </defs>
      <path class="posture-wave-area" d="${area}" fill="url(#posture-wave-fill)" />
      <path class="posture-wave-line" d="${line}" />
      <circle class="posture-wave-now" cx="${now.x.toFixed(2)}" cy="${now.y.toFixed(2)}" r="3" />
    </svg>`;
}

// ---- Top risks: categories, not folders ----------------------------------
// Folders are where Remediation sends you; the dashboard says what KIND of
// exposure the workspace has. Each category is a predicate over a file and
// its primary findings, carries its own glyph, and is worth its own row only
// if at least one file is in it.
// `go` is where the row takes you and with which filter. Five of these are
// finding-level questions the remediation queue can answer exactly, using the
// `category` column the classifiers already write. Two - a changed hash and an
// unreadable file - are properties of a FILE, not of a finding, so they go to
// the inventory instead of asking the queue a question it cannot answer.
// Each category also says how the WHOLE estate answers it. The browser was
// testing `latestFiles` - the 200-row window the workspace holds, sorted by
// risk score - so "Locked or unreadable" read zero on an estate that has
// locked files, "Health records" could never appear, and the four rows that
// did show were capped at whatever the window happened to contain. Three of
// the seven rows were missing and the card had a hand's width of dead space
// under them.
//
// `estate` returns the inventory query that counts the category exactly, or a
// number when the facets already hold it. Each is a bounded COUNT the API
// answers in 14-26 ms, they are issued together once per estate, and the
// result is cached until the estate changes. `test` stays as the fallback for
// the pre-scan and offline paths.
const RISK_CATEGORIES = [
  { key: "credentials", label: "Exposed credentials", icon: "li-key-round", sev: "critical", cat: "secret",
    go: { to: "queue", filters: { category: "credentials_secrets" } },
    estate: (classes) => classQuery(classes, isSecretFinding),
    test: (file, findings) => findings.some(isSecretFinding) },
  { key: "unprotected", label: "Unprotected critical files", icon: "li-shield-off", sev: "critical", cat: "record",
    go: { to: "queue", filters: { severity: "CRITICAL" } },
    estate: () => ({ risk: "CRITICAL", protected: "false" }),
    test: (file, findings, level) => level === "CRITICAL" && !isProtectedFile(file) },
  { key: "payment", label: "Payment and bank data", icon: "li-credit-card", sev: "high", cat: "finance",
    go: { to: "queue", filters: { category: "pci_cardholder_data" } },
    estate: (classes) => classQuery(classes, isPaymentFinding),
    test: (file, findings) => findings.some(isPaymentFinding) },
  { key: "health", label: "Health records", icon: "li-heart-pulse", sev: "high", cat: "health",
    // No stored category groups health on its own, so this one searches - and
    // the search box shows the term, rather than the filter looking exact.
    go: { to: "queue", filters: { q: "health" } },
    estate: (classes) => classQuery(classes, isHealthFinding),
    test: (file, findings) => findings.some(isHealthFinding) },
  { key: "regulated", label: "Regulated personal data", icon: "li-id-card", sev: "high", cat: "identity",
    go: { to: "queue", filters: { category: "pii,government_ids,biometric_data" } },
    // The regulated test is about frameworks, and the inventory indexes those.
    estate: () => ({ framework: "gdpr,pci_dss,hipaa,nist_sp800_60_enterprise" }),
    test: (file, findings) => findings.some(isRegulatedFinding) },
  { key: "changed", label: "Changed since last scan", icon: "li-file-diff", sev: "medium", cat: "record",
    go: { to: "inventory", search: "Hash changed" },
    test: (file) => hasHashChanged(file) },
  { key: "locked", label: "Locked or unreadable", icon: "li-lock", sev: "protected", cat: "legal",
    go: { to: "inventory", risk: "PROTECTED" },
    // Already counted in the facets the dashboard has, so it costs nothing.
    estate: () => Number(estateFacets?.protected || 0),
    test: (file) => isProtectedFile(file) },
];

// "Changed since last scan" has no estate query on purpose: it needs the hash
// comparison between two saved runs, which is loaded when Findings opens.

function isPaymentFinding(finding = {}) {
  return /credit card|payment card|\bpan\b|cvv|track data|iban|swift|routing|bank account|card data|cardholder/i
    .test(findingDisplayName(finding)) || String(finding.pci_category || "").length > 0;
}

function isHealthFinding(finding = {}) {
  return /health|medical|\bphi\b|diagnos|patient|mental|disabilit|genetic|biometric/i
    .test(findingDisplayName(finding));
}

// A category that is a set of data classes asks for all of them at once, which
// is exactly what a multi-value finding_type filter is for.
function classQuery(classes, predicate) {
  const wanted = classes.filter((name) => predicate({ type: name }));
  return wanted.length ? { finding_type: wanted.join(",") } : 0;
}

let riskCategoryCounts = null;
let riskCategoryCountsKey = "";
let riskCategoryCountsInFlight = null;

function estateSignature(facets = estateFacets) {
  return facets ? `${facets.tenant_id || ""}:${facets.total || 0}:${(facets.finding_types || []).length}` : "";
}

async function refreshRiskCategoryCounts() {
  if (!accessToken || !estateFacets) return null;
  const key = estateSignature();
  if (key && key === riskCategoryCountsKey) return riskCategoryCounts;
  if (riskCategoryCountsInFlight) return riskCategoryCountsInFlight;
  const classes = (estateFacets.finding_types || []).map((item) => String(item.value || "")).filter(Boolean);
  const context = captureTenantContext();
  riskCategoryCountsInFlight = (async () => {
    const counts = {};
    await Promise.all(RISK_CATEGORIES.map(async (item) => {
      const query = item.estate?.(classes);
      if (query === undefined || query === null) return;
      if (typeof query === "number") {
        counts[item.key] = query;
        return;
      }
      const params = new URLSearchParams({ ...query, limit: "1" });
      try {
        const page = await api(`/api/inventory?${params}`, null, "GET");
        counts[item.key] = Number(page?.total || 0);
      } catch { /* one category short is better than an empty card */ }
    }));
    if (!isCurrentTenantContext(context)) return null;
    riskCategoryCounts = counts;
    riskCategoryCountsKey = key;
    renderPostureCard(latestReport?.summary || buildCurrentSummary(), getCurrentPostureScore());
    return counts;
  })().finally(() => { riskCategoryCountsInFlight = null; });
  return riskCategoryCountsInFlight;
}

// A category's estate query is {finding_type}, {framework} or {risk} - the
// same three facets Findings offers - so it can be applied to the page
// directly. `protected` is the one key with no facet of its own; it is carried
// beside them so "critical AND not locked" stays the question the card counted.
function applyRiskCategoryToFindings(category) {
  if (!category?.estate) return false;
  const classes = (estateFacets?.finding_types || []).map((item) => String(item.value || "")).filter(Boolean);
  let query = category.estate(classes);
  if (typeof query === "number") query = category.go?.risk ? { risk: category.go.risk } : null;
  if (!query || typeof query !== "object") return false;
  switchTab("findings");
  FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));
  if (filterInput) {
    filterInput.value = "";
    lastInventoryQuery = "";
  }
  if (query.risk) setFacetSelection("inventory-risk-filter", String(query.risk).split(","));
  if (query.finding_type) setFacetSelection("inventory-finding-filter", String(query.finding_type).split(","));
  if (query.framework) setFacetSelection("inventory-framework-select", String(query.framework).split(","));
  inventoryProtectedFacet = query.protected === undefined ? null : String(query.protected);
  applyFindingsFacets();
  return true;
}

function riskCategories(limit = 6) {
  const counts = new Map(RISK_CATEGORIES.map((item) => [item.key, 0]));
  // One pass over the window still answers "changed since last scan", and
  // covers every category before the estate counts land.
  latestFiles.forEach((file) => {
    const findings = primaryFindingsForFile(file);
    const level = String(getEffectiveRisk(file).level || "LOW").toUpperCase();
    RISK_CATEGORIES.forEach((item) => {
      let hit = false;
      try { hit = Boolean(item.test(file, findings, level)); } catch { hit = false; }
      if (hit) counts.set(item.key, counts.get(item.key) + 1);
    });
  });
  return RISK_CATEGORIES
    .map((item) => ({
      ...item,
      count: riskCategoryCounts?.[item.key] ?? counts.get(item.key),
    }))
    .filter((item) => item.count > 0)
    .sort((a, b) => SEVERITY_RANK.indexOf(b.sev.toUpperCase()) - SEVERITY_RANK.indexOf(a.sev.toUpperCase()) || b.count - a.count)
    .slice(0, limit);
}

function renderPostureCard(summary, score) {
  const card = document.querySelector("#posture-card");
  if (!card) return;
  // The server owns this number. Until it answers there IS no score, and a
  // placeholder is more honest than a zero that reads as a failing grade.
  const known = score !== null && score !== undefined;
  const band = postureBand(known ? score : 100);
  const points = posturePoints();
  const comparable = comparablePosturePoints(points);
  const delta = comparable ? comparable.latest.score - comparable.earlier.score : null;
  const risks = riskCategories(dashListCapacity("#posture-card", 36, { min: 3, max: 7, reserve: 196 }));

  setCardMeta("#posture-card-meta", summary.total_files
    ? `${Number(summary.total_files).toLocaleString()} files`
    : "No scan yet");

  card.innerHTML = `
    <div class="posture-hero" data-band="${band.key}">
      <div class="posture-figure">
        <strong class="posture-score">${known ? escapeHtml(score) : "&mdash;"}</strong>
        <span class="posture-scale">/100</span>
      </div>
      <div class="posture-read">
        <p class="posture-band">${band.label}</p>
        <p class="posture-delta" ${comparable
          ? `title="Against the scan saved ${escapeHtml(comparable.earlier.label)}, which covered ${comparable.earlier.files.toLocaleString()} files"`
          : `title="No earlier scan covered comparable ground, so there is nothing to compare this score against"`}>${
          comparable
            ? `${glyph(delta >= 0 ? "li-trending-up" : "li-trending-down")}<b class="${delta >= 0 ? "up" : "down"}">${delta >= 0 ? "+" : ""}${delta}</b> vs ${escapeHtml(comparable.earlier.label)}`
            : escapeHtml(band.note)
        }</p>
      </div>
    </div>
    <div class="posture-wave-wrap" data-band="${band.key}">
      ${points.length > 1
        ? buildPostureSparkline(points)
        : '<p class="posture-wave-empty">A second saved scan draws the trend.</p>'}
    </div>
    <div class="posture-risks">
      <p class="dash-sub">Top risks</p>
      ${risks.length
        ? risks.map((item) => `
            <button type="button" class="risk-row plain-btn" data-risk-jump-key="${escapeHtml(item.key)}"
                    aria-label="${escapeHtml(item.label)}, ${item.count} files — ${
                      item.go?.to === "inventory" ? "open in Findings" : "open in Remediation, filtered"}">
              ${coin(item.icon, item.cat)}
              <span class="risk-row-name">${escapeHtml(item.label)}</span>
              <span class="risk-row-count">${item.count.toLocaleString()}</span>
              ${glyph("li-chevron-right", "risk-row-go")}
            </button>`).join("")
        : '<p class="dash-empty">No exposed data in this workspace.</p>'}
    </div>`;
}

// A window resize changes how many rows fit, so the two adaptive cards are
// re-rendered - but only when the number actually changes, which keeps a drag
// on the window edge from re-rendering on every frame.
let dashFit = "";

function refitDashboardLists() {
  const board = document.querySelector(".dash-board");
  if (!board || !board.clientHeight) return;
  // Three reads, then three writes. Reading a height after writing markup
  // forces the layout the write invalidated, so interleaving them paid for
  // three layouts of the whole document instead of one.
  const next = [
    dashListCapacity("#data-classes-card", 36, { min: 4, max: 14 }),
    dashListCapacity("#locations-card", 29, { min: 6, max: 25 }),
    dashListCapacity("#posture-card", 36, { min: 3, max: 7, reserve: 196 }),
  ].join(":");
  if (next === dashFit) return;
  dashFit = next;
  renderDataClassesCard();
  renderLocationsCard();
  renderPostureCard(latestReport?.summary || buildCurrentSummary(), getCurrentPostureScore());
}

// Two triggers, because neither is sufficient alone. A window resize is the
// common case and always fires; a ResizeObserver additionally catches the
// board changing size without the window doing so - collapsing the sidebar,
// for instance. Both funnel into the same guarded function, so whichever
// arrives first does the work and the other returns immediately.
window.addEventListener("resize", debounce(() => refitDashboardLists(), 150));

if (typeof ResizeObserver === "function") {
  const board = document.querySelector(".dash-board");
  if (board) new ResizeObserver(() => refitDashboardLists()).observe(board);
}

function setCardMeta(selector, text) {
  const meta = document.querySelector(selector);
  if (meta) meta.textContent = text;
}

// ---- Data classes: a glyph and a KIND per row ----------------------------
// One table, two jobs: which glyph the row wears, and which of the eight
// categories tints it. Matched on the display name, most specific first -
// "Payment card data" has to be tested before the generic "card", and
// "Source code secret context" before the "secret" that would claim it.
//
// The category is what the colour encodes. Severity is a separate scale on a
// separate shape, because "what kind of data" and "how bad is it" are two
// questions and one ramp cannot answer both.
const DATA_CLASS_KINDS = [
  // money
  [/credit card|payment card|\bpan\b|\bcvv\b|track data|card data|\bcard number/i, "li-credit-card", "finance"],
  [/iban|swift|\bbic\b|routing|bank account|account number|\btax\b|taxpayer/i, "li-landmark", "finance"],
  [/salary|payroll|compensation|bonus|benefit|\bmoney\b|invoice|financial|finance/i, "li-banknote", "finance"],
  // keys - before identity, so "recovery secret" is a secret
  [/private key|\bsecret|\btoken\b|api key|password|credential|\bjwt\b|bearer|oauth|connection string|kubeconfig|\bdsn\b|kdbx|certificate|\bsaml\b|\bmfa\b|access key|service account/i, "li-key-round", "secret"],
  // code and infrastructure - before "context" is claimed by records
  [/source code|\brepo\b|build log|terraform|docker|jdbc|\bnpm\b|github|gitlab|code context/i, "li-search-code", "code"],
  // health
  [/health|medical|\bphi\b|diagnos|patient|mental|disabilit|genetic|\bdna\b|stethoscope/i, "li-heart-pulse", "health"],
  // people
  [/biometric|photograph|face image|signature|fingerprint/i, "li-fingerprint", "identity"],
  [/passport|national id|\bssn\b|\bfin\b|\bpin\b|employee id|driver|licen[cs]e|id serial|vehicle|\bvin\b/i, "li-id-card", "identity"],
  [/birth|maiden name/i, "li-calendar", "identity"],
  // reachable
  [/\bemail/i, "li-mail", "contact"],
  [/phone|imei|imsi|mac address|mobile/i, "li-phone", "contact"],
  [/address|geolocation|\bgps\b|location|\bgpe\b|\bloc\b|ip address|cookie|tracking|device identifier|browsing|clickstream/i, "li-map-pin", "contact"],
  // legal and special category
  [/legal|contract|court|criminal|immigration|citizenship|residency|union|political|religio|orientation|race|ethnic|special category|belief|next-of-kin|emergency contact/i, "li-scale", "legal"],
  // records
  [/hash|duplicate/i, "li-file-diff", "record"],
  [/protected|locked|unreadable/i, "li-lock", "record"],
  [/customer|board|security ops|retention|confidential|archive|\bcontext\b|\borg\b/i, "li-briefcase", "record"],
  // whatever names a person, last - it is the broadest pattern here
  [/\bname\b|alias|person|\bner\b|username|handle|profile/i, "li-user-round", "identity"],
];

function dataClassKind(name) {
  const hit = DATA_CLASS_KINDS.find(([pattern]) => pattern.test(name));
  return hit ? { glyph: hit[1], cat: hit[2] } : { glyph: "li-file-text", cat: "record" };
}

// ---- Lists that size themselves to the card ------------------------------
// The card's height comes from the grid, not from what is inside it, so the
// body's clientHeight is a fixed target to fill and reading it back after a
// render cannot feed a loop. `min` keeps a card honest on a very short window
// - it is better to clip one row than to render a list of two.
function dashListCapacity(bodySelector, rowHeight, { min, max, reserve = 0 }) {
  const body = document.querySelector(bodySelector);
  if (!body || !body.clientHeight) return min;
  const room = body.clientHeight - reserve;
  return Math.max(min, Math.min(max, Math.floor(room / rowHeight)));
}

// Three entries in the Finding type facet are coverage states, not data
// classes: they say whether a file was read and whether anything was found in
// it. They are filters worth having - the Assessment coverage card opens them
// - but a list headed "Top data classes" is not where they belong, and
// "Classified" would sit at the top of it by definition.
const COVERAGE_FACET_VALUES = new Set(["Classified", "Clear", "Protected / locked"]);

function isDataClass(value) {
  return !COVERAGE_FACET_VALUES.has(String(value || "").trim());
}

function renderDataClassesCard() {
  const card = document.querySelector("#data-classes-card");
  if (!card) return;
  const allStats = (estateFacets?.finding_types || []).filter((item) => isDataClass(item.value)).map((item) => {
    const severityCounts = item.severity_file_counts || {};
    return {
      type: String(item.value || "Unknown"),
      count: Number(item.file_count ?? item.count ?? 0),
      critical: Number(severityCounts.CRITICAL || 0),
      high: Number(severityCounts.HIGH || 0),
      medium: Number(severityCounts.MEDIUM || 0),
      low: Number(severityCounts.LOW || 0),
    };
  }).filter((item) => item.count > 0).sort((left, right) => right.count - left.count);
  // 36px is the row height declared in pages.css; the two have to agree, and
  // the contract test asserts they do.
  const shown = dashListCapacity("#data-classes-card", 36, { min: 4, max: 14 });
  const stats = allStats.slice(0, shown);
  stats.total = allStats.length;
  // The meta is the way in to the rest: the card shows what fits, and the
  // count of what it did not show is the thing worth clicking.
  const meta = document.querySelector("#classes-card-meta");
  if (meta) {
    if (!stats.length) {
      meta.textContent = "No scan yet";
    } else if (stats.total > stats.length) {
      meta.innerHTML = `<button type="button" class="card-more plain-btn" data-open-all-classes>`
        + `${stats.length} of ${stats.total} · <b>View all</b></button>`;
    } else {
      meta.textContent = `All ${stats.total}`;
    }
  }
  if (!stats.length) {
    card.innerHTML = '<p class="dash-empty">Data classes appear after the first scan.</p>';
    return;
  }
  const max = Math.max(...stats.map((item) => item.count), 1);
  // A dot on a rule rather than a fourth stacked bar. The question here is
  // "how much of this class is there", which is one number, and a lollipop
  // puts that number on a shared axis so five rows compare at a glance -
  // without repeating the shape the framework card uses for a different
  // question. The dot takes the row's category colour; severity stays on the
  // framework card where it belongs.
  card.innerHTML = `
    <div class="dash-rows dash-rows-plot">
      ${stats.map((item) => {
        const kind = dataClassKind(item.type);
        const share = Math.max(4, Math.round((item.count / max) * 100));
        return `
        <button type="button" class="class-row plain-btn" data-inventory-search="${escapeHtml(item.type)}"
                data-cat="${escapeHtml(kind.cat)}" style="--plot-share:${share}%"
                aria-label="${escapeHtml(item.type)}, ${item.count} files — open in Findings">
          ${coin(kind.glyph, kind.cat)}
          <span class="class-row-name">${escapeHtml(item.type)}</span>
          <span class="class-row-count">${item.count.toLocaleString()}</span>
          <span class="lolli" aria-hidden="true"><i class="lolli-stem"></i><i class="lolli-dot"></i></span>
        </button>`;
      }).join("")}
    </div>`;
}

// ---- Where the risk is: the estate ranked by where it sits --------------
// The severity band says how much, the class card says what kind, and neither
// says WHERE - which is the only one of the three that names something an
// operator can go and fix. Ordered by weighted severity on the server, so a
// share holding ten critical files outranks one holding a hundred low ones.
function renderLocationsCard() {
  const card = document.querySelector("#locations-card");
  if (!card) return;
  let rows = (estateFacets?.locations || [])
    .map((item) => {
      const severity = item.severity_file_counts || {};
      return {
        name: String(item.value || ""),
        label: String(item.label || item.value || ""),
        depth: Number(item.depth || 0),
        total: Number(item.file_count ?? item.count ?? 0),
        critical: Number(severity.CRITICAL || 0),
        high: Number(severity.HIGH || 0),
        medium: Number(severity.MEDIUM || 0),
        low: Number(severity.LOW || 0),
      };
    })
    .filter((entry) => entry.name && entry.total > 0);

  if (!rows.length) {
    // A backend that predates this facet sends no `locations` key at all.
    // Reporting that as "no scan yet" sent one operator looking for a scan
    // that had already run; the two states now read differently.
    const missing = estateFacets && !Array.isArray(estateFacets.locations);
    setCardMeta("#locations-card-meta", missing ? "Unavailable" : "No scan yet");
    card.innerHTML = missing
      ? '<p class="dash-empty">This service build does not report locations. Restart the Sentro service to pick them up.</p>'
      : '<p class="dash-empty">Locations appear after the first scan.</p>';
    return;
  }
  const shares = rows.filter((entry) => !entry.depth);
  const pressing = rows.filter((entry) => entry.critical || entry.high).length;
  // Counted over the whole estate, then trimmed to what the card can hold:
  // the meta describes the tenant, not the visible slice.
  setCardMeta("#locations-card-meta", `${shares.length} shares · ${pressing} need attention`);
  const max = Math.max(...rows.map((entry) => entry.total), 1);
  rows = rows.slice(0, dashListCapacity("#locations-card", 29, { min: 6, max: 25 }));
  // A tree, because "Shares" and "Shares/IT" are not siblings and the flat
  // list said they were. Each row keeps a compact severity meter on its own
  // line rather than a bar underneath, which is what lets eighteen rows fit
  // where eight used to.
  card.innerHTML = `
    <div class="dash-rows tree-rows">
      ${rows.map((entry, index) => {
        const mix = SEVERITY_CLIMB.filter((sev) => entry[sev]).map((sev) => `${entry[sev].toLocaleString()} ${sev}`).join(", ");
        const last = entry.depth > 0 && (rows[index + 1]?.depth ?? 0) === 0;
        return `
        <button type="button" class="place-row plain-btn" data-location-jump="${escapeHtml(entry.label)}"
                data-depth="${entry.depth}" ${last ? "data-last" : ""}
                style="--fw-share:${Math.max(10, Math.round((entry.total / max) * 100))}%"
                aria-label="${escapeHtml(entry.label)}, ${entry.total} files, ${escapeHtml(mix)} — open in Findings">
          <span class="place-lead">
            <span class="place-mark" aria-hidden="true">${glyph(entry.depth ? "li-folder" : "li-database")}</span>
            <span class="place-row-name">${escapeHtml(entry.label)}</span>
          </span>
          ${buildStack(entry)}
          <span class="place-row-count">${entry.total.toLocaleString()}</span>
        </button>`;
      }).join("")}
    </div>`;
}

// ---- Stale and abandoned sensitive data ---------------------------------
// Age is an ordered scale but it is NOT severity, so it does not borrow the
// severity ramp - a single-hue sequential that darkens as the data is left
// alone longer. Buckets are counted server-side over files carrying at least
// one finding: whether an empty file is old is not a security question.
const AGE_BANDS = [
  ["active", "Active", "Touched in the last 90 days"],
  ["ageing", "Ageing", "Untouched for 90 days to a year"],
  ["abandoned", "Abandoned", "Untouched for over a year"],
];

function renderStaleCard() {
  const card = document.querySelector("#stale-card");
  if (!card) return;
  const age = estateFacets?.sensitive_age;
  if (!age || !Object.keys(age).length) {
    const missing = estateFacets && !age;
    setCardMeta("#stale-card-meta", missing ? "Unavailable" : "No scan yet");
    card.innerHTML = missing
      ? '<p class="dash-empty">This service build does not report file ages. Restart the Sentro service to pick them up.</p>'
      : '<p class="dash-empty">File ages appear after the first scan.</p>';
    return;
  }
  const counts = {
    active: Number(age.fresh || 0) + Number(age.recent || 0),
    ageing: Number(age.ageing || 0),
    abandoned: Number(age.stale || 0),
  };
  const undated = Number(age.unknown || 0);
  const total = counts.active + counts.ageing + counts.abandoned;
  if (!total && !undated) {
    setCardMeta("#stale-card-meta", "No scan yet");
    card.innerHTML = '<p class="dash-empty">File ages appear after the first scan.</p>';
    return;
  }
  const left = counts.ageing + counts.abandoned;
  setCardMeta("#stale-card-meta", undated
    ? `${undated.toLocaleString()} undated`
    : `${total.toLocaleString()} sensitive files`);
  // A gauge, because this is one proportion against a target of zero: what
  // share of the sensitive estate has been left alone. A 240-degree sweep
  // reads as a dial rather than a progress bar, and the three bands sit
  // under it as a single line rather than three legend rows.
  const share = total ? Math.round((left / total) * 100) : 0;
  const sweep = 240;
  const radius = 42;
  const track = (sweep / 360) * 2 * Math.PI * radius;
  card.innerHTML = `
    <div class="gauge" role="img"
         aria-label="${left.toLocaleString()} of ${total.toLocaleString()} sensitive files untouched for 90 days or more">
      <svg class="gauge-dial" viewBox="0 0 104 76">
        <g transform="rotate(150 52 52)">
          <circle class="gauge-track" cx="52" cy="52" r="${radius}"
                  stroke-dasharray="${track.toFixed(2)} ${(2 * Math.PI * radius).toFixed(2)}" />
          <circle class="gauge-fill" cx="52" cy="52" r="${radius}"
                  stroke-dasharray="${(track * share / 100).toFixed(2)} ${(2 * Math.PI * radius).toFixed(2)}" />
        </g>
      </svg>
      <span class="gauge-read"><strong>${share}%</strong><small>left alone</small></span>
    </div>
    <div class="gauge-bands">
      ${AGE_BANDS.map(([key, label, note]) => `
        <div class="gauge-band" title="${escapeHtml(note)}"
                aria-label="${escapeHtml(label)}, ${counts[key].toLocaleString()} files — ${escapeHtml(note.toLowerCase())}">
          <span class="gauge-band-dot" data-age="${key}" aria-hidden="true"></span>
          <span class="gauge-band-label">${escapeHtml(label)}</span>
          <b>${counts[key].toLocaleString()}</b>
        </div>`).join("")}
    </div>`;
}

// ---- Assessment coverage: what the other four cards are counting --------
// Every figure on this page is "of the files we could read and classify". That
// qualifier was nowhere on the dashboard, so a 96% number and a 40% number
// looked identical. Three states, one meter: classified, nothing found,
// unreadable.
function renderCoverageCard() {
  const card = document.querySelector("#coverage-card");
  if (!card) return;
  const total = Number(estateFacets?.total || 0);
  if (!total) {
    setCardMeta("#coverage-card-meta", "No scan yet");
    card.innerHTML = '<p class="dash-empty">Coverage appears after the first scan.</p>';
    return;
  }
  const unreadable = Number(estateFacets.protected || 0);
  const classified = Math.max(0, Math.min(total - unreadable, Number(estateFacets.sensitive || 0)));
  const clear = Math.max(0, total - classified - unreadable);
  const share = Math.round((classified / total) * 100);
  setCardMeta("#coverage-card-meta", `${total.toLocaleString()} assessed`);
  // Three columns on a shared baseline. A one-line meter could not show that
  // "nothing found" and "unreadable" are two orders of magnitude apart - both
  // were slivers. Columns give the small values a readable footing and a
  // label, and the card gets shorter for it.
  // Each column is now a filter the inventory can answer, so the three
  // figures and the three lists they open agree. Before this, two of the three
  // carried "ALL" - the same jump, which cleared the severity facet and opened
  // an unfiltered page - and the third was unreachable anyway because the
  // click handler was looking for a class name the markup never had.
  const columns = [
    ["classified", classified, "Classified", "Classified"],
    ["clear", clear, "Clear", "Clear"],
    ["unreadable", unreadable, "Unreadable", "Protected / locked"],
  ];
  const tallest = Math.max(...columns.map(([, count]) => count), 1);
  card.innerHTML = `
    <p class="coverage-lede"><strong>${share}%</strong> classified</p>
    <div class="col-chart" role="img"
         aria-label="${columns.map(([, count, label]) => `${count.toLocaleString()} ${label.toLowerCase()}`).join(", ")}">
      ${columns.map(([kind, count, label, jump]) => `
        <button type="button" class="col-item plain-btn" data-coverage-jump="${escapeHtml(jump)}" data-kind="${kind}"
                style="--col-height:${Math.max(14, Math.round((count / tallest) * 100))}%"
                aria-label="${escapeHtml(label)}, ${count.toLocaleString()} files — open in Findings">
          <span class="col-value">${count.toLocaleString()}</span>
          <span class="col-bar"></span>
          <span class="col-label">${escapeHtml(label)}</span>
        </button>`).join("")}
    </div>`;
}

// ---- Every data class, in a panel that can scroll ------------------------
// The card shows what its height allows; this shows the whole list. It is the
// same row, so a class looks the same in both places and clicking it does the
// same thing.
function openAllDataClasses() {
  const dialog = document.querySelector("#data-classes-dialog");
  const body = document.querySelector("#data-classes-dialog-body");
  if (!dialog || !body) return;
  const rows = (estateFacets?.finding_types || [])
    .filter((item) => isDataClass(item.value))
    .map((item) => {
      const severity = item.severity_file_counts || {};
      return {
        type: String(item.value || "Unknown"),
        count: Number(item.file_count ?? item.count ?? 0),
        critical: Number(severity.CRITICAL || 0),
        high: Number(severity.HIGH || 0),
        medium: Number(severity.MEDIUM || 0),
        low: Number(severity.LOW || 0),
      };
    })
    .filter((item) => item.count > 0)
    .sort((left, right) => right.count - left.count);
  const max = Math.max(...rows.map((item) => item.count), 1);
  setCardMeta("#data-classes-dialog-count", `${rows.length} classes across ${
    rows.reduce((sum, item) => sum + item.count, 0).toLocaleString()} file matches`);
  body.innerHTML = `
    <div class="dash-rows dash-rows-plot">
      ${rows.map((item) => {
        const kind = dataClassKind(item.type);
        const share = Math.max(4, Math.round((item.count / max) * 100));
        return `
        <button type="button" class="class-row plain-btn" data-inventory-search="${escapeHtml(item.type)}"
                data-cat="${escapeHtml(kind.cat)}" style="--plot-share:${share}%"
                aria-label="${escapeHtml(item.type)}, ${item.count} files — open in Findings">
          ${coin(kind.glyph, kind.cat)}
          <span class="class-row-name">${escapeHtml(item.type)}</span>
          <span class="class-row-count">${item.count.toLocaleString()}</span>
          <span class="lolli" aria-hidden="true"><i class="lolli-stem"></i><i class="lolli-dot"></i></span>
        </button>`;
      }).join("")}
    </div>`;
  openClassesModal();
}

// Same three lines the asset detail runs: unhide, force a frame so the rise
// animation has a start, then mark it open. The backdrop element, the icon
// close, the click-outside and the Escape all come with the shape.
let classesModalReturnFocus = null;

function openClassesModal() {
  const modal = document.querySelector("#data-classes-dialog");
  if (!modal || !modal.classList.contains("hidden")) return;
  classesModalReturnFocus = document.activeElement;
  modal.classList.remove("hidden");
  modal.getBoundingClientRect();
  modal.classList.add("open");
  requestAnimationFrame(() => modal.querySelector(".asset-modal-close")?.focus());
}

function closeClassesModal() {
  const modal = document.querySelector("#data-classes-dialog");
  if (!modal || modal.classList.contains("hidden")) return;
  modal.classList.remove("open");
  modal.classList.add("hidden");
  if (classesModalReturnFocus?.isConnected) classesModalReturnFocus.focus();
  classesModalReturnFocus = null;
}

document.addEventListener("click", (event) => {
  if (event.target.closest("[data-close-classes-modal]")) closeClassesModal();
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape") closeClassesModal();
});

// ---- Frameworks: their own mark, and the severity of what they cover -----
const FRAMEWORK_MARKS = {
  gdpr: { label: "GDPR", glyph: "mk-eu-stars" },
  pci_dss: { label: "PCI DSS", glyph: "li-credit-card" },
  nist_sp800_60_enterprise: { label: "NIST", glyph: "li-shield-check" },
  nist_csf: { label: "NIST CSF", glyph: "li-shield-check" },
  hipaa: { label: "HIPAA", glyph: "li-plus" },
  iso27001: { label: "ISO/IEC 27001", glyph: "li-lock" },
};

function frameworkMark(id) {
  return FRAMEWORK_MARKS[id] || { label: frameworkLabel(id), glyph: "li-badge-check" };
}

// Files per framework, split by the file's effective severity. "standard
// scan" is the absence of a framework and is not a row.
function frameworkBreakdown() {
  if (estateFacets) {
    return (estateFacets.frameworks || [])
      .map((item) => {
        const id = String(item.value || "");
        const severity = item.severity_file_counts || {};
        return {
          id,
          total: Number(item.file_count ?? item.count ?? 0),
          critical: Number(severity.CRITICAL || 0),
          high: Number(severity.HIGH || 0),
          medium: Number(severity.MEDIUM || 0),
          low: Number(severity.LOW || 0),
        };
      })
      .filter((entry) => entry.id && entry.id !== "standard_scan" && entry.id !== "generic" && entry.total > 0)
      .sort((left, right) => right.total - left.total);
  }
  // The preview array is never an estate metric, even when a report happens
  // to contain every file. The canonical facet response is the only source.
  return [];
}

// Least severe first, so the bar climbs into the risk rather than leading
// with it. Reading left to right then matches reading the ramp: green, yellow,
// amber, red.
const SEVERITY_CLIMB = ["low", "medium", "high", "critical"];

function buildStack(entry) {
  const present = SEVERITY_CLIMB.filter((sev) => entry[sev]);
  const segments = present
    .map((sev) => `<i data-sev="${sev}" style="flex-grow:${entry[sev]}" title="${entry[sev].toLocaleString()} ${sev}"></i>`)
    .join("");
  // Colour is never the only channel: the mix is spelled out for a screen
  // reader and in the row's own title.
  const legend = present.map((sev) => `${entry[sev].toLocaleString()} ${sev}`).join(", ");
  return `<span class="stack" role="img" aria-label="${escapeHtml(legend)}">${segments}</span>`;
}

function renderFrameworksCard() {
  const card = document.querySelector("#frameworks-card");
  if (!card) return;
  const rows = frameworkBreakdown();
  const maxTotal = Math.max(...rows.map((row) => row.total), 1);
  setCardMeta("#frameworks-card-meta", rows.length
    ? `${rows.length} mapped`
    : "No scan yet");
  if (!rows.length) {
    card.innerHTML = '<p class="dash-empty">Framework coverage appears after the first scan.</p>';
    return;
  }
  card.innerHTML = `
    <div class="dash-rows">
      ${rows.map((entry) => {
        const mark = frameworkMark(entry.id);
        return `
        <button type="button" class="fw-row plain-btn" data-framework-jump="${escapeHtml(entry.id)}"
                data-mark="${escapeHtml(entry.id)}"
                style="--fw-share:${Math.max(18, Math.round(entry.total / maxTotal * 100))}%"
                aria-label="${escapeHtml(mark.label)}, ${entry.total} files — open in Findings">
          <span class="mark" data-mark="${escapeHtml(entry.id)}" aria-hidden="true">${glyph(mark.glyph)}</span>
          <span class="fw-row-name">${escapeHtml(mark.label)}</span>
          <span class="fw-row-count">${entry.total.toLocaleString()} <small>files</small></span>
          ${buildStack(entry)}
        </button>`;
      }).join("")}
    </div>`;
}

// Finding lifecycle figures come from /api/findings, not file-level summary
// totals. A file can carry several independently owned remediation tasks.
function renderRemediationLoad() {
  const metrics = document.querySelector("#remediation-stats");
  if (!metrics) return;
  if (remediationLoadError && !remediationSummary) {
    metrics.innerHTML = '<div><span>Queue</span><strong>—</strong><small>metrics unavailable</small></div>';
    if (remediationScopeSummary) remediationScopeSummary.textContent = "Finding metrics unavailable";
    return;
  }
  if ((remediationLoading && !remediationLoaded) || !remediationSummary) {
    metrics.innerHTML = Array.from({ length: 5 }, () =>
      '<div><span class="skeleton remediation-stat-skeleton" aria-label="Loading"></span></div>').join("");
    if (remediationScopeSummary) remediationScopeSummary.textContent = "Loading current finding metrics…";
    return;
  }
  const open = Number(remediationSummary.open || 0);
  const affected = Number(remediationSummary.affected_files || 0);
  const overdue = Number(remediationSummary.overdue || 0);
  const shown = remediationFindings.length;
  const total = Number(remediationPage.total || 0);
  metrics.innerHTML = `
    <div><span>Visible</span><strong>${shown.toLocaleString()}</strong><small>of ${total.toLocaleString()} findings</small></div>
    <div><span>Open</span><strong>${open.toLocaleString()}</strong><small>${affected.toLocaleString()} files affected</small></div>
    <div><span>In progress</span><strong>${Number(remediationSummary.in_progress || 0).toLocaleString()}</strong><small>${Number(remediationSummary.pending_validation || 0).toLocaleString()} in validation</small></div>
    <div><span>Overdue</span><strong>${overdue.toLocaleString()}</strong><small>${Math.round((overdue / Math.max(1, open)) * 100)}% of open</small></div>
    <div><span>Resolved</span><strong>${Number(remediationSummary.resolved || 0).toLocaleString()}</strong><small>${Number(remediationSummary.risk_accepted || 0).toLocaleString()} risk accepted</small></div>
  `;
  // The counts the pills carried live on the option labels now, so the select
  // still says how much is behind each choice before you pick it.
  const severityCounts = remediationSummary.findings_by_severity || {};
  facetRealOptions(remediationSeverityFilter).forEach((option) => {
    const level = option.value || "ALL";
    const label = option.dataset.label || (option.dataset.label = option.textContent);
    const count = level === "ALL"
      ? Number(remediationSummary.active_findings || total || 0)
      : Number(severityCounts[level] || 0);
    option.textContent = `${label} (${count.toLocaleString()})`;
  });
  syncFacetSummary(remediationSeverityFilter);
  if (remediationScopeSummary) {
    const scope = remediationStatusLabel(remediationSummary.scope || "current");
    remediationScopeSummary.textContent = `${scope} scope · ${Number(remediationSummary.active_findings || 0).toLocaleString()} active findings across ${affected.toLocaleString()} affected files`;
  }
}

// The server computes posture from the estate, and it is the ONLY thing that
// computes it. Three formulas used to produce this number - a mean of asset
// risk scores here, a severity-weighted mean in the executive API, absolute
// weighted counts in the report - and they disagreed with each other on the
// same data. The client now reads the answer instead of deriving one.
function getCurrentPostureScore() {
  // `measured: false` means nothing has been scanned yet. The score is 100 in
  // that case because no deduction applies, which is a different claim from
  // "the estate is clean" - so the card shows a dash rather than an A.
  if (latestDashboard?.posture && latestDashboard.posture.measured === false) return null;
  const score = latestDashboard?.risk_posture_score;
  return score === undefined || score === null ? null : clampScore(score);
}

// The four subtractions behind the score, for the card that shows them.
function posturePressure() {
  return latestDashboard?.posture?.terms || [];
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

// Severity, worst first. A data class is worth listing with the worst level it
// has been found at - "Credit card numbers, 25k" says how much, not how bad.
const SEVERITY_RANK = ["PROTECTED", "LOW", "MEDIUM", "HIGH", "CRITICAL"];

function worstSeverity(a, b) {
  return SEVERITY_RANK.indexOf(b) > SEVERITY_RANK.indexOf(a) ? b : a;
}

function buildFindingStats(limit = 6) {
  const stats = {};
  latestFiles.forEach((file) => {
    const fileLevel = String(getEffectiveRisk(file).level || "LOW").toUpperCase();
    primaryFindingsForFile(file).forEach((finding) => {
      const name = findingDisplayName(finding);
      const level = String(finding.risk || finding.severity || fileLevel).toUpperCase();
      const entry = stats[name] || { type: name, count: 0, level: "LOW" };
      entry.count += Number(finding.count || 1);
      entry.level = worstSeverity(entry.level, level);
      stats[name] = entry;
    });
    if (hasHashChanged(file)) {
      const entry = stats["Hash changed"] || { type: "Hash changed", count: 0, level: "LOW" };
      entry.count += 1;
      entry.level = worstSeverity(entry.level, fileLevel);
      stats["Hash changed"] = entry;
    }
  });

  const all = Object.values(stats).sort((a, b) => b.count - a.count);
  const shown = all.slice(0, limit);
  shown.total = all.length;
  return shown;
}

// Phase A (3e7a69e) deleted these two with the dead posture-trend code above them, and
// every Remediation load that drew a row has thrown a ReferenceError since - which the
// page reports as "Unable to load remediation findings".
const REMEDIATION_LIFECYCLE_STATUSES = [
  "NEW", "OPEN", "UNDER_REVIEW", "CONFIRMED", "ASSIGNED", "IN_PROGRESS",
  "PENDING_VALIDATION", "RESOLVED", "RISK_ACCEPTED", "FALSE_POSITIVE", "SUPPRESSED", "REOPENED",
];

const REMEDIATION_TERMINAL_STATUSES = new Set(["RESOLVED", "RISK_ACCEPTED", "FALSE_POSITIVE", "SUPPRESSED"]);

function remediationStatus(finding = {}) {
  const value = String(finding.status || finding.review_status || finding.workflow_status || "OPEN").trim().toUpperCase();
  if (value === "UNREVIEWED") return "NEW";
  return REMEDIATION_LIFECYCLE_STATUSES.includes(value) ? value : "OPEN";
}

function remediationStatusLabel(value = "") {
  return String(value || "OPEN").toLowerCase().replaceAll("_", " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

function remediationIsTerminal(finding = {}) {
  return REMEDIATION_TERMINAL_STATUSES.has(remediationStatus(finding));
}

function remediationSeverity(finding = {}) {
  const risk = typeof finding.risk === "object" ? finding.risk?.level : finding.risk;
  const value = String(risk || finding.severity || finding.impact_severity || "LOW").toUpperCase();
  return ["CRITICAL", "HIGH", "MEDIUM", "LOW"].includes(value) ? value : "LOW";
}

function remediationRiskScore(finding = {}) {
  const risk = typeof finding.risk === "object" ? finding.risk?.score : null;
  const explicit = finding.risk_score ?? finding.operational_priority_score ?? risk;
  return explicit === undefined || explicit === null ? severityScore(remediationSeverity(finding)) : clampScore(explicit);
}

function remediationFileContext(finding = {}) {
  const path = String(finding.file?.path || finding.path || "");
  const findingId = String(finding.finding_id || "");
  return latestFiles.find((file) => {
    if (path && String(file.path || "") === path) return true;
    return findingId && (file.findings || []).some((item) => String(item.finding_id || "") === findingId);
  }) || {};
}

function remediationFileName(finding = {}) {
  const path = String(finding.file?.name || finding.file?.path || finding.path || "");
  return path.split(/[\\/]/).filter(Boolean).at(-1) || "Unknown file";
}

function remediationAsset(finding = {}) {
  const file = remediationFileContext(finding);
  return String(
    finding.affected_asset || finding.asset_name || finding.resource_name || file.host_id || file.server || file.share
      || finding.asset_id || finding.file?.source || file.source || "Unknown asset"
  );
}

// The canonical risk category the Risk-category filter reads, shown so the
// column the queue sorts by is the column it displays.
function remediationCategory(finding = {}) {
  return remediationHumanize(finding.finding_category || finding.category || finding.data_type || "Unclassified");
}

function remediationDataType(finding = {}) {
  const domain = String(finding.classification_domain || "").toLowerCase();
  if (domain === "secrets" || domain.includes("credential")) return "Credential";
  const raw = finding.data_type || finding.data_element || finding.personal_data_type
    || finding.finding_category || finding.data_category || finding.category || finding.entity_type || "Unclassified";
  return remediationHumanize(raw);
}

function remediationHumanize(value = "") {
  const text = String(value || "").replaceAll("_", " ").replace(/\s+/g, " ").trim().toLowerCase();
  return text ? text.replace(/\b\w/g, (letter) => letter.toUpperCase()) : "Unknown";
}

function remediationExposure(finding = {}) {
  const file = remediationFileContext(finding);
  const state = finding.exposure || finding.exposure_state;
  if (state && String(state).toUpperCase() !== "UNKNOWN") return remediationHumanize(state);
  return findingExposureText(file, finding);
}

function remediationFrameworkValues(finding = {}) {
  const frameworks = allFindingFrameworks(finding).filter((value) => value && value !== "generic");
  return frameworks.length ? frameworks : [normalizeFrameworkId(finding.framework || "generic")];
}

function remediationFrameworkText(finding = {}) {
  const frameworks = remediationFrameworkValues(finding);
  if (!frameworks.length || frameworks.every((value) => value === "generic")) return "Unmapped";
  return frameworks.map(frameworkLabel).join(", ");
}

function remediationSla(finding = {}) {
  if (remediationIsTerminal(finding)) return { category: "CLOSED", label: "—", detail: "Closed" };
  const due = String(finding.sla_due || finding.due_date || "").trim();
  const dueMs = Date.parse(due);
  if (!due || Number.isNaN(dueMs)) {
    const file = remediationFileContext(finding);
    const fallback = String(finding.sla || file.risk?.remediation?.sla || "").trim();
    return fallback
      ? { category: "ON_TRACK", label: fallback, detail: "Target" }
      : { category: "NO_SLA", label: "—", detail: "No SLA" };
  }
  const remainingHours = (dueMs - Date.now()) / 3600000;
  const absoluteHours = Math.max(1, Math.round(Math.abs(remainingHours)));
  const short = absoluteHours >= 48 ? `${Math.ceil(absoluteHours / 24)}d` : `${absoluteHours}h`;
  if (remainingHours < 0) return { category: "OVERDUE", label: short, detail: "overdue", due };
  if (remainingHours <= 24) return { category: "DUE_SOON", label: short, detail: "remaining", due };
  return { category: "ON_TRACK", label: short, detail: "remaining", due };
}

function remediationOwner(finding = {}) {
  return String(finding.owner || finding.assignee || finding.data_owner || "Unassigned");
}

function remediationSelectOptions(select, placeholder, values, labeler = (value) => value) {
  if (!select) return;
  // A filter that is chosen has to stay visible in its own control. The
  // dashboard's "Regulated personal data" is three stored categories at once,
  // which is a legitimate filter and never a facet value, so rebuilding the
  // options from the facets alone silently dropped it and the queue came up
  // unfiltered. A chosen value the facets do not list is re-added under the
  // label it was applied with.
  select.innerHTML = `<option value="ALL">${escapeHtml(placeholder)}</option>${values.map((value) =>
    `<option value="${escapeHtml(value)}">${escapeHtml(labeler(value))}</option>`).join("")}`;
  facetKeepChosen(select, values, labeler);
}

function remediationFacetValues(name) {
  return (remediationFacets?.[name] || []).map((item) => String(item.value || "")).filter(Boolean);
}

function renderRemediationStatusOptions() {
  if (!remediationStatusFilter) return;
  const groups = [
    ["active", "Active findings"], ["open", "Open group"], ["in_progress", "In progress group"],
    ["validation", "Validation group"], ["resolved", "Resolved group"], ["exceptions", "Exceptions"], ["all", "All statuses"],
  ];
  remediationStatusFilter.innerHTML = `
    <optgroup label="Workflow groups">${groups.map(([value, label]) => `<option value="${value}">${label}</option>`).join("")}</optgroup>
    <optgroup label="Lifecycle status">${REMEDIATION_LIFECYCLE_STATUSES.map((value) => `<option value="${value}">${escapeHtml(remediationStatusLabel(value))}</option>`).join("")}</optgroup>`;
  syncFacetSummary(remediationStatusFilter);
}

let remediationFacetSignature = "";

function renderRemediationFilterOptions() {
  const signature = JSON.stringify([
    remediationFacetValues("categories"), remediationFacetValues("owners"),
    remediationFacetValues("frameworks"), remediationFacetValues("data_types"),
    remediationFacetValues("assets"),
  ]);
  if (signature === remediationFacetSignature) return;
  remediationFacetSignature = signature;
  renderRemediationStatusOptions();
  remediationSelectOptions(remediationCategoryFilter, "Category", remediationFacetValues("categories"), remediationHumanize);
  remediationSelectOptions(remediationOwnerFilter, "Owner", remediationFacetValues("owners"), (value) => value === "__unassigned__" ? "Unassigned" : value);
  remediationSelectOptions(remediationFrameworkFilter, "Framework", remediationFacetValues("frameworks"), frameworkLabel);
  remediationSelectOptions(remediationDataFilter, "Data type", remediationFacetValues("data_types"), remediationHumanize);
  remediationSelectOptions(remediationAssetFilter, "Asset", remediationFacetValues("assets"));
}

function remediationBadge(finding = {}) {
  const severity = remediationSeverity(finding);
  return `<span class="badge badge-sm badge-soft remediation-badge remediation-severity" data-severity="${severity}">${remediationStatusLabel(severity)}</span>`;
}

function remediationStatusBadge(finding = {}) {
  const status = remediationStatus(finding);
  return `<span class="badge badge-sm badge-soft remediation-badge remediation-status" data-status="${status}">${escapeHtml(remediationStatusLabel(status))}</span>`;
}

function remediationSlaMarkup(finding = {}) {
  const sla = remediationSla(finding);
  return `<span class="remediation-sla" data-sla="${escapeHtml(sla.category)}"><span>${escapeHtml(sla.label)}</span><small>${escapeHtml(sla.detail)}</small></span>`;
}

function remediationActionSet(finding = {}) {
  const status = remediationStatus(finding);
  let actions = [];
  if (["NEW", "OPEN", "UNDER_REVIEW"].includes(status)) actions = ["assign", "confirm"];
  if (status === "CONFIRMED") actions = finding.validated_at ? ["resolve"] : ["assign"];
  if (status === "ASSIGNED") actions = ["start"];
  if (status === "IN_PROGRESS") actions = ["request_validation"];
  if (status === "PENDING_VALIDATION") actions = ["validate"];
  if (status === "REOPENED") actions = ["assign", "confirm"];
  if (REMEDIATION_TERMINAL_STATUSES.has(status)) return ["reopen"];
  return [...actions, "risk_acceptance", "false_positive", "suppress"];
}

function remediationActionLabel(action = "") {
  return {
    view: "View details", assign: "Assign", confirm: "Confirm finding", start: "Start remediation",
    request_validation: "Request validation", validate: "Validate evidence", resolve: "Resolve",
    risk_acceptance: "Accept risk", false_positive: "Mark false positive", suppress: "Suppress", reopen: "Reopen",
  }[action] || remediationStatusLabel(action);
}

function remediationActionMenu(finding = {}) {
  const findingId = escapeHtml(finding.finding_id || "");
  const filePath = String(finding.file?.path || "");
  const actions = remediationCanManage(finding) ? remediationActionSet(finding) : [];
  const primary = actions.filter((action) => !["risk_acceptance", "false_positive", "suppress"].includes(action));
  const exceptions = actions.filter((action) => ["risk_acceptance", "false_positive", "suppress"].includes(action));
  return `
    <details class="dropdown dropdown-end remediation-queue-menu">
      <summary class="btn btn-sm btn-square btn-ghost remediation-more-button" aria-label="Actions for ${escapeHtml(findingDisplayName(finding))}">
        <svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="5" cy="12" r="1"/><circle cx="12" cy="12" r="1"/><circle cx="19" cy="12" r="1"/></svg>
      </summary>
      <div class="dropdown-content">
        <button type="button" data-remediation-open="${findingId}">View details</button>
        ${filePath ? `<button type="button" data-remediation-file-open="${escapeHtml(filePath)}">Open file in Findings</button>` : ""}
        ${primary.map((action) => `<button type="button" data-remediation-action="${action}" data-finding-id="${findingId}">${escapeHtml(remediationActionLabel(action))}</button>`).join("")}
        ${exceptions.length ? `<hr />${exceptions.map((action) => `<button type="button" data-remediation-action="${action}" data-finding-id="${findingId}">${escapeHtml(remediationActionLabel(action))}</button>`).join("")}` : ""}
      </div>
    </details>`;
}

// Only the columns the API can actually order by are clickable, so a header
// never offers a sort the queue cannot perform.
const REMEDIATION_SORT_LABELS = {
  severity: "severity",
  finding_name: "finding name",
  category: "risk category",
  data_type: "data type",
  asset: "affected asset",
  owner: "owner",
  status: "status",
  sla_due: "SLA date",
  risk_score: "risk score",
};

function remediationHeadCell(key, label, className = "") {
  const active = remediationSortKey === key;
  const sort = active ? (remediationSortDirection === "asc" ? "ascending" : "descending") : "none";
  return `<th scope="col" class="inv-sortable${active ? " is-sorted" : ""}${className ? ` ${className}` : ""}"
    data-remediation-sort="${key}" aria-sort="${sort}" tabindex="0" role="columnheader"
    title="Sort the queue by ${escapeHtml(REMEDIATION_SORT_LABELS[key] || label)}">${escapeHtml(label)}<span class="inv-sort-ind" aria-hidden="true"></span></th>`;
}

// Severity, risk and SLA are worst-first questions. A name, a category, an
// owner or an asset is a where-is-it question, and those start at A.
const REMEDIATION_SORT_ASC_FIRST = new Set([
  "finding_name", "status", "category", "data_type", "asset", "owner",
]);

function applyRemediationSort(key) {
  if (!REMEDIATION_SORT_LABELS[key]) return;
  if (remediationSortKey === key) {
    remediationSortDirection = remediationSortDirection === "asc" ? "desc" : "asc";
  } else {
    remediationSortKey = key;
    remediationSortDirection = REMEDIATION_SORT_ASC_FIRST.has(key) ? "asc" : "desc";
  }
  loadRemediationFindings({ resetPage: true }).catch(() => {});
}

document.addEventListener("click", (event) => {
  const th = event.target.closest?.(".remediation-table th[data-remediation-sort]");
  if (th) applyRemediationSort(th.dataset.remediationSort);
});
document.addEventListener("keydown", (event) => {
  if (event.key !== "Enter" && event.key !== " ") return;
  const th = event.target.closest?.(".remediation-table th[data-remediation-sort]");
  if (!th) return;
  event.preventDefault();
  applyRemediationSort(th.dataset.remediationSort);
});

// Findings is paginated, so the row may not be on the page that is loaded.
// Search for the path first, then open the row's own detail once it lands -
// and if it never does, the reader is still on the right search.
function openFileInInventory(path) {
  const wanted = String(path || "").trim();
  if (!wanted) return;
  switchTab("findings");
  if (!filterInput) return;
  filterInput.value = wanted;
  lastInventoryQuery = "";
  filterInput.dispatchEvent(new Event("input", { bubbles: true }));
  let tries = 0;
  const open = () => {
    const row = [...document.querySelectorAll("#results-body [data-inventory-expand]")]
      .find((button) => String(button.dataset.inventoryExpand || "").endsWith(wanted));
    if (row) {
      row.click();
      return;
    }
    if (++tries < 12) window.setTimeout(open, 250);
  };
  window.setTimeout(open, 400);
}

function remediationTableMarkup(rows = []) {
  return `
    <div class="table-wrap inventory-table-wrap remediation-table-wrap">
      <table class="remediation-table" aria-label="Remediation findings">
        <thead><tr>${remediationHeadCell("severity", "Severity")}${remediationHeadCell("finding_name", "Finding")}${remediationHeadCell("category", "Category", "remediation-col-category")}${remediationHeadCell("data_type", "Data type", "remediation-col-data")}${remediationHeadCell("asset", "Affected asset")}${remediationHeadCell("risk_score", "Exposure / risk", "remediation-col-exposure")}${remediationHeadCell("owner", "Owner", "remediation-col-owner")}${remediationHeadCell("status", "Status")}${remediationHeadCell("sla_due", "SLA")}<th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>${rows.map((finding) => {
          const findingId = escapeHtml(finding.finding_id || "");
          const filePath = String(finding.file?.path || "");
          return `<tr data-remediation-finding="${findingId}" data-remediation-file="${escapeHtml(filePath)}"
            class="${selectedRemediationFindingId === finding.finding_id ? "is-selected" : ""}">
            <td>${remediationBadge(finding)}</td>
            <td><button type="button" class="remediation-row-button plain-btn" data-remediation-open="${findingId}"><strong>${escapeHtml(findingDisplayName(finding))}</strong><span title="${escapeHtml(filePath)}">${escapeHtml(remediationFileName(finding))}</span></button></td>
            <td class="remediation-col-category" title="${escapeHtml(remediationCategory(finding))}">${escapeHtml(remediationCategory(finding))}</td>
            <td class="remediation-col-data" title="${escapeHtml(remediationDataType(finding))}">${escapeHtml(remediationDataType(finding))}</td>
            <td><span class="remediation-asset-name" title="${escapeHtml(remediationAsset(finding))}">${escapeHtml(remediationAsset(finding))}</span></td>
            <td class="remediation-col-exposure"><span class="remediation-exposure" title="${escapeHtml(remediationExposure(finding))}">${escapeHtml(remediationExposure(finding))}</span><span class="remediation-cell-secondary">Risk ${remediationRiskScore(finding)}</span></td>
            <td class="remediation-col-owner" title="${escapeHtml(remediationOwner(finding))}">${escapeHtml(remediationOwner(finding))}</td>
            <td>${remediationStatusBadge(finding)}</td><td>${remediationSlaMarkup(finding)}</td><td>${remediationActionMenu(finding)}</td>
          </tr>`;
        }).join("")}</tbody>
      </table>
    </div>
    <div class="remediation-mobile-list" aria-label="Remediation findings">
      ${rows.map((finding) => `<button type="button" class="remediation-mobile-card plain-btn" data-remediation-open="${escapeHtml(finding.finding_id || "")}">
        ${remediationBadge(finding)}<span class="remediation-mobile-card-copy"><strong>${escapeHtml(findingDisplayName(finding))}</strong><span>${escapeHtml(remediationAsset(finding))} · ${escapeHtml(remediationFileName(finding))}</span></span>
        <span aria-hidden="true">›</span><span class="remediation-mobile-meta">${remediationStatusBadge(finding)}${remediationSlaMarkup(finding)}</span>
      </button>`).join("")}
    </div>`;
}

function remediationLoadingMarkup() {
  const row = `<tr class="remediation-skeleton-row" aria-hidden="true">${["short", "wide", "mid", "mid", "wide", "mid", "mid", "short", "short"].map((width) => `<td><div class="skeleton skeleton-${width}"></div></td>`).join("")}</tr>`;
  return `<div class="table-wrap inventory-table-wrap remediation-table-wrap"><table class="remediation-table"><thead><tr><th>Severity</th><th>Finding</th><th>Data type</th><th>Asset</th><th>Exposure / risk</th><th>Owner</th><th>Status</th><th>SLA</th><th></th></tr></thead><tbody>${row.repeat(7)}</tbody></table></div>`;
}

function remediationEmptyMarkup(filtered = false) {
  const title = filtered ? "No findings match these filters" : "No active remediation tasks";
  const copy = filtered
    ? "Reset one or more filters to broaden the remediation queue."
    : "All discovered findings are currently resolved, accepted, suppressed, or awaiting new scan results.";
  return `<div class="table-wrap inventory-table-wrap remediation-empty-state"><div><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 12h5l2 3h4l2-3h5"/><path d="M5 5h14l2 7v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-6z"/></svg><strong>${title}</strong><p>${copy}</p>${filtered ? '<button type="button" class="secondary-btn mini-btn" data-remediation-reset>Clear filters</button>' : ""}</div></div>`;
}

function remediationHasNonDefaultFilters() {
  return Boolean(String(remediationSearch?.value || "").trim())
    || (remediationScopeFilter?.value || "current") !== "current"
    || facetAppliedParam("remediation-status-filter") !== "active"
    || REMEDIATION_FILTER_PARAMS.some(([, id]) => facetAppliedValues(id).length);
}

function remediationPaginationMarkup() {
  const total = Number(remediationPage.total || 0);
  if (!total) return "";
  const first = remediationPage.pageIndex * REMEDIATION_PAGE_SIZE + 1;
  const last = first + remediationFindings.length - 1;
  const pages = Math.max(1, Math.ceil(total / REMEDIATION_PAGE_SIZE));
  return `<nav class="remediation-pagination" aria-label="Remediation result pages">
    <span>Showing ${first.toLocaleString()}–${last.toLocaleString()} of ${total.toLocaleString()} findings</span>
    <div class="remediation-page-controls">
      <button type="button" class="secondary-btn mini-btn" data-remediation-page="previous" ${remediationPage.pageIndex === 0 ? "disabled" : ""}>Previous</button>
      <span class="remediation-page-number" aria-current="page">Page ${(remediationPage.pageIndex + 1).toLocaleString()} of ${pages.toLocaleString()}</span>
      <button type="button" class="secondary-btn mini-btn" data-remediation-page="next" ${!remediationPage.hasMore ? "disabled" : ""}>Next</button>
    </div>
  </nav>`;
}

// The server's own words when it gave a reason ("503: ..."), so a failure that is not
// worth retrying - a backend that is not ready - does not read as one that is.
function remediationErrorReason(message = "") {
  const answered = /^(\d{3}): (.+)$/s.exec(String(message || "").trim());
  return answered ? `The server answered ${answered[1]}: ${answered[2]}` : "Please try again.";
}

function renderRemediationWorkspace() {
  if (deferWhileHidden("tab-risk", "workspace", renderRemediationWorkspace)) return;
  if (!remediationWorkflow) return;
  renderRemediationLoad();
  if (remediationError) {
    remediationError.hidden = !remediationLoadError;
    const reason = remediationError.querySelector("[data-remediation-error-reason]");
    if (reason) reason.textContent = remediationErrorReason(remediationLoadError);
  }
  if (remediationLoading && !remediationLoaded) {
    remediationWorkflow.innerHTML = remediationLoadingMarkup();
    if (remediationResultCount) remediationResultCount.textContent = "Loading findings…";
    return;
  }
  renderRemediationFilterOptions();
  if (remediationLoadError && !remediationLoaded) {
    remediationWorkflow.innerHTML = "";
    if (remediationResultCount) remediationResultCount.textContent = "Findings unavailable";
    return;
  }
  if (remediationResultCount) remediationResultCount.textContent = `${Number(remediationPage.total || 0).toLocaleString()} matching findings`;
  remediationWorkflow.innerHTML = remediationFindings.length
    ? `${remediationTableMarkup(remediationFindings)}${remediationPaginationMarkup()}`
    : remediationEmptyMarkup(remediationHasNonDefaultFilters());
}

function resetRemediationPage() {
  remediationPage = { total: 0, hasMore: false, nextCursor: "", pageIndex: 0, pageStarts: [""] };
}

const REMEDIATION_FILTER_PARAMS = [
  ["severity", "remediation-severity-filter"], ["category", "remediation-category-filter"],
  ["owner", "remediation-owner-filter"], ["framework", "remediation-framework-filter"],
  ["data_type", "remediation-data-filter"], ["asset", "remediation-asset-filter"],
  ["sla", "remediation-sla-filter"],
];

function remediationQueryParams() {
  const statuses = facetAppliedValues("remediation-status-filter");
  const params = new URLSearchParams({
    scope: remediationScopeFilter?.value || "current",
    // No status ticked is a question about every status, not about none.
    status: statuses.length ? statuses.join(",") : "all",
    limit: String(REMEDIATION_PAGE_SIZE),
  });
  REMEDIATION_FILTER_PARAMS.forEach(([name, id]) => {
    const value = facetAppliedParam(id);
    if (value) params.set(name, value);
  });
  const query = String(remediationSearch?.value || "").trim();
  if (query) params.set("q", query);
  params.set("sort", remediationSortKey);
  params.set("direction", remediationSortDirection);
  const cursor = remediationPage.pageStarts[remediationPage.pageIndex] || "";
  if (cursor) params.set("after", cursor);
  return params;
}

async function loadRemediationFindings({ showLoading = true, resetPage = false } = {}) {
  if (!remediationWorkflow) return;
  if (resetPage) resetRemediationPage();
  if (!accessToken) {
    remediationFindings = [];
    remediationSummary = null;
    remediationFacets = {};
    resetRemediationPage();
    remediationLoaded = true;
    remediationLoading = false;
    remediationLoadError = "";
    renderRemediationWorkspace();
    return;
  }
  const context = captureTenantContext();
  const requestId = ++remediationListRequest;
  remediationListAbortController?.abort();
  remediationListAbortController = new AbortController();
  if (showLoading && !remediationLoaded) remediationLoading = true;
  remediationLoadError = "";
  if (remediationLoaded) {
    // Rows are already on screen: mark the panel busy instead of rebuilding
    // it into a skeleton and back. One render per load, not three.
    remediationWorkflow?.classList.add("is-refreshing");
  } else {
    renderRemediationWorkspace();
  }
  try {
    const data = await api(`/api/findings?${remediationQueryParams()}`, null, "GET", { signal: remediationListAbortController.signal });
    if (!isCurrentTenantContext(context) || requestId !== remediationListRequest) return;
    remediationFindings = Array.isArray(data?.items) ? data.items : [];
    remediationSummary = data?.summary || null;
    remediationFacets = data?.facets || {};
    remediationPage.total = Number(data?.total || 0);
    remediationPage.hasMore = Boolean(data?.has_more);
    remediationPage.nextCursor = String(data?.next_cursor || "");
    remediationLoaded = true;
    remediationLoading = false;
    remediationWorkflow?.classList.remove("is-refreshing");
    renderRemediationWorkspace();
  } catch (error) {
    if (!isCurrentTenantContext(context) || requestId !== remediationListRequest) return;
    if (error?.name === "AbortError") {
      // Only the newest attempt owns the flag; an older one must not clear it.
      if (requestId === remediationListRequest) {
        remediationLoading = false;
        remediationWorkflow?.classList.remove("is-refreshing");
        renderRemediationWorkspace();
      }
      return;
    }
    remediationLoading = false;
    remediationWorkflow?.classList.remove("is-refreshing");
    remediationLoadError = error.message || "Unable to load findings";
    console.error("Remediation findings could not be loaded", error);
    renderRemediationWorkspace();
  }
}

function remediationDrawerLoadingMarkup() {
  return `<div class="remediation-drawer-loading" aria-label="Loading finding details"><div class="skeleton skeleton-title"></div><div class="skeleton skeleton-short"></div>${Array.from({ length: 9 }, () => '<div class="skeleton skeleton-copy"></div>').join("")}</div>`;
}

function remediationFormatDate(value = "", { dateOnly = false } = {}) {
  const parsed = new Date(value);
  if (!value || Number.isNaN(parsed.getTime())) return "Not available";
  return new Intl.DateTimeFormat(undefined, dateOnly
    ? { year: "numeric", month: "short", day: "2-digit" }
    : { year: "numeric", month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit" }).format(parsed);
}

function remediationRecommendations(finding = {}) {
  const file = remediationFileContext(finding);
  const values = [];
  const add = (value) => {
    if (!value) return;
    if (Array.isArray(value)) {
      value.forEach(add);
      return;
    }
    if (typeof value === "object") {
      add(value.actions || value.steps || value.recommendations);
      return;
    }
    const text = String(value).trim();
    if (text) values.push(text);
  };
  add(finding.remediation);
  add(finding.recommendations);
  add(finding.dlp_recommendations);
  add(file.risk?.remediation);
  add(file.risk?.dlp_recommendations);
  return [...new Set(values)].slice(0, 8);
}

function remediationRiskFactors(finding = {}) {
  const file = remediationFileContext(finding);
  const values = [];
  const add = (value) => {
    if (Array.isArray(value)) value.forEach(add);
    else if (value) values.push(String(value).trim());
  };
  add(finding.risk_factors);
  add(finding.reasons);
  add(file.risk?.reasons);
  return [...new Set(values.filter(Boolean))].slice(0, 5);
}

function remediationOverviewItem(label, value, wide = false, title = "") {
  return `<div class="remediation-overview-item ${wide ? "remediation-overview-wide" : ""}"><span>${escapeHtml(label)}</span><strong${title ? ` title="${escapeHtml(title)}"` : ""}>${escapeHtml(value || "Not available")}</strong></div>`;
}

function remediationWorkflowStage(finding = {}) {
  const status = remediationStatus(finding);
  if (status === "RESOLVED") return 4;
  if (status === "PENDING_VALIDATION" || finding.validated_at) return 3;
  if (status === "IN_PROGRESS") return 2;
  if (status === "ASSIGNED") return 1;
  return 0;
}

function remediationWorkflowMarkup(finding = {}) {
  const stage = remediationWorkflowStage(finding);
  const labels = ["Triage", "Assigned", "Remediation", "Validation", "Resolved"];
  return `<ul class="steps steps-horizontal remediation-workflow-steps" aria-label="Remediation workflow">${labels.map((label, index) => `<li class="step ${index <= stage ? "step-primary" : ""}">${label}</li>`).join("")}</ul>`;
}

function remediationHistory(finding = {}) {
  const items = Array.isArray(finding.__history) ? finding.__history : (finding.status_history || finding.history || []);
  return [...items].sort((left, right) => Date.parse(left.timestamp || left.created_at || "") - Date.parse(right.timestamp || right.created_at || ""));
}

function remediationActivityLabel(event = {}) {
  const action = String(event.action || "status updated").replaceAll("_", " ").replaceAll("-", " ");
  const labels = {
    assign: "Assigned", comment: "Comment added", suppress: "Finding suppressed", "false positive": "Marked false positive",
    "risk acceptance": "Risk accepted", resolve: "Finding resolved", reopen: "Finding reopened", validate: "Validation recorded",
    status: `Status changed to ${remediationStatusLabel(event.status || "")}`,
  };
  return labels[action] || remediationHumanize(action);
}

function remediationActivityMarkup(finding = {}) {
  const events = remediationHistory(finding);
  if (!events.length) return '<p>No lifecycle activity has been recorded for this finding yet.</p>';
  return `<ol class="remediation-activity-list">${events.map((event) => {
    const timestamp = event.timestamp || event.created_at || "";
    const actor = event.actor || event.user || "";
    return `<li class="remediation-activity-item"><time class="remediation-activity-time" datetime="${escapeHtml(timestamp)}">${escapeHtml(remediationFormatDate(timestamp))}</time><span class="remediation-activity-copy"><strong>${escapeHtml(remediationActivityLabel(event))}</strong>${actor ? `<span>${escapeHtml(actor)}</span>` : ""}${event.comment ? `<span>${escapeHtml(event.comment)}</span>` : ""}</span></li>`;
  }).join("")}</ol>`;
}

function remediationValidationMarkup(finding = {}) {
  const status = remediationStatus(finding);
  if (status !== "PENDING_VALIDATION" && !finding.validated_at) return "";
  const occurrences = Math.max(Array.isArray(finding.__occurrences) ? finding.__occurrences.length : 0, findingOccurrenceCount(finding));
  const history = remediationHistory(finding);
  const lastActivity = [...history].reverse().find((event) => ["start", "request_validation", "status"].includes(String(event.action || "")));
  const lastScan = finding.last_seen || remediationFileContext(finding).last_scanned_at || latestReport?.timestamp || "";
  const pending = status === "PENDING_VALIDATION";
  return `<section class="remediation-drawer-section"><div class="remediation-validation-panel">
    <div class="remediation-section-head"><h4>${pending ? "Validation required" : "Validation recorded"}</h4>${pending ? '<span class="badge badge-sm badge-soft remediation-badge remediation-status" data-status="PENDING_VALIDATION">Pending</span>' : ""}</div>
    <p>${pending ? "Review current occurrence evidence before recording validation. This action does not trigger a new scan." : `Validated by ${escapeHtml(finding.validator || "an analyst")}.`}</p>
    <div class="remediation-validation-meta">
      <div><span>Last remediation activity</span><strong>${escapeHtml(remediationFormatDate(lastActivity?.timestamp || lastActivity?.created_at || ""))}</strong></div>
      <div><span>Last scan</span><strong>${escapeHtml(remediationFormatDate(lastScan))}</strong></div>
      <div><span>Current occurrences</span><strong>${occurrences.toLocaleString()}</strong></div>
      <div><span>Validated</span><strong>${escapeHtml(remediationFormatDate(finding.validated_at || ""))}</strong></div>
    </div>
    ${pending && remediationCanManage(finding) ? `<button type="button" class="btn btn-sm" data-remediation-action="validate" data-finding-id="${escapeHtml(finding.finding_id || "")}">Validate current evidence</button>` : ""}
  </div></section>`;
}

function remediationCanManage(finding = null) {
  return (currentRole === "admin" || currentRole === "analyst") && finding?.scope !== "historical";
}

function remediationDrawerActions(finding = {}) {
  if (!remediationCanManage(finding)) {
    const message = finding.scope === "historical" ? "Historical finding · workflow actions are read-only" : "Viewer access · workflow actions are read-only";
    return `<div class="remediation-drawer-actions"><span class="remediation-cell-secondary">${message}</span></div>`;
  }
  const actions = remediationActionSet(finding);
  const main = actions.filter((action) => !["risk_acceptance", "false_positive", "suppress"].includes(action));
  const exceptions = actions.filter((action) => ["risk_acceptance", "false_positive", "suppress"].includes(action));
  const findingId = escapeHtml(finding.finding_id || "");
  return `<div class="remediation-drawer-actions">
    ${main.map((action, index) => `<button type="button" class="btn btn-sm ${index === 0 ? "btn-primary" : ""}" data-remediation-action="${action}" data-finding-id="${findingId}">${escapeHtml(remediationActionLabel(action))}</button>`).join("")}
    ${exceptions.length ? `<details class="dropdown dropdown-end remediation-queue-menu"><summary class="btn btn-sm">More</summary><div class="dropdown-content">${exceptions.map((action) => `<button type="button" data-remediation-action="${action}" data-finding-id="${findingId}">${escapeHtml(remediationActionLabel(action))}</button>`).join("")}</div></details>` : ""}
  </div>`;
}

function renderRemediationDrawer(finding = selectedRemediationFinding) {
  if (!remediationDrawerBody || !finding) return;
  const file = remediationFileContext(finding);
  const path = String(finding.file?.path || file.path || "Not available");
  const severity = remediationSeverity(finding);
  const status = remediationStatus(finding);
  const sla = remediationSla(finding);
  const occurrences = Math.max(Array.isArray(finding.__occurrences) ? finding.__occurrences.length : 0, findingOccurrenceCount(finding));
  const recommendations = remediationRecommendations(finding);
  const factors = remediationRiskFactors(finding);
  const due = finding.sla_due || finding.due_date || "";
  const reason = finding.risk_reason || finding.explanation || finding.description || "No risk explanation is available for this finding.";
  remediationDrawerBody.innerHTML = `
    <header class="remediation-drawer-head">
      <div class="remediation-drawer-headline">${remediationBadge(finding)}<span class="remediation-finding-id" title="${escapeHtml(finding.finding_id || "")}">Finding ID: ${escapeHtml(finding.finding_id || "Not available")}</span></div>
      <div class="remediation-drawer-title-row"><h3 id="remediation-drawer-title">${escapeHtml(findingDisplayName(finding))}</h3><label for="remediation-drawer-toggle" class="btn btn-sm btn-circle btn-ghost remediation-drawer-close" aria-label="Close finding details">×</label></div>
      <div class="remediation-drawer-score-row"><span>Risk score <strong>${remediationRiskScore(finding)} / 100</strong></span>${remediationStatusBadge(finding)}</div>
    </header>
    <div class="remediation-drawer-content">
      <section class="remediation-drawer-section"><h4>Overview</h4><div class="remediation-overview-grid">
        ${remediationOverviewItem("Affected asset", remediationAsset(finding))}${remediationOverviewItem("File", remediationFileName(finding))}
        ${remediationOverviewItem("Full path", path, true, path)}${remediationOverviewItem("Data type", remediationDataType(finding))}
        ${remediationOverviewItem("Finding type", finding.technical_type || finding.type || finding.rule_id || "Not available")}
        ${remediationOverviewItem("Occurrences", occurrences.toLocaleString())}${remediationOverviewItem("Confidence", findingConfidenceLabel(finding))}
        ${remediationOverviewItem("Exposure", remediationExposure(finding))}${remediationOverviewItem("Framework", remediationFrameworkText(finding))}
        ${remediationOverviewItem("Last detected", remediationFormatDate(finding.last_seen || file.last_scanned_at || ""), true)}
      </div></section>
      <section class="remediation-drawer-section"><h4>Why this matters</h4><p>${escapeHtml(reason)}</p>${factors.length ? `<ul class="remediation-risk-list">${factors.map((factor) => `<li>${escapeHtml(factor)}</li>`).join("")}</ul>` : ""}</section>
      <section class="remediation-drawer-section remediation-recommendation"><h4>Recommended remediation</h4>${recommendations.length ? `<ol class="remediation-recommendation-list">${recommendations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ol>` : '<p>No recommendation is available for this finding.</p>'}</section>
      <section class="remediation-drawer-section"><h4>Workflow progress</h4>${remediationWorkflowMarkup(finding)}</section>
      <section class="remediation-drawer-section"><h4>Ownership</h4><div class="remediation-owner-grid">
        <div class="remediation-owner-item"><span>Assigned owner</span><strong>${escapeHtml(remediationOwner(finding))}</strong></div>
        ${finding.team ? `<div class="remediation-owner-item"><span>Team</span><strong>${escapeHtml(finding.team)}</strong></div>` : ""}
        <div class="remediation-owner-item"><span>Due date</span><strong>${escapeHtml(remediationFormatDate(due, { dateOnly: true }))}</strong></div>
        <div class="remediation-owner-item" data-overdue="${sla.category === "OVERDUE"}"><span>SLA</span><strong>${escapeHtml(sla.category === "OVERDUE" ? `Overdue by ${sla.label}` : `${sla.label} ${sla.detail}`)}</strong></div>
      </div></section>
      ${remediationValidationMarkup(finding)}
      <section class="remediation-drawer-section"><div class="remediation-section-head"><h4>Activity</h4><span class="remediation-cell-secondary">${remediationHistory(finding).length} events</span></div>${remediationActivityMarkup(finding)}
        ${remediationCanManage(finding) ? `<form class="remediation-comment-form" data-remediation-comment-form><input class="input input-sm" name="comment" maxlength="1000" required placeholder="Add comment…" aria-label="Add comment" /><button type="submit" class="btn btn-sm">Send</button></form>` : ""}
      </section>
    </div>${remediationDrawerActions(finding)}`;
}

async function openRemediationFinding(findingId, { openDrawer = true } = {}) {
  const finding = remediationFindings.find((item) => String(item.finding_id || "") === String(findingId || ""));
  if (!finding || !remediationDrawerBody) return;
  selectedRemediationFindingId = finding.finding_id;
  selectedRemediationFinding = finding;
  if (openDrawer && remediationDrawerToggle) remediationDrawerToggle.checked = true;
  remediationDrawerBody.innerHTML = remediationDrawerLoadingMarkup();
  renderRemediationWorkspace();
  const context = captureTenantContext();
  const requestId = ++remediationDetailRequest;
  const encodedId = encodeURIComponent(finding.finding_id);
  try {
    const [detail, history, occurrences] = await Promise.all([
      api(`/api/findings/${encodedId}`, null, "GET"),
      api(`/api/findings/${encodedId}/history`, null, "GET").catch(() => ({ history: finding.status_history || [] })),
      api(`/api/findings/${encodedId}/occurrences`, null, "GET").catch(() => ({ occurrences: finding.occurrences || [] })),
    ]);
    if (!isCurrentTenantContext(context) || requestId !== remediationDetailRequest) return;
    selectedRemediationFinding = {
      ...finding,
      ...(detail?.finding || {}),
      __detail: detail?.detail || {},
      __history: history?.history || [],
      __occurrences: occurrences?.occurrences || [],
    };
    renderRemediationDrawer(selectedRemediationFinding);
  } catch (error) {
    if (!isCurrentTenantContext(context) || requestId !== remediationDetailRequest) return;
    remediationDrawerBody.innerHTML = `<div class="remediation-drawer-empty"><strong>Unable to load finding details</strong><span>Please try again.</span><button type="button" class="btn btn-sm" data-remediation-open="${escapeHtml(finding.finding_id)}">Retry</button></div>`;
  }
}

function remediationFindingById(findingId = "") {
  if (selectedRemediationFinding?.finding_id === findingId) return selectedRemediationFinding;
  return remediationFindings.find((finding) => finding.finding_id === findingId) || null;
}

function remediationTomorrow() {
  const date = new Date();
  date.setDate(date.getDate() + 1);
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, "0")}-${String(date.getDate()).padStart(2, "0")}`;
}

function remediationShowModal(modal) {
  if (!modal) return;
  modal.querySelectorAll("[data-remediation-modal-error]").forEach((element) => { element.textContent = ""; });
  if (typeof modal.showModal === "function") modal.showModal();
  else modal.classList.add("modal-open");
}

function closeRemediationModal(modal) {
  if (!modal) return;
  if (typeof modal.close === "function") modal.close();
  else modal.classList.remove("modal-open");
}

function openRemediationAction(action, findingId) {
  const finding = remediationFindingById(findingId);
  if (!finding || !remediationCanManage(finding) || !remediationActionSet(finding).includes(action)) return;
  remediationPendingAction = { action, findingId };
  if (action === "assign") {
    const modal = document.querySelector("#remediation-assignment-modal");
    const form = document.querySelector("#remediation-assignment-form");
    form?.reset();
    const owner = document.querySelector("#remediation-assignment-owner");
    const due = document.querySelector("#remediation-assignment-due");
    if (owner) owner.value = remediationOwner(finding) === "Unassigned" ? "" : remediationOwner(finding);
    if (due) due.value = String(finding.sla_due || finding.due_date || "").slice(0, 10);
    remediationShowModal(modal);
    owner?.focus();
    return;
  }
  if (action === "risk_acceptance") {
    const modal = document.querySelector("#remediation-risk-modal");
    const form = document.querySelector("#remediation-risk-form");
    form?.reset();
    const expiration = form?.elements.namedItem("expiration_date");
    const review = form?.elements.namedItem("review_date");
    const affected = form?.elements.namedItem("affected_assets");
    const volume = form?.elements.namedItem("accepted_volume");
    if (expiration) expiration.min = remediationTomorrow();
    if (review) review.min = remediationTomorrow();
    if (affected) affected.value = remediationAsset(finding);
    if (volume) volume.value = String(Math.max(Array.isArray(finding.__occurrences) ? finding.__occurrences.length : 0, findingOccurrenceCount(finding)));
    remediationShowModal(modal);
    return;
  }
  if (action === "false_positive") {
    const modal = document.querySelector("#remediation-false-positive-modal");
    document.querySelector("#remediation-false-positive-form")?.reset();
    remediationShowModal(modal);
    return;
  }
  if (action === "suppress") {
    const modal = document.querySelector("#remediation-suppression-modal");
    const form = document.querySelector("#remediation-suppression-form");
    form?.reset();
    const expiration = form?.elements.namedItem("expiration_date");
    if (expiration) expiration.min = remediationTomorrow();
    remediationShowModal(modal);
    return;
  }
  const configuration = {
    confirm: ["Confirm finding", "Record that triage confirmed this detection.", "Confirm"],
    start: ["Start remediation", "Move this assigned finding into active remediation.", "Start remediation"],
    request_validation: ["Request validation", "Move this finding to pending validation for evidence review.", "Request validation"],
    validate: ["Validate current evidence", "Record validation against the current evidence. This does not launch or simulate a re-scan.", "Record validation"],
    resolve: ["Resolve finding", "Record the resolution after validation. A resolution note is required.", "Resolve"],
    reopen: ["Reopen finding", "Return this finding to the active remediation queue.", "Reopen"],
  }[action];
  if (!configuration) return;
  const modal = document.querySelector("#remediation-action-modal");
  const form = document.querySelector("#remediation-action-form");
  form?.reset();
  document.querySelector("#remediation-action-title").textContent = configuration[0];
  document.querySelector("#remediation-action-description").textContent = configuration[1];
  document.querySelector("#remediation-action-submit").textContent = configuration[2];
  const comment = document.querySelector("#remediation-action-comment");
  if (comment) {
    comment.required = action === "resolve";
    comment.placeholder = action === "resolve" ? "Describe how the finding was resolved" : "Optional workflow note";
  }
  remediationShowModal(modal);
}

function remediationModalMessage(form, message = "") {
  const element = form?.querySelector("[data-remediation-modal-error]");
  if (element) element.textContent = message;
}

function remediationSetFormBusy(form, busy) {
  form?.querySelectorAll("button, input, select, textarea").forEach((element) => { element.disabled = busy; });
}

async function runRemediationLifecycle(action, findingId, payload = {}, form = null) {
  const finding = remediationFindingById(findingId);
  if (!finding || !remediationActionSet(finding).includes(action)) {
    remediationModalMessage(form, "This action is no longer valid for the finding's current status.");
    return;
  }
  const encodedId = encodeURIComponent(findingId);
  const requests = {
    confirm: [`/api/findings/${encodedId}/status`, "PATCH", { ...payload, status: "CONFIRMED" }],
    start: [`/api/findings/${encodedId}/status`, "PATCH", { ...payload, status: "IN_PROGRESS" }],
    request_validation: [`/api/findings/${encodedId}/status`, "PATCH", { ...payload, status: "PENDING_VALIDATION" }],
    validate: [`/api/findings/${encodedId}/validate`, "POST", payload],
    resolve: [`/api/findings/${encodedId}/resolve`, "POST", { ...payload, resolution: payload.resolution || payload.comment }],
    reopen: [`/api/findings/${encodedId}/reopen`, "POST", payload],
    assign: [`/api/findings/${encodedId}/assign`, "POST", payload],
    risk_acceptance: [`/api/findings/${encodedId}/risk-acceptance`, "POST", payload],
    false_positive: [`/api/findings/${encodedId}/false-positive`, "POST", payload],
    suppress: [`/api/findings/${encodedId}/suppress`, "POST", payload],
  };
  const request = requests[action];
  if (!request) return;
  remediationSetFormBusy(form, true);
  remediationModalMessage(form, "");
  try {
    const data = await api(request[0], request[2], request[1]);
    const updated = data?.finding;
    if (updated) remediationFindings = remediationFindings.map((item) => item.finding_id === findingId ? { ...item, ...updated } : item);
    renderRemediationWorkspace();
    closeRemediationModal(form?.closest("dialog"));
    showToast("Finding updated", `${remediationActionLabel(action)} completed.`, "success");
    if (remediationDrawerToggle?.checked) await openRemediationFinding(findingId, { openDrawer: false });
    await loadRemediationFindings({ showLoading: false, resetPage: true });
  } catch (error) {
    remediationModalMessage(form, String(error.message || "Unable to update finding").replace(/^\d+:\s*/, ""));
  } finally {
    remediationSetFormBusy(form, false);
  }
}

async function addRemediationComment(form) {
  const findingId = selectedRemediationFindingId;
  const input = form?.elements.namedItem("comment");
  const comment = String(input?.value || "").trim();
  if (!findingId || !comment) return;
  remediationSetFormBusy(form, true);
  try {
    await api(`/api/findings/${encodeURIComponent(findingId)}/comment`, { comment }, "POST");
    if (input) input.value = "";
    showToast("Comment added", "The finding activity has been updated.", "success");
    await openRemediationFinding(findingId, { openDrawer: false });
  } catch (error) {
    showToast("Comment not added", String(error.message || "Please try again").replace(/^\d+:\s*/, ""), "danger");
  } finally {
    remediationSetFormBusy(form, false);
  }
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

function reportText(value, fallback = "-") {
  if (Array.isArray(value)) {
    const joined = value.filter(Boolean).join("; ");
    return joined || fallback;
  }
  const text = String(value ?? "").trim();
  return text || fallback;
}

const UNIFIED_PDF_TEMPLATE_ID = "sentro-dspm-unified-v1";

async function exportPdf() {
  if (!activeReportFileCount()) {
    setStatus("Run a scan before filing a PDF report.");
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
      body: JSON.stringify({
        scan_id: latestReport?.scan_id || null,
        severities: [...(reportSeverities() || [])],
      }),
    });
    if (!response.ok) {
      throw new Error(await readErrorMessage(response));
    }
    const artifact = await response.json();
    if (artifact.template_id !== UNIFIED_PDF_TEMPLATE_ID || !artifact.artifact_path) {
      throw new Error("The report service returned an unsupported template.");
    }
    // Fetch with the token in a header, then show the bytes from a same-origin
    // blob. A top-level navigation cannot carry a header, which is the only
    // reason the signed token was ever in the query string - and a query string
    // is written to every access log between here and the server.
    reportWindow.location.replace(await artifactBlobUrl(artifact));
    showToast("Report filed", `${reportType().label} is open as a PDF artifact.`, "success");
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unable to create the PDF report.";
    const status = reportWindow.document.getElementById("composer-status");
    if (status) status.textContent = message;
    setStatus(message);
  }
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
  const context = captureTenantContext();
  const [history, dashboard, estateFacetResponse] = await Promise.all([
    api("/api/history", null, "GET"),
    api("/api/executive-dashboard", null, "GET"),
    api("/api/inventory/facets", null, "GET").catch(() => null),
  ]);
  if (!isCurrentTenantContext(context, history)
      || !isCurrentTenantContext(context, dashboard)
      || (estateFacetResponse && !isCurrentTenantContext(context, estateFacetResponse))) return;
  loadScanProfiles(context).catch(() => {});
  latestDashboard = dashboard;
  estateFacets = estateFacetResponse;
  estateSummary = estateFacetResponse ? facetsToEstateSummary(estateFacetResponse) : null;
  // The boot path sets the facets directly rather than through
  // refreshEstateSummary(), which is where Top risks learns the class names it
  // needs to count. Both entry points ask; the second one returns the cache.
  refreshRiskCategoryCounts().catch(() => {});
  renderHistory(history.history || []);
  // The audit trail lives on this page now, so this page fetches it. It is
  // admin-only at the API and loadAudit() returns early for anyone else.
  loadAudit().catch(() => {});
  renderExecutiveExperience();
  loadTenants().catch(() => {});

  // Everything below feeds panels on other tabs. Waiting for it before the
  // first paint cost two seconds of a dashboard that was already answerable.
  restoreLatestSavedReport(history.history || [], context).then(() => {
    if (!isCurrentTenantContext(context)) return;
    renderExecutiveExperience();
  }).catch(() => {});
}

// Rows already on screen re-render when the comparison lands, so the changed
// and duplicate flags appear without anyone reloading.
function loadHashFlagsForFindings() {
  const context = captureTenantContext();
  loadHashComparison().then((hashComparison) => {
    if (!hashComparison || !isCurrentTenantContext(context, hashComparison)) return;
    latestHashComparison = hashComparison;
    const page = currentInventoryPage();
    if (page) renderRows(page.items, { serverPage: page });
    else if (latestFiles.length) renderRows(latestFiles);
    renderFindingsWorkspace();
  }).catch(() => {});
}

async function loadHashComparison() {
  try {
    return await api("/api/history/hash-changes", null, "GET");
  } catch {
    return null;
  }
}

async function refreshHashComparison() {
  const context = captureTenantContext();
  const [dashboard, hashComparison] = await Promise.all([
    api("/api/executive-dashboard", null, "GET").catch(() => latestDashboard),
    loadHashComparison(),
  ]);
  if (!isCurrentTenantContext(context, dashboard)
      || (hashComparison && !isCurrentTenantContext(context, hashComparison))) return;
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

async function restoreLatestSavedReport(historyItems = latestHistoryItems, context = captureTenantContext()) {
  if (!isCurrentTenantContext(context)) return;
  if (latestReport?.scan_id || !Array.isArray(historyItems) || !historyItems.length) {
    return;
  }
  const candidates = [...historyItems].reverse();
  for (const item of candidates) {
    if (!isCurrentTenantContext(context)) return;
    const scanId = item?.scan_id;
    if (!scanId) continue;
    try {
      const report = await loadSavedReportById(scanId) || {};
      if (!isCurrentTenantContext(context)) return;
      if (!activeCompactReportCount(report) || isDemoSampleReport(report)) {
        continue;
      }
      const scanKind = report.endpoint ? "endpoint" : "file-server";
      applyScanReport(report, scanKind, { refreshEstate: false });
      scanMeta.textContent = `Restored ${activeCompactReportCount(report)} files from saved scan ${scanId}.`;
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

// A tenant's name, and the id under it only when the two differ. Compared
// without case because the seeded tenant is "Default" over "default", which is
// the same string printed twice as far as a reader is concerned.
function tenantLabel(tenant = {}) {
  return String(tenant.display_name || tenant.tenant_id || "");
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
            <strong>${escapeHtml(tenantLabel(tenant))}</strong>
            ${tenantLabel(tenant).toLowerCase() === String(tenant.tenant_id || "").toLowerCase()
              ? ""
              : `<div class="subtext">${escapeHtml(tenant.tenant_id)}</div>`}
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

function publishTenantDashboardAnalytics() {
  // sentro-fx owns only presentation. Its previous independent fetches did
  // not carry X-Tenant-ID, so an MSSP admin's widgets stayed on the token's
  // home tenant. This snapshot is emitted only after the app's guarded,
  // tenant-scoped loaders accept a response.
  const snapshot = {
    tenantId: currentTenant,
    tenantVersion: tenantContextVersion,
    history: [...latestHistoryItems],
    audit: isAdminRole() ? [...latestAuditEvents] : [],
    auditAvailable: isAdminRole(),
  };
  window.__sentroTenantDashboard = snapshot;
  window.dispatchEvent(new CustomEvent("sentro:tenant-dashboard", { detail: snapshot }));
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

// ---- History & audit -----------------------------------------------------
// The page answers one question: what has happened in this workspace, and is
// the estate getting better or worse? History is the scans; audit is the
// actions taken. It had the first half, showing absolute counts and a raw scan
// id, which makes a reader do arithmetic to learn anything.

const HISTORY_COLUMNS = [
  { key: "when", label: "When", value: (row) => row.at },
  { key: "scan", label: "Scan", value: (row) => (row.name || "Unnamed run").toLowerCase(), text: true },
  { key: "source", label: "Source", value: (row) => row.source.toLowerCase(), text: true },
  { key: "files", label: "Files", value: (row) => row.files, numeric: true },
  { key: "critical", label: "Critical", value: (row) => row.critical, numeric: true },
  { key: "high", label: "High", value: (row) => row.high, numeric: true },
  { key: "medium", label: "Medium", value: (row) => row.medium, numeric: true },
  { key: "low", label: "Low", value: (row) => row.low, numeric: true },
  // Sorts by the size of the move, so "what changed most" is one click.
  { key: "change", label: "Change", value: (row) => (row.change ? row.change.serious : Number.NEGATIVE_INFINITY), numeric: true },
];

const AUDIT_COLUMNS = [
  { key: "when", label: "When", value: (row) => row.at },
  { key: "actor", label: "Who", value: (row) => row.actor.toLowerCase(), text: true },
  { key: "what", label: "What happened", value: (row) => row.label.toLowerCase(), text: true },
];

let historySort = { key: "when", dir: -1 };
let auditSort = { key: "when", dir: -1 };

// Two scans are comparable when the smaller covered at least 60% of the
// larger's files - the same rule and the same constant the dashboard's posture
// delta uses, so the two never disagree. Without it the 2-file endpoint check
// that follows a 539-file sweep reads as "174 critical resolved", an
// improvement that never happened.
function historyComparableIndex(items, index) {
  const files = Number(items[index]?.summary?.total_files || 0);
  if (!files) return -1;
  for (let earlier = index - 1; earlier >= 0; earlier -= 1) {
    const before = Number(items[earlier]?.summary?.total_files || 0);
    if (!before) continue;
    if (Math.min(before, files) / Math.max(before, files) >= POSTURE_COMPARABLE_RATIO) return earlier;
  }
  return -1;
}

function historySeverityCounts(summary = {}) {
  return {
    critical: Number(summary.critical || 0),
    high: Number(summary.high || 0),
    medium: Number(summary.medium || 0),
    low: Number(summary.low || 0),
  };
}

function buildHistoryRows(items) {
  return items.map((item, index) => {
    const summary = item.summary || {};
    const counts = historySeverityCounts(summary);
    const serious = counts.critical + counts.high;
    const against = historyComparableIndex(items, index);
    let change = null;
    if (against >= 0) {
      const before = historySeverityCounts(items[against].summary || {});
      const moved = REPORT_SEVERITY_ORDER
        .map((level) => [severityLabel(level), counts[level.toLowerCase()] - before[level.toLowerCase()]])
        .filter(([, delta]) => delta !== 0)
        .map(([label, delta]) => `${label} ${delta > 0 ? "+" : "−"}${Math.abs(delta)}`);
      change = {
        serious: serious - (before.critical + before.high),
        detail: moved.length ? moved.join(", ") : "Nothing moved",
        against: historyScanName(items[against]),
      };
    }
    return {
      ...counts,
      serious,
      change,
      at: Date.parse(getItemTimestampValue(item)) || 0,
      when: getItemTimestampValue(item),
      name: historyScanName(item),
      source: historySourceLabel(item.source),
      files: Number(summary.total_files || 0),
      withFindings: Number(summary.sensitive_files || 0),
      scanId: String(item.scan_id || ""),
    };
  });
}

// A scan id is twenty digits of timestamp. It identifies a run; it does not
// name one, and the old table put it in the column headed "Scan".
function historyScanName(item = {}) {
  return String(item.scan_label || "").trim();
}

// A scan id is a twenty-digit timestamp. The last six identify a run inside
// its day, which is what somebody reads out to support.
function shortScanId(scanId) {
  const value = String(scanId || "");
  return value.length > 6 ? `#${value.slice(-6)}` : value;
}

function historySourceLabel(source) {
  const value = String(source || "").trim();
  return {
    smb: "File server",
    local: "Local disk",
    "endpoint-winrm": "Endpoint",
    endpoint: "Endpoint",
  }[value] || (value ? value.charAt(0).toUpperCase() + value.slice(1) : "");
}

function sortTableRows(rows, sort, columns) {
  const column = columns.find((item) => item.key === sort.key) || columns[0];
  return [...rows].sort((a, b) => {
    const left = column.value(a);
    const right = column.value(b);
    if (column.text) return String(left).localeCompare(String(right)) * sort.dir;
    return (Number(left) - Number(right)) * sort.dir;
  });
}

function sortableHeader(column, sort) {
  const active = sort.key === column.key;
  const ariaSort = active ? (sort.dir === 1 ? "ascending" : "descending") : "none";
  const numeric = column.numeric ? ' class="is-numeric"' : "";
  return `<th data-sort="${column.key}" aria-sort="${ariaSort}"${numeric}>${escapeHtml(column.label)}</th>`;
}

// Clicking a column sorts by it; clicking the one already sorted turns it
// around. A number column opens biggest-first, a name column A-to-Z, because
// that is the answer each is usually asked for.
function toggleSort(sort, key, columns) {
  const column = columns.find((item) => item.key === key);
  if (!column) return sort;
  if (sort.key === key) return { key, dir: sort.dir * -1 };
  return { key, dir: column.text ? 1 : -1 };
}

function renderHistory(items) {
  latestHistoryItems = items || [];
  publishTenantDashboardAnalytics();
  renderInventoryScanOptions();
  const visibleItems = filterHistoryItems(latestHistoryItems);
  updateRangeStatus(historyRange, visibleItems.length, latestHistoryItems.length);
  renderHistoryContext(visibleItems);
  renderHistoryTable(visibleItems);
  syncAuditVisibility();
}

// Replaces four cards that read Posture score / Tenant / Reports / Open
// critical. Tenant repeated the sidebar, and the other three are the
// dashboard's job; this says what the table below covers, which is the one
// thing the table cannot say about itself.
function renderHistoryContext(visibleItems) {
  if (!historyContext) return;
  if (!visibleItems.length) {
    historyContext.textContent = latestHistoryItems.length
      ? "No scans in this range."
      : "No scans saved for this workspace yet.";
    return;
  }
  const first = getItemTimestampValue(visibleItems[0]);
  const last = getItemTimestampValue(visibleItems.at(-1));
  const files = visibleItems.reduce((total, item) => total + Number(item.summary?.total_files || 0), 0);
  historyContext.textContent = [
    `${visibleItems.length} ${visibleItems.length === 1 ? "scan" : "scans"}`,
    visibleItems.length > 1 ? `${formatReportDate(first)} to ${formatReportDate(last)}` : formatReportDate(last),
    `${files.toLocaleString()} files analysed in total`,
  ].join(" · ");
}

function renderHistoryTable(visibleItems = filterHistoryItems(latestHistoryItems)) {
  if (!historyBody) return;
  if (historyHead) {
    historyHead.innerHTML = `<tr>${HISTORY_COLUMNS.map((column) => sortableHeader(column, historySort)).join("")}</tr>`;
  }
  const span = HISTORY_COLUMNS.length;
  if (!latestHistoryItems.length) {
    historyBody.innerHTML = `<tr><td colspan="${span}" class="empty">No scans saved yet. Run one from the Scan page and it will be listed here.</td></tr>`;
    return;
  }
  if (!visibleItems.length) {
    historyBody.innerHTML = `<tr><td colspan="${span}" class="empty">No scans in the selected range. Widen it to see more.</td></tr>`;
    return;
  }
  // Built in chronological order so each row can look backwards, then sorted.
  const rows = sortTableRows(buildHistoryRows(visibleItems), historySort, HISTORY_COLUMNS);
  historyBody.innerHTML = rows.map((row) => `
    <tr>
      <td>
        <span class="history-when">${escapeHtml(getFriendlyTimestamp(row.when))}</span>
        <span class="history-ago">${escapeHtml(relativeAge(row.when))}</span>
      </td>
      <td>
        <span class="history-name"${row.name ? "" : ' data-unnamed="true"'}>${escapeHtml(row.name || "Unnamed run")}</span>
        <span class="history-sub" title="${escapeHtml(row.scanId)}">${escapeHtml(shortScanId(row.scanId))}</span>
      </td>
      <td>${escapeHtml(row.source)}</td>
      <td class="is-numeric">${row.files.toLocaleString()}<span class="history-sub">${row.withFindings.toLocaleString()} with findings</span></td>
      ${["critical", "high", "medium", "low"].map((level) => `
        <td class="is-numeric"><span class="history-count" data-severity="${level.toUpperCase()}"${row[level] ? "" : ' data-zero="true"'}>${row[level].toLocaleString()}</span></td>`).join("")}
      <td class="is-numeric">${historyChangeCell(row)}</td>
    </tr>`).join("");
}

// The one column that turns a list of counts into a history: how the serious
// findings - critical and high together - moved against the last scan that
// covered comparable ground.
function historyChangeCell(row) {
  if (!row.change) {
    return '<span class="history-change" data-move="none" title="No earlier scan covered comparable ground, so there is nothing to compare against.">Baseline</span>';
  }
  const moved = row.change.serious;
  const title = `${row.change.detail} · against ${row.change.against}`;
  if (!moved) {
    return `<span class="history-change" data-move="flat" title="${escapeHtml(title)}">No change</span>`;
  }
  const arrow = moved > 0 ? "▲" : "▼";
  const sign = moved > 0 ? "+" : "−";
  return `<span class="history-change" data-move="${moved > 0 ? "up" : "down"}" title="${escapeHtml(title)}">${arrow} ${sign}${Math.abs(moved).toLocaleString()}</span>`;
}

function relativeAge(value) {
  const at = Date.parse(value);
  if (!at) return "";
  const days = Math.floor((Date.now() - at) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  const months = Math.round(days / 30);
  return months === 1 ? "a month ago" : `${months} months ago`;
}

historyHead?.addEventListener("click", (event) => {
  const header = event.target.closest("th[data-sort]");
  if (!header) return;
  historySort = toggleSort(historySort, header.dataset.sort, HISTORY_COLUMNS);
  renderHistoryTable();
});

async function loadAudit() {
  if (!accessToken || !isAdminRole()) {
    return;
  }
  const context = captureTenantContext();
  try {
    const data = await api("/api/audit", null, "GET");
    if (!isCurrentTenantContext(context, data)) return;
    renderAudit(data.events || []);
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    auditBody.innerHTML = `<tr><td colspan="4" class="empty">Audit unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

// Every action string the product records, in the words an operator would use
// for it. The raw strings are namespaced identifiers - "scan_profile.saved",
// "user.role_updated" - which are precise and unreadable; the table used to
// print them, and a JSON blob beside them.
const AUDIT_ACTIONS = {
  "auth.login": "Signed in",
  "auth.login_failed": "Sign-in refused",
  "auth.login_blocked": "Sign-in blocked after repeated failures",
  "auth.logout": "Signed out",
  "auth.refreshed": "Renewed a session",
  "auth.refresh_replayed": "Session token replayed - all of that session's sign-ins ended",
  "compliance_keywords.exported": "Exported the keyword library",
  "nist.catalog.exported": "Exported the NIST catalog",
  "api_key.created": "Created an API key",
  "suppression.created": "Wrote a suppression rule",
  "suppression.updated": "Changed a suppression rule",
  "suppression.deleted": "Removed a suppression rule",
  "api_key.revoked": "Revoked an API key",
  "connection.test": "Tested a file server connection",
  "credential.stored": "Stored a credential",
  "endpoint.connection.test": "Tested an endpoint connection",
  "endpoint.access.check": "Checked what an endpoint credential can reach",
  "endpoint.scan.queued": "Queued an endpoint scan",
  "endpoint.scan.completed": "Finished an endpoint scan",
  "scan.queued": "Queued a scan",
  "scan.completed": "Finished a scan",
  "scan.cancel": "Cancelled a scan",
  "scan.resumed": "Resumed a scan interrupted by a restart",
  "scan.published": "Queued a scan for the workers",
  "scan.scheduled": "Started a scheduled scan",
  "schedule.created": "Created a scan schedule",
  "schedule.updated": "Changed a scan schedule",
  "schedule.deleted": "Deleted a scan schedule",
  "scan.queue_unavailable": "Ran a scan here because the work queue was unreachable",
  "scan.secondary_operations_degraded": "Scan finished with a degraded step",
  "scan_profile.saved": "Saved a scan profile",
  "scan_profile.deleted": "Deleted a scan profile",
  "settings.feature_toggled": "Changed a feature setting",
  "nist.catalog.imported": "Imported a NIST catalogue",
  "nist.catalog.validated": "Validated a NIST catalogue",
  "nist.catalog.activated": "Activated a NIST catalogue",
  "nist.catalog.rollback": "Rolled back a NIST catalogue",
  "db.activity.viewed": "Viewed database activity",
  "db.slow_queries.viewed": "Viewed slow queries",
  "tenant.created": "Created a workspace",
  "tenant.deleted": "Deleted a workspace",
  "tenant.invite_created": "Invited someone",
  "tenant.invite_revoked": "Revoked an invitation",
  "tenant.registration_code_rotated": "Rotated the registration code",
  "user.created": "Added a user",
  "user.deleted": "Removed a user",
  "user.registered": "Registered an account",
  "user.role_updated": "Changed a user's role",
  "user.status_updated": "Changed a user's status",
  "user.password_changed": "Changed a password",
  "user.password_reset": "Reset a password",
  "user.profile_updated": "Updated a profile",
  "user.avatar_updated": "Updated an avatar",
  "compliance_keywords.imported": "Imported a compliance keyword set",
  "demo_data.generated": "Generated demo data",
  "endpoint.winrm.activate": "Enabled WinRM on an endpoint",
  "endpoint.winrm.activate_local": "Enabled WinRM locally",
  "endpoint.winrm.repair": "Repaired an endpoint's WinRM setup",
  "finding.workflow_updated": "Moved a finding through its workflow",
  "inventory.export.started": "Started an inventory export",
  "tenant.legal_hold.set": "Changed the legal hold",
};

// An unmapped action still reads as a sentence rather than as an identifier.
function auditActionLabel(action) {
  const key = String(action || "").trim();
  if (AUDIT_ACTIONS[key]) return AUDIT_ACTIONS[key];
  if (!key) return "Unrecorded action";
  const words = key.replace(/[._]/g, " ").trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}

// Which half of the product the action belongs to, so the trail can be read by
// area without a filter for it.
function auditActionArea(action) {
  const head = String(action || "").split(".")[0];
  return {
    auth: "Access", user: "Access", api_key: "Access", tenant: "Access",
    scan: "Scanning", scan_profile: "Scanning", endpoint: "Scanning",
    connection: "Scanning", credential: "Scanning",
    nist: "Compliance", settings: "Settings", db: "Settings",
  }[head] || "Other";
}

// The detail is a small object - a scan id, a host, a list of warnings. It was
// printed as JSON.stringify inside a <code>. These are the same facts as
// labelled pairs, with anything long left to the title.
function auditDetailPairs(detail) {
  if (!detail || typeof detail !== "object") return [];
  return Object.entries(detail).map(([key, value]) => {
    const name = key.replace(/[._]/g, " ");
    if (Array.isArray(value)) {
      const first = value[0];
      const summary = value.length === 1 && first && typeof first === "object"
        ? Object.values(first).map((entry) => String(entry)).join(" · ")
        : `${value.length} ${value.length === 1 ? "entry" : "entries"}`;
      return [name, summary];
    }
    if (value && typeof value === "object") return [name, Object.keys(value).length ? "details" : ""];
    return [name, String(value ?? "")];
  }).filter(([, value]) => value !== "");
}

function buildAuditRows(events) {
  return events.map((event) => ({
    at: Date.parse(getItemTimestampValue(event)) || 0,
    when: getItemTimestampValue(event),
    actor: String(event.actor || "").trim() || "system",
    action: String(event.action || ""),
    label: auditActionLabel(event.action),
    area: auditActionArea(event.action),
    pairs: auditDetailPairs(event.detail),
  }));
}

function renderAudit(events) {
  latestAuditEvents = events || [];
  publishTenantDashboardAnalytics();
  const visibleEvents = filterTimedItems(latestAuditEvents, auditRange, auditFrom, auditTo);
  updateRangeStatus(auditRange, visibleEvents.length, latestAuditEvents.length);
  renderAuditTable(visibleEvents);
}

function renderAuditTable(visibleEvents = filterTimedItems(latestAuditEvents, auditRange, auditFrom, auditTo)) {
  if (!auditBody) return;
  if (auditHead) {
    auditHead.innerHTML = `<tr>${AUDIT_COLUMNS.map((column) => sortableHeader(column, auditSort)).join("")}<th>Details</th></tr>`;
  }
  const span = AUDIT_COLUMNS.length + 1;
  if (!latestAuditEvents.length) {
    auditBody.innerHTML = `<tr><td colspan="${span}" class="empty">Nothing has been recorded for this workspace yet.</td></tr>`;
    return;
  }
  if (!visibleEvents.length) {
    auditBody.innerHTML = `<tr><td colspan="${span}" class="empty">No events in the selected range. Widen it to see more.</td></tr>`;
    return;
  }
  const rows = sortTableRows(buildAuditRows(visibleEvents), auditSort, AUDIT_COLUMNS);
  auditBody.innerHTML = rows.map((row) => `
    <tr>
      <td>
        <span class="history-when">${escapeHtml(getFriendlyTimestamp(row.when))}</span>
        <span class="history-ago">${escapeHtml(relativeAge(row.when))}</span>
      </td>
      <td><span class="audit-actor">${escapeHtml(row.actor)}</span></td>
      <td>
        <span class="audit-label">${escapeHtml(row.label)}</span>
        <span class="audit-area" data-area="${escapeHtml(row.area)}">${escapeHtml(row.area)}</span>
      </td>
      <td>${row.pairs.length
        ? `<span class="audit-detail">${row.pairs.map(([name, value]) =>
            `<span class="audit-pair"><span>${escapeHtml(name)}</span><b title="${escapeHtml(value)}">${escapeHtml(value)}</b></span>`).join("")}</span>`
        : '<span class="audit-detail is-empty">—</span>'}</td>
    </tr>`).join("");
}

auditHead?.addEventListener("click", (event) => {
  const header = event.target.closest("th[data-sort]");
  if (!header) return;
  auditSort = toggleSort(auditSort, header.dataset.sort, AUDIT_COLUMNS);
  renderAuditTable();
});

// The trail is admin-only at the API, so a viewer is told why the section is
// not there rather than being shown a table that will never fill.
function syncAuditVisibility() {
  if (!auditSection) return;
  auditSection.hidden = !isAdminRole();
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
            ${user.full_name && user.full_name !== user.username
              ? `<div class="subtext">${escapeHtml(user.full_name)}</div>`
              : ""}
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
    setStatus(`Scan completed in ${formatElapsedTime(lastScanElapsedSeconds)}`, "ok", diagnostics);
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
  localWinrmStatus.textContent = "Checking WinRM on this server only. Credentials for the machine you want to scan go below.";
  try {
    requireAuth();
    const result = await api("/api/endpoint/activate-local-winrm", readLocalWinrmPayload());
    localWinrmStatus.textContent = result.activated
      ? "WinRM is ready on this server. Enter the local-admin credential for the machine you want to scan, below."
      : `WinRM on this server needs attention: ${result.message}`;
    showToast(result.activated ? "WinRM ready on this server" : "WinRM needs attention", result.message || "", result.activated ? "success" : "danger");
  } catch (error) {
    localWinrmStatus.textContent = `Couldn't prepare WinRM on this server. ${error.message}`;
    showToast("WinRM setup failed", error.message, "danger");
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
    const how = describeEndpointTransport(result.transport);
    endpointStatus.textContent = result.connected
      ? `Connected to ${result.computer || result.host} as ${result.user || "remote user"}${how ? ` over ${how}` : ""}.`
      : `Connection failed: ${result.message}`;
    showToast(result.connected ? "Endpoint connected" : "Endpoint test failed", result.message || result.host, result.connected ? "success" : "danger");
  } catch (error) {
    endpointStatus.textContent = `Endpoint test failed: ${error.message}`;
    showToast("Endpoint test failed", error.message, "danger");
  } finally {
    setBusy(false);
  }
});

// Scanning an endpoint needs no administrator, but two Windows defaults make a
// privileged account the easy path: only local Administrators may open a WinRM
// session, and one account cannot read another's profile folder. Both are
// grantable - and this is how an operator confirms a least-privilege account is
// enough without finding out half way through a scan.
if (endpointAccessBtn) endpointAccessBtn.addEventListener("click", async () => {
  setBusy(true);
  endpointStatus.textContent = "Checking what this credential can reach...";
  try {
    requireAuth();
    const payload = await ensureEndpointCredential(readEndpointConnectionPayload());
    const result = await api("/api/endpoint/check-access", payload);
    if (!result.ok) {
      endpointStatus.textContent = `Access check failed: ${result.message || "the target did not answer"}`;
      showToast("Access check failed", result.message || result.host, "danger");
      return;
    }
    const reach = result.profiles_total
      ? `${result.profiles_readable} of ${result.profiles_total} profiles readable`
      : "no user profiles found";
    endpointStatus.textContent = `${result.user || "This account"} on ${result.computer || result.host}: ${reach}. ${result.verdict || ""}`.trim();
    showToast(
      result.profiles_readable || !result.profiles_total ? "Access checked" : "Nothing readable yet",
      result.verdict || reach,
      result.profiles_readable || !result.profiles_total ? "success" : "warning",
    );
  } catch (error) {
    endpointStatus.textContent = `Access check failed: ${error.message}`;
    showToast("Access check failed", error.message, "danger");
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

document.querySelector("#endpoint-transport")?.addEventListener("change", syncEndpointTransportFields);
document.querySelector("#endpoint-cert-trust")?.addEventListener("change", syncEndpointTransportFields);
syncEndpointTransportFields();

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

// Every figure on the dashboard is a way in. The severity band opens Findings
// on that risk level, a data class opens Findings searched for it, a framework
// opens Findings filtered to it, and a top risk opens Remediation - which is
// where you would go to act on it. Buttons, so Enter and Space already work.
document.addEventListener("click", (event) => {
  const cell = event.target.closest("#tab-overview .ledger-cell[data-risk-jump]");
  if (cell) {
    switchTab("findings");
    applyInventoryRisk(cell.dataset.riskJump);
    return;
  }

  if (event.target.closest("[data-open-all-classes]")) {
    openAllDataClasses();
    return;
  }

  const dataClass = event.target.closest("[data-inventory-search]");
  if (dataClass) {
    closeClassesModal();
    switchTab("findings");
    // Typing the class name into the search box matched it as free text
    // against paths and file names too. The inventory has a Finding type
    // facet holding exactly these values, so select it there instead - an
    // exact filter, and the control shows which one is applied.
    const wanted = dataClass.dataset.inventorySearch;
    const selectable = inventoryFindingFilter
      && [...inventoryFindingFilter.options].some((option) => option.value === wanted);
    if (selectable) {
      if (filterInput && filterInput.value) {
        filterInput.value = "";
        lastInventoryQuery = "";
      }
      setFacetSelection("inventory-finding-filter", [wanted]);
      applyFindingsFacets();
    } else if (filterInput) {
      filterInput.value = wanted;
      filterInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    return;
  }

  const place = event.target.closest("[data-location-jump]");
  if (place) {
    switchTab("findings");
    const wanted = place.dataset.locationJump;
    if (filterInput) {
      filterInput.value = wanted;
      filterInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    // The Folder / path control drives this same search, so it has to show
    // what is applied - otherwise the page is filtered by a folder and the
    // only control that could say so reads "Anywhere". Set directly: its own
    // change listener would re-run the search that just ran.
    if (inventoryFolderSelect && [...inventoryFolderSelect.options].some((option) => option.value === wanted)) {
      inventoryFolderSelect.value = wanted;
    }
    return;
  }

  // Assessment coverage: three states of the same estate, each one an entry
  // in the Finding type facet. The handler used to look for `.coverage-item`,
  // a class this markup has never carried, so all three columns were focusable
  // buttons that did nothing at all.
  const coverage = event.target.closest("[data-coverage-jump]");
  if (coverage) {
    switchTab("findings");
    FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));
    setFacetSelection("inventory-finding-filter", [coverage.dataset.coverageJump]);
    if (filterInput) {
      filterInput.value = "";
      lastInventoryQuery = "";
    }
    applyFindingsFacets();
    return;
  }

  const framework = event.target.closest("[data-framework-jump]");
  if (framework) {
    switchTab("findings");
    setFacetSelection("inventory-framework-select", [framework.dataset.frameworkJump]);
    applyFindingsFacets();
    return;
  }

  const topRisk = event.target.closest("[data-risk-jump-key]");
  if (topRisk) {
    const category = RISK_CATEGORIES.find((item) => item.key === topRisk.dataset.riskJumpKey);
    // The row's number is a count of FILES, and it is computed by asking the
    // inventory a question the inventory can be asked again. So the row opens
    // Findings holding exactly that question, and the list it lands on has as
    // many rows as the card said. Sending it to the queue instead answered a
    // different question - findings, not files - with a category string that
    // did not always match how the finding was stored.
    if (applyRiskCategoryToFindings(category)) return;
    const go = category?.go;
    if (!go) {
      switchTab("risk");
    } else if (go.to === "inventory") {
      switchTab("findings");
      if (go.risk) applyInventoryRisk(go.risk);
      if (go.search && filterInput) {
        filterInput.value = go.search;
        lastInventoryQuery = "";
        filterInput.dispatchEvent(new Event("input", { bubbles: true }));
      }
    } else {
      openRemediationFiltered({ ...(go.filters || {}), label: category.label });
    }
    return;
  }
});

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

function facetSet(store, id) {
  let set = store.get(id);
  if (!set) {
    set = new Set();
    store.set(id, set);
  }
  return set;
}

function facetPendingValues(id) { return [...facetSet(facetPending, id)]; }
function facetAppliedValues(id) { return [...facetSet(facetApplied, id)]; }
function facetAppliedParam(id) { return facetAppliedValues(id).join(","); }
function facetGroupOf(id) { return FACET_GROUPS.risk.includes(id) ? "risk" : "findings"; }

function facetLabelName(select) {
  const label = select.closest("label");
  const named = label?.querySelector(".facet-name");
  if (named) return named.textContent.trim();
  const text = [...(label?.childNodes || [])].find((node) => node.nodeType === 3 && node.textContent.trim());
  return text ? text.textContent.trim() : "Filter";
}

function facetRealOptions(select) {
  return [...(select?.options || [])].filter((option) => option.value !== FACET_SUMMARY_VALUE);
}

// "All severities" is not a choice, it is the absence of one: an empty set.
function facetChoiceOptions(select) {
  return facetRealOptions(select).filter((option) => option.value && option.value !== "ALL");
}

function facetPlaceholder(select) {
  const all = facetRealOptions(select).find((option) => option.value === "ALL");
  return all ? all.textContent : facetLabelName(select);
}

function facetSummaryOption(select) {
  let option = select.querySelector(`option[value="${FACET_SUMMARY_VALUE}"]`);
  if (!option) {
    option = new Option("", FACET_SUMMARY_VALUE);
    option.dataset.facetSummary = "1";
    select.insertBefore(option, select.firstChild);
  }
  return option;
}

function syncFacetSummary(select) {
  if (!select?.dataset.facetMulti) return;
  const values = facetPendingValues(select.id);
  const option = facetSummaryOption(select);
  const chosen = facetRealOptions(select).filter((item) => values.includes(item.value));
  option.textContent = !values.length
    ? facetPlaceholder(select)
    : values.length === 1
      ? (chosen[0]?.textContent || values[0])
      : `${facetLabelName(select)} · ${values.length} selected`;
  select.value = FACET_SUMMARY_VALUE;
  const trigger = select.parentElement?.querySelector(".facet-trigger");
  if (!trigger) return;
  trigger.setAttribute("aria-label", `${facetLabelName(select)}: ${option.textContent}`);
  if (values.length) trigger.dataset.facetCount = String(values.length);
  else delete trigger.dataset.facetCount;
}

// A chosen value the freshly-rendered option list does not contain is still
// chosen: a saved scan can drop out of the facets while its filter is applied.
function facetKeepChosen(select, values, labeler = (value) => value) {
  if (!select?.dataset.facetMulti) return;
  const known = new Set(values);
  [...new Set([...facetPendingValues(select.id), ...facetAppliedValues(select.id)])]
    .filter((value) => !known.has(value))
    .forEach((value) => select.append(new Option(select.dataset.appliedLabel || labeler(value), value)));
  syncFacetSummary(select);
}

function attachFacetMulti(select) {
  if (!select || select.dataset.facetMulti || FACET_SINGLE_IDS.has(select.id)) return;
  select.dataset.facetMulti = "1";
  select.tabIndex = -1;
  select.setAttribute("aria-hidden", "true");
  const trigger = document.createElement("button");
  trigger.type = "button";
  // `plain-btn` is the stylesheet's own opt-out from the four rules that
  // paint every <button> as a primary action - without it the trigger fills
  // its facet with an indigo block and hides the control underneath.
  trigger.className = "facet-trigger plain-btn";
  trigger.setAttribute("aria-haspopup", "listbox");
  trigger.setAttribute("aria-expanded", "false");
  trigger.addEventListener("click", () => {
    if (facetMenuOwner === select) closeFacetMenu();
    else openFacetMenu(select);
  });
  select.parentElement?.append(trigger);
  // Every one of these option lists is rebuilt with innerHTML by its own
  // renderer, which takes the summary option with it.
  new MutationObserver(() => {
    syncFacetSummary(select);
    if (facetMenuOwner === select) renderFacetMenuList();
  }).observe(select, { childList: true });
  syncFacetSummary(select);
}

function ensureFacetMenu() {
  if (facetMenuElement) return facetMenuElement;
  const menu = document.createElement("div");
  menu.className = "facet-menu";
  menu.setAttribute("role", "dialog");
  menu.hidden = true;
  // No Clear button: every option is a checkbox, so unticking is the undo,
  // and the row of one-per-facet Clears was four buttons doing what four
  // clicks already did. The page-level Clear filters still resets all of them.
  menu.innerHTML = `<div class="facet-menu-head"><strong class="facet-menu-title"></strong>`
    + `<span class="facet-menu-chosen"></span></div>`
    + `<label class="facet-menu-search" hidden><input type="search" placeholder="Filter options" aria-label="Filter options" autocomplete="off" /></label>`
    + `<div class="facet-menu-list"></div>`;
  menu.querySelector(".facet-menu-search input").addEventListener("input", () => renderFacetMenuList());
  menu.querySelector(".facet-menu-list").addEventListener("change", (event) => {
    const box = event.target.closest("input[type=checkbox]");
    if (!box || !facetMenuOwner) return;
    const set = facetSet(facetPending, facetMenuOwner.id);
    if (box.checked) set.add(box.value);
    else set.delete(box.value);
    syncFacetSummary(facetMenuOwner);
    renderFacetApplyState(facetGroupOf(facetMenuOwner.id));
    updateFacetMenuHead();
  });
  document.body.append(menu);
  facetMenuElement = menu;
  return menu;
}

function updateFacetMenuHead() {
  if (!facetMenuOwner || !facetMenuElement) return;
  const chosen = facetPendingValues(facetMenuOwner.id).length;
  facetMenuElement.querySelector(".facet-menu-title").textContent = facetLabelName(facetMenuOwner);
  facetMenuElement.querySelector(".facet-menu-chosen").textContent = chosen ? `${chosen} selected` : "";
}

function renderFacetMenuList() {
  if (!facetMenuOwner || !facetMenuElement) return;
  const options = facetChoiceOptions(facetMenuOwner);
  const search = facetMenuElement.querySelector(".facet-menu-search");
  // A dozen owners can be read; two hundred assets have to be searched.
  search.hidden = options.length < 12;
  const query = search.hidden ? "" : search.querySelector("input").value.trim().toLowerCase();
  const chosen = new Set(facetPendingValues(facetMenuOwner.id));
  const list = facetMenuElement.querySelector(".facet-menu-list");
  const visible = options.filter((option) => !query || option.textContent.toLowerCase().includes(query));
  list.textContent = "";
  if (!visible.length) {
    const empty = document.createElement("p");
    empty.className = "facet-menu-empty";
    empty.textContent = options.length ? "No option matches." : "Nothing to filter on yet.";
    list.append(empty);
  }
  visible.forEach((option) => {
    const row = document.createElement("label");
    row.className = "facet-menu-item";
    const box = document.createElement("input");
    box.type = "checkbox";
    box.value = option.value;
    box.checked = chosen.has(option.value);
    const text = document.createElement("span");
    text.textContent = option.textContent;
    row.append(box, text);
    list.append(row);
  });
  updateFacetMenuHead();
}

function positionFacetMenu() {
  if (!facetMenuOwner || !facetMenuElement) return;
  const rect = facetMenuOwner.parentElement.getBoundingClientRect();
  const menu = facetMenuElement;
  menu.style.minWidth = `${Math.max(rect.width, 210)}px`;
  menu.style.maxWidth = `${Math.min(360, window.innerWidth - 16)}px`;
  const height = menu.offsetHeight;
  const room = window.innerHeight - rect.bottom - 8;
  const top = room < height && rect.top > height + 8 ? rect.top - height - 6 : rect.bottom + 6;
  menu.style.top = `${Math.max(8, Math.min(top, window.innerHeight - height - 8))}px`;
  menu.style.left = `${Math.max(8, Math.min(rect.left, window.innerWidth - menu.offsetWidth - 8))}px`;
}

function openFacetMenu(select) {
  const menu = ensureFacetMenu();
  facetMenuOwner = select;
  menu.hidden = false;
  const searchInput = menu.querySelector(".facet-menu-search input");
  searchInput.value = "";
  renderFacetMenuList();
  positionFacetMenu();
  select.parentElement?.querySelector(".facet-trigger")?.setAttribute("aria-expanded", "true");
  if (!menu.querySelector(".facet-menu-search").hidden) searchInput.focus();
}

function closeFacetMenu() {
  if (!facetMenuOwner) return;
  facetMenuOwner.parentElement?.querySelector(".facet-trigger")?.setAttribute("aria-expanded", "false");
  facetMenuOwner = null;
  if (facetMenuElement) facetMenuElement.hidden = true;
}

document.addEventListener("pointerdown", (event) => {
  if (!facetMenuOwner) return;
  if (event.target.closest(".facet-menu") || event.target.closest(".facet-trigger")) return;
  closeFacetMenu();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && facetMenuOwner) {
    const trigger = facetMenuOwner.parentElement?.querySelector(".facet-trigger");
    closeFacetMenu();
    trigger?.focus();
  }
});

window.addEventListener("resize", () => positionFacetMenu());
document.addEventListener("scroll", () => { if (facetMenuOwner) positionFacetMenu(); }, true);

function facetSelectionsEqual(left, right) {
  return left.size === right.size && [...left].every((value) => right.has(value));
}

function facetGroupDirty(group) {
  return FACET_GROUPS[group].some((id) => !facetSelectionsEqual(facetSet(facetPending, id), facetSet(facetApplied, id)));
}

function renderFacetApplyState(group) {
  const button = document.getElementById(group === "risk" ? "remediation-apply-filters" : "inventory-apply-filters");
  if (!button) return;
  if (facetGroupDirty(group)) button.dataset.facetDirty = "1";
  else delete button.dataset.facetDirty;
}

function commitFacetGroup(group) {
  FACET_GROUPS[group].forEach((id) => facetApplied.set(id, new Set(facetSet(facetPending, id))));
  renderFacetApplyState(group);
}

// Dashboard cards arrive with their filter already chosen; they set it and
// search in one move, because the operator asked for it by clicking.
function setFacetSelection(id, values) {
  const wanted = (Array.isArray(values) ? values : [values]).filter((value) => value && value !== "ALL");
  facetPending.set(id, new Set(wanted));
  const select = document.getElementById(id);
  // A value the facets do not list is still a legitimate filter - the
  // dashboard's "Regulated personal data" is three stored categories at once.
  if (select && wanted.length) {
    wanted.forEach((value) => {
      if (![...select.options].some((option) => option.value === value)) {
        select.append(new Option(remediationHumanize(value), value));
      }
    });
  }
  syncFacetSummary(select);
  renderFacetApplyState(facetGroupOf(id));
}

function applyFindingsFacets({ reload = true } = {}) {
  commitFacetGroup("findings");
  inventoryRiskFacets = new Set(facetAppliedValues("inventory-risk-filter"));
  inventorySourceFacets = new Set(facetAppliedValues("inventory-source-filter"));
  inventoryFindingFacets = new Set(facetAppliedValues("inventory-finding-filter"));
  inventoryFrameworkFacets = new Set(facetAppliedValues("inventory-framework-select"));
  inventoryRiskFilter = inventoryRiskFacets.size === 1 ? [...inventoryRiskFacets][0] : "ALL";
  inventorySourceFacet = inventorySourceFacets.size === 1 ? [...inventorySourceFacets][0] : "ALL";
  inventoryFindingFacet = inventoryFindingFacets.size === 1 ? [...inventoryFindingFacets][0] : "ALL";
  // The facet counts are computed per scan source, so only a change of source
  // invalidates them. Refetching them on every search undoes the saving.
  const sourceKey = facetAppliedParam("inventory-source-filter");
  if (sourceKey !== inventoryFacetSourceKey) {
    inventoryFacetSourceKey = sourceKey;
    inventoryFacetRequest += 1;
    inventoryFacets = null;
  }
  renderedRowsLimit = ROW_PAGE_SIZE;
  if (reload) refreshInventoryPageWindow();
}

function applyRemediationFacets({ resetPage = true } = {}) {
  commitFacetGroup("risk");
  loadRemediationSearch.cancel();
  loadRemediationFindings({ resetPage }).catch(() => {});
}

function initFacetMultiSelects() {
  Object.values(FACET_GROUPS).flat().forEach((id) => attachFacetMulti(document.getElementById(id)));
  // The queue opens on active findings, as it always has.
  setFacetSelection("remediation-status-filter", ["active"]);
  commitFacetGroup("findings");
  commitFacetGroup("risk");
}

// The inventory has no folder filter of its own, so this drives the same
// text search the dashboard's location rows use. The select is the point:
// it shows which folder is applied, where typing into the box did not.
inventoryFolderSelect?.addEventListener("change", () => {
  const value = inventoryFolderSelect.value || "ALL";
  if (filterInput) {
    filterInput.value = value === "ALL" ? "" : value;
    filterInput.dispatchEvent(new Event("input", { bubbles: true }));
  }
});

initFacetMultiSelects();

inventoryApplyFiltersBtn?.addEventListener("click", () => {
  closeFacetMenu();
  applyFindingsFacets();
});

inventoryClearFiltersBtn?.addEventListener("click", () => {
  closeFacetMenu();
  FACET_GROUPS.findings.forEach((id) => setFacetSelection(id, []));
  if (filterInput) {
    filterInput.value = "";
    lastInventoryQuery = "";
  }
  if (inventoryFolderSelect) inventoryFolderSelect.value = "ALL";
  applyFindingsFacets();
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
  applyTheme(current, { animate: true });
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
  loadRemediationFindings({ showLoading: false, resetPage: true })
    .catch((error) => setStatus(`Remediation refresh failed: ${error.message}`));
});

const loadRemediationSearch = debounce(() => {
  loadRemediationFindings({ resetPage: true }).catch(() => {});
}, 300);
remediationSearch?.addEventListener("input", loadRemediationSearch);
remediationApplyFiltersBtn?.addEventListener("click", () => {
  closeFacetMenu();
  applyRemediationFacets();
});
// The facet row is a form, so Enter searches rather than reloading the page.
remediationFilters?.addEventListener("submit", (event) => {
  event.preventDefault();
  closeFacetMenu();
  applyRemediationFacets();
});
// Scope is the one facet left that answers on its own: it changes which rows
// exist, not which of them are shown.
remediationScopeFilter?.addEventListener("change", () => {
  loadRemediationSearch.cancel();
  loadRemediationFindings({ resetPage: true }).catch(() => {});
});
function resetRemediationFilters({ reload = true } = {}) {
  loadRemediationSearch.cancel();
  closeFacetMenu();
  if (remediationSearch) remediationSearch.value = "";
  if (remediationScopeFilter) remediationScopeFilter.value = "current";
  FACET_GROUPS.risk.forEach((id) => {
    delete document.getElementById(id)?.dataset.appliedLabel;
    setFacetSelection(id, id === "remediation-status-filter" ? ["active"] : []);
  });
  commitFacetGroup("risk");
  remediationSortKey = "risk_score";
  remediationSortDirection = "desc";
  if (reload) loadRemediationFindings({ resetPage: true }).catch(() => {});
}

// ---- Arriving from a dashboard top risk ----------------------------------
// Opening the queue unfiltered from a card that names one kind of exposure is
// the same as not clicking it. Each category carries the filter that answers
// the question the card asked.
function openRemediationFiltered(filters = {}) {
  switchTab("risk");
  loadRemediationSearch.cancel();
  resetRemediationFilters({ reload: false });
  const targets = {
    severity: "remediation-severity-filter",
    category: "remediation-category-filter",
    framework: "remediation-framework-filter",
    data_type: "remediation-data-filter",
    asset: "remediation-asset-filter",
  };
  Object.entries(filters).forEach(([name, value]) => {
    if (name === "label") return;
    if (name === "q") {
      if (remediationSearch) remediationSearch.value = value;
      return;
    }
    const id = targets[name];
    const element = id && document.getElementById(id);
    if (!element) return;
    if (filters.label) element.dataset.appliedLabel = filters.label;
    if (![...element.options].some((option) => option.value === value)) {
      element.append(new Option(filters.label || remediationHumanize(value), value));
    }
    setFacetSelection(id, [value]);
  });
  applyRemediationFacets();
}
remediationDrawerToggle?.addEventListener("change", () => {
  if (remediationDrawerToggle.checked) return;
  remediationDetailRequest += 1;
  selectedRemediationFindingId = "";
  selectedRemediationFinding = null;
  renderRemediationWorkspace();
});

document.addEventListener("click", (event) => {
  const closeModal = event.target.closest?.("[data-close-remediation-modal]");
  if (closeModal) {
    closeRemediationModal(closeModal.closest("dialog"));
    return;
  }
  if (event.target.closest?.("[data-remediation-retry]")) {
    loadRemediationFindings().catch(() => {});
    return;
  }
  if (event.target.closest?.("[data-remediation-reset]")) {
    resetRemediationFilters();
    return;
  }
  const pageButton = event.target.closest?.("[data-remediation-page]");
  if (pageButton && !pageButton.disabled) {
    const direction = pageButton.dataset.remediationPage;
    if (direction === "next" && remediationPage.hasMore && remediationPage.nextCursor) {
      remediationPage.pageStarts[remediationPage.pageIndex + 1] = remediationPage.nextCursor;
      remediationPage.pageIndex += 1;
    } else if (direction === "previous" && remediationPage.pageIndex > 0) {
      remediationPage.pageIndex -= 1;
    } else {
      return;
    }
    loadRemediationFindings({ showLoading: false }).catch(() => {});
    return;
  }
  // A queue row is a unit of WORK, not a file: it is where a finding is
  // assigned, commented on, validated and closed. Sending the row click to
  // the Findings page took the reader out of the queue and gave them a file
  // listing instead of the workflow, so the row opens its drawer again. The
  // file is still one click away, from the row menu.
  const fileButton = event.target.closest?.("[data-remediation-file-open]");
  if (fileButton) {
    fileButton.closest("details")?.removeAttribute("open");
    openFileInInventory(fileButton.dataset.remediationFileOpen);
    return;
  }

  const actionButton = event.target.closest?.("[data-remediation-action]");
  if (actionButton) {
    actionButton.closest("details")?.removeAttribute("open");
    openRemediationAction(actionButton.dataset.remediationAction, actionButton.dataset.findingId);
    return;
  }
  const openButton = event.target.closest?.("[data-remediation-open]");
  if (openButton) {
    openButton.closest("details")?.removeAttribute("open");
    openRemediationFinding(openButton.dataset.remediationOpen).catch(() => {});
    return;
  }
  const row = event.target.closest?.("[data-remediation-finding]");
  if (row && !event.target.closest("button, a, input, select, textarea, details, summary")) {
    openRemediationFinding(row.dataset.remediationFinding).catch(() => {});
  }
});

document.querySelector("#remediation-assignment-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  runRemediationLifecycle("assign", remediationPendingAction?.findingId || "", {
    owner: String(data.get("owner") || "").trim(),
    sla_due: String(data.get("sla_due") || "").trim(),
    comment: String(data.get("comment") || "").trim(),
  }, form);
});

document.querySelector("#remediation-risk-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const lines = (value) => String(value || "").split(/\r?\n/).map((item) => item.trim()).filter(Boolean);
  runRemediationLifecycle("risk_acceptance", remediationPendingAction?.findingId || "", {
    business_justification: String(data.get("business_justification") || "").trim(),
    approver: String(data.get("approver") || "").trim(),
    expiration_date: String(data.get("expiration_date") || "").trim(),
    review_date: String(data.get("review_date") || "").trim(),
    compensating_controls: lines(data.get("compensating_controls")),
    affected_assets: lines(data.get("affected_assets")),
    accepted_volume: Number(data.get("accepted_volume") || 0),
  }, form);
});

document.querySelector("#remediation-false-positive-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const reason = String(data.get("reason") || "").trim();
  const note = String(data.get("comment") || "").trim();
  runRemediationLifecycle("false_positive", remediationPendingAction?.findingId || "", {
    reason,
    comment: [reason, note].filter(Boolean).join(" — ").slice(0, 1000),
  }, form);
});

document.querySelector("#remediation-suppression-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  runRemediationLifecycle("suppress", remediationPendingAction?.findingId || "", {
    reason: String(data.get("reason") || "").trim(),
    expiration_date: String(data.get("expiration_date") || "").trim(),
    comment: String(data.get("comment") || "").trim(),
  }, form);
});

document.querySelector("#remediation-action-form")?.addEventListener("submit", (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const comment = String(new FormData(form).get("comment") || "").trim();
  runRemediationLifecycle(remediationPendingAction?.action || "", remediationPendingAction?.findingId || "", {
    comment,
    resolution: remediationPendingAction?.action === "resolve" ? comment : "",
  }, form);
});

document.addEventListener("submit", (event) => {
  const form = event.target.closest?.("[data-remediation-comment-form]");
  if (!form) return;
  event.preventDefault();
  addRemediationComment(form);
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
  const nextTenant = tenantSwitcher.value || "default";
  if (activeScanJobId || activeEndpointJobId || activeProfileRun) {
    tenantSwitcher.value = currentTenant;
    showToast("Scan in progress", "Wait for the active scan to finish before switching tenant.", "info");
    return;
  }
  if (nextTenant === currentTenant) return;
  tenantContextVersion += 1;
  currentTenant = nextTenant;
  const context = captureTenantContext();
  safeSessionSet("dspm-tenant-id", currentTenant);
  workspaceSliceRequest += 1;
  resetInventoryPageWindow();
  latestFiles = [];
  fileSearchIndex = new WeakMap();
  latestReport = null;
  latestScanKind = "";
  latestDashboard = null;
  latestHashComparison = null;
  latestHistoryItems = [];
  latestAuditEvents = [];
  estateSummary = null;
  estateFacets = null;
  estateFacetsRequestPromise = null;
  inventoryFacetRequest += 1;
  inventoryFacets = null;
  scanProfilesState = [];
  latestComplianceKeywordLibrary = null;
  latestComplianceKeywordLibraries = {};
  remediationListRequest += 1;
  remediationListAbortController?.abort();
  remediationListAbortController = null;
  remediationDetailRequest += 1;
  remediationFindings = [];
  remediationSummary = null;
  remediationFacets = {};
  resetRemediationPage();
  remediationLoaded = false;
  remediationLoading = true;
  remediationLoadError = "";
  selectedRemediationFindingId = "";
  selectedRemediationFinding = null;
  if (remediationDrawerToggle) remediationDrawerToggle.checked = false;
  clearFindingsFacetState();
  expandedInventoryKeys.clear();
  inventoryDetailRequests.clear();
  lastRenderedFileKeys = new Set();
  hasRenderedScanRows = false;
  renderedRowsLimit = ROW_PAGE_SIZE;
  lastInventoryQuery = "";
  activeScanLabel = "";
  if (filterInput) filterInput.value = "";
  closeAssetDetailModal();
  assetModalFile = null;
  closeAnyOpenScanWizard();
  rowOverrides = loadRowOverrides();
  assetRules = loadAssetRules();
  customExtensions = loadCustomExtensions();
  renderProfile();
  renderExtensionFilter(allowedExtensionsList, extensionSearch);
  renderExtensionFilter(endpointAllowedExtensionsList, endpointExtensionSearch);
  applyDefaultSimpleExtensionPolicies();
  renderAssetRules();
  renderInventoryRiskSelection();
  renderInventoryScanOptions();
  updateInventoryFilterOptions([]);
  renderScanDecks();
  renderHistory([]);
  renderAudit([]);
  renderRows([]);
  updateSummaryFromFiles([]);
  scanMeta.textContent = "No scan has been run yet.";
  setStatus(`Switched MSSP customer to ${currentTenant}.`);
  await Promise.all([
    loadAllComplianceKeywordLibraries().catch(() => {}),
    loadAudit().catch(() => {}),
    loadRemediationFindings().catch(() => {}),
    loadHistory().catch((error) => {
      if (isCurrentTenantContext(context)) setStatus(`Tenant switch failed: ${error.message}`);
    }),
  ]);
});

hydrateNavigation();
applyTheme(safeStorageGet("dspm-theme") || "light");
setAuthState(Boolean(accessToken));
applyRoleVisibility();
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
    health.textContent = data.status === "ok" ? "Connected" : "Not connected";
  })
  .catch(() => {
    health.textContent = "Not connected";
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
  // Only the dashboard's own data at boot. Everything else is registered
  // against the tab it paints and runs the first time that tab is opened.
  loadHistory().catch(() => {});
} else {
  loadProtectedMetadata();
}


/* DSPM_V4_PRODUCT_PATCH: small UX helpers added by UI rebuild */
document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  document.querySelector(".profile-menu")?.classList.remove("open");
  profileToggle?.setAttribute("aria-expanded", "false");
  document.querySelector("#detail-drawer")?.classList.add("hidden");
  if (remediationDrawerToggle?.checked && !document.querySelector("#tab-risk dialog[open]")) {
    remediationDrawerToggle.checked = false;
    remediationDrawerToggle.dispatchEvent(new Event("change"));
  }
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
    heading: "#fs-wizard-heading", currentStep: "#fs-wizard-current-step", stepper: '[data-stepper="file-server"]',
    back: "#fs-wizard-back", next: "#fs-wizard-next", save: "#fs-wizard-save",
    close: "#fs-wizard-close", del: "#fs-wizard-delete", hint: "#fs-wizard-hint",
    mirror: "#fs-wizard-status", statusSource: "#connection-status",
    stepLabels: ["", "Scan identity", "Configuration", "Review & launch"],
    newTitle: "New file server scan", icon: "li-server",
  },
  endpoint: {
    deck: "#endpoint-scan-deck", grid: "#endpoint-profile-grid", wizard: "#endpoint-wizard",
    heading: "#endpoint-wizard-heading", currentStep: "#endpoint-wizard-current-step", stepper: '[data-stepper="endpoint"]',
    back: "#endpoint-wizard-back", next: "#endpoint-wizard-next", save: "#endpoint-wizard-save",
    close: "#endpoint-wizard-close", del: "#endpoint-wizard-delete", hint: "#endpoint-wizard-hint",
    mirror: "#endpoint-wizard-status", statusSource: "#endpoint-status",
    stepLabels: ["", "Scan identity", "Configuration", "Connect & launch"],
    newTitle: "New endpoint scan", icon: "li-monitor-cog",
  },
};

const scanWizardState = {
  "file-server": { step: 1, editingId: "" },
  endpoint: { step: 1, editingId: "" },
};
let activeProfileRun = null;
let fsLaunchArmed = false;

function wizardEl(kind, key) {
  return document.querySelector(SCAN_WIZARD_KINDS[kind][key]);
}

async function loadScanProfiles(context = captureTenantContext()) {
  if (!accessToken) return;
  try {
    const data = await api("/api/scan-profiles", null, "GET");
    if (!isCurrentTenantContext(context, data)) return;
    scanProfilesState = Array.isArray(data.profiles) ? data.profiles : [];
  } catch {
    if (!isCurrentTenantContext(context)) return;
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
  renderInventoryScanOptions();
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
  const currentStep = wizardEl(kind, "currentStep");
  const currentNode = wizard.querySelector(`.stepper-node[data-step-node="${step}"]`);
  if (currentStep) {
    const label = SCAN_WIZARD_KINDS[kind].stepLabels?.[step]
      || currentNode?.querySelector(".stepper-label")?.textContent?.trim()
      || "Setup";
    currentStep.textContent = `Step ${step}: ${label}`;
  }
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

// ---- Field-attached validation (F4) ---------------------------------------
// An error belongs to the field that caused it. Every message below used to
// land in one footer line under the wizard - the single place a reader is not
// looking when a field is empty, and a line no screen reader ever associated
// with the field it was about. Now the message sits under its own input, the
// input is marked invalid, and focus moves there.

function clearFieldErrors(root) {
  const scope = root || document;
  scope.querySelectorAll(".field-error").forEach((node) => node.remove());
  scope.querySelectorAll("[aria-invalid='true']").forEach((field) => {
    field.removeAttribute("aria-invalid");
    field.removeAttribute("aria-describedby");
  });
}

function showFieldError(target, message) {
  const field = typeof target === "string" ? document.querySelector(target) : target;
  if (!field) return false;
  const id = `${field.id || "field"}-error`;
  document.getElementById(id)?.remove();
  field.setAttribute("aria-invalid", "true");
  field.setAttribute("aria-describedby", id);
  const note = document.createElement("span");
  note.className = "field-error";
  note.id = id;
  note.setAttribute("role", "alert");
  note.textContent = message;
  // A <span> rather than a <p>: these inputs are wrapped in their own <label>,
  // which may only contain phrasing content.
  (field.closest("label") || field.parentElement || field).appendChild(note);
  // The message goes as soon as the reader starts fixing the thing it is
  // about; an error that outlives its cause is worse than no error.
  field.addEventListener("input", function drop() {
    field.removeEventListener("input", drop);
    field.removeAttribute("aria-invalid");
    field.removeAttribute("aria-describedby");
    document.getElementById(id)?.remove();
  });
  field.focus({ preventScroll: true });
  field.scrollIntoView({ block: "center" });
  return true;
}

function validateWizardStep(kind, step) {
  if (step === 1) {
    if (kind === "file-server") {
      if (!document.querySelector("#fs-profile-name").value.trim()) {
        return { field: "#fs-profile-name", message: "Give this scan a name." };
      }
      const server = document.querySelector("#server").value.trim();
      const hasCred = document.querySelector("#username").value.trim()
        || document.querySelector("#password").value
        || document.querySelector("#credential_ref").value.trim();
      if (server && !hasCred) {
        return {
          field: "#username",
          message: "A Windows file share needs a username and password, or a credential ref.",
        };
      }
    } else {
      if (!document.querySelector("#endpoint-profile-name").value.trim()) {
        return { field: "#endpoint-profile-name", message: "Give this scan a name." };
      }
      if (!document.querySelector("#endpoint-host").value.trim()) {
        return { field: "#endpoint-host", message: "Enter the machine's host name or IP address." };
      }
      if (!document.querySelector("#endpoint-username").value.trim()) {
        return { field: "#endpoint-username", message: "Enter the local-admin username for that machine." };
      }
      const hasCred = document.querySelector("#endpoint-password").value
        || document.querySelector("#endpoint-credential-ref").value.trim();
      if (!hasCred) {
        return { field: "#endpoint-password", message: "Enter a password, or a credential ref instead." };
      }
    }
  }
  if (step === 2 && kind === "endpoint") {
    try {
      readEndpointPayload();
    } catch (error) {
      return { field: "#endpoint-custom-paths", message: error.message };
    }
  }
  return null;
}

function wizardNext(kind) {
  const state = scanWizardState[kind];
  const wizard = wizardEl(kind, "wizard");
  clearFieldErrors(wizard);
  const problem = validateWizardStep(kind, state.step);
  if (problem) {
    // The footer line stays only for a problem with no field to point at.
    setWizardHint(kind, showFieldError(problem.field, problem.message) ? "" : problem.message);
    return;
  }
  setWizardHint(kind, "");
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
  document.querySelector("#endpoint-transport").value = config.use_ssl ? "https" : "http";
  document.querySelector("#endpoint-port").value = config.port || "";
  document.querySelector("#endpoint-cert-trust").value = config.cert_trust || "system";
  document.querySelector("#endpoint-ca-bundle").value = config.ca_bundle || "";
  document.querySelector("#endpoint-cert-thumbprint").value = config.cert_thumbprint || "";
  document.querySelector("#endpoint-kerberos").value = config.kerberos || "";
  syncEndpointTransportFields();
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
