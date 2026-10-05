// C7: the console's JavaScript may not use a name nobody defined. `node --check` finds
// syntax errors only; a renamed function or a deleted constant is a ReferenceError the
// first time a page runs that line - Phase A's Remediation outage was exactly that.
//
// Pinned: eslint and globals are exact versions in package.json, and CI runs this file
// through scripts/static_gate.py with the local install in node_modules (`npm run lint`
// does the same), never a global one. Each script is a classic <script> and needs nothing
// but the browser's globals; if one ever has to use another's, list that name here with
// the reason rather than switching the rule off.
import globals from "globals";

//
// D4 split app.js by feature: console/*.js load before app.js, one feature each. Each
// side uses some of the other's names when a handler runs - never while loading - and
// they are listed here by file, so a name nobody defines is still an error.
const FROM_FEATURES = {
  // console/alerts.js
  loadAlerts: "readonly",
  loadFindingTickets: "readonly",
  remediationTicketSection: "readonly",
  // console/access.js
  loadAccessPrincipals: "readonly",
  resetAccessPage: "readonly",
  // console/exact-match.js
  loadExactMatchSets: "readonly",
  resetExactMatchForm: "readonly",
  // console/scan-scope.js
  applyScanScope: "readonly",
  countScanScopeRules: "readonly",
  readScanScope: "readonly",
  scanScopeHistoryNote: "readonly",
  scanScopeProblem: "readonly",
  scanScopeReviewText: "readonly",
  scanScopeSkipsHidden: "readonly",
};
const FROM_APP = {
  accessToken: "readonly",
  api: "readonly",
  can: "readonly",
  captureTenantContext: "readonly",
  escapeHtml: "readonly",
  filterInput: "readonly",
  getFriendlyTimestamp: "readonly",
  isCurrentTenantContext: "readonly",
  showToast: "readonly",
  switchTab: "readonly",
};

const base = { ecmaVersion: 2024, sourceType: "script" };

export default [
  {
    files: ["*.js"],
    languageOptions: { ...base, globals: { ...globals.browser } },
    rules: { "no-undef": "error" },
  },
  {
    files: ["app.js"],
    languageOptions: { ...base, globals: { ...globals.browser, ...FROM_FEATURES } },
  },
  {
    // The wizard's review mirror reads the scope's one-line summary when it renders.
    files: ["scan-summary.js"],
    languageOptions: { ...base, globals: { ...globals.browser, scanScopeReviewText: "readonly" } },
  },
  {
    files: ["console/*.js"],
    languageOptions: { ...base, globals: { ...globals.browser, ...FROM_APP } },
    rules: { "no-undef": "error" },
  },
];
