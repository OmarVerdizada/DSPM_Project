// C7: every major page of the console, rendered by the real frontend/app.js from
// representative API responses, in a stand-in DOM.
//
//   node tests/js/page_render_smoke.js <fixture.json>
//
// fixture.json: {"responses": {"/api/path": <json>, ...}, "pages": ["dashboard", ...]}
// A request is answered by its path without the query string. Prints one JSON line:
//   {"pages": {name: {"ok": bool, "error": str}}, "html": [every HTML string written],
//    "requested": [paths asked for], "unanswered": [paths with no fixture],
//    "console_errors": [...]}
//
// The stand-in DOM answers every property with another stand-in, so the pages' DATA
// handling and markup building run for real. Every innerHTML/outerHTML assignment and
// insertAdjacentHTML call is recorded, which is what the hostile-filename test reads.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const APP = path.resolve(__dirname, "..", "..", "frontend", "app.js");
const fixture = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const html = [];

function standIn(label = "node") {
  const own = {};
  return new Proxy(function () {}, {
    get(_target, prop) {
      if (prop === Symbol.toPrimitive) return (hint) => (hint === "number" ? 0 : "");
      if (prop === Symbol.iterator) return function* () {};
      if (prop === "then") return undefined;
      if (prop === "length") return 0;
      if (prop === "toString" || prop === "valueOf") return () => "";
      if (prop === "insertAdjacentHTML") return (_where, markup) => { html.push(String(markup)); };
      if (Object.prototype.hasOwnProperty.call(own, prop)) return own[prop];
      return standIn(`${label}.${String(prop)}`);
    },
    set(_target, prop, value) {
      if (prop === "innerHTML" || prop === "outerHTML") html.push(String(value));
      own[prop] = value;
      return true;
    },
    has() { return true; },
    apply() { return standIn(`${label}()`); },
    construct() { return standIn(`new ${label}`); },
  });
}

function storage(initial = {}) {
  const map = new Map(Object.entries(initial));
  return {
    getItem: (key) => (map.has(key) ? map.get(key) : null),
    setItem: (key, value) => map.set(key, String(value)),
    removeItem: (key) => map.delete(key),
    clear: () => map.clear(),
    key: (index) => [...map.keys()][index] ?? null,
    get length() { return map.size; },
  };
}

const consoleErrors = [];
const quietConsole = {
  log() {}, info() {}, debug() {}, warn() {},
  error: (...args) => {
    const error = args.find((arg) => arg && arg.stack);
    consoleErrors.push(error ? String(error.stack).split("\n").slice(0, 4).join("\n") : args.map(String).join(" "));
  },
};

const context = {
  console: quietConsole,
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  URL, URLSearchParams, AbortController, TextEncoder, TextDecoder, Intl, Date, Math, JSON,
  document: standIn("document"),
  localStorage: storage(),
  sessionStorage: storage({ "dspm-access-token": "render-smoke", "dspm-role": "admin", "dspm-user": "admin", "dspm-tenant-id": "default" }),
  location: { pathname: "/dashboard", search: "", hash: "", href: "http://127.0.0.1/dashboard", origin: "http://127.0.0.1", assign() {}, replace() {}, reload() {} },
  history: { pushState() {}, replaceState() {}, back() {}, state: null },
  navigator: { userAgent: "node", language: "en-US", languages: ["en-US"], clipboard: { writeText: async () => {} } },
  matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  requestAnimationFrame: (callback) => setTimeout(() => callback(Date.now()), 0),
  cancelAnimationFrame: (id) => clearTimeout(id),
  requestIdleCallback: (callback) => setTimeout(() => callback({ timeRemaining: () => 50, didTimeout: false }), 0),
  getComputedStyle: () => standIn("style"),
  fetch: async () => { throw new Error("the render smoke has no network"); },
  addEventListener() {}, removeEventListener() {}, dispatchEvent() { return true; },
  CSS: { escape: (value) => String(value) },
  ResizeObserver: class { observe() {} unobserve() {} disconnect() {} },
  IntersectionObserver: class { observe() {} unobserve() {} disconnect() {} },
  MutationObserver: class { observe() {} disconnect() {} takeRecords() { return []; } },
  CustomEvent: class { constructor(type, init) { this.type = type; this.detail = init?.detail; } },
  Event: class { constructor(type) { this.type = type; } },
  HTMLElement: class {}, Element: class {}, Node: class {},
  Option: class { constructor(text = "", value = "", selected = false) { Object.assign(this, { text, value, selected, textContent: text }); } },
  DOMParser: class { parseFromString() { return standIn("parsed"); } },
  Blob: class {},
  FormData: class { get() { return null; } getAll() { return []; } has() { return false; } set() {} append() {} entries() { return [][Symbol.iterator](); } [Symbol.iterator]() { return [][Symbol.iterator](); } },
  FileReader: class { readAsDataURL() {} readAsText() {} },
  Image: class {},
  atob: (value) => Buffer.from(String(value), "base64").toString("binary"),
  btoa: (value) => Buffer.from(String(value), "binary").toString("base64"),
  performance: { now: () => Date.now() },
  scrollTo() {}, alert() {}, confirm: () => true, prompt: () => "",
  innerWidth: 1600, innerHeight: 900, devicePixelRatio: 1,
};
context.window = context;
context.self = context;
context.globalThis = context;
vm.createContext(context);

const requested = [];
const unanswered = new Set();
context.__respond = (url) => {
  const pathOnly = String(url).split("?")[0];
  requested.push(pathOnly);
  if (Object.prototype.hasOwnProperty.call(fixture.responses, pathOnly)) {
    return JSON.parse(JSON.stringify(fixture.responses[pathOnly]));
  }
  unanswered.add(pathOnly);
  return {};
};

function finish(result) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(0);
}

try {
  vm.runInContext(fs.readFileSync(APP, "utf8"), context, { filename: "app.js" });
} catch (error) {
  finish({ pages: {}, error: `app.js did not load: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}`, html, requested, unanswered: [...unanswered], console_errors: consoleErrors });
}

vm.runInContext(`
  api = async (url) => globalThis.__respond(url);
  deferWhileHidden = () => false;
  isCurrentTenantContext = () => true;
  accessToken = "render-smoke";
  if (typeof setPermissions === "function") setPermissions(${JSON.stringify(fixture.permissions || [])});
`, context);

const PAGES = {
  dashboard: "loadHistory()",
  inventory: "Promise.all([refreshEstateSummary(), refreshInventoryFacets(), loadInventoryWindowPage(0)])",
  remediation: "loadRemediationFindings({ showLoading: true, resetPage: true })",
  risk: "refreshRiskCategoryCounts()",
  report: `loadSavedReportById(${JSON.stringify(fixture.scan_id || "")}, 1, 0, true)`,
  audit: "loadAudit()",
  users: "loadUsers()",
  tenants: "loadTenants()",
  scan_targets: "loadScanTargets()",
  scan_profiles: "loadScanProfiles()",
  hash_changes: "loadHashComparison()",
  alerts: "loadAlerts()",
};

(async () => {
  const pages = {};
  for (const name of fixture.pages || Object.keys(PAGES)) {
    const before = consoleErrors.length;
    try {
      await vm.runInContext(PAGES[name], context);
      await new Promise((resolve) => setTimeout(resolve, 20));
      const errors = consoleErrors.slice(before);
      pages[name] = { ok: errors.length === 0, error: errors.join(" || ") };
    } catch (error) {
      pages[name] = { ok: false, error: String(error && error.stack).split("\n").slice(0, 3).join(" | ") };
    }
  }
  finish({ pages, html, requested: [...new Set(requested)], unanswered: [...unanswered], console_errors: consoleErrors });
})();
