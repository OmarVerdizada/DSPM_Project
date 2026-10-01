// Load the console's real frontend/app.js into a stand-in DOM, hand loadRemediationFindings
// an /api/findings response, and report whether the page would render it or show
// "Unable to load remediation findings".
//
//   node tests/js/remediation_render_smoke.js <response.json>
//
// Prints one JSON line: {"loaded": bool, "error": str, "rows": n, "console_errors": [...]}.
// Dependency-free on purpose: CI's runners have Node, and nothing has to be installed.
//
// The stand-in DOM answers every property and call with another stand-in that coerces to
// "" or 0, so the page's DATA handling runs for real while the DOM is a no-op. A
// ReferenceError or TypeError in that handling is exactly what it exists to catch.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { runConsole } = require("./console_scripts");

const APP = path.resolve(__dirname, "..", "..", "frontend", "app.js");
const response = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

function standIn(label = "node") {
  const own = {};
  return new Proxy(function () {}, {
    get(_target, prop) {
      if (prop === Symbol.toPrimitive) return (hint) => (hint === "number" ? 0 : "");
      if (prop === Symbol.iterator) return function* () {};
      if (prop === "then") return undefined;
      if (prop === "length") return 0;
      if (prop === "toString" || prop === "valueOf") return () => "";
      if (Object.prototype.hasOwnProperty.call(own, prop)) return own[prop];
      return standIn(`${label}.${String(prop)}`);
    },
    set(_target, prop, value) { own[prop] = value; return true; },
    has() { return true; },
    apply() { return standIn(`${label}()`); },
    construct() { return standIn(`new ${label}`); },
  });
}

function storage() {
  const map = new Map();
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
  sessionStorage: storage(),
  location: { pathname: "/remediation", search: "", hash: "", href: "http://127.0.0.1/remediation", origin: "http://127.0.0.1", assign() {}, replace() {}, reload() {} },
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

function finish(result) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(result.loaded && !result.error ? 0 : 1);
}

try {
  runConsole(vm, context);
} catch (error) {
  // A browser global app.js started using at load time and this stand-in lacks.
  finish({ loaded: false, error: `app.js did not load in the render smoke: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}`, rows: 0, console_errors: consoleErrors });
}

context.__response = response;
vm.runInContext(`
  api = async () => JSON.parse(JSON.stringify(globalThis.__response));
  deferWhileHidden = () => false;
  isCurrentTenantContext = () => true;
  accessToken = "render-smoke";
`, context);

(async () => {
  try {
    await vm.runInContext("loadRemediationFindings({ showLoading: true, resetPage: true })", context);
    const state = vm.runInContext("({ loaded: remediationLoaded, error: remediationLoadError, rows: remediationFindings.length })", context);
    finish({ ...state, console_errors: consoleErrors });
  } catch (error) {
    finish({ loaded: false, error: String(error && error.stack), rows: 0, console_errors: consoleErrors });
  }
})();
