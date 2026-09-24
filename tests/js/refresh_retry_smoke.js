// Drive the console's real api() against a stubbed server and report how it behaved
// when the access token was rejected.
//
//   node tests/js/refresh_retry_smoke.js <scenario.json>
//
// scenario: {"calls": 5, "refreshSucceeds": true}
// Prints one JSON line: {"refreshCalls", "apiCalls", "resolved", "rejected", "redirected"}.
//
// The property that needs a real test rather than a grep: several panels can be
// rejected at once, and if each exchanged the refresh cookie the second exchange would
// present a token the first had already retired - which the server correctly reads as a
// replay and answers by ending the whole family. Sharing one in-flight refresh is what
// keeps a bounded access token from signing everyone out the first time two requests
// overlap.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..", "..");
const APP = path.join(ROOT, "frontend", "app.js");
const scenario = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

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

const counts = { refreshCalls: 0, apiCalls: 0, redirected: 0 };
let tokenIsGood = false;     // the access token starts rejected, as an expired one is

function reply(status, body) {
  return {
    ok: status >= 200 && status < 300,
    status,
    json: async () => body,
    text: async () => JSON.stringify(body),
    headers: { get: () => null },
  };
}

async function stubFetch(url, options = {}) {
  const target = String(url);
  if (target.includes("/api/auth/refresh")) {
    counts.refreshCalls += 1;
    // A real exchange takes a round trip; without the wait every caller would find
    // the shared promise already settled and the race would not be exercised.
    await new Promise((resolve) => setTimeout(resolve, 15));
    if (!scenario.refreshSucceeds) {
      return reply(401, { detail: "Session expired" });
    }
    tokenIsGood = true;
    return reply(200, { access_token: "refreshed-token", role: "admin", tenant_id: "default" });
  }
  counts.apiCalls += 1;
  const authorized = String(options.headers?.Authorization || "").includes("refreshed-token");
  if (!authorized && !tokenIsGood) {
    return reply(401, { detail: "Invalid or expired token" });
  }
  return reply(200, { ok: true });
}

const context = {
  console: { log() {}, info() {}, debug() {}, warn() {}, error() {} },
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  URL, URLSearchParams, AbortController, TextEncoder, TextDecoder, Intl, Date, Math, JSON,
  document: standIn("document"),
  localStorage: storage(),
  sessionStorage: storage(),
  location: {
    pathname: "/", search: "", hash: "", href: "http://127.0.0.1/", origin: "http://127.0.0.1",
    assign() { counts.redirected += 1; },
    replace() { counts.redirected += 1; },
    reload() {},
  },
  history: { pushState() {}, replaceState() {}, back() {}, state: null },
  navigator: { userAgent: "node", language: "en-US", languages: ["en-US"], clipboard: { writeText: async () => {} } },
  matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  requestAnimationFrame: (callback) => setTimeout(() => callback(Date.now()), 0),
  cancelAnimationFrame: (id) => clearTimeout(id),
  requestIdleCallback: (callback) => setTimeout(() => callback({ timeRemaining: () => 50, didTimeout: false }), 0),
  getComputedStyle: () => standIn("style"),
  fetch: stubFetch,
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

function finish(result, ok) {
  process.stdout.write(`${JSON.stringify(result)}\n`);
  process.exit(ok ? 0 : 1);
}

try {
  vm.runInContext(fs.readFileSync(APP, "utf8"), context, { filename: "app.js" });
} catch (error) {
  finish({ error: `app.js did not load: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}` }, false);
}

// A stale access token, exactly as an expired one behaves: the server says 401.
vm.runInContext('accessToken = "stale-token"; showToast = () => {};', context, { filename: "setup" });

const calls = Math.max(1, Number(scenario.calls) || 1);
context.__calls = calls;
vm.runInContext(
  `globalThis.__result = Promise.allSettled(
     Array.from({length: globalThis.__calls}, (_unused, index) => api("/api/thing" + index, null, "GET"))
   );`,
  context, { filename: "drive" },
);

context.__result
  .then((settled) => {
    finish({
      refreshCalls: counts.refreshCalls,
      apiCalls: counts.apiCalls,
      redirected: counts.redirected,
      resolved: settled.filter((entry) => entry.status === "fulfilled").length,
      rejected: settled.filter((entry) => entry.status === "rejected").length,
    }, true);
  })
  .catch((error) => finish({ error: String(error).slice(0, 200) }, false));
