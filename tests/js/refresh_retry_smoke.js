// Drive the console's real api() against a stubbed server and report how it behaved
// when the access token was rejected.
//
//   node tests/js/refresh_retry_smoke.js <scenario.json>
//
// scenario: {"calls": 5, "refreshSucceeds": true, "script": "app.js", "drive": "api"}
//   script: "app.js" (the console, default) or "profile.js" (the settings page)
//   drive:  "api" (default: `calls` concurrent api() calls), "logout" (sign out), or
//           "password_changed" (profile.js: what the page does after a password change), or
//           "evaluate" (app.js: setPermissions(scenario.permissions); either page: each expression
//           in scenario.evaluate, reported under its name in "values")
// Prints one JSON line: {"refreshCalls", "apiCalls", "resolved", "rejected", "redirected",
// "logoutCalls", "logoutAccepted"}.
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
const scenario = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const SCRIPT = scenario.script === "profile.js" ? "profile.js" : "app.js";
const APP = path.join(ROOT, "frontend", SCRIPT);

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

const counts = { refreshCalls: 0, apiCalls: 0, redirected: 0, logoutCalls: 0, logoutAccepted: 0 };
let tokenIsGood = false;     // the access token starts rejected, as an expired one is
let booting = false;         // while a page's own start-up calls run, answer them and count nothing

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
  if (booting) {
    return reply(200, {});
  }
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
  const authorized = String(options.headers?.Authorization || "").includes("refreshed-token");
  if (target.includes("/api/logout")) {
    // Sign-out is what ends the refresh chain on the server; only an accepted call does.
    counts.logoutCalls += 1;
    if (!authorized && !tokenIsGood) {
      return reply(401, { detail: "Invalid or expired token" });
    }
    counts.logoutAccepted += 1;
    return reply(200, { status: "logged_out" });
  }
  counts.apiCalls += 1;
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

async function main() {
  if (SCRIPT === "profile.js") {
    // The settings page loads its panels as soon as it runs; let those settle first.
    booting = true;
  }
  try {
    vm.runInContext(fs.readFileSync(APP, "utf8"), context, { filename: SCRIPT });
  } catch (error) {
    finish({ error: `${SCRIPT} did not load: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}` }, false);
  }
  if (booting) {
    await new Promise((resolve) => setTimeout(resolve, 50));
    booting = false;
    Object.keys(counts).forEach((key) => { counts[key] = 0; });
  }

  // A stale access token, exactly as an expired one behaves: the server says 401.
  const setup = SCRIPT === "app.js"
    ? 'accessToken = "stale-token"; showToast = () => {};'
    : 'sessionStorage.setItem("dspm-access-token", "stale-token");';
  vm.runInContext(setup, context, { filename: "setup" });

  const calls = Math.max(1, Number(scenario.calls) || 1);
  context.__calls = calls;
  const drives = {
    logout: "globalThis.__result = Promise.allSettled([logout()]);",
    password_changed: "globalThis.__result = Promise.allSettled([Promise.resolve(afterPasswordChange({ status: 'updated', reauthenticate: true }))]);",
    evaluate: "globalThis.__result = Promise.resolve([]);",
  };
  const drive = drives[scenario.drive] || `globalThis.__result = Promise.allSettled(
         Array.from({length: globalThis.__calls}, (_unused, index) => api("/api/thing" + index, null, "GET"))
       );`;
  vm.runInContext(drive, context, { filename: "drive" });

  if (scenario.drive === "evaluate") {
    if (SCRIPT === "app.js") {
      // The console gates on permissions; the settings page has no such step.
      context.__permissions = Array.isArray(scenario.permissions) ? scenario.permissions : [];
      vm.runInContext("setPermissions(globalThis.__permissions);", context, { filename: "permissions" });
    }
    const values = {};
    for (const [name, expression] of Object.entries(scenario.evaluate || {})) {
      try {
        // An expression may be async; its settled value is what is reported.
        values[name] = await Promise.resolve(vm.runInContext(expression, context, { filename: name }));
      } catch (error) {
        values[name] = `threw: ${String(error).slice(0, 160)}`;
      }
    }
    finish({ values }, true);
  }

  const settled = await context.__result;
  if (scenario.drive === "password_changed") {
    // The page tells the operator, then leaves for sign-in a moment later.
    await new Promise((resolve) => setTimeout(resolve, 1700));
  }
  finish({
    refreshCalls: counts.refreshCalls,
    apiCalls: counts.apiCalls,
    redirected: counts.redirected,
    logoutCalls: counts.logoutCalls,
    logoutAccepted: counts.logoutAccepted,
    tokenLeft: context.sessionStorage.getItem("dspm-access-token") || "",
    resolved: settled.filter((entry) => entry.status === "fulfilled").length,
    rejected: settled.filter((entry) => entry.status === "rejected").length,
  }, true);
}

main().catch((error) => finish({ error: String(error).slice(0, 200) }, false));
