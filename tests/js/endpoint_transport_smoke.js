// Run the console's real readEndpointTransport() against the ids frontend/index.html
// actually defines, and print the payload it would send.
//
//   node tests/js/endpoint_transport_smoke.js <fields.json>
//
// Prints one JSON line: {"payload": {...}, "unknown_ids": [...], "console_errors": [...]}.
//
// The point is the id-aware DOM: querySelector("#thing") resolves only when index.html
// really has that id, and records it as unknown otherwise. A form control renamed in the
// HTML but not in the JS (or the reverse) is invisible to `node --check` and to a
// stand-in that answers every selector - and it silently sends the field's default,
// which for a transport choice means scanning in cleartext while the operator believes
// otherwise. Dependency-free, like the remediation render smoke beside it.
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");
const { runConsole } = require("./console_scripts");

const ROOT = path.resolve(__dirname, "..", "..");
const APP = path.join(ROOT, "frontend", "app.js");
const INDEX = path.join(ROOT, "frontend", "index.html");
const fields = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));

const html = fs.readFileSync(INDEX, "utf8");
const knownIds = new Set([...html.matchAll(/\sid="([^"]+)"/g)].map((match) => match[1]));
const unknownIds = new Set();
const consoleErrors = [];

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

// One element per id in index.html, carrying the value this run was given.
const elements = new Map();
function elementFor(id) {
  if (!elements.has(id)) {
    const element = standIn(`#${id}`);
    element.id = id;
    element.value = Object.prototype.hasOwnProperty.call(fields, id) ? String(fields[id]) : "";
    element.checked = Boolean(fields[id]);
    element.disabled = false;
    element.placeholder = "";
    element.classList = {
      _hidden: false,
      add() { this._hidden = true; },
      remove() { this._hidden = false; },
      toggle(_name, force) { this._hidden = Boolean(force); return this._hidden; },
      contains() { return this._hidden; },
    };
    element.addEventListener = () => {};
    element.dispatchEvent = () => true;
    elements.set(id, element);
  }
  return elements.get(id);
}

function querySelector(selector) {
  const text = String(selector);
  if (text.startsWith("#") && /^#[A-Za-z0-9_-]+$/.test(text)) {
    const id = text.slice(1);
    if (!knownIds.has(id)) {
      unknownIds.add(id);
      return null;      // exactly what the browser gives for an id that is not there
    }
    return elementFor(id);
  }
  return standIn(`querySelector(${text})`);
}

const documentStandIn = standIn("document");
documentStandIn.querySelector = querySelector;
documentStandIn.getElementById = (id) => querySelector(`#${id}`);
documentStandIn.querySelectorAll = () => [];
documentStandIn.addEventListener = () => {};
documentStandIn.dispatchEvent = () => true;
documentStandIn.body = standIn("body");
documentStandIn.documentElement = standIn("documentElement");

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

const context = {
  console: { log() {}, info() {}, debug() {}, warn() {}, error: (...args) => consoleErrors.push(args.map(String).join(" ")) },
  setTimeout, clearTimeout, setInterval, clearInterval, queueMicrotask,
  URL, URLSearchParams, AbortController, TextEncoder, TextDecoder, Intl, Date, Math, JSON,
  document: documentStandIn,
  localStorage: storage(),
  sessionStorage: storage(),
  location: { pathname: "/", search: "", hash: "", href: "http://127.0.0.1/", origin: "http://127.0.0.1", assign() {}, replace() {}, reload() {} },
  history: { pushState() {}, replaceState() {}, back() {}, state: null },
  navigator: { userAgent: "node", language: "en-US", languages: ["en-US"], clipboard: { writeText: async () => {} } },
  matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  requestAnimationFrame: (callback) => setTimeout(() => callback(Date.now()), 0),
  cancelAnimationFrame: (id) => clearTimeout(id),
  requestIdleCallback: (callback) => setTimeout(() => callback({ timeRemaining: () => 50, didTimeout: false }), 0),
  getComputedStyle: () => standIn("style"),
  fetch: async () => { throw new Error("the transport smoke has no network"); },
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
  runConsole(vm, context);
} catch (error) {
  finish({ error: `app.js did not load: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}`,
           payload: null, unknown_ids: [...unknownIds], console_errors: consoleErrors }, false);
}

let payload = null;
let trustDisabled = null;
let hiddenFields = null;
try {
  if (fields.__profile) {
    // Replay a saved scan the way the deck does, then read what it would send: a
    // profile that forgets its transport sends the next scan out in cleartext.
    context.__profile = fields.__profile;
    vm.runInContext("applyEndpointProfile({ config: globalThis.__profile });", context, { filename: "profile" });
  }
  vm.runInContext("syncEndpointTransportFields();", context, { filename: "sync" });
  payload = vm.runInContext("JSON.stringify(readEndpointTransport())", context, { filename: "read" });
  trustDisabled = elementFor("endpoint-cert-trust").disabled;
  hiddenFields = {
    "endpoint-ca-bundle-field": elementFor("endpoint-ca-bundle-field").classList._hidden,
    "endpoint-thumbprint-field": elementFor("endpoint-thumbprint-field").classList._hidden,
  };
} catch (error) {
  finish({ error: `readEndpointTransport failed: ${String(error && error.stack).split("\n").slice(0, 3).join(" | ")}`,
           payload: null, unknown_ids: [...unknownIds], console_errors: consoleErrors }, false);
}

// What the operator is told after a Test connection, for each transport the API can
// report back. The wording is the only place the choice becomes visible to them.
const described = {};
for (const [name, transport] of Object.entries(fields.__describe || {})) {
  context.__transport = transport;
  described[name] = vm.runInContext("describeEndpointTransport(globalThis.__transport)", context, { filename: "describe" });
}

finish({
  described,
  payload: JSON.parse(payload),
  trust_disabled: trustDisabled,
  hidden: hiddenFields,
  unknown_ids: [...unknownIds].filter((id) => id.startsWith("endpoint-")),
  console_errors: consoleErrors.slice(0, 5),
}, true);
