// Runs the console's real frontend/console/scan-setup.js against stand-in controls.
// argv[2] is a JSON file: {"cases": [{"controls": {...}, "selected": [...], "scopeProblem": null|{...}}],
// "restore": [{"config": {...}}]}. Prints, per case, the hidden/system request fields, the type
// mode and label, and the problems the step would refuse; per restore, the two choices it set.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const source = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "console", "scan-setup.js"), "utf8");

let controls = {};
let selected = [];
let scopeProblem = null;
const element = (key) => {
  if (!(key in controls)) return null;
  const value = controls[key];
  return {
    get value() { return controls[key].value ?? ""; },
    set value(next) { controls[key].value = next; },
    get checked() { return Boolean(controls[key].checked); },
    classList: { contains: (name) => name === "hidden" && Boolean(value.hidden), toggle() {} },
    closest: () => ({ textContent: value.label || "" }),
    setAttribute() {},
    removeAttribute() {},
    addEventListener() {},
    querySelectorAll: () => [],
  };
};
const context = {
  console,
  window: { setTimeout, clearTimeout },
  Event: function Event(type) { this.type = type; },
  document: {
    querySelector: (selector) => element(selector),
    querySelectorAll: () => [],
    getElementById: () => null,
  },
  // app.js and console/scan-scope.js, as the step calls them
  allowedExtensionsList: {},
  readSelectedExtensions: () => selected,
  scanScopeProblem: () => scopeProblem,
  readScanScope: () => ({}),
  escapeHtml: (text) => String(text),
};
vm.createContext(context);
vm.runInContext(source, context);

const results = { cases: [], restore: [] };
for (const item of input.cases || []) {
  controls = JSON.parse(JSON.stringify(item.controls || {}));
  selected = item.selected || [];
  scopeProblem = item.scopeProblem || null;
  results.cases.push({
    special: context.readSpecialFiles(),
    mode: context.scanTypeMode(),
    label: context.scanTypesLabel(),
    problems: context.scanSetupProblems(),
  });
}
for (const item of input.restore || []) {
  controls = { "#fs-hidden-files": { value: "" }, "#fs-system-files": { value: "" } };
  context.applySpecialFiles(item.config || {});
  results.restore.push({ hidden: controls["#fs-hidden-files"].value, system: controls["#fs-system-files"].value });
}
// "levels": a saved scan's config, restored through setScanLevel; the level radio it checks.
results.levels = [];
for (const config of input.levels || []) {
  const radios = ["inventory", "standard", "full"].map((value) => ({ value, checked: value === "standard" }));
  controls = {};
  context.document.querySelectorAll = (selector) => (selector === "input[name='scan_level']" ? radios : []);
  context.document.querySelector = (selector) => (selector === "input[name='scan_level']:checked"
    ? radios.find((radio) => radio.checked) || null : element(selector));
  context.setScanLevel(config.scan_level);
  results.levels.push(context.scanLevelValue());
}
process.stdout.write(JSON.stringify(results));
