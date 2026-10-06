// Runs the console's real frontend/console/scan-scope.js against stand-in form fields.
// argv[2] is a JSON file: {"cases": [{"kind", "fields", "units", "server"}], "apply": [{"kind", "scope", "include_hidden"}]}.
// Prints, per case, what the console would send (readScanScope) and what it would refuse
// (scanScopeProblem); per apply, the scope read back after restoring it into the card.
const fs = require("fs");
const path = require("path");
const vm = require("vm");

const input = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
const source = fs.readFileSync(path.join(__dirname, "..", "..", "frontend", "console", "scan-scope.js"), "utf8");

function makeCard(fields = {}, units = {}) {
  const inputs = {};
  for (const name of ["include_paths", "exclude_paths", "exclude_folder_patterns", "exclude_extensions",
    "min_size", "max_size", "modified_after", "skip_hidden"]) {
    inputs[name] = { value: "", checked: false, dispatchEvent() {} };
  }
  Object.entries(fields).forEach(([name, value]) => {
    if (typeof value === "boolean") inputs[name].checked = value;
    else inputs[name].value = value;
  });
  const unitSelects = { min_size: { value: units.min_size || "KB" }, max_size: { value: units.max_size || "MB" } };
  const details = { open: false };
  const card = {
    dataset: { scopeMounted: "1" },
    innerHTML: "",
    inputs, unitSelects, details,
    addEventListener() {},
    dispatchEvent() {},
    // The file-server step's rule rows; the stand-in card has none.
    querySelectorAll() { return []; },
    querySelector(selector) {
      let match = selector.match(/data-scope-field="([^"]+)"/);
      if (match) return inputs[match[1]] || null;
      match = selector.match(/data-scope-unit="([^"]+)"/);
      if (match) return unitSelects[match[1]] || null;
      if (selector.includes("data-scope-details")) return details;
      return null;
    },
  };
  return card;
}

const cards = {};
const context = {
  console,
  Event: function Event(type) { this.type = type; },
  document: {
    querySelector(selector) {
      const match = selector.match(/data-scan-scope="([^"]+)"/);
      return match ? cards[match[1]] || null : null;
    },
  },
};
vm.createContext(context);
vm.runInContext(source, context);

const results = { cases: [], apply: [] };
for (const item of input.cases || []) {
  cards[item.kind] = makeCard(item.fields, item.units);
  results.cases.push({
    scope: context.readScanScope(item.kind),
    problem: context.scanScopeProblem(item.kind, { server: item.server || "" }),
    skipHidden: context.scanScopeSkipsHidden(item.kind),
    count: context.countScanScopeRules(context.readScanScope(item.kind), { skipHidden: context.scanScopeSkipsHidden(item.kind) }),
    review: context.scanScopeReviewText(item.kind),
  });
}
for (const item of input.apply || []) {
  cards[item.kind] = makeCard();
  context.applyScanScope(item.kind, item.scope, item.include_hidden);
  results.apply.push({
    scope: context.readScanScope(item.kind),
    skipHidden: context.scanScopeSkipsHidden(item.kind),
    open: cards[item.kind].details.open,
    units: { min: cards[item.kind].unitSelects.min_size.value, max: cards[item.kind].unitSelects.max_size.value },
  });
}
results.historyNote = context.scanScopeHistoryNote(input.summary || {});
process.stdout.write(JSON.stringify(results));
