/* ── Advanced scan scope ──────────────────────────────────────────
   What a scan leaves out before it reads it: folders, file types, sizes and a date.
   One card, rendered into each scan wizard ([data-scan-scope="file-server"] and
   [data-scan-scope="endpoint"]), read into the request's `scope`, restored from a
   saved scan and summarised on the review step, the scan cards and the history.

   The server applies every rule as the target is enumerated (collectors/scan_scope.py):
   a folder out of scope is never listed, a file out of scope never opened, read,
   hashed or stored. It checks the rules again; the checks here are the same ones, so
   a mistake is named beside its field instead of as a refused request.

   The endpoint wizard's card is rendered here. The file-server wizard's fields are
   written into its Configuration step (index.html): the types to skip beside the file
   types, the folders, sizes and date under Advanced options.

   There is no folder-name rule: a scan reads every folder of its target, narrowed only
   by path, type, size and date - the rules the server accepts (collectors/scan_scope.py).

   Loaded before app.js, like every file in console/: definitions and DOM wiring
   only. The console's helpers (escapeHtml ...) are used when a handler runs. */

const SCOPE_SIZE_UNITS = { KB: 1024, MB: 1024 ** 2, GB: 1024 ** 3 };
// The server's extension rule (collectors.file_scanner.EXTENSION_PATTERN).
const SCOPE_EXTENSION_RE = /^\.[a-z0-9][a-z0-9._+-]{0,40}$/;
// One click adds a group; the operator can type any extension or name.
const SCOPE_EXTENSION_GROUPS = [
  { label: "Disk images & VMs", items: [".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".ova", ".qcow2"] },
  { label: "Installers & binaries", items: [".exe", ".dll", ".msi", ".sys", ".cab"] },
  { label: "Video & audio", items: [".mp4", ".mkv", ".avi", ".mov", ".wmv", ".mp3", ".wav", ".flac"] },
  { label: "Archives", items: [".zip", ".7z", ".rar", ".tar", ".gz", ".tgz"] },
];
const SCOPE_KINDS = ["file-server", "endpoint"];

function scopeRoot(kind) {
  return document.querySelector(`[data-scan-scope="${kind}"]`);
}

function scopeField(kind, name) {
  return scopeRoot(kind)?.querySelector(`[data-scope-field="${name}"]`) || null;
}

function scopeId(kind, name) {
  return `${kind}-scope-${name}`;
}

function scopeMarkup(kind) {
  const endpoint = kind === "endpoint";
  const id = (name) => scopeId(kind, name);
  const quick = (groups, target) => groups.map((group) => (
    `<button type="button" class="secondary-btn mini-btn" data-scope-add="${target}" data-scope-items="${group.items.join(" ")}">+ ${group.label.replace(/&/g, "&amp;")}</button>`
  )).join("");
  const sizeUnits = (selected) => Object.keys(SCOPE_SIZE_UNITS)
    .map((unit) => `<option value="${unit}"${unit === selected ? " selected" : ""}>${unit}</option>`).join("");
  const grid = endpoint ? "asset-form-grid endpoint-form scope-fields" : "wizard-behavior-fields scope-fields";
  const includeField = endpoint ? "" : `
      <div class="scope-field scope-field-wide">
        <label for="${id("include_paths")}">Only these folders</label>
        <textarea id="${id("include_paths")}" data-scope-field="include_paths" rows="2" spellcheck="false"
          placeholder="Finance/Reports&#10;HR/Contracts" aria-describedby="${id("include_paths")}-hint"></textarea>
        <small id="${id("include_paths")}-hint" class="field-hint">One per line, under the target - share/folder on a file server. Empty walks everything.</small>
      </div>`;
  return `
    <details class="scan-advanced scope-advanced" data-scope-details>
      <summary>
        <span class="scope-summary-title">Advanced scan scope</span>
        <span class="scope-summary-count" data-scope-count>No rules</span>
      </summary>
      <p class="field-hint scope-intro">Leave out what this scan should not spend time on. A folder or file out of scope is never listed, opened, read, hashed or stored, and is not counted as a failure. An exclusion always wins over an inclusion.</p>
      <div class="${grid}">${includeField}
        <div class="scope-field scope-field-wide">
          <label for="${id("exclude_paths")}">Skip these folders</label>
          <textarea id="${id("exclude_paths")}" data-scope-field="exclude_paths" rows="2" spellcheck="false"
            placeholder="${endpoint ? "C:\\Users\\j.doe\\Downloads\\ISOs" : "Finance/Archive&#10;IT/Software"}" aria-describedby="${id("exclude_paths")}-hint"></textarea>
          <small id="${id("exclude_paths")}-hint" class="field-hint">${endpoint
            ? "One per line, as a full path - C:\\... or \\\\server\\share\\... Everything under each is skipped."
            : "One per line, under the target. Everything under each is skipped."}</small>
        </div>
        <div class="scope-field">
          <label for="${id("exclude_extensions")}">Skip file types</label>
          <input id="${id("exclude_extensions")}" data-scope-field="exclude_extensions" autocomplete="off" spellcheck="false"
            placeholder=".iso, .vhdx, .mp4" aria-describedby="${id("exclude_extensions")}-hint" />
          <small id="${id("exclude_extensions")}-hint" class="field-hint">Never scanned, whatever the file types above allow.</small>
          <span class="scope-quick">${quick(SCOPE_EXTENSION_GROUPS, "exclude_extensions")}</span>
        </div>
        <div class="scope-field">
          <label for="${id("min_size")}">Skip files smaller than</label>
          <span class="scope-size">
            <input id="${id("min_size")}" data-scope-field="min_size" type="number" min="0" step="any" inputmode="decimal" placeholder="No minimum" />
            <select data-scope-unit="min_size" aria-label="Unit of the minimum size">${sizeUnits("KB")}</select>
          </span>
        </div>
        <div class="scope-field">
          <label for="${id("max_size")}">Skip files larger than</label>
          <span class="scope-size">
            <input id="${id("max_size")}" data-scope-field="max_size" type="number" min="0" step="any" inputmode="decimal" placeholder="No maximum" />
            <select data-scope-unit="max_size" aria-label="Unit of the maximum size">${sizeUnits("MB")}</select>
          </span>
          <small class="field-hint">Decided from the file listing: a file over the limit is not downloaded to find out.</small>
        </div>
        <div class="scope-field">
          <label for="${id("modified_after")}">Only files modified on or after</label>
          <input id="${id("modified_after")}" data-scope-field="modified_after" type="date" />
        </div>
        <label class="checkbox-row scope-check">
          <input id="${id("skip_hidden")}" data-scope-field="skip_hidden" type="checkbox" />
          <span>Skip hidden files and folders</span>
        </label>
      </div>
      <div class="scope-footer">
        <p class="scope-describe" data-scope-describe aria-live="polite"></p>
        <button type="button" class="secondary-btn mini-btn" data-scope-clear>Clear scope</button>
      </div>
    </details>`;
}

function splitScopeList(value, { lines = false } = {}) {
  // Paths may hold commas, so they are one per line (or ;); names and types also split on commas.
  const separator = lines ? /[\r\n;]+/ : /[\r\n;,]+/;
  return String(value || "").split(separator).map((item) => item.trim()).filter(Boolean);
}

function normalizeScopeExtension(token) {
  let value = String(token || "").trim().replace(/^['"]+|['"]+$/g, "").trim().toLowerCase().replace(/^\*+/, "");
  if (!value) return "";
  if (!value.startsWith(".")) value = `.${value}`;
  return value;
}

function readScopeSize(kind, name) {
  const input = scopeField(kind, name);
  const raw = String(input?.value || "").trim();
  if (!raw) return null;
  const unit = scopeRoot(kind)?.querySelector(`[data-scope-unit="${name}"]`)?.value || "MB";
  const number = Number(raw);
  if (!Number.isFinite(number) || number < 0) return Number.NaN;
  return Math.round(number * (SCOPE_SIZE_UNITS[unit] || SCOPE_SIZE_UNITS.MB));
}

// The request's `scope`: only the rules that are set. {} is no rule - the scan as before.
function readScanScope(kind) {
  const scope = {};
  const lists = {
    include_paths: { lines: true }, exclude_paths: { lines: true }, exclude_extensions: {},
  };
  Object.entries(lists).forEach(([name, options]) => {
    const values = splitScopeList(scopeField(kind, name)?.value, options);
    if (values.length) scope[name] = name === "exclude_extensions" ? values.map(normalizeScopeExtension) : values;
  });
  const minimum = readScopeSize(kind, "min_size");
  const maximum = readScopeSize(kind, "max_size");
  if (minimum !== null) scope.min_size_bytes = minimum;
  if (maximum !== null) scope.max_size_bytes = maximum;
  const after = String(scopeField(kind, "modified_after")?.value || "").trim();
  if (after) scope.modified_after = after;
  return scope;
}

function scanScopeSkipsHidden(kind) {
  return Boolean(scopeField(kind, "skip_hidden")?.checked);
}

// The first rule the server would refuse, as {field, message}; null when there is none.
// `server` is the file server's host (an SMB scan's paths are share-relative).
function scanScopeProblem(kind, { server = "" } = {}) {
  const field = (name) => `#${scopeId(kind, name)}`;
  const scope = readScanScope(kind);
  const endpoint = kind === "endpoint";
  const badExtension = (scope.exclude_extensions || []).find((item) => !SCOPE_EXTENSION_RE.test(item));
  if (badExtension) return { field: field("exclude_extensions"), message: `"${badExtension}" is not a file extension - for example .iso or vhdx.` };
  for (const [name, label] of [["min_size_bytes", "min_size"], ["max_size_bytes", "max_size"]]) {
    if (Number.isNaN(scope[name])) return { field: field(label), message: "Enter a size of zero or more." };
  }
  if (scope.max_size_bytes === 0) return { field: field("max_size"), message: "A maximum of zero would skip every file." };
  if (scope.min_size_bytes != null && scope.max_size_bytes != null && scope.min_size_bytes > scope.max_size_bytes) {
    return { field: field("min_size"), message: "The minimum size is larger than the maximum: no file would be scanned." };
  }
  if (scope.modified_after) {
    const today = new Date().toISOString().slice(0, 10);
    if (scope.modified_after > today) return { field: field("modified_after"), message: "The date is in the future: no file would be scanned." };
  }
  const host = String(server || "").trim().toLowerCase();
  for (const name of ["include_paths", "exclude_paths"]) {
    for (const path of scope[name] || []) {
      const unc = /^(\\\\|\/\/)/.test(path);
      const drive = /^[a-z]:([\\/]|$)/i.test(path);
      if (/[*?]/.test(path)) return { field: field(name), message: `"${path}": a path cannot hold * or ? - give the folder itself.` };
      if (path.split(/[\\/]+/).includes("..")) return { field: field(name), message: `"${path}": a path cannot climb out of the scan with "..".` };
      if (endpoint && !unc && !drive) return { field: field(name), message: `"${path}": on an endpoint, give the full path - C:\\... or \\\\server\\share\\...` };
      if (!endpoint && drive) return { field: field(name), message: `"${path}": give the folder under the target, like Finance/Archive (share/folder on a file server).` };
      if (!endpoint && unc) {
        const named = path.replace(/^(\\\\|\/\/)/, "").split(/[\\/]/)[0].toLowerCase();
        if (!host) return { field: field(name), message: `"${path}": a local scan's folders are under its local path, not network paths.` };
        if (named !== host) return { field: field(name), message: `"${path}" names another server than ${server}.` };
      }
    }
  }
  return null;
}

function formatScopeBytes(bytes) {
  const value = Number(bytes || 0);
  for (const unit of ["GB", "MB", "KB"]) {
    const size = SCOPE_SIZE_UNITS[unit];
    if (value >= size) {
      const amount = value / size;
      return `${Number.isInteger(amount) ? amount : amount.toFixed(1)} ${unit}`;
    }
  }
  return `${value} bytes`;
}

// How many rules a scope holds - one per path and type, one per limit.
function countScanScopeRules(scope = {}, { skipHidden = false } = {}) {
  let count = 0;
  ["include_paths", "exclude_paths", "exclude_extensions"].forEach((name) => {
    count += Array.isArray(scope[name]) ? scope[name].length : 0;
  });
  ["min_size_bytes", "max_size_bytes", "modified_after"].forEach((name) => {
    if (scope[name] !== undefined && scope[name] !== null && scope[name] !== "") count += 1;
  });
  return count + (skipHidden ? 1 : 0);
}

// The scope in a sentence's worth of phrases, for the card, the review and the history.
function describeScanScope(scope = {}, { skipHidden = false } = {}) {
  const parts = [];
  const list = (items, limit = 3) => (items.length > limit ? `${items.slice(0, limit).join(", ")} +${items.length - limit}` : items.join(", "));
  const plural = (count, word) => `${count} ${word}${count === 1 ? "" : "s"}`;
  if (scope.include_paths?.length) parts.push(`only ${list(scope.include_paths, 2)}`);
  if (scope.exclude_paths?.length) parts.push(`skip ${plural(scope.exclude_paths.length, "folder")}`);
  if (scope.exclude_extensions?.length) parts.push(`skip ${list(scope.exclude_extensions, 4)}`);
  if (scope.min_size_bytes != null) parts.push(`smaller than ${formatScopeBytes(scope.min_size_bytes)} skipped`);
  if (scope.max_size_bytes != null) parts.push(`larger than ${formatScopeBytes(scope.max_size_bytes)} skipped`);
  if (scope.modified_after) parts.push(`modified since ${scope.modified_after}`);
  if (skipHidden) parts.push("hidden skipped");
  return parts;
}

function scanScopeReviewText(kind) {
  const scope = readScanScope(kind);
  const skipHidden = scanScopeSkipsHidden(kind);
  const count = countScanScopeRules(scope, { skipHidden });
  if (!count) return "No scope rules - everything the file types allow";
  return `${count} rule${count === 1 ? "" : "s"}: ${describeScanScope(scope, { skipHidden }).join("; ")}`;
}

function refreshScanScope(kind) {
  const root = scopeRoot(kind);
  if (!root) return;
  const scope = readScanScope(kind);
  const skipHidden = scanScopeSkipsHidden(kind);
  const count = countScanScopeRules(scope, { skipHidden });
  const counter = root.querySelector("[data-scope-count]");
  if (counter) {
    counter.textContent = count ? `${count} rule${count === 1 ? "" : "s"} active` : "No rules";
    counter.classList.toggle("on", count > 0);
  }
  const describe = root.querySelector("[data-scope-describe]");
  if (describe) {
    describe.textContent = count
      ? `This scan will ${describeScanScope(scope, { skipHidden }).join("; ")}.`
      : "Every file the file types allow is scanned.";
  }
}

function setScopeSize(kind, name, bytes) {
  const input = scopeField(kind, name);
  const unitSelect = scopeRoot(kind)?.querySelector(`[data-scope-unit="${name}"]`);
  if (!input) return;
  if (bytes === undefined || bytes === null || bytes === "") {
    input.value = "";
    return;
  }
  const value = Number(bytes);
  const unit = ["GB", "MB", "KB"].find((candidate) => value >= SCOPE_SIZE_UNITS[candidate] && value % SCOPE_SIZE_UNITS[candidate] === 0)
    || (value >= SCOPE_SIZE_UNITS.MB ? "MB" : "KB");
  if (unitSelect) unitSelect.value = unit;
  const amount = value / SCOPE_SIZE_UNITS[unit];
  input.value = Number.isInteger(amount) ? String(amount) : String(Number(amount.toFixed(3)));
}

// A saved scan's scope back into its wizard; nothing (a new scan) clears it.
function applyScanScope(kind, scope, includeHidden = true) {
  const root = scopeRoot(kind);
  if (!root) return;
  const saved = scope && typeof scope === "object" ? scope : {};
  const join = (values, separator) => (Array.isArray(values) ? values.join(separator) : "");
  const set = (name, value) => {
    const input = scopeField(kind, name);
    if (input) input.value = value;
  };
  set("include_paths", join(saved.include_paths, "\n"));
  set("exclude_paths", join(saved.exclude_paths, "\n"));
  set("exclude_extensions", join(saved.exclude_extensions, ", "));
  setScopeSize(kind, "min_size", saved.min_size_bytes);
  setScopeSize(kind, "max_size", saved.max_size_bytes);
  set("modified_after", saved.modified_after ? String(saved.modified_after).slice(0, 10) : "");
  const hidden = scopeField(kind, "skip_hidden");
  if (hidden) hidden.checked = includeHidden === false;
  const details = root.querySelector("[data-scope-details]");
  const count = countScanScopeRules(saved, { skipHidden: includeHidden === false });
  // A saved scan with rules opens on them; a new one starts folded.
  if (details) details.open = count > 0;
  refreshScanScope(kind);
}

function addScopeItems(kind, name, items) {
  const input = scopeField(kind, name);
  if (!input) return;
  const current = splitScopeList(input.value);
  const seen = new Set(current.map((item) => item.toLowerCase()));
  items.forEach((item) => {
    if (!seen.has(item.toLowerCase())) {
      current.push(item);
      seen.add(item.toLowerCase());
    }
  });
  input.value = current.join(", ");
  input.dispatchEvent(new Event("input", { bubbles: true }));
}

// What a scan's summary says its scope left out - the history row's note.
function scanScopeHistoryNote(summary = {}) {
  const scope = summary.scope;
  if (!scope || typeof scope !== "object") return "";
  const excluded = Number(summary.excluded_by_scope || 0);
  const folders = Number(summary.folders_skipped_by_scope || 0);
  const parts = [`scoped (${Number(scope.rule_count || 0)} rule${Number(scope.rule_count || 0) === 1 ? "" : "s"})`];
  if (excluded) parts.push(`${excluded.toLocaleString()} file${excluded === 1 ? "" : "s"} left out`);
  if (folders) parts.push(`${folders.toLocaleString()} folder${folders === 1 ? "" : "s"} skipped`);
  return parts.join(", ");
}

function mountScanScope(kind) {
  const root = scopeRoot(kind);
  if (!root || root.dataset.scopeMounted) return;
  root.dataset.scopeMounted = "1";
  // A wizard that writes its own fields (the file-server Configuration step) keeps them.
  if (!root.querySelector("[data-scope-field]")) root.innerHTML = scopeMarkup(kind);
  root.addEventListener("input", () => refreshScanScope(kind));
  root.addEventListener("change", () => refreshScanScope(kind));
  root.addEventListener("click", (event) => {
    const add = event.target.closest("[data-scope-add]");
    if (add) {
      addScopeItems(kind, add.dataset.scopeAdd, String(add.dataset.scopeItems || "").split(" ").filter(Boolean));
      return;
    }
    if (event.target.closest("[data-scope-clear]")) {
      applyScanScope(kind, {}, true);
      const details = root.querySelector("[data-scope-details]");
      if (details) details.open = true;
      root.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
  refreshScanScope(kind);
}

SCOPE_KINDS.forEach(mountScanScope);
