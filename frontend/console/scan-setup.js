/* ── File-server scan · Configuration step ────────────────────────
   One panel in three parts - Scope (which files the scan may read), Method (how
   each is read), Compliance (which regulations findings map to) - beside a
   manifest that says, in the scan's own terms, what it will do.

   The controls are the ones the step always had, under the same ids, so the
   request (readPayload), a saved scan (collectFileServerProfile /
   applyFileServerProfile) and the review step read them as before. What is here:

   - the file-type mode: all file types (optionally except some), or only a set -
     Recommended, Secrets, Broad, or a custom pick;
   - hidden and system files as two plain choices, where they used to be two
     pseudo-extensions hidden in the type list;
   - which target row shows: shares for a file server named in Basics, the local
     folder otherwise;
   - checks as you go, beside the field, without taking focus;
   - the manifest, rebuilt on every change; each line jumps to its control.

   Loaded before app.js, like every file in console/: definitions and DOM wiring
   only. app.js's functions (readPayload, readSelectedExtensions ...) are called
   when a handler runs, never while this file loads. */

const SETUP_PRESET_NOTES = {
  recommended: "Documents, spreadsheets, data exports, mail, databases and secrets",
  secrets: "Keys, certificates, vaults, configuration and remote-access profiles",
  broad: "Every type Sentro lists except images, audio and video",
};
const SETUP_GROUP_LABELS = {
  "secrets & config": "Secrets", documents: "Documents", "data & exports": "Data", "source code": "Code",
  archives: "Archives", "system & binaries": "System", media: "Media", custom: "Custom", other: "Other",
};
let setupActiveGroup = "all";

function setupEl(selector) {
  return document.querySelector(selector);
}

function setupStep() {
  return setupEl('#fs-wizard [data-wizard-step="2"]');
}

// ---- File types -------------------------------------------------------------

function scanTypeMode() {
  return setupEl("input[name='ext-type-mode']:checked")?.value === "all" ? "all" : "selected";
}

function customTypesOpen() {
  const panel = setupEl("#ext-advanced-mode");
  return Boolean(panel && !panel.classList.contains("hidden"));
}

function setCustomTypes(open) {
  const panel = setupEl("#ext-advanced-mode");
  const toggle = setupEl("#ext-custom-toggle");
  if (!panel) return;
  panel.classList.toggle("hidden", !open);
  toggle?.setAttribute("aria-pressed", String(open));
  setupEl("#ext-simple-mode")?.classList.toggle("is-custom", open);
  if (open) renderTypeGroups();
}

function setScanTypeMode(mode) {
  document.querySelectorAll("input[name='ext-type-mode']").forEach((radio) => {
    radio.checked = radio.value === mode;
  });
  syncTypeMode();
}

function syncTypeMode() {
  const mode = scanTypeMode();
  document.querySelectorAll("#cfg-scope [data-types-mode]").forEach((block) => {
    block.hidden = block.dataset.typesMode !== mode;
  });
  // A scope saved with both a type set and exclusions keeps showing the exclusions.
  const except = setupEl('#cfg-scope [data-types-mode="all"]');
  const excluded = String(setupEl("#file-server-scope-exclude_extensions")?.value || "").trim();
  if (except && mode === "selected" && excluded) except.hidden = false;
}

function selectedTypeCount() {
  return readSelectedExtensions(allowedExtensionsList).filter((item) => item.startsWith(".")).length;
}

function scanTypesLabel() {
  if (scanTypeMode() === "all") {
    const except = readScanScope("file-server").exclude_extensions || [];
    return except.length ? `All file types except ${except.length}` : "All file types";
  }
  const count = selectedTypeCount();
  if (customTypesOpen()) return `Custom (${count} types)`;
  const preset = setupEl("input[name='ext-preset']:checked");
  const name = preset?.closest("label")?.textContent?.trim() || "Recommended";
  return `${name} (${count} types)`;
}

function renderPresetNote() {
  const note = setupEl("#ext-preset-desc");
  if (!note) return;
  const count = selectedTypeCount();
  const types = `${count} type${count === 1 ? "" : "s"}`;
  if (customTypesOpen()) {
    note.textContent = count ? `${types} chosen. Files of any other type are not opened.` : "Choose at least one type below.";
    return;
  }
  const preset = setupEl("input[name='ext-preset']:checked")?.value || "recommended";
  note.textContent = `${SETUP_PRESET_NOTES[preset] || ""} - ${types}.`;
}

// The type list shows one group at a time - no list scrolling inside the page.
function renderTypeGroups() {
  const host = setupEl("[data-picker-groups]");
  const list = setupEl("#allowed_extensions");
  if (!host || !list) return;
  const searching = Boolean(String(setupEl("#extension-search")?.value || "").trim());
  const groups = [...list.querySelectorAll(".extension-group")]
    .map((group) => group.dataset.extensionGroupWrap)
    .filter((key) => key && key !== "scope");
  if (setupActiveGroup !== "all" && !groups.includes(setupActiveGroup)) setupActiveGroup = "all";
  const active = searching ? "all" : setupActiveGroup;
  list.dataset.activeGroup = active;
  const chosen = (key) => list.querySelectorAll(`.extension-group[data-extension-group-wrap="${key}"] input:checked`).length;
  const pill = (key, label, count) => `<button type="button" class="cfg-group-pill plain-btn" data-picker-group="${key}" aria-pressed="${active === key}">${escapeHtml(label)}${count ? ` <span>${count}</span>` : ""}</button>`;
  host.innerHTML = pill("all", "All groups", 0)
    + groups.map((key) => pill(key, SETUP_GROUP_LABELS[key] || key, chosen(key))).join("");
}

// ---- Hidden and system files -----------------------------------------------

function readSpecialFiles() {
  const hidden = setupEl("#fs-hidden-files")?.value || "include";
  const system = setupEl("#fs-system-files")?.value || "skip";
  return {
    include_hidden: hidden !== "skip",
    hidden_filter_enabled: hidden === "only",
    include_system: system !== "skip",
    system_filter_enabled: system === "only",
  };
}

function applySpecialFiles(config = {}) {
  const hidden = setupEl("#fs-hidden-files");
  const system = setupEl("#fs-system-files");
  if (hidden) hidden.value = config.hidden_filter_enabled ? "only" : config.include_hidden === false ? "skip" : "include";
  if (system) system.value = config.system_filter_enabled ? "only" : config.include_system ? "include" : "skip";
}

// ---- Target and method -----------------------------------------------------

function syncScanTarget() {
  const remote = Boolean(String(setupEl("#server")?.value || "").trim());
  document.querySelectorAll("#cfg-scope [data-cfg-target]").forEach((row) => {
    row.hidden = row.dataset.cfgTarget !== (remote ? "smb" : "local");
  });
}

function scanLevelValue() {
  return setupEl("input[name='scan_level']:checked")?.value || "standard";
}

function setScanLevel(level) {
  const value = ["inventory", "standard", "full"].includes(level) ? level : "standard";
  document.querySelectorAll("input[name='scan_level']").forEach((radio) => {
    radio.checked = radio.value === value;
  });
  syncScanMethod();
}

// What a level does to the choices beside it - said, not silently overridden.
function syncScanMethod() {
  const level = scanLevelValue();
  const note = setupEl("#archives-note");
  if (note) {
    note.textContent = level === "inventory" ? "not at Inventory, which reads no content"
      : level === "full" ? "always, at Full compliance" : "read the files inside";
  }
  const hint = setupEl("#compliance-hint");
  if (hint) {
    hint.textContent = level === "full"
      ? "Full compliance applies every framework unless you choose some."
      : level === "inventory" ? "Inventory reads no content, so nothing is mapped." : "Choose one or more frameworks.";
  }
}

// ---- Checks -----------------------------------------------------------------

// Everything the step would refuse, each with the field it is about.
function scanSetupProblems() {
  const problems = [];
  const server = String(setupEl("#server")?.value || "").trim();
  const depth = Number(setupEl("#max_depth")?.value);
  if (!Number.isInteger(depth) || depth < 1 || depth > 12) {
    problems.push({ field: "#max_depth", message: "Folder depth is a whole number from 1 to 12." });
  }
  if (server && setupEl("#smb_encryption")?.checked && !String(setupEl("#smb_shares")?.value || "").trim()) {
    problems.push({ field: "#smb_shares", message: "Name the shares: an SMB 3 encrypted scan cannot list a server's shares." });
  }
  if (scanTypeMode() === "selected" && customTypesOpen() && !selectedTypeCount()) {
    problems.push({ field: "#extension-search", message: "Choose at least one file type, or scan all file types." });
  }
  const scope = scanScopeProblem("file-server", { server });
  if (scope) problems.push(scope);
  return problems;
}

// The same message and markup showFieldError writes, without moving focus: these
// run as the operator types.
function markSetupField(selector, message) {
  const field = setupEl(selector);
  if (!field) return;
  const id = `${field.id || "field"}-error`;
  let note = document.getElementById(id);
  if (!note) {
    note = document.createElement("span");
    note.className = "field-error";
    note.id = id;
    (field.closest("label") || field.parentElement || field).appendChild(note);
  }
  note.textContent = message;
  field.setAttribute("aria-invalid", "true");
  field.setAttribute("aria-describedby", id);
}

function checkScanSetup() {
  const step = setupStep();
  if (!step) return [];
  const problems = scanSetupProblems();
  const marked = new Set(problems.map((problem) => problem.field));
  step.querySelectorAll("[aria-invalid='true']").forEach((field) => {
    if (marked.has(`#${field.id}`)) return;
    field.removeAttribute("aria-invalid");
    field.removeAttribute("aria-describedby");
    document.getElementById(`${field.id}-error`)?.remove();
  });
  problems.forEach((problem) => markSetupField(problem.field, problem.message));
  return problems;
}

// ---- The manifest -----------------------------------------------------------

function manifestRows() {
  const payload = readPayload();
  const scope = payload.scope || {};
  const server = String(payload.server || "").trim();
  const shares = payload.smb_shares || [];
  const rows = [];
  rows.push({
    key: "Target", jump: server ? "#smb_shares" : "#local_path", mono: true,
    value: server ? `\\\\${server}` : payload.local_path,
    note: server ? (shares.length ? shares.join(", ") : "every share") : "local folder",
  });
  rows.push({ key: "Depth", jump: "#max_depth", value: `${payload.max_depth} level${Number(payload.max_depth) === 1 ? "" : "s"}` });
  rows.push({ key: "Files", jump: "input[name='ext-type-mode']:checked", value: scanTypesLabel() });
  if (scope.exclude_extensions?.length) {
    rows.push({ key: "Except", jump: "#file-server-scope-exclude_extensions", mono: true, value: listText(scope.exclude_extensions, 5) });
  }
  if (scope.include_paths?.length) rows.push({ key: "Only in", jump: "#file-server-scope-include_paths", mono: true, value: listText(scope.include_paths, 3) });
  if (scope.exclude_paths?.length) rows.push({ key: "Skips", jump: "#file-server-scope-exclude_paths", mono: true, value: listText(scope.exclude_paths, 3) });
  if (scope.exclude_folder_patterns?.length) {
    rows.push({ key: "Skips named", jump: "#file-server-scope-exclude_folder_patterns", mono: true, value: listText(scope.exclude_folder_patterns, 4) });
  }
  const minimum = scope.min_size_bytes;
  const maximum = scope.max_size_bytes;
  if (minimum != null || maximum != null) {
    const value = minimum != null && maximum != null ? `${formatScopeBytes(minimum)} to ${formatScopeBytes(maximum)}`
      : maximum != null ? `up to ${formatScopeBytes(maximum)}` : `${formatScopeBytes(minimum)} or more`;
    rows.push({ key: "Size", jump: "#file-server-scope-max_size", mono: true, value });
  }
  if (scope.modified_after) rows.push({ key: "Modified", jump: "#file-server-scope-modified_after", mono: true, value: `on or after ${scope.modified_after}` });
  const hidden = setupEl("#fs-hidden-files")?.value || "include";
  const system = setupEl("#fs-system-files")?.value || "skip";
  const special = { include: "included", skip: "skipped", only: "only these" };
  rows.push({ key: "Hidden files", jump: "#fs-hidden-files", value: special[hidden] });
  rows.push({ key: "System files", jump: "#fs-system-files", value: special[system] });
  const level = { inventory: "Inventory", standard: "Standard", full: "Full compliance" }[scanLevelValue()];
  const options = [payload.incremental_enabled && "incremental", payload.async_scan && "background",
    payload.inspect_archives && "archives"].filter(Boolean);
  rows.push({ key: "Method", jump: "input[name='scan_level']:checked", value: options.length ? `${level} · ${options.join(", ")}` : level });
  const names = (payload.compliance_frameworks || [])
    .map((id) => (COMPLIANCE_FRAMEWORKS.find((framework) => framework.id === id) || { name: id }).name);
  rows.push({
    key: "Compliance", jump: "#compliance-enabled",
    value: names.length ? names.join(" + ") : scanLevelValue() === "full" ? "every framework" : "not mapped",
  });
  return rows;
}

function listText(items, limit) {
  return items.length > limit ? `${items.slice(0, limit).join(", ")} +${items.length - limit}` : items.join(", ");
}

function renderScanManifest() {
  const list = setupEl("#cfg-manifest");
  if (!list) return;
  let rows;
  try {
    rows = manifestRows();
  } catch {
    return; // a half-built form (boot, a reset) is described on its next change
  }
  list.innerHTML = rows.map((row) => `
    <li><button type="button" class="cfg-manifest-row plain-btn" data-cfg-jump="${escapeHtml(row.jump)}">
      <span class="cfg-manifest-key">${escapeHtml(row.key)}</span>
      <span class="cfg-manifest-value${row.mono ? " is-literal" : ""}">${escapeHtml(row.value)}${row.note ? ` <small>${escapeHtml(row.note)}</small>` : ""}</span>
    </button></li>`).join("");
  const status = setupEl("#cfg-manifest-status");
  if (status) {
    const problems = scanSetupProblems();
    status.classList.toggle("has-problems", problems.length > 0);
    status.innerHTML = problems.length
      ? `<button type="button" class="plain-btn" data-cfg-jump="${escapeHtml(problems[0].field)}">${problems.length} to fix: ${escapeHtml(problems[0].message)}</button>`
      : "Ready for review";
  }
}

// ---- Wiring -----------------------------------------------------------------

// Everything a change on the step can move, in one pass.
function syncScanSetup() {
  syncScanTarget();
  syncTypeMode();
  syncScanMethod();
  if (customTypesOpen()) renderTypeGroups();
  renderPresetNote();
  renderScanManifest();
}

// Restore what a saved scan says (applyFileServerProfile), or a new scan's defaults.
function applyScanSetup(config = {}, ui = {}) {
  setScanLevel(config.scan_level);
  applySpecialFiles(config);
  const mode = ui.ext_mode === "all" || ui.ext_preset === "all" ? "all" : "selected";
  setScanTypeMode(mode);
  setCustomTypes(mode === "selected" && !ui.ext_preset && Array.isArray(ui.extensions) && ui.extensions.length > 0);
  setupStep()?.querySelectorAll("[aria-invalid='true']").forEach((field) => {
    field.removeAttribute("aria-invalid");
    field.removeAttribute("aria-describedby");
    document.getElementById(`${field.id}-error`)?.remove();
  });
  syncScanSetup();
}

function jumpToSetupControl(selector) {
  const target = setupEl(selector);
  if (!target) return;
  const row = target.closest("[data-scope-rule]");
  if (row?.hidden) return;
  target.scrollIntoView({ block: "center" });
  target.focus({ preventScroll: true });
}

function initScanSetup() {
  const step = setupStep();
  if (!step || step.dataset.setupReady) return;
  step.dataset.setupReady = "1";
  let pending = 0;
  const later = () => {
    window.clearTimeout(pending);
    pending = window.setTimeout(syncScanSetup, 60);
  };
  step.addEventListener("input", later);
  step.addEventListener("change", (event) => {
    if (event.target.matches("input[name='ext-type-mode']")) syncTypeMode();
    if (event.target.matches("input[name='ext-preset']")) setCustomTypes(false);
    if (event.target.matches("input[name='scan_level']")) syncScanMethod();
    later();
  });
  // Checks run when the operator leaves a field, not on every keystroke.
  step.addEventListener("focusout", () => window.setTimeout(checkScanSetup, 0));
  step.addEventListener("click", (event) => {
    const pill = event.target.closest("[data-picker-group]");
    if (pill) {
      setupActiveGroup = pill.dataset.pickerGroup;
      const search = setupEl("#extension-search");
      if (search && search.value) {
        search.value = "";
        search.dispatchEvent(new Event("input", { bubbles: true }));
      }
      renderTypeGroups();
      return;
    }
    if (event.target.closest("#ext-custom-toggle")) {
      setCustomTypes(!customTypesOpen());
      later();
      return;
    }
    const jump = event.target.closest("[data-cfg-jump]");
    if (jump) {
      jumpToSetupControl(jump.dataset.cfgJump);
      return;
    }
    if (event.target.closest("[data-extension-preset], [data-remove-extension], #add-custom-extension-btn, [data-scope-add], [data-scope-rule-add], [data-scope-rule-remove]")) {
      later();
    }
  });
  setupEl("#server")?.addEventListener("input", later);
  // No sync here: app.js, whose functions the sync calls, loads after this file. The
  // step is synced when the wizard opens (applyScanSetup) and on every change.
}

initScanSetup();
