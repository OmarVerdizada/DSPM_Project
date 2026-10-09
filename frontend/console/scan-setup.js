/* ── File-server scan · Configuration step ────────────────────────
   One box, "Scan settings", in two columns - What to scan (target, depth, file
   types) and How to scan (level, options, compliance frameworks) - with the
   settings most scans never change folded into Advanced options below them.

   The controls keep the ids the step always had, so the request (readPayload), a
   saved scan (collectFileServerProfile / applyFileServerProfile) and the review step
   read them as before. What is here:

   - file types as one choice: all file types (optionally skipping some), a set -
     Recommended, Secrets & credentials, Broad - or a custom pick;
   - hidden and system files as two plain choices;
   - which target field shows: shares for a file server named in Basics, the local
     folder otherwise;
   - Advanced options says whether it holds anything but defaults, opens itself for a
     saved scan that does, and opens to show a problem inside it;
   - checks as fields are left, beside the field, without taking focus.

   Loaded before app.js, like every file in console/: definitions and DOM wiring
   only. app.js's functions (readPayload, readSelectedExtensions ...) are called
   when a handler runs, never while this file loads. */

const SETUP_TYPE_NAMES = { recommended: "Recommended", secrets: "Secrets", broad: "Broad" };
const SETUP_GROUP_LABELS = {
  "secrets & config": "Secrets", documents: "Documents", "data & exports": "Data", "source code": "Code",
  archives: "Archives", "system & binaries": "System", media: "Media", custom: "Custom", other: "Other",
};
let setupActiveGroup = "";

function setupEl(selector) {
  return document.querySelector(selector);
}

function setupStep() {
  return setupEl('#fs-wizard [data-wizard-step="2"]');
}

// ---- File types -------------------------------------------------------------

function fileTypeChoice() {
  return setupEl("input[name='ext-preset']:checked")?.value || "recommended";
}

function scanTypeMode() {
  return fileTypeChoice() === "all" ? "all" : "selected";
}

function customTypesOpen() {
  const panel = setupEl("#ext-advanced-mode");
  return Boolean(panel && !panel.classList.contains("hidden"));
}

function setCustomTypes(open) {
  const panel = setupEl("#ext-advanced-mode");
  if (!panel) return;
  panel.classList.toggle("hidden", !open);
  if (open) renderTypeGroups();
}

function setFileTypeChoice(value) {
  document.querySelectorAll("input[name='ext-preset']").forEach((radio) => {
    radio.checked = radio.value === value;
  });
  syncFileTypes();
}

function syncFileTypes() {
  const choice = fileTypeChoice();
  setCustomTypes(choice === "custom");
  const except = setupEl('.cfg-box [data-types-mode="all"]');
  // A scan saved with both a type set and types to skip keeps showing what it skips.
  const skipped = String(setupEl("#file-server-scope-exclude_extensions")?.value || "").trim();
  if (except) except.hidden = !(choice === "all" || skipped);
}

function selectedTypeCount() {
  return readSelectedExtensions(allowedExtensionsList).filter((item) => item.startsWith(".")).length;
}

function scanTypesLabel() {
  const choice = fileTypeChoice();
  if (choice === "all") {
    const skipped = readScanScope("file-server").exclude_extensions || [];
    return skipped.length ? `All file types except ${skipped.length}` : "All file types";
  }
  const count = selectedTypeCount();
  if (choice === "custom") return `Custom (${count} types)`;
  return `${SETUP_TYPE_NAMES[choice] || "Recommended"} (${count} types)`;
}

// The cards say what each set holds; the line under them, what this scan will open.
function renderTypeNote() {
  const note = setupEl("#ext-preset-desc");
  if (!note) return;
  const choice = fileTypeChoice();
  const count = selectedTypeCount();
  const types = `${count} file type${count === 1 ? "" : "s"}`;
  if (choice === "all") note.textContent = "No type filter: every file is scanned. Skip any types you do not need.";
  else if (choice === "custom") note.textContent = count ? `${types} chosen. Files of any other type are skipped.` : "Choose at least one type below.";
  else note.textContent = `${SETUP_TYPE_NAMES[choice] || "This set"}: ${types}. Files of any other type are skipped.`;
}

// The custom list shows one group at a time - nothing scrolls inside the page, and a
// half-width column never lays out every type at once. A search looks in every group.
function renderTypeGroups() {
  const host = setupEl("[data-picker-groups]");
  const list = setupEl("#allowed_extensions");
  if (!host || !list) return;
  const searching = Boolean(String(setupEl("#extension-search")?.value || "").trim());
  const groups = [...list.querySelectorAll(".extension-group")]
    .map((group) => group.dataset.extensionGroupWrap)
    .filter((key) => key && key !== "scope");
  if (!groups.includes(setupActiveGroup)) {
    // Open on the group that holds the first type chosen.
    const first = list.querySelector(".extension-group:not([data-extension-group-wrap='scope']) input:checked");
    setupActiveGroup = first?.closest(".extension-group")?.dataset.extensionGroupWrap || groups[0] || "";
  }
  const active = searching ? "all" : setupActiveGroup;
  list.dataset.activeGroup = active;
  const chosen = (key) => list.querySelectorAll(`.extension-group[data-extension-group-wrap="${key}"] input:checked`).length;
  host.innerHTML = groups.map((key) => {
    const count = chosen(key);
    return `<button type="button" class="cfg-group-pill plain-btn" data-picker-group="${escapeHtml(key)}" aria-pressed="${active === key}">${escapeHtml(SETUP_GROUP_LABELS[key] || key)}${count ? ` <span>${count}</span>` : ""}</button>`;
  }).join("");
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

// ---- Target, method and compliance ------------------------------------------

function syncScanTarget() {
  const remote = Boolean(String(setupEl("#server")?.value || "").trim());
  document.querySelectorAll(".cfg-box [data-cfg-target]").forEach((block) => {
    block.hidden = block.dataset.cfgTarget !== (remote ? "smb" : "local");
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
    note.textContent = level === "inventory" ? "Not at Inventory, which reads no content"
      : level === "full" ? "Always, at Full compliance" : "Read the files inside";
  }
  const hint = setupEl("#compliance-hint");
  if (hint) {
    hint.textContent = level === "full"
      ? "Full compliance applies every framework unless you choose some."
      : level === "inventory" ? "Inventory reads no content, so nothing is mapped."
        : "Findings are mapped to the frameworks you choose.";
  }
}

// ---- Advanced options -------------------------------------------------------

// What Advanced options holds that is not a default - its closed header says so.
function advancedChanges() {
  const scope = readScanScope("file-server");
  const changes = [];
  const hidden = setupEl("#fs-hidden-files")?.value || "include";
  const system = setupEl("#fs-system-files")?.value || "skip";
  if (hidden !== "include") changes.push(hidden === "skip" ? "hidden files skipped" : "hidden files only");
  if (system !== "skip") changes.push(system === "include" ? "system files included" : "system files only");
  const [min, max] = [scope.min_size_bytes, scope.max_size_bytes];
  if (min != null && max != null) changes.push(`${formatScopeBytes(min)} to ${formatScopeBytes(max)}`);
  else if (max != null) changes.push(`up to ${formatScopeBytes(max)}`);
  else if (min != null) changes.push(`from ${formatScopeBytes(min)}`);
  if (scope.modified_after) changes.push(`modified since ${scope.modified_after}`);
  if (scope.include_paths?.length) changes.push(`only ${scope.include_paths.length} folder${scope.include_paths.length === 1 ? "" : "s"}`);
  if (scope.exclude_paths?.length) changes.push(`${scope.exclude_paths.length} folder${scope.exclude_paths.length === 1 ? "" : "s"} skipped`);
  if (setupEl("#include_admin_shares")?.checked) changes.push("admin shares");
  if (setupEl("#smb_encryption")?.checked) changes.push("SMB 3 encryption");
  return changes;
}

function renderAdvancedState() {
  const state = setupEl("[data-advanced-state]");
  if (!state) return;
  const changes = advancedChanges();
  const text = changes.join(" · ");
  state.textContent = text ? text.charAt(0).toUpperCase() + text.slice(1) : "Using defaults";
  state.classList.toggle("is-changed", changes.length > 0);
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
  if (fileTypeChoice() === "custom" && !selectedTypeCount()) {
    problems.push({ field: "#extension-search", message: "Choose at least one file type, or scan all file types." });
  }
  const scope = scanScopeProblem("file-server", { server });
  if (scope) problems.push(scope);
  return problems;
}

// A problem inside the folded Advanced options is shown, not left behind the fold.
function revealSetupField(selector) {
  const details = setupEl(selector)?.closest("details");
  if (details && !details.open) details.open = true;
}

// The same message and markup showFieldError writes, without moving focus: these
// run as the operator leaves a field.
function markSetupField(selector, message) {
  const field = setupEl(selector);
  if (!field) return;
  const id = `${field.id || "field"}-error`;
  let note = document.getElementById(id);
  if (!note) {
    note = document.createElement("span");
    note.className = "field-error";
    note.id = id;
    (field.closest(".cfg-field, label") || field.parentElement || field).appendChild(note);
  }
  note.textContent = message;
  field.setAttribute("aria-invalid", "true");
  field.setAttribute("aria-describedby", id);
}

function clearSetupMarks(keep = new Set()) {
  setupStep()?.querySelectorAll("[aria-invalid='true']").forEach((field) => {
    if (keep.has(`#${field.id}`)) return;
    field.removeAttribute("aria-invalid");
    field.removeAttribute("aria-describedby");
    document.getElementById(`${field.id}-error`)?.remove();
  });
}

function checkScanSetup() {
  if (!setupStep()) return [];
  const problems = scanSetupProblems();
  clearSetupMarks(new Set(problems.map((problem) => problem.field)));
  problems.forEach((problem) => markSetupField(problem.field, problem.message));
  return problems;
}

// ---- Wiring -----------------------------------------------------------------

// Everything a change on the step can move, in one pass.
function syncScanSetup() {
  syncScanTarget();
  syncFileTypes();
  syncScanMethod();
  if (customTypesOpen()) renderTypeGroups();
  renderTypeNote();
  renderAdvancedState();
}

// Restore what a saved scan says (applyFileServerProfile), or a new scan's defaults.
function applyScanSetup(config = {}, ui = {}) {
  setupActiveGroup = "";
  setScanLevel(config.scan_level);
  applySpecialFiles(config);
  let choice = ui.ext_preset || "";
  if (ui.ext_mode === "all" || choice === "all") choice = "all";
  else if (!choice && Array.isArray(ui.extensions) && ui.extensions.length) choice = "custom";
  else if (!["recommended", "secrets", "broad"].includes(choice)) choice = "recommended";
  setFileTypeChoice(choice);
  clearSetupMarks();
  const advanced = setupEl("#cfg-advanced");
  if (advanced) advanced.open = advancedChanges().length > 0;
  syncScanSetup();
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
    if (event.target.matches("input[name='ext-preset']")) syncFileTypes();
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
    if (event.target.closest("[data-extension-preset], [data-remove-extension], #add-custom-extension-btn, [data-scope-add]")) {
      later();
    }
  });
  setupEl("#server")?.addEventListener("input", later);
  // No sync here: app.js, whose functions the sync calls, loads after this file. The
  // step is synced when the wizard opens (applyScanSetup) and on every change.
}

initScanSetup();
