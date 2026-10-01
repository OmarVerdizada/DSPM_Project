/* ── Who can read (D7) ────────────────────────────────────────────
   Which accounts and groups can read the files that hold findings - each one with
   how many files it can read and write - and, when one is picked, those files,
   riskiest first. Read from the access rows each file's last scan wrote: allow
   entries less the same principal's denies. A group is a group: its members are
   not expanded here.

   Loaded before app.js, like every file in console/: definitions and DOM wiring
   only. The console's helpers (api, escapeHtml, can, switchTab ...) are used when a
   handler runs, never while this file loads. */

const ACCESS_KIND_LABELS = {
  broad: "Everyone-type group",
  privileged: "Privileged",
  service: "Service or indexer",
};
const ACCESS_FILES_PAGE = 100;
let accessChosen = null; // {key, kind, label} - whose files the second panel lists
let accessFilesOffset = 0;

function accessParts() {
  return {
    principals: document.querySelector("#access-principals-body"),
    context: document.querySelector("#access-context"),
    kind: document.querySelector("#access-kind"),
    kindFiles: document.querySelector("#access-kind-files"),
    filesPanel: document.querySelector("#access-files-panel"),
    files: document.querySelector("#access-files-body"),
    filesTitle: document.querySelector("#access-files-title"),
    filesNote: document.querySelector("#access-files-note"),
    sensitive: document.querySelector("#access-sensitive-only"),
    writable: document.querySelector("#access-writable-only"),
    more: document.querySelector("#access-files-more"),
  };
}

// The kind the filter asks for: one of the three, or "" for everyone.
function accessKind(parts) {
  const value = String(parts.kind?.value || "");
  return Object.prototype.hasOwnProperty.call(ACCESS_KIND_LABELS, value) ? value : "";
}

function accessCount(value) {
  return Number(value || 0).toLocaleString();
}

function accessKindMarks(row) {
  const marks = ["broad", "privileged", "service"].filter((kind) => row[kind])
    .map((kind) => `<span class="access-kind" data-kind="${kind}">${ACCESS_KIND_LABELS[kind]}</span>`);
  return marks.length ? marks.join(" ") : '<span class="muted">Account or group</span>';
}

function renderAccessPrincipals(rows) {
  const parts = accessParts();
  if (!parts.principals) return;
  const kind = accessKind(parts);
  if (parts.kindFiles) parts.kindFiles.hidden = !kind || !rows.length;
  if (parts.context) {
    const exposed = rows.filter((row) => row.readable_sensitive_files > 0).length;
    parts.context.textContent = rows.length
      ? `${accessCount(rows.length)} ${kind ? `${ACCESS_KIND_LABELS[kind].toLowerCase()} ` : ""}principal${rows.length === 1 ? "" : "s"}; `
        + `${accessCount(exposed)} can read files that hold findings. Pick one to see the files.`
      : "";
  }
  if (!rows.length) {
    parts.principals.innerHTML = `<tr><td colspan="6" class="empty">${kind
      ? "No principal of this kind can read a scanned file."
      : "No access recorded yet. Each scan reads its files' permissions; run one to see who can read what."}</td></tr>`;
    return;
  }
  parts.principals.innerHTML = rows.map((row) => {
    const chosen = Boolean(accessChosen && accessChosen.key === row.key);
    return `<tr class="access-row${chosen ? " is-chosen" : ""}" data-access-key="${escapeHtml(row.key)}"
        data-access-label="${escapeHtml(row.principal || row.key)}" tabindex="0" aria-selected="${chosen}">
      <td><strong>${escapeHtml(row.principal || row.key)}</strong>${row.sid ? `<span class="access-sid">${escapeHtml(row.sid)}</span>` : ""}</td>
      <td>${accessKindMarks(row)}</td>
      <td class="is-numeric">${row.readable_sensitive_files ? `<strong>${accessCount(row.readable_sensitive_files)}</strong>` : "0"}</td>
      <td class="is-numeric">${accessCount(row.readable_files)}</td>
      <td class="is-numeric">${accessCount(row.writable_files)}</td>
      <td class="is-numeric">${Math.round(Number(row.max_risk_score || 0))}</td>
    </tr>`;
  }).join("");
}

async function loadAccessPrincipals() {
  if (!accessToken) return;
  const parts = accessParts();
  const context = captureTenantContext();
  const kind = accessKind(parts);
  try {
    const data = await api(`/api/access/principals?limit=500${kind ? `&kind=${encodeURIComponent(kind)}` : ""}`, null, "GET");
    if (!isCurrentTenantContext(context)) return;
    renderAccessPrincipals(data.principals || []);
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    if (parts.principals) {
      parts.principals.innerHTML = `<tr><td colspan="6" class="empty">Access unavailable: ${escapeHtml(error.message)}</td></tr>`;
    }
  }
}

function accessFileRow(file, forKind) {
  const rights = [file.can_read ? "Read" : "", file.can_write ? "Write" : ""].filter(Boolean).join(", ");
  const level = String(file.risk_level || "").toUpperCase();
  return `<tr>
    <td><button type="button" class="plain-btn access-file" data-access-file="${escapeHtml(file.path)}"
        title="Open in Findings">${escapeHtml(file.path)}</button>${forKind && file.principal
          ? `<span class="access-sid">${escapeHtml(file.principal)}</span>` : ""}</td>
    <td>${level ? `<span class="badge ${escapeHtml(level)}">${escapeHtml(level)}</span>` : '<span class="muted">-</span>'}</td>
    <td class="is-numeric">${accessCount(file.finding_count)}</td>
    <td>${escapeHtml(rights || "-")}</td>
  </tr>`;
}

async function loadAccessFiles({ append = false } = {}) {
  if (!accessToken || !accessChosen) return;
  const parts = accessParts();
  const context = captureTenantContext();
  if (!append) accessFilesOffset = 0;
  const query = new URLSearchParams({
    sensitive_only: String(Boolean(parts.sensitive?.checked)),
    writable_only: String(Boolean(parts.writable?.checked)),
    limit: String(ACCESS_FILES_PAGE),
    offset: String(accessFilesOffset),
  });
  if (accessChosen.kind) query.set("kind", accessChosen.kind);
  else query.set("key", accessChosen.key);
  if (parts.filesPanel) parts.filesPanel.hidden = false;
  if (parts.filesTitle) {
    parts.filesTitle.textContent = accessChosen.kind
      ? `Files any ${ACCESS_KIND_LABELS[accessChosen.kind].toLowerCase()} can ${parts.writable?.checked ? "write" : "read"}`
      : `Files ${accessChosen.label} can ${parts.writable?.checked ? "write" : "read"}`;
  }
  try {
    const data = await api(`/api/access/files?${query}`, null, "GET");
    if (!isCurrentTenantContext(context) || !parts.files) return;
    const files = data.files || [];
    const rows = files.map((file) => accessFileRow(file, Boolean(accessChosen.kind))).join("");
    if (append) {
      parts.files.insertAdjacentHTML("beforeend", rows);
    } else {
      parts.files.innerHTML = rows || `<tr><td colspan="4" class="empty">${parts.sensitive?.checked
        ? "None of these files holds findings."
        : "No files."}</td></tr>`;
    }
    accessFilesOffset += files.length;
    if (parts.more) parts.more.hidden = files.length < ACCESS_FILES_PAGE;
    if (parts.filesNote) {
      parts.filesNote.textContent = `${accessCount(accessFilesOffset)} file${accessFilesOffset === 1 ? "" : "s"} shown, riskiest first`
        + `${parts.sensitive?.checked ? "; only files that hold findings" : ""}.`;
    }
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    if (parts.files) parts.files.innerHTML = `<tr><td colspan="4" class="empty">Files unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

function chooseAccessPrincipal(row) {
  accessChosen = { key: row.dataset.accessKey, kind: "", label: row.dataset.accessLabel || row.dataset.accessKey };
  accessParts().principals?.querySelectorAll(".access-row").forEach((item) => {
    const chosen = item === row;
    item.classList.toggle("is-chosen", chosen);
    item.setAttribute("aria-selected", String(chosen));
  });
  loadAccessFiles();
}

(function wireAccessPage() {
  const parts = accessParts();
  parts.kind?.addEventListener("change", () => {
    accessChosen = null;
    if (parts.filesPanel) parts.filesPanel.hidden = true;
    loadAccessPrincipals();
  });
  document.querySelector("#refresh-access-btn")?.addEventListener("click", () => {
    loadAccessPrincipals();
    if (accessChosen) loadAccessFiles();
  });
  parts.kindFiles?.addEventListener("click", () => {
    const kind = accessKind(parts);
    if (!kind) return;
    accessChosen = { key: "", kind, label: ACCESS_KIND_LABELS[kind] };
    loadAccessFiles();
  });
  parts.principals?.addEventListener("click", (event) => {
    const row = event.target.closest("[data-access-key]");
    if (row) chooseAccessPrincipal(row);
  });
  parts.principals?.addEventListener("keydown", (event) => {
    const row = event.target.closest("[data-access-key]");
    if (row && (event.key === "Enter" || event.key === " ")) {
      event.preventDefault();
      chooseAccessPrincipal(row);
    }
  });
  [parts.sensitive, parts.writable].forEach((toggle) => toggle?.addEventListener("change", () => loadAccessFiles()));
  parts.more?.addEventListener("click", () => loadAccessFiles({ append: true }));
  parts.files?.addEventListener("click", (event) => {
    const file = event.target.closest("[data-access-file]");
    if (!file) return;
    // The Findings page, searched for the file's path: its findings and its detail.
    switchTab("findings");
    if (filterInput) {
      filterInput.value = file.dataset.accessFile;
      filterInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
})();
