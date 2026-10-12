/* ── Who can read (D7, revision 0055) ─────────────────────────────
   The exposure of the sensitive files through their permissions: how many a broad group
   can read or write, which accounts and groups the access lists name - each with what it
   can read, write and fully control, owns and is denied - and, when one is picked, its
   files with the grant on each (rights, explicit or inherited, denied). Then the
   permission changes between scans.

   Read from the access rows each file's last scan wrote and the counts the database keeps
   of them: direct ACL access, never called effective access - a group is a group, its
   members are not expanded here.

   Loaded before app.js, like every file in console/: definitions and DOM wiring only. The
   console's helpers (api, escapeHtml, can, switchTab ...) are used when a handler runs,
   never while this file loads. */

const ACCESS_KIND_LABELS = {
  broad: "Broad group",
  privileged: "Privileged",
  service: "Service identity",
  unresolved: "Unresolved SID",
};
const ACCESS_FILES_PAGE = 100;
const ACCESS_LABELS = {
  read: "can read", write: "can write", modify: "can modify", full_control: "has full control of",
  deny: "is denied on", owner: "owns", explicit: "has an explicit entry on", inherited: "has an inherited entry on",
  any: "appears on",
};
let accessChosen = null; // {key, kind, label} - whose files the second panel lists
let accessFilesOffset = 0;
let accessFilesCursor = "";
// Every files request is numbered; an answer for an older one (another principal picked,
// a second "Show more" while the first was on its way) is dropped, not shown.
let accessFilesRequest = 0;

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
    access: document.querySelector("#access-access"),
    more: document.querySelector("#access-files-more"),
    changes: document.querySelector("#access-changes-body"),
    changesSensitive: document.querySelector("#access-changes-sensitive"),
  };
}

// The kind the filter asks for: one of the four, or "" for every principal.
function accessKind(parts) {
  const value = String(parts.kind?.value || "");
  return Object.prototype.hasOwnProperty.call(ACCESS_KIND_LABELS, value) ? value : "";
}

function accessFilter(parts) {
  const value = String(parts.access?.value || "read");
  return Object.prototype.hasOwnProperty.call(ACCESS_LABELS, value) ? value : "read";
}

function accessCount(value) {
  return Number(value || 0).toLocaleString();
}

function accessKindMarks(row) {
  const marks = Object.keys(ACCESS_KIND_LABELS).filter((kind) => row[kind])
    .map((kind) => `<span class="access-kind" data-kind="${kind}">${ACCESS_KIND_LABELS[kind]}</span>`);
  return marks.length ? marks.join(" ") : `<span class="muted">${escapeHtml(permissionTypeLabel(row.principal_type))}</span>`;
}

function renderAccessHeadline(summary = {}) {
  const set = (id, value) => {
    const node = document.querySelector(id);
    if (node) node.textContent = accessCount(value);
  };
  set("#access-head-broad-read", summary.sensitive_broad_read_files);
  set("#access-head-broad-write", summary.sensitive_broad_write_files);
  set("#access-head-unresolved", summary.unresolved_sid_files);
  const states = summary.acl_states || {};
  set("#access-head-unread", Number(states.failed || 0) + Number(states.not_collected || 0));
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
        + `${accessCount(exposed)} can read sensitive files. Pick one to see its files.`
      : "";
  }
  if (!rows.length) {
    parts.principals.innerHTML = `<tr><td colspan="8" class="empty">${kind
      ? "No principal of this kind appears in a scanned file's access list."
      : "No access recorded yet. Each scan reads its files' permissions; run one to see who can read what."}</td></tr>`;
    return;
  }
  // The page opens on the most exposed principal - the broad group that can read the most
  // sensitive files, else the list's first row - rather than on an empty second panel.
  // SYSTEM and Administrators read nearly everything; they top the list and say nothing.
  if (!accessChosen && !kind) {
    const exposed = rows.find((row) => row.broad && row.readable_sensitive_files > 0) || rows[0];
    accessChosen = { key: exposed.key, kind: "", label: exposed.principal || exposed.key };
  }
  parts.principals.innerHTML = rows.map((row) => {
    const chosen = Boolean(accessChosen && accessChosen.key === row.key);
    return `<tr class="access-row${chosen ? " is-chosen" : ""}" data-access-key="${escapeHtml(row.key)}"
        data-access-label="${escapeHtml(row.principal || row.key)}" tabindex="0" aria-selected="${chosen}">
      <td><strong>${escapeHtml(row.principal || row.key)}</strong>${row.sid && row.sid !== row.principal ? `<span class="access-sid">${escapeHtml(row.sid)}</span>` : ""}</td>
      <td>${accessKindMarks(row)}</td>
      <td class="is-numeric">${row.readable_sensitive_files ? `<strong>${accessCount(row.readable_sensitive_files)}</strong>` : "0"}</td>
      <td class="is-numeric">${accessCount(row.readable_files)}</td>
      <td class="is-numeric">${accessCount(row.writable_files)} <span class="muted">(${accessCount(row.writable_sensitive_files)})</span></td>
      <td class="is-numeric">${accessCount(row.full_control_files)}</td>
      <td class="is-numeric">${accessCount(row.owned_files)}</td>
      <td class="is-numeric">${accessCount(row.denied_files)}</td>
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
    renderFreshness(document.querySelector("#access-freshness"), data.freshness);
    if (accessChosen) loadAccessFiles();
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    if (parts.principals) {
      parts.principals.innerHTML = `<tr><td colspan="8" class="empty">Access unavailable: ${escapeHtml(error.message)}</td></tr>`;
    }
  }
  loadAccessSummary().catch(() => {});
  loadAccessChanges().catch(() => {});
}

async function loadAccessSummary() {
  if (!accessToken) return;
  const context = captureTenantContext();
  const summary = await api("/api/access/summary", null, "GET");
  if (!isCurrentTenantContext(context)) return;
  renderAccessHeadline(summary);
}

function accessGrantCell(file, forKind) {
  const grants = Array.isArray(file.grants) ? file.grants : [];
  return grants.map((grant) => `<div class="access-grant">
      ${forKind ? `<strong>${escapeHtml(grant.principal || grant.key)}</strong>` : ""}
      <span>${escapeHtml(grant.rights || "None")}</span>
      ${permissionGrantedBy(grant)}
      ${grant.denied_rights ? `<span class="perm-chip" data-perm="broad">Denied: ${escapeHtml(grant.denied_rights)}</span>` : ""}
      ${grant.is_owner ? '<span class="perm-chip" data-perm="owner">Owner</span>' : ""}
    </div>`).join("") || '<span class="muted">-</span>';
}

function accessFileRow(file, forKind) {
  const level = String(file.risk_level || "").toUpperCase();
  return `<tr>
    <td><button type="button" class="plain-btn access-file" data-access-asset="${escapeHtml(file.asset_id)}"
        data-access-name="${escapeHtml(file.name || "")}" data-access-file="${escapeHtml(file.path)}"
        title="Open this file's permissions">${escapeHtml(file.path)}</button></td>
    <td>${file.owner ? escapeHtml(file.owner) : '<span class="muted">Not recorded</span>'}</td>
    <td>${level ? `<span class="badge ${escapeHtml(level)}">${escapeHtml(level)}</span>` : '<span class="muted">-</span>'}</td>
    <td class="is-numeric">${accessCount(file.finding_count)}</td>
    <td>${accessGrantCell(file, forKind)}</td>
  </tr>`;
}

async function loadAccessFiles({ append = false } = {}) {
  if (!accessToken || !accessChosen) return;
  const parts = accessParts();
  const context = captureTenantContext();
  const request = ++accessFilesRequest;
  if (!append) {
    accessFilesOffset = 0;
    accessFilesCursor = "";
  }
  if (parts.more) parts.more.disabled = true;
  const filter = accessFilter(parts);
  const query = new URLSearchParams({
    sensitive_only: String(Boolean(parts.sensitive?.checked)),
    access: filter,
    limit: String(ACCESS_FILES_PAGE),
  });
  // The next page starts after the last file shown (W2.5), not after N skipped rows.
  if (append && accessFilesCursor) query.set("cursor", accessFilesCursor);
  if (accessChosen.kind) query.set("kind", accessChosen.kind);
  else query.set("key", accessChosen.key);
  if (parts.filesPanel) parts.filesPanel.hidden = false;
  if (parts.filesTitle) {
    parts.filesTitle.textContent = accessChosen.kind
      ? `Files any ${ACCESS_KIND_LABELS[accessChosen.kind].toLowerCase()} ${ACCESS_LABELS[filter]}`
      : `Files ${accessChosen.label} ${ACCESS_LABELS[filter]}`;
  }
  try {
    const data = await api(`/api/access/files?${query}`, null, "GET");
    if (request !== accessFilesRequest || !isCurrentTenantContext(context) || !parts.files) return;
    const files = data.files || [];
    const rows = files.map((file) => accessFileRow(file, Boolean(accessChosen.kind))).join("");
    if (append) {
      // The rows are built escaped above; parsed in a detached body and moved in.
      const holder = document.createElement("tbody");
      holder.innerHTML = rows;
      parts.files.append(...holder.children);
    } else {
      parts.files.innerHTML = rows || `<tr><td colspan="5" class="empty">${parts.sensitive?.checked
        ? "No sensitive file matches."
        : "No files."}</td></tr>`;
    }
    accessFilesOffset += files.length;
    accessFilesCursor = data.next_cursor || "";
    if (parts.more) {
      parts.more.hidden = !accessFilesCursor;
      parts.more.disabled = false;
    }
    if (parts.filesNote) {
      parts.filesNote.textContent = `${accessCount(accessFilesOffset)} file${accessFilesOffset === 1 ? "" : "s"} shown, sensitive and riskiest first`
        + `${parts.sensitive?.checked ? "; only files that hold sensitive data" : ""}. Open a file for its owner and full access list.`;
    }
  } catch (error) {
    if (request !== accessFilesRequest || !isCurrentTenantContext(context)) return;
    if (parts.more) parts.more.disabled = false;
    if (parts.files) parts.files.innerHTML = `<tr><td colspan="5" class="empty">Files unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

async function loadAccessChanges() {
  if (!accessToken) return;
  const parts = accessParts();
  if (!parts.changes) return;
  const context = captureTenantContext();
  const query = new URLSearchParams({ limit: "50", sensitive_only: String(Boolean(parts.changesSensitive?.checked)) });
  try {
    const data = await api(`/api/access/changes?${query}`, null, "GET");
    if (!isCurrentTenantContext(context)) return;
    const changes = data.changes || [];
    parts.changes.innerHTML = changes.length ? changes.map((change) => `<tr>
        <td><time datetime="${escapeHtml(change.detected_at)}">${escapeHtml(getFriendlyTimestamp(change.detected_at))}</time></td>
        <td><span class="badge ${escapeHtml(String(change.severity || "info").toUpperCase())}">${escapeHtml(change.severity || "info")}</span></td>
        <td><button type="button" class="plain-btn access-file" data-access-asset="${escapeHtml(change.asset_id)}"
            data-access-file="${escapeHtml(change.path)}" title="Open this file's permissions">${escapeHtml(change.path)}</button></td>
        <td>${escapeHtml(change.summary || "")}</td>
      </tr>`).join("")
      : '<tr><td colspan="4" class="empty">No permission has changed between scans.</td></tr>';
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    parts.changes.innerHTML = `<tr><td colspan="4" class="empty">Changes unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

// A workspace switch forgets what was picked and shows nothing of the old workspace:
// its principals, picked or not, are not the new one's.
function resetAccessPage() {
  const parts = accessParts();
  accessChosen = null;
  accessFilesOffset = 0;
  accessFilesCursor = "";
  accessFilesRequest += 1;
  if (parts.principals) parts.principals.innerHTML = "";
  if (parts.files) parts.files.innerHTML = "";
  if (parts.changes) parts.changes.innerHTML = "";
  if (parts.context) parts.context.textContent = "";
  if (parts.filesPanel) parts.filesPanel.hidden = true;
  if (parts.kind) parts.kind.value = "";
  renderAccessHeadline({});
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

function openAccessFile(button) {
  const assetId = button.dataset.accessAsset;
  if (!assetId) return;
  // The file's own detail, on its Permissions tab: owner, summary and the whole list.
  openAssetDetailForAsset({ id: assetId, name: button.dataset.accessName || "", path: button.dataset.accessFile || "" },
    "permissions", button);
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
  [parts.sensitive, parts.access].forEach((control) => control?.addEventListener("change", () => loadAccessFiles()));
  parts.changesSensitive?.addEventListener("change", () => loadAccessChanges());
  parts.more?.addEventListener("click", () => loadAccessFiles({ append: true }));
  [parts.files, parts.changes].forEach((table) => table?.addEventListener("click", (event) => {
    const file = event.target.closest("[data-access-asset]");
    if (file) openAccessFile(file);
  }));
})();
