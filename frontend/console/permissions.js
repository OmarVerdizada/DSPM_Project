/* ── File permissions (revision 0055) ─────────────────────────────
   One way to show who owns a file and who can reach it, wherever the console shows it:
   the asset detail's Permissions tab, a finding's exposure, the remediation drawer and
   Who can read. Every number and row comes from the server's access model
   (/api/access/assets/{id}, a finding's `access` and `access_exposure`) - nothing is
   re-derived here.

   The access is DIRECT ACL ACCESS: the rights each file's own entries grant a principal,
   less the entries that deny it. Group membership is not expanded, so this is never
   called effective access, and the panel says so.

   Loaded before app.js, like every file in console/: definitions only. The console's
   helpers (api, escapeHtml, captureTenantContext ...) are used when a function runs,
   never while this file loads. */

const PERMISSION_TYPE_LABELS = {
  user: "User",
  group: "Group",
  well_known_group: "Well-known group",
  computer: "Computer",
  service: "Service identity",
  unresolved_sid: "Unresolved SID",
  unknown: "Account (type not resolved)",
};
const ACL_STATE_TEXT = {
  failed: "The permissions could not be read in the latest scan",
  not_collected: "The permissions were not collected for this file",
};

function permissionTypeLabel(type) {
  return PERMISSION_TYPE_LABELS[String(type || "")] || "Not recorded";
}

function permissionCount(value) {
  return Number(value || 0).toLocaleString();
}

// What makes a principal worth a second look - each a word, never a colour alone.
function permissionChips(row = {}) {
  const chips = [];
  if (row.broad) chips.push(["broad", "Broad group"]);
  if (row.unresolved) chips.push(["unresolved", "Unresolved SID"]);
  if (row.service) chips.push(["service", "Service identity"]);
  if (row.privileged) chips.push(["privileged", "Privileged"]);
  if (row.is_owner) chips.push(["owner", "Owner"]);
  return chips.map(([kind, label]) => `<span class="perm-chip" data-perm="${kind}">${label}</span>`).join(" ");
}

function permissionGrantedBy(row = {}) {
  const source = String(row.granted_by || "");
  if (source === "explicit") return '<span class="perm-source" data-source="explicit">Explicit</span>';
  if (source === "inherited") return '<span class="perm-source" data-source="inherited">Inherited</span>';
  if (source) return '<span class="perm-source" data-source="both">Explicit and inherited</span>';
  return '<span class="muted">No grant</span>';
}

function permissionRights(row = {}) {
  const rights = String(row.rights || "");
  const denied = String(row.denied_rights || "");
  const granted = rights && rights !== "None" ? escapeHtml(rights) : '<span class="muted">None</span>';
  return denied ? `${granted}<span class="perm-deny">Denied: ${escapeHtml(denied)}</span>` : granted;
}

function permissionPrincipalCell(row = {}) {
  const name = String(row.principal || row.key || "");
  const sid = String(row.sid || "");
  return `<strong>${escapeHtml(name)}</strong>${sid && sid !== name ? `<span class="perm-sid">${escapeHtml(sid)}</span>` : ""}`;
}

// The owner, as collected: its name, its SID, and whether a name was resolved.
function renderPermissionOwner(owner = {}, { aclState = "collected", aclError = "", label = true } = {}) {
  const name = String(owner.name || "");
  const sid = String(owner.sid || "");
  const resolved = Boolean(owner.resolved);
  const ownerLine = name
    ? `<strong>${escapeHtml(name)}</strong>${sid && sid !== name ? `<span class="perm-sid">${escapeHtml(sid)}</span>` : ""}`
    : '<span class="muted">Not recorded</span>';
  const resolution = name
    ? (resolved ? `${escapeHtml(permissionTypeLabel(owner.type))}` : "Unresolved: no authority could name this SID")
    : "";
  const state = ACL_STATE_TEXT[aclState]
    ? `<p class="perm-state" role="note" data-state="${escapeHtml(aclState)}">${escapeHtml(ACL_STATE_TEXT[aclState])}${aclError ? ` (${escapeHtml(aclError.replace(/_/g, " "))})` : ""}.</p>`
    : "";
  return `<div class="perm-owner">
      ${label ? '<span class="perm-label">Owner</span>' : ""}
      <div class="perm-owner-name">${ownerLine}</div>
      ${resolution ? `<span class="perm-owner-kind">${resolution}</span>` : ""}
      ${owner.broad ? '<span class="perm-chip" data-perm="broad">Broad group</span>' : ""}
    </div>${state}`;
}

// Read / Write-Modify / Full control / Deny, as counts of principals.
function renderPermissionSummary(summary = {}) {
  const tiles = [
    ["Can read", summary.read],
    ["Can write or modify", summary.write_modify],
    ["Full control", summary.full_control],
    ["Denied", summary.deny],
  ];
  return `<dl class="perm-summary">${tiles.map(([label, value]) => `<div><dt>${label}</dt><dd>${permissionCount(value)}</dd></div>`).join("")}</dl>`;
}

// Principals and what each can do: the table a finding's exposure and the file detail share.
function renderPermissionPrincipals(rows = [], { caption = "Who has access", empty = "No principal has access." } = {}) {
  if (!rows.length) return `<p class="inventory-detail-empty">${escapeHtml(empty)}</p>`;
  return `<div class="panel-table-wrap"><table class="ledger-table perm-table">
      <caption class="visually-hidden">${escapeHtml(caption)}</caption>
      <thead><tr><th scope="col">Principal</th><th scope="col">Type</th><th scope="col">Access</th><th scope="col">Granted by</th><th scope="col">Notes</th></tr></thead>
      <tbody>${rows.map((row) => `<tr>
        <td>${permissionPrincipalCell(row)}</td>
        <td>${escapeHtml(permissionTypeLabel(row.principal_type))}</td>
        <td>${permissionRights(row)}</td>
        <td>${permissionGrantedBy(row)}</td>
        <td>${permissionChips(row) || '<span class="muted">-</span>'}</td>
      </tr>`).join("")}</tbody>
    </table></div>`;
}

// The ACL as collected, entry by entry, in the order Windows holds it; the raw mask and
// flags only under Advanced.
function renderPermissionEntries(entries = []) {
  if (!entries.length) return '<p class="inventory-detail-empty">The access list has no entries: only the owner can change it.</p>';
  const rows = entries.map((entry) => `<tr${entry.inherit_only ? ' class="is-muted"' : ""}>
      <td>${permissionPrincipalCell(entry)}</td>
      <td>${escapeHtml(permissionTypeLabel(entry.principal_type))}</td>
      <td><span class="perm-access" data-access="${entry.access === "deny" ? "deny" : "allow"}">${entry.access === "deny" ? "Deny" : "Allow"}</span></td>
      <td>${escapeHtml(entry.rights || "")}</td>
      <td>${entry.inherited ? "Inherited" : "Explicit"}</td>
      <td>${escapeHtml(entry.applies_to || "")}</td>
      <td>${permissionChips(entry) || '<span class="muted">-</span>'}</td>
    </tr>`).join("");
  const raw = entries.map((entry) => `<tr>
      <td>${escapeHtml(entry.principal || "")}</td>
      <td><code>0x${Number(entry.mask || 0).toString(16).toUpperCase().padStart(8, "0")}</code></td>
      <td><code>0x${Number(entry.flags || 0).toString(16).toUpperCase().padStart(2, "0")}</code></td>
      <td>${escapeHtml(entry.raw_rights || "")}</td>
    </tr>`).join("");
  return `<div class="panel-table-wrap"><table class="ledger-table perm-table">
      <caption class="visually-hidden">Access control entries</caption>
      <thead><tr><th scope="col">Principal</th><th scope="col">Type</th><th scope="col">Access</th><th scope="col">Rights</th><th scope="col">Explicit / inherited</th><th scope="col">Applies to</th><th scope="col">Notes</th></tr></thead>
      <tbody>${rows}</tbody>
    </table></div>
    <details class="perm-advanced"><summary>Advanced: access masks and entry flags</summary>
      <div class="panel-table-wrap"><table class="ledger-table perm-table">
        <thead><tr><th scope="col">Principal</th><th scope="col">Access mask</th><th scope="col">Entry flags</th><th scope="col">Rights as collected</th></tr></thead>
        <tbody>${raw}</tbody>
      </table></div>
    </details>`;
}

function renderPermissionChanges(changes = []) {
  if (!changes.length) return "";
  return `<section class="inventory-detail-section perm-section">
      <div class="inventory-detail-section-head"><div><span>Between scans</span><h5>Permission changes</h5></div><b>${escapeHtml(changes.length)}</b></div>
      <ul class="perm-changes">${changes.map((change) => `<li>
        <span class="badge ${escapeHtml(String(change.severity || "info").toUpperCase())}">${escapeHtml(String(change.severity || "info"))}</span>
        <span>${escapeHtml(change.summary || "")}</span>
        <time datetime="${escapeHtml(change.detected_at || "")}">${escapeHtml(getFriendlyTimestamp(change.detected_at || ""))}</time>
      </li>`).join("")}</ul>
    </section>`;
}

function renderAccessModelNote(model = {}) {
  return `<p class="perm-model" role="note"><strong>${escapeHtml(model.label || "Direct ACL access")}.</strong> ${escapeHtml(model.note || "Group membership is not expanded.")}</p>`;
}

function renderPermissionsPanel(data = {}) {
  const read = data.acl_state === "collected" || (data.principals || []).length;
  return `
    <section class="inventory-detail-section perm-section">
      <div class="inventory-detail-section-head"><div><span>Who owns this file</span><h5>Owner</h5></div></div>
      ${renderPermissionOwner(data.owner || {}, { aclState: data.acl_state, aclError: data.acl_error, label: false })}
      ${data.inheritance_disabled ? '<p class="perm-inheritance" role="note">Inheritance is disabled on this file: changes to its parent folder do not reach it.</p>' : ""}
    </section>
    ${read ? `<section class="inventory-detail-section perm-section">
      <div class="inventory-detail-section-head"><div><span>Direct ACL access</span><h5>Access summary</h5></div><b>${permissionCount((data.principals || []).length)}</b></div>
      ${renderPermissionSummary(data.summary || {})}
      ${data.acl_state !== "collected" && (data.principals || []).length ? '<p class="perm-state" role="note">The rows below are from the last scan that could read the permissions.</p>' : ""}
      ${renderPermissionPrincipals(data.principals || [])}
    </section>` : ""}
    ${data.acl_state === "collected" ? `<section class="inventory-detail-section perm-section">
      <div class="inventory-detail-section-head"><div><span>As collected</span><h5>Access control list</h5></div><b>${permissionCount((data.entries || []).length)}</b></div>
      ${renderPermissionEntries(data.entries || [])}
      ${data.unsupported_entries ? `<p class="perm-state" role="note">${permissionCount(data.unsupported_entries)} object or conditional entr${data.unsupported_entries === 1 ? "y was" : "ies were"} not evaluated.</p>` : ""}
    </section>` : ""}
    ${renderPermissionChanges(data.changes || [])}
    ${renderAccessModelNote(data.access_model || {})}`;
}

// Fills `container` with one asset's permissions; an answer for another asset or another
// workspace than the one on screen is dropped.
let permissionsRequest = 0;
async function loadAssetPermissions(assetId, container) {
  if (!container || !assetId) return;
  const request = ++permissionsRequest;
  const context = captureTenantContext();
  container.innerHTML = '<div class="inventory-detail-state" role="status"><span class="inventory-detail-spinner" aria-hidden="true"></span><strong>Loading permissions&hellip;</strong></div>';
  try {
    const data = await api(`/api/access/assets/${encodeURIComponent(assetId)}`, null, "GET");
    if (request !== permissionsRequest || !isCurrentTenantContext(context) || !container.isConnected) return;
    container.innerHTML = renderPermissionsPanel(data);
  } catch (error) {
    if (request !== permissionsRequest || !isCurrentTenantContext(context)) return;
    container.innerHTML = `<div class="inventory-detail-state error" role="alert"><strong>Permissions could not be loaded.</strong><small>${escapeHtml(error.message || "")}</small></div>`;
  }
}

// A finding's owner and exposure: the server's `access` context, and - for a permission
// finding - the principals that raised it, why, and what to do.
function renderFindingExposure(finding = {}, { why: showWhy = true } = {}) {
  const access = finding.access || {};
  const exposure = finding.access_exposure || null;
  const owner = (exposure && exposure.owner) || access.owner || {};
  const principals = exposure ? exposure.principals || [] : access.exposed_principals || [];
  const why = exposure ? exposure.severity_rationale : "";
  if (!owner.name && !principals.length && !access.acl_state) return "";
  return `<section class="perm-exposure">
      ${renderPermissionOwner(owner, { aclState: access.acl_state || "collected", aclError: access.acl_error || "" })}
      ${access.summary && !exposure ? renderPermissionSummary(access.summary) : ""}
      ${principals.length
        ? renderPermissionPrincipals(principals, { caption: "Principals that expose this file" })
        : (access.acl_state === "collected" ? '<p class="perm-ok">No broad group, unresolved SID or service identity can read or write this file.</p>' : "")}
      ${why && showWhy ? `<p class="perm-why"><strong>Why:</strong> ${escapeHtml(why)}</p>` : ""}
      ${renderAccessModelNote((exposure && { label: "Direct ACL access", note: exposure.access_model }) || access.access_model || {})}
    </section>`;
}
