/* ── Alerts and a finding's tickets (D3) ──────────────────────────
   The Alerts page (Evidence -> Alerts) and the ticket section of the Remediation
   drawer, moved out of app.js as they were.

   Loaded before app.js, like every file in console/: definitions and DOM wiring
   only. The console's helpers (api, escapeHtml, can ...) are used when a handler
   runs, never while this file loads. */

/* ── Alerts (D3) ──────────────────────────────────────────────── */
// What scans raised, where each alert went, and who acknowledged it. The server owns
// delivery - the queue, the retries, the signatures; this page reads it.
function alertsParts() {
  return {
    body: document.querySelector("#alerts-body"),
    context: document.querySelector("#alerts-context"),
    filter: document.querySelector("#alerts-filter"),
    badge: document.querySelector("#alerts-nav-badge"),
  };
}
const ALERT_CHANNEL_LABELS = { webhook: "Webhook", email: "E-mail" };
const ALERT_DELIVERY_WORDS = { delivered: "delivered", pending: "waiting", cancelled: "cancelled" };

function alertDeliveryText(delivery) {
  const label = ALERT_CHANNEL_LABELS[delivery.channel] || delivery.channel;
  if (delivery.status === "pending" && delivery.attempts > 0) {
    return `${label}: retrying (${delivery.attempts} attempt${delivery.attempts === 1 ? "" : "s"}) - ${delivery.last_error || "not accepted yet"}`;
  }
  return `${label}: ${ALERT_DELIVERY_WORDS[delivery.status] || delivery.status}`;
}

function renderAlerts(alerts, open) {
  const { body: alertsBody, context: alertsContext, filter: alertsFilter, badge: alertsNavBadge } = alertsParts();
  if (alertsNavBadge) {
    alertsNavBadge.hidden = !open;
    alertsNavBadge.textContent = open ? String(open) : "";
  }
  if (alertsContext) {
    alertsContext.textContent = open
      ? `${open} open alert${open === 1 ? "" : "s"}. Acknowledge one when it has been looked at.`
      : "No open alerts.";
  }
  if (!alertsBody) return;
  if (!alerts.length) {
    alertsBody.innerHTML = `<tr><td colspan="6" class="empty">${alertsFilter?.value === "open" ? "No open alerts." : "No alerts yet. A scan raises one when it finds critical exposure."}</td></tr>`;
    return;
  }
  const mayAcknowledge = can("findings.triage");
  alertsBody.innerHTML = alerts.map((alert) => {
    const deliveries = (alert.deliveries || []).map(alertDeliveryText);
    const status = alert.status === "acknowledged"
      ? `Acknowledged by ${escapeHtml(alert.acknowledged_by)} ${escapeHtml(getFriendlyTimestamp(alert.acknowledged_at))}`
      : "Open";
    const action = alert.status === "open" && mayAcknowledge
      ? `<button type="button" class="secondary-btn" data-alert-ack="${Number(alert.alert_id)}">Acknowledge</button>`
      : "";
    return `<tr>
      <td>${escapeHtml(getFriendlyTimestamp(alert.created_at))}</td>
      <td><span class="badge ${escapeHtml(alert.severity || "")}">${escapeHtml(alert.severity || "-")}</span></td>
      <td><strong>${escapeHtml(alert.title)}</strong><br><span class="muted">${escapeHtml(alert.message)}</span></td>
      <td>${deliveries.length ? deliveries.map(escapeHtml).join("<br>") : '<span class="muted">No channel set</span>'}</td>
      <td>${status}</td>
      <td>${action}</td>
    </tr>`;
  }).join("");
}

async function loadAlerts() {
  if (!accessToken) return;
  const { body: alertsBody, filter: alertsFilter } = alertsParts();
  const context = captureTenantContext();
  const status = alertsFilter?.value ?? "open";
  try {
    const data = await api(`/api/alerts${status ? `?status=${encodeURIComponent(status)}` : ""}`, null, "GET");
    if (!isCurrentTenantContext(context)) return;
    renderAlerts(data.alerts || [], Number(data.open || 0));
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    if (alertsBody) alertsBody.innerHTML = `<tr><td colspan="6" class="empty">Alerts unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

alertsParts().filter?.addEventListener("change", () => { loadAlerts(); });
document.querySelector("#refresh-alerts-btn")?.addEventListener("click", () => { loadAlerts(); });
alertsParts().body?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-alert-ack]");
  if (!button) return;
  button.disabled = true;
  try {
    await api(`/api/alerts/${encodeURIComponent(button.dataset.alertAck)}/acknowledge`, null, "POST");
    showToast("Alert acknowledged", "", "success");
  } catch (error) {
    showToast("Could not acknowledge the alert", error.message, "danger");
  }
  loadAlerts();
});


/* ── A finding's ticket (D3) ──────────────────────────────────── */
// Sent to Jira or ServiceNow from the queue; closing the ticket there resolves the
// finding here. The drawer shows the ticket and, when there is none, a button per
// ticket system the workspace has turned on.
const TICKET_SYSTEM_LABELS = { jira: "Jira", servicenow: "ServiceNow" };
const TICKET_STATUS_WORDS = { pending: "being created", open: "open", closed: "closed", cancelled: "cancelled" };

function remediationTicketSection(finding = {}) {
  if (!finding.finding_id) return "";
  return `<section class="remediation-drawer-section" data-ticket-finding="${escapeHtml(finding.finding_id)}"><h4>Ticket</h4><div data-ticket-slot><span class="remediation-cell-secondary">Loading tickets…</span></div></section>`;
}

function findingTicketMarkup(tickets, systems, findingId, mayRequest) {
  const lines = tickets.map((ticket) => {
    const label = TICKET_SYSTEM_LABELS[ticket.system] || ticket.system;
    const name = ticket.external_key ? `${label} ${ticket.external_key}` : label;
    const link = ticket.external_url && /^https:\/\//i.test(ticket.external_url)
      ? `<a href="${escapeHtml(ticket.external_url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(name)}</a>`
      : escapeHtml(name);
    const state = TICKET_STATUS_WORDS[ticket.status] || ticket.status;
    const error = ticket.status === "pending" && ticket.last_error ? ` - ${escapeHtml(ticket.last_error)}` : "";
    const outside = ticket.external_status ? ` (${escapeHtml(ticket.external_status)})` : "";
    return `<li>${link}: ${escapeHtml(state)}${outside}${error}</li>`;
  });
  const live = new Set(tickets.filter((ticket) => ["pending", "open"].includes(ticket.status)).map((ticket) => ticket.system));
  const buttons = mayRequest
    ? systems.filter((system) => !live.has(system)).map((system) => `<button type="button" class="btn" data-ticket-system="${escapeHtml(system)}" data-finding-id="${escapeHtml(findingId)}">Send to ${escapeHtml(TICKET_SYSTEM_LABELS[system] || system)}</button>`)
    : [];
  const empty = !tickets.length && !buttons.length
    ? `<span class="remediation-cell-secondary">${systems.length || !mayRequest ? "No ticket." : "No ticket system is set up (Account → Settings → Features → Alerts & tickets)."}</span>`
    : "";
  return `${lines.length ? `<ul class="remediation-risk-list">${lines.join("")}</ul>` : ""}${buttons.join(" ")}${empty}`;
}

async function loadFindingTickets(findingId) {
  if (!findingId || !accessToken) return;
  const mayRequest = can("findings.triage");
  const [tickets, systems] = await Promise.all([
    api(`/api/tickets?finding_id=${encodeURIComponent(findingId)}`, null, "GET").then((data) => data.tickets || []),
    mayRequest ? api("/api/tickets/systems", null, "GET").then((data) => data.systems || []).catch(() => []) : Promise.resolve([]),
  ]);
  const section = [...document.querySelectorAll("[data-ticket-finding]")].find((item) => item.dataset.ticketFinding === String(findingId));
  const slot = section?.querySelector("[data-ticket-slot]");
  if (slot) slot.innerHTML = findingTicketMarkup(tickets, systems, findingId, mayRequest);
}

document.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-ticket-system]");
  if (!button) return;
  button.disabled = true;
  const system = button.dataset.ticketSystem;
  try {
    await api(`/api/findings/${encodeURIComponent(button.dataset.findingId)}/ticket`, { system }, "POST");
    showToast("Ticket requested", `It is created in ${TICKET_SYSTEM_LABELS[system] || system} from the queue.`, "success");
  } catch (error) {
    showToast("Could not request a ticket", error.message, "danger");
  }
  loadFindingTickets(button.dataset.findingId).catch(() => {});
});
