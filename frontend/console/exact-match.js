/* ── Exact-match reference sets (D2) ──────────────────────────────
   An approved list of real values - customer numbers, card numbers, national IDs -
   that a finding is checked against: one whose value is on a list is confirmed. The
   server fingerprints each value with the workspace's key and keeps only the
   fingerprints; nothing here keeps the values either. The list is read in the browser
   (typed, or from a file that is read here and never uploaded as a file), sent once,
   and cleared. A set made under another evidence key matches nothing and says so.

   Loaded before app.js: definitions and DOM wiring only. */

const EXACT_MATCH_MAX_VALUES = 50_000;
const EXACT_MATCH_TYPE_LABELS = {
  EMAIL_ADDRESS: "E-mail address",
  PHONE_NUMBER: "Phone number",
  GOVERNMENT_ID: "National ID or FIN",
  PASSPORT_NUMBER: "Passport number",
  PERSON_NAME: "Person's name",
};

function exactMatchParts() {
  return {
    body: document.querySelector("#edm-sets-body"),
    form: document.querySelector("#edm-form"),
    name: document.querySelector("#edm-name"),
    type: document.querySelector("#edm-type"),
    values: document.querySelector("#edm-values"),
    file: document.querySelector("#edm-file"),
    count: document.querySelector("#edm-count"),
    status: document.querySelector("#edm-status"),
  };
}

function exactMatchTypeLabel(type) {
  return EXACT_MATCH_TYPE_LABELS[type] || String(type || "").replace(/_/g, " ").toLowerCase();
}

// One value per line, taken whole (a name may hold a comma). Blank lines and repeats go.
function exactMatchValues(text) {
  const seen = new Set();
  for (const line of String(text || "").split(/\r?\n/)) {
    const value = line.trim();
    if (value) seen.add(value);
  }
  return [...seen];
}

// The first field of one CSV row: quoted ("Aliyeva, Leyla" stays whole, "" is a quote)
// or up to the delimiter.
function exactMatchFirstField(line, delimiter) {
  const text = String(line || "").trim();
  if (!text.startsWith('"')) return text.split(delimiter)[0].trim();
  let value = "";
  for (let index = 1; index < text.length; index += 1) {
    if (text[index] === '"') {
      if (text[index + 1] === '"') {
        value += '"';
        index += 1;
      } else {
        break;
      }
    } else {
      value += text[index];
    }
  }
  return value.trim();
}

// A .csv file gives each row's first field - comma, semicolon (the Excel export in
// Azerbaijani, Russian or German) or tab, whichever the first line uses most; any other
// file, its lines.
function exactMatchFileText(name, text) {
  if (!/\.csv$/i.test(String(name || ""))) return String(text || "");
  const lines = String(text || "").split(/\r?\n/);
  const first = lines.find((line) => line.trim()) || "";
  const delimiter = [",", ";", "\t"].map((mark) => [mark, first.split(mark).length])
    .sort((left, right) => right[1] - left[1])[0][0];
  return lines.map((line) => exactMatchFirstField(line, delimiter)).join("\n");
}

// A workspace switch clears the form: values typed for one customer must not be added to
// the next one's set by the next click.
function resetExactMatchForm() {
  const parts = exactMatchParts();
  parts.form?.reset();
  if (parts.values) parts.values.value = "";
  if (parts.count) parts.count.textContent = "";
  if (parts.status) parts.status.textContent = "";
  if (parts.body) parts.body.innerHTML = "";
}

function renderExactMatchCount() {
  const parts = exactMatchParts();
  if (!parts.count) return;
  const count = exactMatchValues(parts.values?.value).length;
  parts.count.textContent = count
    ? `${count.toLocaleString()} value${count === 1 ? "" : "s"}${count > EXACT_MATCH_MAX_VALUES ? ` - at most ${EXACT_MATCH_MAX_VALUES.toLocaleString()} a set` : ""}`
    : "";
}

function renderExactMatchSets(sets, types) {
  const parts = exactMatchParts();
  if (parts.type && types?.length && !parts.type.options.length) {
    parts.type.innerHTML = types.map((type) => `<option value="${escapeHtml(type)}">${escapeHtml(exactMatchTypeLabel(type))}</option>`).join("");
  }
  if (!parts.body) return;
  if (!sets.length) {
    parts.body.innerHTML = '<tr><td colspan="6" class="empty">No reference sets. A finding is then judged by its detector alone.</td></tr>';
    return;
  }
  parts.body.innerHTML = sets.map((set) => `<tr>
    <td><strong>${escapeHtml(set.name)}</strong></td>
    <td>${escapeHtml(exactMatchTypeLabel(set.entity_type))}</td>
    <td class="is-numeric">${Number(set.values || 0).toLocaleString()}</td>
    <td>${escapeHtml(getFriendlyTimestamp(set.created_at))}<br><span class="muted">${escapeHtml(set.created_by || "")}</span></td>
    <td>${set.current ? "Current" : '<span class="edm-stale" title="Made under another evidence key: it matches nothing. Add the list again.">Another key</span>'}</td>
    <td><button type="button" class="secondary-btn mini-btn" data-edm-delete="${escapeHtml(set.set_id)}" data-edm-name="${escapeHtml(set.name)}">Remove</button></td>
  </tr>`).join("");
}

async function loadExactMatchSets() {
  if (!accessToken || !can("rules.manage")) return;
  const parts = exactMatchParts();
  const context = captureTenantContext();
  try {
    const data = await api("/api/exact-match/sets", null, "GET");
    if (!isCurrentTenantContext(context)) return;
    renderExactMatchSets(data.sets || [], data.entity_types || []);
  } catch (error) {
    if (!isCurrentTenantContext(context)) return;
    if (parts.body) parts.body.innerHTML = `<tr><td colspan="6" class="empty">Reference sets unavailable: ${escapeHtml(error.message)}</td></tr>`;
  }
}

(function wireExactMatchPanel() {
  const parts = exactMatchParts();
  parts.values?.addEventListener("input", renderExactMatchCount);
  document.querySelector("#refresh-edm-btn")?.addEventListener("click", () => loadExactMatchSets());
  parts.file?.addEventListener("change", () => {
    const file = parts.file.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      // Read here; the file itself is never sent anywhere.
      if (parts.values) parts.values.value = exactMatchFileText(file.name, reader.result);
      parts.file.value = "";
      renderExactMatchCount();
    };
    reader.readAsText(file);
  });
  parts.form?.addEventListener("submit", async (event) => {
    event.preventDefault();
    const values = exactMatchValues(parts.values?.value);
    const name = (parts.name?.value || "").trim();
    if (!name || !values.length) {
      if (parts.status) parts.status.textContent = "Give the set a name and at least one value.";
      return;
    }
    if (values.length > EXACT_MATCH_MAX_VALUES) {
      if (parts.status) parts.status.textContent = `A set holds at most ${EXACT_MATCH_MAX_VALUES.toLocaleString()} values; split the list.`;
      return;
    }
    const submit = parts.form.querySelector("[type=submit]");
    if (submit) submit.disabled = true;
    if (parts.status) parts.status.textContent = "Fingerprinting the values...";
    try {
      const created = await api("/api/exact-match/sets", { name, entity_type: parts.type?.value || "", values }, "POST");
      if (parts.values) parts.values.value = "";
      if (parts.name) parts.name.value = "";
      renderExactMatchCount();
      if (parts.status) parts.status.textContent = `"${created.name}" holds ${Number(created.values || 0).toLocaleString()} values. Findings are checked against it from the next scan.`;
      showToast("Reference set added", `${Number(created.values || 0).toLocaleString()} values, kept as fingerprints only.`, "success");
      loadExactMatchSets();
    } catch (error) {
      if (parts.status) parts.status.textContent = error.message;
    } finally {
      if (submit) submit.disabled = false;
    }
  });
  parts.body?.addEventListener("click", async (event) => {
    const button = event.target.closest("[data-edm-delete]");
    if (!button) return;
    if (!window.confirm(`Remove the reference set "${button.dataset.edmName}"? Findings are no longer confirmed against it from the next scan.`)) return;
    button.disabled = true;
    try {
      await api(`/api/exact-match/sets/${encodeURIComponent(button.dataset.edmDelete)}`, null, "DELETE");
      showToast("Reference set removed", "", "success");
    } catch (error) {
      showToast("Could not remove the set", error.message, "danger");
    }
    loadExactMatchSets();
  });
})();
