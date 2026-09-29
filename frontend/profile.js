/* Settings page: profile, security, appearance, install features, session.
   The avatar's source of truth is the account record (/api/profile/avatar);
   localStorage only caches it per browser for instant paint. */

const profileForm = document.querySelector("#profile-form");
const passwordForm = document.querySelector("#password-form");
const profileStatus = document.querySelector("#profile-status");
const passwordStatus = document.querySelector("#password-status");
const featuresStatus = document.querySelector("#features-status");
const logoutBtn = document.querySelector("#profile-logout-btn");
const identityAvatar = document.querySelector("#settings-avatar");
const identityName = document.querySelector("#settings-identity-name");
const identityRole = document.querySelector("#settings-identity-role");
const identityTenant = document.querySelector("#settings-identity-tenant");
const protectionBadge = document.querySelector("#settings-protection-badge");
const usernameLabel = document.querySelector("#profile-username");
const roleLabel = document.querySelector("#profile-role-label");
const tenantLabel = document.querySelector("#profile-tenant-label");
const fullNameInput = document.querySelector("#profile-full-name");
const saveProfileBtn = document.querySelector("#save-profile-btn");
const avatarPreview = document.querySelector("#profile-avatar-preview");
const avatarFileInput = document.querySelector("#avatar-file-input");
const chooseAvatarBtn = document.querySelector("#choose-avatar-btn");
const removeAvatarBtn = document.querySelector("#remove-avatar-btn");
const avatarHelp = document.querySelector("#avatar-help");
const avatarCropModal = document.querySelector("#avatar-crop-modal");
const avatarCropCanvas = document.querySelector("#avatar-crop-canvas");
const avatarZoom = document.querySelector("#avatar-zoom");
const avatarApplyBtn = document.querySelector("#avatar-apply-btn");
const avatarCropClose = document.querySelector("#avatar-crop-close");
const avatarCropCancel = document.querySelector("#avatar-crop-cancel");
const ocrToggle = document.querySelector("#feature-ocr-toggle");
const ocrState = document.querySelector("#feature-ocr-state");
const sessionUserLabel = document.querySelector("#session-user");
const sessionRoleLabel = document.querySelector("#session-role");
const sessionTenantLabel = document.querySelector("#session-tenant");
const sessionExpiresLabel = document.querySelector("#session-expires");

let protectedAccount = false;
let activeAvatarUser = null;
let cropImage = null;
let cropState = { scale: 1, offsetX: 0, offsetY: 0, dragging: false, startX: 0, startY: 0 };
let cropBase = { width: 0, height: 0 };

const AVATAR_MAX_BYTES = 2 * 1024 * 1024;
const AVATAR_MIN_SIZE = 160;
const AVATAR_MAX_SIZE = 4096;
const AVATAR_OUTPUT_SIZE = 256;

function sessionGet(key) {
  try {
    return window.sessionStorage.getItem(key);
  } catch {
    return "";
  }
}

function sessionSet(key, value) {
  try {
    if (value) window.sessionStorage.setItem(key, value);
    else window.sessionStorage.removeItem(key);
  } catch {
    return false;
  }
  return true;
}

function storageGet(key) {
  try {
    return window.localStorage.getItem(key);
  } catch {
    return "";
  }
}

function storageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
  } catch {
    return false;
  }
  return true;
}

function storageRemove(key) {
  try {
    window.localStorage.removeItem(key);
  } catch {
    return false;
  }
  return true;
}

function authHeaders() {
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${sessionGet("dspm-access-token")}`,
    "X-Tenant-ID": sessionGet("dspm-tenant-id") || "default",
  };
}

async function readError(response) {
  const message = await response.text();
  try {
    const data = JSON.parse(message);
    if (typeof data.detail === "string") return { message: data.detail, code: "" };
    // C2: a refusal can carry a code - "mfa_required" asks for the second factor.
    if (data.detail && typeof data.detail === "object") {
      return { message: data.detail.message || "Request failed.", code: data.detail.code || "" };
    }
    return { message: "Request failed.", code: "" };
  } catch {
    return { message: message || "Request failed.", code: "" };
  }
}

// C1: the access token lasts half an hour and the session is carried by the refresh
// cookie, exactly as on the console - so a 401 here is the normal end of an access
// token, not of the session. One exchange at a time: the page loads several panels at
// once, and a second exchange would present the token the first had just retired,
// which the server reads as a replay and answers by ending the session everywhere.
let refreshInFlight = null;

async function refreshAccessToken() {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      try {
        const response = await fetch("/api/auth/refresh", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          credentials: "same-origin",
        });
        if (!response.ok) return false;
        const data = await response.json();
        if (!data.access_token) return false;
        sessionSet("dspm-access-token", data.access_token);
        renderSessionExpiry();
        return true;
      } catch {
        return false;
      } finally {
        window.setTimeout(() => { refreshInFlight = null; }, 0);
      }
    })();
  }
  return refreshInFlight;
}

async function api(path, payload, method = "GET", isRetry = false) {
  const response = await fetch(path, {
    method,
    headers: authHeaders(),
    body: payload ? JSON.stringify(payload) : undefined,
  });
  if (response.status === 401 && !isRetry && await refreshAccessToken()) {
    return api(path, payload, method, true);
  }
  if (!response.ok) {
    const problem = await readError(response);
    const error = new Error(problem.message);
    error.code = problem.code;
    error.status = response.status;
    throw error;
  }
  return response.json();
}

function setStatus(element, message) {
  if (element) element.textContent = message || " ";
}

/* ── Section routing ──────────────────────────────────────────── */
const navItems = [...document.querySelectorAll(".settings-nav-item")];
const sections = [...document.querySelectorAll(".settings-section")];

function activateSection(name, updateHash = true) {
  const known = sections.some((section) => section.dataset.panel === name);
  const target = known ? name : "profile";
  navItems.forEach((item) => item.classList.toggle("active", item.dataset.section === target));
  sections.forEach((section) => section.classList.toggle("active", section.dataset.panel === target));
  if (updateHash) history.replaceState(null, "", `#${target}`);
}

navItems.forEach((item) => {
  item.addEventListener("click", () => activateSection(item.dataset.section));
});
window.addEventListener("hashchange", () => activateSection(location.hash.slice(1), false));

/* ── Theme ────────────────────────────────────────────────────── */
const themeQuickToggle = document.querySelector("#settings-theme-toggle");

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  storageSet("dspm-theme", theme);
  if (themeQuickToggle) {
    // Same control as the console topbar: sun in dark mode, moon in light.
    const nextLabel = theme === "dark" ? "Switch to light mode" : "Switch to dark mode";
    themeQuickToggle.querySelector(".theme-icon").innerHTML = theme === "dark" ? "&#9728;" : "&#9790;";
    themeQuickToggle.setAttribute("aria-label", nextLabel);
    themeQuickToggle.title = nextLabel;
  }
}

if (themeQuickToggle) {
  themeQuickToggle.addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
}

/* Collapsible rail, remembered per browser like the console sidebar. */
const railToggle = document.querySelector("#settings-rail-toggle");
const settingsShell = document.querySelector(".settings-shell");

function applyRailState(collapsed) {
  settingsShell.classList.toggle("rail-collapsed", collapsed);
  railToggle.setAttribute("aria-label", collapsed ? "Expand navigation" : "Collapse navigation");
  railToggle.title = collapsed ? "Expand navigation" : "Collapse navigation";
  storageSet("dspm-settings-rail", collapsed ? "collapsed" : "expanded");
}

if (railToggle && settingsShell) {
  railToggle.addEventListener("click", () => {
    applyRailState(!settingsShell.classList.contains("rail-collapsed"));
  });
  applyRailState(storageGet("dspm-settings-rail") === "collapsed");
}

/* ── Avatar ───────────────────────────────────────────────────── */
function avatarStorageKey(user = activeAvatarUser) {
  const username = String(user?.username || sessionGet("dspm-user") || "user").toLowerCase();
  const tenant = String(user?.tenant_id || sessionGet("dspm-tenant-id") || "default").toLowerCase();
  return `dspm-avatar-${tenant}-${username}`;
}

function setAvatarElement(element, imageData, fallbackInitial) {
  if (!element) return;
  if (imageData) {
    element.textContent = "";
    element.style.backgroundImage = `url("${imageData}")`;
    element.classList.add("has-image");
    element.setAttribute("aria-label", "Profile photo");
  } else {
    element.style.backgroundImage = "";
    element.textContent = fallbackInitial || "U";
    element.classList.remove("has-image");
    element.removeAttribute("aria-label");
  }
}

function paintAvatar(imageData) {
  const initial = (activeAvatarUser?.username || "U").trim().charAt(0).toUpperCase() || "U";
  setAvatarElement(identityAvatar, imageData, initial);
  setAvatarElement(avatarPreview, imageData, initial);
}

function updateAvatarHelp(message, isError = false) {
  avatarHelp.textContent = message;
  avatarHelp.classList.toggle("error", Boolean(isError));
}

function closeAvatarCrop() {
  avatarCropModal.classList.add("hidden");
  cropImage = null;
  cropState.dragging = false;
}

function drawCropCanvas() {
  if (!cropImage) return;
  const canvas = avatarCropCanvas;
  const ctx = canvas.getContext("2d");
  const size = canvas.width;
  ctx.clearRect(0, 0, size, size);
  ctx.fillStyle = "#0f172a";
  ctx.fillRect(0, 0, size, size);

  const drawWidth = cropBase.width * cropState.scale;
  const drawHeight = cropBase.height * cropState.scale;
  cropState.offsetX = Math.min(0, Math.max(size - drawWidth, cropState.offsetX));
  cropState.offsetY = Math.min(0, Math.max(size - drawHeight, cropState.offsetY));

  ctx.drawImage(cropImage, cropState.offsetX, cropState.offsetY, drawWidth, drawHeight);
  ctx.save();
  ctx.fillStyle = "rgba(2, 6, 23, .50)";
  ctx.beginPath();
  ctx.rect(0, 0, size, size);
  ctx.arc(size / 2, size / 2, size * 0.42, 0, Math.PI * 2, true);
  ctx.fill("evenodd");
  ctx.restore();
  ctx.beginPath();
  ctx.arc(size / 2, size / 2, size * 0.42, 0, Math.PI * 2);
  ctx.strokeStyle = "rgba(255, 255, 255, .92)";
  ctx.lineWidth = 3;
  ctx.stroke();
}

function openAvatarCrop(image) {
  cropImage = image;
  const size = avatarCropCanvas.width;
  const baseScale = Math.max(size / image.naturalWidth, size / image.naturalHeight);
  cropBase = { width: image.naturalWidth * baseScale, height: image.naturalHeight * baseScale };
  cropState = {
    scale: 1,
    offsetX: (size - cropBase.width) / 2,
    offsetY: (size - cropBase.height) / 2,
    dragging: false,
    startX: 0,
    startY: 0,
  };
  avatarZoom.value = "1";
  avatarCropModal.classList.remove("hidden");
  drawCropCanvas();
}

function canvasPoint(event) {
  const rect = avatarCropCanvas.getBoundingClientRect();
  const pointer = event.touches?.[0] || event;
  return {
    x: (pointer.clientX - rect.left) * (avatarCropCanvas.width / rect.width),
    y: (pointer.clientY - rect.top) * (avatarCropCanvas.height / rect.height),
  };
}

function exportAvatarImage() {
  if (!cropImage) return "";
  const output = document.createElement("canvas");
  output.width = AVATAR_OUTPUT_SIZE;
  output.height = AVATAR_OUTPUT_SIZE;
  const ctx = output.getContext("2d");
  const scale = AVATAR_OUTPUT_SIZE / avatarCropCanvas.width;
  ctx.clearRect(0, 0, AVATAR_OUTPUT_SIZE, AVATAR_OUTPUT_SIZE);
  ctx.save();
  ctx.beginPath();
  ctx.arc(AVATAR_OUTPUT_SIZE / 2, AVATAR_OUTPUT_SIZE / 2, AVATAR_OUTPUT_SIZE / 2, 0, Math.PI * 2);
  ctx.clip();
  ctx.drawImage(
    cropImage,
    cropState.offsetX * scale,
    cropState.offsetY * scale,
    cropBase.width * cropState.scale * scale,
    cropBase.height * cropState.scale * scale,
  );
  ctx.restore();
  return output.toDataURL("image/png");
}

function validateAvatarFile(file) {
  if (!file) return "Select an image file.";
  if (!["image/png", "image/jpeg", "image/webp"].includes(file.type)) {
    return "Only PNG, JPG, and WebP images are supported.";
  }
  if (file.size > AVATAR_MAX_BYTES) return "Image must be 2 MB or smaller.";
  return "";
}

function loadAvatarFile(file) {
  const fileError = validateAvatarFile(file);
  if (fileError) {
    updateAvatarHelp(fileError, true);
    return;
  }
  const reader = new FileReader();
  reader.addEventListener("load", () => {
    const image = new Image();
    image.addEventListener("load", () => {
      if (image.naturalWidth < AVATAR_MIN_SIZE || image.naturalHeight < AVATAR_MIN_SIZE) {
        updateAvatarHelp(`Image must be at least ${AVATAR_MIN_SIZE}×${AVATAR_MIN_SIZE} px.`, true);
        return;
      }
      if (image.naturalWidth > AVATAR_MAX_SIZE || image.naturalHeight > AVATAR_MAX_SIZE) {
        updateAvatarHelp(`Image must be no larger than ${AVATAR_MAX_SIZE}×${AVATAR_MAX_SIZE} px.`, true);
        return;
      }
      updateAvatarHelp("Drag the image inside the circle and adjust zoom.");
      openAvatarCrop(image);
    });
    image.addEventListener("error", () => updateAvatarHelp("Could not read this image.", true));
    image.src = String(reader.result || "");
  });
  reader.addEventListener("error", () => updateAvatarHelp("Could not load this file.", true));
  reader.readAsDataURL(file);
}

async function saveAvatar(avatarData) {
  const data = await api("/api/profile/avatar", { avatar: avatarData || "" }, "PUT");
  const saved = String(data.avatar || "");
  if (saved) storageSet(avatarStorageKey(), saved);
  else storageRemove(avatarStorageKey());
  paintAvatar(saved);
  return saved;
}

/* ── Profile ──────────────────────────────────────────────────── */
function renderProfile(user, isProtected, serverAvatar) {
  protectedAccount = Boolean(isProtected);
  activeAvatarUser = user;
  const name = user.full_name || user.username || "Account";
  identityName.textContent = name;
  identityRole.textContent = user.role || "viewer";
  identityTenant.textContent = user.tenant_id || "default";
  usernameLabel.textContent = user.username || "-";
  roleLabel.textContent = user.role || "-";
  tenantLabel.textContent = user.tenant_id || "-";
  protectionBadge.hidden = !protectedAccount;
  fullNameInput.value = user.full_name || "";
  fullNameInput.disabled = protectedAccount;
  saveProfileBtn.disabled = protectedAccount;
  passwordForm.querySelectorAll("input, button").forEach((item) => {
    item.disabled = protectedAccount;
  });
  if (protectedAccount) {
    setStatus(profileStatus, "The built-in admin identity is fixed; only the photo can change.");
    setStatus(passwordStatus, "The built-in admin password is managed at install level.");
  }
  sessionSet("dspm-user", user.username || "");
  sessionSet("dspm-role", user.role || "");
  sessionSet("dspm-tenant-id", user.tenant_id || "default");
  sessionUserLabel.textContent = user.username || "-";
  sessionRoleLabel.textContent = user.role || "-";
  sessionTenantLabel.textContent = user.tenant_id || "-";
  const avatarData = serverAvatar || storageGet(avatarStorageKey(user)) || "";
  if (serverAvatar) storageSet(avatarStorageKey(user), serverAvatar);
  paintAvatar(avatarData);
}

function renderSessionExpiry() {
  const token = sessionGet("dspm-access-token") || "";
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    if (payload.exp) {
      sessionExpiresLabel.textContent = new Date(payload.exp * 1000).toLocaleString([], {
        dateStyle: "medium",
        timeStyle: "short",
      });
      return;
    }
  } catch {
    /* fall through to the placeholder */
  }
  sessionExpiresLabel.textContent = "-";
}

async function loadProfile() {
  if (!sessionGet("dspm-access-token")) {
    window.location.replace("/login");
    return;
  }
  try {
    const data = await api("/api/profile");
    renderProfile(data.user || {}, data.protected, String(data.avatar || ""));
  } catch (error) {
    const username = sessionGet("dspm-user") || "user";
    renderProfile(
      {
        username,
        role: sessionGet("dspm-role") || "viewer",
        tenant_id: sessionGet("dspm-tenant-id") || "default",
        full_name: username,
      },
      username === "admin",
      "",
    );
    setStatus(profileStatus, `Could not load the account record: ${error.message}`);
  }
}

/* ── Install features ─────────────────────────────────────────── */
const OCR_STATE_LINES = {
  enabled: "On — images and scanned documents are text-extracted during scans.",
  enabled_but_dependency_missing:
    "On, but the OCR engine is not installed on the server (pip install -r requirements-ocr.txt).",
  disabled_dependency_present: "Off — the OCR engine is installed and ready.",
  disabled: "Off — install the OCR engine on the server to use this.",
};

function renderFeatures(features) {
  renderSiemSummary(features?.siem);
  const ocr = features?.ocr;
  if (!ocr) return;
  ocrToggle.checked = Boolean(ocr.enabled);
  ocrToggle.disabled = !ocr.editable;
  ocrState.textContent = OCR_STATE_LINES[ocr.state] || (ocr.enabled ? "On." : "Off.");
  setStatus(
    featuresStatus,
    ocr.editable ? "" : "Only administrators can change install features.",
  );
}

async function loadFeatures() {
  try {
    const data = await api("/api/settings/features");
    renderFeatures(data.features);
  } catch (error) {
    ocrState.textContent = "Unavailable.";
    setStatus(featuresStatus, `Could not load features: ${error.message}`);
  }
}

ocrToggle.addEventListener("change", async () => {
  const wanted = ocrToggle.checked;
  ocrToggle.disabled = true;
  setStatus(featuresStatus, wanted ? "Turning OCR on…" : "Turning OCR off…");
  try {
    const data = await api("/api/settings/features", { ocr_enabled: wanted }, "PUT");
    renderFeatures(data.features);
    setStatus(featuresStatus, wanted
      ? "OCR is on. It applies from the next scan — no restart needed."
      : "OCR is off. It applies from the next scan — no restart needed.");
  } catch (error) {
    ocrToggle.checked = !wanted;
    ocrToggle.disabled = false;
    setStatus(featuresStatus, `Change failed: ${error.message}`);
  }
});

/* ── SIEM integration (C4) ────────────────────────────────────── */
// The server owns forwarding - the queue, retries, TLS, delivery. This is where it is
// configured and watched. The page never holds the CA certificate the server stored (it
// gets a name and a fingerprint), and a save carries a certificate only when one was
// chosen here: an omitted certificate keeps the stored one, "Remove certificate" deletes
// it. Syslog over TLS, TCP or UDP has no credential, so there is no password field.
const siemToggle = document.querySelector("#feature-siem-toggle");
const siemState = document.querySelector("#siem-state");
const siemStateText = document.querySelector("#siem-state-text");
const siemPanel = document.querySelector("#siem-panel");
const siemForm = document.querySelector("#siem-form");
const siemHost = document.querySelector("#siem-host");
const siemPort = document.querySelector("#siem-port");
const siemTransport = document.querySelector("#siem-transport");
const siemFormat = document.querySelector("#siem-format");
const siemTrust = document.querySelector("#siem-trust");
const siemCaField = document.querySelector("#siem-ca-field");
const siemCaSummary = document.querySelector("#siem-ca-summary");
const siemCaFile = document.querySelector("#siem-ca-file");
const siemCaChoose = document.querySelector("#siem-ca-choose");
const siemCaRemove = document.querySelector("#siem-ca-remove");
const siemNote = document.querySelector("#siem-transport-note");
const siemTestBtn = document.querySelector("#siem-test-btn");
const siemRetryBtn = document.querySelector("#siem-retry-btn");
const siemSaveBtn = document.querySelector("#siem-save-btn");
const siemRemoveRow = document.querySelector("#siem-remove-row");
const siemRemoveBtn = document.querySelector("#siem-remove-btn");
const siemStatus = document.querySelector("#siem-status");
const siemFacts = {
  receiver: document.querySelector("#siem-fact-receiver"),
  delivery: document.querySelector("#siem-fact-delivery"),
  queue: document.querySelector("#siem-fact-queue"),
  ca: document.querySelector("#siem-fact-ca"),
  errorRow: document.querySelector("#siem-fact-error-row"),
  error: document.querySelector("#siem-fact-error"),
};

const SIEM_DEFAULT_PORTS = { tls: 6514, tcp: 514, udp: 514 };
const SIEM_CA_MAX_BYTES = 64 * 1024;
const SIEM_TRANSPORT_NOTES = {
  tls: "The receiver's certificate and name are always verified.",
  tcp: "TCP is not encrypted: audit events cross the network in clear text.",
  udp: "UDP is not encrypted and confirms nothing: an event lost in transit is not resent.",
};

let siemView = null;        // the last /api/settings/siem answer
let siemPendingCa = null;   // { pem, name } chosen on this visit, not saved yet
let siemRemoveCa = false;   // "Remove certificate" pressed, not saved yet

function siemWhen(iso, now = Date.now()) {
  if (!iso) return "Never";
  const at = Date.parse(iso);
  if (Number.isNaN(at)) return "Never";
  const seconds = Math.max(0, Math.round((now - at) / 1000));
  if (seconds < 60) return "Just now";
  if (seconds < 3600) return `${Math.round(seconds / 60)} min ago`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)} h ago`;
  return new Date(at).toLocaleString();
}

// One sentence for the state. "On" is never "connected": only a delivery or a passed
// test of this configuration, with no failure since, is.
function siemStateLine(view, now = Date.now()) {
  if (!view) return "Checking…";
  const queue = view.queue || {};
  const receiver = view.config?.host ? `${view.config.host}:${view.config.port}` : "";
  switch (view.state) {
    case "disabled":
      return receiver ? `Off — the configuration for ${receiver} is kept.` : "Off — audit events are not forwarded.";
    case "not_configured":
      return "On — no receiver configured yet. Events are not being sent.";
    // Someone who may not change the receiver is not told where it is: the summary
    // carries the state alone, and the sentence says only that.
    case "not_connected":
      return receiver
        ? `On — not connected to ${receiver} yet. Test the connection, or wait for the next delivery.`
        : "On — not connected yet.";
    case "connected":
      return receiver
        ? `Connected to ${receiver} — last delivery ${siemWhen(view.status?.last_delivery_at, now).toLowerCase()}.`
        : "Connected — audit events are being delivered.";
    case "degraded": {
      if (!receiver) return "Delivery degraded — audit events are queued and being retried.";
      const count = Number(queue.pending || 0);
      return `Delivery degraded — ${count} event${count === 1 ? "" : "s"} queued for ${receiver}, retrying.`;
    }
    case "unavailable":
      return "Status unavailable.";
    default:
      return "Checking…";
  }
}

// What a save or a test sends. A certificate only when one was chosen here; nothing that
// stands for a stored value is ever sent back as if it were one.
function siemRequestBody(fields, pendingCa, removeCa) {
  const port = Number(String(fields.port ?? "").trim());
  const body = {
    transport: fields.transport || "tls",
    host: String(fields.host || "").trim(),
    port: Number.isInteger(port) && port > 0 ? port : null,
    format: fields.format || "cef",
    trust: fields.transport === "tls" ? (fields.trust || "system") : "system",
  };
  if (pendingCa && pendingCa.pem) {
    body.ca_pem = pendingCa.pem;
    body.ca_name = pendingCa.name || "ca.pem";
  } else if (removeCa) {
    body.remove_ca = true;
  }
  return body;
}

function siemFields() {
  return {
    host: siemHost.value,
    port: siemPort.value,
    transport: siemTransport.value,
    format: siemFormat.value,
    trust: siemTrust.value,
  };
}

function siemCaText() {
  if (siemPendingCa) return `${siemPendingCa.name} — will be saved`;
  if (siemRemoveCa) return "Will be removed when you save";
  const ca = siemView?.config?.ca;
  if (!ca) return "No certificate uploaded";
  return `${ca.name} · SHA-256 ${String(ca.fingerprint || "").slice(0, 23)}…`;
}

function syncSiemFieldVisibility() {
  const tls = siemTransport.value === "tls";
  document.querySelectorAll(".siem-tls-only").forEach((element) => { element.hidden = !tls; });
  siemCaField.hidden = !tls || siemTrust.value !== "custom";
  siemNote.textContent = SIEM_TRANSPORT_NOTES[siemTransport.value] || "";
  siemPort.placeholder = String(SIEM_DEFAULT_PORTS[siemTransport.value] || 6514);
  siemCaSummary.textContent = siemCaText();
  siemCaRemove.hidden = !(siemPendingCa || (siemView?.config?.ca && !siemRemoveCa));
}

function setSiemState(state, line) {
  siemState.dataset.state = state;
  siemStateText.textContent = line;
}

function renderSiemSummary(summary) {
  if (!summary) return;
  siemToggle.checked = Boolean(summary.enabled);
  siemToggle.disabled = !summary.editable;
  if (!summary.editable) {
    siemPanel.hidden = true;
    siemRemoveRow.hidden = true;
    setSiemState(summary.state, siemStateLine({ state: summary.state }));
    setStatus(siemStatus, "Only the installation's administrator can change SIEM forwarding.");
    return;
  }
  // Loaded once per visit: the OCR switch re-renders the features, and reloading here
  // would throw away a half-filled form.
  if (!siemView) {
    setSiemState(summary.state, siemStateLine({ state: summary.state }));
    loadSiem();
  }
}

function renderSiem(view, { fillForm = true } = {}) {
  siemView = view;
  const config = view.config || {};
  siemToggle.checked = Boolean(view.enabled);
  siemToggle.disabled = !view.editable;
  const open = Boolean(view.enabled && view.editable);
  siemPanel.hidden = !open;
  siemToggle.setAttribute("aria-expanded", String(open));
  setSiemState(view.state, siemStateLine(view));
  if (fillForm) {
    siemHost.value = config.host || "";
    siemPort.value = config.host ? String(config.port || "") : "";
    siemTransport.value = config.transport || "tls";
    siemFormat.value = config.format || "cef";
    siemTrust.value = config.trust || "system";
    siemPendingCa = null;
    siemRemoveCa = false;
  }
  syncSiemFieldVisibility();
  const queue = view.queue || {};
  const status = view.status || {};
  siemFacts.receiver.textContent = config.host ? `${config.host}:${config.port} (${String(config.transport).toUpperCase()}, ${String(config.format).toUpperCase()})` : "Not configured";
  siemFacts.delivery.textContent = siemWhen(status.last_delivery_at);
  siemFacts.queue.textContent = queue.pending
    ? `${queue.pending} waiting${queue.failing ? `, ${queue.failing} failed at least once` : ""}`
    : "None";
  siemFacts.ca.textContent = config.transport !== "tls"
    ? `Not used over ${String(config.transport || "").toUpperCase()}${config.ca ? ` (${config.ca.name} is kept for TLS)` : ""}`
    : (config.trust === "custom" ? (config.ca ? `${config.ca.name} · ${config.ca.fingerprint}` : "Missing") : "System trust store");
  // The last error matters while delivery is failing; once events flow again it is history.
  siemFacts.errorRow.hidden = !(status.last_error && (view.state === "degraded" || view.state === "not_connected"));
  siemFacts.error.textContent = status.last_error ? `${status.last_error} (${siemWhen(status.last_error_at).toLowerCase()})` : "";
  siemRetryBtn.hidden = !queue.pending;
  siemRemoveRow.hidden = !(view.editable && view.configured);
}

async function loadSiem() {
  try {
    renderSiem(await api("/api/settings/siem"));
  } catch (error) {
    setSiemState("unavailable", "Status unavailable.");
    setStatus(siemStatus, `Could not load the SIEM settings: ${error.message}`);
  }
}

function siemBusy(busy) {
  [siemTestBtn, siemRetryBtn, siemSaveBtn, siemRemoveBtn, siemCaChoose, siemCaRemove].forEach((button) => {
    if (button) button.disabled = busy;
  });
}

async function siemAction(pending, run, done) {
  siemBusy(true);
  siemStatus.classList.remove("error");
  setStatus(siemStatus, pending);
  try {
    setStatus(siemStatus, done(await run()));
  } catch (error) {
    siemStatus.classList.add("error");
    setStatus(siemStatus, error.message);
  } finally {
    siemBusy(false);
  }
}

siemToggle.addEventListener("change", () => {
  const wanted = siemToggle.checked;
  siemToggle.disabled = true;
  siemAction(wanted ? "Turning SIEM forwarding on…" : "Turning SIEM forwarding off…", async () => {
    const view = await api("/api/settings/siem/enabled", { enabled: wanted }, "PUT");
    renderSiem(view);
    if (wanted && !view.configured) siemHost.focus();
    return view;
  }, (view) => (wanted
    ? (view.configured ? "SIEM forwarding is on." : "SIEM forwarding is on. Configure the receiver and save.")
    : "SIEM forwarding is off. The configuration is kept.")).finally(() => {
    // Whatever happened, the switch shows what the server says.
    siemToggle.disabled = !(siemView?.editable);
    siemToggle.checked = siemView ? Boolean(siemView.enabled) : !wanted;
  });
});

siemTransport.addEventListener("change", () => {
  const previous = Object.values(SIEM_DEFAULT_PORTS).map(String);
  if (!siemPort.value || previous.includes(siemPort.value)) siemPort.value = String(SIEM_DEFAULT_PORTS[siemTransport.value]);
  syncSiemFieldVisibility();
});
siemTrust.addEventListener("change", syncSiemFieldVisibility);

siemCaChoose.addEventListener("click", () => siemCaFile.click());
siemCaFile.addEventListener("change", async () => {
  const file = siemCaFile.files?.[0];
  siemCaFile.value = "";
  if (!file) return;
  siemStatus.classList.add("error");
  if (file.size > SIEM_CA_MAX_BYTES) {
    setStatus(siemStatus, "That file is larger than 64 KB. Upload the CA certificate only.");
    return;
  }
  const pem = await file.text();
  if (/PRIVATE KEY/i.test(pem)) {
    // Not kept, not sent: a private key is never needed here.
    setStatus(siemStatus, "That file contains a private key. Upload the CA's certificate only.");
    return;
  }
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    setStatus(siemStatus, "Upload a PEM certificate (-----BEGIN CERTIFICATE-----).");
    return;
  }
  siemStatus.classList.remove("error");
  siemPendingCa = { pem, name: file.name };
  siemRemoveCa = false;
  syncSiemFieldVisibility();
  setStatus(siemStatus, `${file.name} is ready. Save to use it, or test the connection with it first.`);
});
siemCaRemove.addEventListener("click", () => {
  siemPendingCa = null;
  siemRemoveCa = Boolean(siemView?.config?.ca);
  syncSiemFieldVisibility();
});

siemForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const body = siemRequestBody(siemFields(), siemPendingCa, siemRemoveCa);
  siemAction("Saving…", async () => renderSiem(await api("/api/settings/siem", body, "PUT")),
    () => "Saved. Test the connection to confirm the receiver answers.");
});

siemTestBtn.addEventListener("click", () => {
  const body = siemRequestBody(siemFields(), siemPendingCa, siemRemoveCa);
  siemAction("Testing the connection…", async () => {
    const data = await api("/api/settings/siem/test", body, "POST");
    renderSiem(data, { fillForm: false });
    if (!data.test.ok) throw new Error(data.test.message);
    return data.test.message;
  }, (message) => message);
});

siemRetryBtn.addEventListener("click", () => {
  siemAction("Sending the queued events…", async () => {
    const data = await api("/api/settings/siem/retry", null, "POST");
    renderSiem(data, { fillForm: false });
    if (data.retry.failed) throw new Error(`${data.retry.sent} sent; ${data.retry.failed} still waiting. ${data.status?.last_error || ""}`.trim());
    return data.retry;
  }, (retry) => (retry.sent ? `Sent ${retry.sent} queued event${retry.sent === 1 ? "" : "s"}.` : "Nothing was due."));
});

// The state changes on its own - a receiver goes down, a queue drains - so while the
// Features section is on screen the status is re-read every 15 seconds. The form is
// never touched by it.
window.setInterval(() => {
  if (document.visibilityState !== "visible" || !siemView?.editable) return;
  if (!document.querySelector('.settings-section[data-panel="features"]')?.classList.contains("active")) return;
  api("/api/settings/siem").then((view) => renderSiem(view, { fillForm: false })).catch(() => {});
}, 15000);

siemRemoveBtn.addEventListener("click", () => {
  const receiver = siemView?.config?.host ? `${siemView.config.host}:${siemView.config.port}` : "the receiver";
  if (!window.confirm(`Remove the SIEM configuration for ${receiver}? Forwarding stops and its certificate is deleted. Events already queued stay queued.`)) return;
  siemAction("Removing the configuration…", async () => renderSiem(await api("/api/settings/siem", null, "DELETE")),
    () => "Configuration removed. Forwarding is off.");
});

/* ── Two-step sign-in (C2) ────────────────────────────────────── */
// The key is on screen only while it is being set up, and recovery codes only until
// "I saved them": both live in the DOM for that moment and nowhere else.
const mfaStateLabel = document.querySelector("#mfa-state");
const mfaCodesLeft = document.querySelector("#mfa-codes-left");
const mfaSessionLabel = document.querySelector("#mfa-session");
const mfaSetupBtn = document.querySelector("#mfa-setup-btn");
const mfaNewCodesBtn = document.querySelector("#mfa-new-codes-btn");
const mfaDisableBtn = document.querySelector("#mfa-disable-btn");
const mfaStepupForm = document.querySelector("#mfa-stepup-form");
const mfaStepupCode = document.querySelector("#mfa-stepup-code");
const mfaStepupLabel = document.querySelector("#mfa-stepup-label");
const mfaStepupRecovery = document.querySelector("#mfa-stepup-recovery");
const mfaSetupPanel = document.querySelector("#mfa-setup-panel");
const mfaSetupSecret = document.querySelector("#mfa-setup-secret");
const mfaSetupForm = document.querySelector("#mfa-setup-form");
const mfaSetupCode = document.querySelector("#mfa-setup-code");
const mfaCodesPanel = document.querySelector("#mfa-codes-panel");
const mfaCodesList = document.querySelector("#mfa-codes-list");
const mfaStatusLine = document.querySelector("#mfa-status");

let mfaView = null;
let mfaStepupWithRecovery = false;
// What to do once the session has proved the factor (the action that asked for it).
let mfaAfterStepup = null;

function mfaSay(message, isError = false) {
  mfaStatusLine.classList.toggle("error", Boolean(isError));
  setStatus(mfaStatusLine, message);
}

function renderMfa(view) {
  mfaView = view;
  const enabled = Boolean(view.enabled);
  mfaStateLabel.textContent = enabled
    ? "On"
    : (view.required_at_sign_in ? "Off - your role requires it at the next sign-in" : "Off");
  mfaCodesLeft.textContent = enabled ? String(view.recovery_codes_left ?? 0) : "-";
  mfaSessionLabel.textContent = view.session_verified ? "Confirmed with a code" : (enabled ? "Not confirmed" : "-");
  mfaSetupBtn.textContent = enabled ? "Replace authenticator" : "Set up authenticator";
  mfaNewCodesBtn.hidden = !enabled;
  // A role that requires the factor cannot turn it off; an administrator resets it.
  mfaDisableBtn.hidden = !enabled || Boolean(view.required_at_sign_in);
}

async function loadMfa() {
  try {
    renderMfa(await api("/api/profile/mfa"));
  } catch (error) {
    mfaStateLabel.textContent = "Unavailable";
    mfaSay(`Could not load two-step sign-in: ${error.message}`, true);
  }
}

// Replacing the factor, new codes and turning it off all need this session to have
// proved the current factor. The server says so; the page asks for a code and carries on.
async function withStepup(run) {
  try {
    return await run();
  } catch (error) {
    if (error.code !== "mfa_required") throw error;
    mfaAfterStepup = run;
    mfaStepupForm.hidden = false;
    mfaStepupCode.value = "";
    mfaStepupCode.focus();
    mfaSay("Enter a code from your authenticator to continue.");
    return null;
  }
}

mfaStepupRecovery.addEventListener("click", () => {
  mfaStepupWithRecovery = !mfaStepupWithRecovery;
  mfaStepupLabel.textContent = mfaStepupWithRecovery ? "Recovery code" : "Authenticator code";
  mfaStepupCode.inputMode = mfaStepupWithRecovery ? "text" : "numeric";
  mfaStepupCode.placeholder = mfaStepupWithRecovery ? "XXXX-XXXX-XXXX-XXXX" : "123 456";
  mfaStepupRecovery.textContent = mfaStepupWithRecovery ? "Use the authenticator app" : "Use a recovery code";
  mfaStepupCode.value = "";
  mfaStepupCode.focus();
});

mfaStepupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const value = String(mfaStepupCode.value || "");
  const body = mfaStepupWithRecovery ? { recovery_code: value.trim() } : { code: value.replace(/\s+/g, "") };
  mfaSay("Checking...");
  try {
    await api("/api/profile/mfa/verify", body, "POST");
  } catch (error) {
    mfaStepupCode.value = "";
    mfaSay(error.message, true);
    return;
  }
  mfaStepupForm.hidden = true;
  mfaStepupCode.value = "";
  const next = mfaAfterStepup;
  mfaAfterStepup = null;
  mfaSay("Confirmed for this session.");
  await loadMfa();
  if (next) {
    try {
      await next();
    } catch (error) {
      mfaSay(error.message, true);
    }
  }
});

async function startMfaSetup() {
  const data = await api("/api/profile/mfa/enroll/start", {}, "POST");
  mfaSetupSecret.textContent = String(data.secret || "").replace(/(.{4})/g, "$1 ").trim();
  mfaSetupPanel.hidden = false;
  mfaCodesPanel.hidden = true;
  mfaSetupCode.value = "";
  mfaSetupCode.focus();
  mfaSay("Add the key to your authenticator app, then enter the code it shows.");
  return data;
}

function closeMfaSetup() {
  mfaSetupSecret.textContent = "";
  mfaSetupPanel.hidden = true;
}

function showRecoveryCodes(codes) {
  mfaCodesList.replaceChildren(...codes.map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  mfaCodesPanel.hidden = false;
}

mfaSetupBtn.addEventListener("click", () => {
  withStepup(startMfaSetup).catch((error) => mfaSay(error.message, true));
});

document.querySelector("#mfa-setup-copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(mfaSetupSecret.textContent.replace(/\s+/g, ""));
    mfaSay("Key copied.");
  } catch {
    mfaSay("Copy is not available here; type the key into the app.");
  }
});

document.querySelector("#mfa-setup-cancel").addEventListener("click", () => {
  closeMfaSetup();
  mfaSay("Setup cancelled. Nothing changed.");
});

mfaSetupForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  mfaSay("Checking...");
  try {
    const data = await api("/api/profile/mfa/enroll/confirm", { code: String(mfaSetupCode.value || "").replace(/\s+/g, "") }, "POST");
    closeMfaSetup();
    showRecoveryCodes(Array.isArray(data.recovery_codes) ? data.recovery_codes : []);
    mfaSay("Two-step sign-in is on. Save your recovery codes.");
    await loadMfa();
  } catch (error) {
    mfaSetupCode.value = "";
    mfaSay(error.message, true);
  }
});

mfaNewCodesBtn.addEventListener("click", () => {
  if (!window.confirm("Make new recovery codes? The codes you have now stop working.")) return;
  withStepup(async () => {
    const data = await api("/api/profile/mfa/recovery-codes", {}, "POST");
    showRecoveryCodes(Array.isArray(data.recovery_codes) ? data.recovery_codes : []);
    mfaSay("New recovery codes made. The old ones no longer work.");
    await loadMfa();
  }).catch((error) => mfaSay(error.message, true));
});

mfaDisableBtn.addEventListener("click", () => {
  if (!window.confirm("Turn off two-step sign-in? Sign-in will ask for your password only.")) return;
  withStepup(async () => {
    await api("/api/profile/mfa/disable", {}, "POST");
    mfaCodesPanel.hidden = true;
    mfaCodesList.replaceChildren();
    mfaSay("Two-step sign-in is off.");
    await loadMfa();
  }).catch((error) => mfaSay(error.message, true));
});

document.querySelector("#mfa-codes-copy").addEventListener("click", async () => {
  const text = [...mfaCodesList.querySelectorAll("li")].map((item) => item.textContent).join("\n");
  try {
    await navigator.clipboard.writeText(text);
    mfaSay("Codes copied.");
  } catch {
    mfaSay("Copy is not available here; select the codes and copy them.");
  }
});

document.querySelector("#mfa-codes-done").addEventListener("click", () => {
  mfaCodesList.replaceChildren();
  mfaCodesPanel.hidden = true;
  mfaSay(" ");
});

/* ── Directory sign-in (C2) ───────────────────────────────────── */
// The service account's password is never sent back. The field starts empty every time:
// left empty, the saved one is kept; typed, it replaces it; "Remove password" deletes it.
// Nothing here ever sends a mask as a password.
const directoryCard = document.querySelector("#directory-card");
const directoryToggle = document.querySelector("#directory-toggle");
const directoryState = document.querySelector("#directory-state");
const directoryStateText = document.querySelector("#directory-state-text");
const directoryPanel = document.querySelector("#directory-panel");
const directoryForm = document.querySelector("#directory-form");
const directoryFields = {
  host: document.querySelector("#directory-host"),
  security: document.querySelector("#directory-security"),
  port: document.querySelector("#directory-port"),
  trust: document.querySelector("#directory-trust"),
  base_dn: document.querySelector("#directory-base-dn"),
  bind_dn: document.querySelector("#directory-bind-dn"),
  user_attribute: document.querySelector("#directory-user-attribute"),
  group_search: document.querySelector("#directory-group-search"),
  group_base_dn: document.querySelector("#directory-group-base-dn"),
};
const directoryPassword = document.querySelector("#directory-bind-password");
const directorySecretNote = document.querySelector("#directory-secret-note");
const directoryCaField = document.querySelector("#directory-ca-field");
const directoryCaSummary = document.querySelector("#directory-ca-summary");
const directoryCaFile = document.querySelector("#directory-ca-file");
const directoryGroupBaseField = document.querySelector("#directory-group-base-field");
const directoryMappings = document.querySelector("#directory-mappings");
const directoryTestLogin = document.querySelector("#directory-test-login");
const directoryRemoveRow = document.querySelector("#directory-remove-row");
const directoryStatus = document.querySelector("#directory-status");
const DIRECTORY_PORTS = { ldaps: 636, starttls: 389 };

let directoryView = null;
let directoryRoles = [];
let directoryPendingCa = null;
let directoryRemovePassword = false;

function directorySay(message, isError = false) {
  directoryStatus.classList.toggle("error", Boolean(isError));
  setStatus(directoryStatus, message);
}

function directoryStateFor(view) {
  if (!view.configured) return ["not_configured", view.enabled ? "On - finish the settings and save." : "Off - not configured."];
  if (!view.enabled) return ["disabled", "Off - the settings are kept."];
  // On is not connected: only a test that signed the service account in says that.
  return ["enabled", `On - ${view.config.security === "starttls" ? "StartTLS" : "LDAPS"} to ${view.config.host}. Test the connection to confirm it answers.`];
}

function mappingRow(mapping = {}) {
  const item = document.createElement("li");
  item.className = "directory-mapping";
  const group = document.createElement("input");
  group.className = "directory-map-group";
  group.placeholder = "CN=Sentro Admins,OU=Groups,DC=corp,DC=local";
  group.setAttribute("aria-label", "Directory group");
  group.spellcheck = false;
  group.value = mapping.group_dn || "";
  const role = document.createElement("select");
  role.className = "directory-map-role";
  role.setAttribute("aria-label", "Role for this group");
  for (const entry of directoryRoles) {
    const option = document.createElement("option");
    option.value = entry.name;
    option.textContent = entry.label || entry.name;
    role.append(option);
  }
  role.value = mapping.role || "viewer";
  const remove = document.createElement("button");
  remove.type = "button";
  remove.className = "secondary-btn";
  remove.textContent = "Remove";
  remove.addEventListener("click", () => item.remove());
  item.append(group, role, remove);
  return item;
}

function syncDirectoryFields() {
  directoryCaField.hidden = directoryFields.trust.value !== "custom";
  directoryGroupBaseField.hidden = directoryFields.group_search.value !== "ad_nested";
  const config = directoryView?.config || {};
  directoryCaSummary.textContent = directoryPendingCa
    ? `${directoryPendingCa.name} (not saved yet)`
    : (config.ca_name ? `${config.ca_name} · ${config.ca_fingerprint || ""}`.trim() : "No certificate uploaded");
  const saved = Boolean(directoryView?.bind_password_configured);
  directoryPassword.placeholder = saved && !directoryRemovePassword ? "Saved - leave empty to keep it" : "Enter the password";
  directorySecretNote.textContent = directoryRemovePassword
    ? "Will be removed when you save."
    : (saved ? "Saved. Type a new one to replace it." : "Not set.");
  if (saved && !directoryRemovePassword) {
    const remove = document.createElement("button");
    remove.type = "button";
    remove.className = "link-btn";
    remove.textContent = "Remove password";
    remove.addEventListener("click", () => {
      directoryRemovePassword = true;
      directoryPassword.value = "";
      syncDirectoryFields();
    });
    directorySecretNote.append(" ", remove);
  }
}

function renderDirectory(view, { fillForm = true } = {}) {
  directoryView = view;
  const config = view.config || {};
  directoryToggle.checked = Boolean(view.enabled);
  directoryToggle.disabled = !view.editable;
  const [state, line] = directoryStateFor(view);
  directoryState.dataset.state = state;
  directoryStateText.textContent = line;
  const open = Boolean(view.enabled || !view.configured && directoryToggle.checked);
  directoryPanel.hidden = !open;
  directoryToggle.setAttribute("aria-expanded", String(open));
  if (fillForm) {
    directoryFields.host.value = config.host || "";
    directoryFields.security.value = config.security || "ldaps";
    directoryFields.port.value = config.host ? String(config.port || "") : "";
    directoryFields.trust.value = config.trust || "system";
    directoryFields.base_dn.value = config.base_dn || "";
    directoryFields.bind_dn.value = config.bind_dn || "";
    directoryFields.user_attribute.value = config.user_attribute || "sAMAccountName";
    directoryFields.group_search.value = config.group_search || "memberof";
    directoryFields.group_base_dn.value = config.group_base_dn || "";
    directoryPassword.value = "";
    directoryPendingCa = null;
    directoryRemovePassword = false;
    const mappings = Array.isArray(config.mappings) && config.mappings.length ? config.mappings : [{}];
    directoryMappings.replaceChildren(...mappings.map(mappingRow));
  }
  directoryFields.port.placeholder = String(DIRECTORY_PORTS[directoryFields.security.value] || 636);
  document.querySelector("#directory-fact-host").textContent = config.host
    ? `${config.host}:${config.port} (${config.security === "starttls" ? "StartTLS" : "LDAPS"})` : "Not configured";
  document.querySelector("#directory-fact-ca").textContent = config.trust === "custom"
    ? (config.ca_name ? `${config.ca_name} · ${config.ca_fingerprint || ""}` : "Missing")
    : (config.host ? "System trust store" : "-");
  document.querySelector("#directory-fact-changed").textContent = view.updated_at
    ? `${new Date(view.updated_at).toLocaleString([], { dateStyle: "medium", timeStyle: "short" })}${view.updated_by ? ` by ${view.updated_by}` : ""}`
    : "-";
  directoryRemoveRow.hidden = !(view.editable && view.configured);
  syncDirectoryFields();
}

function directoryRequest() {
  const body = {
    host: directoryFields.host.value.trim(),
    security: directoryFields.security.value,
    port: Number(directoryFields.port.value || DIRECTORY_PORTS[directoryFields.security.value]),
    trust: directoryFields.trust.value,
    base_dn: directoryFields.base_dn.value.trim(),
    bind_dn: directoryFields.bind_dn.value.trim(),
    user_attribute: directoryFields.user_attribute.value,
    group_search: directoryFields.group_search.value,
    group_base_dn: directoryFields.group_base_dn.value.trim(),
    mappings: [...directoryMappings.querySelectorAll(".directory-mapping")]
      .map((row) => ({ group_dn: row.querySelector(".directory-map-group").value.trim(), role: row.querySelector(".directory-map-role").value }))
      .filter((mapping) => mapping.group_dn),
    enabled: directoryToggle.checked,
  };
  if (directoryPendingCa) {
    body.ca_pem = directoryPendingCa.pem;
    body.ca_name = directoryPendingCa.name;
  }
  // Only what was typed: an empty field keeps the saved password.
  if (directoryPassword.value) body.bind_password = directoryPassword.value;
  else if (directoryRemovePassword) body.remove_bind_password = true;
  return body;
}

async function loadDirectory() {
  let permissions = [];
  try {
    permissions = JSON.parse(sessionGet("dspm-permissions") || "[]");
  } catch {
    permissions = [];
  }
  if (!permissions.includes("tenant.admin")) return;
  try {
    const [view, roles] = await Promise.all([api("/api/settings/directory"), api("/api/roles")]);
    directoryRoles = (roles.roles || []).map((role) => ({ name: role.name, label: role.label || role.name }));
    directoryCard.hidden = false;
    renderDirectory(view);
  } catch (error) {
    if (error.status === 403 && error.code !== "mfa_required") return;
    directoryCard.hidden = false;
    directoryState.dataset.state = "unavailable";
    directoryStateText.textContent = "Status unavailable.";
    directorySay(error.code === "mfa_required"
      ? "Confirm a code from your authenticator (Two-step sign-in, above) to manage directory sign-in."
      : `Could not load the directory settings: ${error.message}`, true);
  }
}

async function directoryAction(pending, run, done) {
  const buttons = directoryCard.querySelectorAll("button");
  buttons.forEach((button) => { button.disabled = true; });
  directorySay(pending);
  try {
    directorySay(done(await run()));
  } catch (error) {
    directorySay(error.message, true);
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

directoryToggle.addEventListener("change", () => {
  const wanted = directoryToggle.checked;
  if (!directoryView?.configured) {
    // Nothing to turn on yet: open the form, and Save turns it on.
    directoryPanel.hidden = !wanted;
    directoryToggle.setAttribute("aria-expanded", String(wanted));
    directoryState.dataset.state = "not_configured";
    directoryStateText.textContent = wanted ? "On once saved - fill in the settings." : "Off - not configured.";
    if (wanted) directoryFields.host.focus();
    return;
  }
  directoryToggle.disabled = true;
  directoryAction(wanted ? "Turning directory sign-in on..." : "Turning directory sign-in off...",
    async () => renderDirectory(await api("/api/settings/directory", { enabled: wanted }, "PUT"), { fillForm: false }),
    () => (wanted ? "Directory sign-in is on." : "Directory sign-in is off. The settings are kept.")).finally(() => {
    directoryToggle.disabled = !(directoryView?.editable);
    directoryToggle.checked = Boolean(directoryView?.enabled);
  });
});

directoryFields.security.addEventListener("change", () => {
  const known = Object.values(DIRECTORY_PORTS).map(String);
  if (!directoryFields.port.value || known.includes(directoryFields.port.value)) {
    directoryFields.port.value = String(DIRECTORY_PORTS[directoryFields.security.value]);
  }
  directoryFields.port.placeholder = String(DIRECTORY_PORTS[directoryFields.security.value]);
});
directoryFields.trust.addEventListener("change", syncDirectoryFields);
directoryFields.group_search.addEventListener("change", syncDirectoryFields);
directoryPassword.addEventListener("input", () => {
  if (directoryPassword.value) directoryRemovePassword = false;
});

document.querySelector("#directory-add-mapping").addEventListener("click", () => {
  const row = mappingRow();
  directoryMappings.append(row);
  row.querySelector("input").focus();
});

document.querySelector("#directory-ca-choose").addEventListener("click", () => directoryCaFile.click());
directoryCaFile.addEventListener("change", async () => {
  const file = directoryCaFile.files?.[0];
  directoryCaFile.value = "";
  if (!file) return;
  if (file.size > 65536) {
    directorySay("That file is larger than 64 KB. Upload the CA certificate only.", true);
    return;
  }
  const pem = await file.text();
  if (/PRIVATE KEY/i.test(pem)) {
    directorySay("That file contains a private key. Upload the CA's certificate only.", true);
    return;
  }
  if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
    directorySay("Upload a PEM certificate (-----BEGIN CERTIFICATE-----).", true);
    return;
  }
  directoryPendingCa = { pem, name: file.name };
  syncDirectoryFields();
  directorySay(`${file.name} is ready. Save to use it.`);
});

directoryForm.addEventListener("submit", (event) => {
  event.preventDefault();
  const body = directoryRequest();
  directoryAction("Saving...", async () => {
    const view = await api("/api/settings/directory", body, "PUT");
    renderDirectory(view);
    return view;
  }, (view) => (view.enabled ? "Saved. Test the connection to confirm the service account signs in." : "Saved. Directory sign-in is off."));
});

document.querySelector("#directory-test-btn").addEventListener("click", () => {
  const login = directoryTestLogin.value.trim();
  directoryAction("Testing the connection...", async () => {
    const report = await api("/api/settings/directory/test", { login }, "POST");
    directoryState.dataset.state = report.ok ? "connected" : "not_connected";
    directoryStateText.textContent = report.ok
      ? `Connected - the service account signed in to ${directoryView?.config?.host || "the directory"} just now.`
      : `Not connected - ${report.message}`;
    if (!report.ok) throw new Error(report.message);
    return report.message;
  }, (message) => message);
});

document.querySelector("#directory-remove-btn").addEventListener("click", () => {
  if (!window.confirm("Remove the directory settings and the service account's password? Directory accounts can no longer sign in.")) return;
  directoryAction("Removing...", async () => renderDirectory(await api("/api/settings/directory", null, "DELETE")),
    () => "Directory settings removed.");
});

/* ── Saved scan credentials (C12) ─────────────────────────────── */
// The list shows accounts and dates; a password is only ever typed, to replace one. Built
// with DOM nodes, not HTML strings: labels come from the directory and from people.
const credentialsCard = document.querySelector("#credentials-card");
const credentialsBody = document.querySelector("#credentials-body");
const credentialsStatus = document.querySelector("#credentials-status");
const credentialReplaceForm = document.querySelector("#credential-replace-form");
const credentialReplaceLead = document.querySelector("#credential-replace-lead");
const credentialReplaceUser = document.querySelector("#credential-replace-user");
const credentialReplaceDomain = document.querySelector("#credential-replace-domain");
const credentialReplacePassword = document.querySelector("#credential-replace-password");
const PRIVILEGE_WORDS = { excessive: "Too much", warning: "Check", ok: "Read-only", unchecked: "Not checked" };
let credentialReplacing = "";

function credentialsSay(message, isError = false) {
  credentialsStatus.classList.toggle("error", Boolean(isError));
  setStatus(credentialsStatus, message);
}

function shortDate(value) {
  if (!value) return "Never";
  try {
    return new Date(value).toLocaleDateString([], { dateStyle: "medium" });
  } catch {
    return String(value).slice(0, 10);
  }
}

function cell(text, className = "") {
  const td = document.createElement("td");
  td.textContent = text;
  if (className) td.className = className;
  return td;
}

function credentialRow(item) {
  const row = document.createElement("tr");
  const account = cell(item.label || "(unnamed)");
  if (item.kind === "directory") {
    const note = document.createElement("div");
    note.className = "settings-hint credentials-note";
    note.textContent = "Directory sign-in service account";
    account.append(note);
  }
  row.append(account, cell(shortDate(item.created_at)), cell(shortDate(item.last_used_at)));
  const changed = cell(item.rotated_at ? shortDate(item.rotated_at) : "Not since saved");
  if (item.rotation_due) {
    const due = document.createElement("span");
    due.className = "credential-badge credential-badge-due";
    due.textContent = `Change due (${item.age_days} days)`;
    changed.append(document.createElement("br"), due);
  }
  row.append(changed);
  const privilege = document.createElement("td");
  const level = (item.privilege && item.privilege.level) || "unchecked";
  const badge = document.createElement("span");
  badge.className = `credential-badge credential-badge-${level}`;
  badge.textContent = PRIVILEGE_WORDS[level] || level;
  privilege.append(badge);
  for (const finding of (item.privilege && item.privilege.findings) || []) {
    const line = document.createElement("div");
    line.className = "settings-hint credentials-note";
    line.textContent = finding;
    privilege.append(line);
  }
  row.append(privilege);
  const actions = document.createElement("td");
  actions.className = "credentials-actions";
  if (item.kind === "scan") {
    for (const [label, action] of [["Replace password", "replace"], ["Check privilege", "check"], ["Delete", "delete"]]) {
      const button = document.createElement("button");
      button.type = "button";
      button.className = action === "delete" ? "settings-danger-btn" : "secondary-btn";
      button.textContent = label;
      button.dataset.credentialAction = action;
      button.dataset.credentialRef = item.credential_ref;
      button.dataset.credentialLabel = item.label || "";
      actions.append(button);
    }
  }
  row.append(actions);
  return row;
}

async function loadCredentials() {
  let permissions = [];
  try {
    permissions = JSON.parse(sessionGet("dspm-permissions") || "[]");
  } catch {
    permissions = [];
  }
  if (!permissions.includes("credential.manage")) return;
  credentialsCard.hidden = false;
  try {
    const data = await api("/api/credentials");
    document.querySelector("#credentials-rotation-days").textContent = String(data.rotation_days || 90);
    const items = data.credentials || [];
    if (!items.length) {
      const empty = document.createElement("tr");
      empty.append(cell("No saved credentials. Scans that save their password add one here.", "settings-hint"));
      empty.firstChild.colSpan = 6;
      credentialsBody.replaceChildren(empty);
      return;
    }
    credentialsBody.replaceChildren(...items.map(credentialRow));
  } catch (error) {
    credentialsSay(error.code === "mfa_required"
      ? "Confirm a code from your authenticator (Two-step sign-in, above) to see saved credentials."
      : `Could not load saved credentials: ${error.message}`, true);
  }
}

credentialsBody.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-credential-action]");
  if (!button) return;
  const ref = button.dataset.credentialRef;
  const label = button.dataset.credentialLabel;
  if (button.dataset.credentialAction === "replace") {
    credentialReplacing = ref;
    const [domain, user] = label.includes("\\") ? label.split("\\", 2) : ["", label];
    credentialReplaceUser.value = user;
    credentialReplaceDomain.value = domain;
    credentialReplacePassword.value = "";
    credentialReplaceLead.textContent = `New password for ${label}. The same reference is kept, so scans and schedules that use it carry on.`;
    credentialReplaceForm.hidden = false;
    credentialReplacePassword.focus();
    return;
  }
  if (button.dataset.credentialAction === "delete") {
    if (!window.confirm(`Delete the saved credential for ${label}? Scans and schedules that use it will fail until they get another.`)) return;
    try {
      await api(`/api/credentials/${encodeURIComponent(ref)}`, null, "DELETE");
      credentialsSay(`Deleted the credential for ${label}.`);
      await loadCredentials();
    } catch (error) {
      credentialsSay(error.message, true);
    }
    return;
  }
  credentialsSay(`Checking ${label}...`);
  try {
    const result = await api(`/api/credentials/${encodeURIComponent(ref)}/preflight`, {}, "POST");
    credentialsSay(`${label}: ${PRIVILEGE_WORDS[result.privilege.level] || result.privilege.level}.`);
    await loadCredentials();
  } catch (error) {
    credentialsSay(error.message, true);
  }
});

document.querySelector("#credential-replace-cancel").addEventListener("click", () => {
  credentialReplacePassword.value = "";
  credentialReplaceForm.hidden = true;
  credentialReplacing = "";
});

credentialReplaceForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  const body = {
    username: credentialReplaceUser.value.trim(),
    domain: credentialReplaceDomain.value.trim() || "WORKGROUP",
    password: credentialReplacePassword.value,
  };
  credentialReplacePassword.value = "";
  if (!body.username || !body.password) {
    credentialsSay("Enter the user name and the new password.", true);
    return;
  }
  try {
    const result = await api(`/api/credentials/${encodeURIComponent(credentialReplacing)}`, body, "PUT");
    credentialReplaceForm.hidden = true;
    credentialsSay(`Password replaced. Privilege: ${PRIVILEGE_WORDS[result.privilege.level] || result.privilege.level}.`);
    credentialReplacing = "";
    await loadCredentials();
  } catch (error) {
    credentialsSay(error.message, true);
  }
});

/* ── Forms ────────────────────────────────────────────────────── */
profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (protectedAccount) return;
  setStatus(profileStatus, "Saving…");
  try {
    const data = await api("/api/profile", { full_name: fullNameInput.value.trim() }, "PUT");
    renderProfile(data.user || {}, false, "");
    setStatus(profileStatus, "Name saved.");
  } catch (error) {
    setStatus(profileStatus, `Save failed: ${error.message}`);
  }
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (protectedAccount) return;
  const data = new FormData(passwordForm);
  const currentPassword = String(data.get("current_password") || "");
  const newPassword = String(data.get("new_password") || "");
  const confirmPassword = String(data.get("confirm_password") || "");
  if (newPassword.length < 12) {
    setStatus(passwordStatus, "Password must be at least 12 characters.");
    return;
  }
  if (newPassword !== confirmPassword) {
    setStatus(passwordStatus, "New passwords do not match.");
    return;
  }
  setStatus(passwordStatus, "Changing password…");
  try {
    const result = await api("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword }, "POST");
    afterPasswordChange(result);
  } catch (error) {
    setStatus(passwordStatus, `Password change failed: ${error.message}`);
  }
});

// C1: a password change ends every session, this one included, and the server says so
// with `reauthenticate`. Leaving the page on a session that no longer works would make
// the next click fail for no visible reason - say what happened and go to sign-in.
function afterPasswordChange(result) {
  passwordForm.reset();
  if (result && result.reauthenticate) {
    setStatus(passwordStatus, "Password changed. Sign in again with the new password.");
    clearLocalSession();
    window.setTimeout(() => window.location.replace("/login"), 1500);
    return;
  }
  setStatus(passwordStatus, "Password changed.");
}

/* ── Avatar events ────────────────────────────────────────────── */
chooseAvatarBtn.addEventListener("click", () => avatarFileInput.click());

avatarFileInput.addEventListener("change", () => {
  const file = avatarFileInput.files?.[0];
  avatarFileInput.value = "";
  loadAvatarFile(file);
});

removeAvatarBtn.addEventListener("click", async () => {
  updateAvatarHelp("Removing photo…");
  try {
    await saveAvatar("");
    updateAvatarHelp("Profile photo removed.");
  } catch (error) {
    updateAvatarHelp(`Remove failed: ${error.message}`, true);
  }
});

avatarZoom.addEventListener("input", () => {
  if (!cropImage) return;
  const canvasSize = avatarCropCanvas.width;
  const previousScale = cropState.scale;
  const nextScale = Number(avatarZoom.value) || 1;
  const centerX = canvasSize / 2;
  const centerY = canvasSize / 2;
  cropState.offsetX = centerX - ((centerX - cropState.offsetX) / previousScale) * nextScale;
  cropState.offsetY = centerY - ((centerY - cropState.offsetY) / previousScale) * nextScale;
  cropState.scale = nextScale;
  drawCropCanvas();
});

avatarCropCanvas.addEventListener("pointerdown", (event) => {
  if (!cropImage) return;
  avatarCropCanvas.setPointerCapture(event.pointerId);
  const point = canvasPoint(event);
  cropState.dragging = true;
  cropState.startX = point.x - cropState.offsetX;
  cropState.startY = point.y - cropState.offsetY;
});

avatarCropCanvas.addEventListener("pointermove", (event) => {
  if (!cropImage || !cropState.dragging) return;
  const point = canvasPoint(event);
  cropState.offsetX = point.x - cropState.startX;
  cropState.offsetY = point.y - cropState.startY;
  drawCropCanvas();
});

avatarCropCanvas.addEventListener("pointerup", () => {
  cropState.dragging = false;
});

avatarCropCanvas.addEventListener("pointercancel", () => {
  cropState.dragging = false;
});

avatarApplyBtn.addEventListener("click", async () => {
  const avatarData = exportAvatarImage();
  if (!avatarData) {
    updateAvatarHelp("Choose an image before applying.", true);
    return;
  }
  updateAvatarHelp("Saving photo…");
  try {
    await saveAvatar(avatarData);
    updateAvatarHelp("Profile photo saved to your account.");
    closeAvatarCrop();
  } catch (error) {
    updateAvatarHelp(`Save failed: ${error.message}`, true);
  }
});

avatarCropClose.addEventListener("click", closeAvatarCrop);
avatarCropCancel.addEventListener("click", closeAvatarCrop);
avatarCropModal.addEventListener("click", (event) => {
  if (event.target === avatarCropModal) closeAvatarCrop();
});

/* ── Session ──────────────────────────────────────────────────── */
async function logout() {
  try {
    if (sessionGet("dspm-access-token")) {
      // C1: the same as the console - a lapsed access token is renewed once, so that
      // signing out still ends the refresh chain rather than leaving it in the browser.
      const send = () => fetch("/api/logout", { method: "POST", headers: authHeaders() });
      const response = await send();
      if (response.status === 401 && await refreshAccessToken()) {
        await send();
      }
    }
  } catch {
    /* local session clearing must still happen */
  }
  clearLocalSession();
  window.location.replace("/login");
}

function clearLocalSession() {
  sessionSet("dspm-access-token", "");
  sessionSet("dspm-tenant-id", "");
  sessionSet("dspm-role", "");
  sessionSet("dspm-user", "");
}

logoutBtn.addEventListener("click", logout);

/* ── Boot ─────────────────────────────────────────────────────── */
applyTheme(storageGet("dspm-theme") || "light");
activateSection(location.hash.slice(1) || "profile", false);
renderSessionExpiry();
loadProfile();
loadFeatures();
loadMfa();

/* ── Alerts & tickets (D3) ────────────────────────────────────── */
// A workspace's webhook, mail relay, Jira and ServiceNow. The server owns delivery - the
// queue, retries, signatures and TLS; this is where it is configured and watched. A
// secret field is always empty: typed, it replaces the saved secret; left empty, the
// saved one is kept; "Remove saved ..." deletes it. The page never holds a saved secret
// and never sends a mask back. The webhook's signing secret is made by the server and
// shown once, when it is made.
const integrationsCard = document.querySelector("#integrations-card");
const INTEGRATION_SECRET_FIELD = { email: "password", jira: "token", servicenow: "password" };
const INTEGRATION_CA_MAX_BYTES = 64 * 1024;
const integrationDrafts = {};   // channel -> { view, pendingCa, removeCa, removeSecret }

function integrationBlock(channel) {
  return integrationsCard?.querySelector(`.integration[data-channel="${channel}"]`) || null;
}

function integrationPart(block, role) {
  return block.querySelector(`[data-role="${role}"]`);
}

function integrationDraft(channel) {
  if (!integrationDrafts[channel]) {
    integrationDrafts[channel] = { view: null, pendingCa: null, removeCa: false, removeSecret: false };
  }
  return integrationDrafts[channel];
}

// Enabled is never connected: only a delivery or a passed test of these settings is.
function integrationStateLine(view) {
  const queue = view.queue || {};
  const ticket = view.channel === "jira" || view.channel === "servicenow";
  switch (view.state) {
    case "disabled":
      return view.configured ? "Off - the settings are kept." : "Off.";
    case "not_configured":
      return "On - not configured yet. Nothing is sent.";
    case "not_connected":
      return "On - not connected yet. Test it, or wait for the next delivery.";
    case "connected":
      return `Connected - last ${ticket ? "ticket" : "delivery"} ${siemWhen(view.status?.last_delivery_at).toLowerCase()}.`;
    case "degraded": {
      const count = Number(queue.pending || 0);
      return `Delivery degraded - ${count} waiting, retrying.`;
    }
    default:
      return "Checking...";
  }
}

function integrationCaText(draft) {
  if (draft.pendingCa) return `${draft.pendingCa.name} - will be saved`;
  if (draft.removeCa) return "Will be removed when you save";
  const ca = draft.view?.config?.ca;
  return ca ? `${ca.name} · SHA-256 ${String(ca.fingerprint || "").slice(0, 23)}...` : "System trust store";
}

function integrationSay(block, message, isError = false) {
  const status = integrationPart(block, "status");
  status.classList.toggle("error", Boolean(isError));
  setStatus(status, message);
}

function renderIntegration(view, { fillForm = true } = {}) {
  const block = integrationBlock(view.channel);
  if (!block) return;
  const draft = integrationDraft(view.channel);
  draft.view = view;
  const config = view.config || {};
  const toggle = integrationPart(block, "toggle");
  toggle.disabled = false;
  toggle.checked = Boolean(view.enabled);
  const open = Boolean(view.enabled);
  integrationPart(block, "panel").hidden = !open;
  toggle.setAttribute("aria-expanded", String(open));
  const state = integrationPart(block, "state");
  state.dataset.state = view.state;
  integrationPart(block, "state-text").textContent = integrationStateLine(view);
  const form = integrationPart(block, "form");
  if (fillForm) {
    form.querySelectorAll("input[name], select[name]").forEach((field) => {
      if (field.hasAttribute("data-secret")) {
        field.value = "";
      } else if (field.name === "recipients") {
        field.value = (config.recipients || []).join(", ");
      } else if (field.tagName === "SELECT") {
        field.value = config[field.name] || field.options[field.name === "min_severity" ? 1 : 0].value;
      } else {
        field.value = config[field.name] === undefined || config[field.name] === null ? "" : String(config[field.name]);
      }
    });
    draft.pendingCa = null;
    draft.removeCa = false;
    draft.removeSecret = false;
  }
  const secretField = INTEGRATION_SECRET_FIELD[view.channel];
  if (secretField) {
    const saved = Boolean(config[`${secretField}_configured`]);
    const note = integrationPart(block, "secret-note");
    note.textContent = draft.removeSecret ? "Will be removed when you save." : (saved ? "Saved - leave empty to keep it." : "Not set.");
    block.querySelector('[data-action="remove-secret"]').hidden = !saved || draft.removeSecret;
  }
  if (view.channel === "webhook") {
    const rotate = block.querySelector('[data-action="rotate"]');
    rotate.hidden = !config.signing_secret_configured;
    integrationPart(block, "signing-note").textContent = config.signing_secret_configured
      ? "Set. It was shown once, when it was made; make a new one if the receiver lost it."
      : "Made when you save. Every delivery is signed with it (X-Sentro-Signature).";
  }
  integrationPart(block, "ca-summary").textContent = integrationCaText(draft);
  block.querySelector('[data-action="ca-remove"]').hidden = !(draft.pendingCa || (config.ca && !draft.removeCa));
  const queue = view.queue || {};
  const status = view.status || {};
  block.querySelector('[data-fact="delivery"]').textContent = siemWhen(status.last_delivery_at);
  block.querySelector('[data-fact="queue"]').textContent = queue.pending
    ? `${queue.pending} waiting${queue.failing ? `, ${queue.failing} failed at least once` : ""}`
    : "None";
  block.querySelector('[data-fact="ca"]').textContent = config.ca ? `${config.ca.name} · ${config.ca.fingerprint}` : "System trust store";
  block.querySelector('[data-fact="error-row"]').hidden = !(status.last_error && (view.state === "degraded" || view.state === "not_connected"));
  block.querySelector('[data-fact="error"]').textContent = status.last_error
    ? `${status.last_error} (${siemWhen(status.last_error_at).toLowerCase()})` : "";
  block.querySelector('[data-action="retry"]').hidden = !queue.pending;
  integrationPart(block, "remove-row").hidden = !view.configured;
}

// What a save sends: the form's fields, a secret only when one was typed, a certificate
// only when one was chosen here.
function integrationBody(channel) {
  const block = integrationBlock(channel);
  const draft = integrationDraft(channel);
  const body = {};
  integrationPart(block, "form").querySelectorAll("input[name], select[name]").forEach((field) => {
    const value = String(field.value || "").trim();
    if (field.hasAttribute("data-secret")) {
      if (field.value) body[field.name] = field.value;
    } else if (field.name === "recipients") {
      body.recipients = value.split(",").map((item) => item.trim()).filter(Boolean);
    } else if (["url", "base_url", "instance_url"].includes(field.name)) {
      // An address typed without its scheme is an https one: nothing else is called.
      body[field.name] = value && !/^[a-z][a-z0-9+.-]*:/i.test(value) ? `https:${"//"}${value}` : value;
    } else if (field.name === "port") {
      const port = Number(value);
      if (Number.isInteger(port) && port > 0) body.port = port;
    } else {
      body[field.name] = value;
    }
  });
  if (draft.removeSecret && !body[INTEGRATION_SECRET_FIELD[channel]]) body.remove_secret = true;
  if (draft.pendingCa?.pem) {
    body.ca_pem = draft.pendingCa.pem;
    body.ca_name = draft.pendingCa.name || "ca.pem";
  } else if (draft.removeCa) {
    body.remove_ca = true;
  }
  return body;
}

function showSigningSecret(block, secret) {
  const shown = integrationPart(block, "shown-secret");
  integrationPart(block, "shown-secret-value").value = secret || "";
  shown.hidden = !secret;
}

async function integrationAction(block, pending, run, done) {
  const buttons = block.querySelectorAll("button");
  buttons.forEach((button) => { button.disabled = true; });
  integrationSay(block, pending);
  try {
    integrationSay(block, done(await run()));
  } catch (error) {
    integrationSay(block, error.code === "mfa_required"
      ? "Confirm a code from your authenticator (Two-step sign-in, above) to change integrations."
      : error.message, true);
  } finally {
    buttons.forEach((button) => { button.disabled = false; });
  }
}

async function loadIntegrations() {
  if (!integrationsCard) return;
  let permissions = [];
  try {
    permissions = JSON.parse(sessionGet("dspm-permissions") || "[]");
  } catch {
    permissions = [];
  }
  if (!permissions.includes("tenant.admin")) return;
  try {
    const data = await api("/api/integrations");
    integrationsCard.hidden = false;
    (data.integrations || []).forEach((view) => renderIntegration(view));
  } catch (error) {
    if (error.status === 403 && error.code !== "mfa_required") return;
    integrationsCard.hidden = false;
    integrationsCard.querySelectorAll(".integration").forEach((block) => {
      integrationPart(block, "state").dataset.state = "unavailable";
      integrationPart(block, "state-text").textContent = "Status unavailable.";
    });
    const first = integrationsCard.querySelector(".integration");
    if (first) {
      integrationSay(first, error.code === "mfa_required"
        ? "Confirm a code from your authenticator (Two-step sign-in, above) to manage integrations."
        : `Could not load the integrations: ${error.message}`, true);
    }
  }
}

integrationsCard?.addEventListener("change", async (event) => {
  const block = event.target.closest(".integration");
  if (!block) return;
  const channel = block.dataset.channel;
  const draft = integrationDraft(channel);
  if (event.target.matches('[data-role="toggle"]')) {
    const wanted = event.target.checked;
    if (!draft.view?.configured) {
      // Nothing to turn on yet: open the form, and Save turns it on.
      integrationPart(block, "panel").hidden = !wanted;
      event.target.setAttribute("aria-expanded", String(wanted));
      integrationPart(block, "state-text").textContent = wanted ? "On once saved - fill in the settings." : "Off.";
      return;
    }
    await integrationAction(block, wanted ? "Turning it on..." : "Turning it off...", async () => {
      const view = await api(`/api/integrations/${channel}/enabled`, { enabled: wanted }, "PUT");
      renderIntegration(view, { fillForm: false });
      return view;
    }, () => (wanted ? "On." : "Off. The settings are kept; alerts waiting for it were cancelled."));
    renderIntegration(draft.view, { fillForm: false });
    return;
  }
  if (event.target.matches('[data-role="ca-file"]')) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > INTEGRATION_CA_MAX_BYTES) {
      integrationSay(block, "That file is larger than 64 KB. Upload the CA certificate only.", true);
      return;
    }
    const pem = await file.text();
    if (/PRIVATE KEY/i.test(pem)) {
      integrationSay(block, "That file contains a private key. Upload the CA's certificate only.", true);
      return;
    }
    if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
      integrationSay(block, "Upload a PEM certificate (-----BEGIN CERTIFICATE-----).", true);
      return;
    }
    draft.pendingCa = { pem, name: file.name };
    draft.removeCa = false;
    integrationPart(block, "ca-summary").textContent = integrationCaText(draft);
    block.querySelector('[data-action="ca-remove"]').hidden = false;
    integrationSay(block, `${file.name} is ready. Save to use it.`);
  }
});

integrationsCard?.addEventListener("submit", async (event) => {
  const block = event.target.closest(".integration");
  if (!block) return;
  event.preventDefault();
  const channel = block.dataset.channel;
  const body = { ...integrationBody(channel), enabled: integrationPart(block, "toggle").checked };
  await integrationAction(block, "Saving...", async () => {
    const view = await api(`/api/integrations/${channel}`, body, "PUT");
    renderIntegration(view);
    showSigningSecret(block, view.signing_secret);
    return view;
  }, (view) => (view.signing_secret
    ? "Saved. Copy the signing secret into the receiver now - it is not shown again."
    : "Saved."));
});

integrationsCard?.addEventListener("click", async (event) => {
  const button = event.target.closest("[data-action]");
  const block = event.target.closest(".integration");
  if (!button || !block || button.type === "submit") return;
  const channel = block.dataset.channel;
  const draft = integrationDraft(channel);
  switch (button.dataset.action) {
    case "test":
      await integrationAction(block, "Testing...", async () => {
        const result = await api(`/api/integrations/${channel}/test`, null, "POST");
        renderIntegration(result, { fillForm: false });
        if (!result.test.ok) throw new Error(result.test.message);
        return result;
      }, (result) => result.test.message);
      break;
    case "retry":
      await integrationAction(block, "Sending what is waiting...", async () => {
        const result = await api(`/api/integrations/${channel}/retry`, null, "POST");
        renderIntegration(result, { fillForm: false });
        return result;
      }, (result) => `${result.made_due} waiting will be sent now.`);
      break;
    case "rotate":
      await integrationAction(block, "Making a new signing secret...", async () => {
        const view = await api(`/api/integrations/${channel}`, { rotate_secret: true }, "PUT");
        renderIntegration(view, { fillForm: false });
        showSigningSecret(block, view.signing_secret);
        return view;
      }, () => "A new signing secret is in use. Copy it into the receiver now - it is not shown again.");
      break;
    case "copy": {
      const value = integrationPart(block, "shown-secret-value").value;
      try {
        await navigator.clipboard.writeText(value);
        integrationSay(block, "Copied.");
      } catch {
        integrationPart(block, "shown-secret-value").select();
        integrationSay(block, "Select the secret and copy it.");
      }
      break;
    }
    case "remove-secret":
      draft.removeSecret = true;
      renderIntegration(draft.view, { fillForm: false });
      break;
    case "ca-choose":
      integrationPart(block, "ca-file").click();
      break;
    case "ca-remove":
      draft.pendingCa = null;
      draft.removeCa = Boolean(draft.view?.config?.ca);
      renderIntegration(draft.view, { fillForm: false });
      break;
    case "remove":
      if (!window.confirm("Remove these settings and their secret? This cannot be undone.")) return;
      await integrationAction(block, "Removing...", async () => {
        const view = await api(`/api/integrations/${channel}`, null, "DELETE");
        renderIntegration(view);
        showSigningSecret(block, "");
        return view;
      }, () => "Removed.");
      break;
    default:
      break;
  }
});

loadDirectory();
loadCredentials();
loadIntegrations();
