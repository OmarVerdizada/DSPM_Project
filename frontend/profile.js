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

async function readErrorMessage(response) {
  const message = await response.text();
  try {
    const data = JSON.parse(message);
    return typeof data.detail === "string" ? data.detail : "Request failed.";
  } catch {
    return message || "Request failed.";
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
  if (!response.ok) throw new Error(await readErrorMessage(response));
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
