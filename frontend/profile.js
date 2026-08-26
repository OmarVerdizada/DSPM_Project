/* Settings page: profile, security, appearance, install features, session.
   The avatar's source of truth is the account record (/api/profile/avatar);
   localStorage only caches it per browser for instant paint. */

const profileForm = document.querySelector("#profile-form");
const passwordForm = document.querySelector("#password-form");
const profileStatus = document.querySelector("#profile-status");
const passwordStatus = document.querySelector("#password-status");
const featuresStatus = document.querySelector("#features-status");
const logoutBtn = document.querySelector("#profile-logout-btn");
const themeLightBtn = document.querySelector("#theme-light-btn");
const themeDarkBtn = document.querySelector("#theme-dark-btn");
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

async function api(path, payload, method = "GET") {
  const response = await fetch(path, {
    method,
    headers: authHeaders(),
    body: payload ? JSON.stringify(payload) : undefined,
  });
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
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  storageSet("dspm-theme", theme);
  themeLightBtn.classList.toggle("active", theme !== "dark");
  themeDarkBtn.classList.toggle("active", theme === "dark");
  themeLightBtn.setAttribute("aria-checked", String(theme !== "dark"));
  themeDarkBtn.setAttribute("aria-checked", String(theme === "dark"));
}

themeLightBtn.addEventListener("click", () => applyTheme("light"));
themeDarkBtn.addEventListener("click", () => applyTheme("dark"));

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
  if (newPassword.length < 8) {
    setStatus(passwordStatus, "Password must be at least 8 characters.");
    return;
  }
  if (newPassword !== confirmPassword) {
    setStatus(passwordStatus, "New passwords do not match.");
    return;
  }
  setStatus(passwordStatus, "Changing password…");
  try {
    await api("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword }, "POST");
    passwordForm.reset();
    setStatus(passwordStatus, "Password changed.");
  } catch (error) {
    setStatus(passwordStatus, `Password change failed: ${error.message}`);
  }
});

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
  const tokenToRevoke = sessionGet("dspm-access-token");
  try {
    if (tokenToRevoke) {
      await fetch("/api/logout", {
        method: "POST",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${tokenToRevoke}` },
      });
    }
  } catch {
    /* local session clearing must still happen */
  }
  sessionSet("dspm-access-token", "");
  sessionSet("dspm-tenant-id", "");
  sessionSet("dspm-role", "");
  sessionSet("dspm-user", "");
  window.location.replace("/login");
}

logoutBtn.addEventListener("click", logout);

/* ── Boot ─────────────────────────────────────────────────────── */
applyTheme(storageGet("dspm-theme") || "light");
activateSection(location.hash.slice(1) || "profile", false);
renderSessionExpiry();
loadProfile();
loadFeatures();
