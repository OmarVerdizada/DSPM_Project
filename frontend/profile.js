const profileForm = document.querySelector("#profile-form");
const passwordForm = document.querySelector("#password-form");
const profileStatus = document.querySelector("#profile-status");
const logoutBtn = document.querySelector("#profile-logout-btn");
const themeBtn = document.querySelector("#profile-theme-btn");
const avatar = document.querySelector("#profile-avatar-large");
const title = document.querySelector("#profile-title");
const subtitle = document.querySelector("#profile-subtitle");
const usernameLabel = document.querySelector("#profile-username");
const roleLabel = document.querySelector("#profile-role-label");
const tenantLabel = document.querySelector("#profile-tenant-label");
const protectionBadge = document.querySelector("#profile-protection-badge");
const editState = document.querySelector("#profile-edit-state");
const fullNameInput = document.querySelector("#profile-full-name");
const saveProfileBtn = document.querySelector("#save-profile-btn");
const savePasswordBtn = document.querySelector("#save-password-btn");
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

let protectedAccount = false;
let profileApiAvailable = true;
let activeAvatarUser = sessionUser();
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
    if (value) {
      window.sessionStorage.setItem(key, value);
    } else {
      window.sessionStorage.removeItem(key);
    }
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

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeBtn.textContent = theme === "dark" ? "Light mode" : "Dark mode";
  storageSet("dspm-theme", theme);
}

function authHeaders() {
  const token = sessionGet("dspm-access-token");
  return {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${token}`,
    "X-Tenant-ID": sessionGet("dspm-tenant-id") || "default",
  };
}

function setStatus(message) {
  profileStatus.textContent = message;
}

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

function applyStoredAvatar(user = activeAvatarUser) {
  const initial = (user?.username || "U").trim().charAt(0).toUpperCase() || "U";
  const imageData = storageGet(avatarStorageKey(user));
  setAvatarElement(avatar, imageData, initial);
  setAvatarElement(avatarPreview, imageData, initial);
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
  if (!response.ok) {
    throw new Error(await readErrorMessage(response));
  }
  return response.json();
}

function sessionUser() {
  const username = sessionGet("dspm-user") || "user";
  return {
    username,
    role: sessionGet("dspm-role") || "viewer",
    tenant_id: sessionGet("dspm-tenant-id") || "default",
    full_name: username,
  };
}

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
    // Local session clearing must still happen if the revoke request cannot reach the API.
  }
  sessionSet("dspm-access-token", "");
  sessionSet("dspm-tenant-id", "");
  sessionSet("dspm-role", "");
  sessionSet("dspm-user", "");
  window.location.replace("/login");
}

function renderProfile(user, isProtected) {
  protectedAccount = Boolean(isProtected);
  activeAvatarUser = user;
  const name = user.full_name || user.username;
  title.textContent = name || "Profile";
  subtitle.textContent = protectedAccount
    ? "Built-in admin account is protected and cannot be edited."
    : "Manage your display name and local password.";
  usernameLabel.textContent = user.username || "-";
  roleLabel.textContent = user.role || "-";
  tenantLabel.textContent = user.tenant_id || "-";
  protectionBadge.textContent = protectedAccount ? "Protected" : "Editable";
  if (!profileApiAvailable) {
    protectionBadge.textContent = "Session";
  }
  protectionBadge.classList.toggle("protected", protectedAccount);
  editState.textContent = !profileApiAvailable ? "Password only" : protectedAccount ? "Read-only" : "Profile and password";
  fullNameInput.value = user.full_name || "";
  fullNameInput.disabled = protectedAccount || !profileApiAvailable;
  saveProfileBtn.disabled = protectedAccount || !profileApiAvailable;
  passwordForm.querySelectorAll("input, button").forEach((item) => {
    item.disabled = protectedAccount;
  });
  sessionSet("dspm-user", user.username || "");
  sessionSet("dspm-role", user.role || "");
  sessionSet("dspm-tenant-id", user.tenant_id || "default");
  applyStoredAvatar(user);
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
  const minX = size - drawWidth;
  const minY = size - drawHeight;
  cropState.offsetX = Math.min(0, Math.max(minX, cropState.offsetX));
  cropState.offsetY = Math.min(0, Math.max(minY, cropState.offsetY));

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
  cropBase = {
    width: image.naturalWidth * baseScale,
    height: image.naturalHeight * baseScale,
  };
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
  if (file.size > AVATAR_MAX_BYTES) {
    return "Image must be 2 MB or smaller.";
  }
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
        updateAvatarHelp(`Image must be at least ${AVATAR_MIN_SIZE}x${AVATAR_MIN_SIZE} px.`, true);
        return;
      }
      if (image.naturalWidth > AVATAR_MAX_SIZE || image.naturalHeight > AVATAR_MAX_SIZE) {
        updateAvatarHelp(`Image must be no larger than ${AVATAR_MAX_SIZE}x${AVATAR_MAX_SIZE} px.`, true);
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

async function loadProfile() {
  if (!sessionGet("dspm-access-token")) {
    window.location.replace("/login");
    return;
  }
  try {
    const data = await api("/api/profile");
    profileApiAvailable = true;
    renderProfile(data.user || {}, data.protected);
    setStatus(data.protected ? "This protected account is read-only." : "Profile loaded.");
  } catch (error) {
    profileApiAvailable = false;
    const fallbackUser = sessionUser();
    renderProfile(fallbackUser, fallbackUser.username === "admin");
    setStatus("Profile API is not active yet. Password change can still be used; restart the server to edit profile details.");
  }
}

profileForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (protectedAccount) {
    setStatus("Built-in admin account is protected.");
    return;
  }
  setStatus("Saving profile...");
  try {
    const data = await api("/api/profile", { full_name: fullNameInput.value.trim() }, "PUT");
    renderProfile(data.user || {}, false);
    setStatus("Profile updated.");
  } catch (error) {
    setStatus(`Profile update failed: ${error.message}`);
  }
});

passwordForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (protectedAccount) {
    setStatus("Built-in admin account is protected.");
    return;
  }
  const data = new FormData(passwordForm);
  const currentPassword = String(data.get("current_password") || "");
  const newPassword = String(data.get("new_password") || "");
  const confirmPassword = String(data.get("confirm_password") || "");
  if (newPassword.length < 8) {
    setStatus("Password must be at least 8 characters.");
    return;
  }
  if (newPassword !== confirmPassword) {
    setStatus("New passwords do not match.");
    return;
  }
  setStatus("Changing password...");
  try {
    await api("/api/auth/change-password", { current_password: currentPassword, new_password: newPassword }, "POST");
    passwordForm.reset();
    setStatus("Password changed.");
  } catch (error) {
    setStatus(`Password change failed: ${error.message}`);
  }
});

chooseAvatarBtn.addEventListener("click", () => avatarFileInput.click());

avatarFileInput.addEventListener("change", () => {
  const file = avatarFileInput.files?.[0];
  avatarFileInput.value = "";
  loadAvatarFile(file);
});

removeAvatarBtn.addEventListener("click", () => {
  storageRemove(avatarStorageKey());
  applyStoredAvatar();
  updateAvatarHelp("Profile photo removed.");
  setStatus("Profile photo removed.");
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

avatarApplyBtn.addEventListener("click", () => {
  const avatarData = exportAvatarImage();
  if (!avatarData) {
    updateAvatarHelp("Choose an image before applying.", true);
    return;
  }
  const saved = storageSet(avatarStorageKey(), avatarData);
  if (!saved) {
    updateAvatarHelp("Browser storage is full or unavailable.", true);
    return;
  }
  applyStoredAvatar();
  updateAvatarHelp("Profile photo applied.");
  setStatus("Profile photo updated.");
  closeAvatarCrop();
});

avatarCropClose.addEventListener("click", closeAvatarCrop);
avatarCropCancel.addEventListener("click", closeAvatarCrop);
avatarCropModal.addEventListener("click", (event) => {
  if (event.target === avatarCropModal) closeAvatarCrop();
});

logoutBtn.addEventListener("click", logout);
themeBtn.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

applyTheme(storageGet("dspm-theme") || "light");
loadProfile().catch((error) => {
  setStatus(`Profile failed: ${error.message}`);
});
