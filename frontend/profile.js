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

let protectedAccount = false;
let profileApiAvailable = true;

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

function logout() {
  sessionSet("dspm-access-token", "");
  sessionSet("dspm-tenant-id", "");
  sessionSet("dspm-role", "");
  sessionSet("dspm-user", "");
  window.location.replace("/login");
}

function renderProfile(user, isProtected) {
  protectedAccount = Boolean(isProtected);
  const name = user.full_name || user.username;
  title.textContent = name || "Profile";
  subtitle.textContent = protectedAccount
    ? "Built-in admin account is protected and cannot be edited."
    : "Manage your display name and local password.";
  avatar.textContent = (user.username || "U").charAt(0).toUpperCase();
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

logoutBtn.addEventListener("click", logout);
themeBtn.addEventListener("click", () => {
  applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
});

applyTheme(storageGet("dspm-theme") || "light");
loadProfile().catch((error) => {
  setStatus(`Profile failed: ${error.message}`);
});
