const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");
const workspaceInput = document.querySelector("#login-workspace");

let signedInAs = "";

try {
  if (window.sessionStorage.getItem("dspm-access-token")) {
    window.location.replace("/dashboard");
  }
} catch {
  // Continue to login form when storage is unavailable.
}

// The workspace is remembered per browser: a convenience, not a secret.
try {
  const remembered = window.localStorage.getItem("dspm-workspace");
  if (remembered && workspaceInput) workspaceInput.value = remembered;
} catch {
  // Storage unavailable: the field starts empty.
}

function setLoginStatus(message) {
  loginStatus.textContent = message;
}

function sessionSet(key, value) {
  try {
    window.sessionStorage.setItem(key, value);
  } catch {
    return false;
  }
  return true;
}

async function postJson(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    // C1: a completed sign-in sets the HttpOnly refresh cookie that carries the session.
    credentials: "same-origin",
    body: JSON.stringify(body),
  });
  let payload = {};
  try {
    payload = await response.json();
  } catch (_) {
    payload = {};
  }
  return { response, payload };
}

function problem(payload, fallback) {
  const detail = payload?.detail;
  if (typeof detail === "string") return detail;
  if (detail && typeof detail === "object") return detail.message || fallback;
  return fallback;
}

function finishSignIn(result) {
  sessionSet("dspm-access-token", result.access_token);
  sessionSet("dspm-tenant-id", result.tenant_id || "default");
  sessionSet("dspm-role", result.role || "viewer");
  // C3: the console gates on what the account may do, as the server states it.
  sessionSet("dspm-permissions", JSON.stringify(Array.isArray(result.permissions) ? result.permissions : []));
  sessionSet("dspm-user", signedInAs || "user");
  setLoginStatus("Success. Opening dashboard...");
  window.location.replace("/");
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoginStatus("Signing in...");
  const data = new FormData(loginForm);
  const workspace = String(data.get("workspace") || "").trim();
  signedInAs = String(data.get("username") || "");
  try {
    const { response, payload } = await postJson("/api/auth/login", {
      username: signedInAs,
      password: data.get("password") || "",
      workspace,
    });
    if (!response.ok) {
      const detail = response.status === 401
        ? "Username or password is incorrect."
        : problem(payload, "Username or password is incorrect.");
      throw new Error(detail);
    }
    try {
      if (workspace) window.localStorage.setItem("dspm-workspace", workspace);
      else window.localStorage.removeItem("dspm-workspace");
    } catch {
      // Not remembered: harmless.
    }
    finishSignIn(payload);
  } catch (error) {
    setLoginStatus(`Sign-in failed: ${error.message}`);
  }
});
