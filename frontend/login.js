const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");

try {
  if (window.sessionStorage.getItem("dspm-access-token")) {
    window.location.replace("/dashboard");
  }
} catch {
  // Continue to login form when storage is unavailable.
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

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setLoginStatus("Signing in...");

  const data = new FormData(loginForm);
  try {
    const response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: data.get("username") || "",
        password: data.get("password") || "",
      }),
    });

    if (!response.ok) {
      let detail = "Username or password is incorrect.";
      try {
        const errorPayload = await response.json();
        detail = errorPayload.detail || detail;
      } catch (_) {
        // Keep the safe generic message if the server did not return JSON.
      }
      if (response.status === 401) {
        detail = "Username or password is incorrect. Default local login is admin / Admin12345 unless DSPM_ADMIN_PASSWORD is set.";
      }
      throw new Error(detail);
    }

    const result = await response.json();
    sessionSet("dspm-access-token", result.access_token);
    sessionSet("dspm-tenant-id", result.tenant_id || "default");
    sessionSet("dspm-role", result.role || "viewer");
    sessionSet("dspm-user", data.get("username") || "user");
    setLoginStatus("Success. Opening dashboard...");
    window.location.replace("/");
  } catch (error) {
    setLoginStatus(`Sign-in failed: ${error.message}`);
  }
});
