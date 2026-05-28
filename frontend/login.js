const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");

try {
  if (window.sessionStorage.getItem("dspm-access-token")) {
    window.location.replace("/");
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
      throw new Error("Username or password is incorrect.");
    }

    const result = await response.json();
    sessionSet("dspm-access-token", result.access_token);
    sessionSet("dspm-tenant-id", result.tenant_id || "default");
    setLoginStatus("Success. Opening dashboard...");
    window.location.replace("/");
  } catch (error) {
    setLoginStatus(`Sign-in failed: ${error.message}`);
  }
});
