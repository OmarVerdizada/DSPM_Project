const registerForm = document.querySelector("#register-form");
const registerStatus = document.querySelector("#register-status");

function setRegisterStatus(message) {
  registerStatus.textContent = message;
}

async function readErrorMessage(response) {
  const message = await response.text();
  if (!message) {
    return "Registration failed.";
  }
  try {
    const data = JSON.parse(message);
    return typeof data.detail === "string" ? data.detail : "Registration failed.";
  } catch {
    return "Registration failed.";
  }
}

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setRegisterStatus("Creating account...");

  const data = new FormData(registerForm);
  const username = String(data.get("username") || "").trim();
  const tenantId = String(data.get("tenant_id") || "").trim();
  const registrationCode = String(data.get("registration_code") || "").trim();
  const password = data.get("password") || "";
  const confirmPassword = data.get("password_confirm") || "";
  if (!username || username.length < 3) {
    setRegisterStatus("Register failed: enter a username with at least 3 characters.");
    return;
  }
  if (!tenantId || !registrationCode) {
    setRegisterStatus("Register failed: tenant ID and registration code are required.");
    return;
  }
  if (password.length < 8) {
    setRegisterStatus("Register failed: password must be at least 8 characters.");
    return;
  }
  if (password !== confirmPassword) {
    setRegisterStatus("Register failed: passwords do not match.");
    return;
  }

  try {
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username,
        password,
        full_name: data.get("full_name") || "",
        tenant_id: tenantId,
        registration_code: registrationCode,
      }),
    });

    if (!response.ok) {
      throw new Error(await readErrorMessage(response));
    }

    setRegisterStatus("Account created. Opening sign in...");
    window.location.replace("/login");
  } catch (error) {
    setRegisterStatus(`Register failed: ${error.message}`);
  }
});
