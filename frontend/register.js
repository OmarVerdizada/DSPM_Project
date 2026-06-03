const registerForm = document.querySelector("#register-form");
const registerStatus = document.querySelector("#register-status");
const registerTenant = document.querySelector("#register-tenant");

function setRegisterStatus(message) {
  registerStatus.textContent = message;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

async function loadTenants() {
  try {
    const response = await fetch("/api/auth/tenants");
    if (!response.ok) {
      throw new Error("Tenant list unavailable.");
    }
    const data = await response.json();
    registerTenant.innerHTML = (data.tenants || [{ tenant_id: "default", display_name: "Default" }])
      .map((tenant) => `<option value="${escapeHtml(tenant.tenant_id)}">${escapeHtml(tenant.display_name || tenant.tenant_id)}</option>`)
      .join("");
    setRegisterStatus("Ready.");
  } catch (error) {
    registerTenant.innerHTML = '<option value="default">default</option>';
    setRegisterStatus(error.message);
  }
}

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setRegisterStatus("Creating account...");

  const data = new FormData(registerForm);
  const password = data.get("password") || "";
  const confirmPassword = data.get("password_confirm") || "";
  if (password !== confirmPassword) {
    setRegisterStatus("Register failed: passwords do not match.");
    return;
  }

  try {
    const response = await fetch("/api/auth/register", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: data.get("username") || "",
        password,
        full_name: data.get("full_name") || "",
        tenant_id: data.get("tenant_id") || "default",
      }),
    });

    if (!response.ok) {
      throw new Error(await response.text());
    }

    setRegisterStatus("Account created. Opening sign in...");
    window.location.replace("/login");
  } catch (error) {
    setRegisterStatus(`Register failed: ${error.message}`);
  }
});

loadTenants();
