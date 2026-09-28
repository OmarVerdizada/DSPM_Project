const loginForm = document.querySelector("#login-form");
const loginStatus = document.querySelector("#login-status");
const workspaceInput = document.querySelector("#login-workspace");
const mfaForm = document.querySelector("#mfa-form");
const mfaCode = document.querySelector("#mfa-code");
const mfaCodeLabel = document.querySelector("#mfa-code-label");
const mfaHint = document.querySelector("#mfa-hint");
const mfaStatus = document.querySelector("#mfa-status");
const mfaUseRecovery = document.querySelector("#mfa-use-recovery");
const enrollSection = document.querySelector("#mfa-enroll");
const enrollForm = document.querySelector("#mfa-enroll-form");
const enrollCode = document.querySelector("#mfa-enroll-code");
const enrollStatus = document.querySelector("#mfa-enroll-status");
const enrollSecret = document.querySelector("#mfa-secret");
const recoverySection = document.querySelector("#mfa-recovery");
const recoveryList = document.querySelector("#mfa-codes");
const recoverySaved = document.querySelector("#mfa-saved");
const recoveryContinue = document.querySelector("#mfa-continue");

// C2: between the password and the session, the challenge lives only here - never in
// storage or a URL - and is good for five minutes.
let mfaToken = "";
let signedInAs = "";
let usingRecovery = false;
let pendingSession = null;

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

function show(section) {
  for (const element of [loginForm, mfaForm, enrollSection, recoverySection]) {
    element?.classList.toggle("is-hidden", element !== section);
  }
  section?.querySelector("input")?.focus();
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

function codeFrom(input) {
  return String(input?.value || "").replace(/\s+/g, "");
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
    if (payload.mfa_required) {
      mfaToken = payload.mfa_token;
      setLoginStatus("");
      show(mfaForm);
      return;
    }
    if (payload.mfa_enrollment_required) {
      mfaToken = payload.mfa_token;
      setLoginStatus("");
      await beginEnrollment();
      return;
    }
    finishSignIn(payload);
  } catch (error) {
    setLoginStatus(`Sign-in failed: ${error.message}`);
  }
});

mfaUseRecovery?.addEventListener("click", () => {
  usingRecovery = !usingRecovery;
  mfaCode.value = "";
  mfaCode.inputMode = usingRecovery ? "text" : "numeric";
  mfaCode.pattern = usingRecovery ? "[A-Za-z2-7 -]{16,23}" : "[0-9 ]{6,7}";
  mfaCode.maxLength = usingRecovery ? 23 : 7;
  mfaCode.placeholder = usingRecovery ? "XXXX-XXXX-XXXX-XXXX" : "123 456";
  mfaCode.autocomplete = usingRecovery ? "off" : "one-time-code";
  mfaCodeLabel.textContent = usingRecovery ? "Recovery code" : "Authenticator code";
  mfaHint.textContent = usingRecovery
    ? "Enter one of the recovery codes you saved. Each works once."
    : "Open your authenticator app and enter the six-digit code for Sentro.";
  mfaUseRecovery.textContent = usingRecovery ? "Use the authenticator app instead" : "Use a recovery code instead";
  mfaCode.focus();
});

mfaForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  mfaStatus.textContent = "Checking...";
  const body = { mfa_token: mfaToken };
  if (usingRecovery) body.recovery_code = String(mfaCode.value || "").trim();
  else body.code = codeFrom(mfaCode);
  const { response, payload } = await postJson("/api/auth/mfa/verify", body);
  if (!response.ok) {
    mfaCode.value = "";
    mfaStatus.textContent = response.status === 401 && /expired/i.test(problem(payload, ""))
      ? "This sign-in has expired. Sign in again."
      : problem(payload, "That code is not valid.");
    if (/expired/i.test(mfaStatus.textContent)) {
      mfaToken = "";
      show(loginForm);
      setLoginStatus(mfaStatus.textContent);
    }
    return;
  }
  mfaToken = "";
  finishSignIn(payload);
});

async function beginEnrollment() {
  show(enrollSection);
  enrollStatus.textContent = "Preparing a key...";
  const { response, payload } = await postJson("/api/auth/mfa/enroll/start", { mfa_token: mfaToken });
  if (!response.ok) {
    show(loginForm);
    setLoginStatus(problem(payload, "This sign-in has expired. Sign in again."));
    return;
  }
  // Grouped in fours so it can be read aloud or typed without losing the place.
  enrollSecret.textContent = String(payload.secret || "").replace(/(.{4})/g, "$1 ").trim();
  enrollSecret.dataset.uri = payload.otpauth_uri || "";
  enrollStatus.textContent = "";
  enrollCode.focus();
}

document.querySelector("#mfa-copy-secret")?.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(enrollSecret.textContent.replace(/\s+/g, ""));
    enrollStatus.textContent = "Key copied.";
  } catch {
    enrollStatus.textContent = "Copy is not available here; type the key into the app.";
  }
});

enrollForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  enrollStatus.textContent = "Checking...";
  const { response, payload } = await postJson("/api/auth/mfa/enroll/confirm",
    { mfa_token: mfaToken, code: codeFrom(enrollCode) });
  if (!response.ok) {
    enrollCode.value = "";
    enrollStatus.textContent = problem(payload, "That code does not match. Check the app and try again.");
    return;
  }
  mfaToken = "";
  enrollSecret.textContent = "";
  enrollSecret.dataset.uri = "";
  const codes = Array.isArray(payload.recovery_codes) ? payload.recovery_codes : [];
  recoveryList.replaceChildren(...codes.map((code) => {
    const item = document.createElement("li");
    item.textContent = code;
    return item;
  }));
  // The session waits until the codes are acknowledged; it is held here, not stored.
  pendingSession = { ...payload, recovery_codes: undefined };
  show(recoverySection);
});

document.querySelector("#mfa-copy-codes")?.addEventListener("click", async () => {
  const text = [...recoveryList.querySelectorAll("li")].map((item) => item.textContent).join("\n");
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    // Selecting the list and copying by hand still works.
  }
});

recoverySaved?.addEventListener("change", () => {
  recoveryContinue.disabled = !recoverySaved.checked;
});

recoveryContinue?.addEventListener("click", () => {
  if (!pendingSession) return;
  const session = pendingSession;
  pendingSession = null;
  recoveryList.replaceChildren();
  finishSignIn(session);
});
