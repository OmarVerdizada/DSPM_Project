// SSO handoff from the SENTRO landing page: the token arrives in the URL
// fragment (never sent to the server), is stored for app.js, and the
// fragment is removed from the address bar. Must load before app.js.
(function () {
  if (!window.location.hash || window.location.hash.indexOf("#sso=") !== 0) {
    return;
  }
  try {
    var params = new URLSearchParams(window.location.hash.slice(1));
    var token = params.get("sso");
    if (token) {
      window.sessionStorage.setItem("dspm-access-token", token);
      window.sessionStorage.setItem("dspm-tenant-id", params.get("tenant") || "default");
      window.sessionStorage.setItem("dspm-role", params.get("role") || "viewer");
      window.sessionStorage.setItem("dspm-user", params.get("user") || "user");
    }
  } catch (e) {
    // Storage unavailable — the app will fall back to the login page.
  }
  history.replaceState(null, "", window.location.pathname + window.location.search);
})();
