/* Live scan-summary mirror for the file-server scan form. External on purpose:
   this logic previously lived in an inline <script> block that the CSP
   (script-src 'self') silently blocked, so the summary panel never updated. */
(function () {
  var form = document.getElementById("connection-form");
  var panel = document.getElementById("scan-summary-options");
  if (!form || !panel) return;
  var optionInputs = {
    async: "async_scan",
    zip: "inspect_archives",
    admin: "include_admin_shares",
    smb3: "smb_encryption",
    compliance: "compliance-enabled",
  };
  function fieldValue(id, fallback) {
    var el = document.getElementById(id);
    var value = el && typeof el.value === "string" ? el.value.trim() : "";
    return value || fallback;
  }
  function setText(id, value) {
    var el = document.getElementById(id);
    if (el && el.textContent !== value) el.textContent = value;
  }
  function policyLabel() {
    var advanced = document.getElementById("ext-advanced-mode");
    if (advanced && !advanced.classList.contains("hidden")) {
      var count = document.querySelectorAll("#allowed_extensions input:checked").length;
      return count ? "Custom (" + count + " selected)" : "Custom selection";
    }
    var checked = document.querySelector("input[name='ext-preset']:checked");
    var card = checked && checked.closest(".ext-preset-card");
    var title = card && card.querySelector(".ext-preset-title");
    return title ? title.textContent.trim() : "—";
  }
  function render() {
    var server = fieldValue("server", "");
    setText("scan-summary-target", server || "Local dataset");
    setText("scan-summary-domain", fieldValue("domain", "—"));
    setText("scan-summary-path", server ? "\\\\" + server + "\\" + fieldValue("smb_shares", "*") : fieldValue("local_path", "—"));
    setText("scan-summary-depth", fieldValue("max_depth", "—"));
    setText("scan-summary-policy", policyLabel());
    Object.keys(optionInputs).forEach(function (key) {
      var input = document.getElementById(optionInputs[key]);
      var chip = panel.querySelector('[data-summary-option="' + key + '"]');
      if (chip) chip.classList.toggle("on", Boolean(input && input.checked));
    });
  }
  var scheduled = false;
  function schedule() {
    if (scheduled) return;
    scheduled = true;
    window.requestAnimationFrame(function () {
      scheduled = false;
      render();
    });
  }
  form.addEventListener("input", schedule);
  form.addEventListener("change", schedule);
  form.addEventListener("click", schedule);
  render();
})();
