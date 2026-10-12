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
    // The Configuration step says it itself (console/scan-setup.js).
    if (typeof scanTypesLabel === "function") return scanTypesLabel();
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
  // W2.6: what each scan level costs and covers, said where it is chosen.
  var levelHints = {
    inventory: "Lists files, owners and access; no content is inspected for findings. Fastest. A file the scan would otherwise read shows as not read by policy.",
    standard: "Reads text up to 16 MiB and documents up to 64 MiB, once each. A longer text file is read up to its cap and marked partly inspected; a larger document and other types are listed by their metadata.",
    full: "Standard, with ZIP archives opened and findings mapped to the frameworks you choose - every framework if you choose none. The slowest and most thorough.",
  };
  function levelLabel() {
    var checked = document.querySelector("input[name='scan_level']:checked");
    var name = checked && checked.parentElement && checked.parentElement.querySelector("b");
    return name ? name.textContent.trim() : "Standard";
  }
  function render() {
    var server = fieldValue("server", "");
    var levelInput = document.querySelector("input[name='scan_level']:checked");
    var level = levelInput ? levelInput.value : "standard";
    setText("scan-level-hint", levelHints[level] || levelHints.standard);
    setText("scan-summary-level", levelLabel());
    setText("scan-summary-target", server || "Local dataset");
    setText("scan-summary-domain", fieldValue("domain", "—"));
    setText("scan-summary-path", server ? "\\\\" + server + "\\" + fieldValue("smb_shares", "*") : fieldValue("local_path", "—"));
    setText("scan-summary-depth", fieldValue("max_depth", "No limit"));
    setText("scan-summary-policy", policyLabel());
    // Advanced scan scope (console/scan-scope.js): how many rules, and what they leave out.
    if (typeof scanScopeReviewText === "function") setText("scan-summary-scope", scanScopeReviewText("file-server"));
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
  // A restored scan, or the review step opening: rendered now, not on the next frame,
  // which a page in the background never paints.
  document.addEventListener("scan-form-updated", render);
  render();
})();
