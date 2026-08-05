(function () {
  const themeToggle = document.querySelector("#auth-theme-toggle");

  function safeStorageGet(key) {
    try {
      return window.localStorage.getItem(key);
    } catch {
      return null;
    }
  }

  function safeStorageSet(key, value) {
    try {
      window.localStorage.setItem(key, value);
    } catch {
      // The current page can still use the selected theme.
    }
  }

  function applyTheme(theme) {
    const normalized = theme === "dark" ? "dark" : "light";
    document.documentElement.dataset.theme = normalized;
    const icon = themeToggle?.querySelector(".theme-icon");
    const nextLabel = normalized === "dark" ? "Switch to light mode" : "Switch to dark mode";
    if (icon) icon.innerHTML = normalized === "dark" ? "&#9728;" : "&#9790;";
    themeToggle?.setAttribute("aria-label", nextLabel);
    if (themeToggle) themeToggle.title = nextLabel;
    safeStorageSet("dspm-theme", normalized);
  }

  applyTheme(safeStorageGet("dspm-theme") || "light");
  themeToggle?.addEventListener("click", () => {
    applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });
})();
