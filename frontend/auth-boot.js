/* Applies the saved theme before first paint. External on purpose: the CSP is
   script-src 'self', so inline <script> blocks and onclick attributes never
   execute — this file replaces the former inline theme-restore snippets on the
   login and profile pages. Loaded synchronously in <head> to avoid a flash. */
(function () {
  try {
    var t = window.localStorage.getItem("dspm-theme");
    if (t) document.documentElement.setAttribute("data-theme", t);
  } catch (e) {}
})();
