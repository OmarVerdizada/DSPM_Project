/* =========================================================
   SENTRO Mission Control effects — additive visual layer.
   Custom cursor, ambient mouse spotlight, Ctrl/Cmd+K command
   palette, and the API-health status dot. This file never
   modifies app.js state; the palette only clicks the same
   nav buttons a user would click. Safe to remove entirely.
   ========================================================= */
(function () {
  "use strict";

  var reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

  /* P5 motion budget: the custom cursor + ambient mouse spotlight are removed.
     The skin layers had already hidden them with display:none — the code was
     burning a permanent rAF loop and three mousemove listeners for nothing.
     A professional console keeps the native pointer. */

  /* ── API health dot: mirror the text app.js writes ─────── */
  var health = document.getElementById("health");
  if (health) {
    var syncHealth = function () {
      var ok = /online|ok/i.test(health.textContent || "");
      var bad = /unavailable|error|offline/i.test(health.textContent || "");
      health.classList.toggle("is-ok", ok);
      health.classList.toggle("is-bad", bad && !ok);
    };
    syncHealth();
    new MutationObserver(syncHealth).observe(health, { childList: true, characterData: true, subtree: true });
  }

  /* ── Command palette (Ctrl/Cmd+K) ──────────────────────── */
  var overlay = null;
  var activeIndex = 0;
  var visibleItems = [];

  function collectEntries() {
    var entries = [];
    document.querySelectorAll(".side-nav .tab").forEach(function (tab) {
      var label = tab.querySelector("span");
      var sub = tab.querySelector("small");
      entries.push({
        title: label ? label.textContent.trim() : tab.textContent.trim(),
        subtitle: sub ? sub.textContent.trim() : "",
        kind: "Page",
        run: function () { tab.click(); },
      });
    });
    var actions = [
      { sel: '[data-tab-jump="file-servers"]', title: "Start file scan", subtitle: "Jump to File Server Scan", kind: "Action" },
      { sel: '[data-tab-jump="endpoint"]', title: "Start endpoint scan", subtitle: "Jump to Endpoint Scan", kind: "Action" },
      { sel: "#export-csv-btn", title: "Export Excel workbook", subtitle: "Reporting center", kind: "Action" },
      { sel: "#export-word-btn", title: "Export Word pack", subtitle: "Reporting center", kind: "Action" },
      { sel: "#export-pdf-btn", title: "Open PDF composer", subtitle: "Reporting center", kind: "Action" },
      { sel: "#theme-toggle", title: "Toggle theme", subtitle: "Light / dark", kind: "Action" },
      { sel: "#copilot-launcher", title: "Open AI Copilot", subtitle: "Ask about DSPM data", kind: "Action" },
    ];
    actions.forEach(function (a) {
      var el = document.querySelector(a.sel);
      if (el) {
        entries.push({
          title: a.title,
          subtitle: a.subtitle,
          kind: a.kind,
          run: function () { el.click(); },
        });
      }
    });
    return entries;
  }

  /* Recent commands — palette shows them first when idle */
  var RECENT_KEY = "sentro-palette-recent";
  function getRecents() {
    try { return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]"); }
    catch (e) { return []; }
  }
  function pushRecent(title) {
    try {
      var list = getRecents().filter(function (t) { return t !== title; });
      list.unshift(title);
      localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, 5)));
    } catch (e) { /* storage unavailable — recents are optional */ }
  }
  function orderEntries(entries) {
    var recents = getRecents();
    entries.forEach(function (en) {
      var idx = recents.indexOf(en.title);
      en.isRecent = idx !== -1;
      en.recentRank = idx === -1 ? 99 : idx;
      var origRun = en.run;
      en.run = function () { pushRecent(en.title); origRun(); };
    });
    return entries.slice().sort(function (a, b) { return a.recentRank - b.recentRank; });
  }

  function closePalette() {
    if (overlay) {
      overlay.remove();
      overlay = null;
      visibleItems = [];
    }
  }

  function renderList(listEl, entries, query) {
    listEl.textContent = "";
    var q = query.trim().toLowerCase();
    visibleItems = entries.filter(function (en) {
      return !q ||
        en.title.toLowerCase().indexOf(q) !== -1 ||
        en.subtitle.toLowerCase().indexOf(q) !== -1;
    });
    if (activeIndex >= visibleItems.length) activeIndex = 0;

    if (visibleItems.length === 0) {
      var empty = document.createElement("div");
      empty.className = "mc-palette-empty";
      empty.textContent = "No results for “" + query + "”";
      listEl.appendChild(empty);
      return;
    }

    visibleItems.forEach(function (en, i) {
      var item = document.createElement("div");
      item.className = "mc-palette-item" + (i === activeIndex ? " is-active" : "");
      item.setAttribute("role", "option");
      item.setAttribute("aria-selected", i === activeIndex ? "true" : "false");

      var kindTag = document.createElement("span");
      kindTag.className = "mc-palette-k" + (en.isRecent && !q ? " is-recent" : "");
      kindTag.textContent = en.isRecent && !q ? "Recent" : en.kind;

      var body = document.createElement("span");
      body.style.flex = "1";
      body.style.minWidth = "0";
      var titleEl = document.createElement("span");
      titleEl.textContent = en.title;
      var subEl = document.createElement("small");
      subEl.textContent = en.subtitle;
      body.appendChild(titleEl);
      if (en.subtitle) body.appendChild(subEl);

      item.appendChild(kindTag);
      item.appendChild(body);
      item.addEventListener("mouseenter", function () {
        activeIndex = i;
        Array.prototype.forEach.call(listEl.children, function (c, j) {
          c.classList.toggle("is-active", j === i);
        });
      });
      item.addEventListener("click", function () {
        closePalette();
        en.run();
      });
      listEl.appendChild(item);
    });
  }

  function openPalette() {
    if (overlay) return;
    var entries = orderEntries(collectEntries());
    activeIndex = 0;

    overlay = document.createElement("div");
    overlay.className = "mc-palette-overlay";
    overlay.setAttribute("role", "dialog");
    overlay.setAttribute("aria-modal", "true");
    overlay.setAttribute("aria-label", "Command palette");

    var panel = document.createElement("div");
    panel.className = "mc-palette";

    var inputRow = document.createElement("div");
    inputRow.className = "mc-palette-input-row";
    var input = document.createElement("input");
    input.type = "text";
    input.placeholder = "Search pages and actions...";
    input.setAttribute("aria-label", "Search pages and actions");
    var esc = document.createElement("kbd");
    esc.textContent = "esc";
    inputRow.appendChild(input);
    inputRow.appendChild(esc);

    var list = document.createElement("div");
    list.className = "mc-palette-list";
    list.setAttribute("role", "listbox");

    panel.appendChild(inputRow);
    panel.appendChild(list);
    overlay.appendChild(panel);
    document.body.appendChild(overlay);

    renderList(list, entries, "");
    input.focus();

    input.addEventListener("input", function () {
      activeIndex = 0;
      renderList(list, entries, input.value);
    });

    overlay.addEventListener("mousedown", function (e) {
      if (e.target === overlay) closePalette();
    });

    input.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        activeIndex = Math.min(activeIndex + 1, visibleItems.length - 1);
        renderList(list, entries, input.value);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        activeIndex = Math.max(activeIndex - 1, 0);
        renderList(list, entries, input.value);
      } else if (e.key === "Enter") {
        e.preventDefault();
        var chosen = visibleItems[activeIndex];
        if (chosen) {
          closePalette();
          chosen.run();
        }
      } else if (e.key === "Escape") {
        e.preventDefault();
        closePalette();
      }
    });
  }

  addEventListener("keydown", function (e) {
    if ((e.metaKey || e.ctrlKey) && String(e.key).toLowerCase() === "k") {
      e.preventDefault();
      if (overlay) closePalette();
      else openPalette();
    } else if (e.key === "Escape" && overlay) {
      closePalette();
    }
  });

  /* ── KPI count-up: animate the numbers app.js writes ───── */
  if (!reduced) {
    ["critical-count", "high-count", "medium-count", "low-count", "protected-count", "total-count"].forEach(function (id) {
      var el = document.getElementById(id);
      if (!el) return;
      var lastValue = parseInt((el.textContent || "").replace(/[^\d-]/g, ""), 10) || 0;
      var animating = false;
      var raf = 0;
      new MutationObserver(function () {
        if (animating) return;
        var target = parseInt((el.textContent || "").replace(/[^\d-]/g, ""), 10);
        if (isNaN(target) || target === lastValue) return;
        var from = lastValue;
        lastValue = target;
        animating = true;
        el.classList.add("mc-counting");
        var start = performance.now();
        var dur = 700;
        cancelAnimationFrame(raf);
        raf = requestAnimationFrame(function step(now) {
          var t = Math.min(1, (now - start) / dur);
          var eased = 1 - Math.pow(1 - t, 3);
          el.textContent = String(Math.round(from + (target - from) * eased));
          if (t < 1) {
            raf = requestAnimationFrame(step);
          } else {
            el.classList.remove("mc-counting");
            animating = false;
          }
        });
      }).observe(el, { childList: true, characterData: true, subtree: true });
    });
  }

  /* ── Empty-state CTAs: a next step inside curated empties.
     Buttons only click the same nav tabs a user would. ───── */
  var emptyCtas = [
    { root: "#results-body", label: "Start your first scan", tab: "file-servers" },
    { root: "#findings-signal-summary", label: "Run a file scan", tab: "file-servers" },
    { root: "#exposure-permissions-summary", label: "Run an endpoint scan", tab: "endpoint" },
    { root: "#report-preview", label: "Start a scan", tab: "file-servers" }
  ];
  emptyCtas.forEach(function (cfg) {
    var root = document.querySelector(cfg.root);
    if (!root) return;
    var decorate = function () {
      var host = root.classList && root.classList.contains("empty")
        ? root
        : root.querySelector(".empty, .report-empty");
      if (!host || host.querySelector(".mc-empty-cta")) return;
      var navTab = document.querySelector('.side-nav .tab[data-tab="' + cfg.tab + '"]');
      if (!navTab) return;
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "mc-empty-cta";
      btn.textContent = cfg.label;
      btn.addEventListener("click", function () { navTab.click(); });
      host.appendChild(btn);
    };
    decorate();
    new MutationObserver(decorate).observe(root, { childList: true, subtree: true, attributes: true, attributeFilter: ["class"] });
  });

  /* ── v3: search pill opens the command palette ─────────── */
  document.getElementById("fx-search")?.addEventListener("click", function () {
    openPalette();
  });

  /* ── v3: "+ New Scan" dropdown (buttons use data-tab-jump,
     handled by app.js's own delegated click listener) ────── */
  (function () {
    var wrap = document.getElementById("fx-newscan");
    var btn = document.getElementById("fx-newscan-btn");
    if (!wrap || !btn) return;
    var setOpen = function (open) {
      wrap.classList.toggle("open", open);
      btn.setAttribute("aria-expanded", String(open));
    };
    btn.addEventListener("click", function (e) {
      e.stopPropagation();
      setOpen(!wrap.classList.contains("open"));
    });
    wrap.querySelectorAll(".tb-newscan-menu button").forEach(function (item) {
      item.addEventListener("click", function () { setOpen(false); });
    });
    document.addEventListener("click", function (e) {
      if (!wrap.contains(e.target)) setOpen(false);
    });
    document.addEventListener("keydown", function (e) {
      if (e.key === "Escape") setOpen(false);
    });
  })();

  /* ── v3: mobile drawer — start closed, close after nav ─── */
  (function () {
    var mq = window.matchMedia("(max-width: 1024px)");
    var sync = function () {
      if (mq.matches) document.body.classList.add("sidebar-collapsed");
    };
    sync();
    mq.addEventListener ? mq.addEventListener("change", sync) : mq.addListener(sync);
    document.querySelectorAll(".side-nav .tab").forEach(function (tab) {
      tab.addEventListener("click", function () {
        if (mq.matches) document.body.classList.add("sidebar-collapsed");
      });
    });
  })();

  /* (P6 polish) the v3 dashboard-charts block was removed: it rendered into
     #fx-posture-chart / #fx-severity-donut / #fx-recent-scans hosts that do
     not exist in the current markup, so the whole IIFE early-returned on
     every load — ~290 lines of guarded dead code. */
})();
