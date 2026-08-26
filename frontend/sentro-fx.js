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

  /* ── Topbar search: standalone inline suggestions (pages + actions, the
     same entries the old palette suggested) anchored under the bar — no modal
     window, and no connection to the Data-inventory search. Ctrl/Cmd+K still
     opens the full palette. ── */
  (function () {
    var input = document.getElementById("fx-search");
    var wrap = input && input.closest(".tb-search");
    if (!input || !wrap) return;
    var box = document.createElement("div");
    box.className = "tb-suggest";
    box.hidden = true;
    box.setAttribute("role", "listbox");
    wrap.appendChild(box);
    var items = [], active = 0;

    function close() { box.hidden = true; box.textContent = ""; items = []; active = 0; }
    function paint() {
      Array.prototype.forEach.call(box.children, function (c, i) {
        c.classList.toggle("is-active", i === active);
      });
    }
    function choose(en) {
      close();
      input.value = "";
      input.blur();
      en.run();
    }
    function render() {
      var qv = input.value.trim().toLowerCase();
      var entries = orderEntries(collectEntries()).filter(function (en) {
        return !qv ||
          en.title.toLowerCase().indexOf(qv) !== -1 ||
          en.subtitle.toLowerCase().indexOf(qv) !== -1;
      }).slice(0, 8);
      items = entries; active = 0; box.textContent = "";
      if (!entries.length) { close(); return; }
      entries.forEach(function (en, i) {
        var el = document.createElement("button");
        el.type = "button";
        el.className = "tb-suggest-item" + (i === 0 ? " is-active" : "");
        el.setAttribute("role", "option");
        var k = document.createElement("span");
        k.className = "tb-suggest-k";
        k.textContent = en.isRecent && !qv ? "Recent" : en.kind;
        var t = document.createElement("span");
        t.className = "tb-suggest-t";
        t.textContent = en.title;
        var s = document.createElement("small");
        s.textContent = en.subtitle;
        el.appendChild(k); el.appendChild(t);
        if (en.subtitle) el.appendChild(s);
        el.addEventListener("mousedown", function (e) { e.preventDefault(); choose(en); });
        el.addEventListener("mouseenter", function () { active = i; paint(); });
        box.appendChild(el);
      });
      box.hidden = false;
    }

    input.addEventListener("input", render);
    input.addEventListener("focus", render);
    input.addEventListener("blur", function () { setTimeout(close, 140); });
    input.addEventListener("keydown", function (e) {
      if (box.hidden) { if (e.key === "ArrowDown") { render(); e.preventDefault(); } return; }
      if (e.key === "ArrowDown") { e.preventDefault(); active = (active + 1) % items.length; paint(); }
      else if (e.key === "ArrowUp") { e.preventDefault(); active = (active + items.length - 1) % items.length; paint(); }
      else if (e.key === "Enter") { e.preventDefault(); if (items[active]) choose(items[active]); }
      else if (e.key === "Escape") { close(); input.blur(); }
    });
  })();

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

  /* ── Dashboard charts — resurrected: this suite shipped for versions with
     its host elements missing, so it never rendered once. The overview now
     carries the hosts (posture trend, severity donut, recent scans, activity
     feed, KPI sparklines) and the suite reads /api/history + /api/audit
     read-only, exactly as designed. ── */
  /* ── v3: dashboard charts — read-only views over the same
     APIs app.js already uses (GET /api/history, /api/audit).
     Renders sparklines, the posture area chart, the severity
     donut, recent scans, and the activity feed. Never writes
     state; app.js remains the only owner of app logic. ───── */
  (function () {
    var sparkHosts = document.querySelectorAll(".kpi-spark[data-spark]");
    var postureHost = document.getElementById("fx-posture-chart");
    var pillsHost = document.getElementById("fx-posture-pills");
    var donutHost = document.getElementById("fx-severity-donut");
    var scansHost = document.getElementById("fx-recent-scans");
    var feedHost = document.getElementById("fx-activity");
    if (!postureHost && !donutHost && !scansHost) return;

    var SEVS = ["critical", "high", "medium", "low"];
    var historyItems = [];
    var postureMode = "all";

    /* Severity mix is a drill-down: a segment or legend row opens the
       Data inventory on Findings filtered to that severity (center = all). */
    if (donutHost) {
      donutHost.addEventListener("click", function (event) {
        var hit = event.target.closest ? event.target.closest("[data-sev]") : null;
        var sev = hit ? hit.getAttribute("data-sev") : "";
        if (typeof window.switchTab !== "function") return;
        window.switchTab("inventory");
        var btn = document.querySelector('[data-risk-filter="' + (sev ? sev.toUpperCase() : "ALL") + '"]');
        if (btn) btn.click();
      });
    }

    function cssVar(name) {
      return getComputedStyle(document.documentElement).getPropertyValue(name).trim() || "#4f46e5";
    }
    function sevColor(sev) { return cssVar("--status-" + sev); }
    function token() {
      try { return sessionStorage.getItem("dspm-access-token") || ""; }
      catch (e) { return ""; }
    }
    function apiGet(path) {
      var t = token();
      if (!t) return Promise.reject(new Error("no session"));
      return fetch(path, { headers: { Authorization: "Bearer " + t } }).then(function (res) {
        if (!res.ok) throw new Error(String(res.status));
        return res.json();
      });
    }
    function esc(value) {
      return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
      });
    }
    function itemTime(item) {
      return item.timestamp || item.saved_at || item.created_at || "";
    }
    function friendly(ts) {
      var d = new Date(ts);
      if (isNaN(d.getTime())) return String(ts || "");
      var diff = (Date.now() - d.getTime()) / 60000;
      if (diff < 1) return "just now";
      if (diff < 60) return Math.round(diff) + "m ago";
      if (diff < 1440) return Math.round(diff / 60) + "h ago";
      return d.toLocaleDateString(undefined, { month: "short", day: "numeric" }) +
        " " + d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
    }
    function counts(item) {
      var s = item.summary || {};
      return {
        critical: Number(s.critical) || 0,
        high: Number(s.high) || 0,
        medium: Number(s.medium) || 0,
        low: Number(s.low) || 0,
      };
    }
    function emptyBlock(msg, ctaLabel, ctaTab) {
      var cta = ctaLabel
        ? '<button type="button" class="mc-empty-cta" data-tab-jump="' + esc(ctaTab) + '">' + esc(ctaLabel) + "</button>"
        : "";
      return '<div class="empty compact">' + esc(msg) + cta + "</div>";
    }

    /* Sparklines inside the 4 KPI cards */
    function renderSparks() {
      sparkHosts.forEach(function (host) {
        var sev = host.dataset.spark;
        var series = historyItems.map(function (item) { return counts(item)[sev]; });
        if (series.length < 2) { host.innerHTML = ""; return; }
        var recent = series.slice(-12);
        var max = Math.max.apply(null, recent.concat([1]));
        var W = 100, H = 34, step = W / (recent.length - 1);
        var pts = recent.map(function (v, i) {
          return [i * step, H - 4 - (v / max) * (H - 10)];
        });
        var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
        var area = line + " L" + W + " " + H + " L0 " + H + " Z";
        var color = sevColor(sev);
        host.innerHTML =
          '<svg viewBox="0 0 ' + W + " " + H + '" preserveAspectRatio="none" aria-hidden="true">' +
          '<path d="' + area + '" fill="' + color + '" opacity="0.12"></path>' +
          '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="1.6" opacity="0.85"></path>' +
          "</svg>";
      });
    }

    /* Posture overview area chart with series pills */
    function renderPills() {
      if (!pillsHost) return;
      var modes = [["all", "All findings"], ["critical", "Critical"], ["high", "High"]];
      pillsHost.innerHTML = modes.map(function (m) {
        return '<button type="button" data-mode="' + m[0] + '" class="' + (postureMode === m[0] ? "active" : "") + '">' + m[1] + "</button>";
      }).join("");
      pillsHost.querySelectorAll("button").forEach(function (b) {
        b.addEventListener("click", function () {
          postureMode = b.dataset.mode;
          renderPills();
          renderPosture();
        });
      });
    }
    function renderPosture() {
      if (!postureHost) return;
      if (historyItems.length < 2) {
        postureHost.innerHTML = emptyBlock(
          historyItems.length === 0
            ? "No scans yet. Run your first scan to draw the posture trend."
            : "One scan saved. The trend appears after your next scan.",
          "Run a scan", "file-servers");
        return;
      }
      var series = historyItems.map(function (item) {
        var c = counts(item);
        return postureMode === "all" ? c.critical + c.high + c.medium + c.low : c[postureMode];
      });
      var labels = historyItems.map(function (item) { return friendly(itemTime(item)); });
      var W = Math.max(postureHost.clientWidth || 560, 320), H = 260;
      var padL = 34, padR = 12, padT = 14, padB = 26;
      var max = Math.max.apply(null, series.concat([1]));
      var innerW = W - padL - padR, innerH = H - padT - padB;
      var step = innerW / (series.length - 1);
      var color = postureMode === "critical" ? sevColor("critical")
        : postureMode === "high" ? sevColor("high") : cssVar("--accent");
      var pts = series.map(function (v, i) {
        return [padL + i * step, padT + innerH - (v / max) * innerH];
      });
      var line = pts.map(function (p, i) { return (i ? "L" : "M") + p[0].toFixed(1) + " " + p[1].toFixed(1); }).join(" ");
      var area = line + " L" + (padL + innerW) + " " + (padT + innerH) + " L" + padL + " " + (padT + innerH) + " Z";
      var grid = [0, .5, 1].map(function (f) {
        var y = padT + innerH - f * innerH;
        return '<line x1="' + padL + '" x2="' + (W - padR) + '" y1="' + y + '" y2="' + y +
          '" stroke="' + cssVar("--line") + '" stroke-width="1"></line>' +
          '<text x="' + (padL - 8) + '" y="' + (y + 4) + '" text-anchor="end" font-size="10" fill="' + cssVar("--muted") + '">' +
          Math.round(f * max) + "</text>";
      }).join("");
      var dots = pts.map(function (p, i) {
        return '<circle cx="' + p[0].toFixed(1) + '" cy="' + p[1].toFixed(1) + '" r="3" fill="' + color +
          '"><title>' + esc(labels[i]) + ": " + series[i] + "</title></circle>";
      }).join("");
      var gid = "fxg" + Math.round(Math.random() * 1e6);
      postureHost.innerHTML =
        '<svg viewBox="0 0 ' + W + " " + H + '" role="img" aria-label="Findings trend across scans">' +
        grid +
        '<path d="' + line + '" fill="none" stroke="' + color + '" stroke-width="2" stroke-linejoin="round"></path>' +
        dots +
        '<text x="' + padL + '" y="' + (H - 8) + '" font-size="10" fill="' + cssVar("--muted") + '">' + esc(labels[0]) + "</text>" +
        '<text x="' + (W - padR) + '" y="' + (H - 8) + '" text-anchor="end" font-size="10" fill="' + cssVar("--muted") + '">' +
        esc(labels[labels.length - 1]) + "</text>" +
        "</svg>";
    }

    /* Severity donut fed by the KPI numbers app.js maintains */
    function kpiValue(id) {
      var el = document.getElementById(id);
      return el ? (parseInt((el.textContent || "").replace(/[^\d]/g, ""), 10) || 0) : 0;
    }
    function renderDonut() {
      if (!donutHost) return;
      var values = {
        critical: kpiValue("critical-count"),
        high: kpiValue("high-count"),
        medium: kpiValue("medium-count"),
        low: kpiValue("low-count"),
      };
      var total = SEVS.reduce(function (sum, s) { return sum + values[s]; }, 0);
      var R = 58, C = 2 * Math.PI * R, cx = 75, cy = 75;
      /* Quiet full-circle track behind the data; dotted when there is nothing
         to show so the empty state reads as "waiting", not "broken". */
      var segments = '<circle cx="' + cx + '" cy="' + cy + '" r="' + R + '" fill="none" stroke="' + cssVar("--line") +
        '" stroke-width="' + (total === 0 ? 3 : 8) + '"' +
        (total === 0 ? ' stroke-dasharray="2 8" stroke-linecap="round" opacity=".9"' : ' opacity=".45"') + "></circle>";
      if (total > 0) {
        var offset = 0, GAP = 4;
        SEVS.forEach(function (sev) {
          if (!values[sev]) return;
          var frac = values[sev] / total;
          var arc = Math.max(frac * C - GAP, 2);
          segments += '<circle data-sev="' + sev + '" cx="' + cx + '" cy="' + cy + '" r="' + R + '" fill="none" stroke="' + sevColor(sev) +
            '" stroke-width="12" stroke-linecap="round" stroke-dasharray="' + arc.toFixed(2) + " " + C.toFixed(2) +
            '" stroke-dashoffset="' + (-(offset * C + GAP / 2)).toFixed(2) + '" transform="rotate(-90 ' + cx + " " + cy + ')">' +
            "<title>" + sev.charAt(0).toUpperCase() + sev.slice(1) + ": " + values[sev] + "</title></circle>";
          offset += frac;
        });
      }
      var legend = SEVS.map(function (sev) {
        var pct = total ? Math.round((values[sev] / total) * 100) : 0;
        return '<div data-sev="' + sev + '"><i style="background:' + sevColor(sev) + '"></i>' +
          sev.charAt(0).toUpperCase() + sev.slice(1) + "<b>" + (total ? values[sev] + " · " + pct + "%" : "0") + "</b></div>";
      }).join("");
      donutHost.innerHTML =
        '<svg width="150" height="150" viewBox="0 0 150 150" role="img" aria-label="Findings by severity">' + segments +
        '<text x="75" y="72" text-anchor="middle" font-size="27" font-weight="700" fill="' + cssVar("--text") + '">' + total + "</text>" +
        '<text x="75" y="91" text-anchor="middle" font-size="10" letter-spacing=".04em" fill="' + cssVar("--muted") + '">' +
        (total === 0 ? "no findings yet" : "findings") + "</text></svg>" +
        '<div class="fx-legend">' + legend + "</div>";
    }

    /* Recent scans table */
    function renderScans() {
      if (!scansHost) return;
      if (!historyItems.length) {
        scansHost.innerHTML = emptyBlock("No scans yet.", "Run your first scan", "file-servers");
        return;
      }
      var rows = historyItems.slice(-5).reverse().map(function (item) {
        var c = counts(item);
        var totalFindings = c.critical + c.high + c.medium + c.low;
        var level = c.critical ? "CRITICAL" : c.high ? "HIGH" : c.medium ? "MEDIUM" : "LOW";
        var label = c.critical ? "Critical" : c.high ? "High" : c.medium ? "Medium" : "Clean";
        return "<tr>" +
          '<td class="fx-scan-id">' + esc(item.scan_id || "scan") + "</td>" +
          '<td class="fx-time">' + esc(friendly(itemTime(item))) + "</td>" +
          "<td>" + totalFindings + "</td>" +
          '<td><span class="badge ' + level + '">' + label + "</span></td>" +
          "</tr>";
      }).join("");
      scansHost.innerHTML =
        '<table class="fx-table"><thead><tr><th>Scan</th><th>When</th><th>Findings</th><th>Status</th></tr></thead><tbody>' +
        rows + "</tbody></table>";
    }

    /* Activity feed from the audit trail (admins see data) */
    function renderFeed(events, denied) {
      if (!feedHost) return;
      if (denied) {
        feedHost.innerHTML = emptyBlock("The audit trail is visible to admin users.");
        return;
      }
      if (!events.length) {
        feedHost.innerHTML = emptyBlock("No activity recorded yet.");
        return;
      }
      feedHost.innerHTML = '<div class="fx-feed">' + events.slice(-5).reverse().map(function (ev) {
        var action = String(ev.action || ev.event || "event");
        var initial = (String(ev.actor || ev.user || "S").charAt(0) || "S").toUpperCase();
        return '<div class="fx-feed-item"><span class="fx-feed-ico">' + esc(initial) + "</span>" +
          "<div><p>" + esc(action.replace(/[_-]/g, " ")) + (ev.actor ? " — " + esc(ev.actor) : "") + "</p>" +
          "<small>" + esc(friendly(ev.timestamp || ev.time || "")) + "</small></div></div>";
      }).join("") + "</div>";
    }

    function refresh() {
      apiGet("/api/history").then(function (data) {
        historyItems = (data && data.history) || [];
        renderSparks();
        renderPosture();
        renderScans();
      }).catch(function () {
        historyItems = [];
        renderSparks();
        renderPosture();
        renderScans();
      });
      apiGet("/api/audit").then(function (data) {
        renderFeed((data && (data.events || data.audit)) || [], false);
      }).catch(function (err) {
        renderFeed([], String(err && err.message).indexOf("403") !== -1);
      });
      renderDonut();
    }

    var debounceTimer = 0;
    function refreshSoon() {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(refresh, 500);
    }

    /* Skeletons paint instantly on load; the first fetch (or its empty
       state) replaces them. Init-only - never on pill clicks. */
    (function paintSkeletons() {
      function sklRows(n, h) {
        var rows = "";
        for (var i = 0; i < n; i++) rows += '<div class="skl" style="height:' + h + 'px;margin:10px 0;width:' + (92 - i * 9) + '%"></div>';
        return rows;
      }
      if (scansHost) scansHost.innerHTML = sklRows(4, 16);
      if (feedHost) feedHost.innerHTML = sklRows(4, 16);
      if (postureHost) postureHost.innerHTML = '<div class="skl" style="height:150px"></div>';
      if (donutHost) donutHost.innerHTML = '<div class="skl skl-circle"></div>';
    })();

    renderPills();
    refresh();
    /* re-render when app.js updates the KPI numbers */
    SEVS.forEach(function (sev) {
      var el = document.getElementById(sev + "-count");
      if (el) new MutationObserver(function () { renderDonut(); }).observe(el, { childList: true, characterData: true, subtree: true });
    });
    /* refresh on tenant switch, scan completion, tab return, theme flip */
    document.getElementById("tenant-switcher")?.addEventListener("change", refreshSoon);
    var scanMeta = document.getElementById("scan-meta");
    if (scanMeta) new MutationObserver(refreshSoon).observe(scanMeta, { childList: true, characterData: true, subtree: true });
    document.querySelector('.side-nav .tab[data-tab="overview"]')?.addEventListener("click", refreshSoon);
    document.getElementById("theme-toggle")?.addEventListener("click", function () {
      setTimeout(function () { renderSparks(); renderPosture(); renderDonut(); }, 80);
    });
    var resizeTimer = 0;
    addEventListener("resize", function () {
      clearTimeout(resizeTimer);
      resizeTimer = setTimeout(renderPosture, 200);
    });
  })();
})();
