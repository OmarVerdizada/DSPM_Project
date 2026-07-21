(() => {
  const launcher = document.querySelector("#copilot-launcher");
  const popup = document.querySelector("#copilot-popup");
  const closeButton = document.querySelector("#copilot-close-btn");
  const newButton = document.querySelector("#copilot-new-btn");
  const expandButton = document.querySelector("#copilot-expand-btn");
  const form = document.querySelector("#copilot-form");
  const input = document.querySelector("#copilot-input");
  const send = document.querySelector("#copilot-send-btn");
  const messages = document.querySelector("#copilot-messages");
  const empty = document.querySelector("#copilot-empty");
  const meta = document.querySelector("#copilot-meta");
  const insightsHost = document.querySelector("#copilot-insights");
  const badge = document.querySelector("#copilot-insight-badge");
  if (!launcher || !popup || !form) return;

  const conversationKey = "dspm-copilot-conversation-id";
  const dismissedInsightsKey = "dspm-copilot-dismissed-insights";
  let conversationId = sessionStorage.getItem(conversationKey) || "";
  let dismissedInsightIds = new Set();
  try { dismissedInsightIds = new Set(JSON.parse(sessionStorage.getItem(dismissedInsightsKey) || "[]")); } catch { dismissedInsightIds = new Set(); }
  let controller = null;
  const COMPOSER_MAX_HEIGHT = 118;

  const escape = (value = "") => String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[char]);
  const artifactUrlPattern = "\\/api\\/v1\\/copilot\\/artifacts\\/[a-f0-9]{32}(?:\\?[^\\s)]*)?";
  function reportAction(url, filename = "") {
    const title = filename ? `Download ${filename}` : "Download generated report";
    return `<a class="copilot-report-action" href="${escape(url)}" target="_blank" rel="noopener" aria-label="${escape(title)}" title="${escape(title)}"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3v12"/><path d="m7 10 5 5 5-5"/><path d="M5 21h14"/></svg><span>Download report</span></a>`;
  }
  function formatInline(value = "") {
    const actions = [];
    const markdownArtifact = new RegExp(`\\[([^\\]\\n]+)\\](\\((${artifactUrlPattern})\\))`, "g");
    const protectedValue = String(value).replace(markdownArtifact, (_match, label, _wrapped, url) => {
      const index = actions.push(reportAction(url, label)) - 1;
      return `\u0000REPORT_ACTION_${index}\u0000`;
    });
    const rawArtifact = new RegExp(`(${artifactUrlPattern})`, "g");
    let rendered = escape(protectedValue)
      .replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")
      .replace(/`([^`]+)`/g, "<code>$1</code>")
      .replace(rawArtifact, (url) => reportAction(url.replaceAll("&amp;", "&")));
    actions.forEach((action, index) => { rendered = rendered.replace(`\u0000REPORT_ACTION_${index}\u0000`, action); });
    return rendered;
  }

  function renderAnswer(value = "") {
    const lines = String(value).split(/\r?\n/);
    const blocks = [];
    let list = [];
    const flushList = () => { if (list.length) { blocks.push(`<ul>${list.join("")}</ul>`); list = []; } };
    lines.forEach((line) => {
      const text = line.trim();
      if (!text) { flushList(); return; }
      if (/^[-•]\s+/.test(text)) { list.push(`<li>${formatInline(text.replace(/^[-•]\s+/, ""))}</li>`); return; }
      flushList();
      if (/^(#{1,3}\s+|[A-Z][^.!?]{2,48}:$)/.test(text)) blocks.push(`<h4>${formatInline(text.replace(/^#{1,3}\s+/, ""))}</h4>`);
      else blocks.push(`<p>${formatInline(text)}</p>`);
    });
    flushList();
    return blocks.join("");
  }

  function open() {
    popup.classList.remove("hidden");
    launcher.setAttribute("aria-expanded", "true");
    launcher.setAttribute("aria-label", "Close AI Copilot");
    launcher.title = "Close AI Copilot";
    input.focus();
    loadInsights();
  }
  function close() {
    popup.classList.add("hidden");
    popup.classList.remove("fullscreen");
    launcher.setAttribute("aria-expanded", "false");
    launcher.setAttribute("aria-label", "Open AI Copilot");
    launcher.title = "AI Copilot";
  }
  function resizeComposerHeight() {
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, COMPOSER_MAX_HEIGHT)}px`;
    input.style.overflowY = input.scrollHeight > COMPOSER_MAX_HEIGHT ? "auto" : "hidden";
  }
  function resetComposerHeight() {
    input.style.removeProperty("height");
    input.style.overflowY = "hidden";
  }
  function resetConversation() {
    if (controller) controller.abort();
    conversationId = "";
    sessionStorage.removeItem(conversationKey);
    messages.querySelectorAll(".copilot-message").forEach((item) => item.remove());
    empty?.classList.remove("hidden");
    meta.innerHTML = "<span>New conversation · grounded in your latest authorized scan</span>";
    input.value = "";
    resetComposerHeight();
    setBusy(false);
    input.focus();
  }
  const COPY_ICON_HTML = '<svg class="copy-icon" viewBox="0 0 24 24" aria-hidden="true"><rect width="14" height="14" x="8" y="8" rx="2" ry="2"/><path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/></svg><svg class="check-icon" viewBox="0 0 24 24" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
  const USER_MESSAGE_ACTIONS_HTML = `<div class="copilot-message-actions"><button type="button" data-copilot-action="edit" aria-label="Edit message" title="Edit"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z"/><path d="m15 5 4 4"/></svg></button><button type="button" data-copilot-action="copy" aria-label="Copy message" title="Copy">${COPY_ICON_HTML}</button></div>`;
  const ASSISTANT_MESSAGE_ACTIONS_HTML = `<div class="copilot-message-actions"><button type="button" data-copilot-action="copy" aria-label="Copy answer" title="Copy answer">${COPY_ICON_HTML}</button></div>`;
  function addMessage(role, text, extra = "") {
    empty?.classList.add("hidden");
    const item = document.createElement("article");
    item.className = `copilot-message ${role} ${extra} has-actions`.trim();
    const assistant = role.includes("assistant");
    const messageActions = role === "user" ? USER_MESSAGE_ACTIONS_HTML : ASSISTANT_MESSAGE_ACTIONS_HTML;
    item.innerHTML = `${assistant ? '<span class="copilot-message-avatar" aria-hidden="true">S</span>' : ""}<div class="copilot-message-content"><span class="copilot-message-role">${assistant ? "SENTRO Copilot" : "You"}</span><div class="copilot-message-body">${renderAnswer(text)}</div>${messageActions}</div>`;
    if (role === "user") {
      item.dataset.raw = text;
      item.dataset.turnIndex = String(messages.querySelectorAll(".copilot-message.user").length);
    }
    messages.appendChild(item);
    messages.scrollTop = messages.scrollHeight;
    return item;
  }
  async function copyToClipboard(text) {
    try { await navigator.clipboard.writeText(text); return true; }
    catch {
      const helper = document.createElement("textarea");
      helper.value = text;
      helper.setAttribute("readonly", "");
      helper.style.cssText = "position:fixed;left:-9999px;opacity:0";
      document.body.appendChild(helper);
      helper.select();
      let ok = false;
      try { ok = document.execCommand("copy"); } catch { ok = false; }
      helper.remove();
      return ok;
    }
  }
  function copyableMessageText(item) {
    if (!item) return "";
    if (item.classList.contains("user")) return item.dataset.raw || "";
    const body = item.querySelector(".copilot-message-body");
    return (body?.innerText || body?.textContent || "").trim();
  }
  function setBusy(busy) {
    send.disabled = !busy && !input.value.trim();
    send.classList.toggle("is-stopping", busy);
    send.setAttribute("aria-label", busy ? "Stop response" : "Send message");
    input.readOnly = busy;
  }
  function clearResponseStatus() {
    meta.replaceChildren();
  }
  async function request(path, payload, method = "POST", signal) {
    const response = await fetch(path, { method, headers: authHeaders(), body: payload ? JSON.stringify(payload) : undefined, signal });
    if (!response.ok) throw new Error(await response.text() || `Request failed (${response.status})`);
    return response.json();
  }
  async function ask(text) {
    addMessage("user", text);
    meta.innerHTML = '<span class="copilot-working"><i></i>Analyzing authorized scan evidence…</span>';
    controller = new AbortController();
    setBusy(true);
    const typing = addMessage("assistant", "Thinking…", "typing");
    try {
      const payload = { message: text, selected_language_source: "absent" };
      if (conversationId) payload.conversation_id = conversationId;
      const data = await request("/api/v1/copilot/chat", payload, "POST", controller.signal);
      typing.remove();
      conversationId = data.conversation_id || conversationId;
      if (conversationId) sessionStorage.setItem(conversationKey, conversationId);
      const answer = data.answer || data.error?.message || "Copilot could not produce an answer.";
      addMessage(data.error ? "assistant error" : "assistant", answer);
      clearResponseStatus();
    } catch (error) {
      typing.remove();
      addMessage("assistant error", error.name === "AbortError" ? "Response stopped." : "Copilot request failed. Check the model health and try again.");
      meta.innerHTML = `<span>${error.name === "AbortError" ? "Response stopped" : "Request failed"}</span>`;
    } finally {
      controller = null;
      setBusy(false);
      input.focus();
    }
  }
  function restoreMessage(item) {
    const body = item?.querySelector(".copilot-message-body");
    if (!body) return;
    body.innerHTML = renderAnswer(item.dataset.raw || "");
    item.classList.remove("is-editing");
  }
  function startInlineEdit(item) {
    if (!item || item.classList.contains("is-editing")) return;
    const body = item.querySelector(".copilot-message-body");
    if (!body) return;
    item.classList.add("is-editing");
    body.innerHTML = `<div class="copilot-inline-editor"><textarea aria-label="Edit message" rows="2">${escape(item.dataset.raw || "")}</textarea><div class="copilot-inline-editor-actions"><button type="button" data-copilot-action="cancel-edit" aria-label="Cancel edit" title="Cancel"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18"/><path d="m6 6 12 12"/></svg></button><button type="button" data-copilot-action="save-edit" aria-label="Save edit" title="Save"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m20 6-11 11-5-5"/></svg></button></div></div>`;
    const editor = body.querySelector("textarea");
    editor?.focus();
    editor?.setSelectionRange(editor.value.length, editor.value.length);
  }
  function removeMessagesAfter(item) {
    let next = item?.nextElementSibling;
    while (next) {
      const current = next;
      next = next.nextElementSibling;
      current.remove();
    }
  }
  async function replaceMessage(item, text) {
    if (!conversationId || !item) return;
    const turnIndex = Number(item.dataset.turnIndex);
    if (!Number.isInteger(turnIndex) || turnIndex < 0) return;
    removeMessagesAfter(item);
    item.dataset.raw = text;
    restoreMessage(item);
    meta.innerHTML = '<span class="copilot-working"><i></i>Regenerating from edited message...</span>';
    controller = new AbortController();
    setBusy(true);
    const typing = addMessage("assistant", "Thinking...", "typing");
    try {
      const payload = { message: text, conversation_id: conversationId, selected_language_source: "absent" };
      const method = "PUT";
      const data = await request(`/api/v1/copilot/conversations/${encodeURIComponent(conversationId)}/messages/${turnIndex}`, payload, method, controller.signal);
      typing.remove();
      const answer = data.answer || data.error?.message || "Copilot could not produce an answer.";
      addMessage(data.error ? "assistant error" : "assistant", answer);
      clearResponseStatus();
    } catch (error) {
      typing.remove();
      addMessage("assistant error", error.name === "AbortError" ? "Response stopped." : "The edited message could not be regenerated.");
      meta.innerHTML = `<span>${error.name === "AbortError" ? "Response stopped" : "Edit failed"}</span>`;
    } finally {
      controller = null;
      setBusy(false);
    }
  }
  function saveDismissedInsights() {
    sessionStorage.setItem(dismissedInsightsKey, JSON.stringify([...dismissedInsightIds]));
  }
  function updateInsightVisibility() {
    const count = insightsHost.querySelectorAll(".copilot-insight").length;
    badge.textContent = String(count);
    badge.classList.toggle("hidden", !count);
    insightsHost.classList.toggle("hidden", !count);
  }
  async function loadInsights() {
    try {
      const data = await request("/api/v1/copilot/insights?limit=5", null, "GET");
      const rows = (data.insights || []).filter((item) => !dismissedInsightIds.has(String(item.id)));
      insightsHost.innerHTML = rows.map((item) => `<div class="copilot-insight" data-insight-id="${escape(item.id)}"><button type="button" class="copilot-insight-action" data-insight-action="${escape(item.id)}"><i class="insight-severity ${escape(item.severity || "info")}"></i><span><strong>${escape(item.title?.en || item.title?.az || "Insight")}</strong><small>${escape(item.summary?.en || item.summary?.az || "")}</small></span><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m9 18 6-6-6-6"></path></svg></button><button type="button" class="copilot-insight-dismiss" data-insight-dismiss="${escape(item.id)}" aria-label="Dismiss notification" title="Dismiss"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M18 6 6 18"></path><path d="m6 6 12 12"></path></svg></button></div>`).join("");
      updateInsightVisibility();
    } catch { badge.classList.add("hidden"); }
  }

  launcher.addEventListener("click", () => {
    if (popup.classList.contains("hidden")) open();
    else close();
  });
  newButton?.addEventListener("click", resetConversation);
  closeButton.addEventListener("click", close);
  expandButton.addEventListener("click", () => popup.classList.toggle("fullscreen"));
  input.addEventListener("input", () => { send.disabled = !input.value.trim(); resizeComposerHeight(); });
  input.addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); form.requestSubmit(); } });
  form.addEventListener("submit", (event) => { event.preventDefault(); if (controller) { controller.abort(); return; } const text = input.value.trim(); if (!text) return; input.value = ""; resetComposerHeight(); ask(text); });
  messages.addEventListener("click", async (event) => {
    const action = event.target.closest("[data-copilot-action]");
    if (action) {
      const item = action.closest(".copilot-message");
      const raw = item?.dataset.raw || "";
      if (action.dataset.copilotAction === "copy") {
        if (await copyToClipboard(copyableMessageText(item))) {
          action.classList.add("is-copied");
          window.setTimeout(() => action.classList.remove("is-copied"), 1400);
        }
      } else if (action.dataset.copilotAction === "edit" && !controller) {
        startInlineEdit(action.closest(".copilot-message"));
      } else if (action.dataset.copilotAction === "cancel-edit") {
        restoreMessage(action.closest(".copilot-message"));
      } else if (action.dataset.copilotAction === "save-edit" && !controller) {
        const item = action.closest(".copilot-message");
        const edited = item?.querySelector(".copilot-inline-editor textarea")?.value.trim() || "";
        if (edited && edited !== raw) await replaceMessage(item, edited);
        else restoreMessage(item);
      }
      return;
    }
    const starter = event.target.closest("[data-copilot-prompt]");
    if (!starter || controller) return;
    input.value = starter.dataset.copilotPrompt || "";
    form.requestSubmit();
  });
  insightsHost.addEventListener("click", async (event) => {
    const dismiss = event.target.closest("[data-insight-dismiss]");
    if (dismiss) {
      event.preventDefault();
      event.stopPropagation();
      const insightId = String(dismiss.dataset.insightDismiss || "");
      if (!insightId) return;
      dismissedInsightIds.add(insightId);
      saveDismissedInsights();
      dismiss.closest(".copilot-insight")?.remove();
      updateInsightVisibility();
      try { await request(`/api/v1/copilot/insights/${encodeURIComponent(insightId)}/dismiss`, {}); } catch { /* Keep session dismissal stable. */ }
      return;
    }
    const button = event.target.closest("[data-insight-action]");
    if (!button) return;
    open();
    try {
      const data = await request(`/api/v1/copilot/insights/${encodeURIComponent(button.dataset.insightAction)}/action`, {});
      conversationId = data.conversation_id || conversationId;
      addMessage("assistant", data.answer || "Insight reviewed.");
      loadInsights();
    } catch { meta.textContent = "Insight action failed"; }
  });
  document.addEventListener("keydown", (event) => { if (event.key === "Escape" && !popup.classList.contains("hidden")) close(); });
  // Auto-close when interacting outside the panel (covers main navigation clicks).
  // Capture phase so page handlers that stop propagation cannot keep it open.
  document.addEventListener("pointerdown", (event) => {
    if (popup.classList.contains("hidden")) return;
    if (event.target instanceof Element && event.target.closest("#copilot-widget")) return;
    close();
  }, true);
  // Auto-close when the user leaves for another browser tab or page.
  document.addEventListener("visibilitychange", () => {
    if (document.visibilityState === "hidden" && !popup.classList.contains("hidden")) close();
  });
  window.setTimeout(loadInsights, 1200);
})();
