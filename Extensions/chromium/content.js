// RamPart Web Protection: content script (isolated world). Collects page signals, asks the
// background for a verdict, and renders the calm interstitial / banner. Also intercepts
// copy-to-clipboard of shell commands on non-developer sites.
(() => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  if (window.top !== window) return;
  if (document.documentElement.hasAttribute("data-rampart-ready")) return;
  document.documentElement.setAttribute("data-rampart-ready", "1");

  const H = globalThis.RampartHeuristics;
  const PAGE_URL = location.href;
  let shownLevel = null;          // "block" | "warn"
  let userContinued = false;

  // MARK: Signal collection

  function collectSignals() {
    const forms = Array.from(document.forms).slice(0, 20).map((f) => {
      const inputs = Array.from(f.querySelectorAll("input"));
      const names = inputs.map((i) => ((i.name || "") + " " + (i.id || "") + " " + (i.autocomplete || "") + " " + (i.placeholder || "")).toLowerCase());
      let action = null; try { action = f.action ? new URL(f.getAttribute("action") || "", location.href).href : null; } catch {}
      return {
        action,
        hasPassword: inputs.some((i) => i.type === "password"),
        hasEmailOrUser: inputs.some((i, k) => i.type === "email" || /user|login|email|account/.test(names[k])),
        hasCardNumber: names.some((n) => /card|cc-number|cardnumber|cvv|cvc/.test(n)),
        hasOTP: names.some((n) => /otp|one-time|onetime|totp|2fa|verification.?code/.test(n)) || inputs.some((i) => i.autocomplete === "one-time-code"),
      };
    });
    // Overlays: fixed/absolute elements covering most of the viewport.
    const vw = innerWidth, vh = innerHeight;
    let overlayText = "";
    for (const el of document.querySelectorAll("div, section, dialog, main, form")) {
      if (overlayText.length > 4000) break;
      const cs = getComputedStyle(el);
      if (cs.position !== "fixed" && cs.position !== "absolute" && el.tagName !== "DIALOG") continue;
      const r = el.getBoundingClientRect();
      if (r.width >= vw * 0.6 && r.height >= vh * 0.6) overlayText += " " + (el.innerText || "").slice(0, 2000);
    }
    const scripts = [];
    let usesClipboardWrite = false, hasWalletConnect = false;
    for (const s of document.scripts) {
      const t = s.textContent || "";
      if (!t) continue;
      if (/clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy|ClipboardItem/.test(t)) usesClipboardWrite = true;
      if (/eth_requestAccounts|WalletConnect|window\.ethereum|solana\.connect|setApprovalForAll/.test(t)) hasWalletConnect = true;
      if (/clipboard|execCommand|terminal|powershell|osascript|curl |wget |base64|eth_|setApprovalForAll|permit|requestFullscreen|setInterval[\s\S]{0,60}alert|onbeforeunload|speechSynthesis|keydown|sendBeacon/i.test(t)) scripts.push(t.slice(0, 6000));
      if (scripts.length >= 12) break;
    }
    for (const el of document.querySelectorAll("[onclick], [onmousedown]")) {
      const a = el.getAttribute("onclick") || el.getAttribute("onmousedown") || "";
      if (/clipboard|execCommand/.test(a)) { usesClipboardWrite = true; scripts.push(a.slice(0, 1000)); }
    }
    if (window.__rampartClipboardSeen) usesClipboardWrite = true;
    const imageAlts = Array.from(document.images).slice(0, 40).map((i) => (i.alt || "") + " " + (i.src || "").split("/").pop()).filter(Boolean);
    const externalScriptHosts = Array.from(new Set(Array.from(document.scripts).map((s) => { try { return s.src ? new URL(s.src).hostname : null; } catch { return null; } }).filter(Boolean))).slice(0, 30);
    return {
      title: document.title || "", forms, usesClipboardWrite, overlayText: overlayText.trim().slice(0, 4000),
      visibleText: (document.body ? document.body.innerText || "" : "").slice(0, 12000), scriptSnippets: scripts, imageAlts, externalScriptHosts,
      hasWalletConnect, isTopFrame: true, isHTTPS: location.protocol === "https:",
    };
  }

  // MARK: Rendering

  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (k === "text") e.textContent = v; else e.setAttribute(k, v); }
    for (const c of children || []) e.appendChild(c);
    return e;
  }
  function removeUI() { for (const n of document.querySelectorAll(".rampart-root")) n.remove(); document.documentElement.classList.remove("rampart-locked"); }

  function showInterstitial(resp) {
    if (shownLevel === "block" || userContinued) return;
    removeUI(); shownLevel = "block";
    const host = (() => { try { return new URL(PAGE_URL).hostname; } catch { return PAGE_URL; } })();
    const reasons = (resp.reasons || []).slice(0, 5);
    const root = el("div", { class: "rampart-root rampart-interstitial", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "rampart-title" }, [
      el("div", { class: "rampart-card" }, [
        el("div", { class: "rampart-badge", text: "RamPart" }),
        el("h1", { id: "rampart-title", text: "This page looks like a scam" }),
        el("p", { class: "rampart-headline", text: resp.headline || "RamPart found strong signs that this page is trying to trick you." }),
        el("p", { class: "rampart-host" }, [el("span", { text: "Address: " }), el("code", { text: host })]),
        el("ul", { class: "rampart-reasons" }, reasons.map((r) => el("li", {}, [el("strong", { text: r.title }), el("span", { text: " " + (r.detail || "") })]))),
        el("div", { class: "rampart-actions" }, [
          el("button", { class: "rampart-primary", id: "rampart-back", text: "Go back" }),
          el("button", { class: "rampart-secondary", id: "rampart-continue", text: "Continue anyway" }),
        ]),
        el("p", { class: "rampart-foot", text: resp.fallback ? "Checked with the extension's built-in rules. Open RamPart on your Mac for the full engine." : "Checked by RamPart on your Mac. Nothing about this page was sent to the cloud." }),
      ]),
    ]);
    document.documentElement.appendChild(root);
    document.documentElement.classList.add("rampart-locked");
    root.querySelector("#rampart-back").focus();
    root.querySelector("#rampart-back").onclick = () => { api.runtime.sendMessage({ type: "decision", url: PAGE_URL, decision: "wentBack" }); if (history.length > 1) history.back(); else location.replace("about:blank"); };
    root.querySelector("#rampart-continue").onclick = () => { userContinued = true; api.runtime.sendMessage({ type: "decision", url: PAGE_URL, decision: "continued" }); removeUI(); showBanner(resp, true); };
  }

  function showBanner(resp, afterContinue) {
    if (shownLevel === "warn" && !afterContinue) return;
    if (!afterContinue) removeUI();
    shownLevel = afterContinue ? "block" : "warn";
    const host = (() => { try { return new URL(PAGE_URL).hostname; } catch { return ""; } })();
    const top = (resp.reasons || [])[0];
    const bar = el("div", { class: "rampart-root rampart-banner" + (afterContinue ? " rampart-banner-danger" : ""), role: "status" }, [
      el("span", { class: "rampart-badge", text: "RamPart" }),
      el("span", { class: "rampart-banner-text", text: afterContinue ? "You chose to continue on a page RamPart thinks is a scam. Don't enter passwords or payment details here." : (resp.headline || "This page has some warning signs.") + (top ? " " + top.title + "." : "") }),
      el("button", { class: "rampart-link", id: "rampart-why", text: "Why?" }),
      el("button", { class: "rampart-link", id: "rampart-trust", text: "Don't warn for " + host }),
      el("button", { class: "rampart-close", id: "rampart-dismiss", "aria-label": "Dismiss", text: "×" }),
    ]);
    document.documentElement.appendChild(bar);
    bar.querySelector("#rampart-dismiss").onclick = () => { bar.remove(); api.runtime.sendMessage({ type: "decision", url: PAGE_URL, decision: "dismissedBanner" }); };
    bar.querySelector("#rampart-trust").onclick = () => { api.runtime.sendMessage({ type: "allowHost", host }); bar.remove(); };
    bar.querySelector("#rampart-why").onclick = () => {
      const list = el("ul", { class: "rampart-reasons rampart-banner-reasons" }, (resp.reasons || []).slice(0, 5).map((r) => el("li", {}, [el("strong", { text: r.title }), el("span", { text: " " + (r.detail || "") })])));
      bar.appendChild(list); bar.querySelector("#rampart-why").remove();
    };
  }

  function showClipboardWarning(resp, text, onCopyAnyway) {
    const existing = document.querySelector(".rampart-clip"); if (existing) existing.remove();
    const top = (resp.reasons || [])[0] || {};
    const box = el("div", { class: "rampart-root rampart-clip", role: "alertdialog" }, [
      el("div", { class: "rampart-card rampart-card-small" }, [
        el("div", { class: "rampart-badge", text: "RamPart" }),
        el("h2", { text: top.title || "This site copied a command to your clipboard" }),
        el("p", { text: top.detail || "Pasting it into Terminal would run it with your permissions." }),
        el("pre", { class: "rampart-cmd", text: String(text).slice(0, 400) }),
        el("div", { class: "rampart-actions" }, [
          el("button", { class: "rampart-primary", id: "rampart-clip-block", text: "Don't copy" }),
          el("button", { class: "rampart-secondary", id: "rampart-clip-allow", text: "Copy anyway" }),
        ]),
      ]),
    ]);
    document.documentElement.appendChild(box);
    box.querySelector("#rampart-clip-block").onclick = () => box.remove();
    box.querySelector("#rampart-clip-allow").onclick = () => { box.remove(); onCopyAnyway && onCopyAnyway(); };
  }

  function applyVerdict(resp, stage) {
    if (!resp || !resp.ok || resp.disabled || resp.allowlisted) return;
    if (resp.action === "block") showInterstitial(resp);
    else if (resp.action === "warn" && stage !== "url-only") showBanner(resp, false);
  }

  // MARK: Clipboard interception

  async function screenClipboard(text, allowFn) {
    if (!text || text.length > 5000) return true;
    if (!H.looksLikeShellCommand(text)) return true;
    const resp = await api.runtime.sendMessage({ type: "checkClipboard", url: PAGE_URL, text }).catch(() => null);
    if (!resp || !resp.ok || resp.action === "allow") return true;
    showClipboardWarning(resp, text, allowFn);
    return false;
  }
  document.addEventListener("copy", (e) => {
    const sel = String(getSelection && getSelection() || "");
    if (!sel || !H.looksLikeShellCommand(sel) || H.isDeveloperHost(location.hostname)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    screenClipboard(sel, () => { navigator.clipboard && navigator.clipboard.writeText(sel).catch(() => {}); });
  }, true);
  // Programmatic writes are hooked in the MAIN world (shared/clipboard-main.js) and relayed here.
  window.addEventListener("message", (e) => {
    if (e.source !== window || !e.data || e.data.__rampart !== "clipboardWrite") return;
    window.__rampartClipboardSeen = true;
    const text = String(e.data.text || "");
    if (!H.looksLikeShellCommand(text) || H.isDeveloperHost(location.hostname)) { window.postMessage({ __rampart: "clipboardDecision", id: e.data.id, allow: true }, "*"); return; }
    screenClipboard(text, () => window.postMessage({ __rampart: "clipboardDecision", id: e.data.id, allow: true }, "*")).then((ok) => { if (ok) window.postMessage({ __rampart: "clipboardDecision", id: e.data.id, allow: true }, "*"); else window.postMessage({ __rampart: "clipboardDecision", id: e.data.id, allow: false, pending: true }, "*"); });
  });

  // MARK: Flow

  api.runtime.onMessage.addListener((msg) => { if (msg && msg.type === "verdict") applyVerdict(msg.resp, msg.stage); });

  async function run() {
    // 1. Early URL verdict from the navigation hook (may already be cached).
    const early = await api.runtime.sendMessage({ type: "urlVerdict", url: PAGE_URL }).catch(() => null);
    if (early) applyVerdict(early, "url");
    // 2. Full page check with signals; repeat once after late-loading overlays appear.
    const check = async () => {
      const signals = collectSignals();
      const tamper = globalThis.RampartTamper ? globalThis.RampartTamper.drain() : [];
      const resp = await api.runtime.sendMessage({ type: "checkPage", url: PAGE_URL, signals, tamper }).catch(() => null);
      applyVerdict(resp, "page");
      return resp;
    };
    await check();
    setTimeout(check, 2500);
    // Re-check when a big overlay is injected later (ClickFix pages often render on click).
    let scheduled = false;
    const mo = new MutationObserver(() => { if (scheduled || shownLevel === "block") return; scheduled = true; setTimeout(() => { scheduled = false; check(); }, 1200); });
    mo.observe(document.body || document.documentElement, { childList: true, subtree: true });
    setTimeout(() => mo.disconnect(), 60000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run); else run();
})();
