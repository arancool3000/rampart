// RamPart Web Protection: content script (isolated world). Collects page signals, asks the
// background for a verdict, and renders the calm interstitial / banner. Also intercepts
// copy-to-clipboard of shell commands on non-developer sites.
(() => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  if (window.top !== window) return;
  // Run-once guard lives in the isolated world. (It used to be a data-rampart-ready attribute on
  // <html>, which a page could pre-set in its own markup to switch RamPart off.)
  if (globalThis.__rampartContentLoaded) return;
  globalThis.__rampartContentLoaded = true;

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
    // Installer links and the main heading (fake-update / fake-download rules, W-X6-1).
    const downloadLinks = [];
    for (const a of document.querySelectorAll("a[href]")) {
      if (downloadLinks.length >= 30) break;
      try { const u = new URL(a.href, location.href); if (/\.(dmg|pkg|mpkg|zip|app|iso)$/i.test(u.pathname)) downloadLinks.push(u.href.slice(0, 500)); } catch {}
    }
    const h1 = ((document.querySelector("h1") || {}).innerText || "").slice(0, 200);
    return {
      title: document.title || "", h1, downloadLinks, forms, usesClipboardWrite, overlayText: overlayText.trim().slice(0, 4000),
      visibleText: (document.body ? document.body.innerText || "" : "").slice(0, 12000), scriptSnippets: scripts, imageAlts, externalScriptHosts,
      hasWalletConnect, isTopFrame: true, isHTTPS: location.protocol === "https:",
    };
  }

  // MARK: Rendering (N1, harden-hx6)
  // Every RamPart surface lives in a CLOSED shadow root on a host element with a random tag name, so
  // page scripts can't find, read, restyle or click our buttons (querySelector, .shadowRoot and
  // innerText all stop at the host). Every handler also drops synthetic events (!e.isTrusted) and
  // clicks that land in the first 500 ms (a click-through trick), and Trust/Continue are confirmed by
  // the service worker, which checks the request came from our content script for this tab's host.
  // Honest limit: the host element is still in the page's DOM, so a page can remove or hide it. For a
  // block, the watchdog then moves the tab to RamPart's own extension page, which the site can't touch.

  const CSS = `
:host { all: initial !important; }
*, *::before, *::after { box-sizing: border-box; font-family: -apple-system, "SF Pro Text", "Helvetica Neue", Helvetica, Arial, sans-serif; }
.root { color: #0d1b2a; }
.interstitial { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; padding: 24px; overflow: auto;
  background: radial-gradient(1200px 800px at 70% 20%, #0a2a3a 0%, #071320 60%, #050b14 100%); }
.card { width: min(560px, 100%); background: rgba(255,255,255,0.96); border-radius: 18px; padding: 28px 30px; box-shadow: 0 30px 80px rgba(0,0,0,0.45); border: 1px solid rgba(255,255,255,0.4); }
.card-small { width: min(440px, 100%); }
.badge { display: inline-block; font-size: 11px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #0a84a0; background: rgba(10,132,160,0.12); padding: 3px 9px; border-radius: 999px; margin-bottom: 14px; }
h1 { font-size: 24px; font-weight: 700; margin: 0 0 8px; line-height: 1.2; color: #0d1b2a; }
h2 { font-size: 18px; font-weight: 700; margin: 0 0 6px; color: #0d1b2a; }
p { font-size: 15px; line-height: 1.45; margin: 0 0 10px; color: #2c3e50; }
.host code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 13px; background: #eef3f6; padding: 2px 6px; border-radius: 6px; color: #a33; }
.reasons { margin: 12px 0 18px; padding: 0 0 0 18px; }
.reasons li { font-size: 14px; line-height: 1.4; margin: 0 0 8px; color: #2c3e50; }
.reasons strong { color: #0d1b2a; font-weight: 600; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 6px; }
button { cursor: pointer; font: 600 14px -apple-system, "Helvetica Neue", Arial, sans-serif; border-radius: 999px; padding: 9px 18px; border: 0; }
.primary { background: linear-gradient(180deg, #17b8cc, #0a84a0); color: #fff; box-shadow: 0 6px 18px rgba(10,132,160,0.35); }
.secondary { background: #eef3f6; color: #2c3e50; }
.primary:focus-visible, .secondary:focus-visible, .link:focus-visible, .close:focus-visible { outline: 3px solid rgba(23,184,204,0.5); }
.foot { font-size: 12px; color: #6c7a89; margin-top: 14px; }
.banner { display: flex; align-items: center; gap: 12px; flex-wrap: wrap; padding: 10px 16px; background: #fff6df; color: #4a3b00; border-bottom: 1px solid #f0d890; box-shadow: 0 4px 16px rgba(0,0,0,0.12); font-size: 14px; }
.banner-danger { background: #ffe9e6; border-bottom-color: #f3b8b0; color: #5a1a12; }
.banner .badge { margin: 0; }
.banner-text { flex: 1 1 320px; line-height: 1.35; }
.link { background: transparent; color: #0a84a0; padding: 4px 8px; text-decoration: underline; }
.close { background: transparent; font-size: 20px; line-height: 1; padding: 0 6px; color: inherit; }
.banner-reasons { flex-basis: 100%; margin: 4px 0 0; }
.clip { position: fixed; inset: 0; display: flex; align-items: center; justify-content: center; background: rgba(5,11,20,0.55); padding: 24px; }
.cmd { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 12px; background: #0d1b2a; color: #ffd166; padding: 10px 12px; border-radius: 10px; white-space: pre-wrap; word-break: break-all; max-height: 140px; overflow: auto; margin: 8px 0 14px; }
@media (prefers-color-scheme: dark) {
  .card { background: rgba(18,28,40,0.98); border-color: rgba(255,255,255,0.12); }
  h1, h2, .reasons strong { color: #f2f6f9; }
  p, .reasons li { color: #c7d1db; }
  .host code { background: #1e2b3a; color: #ff8a80; }
  .secondary { background: #243447; color: #e6edf3; }
}
@media (prefers-reduced-motion: no-preference) { .card { animation: in 240ms ease-out; } @keyframes in { from { opacity: 0; transform: translateY(8px) scale(0.98); } to { opacity: 1; transform: none; } } }
`;

  function randomTag() {
    const b = new Uint8Array(12); crypto.getRandomValues(b);
    const letters = Array.from(b, (x) => String.fromCharCode(97 + (x % 26))).join("");
    return letters.slice(0, 5) + "-" + letters.slice(5);
  }
  const HOST_STYLE = {
    full: "position: fixed !important; inset: 0 !important; width: 100vw !important; height: 100vh !important; max-width: none !important; max-height: none !important;",
    banner: "position: fixed !important; top: 0 !important; left: 0 !important; right: 0 !important; bottom: auto !important; width: 100% !important; height: auto !important; max-width: none !important;",
  };
  const BASE_STYLE = "all: initial !important; display: block !important; visibility: visible !important; opacity: 1 !important; pointer-events: auto !important; z-index: 2147483647 !important; margin: 0 !important; padding: 0 !important; border: 0 !important; background: transparent !important; overflow: visible !important; transform: none !important; filter: none !important; clip-path: none !important;";

  const surfaces = new Set();   // live UI mounts
  /** Mount a closed-shadow surface. kind: "full" | "banner". Uses the top layer (popover) when available. */
  function mount(kind) {
    const host = document.createElement(randomTag());
    host.setAttribute("style", BASE_STYLE + HOST_STYLE[kind]);
    const usePopover = typeof host.showPopover === "function";
    if (usePopover) host.setAttribute("popover", "manual");
    const root = host.attachShadow({ mode: "closed" });
    const style = document.createElement("style"); style.textContent = CSS; root.appendChild(style);
    const m = { host, root, kind, usePopover, shownAt: performance.now() };
    m.attach = () => {
      document.documentElement.appendChild(host);
      if (usePopover) { try { host.showPopover(); } catch {} }
      m.shownAt = performance.now();
    };
    m.remove = () => { surfaces.delete(m); try { if (usePopover) host.hidePopover(); } catch {} host.remove(); };
    m.intact = () => {
      if (!host.isConnected) return false;
      if (usePopover) { try { if (!host.matches(":popover-open")) return false; } catch {} }
      const cs = getComputedStyle(host);
      if (cs.display === "none" || cs.visibility !== "visible" || Number(cs.opacity) < 0.95) return false;
      if (kind === "full") { const r = host.getBoundingClientRect(); if (r.width < innerWidth * 0.9 || r.height < innerHeight * 0.9) return false; }
      return true;
    };
    surfaces.add(m);
    return m;
  }
  function el(tag, attrs, children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) { if (k === "text") e.textContent = v; else e.setAttribute(k, v); }
    for (const c of children || []) e.appendChild(c);
    return e;
  }
  // wms-o3 (clickjacking): the top layer is ordered by insertion, so a page could open its own popover,
  // modal dialog or fullscreen element AFTER our warning, give it pointer-events:none and draw a fake
  // "Go back" label over our "Continue anyway". We note every foreign top-layer change (toggle and
  // fullscreenchange are seen in the capture phase), put our surfaces back on top, and ignore clicks
  // until they have been on top again for 500 ms (H.uiClickAllowed).
  let lastForeignTopLayerAt = -1;
  const isOurs = (n) => { for (const m of surfaces) if (m.host === n) return true; return false; };
  function foreignTopLayer() {
    try { for (const n of document.querySelectorAll(":popover-open, :modal, :fullscreen")) if (!isOurs(n)) return true; } catch {}
    return !!(document.fullscreenElement && !isOurs(document.fullscreenElement));
  }
  function raiseSurfaces() {
    for (const m of surfaces) {
      if (!m.usePopover || !m.host.isConnected) continue;
      try { m.host.hidePopover(); m.host.showPopover(); } catch {}
      m.shownAt = performance.now();
    }
  }
  function onForeignTopLayer(e) {
    if (!surfaces.size || (e && (isOurs(e.target) || !foreignTopLayer()))) return;   // <details> toggles etc. don't count
    lastForeignTopLayerAt = performance.now();
    if (document.fullscreenElement && !isOurs(document.fullscreenElement)) { try { document.exitFullscreen(); } catch {} }
    raiseSurfaces();
  }
  for (const t of ["toggle", "fullscreenchange", "webkitfullscreenchange"]) document.addEventListener(t, onForeignTopLayer, true);
  /** Click handler that ignores synthetic events, clicks in the first 500 ms after the UI appeared or was
   *  raised again, and clicks while something of the page's may sit above it. */
  function onTrusted(m, button, fn) {
    button.addEventListener("click", (e) => {
      e.stopPropagation();
      if (!e.isTrusted) return;
      const now = performance.now();
      if (!H.uiClickAllowed(now, m.shownAt, lastForeignTopLayerAt)) return;
      if (m.usePopover && foreignTopLayer()) { lastForeignTopLayerAt = now; raiseSurfaces(); return; }
      fn(e);
    });
  }
  // Scroll lock while the block is up: an inline style set only then (wms-o3; a manifest stylesheet in
  // every page let any site detect RamPart).
  let savedOverflow = null;
  function lockScroll() {
    const st = document.documentElement.style;
    if (savedOverflow === null) savedOverflow = [st.getPropertyValue("overflow"), st.getPropertyPriority("overflow")];
    st.setProperty("overflow", "hidden", "important");
  }
  function unlockScroll() {
    if (savedOverflow === null) return;
    const st = document.documentElement.style;
    if (savedOverflow[0]) st.setProperty("overflow", savedOverflow[0], savedOverflow[1]); else st.removeProperty("overflow");
    savedOverflow = null;
  }
  function removeUI() { for (const m of Array.from(surfaces)) if (m.kind !== "clip") m.remove(); unlockScroll(); stopWatchdog(); }
  const send = (msg) => api.runtime.sendMessage(msg).catch(() => null);

  // Watchdog: if the page removes or hides a RamPart surface, put it back (banner, 3 times), or move
  // the tab to the extension's own interstitial page (block).
  let watchdog = null;
  function startWatchdog() {
    if (watchdog) return;
    let banners = 0;
    let foreignSeen = false;
    watchdog = setInterval(() => {
      const f = foreignTopLayer();
      if (f && !foreignSeen) onForeignTopLayer(null);   // newly appeared: raise once (not every tick, so a site's own open dialog can't lock our buttons)
      foreignSeen = f;
      for (const m of Array.from(surfaces)) {
        if (m.intact()) continue;
        if (m.kind === "full" && shownLevel === "block" && !userContinued) { stopWatchdog(); send({ type: "openInterstitial" }); return; }
        if (m.kind === "banner" && banners++ < 3) { m.host.setAttribute("style", BASE_STYLE + HOST_STYLE.banner); m.attach(); }
      }
    }, 750);
  }
  function stopWatchdog() { if (watchdog) { clearInterval(watchdog); watchdog = null; } }

  function reasonList(cls, reasons) {
    return el("ul", { class: cls }, (reasons || []).slice(0, 5).map((r) => el("li", {}, [el("strong", { text: String((r && r.title) || "") }), el("span", { text: " " + String((r && r.detail) || "") })])));
  }

  function showInterstitial(resp) {
    if (shownLevel === "block" || userContinued) return;
    removeUI(); shownLevel = "block";
    const host = (() => { try { return new URL(PAGE_URL).hostname; } catch { return PAGE_URL; } })();
    const m = mount("full");
    const back = el("button", { class: "primary", text: "Go back" });
    const cont = el("button", { class: "secondary", text: "Continue anyway" });
    m.root.appendChild(el("div", { class: "root interstitial", role: "alertdialog", "aria-modal": "true", "aria-label": "RamPart: this page looks like a scam" }, [
      el("div", { class: "card" }, [
        el("div", { class: "badge", text: "RamPart" }),
        el("h1", { text: "This page looks like a scam" }),
        el("p", { class: "headline", text: resp.headline || "RamPart found strong signs that this page is trying to trick you." }),
        el("p", { class: "host" }, [el("span", { text: "Address: " }), el("code", { text: host })]),
        reasonList("reasons", resp.reasons),
        el("div", { class: "actions" }, [back, cont]),
        el("p", { class: "foot", text: resp.fallback ? "Checked with the extension's built-in rules. Open RamPart on your Mac for the full engine." : "Checked by RamPart on your Mac. Nothing about this page was sent to the cloud." }),
      ]),
    ]));
    m.attach();
    lockScroll();
    if (document.fullscreenElement) { try { document.exitFullscreen(); } catch {} }   // wms-o3: nothing of the page's above the warning
    back.focus();
    onTrusted(m, back, () => { send({ type: "decision", decision: "wentBack" }); if (history.length > 1) history.back(); else location.replace("about:blank"); });
    onTrusted(m, cont, async () => {
      const ok = await send({ type: "continueSite" });
      if (!ok || !ok.ok) return;
      userContinued = true; removeUI(); showBanner(resp, true);
    });
    startWatchdog();
  }

  function showBanner(resp, afterContinue) {
    if (shownLevel === "warn" && !afterContinue) return;
    if (!afterContinue) removeUI();
    shownLevel = afterContinue ? "block" : "warn";
    const host = (() => { try { return new URL(PAGE_URL).hostname; } catch { return ""; } })();
    const top = (resp.reasons || [])[0];
    const m = mount("banner");
    const why = el("button", { class: "link", text: "Why?" });
    const trust = el("button", { class: "link", text: "Don't warn for " + host });
    const dismiss = el("button", { class: "close", "aria-label": "Dismiss", text: "×" });
    const bar = el("div", { class: "root banner" + (afterContinue ? " banner-danger" : ""), role: "status" }, [
      el("span", { class: "badge", text: "RamPart" }),
      el("span", { class: "banner-text", text: afterContinue ? "You chose to continue on a page RamPart thinks is a scam. Don't enter passwords or payment details here." : (resp.headline || "This page has some warning signs.") + (top && top.title ? " " + top.title + "." : "") }),
      why, trust, dismiss,
    ]);
    m.root.appendChild(bar);
    m.attach();
    onTrusted(m, dismiss, () => { m.remove(); send({ type: "decision", decision: "dismissedBanner" }); });
    onTrusted(m, trust, async () => { const ok = await send({ type: "allowHost", host }); if (ok && ok.ok) m.remove(); });
    onTrusted(m, why, () => { bar.appendChild(reasonList("reasons banner-reasons", resp.reasons)); why.remove(); });
    startWatchdog();
  }

  let clipSurface = null;
  function showClipboardWarning(resp, text, onCopyAnyway, onDontCopy) {
    if (clipSurface) clipSurface.remove();
    const top = (resp.reasons || [])[0] || {};
    const m = mount("full"); m.kind = "clip"; clipSurface = m;
    const block = el("button", { class: "primary", text: "Don't copy" });
    const allow = el("button", { class: "secondary", text: "Copy anyway" });
    m.root.appendChild(el("div", { class: "root clip", role: "alertdialog", "aria-label": "RamPart clipboard warning" }, [
      el("div", { class: "card card-small" }, [
        el("div", { class: "badge", text: "RamPart" }),
        el("h2", { text: top.title || "This site copied a command to your clipboard" }),
        el("p", { text: top.detail || "Pasting it into Terminal would run it with your permissions." }),
        el("pre", { class: "cmd", text: String(text).slice(0, 400) }),
        el("div", { class: "actions" }, [block, allow]),
      ]),
    ]));
    m.attach();
    block.focus();
    onTrusted(m, block, () => { m.remove(); clipSurface = null; onDontCopy && onDontCopy(); });
    onTrusted(m, allow, () => { m.remove(); clipSurface = null; onCopyAnyway && onCopyAnyway(); });
  }

  function applyVerdict(resp, stage) {
    if (!resp || !resp.ok || resp.disabled || resp.allowlisted) return;
    if (resp.action === "block") { if (resp.continued) { userContinued = true; if (!surfaces.size) showBanner(resp, true); } else showInterstitial(resp); }
    else if (resp.action === "warn" && stage !== "url-only") showBanner(resp, false);
  }

  // MARK: Clipboard interception

  async function screenClipboard(text, allowFn, denyFn) {
    if (!text || text.length > 5000) return true;
    if (!H.looksLikeShellCommand(text)) return true;
    const resp = await send({ type: "checkClipboard", text });
    if (!resp || !resp.ok || resp.action === "allow") return true;
    showClipboardWarning(resp, text, allowFn, denyFn);
    return false;
  }
  document.addEventListener("copy", (e) => {
    const sel = String(getSelection && getSelection() || "");
    if (!sel || !H.looksLikeShellCommand(sel) || H.isDeveloperHost(location.hostname)) return;
    e.preventDefault(); e.stopImmediatePropagation();
    screenClipboard(sel, () => { navigator.clipboard && navigator.clipboard.writeText(sel).catch(() => {}); });
  }, true);

  // Programmatic writes are hooked in the MAIN world (shared/clipboard-main.js) and reach us over a
  // private MessageChannel (shared/clipboard-bridge.js), never through window messages (N4).
  // Fallback for browsers whose manifest doesn't load the bridge at document_start yet (Safari, needs
  // owner): same code, installed late, so a page that forges the handshake first can bypass screening.
  function lateBridge() {
    const bytes = new Uint8Array(16); crypto.getRandomValues(bytes);
    const nonce = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
    const ch = new MessageChannel(); const queue = []; let handler = null;
    ch.port1.onmessage = (m) => {
      const d = m.data;
      if (!d || typeof d !== "object" || d.nonce !== nonce || d.type !== "clipboardWrite") return;
      if (typeof d.id !== "number" || !Number.isSafeInteger(d.id) || typeof d.text !== "string") return;
      const msg = { id: d.id, text: d.text.slice(0, 5000), sync: d.sync === true };
      if (handler) handler(msg); else if (queue.length < 50) queue.push(msg);
    };
    window.postMessage({ __rampartBridge: true, nonce }, "*", [ch.port2]);
    return { onWrite(fn) { handler = fn; for (const m of queue.splice(0)) fn(m); },
             decide(id, allow, pending) { try { ch.port1.postMessage({ type: "clipboardDecision", nonce, id, allow: allow === true, pending: pending === true }); } catch {} } };
  }
  const bridge = globalThis.RampartClipboardBridge || lateBridge();
  bridge.onWrite((w) => {
    window.__rampartClipboardSeen = true;
    const text = w.text;
    if (w.sync) return;   // execCommand("copy"): the capture-phase copy handler above decides
    if (!H.looksLikeShellCommand(text) || H.isDeveloperHost(location.hostname)) { bridge.decide(w.id, true); return; }
    screenClipboard(text, () => bridge.decide(w.id, true), () => bridge.decide(w.id, false))
      .then((ok) => { if (ok) bridge.decide(w.id, true); else bridge.decide(w.id, false, true); });
  });

  // MARK: Flow

  api.runtime.onMessage.addListener((msg, sender) => {
    if (!sender || sender.id !== api.runtime.id || sender.tab) return;   // only the service worker
    if (msg && msg.type === "verdict") applyVerdict(msg.resp, msg.stage);
  });

  async function run() {
    // 1. Early URL verdict from the navigation hook (may already be cached).
    const early = await send({ type: "urlVerdict" });
    if (early) applyVerdict(early, "url");
    // 2. Full page check with signals; repeat once after late-loading overlays appear.
    const check = async () => {
      const signals = collectSignals();
      const tamper = globalThis.RampartTamper ? globalThis.RampartTamper.drain() : [];
      const resp = await send({ type: "checkPage", signals, tamper });
      applyVerdict(resp, "page");
      return resp;
    };
    await check();
    setTimeout(check, 2500);
    // Per-site tracker count (popup): third-party hosts this page loaded, classified by RamPart's tracker list.
    if (window.top === window) setTimeout(() => {
      try {
        const hosts = Array.from(new Set(performance.getEntriesByType("resource").map((e) => { try { return new URL(e.name).hostname; } catch { return ""; } })
          .filter((h) => h && h !== location.hostname))).slice(0, 300);
        if (hosts.length) send({ type: "countTrackers", hosts });
      } catch { /* ignore */ }
    }, 4000);
    // Re-check when a big overlay is injected later (ClickFix pages often render on click).
    let scheduled = false;
    const mo = new MutationObserver(() => { if (scheduled || shownLevel === "block") return; scheduled = true; setTimeout(() => { scheduled = false; check(); }, 1200); });
    mo.observe(document.body || document.documentElement, { childList: true, subtree: true });
    setTimeout(() => mo.disconnect(), 60000);
  }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", run); else run();
})();
