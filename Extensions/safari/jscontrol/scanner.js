// Scanner injected by RamPart in "Safari JavaScript control" mode (Develop › Allow JavaScript from
// Apple Events). Runs via `do JavaScript` and RETURNS a JSON string: {url, signals, tamper}. The app
// feeds it to WebVerdictService as a checkPage request. Idempotent: installs its tamper observer once
// and drains observations on each call. Must not depend on extension APIs.
(function () {
  const W = window;
  if (!W.__rampartTamper) {
    const findings = [], seen = new Set();
    const note = (s) => { if (findings.length < 40 && !seen.has(s)) { seen.add(s); findings.push(s); } };
    const isNative = (f) => { try { return typeof f === "function" && /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(f)); } catch { return false; } };
    const probes = {
      fetch: () => isNative(W.fetch), xhrOpen: () => isNative(XMLHttpRequest.prototype.open), xhrSend: () => isNative(XMLHttpRequest.prototype.send),
      formSubmit: () => isNative(HTMLFormElement.prototype.submit), clipboardWrite: () => !navigator.clipboard || isNative(navigator.clipboard.writeText),
      inputValue: () => { const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value"); return !d || isNative(d.get); },
      addEventListener: () => isNative(EventTarget.prototype.addEventListener),
    };
    const baseline = {}; for (const k in probes) baseline[k] = probes[k]();
    for (const k in probes) if (!baseline[k]) note(k + " is not native code at first scan");
    const recheck = () => { for (const k in probes) { const now = probes[k](); if (baseline[k] && !now) { note(k + " was overridden after load"); baseline[k] = now; } } };
    const t0 = Date.now();
    const origAdd = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, fn, opts) {
      try { if (/^key(down|up|press)$|^input$/.test(type) && this instanceof HTMLInputElement && this.type === "password" && Date.now() - t0 > 1500) note("keystroke listener (" + type + ") added to a password field after load"); } catch {}
      return origAdd.call(this, type, fn, opts);
    };
    const mo = new MutationObserver((muts) => {
      for (const m of muts) {
        for (const n of m.addedNodes) {
          if (n.nodeType !== 1) continue;
          if (n.tagName === "SCRIPT" && Date.now() - t0 > 1500) { let src = "inline"; try { if (n.src) src = new URL(n.src).hostname; } catch {} if (src === "inline" || src !== location.hostname) note("new " + (src === "inline" ? "inline <script>" : "<script> from " + src) + " added after load"); }
          if (n.tagName === "IFRAME") { const cs = getComputedStyle(n), r = n.getBoundingClientRect(); if (cs.display === "none" || cs.visibility === "hidden" || cs.opacity === "0" || (r.width <= 2 && r.height <= 2)) note("hidden iframe added"); }
          if (n.querySelectorAll) for (const el of n.querySelectorAll("[onsubmit],[onkeydown],[onkeyup],[onkeypress],[oninput]")) note("inline handler added after load");
        }
        if (m.type === "attributes") note("inline handler " + m.attributeName + " set after load");
      }
      recheck();
    });
    mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["onsubmit", "onkeydown", "onkeyup", "onkeypress", "oninput"] });
    setInterval(recheck, 5000);
    W.__rampartTamper = { drain: () => findings.splice(0) };
  }
  const forms = Array.from(document.forms).slice(0, 20).map((f) => {
    const inputs = Array.from(f.querySelectorAll("input"));
    const names = inputs.map((i) => ((i.name || "") + " " + (i.id || "") + " " + (i.autocomplete || "") + " " + (i.placeholder || "")).toLowerCase());
    let action = null; try { action = new URL(f.getAttribute("action") || "", location.href).href; } catch {}
    return { action, hasPassword: inputs.some((i) => i.type === "password"), hasEmailOrUser: inputs.some((i, k) => i.type === "email" || /user|login|email|account/.test(names[k])),
             hasCardNumber: names.some((n) => /card|cc-number|cardnumber|cvv|cvc/.test(n)), hasOTP: names.some((n) => /otp|one-time|onetime|totp|2fa|verification.?code/.test(n)) || inputs.some((i) => i.autocomplete === "one-time-code") };
  });
  let overlayText = "";
  for (const el of document.querySelectorAll("div, section, dialog, main, form")) {
    if (overlayText.length > 4000) break;
    const cs = getComputedStyle(el); if (cs.position !== "fixed" && cs.position !== "absolute" && el.tagName !== "DIALOG") continue;
    const r = el.getBoundingClientRect(); if (r.width >= innerWidth * 0.6 && r.height >= innerHeight * 0.6) overlayText += " " + (el.innerText || "").slice(0, 2000);
  }
  const scripts = []; let usesClipboardWrite = false, hasWalletConnect = false;
  for (const s of document.scripts) { const t = s.textContent || ""; if (!t) continue;
    if (/clipboard\s*\.\s*writeText|execCommand\s*\(\s*["']copy|ClipboardItem/.test(t)) usesClipboardWrite = true;
    if (/eth_requestAccounts|WalletConnect|window\.ethereum|solana\.connect|setApprovalForAll/.test(t)) hasWalletConnect = true;
    if (/clipboard|execCommand|terminal|powershell|osascript|curl |wget |base64|eth_|setApprovalForAll|permit|requestFullscreen|setInterval[\s\S]{0,60}alert|onbeforeunload|speechSynthesis|keydown|sendBeacon/i.test(t)) scripts.push(t.slice(0, 6000));
    if (scripts.length >= 12) break; }
  for (const el of document.querySelectorAll("[onclick],[onmousedown]")) { const a = el.getAttribute("onclick") || el.getAttribute("onmousedown") || ""; if (/clipboard|execCommand/.test(a)) { usesClipboardWrite = true; scripts.push(a.slice(0, 1000)); } }
  const signals = { title: document.title || "", forms, usesClipboardWrite, overlayText: overlayText.trim().slice(0, 4000), visibleText: (document.body ? document.body.innerText || "" : "").slice(0, 12000),
    scriptSnippets: scripts, imageAlts: Array.from(document.images).slice(0, 40).map((i) => (i.alt || "") + " " + (i.src || "").split("/").pop()).filter(Boolean),
    externalScriptHosts: Array.from(new Set(Array.from(document.scripts).map((s) => { try { return s.src ? new URL(s.src).hostname : null; } catch { return null; } }).filter(Boolean))).slice(0, 30),
    hasWalletConnect, isTopFrame: W.top === W, isHTTPS: location.protocol === "https:" };
  return JSON.stringify({ url: location.href, signals, tamper: W.__rampartTamper.drain() });
})();
