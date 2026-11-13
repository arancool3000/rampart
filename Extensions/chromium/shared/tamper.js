// In-page tamper detection (best effort). Snapshots key APIs at load, then watches for script
// nodes, inline handlers, hidden iframes, API overrides and keystroke listeners on password
// fields added after load. Observations are drained by content.js and sent with each verdict
// request; the host only weighs them on credential/payment pages or when something else is
// scripting Safari (the "JavaScript from Apple Events" guard). Normal sites add scripts all the
// time, so on its own this never produces a warning.
(() => {
  if (globalThis.RampartTamper) return;
  const findings = [];
  const seen = new Set();
  function note(s) { if (findings.length < 40 && !seen.has(s)) { seen.add(s); findings.push(s); } }
  const isNative = (f) => { try { return typeof f === "function" && /\{\s*\[native code\]\s*\}/.test(Function.prototype.toString.call(f)); } catch { return false; } };

  // Snapshot: are these native right now? (In the isolated world they always are; we record the
  // page's view by probing via a MAIN-world property the clipboard hook can't fake.)
  const probes = {
    fetch: () => isNative(window.fetch),
    xhrOpen: () => isNative(XMLHttpRequest.prototype.open),
    xhrSend: () => isNative(XMLHttpRequest.prototype.send),
    formSubmit: () => isNative(HTMLFormElement.prototype.submit),
    clipboardWrite: () => !navigator.clipboard || isNative(navigator.clipboard.writeText),
    inputValue: () => { const d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value"); return !d || isNative(d.get); },
    addEventListener: () => isNative(EventTarget.prototype.addEventListener),
  };
  const baseline = {}; for (const k in probes) baseline[k] = probes[k]();
  function recheckAPIs() { for (const k in probes) { const now = probes[k](); if (baseline[k] && !now) { note(k + " was overridden after load"); baseline[k] = now; } } }

  const loadTime = Date.now();
  let scriptsAtLoad = new Set(Array.from(document.scripts));
  const mo = new MutationObserver((muts) => {
    for (const m of muts) {
      for (const n of m.addedNodes) {
        if (n.nodeType !== 1) continue;
        if (n.tagName === "SCRIPT" && !scriptsAtLoad.has(n) && Date.now() - loadTime > 1500) {
          const src = n.src ? (() => { try { return new URL(n.src).hostname; } catch { return "inline"; } })() : "inline";
          if (src === "inline" || src !== location.hostname) note("new " + (src === "inline" ? "inline <script>" : "<script> from " + src) + " added " + Math.round((Date.now() - loadTime) / 1000) + "s after load");
        }
        if (n.tagName === "IFRAME") {
          const cs = getComputedStyle(n); const r = n.getBoundingClientRect();
          if (cs.display === "none" || cs.visibility === "hidden" || cs.opacity === "0" || (r.width <= 2 && r.height <= 2)) note("hidden iframe added" + (n.src ? " (" + (() => { try { return new URL(n.src).hostname; } catch { return "?"; } })() + ")" : ""));
        }
        if (n.querySelectorAll) for (const el of n.querySelectorAll("[onsubmit],[onkeydown],[onkeyup],[onkeypress],[oninput]")) note("inline handler " + Array.from(el.attributes).find((a) => a.name.startsWith("on")).name + " added after load");
      }
      if (m.type === "attributes" && /^on(submit|key|input)/.test(m.attributeName)) note("inline handler " + m.attributeName + " set after load");
    }
    recheckAPIs();
  });
  const start = () => mo.observe(document.documentElement, { childList: true, subtree: true, attributes: true, attributeFilter: ["onsubmit", "onkeydown", "onkeyup", "onkeypress", "oninput"] });
  if (document.documentElement) start(); else document.addEventListener("DOMContentLoaded", start);

  // (A window "message" listener for page-world tamper notes used to live here. Nothing sent
  // them and any page could forge them, so it was removed: harden-hx6 N4.)
  setInterval(recheckAPIs, 5000);

  globalThis.RampartTamper = { drain: () => { const out = findings.slice(); findings.length = 0; return out; }, peek: () => findings.slice() };
})();
