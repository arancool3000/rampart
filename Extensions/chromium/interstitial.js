// Standalone interstitial (N3, harden-hx6). The service worker sends the tab here when a page removes
// or hides RamPart's in-page warning. It never reads text from its URL: the fragment holds only an
// opaque token, and headline, host and reasons come from the service worker, which hands them out
// only to this page in the tab the token was issued for. It refuses to render inside a frame
// (frame-ancestors 'none' in the manifest CSP is the main guard; this is the backstop).
(() => {
  const api = typeof browser !== "undefined" ? browser : chrome;
  const card = document.getElementById("card");
  if (window.top !== window) { document.documentElement.textContent = ""; return; }
  const token = location.hash.slice(1);
  if (!/^[0-9a-f]{32}$/.test(token)) { card.hidden = true; return; }
  const $ = (id) => document.getElementById(id);
  const guard = (fn) => (e) => { if (!e.isTrusted) return; fn(e); };
  api.runtime.sendMessage({ type: "interstitialData", token }).then((d) => {
    if (!d || typeof d.host !== "string") { $("headline").textContent = "This warning has expired. Close this tab or go back."; $("continue").hidden = true; return; }
    $("host").textContent = d.host;
    if (d.headline) $("headline").textContent = d.headline;
    for (const r of Array.isArray(d.reasons) ? d.reasons : []) {
      const li = document.createElement("li"); const b = document.createElement("strong");
      b.textContent = String(r.title || ""); li.appendChild(b); li.appendChild(document.createTextNode(" " + String(r.detail || "")));
      $("reasons").appendChild(li);
    }
    if (d.fallback) $("foot").textContent = "Checked with the extension's built-in rules. Open RamPart on your Mac for the full engine.";
    $("continue").onclick = guard(() => api.runtime.sendMessage({ type: "interstitialContinue", token }).catch(() => {}));
  }).catch(() => { $("continue").hidden = true; });
  $("back").onclick = guard(() => {
    api.runtime.sendMessage({ type: "interstitialBack", token }).catch(() => {});
    if (history.length > 2) history.go(-2); else location.replace("about:blank");
  });
  $("back").focus();
})();
