// Standalone interstitial page (used when a page can't host the in-page overlay, e.g. CSP-sandboxed documents).
// Opened as interstitial.html?u=<url>&r=<json reasons>.
const q = new URLSearchParams(location.search);
const url = q.get("u") || "";
try { document.getElementById("host").textContent = new URL(url).hostname; } catch { document.getElementById("host").textContent = url; }
if (q.get("h")) document.getElementById("headline").textContent = q.get("h");
try { for (const r of JSON.parse(q.get("r") || "[]")) { const li = document.createElement("li"); const b = document.createElement("strong"); b.textContent = r.title; li.appendChild(b); li.appendChild(document.createTextNode(" " + (r.detail || ""))); document.getElementById("reasons").appendChild(li); } } catch {}
document.getElementById("back").onclick = () => { if (history.length > 2) history.go(-2); else location.replace("about:blank"); };
document.getElementById("continue").onclick = () => { (typeof browser !== "undefined" ? browser : chrome).runtime.sendMessage({ type: "decision", url, decision: "continued" }); location.replace(url); };
