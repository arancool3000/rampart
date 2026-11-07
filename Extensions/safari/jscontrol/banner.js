// Injected after a non-safe verdict in JavaScript-control mode. Placeholders (double-underscore names
// below) are filled by the app: LEVEL ("block"|"warn"), HEADLINE, REASONS (JSON array of {title, detail}),
// EXPECTED_URL (the URL Safari reported for the scanned tab). Filled in one pass by
// SafariJSControlScript.fillBanner. hx6: draws nothing unless this tab is still on the judged page.
(function () {
  const expected = __EXPECTED_URL__;
  const strip = (u) => String(u).split("#")[0];
  if (strip(location.href) !== strip(expected)) return;
  if (document.getElementById("rampart-jsc")) return;
  const level = "__LEVEL__", headline = __HEADLINE__, reasons = __REASONS__;
  const root = document.createElement("div"); root.id = "rampart-jsc";
  root.style.cssText = (level === "block" ? "position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(5,11,20,0.92);padding:24px;" : "position:fixed;top:0;left:0;right:0;z-index:2147483646;background:#fff6df;color:#4a3b00;border-bottom:1px solid #f0d890;padding:10px 16px;") + "font-family:-apple-system,Helvetica,Arial,sans-serif;font-size:14px;";
  const card = document.createElement("div");
  card.style.cssText = level === "block" ? "width:min(560px,100%);background:#fff;color:#0d1b2a;border-radius:18px;padding:28px 30px;box-shadow:0 30px 80px rgba(0,0,0,.45);" : "display:flex;gap:12px;align-items:center;flex-wrap:wrap;";
  const badge = document.createElement("span"); badge.textContent = "RamPart"; badge.style.cssText = "display:inline-block;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:#0a84a0;background:rgba(10,132,160,.12);padding:3px 9px;border-radius:999px;margin-bottom:10px;";
  card.appendChild(badge);
  if (level === "block") { const h = document.createElement("h1"); h.textContent = "This page looks like a scam"; h.style.cssText = "font-size:24px;margin:0 0 8px;"; card.appendChild(h); }
  const p = document.createElement("p"); p.textContent = headline; p.style.cssText = "margin:0 0 10px;line-height:1.45;flex:1 1 300px;"; card.appendChild(p);
  const ul = document.createElement("ul"); ul.style.cssText = "margin:8px 0 16px;padding-left:18px;" + (level === "block" ? "" : "flex-basis:100%;");
  for (const r of reasons.slice(0, 5)) { const li = document.createElement("li"); const b = document.createElement("strong"); b.textContent = r.title; li.appendChild(b); li.appendChild(document.createTextNode(" " + (r.detail || ""))); li.style.marginBottom = "6px"; ul.appendChild(li); }
  card.appendChild(ul);
  const mk = (t, primary) => { const b = document.createElement("button"); b.textContent = t; b.style.cssText = "cursor:pointer;font-size:14px;font-weight:600;border-radius:999px;padding:9px 18px;border:0;margin-right:8px;" + (primary ? "background:linear-gradient(180deg,#17b8cc,#0a84a0);color:#fff;" : "background:#eef3f6;color:#2c3e50;"); return b; };
  const back = mk("Go back", true); back.onclick = () => { if (history.length > 1) history.back(); else location.replace("about:blank"); };
  const cont = mk(level === "block" ? "Continue anyway" : "Dismiss", false); cont.onclick = () => root.remove();
  card.appendChild(back); card.appendChild(cont);
  const foot = document.createElement("p"); foot.textContent = "Checked by RamPart on your Mac (Safari JavaScript control mode)."; foot.style.cssText = "font-size:12px;color:#6c7a89;margin-top:12px;";
  if (level === "block") card.appendChild(foot);
  root.appendChild(card); document.documentElement.appendChild(root);
})();
