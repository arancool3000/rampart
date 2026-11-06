const api = typeof browser !== "undefined" ? browser : chrome;
async function refresh() {
  const st = await api.runtime.sendMessage({ type: "status" });
  const s = st.settings, h = st.host;
  document.getElementById("checked").textContent = s.stats.checked || 0;
  document.getElementById("warned").textContent = s.stats.warned || 0;
  document.getElementById("blocked").textContent = s.stats.blocked || 0;
  document.getElementById("enabled").checked = !!s.enabled;
  document.getElementById("clip").checked = !!s.interceptClipboard;
  document.getElementById("allowcount").textContent = (s.allowedHosts.length || 0) + " trusted site" + (s.allowedHosts.length === 1 ? "" : "s");
  const line = document.getElementById("hostline");
  if (h.reachable) { line.innerHTML = '<span class="ok">●</span> Connected to RamPart ' + (h.version || "") + (h.daemon ? " · full protection" : " · app only"); document.getElementById("hint").textContent = h.daemon ? "" : "The RamPart background service isn't running, so known-bad site lists aren't checked. Open RamPart to start it."; }
  else { line.innerHTML = '<span class="bad">●</span> RamPart not reachable'; document.getElementById("hint").textContent = "Using the extension's built-in rules only. Install RamPart and run “Install browser protection” from its Settings to connect this extension (" + (h.lastError || "native host not found") + ")."; }
}
document.getElementById("enabled").onchange = (e) => api.runtime.sendMessage({ type: "setSettings", patch: { enabled: e.target.checked } });
document.getElementById("clip").onchange = (e) => api.runtime.sendMessage({ type: "setSettings", patch: { interceptClipboard: e.target.checked } });
document.getElementById("clear").onclick = async () => { await api.runtime.sendMessage({ type: "setSettings", patch: { allowedHosts: [] } }); refresh(); };
refresh();
