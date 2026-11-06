// RamPart Web Protection: background service worker (Chromium MV3; also used by Safari).
// Talks to the native host (rampart-nmh on Chromium, the RamPart app's extension handler on
// Safari). When no host is reachable, falls back to the in-extension heuristics in
// shared/heuristics.js so the user still gets basic look-alike and ClickFix warnings.

importScripts("shared/heuristics.js");
const { localVerdict } = globalThis.RampartHeuristics;

const HOST_NAME = "app.rampart.nmh";
const isSafari = typeof browser !== "undefined" && navigator.vendor && navigator.vendor.includes("Apple");
const api = typeof browser !== "undefined" ? browser : chrome;

let port = null;
let nextId = 1;
const pending = new Map();           // id -> {resolve, timer}
let hostState = { connected: false, lastError: null, daemon: false, version: null };
const verdictCache = new Map();      // url -> {at, resp}

function connect() {
  if (isSafari) return null;        // Safari uses sendNativeMessage per request
  if (port) return port;
  try {
    port = api.runtime.connectNative(HOST_NAME);
    port.onMessage.addListener((msg) => {
      hostState.connected = true;
      if (msg && msg.version) { hostState.version = msg.version; hostState.daemon = !!msg.daemon; }
      const p = pending.get(msg && msg.id);
      if (p) { clearTimeout(p.timer); pending.delete(msg.id); p.resolve(msg); }
    });
    port.onDisconnect.addListener(() => {
      hostState.connected = false;
      hostState.lastError = (api.runtime.lastError && api.runtime.lastError.message) || "disconnected";
      port = null;
      for (const [id, p] of pending) { clearTimeout(p.timer); p.resolve({ id, ok: false, error: hostState.lastError }); }
      pending.clear();
    });
    return port;
  } catch (e) {
    hostState.connected = false; hostState.lastError = String(e); port = null; return null;
  }
}

/** Ask the native host. Resolves to a response object; never rejects. */
function askHost(req, timeoutMs = 4000) {
  const id = String(nextId++);
  req.id = id;
  return new Promise((resolve) => {
    if (isSafari) {
      api.runtime.sendNativeMessage("app.rampart.safari", req).then((msg) => { hostState.connected = true; resolve(msg || { ok: false, error: "empty" }); })
        .catch((e) => { hostState.connected = false; hostState.lastError = String(e); resolve({ ok: false, error: String(e) }); });
      return;
    }
    const p = connect();
    if (!p) return resolve({ ok: false, error: hostState.lastError || "no native host" });
    const timer = setTimeout(() => { pending.delete(id); resolve({ ok: false, error: "timeout" }); }, timeoutMs);
    pending.set(id, { resolve, timer });
    try { p.postMessage(req); } catch (e) { clearTimeout(timer); pending.delete(id); resolve({ ok: false, error: String(e) }); }
  });
}

async function verdictFor(req) {
  const settings = await getSettings();
  if (!settings.enabled) return { ok: true, verdict: "likelySafe", action: "allow", reasons: [], disabled: true };
  const host = hostOf(req.url);
  if (host && settings.allowedHosts.includes(host)) return { ok: true, verdict: "likelySafe", action: "allow", reasons: [], allowlisted: true };
  const resp = await askHost(req);
  if (resp && resp.ok) return resp;
  // Fallback: in-extension heuristics (weaker, but better than nothing).
  const local = localVerdict(req);
  local.fallback = true; local.hostError = resp && resp.error;
  return local;
}

function hostOf(url) { try { return new URL(url).hostname.toLowerCase(); } catch { return null; } }

const DEFAULTS = { enabled: true, interceptClipboard: true, allowedHosts: [], stats: { checked: 0, warned: 0, blocked: 0 } };
async function getSettings() {
  const s = await api.storage.local.get("settings");
  return Object.assign({}, DEFAULTS, s.settings || {});
}
async function setSettings(patch) {
  const s = await getSettings();
  const next = Object.assign({}, s, patch);
  await api.storage.local.set({ settings: next });
  return next;
}
async function bump(key) {
  const s = await getSettings(); s.stats[key] = (s.stats[key] || 0) + 1; await api.storage.local.set({ settings: s });
}

// Early URL check on navigation: the content script asks again with page signals once the DOM is ready.
api.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const cached = verdictCache.get(d.url);
  if (cached && Date.now() - cached.at < 5 * 60 * 1000) return;
  const resp = await verdictFor({ type: "checkURL", url: d.url });
  verdictCache.set(d.url, { at: Date.now(), resp });
  if (verdictCache.size > 300) verdictCache.delete(verdictCache.keys().next().value);
  await bump("checked");
  if (resp.action === "block" || resp.action === "warn") {
    await bump(resp.action === "block" ? "blocked" : "warned");
    try { await api.tabs.sendMessage(d.tabId, { type: "verdict", stage: "url", resp }); } catch { /* content script not ready yet; it will ask */ }
  }
});

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    switch (msg && msg.type) {
      case "checkPage": {
        const resp = await verdictFor({ type: "checkPage", url: msg.url, signals: msg.signals, tamper: msg.tamper });
        if (resp.action === "block" || resp.action === "warn") await bump(resp.action === "block" ? "blocked" : "warned");
        sendResponse(resp); break;
      }
      case "urlVerdict": {
        const c = verdictCache.get(msg.url);
        sendResponse(c ? c.resp : null); break;
      }
      case "checkClipboard": {
        const resp = await verdictFor({ type: "checkClipboard", url: msg.url, text: msg.text });
        sendResponse(resp); break;
      }
      case "allowHost": {
        const s = await getSettings();
        if (!s.allowedHosts.includes(msg.host)) s.allowedHosts.push(msg.host);
        await setSettings({ allowedHosts: s.allowedHosts });
        askHost({ type: "allowHost", host: msg.host });
        for (const [u] of verdictCache) if (hostOf(u) === msg.host) verdictCache.delete(u);
        sendResponse({ ok: true }); break;
      }
      case "decision": { askHost({ type: "reportDecision", url: msg.url, decision: msg.decision }); sendResponse({ ok: true }); break; }
      case "status": {
        const s = await getSettings();
        const ping = await askHost({ type: "ping" }, 1500);
        sendResponse({ settings: s, host: Object.assign({}, hostState, { reachable: !!(ping && ping.ok), version: ping && ping.version, daemon: ping && ping.daemon }) });
        break;
      }
      case "setSettings": { sendResponse(await setSettings(msg.patch)); break; }
      default: sendResponse({ ok: false, error: "unknown message" });
    }
  })();
  return true; // async sendResponse
});
