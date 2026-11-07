// RamPart Web Protection: background service worker (Chromium MV3; also used by Safari).
// Talks to the native host (rampart-nmh on Chromium, the RamPart app's extension handler on
// Safari). When no host is reachable, falls back to the in-extension heuristics in
// shared/heuristics.js so the user still gets basic look-alike and ClickFix warnings.

importScripts("shared/heuristics.js");
// Note: heuristics.js declares localVerdict etc. as globals. Re-declaring them here (the old
// `const { localVerdict } = ...`) made importScripts throw "already declared" and the worker fail.
const HX = globalThis.RampartHeuristics;

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
  if (req.type === "checkClipboard" && !settings.interceptClipboard) return { ok: true, verdict: "likelySafe", action: "allow", reasons: [], disabled: true };
  const resp = await askHost(req);
  if (resp && resp.ok) return req.type === "checkPage" ? mergeExtra(resp, req) : resp;
  // Fallback: in-extension heuristics (weaker, but better than nothing).
  const local = HX.localVerdict(req);
  local.fallback = true; local.hostError = resp && resp.error;
  return local;
}

/** X3-4 / W-X6-1: the extension's fake-AV, fake-update and fake-download rules also apply when the
 *  native host answers (until RampartWeb has them, docs/security/needs-web.md). Never lowers a verdict. */
const RANK = { allow: 0, warn: 1, block: 2 };
function mergeExtra(resp, req) {
  const extra = HX.extraPageSignals(req.signals, req.url);
  if (!extra.length) return resp;
  const score = HX.combine(extra);
  const action = HX.actionFor(HX.verdictFromScore(score));
  const have = new Set((resp.reasons || []).map((r) => r && r.title));
  const reasons = extra.filter((x) => !have.has(x.title)).map((x) => ({ title: x.title, detail: x.detail, score: x.score, evidence: [] })).concat(resp.reasons || []);
  if ((RANK[action] || 0) <= (RANK[resp.action] || 0)) return Object.assign({}, resp, { reasons });
  const verdict = action === "block" ? "likelyScam" : "suspicious";
  return Object.assign({}, resp, { verdict, action, score: Math.max(score, resp.score || 0), reasons,
    headline: (action === "block" ? "This looks like a scam: " : "Warning signs: ") + extra[0].title.toLowerCase() + "." });
}

function hostOf(url) { try { return new URL(url).hostname.toLowerCase(); } catch { return null; } }
const HOSTNAME_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
/** A host the user may trust: a strict ASCII hostname that is more than a bare public suffix. */
function isTrustableHost(h) {
  if (typeof h !== "string" || !HOSTNAME_RE.test(h)) return false;
  return !!HX.splitHost(h);
}

const DEFAULTS = { enabled: true, interceptClipboard: true, allowedHosts: [], stats: { checked: 0, warned: 0, blocked: 0 } };
async function getSettings() {
  const s = (await api.storage.local.get("settings")).settings || {};
  return {
    enabled: typeof s.enabled === "boolean" ? s.enabled : DEFAULTS.enabled,
    interceptClipboard: typeof s.interceptClipboard === "boolean" ? s.interceptClipboard : DEFAULTS.interceptClipboard,
    allowedHosts: Array.isArray(s.allowedHosts) ? s.allowedHosts.filter(isTrustableHost).slice(0, 5000) : [],
    stats: Object.assign({}, DEFAULTS.stats, s.stats && typeof s.stats === "object" ? s.stats : {}),
  };
}
async function writeSettings(next) { await api.storage.local.set({ settings: next }); return next; }

/** N5: the popup may only flip the two booleans, or shrink the trusted list (it only offers "clear").
 *  Anything else (unknown keys, wrong types, stats, new hosts) rejects the whole patch. */
function sanitizePatch(patch, current) {
  if (!patch || typeof patch !== "object" || Array.isArray(patch)) return null;
  const out = {};
  for (const k of Object.keys(patch)) {
    const v = patch[k];
    if (k === "enabled" || k === "interceptClipboard") { if (typeof v !== "boolean") return null; out[k] = v; }
    else if (k === "allowedHosts") {
      if (!Array.isArray(v) || v.length > current.allowedHosts.length || !v.every((h) => typeof h === "string" && current.allowedHosts.includes(h))) return null;
      out[k] = Array.from(new Set(v));
    } else return null;
  }
  return out;
}
async function bump(key) {
  const s = await getSettings(); s.stats[key] = (s.stats[key] || 0) + 1; await writeSettings(s);
}

// MARK: Per-tab state (memory only; a browser restart forgets it)
// tabId -> { last: {url, host, resp, at}, continued: Set<host> }
const tabs = new Map();
function tabState(id) { let t = tabs.get(id); if (!t) { t = { last: null, continued: new Set() }; tabs.set(id, t); } return t; }
function noteVerdict(tabId, url, resp) {
  if (typeof tabId !== "number" || tabId < 0 || !resp || (resp.action !== "block" && resp.action !== "warn")) return;
  const t = tabState(tabId);
  const cur = t.last;
  if (cur && cur.host === hostOf(url) && RANK[cur.resp.action] > RANK[resp.action] && Date.now() - cur.at < 10 * 60 * 1000) return;  // keep the stronger one
  t.last = { url, host: hostOf(url), resp, at: Date.now() };
}
/** The verdict RamPart itself recorded for this tab and host (never what a content script claims). */
function recordedVerdict(tabId, host, minAction) {
  const t = tabs.get(tabId);
  if (!t || !t.last || t.last.host !== host || Date.now() - t.last.at > 30 * 60 * 1000) return null;
  return RANK[t.last.resp.action] >= RANK[minAction] ? t.last : null;
}
api.tabs.onRemoved.addListener((id) => { tabs.delete(id); for (const [k, v] of tokens) if (v.tabId === id) tokens.delete(k); });

// MARK: Standalone interstitial tokens (N3). The page gets only an opaque token in its fragment;
// headline and reasons stay here and are handed only to our own interstitial page in that tab.
const tokens = new Map();   // token -> {tabId, url, host, resp, at}
function newToken() { const b = new Uint8Array(16); crypto.getRandomValues(b); return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); }
const INTERSTITIAL_URL = api.runtime.getURL("interstitial.html");
function fromInterstitial(sender, tok) {
  const e = tokens.get(tok);
  if (!e || !sender.tab || sender.tab.id !== e.tabId || Date.now() - e.at > 60 * 60 * 1000) return null;
  if (typeof sender.url !== "string" || !sender.url.startsWith(INTERSTITIAL_URL)) return null;
  return e;
}

// MARK: Sender checks (N5)
/** A message from our own content script in the top frame of a normal web tab. */
function isContentSender(sender) {
  return !!(sender && sender.id === api.runtime.id && sender.tab && typeof sender.tab.id === "number" && sender.tab.id >= 0
    && (sender.frameId === 0 || sender.frameId === undefined) && typeof sender.url === "string" && /^https?:\/\//.test(sender.url));
}
/** A message from one of our own extension pages (popup or interstitial). */
function isExtensionPage(sender) {
  return !!(sender && sender.id === api.runtime.id && typeof sender.url === "string" && sender.url.startsWith(api.runtime.getURL("")));
}
const str = (v, max) => (typeof v === "string" ? v.slice(0, max) : "");
function cleanSignals(sig) {
  if (!sig || typeof sig !== "object" || Array.isArray(sig)) return {};
  return sig;   // shape-checked by the native host; size is bounded by collectSignals and the messaging limit
}
function cleanTamper(t) { return Array.isArray(t) ? t.filter((x) => typeof x === "string").slice(0, 40).map((x) => x.slice(0, 160)) : []; }
const DECISIONS = new Set(["wentBack", "continued", "dismissedBanner"]);

// Early URL check on navigation: the content script asks again with page signals once the DOM is ready.
api.webNavigation.onCommitted.addListener(async (d) => {
  if (d.frameId !== 0 || !/^https?:/.test(d.url)) return;
  const cached = verdictCache.get(d.url);
  if (cached && Date.now() - cached.at < 5 * 60 * 1000) { noteVerdict(d.tabId, d.url, cached.resp); return; }
  const resp = await verdictFor({ type: "checkURL", url: d.url });
  verdictCache.set(d.url, { at: Date.now(), resp });
  noteVerdict(d.tabId, d.url, resp);
  if (verdictCache.size > 300) verdictCache.delete(verdictCache.keys().next().value);
  await bump("checked");
  if (resp.action === "block" || resp.action === "warn") {
    await bump(resp.action === "block" ? "blocked" : "warned");
    try { await api.tabs.sendMessage(d.tabId, { type: "verdict", stage: "url", resp }); } catch { /* content script not ready yet; it will ask */ }
  }
});

api.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // N5: only our own extension may talk to us (no externally_connectable, but check anyway), and each
  // message type only from the context that legitimately sends it.
  if (!sender || sender.id !== api.runtime.id || !msg || typeof msg !== "object" || typeof msg.type !== "string") { sendResponse({ ok: false, error: "rejected" }); return false; }
  (async () => {
    const content = isContentSender(sender);
    const page = isExtensionPage(sender);
    // The page URL is taken from the browser (sender.url), not from the message.
    const tabId = content ? sender.tab.id : null;
    const pageURL = content ? sender.url : null;
    const pageHost = content ? hostOf(pageURL) : null;
    switch (content ? msg.type : page ? "page:" + msg.type : "") {
      case "checkPage": {
        const resp = await verdictFor({ type: "checkPage", url: pageURL, signals: cleanSignals(msg.signals), tamper: cleanTamper(msg.tamper) });
        noteVerdict(tabId, pageURL, resp);
        if (resp.action === "block" || resp.action === "warn") await bump(resp.action === "block" ? "blocked" : "warned");
        sendResponse(withContinued(resp, tabId, pageHost)); break;
      }
      case "urlVerdict": {
        const c = verdictCache.get(pageURL);
        sendResponse(c ? withContinued(c.resp, tabId, pageHost) : null); break;
      }
      case "checkClipboard": {
        const text = str(msg.text, 5000);
        sendResponse(text ? await verdictFor({ type: "checkClipboard", url: pageURL, text }) : { ok: true, action: "allow", reasons: [] }); break;
      }
      case "allowHost": {
        // N1: "Don't warn for <host>" must name this tab's own host, and RamPart must actually have
        // warned or blocked this host in this tab (so a banner with the button existed).
        const host = str(msg.host, 253).toLowerCase();
        if (host !== pageHost || !isTrustableHost(host) || !recordedVerdict(tabId, host, "warn")) { sendResponse({ ok: false, error: "rejected" }); break; }
        await trustHost(host);
        sendResponse({ ok: true }); break;
      }
      case "continueSite": {
        // N1: "Continue anyway" on the in-page interstitial. Session-only, exact host, this tab.
        if (!pageHost || !recordedVerdict(tabId, pageHost, "block")) { sendResponse({ ok: false, error: "rejected" }); break; }
        tabState(tabId).continued.add(pageHost);
        askHost({ type: "reportDecision", url: pageURL, decision: "continued" });
        sendResponse({ ok: true }); break;
      }
      case "openInterstitial": {
        // The in-page overlay was removed or hidden by the page: move the tab to our own page,
        // which the site can't script. Uses RamPart's recorded verdict, not anything from the message.
        const rec = recordedVerdict(tabId, pageHost, "block");
        if (!rec || tabState(tabId).continued.has(pageHost)) { sendResponse({ ok: false }); break; }
        const tok = newToken();
        tokens.set(tok, { tabId, url: pageURL, host: pageHost, resp: rec.resp, at: Date.now() });
        if (tokens.size > 200) tokens.delete(tokens.keys().next().value);
        try { await api.tabs.update(tabId, { url: INTERSTITIAL_URL + "#" + tok }); } catch {}
        sendResponse({ ok: true }); break;
      }
      case "decision": {
        const decision = str(msg.decision, 40);
        if (DECISIONS.has(decision) && decision !== "continued") askHost({ type: "reportDecision", url: pageURL, decision });
        sendResponse({ ok: true }); break;
      }
      case "page:interstitialData": {
        const e = fromInterstitial(sender, str(msg.token, 64));
        if (!e) { sendResponse(null); break; }
        const r = e.resp || {};
        sendResponse({ host: e.host, headline: str(r.headline, 300), fallback: !!r.fallback,
          reasons: (Array.isArray(r.reasons) ? r.reasons : []).slice(0, 5).map((x) => ({ title: str(x && x.title, 200), detail: str(x && x.detail, 400) })) });
        break;
      }
      case "page:interstitialContinue": {
        const e = fromInterstitial(sender, str(msg.token, 64));
        if (!e || !/^https?:\/\//.test(e.url)) { sendResponse({ ok: false }); break; }
        tokens.delete(str(msg.token, 64));
        tabState(e.tabId).continued.add(e.host);
        askHost({ type: "reportDecision", url: e.url, decision: "continued" });
        try { await api.tabs.update(e.tabId, { url: e.url }); } catch {}
        sendResponse({ ok: true }); break;
      }
      case "page:interstitialBack": {
        const e = fromInterstitial(sender, str(msg.token, 64));
        if (e) askHost({ type: "reportDecision", url: e.url, decision: "wentBack" });
        sendResponse({ ok: true }); break;
      }
      case "page:status": {
        if (sender.tab) { sendResponse(null); break; }       // popup only
        const s = await getSettings();
        const ping = await askHost({ type: "ping" }, 1500);
        sendResponse({ settings: s, host: Object.assign({}, hostState, { reachable: !!(ping && ping.ok), version: str(ping && ping.version, 40), daemon: !!(ping && ping.daemon) }) });
        break;
      }
      case "page:setSettings": {
        if (sender.tab) { sendResponse({ ok: false, error: "rejected" }); break; }   // popup only
        const cur = await getSettings();
        const patch = sanitizePatch(msg.patch, cur);
        if (!patch) { sendResponse({ ok: false, error: "rejected" }); break; }
        sendResponse(await writeSettings(Object.assign(cur, patch))); break;
      }
      default: sendResponse({ ok: false, error: "unknown message" });
    }
  })().catch(() => { try { sendResponse({ ok: false, error: "internal" }); } catch {} });
  return true; // async sendResponse
});

function withContinued(resp, tabId, host) {
  if (!resp || !host || !tabs.has(tabId) || !tabState(tabId).continued.has(host)) return resp;
  return Object.assign({}, resp, { continued: true });
}
async function trustHost(host) {
  const s = await getSettings();
  if (!s.allowedHosts.includes(host)) s.allowedHosts.push(host);
  await writeSettings(s);
  askHost({ type: "allowHost", host });
  for (const [u] of verdictCache) if (hostOf(u) === host) verdictCache.delete(u);
}
