// Lightweight in-extension heuristics used when the native host isn't reachable, and by the
// content script to pre-screen clipboard text. A reduced port of RampartWeb's URLAnalyzer and
// PageAnalyzer: the full engine (brand list, confusables, email headers) lives in Swift.
// Classic script: exposes globalThis.RampartHeuristics (background uses importScripts, content scripts load it directly).

const BRANDS = {
  apple: ["apple.com", "icloud.com"], icloud: ["icloud.com", "apple.com"], appleid: ["apple.com"], microsoft: ["microsoft.com", "live.com", "office.com"],
  office365: ["office.com", "microsoft.com"], outlook: ["outlook.com", "live.com", "microsoft.com"], google: ["google.com"], gmail: ["google.com", "gmail.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de"], paypal: ["paypal.com"], netflix: ["netflix.com"], facebook: ["facebook.com"], instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com"], dhl: ["dhl.com", "dhl.de"], fedex: ["fedex.com"], usps: ["usps.com"], royalmail: ["royalmail.com"], evri: ["evri.com"],
  chase: ["chase.com"], wellsfargo: ["wellsfargo.com"], bankofamerica: ["bankofamerica.com"], hsbc: ["hsbc.com", "hsbc.co.uk"], barclays: ["barclays.co.uk"],
  natwest: ["natwest.com"], santander: ["santander.co.uk", "santander.com"], coinbase: ["coinbase.com"], binance: ["binance.com"], metamask: ["metamask.io"],
  ledger: ["ledger.com"], dropbox: ["dropbox.com"], docusign: ["docusign.com"], adobe: ["adobe.com"], ebay: ["ebay.com", "ebay.co.uk"], steampowered: ["steampowered.com"],
  discord: ["discord.com", "discord.gg"], telegram: ["telegram.org"], twitter: ["twitter.com", "x.com"], linkedin: ["linkedin.com"], github: ["github.com"],
  norton: ["norton.com"], mcafee: ["mcafee.com"], venmo: ["venmo.com"], zelle: ["zellepay.com"], cashapp: ["cash.app"], ezpass: ["e-zpassny.com"], hmrc: ["gov.uk"], irs: ["irs.gov"],
};
const LEGIT = new Set(Object.values(BRANDS).flat().concat(["apple.co", "me.com", "mac.com", "microsoftonline.com", "sharepoint.com", "onedrive.com", "youtube.com", "googleapis.com", "amazonaws.com", "paypal.me", "fb.com", "meta.com", "t.me", "t.co", "x.com", "gov.uk", "service.gov.uk", "usps.gov"]));
const AFFIXES = new Set(["secure", "security", "login", "signin", "sign", "id", "verify", "verification", "account", "accounts", "support", "update", "billing", "help", "service", "pay", "payment", "my", "online", "auth", "center", "team", "alert", "notice", "official", "store", "app", "mail", "web", "info", "admin", "check", "confirm", "portal", "access", "wallet", "claim", "bonus", "gift", "reward", "refund", "invoice", "order", "delivery", "tracking", "parcel", "fee", "fees", "toll", "tax", "customer", "user", "password", "reset", "unlock", "locked", "limited", "suspended", "review", "desk", "care", "us", "uk", "now", "new", "safe", "device", "sync", "validate", "connect", "airdrop", "nft", "cloud", "drive", "mobile", "banking", "bank", "card", "shop", "prime", "plus", "pro", "member", "renew", "subscription", "cancel", "manage", "status", "redelivery", "reschedule", "customs", "shipment", "shipping", "express", "post", "www"]);
const SHORTENERS = new Set(["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "t.ly", "s.id", "rebrand.ly", "short.io", "v.gd"]);
const RISKY_TLD = new Set(["zip", "mov", "top", "xyz", "icu", "cfd", "sbs", "rest", "click", "link", "work", "buzz", "monster", "quest", "cyou", "tk", "ml", "ga", "cf", "gq", "pw", "cam", "bond", "lol", "win", "bid", "loan", "men", "party", "racing", "review", "stream", "trade", "date", "download", "kim", "science", "support", "live", "online", "site", "website", "shop", "store", "vip", "wang", "lat", "ink", "surf", "fit", "best", "mom"]);
const TWO_PART = new Set(["co.uk", "org.uk", "gov.uk", "ac.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "co.kr", "com.br", "com.mx", "com.ar", "com.tr", "com.cn", "com.hk", "com.sg", "co.in", "co.za", "co.il", "com.sa", "com.ua", "com.pl", "co.id", "com.ph", "com.vn", "com.tw", "co.th", "github.io", "pages.dev", "web.app", "netlify.app", "vercel.app", "herokuapp.com", "azurewebsites.net", "cloudfront.net", "weebly.com", "wixsite.com", "webflow.io", "glitch.me", "workers.dev", "r2.dev", "godaddysites.com", "myshopify.com", "blogspot.com", "wordpress.com", "notion.site", "duckdns.org", "ddns.net", "000webhostapp.com"]);
const CONFUSABLE = { "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w", "ӏ": "l", "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "ɑ": "a", "ℓ": "l", "ⅼ": "l", "ⅰ": "i" };
const DEV_HOSTS = ["github.com", "gitlab.com", "stackoverflow.com", "stackexchange.com", "superuser.com", "askubuntu.com", "serverfault.com", "npmjs.com", "pypi.org", "brew.sh", "rubygems.org", "crates.io", "python.org", "developer.apple.com", "learn.microsoft.com", "developer.mozilla.org", "docs.docker.com", "kubernetes.io", "rust-lang.org", "go.dev", "nodejs.org", "swift.org", "readthedocs.io", "dev.to", "medium.com", "bitbucket.org", "apple.com", "ubuntu.com", "debian.org", "archlinux.org", "digitalocean.com", "cloudflare.com", "aws.amazon.com", "cloud.google.com", "vercel.com", "netlify.com", "heroku.com", "sourceforge.net", "localhost"];

function skeleton(s) {
  let out = "";
  for (const ch of s.toLowerCase()) out += CONFUSABLE[ch] || ch.normalize("NFD").replace(/[̀-ͯ]/g, "");
  return out.replace(/rn/g, "m").replace(/vv/g, "w").replace(/0/g, "o").replace(/1/g, "l").replace(/3/g, "e").replace(/5/g, "s").replace(/7/g, "t");
}
function editDistance(a, b) {
  const d = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
  for (let j = 1; j <= b.length; j++) d[0][j] = j;
  for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) {
    d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
  }
  return d[a.length][b.length];
}
function splitHost(host) {
  const labels = host.split(".");
  if (labels.length < 2) return null;
  const last2 = labels.slice(-2).join(".");
  if (TWO_PART.has(last2)) { if (labels.length < 3) return null; return { registrable: labels.slice(-3).join("."), label: labels[labels.length - 3], suffix: last2, subs: labels.slice(0, -3) }; }
  return { registrable: last2, label: labels[labels.length - 2], suffix: labels[labels.length - 1], subs: labels.slice(0, -2) };
}
function remainderIsAffixes(s, k) {
  const i = s.indexOf(k); if (i < 0) return false;
  const ok = (t) => { if (!t) return true; for (let n = t.length; n >= 1; n--) if (AFFIXES.has(t.slice(0, n)) && ok(t.slice(n))) return true; return false; };
  return ok(s.slice(0, i)) && ok(s.slice(i + k.length));
}
function decodeHost(host) { try { return new URL("http://" + host).hostname; } catch { return host; } }
function unicodeHost(host) {
  // The browser gives us the punycode form; decode for display via URL where possible.
  try { const a = document.createElement("a"); a.href = "http://" + host; return a.hostname; } catch { return host; }
}

function urlSignals(url) {
  const out = [];
  let u; try { u = new URL(url); } catch { return out; }
  if (u.protocol === "javascript:" || u.protocol === "data:") { out.push({ title: "Runs code or embeds a page in the link", detail: u.protocol + " links are never needed by legitimate sites.", score: 85 }); return out; }
  const host = u.hostname.toLowerCase();
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host) || host.startsWith("[")) out.push({ title: "Uses a raw IP address instead of a name", detail: "Real companies use their domain name.", score: 45 });
  if (u.username) out.push({ title: "Hidden destination after an @ sign", detail: "The part before @ is ignored; the page is really " + host + ".", score: 75 });
  const sp = splitHost(host);
  if (!sp) return out;
  if (SHORTENERS.has(sp.registrable)) out.push({ title: "Shortened link", detail: "You can't see where it goes until you open it.", score: 30 });
  if (sp.subs.length >= 3) out.push({ title: "Many nested subdomains", detail: "The real domain is " + sp.registrable + ".", score: 25 });
  const tld = sp.suffix.split(".").pop();
  if (RISKY_TLD.has(tld) && !LEGIT.has(sp.registrable)) out.push({ title: "Frequently abused domain ending (." + tld + ")", detail: "Cheap endings are popular with throwaway scam sites.", score: 20 });
  if (LEGIT.has(sp.registrable)) return out;
  // Look-alikes
  let label = sp.label;
  try { label = decodeHost(host).split(".").slice(-(sp.suffix.split(".").length + 1))[0] || sp.label; } catch {}
  const nonAscii = /[^\x00-\x7f]/.test(label) || sp.label.startsWith("xn--");
  const folded = skeleton(label);
  const tokens = folded.split(/[-_]/);
  for (const t of tokens) if (BRANDS[t] && t.length >= 3) {
    const brand = t;
    const whole = tokens.length === 1;
    out.push({ title: nonAscii ? "Looks like " + brand + " but uses foreign letters" : whole ? (folded !== label.toLowerCase() ? "Imitates " + brand + " with swapped characters" : brand + " name on the wrong domain ending") : brand + " name combined with extra words",
               detail: "“" + sp.registrable + "” is not a " + brand + " domain. The real site is " + BRANDS[brand][0] + ".", score: nonAscii ? 92 : whole ? 80 : 75, brand });
    return out;
  }
  for (const k of Object.keys(BRANDS)) if (k.length >= 5 && folded.includes(k) && folded !== k && remainderIsAffixes(folded, k)) {
    out.push({ title: k + " name combined with extra words", detail: "“" + sp.registrable + "” contains the " + k + " name. The real site is " + BRANDS[k][0] + ".", score: 75, brand: k }); return out;
  }
  const cands = tokens.length > 1 ? tokens.filter((t) => t.length >= 4 && !AFFIXES.has(t)) : [folded];
  if (tokens.filter((t) => !AFFIXES.has(t)).length <= 1) for (const c of cands) for (const k of Object.keys(BRANDS)) {
    if (k.length < 4) continue; const max = k.length >= 8 ? 2 : 1;
    if (k.length < 7 && c.length !== k.length) continue;
    const d = editDistance(c, k);
    if (d > 0 && d <= max) { out.push({ title: "One letter away from " + k, detail: "“" + label + "” differs from “" + k + "” by " + d + ". The real site is " + BRANDS[k][0] + ".", score: 70, brand: k }); return out; }
  }
  for (const s of sp.subs) for (const t of skeleton(s).split(/[-_]/)) if (BRANDS[t] && t.length >= 3) {
    out.push({ title: t + " name hidden in a subdomain", detail: "The site is really " + sp.registrable + ". The real " + t + " site is " + BRANDS[t][0] + ".", score: 80, brand: t }); return out;
  }
  return out;
}

const CLICKFIX = /(verify|verification|not\s+a\s+robot|prove\s+you\s+are\s+human|human\s+verification|captcha|checking\s+your\s+browser|to\s+(continue|proceed))[\s\S]{0,400}?(open\s+(the\s+)?(terminal|command\s+prompt|cmd|powershell|run\s+(dialog|box)|spotlight)|press\s+(the\s+)?(win(dows)?(\s*key)?\s*\+\s*r|⌘\s*\+?\s*space|cmd\s*\+\s*space|command\s*\+\s*space|ctrl\s*\+\s*v|cmd\s*\+\s*v|⌘\s*\+?\s*v)|paste\s+(the\s+)?(command|code|text|it))/i;
const SCAREWARE = /((your|this)\s+(mac|computer|pc|device|iphone|system)\s+(is|has\s+been|may\s+be)\s+(infected|compromised|hacked|at\s+risk|blocked|locked)|(virus|malware|spyware|trojan)e?s?\s+(has\s+been\s+|have\s+been\s+|was\s+)?(detected|found)|(apple|microsoft|windows)\s+(security|support|defender)\s+(alert|warning|center)|do\s+not\s+(shut\s*down|restart|close\s+this))/i;
const PHONE = /(\+?\d{1,3}[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/;
const DRAINER = /(connect\s+(your\s+)?wallet|wallet\s*connect)[\s\S]{0,300}?(claim|airdrop|mint|reward|eligib|free\s+(nft|tokens?)|migrat|validate|sync)/i;
const SHELL = /^\s*(sudo\s+)?(curl|wget|bash|sh|zsh|osascript|python3?|perl|ruby|powershell|mshta|cmd(\.exe)?|xattr|chmod|open\s+-a|nohup|base64|eval|echo\s+[A-Za-z0-9+\/=]{30,})\b|\|\s*(bash|sh|zsh|python3?)\b|\$\(|`[^`]+`|;\s*(bash|sh)\s/im;
const DANGEROUS = /(curl|wget)[^\n]*\|\s*(bash|sh|zsh)|base64\s+-d|osascript|xattr\s+-[cdr]|nohup|mshta|powershell\s+-(e|enc|w\s+hidden)/i;

function pageSignalsVerdict(signals) {
  const out = [];
  const text = [signals.title, signals.overlayText, signals.visibleText].join("\n");
  if (CLICKFIX.test(text)) out.push({ title: "Fake verification that tells you to run a command", detail: "No CAPTCHA asks you to open Terminal or paste anything. This is ClickFix malware.", score: 90 });
  if (SCAREWARE.test(text)) { out.push({ title: "Fake virus alert", detail: "Web pages can't scan your Mac. Close the tab.", score: 75 }); if (PHONE.test(text)) out.push({ title: "Shows a phone number to call", detail: "Real alerts never include phone numbers.", score: 70 }); }
  if (DRAINER.test(text) || signals.hasWalletConnect && /claim|airdrop|mint/i.test(text)) out.push({ title: "Crypto claim with wallet connect", detail: "Signing an unexpected approval can empty your wallet.", score: 60 });
  if (signals.usesClipboardWrite && out.some((s) => s.score >= 80)) out.push({ title: "Copies a command to your clipboard", detail: "The page writes to the clipboard while telling you to paste.", score: 70 });
  for (const s of signals.scriptSnippets || []) if (/(clipboard\.writeText|execCommand\(['"]copy)[\s\S]{0,300}?(curl|wget|osascript|powershell|mshta|\|\s*bash|base64)/i.test(s) || /(curl|wget|osascript|powershell|mshta|\|\s*bash|base64)[\s\S]{0,300}?(clipboard\.writeText|execCommand\(['"]copy)/i.test(s)) { out.push({ title: "Clipboard payload is a shell command", detail: "Never paste it anywhere.", score: 85 }); break; }
  return out;
}

function combine(signals) {
  let product = 1;
  const byCat = {};
  for (const s of signals) { const k = s.title; byCat[k] = Math.max(byCat[k] || 0, Math.min(100, s.score)); }
  for (const v of Object.values(byCat)) product *= 1 - v / 100;
  return Math.round(100 * (1 - product));
}
function verdictFromScore(score) { return score >= 70 ? "likelyScam" : score >= 35 ? "suspicious" : "likelySafe"; }
function actionFor(v) { return v === "likelyScam" ? "block" : v === "suspicious" ? "warn" : "allow"; }
function isDeveloperHost(host) { if (!host) return false; host = host.toLowerCase(); return DEV_HOSTS.some((d) => host === d || host.endsWith("." + d)); }

/** Mirror of WebVerdictService.handle for the subset the extension can do alone. */
function localVerdict(req) {
  let signals = [];
  if (req.type === "checkURL" || req.type === "checkPage") signals = signals.concat(urlSignals(req.url));
  if (req.type === "checkPage" && req.signals) signals = signals.concat(pageSignalsVerdict(req.signals));
  if (req.type === "checkClipboard") {
    const host = (() => { try { return new URL(req.url).hostname; } catch { return null; } })();
    if (SHELL.test(req.text || "")) { const dev = isDeveloperHost(host), dang = DANGEROUS.test(req.text); signals.push({ title: dang ? "Copied a command that downloads and runs code" : "Copied a shell command", detail: dev ? "Developer site; read it before you run it." : "A non-developer site put a shell command on your clipboard. Don't paste it into Terminal.", score: dev ? (dang ? 25 : 5) : (dang ? 90 : 60) }); }
  }
  signals.sort((a, b) => b.score - a.score);
  const score = combine(signals);
  const verdict = verdictFromScore(score);
  const top = signals.filter((s) => s.score >= 30).slice(0, 2).map((s) => s.title.toLowerCase());
  return { ok: true, verdict, action: actionFor(verdict), score, reasons: signals.map((s) => ({ title: s.title, detail: s.detail, score: s.score, evidence: [] })),
           headline: verdict === "likelySafe" ? "No strong signs of a scam." : (verdict === "likelyScam" ? "This looks like a scam: " : "Warning signs: ") + top.join(" and ") + ".",
           brand: (signals.find((s) => s.brand) || {}).brand, tips: [], fallback: true };
}

const RampartHeuristics = { localVerdict, urlSignals, pageSignalsVerdict, isDeveloperHost, looksLikeShellCommand: (t) => SHELL.test(t || ""), CLICKFIX };
if (typeof globalThis !== "undefined") globalThis.RampartHeuristics = RampartHeuristics;
