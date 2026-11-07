# needs-web (owner: W1)

Appended by attack pass X3 (2026-11-07). See docs/security/attacks-X3.md.

## X3-1 (High) — Decode QR codes and on-page image lures
Scenarios S10/S11: a scam page can show the malicious URL only inside a **QR code image** or a
screenshot/`<canvas>`, so nothing reaches URLAnalyzer. The extension already collects `imageAlts`
and script snippets; add image handling:
- In the content script, for `<img>`/`<canvas>` that are large and near overlay/"scan to continue"
  text, pass the pixels to a bundled JS QR decoder (e.g. a vendored `jsQR`-style module, MV3-safe,
  no network) and put any decoded string into a new `PageSignals.decodedImageURLs: [String]`.
- In `PageAnalyzer.analyze`, run each decoded string through `URLAnalyzer.analyze` exactly like a
  link, and add a `.lure` signal "URL hidden in a QR code / image" (score 45) when the decoded host
  is a lookalike or on the blocklist.
Self-test: `checkPage` with `PageSignals.decodedImageURLs = ["https://appleid-signin.test/x"]` →
verdict != .likelySafe; a decoded `https://www.apple.com/` → stays safe.

## X3-4 (High, confirmed by test: S8 scores likelySafe today) — Dedicated "fake security alert / disable your antivirus" signal
Scenario S8: copy that **impersonates RamPart (or any AV)** and instructs the user to *disable
protection* / *call support* is only caught by the generic scareware rule. Add a `.pageScareware`
pattern in the lexicon/PageAnalyzer: overlay or visible text matching
`(?i)(disable|turn off|pause).{0,20}(protection|antivirus|real-?time|rampart|defender)` combined with
`(?i)(call|contact).{0,20}(support|technician|apple)` or a virus-count claim → score 70 (block), with
the explanation "No real antivirus asks you to switch it off. RamPart can't be disabled by a website."
Self-test: the S8 fixture → `likelyScam`; a genuine security blog post that merely mentions
"disable antivirus" in prose → stays `likelySafe` (false-positive guard).

## From attack suite X6 (everyday Mac threats, 2026-11-07)

### W-X6-1 (Medium): fake browser-update and fake-download pages score 0
X6 W02: "Your version of Chrome is out of date … Update Chrome" + link to `ChromeUpdate.dmg` on a non-vendor host →
likelySafe, 0. X6 W03: a fake Notion download page whose text says "if the app is damaged … run xattr -c in Terminal" →
likelySafe, 0.
**Fix (`Sources/RampartWeb/PageAnalyzer.swift` textRules + a link check):**
1. `page.fakeupdate` (score 70, `.pageScareware`): `\b(your\s+)?(version\s+of\s+)?(chrome|safari|firefox|edge|flash(\s+player)?|browser|macos)\s+(is\s+)?(out\s+of\s+date|outdated|needs?\s+(an?\s+)?update|requires?\s+an?\s+update|critical\s+update)`
   Raise to 85 when the page links a `.dmg|.pkg|.zip|.app` whose registrable domain is not the brand's own
   (google.com, mozilla.org, microsoft.com, apple.com, adobe.com). Flash is dead, so any "Flash update" scores 85.
2. `page.gatekeeper.bypass` (score 80, `.pageClickFix`): `(app\s+is\s+damaged|can.?t\s+be\s+opened|unidentified\s+developer).{0,300}?(xattr\s+-c|xattr\s+-d|right.?click.{0,40}open|open\s+anyway|sudo\s+spctl)`,
   and also bare `xattr\s+-(c|cr|d)\b` anywhere in visible text (the current `xattr\s+-[cdr]\` part of clickfix.command needs extra context).
3. A download-link signal: a page whose title or H1 names a well-known app (Brands list) and links a DMG/PKG on a
   domain that is neither the brand's nor a known mirror → +40 "Download is not from the developer's site".
Self-tests: the W02/W03 fixtures → at least suspicious. The real `google.com/chrome` download page text → likelySafe.

## Extension status and RampartWeb proposal for X3-4 / W-X6-1 (extension hardening pass, 2026-11-07)

**Done in the extension** (`Extensions/chromium/shared/heuristics.js` `extraPageSignals`). `background.js`
`mergeExtra` also runs these rules when the native host answers. It only ever raises the host's verdict,
so they protect users now, before RampartWeb has them. Fixture results (scratch harness, 9/9):
S8 fake RamPart alert → likelyScam 70; security-blog prose → likelySafe; W02 fake Chrome update + off-vendor
.dmg → likelyScam 85; W03 fake Notion + "app is damaged … xattr -c" → likelyScam 88; real google.com/chrome
and notion.com download pages → likelySafe; GitHub README with `xattr -cr` → likelySafe; Flash update → 85;
"Your web browser is out of date" with no download → suspicious 55.

New `PageSignals` fields sent by the content script, which RampartWeb should decode (optional, default empty):
`h1: String` (first `<h1>`, ≤200 chars) and `downloadLinks: [String]` (≤30 absolute hrefs whose path ends
.dmg/.pkg/.mpkg/.zip/.app/.iso). Codable ignores them today, so nothing breaks.

**Proposal for `Sources/RampartWeb/PageAnalyzer.swift`** (mirror these so Safari and the in-app browser get the same rules):
1. `page.fakeav` (70, `.pageScareware`). A match for `(?i)\b(disable|turn\s+off|switch\s+off|pause|deactivate|uninstall)\b[^\n]{0,20}?\b(protection|antivirus|anti-virus|real-?time|rampart|defender|firewall|security\s+software|xprotect|gatekeeper)`
   counts only if, within ±400 characters, there is also `(?i)\b(call|contact|dial|phone|ring)\b[^\n]{0,20}?\b(support|technician|apple|microsoft|help\s*desk|helpline|toll[-\s]?free|our\s+(team|experts?|agents?))`,
   a virus count `\b\d{1,4}\s+(viruses|threats|infections|trojans|spyware)\b`, or the existing scareware rule.
   The proximity requirement is the false-positive guard. Explanation: "No real antivirus asks you to switch it off. RamPart can't be disabled by a website."
2. `page.fakeupdate` (`.pageScareware`): use the regex from W-X6-1, plus `google chrome|microsoft edge|mac os`. **This deviates from the original spec:**
   text alone scores **55**, not 70, because sites like whatismybrowser.com legitimately say "your browser is out of date".
   The score becomes 85 when an installer link's registrable domain is not the brand's (chrome→google.com; safari/macos→apple.com;
   firefox→mozilla.org/mozilla.net/firefox.com; edge→microsoft.com; flash→adobe.com; "browser"→any of them), and any Flash update scores 85.
   Skip the rule when the page itself is on the brand's domain.
3. `page.gatekeeper.bypass` (80, `.pageClickFix`): use the W-X6-1 regex as written. Bare `\bxattr\s+-(c|cr|rc|d)\b` in visible or overlay text scores **50**.
   Both are skipped on developer hosts (GitHub READMEs for unsigned open-source apps say exactly this).
4. `page.fakedownload` (40): the title or H1 names a known app (word-bounded; app→domains list in heuristics.js `APPS`). The page's registrable domain
   is neither the app's nor a mirror (github.com, githubusercontent.com, sourceforge.net, apple.com), and an installer link sits on such a domain.
   Detail: "This page is named after X but its installer comes from Y. Get X from Z."
Self-tests: the nine fixtures above (strings in this section) as `checkPage` cases with the same expected verdicts.

## Needs owner from the extension hardening pass (Safari manifest, not in the extension owner's files)

- **Extensions/safari/manifest.json** needs four changes:
  (a) Add `{ "matches": ["http://*/*","https://*/*"], "js": ["shared/clipboard-bridge.js"], "run_at": "document_start", "all_frames": false }` before the MAIN-world entry.
  Without it, content.js installs the clipboard bridge late (at document_idle), and a page that forges the handshake first can bypass clipboard screening (N4).
  (b) Narrow `web_accessible_resources` to `{ "resources": ["interstitial.html"], "matches": ["http://*/*","https://*/*"] }`, with `use_dynamic_url: true` if Safari accepts it.
  (c) Add `"content_security_policy": { "extension_pages": "script-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" }`.
  (d) Make `build-appex.sh` copy `shared/clipboard-bridge.js`, if it copies files one by one.
- **RampartWeb `.allowHost` (N7)**: unchanged. The extension now sends only strict hostnames that are more than a bare public suffix, but the host must still validate.
