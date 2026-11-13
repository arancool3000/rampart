# wms-o3: browser attack surface (2026-11-13)

Scope: `Extensions/chromium/**` (shared JS, popup, interstitial, content script), `Extensions/safari/manifest.json`,
`Extensions/native-host/*`, `Sources/rampart-nmh`, `Sources/RampartWeb/NativeMessaging.swift`,
`Sources/RampartSafariExtension/MessageValidator.swift`, `Sources/RampartBrowser/**`.

## Threat model

The attacker is a hostile web page (and the ads and frames it loads). It controls DOM, page-world JS, timing, the top layer
and fullscreen (with a user gesture), and every string the content script collects. It wants to:
reach rampart-nmh or rampartd; forge extension messages; get rid of or click through RamPart's warnings; read or change
clipboard decisions; misuse the tracker-count feature; inject into the popup; and tell RamPart users apart from everyone else.
Out of scope: local malware running as the user (it can launch rampart-nmh or edit the extension itself) and malicious
browser extensions with broader permissions.

## What was already sound (verified, now covered by regression tests)

- There's no `externally_connectable`. The background accepts only `sender.id === runtime.id`. Content messages must come from frame 0 of an http(s) tab, and the page URL is taken from `sender.url`.
  Settings and status go only to the popup. Allow, continue and open-interstitial need a verdict that RamPart itself recorded.
  The interstitial uses a 128-bit token. JSC-driven tests cover all of this with spoofed senders.
- The native host manifests pin exactly one `chrome-extension://<id>/` origin and use stdio, with no wildcard. Pages can't reach the host: only the extension can call `connectNative`.
- The popup, interstitial and content UI are built with `textContent` only. The CSP is `script-src 'self'` with `frame-ancestors 'none'`. The interstitial is the only web-accessible resource, and its URL is per-session (`use_dynamic_url`).
- The Secure Browser: file:, blob:, data: and javascript: URLs are blocked in every frame. It isn't inspectable. Message handlers exist only in the isolated `WKContentWorld`.
  Every download goes through the `WKDownload` vault. Each tab gets a non-persistent store per session (Banking mode) or an identified profile that is separate from Safari's.

## Findings

| # | Sev | Where | Issue | Fix | Status |
|---|-----|-------|-------|-----|--------|
| 1 | Med | rampart-nmh / `WebVerdictService.handle` | The Chromium host had no validator (Safari's validator didn't apply to it). It accepted any URL scheme (file:, javascript:), so those were forwarded to rampartd's activity log. It also accepted unbounded html, text and signals (regex CPU), any `decision` string, raw `hosts`, and echoed ids of any length. | Added `NMRequestSanitizer`, which `handle()` runs first, so it covers every transport. It requires http(s) URLs of at most 8 KB and an id of at most 64 characters, whitelists decisions, accepts only plain hostnames in `hosts` (300 at most), and caps every string and array in `PageSignals`. | Fixed |
| 2 | Low | `NativeMessaging.readFrame` | The host accepted 64 MiB frames, Chrome's ceiling, so a single message could make it allocate 64 MiB. | `hostMaxInbound` is 4 MiB. An oversized length header ends the session without reading the body. | Fixed |
| 3 | Med | `shared/clipboard-main.js` | Fingerprinting: `"__rampartClipboardHooked" in window` identified every RamPart user to any site, and `writeText.toString()` printed RamPart's source. | Removed the global. The hooks are now Proxies around the native functions, which keeps the native name, length and toString. Running the script a second time does nothing, because the prototypes are already locked. | Fixed |
| 4 | Med | `content.css` in both manifests | Fingerprinting: a stylesheet was injected into every page. A site could add `rampart-locked` to `<html>` and see the `!important` rule apply. | Removed it from both manifests. The scroll lock is now an inline style, set only while a block is showing and restored afterwards. | Fixed |
| 5 | Med | content.js | Clickjacking: the top layer is ordered by insertion. A page could open a popover, modal or fullscreen element after the warning, set `pointer-events:none` on it, and paint a fake "Go back" over "Continue anyway". | Toggle and fullscreen changes are caught in the capture phase, and the watchdog also polls for them. When one appears, page fullscreen is exited, the warning is moved back on top, and clicks are ignored for 500 ms (`H.uiClickAllowed`). A click is also refused if a foreign top-layer element is open at click time. | Fixed |
| 6 | Low | background.js `page:status` | The popup showed the tracker count stored for the tab even after the tab had moved to another site, attributing one site's trackers to another. | The count is shown only when the active tab's host matches the counted host. | Fixed |
| 7 | Low | Safari `MessageValidator` | `countTrackers` and `hosts` weren't whitelisted, so the Safari tracker count always failed. | Added both, with hostname-only `hosts`. | Fixed |
| 8 | Low | Secure Browser `BrowserModel.configuration` | WKWebView's default user agent has no `Version/… Safari/…` part, which marks RamPart browser users, and some sites treat it as an in-app web view. | The browser now sets `applicationNameForUserAgent` to the installed Safari's version, validated as a dotted number, with a fallback of `18.0`. | Fixed |

## Tests

- `Sources/rampart-selftest/SelfTest+WMSo3.swift`, suite `wmso3`, 88 checks:
  - the sanitizer and caps;
  - the frame cap over a pipe;
  - manifest and native-host manifest invariants;
  - JavaScriptCore runs of `heuristics.js` (click guard);
  - `clipboard-main.js` with page-world stubs: no global, no source in toString, forged and second handshakes, wrong-nonce decisions, deny and allow;
  - `background.js` with 15 spoofed-sender cases and the tracker-host check;
  - an end-to-end rampart-nmh run with a 5 KB id, a file: URL and a 60 MiB header.
- `Sources/RampartBrowser/SelfTests+WMSo3.swift` (`RampartBrowser --selftest`): UA policy and hostile version strings, local and script schemes blocked in every frame.

## Residual risks (honest limits)

- **Page-world hooks are detectable.** The locked prototype descriptors (needed to stop `delete`) and the clipboard prompt itself can still be seen. The Secure Browser's page-world shim wraps `appendChild` and similar functions and keeps a `__rampartShim` global. That browser is identifiable by design.
- **A page can block the warning's buttons.** It can toggle its own popover over and over to keep re-raising us, which makes the buttons unclickable (denial of service, not a click-through). A modal `<dialog>` can make our popover inert. The browser's own Back still works.
- **Same-origin iframe realms** still hold unpatched clipboard prototypes (extension, as before).
- **Any local process can launch rampart-nmh.** Chrome's `allowed_origins` only limits browsers. No code in the repo installs the native-host manifests yet ("Install browser protection" isn't wired up). Whoever adds it must substitute one real extension ID, never `*`.
- **No ES or NE entitlements, ad-hoc signing.** The extension and the browser are the only enforcement points for web content. Downloads made in other browsers rely on Download Gate when they arrive.
