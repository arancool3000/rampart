# RamPart Secure Browser

A separate, hardened browser for banking, shopping and risky links. Executable target `RampartBrowser`,
depends on `RampartShared` (daemon IPC, paths) and `RampartWeb` (URL risk, brands, blocklists).

## Engine

Built on **WKWebView**. WebKit is the only browser engine Apple lets an app embed on macOS with system
sandboxing, process separation and automatic security updates; shipping Chromium/Gecko without Xcode,
entitlements or a Developer ID is not practical and would lose Apple's patching. Consequences we state honestly in the UI:
- We cannot disable JIT or prove it is off (no public API, no `com.apple.security.cs.allow-jit` control), so we don't claim it.
- Geolocation: macOS WKWebView has no public permission callback, so location requests are never granted (effectively "always denied").
- Third-party cookies are blocked via a `block-cookies` content rule plus the non-persistent store; there is no public "block third-party cookies" switch.
- No browser extensions, by design.

## What it does
- **Before load** (`WKNavigationDelegate.decidePolicyFor`): `URLDecisionPolicy` combines RampartWeb's `URLAnalyzer`
  verdict, brand look-alike match, RamPart blocklists (`*.txt` in the daemon's Blocklists folder, read via
  `FileBlocklistProvider`), scheme rules (javascript:/data:/file: blocked), HTTPS-only upgrade with a warning only when the
  upgrade fails. Risky pages get a calm interstitial whose default button is **Go back**.
- **After load**: a scanner `WKUserScript` in the isolated world `rampart` (page scripts can't see it) reports ClickFix /
  fake-CAPTCHA text, scareware overlays, wallet-drainer prompts, hidden off-site iframes, click-capturing overlays, and password
  forms (native side decides whether the host is a look-alike of the brand shown). A small page-world shim wraps
  `navigator.clipboard.writeText`, `DataTransfer.setData` and `execCommand('copy')`; shell-looking text is replaced with a note
  and reported. Findings arrive through `WKScriptMessageHandler`; `PageFindingPolicy` picks banner / warning / block.
- **Trackers and miners**: `ContentRules` compiles a curated list into a `WKContentRuleList` (third-party only), blocks
  third-party cookies and upgrades mixed content.
- **Privacy**: Banking mode (default) uses one `WKWebsiteDataStore.nonPersistent()` per app session; off = an isolated
  `WKWebsiteDataStore(forIdentifier:)` profile. `isFraudulentWebsiteWarningEnabled`, no auto pop-ups, pop-ups become tabs.
- **Downloads**: `WKDownloadDelegate` → vault folder (`~/Library/Application Support/Rampart/BrowserDownloads`, 0700),
  `com.apple.quarantine` set, exec bits stripped, scanned through the daemon socket (`IPCRequest.scan`), then `DownloadPolicy`
  releases to ~/Downloads, holds for confirmation, or blocks (infected).
- **Permissions**: camera/mic/motion requests render an in-window sheet, default **Don't allow**. JS alerts are in-window too.
- **Anti-phishing address bar**: registrable domain bold, rest dimmed, lock state; punycode shown decoded with an amber badge;
  brand look-alikes labelled "Not <Brand>"; identity popover with certificate subject/issuer and system trust result.
- **Keyboard**: ⌘L, ⌘T, ⌘W, ⌘R, ⌘., ⌘[ / ⌘], ⌘⇧[ / ⌘⇧], ⌘F, ⌘⇧J downloads, ⌘⇧I identity.

## Flags
`--selftest` (pure logic tests, exits), `--render <dir>` (offscreen PNGs, no window, no page load), `--developer`
(exposes "Visit anyway" on blocked pages), `--socket <path>`.
