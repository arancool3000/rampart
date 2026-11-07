# hx8: the app's own attack surface (2026-11-07)

Scope: `Sources/RampartApp/{DaemonClient,DaemonLauncher,AppModel,Notifier,PasteGuardHost,PublicWiFiHost,RampartApp,PermissionGuidePanel}.swift` and `Views/**` (except QuarantineManager.swift and ThreatsView.swift).

## Threat model

Assets: what the app sends to the daemon (PasteGuard clipboard events, URLs and text for scam checks, settings, allow rules, quarantine/restore decisions, disable/uninstall authorization data); what the app shows the user as RamPart's own voice (status, threats, notifications); the user's focus and screen; the passwords and authenticator screens.

Attackers:
- Local malware running as the user. The main one. It can bind sockets in `~/Library`, kill and replace the user-mode helper, post distributed notifications, run `open -a RamPart <files>`, launch the app with arguments, and create files with any names.
- A malicious file, website or message. It chooses file names, process names, LaunchAgent labels and evidence text.
- A hostile Wi-Fi access point. It chooses the SSID that appears in RamPart's UI and notifications.
- Another local user. It can't write in our home folder, but it could try a world-writable socket folder.
- A local root attacker is out of scope: it already owns the machine.

Entry points: the daemon Unix sockets; the helper launch path and its QA flags (`--helper`, `--socket`, `--daemon-root`); notification responses; the distributed "reveal" notification; `application(_:open:)` (Dock drop or `open -a`); every UI string that comes from detections, the activity log, persistence items, Wi-Fi or network data; PasteGuard's clipboard reads; single-instance detection.

## Findings

| # | Severity | File:line | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | DaemonClient.swift:41-75 | The app connected to whatever was listening on `/var/run/rampart.sock` or `~/Library/Application Support/Rampart/rampart.sock` and trusted it fully. Malware running as the user could kill the user helper, bind its own socket and then receive every clipboard event, URL and settings change, show fake "Protected" status, and suppress real detections. | `DaemonPeerTrust` checks every connection before the first byte is written. The socket file is checked with lstat: it must not be a symlink and must be a real socket; the root socket must be owned by root; the user socket must be ours, in a folder no one else can write. The peer is checked with getpeereid: uid 0 is accepted (the root daemon). Same-uid peers are accepted only if their running code (LOCAL_PEERPID → SecCode) satisfies the bundled helper's designated requirement, and only after the app's own signature, including nested code in Contents/Helpers, has verified. Anything else gets the new `.untrusted` error, which tells the user "Something that isn't RamPart's background service answered…" | Fixed |
| 2 | High | DaemonClient.swift:27, DaemonLauncher.swift:30-44 | Anyone could relaunch the installed app with `--socket /evil` or `--helper /evil`, which pointed the real, trusted app at a fake daemon. | QA flags are honoured only by copies outside /Applications, or in headless checks (`DaemonPeerTrust.devOverridesAllowed`). | Fixed |
| 3 | Medium | DaemonLauncher.swift:83-116 | The helper was launched if `Contents/Helpers/rampartd` existed and was executable. A swapped file or a symlink would be run. | Before `run()`, the file must be a regular file (no symlink) that satisfies the trusted helper requirement. If not, launch is refused with honest copy. | Fixed (a TOCTOU window remains between the check and exec. Once it is running, the peer check (#1) catches a swapped binary.) |
| 4 | Medium | DaemonLauncher.swift:100-111 | The helper inherited the app's whole environment, including any `DYLD_*`. Its log was opened through a path that a planted symlink could redirect. | `DYLD_*` and `__XPC_DYLD*` are stripped. The log is opened with `O_NOFOLLOW \| O_APPEND \| O_CLOEXEC` and mode 0600. If that fails, output goes to /dev/null. | Fixed |
| 5 | Medium | Notifier.swift:72-85, 113-121 | File names, detection names, Wi-Fi SSIDs and reasons went straight into notification text. An SSID such as `Free\nRamPart: this network is safe` or a file named `invoice‮exe.pdf` would read as RamPart's own words. | All of it goes through `SafeText.line`, which strips C0/C1 controls, bidi overrides and isolates, zero-width and tag characters, collapses line breaks, and truncates (names to 60, SSIDs to 32). The values are also quoted. | Fixed |
| 6 | Medium | Notifier.swift:128-146 | "Stay connected" was obeyed for any response with that action ID, even with no disconnect pending. Every other action, including unknown ones, activated the app. | The action is honoured only for the wifi category, while a disconnect is pending, and when it carries a per-notification token that matches the newest one. Only the default, `review` and `allow` actions activate the app. | Fixed |
| 7 | Medium | AppModel.swift:163-176 + Views | Activity titles, scan paths, persistence labels and targets, remediation commands, network hosts and app names, SSIDs and rule names were shown raw. These include newlines, RTL overrides and unbounded length. | `ActivityItem.init` sanitises its title and outcome. ScanView, MenuBarView, NetworkView, RulesView and PostureView use `SafeText.line` for names and `SafeText.path` for paths (middle truncation keeps the file name visible). Markdown: every site uses `Text(String)` or interpolation inside a literal, and SwiftUI never parses Markdown in either, so `[link](…)` stays literal text. Verified: no `AttributedString(markdown:)` or `LocalizedStringKey(var)` in the owned files. | Fixed |
| 8 | Medium | RampartApp.swift:33-39 | Single instance matched on bundle ID alone. Any app claiming `app.rampart.app` would make RamPart quit on every launch, which is an easy way to silence it. | The other process must run from this very bundle path or satisfy our own designated requirement (the same certificate, or for ad-hoc builds the same binary). | Fixed |
| 9 | Low | RampartApp.swift:28-30 | Any process can post the distributed "reveal" notification to keep pulling RamPart to the front (focus stealing, or cover for a spoofed dialog). | It only ever shows our own window and is rate-limited to once per 2 s. | Fixed (an honest limit: distributed notifications carry no sender identity) |
| 10 | Low | RampartApp.swift:100-110 | `open -a RamPart <anything>` could start a scan with unbounded, non-existent or duplicate paths, repeatedly. | Only existing local file URLs are accepted, standardised, de-duplicated and capped at 64, and nothing happens while a scan is running. The app has no URL scheme (no CFBundleURLTypes in build.sh). | Fixed |
| 11 | Low | PasteGuardHost.swift:27-66 | The clipboard was read whenever not headless, including dev runs with `RAMPART_NO_PRIVILEGED_TOOLS=1`. The event queue was unbounded while the daemon was away. | Now gated on not headless, not `RAMPART_NO_PRIVILEGED_TOOLS=1`, and the `pasteGuard.enabled` default (true). The queue is capped at 200. PasteGuard already honours "Paste from Other Apps" and skips concealed types. Clipboard events only reach a verified daemon (#1). | Fixed |
| 12 | Info | owned files | Secrets in UserDefaults | None found. Owned keys are UI preferences only. A regression check scans the owned files. | OK |
| 13 | Info | Features/Passwords/CaptureShield.swift | Sensitive windows and screen capture | Already handled by the Passwords owner (`protectedFromCapture`, `sharingType = .none`). I didn't add a second mechanism, so the two can't fight. | OK (owner) |

## Honest limits
- RamPart is ad-hoc signed (or signed with a local certificate) and has no Apple-issued identity. Malware running as you that can rewrite and re-sign the whole app bundle can still impersonate it. What stops that is macOS App Management protection for /Applications, not these checks.
- With pure ad-hoc signing, the helper requirement is a cdhash. A user helper left running from an older build (Keep protecting when closed) is refused after an update until it restarts. The app then says the service "isn't RamPart's". This is safe but noisy. With the "Rampart Local Signing" identity, the requirement is identifier plus certificate, so it holds across versions.
- `sharingType = .none` is a request. Recent ScreenCaptureKit versions and cameras ignore it.

## Needs owner
- **Views/ThreatsView.swift and QuarantineManager.swift**: wrap detection `name`, `path`, evidence `title`/`detail` and process names in `SafeText.line(_, max:)` and `SafeText.path(_)` (defined in AppModel.swift). These are the main places attacker text appears.
- **Features/** (ScamCheck, NetworkScan, RemoteAccess, AIAssistant): use `SafeText.line` for host names, device names, tool names and AI or daemon reasons.
- **RampartBrowser/Engine/BrowserDaemonClient.swift and Sources/rampart/main.swift**: they have the same fake-socket exposure. Copy `DaemonPeerTrust` (socket lstat + getpeereid + SecCode requirement), or better, move it into RampartShared.
- **RampartShared**: move `SafeText` and `DaemonPeerTrust`'s pure policy functions there, so rampart-selftest can unit-test them directly. Until then, hx8 tests the OS primitives and pins the code (see below). The pure policies were exercised in a scratch harness (24/24 cases).
- **rampartd IPCServer (user mode)**: make sure the socket folder is created 0700 and the socket is 0600. The app now refuses a group- or world-writable folder.
- **Updater / InstallToApplications**: after replacing the app, restart the user helper (`SMAppService` unregister and register, or terminate the child), so an ad-hoc build doesn't hit the stale-helper limit above.

## Tests
`Sources/rampart-selftest/SelfTest+HX8.swift` → `hx8Checks()`:
- Peer primitives on a scratch socket in the temp dir. lstat detects the socket and a symlinked path. getpeereid gives the server uid. LOCAL_PEERPID gives the server pid. SecCode for that pid fails a look-alike requirement and passes its own designated requirement.
- Source invariants. The peer check runs before the first write. The socket file is checked. Trust is anchored with nested-code verification. The QA flags are gated. The helper is verified before launch. The log uses O_NOFOLLOW. DYLD is stripped. SafeText covers activity, notifications and SSIDs. The Stay connected token is checked. The single-instance sibling is verified. Reveal is rate-limited. Dock paths are capped. PasteGuard is gated and its queue bounded. No secret-looking UserDefaults keys.

Suites.swift line: `("hx8", SelfTest.hx8Checks),`
