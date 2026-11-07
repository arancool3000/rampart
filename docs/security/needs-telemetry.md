# needs-telemetry — fix proposals from attack set X4 (do NOT edit production source; owner = B4)

Source: `Sources/rampart-selftest/SelfTest+AttackX4.swift`, `docs/security/attacks-X4.md`.

## 1. (High) Telemetry-blind is silent — X4.17

`Sources/RampartTelemetry/EsloggerSource.swift`: when the eslogger child exits with "not permitted" / "full
disk access" (FDA was revoked), `onExit` records the reason in `lastError` and sets `s?.restartOnExit = false`.
`EventHub` (`start`) only checks `s.isAvailable` once at startup. There is no path that turns "the primary
exec feed has died and will not come back" into a `Detection` or user-facing alert. An attacker who revokes
FDA (see needs-guard #1, the unqualified `tccutil reset`) silences BehaviourEngine and most tamper detection
with no visible sign — the single most effective way to blind RamPart unnoticed.

Proposed fix: make source health observable and promote a dead/blinded primary source into a Detection.

1. Add to `EventSource` (RampartShared, note for the lead) or to `EsloggerSource`/`EventHub` a health signal:
   `var lastError: String? { get }` already exists on `EsloggerSource`; expose `healthy: Bool`
   (`isAvailable && isRunning && lastError == nil`).
2. In `EventHub`, run a lightweight health timer (every ~15 s). When a source that was available becomes
   unavailable or stops restarting, emit a synthetic high-severity Detection via the normal handler path, e.g.:

```swift
Detection(name: "\(Product.name) lost its real-time event feed",
          category: .suspicious, severity: .high, confidence: 85,
          evidence: [Evidence(source: .behaviour,
            title: "Primary telemetry source '\(source.name)' is down",
            detail: source.lastError ?? "source stopped; real-time protection is blind until it restarts",
            score: 85)])
```
   The daemon (B9) routes this to the UI so the menu-bar state flips to "not protected" instead of silently
   staying green. This is the honest-limit counterpart to the ZERO POP-UPS rule: no block is possible, but the
   user must see that protection went dark.

Self-test: inject a stub `EventSource` whose `isAvailable` flips to false (or whose `lastError` is set) and
assert the hub emits exactly one "feed lost" Detection, and none while healthy.

## 2. (Low) Impostor `rampartd` binary — X4.19

A decoy process named `rampartd` from a non-install path (e.g. `/tmp/rampartd`, ad-hoc / foreign signing id)
can spoof the user's trust and menu-bar presence. Guard correctly does NOT treat it as a kill target, so the
check belongs here: `ProcessSweepSource` / `EsloggerSource` enrichment should flag an exec whose process name
matches a RamPart service name (`rampartd`, watchdog) but whose path is outside the install paths or whose
signing id is not `app.rampart.*`. Emit a low/medium Detection ("process impersonating \(Product.name)").

## 3. (Medium-High) No clipboard-read event — clipboard sniffing is invisible — X5.17

RamPart's vault and Authenticator offer "Copy password" / "Copy code". A background process that polls
`NSPasteboard.general.changeCount` and reads the pasteboard right after a copy lifts those secrets, but **no
`EventSource` emits any event for a clipboard read**, so no behaviour rule can ever fire (PasteGuard only
watches paste *into* Terminal). Proposal: add a best-effort clipboard-access signal.
- Emit `SecurityEvent(kind: .other, detail: ["type": "clipboardRead", "poll": "1"])` attributed to the reading
  process when telemetry can observe pasteboard access. macOS surfaces pasteboard access in the unified log
  (`com.apple.pasteboard` / `Pasteboard access` entries since Ventura) — `UnifiedLogSource` can parse these and
  attribute the reader. Where attribution is impossible, still emit the event with the accessor pid left nil so
  the behaviour engine can at least correlate with an untrusted actor already in a stealer story.
- Honest-limit note for the UI: without the Endpoint Security entitlement this is after-the-fact, not a block.

Self-test (behaviour side, X5-17): a synthetic `clipboardRead` event from an untrusted actor currently yields
zero detections; once the event exists, add the paired rule in needs-behaviour.md item 4.

## From attack suite X6 (everyday Mac threats, 2026-11-07). Evidence: `rampart-selftest attackx6`, compare with `X6_NOMUTE=1`

### T-X6-1 (High): standard muting drops Apple Terminal / Script Editor execs, which breaks ClickFix lineage
**File:** `Sources/RampartTelemetry/EventHub.swift` `shouldMute(_:policy:)`, `.standard` branch (~line 145).
`daemonDir = p.path.hasPrefix("/System/") || …; return daemonDir && p.ppid == 1` also matches the GUI apps
`/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal` and `/System/Applications/Utilities/Script Editor.app/...`
(both launched by launchd, ppid 1). With no Terminal node, `ancestor: ["@terminals"]` never matches. R31 (ClickFix)
then never fires for the built-in Terminal, the `pasteEntry` mark is never set, and R08/L07/R23/R57 miss pasted chains.
X6 A02: R41 only (conf 45) instead of R31+R41 (conf 99). A26 and A36: missed instead of caught.
**Fix:** in `.standard`, never mute execs of app bundles:
```swift
if ev.kind == .exec {
    if p.path.contains(".app/Contents/MacOS/") { return false }   // GUI apps (Terminal, Script Editor, Finder…) anchor lineage
    let daemonDir = p.path.hasPrefix("/System/") || p.path.hasPrefix("/usr/libexec/") || p.path.hasPrefix("/usr/sbin/")
    return daemonDir && p.ppid == 1
}
```
(At minimum add `/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal` and Script Editor to `neverMute`.)
Also, when ProcessSweep seeds already-running processes at startup, it should not run them through this filter.
Self-test: X6 A02 must report R31 with muting on.

### T-X6-2 (Medium-High): file events from non-LOLBin Apple tools are muted, so these writes are invisible
`.standard` drops all file events of platform binaries outside `neverMute`. Writers seen in real attacks that fall
into that gap: `/usr/bin/tee` (`sudo tee -a /etc/hosts`, `tee -a ~/.ssh/authorized_keys`, `tee /etc/pam.d/sudo`),
`/usr/libexec/PlistBuddy` and `/usr/bin/plutil` / `/usr/bin/defaults` (LaunchAgent plists), `/usr/bin/sed -i`, `/usr/bin/at`.
X6 A18/A20/A25/A33 are missed or partial only because of this.
**Fix:** do not mute file events whose path is persistence- or trust-critical, whoever writes them. Add before the
platform check:
```swift
static let criticalPathPrefixes = ["/private/etc/", "/etc/", "/Library/LaunchAgents/", "/Library/LaunchDaemons/",
    "/usr/lib/cron/", "/private/var/at/", "/Library/Security/SecurityAgentPlugins/", "/usr/local/lib/pam/",
    "/Library/Preferences/SystemConfiguration/", "/Library/Managed Preferences/"]
static let criticalPathInfixes = ["/Library/LaunchAgents/", "/.ssh/", "/External Extensions/", "/NativeMessagingHosts/"]
if isFileEvent(ev.kind), let path = ev.destPath ?? ev.path,
   criticalPathPrefixes.contains(where: path.hasPrefix) || criticalPathInfixes.contains(where: path.contains) { return false }
```
and add `/usr/bin/tee`, `/usr/libexec/PlistBuddy`, `/usr/bin/plutil`, `/usr/bin/defaults`, `/usr/bin/at` to `neverMute`
(their exec volume is low).
