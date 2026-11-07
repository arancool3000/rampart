# harden-hx10: root-daemon authorization and security posture (2026-11-07)

Scope: `Sources/rampartd/IPCServer.swift`, `Core/Router.swift`, `Core/IPCAuthz.swift` (new), `Core/Privileged.swift`,
`Core/Activity.swift`, `Core/Store.swift`, `Core/GuardWiring.swift`, `Core/Config.swift`, `main.swift`, `Sources/RampartPosture/**`.
Tests: `Sources/rampart-selftest/SelfTest+Hx10.swift` (`hx10Checks`), with `Sources/rampart-selftest/IPCAuthz.swift` symlinked to the daemon's copy.

## Threat model

Assets: the root daemon's power (kill, quarantine, restore, DNS, firewall and posture toggles, allow rules, pause and uninstall),
the detection, activity and allow-rule stores (they hold every user's file paths and URLs), the settings-session and disable tokens, and the log.

Attackers:
1. Local malware running as the console user, who is usually an admin. It can open the 0666 root socket, run RamPart's own CLI, and read and write the user's files.
2. Another local user (standard or admin) on the same Mac.
3. A raw-socket client or a re-signed copy of RamPart's binaries.
4. A malicious web page or message whose text reaches the activity feed or the log (page titles, URLs, file names).
5. A tampered or planted file in the state folder (symlinks, loose permissions left by older versions).

Entry points: every `IPCRequest` on `/var/run/rampart.sock`, the posture-fix path, forwarded session events, and the state files read at startup.

## Authorization matrix (root daemon; `IPCAuthz.level` / `IPCAuthz.denial`)

Levels:
- **anyLocal**: any peer the kernel identified.
- **sessionUser**: root, the console user (owner of `/dev/console`), or any admin.
- **adminClient**: root, or an admin calling from RamPart's own signed app or CLI.
- **adminClientWeakening**: the same as adminClient, plus: from the CLI, the call also needs an admin-authenticated settings session opened by that same process. The GUI app may make these calls directly, because a script cannot drive the app without an Accessibility grant.

| Caller ↓ / level → | anyLocal | sessionUser | adminClient | adminClientWeakening |
|---|---|---|---|---|
| root | allow | allow | allow | allow |
| console admin + RamPart app | allow | allow | allow | allow |
| console admin + RamPart CLI | allow | allow | allow | needs settings session |
| console admin + unverified client (script, raw socket, re-signed copy, nmh) | allow | allow | **deny** | **deny** |
| console standard user | allow | allow | deny | deny |
| other admin user + app / CLI | allow | allow | allow | allow / needs session |
| other standard user | allow | **deny** | deny | deny |
| unauthenticated (no peer credentials) | deny (connection dropped) | deny | deny | deny |

Requests by level:
- **anyLocal**: status, health, checkURL, scamCheck, webLookup, scan (standard users stay limited to their own and shared folders), forwardEvents (now sanitized).
- **sessionUser**: listDetections, listQuarantine, posture, persistence, activity, connections, wifi, networkStats, getSettings, previewRemediation, listAllowRules, remoteAccessReport, tamperStatus, subscribeEvents, pauseScan, cancelScan, webVerdict.
- **adminClient**: quarantine, deleteQuarantined, fixPosture, updateSignatures, remediate, removeAllowRule, revokeRemoteTool, requestDisableProtection, disableProtection, requestUninstall, uninstall, setRealtime(on), setWebProtection(on), setRemoteLockdown(on), and setSettings when it weakens nothing.
- **adminClientWeakening**: allow, addAllowRule, allowRemoteTool, restore, restoreQuarantinedTo, exportQuarantined, sandboxRun, setRealtime(off), setWebProtection(off), setRemoteLockdown(off), and setSettings that turns a protection off (`IPCAuthz.settingsWeaken`).

The tests run every request through every caller column (13 caller variants × all 46 request cases, plus the on/off variants) and check that every request Router lists as privileged needs at least adminClient.

User mode (`--user`) is unchanged: its socket is 0600 and accepts only the same uid, so the matrix is not applied there.

## Findings

| # | Sev | File:line | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | Router.swift:94, IPCServer.swift:131 | Privileged calls checked only that the caller was in the admin group (getpeereid). Any script running as the usually-admin console user could open the 0666 socket and turn off real-time protection, web protection or lockdown, add allow rules, restore or export malware, or run remediation. | Client code identity is now read through the kernel audit token (`LOCAL_PEERTOKEN` → `SecCodeCopyGuestWithAttributes`; strict static check plus dynamic validity; hardened runtime required; not linker-signed only; no get-task-allow, disable-library-validation, DYLD or unsigned-memory entitlements; identifier `app.rampart.app` or `app.rampart.cli`; Team ID must match the daemon's when the daemon has one; optional install-time cdhash pins in `<root>/trusted-clients.json`, which must be root-owned and not group- or other-writable). Privileged calls need an admin plus a verified client. | Fixed |
| 2 | High | IPCAuthz.swift `level` | Malware can still run the real CLI (`rampart realtime off`, `rampart allow <sha>`). | Protection-weakening calls from the CLI also need an admin-authenticated settings session opened by the same process (see #5). The GUI app is exempt, because a script cannot drive it without Accessibility. | Fixed (CLI side: needs owner) |
| 3 | Medium | Router.swift `IPCAuthz.level` | Any local user, including other standard users, could read listDetections, activity, subscribeEvents, persistence, connections and settings. These hold other users' file paths, URLs and events. Other users could also cancel or pause the admin's scans and add web-warning entries to the activity feed. | These requests are now sessionUser: console user, admin or root only. | Fixed |
| 4 | High | Router.swift `forwardEvents` → `IPCAuthz.sanitizeForwarded` | A standard user could forward a forged event naming another user's process or a root-owned file. Behaviour rules could then make the root daemon kill that process or quarantine that file. Forged `isPlatformBinary` and `signingID` values were trusted. | For non-root peers, an event whose process is not owned by the peer (checked with sysctl) or whose path or destination exists with a different owner is dropped. Claimed signing facts are cleared, the real uid is set, and oversized detail fields are removed. | Fixed |
| 5 | Medium | GuardWiring.swift:89-106 | The settings session was per uid and per any purpose: once the admin authenticated, every process of that user could add broad exclusions for 10 minutes. A pause or uninstall session also authorized broad exclusions. | The session is bound to the redeeming process (pid plus pidversion from its audit token), and only a `.settings` purpose counts. | Fixed |
| 6 | Low | GuardWiring.swift:100 | `minutes` was unbounded for the session length (pausedUntil was capped but the session was not). Huge or negative values were accepted. | Clamped to 1...1440. Router refuses a pause longer than 24 h, and allowRemoteTool minutes must be 1...10080. | Fixed |
| 7 | Medium | Router.swift:140 | fixPosture passed caller text into errors, the log and an Activity title ("Could not fix <text>"), which allowed UI spoofing and log forging. | The check id must be ≤40 ASCII alphanumerics and an exact member of `PostureFixer.fixableCheckIDs`, and the planned fix must pass `PostureFixer.isSafe`. No shell is used anywhere: argument arrays only, from a fixed table. | Fixed |
| 8 | Low | PostureFixer.swift:32-52 | There was no executor-side validation that a fix's commands are the allow-listed tools. | Added `allowedExecutables` and `isSafe` (absolute allow-listed executables only; arguments are short printable ASCII with no space, `;`, `|`, `&`, `$` or backtick; reverts included). `fix(for:)` now returns nil for anything not exactly fixable. | Fixed |
| 9 | Medium | Store.swift, Activity.swift, Config.swift, GuardWiring.swift:119 | `Util.writeJSON` writes with `.atomic` (umask-dependent temp file, 0644 as root), then chmods, which leaves a window where detections, allow rules and policy are world-readable. Activity was appended through `FileHandle` (follows symlinks). Loose permissions from older versions were never tightened. | New `SecureStore`: O_EXCL, O_NOFOLLOW temp file, fchmod 0600, fchown root, fsync, rename. Reads refuse symlinks, non-regular files and files over 64 MB, and tighten loose permissions. Activity appends with O_NOFOLLOW and O_APPEND at 0600. At startup the root daemon checks the state folder's owner and mode and sets 0600 on the known state files. | Fixed |
| 10 | Medium | Activity.swift `add`, Router.swift (webVerdict, posture, disable reason) | Attacker text (page titles, file names, reason strings) went unfiltered into the log file and the activity feed. Newlines forged log lines, and bidi overrides reversed text (`invoice‮fdp.exe`). | `LogRedact.clean`: removes control, bidi and invisible characters, caps length, and redacts tokens, `password=`, bearer and API keys, and long hex or base64 blobs (SHA-256 kept). Applied to every activity entry and to the attacker-influenced log lines. webVerdict score is clamped to 0...100. | Fixed |
| 11 | Info | TamperProtection.swift `redeem` | Settings token review: single use (consumed before the expiry check), uid-bound (a wrong-uid try does not consume it), 120 s TTL, MAC over nonce.uid.expiry (rebinding to root fails), replay refused. All are covered by hx10 tests. `issued` is never pruned, so tokens that are never redeemed accumulate (admin plus authorization needed per token: low risk). | Needs owner (RampartGuard): drop expired entries in `issueToken`. | Needs owner |
| 12 | Low | Integrations.swift:216 `PostureAdapter.fix` | Fix commands run through `Process` with no timeout (a hung `systemsetup` blocks the IPC thread forever) and without calling `PostureFixer.isSafe`. | Needs owner: `guard PostureFixer.isSafe(fix) else { throw ServiceError.denied("unsafe fix") }`. Run through `GuardedPostureRunner().run(cmd[0], Array(cmd.dropFirst()), timeout: 30)` and fail on `!usable`. | Needs owner |
| 13 | Low | Util.swift `writeJSON` / `DLog` (not owned) | Other modules still use `Util.writeJSON`, with the same window as #9. The log file is 0640 in a 0755 folder, and `DLog.log` does not filter messages. | Needs owner: make `Util.writeJSON` call `SecureStore.writeJSON`, and pass every message in `DLog.log` through `LogRedact.clean(msg, max: 4000)`. | Needs owner |
| 14 | Info | CLI `Sources/rampart/main.swift` (not owned) | After #2, `rampart realtime off`, `rampart allow`, `rampart lockdown off` and similar fail against the root daemon unless a settings session exists. | Needs owner: the CLI should run the admin-authentication flow (`requestDisableProtection(authorization:)` → `disableProtection(token, minutes: 0)`) on the same connection or process before weakening calls, or tell the user to use the app. | Needs owner |
| 15 | Info | rampart-setup.sh / installer (not owned) | cdhash pins are optional. | Needs owner: at install (as root) write `/Library/Application Support/Rampart/trusted-clients.json` (root:wheel 0644) with `codesign -dv --verbose=4` CDHash values of `Rampart.app/Contents/MacOS/Rampart` and `Contents/Helpers/rampart`. | Needs owner |

## Honest limits

- RamPart is ad-hoc signed today. An ad-hoc signature proves the binary is intact but not who signed it: anyone can sign their own program with the identifier `app.rampart.cli`. Without install-time cdhash pins (#15) or a real Developer ID (then the Team ID check applies automatically), a determined attacker running as an admin can make a convincing fake client. The client check stops raw-socket scripts and unsigned or debuggable tools, not a targeted attacker.
- Malware running as the user can always call whatever the real app or CLI can call without a password. Weakening from the CLI now needs an administrator password. The app is exempt only because macOS prevents scripted UI control without an Accessibility grant.
- A process can hand its open socket to another process. Identity is taken at connect time, which is how macOS reports it.
- The console user is whoever owns `/dev/console`. At the login window nobody counts as the console user, so only admins and root get sessionUser access.

## Tests

`hx10Checks`: 13 caller variants × 4 levels, all 46 request cases (49 samples) × 13 callers, client-identity trust rules, real-kernel checks (a real audit token over a socketpair, and a stale pidversion that yields no identity), forwarded-event sanitizing, posture-fix injection, settings-token single use / uid / expiry / replay / forgery, SecureStore permissions and symlink races, and log redaction.

Suites.swift line: `("hx10", SelfTest.hx10Checks),`
hx10: 859 passed, 0 failed; daemon 39/0, redteam 128/0, guard 111/0, posture 140/0.
