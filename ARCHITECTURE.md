# Rampart — architecture and build rules

Rampart is a macOS antivirus (the product is **Rampart**, renamed because Apple ships
an XProtect engine called "Bastion"). Research lives in `docs/research/01..10-*.md`. Read the ones listed for your module.

## Hard constraints of this machine
- macOS 27, arm64, Swift 6.4, **Command Line Tools only** (no Xcode, no xcodebuild, no paid Developer ID).
- **No Endpoint Security entitlement.** Real-time events come from Apple's `/usr/bin/eslogger` (run by our root daemon), FSEvents, libproc polling and `/usr/bin/log stream`. We detect and respond right after execution; we cannot block before exec.
- **No NetworkExtension.** Web protection = local DNS resolver + DoH upstream + blocklists, plus `pf` IP tables.
- **No XCTest / Swift Testing** (macro plugins missing). Tests go in `Sources/rampart-selftest/SelfTest+<Module>.swift` using `check(cond, "name")`. Run: `.build-<you>/out/Products/Debug/rampart-selftest <suite>`.
- **SwiftUI `@State` does not compile** (SwiftUIMacros plugin missing). Use `typealias StateVar = SwiftUI.State` then `@StateVar`. `@Observable`, `@StateObject`, `@ObservedObject`, `@Bindable`, `@Environment`, `@AppStorage`, `@Binding` work. Do NOT use `#Preview`, `@Entry`. Do not name the `@main` file `main.swift`.
- Language mode is Swift 5 (`swiftLanguageModes: [.v5]`) to reduce concurrency friction.
- Never run `caffeinate` or anything that keeps the Mac awake. Never install system-wide (no sudo, no launchctl bootstrap, no networksetup changes, no pfctl changes) during development; write code and dry-run modes instead. A network web filter (Securly) blocks some security domains and raw.githubusercontent.com; downloaders must validate status and content.
- Never create, download or store real malware or malware-like samples. Test with the EICAR string assembled at runtime from fragments, Apple binaries, and harmless fixtures named `com.rampart.test.*`.

## Ownership (one agent per row; edit ONLY your files)
| Module (target) | Owner | Scope | Research |
|---|---|---|---|
| RampartShared | lead | Models.swift, IPC.swift, Log.swift — shared contract. Do not edit; if you need a change, add a type in your own module or note it in your final report. | all |
| RampartEngine | B1 | File walker (fast enumeration, exclusions, iCloud placeholder skip), file-type sniffing → FileKind, streamed SHA-256, SQLite hash DB (`import SQLite3`) with known-bad hashes + allowlist + scan cache keyed on inode/mtime/size, archive/DMG/PKG unpacking (`/usr/bin/ditto -x -k`, `hdiutil attach -nobrowse -readonly`, `pkgutil --expand-full`) with limits, `ScanCoordinator` that runs registered `FileDetector`s concurrently and turns Evidence into `Detection`s (scoring thresholds), EICAR detector, hash-feed updater (abuse.ch MalwareBazaar recent SHA-256 list) with validation. | 04, 10 |
| CYara + RampartYara | B2 | **CHANGED: no external code. B2 writes a native pure-Swift YARA-compatible engine in RampartYara; CYara stays an empty placeholder.** Original plan was: vendor libyara 4.5.x C sources into `Sources/CYara` (BSD-3; build without OpenSSL/magic/cuckoo; keep LICENSE) or, if source download is blocked, a documented fallback. Swift wrapper `YaraEngine: FileDetector`, compile Apple XProtect rules in place (`Paths.xprotectBundles`, rule-by-rule tolerant compile, recompile on version change, never copy Apple's file into the repo) plus `Rules/rampart-generic.yar` (EICAR + structural rules only, no malware-family strings). Map XProtect rule names to Detection names. | 02, 04 |
| RampartSigning | B3 | `SigningInspector` (SecStaticCode: Apple / DeveloperID / AppStore / adHoc / unsigned / invalid / revoked, Team ID, notarized requirement, hardened runtime, entitlements), Mach-O parser (thin/fat, load commands, LC_CODE_SIGNATURE, dylib list, suspicious load commands), provenance (`com.apple.quarantine` xattr parse, kMDItemWhereFroms), and a `SigningHeuristicDetector: FileDetector` (unsigned/adhoc executable in user-writable or temp path, quarantine stripped, etc.). Cache by cdhash/path+mtime. | 02, 04 |
| RampartTelemetry | B4 | `EventSource` implementations: `EsloggerSource` (spawns `/usr/bin/eslogger` with event list, parses JSONL robustly, version-guarded; only works as root+FDA, reports isAvailable=false otherwise), `FSEventsSource` (FSEventStream with file events on configurable paths, persisted event ID), `ProcessSweepSource` (libproc every N s → exec events for new pids, with signing info), `UnifiedLogSource` (`/usr/bin/log stream --style ndjson` with XProtect/BTM/TCC/syspolicyd predicate). An `EventHub` that fans in sources, dedupes and rate-limits. Mute Apple platform binaries. | 02, 05 |
| RampartBehaviour | B5 | `BehaviourEngine` consuming `SecurityEvent`s: process-lineage tracker, scored rule set (defensive watch conditions from doc 05; e.g. browser→shell→script interpreter chains, Terminal paste-and-run, unsigned code reading browser credential/keychain/wallet paths, quarantine xattr removal then exec, new persistence pointing at unsigned/temp targets, ransomware: canary files + write/rename-rate + entropy), decay windows, thresholds → `Detection`. `PersistenceScanner` enumerating every `PersistenceItem.Kind` (LaunchAgents/Daemons, BTM via `sfltool dumpbtm`, cron, periodic, shell rc, profiles, browser extensions for Chrome/Brave/Edge/Arc/Firefox, system extensions, ssh authorized_keys) and a snapshot differ. | 05, 01, 07 |
| RampartRemediation | B6 | `QuarantineVault` (AES-GCM via CryptoKit, key in Keychain or root-only file, HMAC-signed metadata, strip exec bits, restore with allowlist, purge after 30 days), `ProcessKiller` (SIGSTOP tree, kill leaves-up, pid reuse checks), `LaunchdRemediator` (bootout + disable, dry-run), login item/profile/browser-extension/cron cleanup actions, and an action journal with undo + preview. Everything has `dryRun`. | 07 |
| RampartNetwork | B7 | `DNSFilterServer` (UDP+TCP on configurable port, default 127.0.0.1:53 for root, 5353 for dev), DoH upstream (security.cloudflare-dns.com, fallback dns.quad9.net) via URLSession, domain trie blocklist (hosts / adblock / plain formats), list updater (HaGeZi TIF, URLhaus hostfile; validate), `use-application-dns.net` NXDOMAIN canary, watchdog-safe DNS switch helper (generates `networksetup` commands; dry-run by default) with restore, `PFManager` (anchor + table file generation, dry-run), `ConnectionMonitor` (libproc socket fds/lsof fallback → remote IP + process), `WiFiGuard` (CoreWLAN + ARP gateway MAC change), `PwnedPasswords` (k-anonymity range API). | 06 |
| RampartPosture | B8 | `PostureScanner` producing the 25 `PostureCheck`s from doc 07 (FileVault, firewall, stealth, Gatekeeper, SIP, auto-updates, Lockdown, screen lock via `sysadminctl -screenLock status`, guest, SSH, screen sharing, file sharing, AirDrop, admin count, Rosetta, outdated apps, etc.) with weights, `unknown` never counts as fail, Security Score 0–100, one-click `PostureFixer` only for safe toggles (returns the privileged command; executes only via daemon), plus TCC grant review (when FDA) and browser hijack audit (homepage/search engine). Parsers must be unit-tested on fixture strings. | 07, 09 |
| rampartd + rampart CLI + Packaging | B9 | `rampartd`: root daemon wiring every module — EventHub → BehaviourEngine + on-write scanning via ScanCoordinator → remediation policy → Detection store (JSON/SQLite) → IPC server on Unix socket (`IPC.socketPath` as root, `IPC.userSocketPath` in `--user` dev mode) with peer credential check (`getpeereid`), scheduled scans, signature/blocklist updates. `rampart` CLI: `scan`, `status`, `quarantine list/restore/delete`, `persistence`, `posture`, `update`, `eicar` (writes test file), `--json`. `scripts/build.sh` (release build, assemble `Rampart.app` with Info.plist/icon, embed rampartd + CLI, sign with stable self-signed identity if present else ad-hoc, DMG via `diskutil image create from`, pkg via pkgbuild/productbuild with postinstall that bootstraps the daemon), `scripts/install.sh`/`uninstall.sh` (verified clean uninstall), LaunchDaemon/LaunchAgent plists in `Packaging/`. Do NOT execute install scripts. | 02, 08 |
| RampartApp | B10 | SwiftUI + AppKit app per doc 09: sidebar (Dashboard, Scan, Threats & Quarantine, Protection/Activity, Network, Privacy & Posture, Settings), menu bar extra, onboarding (FDA deep link + detection), notifications (UNUserNotificationCenter, rate-limited), "Why was this flagged?" panel, calm copy, teal accent. Talks to the daemon only via `RampartShared` IPC (a `DaemonClient` you write in the app target); must render a useful demo/offline state when no daemon is running. The app target depends only on RampartShared. | 09, 08, 03 |

## Interfaces
- Detectors implement `FileDetector` (RampartShared). Event producers implement `EventSource`. Results are `Detection` with `Evidence` list.
- Scoring: each Evidence has a 0–100 score; combined confidence = 100·(1 − Π(1 − s/100)). Thresholds: ≥90 auto-quarantine (if enabled), ≥60 alert, ≥30 log only. Hash/YARA-XProtect/EICAR hits are ≥95. Signing heuristics alone never exceed 50.
- **Signal-to-noise policy (2026-11-07, `RampartShared/DetectionPolicy.swift`) is applied after scoring**, in `Protection.handle` before storing and on upgrade by `DetectionReevaluator`. Confirmed (100 % allowed) only for a known-bad hash, XProtect, a vetted YARA rule on a non-test file, an Apple-revoked signature or the R40 stealer chain. One uncorroborated heuristic is capped at 70 %, corroborated heuristics at 89 %, developer / own / bait-opened contexts at 45 %. Tiers: "Needs you" (Likely/Confirmed, open) is the only thing the badge, footer and notifications count; "Handled automatically"; "FYI". Only Confirmed, or Likely with an independent second signal and raw score ≥ 90, may quarantine / kill / reach `Emergency.consider` (EICAR may still be auto-quarantined). Identical findings are merged into one row (count, first/last seen).
- False positives are a release blocker: Apple platform binaries and notarized Developer ID apps get a strong negative prior; heuristics must not fire on `/usr/bin`, `/System`, `/Applications` (Apple-signed).

## Building without colliding
Ten agents build in parallel. Always use your own scratch path and target:
```sh
cd /Users/arankeyhan/Rampart
swift build --scratch-path .build-<module> --target <YourTarget>
swift build --scratch-path .build-<module> --product rampart-selftest && .build-<module>/out/Products/Debug/rampart-selftest <suite>
```
Only the lead edits Package.swift, Sources/RampartShared, Sources/rampart-selftest/main.swift and Suites.swift.
If another module's half-written code breaks your build of a combined product, build your own target only and retry later. Don't fix other agents' files.
Do not `git commit`; the lead commits.

## Phase 2 additions (2026-11-06)
Display name is now **RamPart** (`Product.name`). Bundle IDs, paths and module names stay lowercase `rampart`.
No sample/demo data in shipping builds: the app auto-starts the bundled `rampartd --user` and shows only real data (demo only with an explicit `--demo` dev flag).

| Module | Owner | Scope |
|---|---|---|
| RampartGuard | G1 (Fable) | Tamper protection (self-defence) and remote-access lockdown: block remote access until the user allows it. Wired into rampartd by B9. |
| RampartWeb + rampart-nmh + Extensions/ | W1 (Fable) | Scam Check engine, website auto-scanning (URL + page heuristics), browser extensions (Chromium MV3 + Safari Web Extension sources) with a native messaging host. |
| RampartNetwork/NetworkScanner*.swift | N1 (Fable) | LAN device discovery and risk scan (own subnet only, rate-limited), open ports on this Mac and the router. |
| RampartVault | V1 (Opus) | Password generator, encrypted vault, password storage, Touch ID unlock, Keychain integration, breach check. |
| RampartAI | A1 (Opus) | Gemini-powered tools. API key lives ONLY in the login Keychain (service `app.rampart.ai.gemini`, account `gemini-api-key`). Never write it to disk, logs, or the repo. |
| Resources/Brand | L1 (Opus) | Logo and app icon. |

Every new feature must also be explained honestly in the UI where macOS limits it (e.g. no pre-execution blocking without the Endpoint Security entitlement; Safari extension needs a signed app).

## ZERO POP-UPS RULE (user complaint, 2026-11-06) — overrides everything
During development nothing may cause any dialog on the user's screen. Banned while developing:
- Running `rampartd` in any mode except with `--no-scheduler` AND `RAMPART_NO_PRIVILEGED_TOOLS=1` set in the environment, and killed within 60 s.
- Running `sfltool`, `profiles`, `systemextensionsctl`, `tccutil`, `osascript`, `security` with a write or unlock, `sudo`, or anything using AuthorizationServices.
- Reading the user's login keychain from a freshly built binary (it pops "wants to use your confidential information"). For the Gemini key in dev, read it only via `/usr/bin/security find-generic-password -s app.rampart.ai.gemini -a gemini-api-key -w` piped directly into the request, never printed.
- LocalAuthentication evaluatePolicy, the general NSPasteboard (reading or writing), NSWorkspace open, Apple Events, Accessibility, Location, Bluetooth or Local Network prompts.
- Launching dist/Rampart.app or any .app bundle.
Code must make these impossible by default: `rampartd` must honour `RAMPART_NO_PRIVILEGED_TOOLS=1` by refusing to spawn any of the tools above.

The ONE exception: the **Super Kill Switch** (user-triggered only). After Touch ID (LocalAuthentication, password fallback) the app asks the service (IPC `killSwitch`, 3 s ceiling); if the service doesn't answer, it runs the bundled, signed `Contents/Resources/killswitch.sh` (from `Packaging/killswitch.sh`) through the macOS administrator prompt. With `RAMPART_NO_PRIVILEGED_TOOLS=1` there is no prompt: the script runs in dry-run mode and prints its commands. `sudo rampart killswitch` and `sudo rampart emergency off` are the Terminal escape hatches.

### Emergency Lockdown safety (user incident 2026-11-07)
- Telemetry source failures (eslogger not permitted / missing Full Disk Access / never started / crashed) are `HealthNote`s in `ProtectionStatus.healthNotes`, deduplicated with a count. Never detections, never tampering, never a lockdown trigger (`EmergencyTriggerPolicy.isHealthIssue`).
- Automatic triggers go through `EmergencyNetworkPolicy`: a single signal may alert / freeze / quarantine; tamper and deception signals alone do nothing; the network is cut only for a ransomware burst, exfiltration plus a malicious detection, or two independent strong signals within 10 minutes. Automatic network blocks expire after 10 minutes unless the user chooses Keep blocking, are never re-applied after a restart, and are unloaded on SIGTERM / bootout / uninstall. Only a manual lockdown persists.
- An authenticated admin (or a root peer) can always lift lockdown or restore the internet: readiness is advice, never a gate.

