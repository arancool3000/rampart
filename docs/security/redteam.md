# Red-team pass (2026-11-07)

Suite: `Sources/rampart-selftest/SelfTest+RedTeam.swift`, `static func redTeamChecks()`, registered in Suites.swift as
`("redteam", SelfTest.redTeamChecks),`. Run:
`RAMPART_NO_PRIVILEGED_TOOLS=1 RAMPART_REDTEAM_DIR=<scratch> .build-agents/out/Products/Debug/rampart-selftest redteam`
(optional `RAMPART_REDTEAM_FUZZ=<n>` fuzz cases, default 3000; `RAMPART_REDTEAM_KEEP=1` keeps the scratch root).
It drives a disposable `rampartd --user --no-scheduler --no-realtime --no-updates` with `RAMPART_NO_PRIVILEGED_TOOLS=1`
on a scratch root. Note: when RamPart is installed on the machine, the real daemon may quarantine scratch EICAR files
within ~3 s; affected checks print SKIP.

## Fixed (in owned modules)

| Sev | File | Issue | Fix |
|---|---|---|---|
| High | Sources/RampartShared/IPC.swift `readFrame` | Buffer for the announced length (up to 64 MB) was allocated and zero-filled before any body byte arrived. 40 connections each sending only a 60 MB header pinned ~2.4 GB in rampartd. | Buffer grows as bytes arrive (1 MB chunks, EINTR-safe). Added `readFrame(fd:maxLength:)`, `IPC.maxFrameLength`, `IPC.maxRequestLength` (8 MB). Test: "40 x 60 MB announced frames do not pin memory". |
| High (root mode) | Sources/RampartRemediation/QuarantineVault.swift `restore` | TOCTOU: the destination folder was checked by path (QuarantineSandbox.checkDestination, ProtectedPaths) and then written by path. A user could swap their own folder for a symlink to e.g. /Library/LaunchDaemons between the check and the write, and the root daemon would create the file there. | The parent is opened once (`O_DIRECTORY|O_NOFOLLOW`), its real path (F_GETPATH) must equal the checked path (or the /private alias), ProtectedPaths is re-checked on the real path, and create/xattr/chown/chmod/rename go through `openat`/`fsetxattr`/`fchown`/`fchmod`/`renameatx_np(RENAME_EXCL)` on that descriptor. |
| Medium | Sources/RampartGuard/TamperProtection.swift + new UpdateAwareness.swift | Lead report: a legitimate app update (`ditto` new bundle, `rm -rf` old, `mv` new in) and quitting the app raised fileTamper / killAttempt. | App-bundle changes are held for `updateGrace` (30 s) and reported only if afterwards the bundle is not a valid RamPart build (`RamPartIdentity.isValidBundle`: bundle ID app.rampart.app, valid app signature, Helpers/rampartd + rampart verify with identifiers app.rampart.daemon / app.rampart.cli, Team ID consistent and in `trustedTeamIDs` when set) or the service is down. Kill/signal alerts only when the target is the service (daemon, watchdog, bundled helper, own pids), not the UI app; pkill/killall/kill operands are matched properly. Launch plist writes are alerts only when the new content is not RamPart's job (Label ours + program in a RamPart service path); deletion still alerts at once. Tests both ways in `redTeamGuardUpdateChecks`. |

**Wiring hook (rampartd owner):** call `detector.flushPending()` from a timer every ~5 s and handle the returned
Detections like `inspect()` results (pending items are otherwise only flushed on the next event). In
IPCServer use `IPC.readFrame(fd: fd, maxLength: IPC.maxRequestLength)` for requests.

## Fixed in rampartd (second pass, after ownership moved)

| Sev | File | Issue | Fix |
|---|---|---|---|
| High | Sources/rampartd/IPCServer.swift | Slowloris: 64 slots, 300 s timeout, new connections dropped when full; 80 idle sockets locked every client out. | Per-connection accounting: global cap 64, per-uid cap 24; a connection that has not sent a complete frame is "idle" and the oldest idle one (same uid first, then any) is shut down to make room; 5 s deadline for the first frame, 300 s afterwards; requests read with `IPC.readFrame(fd:, maxLength: IPC.maxRequestLength)` (8 MB). |
| Medium | Sources/rampartd/main.swift | Two daemons on one state root both ran. | `flock(LOCK_EX|LOCK_NB)` on `<root>/rampartd.lock` (O_NOFOLLOW, pid written) before any service starts; a second instance exits 75. |
| Medium | Sources/rampartd/Core/Activity.swift | Folder allow-rule guard was case-sensitive (`/users`, `/SYSTEM` accepted) and missed /tmp, /var, /Volumes, ~/Downloads etc. | New `PathScope`: realpath + standardize, lowercased, /private aliases folded; blocks the whole disk, system and top-level folders, /Volumes/<drive>, any home and its main subfolders. |
| Medium | Sources/rampartd/Core/Router.swift, GuardWiring.swift | Any admin peer could add broad exclusions / folder rules without authentication. | New exclusions and folder rules that are not a single file or one user-owned subfolder inside the peer's home need an admin-authenticated session: `requestDisableProtection(authorization:)` then `disableProtection(token:, minutes: 0)` opens a 10-minute settings session without pausing protection (minutes > 0 keeps the old pause behaviour). Hash, developer and signing-ID rules stay token-free, so "Not a Threat" is unchanged. **App owner:** before saving such settings, run that two-step flow (root mode needs the AuthorizationExternalForm as today). |
| Low | Sources/rampartd/Core/GuardWiring.swift | Held bundle/plist changes were decided only on the next event. | The 5 s guard timer now calls `detector.flushPending()` and raises what it returns. |

## Attacks that held (passing checks)
4 GB / 64 MB length prefixes, 200 truncated frames, malformed JSON, 19 out-of-range / wrong-typed enum payloads
(Int.min/Int.max limits, bad UUIDs, 200 KB URL, 500 KB scam text), 3000-case seeded fuzz (raw garbage, framed garbage,
byte-flipped valid requests), 3000 connect/close flood, peak RSS under fuzz < 400 MB; restore-to and export refuse
/etc, `..` traversal, an existing file, a symlink into /etc, /var/root, other homes, /System, relative, NUL and empty
paths; sandbox run refused under RAMPART_NO_PRIVILEGED_TOOLS; scheduled hour clamped (-5, Int.max); 100k exclusions;
excluding `/` refused; EICAR under 6 extensions and with spec-compliant whitespace padding; zip depth 1 found; 12-deep
nesting and a 1 GB-in-~1 MB zip bomb finish with bounded RSS; 20 GB sparse file, symlink loops, `/etc` symlink,
chmod 000 file and folder, file rewritten during the scan; SIGSTOP/SIGCONT mid-scan; same-socket second daemon exits;
5 rounds of kill -9 during settings/allow-rule churn leave valid JSON and the earlier rule; corrupt / empty /
wrong-typed / chmod 000 config.json, truncated detections.json and allowrules.json, 60 MB junk activity.jsonl, symlinked
detections.json (target not overwritten); vault: flipped ciphertext refused, flipped metadata hidden, deleted vault.key
-> starts and refuses restore, allow rules unaffected.
