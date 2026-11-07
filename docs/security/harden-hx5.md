# harden-hx5: tamper protection and remote-access lockdown

Scope: `Sources/RampartGuard/**`, `Sources/RampartApp/Features/RemoteAccess/**`. Tests: `Sources/rampart-selftest/SelfTest+HX5.swift` (`hx5Checks`).
Also covers the three proposals in `docs/security/needs-guard.md` (attack set X4).

## Threat model

Assets: the three root guardian jobs (daemon, watchdog, sentinel) with their binaries and plists, the app bundle and its helpers, sealed config / allow rules / remote policy, the HMAC key, the install manifest, the admin disable/uninstall session, and the remote-access default-deny policy.

Attackers:
- **Non-root malware running as the user** (the main case). It can run `launchctl`/`kill` against its own jobs only, write anything the user owns (often including `/Applications/RamPart.app`), ad-hoc sign binaries with any identifier, and plant symlinks.
- **Admin-level script / scammer with the password** (root via sudo). See "What root can still do".
- **Hostile remote tool**: renamed, re-signed, on a non-default port, or riding on an allowance the user gave a real tool.
- **Clock manipulation**: an admin moving the clock to stretch or skip time-limited trust.

Entry points: `TamperDetector.inspect` (exec / file / signal / BTM events), `GuardianLoop.tick`, `SealedStore`, `InstallManifest.verify`, `RamPartIdentity` (bundle and plist validation), `ProtectionDisableFlow` (tokens, sessions), `RemoteAccessMonitor.report`, `RemoteAccessPolicy`, `RemoteAccessEnforcer.plan`.

## Findings

| # | Sev | Where | Issue | Fix | Status |
|---|-----|-------|-------|-----|--------|
| 1 | Critical | TamperProtection.swift `isSelf` | Any process whose signing ID started with `app.rampart` counted as RamPart. Ad-hoc signing lets anyone choose that identifier (`codesign -s - --identifier app.rampart.x`), so it could boot out, kill or delete RamPart without a single alert. | Signing IDs count only with a trusted Team ID (`trustUnverifiedSigningIDs`, default false). Children of our own pids (ppid) count as self. | Fixed |
| 2 | High | TamperProtection.swift `isSelf` | Every process running from a protected path counted as self, including `/Applications/RamPart.app`, which the admin user can usually write to. Dropping `Contents/Helpers/evil` and running it gave a silent actor. | App-bundle processes are self only when their hash matches the sealed manifest (`manifestProvider`). Root-owned install paths still count. | Fixed |
| 3 | Critical | UpdateAwareness.swift `isOurPlist` | Any Program under `Contents/Helpers/` was accepted, and Disabled, KeepAlive=false, `DYLD_INSERT_LIBRARIES`, `RAMPART_NO_PRIVILEGED_TOOLS=1`, a non-root `UserName` or `--no-scheduler` were not checked. A rewritten plist could run a dropped binary as root, or neuter the daemon, with no alert. | `isOurJob`: the executable must be one of the exact job binaries (case-insensitive), with no neutering keys, environment or arguments, and the plist must not be a symlink. | Fixed |
| 4 | High | UpdateAwareness.swift `isValidBundle` | A look-alike bundle that is ad-hoc signed with RamPart's identifiers passes. With an empty trusted-team set, a bundle signed by any team also passes. This is the "update" exit from the 30 s hold. | New `isGenuineBundle`: the bundle needs a trusted Team ID or helpers that match the sealed manifest, and fails closed otherwise. Used by default once `manifestProvider` is set. | Fixed (needs wiring, see N2) |
| 5 | High | GuardSupport.swift `GuardPaths` | The sentinel guardian was missing from labels, plists, binaries and serviceNames, so `killall app.rampart.sentinel`, `rm` of its binary and edits to its plist were never reported. | Added `sentinelLabel/Binary/Plist`, derived from the watchdog paths so the Codable layout is unchanged, and included them everywhere. | Fixed |
| 6 | High | Guardians.swift `isRunning` | `pid = N` was taken to mean alive. A SIGSTOPped guardian (`kill -STOP`, `launchctl kill SIGSTOP`) stays "running" forever, and launchd never restarts it. | `isLive` checks the BSD status. A stopped or zombie process counts as down, so the ring runs `kickstart -k` (SIGKILL works on a stopped process). | Fixed |
| 7 | High | Guardians.swift, Integrity.swift restore | `restoreIfNeeded` wrote the JSON **envelope** over binaries and plists, so a "restored" daemon could not run. | `SealedStore.backupOnly` and `restoreRawIfNeeded` write the payload, only if it matches the manifest hash (or the legacy envelope layout). Used by the ring and by `SelfDefencePolicy` for plists. | Fixed |
| 8 | Medium | Guardians.swift back-off | Back-off reached 60 s, so re-running bootout each time the job came back gave minute-long gaps. Back-off also used the wall clock: moving the clock back by an hour froze the ring for an hour. | Max back-off is now 8 s. A deadline further away than `maxBackoff` (clock rolled back) is ignored. | Fixed |
| 9 | Medium | TamperProtection.swift `hold` | Each new touch of the bundle extended the hold, so touching it every 20 s kept a swap pending forever. A clock rollback also froze `due`. More than 256 held keys were dropped silently. | Hold is capped at `firstSeen + maxHold` (120 s). Anything due past the horizon counts as due now. Overflow is reported, not dropped. | Fixed |
| 10 | Medium | TamperProtection.swift kill parsing | `kill -9 -1` and `kill -- -PGID` were parsed as flags. pkill patterns were matched as substrings, not regexes (`pkill '[r]ampartd'`). `killall -m`, `killall -u root` and `pkill -U 0` were missed. | A real argument parser, regex matching (bounded pattern length), and user-wide kills of root. | Fixed |
| 11 | Medium | TamperProtection.swift `inspectExec` | A renamed copy of launchctl/kill (`cp /bin/launchctl /tmp/lc`) was not recognised. `launchctl unload /tmp/link.plist` (a symlink to our plist) was not recognised. `bsexec`/`asuser` wrappers were missed. | Map tools by Apple signing ID and by executable path, read launchctl-shaped arguments with our label, resolve symlinked path arguments, add more verbs. | Fixed |
| 12 | High | TamperProtection.swift (X4.8) | An unqualified `tccutil reset SystemPolicyAllFiles`/`All` strips RamPart's Full Disk Access without naming RamPart. | Flagged high when unqualified, critical when it names RamPart. | Fixed |
| 13 | Medium | TamperProtection.swift (X4.9) | Clock changes were not watched. | New `TamperKind.clockTamper` for `systemsetup -setdate/-settime/-setusingnetworktime/-setnetworktimeserver`, `date <digits>`, `sntp -s/-S` and `ntpdate`. | Fixed |
| 14 | Medium | TamperProtection.swift `ProtectionDisableFlow` (X4.18) | Token and session lifetimes used the wall clock only. A session could be requested for any length. Token MACs shared the seal key space. The issued-token map was unbounded. | Both wall-clock and monotonic (`CLOCK_MONOTONIC_RAW`, injectable via `GuardClock.monotonic`) must be in bounds. Sessions are capped at 4 h. Token MACs are domain-separated, compared in constant time, and the token map is pruned. | Fixed |
| 15 | Medium | Integrity.swift `Sealed` | The MAC did not cover the path, so a valid sealed `allow-rules.json` could be copied over `config.json`. | v2 envelopes bind the path into the MAC. v1 is still read (migration) and rewritten as v2 on save. `allowV1:false` is available. Envelopes are capped at 64 MB. | Fixed |
| 16 | Medium | Integrity.swift `IntegrityKey.loadOrCreate` | A key of the wrong length was silently replaced, which orphans every seal and backup. The key could be followed through a symlink, and a folder that another user could write to (or owned by someone else) was accepted. | lstat checks on owner and mode for the folder and the file. A short key is refused. New keys are created with `O_EXCL|O_NOFOLLOW`. | Fixed |
| 17 | Medium | Integrity.swift `InstallManifest.verify` | Files added to the bundle (a dropped dylib) were never reported. A binary swapped for a symlink to a genuine copy passed. Ownership was never checked. | New `roots` field (optional, Codable-compatible) reports `unlisted` files. Added `symlink` and `unsafeOwnership` (`verify(requireOwner: 0)`). | Fixed |
| 18 | Medium | RemoteAccess.swift `RemoteAllowance` | Time-limited allowances could last forever: `minutes: Int.max` was not clamped, `0` was not handled, and moving the clock back kept a "1 hour" allowance alive. | Minutes are clamped to 1–10080. An allowance is void if the clock reads more than 5 min before the grant, or if its window is longer than the maximum. | Fixed |
| 19 | Medium | RemoteAccess.swift allowance matching | An allowance covered any process that claimed the tool's identifier, including an ad-hoc look-alike. | Optional `teamIDs` pin (`allow(..., pinTeamIDs:)`). A pinned allowance does not cover processes from another signer. | Fixed (needs wiring, see N3) |
| 20 | Medium | RemoteAccess.swift detection | A tool that was renamed, re-signed and moved to another port disappeared from the report. | `unsignedListeners`: non-loopback listeners held by a program without a Team ID (signing info required). Shown as a low-severity detection. | Fixed (heuristic) |
| 21 | Medium | RemoteAccess.swift `isSystem` | The `/usr/` prefix covered `/usr/local`, so a remote tool installed there (Homebrew, user-writable) was never suspended. | `/usr/local` is no longer treated as a system path. | Fixed |
| 22 | Low | UI copy (Guardians.swift TamperCopy, RemoteAccessModel.swift) | The copy said admin-level scripts are always detected and undone, and did not mention renamed tools on other ports. | Reworded to say what is true. | Fixed |

## What root can still do (honest limits)

RamPart has no Endpoint Security entitlement and no kernel presence. A root process can:
- read `integrity.key` and forge any seal, token or manifest (the key is only root-only, not hardware-backed);
- `chflags noschg` (securelevel 0), then replace binaries, plists, backups and the manifest together;
- `launchctl bootout` all three guardians in one command, or SIGSTOP all three at once. With no guardian left running, nothing restarts them until reboot or reinstall;
- stop the event source (eslogger) so RamPart sees nothing, and set the clock;
- wipe RamPart from Recovery Mode.
Detection of exec events needs a working event source. Without it, everything above happens silently.

## Needs owner

| # | Owner | Item | Exact fix |
|---|-------|------|-----------|
| N1 | selftest owners | `SelfTest+AttackX4.swift` X4.8 and X4.9 assert misses that are now fixed, so they fail. X4.20 asserts that an ad-hoc `app.rampart.installer` signing ID is exempt (finding 1), so it fails too. `SelfTest+Guard.swift:82` asserts the same thing but only passes because of the 5 s dedupe. | X4.8 and X4.9: flip them to `.count == 1`. X4.20 and Guard:82: give the process `teamID: "TEAMTEST01"` and create the detector with `trustedTeamIDs: ["TEAMTEST01"]`, or use `ppid: <own pid>`. |
| N2 | rampartd `GuardWiring.swift:40` | The detector has no manifest yet. | After building the detector: `detector.manifestProvider = { [store] in InstallManifest.load(from: store, path: paths.manifestFile) }`. Build the manifest over `paths.binaries + paths.plists + [paths.appBundle]`, and re-seal it from the daemon's update path **before** it swaps the bundle in. Spawn the update `ditto`/`mv` as children of the daemon (ppid exemption). On start and in the periodic sweep, call `detector.flushPending(force: true)` and `manifest.verify(requireOwner: 0)`. |
| N3 | rampartd remote-access IPC | Allowances are not pinned. | In `allowRemoteTool`, pass `pinTeamIDs: currentFinding.pids.compactMap { enrichedProc[$0]?.teamID }`. Enrich `ProcessInfoLite` with signing info (RampartSigning) so `unsignedListeners` is populated. |
| N4 | installer / GuardianMain | Binary and plist backups must be raw. | Back up with `store.backupOnly(data, for: path)`, not `store.write` (which overwrites the live file with an envelope). Pass the manifest into `SelfDefencePolicy(paths:store:manifest:)`. |
| N5 | GuardWiring | The key folder is now checked. | `runtime.root` must be owned by the daemon's uid and not group- or world-writable, or the disable flow key fails to load (fails closed). |

## Test results
`hx5` 75/0. `guard` 111/0. `redteam` 114/2 (the 2 failures are EICAR engine checks at RedTeam.swift:316-317, not in Guard). `attackx4` 24/3 (X4.8, X4.9 and X4.20, see N1). RampartApp and rampartd build.
