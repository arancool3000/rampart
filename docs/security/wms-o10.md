# WMS o10: persistence, posture and scan coverage

Owner: agent o10. Scope: RampartPosture, PersistenceScanner / snapshot / diff / BTM, LaunchItemPolicy, FileWalker
exclusions, ScanCoordinator quick-scan roots, SIP/SSV and Apple-signature checks, Rules/rampart-generic.yar.

## Threat model
A user-level or root attacker who has code running once and wants to (a) survive reboot through a macOS
persistence location RamPart doesn't enumerate, (b) hide a payload where RamPart never scans, or (c) make
untrusted code look like Apple's. RamPart has no Endpoint Security AUTH and no NetworkExtension, and it is
ad-hoc signed: everything here is after-the-fact detection, by baseline diff (scheduled and on FSEvents nudges).

## Coverage map (after this pass)
| Location / technique | Before | Now |
|---|---|---|
| LaunchAgents/Daemons (user, /Library) | parsed, R07/R09 | + hidden plists (dot name / UF_HIDDEN) -> RP6; YARA rules for curl\|sh and DYLD_INSERT in XML plists |
| BTM / login items | sfltool as root | unchanged (needs root; reported incomplete otherwise) |
| cron, at, periodic | yes | unchanged |
| emond (rules, clients) | no | R11 |
| Authorization / DS plug-ins, StartupItems | yes, but dot-named bundles skipped | hidden entries enumerated (R17 / R11) |
| PAM, sudoers, sudoers.d | event rule R16 only | hashed snapshot (P03); new known-bad lines -> R16 |
| /etc/hosts, /etc/resolver | event rule R25 only | hashed snapshot (P03); security-update blocking or pharming -> RP1 |
| sshd_config(.d), /etc/ssh/sshrc, ~/.ssh/rc, ~/.ssh/environment | no | RP2 on new risky lines |
| ~/.ssh/authorized_keys | yes | + /var/root/.ssh (root daemon) |
| zsh / bash rc | yes | + fish (config, conf.d, vendor_conf.d, prompt), oh-my-zsh custom, logout files, *_Apple_Terminal; event R12 also for fish |
| Folder Actions | no | dispatcher plist + scripts -> RP4 |
| Dock tile plug-ins, Spotlight importers, QuickLook, screen savers, colour pickers, input methods, pref panes, internet / audio HAL plug-ins | no | inventory; unsigned/ad-hoc/broken or hidden -> RP3 |
| Kernel extensions (/Library/Extensions) | no | inventory; untrusted -> RP3 |
| System extensions, profiles | systemextensionsctl / profiles | unchanged |
| Chromium extensions | Extensions/<id> only | + unpacked (location 4) from (Secure) Preferences, External Extensions JSON (user + system), ExtensionInstallForcelist in plain prefs -> R20 (P02) |
| Safari extensions | no | inventory only (AppExtensions / WebExtensions plists; needs FDA) |
| DYLD via LaunchServices (LSEnvironment), ~/.MacOSX/environment.plist | no | RP5 |
| Re-opened apps (TALAppsToRelaunchAtLogin) | no | only temp/hidden/shared paths -> RP6 |
| Login/Logout hooks | yes | unchanged |
| TCC.db tampering | R53 (event) | unchanged; snapshot needs FDA (residual) |
| XProtect / MRT tampering, Gatekeeper off | posture (SIP, SSV, xprotectFresh, gatekeeper) + L06 | unchanged; XProtect lives under SIP |

Quiet by design: each new collector tags its records (`collector`) and snapshots list the collectors that ran.
A collector the baseline never ran only seeds the baseline (no upgrade alert storm). After that only
changes are assessed, and config files alert only on newly added known-bad lines (Touch ID sudo, pam_reattach,
ad-block hosts, dev/Tailscale resolvers, notarized plug-ins all stay quiet).

## Findings
| ID | Severity | Finding | Status |
|---|---|---|---|
| O10-1 | High | `OwnData.contains` and `WalkOptions.isExcluded` matched `/Library/Application Support/Rampart` anywhere in a path, so `/tmp/x/Library/Application Support/Rampart/`, a USB stick or `~/Downloads/a/Library/...` was never scanned (scheduled, explicit or real-time). Also `..` escapes. | Fixed: anchored to `/Users/<name>` and `/private/var/root`, `..` standardised. |
| O10-2 | Medium | The real per-user data folder is user-writable, so a payload planted there was never scanned. | Fixed: a runnable file (exec bit, Mach-O, `#!`) in a data folder is not own data; walks sweep skipped data folders for programs (vault `staging/` exempt); launch items / login items pointing there are R07 / threats, never "benign user agent". |
| O10-3 | High | `SigningInspector` trusted the CodeDirectory platform byte: an ad-hoc binary with a forged platform field was classified `.apple`. | Fixed: believed only on the sealed volume, cryptexes, /usr (not /usr/local), /bin, /sbin, /Library/Apple. PoC test patches a copy of the selftest binary. (Minimal edit in RampartSigning.) |
| O10-4 | Medium | `isRampartOwn` (label + path prefix) exempted `app.rampart.*` jobs whose target was `/Applications/Rampart.app/Contents/../../../tmp/x` or a symlink. | Fixed: `.`/`..`/`//` and symlink targets rejected. |
| O10-5 | Medium | Dot-named bundles in SecurityAgentPlugins / DirectoryServices PlugIns / StartupItems were skipped. | Fixed. |
| O10-6 | Medium | P02/P03 backlog, and the coverage gaps in the table above. | Fixed (collectors + RP1-RP6). |
| O10-7 | Low | Quick scan skipped privileged helpers, plug-in folders, kexts, scripts and hidden home folders. | Fixed: `ScanOptions.persistenceRoots` (shared with the daemon's quick-scan list). |

FP2's own-data fixture used a home-shaped temp folder and relied on O10-1. It now registers the folder with
`OwnData.register(root:)`; its assertions are unchanged, and the stricter "unregistered look-alike IS scanned"
check is in `SelfTest+WMSo10.swift`.

## Residual risks
- BTM/login items, profiles and system extensions need root (sfltool prompts otherwise).
- TCC.db, Safari extension plists and other users' homes need Full Disk Access, which ad-hoc signing resets.
- Real-time FSEvents and the Download Gate still skip RamPart's data folders (Guard/daemon areas); only scans
  sweep them. Suggest the lead apply `OwnData.contains` (which now passes runnable files) there too.
- An admin-group user can create `/Applications/RamPart.app` when RamPart isn't installed there; the assessor
  still exempts `app.rampart.*` jobs pointing into it (the daemon's LaunchItemPolicy verifies the signature).
- Known-bad lists (hosts domains, sudoers/PAM patterns) are heuristics; a novel config backdoor that matches none
  updates the baseline silently. Binary launchd plists are not covered by the YARA rules (the scanner parses them).
- `launchctl setenv`, Python `.pth`/sitecustomize, `~/.zshenv` via ZDOTDIR, and re-signing of third-party plug-ins
  with a stolen Developer ID are not covered.

## Note: daemon suite regression (fixed)
The first draft of the YARA launch-plist rule used bounded regexes (`[^<]{0,300}`), which made the lazy rule compile
slower. On a heavily loaded machine (load average ~200), the daemon's first socket scan waited for that compile
past the 20 s per-file deadline, so 0 files were scanned (daemon suite, 7 failures). The rule now uses only
literal strings. The general risk remains: the first scan after start-up blocks on the YARA compile (~20 s
under load), so a background warm-up compile at daemon start would help (daemon area).
