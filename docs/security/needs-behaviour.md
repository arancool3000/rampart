# needs-behaviour (from attack suite X1 — attacks on trust)

Appended by the X1 attack agent (2026-11-07). Do NOT treat as applied; these are fix
proposals for the BehaviourEngine owner (B5). Evidence: `rampart-selftest attackx1`,
scenarios X1.6 and X1.7.

## Finding B-X1-1 (High): a broad "Not a Threat" allow suppresses even alwaysActive strong rules

**File:** `Sources/RampartBehaviour/BehaviourEngine.swift` `isAllowlisted(node:rule:path:)` (~line 548).

**Problem.** A user-added `AllowEntry(teamID:)` or `AllowEntry(pathPrefix:)` with `weakOnly`
unset returns `true` for *every* rule, including strong, alwaysActive credential-theft and
tamper rules. The only guard is `if a.weakOnly == true, let r = rule, r.type == .strong { continue }`
— so an allow that is *not* marked weakOnly suppresses strong rules.

**Trust-abuse kill chain (X1.6 / X1.7).** The attacker gets the user to click "Not a Threat" /
"Trust this developer" once for a benign-looking helper (a legitimate-feeling action). That
single decision adds a broad Team-ID or folder allow. The attacker then runs an outright
infostealer under that Team ID (or from that folder): the osascript password dialog (R34),
Safe-Storage key request (R36) and temp credential staging (R38) are all suppressed. Observed:
**no detection at all** — the whole stealer is whitelisted by one trust decision.

**Proposed fix.**
1. Make a set of rules *non-suppressible* by scoped allows: honeytoken (R39), keylogger (R48),
   mic/cam (R50), Safe-Storage / password-dialog / credential-staging (R34/R36/R38),
   security-tool tampering (R55), TCC tampering (R53). In `isAllowlisted`, after matching,
   `if rule?.nonSuppressible == true { continue }` (add a `nonSuppressible` flag to `Rule`,
   default true for alwaysActive strong infostealer/malware rules).
2. Default user-created allows to `weakOnly: true` unless the user explicitly chooses
   "trust completely" in a second, higher-friction step; surface the difference in the UI.
3. Require `pathPrefix` allows to be at least a specific file or a single user-owned subfolder
   (the daemon Router already gates *adding* broad folder rules behind admin auth per redteam.md;
   the behaviour engine should refuse to honour a prefix shorter than the home dir or equal to a
   top-level folder even if one is somehow present).

**Regression test:** extend `attackX1Checks` X1.6/X1.7 to assert `R34||R36||R38` still fire under a
broad Team-ID / pathPrefix allow.

## From attack suite X6 (everyday Mac threats, 2026-11-07). Evidence: `rampart-selftest attackx6`

### B-X6-1 (High): the default Homebrew allow hides npm/pip supply-chain stealers
`BehaviourConfig.defaultAllowlist` has `AllowEntry(pathPrefix: "/opt/homebrew/", weakOnly: true)` (and /usr/local/Homebrew).
In `apply()`, `nodes.contains(where: isAllowlisted)` covers the whole chain for lineage rules. So every weak rule
(R37 credential read, R42 Discord/Telegram webhook, R30, R43, R44, R45 …) is silenced for Homebrew node/python/ruby
**and everything they spawn**. X6 A09 (npm postinstall reads `~/.ssh/id_ed25519` + `~/.aws/credentials`, resolves
discord.com): **zero detections**.
**Fix:** give the default toolchain allows `ruleIDs` scoped to the build/dev noise they exist for (R29, R30, L03,
L05, M03, R41, R47, R57) instead of "all weak rules", and never apply them to the credential/exfil set
(R37, R38, R42, R43, R44, R45, R36, R39). Equivalent: add `let credentialExfil: Set = ["R37","R42","R43","R44","R45"]`
and in `isAllowlisted`, `if a.note?.hasPrefix("Homebrew") == true, let r = rule, credentialExfil.contains(r.id) { continue }`.
Self-test: X6 A09 must give R37 + R42 (≥60 together).

### B-X6-2 (High): credential reads by Apple interpreters, and common secrets, are not watched
- R37 matcher 2 has `"trust": "nonApple"`. PyPI and osascript stealers read with `/usr/bin/python3`, `osascript`,
  `/usr/bin/sqlite3` (Apple). X6 A10 (Apple python3 opens Chrome Login Data + Cookies): missed. **Fix:** replace
  `trust: nonApple` with `processNot` of the Apple daemons that legitimately read these files (`securityd`, `secd`,
  `trustd`, `mds*`, `backupd`, `cloudd`, `Safari`, `com.apple.WebKit.*`, `SafariBookmarksSyncAgent`) and allow
  interpreters (`@interpreters`, `osascript`, `sqlite3`, `cp`, `ditto`, `cat`).
- `sensitivePaths` additions (X6 A11–A14): `/\.ssh(/|\s|$|")` (the directory; keep `id_*`), `/\.zsh_history$`, `/\.bash_history$`,
  `/\.config/gh/hosts\.yml`, `/\.npmrc$`, `/\.pypirc$`, `/\.docker/config\.json`, `/\.git-credentials$`, `/\.netrc$`,
  `/\.gnupg/`, `Library/Messages/chat\.db`, `Library/Safari/(History\.db|Form Values)`, `\.kdbx$`, `/\.config/solana/`,
  `Library/Application Support/(Exodus|Electrum)/`, plus Chromium `Local Extension Settings/(nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|…)` wallet IDs.
- Remove `scp` from R37 processNot when the argument is the whole `~/.ssh` directory or a private key and the destination is remote (`\S+@\S+:`). X6 A12.
- New weak rule **R37b "Document sweep"** (collection, 45): ≥25 `fileClose` events on `~/Desktop|~/Documents` with
  extensions txt|pdf|docx|rtf|kdbx|key|wallet by one untrusted actor in 60 s (threshold, groupBy actor), or any
  fileCreate of those extensions under a temp/hidden staging folder. X6 A14.

### B-X6-3 (Medium-High): backdoors with no rule
Add matchers (all exec unless stated):
- **R16** (sudoers/auth) also covers PAM: file path `^(/private)?/etc/pam\.d/` and `^/usr/local/lib/pam/` (processNot @installers),
  exec `(cp|mv|tee|sed|ditto)` with args `/etc/pam\.d/`. X6 A23.
- **R16b "Hidden or new admin account"** (strong, backdoor, 75, interactiveFactor 0.5): `sysadminctl` args `-addUser`;
  `dscl` args `-create\s+/Users/\S+(\s+IsHidden\s+1|\s+UniqueID\s+[0-4]\d\d\b)`; `dseditgroup` args `-a\s+\S+.*\badmin\b`;
  `dscl` args `-append\s+/Groups/admin\s+GroupMembership`. X6 A24.
- **R14**: exec matcher `tee` args `/\.ssh/authorized_keys`. **R25**: exec matcher `tee|sed|cp|mv` args `/etc/hosts\b|/etc/resolver/`,
  and file path `^/Library/Preferences/SystemConfiguration/preferences\.plist$` (processNot `configd`, `networksetup`,
  System Settings). Exec `scutil` from an untrusted lineage. X6 A25/A31/A33.
- **R11**: exec `at` (any args except `-l`/`atq`) and `atrun` enable via `launchctl … com.apple.atrun`. X6 A20.
- **R15**: exec `kickstart` (path `…/ARDAgent.app/Contents/Resources/kickstart`) args `-activate|-access\s+-on`;
  `launchctl` args `(enable|bootstrap|load).*com\.apple\.screensharing`. X6 A39.
- **R24**: `security` args `trust-settings-import|add-certificates.*-k\s+\S*System\.keychain`. X6 A35.
- **L06**: `socketfilterfw` args `--setglobalstate\s+off|--setblockall\s+off|--add\s+/`; `pfctl` args `-d\b`. X6 A37.
- **L11 "Indicator removal"** (weak, 45): `log` args `erase`; `rm` args `/\.(zsh|bash)_history|/var/log/|/Library/Logs/DiagnosticReports`;
  `history` args `-c` from an untrusted lineage. X6 A38.
- **R07** should also flag a target that is an Apple interpreter (`python3`, `osascript`, `bash -c`, `sh -c`, `curl`)
  whose ProgramArguments contain inline code (`-c`, `-e`) with a fetch (`urlopen|curl|wget|NSURL`) or `base64`/`exec(`.
  Today R07 only judges the target binary's signature. X6 A07.
- **L04**: add `(exec|eval)\s*\(\s*(base64\.b64decode|codecs\.decode|zlib\.decompress|bytes\.fromhex)` and
  `osascript\s+-l\s+JavaScript.*(NSData|dataWithContentsOfURL|doShellScript)`. X6 A08/A02.
- **Clipboard hijacker (new weak rule, 50)**: ≥5 `pbpaste`/`pbcopy` execs with an untrusted ancestor in 120 s. X6 A15.
- **App-bundle tamper (new strong rule, 70)**: fileWrite/fileRename inside `/Applications/[^/]+\.app/Contents/` by an untrusted
  actor or interpreter lineage, processNot @installers / Sparkle `Autoupdate` / the app itself. Wallet apps
  (Ledger Live, Exodus, Trezor Suite, Electrum, Atomic) → score 90. X6 A16.

### B-X6-4 (Medium): browser-extension side channels
- **R20** add: exec of any `@browsers` binary with args `--load-extension=`, `--disable-extensions-except=`; file
  path `/(Google/Chrome|BraveSoftware/Brave-Browser|Microsoft Edge|Chromium)/External Extensions/[^/]+\.json$` and
  `^/Library/Application Support/Google/Chrome/External Extensions/`. X6 A28/A29.
- **PersistenceScanner.chromiumExtensions**: also enumerate entries in `(Secure) Preferences → extensions.settings`
  whose `location` is 4 (unpacked) or 3/6 (external) and whose `path` is outside `Extensions/` (read
  `<path>/manifest.json`; set attrs `installLocation`, `unpacked: 1`). Also enumerate `External Extensions/*.json`
  under the user and `/Library/Application Support/<vendor>/External Extensions`. X6 P02 found 0 of 2.
- **Safari**: enumerate Safari web/app extensions through `~/Library/Containers/com.apple.Safari/Data/Library/Safari/AppExtensions/Extensions.plist`
  and `WebExtensions/Extensions.plist` (read-only plist, no `pluginkit`). They are not inventoried today.

### B-X6-5 (Medium): Office as an entry point, and miners
- Add list `officeApps: ["Microsoft (Word|Excel|PowerPoint|Outlook)", "Pages", "Numbers", "Keynote", "Preview", "Adobe Acrobat.*"]`
  and extend **L08** with a matcher `process: [@shells, @interpreters, @fetchers], ancestor: [@officeApps], ancestorNot: [@terminals]`
  (score 60 for Office: macros spawning shells are almost never legitimate). X6 A06.
- **R08** matcher: LaunchAgent plist written whose basename starts with `~$` (Office sandbox-escape trick), any writer. X6 A07.
- **New "Cryptominer" rule** (category miner, 60): exec args `stratum\+(tcp|ssl|tls)://|--donate-level|\b(-o|--url)\s+\S+:(3333|4444|5555|7777|14444|14433|45700)\b|--randomx|--coin\s+(monero|xmr)`;
  networkConnect remote_port in that pool list from an untrusted actor; and (needs telemetry CPU) a sustained >80%
  CPU for 10 min from an ad-hoc/unsigned image. X6 A41 has only R41 (42).
- **P03**: add `PersistenceItem.Kind.other` records with class `sudoers`, `pam`, `hosts`, `resolver` (fingerprint = sha256 of
  `/etc/sudoers`, each `/etc/sudoers.d/*`, `/etc/pam.d/*`, `/etc/hosts`, `/etc/resolver/*`, all world-readable or root-readable in root mode)
  so a change made while rampartd was down appears as a "changed" persistence item.
