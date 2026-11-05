# 05 — Behavioural / Heuristic Detection on macOS without Endpoint Security

Status: research draft (2026-11). Audience: Bastion engineers.
Constraint: no `com.apple.developer.endpoint-security.client` entitlement, no Network Extension entitlement, no Xcode (Command Line Tools + SwiftPM only). Everything below uses public or documented-but-unentitled APIs, standard CLI tools, or root privileges from a LaunchDaemon.

---

## 1. Architecture summary

Without Endpoint Security (ES) we do not get synchronous, kernel-ordered exec/open/write events and we cannot **block** before something happens. Bastion's behavioural engine is therefore a **near-real-time observer with fast response** (SIGSTOP, then kill, quarantine, or roll back), assembled from several weaker sensors:

| Sensor | API / tool | Privilege | Latency | What it gives | Blind spots |
|---|---|---|---|---|---|
| Process poller | `proc_listallpids`, `proc_pidpath`, `proc_pidinfo(PROC_PIDTBSDINFO)`, `sysctl(KERN_PROCARGS2)` | root to see other users' processes, argv and env | 50–250 ms poll | pid, ppid, uid, path, argv, start time | Processes that live shorter than the poll interval |
| Process watcher | `kqueue` `EVFILT_PROC` (`NOTE_FORK`, `NOTE_EXEC`, `NOTE_EXIT`) on interesting pids (shells, Terminal, osascript, browsers) | root for other uids | ~immediate | Children of watched parents, even short-lived ones | `NOTE_TRACK` is not supported on macOS, so you must re-arm on every child |
| Code-signing evaluator | `SecCodeCopyGuestWithAttributes` (pid) / `SecStaticCodeCreateWithPath` + `SecCodeCheckValidity`, `SecCodeCopySigningInformation`, `SecRequirementCreateWithString("notarized")` | none | ms, cached by cdhash | Apple / Developer ID / ad-hoc / unsigned, Team ID, notarization | Cost of a cold check; cache on (path, inode, mtime, cdhash) |
| Provenance | `getxattr("com.apple.quarantine")`, `com.apple.provenance`, `kMDItemWhereFroms`, App Translocation path (`/private/var/folders/.../AppTranslocation/`) | none | ms | Downloaded-from-internet, origin URL, removed quarantine | Quarantine is easily removed (and removal is itself a signal) |
| File events | FSEvents (`FSEventStreamCreate`, `kFSEventStreamCreateFlagFileEvents`) | root for system paths; FDA for TCC-protected user paths | ~0.1–1 s (configurable latency) | Path plus create, rename, modify, xattr-change, and remove flags | **No pid**. Attribute by correlation (see §5.3) |
| Open-file sampler | `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)` | root | per-sweep | Which process holds which file open | Quick open, read, close sequences are missed |
| Socket sampler | `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)`; fallback `lsof -nP -i`, `nettop -L1 -P -x` | root | per-sweep | Per-process TCP/UDP 5-tuple | No DNS names or SNI; short connections can be missed |
| Unified log | `log stream --style ndjson --predicate ...` (child process, root) or `OSLogStore` for history | root, plus a private-data logging profile if `<private>` fields are needed | ~0.5–2 s | TCC decisions, BTM (login-item) registrations, XProtect/syspolicyd, sudo, authd, camera/mic hints | Messages change between OS releases. Many fields show `<private>` |
| Device-use listeners | CoreAudio `kAudioDevicePropertyDeviceIsRunningSomewhere`, CoreMediaIO `kCMIODevicePropertyDeviceIsRunningSomewhere` | none | immediate | Mic or camera turned on or off | Does not say *who*. Correlate with the log (OverSight approach) |
| Input taps | `CGGetEventTapList` | none | poll | Every keyboard/mouse event tap, including `tappingProcess` pid | Only CGEventTap-based keyloggers. IOHID-level monitoring is separate |
| Pasteboard | `NSPasteboard.general.changeCount` polling; on macOS 15.4+/26, prefer `detect` pattern APIs where possible to avoid paste-privacy alerts | user session agent | 250 ms | Clipboard content changes | Recent macOS may alert the user when an app reads the pasteboard programmatically. Check behaviour per OS |
| Persistence enumerator | Periodic full scan (KnockKnock-style) + FSEvents on the same paths (BlockBlock-style) | root + FDA | event + periodic | New or changed autoruns | — |
| Optional legacy | OpenBSM `/dev/auditpipe` | root | immediate | exec, open, and connect with pid | Deprecated since macOS 11. Availability and reliability vary by release. Keep behind a feature flag; never depend on it |

**Process layout:** `bastiond` (root LaunchDaemon: pollers, FSEvents, log stream, scoring, response) plus `bastion-agent` (per-user LaunchAgent: pasteboard, frontmost-app via `NSWorkspace` notifications, UI alerts, user prompts) plus an XPC or Unix-socket channel between them. Ask for **Full Disk Access** for the daemon binary. TCC keys grants on code identity: an ad-hoc-signed binary loses the grant on every rebuild because its cdhash changes, so sign release builds with a stable Developer ID (Developer ID signing does not require Xcode; `codesign` ships with CLT).

**Short-lived-process gap.** This is the biggest weakness compared with ES. Mitigations, in order of value:
1. `kqueue` `NOTE_FORK`/`NOTE_EXEC` on every shell, Terminal/iTerm, `osascript`, Script Editor, `python*`, `node`, and browser pid, re-arming on each new child. This catches the fast child chains used by loaders.
2. Poll `proc_listallpids` at 50–100 ms. A diff over ~600 pids is cheap (sub-millisecond); only new pids get the expensive enrichment (argv, signature).
3. **Consequence detection**: even if the process is gone, its artefacts remain (new files in temp dirs, new plists, new sockets, staged archives). Rules must fire on artefacts, not only on process sightings.

---

## 2. Process monitoring details

- **Enumeration:** `proc_listallpids` → for each new pid: `proc_pidpath`, `PROC_PIDTBSDINFO` (ppid, uid, start time `pbi_start_tvsec`, flags), `KERN_PROCARGS2` (argc, exec path, argv, envp). Key the process record on (pid, start time) so pid reuse is handled.
- **Lineage:** keep a process tree with parent chains even after exit (ring buffer ~10 min). Use the *responsible* process as well as ppid. `responsibility_get_pid_responsible_for_pid` is private SPI (resolve with `dlsym`, and handle its absence). It maps XPC/launchd-spawned helpers back to the app that caused them.
- **Launch origin:** ppid == 1 hides the real origin, because many processes are spawned by launchd. Use the responsible pid, the BTM/launchd label (`launchctl print` / `launchctl procinfo <pid>` as root), and the log stream to recover context.
- **Enrichment per binary (cached by cdhash):** signing tier (Apple platform / App Store / Developer ID notarized / Developer ID not notarized / ad-hoc / unsigned / invalid), Team ID, quarantine xattr, origin URL, file age (birthtime), location class (`/Applications`, `~/Applications`, `/tmp`, `/private/var/folders`, `~/Library/*`, hidden dot-dir, mounted DMG `/Volumes/*`, App Translocation), Mach-O traits (fat vs thin, linked frameworks, packed or high-entropy sections), and whether the binary is a script interpreter.
- **`ps` / `lsof` polling:** only as a fallback or for debugging. Forking `ps` 10×/s costs far more than libproc. `lsof` is slow (hundreds of ms), so use it only for on-demand deep inspection of a suspect pid.
- **Suspend-first response:** `kill(pid, SIGSTOP)` is available to root and freezes a suspect while the user or the engine decides. It works on everything except protected platform processes. Always stop the whole process group or tree, not just the leaf.

---

## 3. Persistence monitoring (BlockBlock + KnockKnock design)

Combine two mechanisms: **FSEvents watch** for immediacy and a **periodic full enumeration with a diff against a signed baseline** for completeness (FSEvents can drop events; check `kFSEventStreamEventFlagMustScanSubDirs` and rescan when it appears).

Watched locations and items (each is a "plugin" with a parse step that extracts the *program actually executed*):

| Category | Locations / source | Parse |
|---|---|---|
| Launch agents/daemons | `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` (`/System/...` is SIP-protected, so verify instead of watching) | `Program` / `ProgramArguments[0]`, `RunAtLoad`, `KeepAlive`, `EnvironmentVariables` (watch for `DYLD_*`), `StartInterval`, label vs file-name mismatch, binary location and signature |
| Login items / BTM (macOS 13+) | `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm` (root), `sfltool dumpbtm` (root), unified log subsystem `com.apple.backgroundtaskmanagement` | New item, developer name, executable, whether it is an `SMAppService` helper |
| Cron / at / periodic | `/usr/lib/cron/tabs/*`, `/etc/crontab`, `/usr/lib/cron/jobs`, `/etc/periodic/*`, `/usr/local/etc/periodic/*`, `/etc/periodic.conf*` | Any new entry. Cron is rare on modern macOS, so a new entry is a strong signal |
| Shell startup | `~/.zshenv`, `~/.zprofile`, `~/.zshrc`, `~/.zlogin`, `~/.bash_profile`, `~/.bashrc`, `~/.profile`, `/etc/zshrc`, `/etc/zprofile`, `/etc/profile`, `/etc/bashrc` | Diff the added lines. Flag network fetches, hidden-path execution, encoded blobs, `DYLD_*` exports, alias overrides of `sudo`/`ssh` |
| SSH | `~/.ssh/authorized_keys`, `~/.ssh/config`, `/etc/ssh/sshd_config*`, Remote Login state (`systemsetup -getremotelogin`) | New key, new `ProxyCommand`/`LocalCommand`, sshd enabled |
| Privilege config | `/etc/sudoers`, `/etc/sudoers.d/*`, `security authorizationdb` rights, `/Library/Security/SecurityAgentPlugins` | Any change outside an MDM or installer session |
| Login/logout hooks (legacy) | `com.apple.loginwindow` `LoginHook`/`LogoutHook` | Any value |
| Relaunch-at-login | `~/Library/Preferences/ByHost/com.apple.loginwindow.*.plist` (`TALAppsToRelaunchAtLogin`) | Unsigned or hidden-path entries |
| Dock | `~/Library/Preferences/com.apple.dock.plist` `persistent-apps` | Entry whose label is a known app but whose path or bundle ID points elsewhere (Dock-tile hijack) |
| Browser extensions | Chrome/Brave/Edge/Arc: `~/Library/Application Support/<vendor>/<profile>/Extensions/`, `Preferences`/`Secure Preferences`; enterprise policy `ExtensionInstallForcelist` in `/Library/Managed Preferences/` and `~/Library/Preferences/com.google.Chrome.plist`. Safari: app extensions via `pluginkit -mAvvv -p com.apple.Safari.web-extension` (and `.extension`) | New extension. Weight by permissions (`<all_urls>`, `cookies`, `webRequest`, `nativeMessaging`), sideloaded vs store install, force-installed by a non-MDM policy |
| Native messaging hosts | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/*.json` (and other vendors) | New host pointing to an unsigned binary |
| Configuration profiles | `profiles list` / `profiles show -type configuration` (root), `/private/var/db/ConfigurationProfiles/`, log subsystem `com.apple.ManagedClient` | Profile installed outside the known MDM. Watch payloads: root CA, proxy, DNS settings, Chrome policies, PPPC/TCC |
| Kernel / system extensions | `kmutil showloaded`, `/Library/Extensions`, `systemextensionsctl list`, `/Library/SystemExtensions/db.plist` | New kext or system extension, especially a network or ES extension from an unknown Team ID |
| Trust / network config | System keychain trust settings (`security dump-trust-settings -d`), `/etc/hosts`, proxy settings (SCDynamicStore notifications on `State:/Network/Global/Proxies`), DNS (`scutil --dns`), `/etc/resolver/*` | New trusted root, new proxy, DNS redirect |
| Misc plugin dirs | `~/Library/QuickLook`, `/Library/QuickLook`, `~/Library/Spotlight`, `/Library/Spotlight`, Folder Actions (`~/Library/Scripts/Folder Action Scripts`), `/Library/DirectoryServices/PlugIns`, Input Methods, Screen Savers, `~/Library/Application Support/iTerm2/Scripts/AutoLaunch`, xbar/SwiftBar plugin dirs | New bundle or script that is unsigned or from an unknown Team ID |

**Scoring a new persistence item.** Score depends on *who wrote it* (correlate the FSEvents timestamp with live processes that have the directory open, or with a recently started process whose argv references the path) and *what it runs*. Signed + notarized + known Team ID + written by an installer (`installd`, `PackageKit`, the app itself in `/Applications`) is low risk. Unsigned or ad-hoc, in a hidden or temp location, written by a shell or interpreter descendant, is high risk.

Apple has its own observer: from macOS 13 the BTM daemon posts "Background Items Added" notifications. Bastion should add value by **scoring** these items, not merely notifying.

---

## 4. Unified log streaming

Run `log stream --style ndjson --level info --predicate '<P>'` as a child of `bastiond`. Restart it with backoff when it dies, and use `log show --start` to backfill the gap. Use one stream per predicate group to keep parsing cheap. Treat message formats as **version-specific**: keep the parsers in data files keyed by OS build, and include regression fixtures.

| Purpose | Predicate (starting point — verify per OS release) | Notes |
|---|---|---|
| TCC prompts / decisions | `subsystem == "com.apple.TCC"` (process `tccd`) | Look for auth-request / result messages naming the service (`kTCCServiceAppleEvents`, `ScreenCapture`, `Microphone`, `Camera`, `SystemPolicyAllFiles`, `SystemPolicyAppData`, `Accessibility`, `ListenEvent`, `PostEvent`) and the requesting client. A burst of requests from one unsigned client is a strong signal |
| Apple Events / automation | `subsystem == "com.apple.appleevents"` and TCC `kTCCServiceAppleEvents` | Script hosts automating Finder/System Events/Terminal |
| Gatekeeper / XProtect | `process == "syspolicyd" OR subsystem == "com.apple.xprotect" OR process == "XprotectService"` | Assessment denials, user overrides ("Open Anyway"), XProtect Remediator detections |
| Background items | `subsystem == "com.apple.backgroundtaskmanagement"` | New login item or launch item registrations |
| Privilege use | `process == "sudo"`, `process == "authd" OR subsystem == "com.apple.Authorization"` | sudo commands; authorization rights requested (e.g. `system.privilege.admin`) and by which client |
| Keychain | `process == "securityd" OR subsystem == "com.apple.securityd"` | Noisy. Use it only to correlate with argv-based keychain rules |
| Profiles / MDM | `subsystem == "com.apple.ManagedClient"` | Profile install/remove |
| Camera / mic | `subsystem == "com.apple.cmio"`, `process == "coreaudiod"`, Control Center sensor-indicator messages | Used by OverSight to attribute device use to a pid |
| Screen capture | ScreenCaptureKit / `replayd` messages, TCC `kTCCServiceScreenCapture` | Capture-session start by an unexpected client |
| Terminal paste protection (macOS 26.4+) | Terminal process messages about blocked pastes (exact subsystem TBD; capture on a test machine) | Apple now warns about suspicious pasted commands. A user overriding that warning is a high-value signal |

Private data: most process names and paths appear in the clear, but many arguments are `<private>`. Enabling private data needs a configuration profile (`com.apple.system.logging` `Enable-Private-Data`). That is a privacy trade-off, so make it opt-in.

---

## 5. Ransomware heuristics (RansomWhere-inspired)

### 5.1 Signals
1. **Encrypted-output detection.** For each newly written or renamed file in user data dirs, read the first 4–64 KB and compute Shannon entropy plus a chi-square test (RansomWhere uses a chi-square and Monte-Carlo-π style randomness test). Encrypted data scores ~7.99 bits/byte and passes the chi-square test as uniform. **Compressed formats are also high entropy**, so:
   - Compare the new file's magic bytes against its extension and against the *previous* version of the file (cache the first 16 bytes of user documents on first sight). The strongest signal is "file *was* a valid PDF/DOCX/JPEG header and is now random."
   - Exempt known high-entropy types only when their magic bytes still validate.
2. **Mass write / rename velocity** per attributed process: N distinct user files modified or renamed in T seconds (e.g. more than 20 in 10 s across more than 2 directories). Weight it higher when the extension changes to one unknown extension, or when a ransom-note-like file (same name, many dirs) appears.
3. **Delete-after-write pattern**: create a new file → delete or rename the original, repeated.
4. **Canary files.** Drop hidden-but-plausible decoy documents in `~/Documents`, `~/Desktop`, `~/Downloads`, and top-level dirs of mounted volumes. Name them so they sort both first and last alphabetically, because ransomware often walks directories in order. Any modify, rename, or delete of a canary is near-certain malice (apart from sync clients and backup tools, which are excluded by allowlist and by checking that content changed).
5. **Backup tampering**: `tmutil` delete / disable invoked by a non-Apple parent, APFS local snapshot deletion, or shadow copies of iCloud data removed in bulk.

### 5.2 Response
SIGSTOP the attributed process (and its tree) at the first strong signal (canary hit, or encrypted output above the threshold). Then alert, and on user confirmation kill it, quarantine its binary, and record affected paths for restore. Optionally take an APFS snapshot (`tmutil localsnapshot`) as soon as a medium-level ransomware score appears. It is cheap and enables rollback.

### 5.3 Attributing FSEvents to a process (no pid from FSEvents)
- On a burst in directory D: sweep `PROC_PIDLISTFDS`/`PROC_PIDFDVNODEPATHINFO` across non-Apple processes for open vnodes under D or for cwd (`PROC_PIDVNODEPATHINFO`) in D.
- Rank candidates by recent start time, CPU time delta (`PROC_PIDTASKINFO` `pti_total_user`), disk I/O delta (`proc_pid_rusage` `ri_diskio_byteswritten`, a very good attribution signal), and signing tier.
- `proc_pid_rusage` bytes-written deltas alone often identify the writer within one or two sweeps.

---

## 6. Credential-theft heuristics (infostealer: AMOS, Cuckoo, Banshee, Poseidon, MacSync families)

Modern macOS stealers usually follow a recognisable *sequence*: user-assisted execution (fake installer DMG, ClickFix-style paste, Script Editor via `applescript://` URL) → **fake password dialog** produced by a script host → validation of the password via a directory-services authentication tool → **bulk copying** of browser profiles, keychain DBs, wallet dirs, notes, and documents into a staging folder in a temp dir → archive → HTTP upload → cleanup. Each stage alone is ambiguous; the chain is not.

Watch conditions (no ES, so mostly lineage + argv + open-fd sampling + FSEvents in temp dirs):
- **Sensitive-path set:** `~/Library/Keychains/`, `~/Library/Application Support/{Google/Chrome,BraveSoftware,Microsoft Edge,Arc,Vivaldi,Opera*}/*/{Login Data,Cookies,Web Data}`, `Local State`, Firefox `logins.json`/`key4.db`/`cookies.sqlite`, `~/Library/Cookies`, Safari dirs (TCC-protected), Apple Notes store, Telegram data, wallet extension IndexedDB/Local Extension Settings for known wallet extension IDs, desktop wallet dirs (Exodus, Electrum, Atomic, Ledger Live, etc.), `~/.ssh`, cloud CLI credentials (`~/.aws`, `~/.config/gcloud`, `~/.kube`).
- **Who touched it:** open-fd sampling hits on the sensitive set by any process that is not the owning app (browser), not Apple, and not an allowlisted password manager or backup tool.
- **FSEvents in temp:** files *created* under `/tmp`, `/private/var/folders/*`, or hidden dirs whose **names or relative structure mirror** browser or wallet profile files (e.g. a new file named `Login Data` or `Cookies` outside the browser dir). This is cheap and catches stealers even after they exit.
- **Keychain-related CLI use:** argv of `security` invocations asking for generic passwords for browser "Safe Storage" items, or dumping the keychain, with a non-browser parent.
- **Password-phishing dialog:** a script host (osascript / Script Editor / an unsigned app) producing a modal dialog with a hidden-answer field while its lineage is untrusted, *followed by* a local authentication check via the directory-services CLI. These are argv- and lineage-based watch conditions only.
- **TCC side channel:** on macOS 14+ the "access data from other apps" (`kTCCServiceSystemPolicyAppData`) prompt, and FDA/Files-and-Folders prompts for an unsigned client, show up in the TCC log. A sudden cluster of these from one client is suspicious.

Honeytokens: plant decoy files in the sensitive set (a fake wallet directory, a decoy keychain-looking DB, a decoy `~/.aws/credentials` with a canary key). Any read of these (open-fd sampling, plus atime where the volume updates it) or any external use of the canary key is high confidence. Note that APFS atime behaviour is not reliable for this, so do not rely on atime alone.

---

## 7. ClickFix / clipboard-to-terminal detection

ClickFix (fake CAPTCHA / "fix your Mac" pages, including troubleshooting posts on legitimate platforms) causes users to paste a command into Terminal. Malwarebytes reported that ClickFix accounted for more than half of loader activity in 2025. Apple added a "Possible malware, Paste blocked" warning in macOS 26.4. Attackers pivoted to the `applescript://` URL scheme, which opens Script Editor with pre-filled script (Jamf Threat Labs).

Detection design (session agent + daemon):
1. **Clipboard classifier.** On every `changeCount` bump, classify the content with a small rule set: does it look like a shell one-liner that fetches remote content and hands it to an interpreter, decodes an encoded blob, or invokes a script host? Store only a **hash and a class label**, never the raw clipboard (privacy). Track the *source*: the frontmost app at copy time (a browser is the risk case).
2. **Paste-to-terminal correlation.** Within ~120 s of a risky clipboard class copied from a browser, a Terminal/iTerm shell spawns a child whose argv shares tokens with the classified clipboard text (compare the hash of normalised argv against a hash of the normalised clipboard, or measure token overlap computed in-memory). This is the core ClickFix rule.
3. **Script Editor via URL scheme.** Script Editor launched by LaunchServices on behalf of a browser (responsible process = browser) shortly after a web visit, followed by a script run that spawns network or shell children.
4. **Apple paste-warning override** (macOS 26.4+): log event showing the user bypassed the paste block. Treat it as a strong signal and pre-arm the stealer rules for the next 10 minutes.
5. **Post-paste behaviour** gets amplified scoring: downloads into temp dirs, quarantine removal, ad-hoc-signed binaries executed from temp, and script-host dialogs.

FP: developers routinely paste install one-liners (Homebrew, rustup, nvm). Mitigate with a "known installer domain/script" allowlist (match on URL host in argv), with a developer-mode profile, and by requiring a downstream behaviour (credential or persistence rule) before a high-severity alert.

---

## 8. LOLBin / living-off-the-land watch list

Use argv-pattern + parent-lineage + location rules. **Never score the tool alone**, only the combination of tool + context:
- Downloader output piped into a shell or interpreter, especially when the parent is Terminal and the clipboard rule is armed, or when the parent is a script host or an unsigned binary.
- Base64 or other decoders feeding an interpreter, or writing an executable into a temp dir.
- `osascript` with inline script text (as opposed to a script file path) whose parent is a shell descended from a browser, an installer, or an unsigned binary. Also osascript producing dialogs or automating System Events, Finder, or Terminal.
- Quarantine attribute removal (`xattr` deleting `com.apple.quarantine`), or recursive xattr clearing on a freshly downloaded app/DMG.
- Making a file executable in `/tmp`, `/private/var/folders`, `/Users/Shared`, or a hidden dot-dir, followed by its execution.
- `nohup` / `disown` / `screen -dm` / `launchctl submit` detaching a process from a non-interactive parent.
- `launchctl load`/`bootstrap` of a plist the same lineage just wrote.
- `codesign` ad-hoc re-signing (`--sign -`) of a freshly downloaded binary, followed by execution (bypassing the "damaged" message).
- `spctl` assessment disable, `defaults write` of Gatekeeper-related prefs, `csrutil` queries from non-interactive contexts (recon).
- `system_profiler`/`sw_vers`/`ioreg` hardware-UUID queries in rapid succession by one unsigned lineage (stealer host fingerprinting and VM checks). Score low alone.
- `ditto`/`zip` archiving a temp staging dir, followed by an HTTP upload with a multipart file argument from the same lineage.
- `tccutil reset` invoked by a non-Apple parent; `sqlite3` touching `TCC.db`.
- `screencapture` invoked silently (`-x`) by a non-interactive, non-Apple parent.
- `dscl` local authentication checks issued by a script lineage (password validation).
- `pkill`/`killall` of security tools (Bastion, LuLu, BlockBlock, Little Snitch) by a non-user lineage. This is tamper.

Implementation note: normalise argv (strip quotes, collapse whitespace, decode obvious `\x` escapes) before matching. Keep the patterns in a versioned rules file (YAML/JSON) that the engine loads, not hard-coded Swift.

---

## 9. Network exfil heuristics (no Network Extension)

Without NE we cannot see DNS per process, SNI, or block. We can **observe sockets** (pid → 5-tuple) and **argv**:
- **New outbound connection from an untrusted binary**: unsigned / ad-hoc / not notarized / in a temp or hidden path / first seen < 24 h. LuLu's core heuristic is "unknown, non-Apple process makes a first connection." We approximate it passively.
- **Destination classification** via IP sets refreshed daily: Telegram Bot API ranges (Telegram publishes its CIDRs), Discord (webhook URLs in argv are the stronger signal), Tor (consensus relay list; ports 9001/9030 outbound; local SOCKS 9050/9150 listeners), known DoH resolvers (Cloudflare, Google, Quad9, NextDNS IPs on 443) contacted by **non-browser** processes, paste and file-sharing sites, raw IPs with no recent DNS resolution observed for them, and cloud tunnel services (ngrok, trycloudflare).
- **argv URLs**: downloader or interpreter processes whose argv contains webhook/bot-API hosts or raw-IP URLs with multipart upload options.
- **Volume**: `nettop` / `proc_pid_rusage` network bytes are not exposed per process via libproc. Use `nettop -P -L 1 -J bytes_out` sampling every 10–30 s for top talkers. Flag an untrusted process with more than X MB out shortly after a sensitive-path access.
- **Beaconing**: fixed-interval connections (low jitter) to the same IP from a non-browser process over 30+ minutes.
- **Listeners**: an unsigned process opening a listening TCP port on 0.0.0.0 (reverse shell / bind shell / remote access).
- **Config tampering**: a new system proxy, a new DNS resolver, or a new root CA (§3) all enable interception.

---

## 10. Surveillance signals (OverSight / ReiKey designs)

- **Mic/camera**: CoreAudio/CoreMediaIO "running somewhere" listeners fire on every on/off. Attribute the user via the log (cmio / coreaudiod messages) and via processes that have the camera assistant or audio HAL open. Alert only when the client is untrusted or has no visible windows (`CGWindowListCopyWindowInfo` for the pid, and `NSRunningApplication.activationPolicy == .prohibited`).
- **Screen capture**: TCC ScreenCapture grants to new or untrusted clients; ScreenCaptureKit sessions from background-only processes; silent `screencapture` from non-interactive lineages; bursts of image files written to temp dirs.
- **Keyloggers**: `CGGetEventTapList` every 10 s. A new tap (`kCGEventTapOptionDefault` or listen-only) on key-down events, owned by a non-Apple, untrusted process, is a strong signal (ReiKey's approach). Also TCC `ListenEvent` (Input Monitoring) and `Accessibility` grants to new clients.

---

## 11. Objective-See reference designs (study, do not copy)

Objective-See tools are open source on GitHub (`github.com/objective-see`), mostly GPLv3. **Do not copy code into Bastion unless the licence is compatible.** Re-implement the ideas.

| Tool | What it does | Mechanism then → now | Lesson for Bastion |
|---|---|---|---|
| **BlockBlock** | Alerts on (and can block) new persistence | Early: kext + FSEvents + root daemon + user agent. Now: ES (`AUTH`/`NOTIFY` file events) | Plugin-per-persistence-type model; alert shows the *executed binary* with signing info, the *parent process*, and the plist path. Our version: FSEvents + periodic diff + after-the-fact removal (unload, then move to quarantine) |
| **KnockKnock** | On-demand persistence enumeration | Plugin scanners per autorun class; VirusTotal hash lookups; signing status | Model for our scheduled full scan and baseline diff. Its plugin list is a good checklist |
| **RansomWhere** | Generic ransomware detection | FSEvents on user dirs; trusts apps present at install time; flags **untrusted processes rapidly creating encrypted files** (entropy/chi-square test); suspends the process (SIGSTOP) and asks the user | Exactly our §5 design: suspend first, ask second. Trust baseline at install. Coverage was reported to weaken against newer variants, so add canaries and magic-byte transition checks |
| **LuLu** | Outbound firewall | Network Extension content filter (requires entitlement) | We cannot block. Copy the *policy UX* (per-binary allow/deny keyed on code signature, "allow Apple binaries" default, passive mode) for alerting |
| **OverSight** | Mic/camera monitor | CoreAudio/CoreMediaIO property listeners; identifies the client via the unified log (recent versions) | Direct template for §10; no entitlement needed |
| **ReiKey** | Keyboard event-tap scanner | `CGGetEventTapList` | Cheap, high-value keylogger rule |
| **Netiquette / TaskExplorer** | Network and process explorers | libproc/`nettop`-style enumeration plus signing | Reference UI for process/socket inspection |
| **DHS (Dylib Hijack Scanner)** | Finds dylib hijack / proxy opportunities | Mach-O load-command parsing (`LC_LOAD_WEAK_DYLIB`, `@rpath`) | Optional static check on persistence targets |

---

## 12. Scoring and correlation model

### 12.1 Entities
Score **process lineages** (a "story" rooted at the first untrusted ancestor, or at the user-assisted entry point such as Terminal paste, DMG open, or Script Editor launch), not individual events. Each story has a rolling score, a list of fired rules, and a TTL (default 30 min, extended on activity).

### 12.2 Computation
- Each rule has a base score 1–100 (see catalogue) and a **confidence class**: *atomic-strong* (alerts alone: canary hit, event-tap keylogger by an unsigned binary), *atomic-weak* (context only), or *sequence* (fires on ordered rule combinations).
- **Context multipliers** on the story's binary: unsigned ×1.5; ad-hoc ×1.4; quarantined-and-unnotarized ×1.3; temp/hidden path ×1.3; first-seen < 1 h ×1.2; Apple platform binary ×0.2 (LOLBins are scored through their untrusted *ancestor*, not their own signature); notarized known-vendor Team ID ×0.3; user-allowlisted ×0.
- **Combination:** noisy-OR over normalised rule probabilities, `S = 100 × (1 − Π(1 − sᵢ/100))`, with a per-rule cap so ten weak hits cannot outweigh one strong hit. Count each rule at most once per story per 10 min (de-duplication).
- **Sequence bonuses** (kill-chain): entry (paste / DMG / URL-scheme) → execution from temp → credential access → archive → upload. Each consecutive stage adds +15. Any three stages within 10 min is treated as a "stealer chain" and goes straight to *critical*.
- **Decay:** half-life of 15 min for weak signals. Strong signals do not decay within the TTL.

### 12.3 Thresholds and actions
| Score | Level | Action |
|---|---|---|
| < 40 | log | Telemetry only |
| 40–69 | notice | Non-blocking notification; offer "show details" |
| 70–89 | alert | Alert. SIGSTOP the lineage if the ransomware/stealer category is active; user chooses allow or kill |
| ≥ 90 or atomic-strong | critical | SIGSTOP immediately, kill on timeout (60 s) if no answer, quarantine the binary, undo persistence written by the lineage |

### 12.4 False-positive controls
1. **Learning mode** for the first 7 days: rules fire into telemetry only and build a per-machine baseline (which Team IDs start at login, which processes connect out, which processes touch browser dirs).
2. **Trust baseline at install**: hash and record every existing app and persistence item (RansomWhere's approach). Changes to those are scored; their mere presence is not.
3. **Vendor allowlists keyed by Team ID + designated requirement**, never by path: browsers, password managers (1Password, Bitwarden, Dashlane), backup and sync (Time Machine, Backblaze, Arq, Dropbox, iCloud `bird`/`cloudd`, Google Drive, OneDrive), dev tools (Homebrew, Xcode CLT, `node`/`npm` postinstall, `cargo`, `pip`), MDM agents (Jamf, Kandji, Mosyle, Intune), and other security products.
4. **Developer mode** profile that down-weights interpreter/LOLBin rules when the parent is an IDE or a terminal session with a dev toolchain, but keeps credential, canary, and keylogger rules at full weight.
5. **Require corroboration** before high severity for every *atomic-weak* rule. One weak signal alone never pages the user.
6. **Feedback loop**: user "allow" decisions create scoped exceptions (Team ID + rule ID + path class). Export them in anonymised telemetry for tuning.
7. **Regression corpus**: replay recorded benign telemetry from real dev, office, and creative machines plus public malware behaviour reports (Objective-See's Mac Malware of the Year reports, Jamf/SentinelOne/Moonlock write-ups) through the engine in CI. Track the FP rate per rule.

### 12.5 Performance budget
Target < 1% CPU average and < 80 MB RSS for the daemon. Poll pids at 100 ms but enrich only new pids. Cache signing by cdhash. Sweep fds and sockets every 2–5 s, plus on demand when a trigger fires. Keep FSEvents latency at 0.5 s with file-level events only on watched trees. Keep each log stream predicate narrow.

---

## 13. Sources

- Objective-See tools and source: https://objective-see.org/tools.html, https://github.com/objective-see (BlockBlock, KnockKnock, RansomWhere, LuLu, OverSight, ReiKey)
- RansomWhere README: https://raw.githubusercontent.com/objective-see/RansomWhere/main/README.md
- RansomWhere coverage: https://securityaffairs.com/46534/breaking-news/ransomwhere-detection-tool.html, https://eclecticlight.co/2016/04/21/no-fear-of-ransomware/
- BlockBlock overview: https://sourceforge.net/app/blockblock/mac/
- ClickFix on macOS (Terminal paste, stealer families, macOS 26.4 paste warning): https://www.malwarebytes.com/blog/news/2026/04/clickfix-finds-new-way-to-infect-macs
- ClickFix via Script Editor / `applescript://`: https://www.jamf.com/blog/clickfix-macos-script-editor-atomic-stealer/
- ClickFix detection guidance: https://cybersecuritynews.com/new-clickfix-attack-targets-macos-users/, https://feed.craftedsignal.io/briefs/2026-05-clickfix/
- Apple docs: libproc (`<libproc.h>` in the SDK), FSEvents Programming Guide, Security framework Code Signing Services, `log(1)`, `kqueue(2)`, `CGGetEventTapList`.

---

## 14. Rule catalogue

Scores are base scores (1–100) before the context multipliers in §12.2. Type: **S** = atomic-strong (may alert alone), **W** = atomic-weak (context only; needs corroboration), **Q** = sequence/correlation rule. "Untrusted" means unsigned, ad-hoc, unnotarized, or first seen < 24 h and not allowlisted. Each rule is a *watch condition*; implementation patterns live in the versioned rules file.

| # | Name | Type | Signal source | Watch condition | Score | False-positive notes |
|---|---|---|---|---|---|---|
| R01 | Canary document modified | S | FSEvents on canary paths | Any write, rename, or delete of a Bastion decoy document | 95 | Sync/backup clients may touch it. Exclude by Team ID and check whether content actually changed |
| R02 | Encrypted-output burst | S | FSEvents + entropy/chi-square + rusage attribution | One untrusted process produces ≥ 10 user files with random-looking content in 30 s | 85 | Archivers, encrypted-disk-image tools, and media encoders. Validate magic bytes; allowlist known archivers |
| R03 | Header-to-random transition | S | FSEvents + cached magic bytes | A file previously valid as a known document/image type is rewritten with random-looking content | 80 | Legit encryption tools (rare). User-initiated by an allowlisted app → drop |
| R04 | Mass rename to single new extension | W | FSEvents rename flags | ≥ 20 user files renamed to the same previously-unseen extension in 60 s by one attributed process | 55 | Photo/batch-rename utilities. Require an untrusted writer to escalate |
| R05 | Ransom-note pattern | W | FSEvents | Same new text/HTML file name created in ≥ 5 user directories within 2 min | 50 | Rare. Some installers drop README files. Combine with R02 |
| R06 | Backup / snapshot tampering | S | Process poller argv + lineage | Time Machine or local-snapshot deletion/disable launched by a non-Apple, non-interactive lineage | 75 | Disk-cleanup utilities and admins. Down-weight when the parent is an interactive Terminal under admin consent |
| R07 | New LaunchAgent/Daemon → untrusted target | S | FSEvents + periodic diff on launchd dirs + plist parse + signing | New/changed plist whose executed program is untrusted, or sits in a temp/hidden/`/Users/Shared` path | 70 | Dev tools and small vendors ship unsigned helpers. Allowlist via user decision |
| R08 | LaunchAgent written by script lineage | Q | FSEvents attribution + lineage | Plist created by a shell/interpreter lineage descended from a browser, DMG app, or Terminal paste within 10 min | 80 | Homebrew services, dev scripts. Developer-mode down-weight |
| R09 | Launch plist injects dylib env | S | Plist parse | `EnvironmentVariables` containing `DYLD_*` keys in any launchd plist | 75 | Very rare legitimately. Some debugging setups |
| R10 | New BTM login item (untrusted) | W | Log subsystem `com.apple.backgroundtaskmanagement` + BTM db diff | New background/login item whose executable is untrusted | 45 | Most items are legit vendor software. Score only untrusted ones |
| R11 | New cron / periodic job | W | FSEvents + diff on cron tabs and periodic dirs | Any new cron/periodic entry not written by an installer | 50 | Power users/admins. Rare on modern macOS, so keep it visible |
| R12 | Shell rc file gains remote-fetch or hidden-exec line | S | FSEvents + line diff on shell startup files | Added line performs a network fetch, executes from a hidden/temp path, or contains an encoded blob | 70 | Tool installers (nvm, conda, rustup) add lines. Allowlist known installer signatures |
| R13 | Shell rc file modified by non-shell process | W | FSEvents attribution | Startup file changed by a process that is neither an editor, a known installer, nor the user's shell | 35 | Dotfile managers. Allowlist |
| R14 | New SSH authorized key | S | FSEvents on `~/.ssh/authorized_keys` | Key added while no interactive ssh/editor process is in the writer's lineage | 70 | Users adding keys by hand; provisioning tools. Show key comment in alert |
| R15 | Remote Login enabled | W | Periodic `systemsetup`/launchd state diff | sshd enabled by a non-System-Settings lineage | 45 | Admin action. Corroborate with R14 |
| R16 | Sudoers / authorization DB change | S | FSEvents on sudoers paths + authorizationdb diff | Any change outside an installer/MDM session | 75 | MDM agents. Allowlist by Team ID |
| R17 | Authorization / directory-services plugin added | S | FSEvents on SecurityAgentPlugins and DirectoryServices PlugIns | New bundle from an unknown Team ID | 80 | Enterprise SSO/auth vendors. Allowlist |
| R18 | Login/logout hook set | S | loginwindow prefs diff | `LoginHook`/`LogoutHook` value present or changed | 70 | Legacy admin scripts in old fleets |
| R19 | Dock tile hijack | S | Dock plist diff + bundle resolution | A `persistent-apps` entry's label matches a known app but its path/bundle ID resolves to a different or untrusted bundle | 75 | Users relocating apps. Compare Team IDs |
| R20 | Browser extension sideloaded / force-installed | S | Extensions dir + Preferences diff + managed-policy plists | New extension not from a store install, or force-install policy written outside MDM | 70 | Enterprise policy via MDM. Check the profile source |
| R21 | High-permission browser extension added | W | Extension manifest parse | New store extension requesting all-sites + cookies/webRequest/nativeMessaging | 35 | Many legit extensions (ad blockers, password managers). Context only |
| R22 | New native-messaging host → untrusted binary | S | FSEvents on NativeMessagingHosts dirs + signing | Host manifest points to an untrusted binary | 70 | Small dev tools. Allowlist |
| R23 | Configuration profile installed outside MDM | S | `com.apple.ManagedClient` log + `profiles` diff | New profile not from the enrolled MDM, especially with root-CA, proxy, DNS, or browser-policy payloads | 80 | Corporate Wi-Fi/VPN profiles installed manually. Show payload types |
| R24 | New trusted root certificate | S | Trust-settings diff | New admin/user trust setting for a root CA | 80 | Corporate TLS inspection, dev proxies (mitmproxy, Charles). Allowlist by cert hash |
| R25 | Proxy / DNS / hosts redirect | W | SCDynamicStore notifications + `/etc/hosts` + `/etc/resolver` diff | New system proxy, resolver, or hosts entry for a popular domain, set by a non-VPN/non-MDM process | 50 | VPN clients, ad-blockers, dev setups. Allowlist by Team ID |
| R26 | New kernel/system extension from unknown Team ID | W | `kmutil`/`systemextensionsctl` diff | Newly loaded extension whose Team ID is not in the trust baseline | 45 | Drivers, VPNs, security tools. User approval is already required by macOS |
| R27 | Quarantine removed then executed | Q | Process argv + xattr check + lineage | Quarantine attribute stripped from a downloaded item by a script/Terminal lineage, then that item is executed within 10 min | 65 | Developers and power users. Developer-mode down-weight |
| R28 | Ad-hoc re-sign then execute | Q | Process argv + signing | Freshly downloaded binary is ad-hoc re-signed and then executed by the same lineage | 60 | Open-source app users following README workarounds. Medium only |
| R29 | Execution from temp / hidden path | W | Process poller + path class | New process image in `/tmp`, `/private/var/folders`, `/Users/Shared`, or a hidden dot-dir, and untrusted | 40 | Installers and updaters (Sparkle) run from temp. Allowlist signed updaters |
| R30 | Remote content piped to interpreter | W | Process lineage (kqueue fork/exec) | A downloader process whose stdout feeds a shell/interpreter sibling in the same pipeline | 40 | Very common dev installer pattern. Needs R31 or a downstream rule |
| R31 | ClickFix: browser copy → Terminal paste → exec | Q | Agent pasteboard classifier + frontmost app + kqueue on Terminal shells | Risky-class clipboard copied from a browser, then within 120 s a Terminal shell spawns a child whose normalised argv matches the clipboard hash/tokens | 70 | Devs pasting install commands. Allowlist known installer hosts; escalate only with downstream rules |
| R32 | Apple paste-warning overridden | S | Unified log (Terminal paste-protection message, macOS 26.4+) | User bypasses the "Possible malware, Paste blocked" warning | 65 | Rare false triggers by Apple's classifier. Arms stealer rules for 10 min |
| R33 | Script Editor launched by browser URL scheme | W | Lineage: responsible process = browser; Script Editor launch | Script Editor opened on behalf of a browser, then runs a script that spawns shell or network children | 55 | Rare legitimately. Some AppleScript tutorials |
| R34 | Script-host password dialog | S | Process argv + lineage | A script host (osascript/Script Editor/untrusted app) shows a dialog with a hidden-answer field, and its lineage is untrusted or paste-derived | 75 | IT scripts in managed fleets. Allowlist MDM Team IDs |
| R35 | Local password validation by script lineage | S | Process argv + lineage | Directory-services local-auth check issued by a script/untrusted lineage, especially right after R34 | 75 | Admin scripts. Rare for end users |
| R36 | Browser "Safe Storage" keychain query | S | Process argv + parent | Keychain CLI request for a browser Safe Storage item from a non-browser parent | 80 | Some browser-migration and cookie-export tools. Allowlist |
| R37 | Sensitive credential file opened by foreign process | W | Open-fd sampler on the sensitive-path set | A process that is not the owning app, not Apple, and not an allowlisted manager/backup tool holds a sensitive file open | 50 | Backup, sync, Spotlight, AV. Allowlist by Team ID |
| R38 | Credential-store mirror in temp | S | FSEvents on temp dirs | Files named or structured like browser/wallet/keychain profile files created under temp or hidden dirs | 80 | Browser updaters migrating profiles (rare outside the browser's own dir) |
| R39 | Honeytoken credential touched | S | Open-fd sampler + FSEvents on decoys; external canary callback | Any access to decoy wallet/keychain/cloud-credential files, or external use of the canary key | 95 | Full-disk backup tools. Exclude by Team ID |
| R40 | Stealer chain | Q | Story correlation | ≥ 3 of: entry (R31/R32/R33/DMG open) → temp exec (R29) → credential access (R34–R39) → archive of temp staging dir → upload (R43) within 10 min | 95 | Very low FP by construction |
| R41 | Untrusted first outbound connection | W | Socket sampler + signing | Untrusted binary opens its first-ever external TCP connection | 30 | Common for new legit unsigned tools. Context only |
| R42 | Messaging-API / webhook destination | W | Socket sampler + IP sets; argv URLs | Non-messaging-app process connects to Telegram Bot API ranges or carries Discord/Telegram webhook URLs in argv | 55 | Bots and CI notifications run by developers. Score up with credential rules |
| R43 | Archive then upload from same lineage | Q | Process lineage + FSEvents | Lineage archives a temp staging dir, then a network client uploads a file from that dir | 70 | Backup scripts, crash reporters. Allowlist signed vendors |
| R44 | Tor usage by non-Tor app | W | Socket sampler + relay IP list + local listener scan | Connections to Tor relay IPs/ports, or a local SOCKS listener, from a process that is not Tor Browser | 50 | Privacy-conscious users. Notice only |
| R45 | DoH from non-browser | W | Socket sampler + resolver IP list | Non-browser, untrusted process talking 443 to known DoH resolver IPs | 40 | VPNs, privacy tools, some apps' built-in DoH. Allowlist by Team ID |
| R46 | Beaconing | W | Socket sampler time series | Low-jitter periodic connections to one IP from a non-browser, untrusted process over 30+ min | 45 | Update checkers, telemetry. Restrict to untrusted |
| R47 | Untrusted listener on all interfaces | W | Socket sampler | Untrusted process listens on 0.0.0.0/:: TCP | 45 | Dev servers. Developer-mode down-weight |
| R48 | Keyboard event tap by untrusted process | S | `CGGetEventTapList` poll | New key-event tap owned by a non-Apple, untrusted process | 85 | Text expanders, accessibility tools, Karabiner. Allowlist by Team ID |
| R49 | Input Monitoring / Accessibility granted to new untrusted client | W | TCC log | TCC grant of ListenEvent/PostEvent/Accessibility to an untrusted client | 50 | Users intentionally approving utilities. Context + R48 |
| R50 | Mic/camera used by background or untrusted process | S | CoreAudio/CMIO listeners + log attribution + window check | Device activated by a process that is untrusted or has no visible window | 70 | Background recorders, meeting helpers. Allowlist |
| R51 | Silent screen capture | W | Process argv + lineage; ScreenCaptureKit/TCC log | Silent capture by a non-interactive, non-Apple lineage, or burst of images in temp | 55 | Screenshot utilities, MDM remote support |
| R52 | TCC prompt burst | W | TCC log | ≥ 3 distinct TCC service requests from one untrusted client within 2 min | 50 | First run of legitimate apps. Corroborate |
| R53 | TCC database tampering | S | FSEvents on TCC.db + process argv | A non-Apple process writes TCC.db, or a TCC reset is issued by a non-interactive lineage | 85 | MDM tools. Allowlist |
| R54 | Gatekeeper override + untrusted exec | W | syspolicyd log + process poller | User "Open Anyway" on an unnotarized app, followed by that app spawning shells or interpreters | 45 | Users opening indie apps. Context only |
| R55 | Security tool tamper | S | Process argv + kqueue `NOTE_EXIT` on Bastion and other security tools | Kill or unload of Bastion/other security tools by a non-user, non-Apple lineage | 85 | Updates of those tools. Verify the actor's Team ID |
| R56 | Host fingerprinting / VM check burst | W | Process lineage argv | Untrusted lineage runs ≥ 3 hardware/OS inventory tools within 30 s | 25 | Inventory/MDM agents, support tools. Context only |
| R57 | Detached background process from script lineage | W | Process poller (ppid 1 re-parent) + lineage history | Process from a script/paste-derived lineage detaches and keeps running after its parent exits | 35 | Dev servers and helper daemons. Context only |
| R58 | Self-deleting binary | W | FSEvents remove + process poller | Executable file deleted while its process is still running, and untrusted | 55 | Some updaters. Restrict to untrusted |

**Tuning order for v1:** ship S-class rules R01, R02, R07, R14, R24, R36, R38, R39, R40, R48, and R50 enabled and blocking (SIGSTOP). Ship all W/Q rules in telemetry-only learning mode for the first two releases. Promote individual rules once their measured FP rate on the regression corpus is below 1 per 1,000 machine-days.
