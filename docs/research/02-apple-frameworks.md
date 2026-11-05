# 02 — Apple Frameworks & OS Facilities for a macOS Antivirus

Target: Bastion (Swift 6.4, Command Line Tools only, no Xcode, no paid Apple Developer entitlements), macOS 27.0.1 (build 26A434), arm64, SIP enabled, Gatekeeper enabled.

Findings marked **[verified locally]** were run on this machine (read-only). Everything else comes from Apple docs, Apple Developer Forums, and Eclectic Light. Apple documents little about XProtect internals, so check those parts again after each OS update.

---

## 0. Local environment facts [verified locally]

| Item | Result |
|---|---|
| `sw_vers` | macOS 27.0.1, 26A434 |
| `swift --version` | Swift 6.4, target `arm64-apple-macosx27.0.0` |
| `xcode-select -p` | `/Library/Developer/CommandLineTools` (no Xcode) |
| SDKs | `MacOSX27.sdk` and older 26.x |
| `csrutil status` | SIP **enabled** |
| `spctl --status` | `assessments enabled` |
| ES headers | Present: `MacOSX.sdk/usr/include/EndpointSecurity/{EndpointSecurity,ESClient,ESMessage,ESTypes}.h` and a `module.modulemap`. The code compiles; it just won't run without the entitlement. |
| SDK frameworks | `NetworkExtension`, `SystemExtensions`, `ServiceManagement`, `Security`, `CoreServices` are all present |
| `eslogger` | `/usr/bin/eslogger` exists. `--list-events` lists **106** event types. |
| `fs_usage` | `/usr/bin/fs_usage` exists (root only) |
| `xprotect version` | `Version: 5371 Installed: 2026-11-04` |
| `systemextensionsctl list` | Works without root (1 third-party driver extension is installed) |
| `sfltool dumpbtm` | Works for the current user and lists BTM records (Docker legacy daemon, etc.) |
| `yara` CLI | Not installed |

**Name collision:** Apple already ships an XProtect behavioural engine called **"Bastion"**: `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources/bastion.sb` (sandbox-profile-style rules) and `BastionMeta.plist` (signature names like `macOS.Browser.Generic`, `macOS.Messages.Generic`, `macOS.QntDb.Generic`). Expect confusion in logs and search results. Consider renaming the product, or always write "Bastion AV" in log subsystems (e.g. `com.<you>.bastionav`).

---

## 1. Endpoint Security (ES) framework

**What it is:** A C API (`libEndpointSecurity.tbd`, `#include <EndpointSecurity/EndpointSecurity.h>`) that replaced kauth/kexts. It streams kernel-sourced events to a user-space client. **AUTH** events let the client allow or deny an operation (exec, open, rename, unlink, mmap, ...). **NOTIFY** events are observe-only.

**Entitlement:** `com.apple.developer.endpoint-security.client` = `true`.
- This is a **restricted entitlement**. You request it from Apple at `https://developer.apple.com/contact/request/system-extension/`, and only a paid Developer Program member (the Account Holder, for orgs) can file the request. After approval you enable "Endpoint Security" under the App ID's Additional Capabilities and get a provisioning profile that permits it.
- Turnaround is anecdotally anywhere from days to 13+ months, and some requests never get an answer.
- Without the entitlement, `es_new_client()` returns `ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED`. Other failure codes: `ERR_NOT_PERMITTED` (no Full Disk Access / TCC approval), `ERR_NOT_PRIVILEGED` (not root).
- Runtime requirements: root, the entitlement in a profile-backed signature, and FDA ("Endpoint Security Extension" TCC). The supported packaging is a **System Extension** (`com.apple.system_extension.endpoint_security`) inside a `/Applications` app. A plain launchd daemon with the entitlement also works.
- **Dev-only bypass:** with SIP disabled and `amfi_get_out_of_my_way=1` in boot-args, ad-hoc signed binaries can claim restricted entitlements. That's fine for a lab VM but unacceptable for users.

**Key event types (es_event_type_t):**
- AUTH: `ES_EVENT_TYPE_AUTH_EXEC`, `AUTH_OPEN`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_MMAP`, `AUTH_MPROTECT`, `AUTH_CREATE`, `AUTH_TRUNCATE`, `AUTH_SIGNAL`, `AUTH_KEXTLOAD`, `AUTH_MOUNT`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`, `AUTH_LINK`, `AUTH_COPYFILE`, `AUTH_CLONE`
- NOTIFY: `NOTIFY_EXEC`, `NOTIFY_FORK`, `NOTIFY_EXIT`, `NOTIFY_CREATE`, `NOTIFY_WRITE`, `NOTIFY_CLOSE` (with `modified` flag, the best trigger for scan-on-write), `NOTIFY_RENAME`, `NOTIFY_UNLINK`, `NOTIFY_MMAP`, `NOTIFY_SIGNAL`, `NOTIFY_KEXTLOAD`, `NOTIFY_MOUNT`, `NOTIFY_SETEXTATTR`, `NOTIFY_CS_INVALIDATED`, `NOTIFY_REMOTE_THREAD_CREATE`, `NOTIFY_GET_TASK`, `NOTIFY_PTRACE`, `NOTIFY_PROC_SUSPEND_RESUME`
- Newer (macOS 13+): `NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE` (persistence), `NOTIFY_LW_SESSION_LOGIN/LOGOUT/LOCK/UNLOCK`, `NOTIFY_SCREENSHARING_ATTACH`, `NOTIFY_OPENSSH_LOGIN`, `NOTIFY_LOGIN_LOGIN`, `NOTIFY_XP_MALWARE_DETECTED` / `NOTIFY_XP_MALWARE_REMEDIATED` (XProtect detections), `NOTIFY_PROFILE_ADD`, `NOTIFY_SU`, `NOTIFY_SUDO`, `NOTIFY_AUTHENTICATION`, `NOTIFY_AUTHORIZATION_PETITION/JUDGEMENT`, `NOTIFY_OD_*` (directory services), `NOTIFY_XPC_CONNECT`, `NOTIFY_GATEKEEPER_USER_OVERRIDE`, `NOTIFY_TCC_MODIFY`
- AUTH responses must arrive before `msg->deadline` or the client gets killed. Use `es_mute_path`/`es_mute_process` and `es_respond_auth_result(..., ES_AUTH_RESULT_ALLOW, cache=true)` to keep things fast.

**`eslogger` (macOS 13+) [verified present]:** Apple's CLI that prints ES events as JSON (`sudo eslogger exec create rename close btm_launch_item_add xp_malware_detected`). It's Apple-signed, so it already **has** the entitlement. It needs root, and the *responsible* terminal or parent app needs Full Disk Access. **This is our legal path to ES NOTIFY data without an entitlement:** a root daemon spawns `eslogger` and parses its JSONL stdout. It has no AUTH events, so it can't block. Apple says eslogger isn't a stable API for products, so pin the JSON schema version (`"version"` field) and tolerate changes.

## 2. NetworkExtension content filter

- `NEFilterDataProvider` / `NEFilterPacketProvider` (content filter) and `NEDNSProxyProvider` / `NETransparentProxyProvider`, packaged as a System Extension.
- Entitlement: `com.apple.developer.networking.networkextension` with values `content-filter-provider-systemextension`, `dns-proxy-systemextension`, `app-proxy-provider-systemextension`. It's provisioning-profile-gated, so it needs a paid team ID. It isn't "request-only" like ES, but it still can't be ad-hoc signed.
- Configuration goes through `NEFilterManager.shared()` and needs user approval in System Settings.
- **Not achievable under our constraint.** Fallbacks: `nettop -L 1 -P`, `lsof -i -n -P`, `netstat -anv`, `/usr/bin/log` with `subsystem == "com.apple.network"`, `pf` anchors via `pfctl` (root) for blocking known-bad IPs, and `/etc/hosts` or a local DNS resolver for domain blocklists. The last two are invasive, so make them opt-in.

## 3. System Extensions

- `OSSystemExtensionRequest.activationRequest(forExtensionWithIdentifier:queue:)` from `SystemExtensions.framework`. The host app must live in `/Applications`, carry the `com.apple.developer.system-extension.install` entitlement, and be signed with Developer ID plus notarized. Users approve in *System Settings > General > Login Items & Extensions*.
- **Not achievable without a paid team.** Read-only inventory works: `systemextensionsctl list` [verified locally]. That's useful for listing third-party sysexts as a security-posture check.

## 4. File monitoring fallbacks (no entitlement needed)

| Mechanism | API | Pros | Cons |
|---|---|---|---|
| **FSEvents** | `FSEventStreamCreate` (CoreServices) with `kFSEventStreamCreateFlagFileEvents \| kFSEventStreamCreateFlagNoDefer \| kFSEventStreamCreateFlagUseCFTypes \| kFSEventStreamCreateFlagUseExtendedData`. Set it with `FSEventStreamSetDispatchQueue`. | Recursive, whole-tree, low cost, persistent event IDs (`sinceWhen`) let you catch up after a restart. Per-file flags: `ItemCreated`, `ItemModified`, `ItemRenamed`, `ItemXattrMod`, `ItemInodeMetaMod`. | Post-hoc (no blocking), coalesced, no PID. TCC-protected dirs (Desktop, Documents, Downloads, Mail, ...) need FDA or a user grant. |
| **DispatchSource** | `DispatchSource.makeFileSystemObjectSource(fileDescriptor:eventMask:[.write,.rename,.delete,.extend,.attrib],queue:)` on an `open(path, O_EVTONLY)` fd | Precise and immediate for a single file or directory. Good for watching `~/Library/LaunchAgents`, `/Library/LaunchDaemons`, `/etc/hosts`, browser extension dirs. | One fd per node, not recursive. |
| **kqueue** | `kqueue()`/`kevent()` with `EVFILT_VNODE` (`NOTE_WRITE\|NOTE_DELETE\|NOTE_RENAME\|NOTE_ATTRIB\|NOTE_EXTEND`), `EVFILT_PROC` (`NOTE_EXIT\|NOTE_FORK\|NOTE_EXEC`) | `EVFILT_PROC` tracks lifecycle of known PIDs. DispatchSource wraps it. | Same limits as above, and you can't discover *new* processes. |
| **Process polling** | `proc_listallpids`, `proc_pidpath`, `proc_pidinfo` (libproc), `sysctl KERN_PROC_ALL` | No privileges for own-user procs, and root sees everything. | Polling: short-lived processes get missed. |
| **`fs_usage`** | `sudo fs_usage -w -f filesys` / `-f exec` | Includes PID and process name for every FS syscall. | Root only, very noisy, uses the ktrace facility (only one consumer at a time). Diagnostics only, don't ship it. |

Recommendation: FSEvents for broad on-access-ish scanning of `~/Downloads`, `/Applications`, `~/Applications`, `/tmp`, `/Users/Shared`, and `~/Library`. DispatchSource on persistence directories for immediate alerts.

## 5. Unified log (`log stream` / `log show`) predicates

Note: in zsh `log` can be shadowed. Always call **`/usr/bin/log`** (bare `log show` failed here with "too many arguments") [verified locally]. Reading all logs needs admin; private data shows as `<private>` unless a profile enables it.

```sh
# XProtect / Gatekeeper / syspolicyd decisions   [verified: returns syspolicyd + com.apple.xprotect lines]
/usr/bin/log stream --style ndjson --predicate 'subsystem == "com.apple.xprotect" OR process == "syspolicyd" OR subsystem == "com.apple.syspolicy.exec"'
# XProtect Remediator scans and detections
/usr/bin/log stream --style ndjson --predicate 'subsystem == "com.apple.XProtectFramework" OR process BEGINSWITH "XProtectRemediator"'
# TCC grants/denials                              [verified: AUTHREQ_RESULT lines returned]
/usr/bin/log stream --style ndjson --predicate 'subsystem == "com.apple.TCC" AND eventMessage CONTAINS "AUTHREQ"'
# Background Task Management (new login items / daemons)
/usr/bin/log stream --style ndjson --predicate 'subsystem == "com.apple.backgroundtaskmanagement"'
# Gatekeeper user override / quarantine
/usr/bin/log stream --style ndjson --predicate 'process == "syspolicyd" AND eventMessage CONTAINS[c] "override"'
/usr/bin/log stream --style ndjson --predicate 'subsystem == "com.apple.launchservices" AND eventMessage CONTAINS[c] "quarantine"'
# Auth / sudo / ssh
/usr/bin/log stream --style ndjson --predicate 'process == "sudo" OR process == "sshd" OR subsystem == "com.apple.opendirectoryd"'
# Kernel code-signing violations (AMFI)
/usr/bin/log stream --style ndjson --predicate 'sender == "AppleMobileFileIntegrity" OR eventMessage CONTAINS "CODE SIGNING"'
```
Programmatic historical read: `OSLogStore(scope: .system)` (needs admin, so do it in the root helper) or `OSLogStore.local()`. Use `getEntries(at:matching: NSPredicate)`. For live tailing, spawn `/usr/bin/log stream --style ndjson` and parse it. There's no public live-streaming Swift API.

## 6. launchd / XPC

- User agent: `~/Library/LaunchAgents/com.bastionav.agent.plist` (runs as the user, has GUI/notification access). System daemon: `/Library/LaunchDaemons/com.bastionav.daemon.plist` (root, needs admin to install).
- Load with `launchctl bootstrap gui/$(id -u) <plist>` / `launchctl bootstrap system <plist>`. Inspect with `launchctl print system/<label>`, and kick with `launchctl kickstart -k`.
- IPC: `NSXPCConnection(machServiceName:options: .privileged)`, with the daemon advertising `MachServices` in its plist. Validate the peer with `NSXPCConnection.setCodeSigningRequirement(_:)` (macOS 13+), e.g. `anchor apple generic and identifier "com.bastionav.app" and certificate leaf[subject.OU] = "TEAMID"`. With ad-hoc signing there's no team ID, so pin the **cdhash** instead (`cdhash H"..."`) or use `identifier` plus a file-owner check. Low-level alternative: `xpc_connection_create_mach_service` + `xpc_connection_set_peer_code_signing_requirement`.

## 7. Full Disk Access & TCC

- FDA (`kTCCServiceSystemPolicyAllFiles`) **cannot be requested programmatically**. There's no prompt API. The app has to guide the user: `open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"` and have them add the binary or app.
- Detect FDA by trying to read a protected file, e.g. `FileManager.isReadableFile(atPath: "/Library/Application Support/com.apple.TCC/TCC.db")` or `~/Library/Safari/Bookmarks.plist`, and treat an `EPERM` as "no FDA".
- TCC records the grant by code identity (bundle ID plus designated requirement). **Ad-hoc signed binaries get a cdhash-based requirement, so every rebuild invalidates the grant.** Mitigation: sign with a stable self-signed certificate from the Keychain (`codesign -s "Bastion Local Signing"`). That gives a stable DR without a paid account.
- A launchd daemon gets FDA by adding its executable to the FDA list. Children inherit the "responsible process" (this matters for `eslogger`).
- Individual folder prompts (Desktop/Documents/Downloads) appear on first access, but only for bundled apps with usage strings in the Info.plist (`NSDesktopFolderUsageDescription`, etc.).
- Reading `TCC.db` (`sqlite3 ~/Library/Application\ Support/com.apple.TCC/TCC.db 'select service,client,auth_value from access'`) needs FDA. It's useful for auditing which apps hold Accessibility, Screen Recording, or Input Monitoring, which is a classic spyware signal.

## 8. Code signing, notarization, Gatekeeper checks

CLI [verified locally on Safari]:
```sh
codesign -dv --verbose=4 <path>          # Identifier, TeamIdentifier, Authority chain, flags (runtime, library-validation), cdhash
codesign --verify --deep --strict -v <path>
codesign -d --entitlements :- <path>     # dump entitlements (look for get-task-allow, disable-library-validation, allow-dyld-environment-variables)
spctl -a -vv -t exec <path>              # "accepted / source=Notarized Developer ID" or "rejected"
spctl -a -vv -t install <pkg>; spctl -a -vv -t open --context context:primary-signature <dmg>
stapler validate <path>                  # stapled notarization ticket present?
pkgutil --check-signature <pkg>
```
Swift (Security.framework, no entitlement needed):
```swift
var code: SecStaticCode?
SecStaticCodeCreateWithPath(url as CFURL, [], &code)
let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode)
let status = SecStaticCodeCheckValidityWithErrors(code!, flags, nil, &err)      // errSecCSUnsigned, errSecCSSignatureFailed ...
var info: CFDictionary?
SecCodeCopySigningInformation(code!, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation | kSecCSDynamicInformation), &info)
// keys: kSecCodeInfoIdentifier, kSecCodeInfoTeamIdentifier, kSecCodeInfoCertificates, kSecCodeInfoUnique (cdhash), kSecCodeInfoFlags, kSecCodeInfoEntitlementsDict
// Notarized check:
var req: SecRequirement?; SecRequirementCreateWithString("notarized" as CFString, [], &req)
SecStaticCodeCheckValidity(code!, [], req)   // errSecSuccess => notarized (online or stapled ticket)
// Apple platform binary:  "anchor apple"   Developer ID:  "anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
```
Running processes: `SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributePid: pid] as CFDictionary, [], &dynCode)` then `SecCodeCheckValidity`. Root is needed to inspect other users' processes.

Gatekeeper assessment API: `SecAssessmentCreate` is private-ish/deprecated. Shell out to `spctl` for that.

Heuristic scoring signals: unsigned, ad-hoc, not notarized, unexpected team ID, `get-task-allow` in release builds, `com.apple.security.cs.disable-library-validation`, `allow-unsigned-executable-memory`, and a signature whose identifier doesn't match the bundle ID.

## 9. Quarantine xattr [verified locally]

- Format: `com.apple.quarantine: FLAGS;HEXTIME;AGENT;UUID`, e.g. `0083;6ac74a3b;Safari;685C002A-...`. Flag `0x0040` means the user approved it in Gatekeeper; `0081`/`0083`/`0086` are typical. Files written by apps that aren't quarantine-aware have **no** xattr (seen here on a CLI-downloaded folder). That's a gap worth flagging: anything `curl`/`git`/`unzip` fetched bypasses Gatekeeper.
- Read: `xattr -p com.apple.quarantine <f>`. In Swift use `getxattr(path, "com.apple.quarantine", buf, len, 0, 0)` or `URLResourceValues.quarantineProperties` (`kLSQuarantineAgentNameKey`, `kLSQuarantineDataURLKey`, `kLSQuarantineOriginURLKey`, `kLSQuarantineTimeStampKey`).
- Download origin: `mdls -name kMDItemWhereFroms <f>` / xattr `com.apple.metadata:kMDItemWhereFroms` (binary plist).
- History DB: `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` (SQLite, table `LSQuarantineEvent`) holds the download history with origin URLs.
- **Bastion should add quarantine** to suspicious files it can't classify (`setxattr` or `URLResourceValues.quarantineProperties` write). That forces Gatekeeper evaluation on first launch.

## 10. XProtect, XProtect Remediator, and reading their YARA rules [verified locally]

**Two rule locations exist. The active one is `/var/protected/xprotect`** (since macOS 15, updated via iCloud/CloudKit by `XProtectUpdateService`). Unified log confirms: `Using XProtect rules location: /var/protected/xprotect/XProtect.bundle/Contents/Resources/XPScripts.yr`.

| Path | Contents |
|---|---|
| `/var/protected/xprotect/XProtect.bundle/Contents/Resources/` (**active**, world-readable) | `XProtect.yara` (512 rules), `XPScripts.yr` (script/AppleScript rules), `XProtect.plist` (legacy plugin blocklist), `XProtect.meta.plist` (min versions for plugins/extensions), `gk.db` (Gatekeeper SQLite: revoked cdhashes/team IDs), `LegacyEntitlementAllowlist.plist`, `AppProtectionPolicy.plist` |
| `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Resources/` (legacy, Software Update path) | Same file set. 18,388-line `XProtect.yara`, 512 rules, version 5371. |
| `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/` | 25 binaries: `XProtect` plus `XProtectRemediator*` scanners (Adload, BadGacha, BlueTop, Bundlore, CardboardCutout, ColdSnap, Conductor, Crapyrator, Dolittle, ...) |
| `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Resources/` | `bastion.sb` + `BastionMeta.plist` (behavioural rules), `com.apple.XProtect.{agent,daemon}.scan*.plist`, `libXProtectPayloads.dylib` |
| `/var/protected/xprotect/db` | Root-only XProtect behaviour DB |

- Version: `xprotect version` (no root) → `Version: 5371`. Admin commands: `sudo xprotect check`, `sudo xprotect update`.
- The YARA rules use `import "hash"` and private rules (`Macho`, `PE`, `Dylib`) and are standard YARA 4 syntax. **Plan:** at startup Bastion copies the active `XProtect.yara` into its own cache, keyed by version, and compiles it with libyara. Vendor YARA as a C target in SwiftPM (BSD-3 licence). The rules are Apple's copyrighted data, so read them in place and don't redistribute them inside the Bastion bundle.
- Remediator binaries are encrypted/obfuscated Swift. Don't depend on them; just surface their results from the unified log or `ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED` (via eslogger `xp_malware_detected`).

## 11. Background Task Management (BTM) [verified locally]

- macOS 13+ tracks every login item, launch agent/daemon, and SMAppService registration in `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm` (root-only, NSKeyedArchiver plist).
- `sfltool dumpbtm` (works as a user for its own UID records; use `sudo` for all) prints UUID, Name, Developer Name, Team Identifier, Type (`legacy daemon 0x10010`, `developer 0x20`, `agent`, `login item`...), Disposition (`enabled/allowed/notified`), Identifier, URL, Executable path, and parent bundle. **This is the best single persistence-enumeration source.** Parse its text output.
- Also enumerate directly: `/Library/LaunchDaemons`, `/Library/LaunchAgents`, `~/Library/LaunchAgents`, `/Library/StartupItems`, cron (`crontab -l`, `/usr/lib/cron/tabs`), `/etc/periodic`, login/logout hooks (`defaults read com.apple.loginwindow`), Safari/Chrome extensions, `~/.zshrc`-family, `/etc/pam.d`, authorization plugins (`/Library/Security/SecurityAgentPlugins`), `/Library/Extensions`, configuration profiles (`profiles list`).
- Live alerts: `/usr/bin/log stream --predicate 'subsystem == "com.apple.backgroundtaskmanagement"'`, or eslogger `btm_launch_item_add`.
- Don't run `sfltool resetbtm`. It's destructive.

## 12. Privileged helpers: SMAppService vs. raw launchd

- **`SMAppService`** (ServiceManagement, macOS 13+): `SMAppService.daemon(plistName: "com.bastionav.daemon.plist").register()`. The plist goes in `App.app/Contents/Library/LaunchDaemons/`, uses `BundleProgram` (relative path), and is approved by the user in Login Items. **It needs a properly signed app bundle.** With ad-hoc signing, registration generally fails or ends up `.requiresApproval` with an unstable identity. `SMAppService.agent(plistName:)` and `.mainApp` (login item) are friendlier. Status: `.status` → `.enabled/.requiresApproval/.notRegistered/.notFound`; `SMAppService.openSystemSettingsLoginItems()`.
- `SMJobBless` is deprecated, and it requires Developer ID anyway.
- **Workable without Xcode/paid account:** an installer script run with admin rights (`sudo`, or `osascript -e 'do shell script "..." with administrator privileges'`) that copies the daemon binary to `/Library/PrivilegedHelperTools/com.bastionav.daemon` (root:wheel 755), drops `/Library/LaunchDaemons/com.bastionav.daemon.plist` (root:wheel 644), then runs `launchctl bootstrap system ...`. BTM will show it as a "legacy daemon" and notify the user. That's expected and acceptable.

---

## 13. What Bastion can vs. cannot do (summary matrix)

| Capability | Proper Apple way | Without entitlements/Xcode |
|---|---|---|
| Block exec of malware pre-launch | ES `AUTH_EXEC` | **No.** Post-exec kill instead (`kill(pid, SIGKILL)` from the root daemon) after eslogger `exec` or polling |
| Real-time file events with PID | ES `NOTIFY_CLOSE/CREATE/RENAME` | **Yes via `eslogger`** (root + FDA), else FSEvents without PID |
| Network filtering | NEFilterDataProvider sysext | **No.** Monitoring only (nettop/lsof), optional `pfctl`/hosts blocklist |
| On-demand file scan (YARA + hash + signing) | n/a | **Yes**: libyara + XProtect rules + CryptoKit SHA-256 + SecStaticCode |
| Persistence audit | ES BTM events | **Yes**: `sfltool dumpbtm`, plist dirs, DispatchSource watchers, BTM log stream |
| Quarantine / Gatekeeper posture | n/a | **Yes**: getxattr/setxattr, `spctl`, `codesign`, `stapler` |
| Quarantine (isolate) a file | n/a | **Yes**: move to root-owned `/Library/Application Support/BastionAV/Quarantine` (0700), `chmod 000`, strip exec bit, record metadata |
| Read XProtect detections | ES `NOTIFY_XP_MALWARE_*` | **Yes** via eslogger `xp_malware_detected` or the unified log |
| TCC privacy audit | n/a | **Yes** with FDA: read TCC.db |
| Kernel self-protection / tamper resistance | ES + sysext | **No.** Rely on root ownership; the user can always `launchctl bootout` |

---

## Recommended architecture given no-Xcode/no-entitlement constraint

**Build:** a single SwiftPM workspace (`swift build -c release`), three executables, plus a C target for libyara.

```
Package.swift
  targets:
    CYara          (C, vendored libyara 4.x, compiled without OpenSSL/magic or with CommonCrypto shim)
    BastionCore    (library: scanner, rules loader, signing checks, persistence enumerator, quarantine store)
    bastiond       (root LaunchDaemon: eslogger/FSEvents ingest, scanning, kill/quarantine, XPC server)
    bastion-agent  (per-user LaunchAgent: notifications, FDA onboarding, menu-bar UI via AppKit w/o Xcode)
    bastion        (CLI: scan <path>, status, persistence, quarantine list/restore)
```

**Signing (no paid account):** create a self-signed code-signing certificate once (Keychain Access › Certificate Assistant, or `security` + `openssl`). Then run `codesign --force --options runtime --timestamp=none -s "Bastion Local Signing" --identifier com.bastionav.daemon .build/release/bastiond`. A stable identity keeps FDA/TCC grants across rebuilds. You can't notarize, so ship from source or via a `.pkg` built with `pkgbuild`/`productbuild`. Users either run the installer script themselves or remove quarantine from the downloaded installer. Document this.

**Install (privileged, one-time):**
```sh
sudo install -o root -g wheel -m 755 bastiond /Library/PrivilegedHelperTools/com.bastionav.daemon
sudo install -o root -g wheel -m 644 com.bastionav.daemon.plist /Library/LaunchDaemons/
sudo launchctl bootstrap system /Library/LaunchDaemons/com.bastionav.daemon.plist
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.bastionav.agent.plist
open "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"   # user adds /Library/PrivilegedHelperTools/com.bastionav.daemon
```
Daemon plist: `Label`, `ProgramArguments`, `RunAtLoad=true`, `KeepAlive=true`, `MachServices={com.bastionav.daemon.xpc=true}`, `ProcessType=Adaptive`, `LowPriorityIO=true` for scan workers.

**Real-time telemetry (in `bastiond`, preference order):**
1. **`/usr/bin/eslogger`** child process (`Process()` with `exec create rename close btm_launch_item_add xp_malware_detected mmap signal`), reading JSONL from a `Pipe`. Decode with `JSONDecoder`, guarded by the schema `version` field. Needs root and FDA on `bastiond` (the responsible process). This gives PIDs, signing info (`signing_id`, `team_id`, `cdhash`, `is_platform_binary`), and full paths. Mute Apple platform binaries in our own filter.
2. **FSEvents** fallback (`FSEventStreamCreate` + `kFSEventStreamCreateFlagFileEvents`, `FSEventStreamSetDispatchQueue`) on `/Applications`, `/Users/*/Downloads`, `/Users/*/Applications`, `/Users/Shared`, `/tmp`, `/private/var/folders`, `/Library/Launch*`, `/Users/*/Library/LaunchAgents`. Persist `FSEventStreamGetLatestEventID` to resume after restarts.
3. **DispatchSource.makeFileSystemObjectSource** on persistence directories for instant alerts.
4. **Process sweep** every few seconds: `proc_listallpids` + `proc_pidpath`, then `SecCodeCopyGuestWithAttributes` (pid) + `SecCodeCopySigningInformation`. This catches anything eslogger missed.
5. **Unified log tail:** `Process("/usr/bin/log", ["stream","--style","ndjson","--predicate", P])` with P = `subsystem == "com.apple.xprotect" OR subsystem == "com.apple.XProtectFramework" OR subsystem == "com.apple.backgroundtaskmanagement" OR (subsystem == "com.apple.TCC" AND eventMessage CONTAINS "AUTHREQ") OR process == "syspolicyd"`.

**Scan pipeline (BastionCore):**
1. Gate by type (Mach-O magic / script shebang / archive / dmg / pkg) and size.
2. SHA-256 via `CryptoKit.SHA256` (streamed with `FileHandle.read(upToCount:)`), checked against the local hash DB (SQLite via `import SQLite3`). Also check against cdhash/team revocations from XProtect's `gk.db` (open it read-only).
3. YARA via libyara with three rule sets: (a) the active Apple rules from `/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara` + `XPScripts.yr` (fall back to the `/Library/Apple/...` copy, check `xprotect version` to detect updates, and re-compile when it changes), (b) Bastion's own rules, (c) optional community rules.
4. Code-signing verdict: `SecStaticCodeCreateWithPath` → `SecStaticCodeCheckValidityWithErrors(kSecCSStrictValidate|kSecCSCheckAllArchitectures|kSecCSCheckNestedCode)`, plus the `notarized` requirement, plus entitlement red flags. `spctl -a -vv -t exec` is the second opinion for apps.
5. Provenance: the `com.apple.quarantine` xattr (`getxattr`) plus `kMDItemWhereFroms`. No quarantine on an executable in Downloads raises the score.
6. Verdict actions (root): `kill(pid, SIGKILL)` if running. Move the file to `/Library/Application Support/BastionAV/Quarantine/<uuid>` (0700 root), strip the exec bit, and keep a JSON sidecar (orig path, hash, owner, mode, xattrs). Notify the user via the agent over XPC.

**IPC:** `NSXPCListener(machServiceName: "com.bastionav.daemon.xpc")` in the daemon. In `listener(_:shouldAcceptNewConnection:)` call `newConnection.setCodeSigningRequirement("identifier \"com.bastionav.agent\" and certificate leaf = H\"<sha1 of self-signed cert>\"")`. Pinning the self-signed cert hash works without a team ID.

**Agent/UI:** an AppKit `NSStatusItem` menu-bar app built with plain `swiftc`/SwiftPM (no storyboards; SwiftUI `MenuBarExtra` also compiles from CLT). Notifications via `UNUserNotificationCenter` require a proper `.app` bundle with Info.plist and a `CFBundleIdentifier`. Assemble `BastionAV.app` manually (`Contents/MacOS`, `Contents/Info.plist`), then codesign it. FDA onboarding: test-read the protected file and deep-link to the Privacy_AllFiles pane.

**Persistence/posture audit (CLI `bastion audit`):** `sfltool dumpbtm` (sudo), LaunchAgents/Daemons plist parse (`PropertyListSerialization`), each target's `codesign`/`spctl` verdict, `systemextensionsctl list`, `profiles list`, `csrutil status`, `spctl --status`, `fdesetup status`, `xprotect version`, `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`, TCC.db audit (with FDA).

**Upgrade path (once a paid Developer ID team exists):** move the ingest layer from eslogger to a native `es_new_client` System Extension (same event types, plus AUTH_EXEC/AUTH_OPEN blocking), add an `NEFilterDataProvider` for network blocking, swap the install script for `SMAppService.daemon` and the self-signed cert for Developer ID, and notarize with `xcrun notarytool` (also available in CLT). Keep `BastionCore` API-agnostic so only the ingest adapter changes.

---

### Sources
- [Apple: com.apple.developer.endpoint-security.client](https://developer.apple.com/documentation/bundleresources/entitlements/com.apple.developer.endpoint-security.client)
- [Apple Forums: Request ES entitlement](https://developer.apple.com/forums/thread/736042), [thread 133494](https://developer.apple.com/forums/thread/133494), [thread 653877](https://developer.apple.com/forums/thread/653877), [ES & paid account](https://developer.apple.com/forums/thread/741950)
- [seafoodfry: entitlements guide](https://seafoodfry.github.io/osx/2022/02/26/entitlements)
- [Eclectic Light: How XProtect is updated (2026)](https://eclecticlight.co/2026/08/20/how-xprotect-is-updated/), [Explainer: XProtect data updates](https://eclecticlight.co/2025/10/11/explainer-how-is-xprotects-data-updated/), [XProtect in Sequoia](https://eclecticlight.co/2024/10/10/a-simple-guide-to-how-xprotect-installs-and-updates-in-sequoia/), [What to expect of XProtects](https://eclecticlight.co/2025/05/23/what-to-expect-of-xprotects/)
- Local SDK headers: `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/EndpointSecurity/ESTypes.h` (authoritative event enum for this SDK)
