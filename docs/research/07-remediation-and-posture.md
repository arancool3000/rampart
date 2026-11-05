# 07 — Remediation, Quarantine and Security Posture

Status: research notes for Bastion (Swift, macOS 13+). Commands below marked **[tested]** were run read-only on the dev machine (macOS 27.0.1, build 26A434, Apple silicon, FileVault on, SIP on). Everything else comes from documentation or community sources (listed at the end) and still needs checking on hardware.

---

## 1. Design principles

1. **Never destroy on first action.** Every remediation step is reversible by default. Quarantine first, delete later: auto-purge after N days, or on explicit user action.
2. **Transactions.** A "remediation plan" is an ordered list of actions (kill, unload, disable, quarantine file, edit plist, remove profile, ...). It runs under a single journal entry so it can be rolled back as a unit.
3. **Privileged work lives in one small helper.** The UI app stays unprivileged. A privileged helper (`SMAppService.daemon`, registered via BTM) runs the actions over XPC, checks the caller's code signature (`SecCodeCheckValidity` plus audit token / team ID), and accepts only typed actions, never raw shell strings.
4. **Prefer APIs to shelling out.** Use `launchctl`, `profiles`, `sfltool` etc. only where no API exists. Always use absolute paths (`/bin/launchctl`) and argument arrays (`Process`), never `sh -c`.
5. **Scope safety.** Hard-deny list: anything on the SSV or SIP-protected (`/System`, `/usr` except `/usr/local`, `/bin`, `/sbin`, `/Library/Apple`), Apple-signed binaries (`SecStaticCode` + `anchor apple`), Bastion itself, and the user's home root and top-level folders.

---

## 2. Quarantine design

### 2.1 Location and protection
- Store: `/Library/Application Support/Bastion/Quarantine/` (system, for root-owned or multi-user items) plus a per-user vault only when the helper is unavailable.
- Directory mode `0700 root:wheel`. Add the `UF_HIDDEN` flag. Optionally exclude it from Spotlight with a `.metadata_never_index` file, and from Time Machine with `tmutil addexclusion` / `CSBackupSetItemExcluded`. Backing up malware is pointless and it would re-trigger other AV products.
- Self-protection: with an ES client, deny `ES_EVENT_TYPE_AUTH_OPEN/UNLINK/RENAME` on the vault for every process except the helper (see doc 03/ES research).

### 2.2 Neutralising the sample
1. **Kill** any process whose executable is the file (check `proc_pidpath` against the target's vnode/inode, not only the path).
2. **Strip execute bits**: `chmod 0400` and `chflags nouchg,noschg` (where permitted) before moving.
3. **Strip xattrs that could re-trigger**: keep a copy of `com.apple.quarantine`, `com.apple.provenance` and `com.apple.macl` in metadata, then remove them from the sample.
4. **Encode**: don't store raw bytes. Options:
   - XOR with a random 1-byte or 16-byte key. This is what many AV products do; it's enough to defeat re-detection by other scanners and Spotlight importers. Cheap.
   - **Recommended:** AES-GCM via CryptoKit, using a per-item random key wrapped by a vault key kept in the System keychain (or a file readable only by root). This gives integrity (the GCM tag) so restore can detect tampering. Cost is negligible.
   - Compress first (`Compression` framework, LZFSE) to save space.
5. **Rename** to an opaque UUID: `<uuid>.bqf` (Bastion Quarantine File). Bundles (`.app`, `.pkg` dirs, `.kext`, `.plugin`) get archived as one unit first, using `AppleArchive` (preserves xattrs, ACLs, symlinks) or `ditto -c -k --sequesterRsrc --keepParent`.
6. **Move atomically**: `rename(2)` if on the same volume, otherwise copy, fsync, verify the hash, then unlink the original.

### 2.3 Metadata record (SQLite or one JSON sidecar per item, `<uuid>.json`)
```
id, created_at, detection_name, engine (yara/sig/heuristic/xpr), severity,
original_path, original_volume_uuid, inode, is_bundle,
sha256 (plaintext), size, owner uid/gid, mode, flags, acl (text form),
xattrs { name: base64 }, codesign { team_id, signing_id, cdhash, notarized },
related_actions [ action ids in same remediation transaction ],
crypto { alg: "AES-GCM", wrapped_key, nonce } | { alg: "xor", key },
status (quarantined | restored | purged), restored_at, purge_after
```
Sign the records with an HMAC (vault key) so a tampered record can't be used to restore a file to an attacker-chosen path.

### 2.4 Restore
- Check that the HMAC and GCM tag are valid, the original parent dir exists (recreate it with the recorded owner and mode if not), and no file now sits at the destination. If one does, offer "restore as `name (restored)`".
- Re-apply mode, owner, ACL and xattrs. **Do not** re-apply `com.apple.quarantine` unless the user chooses to. Gatekeeper will re-check either way.
- Add the restored hash to a per-user **allow-list** so it isn't immediately re-quarantined.
- Restoring a file whose related actions include an unloaded LaunchAgent should prompt: "Also re-enable its launch job?" (see Rollback, §12).

### 2.5 Purge
- Default retention: 30 days, configurable. Purge = unlink the `.bqf` and the sidecar, and mark the DB row `purged`. Keep the row for history.

---

## 3. Killing processes and process trees

- Enumerate with `proc_listallpids` / `proc_pidinfo(PROC_PIDTBSDINFO)`, which gives `pbi_ppid`, `pbi_pgid` and the start time. Build the parent-to-child tree in memory. **Don't** rely on ppid alone: orphans get reparented to launchd (pid 1). Use the **responsible pid** (`responsibility_get_pid_responsible_for_pid`, a private SPI, or ES `responsible_audit_token` on 13+) and the process group.
- Order: `SIGSTOP` the whole tree first, so nothing can respawn or fork during enumeration. Then `SIGKILL` leaf-to-root. Re-scan after 500 ms and repeat until stable (3 rounds max).
- **Kill launchd jobs via launchd, not signals.** If the process is owned by a launchd job (it has `KeepAlive`), killing it just makes launchd respawn it. Bootout the job first (§4), then kill the stragglers.
- Validate pid reuse: capture `(pid, p_starttime)` or the audit token and re-check it before signalling.
- Never signal pid 0/1, Apple platform binaries (`csops` `CS_PLATFORM_BINARY`), or Bastion's own processes.

---

## 4. launchd jobs

Locations to scan:
`~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons`, plus (read-only, SIP) `/System/Library/Launch*`. Also check app-bundled jobs in `Contents/Library/LaunchAgents|LaunchDaemons|LoginItems` registered through `SMAppService`, which appear in BTM, not in those folders.

Commands (modern domain-target syntax; `load`/`unload` are legacy):
```
# inspect
launchctl print gui/$UID/<label>
launchctl print system/<label>
launchctl print-disabled gui/$UID            # [tested] works unprivileged
launchctl print-disabled system              # [tested]

# stop + unload
launchctl bootout gui/$UID/<label>           # user agent (run as that user or root)
launchctl bootout gui/$UID <plistpath>
sudo launchctl bootout system/<label>        # daemon

# prevent re-load (persistent override, survives reboot, stored in
# /private/var/db/com.apple.xpc.launchd/disabled.*.plist)
launchctl disable gui/$UID/<label>
sudo launchctl disable system/<label>

# rollback
launchctl enable gui/$UID/<label>
launchctl bootstrap gui/$UID <plistpath>
```
Plan for one launch job: `bootout`, then `disable`, then quarantine the plist, then quarantine the `ProgramArguments[0]`/`Program` target (and its bundle). Record the label, the domain and the original plist bytes for rollback. For every logged-in user's GUI domain, enumerate `gui/<uid>` per console user (`SCDynamicStoreCopyConsoleUser`, or `who`). For non-GUI sessions, use `user/<uid>`.

Gotchas:
- `bootout` of a job that's not loaded returns error 3/113. Treat that as success.
- Adload often uses randomized labels (`com.<random>.plist`) pointing to binaries in `~/Library/Application Support/.<random>/` or `/var/root/.<random>`. Match on behaviour (hidden dir plus an unsigned binary plus a `StartInterval`), not on names.

---

## 5. Login items and Background Task Management (BTM)

- macOS 13+ tracks all login items, launch agents/daemons and `SMAppService` items in the BTM database: `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm` (root-only, NSKeyedArchiver plist).
- **Read:** `sudo sfltool dumpbtm`. It gives a text dump per uid: UUID, name, type (legacy agent, daemon, login item, app), disposition (enabled/allowed/notified), identifier, URL, developer name/team ID, and the parent. `sfltool` usage string **[tested]**: `csinfo|dumpbtm|archive|clear|resetbtm|resetlist|list|list-info`.
- Parse the BTM file directly from the helper (NSKeyedUnarchiver of `Storage`/`ItemRecord`). That's more structured than scraping `dumpbtm`, but the format is private and changes between releases. Keep a `dumpbtm` text parser as a fallback.
- **ES events** (13+): `ES_EVENT_TYPE_NOTIFY_BTM_LAUNCH_ITEM_ADD/REMOVE` give live persistence monitoring (see the ES doc).
- **Remove:**
  - Legacy plist-backed items: remove the underlying plist or binary (§4). BTM marks the record stale and drops it.
  - Legacy "Open at Login" apps (old `LSSharedFileList` items): no public removal API since 13. Use AppleScript `tell application "System Events" to delete login item "<name>"`. This needs an Automation TCC grant for System Events. Ask only when it's actually needed.
  - `SMAppService`-registered items: only the owning app can `unregister()`. Bastion can remove or quarantine the app bundle; BTM then drops the item on the next evaluation.
  - **`sfltool resetbtm` is a nuclear option.** It wipes all third-party items and makes the user re-approve them. Never run it automatically. Offer it only as a manual "reset background items" with a warning.
- **MDM-managed items** (`com.apple.servicemanagement` payload) can't be removed by the user. Report them as "managed by your organization".

---

## 6. Configuration profiles

- **Read:** `profiles list` (user) **[tested]**: on the dev machine it shows one user profile `com.apple.ManagedSettings.macOS.<UUID>` (Screen Time / ManagedSettings, benign). `sudo profiles list -all`, `sudo profiles show -type configuration -output stdout-xml`, or `profiles -P -o stdout-xml`.
- Raw store (root only): `/private/var/db/ConfigurationProfiles/Store/`.
- **Install is blocked from the CLI since Big Sur** (it needs user approval in System Settings or MDM). **Removal from the CLI still works** for manually installed (non-MDM, non-"removal disallowed") profiles: `sudo profiles remove -identifier <PayloadIdentifier>` (older form: `sudo profiles -R -p <id>`). Verify against `profiles help` on each OS release.
- **Can't remove:** MDM-enrolled profiles, profiles with `PayloadRemovalDisallowed` set, or ones with a removal password. Report these and link to System Settings > General > Device Management.
- **Adware patterns:** profiles whose payloads are `com.apple.Safari`, `com.google.Chrome` (`HomepageLocation`, `DefaultSearchProviderSearchURL`, `ExtensionInstallForcelist`), or `com.apple.ManagedClient.preferences` forcing a homepage or search engine, or that pin a proxy or DNS (`com.apple.dnsSettings.managed`, Web Content Filter). Flag profiles with an unknown or unsigned issuer and a recent install date.
- **Rollback:** before removal, export the profile XML (`profiles show ... -output`). The user can re-install it manually by double-clicking, since a CLI install isn't possible. Document this limitation in the UI.
- Managed Chrome/Edge/Brave policies can also live as plain plists: `/Library/Managed Preferences/<user>/com.google.Chrome.plist` (written by mobileconfig) and `/Library/Preferences/com.google.Chrome.plist`. Policy hijackers sometimes write the latter directly. Check both, plus `chrome://policy` equivalents.

---

## 7. Browser cleanup

General rule: **close the browser first** (`NSRunningApplication.terminate`, then force after a timeout, with user consent). Browsers rewrite their prefs on exit and will undo changes made while they run. Back up every file before editing (journal it).

| Browser | Profile root | Extensions | Search/homepage |
|---|---|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/<Default|Profile N>/` | `Extensions/<id>/<ver>/manifest.json` **[tested: dir readable without FDA]**, registration in `Preferences` → `extensions.settings` and `Secure Preferences` | `Preferences` → `default_search_provider_data`, `homepage`, `session.startup_urls`, `session.restore_on_startup`; `Web Data` (SQLite) table `keywords` |
| Brave | `~/Library/Application Support/BraveSoftware/Brave-Browser/<profile>/` | same as Chrome | same as Chrome |
| Edge | `~/Library/Application Support/Microsoft Edge/<profile>/` | same | same |
| Arc | `~/Library/Application Support/Arc/User Data/<profile>/` (Chromium layout); Arc-specific state in `~/Library/Application Support/Arc/StorableSidebar.json` | same as Chrome | same as Chrome |
| Vivaldi/Opera | `.../Vivaldi/`, `.../com.operasoftware.Opera/` | Chromium layout | Chromium layout |
| Firefox | `~/Library/Application Support/Firefox/Profiles/<x>.default-release/` (list in `profiles.ini`) | `extensions.json`, `extensions/*.xpi`; policies in `/Applications/Firefox.app/Contents/Resources/distribution/policies.json` (abused by hijackers) | `prefs.js`/`user.js` (`browser.startup.homepage`), `search.json.mozlz4` (mozLZ4: magic `mozLz40\0` + LZ4 block) |
| Safari | `~/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist` (sandboxed; **needs FDA**: `~/Library/Safari` gave "Operation not permitted" **[tested]**) | Safari extensions are App Extensions inside apps: `pluginkit -mAvvv -p com.apple.Safari.web-extension` and `-p com.apple.Safari.extension` (legacy). Remove = quarantine the host `.app`. Legacy `.safariextz` are gone since Safari 13 | `HomePage`, `SearchProviderShortName` (only Apple-approved engines are allowed, so hijacks happen through extensions or profiles) |

Chromium specifics:
- `Secure Preferences` and `Preferences` are protected by HMAC (`protection.macs`) seeded per machine. Editing them directly makes Chrome flag "settings were modified by another program" and reset them, which actually helps us. A **safer approach**: remove the extension directory and its entries from `extensions.settings`, and let Chrome reconcile. Or reset the search provider to default by deleting `default_search_provider_data` and the bad `keywords` row in `Web Data`.
- Policy-installed extensions (`ExtensionInstallForcelist`) reinstall themselves until the policy source (profile or plist, §6) is removed. Always fix the policy first.
- Detection heuristics: extension IDs not in the Web Store (`update_url` not `clients2.google.com`), `from_webstore: false`, broad permissions (`<all_urls>`, `webRequest`, `management`, `proxy`, `nativeMessaging`), a search URL pointing to known redirector domains (e.g. `search.*.com/?q=` chains, Yahoo `/yhs/search?type=`).
- Native messaging hosts: `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/*.json`, `/Library/Google/Chrome/NativeMessagingHosts/`, and the Mozilla equivalent `~/Library/Application Support/Mozilla/NativeMessagingHosts/`. Adware uses these for persistence.

---

## 8. Cron, periodic and other persistence leftovers

- `crontab -l` per user **[tested: "no crontab for arankeyhan"]**. Raw: `/usr/lib/cron/tabs/<user>` (root-only, **[tested: Permission denied unprivileged]**; also needs FDA). `/etc/crontab` (not present by default).
- Remove a single line: read the tabs file as root, filter, write via `crontab -u <user> -` (atomic). Keep the original for rollback.
- Also check: `/etc/periodic/{daily,weekly,monthly}`, `/etc/periodic.conf`, `at` jobs (`/usr/lib/cron/jobs`, `atq`), emond (removed in 13+, but check `/etc/emond.d/rules` on older systems), `/Library/StartupItems`, login/logout hooks (`defaults read com.apple.loginwindow LoginHook`), shell rc files (`~/.zshrc`, `~/.zprofile`, `~/.bash_profile`, `/etc/zshenv`), `DYLD_INSERT_LIBRARIES` in launchd plists, `/etc/hosts`, DNS overrides (`scutil --dns`), proxy settings (`scutil --proxy`, `networksetup -getwebproxy`), Authorization plugins (`/Library/Security/SecurityAgentPlugins`), Directory Services plugins, `/Library/Audio/Plug-Ins/HAL`, Spotlight importers, QuickLook plugins, Finder Sync extensions, Dock tile plugins, and folder actions.

---

## 9. Family-specific leftovers (Adload / Pirrit / Shlayer / Bundlore)

Apple ships remediators for these (`XProtectRemediatorAdload`, `...Pirrit`, `...Bundlore`, `...Genieo`, `...Trovi` etc. **[tested: 24 remediators present in `/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/`, XProtect bundle 5371]**). Bastion should complement them, not duplicate them, and surface their results (§11).

- **Shlayer / Bundlore** (dropper, installs adware): DMG or `.command` script, base64 + openssl `enc -aes-256-cbc` payload decoded into `/tmp`, then `xattr -c` to remove quarantine. Leftovers: `/tmp/<random>`, `~/Library/Application Support/<random>/`, browser extensions, Safari app extensions with nonsense names, LaunchAgents with `StartInterval`. Remediation means removing the installed adware (Adload/Pirrit/etc.); the dropper itself is usually transient.
- **Adload**: LaunchAgent/LaunchDaemon `com.<word>.<word>` (or random) that runs a Go or Mach-O binary from `~/Library/Application Support/.<random>/` or `/Library/Application Support/.<random>/`. Often also `/var/root/.<random>`. Proxy via `/Library/Application Support/<name>/<name>` with `--proxy`. It installs a system proxy or DNS profile and a Safari app extension. Unsigned or ad-hoc signed, frequently packed. Full cleanup = bootout + disable + quarantine the plist, binary, hidden dir and app extension host, remove the proxy/DNS profile, and reset browser search.
- **Pirrit**: LaunchAgent pointing to a binary in `~/Library/<random>/` or `/Library/<random>/`, with a hidden `.app` (often agent-only, `LSUIElement`). Uses `osascript` to inject JS into Safari/Chrome, and a man-in-the-browser proxy (`mitmproxy`-like) with a root CA installed in the System keychain. **Check the keychain for unexpected trusted root CAs**: `security find-certificate -a -p /Library/Keychains/System.keychain` plus `security dump-trust-settings -d`. Remove with `security remove-trusted-cert -d` (admin) after a backup export.
- **Genieo/Mughthesec/Crossrider/Trovi/MacKeeper/"Search Baron"**: Safari/Chrome extensions plus homepage, search-engine and profile changes. Same browser cleanup as §7.
- Rule: always also check **codesign team IDs** across all artifacts. A family often reuses one team ID (Apple revokes them, but older installs keep working). Group the artifacts of one team ID into a single remediation transaction.

---

## 10. SIP, SSV and protected locations

- `csrutil status` **[tested: "enabled"]**. SIP blocks writes to `/System`, `/usr` (except `/usr/local`), `/bin`, `/sbin`, `/var` subtrees with the `restricted` flag, Apple apps in `/Applications`, and `/Library/Apple`. The SSV makes the system volume read-only and sealed, so malware **can't** persist there unless SIP is disabled. If SIP is off, raise posture severity to critical.
- Check `ls -lO <path>` for the `restricted`/`sunlnk` flags before attempting an action. `rootless.conf`: `/System/Library/Sandbox/rootless.conf`.
- TCC-protected user data (Mail, Messages, Safari, Desktop/Documents/Downloads, iCloud Drive, Containers of other apps, `~/Library/Application Support/com.apple.TCC`) needs **Full Disk Access** for scanning and remediation.
- App containers (`~/Library/Containers/<id>`, `~/Library/Group Containers/`) on 14+ also have **App Data protection** ("Bastion would like to access data from other apps"). This is separate from FDA, though FDA covers it.
- `/Applications/<App>.app` bundles signed by third parties are "app-management protected" on 13+. Modifying or deleting one needs the **App Management** TCC grant (`kTCCServiceSystemPolicyAppBundles`), or FDA. Without it, deletion fails with EPERM even as root. Ask for it when the first app-bundle quarantine is needed.
- If a malicious file sits in a SIP-protected or immutable location: report it, never try to work around SIP, and tell the user to boot to Recovery (it's almost always a false positive).

---

## 11. Secure delete on APFS

- **There is no reliable secure overwrite on APFS/SSD.** APFS is copy-on-write and keeps snapshots (local Time Machine snapshots: `tmutil listlocalsnapshots /`). The SSD controller remaps blocks with wear levelling. `srm` was removed in 10.12 and Finder "Secure Empty Trash" in 10.11. `diskutil secureErase` doesn't work on SSDs per Apple.
- **What actually works:** encryption. On an encrypted volume (FileVault, or every Apple-silicon/T2 volume, which is hardware-encrypted at rest), deleting a file destroys the access to its per-file key (on APFS with per-file encryption on iOS-style data protection) and TRIM eventually frees the blocks. For quarantine we hold the sample **encrypted under our own key**, so crypto-shredding is "delete the wrapped key, then unlink". That's the honest "secure purge".
- UI wording: "Permanently delete" (not "secure shred"). Optionally offer "also delete local snapshots that contain this file" via `tmutil deletelocalsnapshots <date>`, with a warning that it removes all data in that snapshot.
- `diskutil apfs list` **[tested]** shows `FileVault: Yes (Unlocked)` on the data volume, which is useful for posture.

---

## 12. XProtect Remediator reporting (unified log)

- XPR runs periodically (from `XProtect.app`, launched by `com.apple.XProtect.daemon.scan`; since macOS 15 the `xprotect` CLI also exists). It reports scans and remediations to the unified log:
```
log show --last 24h --style ndjson \
  --predicate 'subsystem == "com.apple.XProtectFramework.PluginAPI" && category == "XPEvent.structured"'
```
  Each entry is a JSON payload (in `eventMessage`) that includes the remediator/plugin name (e.g. `XProtectRemediatorAdload`), the caller, a status code and message (`NoThreatsFound`, `ThreatsRemediated`, `FailedToRemediate`, ...), the threat name and the affected file paths. The subsystem-only filter is noisy; the category narrows it to scan results. Field names aren't documented by Apple, so parse defensively and version-gate.
- **[tested]** On the dev machine both predicates returned 0 entries for the last 7 days when run unprivileged. Either nothing was written or the read needs admin (`log show` of private data) or `log` collect privileges. Retry from the root helper, and use `log stream` for live capture. Also check that XPR scans actually ran (`launchctl print system/com.apple.XProtect.daemon.scan`).
- **Better on 13+:** Endpoint Security `ES_EVENT_TYPE_NOTIFY_XP_MALWARE_DETECTED` and `ES_EVENT_TYPE_NOTIFY_XP_MALWARE_REMEDIATED` (the struct includes `signature_version`, `malware_identifier`, `incident_identifier`, `detected_path`, plus remediation action/result). Use ES as the primary source and the log as backfill and history (`OSLogStore(scope: .system)` from the helper; requires root).
- The XProtect version for posture is in `/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist` `CFBundleShortVersionString` **[tested: 5371]**. Also check `XProtect.app` (XPR) and `/Library/Apple/System/Library/CoreServices/MRTConfigData.bundle` (older). Compare against `softwareupdate --history` and the last-update time. Flag if older than ~30 days.

---

## 13. Full Disk Access (FDA) and other TCC grants

- **Detection without prompting:** try `open(O_RDONLY)` on a canary file that only FDA can read: `~/Library/Application Support/com.apple.TCC/TCC.db` **[tested: fails without FDA]** or `~/Library/Safari/Bookmarks.plist` **[tested: EPERM]**. Run it from both the app and the helper. Each binary needs its own grant: an ES client system extension or daemon needs FDA separately from the GUI app, and an ES client's `es_new_client` fails with `ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED` without it.
- **Request flow:** there's no API to prompt for FDA. Show an onboarding card that explains why, with a screenshot, then deep-link with `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles` (works in System Settings 13+; the newer `x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles` form also exists). Mention dragging the app or the "+" button. Poll the canary every 2 s and continue automatically once it passes. **Don't** nag; degrade gracefully with a banner listing what's skipped (Mail, Safari, Messages, other users, cron tabs, TCC review, ...).
- After the grant, the process may need to relaunch for some protected locations. Offer "Restart Bastion".
- Other grants, requested only when needed: App Management (§10), Automation → System Events (legacy login items), Accessibility (not needed, avoid).

---

## 14. Rollback / undo design

- **Journal** (SQLite, WAL, in `/Library/Application Support/Bastion/journal.db`, root-only): one `transaction` row per remediation run, with `action` rows `{seq, type, target, before_state blob, after_state, status, error}`.
- Each action type implements `apply()`, `verify()` and `revert()`:
  | Action | before_state captured | revert |
  |---|---|---|
  | QuarantineFile | vault id | restore (§2.4) |
  | BootoutJob | label, domain, plist bytes, was_loaded | `bootstrap` |
  | DisableJob | was_disabled | `enable` |
  | KillProcess | — | not revertible (mark as such; UI says "process will start next login if restored") |
  | EditPlist / EditJSON / EditSQLite row | full original file copy (in vault, unencrypted) | atomic replace, only if the current hash equals after_state hash (otherwise ask) |
  | RemoveProfile | exported XML | manual reinstall (open the `.mobileconfig` for the user) |
  | RemoveCronLine | original tab | `crontab -u` restore |
  | RemoveTrustedCert | exported PEM + trust settings | `security add-trusted-cert` |
- Run transactions as **plan → preview (dry-run diff shown to the user) → apply → verify → re-scan**. If any step fails, offer "roll back completed steps" or "keep partial".
- Undo is available from the History screen per transaction or per item, until purge.
- **Crash safety:** write the action row as `pending` before acting and as `done` after. On helper startup, reconcile pending rows.

---

## 15. Security Score: posture checks

Weights are a suggestion (sum 100). "Admin" = needs the root helper; everything else works unprivileged. **[tested]** values are from the dev machine.

| # | Check | Command / API | Good value | Weight | Notes |
|---|---|---|---|---|---|
| 1 | FileVault | `fdesetup status` **[tested: "FileVault is On."]**; API-free alternative `diskutil apfs list` | On | 12 | Also `fdesetup isactive`. "Deferred enablement" means pending |
| 2 | SIP | `csrutil status` **[tested: enabled]** | enabled | 12 | "Custom Configuration" is partial; treat as fail |
| 3 | Gatekeeper | `spctl --status` **[tested: "assessments enabled"]** | enabled | 8 | 15+: can't disable via `--master-disable` without a profile. Also check `spctl --status --verbose` |
| 4 | Firewall | `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate` **[tested: "disabled (State = 0)"]**; or `defaults read /Library/Preferences/com.apple.alf globalstate` (pre-15; 15+ moved to `com.apple.ApplicationFirewall` / the socketfilterfw API) | enabled | 8 | Also `--getblockall`, `--getallowsigned` **[tested: both ENABLED]** (info only) |
| 5 | Stealth mode | `socketfilterfw --getstealthmode` **[tested: off]** | on | 3 | Only meaningful if the firewall is on |
| 6 | Automatic updates | `defaults read /Library/Preferences/com.apple.SoftwareUpdate` keys `AutomaticCheckEnabled`, `AutomaticDownload` **[tested 1]**, `AutomaticallyInstallMacOSUpdates` **[tested 1]**, `CriticalUpdateInstall` **[tested 1]**, `ConfigDataInstall` **[tested 1]**; App Store: `defaults read /Library/Preferences/com.apple.commerce AutoUpdate` **[tested 1]** | all 1 | 8 | A missing key means the default (on). `ConfigDataInstall`/`CriticalUpdateInstall` = XProtect/RSR updates, the most important ones |
| 7 | OS up to date | `softwareupdate --list` (slow, network) **[tested: lists CLT update]**; `sw_vers` **[tested 27.0.1]**; compare against the Apple security releases feed / `gdmf.apple.com/v2/pmv` JSON | no pending security updates | 8 | Cache it; run at most daily. Use `softwareupdate --list --no-scan`? (not reliable) |
| 8 | XProtect freshness | Info.plist versions (§12) + `softwareupdate --history` | updated < 30 d | 4 | |
| 9 | Screen lock | `sysadminctl -screenLock status` **[tested: "screenLock delay is 300 seconds"]**; on 13+ `defaults read com.apple.screensaver askForPasswordDelay` no longer works **[tested: key missing]**. Idle time: `defaults -currentHost read com.apple.screensaver idleTime` | delay ≤ 5 min (0 = immediately best) | 6 | "off" = fail |
| 10 | Guest account | `sysadminctl -guestAccount status` **[tested: disabled]** or `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` **[tested 0]** | disabled | 3 | Also `-afpGuestAccess` / `-smbGuestAccess` status **[tested: disabled]** |
| 11 | Remote Login (SSH) | `sudo systemsetup -getremotelogin` (**admin** **[tested: needs admin]**); unprivileged: `launchctl print system/com.openssh.sshd` **[tested: "Could not find service" = off]** or listen check `lsof -nP -iTCP:22 -sTCP:LISTEN` | off | 5 | Also check `launchctl print-disabled system` for `com.openssh.sshd => disabled` |
| 12 | Screen Sharing / Remote Management | `launchctl print system/com.apple.screensharing` **[tested: not loaded = off]**; ARD: `/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd` exists, or `launchctl print system/com.apple.RemoteDesktop.PrivilegeProxy`; listen ports 5900/3283 | off | 5 | |
| 13 | File Sharing (SMB) | `launchctl print system/com.apple.smbd`; `sharing -l` (admin); ports 445/548 | off (or justified) | 3 | |
| 14 | Other sharing | Remote Apple Events: `launchctl print system/com.apple.AEServer` / `sudo systemsetup -getremoteappleevents`; Internet Sharing: `defaults read /Library/Preferences/SystemConfiguration/com.apple.nat NAT` (`Enabled`); Printer Sharing: `cupsctl \| grep _share_printers`; Media Sharing: `defaults read com.apple.amp.mediasharingd home-sharing-enabled`; Content Caching: `AssetCacheManagerUtil status` | off | 3 | Group as one "Sharing services" check |
| 15 | AirDrop | `defaults read com.apple.sharingd DiscoverableMode` **[tested: "Contacts Only"]** | "Contacts Only" or "Off" | 2 | "Everyone" fail (since 14 it auto-reverts after 10 min) |
| 16 | Lockdown Mode | `defaults read .GlobalPreferences LDMGlobalEnabled` (user domain) **[tested: key missing = off]**; system-level `/Library/Preferences/.GlobalPreferences.plist` | info / bonus | +2 bonus | Don't penalise if off. Recommend it only for high-risk users |
| 17 | Admin user count | `dscl . -read /Groups/admin GroupMembership` **[tested: root arankeyhan _mbsetupuser]** — filter `root` and `_`-prefixed system accounts; per-user `dseditgroup -o checkmember -m <user> admin` | ≤ 1 human admin, and daily user ideally standard | 4 | Here: 1 human admin. Also flag a root account with a password (`dscl . -read /Users/root AuthenticationAuthority`) |
| 18 | Secure Keyboard Entry (Terminal) | `defaults read -app Terminal SecureKeyboardEntry` **[tested: 0]**; iTerm2 `defaults read com.googlecode.iterm2 "Secure Input"` | 1 | 1 | Low weight; info |
| 19 | Rosetta | `pgrep oahd` **[tested: running, pid 753]**; `/Library/Apple/usr/libexec/oah/` exists **[tested]**; `arch -x86_64 /usr/bin/true` exit status | info | 0 | Not a vuln itself; it shows x86 malware can run. List running Intel processes (`proc_pidinfo` `PROC_PIDARCHINFO` or `sysctl.proc_translated`) |
| 20 | Outdated third-party apps | Enumerate `/Applications`, `~/Applications`: `CFBundleShortVersionString`; compare against Sparkle appcasts (`SUFeedURL` in Info.plist), Homebrew `brew outdated --cask --greedy`, or a curated CVE feed for high-risk apps (Chrome, Firefox, Zoom, Office, Java, Adobe) | none critical outdated | 5 | Phase 2; ship a curated list first |
| 21 | TCC grants review | System db `/Library/Application Support/com.apple.TCC/TCC.db` and user db `~/Library/Application Support/com.apple.TCC/TCC.db` (both **need FDA** **[tested: authorization denied / unable to open]**): `select service, client, client_type, auth_value, auth_reason, last_modified from access` | review list | 4 | Highlight `kTCCServiceAccessibility`, `kTCCServiceScreenCapture`, `kTCCServiceSystemPolicyAllFiles`, `kTCCServiceListenEvent`, `kTCCServiceDeveloperTool`, `kTCCServiceEndpointSecurityClient` held by unsigned/unknown apps or apps that no longer exist. `auth_value` 2 = allowed. Schema varies by OS; probe columns via `PRAGMA table_info(access)`. Read-only — never write TCC.db (SIP-protected anyway); deep-link to the pane to revoke |
| 22 | Secure boot (Apple silicon) | `sudo bputil -d` (**admin** **[tested: requires root]**) → "Full Security" vs "Reduced/Permissive"; kexts allowed by user (`kmutil showloaded --list-only`, third-party kexts) | Full Security | 3 | Intel T2: `nvram 94b73556-...:AppleSecureBootPolicy` **[tested: not present on Apple silicon]** |
| 23 | Configuration profiles | `profiles list` / `sudo profiles list -all` **[tested]** | no unexpected profiles | 3 | Ties into §6 |
| 24 | Trusted root CAs added | `security dump-trust-settings -d` (admin domain) | none unexpected | 2 | Ties into §9 Pirrit |
| 25 | Firmware password / Recovery lock (Intel only) | `sudo firmwarepasswd -check` | on (Intel only) | 0–2 | Skip on Apple silicon |

Scoring notes:
- Present as 0–100 plus a letter grade. Each check result is `pass / fail / warn / unknown (needs FDA or admin)`. **Unknown should not count as fail**; renormalise over the known checks and show "X checks need permissions".
- Managed devices: if a profile enforces a setting (e.g. FileVault via MDM), show "Managed by your organization" and mark it pass/fail without offering a fix.
- One-click fixes only where safe and reversible: Firewall on (`sudo socketfilterfw --setglobalstate on`), stealth on (`--setstealthmode on`), guest off (`sudo sysadminctl -guestAccount off`), SSH off (`sudo systemsetup -setremotelogin off`; needs FDA on 13+), auto-update keys (`defaults write` as root, plus verify). FileVault, SIP, Lockdown Mode and Secure Boot: deep-link to System Settings or instructions only. Never toggle SIP or FileVault programmatically.
- Deep links: `x-apple.systempreferences:com.apple.preference.security?FileVault`, `...?Firewall`, `...?Privacy_AllFiles`, `x-apple.systempreferences:com.apple.Sharing-Settings.extension`, `x-apple.systempreferences:com.apple.Software-Update-Settings.extension`, `x-apple.systempreferences:com.apple.LoginItems-Settings.extension`.

---

## 16. Implementation checklist (Swift)

- `RemediationKit` (shared): `RemediationAction` protocol (`apply/verify/revert`), `Transaction`, `Journal` (SQLite), `QuarantineVault` (CryptoKit AES-GCM, AppleArchive, HMAC'd records).
- `BastionHelper` (SMAppService daemon): XPC service with an audit-token code-signing requirement; executes actions; wraps `launchctl`, `profiles`, `sfltool`, `crontab`, `security` with argument arrays and timeouts.
- `ProcessTree` utility via libproc (`proc_listallpids`, `proc_pidinfo`, `proc_pidpath`), with SIGSTOP-then-kill.
- `BrowserCleaner` per-engine adapters (Chromium, Firefox incl. mozLz4 decode, Safari plist + pluginkit).
- `PostureScanner`: one `PostureCheck` struct per row in §15, with `requires: [.fda, .admin, .network]`, a cached result and a TTL.
- `XPRMonitor`: ES XP events plus `OSLogStore` backfill with the predicate in §12.

---

## Sources
- Eclectic Light: [Hunting malware protection in the log](https://eclecticlight.co/2022/09/01/hunting-malware-protection-in-the-log/), [Checking macOS malware scans: Endpoint Security or the log?](https://eclecticlight.co/2022/12/29/checking-macos-malware-scans-endpoint-security-or-the-log/)
- Huntress: [dmXProtect](https://huntress.com/blog/dmxprotect-stop-drop-shut-malware-down-before-it-opens-up-shop)
- Cisco XDR: [XProtect Remediation collection](https://docs.xdr.security.cisco.com/Content/Forensics/air/features/acquisition/supported-evidence/macos-collections-detail/xprotect-remediation.htm); Binalyze: [XProtect Remediation](https://kb.binalyze.com/air/features/acquisition/acquisition-profiles/macos-collections/xprotect-remediation)
- Apple Platform Deployment: [Manage login items and background tasks](https://support.apple.com/guide/deployment/depdca572563)
- mjtsai / Howard Oakley on `sfltool resetbtm`: [2023-07-05](https://mjtsai.com/blog/2023/07/05/)
- DSSW: [macOS Login Items](https://dssw.co.uk/powermanager/guide/finding-and-fixing/macos-login-items/)
- Apple Developer Forums: [Remove configuration profiles?](https://developer.apple.com/forums/thread/106799)
- FileWave KB: [Profiles in macOS 11 Big Sur and beyond must be installed via MDM](https://kb.filewave.com/books/profiles-apple/page/profiles-in-macos-11-big-sur-and-beyond-must-be-installed-via-mdm)
- Slashdot: [Big Sur feature to hamper adware](https://it.slashdot.org/story/20/07/04/0014202/new-apple-macos-big-sur-feature-to-hamper-adware-operations)
- Apple Community: [Profile changes browser settings](https://discussions.apple.com/thread/251117866)
- Apple docs (background knowledge, not fetched this session): Endpoint Security `es_event_xp_malware_detected_t` / `_remediated_t`, `es_event_btm_launch_item_add_t`; Apple Platform Security guide (SSV, SIP, data protection).
