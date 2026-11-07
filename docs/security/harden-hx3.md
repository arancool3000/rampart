# harden-hx3: quarantine vault, restore/export, Run in Sandbox (2026-11-07)

Scope (owned): `Sources/RampartRemediation/**` (new: `SafeFS.swift`), `Sources/rampartd/Core/QuarantineSandbox.swift`,
`Sources/rampartd/Core/SandboxProfile.swift`, `Sources/RampartApp/Views/QuarantineManager.swift`.
Tests: `Sources/rampart-selftest/SelfTest+Hx3.swift`, `static func hx3Checks()` (53 checks, all pass in a scratch harness).

## Threat model

Assets: other users' and root-only files (the daemon runs as root), the vault key and encrypted samples, the user's home
data (keys, browser profiles, documents), system integrity (LaunchDaemons, sudoers), the honesty of RamPart's UI text.

Attackers: local malware running as the user (controls its own files, folders and file names, can race renames and
symlinks, can plant hard links), a malicious quarantined item running in the sandbox, another local user using the
daemon's IPC, a tampered file in the vault or journal (needs root), attacker-controlled text shown in the app.

Entry points: `quarantine(path:)` on a user-controlled path as root; `restore`, `restoreQuarantinedTo`, `exportQuarantined`
(root writes into a user folder); `sandboxRun` (runs the item under sandbox-exec in the user session); journal undo
(`runCommands`, `restoreBackups`, `restoreQuarantine`); purge; the Quarantine tab (file names, item output).

## Sandbox profile review (every allowed operation)

Verified live with `sandbox-exec` and inert probe scripts that I wrote (never quarantined content), see "Evidence".

| Operation | Before | After |
|---|---|---|
| default | deny | deny |
| process-exec | item + interpreter (+ sh trampolines, CLT python framework) | same; python is the CLT binary, not the `/usr/bin/python3` shim; perl5.x re-exec added |
| process-fork | deny | deny (also blocks `posix_spawn`: tested) |
| file-read* | **allowed everywhere** except a list of ~25 home folders | contents readable only from `/System`, `/usr/{lib,share,libexec,bin}`, `/bin`, `/sbin`, CLT, tz data, a few devices and the work folder. `/Users`, `/Volumes`, `/usr/local`, `/private/var/root`, `/Library/Keychains` unreadable even as metadata. Old deny list kept as belt and braces |
| file-write* | work folder, /dev/null, /dev/zero | same, plus deny `file-write-flags`, `file-write-owner`, `file-link` |
| file-map-executable | everywhere | OS roots, CLT and the work folder only |
| mach-lookup | logger, notification_center, opendirectoryd.libinfo, logd | **none** (`deny mach-lookup`); sh, bash, zsh, python, perl, ruby and a C program all still run |
| ipc-posix-shm | notification_center read | none |
| iokit-open | default deny | explicit deny |
| network* | deny | deny |
| signal / process-info | self only | self only |
| sysctl-read | allowed | allowed (needed by libc; leaks hardware details only) |

## Findings

| # | Severity | File:line | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | Critical | QuarantineVault.swift:108 (`quarantine`) | Root followed symlinks after `lstat`: swapping the file for a link to `/etc/master.passwd` made root read it into the vault (then restorable by the user), and `chmod(p)` changed the mode of the link target (could make a root-only file world-readable). `unlink(p)` through a swapped parent folder could delete a root file of the same name | Parent pinned with `SafeFS.pin` (O_NOFOLLOW + F_GETPATH); `openat(O_NOFOLLOW)` + inode match; `fchflags`/`fchmod`/`flistxattr` on the descriptor; read from the descriptor; `unlinkat` only if the entry is still the same inode; protected-path check on the real path | Fixed |
| 2 | High | QuarantineVault.swift:141, :216 | Hard link (in a user folder) to a root-only file: root read and chmodded the shared inode; same inside a quarantined folder via ditto | Refuse a regular file with nlink > 1 owned by someone other than the folder owner (`SafeFS.isForeignHardLink`), for files and every entry of a folder | Fixed |
| 3 | High | QuarantineVault.swift:196 | Folders were archived in place while the user could still edit or swap them | Folder is atomically `renameat`-ed into root-only `vault/staging/<id>/` first, inode re-checked, archived there, moved back on any failure. Across volumes it is refused with a clear message | Fixed |
| 4 | High | QuarantineVault.swift:294-345 | Folder restore ran `ditto -x` by path into `<parent>/.rampart-restore-*`: swapping the parent after the pin check redirected root's writes anywhere | Temp folder created with `mkdirat` (0700, root), ditto runs with `posix_spawn_file_actions_addfchdir_np` and destination `.`, final `renameatx_np` from that descriptor | Fixed |
| 5 | High | QuarantineVault.swift:308; QuarantineSandbox.swift (`restore`) | Restore elsewhere as root created the file owned by the recorded owner with setuid/setgid intact, then `lchown`ed later: a setuid-root binary could appear in a user folder for a moment, and setuid survived in folders | Owner set at create time (`ownerUID/ownerGID` options), setuid/setgid dropped for restores elsewhere or to a new owner (`SafeFS.restoredMode`, `SafeFS.sanitizeTree` through descriptors) | Fixed |
| 6 | Medium | QuarantineVault.swift:302 | Destination ownership checked only in `checkDestination` (TOCTOU) | `requireParentOwnerUID` re-checked on the pinned descriptor | Fixed |
| 7 | High | QuarantineSandbox.swift:~150 (`export`) | Encrypted zip written by root through `open(path, O_NOFOLLOW)`: only the last component was protected, so a swapped parent let root create a file anywhere (e.g. `/etc/sudoers.d/x`, breaking sudo) | Pinned folder, owner re-check on the descriptor, `SafeFS.createFile` (`openat` O_EXCL, owner set before content) | Fixed |
| 8 | Medium | QuarantineSandbox.swift:73 | A non-admin peer could restore or export any user's item (if the admin gate is off) | `checkItemAccess`: non-admins only items they owned | Fixed |
| 9 | Medium | QuarantineSandbox.swift (`plaintext`) | Daemon code re-read `vault.key` with `Data(contentsOf:)` (follows links) and duplicated the key derivation | New `QuarantineVault.verifiedPlaintext(id:)`; the key never leaves the vault class | Fixed |
| 10 | Medium | QuarantineVault.swift:72 | Vault key opened following symlinks with no owner/type check | O_NOFOLLOW, must be a regular 32-byte file owned by the running uid, else the vault refuses to open | Fixed |
| 11 | High | SandboxProfile.swift:118 (`generate`) | `(allow file-read*)` let the item read everything not listed: `~/.zsh_history`, `~/.config`, `~/Library/*` (most of it), other apps' temp files, `/usr/local`, external volumes. A python script could also import code from anywhere | Allow-list for file contents (see table); home, /Users, /Volumes, /usr/local unreadable even as metadata; work folder must not sit inside an unreadable root | Fixed |
| 12 | Medium | SandboxProfile.swift:166 | mach-lookup to notifyd, opendirectoryd, logger, logd (posting arbitrary Darwin notifications, user directory lookups) | `deny mach-lookup`; also `deny iokit-open` | Fixed |
| 13 | Medium | QuarantineSandbox.swift:215 | `/usr/bin/python3` is an xcode-select shim: runs xcrun (cache writes) and, with no CLT, can ask to install tools (a pop-up) | Resolved to `/Library/Developer/CommandLineTools/usr/bin/python3` or refused; python runs with `-I -B`, zsh `-f`, bash `--noprofile --norc`, ruby `--disable-gems` | Fixed |
| 14 | Medium | QuarantineSandbox.swift:223 | Symlinks in the extracted item could point outside the work folder (the sandbox resolves them, but daemon-side steps read `Info.plist` etc.) | `SandboxProfile.removeEscapingLinks` removes links that resolve outside or nowhere (realpath, not lexical) before anything runs; noted in the report | Fixed |
| 15 | Medium | QuarantineSandbox.swift:255 | No disk limit: the item could fill the disk in 60 s via its folder or stdout | Watchdog every second: >256 MB or >20,000 entries stops it | Fixed |
| 16 | Low | SandboxProfile.swift:166, QuarantineSandbox.swift:101 | `chflags uchg` inside the work folder made cleanup fail and leaked the folder | `deny file-write-flags`; cleanup runs `chflags -R -P` and `chmod -R -P` (never follows links) | Fixed |
| 17 | Medium | SandboxProfile.swift:226; QuarantineManager.swift (`QuarantineText`) | Item output, violation targets and file names shown in RamPart's UI could contain terminal escapes and bidi overrides (e.g. a right-to-left override making a name read as `.jpg`), and output was labelled just "Output" | Stripped in the daemon and again in the app; sections now say "Output printed by the item (not from RamPart)"; names capped | Fixed |
| 18 | Medium | RemediationPlan.swift:230 | Undo had no in-progress marker: a crash during undo, or a stale state passed twice, replayed `runCommands` (e.g. writing an old crontab over newer edits) | Undo re-reads the journal and requires phase `done`, then writes a new `undoPending` line before acting; `recoverInterrupted` reports it and it is never replayed automatically | Fixed |
| 19 | High | Cleanup.swift:48 (`BackupIO.restore`) | Undo moved/copied backups (attacker-controlled browser files) as root to a path whose parent could be swapped for a link to e.g. `/Library/LaunchDaemons` | Pinned parent, `renameatx_np(RENAME_EXCL)` / `SafeFS.createFile` + `renameat` relative to the descriptor, protected-path check on the real path | Fixed |
| 20 | Low | QuarantineVault.swift:421 | A purge racing a restore rewrote the restored item's history as "purged" | `purge` only deletes items still quarantined | Fixed |
| 21 | Low | QuarantineVault.swift (`delete` doc) | Called "crypto-shred", which it isn't (one shared key, APFS keeps blocks) | Honest wording in the code | Fixed |
| 22 | Info | QuarantineManager.swift | UI copy claimed only a few folders were protected and that child processes were stopped | Copy now matches the profile and says scripts can't run commands; still says "best-effort, not a VM" | Fixed |

## Honest limits (not fixable within macOS's rules)

- `sandbox-exec` is deprecated and is not a VM. Kernel or sandbox bugs could allow escape; the item can still read macOS's
  own files and sysctl values, so it can fingerprint the machine. The UI says this.
- The vault key sits on disk next to the ciphertext (root-only, 0600). Encryption stops accidental execution and AV
  re-detection, not an attacker with root. A root attacker can also replay an older signed sidecar (rollback of status);
  the blob is gone after restore/purge so this gains little.
- `delete`/`purge` unlink the ciphertext; they are not a secure erase.
- The journal is root-only but not signed; anyone with root can already do anything it would.
- Folders on another volume can't be staged atomically and are refused rather than archived in place.

## Needs owner

1. `Sources/rampart-selftest/Suites.swift`: add `("hx3", SelfTest.hx3Checks),` to `moduleSuites`.
2. `Sources/rampartd/Core/Router.swift` `.restore` (original location) → `p.restore`: when `requireAdminForPrivileged` is
   off, add the same check as `QuarantineSandbox.checkItemAccess` (non-admins only items with `ownerUID == peer.uid`).
3. `Sources/rampartd/Core/Integrations.swift` `VaultQuarantine.purgeExpired`: nothing to change; it now skips non-quarantined
   items through `purge`.

## Evidence

Live probes (my own inert python/sh/C fixtures under the scratchpad, generated profile from `SandboxProfile.generate`):
work-folder write allowed; hard link to an outside file, hard link inside, read through a symlink to `~/.zsh_history`,
reading home, `stat ~/.ssh`, listing `$TMPDIR`, `/usr/local`, `/etc/hosts`, chflags, `posix_spawn`, fork, TCP, Unix socket,
writing `/private/tmp`, exec of `/bin/ls` all denied; reading `/System` allowed; `getpwuid` and `notify_post` fail (no
mach services). Before the fix the same probe read `~/.zsh_history`, listed `~/Library` and `$TMPDIR`.
`sandbox-exec -f <profile> /usr/bin/true` is part of `hx3Checks` (profile parses, unlisted program can't start).
