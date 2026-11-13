# wms-o2: restore/export, vault exhaustion, Run in Sandbox, Download Gate (2026-11-13)

Owned area: `Sources/RampartRemediation/**`, `Sources/rampartd/Core/QuarantineSandbox.swift` + `SandboxProfile.swift`,
`Sources/RampartGuard/DownloadGate*.swift` (new: `DownloadGateFS.swift`).
Tests: `Sources/rampart-selftest/SelfTest+WMSo2.swift`, suite `wmso2`.
Outside the owned area (minimal, additive): `Sources/rampartd/Core/Integrations.swift` (`VaultQuarantine` passes the
scanned hash to the vault and re-applies the quarantine flag on restore).

## Threat model

Builds on harden-hx3 (descriptor-pinned vault operations, strict sandbox profile). Attackers: malware running as the
user (races renames, symlinks and hard links, rewrites files and resets their mtime, can `chmod` and `xattr -d`), a
quarantined item running under sandbox-exec, a flood of files that RamPart is made to quarantine, another local user
using the daemon's IPC. Assets: root-owned system folders, other users' files, the user's data, the root daemon's
memory and the startup disk, and the truth of "quarantined" / "held".

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| 1 | High | Download Gate fingerprint was dev/inode/size/mtime only. `chmod +x` or `xattr -d com.apple.quarantine` after the check changes neither, so a held program could be made runnable again without the gate noticing. | Fixed: the fingerprint also covers execute bits and the quarantine flag (and the Info.plist change time for apps). Held/blocked items are also re-checked every ~2 s, which also catches a chmod through another hard link that FSEvents reports under a different path. Re-gating keeps the original stripped modes. |
| 2 | Medium | Gate `Allow` restored the recorded mode with path-based `chmod`: setuid/setgid bits came back, the chmod followed links in any parent folder, and a file swapped in under the same name got the execute bits. | Fixed: all chmods go through `O_NOFOLLOW_ANY` parent + descriptor (`DownloadGateFS.swift`), only on the inode that was stripped, never with setuid/setgid. Quarantine-flag reads/writes are fd-based too. |
| 3 | Medium | App bundles: only `Contents/MacOS` and `Helpers` were stripped and scanned. An executable in `Contents/Resources` stayed runnable; an `Info.plist` whose `CFBundleExecutable` is `../Resources/x` points LaunchServices at a file the gate never looked at, and a signed app with it would be cleared. | Fixed: every executable file in the bundle is stripped (fd walk, no links); the plist's main executable is scanned; a non-plain `CFBundleExecutable` holds the app. |
| 4 | Medium | Gate race: the file could be rewritten between the signature check and giving the execute bits back. Hard-linked programs could be cleared and later run via the other name. | Fixed: the inode change time is compared before restoring (changed → held); single-file programs with more than one hard link are held. |
| 5 | Medium | Vault exhaustion: one file up to 4 GiB was held in the root daemon's memory about four times; there was no limit on total vault size, item count or free disk space; a file's xattrs were unbounded in the sidecar that every listing reads. | Fixed: 1 GiB per item (checked before anything changes, folders measured in staging), 20 GiB / 20 000 items per vault, at least 2 GiB left free, xattrs capped at 256 / 4 MiB. Refusals leave the file as it was. |
| 6 | Medium | Scan → quarantine TOCTOU: renaming the scanned file away and putting another file (e.g. the victim's) at the path made RamPart quarantine the wrong file and mark the threat handled. | Fixed: `quarantine(expectedSHA256:)`; `VaultQuarantine` passes the hash the scanner saw when the detection is about that exact file. A mismatch is refused ("changed since it was scanned"). |
| 7 | Medium | Restore created missing parent folders with `FileManager` (follows links). As root, a link swapped into the original path could create root-owned folders in e.g. `/Library/LaunchDaemons`. | Fixed: `SafeFS.makeParents` pins the deepest existing ancestor and creates each folder with `mkdirat` + `O_NOFOLLOW`, owned by the item's owner, never on a protected path. |
| 8 | Low | Restore to the original place as root went into the folder even if it now belongs to a different user. | Fixed: refused unless the folder is owned by the item's owner or root. |
| 9 | Low | Restore dropped `com.apple.quarantine`, so Gatekeeper never checked a restored download. | Fixed in the daemon paths (`restore`, `restoreQuarantinedTo`): the original flag is put back. Vault default unchanged (existing test). |
| 10 | Medium | Sandbox profile had a blanket `(allow sysctl-read)`: the item could list every process (`kern.proc.all`) and read the host name. | Fixed: sysctl reads are an allow-list (`hw.*`, `kern.os*`, `vm.*`, `sysctl.*` name lookups, a few kern names). sh, zsh, perl, ruby, CLT python and a Swift binary verified to still run. |

Checked and found sound (no change): sandbox denies network, mach-lookup, IOKit, AppleEvents (deny default), fork,
signals to others, file writes outside the work folder; export pins the destination and creates the zip owned by the
peer; vault quarantine pins the parent and refuses foreign hard links; restore never overwrites (RENAME_EXCL).

## Residual risks (honest limits)

- No Endpoint Security AUTH: the gate acts about a second after a download settles; anything opened in that window runs.
  Archives extracted outside the watched folders (e.g. with `ditto`/`unzip` into `~/Applications`) aren't gated; the gate
  makes sure the archive carries the quarantine flag so Archive Utility propagates it to what it unpacks.
- sandbox-exec can't stop `sysctl KERN_PROCARGS2` for a guessed pid: the item can still read the command line (not the
  environment) of the user's other processes. Fixing that needs a separate uid or a VM.
- Gate "Delete" removes one name; another hard link elsewhere keeps the (non-executable) content.
- Quarantine of a file with other hard links removes one name; the inode stays (made 0400) under the other names.
- A file changed after the scan is now left in place (honestly reported as not quarantined) until it is rescanned.
- Ad-hoc signing: each install changes the cdhash (TCC/FDA reset); Developer ID would fix it.
