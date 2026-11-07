# harden-hx7: install / uninstall / update, the CLI and packaging

Owner files: `Packaging/**`, `scripts/**` (not agent-build.sh), `Sources/rampart/main.swift`, `Sources/rampart/Client.swift`,
`Sources/RampartApp/InstallToApplications.swift`, `Sources/RampartApp/FullProtectionInstaller.swift`.
Tests: `Sources/rampart-selftest/SelfTest+HX7.swift` (`hx7Checks`, 73 checks, all pass; dry runs and read-only checks only).

## Threat model
**Assets:** root code execution (the LaunchDaemon and its binary), the admin password prompt, the user's files during
uninstall, the integrity of the installed app across updates.
**Attackers:** malware running as the user (it can edit any user-owned copy of the app, e.g. `~/Downloads/RamPart.app`,
before, during or after the admin prompt); a process in the `admin` group without the password (it can write to
`/Applications`, `/Library/Application Support` and rename bundles there); another local user (socket squatting,
symlinks in their home that root walks during uninstall); a tampered or older bundle offered as an "update".
**Entry points:** `rampart install|uninstall --gui-auth` (AppleScript `do shell script ... with administrator privileges`),
`scripts/install.sh`/`uninstall.sh` (sudo), `.pkg` pre/postinstall (root), `rampart-setup.sh`, the in-app
"Move to Applications" copier, the CLI's daemon socket.

## Install flow after hardening
1. As the user, the CLI checks the source: bundle id `app.rampart.app`, no world-writable file/folder, strict
   `codesign --verify --deep`, no control characters in any path, no downgrade over the installed copy, not replacing
   a foreign app. It then **pins the cdhash of every architecture slice** (`arm64=…,x86_64=…`).
2. The single root script (`mktemp -d /private/tmp/app.rampart.stage.XXXXXX`, mode 700) `ditto`s the source into the
   root-only folder, `chown -R root:wheel`, `chmod -R go-w`, then verifies **the copy** (strict codesign + identifier +
   the pinned cdhash) **before any of the copy's code runs**. Changing the source mid-copy or after the prompt only
   makes the install fail.
3. The verified staged `rampart-setup.sh place-staged` checks the install identity record (below), moves the old copy
   aside, renames the verified copy into `/Applications/Rampart.app`, copies `rampartd` from the root-only folder to a
   temp file in `/Library/PrivilegedHelperTools`, verifies the copy's identifier and cdhash, and renames it into place
   (root:wheel 755, refuses if the folder isn't root-owned / non-writable).
4. Launchd plists are **written from the script's own text** (temp file + `plutil -lint` + atomic rename, root:wheel 644),
   never copied from the admin-writable bundle. `ProgramArguments` is only the root-owned helper path.
5. `/Library/Application Support/Rampart/install-identity.plist` (root:wheel 644) records signer kind, Team ID,
   designated requirement, app + daemon cdhashes, version and build. This is the shared source of truth for updates
   (and for Guard / the updater, see needs-owner).

**Update rules (X1 S-X1-2):** never below the recorded version/build (and never below the copy in /Applications)
unless `--allow-downgrade` is passed explicitly; a recorded Team ID / certificate requirement must still be satisfied;
an ad-hoc copy never replaces a certificate-signed install; an ad-hoc update must equal the recorded cdhash or be the
exact cdhash approved in this run (admin prompt / sudo). Unattended paths therefore can't swap ad-hoc builds.

## Findings
| # | Sev | File:line (before) | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | Critical | main.swift:131-134 | `--gui-auth` ditto'd the user-owned source into `/Applications/.RamPart-installing.app`, then chowned, then ran the bundle's `rampart-setup.sh` as root. User malware could edit the source mid-copy, or edit the copy (still user-owned until `chown`) and get root. No signature check of what was copied. | Stage in a root-only `mktemp -d`, verify the copy (strict codesign + pinned cdhash) before running anything from it. | Fixed |
| 2 | Critical | rampart-setup.sh:52-53 | Daemon plist copied from `$APP/Contents/Resources` (admin-writable `/Applications`) into `/Library/LaunchDaemons`: swapping the plist = arbitrary root program. | Plists generated from the script; test asserts they match `Packaging/*.plist`. | Fixed |
| 3 | High | rampart-setup.sh:50; postinstall | `install` copied `rampartd` and ran `rampart-setup.sh` from `/Applications/Rampart.app` as root; an admin-group process can rename the bundle and drop its own between payload and postinstall. | postinstall opens the setup script once and checks root ownership/mode via the descriptor and runs `/dev/fd/3`; `rampartd` is read through one checked descriptor, copied to a temp file in PrivilegedHelperTools, verified, then renamed. | Fixed |
| 4 | High | install.sh:24-27 | Same chown-after-copy window in `/Applications`; no signature pin. | `install.sh` → `rampart-setup.sh install-from` (pin, stage, verify, place). | Fixed |
| 5 | High | main.swift:136-137 | Uninstall ran `rampart-setup.sh` as root directly from the (possibly user-writable) source bundle. | Uninstall also stages + pins + verifies, then runs the staged script. | Fixed |
| 6 | High | rampart-setup.sh:109 | `rm -rf "$APP"` with `$APP` from `RAMPART_APP` env and no checks (`RAMPART_APP=/` = `rm -rf /`). | App path must be `/Applications/<name>.app` (no `..`, no hidden, no control chars) and its bundle id must be ours, otherwise skipped. | Fixed |
| 7 | Medium | rampart-setup.sh:111-117 | Per-user loop deleted `$home/Library/Application Support/Rampart` etc. as root; a symlinked intermediate folder redirects root's `rm -rf`. `/Users/Shared` and system homes included. | uid ≥ 500 only; every intermediate folder must be a real folder owned by the user/root; deletion runs as that user (`sudo -n -u #uid rm`), so a race can only delete what the user could. | Fixed |
| 8 | Medium | rampart-setup.sh:51 | `/Library/Logs/Rampart` and `/Library/Application Support/Rampart` (parents admin-writable) could be pre-planted as symlinks; launchd then writes root logs through them. | `ensure_root_dir`: symlink removed, non-root folder moved aside, recreated root:wheel 755. | Fixed |
| 9 | Medium | (none) | No downgrade protection; no identity continuity on update. | CLI + `place-staged` refuse rollback (version then build), foreign apps, different Team ID/requirement; identity record (above). | Fixed |
| 10 | Medium | rampart-setup.sh:71-84 | DNS restore trusted any `dns-original.json`; values passed to `networksetup`. | Only root-owned snapshot in root-owned folder; services starting with `-` / control chars skipped; servers must be IP literals; counts bounded. | Fixed |
| 11 | Medium | main.swift:93,134 | AppleScript/shell quoting accepted newlines/control chars in `--app`. | Paths with C0/C1/format/line-separator characters refused; `'`, `"`, `\`, `$()`, backticks, `;&` round-trip (tested via `sh -n`, `printf` evaluation, AppleScript unescape). | Fixed |
| 12 | Low | main.swift:143 | `RAMPART_NO_PRIVILEGED_TOOLS` check came after path resolution. | Moved to the first line of the install/uninstall case. | Fixed |
| 13 | Low | Client.swift:47 | CLI trusted whatever process listened on the socket path. | `getpeereid`: peer must be root or the current user. | Fixed |
| 14 | Low | InstallToApplications.swift:34-38 | "Move to Applications" could replace a newer copy or a different app of the same name; copy not verified before swap. | Refuses foreign/newer destination; strict SecStaticCode check of the copy before replacing. | Fixed |
| 15 | Low | FullProtectionInstaller.swift:59 | CLI error text shown verbatim in the UI. | Prefix stripped, control chars removed, 240 chars max; installer must not be a symlink out of the bundle. | Fixed |
| 16 | Low | rampart-setup.sh verify_removed | `pkgutil … | grep -q` under `pipefail` can report "no receipt" on SIGPIPE; same bug made `is_adhoc` always false. | Capture output first, then match. | Fixed |
| 17 | Info | postinstall | Non-startup-volume installs placed a daemon pointing at the wrong volume. | Service install only for target `/`. | Fixed |

## Honest limits
- **Ad-hoc signing has no signer identity.** Anyone can produce a valid ad-hoc signature with identifier
  `app.rampart.app`. The pin proves that root runs exactly the bytes the user approved, not that those bytes came from
  us. Malware already running as the user can show its own fake "RamPart" password prompt; no installer can stop that.
  With a real Developer ID, the identity record pins the Team ID and requirement and closes the update gap.
- The `.pkg` path trusts the payload Installer laid down (root-owned). The descriptor checks stop a swap after that,
  but a pkg that is itself unsigned can be replaced before the user opens it. Ship a signed pkg when possible.
- `/Applications/Rampart.app` stays admin-writable at the folder level (macOS design). Only the user-level agent runs
  from it; root code runs only from `/Library/PrivilegedHelperTools`.
- SMAppService registrations (the no-root `app.rampart.userdaemon`) are removed with `launchctl bootout`; the BTM
  entry can only be fully cleared by the app (`SMAppService.unregister`) or by macOS when the bundle is gone.

## Needs owner
- **Lead (Suites.swift):** add `("hx7", SelfTest.hx7Checks),`. The suite needs the `rampart` product built next to
  `rampart-selftest` (both in `.build-agents/out/Products/Debug`).
- **Guard / updater (RampartGuard, RampartRefresh):** read `/Library/Application Support/Rampart/install-identity.plist`
  (root-owned only; ignore otherwise) as the pinned identity. Before swapping any bundle: `codesign --verify --strict
  --deep`, the same `teamID`/`requirement` when `signature == signed`, cdhash equal to `appCDHash` when ad-hoc (or
  hand off to `rampart install --gui-auth` for a fresh admin approval), and version/build ≥ the record. Equivalent
  shell check: `rampart-setup.sh check-update NEW.app [RECORD]`. Guard can also compare the running helper's cdhash
  with `daemonCDHash`.
- **rampartd (B9):** on start as root, refuse to run if its own path isn't `/Library/PrivilegedHelperTools/app.rampart.daemon`
  or the file/folder is not root-owned and non-writable by group/other (defence in depth for a manual misinstall).
