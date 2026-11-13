# wms-fc: supply chain and integrity (2026-11-13)

Owned area: `Packaging/rampart-setup.sh`, `scripts/build.sh`, `scripts/install.sh`, `scripts/uninstall.sh`,
`Packaging/killswitch.sh`, `Packaging/scripts/{pre,post}install`, code-signing / cdhash pins (`install-identity.plist`,
`trusted-clients.json`), the Guard manifest (`RampartGuard/Integrity.swift`, `OwnInstallTrust.swift`), and everything
RamPart downloads: the MalwareBazaar hash feed (`RampartEngine/HashFeedUpdater.swift`), HaGeZi / URLhaus domain lists
(`RampartNetwork/BlocklistUpdater.swift`), DoH upstreams and their key pins (`RampartNetwork/DoHClient.swift`), XProtect
and generic YARA rules (`RampartYara/YaraEngine.swift`).

Suite: `Sources/rampart-selftest/SelfTest+WMSFc.swift` (`wmsfc`, 70 checks). Everything runs offline (mock
`URLProtocol`) or as `--dry-run` of the scripts; nothing is installed and no dialog can appear.

## Threat model

| Attacker | Capability | Goal |
|---|---|---|
| Malicious feed / compromised mirror / CDN | serves any body with status 200 and the expected content type | plant hashes of legitimate files (a hash hit scores 100 and is quarantined: a file-deletion primitive), remove real entries, replace a blocklist with a tiny or huge one, or replay an old copy forever |
| Network MITM (hostile Wi-Fi, corporate TLS proxy, DNS poisoning) | redirects, downgrades, substitutes hosts, serves gigabytes | same as above, plus memory exhaustion of the root daemon |
| Local admin-group process without the password | writes to `/Applications`, `/Library/Application Support`, `/usr/local/bin`, `/private/tmp`; controls the environment of the shell it asks root to run | get its own binary installed as the root LaunchDaemon (TOCTOU swap during install, symlink / hard-link tricks, `BASH_ENV` / `DYLD_*` / `PATH` / `IFS` injection, env-selected daemon source), redirect root's `rm -rf`, make root `chown`/`chmod` files it names |
| Rollback attacker | offers an older, validly signed build or feed | reintroduce a fixed vulnerability or stale definitions |

## Findings

| # | Sev | Where | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | `HashFeedUpdater.update` | Used `URLSession.shared`: every redirect followed (any host, even `http://`), no TLS floor, cookies and cache on, and the whole body read with `data(for:)` before the 64 MB check (a hostile mirror could make the root daemon buffer gigabytes). No host pinning: a hosts-file or DNS redirect to a look-alike was accepted as long as the final host matched the (spoofed) name. | Own ephemeral session: TLS 1.2 floor, no cookies/cache, redirects only to https on the same host; `sourceRefusal` requires https without credentials and, for unsigned feeds, a host in `trustedHosts` (`bazaar.abuse.ch`); the body is streamed under a hard ceiling and abandoned when exceeded; a non-TLS final URL is refused. The database is untouched unless every check passes. | Fixed |
| 2 | High (design) | all feeds | Nothing RamPart downloads carried a signature it could verify, so a mirror or MITM could alter RamPart's own future feeds; the existing detached-`.sig` option for blocklists could be replayed with any older signed list (no version or date). | New `RampartShared/FeedSigning.swift` (additive file in the lead's module): Ed25519-signed manifest `{feed, version, created, sha256, size, expires?}` verified signature-first, then feed id, size, SHA-256, monotonic version (rollback), freshness (45 days) and expiry. `HashFeed.rampartSigned(...)` and `BlocklistUpdater.Source.rampartSigned(...)` are the hook: they return nil until `FeedSigning.productionPublicKeyBase64` is set, so no unsigned "RamPart feed" can be configured. The last accepted version and hash are recorded (hash DB meta, blocklist `.meta.json`); a lower version or a same-version different body is refused and the last known good copy stays. Tests use a fresh random key per run only. | Fixed (key: lead) |
| 3 | Medium | `rampart-setup.sh` (`install`) | `RAMPART_DAEMON_SRC` was read from the environment by `install_rampart` and only required its folder to be root-owned. `/private/tmp` is root-owned, so a caller controlling the env of the `.pkg` postinstall / `sudo` invocation could name any ad-hoc binary signed as `app.rampart.daemon` and have it copied to `/Library/PrivilegedHelperTools` and run as root. | The daemon source is an internal variable set only by `place_staged`; the env var is unset at start; the source must sit in a `STAGE_PREFIX` folder that is root-owned mode 700 and be a regular file; its cdhash is pinned before the copy. | Fixed |
| 4 | Medium | all root scripts | No fixed `PATH`; `BASH_ENV`, `ENV`, `CDPATH`, `GLOBIGNORE`, `IFS`, `DYLD_*`, `LD_*` inherited from the caller; wrappers passed their whole environment to the root script; `set -e` absent in `rampart-setup.sh` / `uninstall.sh`, so a failed `launchctl bootstrap`, `install -d` or `cp` continued half-installed. | `rampart-setup.sh`: `set -euo pipefail`, fixed `PATH`, injection variables unset, `IFS` reset; every optional step has an explicit `|| true`, every required one dies; `launchctl bootstrap` retries 10 s then dies instead of silently leaving no service. `install.sh`, `uninstall.sh`, `postinstall` start the root script with `/usr/bin/env -i PATH=...` (dry-run fixture variables are the only pass-through, honoured only with `--dry-run`); `preinstall`/`postinstall` use absolute tool paths. `killswitch.sh`: `set -u`, `set -f`, injection variables unset, `RAMPART_KS_*` fixtures ignored outside dry runs, pids > 1 only, symlinked `emergency.json` ignored. | Fixed |
| 5 | Medium | `rampart-setup.sh install-from`, `place_staged` | A source bundle could contain symlinks or hard links; root then ran `ditto`, `chown -R`, `chmod -R` over the copy. macOS `chown/chmod -R` do not follow links inside the tree (verified), but a hard link to a file outside the bundle is the file itself, and `--expect-cdhash` skipped the source-side codesign check, so nothing refused links before the copy. | `check_source_no_links` (symlink or `-links +1`) runs on the source and again on the root-only staged copy before `chown -R -h` / `chmod -R -P`; `build.sh` fails the build if the bundle contains a link or a group/other-writable entry. Our bundle never contains links (verified on `dist/RamPart.app`). | Fixed |
| 6 | Low | `rampart-setup.sh uninstall`, `killswitch.sh` | pf anchor names taken from `pfctl -s Anchors` were word-split and glob-expanded, then passed to `pfctl -a`. | Names must match `[A-Za-z0-9._/-]`; expansion runs under `set -f`; a dry run can take the listing from `RAMPART_TEST_PF_ANCHORS`. | Fixed |
| 7 | Low | `rampart-setup.sh install` | `ln -sfn` over `/usr/local/bin/rampart` when something that is not a symlink sits there (admin-owned `/usr/local/bin`). | A non-symlink is left alone with a message; a CLI-link failure never fails the install. | Fixed |
| 8 | Low | `build.sh` | No `umask`, PATH from the developer shell, no record of what was shipped. | `umask 022`, fixed PATH, `dist/SHA256SUMS.txt` with the artefact hashes and the app cdhash. | Fixed |
| 9 | Info | `rampart/main.swift` (CLI `--gui-auth`, not owned) | The AppleScript root script runs `chown -R`/`chmod -R` on the staged copy and starts `rampart-setup.sh` with the environment `osascript` gives it. | Needs owner: add `/usr/bin/find "$S" \( -type l -o -links +1 \) -print -quit` refusal after `ditto`, use `chown -R -h` / `chmod -R -P`, and start the setup script with `/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin`. | Needs owner |

## Reviewed and held (no change needed)
- `install-identity.plist` / `trusted-clients.json`: written root:wheel 644 through temp file + rename in a root-only
  folder; `OwnInstallTrust.currentCDHashes` ignores them unless root-owned, not group/other-writable, regular, < 1 MB.
- Rollback of the app: `identity_refusal` refuses a lower version/build than the record (and than the copy in
  `/Applications`), a different Team ID / requirement, and an ad-hoc copy over a signed install, unless
  `--allow-downgrade` is passed explicitly by the admin. Verified under `set -e`: a record missing its version refuses
  with a message (test).
- Helper install: temp file in `/Library/PrivilegedHelperTools`, verified by identifier + pinned cdhash, renamed; the
  `.pkg` path opens `rampartd` once and checks owner/mode through the descriptor.
- Guard manifest (`Integrity.swift`): HMAC key 0600 in a 0700 folder with owner/mode checks, v2 envelopes bound to the
  path, raw restores only when the backup matches the manifest hash, `unlisted` and `unsafeOwnership` reported.
- Blocklists: pinned hosts, https only, TLS 1.2 floor, same-host redirects, streamed 64 MB cap, HTML/JSON/binary
  rejection, 4 M entry cap, 25 % shrink guard, atomic write; `buildBlocklist` never accepts allow rules from a feed.
- DoH: TLS 1.2 floor, no redirects, no proxy, system trust then key pin, bailiwick check on answers.
- YARA: XProtect rules come from Apple's SIP-protected bundle; the generic rules come from root-owned
  `/Library/Application Support/Rampart/Rules` or the signed app bundle. There is no remote rule feed.

## Residual risks (honest limits)
- **Third-party feeds are unsigned.** abuse.ch and HaGeZi publish no signatures RamPart can verify. A compromise of
  their origin (not of a mirror or the network) still reaches the daemon; a poisoned hash in MalwareBazaar would be
  quarantined with score 100. Mitigation outside this area: the engine should never auto-quarantine an Apple-signed
  platform binary or a notarized Developer ID file on a hash hit alone (lead / engine owner).
- **DoH pins are TOFU.** `DoHPinStore.staticPins` is empty on purpose; the first connection on a hostile network pins
  the attacker's key. The release owner should capture Cloudflare's and Quad9's SPKI hashes from a trusted network.
- **Freeze attacks on unsigned lists.** A MITM can answer `304 Not Modified` forever; RamPart keeps the last copy and
  cannot tell. Only the signed manifest (`created` freshness) detects this, so it applies to RamPart's own feeds only.
- **Ad-hoc signing.** Without Developer ID every install changes the cdhash, so the install record pins an exact
  build, not a signer; an admin with the password can always approve a different ad-hoc build (`--expect-cdhash`).
- **BASH_ENV in the caller's shell.** `env -i` protects the root script, not the wrapper the admin runs with `sudo`;
  `sudo` itself already drops `BASH_ENV` and `DYLD_*` (env_reset). The AppleScript path is item 9 above.
- Root can forge anything: the HMAC key, the identity record and the pins are readable by root. Documented limit.

## Hand-off for the lead
1. Generate the feed release key offline (`FeedSigning.generateKeyPair()` or `openssl genpkey -algorithm ed25519`),
   keep the seed out of the repo, set `FeedSigning.productionPublicKeyBase64`, and publish
   `<feed>.manifest.json` next to each own feed (`FeedSigning.sign`).
2. Item 9 (CLI `--gui-auth` script) and the engine-side platform-binary guard above.
3. `Package.swift` was not touched; the only edit outside the owned area is the additive file
   `Sources/RampartShared/FeedSigning.swift` and one line in `Suites.swift`.
