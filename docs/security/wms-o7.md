# wms-o7: self-protection red team (2026-11)

Owned area: RampartGuard TamperProtection, OwnInstallTrust, StaleHelper, RemoteAccess, EmergencyLockdown, KillSwitch;
rampartd Emergency.swift, KillSwitchExec.swift, GuardWiring.swift. Regression suite: `wmso7`
(`Sources/rampart-selftest/SelfTest+WMSo7.swift`).

## Threat model

- **Same-user attacker**: code running as the logged-in user, without the password. It can kill or replace its own
  processes (the app, the `--user` helper), run `launchctl` in its gui domain, touch decoys, run the RamPart CLI and
  connect to the daemon socket (anyLocal or sessionUser calls only; admin calls need RamPart's own client and an admin
  account).
- **Admin-user attacker without the password**: as above, plus it can write group-`admin` locations like
  `/Applications`. That means it can rename the root-owned `/Applications/RamPart.app` and put its own copy in its place.
  Hard links keep the original files root-owned. It cannot write root-owned files or run root code.
- Out of scope: root. A root process can stop any service. TamperProtection's `honestLimitCopy` says this.

Safety guarantees kept, and checked by tests: an owner can always lift a lockdown (root peer or admin token). One signal
never cuts the internet. The Kill Switch path A still needs Touch ID or the password (an admin token) or root.

## Findings

| # | Severity | Finding | Status |
|---|---|---|---|
| F1 | High | **Fake own-install files were trusted.** `OwnInstallTrust` treated any file in the app bundle as RamPart's own once the main executable verified. It never checked that the bundle seal still covered that file. It also trusted any `app.rampart.*`-signed binary in the bundle because the bundle's helper was trusted. An admin without the password could swap in a copy of the bundle (hard-linked originals plus one added payload). The payload was then never quarantined or frozen and never triggered a lockdown. The manifest mismatch it caused was resealed as a "verified upgrade", which put the payload into the manifest. From then on, `TamperDetector.isSelf` ignored everything the payload did to RamPart. | Fixed. For the real install layout, every vouched-for file, and each folder from it up to the bundle, must be root-owned and not group- or world-writable (`requireRootOwnership`). Bundle resources and same-bundle executables also need a strict, cached bundle-seal check (`BundleSeal`). |
| F2 | Medium | **A LaunchAgent unload could be hidden.** The sequence bootout, bootstrap, bootout left the first hold in place, so the final unload was excused by the bootstrap. Bootstrapping a look-alike `/tmp/x/app.rampart.agent.plist`, or running `kickstart`, also counted as a reload. Separately, `kill -0 <pid>` (an existence probe) was reported as a critical kill attempt. | Fixed. Only a bootstrap or load of our own plist path counts as a reload, and an answered hold is replaced by the next unload. Signal 0 is ignored. |
| F3 | Medium | **DoS through forged signals.** Any local program can produce a tamper signal (`pkill rampartd`) and a decoy signal (open a decoy). Together they counted as "two independent signals" and cut the internet. The attacker could repeat this after every 10-minute expiry. | Fixed. Tamper and decoy signals still engage lockdown (freeze, quarantine, alert), but they cut the network only when a threat-kind signal is also present: malware, credential theft, ransomware or exfiltration. |
| F4 | Medium | **Name-based exemptions.** `EmergencyProcessGuard` never froze processes named `rampartd`, `WindowServer` and so on, or anything with `/Rampart.app/` in its path (for example `~/Downloads/Rampart.app`). The planner never paused launch items with any `app.rampart.*` label, so malware at `~/Library/LaunchAgents/app.rampart.update.plist` escaped. | Fixed. The exemption now covers only RamPart's installed locations (`/Applications/RamPart.app/`, `/Library/PrivilegedHelperTools/app.rampart.*`), and only known labels at their real plist paths. |
| F5 | Medium | **Kill Switch path B ran the script by path as root.** The script ran after the admin prompt. In a bundle the user (or a swapping admin) can write, the script could be replaced while the prompt was on screen, so the owner's password would run attacker code as root. | Fixed. The real run needs the script and its folders up to the bundle to be root-owned. Dry runs are unaffected. A copy that isn't root-owned falls back to `sudo rampart killswitch`. Path A is unchanged. Minimal app edit: `KillSwitchScript.locate(dryRun:)`. |
| F6 | Medium | **Remote-access allowances.** The live probe had no signing facts. A pinned allowance therefore marked the approved tool as an impostor, and it got suspended. Unpinned allowances covered any look-alike that matched by path or by an ad-hoc signing identifier. | Fixed. Remote-tool processes now get an Apple-anchored Team ID (`anchor apple generic`, so a self-signed certificate's OU is ignored), cached per pid and start time. An unpinned third-party allowance doesn't cover a tool none of whose processes has a Team ID. Apple services are exempt. Only path-matched candidates are enriched, so there are no new unsigned-listener alerts for dev servers. |
| F7 | Low | **StaleHelper spoofing.** "Installed after it started" is read from the binary's ctime, which anyone can bump with a hard link. After that, any second helper instance stopped the current helper and took its place. | Fixed. A holder at the same path with the same cdhash is never stale. A replaced build is still stopped. |
| F8 | Medium | **Notification suppression.** The app was started for a lockdown notice only when nobody was subscribed to the daemon. A script that killed the app and held a subscription made every notice silent. | Fixed. The agent is always kickstarted, and bootstrapped again if it was booted out. This works in the installed root daemon only. Dev builds never spawn launchctl. |
| F9 | Medium | **Disable tokens weren't bound to a purpose** (lead / FA request). A token the user authorized for one action (pause, lift, Kill Switch) could be redeemed for any other, including uninstall. | Fixed. `issueToken(purposes:)` binds each token when it is issued. A redeem for any other purpose fails with `tokenWrongPurpose` and burns the token. `requestDisableProtection` issues `{pause, settings}` and `requestUninstall` issues `{uninstall}`. Residual: pause and settings share one request until the IPC request carries an explicit purpose. |

The test changed in `SelfTest+Emergency.swift` used to require that `/opt/fake/WindowServer` be spared from freezing,
which is exactly the F4 evasion. It now requires that process to be frozen, and still requires real RamPart and
platform binaries to be spared.

## Checked and not changed

- The Kill Switch IPC (path A) needs an admin token redeemed in the daemon or a root peer. In user mode the helper has no
  privileged-call authorization at all (by design: everything there runs as the same user, who can also kill it).
- Lift and restore-internet always succeed for an authorized owner. Readiness is advice, not a gate.
- `emergency.json`, the remote policy and the Guard key live in the root-owned support folder, so a non-root attacker
  can't edit them. In user mode they live in the user's own folder (same-user, no privilege boundary).

## Residual risks (honest limits)

- No Endpoint Security AUTH: unload, kill and file tampering are detected after the fact and restored where possible,
  never blocked. A root attacker wins.
- `keepBlocking` is `sessionUser` (IPCAuthz, not this area). During a real automatic network block, a same-user
  program can make it permanent until the owner restores the internet. The owner can still do that at any time.
- Forwarded events (`forwardEvents`, anyLocal) about the caller's own processes and files can still produce behaviour
  detections. A forged ransomware burst still cuts the network for 10 minutes. The owner can restore it, and the policy
  allows a single ransomware signal on purpose. Provenance-aware scoring belongs to IPCAuthz / RealtimePipeline.
- With ad-hoc signing, the same-bundle helper rule and StaleHelper's "same signer" check rest on cdhashes and root
  ownership, not on a Team ID. Developer ID signing would make both stronger.
- Unpinned remote allowances still cover a Developer-ID-signed look-alike. Pins are taken whenever the tool is running
  at approval time.
- `BundleSeal` caches its result for 60 s per bundle, keyed on folder inode and mtime. An in-place content change that
  leaves folder mtimes alone needs root anyway, given the ownership rule.
