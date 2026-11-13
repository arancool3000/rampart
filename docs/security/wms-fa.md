# wms-fa: privilege boundaries and cross-component attack chains (2026-11-13)

Scope: `Sources/rampartd/Core/IPCAuthz.swift`, `Core/Router.swift`, `IPCServer.swift`, `RampartShared/DaemonPeerPolicy.swift`,
`RampartShared/IPC.swift` (read; unchanged), the peer trust in the app (`DaemonPeerTrust`), the CLI (`SocketTransport`), the
secure browser (`BrowserDaemonClient`) and `rampart-nmh`. Tests: `SelfTest+WMSfa.swift` (`wmsfa`).

## Trust graph

| Peer | Runs as | Talks to | Verified how |
|---|---|---|---|
| root daemon (`/Library/PrivilegedHelperTools/app.rampart.daemon`) | root | user helper socket (`forwardEvents` for decoy events) | the helper accepts uid 0 unconditionally |
| user helper (`Rampart.app/Contents/Helpers/rampartd --user`, LaunchAgent) | login user | nothing (it only listens) | app: bundled helper's designated requirement over `LOCAL_PEERPID`; CLI / browser / nmh: `DaemonPeerPolicy` |
| app (`app.rampart.app`) | login user | root socket first, then user socket | root daemon: audit-token code identity (`ClientIdentity`), admin group, console owner; user helper: **now** audit-token identity + bundle cdhash pins |
| CLI (`app.rampart.cli`) | login user or root (`sudo`) | same | same, plus an admin-confirmed settings session for weakening calls |
| nmh (`app.rampart.nmh`, launched by the browser) | login user | root socket, else user socket | `anyLocal` / `sessionUser` calls only; **now** verifies the daemon behind the socket |
| secure browser | login user | same | `scan` and `status` only |
| anything else (scripts, raw sockets, re-signed copies) | login user / other users | root socket (0666) and, as the same user, the user socket (0600) | kernel credentials only |

Levels (`IPCAuthz.level` / `denial`): anyLocal < sessionUser < adminClient < adminClientWeakening. Root passes everything; the
root daemon's matrix is unchanged from hx10 except where noted below. The user helper **now** has its own column set
(`denial(..., userMode: true)`): same-uid peers get anyLocal and sessionUser; adminClient needs the verified app or CLI;
adminClientWeakening from the CLI needs a settings session. Enforcement is on only for a packaged helper (hardened runtime,
strict signature, identifier `app.rampart.daemon`); a `swift build` helper keeps the old same-uid behaviour.

## Findings

| # | Sev | Where | Chain | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | `IPCServer.swift:189`, `Router.handle` | The user helper applied no authorization at all (`requireAdminForPrivileged: !userMode`, client identity never read). Any same-user process (a malicious npm script, a compromised app, a browser-driven helper) could, with ten lines over the 0600 socket: `downloadGateSetEnabled(false)`, `downloadGateDecide(allow: true)` (give a held download its execute bit back), `mediaGuardSetEnabled(false)`, `deceptionRemoveAll`, `setRealtime(false)`, `restore(allow: true)` / `exportQuarantined` from the user vault, `requestDisableProtection` (tokens were issued without authorization in user mode) and `vpn disconnect`. | The packaged helper reads the peer's code identity through the audit token like the root daemon, and additionally pins the cdhashes of the app and CLI that ship in its own bundle (`IPCAuthz.siblingClientPins`), so an ad-hoc look-alike identifier is not enough. `IPCAuthz.denial(userMode:)` applies the client gate without the admin/console columns (a standard user owns their helper). | Fixed |
| 2 | High | `Router.forwardEvents`, `IPCAuthz.sanitizeForwarded` | `forwardEvents` is anyLocal. A non-root peer could feed forged telemetry about its own processes with a forged image path (`/Applications/Safari.app/...`, a root-owned binary) and forged parent ("the browser spawned me"), steering lineage rules, trust multipliers and the kill target; two forged behaviour rule hits corroborate each other, a "ransomware burst" passes `EmergencyNetworkPolicy`, and the root daemon cuts the whole Mac's network with pf and suspends processes. | Non-root forwarding needs a verified RamPart client (the app's PasteGuard is the only legitimate one; the root daemon's DecoyForwarder is root): `IPCAuthz.forwardDenial`. The image path and parent now come from the kernel (`proc_pidpath`, sysctl ppid) and an event whose pid is gone is dropped. | Fixed |
| 3 | High | `IPCAuthz.level(.vpn)` | `importConfig` and `setupHome` were "strengthening" (adminClient): malware running the real CLI (a verified client, admin user, no password) could import its own WireGuard endpoint and `connect`, routing all traffic and DNS of the Mac through the attacker's server. | Every VPN op except `status` and `connect` is adminClientWeakening (CLI needs the administrator prompt; the app, which already asks the user, is exempt as before). A test ties the matrix to `VPNOp.allCases`. | Fixed |
| 4 | Medium | `IPCAuthz.level(.emergencyNetwork(keep: true))` | sessionUser: any console process could make a 10-minute automatic network block permanent; an administrator must then authenticate to get the internet back. | adminClient (RamPart's own clients only). | Fixed |
| 5 | Medium | `IPCAuthz.settingsWeaken` | A new exclusion was not weakening, so the CLI could add a narrow one (e.g. `~/Downloads/drop`) with no confirmation and hide a payload folder from the scanner. | Any new exclusion weakens (matches RampartAI's mirror, wms-o5). Removal stays free. | Fixed |
| 6 | Medium | `rampart-nmh/main.swift` `RampartdBridge.roundTrip` | The native messaging host connected to whatever listened on the socket path with no peer check. Same-user malware squatting the user socket could answer every blocklist lookup "not listed" and swallow every reported warning. | `DaemonPeerPolicy.connectedPeerProblem` before the first byte, as in the app, CLI and browser. | Fixed |
| 7 | Medium | `DaemonPeerPolicy.peerLooksLikeDaemon` | A packaged CLI or nmh accepted the development identifiers `rampartd` / `rampartd-<hash>`: any same-user binary ad-hoc signed as `rampartd-x` passed as the daemon. | `daemonIdentifierAcceptable`: a packaged client (`app.rampart.*`) accepts only `app.rampart.daemon` with hardened runtime; development clients still accept development daemons. | Fixed |
| 8 | Info | `GuardWiring.requestDisable` / `redeem` | A disable token is not bound to a purpose at issue time: a token obtained for a settings session can be redeemed for `uninstall`. Both calls come from the same process that already holds the admin authorization, so no cross-process gain. | Needs owner (RampartGuard): record the purpose in the token body. | Needs owner |
| 9 | Info | `Emergency.authorize` | Redeeming an admin token for `killSwitch` / `restoreNetwork` opens a 5-minute settings session for the app process. The app is exempt from the session anyway. | None. | OK |
| 10 | Info | token flow | Tokens: single use, uid-bound, MAC'd, 120 s TTL; settings session bound to pid + pidversion; identity read at connect time through the audit token (a reused pid or an exec never inherits it). Replay and TOCTOU reviewed, nothing new. | None. | OK |

## Residual risks (honest limits)
- Ad-hoc signing: an identifier is forgeable. The root daemon has optional install pins (`trusted-clients.json`); the user helper now pins its bundle siblings. A same-user attacker who can rewrite and re-sign the installed bundle still wins; macOS App Management is what stops that.
- Malware running as the user can still do whatever the real app can do without a password, because the GUI app is exempt from the settings session (a script cannot drive it without an Accessibility grant). The CLI needs the administrator prompt for every weakening call.
- A process may hand its connected socket to another process; identity is taken at connect time.
- Development helpers (`swift build`) accept any same-uid peer, as before. Every shipped copy is packaged by `scripts/build.sh` with `--options runtime`.
- No Endpoint Security / NetworkExtension entitlements: none of this blocks anything before exec; it only decides who may drive the daemons.

## Tests
`wmsfa`: every IPCRequest case parsed from Models.swift has a sample and an explicit level (new cases fail the test until added);
matrix monotone and refusals per column; every off/allow/restore/remove/disconnect direction is adminClientWeakening; VPN ops
versus `VPNOp.allCases`; user-mode matrix (9 columns × 4 levels) and the concrete chain requests; enforcement switch and sibling
pins; forwarding gate and kernel-truth sanitizing (live pid); daemon identifier policy; source invariants for Router, IPCServer,
nmh, CLI and browser.
