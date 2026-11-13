# WMS-o9: Cat & Mouse network lure and VPN system layer

Scope: `Sources/rampart-lure`, `DeceptionTarpit`, `DeceptionContainment`, `DeceptionLure`; the non-crypto VPN code
(`TunnelIO`, `VPNSystem`, `WGConfig`, `VPNService`, `HomeServerSetup`). Regression suite: `wmso9`
(`Sources/rampart-selftest/SelfTest+WMSo9.swift`).

## Threat model
- **Lure:** an attacker on the LAN (or on the internet, if the user opted into "anywhere") connects to the tarpit
  over and over, sends malformed or huge input, floods connections from many source addresses, and tries to take
  over the helper and break out of it. Assume the helper process is fully compromised and check that each
  containment layer still holds.
- **VPN:** three attackers. (1) A malicious or compromised server or peer, or anyone on the internet who can reach the UDP
  port. (2) A hostile `.conf` (from a QR code or a pasted file) that tries to sneak arguments into
  ifconfig, route, scutil or pf, which all run as root. (3) Network churn: the tunnel drops, the daemon crashes, or the Mac roams.

## How the sandbox was verified
I ran the real `rampart-lure` under the generated profile on 127.0.0.1. Then I put a small C probe at the
helper path, under the same profile. The probe only reports whether each call is allowed; it touches nothing else. Before the fix it found:
`stat` of any home file **allowed**, AF_SYSTEM / AF_ROUTE sockets **allowed**, `kern.proc` (the full
process list) and `kern.hostname` **readable**, and **no unified-log output at all** from the sandboxed helper.
After the fix, all of these are denied. File reads and writes, fork, exec, outbound TCP and UDP, other ports
and mach services were already denied, and still are. The helper still serves and logs. The `wmso9` suite repeats the "serves
under the generated profile" check live, on loopback.

## Findings
| # | Sev | Finding | Status |
|---|-----|---------|--------|
| 1 | High | **The lure was effectively silent in production.** The sandbox did not allow `com.apple.logd`, so every `os_log` line (the attempt JSON the daemon reads) was dropped. Layer 10 (logging and alerting) did nothing. | Fixed: `com.apple.logd` allowed. Checked live with `log show`. |
| 2 | High | **pf rule injection via the subnet list.** `pfAnchor` and `LureHelperArgs.arguments` checked only the text before the "/". So a string like `"192.168.1.0/24 }\npass in quick all"` reached an anchor that is loaded as root. | Fixed: `LureAccessFilter.canonicalCIDR` (strict, canonical) is used everywhere. `TarpitServer` refuses invalid subnets. `ipv4()` no longer accepts `+1`. |
| 3 | Medium | **Sandbox info leaks after a compromise:** unrestricted `file-read-metadata` (could test whether `~/.ssh/id_*` or wallets exist), `system-socket` (kernel-control and routing sockets), and `sysctl` access to the process list and host name. | Fixed: metadata limited to the load paths, `system-socket` removed, those sysctls denied. |
| 4 | Medium | **Log, disk and alert flooding.** Every refused connection (rate, scope or concurrency limit) became a log line, a full `tarpit.json` rewrite and a High alert. One host could cause thousands per minute. | Fixed: `LureRefusalThrottle`. At most 1 record per peer per minute and 20 per minute in total; skipped ones are counted in the next record. |
| 5 | Medium | **The rate-limiter table had no upper bound.** It only dropped expired entries, so an attacker using more than 2048 source addresses within one minute could grow it without limit. | Fixed: hard cap. When the table is full, new peers are refused. |
| 6 | Low | The accept loop spun at 100% CPU on `EMFILE` (launchd caps the helper at 32 open files). | Fixed: waits 50 ms before retrying. |
| 7 | Low | No send timeout: a peer that never reads (zero receive window) could keep a session thread busy past the session deadline. | Fixed: `SO_SNDTIMEO` 5 s. |
| 8 | High | **VPN config injection.** `parseAddress` drops a `%zone` suffix but the raw text was kept. So `Endpoint = 1.2.3.4%x port 0:65535 ...:51820` was accepted and its text went into the kill-switch pf rule, which is loaded as root. The same applied to `DNS` (scutil script), `Address`, `AllowedIPs` and the home-server host. A leading `+` was also accepted in ports and prefix lengths. | Fixed: strict literals (hex digits, `.` and `:` only) stored in canonical form, strict ports and prefixes, limits on how many entries each field may have. The plan also fails closed on its own: if the endpoint or interface is not a valid literal, the pass rule is left out, and DNS and search domains are filtered again. |
| 9 | High | **IPv6 leak with an IPv4-only full tunnel** (`AllowedIPs = 0.0.0.0/0`). IPv6 still left through Wi-Fi when the kill switch was off. | Fixed: `leakBlockRoutes` sends `::/1` and `8000::/1` into the tunnel, where the peer drops them because they are outside AllowedIPs. This is not done when the endpoint itself is IPv6, to avoid a routing loop. The same applies the other way round for an IPv6-only full tunnel. |
| 10 | Medium | **Crash residue.** The endpoint's host route through the old gateway survived a daemon crash. The routes on the utun disappear when the kernel destroys the utun, but this one does not. | Fixed: `system-state.json` is written when the tunnel comes up and removed at teardown. `cleanupStale` (through `sweepStaleState`) deletes the leftover route, and ignores a state file that has been tampered with. |
| 11 | Low | **TunnelIO.** Non-IPv4/IPv6 packets were written to the utun as AF_INET. The family header from the utun was never checked. A zero-length datagram stopped the drain loop early, and an unbounded drain loop let a UDP flood starve the VPN queue (timers and teardown). | Fixed: `UTunDevice.frame` / `unframe` validate the packet. At most 256 packets are drained per event. |
| — | Info | **Banners:** fixed synthetic text only. No host name, user name or RamPart name, and attacker input is never echoed. The total reply is ≤ 2 KB, so the lure is TCP-only (cannot be spoofed) and gives negligible amplification. | Test added. |
| — | Info | **Malicious peer packets** (oversized, truncated, wrong type, replayed, inner source address forged, lying IP length) are all dropped, and a replay cannot take over the endpoint. | Test added (no code change needed). |

## Residual risks (honest)
- No NetworkExtension entitlement: the kill switch is pf only. If a connect fails at the start, everything is torn down
  and no kill switch is left in place. The user sees "failed", but traffic is not blocked.
- The pf rule `user _rampartlure` only matches TCP/UDP sockets. Blocking ICMP from the helper depends on the sandbox
  (`network-outbound` denied, which the probe confirmed).
- Not tested live: the pf anchor and the launchd plist. Loading them needs root, which agents are not allowed to use. I checked the generated text only.
  `RLIMIT_DATA` is not enforced by macOS; the watchdog's RSS check is the real memory cap.
- `sandbox-exec` / SBPL is deprecated by Apple but still works. It could change in a future macOS.
- Ad-hoc signing: anyone with root can replace the helper binary. That is outside this threat model.
- When the helper receives SIGTERM, sessions still in progress lose their attempt record.
