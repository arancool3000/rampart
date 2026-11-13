# WMS o4: network stack (DNS filter, DoH, pf, App Firewall)

Date: 2026-11-13. Scope: `Sources/RampartNetwork/**` and the DNS/blocklist side of the web layer. Regression suite:
`Sources/rampart-selftest/SelfTest+WMSo4.swift` (`wmso4`). Builds on hx4 (docs/security/harden-hx4.md), which already
fixed compression-pointer loops, label escaping, loopback-only bind, QR reflection, DoH answer validation/bailiwick,
pinning, cache keying, pf name injection and the DNS-restore watchdog API.

## Threat model

- **Local malware as the user**: floods 127.0.0.1:53, sends malformed or EDNS-abusing queries, holds TCP slots,
  squats unclaimed resolver addresses, names itself after RamPart to dodge the App Firewall, or deliberately
  touches Apple/RamPart destinations so that the user's "Block" hurts the Mac.
- **Hostile web page / DNS operator**: DNS rebinding (public name -> 127.0.0.1 / LAN / link-local, including via
  HTTPS-record address hints and IPv4-mapped/NAT64 IPv6 forms).
- **On-path attacker / bad upstream**: spoofed or poisoned answers. The upstream path is DoH over pinned TLS with
  ID 0 (RFC 8484) and exact question + bailiwick validation (hx4), so UDP ID/port guessing and 0x20 do not apply:
  there is no plaintext upstream leg to spoof.
- **Hostile feed**: IP lists that would cut off resolvers or IPv6-only networks.

## Findings

| # | Sev | Where | Issue | Fix | Status |
|---|-----|-------|-------|-----|--------|
| 1 | High | DNSFilterServer DoH path, `DNSRebindGuard` | No rebinding protection: any public name could resolve to 127.0.0.1, RFC 1918, 169.254.169.254, ULA/link-local, or `::ffff:127.0.0.1`, also via HTTPS/SVCB `ipv4hint`/`ipv6hint` and additional-section glue. A web page could then reach local services as same-origin. | Private answers for public names are stripped (empty NOERROR, CNAMEs kept), logged as `blocked` with list `rebind-guard`, and only the sanitised copy is cached. Exempt: local-only names (`.local`, `.lan`, `.home.arpa`, `.internal`, single-label...), well-known dev loopback domains (`lvh.me`, `localtest.me`, `nip.io`, `sslip.io`, `plex.direct`, `ts.net`...) and anything on the user's allowlist. CGNAT is not treated as private (VPN overlays). | Fixed + tests |
| 2 | High | DNSFilterServer `start` (IPv6 gap) | DNSSwitcher points the Mac at `127.0.0.1` **and** `::1`, but the filter only listened on 127.0.0.1. macOS lets any user bind ports below 1024, so local malware could bind `[::1]:53` and answer the Mac's lookups past the filter. | The filter also claims `[::1]` on the same port (UDP + TCP, best effort; logged if IPv6 is off on lo0). A squatter cannot bind it even with SO_REUSEPORT. | Fixed + test |
| 3 | Medium | DNSFilterServer `handle` (flood) | One global in-flight cap covered all work, so a random-subdomain flood starved cached and blocked names too, including the watchdog probe (`apple.com`). | Split limits: 2048 queued datagrams; 256 slots only for DoH lookups. Blocked, canary, bootstrap and cached answers never need an upstream slot. Over-limit upstream work is dropped (UDP, the stub retries) or SERVFAIL (TCP/API) and counted in `droppedOverload`. | Fixed + test |
| 4 | Medium | DNSFilterServer TCP | `SO_RCVTIMEO` restarts on every byte, so a slow-loris client trickling one byte every 9 s could hold all 32 TCP slots forever (TCP fallback for large answers dies). | Absolute deadlines with `poll`: 10 s idle between queries, 5 s for a whole message once its length arrived. | Fixed + test |
| 5 | Medium | DNSFilterServer / `DNSWire.upstreamQuery` | The client's raw packet went upstream: EDNS Client Subnet and other options (privacy leak / cache-poisoning surface), stray answer/authority/additional records, and the CD bit (which disables upstream DNSSEC validation, so bogus answers the upstream would SERVFAIL get through). | The upstream query is rebuilt from the question only: RD set, CD cleared, a fresh OPT (4096, DO bit kept) only if the client used EDNS. | Fixed + tests |
| 6 | Low | `DNSMessage` EDNS | Duplicate OPT, non-root OPT owner, and queries carrying answer/authority records were accepted; the advertised UDP size was unbounded (65,535). | FORMERR for those (RFC 6891 6.1.1), payload size clamped to 512...4096. | Fixed + tests |
| 7 | High | AppFirewall `plan` | Blocks are global (pf table + DNS), not per app. Malware that touched Apple, the DoH upstreams, the feed CDN, or the user's DNS server (e.g. 8.8.8.8) before any other app was seen using them would get those destinations blocked for the whole Mac when the user clicked Block, breaking updates, iCloud, RamPart's feeds, or DNS after the watchdog restores it (offline). | Protected destinations are never blocked: Apple's 17.0.0.0/8, Apple/RamPart/DoH/feed domains (and IPs the DNS log ties to them), the public resolvers, and the user's original DNS servers from the snapshot (`extraProtectedAddresses`, refreshed each tick in NetGuardWiring). The rule notes say why. | Fixed + test |
| 8 | High | AppFirewall `protectedKey` | "RamPart can't block itself" matched any path containing `/rampart.app/` or ending `/rampartd`, and "macOS" included `/usr/local/`. Malware could make itself unblockable by its name or by living in Homebrew's prefix. | Only RamPart's installed locations (`/Applications/Rampart.app`, `/Library/PrivilegedHelperTools/app.rampart.*`) and SIP paths outside `/usr/local` are protected. Apple-signed apps (signer check) are refused instead. | Fixed + test |
| 9 | Medium | PFManager `reservedRanges` / `protectedAddresses` | A feed could block NAT64 (`64:ff9b::/96`, `64:ff9b:1::/48`, every IPv4 site on an IPv6-only network) or the well-known public resolvers that the DNS watchdog falls back to. | Both are now un-blockable; `PFManager.alsoProtect` adds run-time addresses. | Fixed + test |
| 10 | Info | pf generation | Re-checked: anchor/table/path validators (hx4) hold; table entries are canonical address text only. | 20k-case fuzz added: sanitize never emits pf syntax characters; injection strings rejected. | Tested |
| 11 | Info | DNS watchdog (rampartd Integrations) | Re-checked: launch recovery, SIGTERM restore, 10 s probe with a real query, restore after 2 failed probes or an unhealthy upstream, re-apply when healthy. With finding 3 the probe keeps working under a local flood as long as `apple.com` is cached; with findings 7 and 9 neither the App Firewall nor a feed can block the servers it restores to. | No change needed in the daemon. | Reviewed |

## Residual risks (honest limits)

- **No NetworkExtension**: anything that does its own DoH/DoT to a hard-coded IP, or plain DNS to a hard-coded
  server, bypasses the filter. pf `forceLocalDNS`/`blockDoT` exist but are off: blocking port 53 would break VPN
  split DNS and, combined with the watchdog's restore, could leave the user offline. Firefox is handled by the
  `use-application-dns.net` canary.
- **Fail-open by design**: a local process that makes the DoH upstream fail (e.g. driving it into rate limiting)
  trips the watchdog, which hands DNS back to the system. That is the right call (never offline) but it is a way
  to turn the filter off; it is visible (logged, Network screen).
- **Random-subdomain floods** still use up the 256 upstream slots, so new uncached names stall while it lasts;
  cached and blocked names keep working.
- **Rebinding exemptions** (`nip.io`, `sslip.io`, `lvh.me`...) can be abused by an attacker too; they exist so the
  user's dev tools keep working. CGNAT (100.64/10) and public IPs that NAT back to the Mac are not covered.
- **App Firewall** is still by destination: an IP shared with a not-yet-seen app (CDN) can be blocked for both.
  The protected list covers macOS/RamPart, not every third-party app.
- **If rampartd never comes back** after a crash while DNS points at 127.0.0.1, nothing can restore DNS until the
  next launch (launchd KeepAlive restarts it, and `recoverAtLaunch` runs first).
- Ad-hoc signing and no Endpoint Security are unchanged platform limits.

## Outside the owned area

- `Sources/rampartd/Core/NetGuardWiring.swift` `tick()`: 5 lines that feed the DNS snapshot's original servers to
  `firewall.extraProtectedAddresses`.
