# needs-network (from attack suite X1 — attacks on trust)

Fix proposals for the RampartNetwork owner (B7). Scenarios X1.12 and X1.17. The behaviour layer
catches an *untrusted local process* doing DoH (R45, CAUGHT in X1.12); these items are about the
resolver's own upstream trust, which the behaviour harness cannot exercise.

## Finding N-X1-1 (High): DoH upstream compromise / MITM poisons every lookup

**Where.** `DNSFilterServer` DoH upstream (security.cloudflare-dns.com, fallback dns.quad9.net)
via URLSession.

**Problem.** If the DoH upstream (or a rogue trusted root — see X1.10 behaviour catch R24) is
compromised or MITM'd, every answer RamPart returns is attacker-controlled, including the
hostnames RamPart itself uses for updates and feeds. A planted trust anchor makes a transparent
proxy invisible to URLSession.

**Proposed fix.**
1. Certificate-pin the DoH upstreams (pin the resolver leaf/intermediate SPKI; do not rely on the
   system trust store, which a rogue root defeats). Use a `URLSessionDelegate`
   `didReceive challenge` SPKI check.
2. Add a signed-response or DNSSEC sanity path for RamPart's own update/feed hostnames, or resolve
   them via a second independent pinned resolver and require agreement.
3. Keep / honour the `use-application-dns.net` NXDOMAIN canary and alert if an upstream answers it
   (indicates interception).

## Finding N-X1-2 (Medium): feed/blocklist fetch needs the same pinning

Blocklist and hash-feed fetches (HaGeZi TIF, URLhaus, MalwareBazaar) should share the pinned
session and signature verification (see needs-engine E-X1-1), so a hosts/DNS redirect (X1.11,
behaviour-CAUGHT as R25) or rogue root cannot silently swap feed content.

## X3-3 (Medium) — Reputation on outbound connections + first-POST exfil
Scenario S6/S3: a disguised "analytics" agent exfiltrates to a lookalike host (e.g.
`analytics-collector.test`) with a single HTTPS POST on first run. Today R46 beaconing needs ~30 min
and scores only 45, and the destination host's reputation is not consulted for outbound traffic.
Proposed: when `ConnectionMonitor` resolves a remote host for an untrusted process, run the host
through the existing blocklist trie + `URLAnalyzer` lookalike check; a connection from an untrusted
actor to a blocklisted/lookalike host emits a `.network` detection (score 60) even on the first
connection, and escalates to the stealer story (R40) if a credential-read stage already fired.
Self-test: feed one synthetic `networkConnect` event (untrusted actor → lookalike host) and assert a
detection; a connection to `www.apple.com` from the same actor does not trip it.
