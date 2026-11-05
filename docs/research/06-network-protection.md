# 06 - Network & Web Protection without NetworkExtension

Researched 2026-11-05 for Bastion (Swift, SwiftPM, no Xcode, no `com.apple.developer.networking.networkextension` entitlement).

## 0. Constraints and what they rule out

| Mechanism | Needs NE entitlement? | Needs root? | Needs Xcode/appex? | Verdict |
|---|---|---|---|---|
| NEFilterDataProvider / NEDNSProxyProvider / NEPacketTunnel | Yes | - | Yes (system extension) | Not available |
| `pf` (pfctl anchors + tables) | No | Yes | No | **Use** - IP blocking |
| Local DNS proxy on 127.0.0.1:53 + `networksetup -setdnsservers` | No | Yes (port 53, networksetup) | No | **Use** - primary web protection |
| `.mobileconfig` DNS Settings payload (DoH/DoT) | No | User approval in System Settings | No | Optional - lets OS do encrypted DNS to *our* or a vendor resolver |
| `/etc/hosts` | No | Yes | No | Fallback only (no wildcards, slow with 100k+ lines) |
| Safari Content Blocker | No | No | Yes - app extension inside a signed .app | Phase 2 (can be built with `xcodebuild`-less tooling only with effort; see 6) |
| Chrome/Firefox WebExtension | No | No | No | **Use** for phishing warning UI |
| `socketfilterfw` (Application Firewall) | No | Yes | No | **Use** for inbound hardening/report |
| `nettop` / `lsof -i` / `netstat` polling, `proc_pidfdinfo` | No | Root for other users' procs | No | **Use** for connection monitor |

Key point: DNS filtering at 127.0.0.1 + pf IP table gives roughly 90% of what a NEFilter would, minus per-flow, per-process enforcement. Per-process attribution is done passively (polling), not enforced.

## 1. pf (packet filter)

- macOS ships pf with `/etc/pf.conf` that already contains `anchor "com.apple/*"`. Do **not** edit `/etc/pf.conf` (overwritten on OS updates, SIP-adjacent). Instead, load our own anchor under the Apple namespace or reference our own anchor via `pfctl -a`.
- Anchors under `com.apple/*` are evaluated because of the wildcard; a custom name like `com.apple/250.Bastion` is the common trick used by tools (e.g., Murus, LuLu-adjacent scripts, Little Snitch doesn't use pf). Alternative: load a full ruleset with `pfctl -f /Library/Application Support/Bastion/pf.conf` that includes Apple's lines plus ours (more invasive).
- pf is reference-counted: `pfctl -E` returns a token; `pfctl -X <token>` releases it. Use `-E` (not `-e`) so we don't disable pf for other users of it.
- Tables scale to hundreds of thousands of entries and are updated atomically: `pfctl -a <anchor> -t <table> -T replace -f file`.

Example anchor rules (`/Library/Application Support/Bastion/pf.anchor`):
```
table <bastion_block> persist file "/Library/Application Support/Bastion/block_ips.txt"
block drop out quick log proto { tcp udp } from any to <bastion_block>
block drop in  quick log from <bastion_block> to any
# Force DNS to our resolver (prevents apps bypassing with hard-coded 8.8.8.8). Optional, aggressive:
# block drop out quick proto { tcp udp } from any to ! 127.0.0.1 port 53
# Block DoT to prevent bypass (port 853); DoH can't be blocked by port - use DoH resolver IP table instead
# block drop out quick proto tcp to any port 853
```
Commands:
```
sudo pfctl -a com.apple/250.Bastion -f "/Library/Application Support/Bastion/pf.anchor"
sudo pfctl -E                           # prints "Token : NNNN" - persist it
sudo pfctl -a com.apple/250.Bastion -t bastion_block -T replace -f block_ips.txt
sudo pfctl -a com.apple/250.Bastion -s rules
sudo pfctl -a com.apple/250.Bastion -t bastion_block -T show | wc -l
sudo pfctl -a com.apple/250.Bastion -F all   # remove our rules
sudo pfctl -X <token>                    # release enable reference
```
Logging: `log` keyword sends to `pflog0`; create with `sudo ifconfig pflog0 create` and read via `tcpdump -n -e -ttt -i pflog0`. Rules reset at reboot -> re-apply from a LaunchDaemon (`RunAtLoad`).

IP feeds suitable for pf: Spamhaus DROP (`https://www.spamhaus.org/drop/drop.txt` - moved to `https://www.spamhaus.org/drop/drop_v4.json` / `drop_v6.json`), Feodo Tracker C2 (`https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`), FireHOL level1 (`https://iplists.firehol.org/files/firehol_level1.netset`), ThreatFox IOCs. Avoid aggressive lists (FireHOL level1 includes bogons/private ranges - strip RFC1918 before loading or you will break LANs).

## 2. DNS-level filtering (primary mechanism)

### Architecture
1. A root LaunchDaemon `com.bastion.dnsd` binds UDP+TCP `127.0.0.1:53` (and `::1`). Pure Swift using `Network.framework` `NWListener` (UDP) works without entitlements; or embed a small Go/Rust resolver - but Swift keeps the build simple.
2. For each query: normalise name, check allowlist -> blocklist (suffix/wildcard match in a compact set: sorted array of reversed labels, or a hash set walked label by label) -> on block reply `0.0.0.0`/`::` (or NXDOMAIN; 0.0.0.0 is faster for browsers) with TTL 60, or the IP of a local "blocked" page server.
3. Otherwise forward upstream over **DoH** (RFC 8484, `POST https://<resolver>/dns-query`, `Content-Type: application/dns-message`) via `URLSession` with HTTP/2 keep-alive. Cache by TTL.
4. Point every network service at us:
```
networksetup -listallnetworkservices
networksetup -getdnsservers "Wi-Fi"            # save original (may be "There aren't any DNS Servers set")
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1 ::1
sudo networksetup -setdnsservers "Wi-Fi" empty  # restore DHCP
sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
scutil --dns                                     # verify resolver order
```
   Apply to every service (Wi-Fi, Ethernet, Thunderbolt Bridge, USB LAN). Watch for new interfaces with `SCDynamicStore` notifications on `State:/Network/Global/IPv4` and re-apply.
5. Fail-open: if dnsd crashes, DNS breaks for the whole machine. Mitigations: launchd `KeepAlive`, a watchdog that restores original DNS if the daemon is unhealthy for >5 s, and restore on uninstall.

### Caveats / bypasses
- Browsers with built-in DoH (Chrome "Secure DNS", Firefox TRR) bypass system DNS. Chrome auto-upgrades only if the system resolver is a known DoH provider - with 127.0.0.1 it stays on system DNS. Firefox: deploy policy `/Applications/Firefox.app/Contents/Resources/distribution/policies.json` with `"DNSOverHTTPS": {"Enabled": false, "Locked": true}` or rely on canary domain `use-application-dns.net` -> return NXDOMAIN to disable Firefox auto-DoH. Chrome: managed pref `DnsOverHttpsMode=off` via `/Library/Managed Preferences` (needs profile) - otherwise just document.
- iCloud Private Relay bypasses local DNS for Safari: answer `mask.icloud.com` and `mask-h2.icloud.com` with NXDOMAIN (Apple's documented network opt-out signal) when the user enables "strict" mode.
- VPN clients override DNS; detect via `scutil --dns` and warn.
- Hard-coded resolvers in malware: pf rule redirecting/blocking outbound :53 not to 127.0.0.1 (see pf section).

### Upstream resolvers (DoH)
| Provider | Filtering | DoH URL | Plain IPs |
|---|---|---|---|
| Cloudflare 1.1.1.2 | Malware | `https://security.cloudflare-dns.com/dns-query` | 1.1.1.2, 1.0.0.2, 2606:4700:4700::1112 |
| Cloudflare 1.1.1.3 | Malware + adult | `https://family.cloudflare-dns.com/dns-query` | 1.1.1.3, 1.0.0.3, 2606:4700:4700::1113 |
| Quad9 | Malware/phishing (threat-intel from ~20 feeds) | `https://dns.quad9.net/dns-query` | 9.9.9.9, 149.112.112.112, 2620:fe::fe |
| Quad9 + ECS | same | `https://dns11.quad9.net/dns-query` | 9.9.9.11 |
| Cloudflare unfiltered | none | `https://cloudflare-dns.com/dns-query` | 1.1.1.1 |

Blocked responses: Cloudflare 1.1.1.2/3 return `0.0.0.0`; Quad9 returns NXDOMAIN with no AA flag. Use a filtering upstream as a second, free reputation layer on top of local lists. Both free for commercial device use (check ToS: no reselling of the resolver as a product).

### Blocklists (domain level)
| List | Purpose | URL (raw) | Format | Update cadence |
|---|---|---|---|---|
| HaGeZi TIF (Threat Intelligence Feeds) | malware, phishing, C2, scams | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt` | one domain/line, wildcard semantics (blocks subdomains) | daily 11:00 UTC on GitHub/jsDelivr; mirror every 4-8 h |
| HaGeZi TIF medium (smaller) | same, fewer FPs | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif.medium-onlydomains.txt` | domains | daily |
| HaGeZi Pro (ads/trackers + some threat) | optional ad/tracker blocking | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt` | domains | daily |
| HaGeZi Pro++ / Ultimate | aggressive | `.../wildcard/pro.plus-onlydomains.txt`, `.../wildcard/ultimate-onlydomains.txt` | domains | daily |
| HaGeZi adblock syntax | same lists | `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/tif.txt` | `||domain^` | daily |
| StevenBlack unified | ads+malware | `https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts` | hosts (`0.0.0.0 domain`) | several times/week |
| URLhaus hostfile | active malware distribution hosts | `https://urlhaus.abuse.ch/downloads/hostfile/` | hosts (`127.0.0.1 host`) | regenerated every 5 min (poll <= every 5 min; hourly is fine) |
| URLhaus online URLs | full URLs (for browser ext.) | `https://urlhaus.abuse.ch/downloads/text_online/` | URL/line | 5 min |
| URLhaus RPZ | DNS RPZ zone | `https://urlhaus.abuse.ch/downloads/rpz/` | RPZ | 5 min |
| malware-filter URLhaus (domain-only mirror, no auth) | | `https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt` | hosts | 2x daily |
| Phishing Army extended | phishing (PhishTank+OpenPhish+...) | `https://phishing.army/download/phishing_army_blocklist_extended.txt` | domain/line | every 6 h |
| oisd big | ads+malware, low-FP | `https://big.oisd.nl/domainswild2` | wildcard domains | daily |
| oisd small | lighter | `https://small.oisd.nl/domainswild2` | wildcard domains | daily |
| oisd NSFW (family mode) | adult | `https://nsfw.oisd.nl/domainswild2` | wildcard domains | daily |

Format handling in the parser: strip comments (`#`, `!`), handle `0.0.0.0 x`, `127.0.0.1 x`, bare `x`, `||x^`, `*.x`; lowercase; IDNA punycode; drop `localhost`, `local`, `broadcasthost`. Dedupe across lists; tag source for "why blocked". Use `ETag`/`If-Modified-Since`; ship a baked-in snapshot so first run is protected. Licences: HaGeZi GPLv3, StevenBlack MIT, oisd own licence (free; commercial redistribution - check), Phishing Army CC BY-NC 4.0 (**non-commercial** - needs permission for a paid product), URLhaus CC0. Note: during research, `urlhaus-api.abuse.ch` was blocked by a Securly web filter on this network - expect similar on school/corp networks and handle fetch failures gracefully.

Memory: TIF ~ 600k-1M domains; a Swift `Set<String>` costs ~60-100 MB. Better: sorted, reversed-label array mmapped from disk and binary searched (~20-30 MB), or a Bloom filter (1% FP, ~1.2 MB/1M) with exact confirm.

## 3. Configuration profile for DNS (`com.apple.dnsSettings.managed`)

macOS 11+ supports encrypted DNS via profile, no entitlement needed. The user installs it by double-click then approves in System Settings > Privacy & Security > Profiles (cannot be silently installed without MDM; `profiles install` CLI is disabled since macOS 11). Payload:
```xml
<dict>
  <key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
  <key>PayloadIdentifier</key><string>com.bastion.dns</string>
  <key>PayloadUUID</key><string>GENERATED-UUID</string>
  <key>PayloadVersion</key><integer>1</integer>
  <key>DNSSettings</key>
  <dict>
    <key>DNSProtocol</key><string>HTTPS</string>
    <key>ServerURL</key><string>https://security.cloudflare-dns.com/dns-query</string>
  </dict>
  <key>OnDemandRules</key><array><dict><key>Action</key><string>Connect</string></dict></array>
  <key>ProhibitDisablement</key><false/>
</dict>
```
Use cases: (a) "lite" mode without a daemon - OS sends DoH straight to Cloudflare Security / Quad9 / a future Bastion cloud resolver; (b) cannot point at `127.0.0.1` over HTTPS without a trusted TLS cert, so it is an alternative to - not a complement of - the local proxy. Profile DNS overrides `networksetup` settings.

## 4. /etc/hosts

- `sudo` write `0.0.0.0 bad.example` lines between `# BEGIN BASTION` / `# END BASTION` markers; flush with `dscacheutil -flushcache; killall -HUP mDNSResponder`.
- No wildcard; each subdomain must be listed. mDNSResponder handles ~100k lines OK, but 1M lines slows lookups and boot. Use only as fallback (<=50k highest-confidence entries, e.g. URLhaus + Phishing Army) when the daemon is disabled.
- Also **monitor** /etc/hosts for tampering (malware adds entries redirecting banking / update / AV domains): FSEvents on `/etc` (actually `/private/etc/hosts`) and diff.

## 5. Connection monitoring (passive, per-process)

| Tool | Command | Notes |
|---|---|---|
| lsof | `sudo lsof -nP -iTCP -iUDP -FpcnPT` | machine-parsable (`-F`), gives pid, command, local->remote, state. ~100-300 ms; poll every 5-10 s |
| nettop | `nettop -P -L 1 -J bytes_in,bytes_out -x` / `nettop -m tcp -L 1 -n -x` | per-process byte counts, CSV with `-L`; no root needed for own user |
| netstat | `netstat -anv -p tcp` / `netstat -anv -p udp` | `-v` shows pid on recent macOS; fast |
| libproc (native) | `proc_listallpids` + `proc_pidinfo(PROC_PIDLISTFDS)` + `proc_pidfdinfo(PROC_PIDFDSOCKETINFO)` | best: no subprocess, gives socket tuples per pid. Root for other users' processes |
| Endpoint Security | `ES_EVENT_TYPE_NOTIFY_*` has no socket connect events | ES needs entitlement anyway |

Pipeline: snapshot tuples -> join with DNS log from dnsd (IP -> queried name, last N min) -> score (blocklist IP/domain, unsigned binary contacting rare host, `codesign -dv` team ID, non-standard ports, Tor 9001/9050, high-volume upload) -> alert. Also check local IP against Feodo/ThreatFox IP table.

## 6. Safari content blockers / Safari Web Extension

- Content Blocker = `com.apple.Safari.content-blocker` app extension (`.appex`) inside a signed `.app`, JSON rules (`trigger.url-filter`, `action.type: block`), max 150k rules per extension (Safari 15+). Must be enabled by user in Safari > Settings > Extensions.
- Requires an app extension bundle. Possible without Xcode IDE: build appex with `swiftc` + hand-written Info.plist (`NSExtensionPointIdentifier = com.apple.Safari.content-blocker`), place in `Bastion.app/Contents/PlugIns/`, codesign with Developer ID + entitlements (`com.apple.security.app-sandbox`, app group). Needs a paid Apple Developer account, notarization, and is fiddly - **Phase 2**. `xcrun safari-web-extension-converter` needs Xcode.
- Rule updates: host app writes JSON to the shared app-group container then calls `SFContentBlockerManager.reloadContentBlocker(withIdentifier:)`.
- Safari Web Extension (JS) for phishing banners also needs the appex wrapper.

## 7. Browser extension (Chrome/Edge/Brave/Firefox) for phishing warnings

- Manifest V3 extension: `declarativeNetRequest` dynamic rules (up to 30k dynamic + 330k static rules) for URL-level blocks the DNS layer can't express (path-level phishing URLs from URLhaus/PhishTank).
- `webNavigation.onCommitted` -> send URL to Bastion via **Native Messaging** (`/Library/Google/Chrome/NativeMessagingHosts/com.bastion.host.json` system-wide, or `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/`; Firefox: `/Library/Application Support/Mozilla/NativeMessagingHosts/`). Host = small Swift CLI speaking length-prefixed JSON on stdin/stdout.
- Show interstitial (redirect to extension page `blocked.html?u=...`) with "go back"/"proceed anyway".
- Heuristics in-extension: punycode/homoglyph domains, brand keyword in subdomain of new domain, password field on non-HTTPS or on domain not matching brand, newly registered domain (via Bastion lookup).
- Distribution: Chrome Web Store (unlisted is fine) + force-install via `ExtensionInstallForcelist` needs managed prefs (MDM/profile); otherwise prompt user. Firefox AMO signing required.

## 8. Application firewall (`socketfilterfw`)

Path `/usr/libexec/ApplicationFirewall/socketfilterfw` (root for setters):
```
socketfilterfw --getglobalstate          # Firewall is enabled/disabled (State = 0/1/2)
sudo socketfilterfw --setglobalstate on
sudo socketfilterfw --setstealthmode on   # no ICMP/closed-port replies
sudo socketfilterfw --setblockall on      # block all incoming (strict)
sudo socketfilterfw --setallowsigned on   # auto-allow Apple-signed
sudo socketfilterfw --setallowsignedapp off  # do not auto-allow downloaded signed apps
sudo socketfilterfw --setloggingmode on
socketfilterfw --listapps
sudo socketfilterfw --add /path/App.app ; sudo socketfilterfw --blockapp /path/App.app
```
Inbound only (no outbound control). On macOS 15+ some setters print a note that settings are managed via System Settings; global state also readable via `defaults read /Library/Preferences/com.apple.alf globalstate` (legacy) - prefer the CLI. Use in "Security Checkup": firewall off -> one-click fix.

## 9. Open ports on the Mac

```
sudo lsof -nP -iTCP -sTCP:LISTEN        # TCP listeners with process
sudo lsof -nP -iUDP                     # UDP sockets
netstat -anv -p tcp | grep LISTEN
```
Flag listeners bound to `*`/`0.0.0.0`/`::` (exposed to LAN) vs `127.0.0.1`. Known-benign: `rapportd`, `ControlCenter` (AirPlay 5000/7000), `sharingd`, `mDNSResponder` 5353. Flag: Remote Login 22 (`sudo systemsetup -getremotelogin`), Screen Sharing 5900 (`launchctl print system/com.apple.screensharing`), File Sharing 445/548, unexpected high ports from unsigned binaries, Remote Management (ARDAgent). Correlate pid -> path (`proc_pidpath`) -> `codesign -dv --verbose=2`.

## 10. Rogue Wi-Fi / evil twin / ARP spoofing

Data sources (no root needed except where noted):
- CoreWLAN (`CWWiFiClient.shared().interface()`): `ssid()`, `bssid()`, `security()`, `rssiValue()`, `wlanChannel()`, `scanForNetworks(withName:)`. **SSID/BSSID require Location Services permission** since macOS 14 (otherwise nil) - the app must request `CLLocationManager` authorization and be a bundled .app with `NSLocationUsageDescription`.
- `airport` CLI was removed in macOS 14.4; use `system_profiler SPAirPortDataType -json` (slow, ~1-2 s) or `wdutil info` (root) as fallbacks.
- `ipconfig getsummary en0`, `ipconfig getpacket en0` (DHCP server id, router, DNS offered).
- `arp -an`, `route -n get default`, `ndp -an` (IPv6).

Detections:
1. **Evil twin**: remember (SSID -> set of BSSIDs, security type, channel, router MAC, DHCP server IP, gateway's TLS/HTTP fingerprint) per known network. Alert on same SSID with downgraded security (WPA2 -> Open/WEP), new BSSID with different OUI vendor, or scan showing two APs with same SSID but different security.
2. **Open / weak Wi-Fi**: `security()` in [.none, .WEP, .dynamicWEP, .wpaPersonal (TKIP)] -> warn; captive portal detection.
3. **ARP spoofing**: poll `arp -an` every 10 s; alert if gateway IP's MAC changes from the learned value, or if two IPs map to the same MAC (attacker claiming gateway + others), or gateway MAC OUI is a laptop vendor. Optionally passive sniff with BPF (`/dev/bpf*`, root) for gratuitous ARP floods.
4. **DHCP/DNS hijack**: DHCP-offered DNS server not in RFC1918/gateway and not expected; DNS answers for known domains (e.g. `apple.com`) differ from DoH answer -> local DNS tampering.
5. **Rogue gateway / MITM**: TLS check against a pinned host (Bastion API) - cert chain anomaly means interception (corporate proxies are a FP source).
6. **IPv6 RA spoofing**: `ndp -rn` unexpected default router.
Mitigation suggestion: auto-enable strict DoH upstream (already done by dnsd) and suggest VPN on untrusted networks.

## 11. Reputation lookups

### Google Safe Browsing
- **v4 Update API** (`https://safebrowsing.googleapis.com/v4/threatListUpdates:fetch`, `.../v4/fullHashes:find`) still answers but Google positions **v5** as current; v4 described as legacy "allow-by-default".
- **v5**: `GET https://safebrowsing.googleapis.com/v5/hashes:search?key=API_KEY&hashPrefixes=<base64 4-byte prefix>` (privacy-preserving real-time mode); local list mode: `GET /v5/hashLists:batchGet?names=se&names=mw...`, `GET /v5/hashList/{name}`; `urls:search` (v5alpha1) sends raw URLs.
- **Licence: Safe Browsing API is non-commercial only.** A paid antivirus must use **Google Cloud Web Risk API** (`https://webrisk.googleapis.com/v1/uris:search?threatTypes=MALWARE&threatTypes=SOCIAL_ENGINEERING&uri=...&key=...`, plus `hashes:search` and `threatLists:computeDiff`). Web Risk pricing: first 100k calls/month free, then ~$0.50 per 1,000 (verify on cloud.google.com/web-risk/pricing). Do not ship Safe Browsing keys in a commercial build.

### URLhaus (abuse.ch)
- API now requires a free **Auth-Key** (abuse.ch Authentication Portal) in header `Auth-Key: <key>`; 401 without, 403 `unknown_auth_key` if wrong.
- `POST https://urlhaus-api.abuse.ch/v1/url/` form `url=<url>`; `POST /v1/host/` form `host=<host>`; `POST /v1/payload/` form `sha256_hash=`; `GET /v1/urls/recent/`.
- Free under fair use; commercial use may require abuse.ch commercial subscription - contact them. Prefer bulk downloads (section 2) over per-URL calls.

### PhishTank
- Registrations for new API keys have been closed/intermittent for years; data feed `http://data.phishtank.com/data/<app_key>/online-valid.json` (hourly). Treat as unreliable - use Phishing Army (aggregates PhishTank + OpenPhish) or OpenPhish community feed `https://openphish.com/feed.txt` (free, non-commercial, 12h refresh) instead.

### Others worth adding
- ThreatFox IOCs: `https://threatfox.abuse.ch/export/json/recent/` (Auth-Key for API).
- Feodo Tracker IPs (pf): `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`.
- DNS-based reputation: query `domain` via 1.1.1.2 and 9.9.9.9; `0.0.0.0`/NXDOMAIN while 1.1.1.1 resolves => flagged.

## 12. Dark-web / breach monitoring (Have I Been Pwned)

### API v3 (email breaches) - needs paid key
- Base `https://haveibeenpwned.com/api/v3/`
- Headers: `hibp-api-key: <key>`, `user-agent: Bastion/1.0` (required, else 403).
- `GET /breachedaccount/{urlencoded email}?truncateResponse=false&includeUnverified=true` -> 200 JSON array of breaches, **404 = not pwned**, 429 with `retry-after`.
- `GET /pasteaccount/{email}`; `GET /breaches` (all, no key), `GET /breach/{name}`, `GET /latestbreach`, `GET /dataclasses` (no key).
- Domain search `GET /breacheddomain/{domain}` (domain must be verified in HIBP dashboard).
- Ethics: verify the user owns the email (send a confirmation code) before searching; never let a user search arbitrary addresses. Proxy through Bastion's backend so the API key is not in the app binary.

### Pricing (haveibeenpwned.com/Subscription, fetched 2026-11-05; annual billing)
| Plan | $/month | Email RPM | Notes |
|---|---|---|---|
| Core 1 | 4.39 | 10 | 1 domain, 25 breached addresses |
| Core 2 | 21.59 | 50 | |
| Core 3 | 36.99 | 100 | |
| Core 4 | 159 | 500 | |
| Core 5 | 319 | 1,000 | |
| Pro 1-5 | 379-4,599 | 1,000-16,000 | needed for third-party domain search (MSPs) |
| High RPM | 1,150-5,833 | 4,000-24,000 | |
Checking individual email addresses of your own users is permitted on any plan. A consumer AV with server-side caching (re-check each user weekly + on new-breach webhook via `/latestbreach` polling) fits Core 2-3 early on.

### Pwned Passwords (free, no key, unlimited)
- k-anonymity: `SHA1(password)` uppercase hex; send first 5 chars: `GET https://api.pwnedpasswords.com/range/{5 hex}` with header `Add-Padding: true`; response lines `SUFFIX35:COUNT` (padded entries have count 0). Match locally - password never leaves the device. `?mode=ntlm` for NTLM hashes.
- Swift: `Insecure.SHA1.hash(data:)` from CryptoKit.

## Recommended implementation

**Phase 1 (ship, no Xcode, no entitlements)**

1. **`bastion-dnsd` LaunchDaemon (root)** - Swift, `NWListener` UDP/TCP on 127.0.0.1:53 and [::1]:53; blocklist match -> `0.0.0.0`/`::` TTL 60; forward via DoH (`URLSession`, HTTP/2) to `https://security.cloudflare-dns.com/dns-query`, fallback `https://dns.quad9.net/dns-query`; LRU cache; query log (pid unknown - name, time, verdict) to SQLite for UI + connection join. Return NXDOMAIN for `use-application-dns.net` (disable Firefox auto-DoH) and optionally `mask.icloud.com`, `mask-h2.icloud.com`.
   ```
   # save originals then point every service at us
   for s in $(networksetup -listallnetworkservices | tail -n +2); do networksetup -getdnsservers "$s"; done
   sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1 ::1
   sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder
   # restore
   sudo networksetup -setdnsservers "Wi-Fi" empty
   ```
   (Handle service names with spaces by reading lines, not word-splitting.) Watchdog restores DNS if daemon unhealthy > 5 s.
2. **Lists** (updater in daemon, `ETag`, atomic swap, baked-in snapshot):
   - Default threat: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/tif-onlydomains.txt` (every 12 h)
   - `https://urlhaus.abuse.ch/downloads/hostfile/` (hourly)
   - `https://phishing.army/download/phishing_army_blocklist_extended.txt` (every 6 h) - **CC BY-NC: get permission before paid release**, else substitute HaGeZi TIF only
   - Optional ad/tracker toggle: `https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/pro-onlydomains.txt` or `https://big.oisd.nl/domainswild2`
   - Optional family toggle: upstream `https://family.cloudflare-dns.com/dns-query` + `https://nsfw.oisd.nl/domainswild2`
   - Store as sorted reversed-label array (mmap) for ~1M domains.
3. **pf IP blocking**:
   ```
   sudo pfctl -a com.apple/250.Bastion -f "/Library/Application Support/Bastion/pf.anchor"
   sudo pfctl -E      # keep token
   sudo pfctl -a com.apple/250.Bastion -t bastion_block -T replace -f "/Library/Application Support/Bastion/block_ips.txt"
   ```
   Feeds: `https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt`, `https://www.spamhaus.org/drop/drop_v4.json`, `https://www.spamhaus.org/drop/drop_v6.json`. Re-apply at boot from the daemon. Uninstall: `pfctl -a com.apple/250.Bastion -F all; pfctl -X <token>`.
4. **Connection monitor**: libproc (`proc_pidfdinfo` PROC_PIDFDSOCKETINFO) every 5 s, fallback `lsof -nP -iTCP -iUDP -F pcnPT`; join remote IP to dnsd log + pf/IOC tables; code-signing check of owning binary.
5. **Firewall + ports checkup**: `socketfilterfw --getglobalstate/--getstealthmode`, one-click `--setglobalstate on --setstealthmode on`; `lsof -nP -iTCP -sTCP:LISTEN` -> flag wildcard binds from unsigned/unknown binaries, Remote Login, Screen Sharing, File Sharing.
6. **Wi-Fi guard**: CoreWLAN + Location permission; per-SSID fingerprint (BSSID set, security, gateway MAC, DHCP server); `arp -an` poll every 10 s for gateway MAC change / duplicate MACs; warn on open/WEP/TKIP networks; DNS answer consistency check vs DoH.
7. **Hosts integrity**: FSEvents watch on `/private/etc/hosts`; alert on non-Bastion entries for banking/Apple/AV domains. Hosts-file blocking only as fallback mode (<=50k entries).
8. **Breach monitoring** (via Bastion backend, key never in app): `GET https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false` with `hibp-api-key` + `user-agent`; email ownership verified by code; start on Core 2 ($21.59/mo, 50 RPM), poll `GET https://haveibeenpwned.com/api/v3/latestbreach` hourly to trigger re-checks. Passwords on-device: `GET https://api.pwnedpasswords.com/range/{first5SHA1}` with `Add-Padding: true`.
9. **URL reputation** (backend, cached): Google **Web Risk** `https://webrisk.googleapis.com/v1/uris:search` (commercial-licensed; do NOT use Safe Browsing v4/v5 in a paid product), URLhaus `POST https://urlhaus-api.abuse.ch/v1/host/` with `Auth-Key`. Used for on-demand "check this link" and download-URL checks.

**Phase 2**
10. Chrome/Edge/Firefox MV3 extension + Native Messaging host (`/Library/Google/Chrome/NativeMessagingHosts/com.bastion.host.json`) for URL-path-level phishing interstitials and homoglyph heuristics.
11. Optional `.mobileconfig` "Lite mode" (`com.apple.dnsSettings.managed`, DoH to Cloudflare Security) for users who decline the daemon.
12. Safari content blocker appex (signed, notarized, app group) once Developer ID pipeline exists.

**Risks**: DNS daemon is a single point of failure (watchdog + restore mandatory); browser DoH/VPN/iCloud Private Relay bypass; list licences (Phishing Army NC, OpenPhish NC, Safe Browsing NC, URLhaus commercial terms); CoreWLAN SSID needs Location permission; web filters (e.g. Securly observed on this network) may block abuse.ch fetches.

## Sources
- https://github.com/hagezi/dns-blocklists
- https://developers.google.com/safe-browsing/reference
- https://cloud.google.com/web-risk/docs
- https://haveibeenpwned.com/Subscription , https://haveibeenpwned.com/API/v3
- https://www.troyhunt.com/the-have-i-been-pwned-api-now-has-different-rate-limits-and-annual-billing
- https://github.com/TundraSoft/tundra-connect/wiki/URLhaus-API (URLhaus Auth-Key requirement)
- https://urlhaus.abuse.ch/api/ , https://urlhaus.abuse.ch/downloads/
- https://phishing.army , https://oisd.nl , https://github.com/StevenBlack/hosts
- https://developers.cloudflare.com/1.1.1.1/setup/#1111-for-families , https://quad9.net/service/service-addresses-and-features
- Apple: Configuration Profile Reference - DNS Settings payload; `man pfctl`, `man networksetup`, `man nettop`
