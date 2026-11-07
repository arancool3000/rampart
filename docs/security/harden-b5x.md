# harden-b5x: behaviour + telemetry fixes for attack sets X1/X4/X5/X6 (2026-11-07)

Owner files: Sources/RampartBehaviour/{DefaultRules,BehaviourEngine,PersistenceScanner,Support}.swift,
Sources/RampartTelemetry/{EventHub,ClipboardSource,SocketSource,FSEventsSource}.swift. Tests: `rampart-selftest b5x`
(Sources/rampart-selftest/SelfTest+B5X.swift), plus flipped expectations in attackx5 / attackx6 / behaviour.

## Threat model (short)
Local malware running as the user (stealers, adware, miners, backdoors), pasted ClickFix commands, compromised
npm/pip/brew packages, social engineering of "Not a Threat" allows, and attempts to read RamPart's own secrets.
Without the Endpoint Security entitlement everything here is detection after the fact, not blocking.

## Findings
| # | Sev | File | Issue | Fix | Status |
|---|-----|------|-------|-----|--------|
| T-X6-1 | High | EventHub.swift shouldMute | Terminal / Script Editor execs (ppid 1, under /System) were muted, so ClickFix lineage rules never matched | `.app/Contents/MacOS/` execs are never muted | Fixed |
| T-X6-2 | Med-High | EventHub.swift | tee/PlistBuddy/at/sed writes to /etc, LaunchAgents, ~/.ssh, pam, External Extensions were muted | critical path prefixes/infixes never muted; tee, PlistBuddy, plutil, defaults, at, sed, sysadminctl, dseditgroup, socketfilterfw, pfctl, log, scutil, kickstart, lldb/vmmap/leaks/sample, rsync, rm added to neverMute | Fixed |
| B-X1-1 | High | BehaviourEngine.isAllowlisted | folder allows hid strong rules; broad prefixes honoured | user folder allows with weakOnly unset are weak-only; prefixes for /, a top-level folder, home or home/<folder> are ignored | Fixed |
| B-X6-1 | High | BehaviourEngine.isAllowlisted | built-in Homebrew/CLT allows hid credential theft and exfil by toolchain interpreters | built-in toolchain allows never hide R30/R36-R39/R37b/R37S/R42/R42D/R43/R43C/R44/R45/R59/R60/R62/L11 | Fixed |
| B-X6-2 | High | DefaultRules R36/R37/R38 | Apple interpreters were excluded; many secrets weren't watched; scp of ~/.ssh was exempt | R37 has an Apple interpreter/LOLBin reader matcher; new paths: shell history, gh/npm/pypi/docker/git/netrc tokens, GPG, Messages, Safari history, .kdbx, solana, wallet extension IDs, RamPart Vault/Chats, .rpvault; ~/.ssh as a directory argument; new strong R37S (scp/rsync of ~/.ssh or a private key to a remote host); R36 covers `security find-*-password … app.rampart.*`; R38 covers staged .rpvault/.kdbx; new R37b document sweep | Fixed |
| B-X6-3 | Med-High | DefaultRules | backdoors without rules | R16 PAM; new R16b hidden/new admin; R14 tee/cp exec; R25 tee/sed exec, SystemConfiguration plist, untrusted scutil; R11 at/atrun; R15 ARD kickstart and screensharing; R24 trust-settings-import and add-certificates to System.keychain; L06 socketfilterfw off and pfctl -d; new L11 indicator removal; R07 inline downloaded/encoded code (scanner patterns; no Apple discount for inline jobs); L04 python exec(b64decode) and JXA; new R59 clipboard hijacker; new R60 app-bundle tamper and R60W wallet trojanisation (90) | Fixed |
| B-X6-4 | Medium | DefaultRules | adware side channels | new R20L (`--load-extension`/`--disable-extensions-except` from an untrusted or pasted lineage); R20 covers External Extensions JSON | Fixed (rules). Scanner inventory: see needs owner |
| B-X6-5 | Medium | DefaultRules | Office as an entry point; miners | `officeApps` list; L08 Office to shell matcher; R08 `~$` plist and Office-lineage plist writes; new strong R62 cryptominer (stratum, pool ports, RandomX/Monero args, untrusted connect to pool ports) | Fixed (no sustained-CPU signal, see limits) |
| X5-12..19 | High | DefaultRules | RamPart vault/chat/keychain theft, DNS tunnelling, memory scraping, iCloud staging, clipboard reads | R36/R37/R38 additions; new R42D DNS tunnelling (≥10 long or high-entropy distinct subdomains in 60 s per actor); new R55M memory tool attached to a security tool (always active); new R43C iCloud Drive staging; R59R clipboardRead by an untrusted actor | Fixed (rules) |
| ClickFix | Medium | BehaviourEngine.multiplier | the "typed by hand" interactive discount applied while a risky browser copy was armed | no discount while `riskyClipboard` or `pasteEntry` is active; R31 also matches `python -c exec/b64decode/urlopen` and `perl/ruby -e eval` | Fixed |
| HX9 salt | Medium | Support.swift / ClipboardSource.swift | clip_tokens were 32-bit SHA-256 prefixes salted with the world-readable boot UUID | HMAC-SHA256 under a private random 256-bit key, 64-bit output; both mirrors share the key in-process through RAMPART_CLIPFP_KEY; engine also accepts EventHub's ClipboardMemory match (`clipboard_match`) | Fixed (wiring: see needs owner) |
| TC5/TC6 | Medium | SocketSource / FSEventsSource / EventHub | fields the threat-chain rules need | `remote_host` from new `DNSAnswerCache` (fed from dnsQuery `answers`, or by the DNS filter); `origin_url` from kMDItemWhereFroms (http(s) only, user info/query stripped, 8 KiB cap) | Fixed; bytes_out is a limit |

## Needs owner
- **Daemon/agent (B9):** the session agent and the daemon must use the same clipboard key. Generate 32 random bytes in
  the daemon, send them to the agent over the authenticated IPC, and set `RAMPART_CLIPFP_KEY` (64 hex) in the agent
  before the first fingerprint. Until then, cross-process R31 token overlap relies on EventHub's `clipboard_match`.
- **Network DNS filter (B6):** call `DNSAnswerCache.shared.record(ip:host:)` for each answer, or put `answers` on dnsQuery events.
- **Telemetry, clipboardRead event:** UnifiedLogSource should emit `type=clipboardRead` from pasteboard-access log lines. R59/R59R are ready for it.
- **PersistenceScanner, P02/P03 (not done in this time box):** unpacked or external Chromium extensions from (Secure)
  Preferences and External Extensions JSON; Safari extensions plists; `other` records hashing sudoers(.d), pam.d, hosts, resolver.

## Honest limits
- **bytes_out:** public libproc gives no cumulative per-socket byte counters (only current buffer fill), so SocketSource does not emit it. Real counters need NetworkStatistics (private) or a Network Extension.
- No "sustained CPU from an unsigned image" miner signal yet; R62 needs the miner's arguments or a pool port.
- Everything here is after-the-fact detection, not prevention.
