# 03 — Norton 360 for Mac and the macOS Security Competitive Landscape

Research date: 2026-11-05. Sources are at the end. **How sure we are:** "[verified]" means a primary or reputable source confirmed it this session. "[reported]" means only secondary or affiliate sources said it. "[background]" means it comes from long-standing public knowledge and was not re-checked this session. Some sites (AV-TEST, Tom's Guide) were blocked by a network filter during research, so their per-product score tables were not read directly.

---

## 1. Norton 360 for Mac: product overview

Norton is owned by **Gen Digital**, which also owns Avast, AVG, Avira, CCleaner, LifeLock and ReputationDefender [verified]. On Mac the product is a single "Norton 360" app with a tiered licence. Most of the identity features are web-portal services, not native Mac code.

### 1.1 Plans and pricing (US)

| Plan | Devices | Key Mac-relevant inclusions | Intro price | Renewal |
|---|---|---|---|---|
| Norton AntiVirus Plus | 1 | AV, firewall, password manager, 2 GB backup (Windows only) | ~$29.99 | ~$59.99+ [reported] |
| Norton 360 Standard | 1 (some regions 3) | + Secure VPN, Dark Web Monitoring | ~$41.88 | ~$94.99 [reported] |
| Norton 360 Deluxe | 5 | + 50 GB cloud backup (Windows only), parental controls (not on Mac) | $39.99–$49.99 promo | **$124.99** (official list, March 2026) [verified] |
| Norton 360 with LifeLock Select / Advantage / Ultimate Plus | 10–unlimited | + identity theft insurance, credit monitoring, Scam Protection Pro | ~$99.99 | ~$189.99+ [reported] |

- The free trial needs a card. There is a 60-day money-back guarantee. Plans renew automatically by default [verified, Macworld].
- **Renewal is often 2–3x the first-year price.** This is the most common pricing complaint.

### 1.2 Feature inventory on Mac

| Feature | On Mac? | Notes |
|---|---|---|
| Real-time ("Auto-Protect") file scanning | Yes | Uses Apple's Endpoint Security / system extension. Needs Full Disk Access [verified, Macworld] |
| Quick / Full / Custom (folder, external volume) scans | Yes | Exclusions list. Scans are fast [verified] |
| Archive (.zip) scanning | **No / weak** | Macworld flagged in two consecutive years that it cannot scan .zip archives [verified] |
| Scheduled scans, quarantine | Yes | |
| Smart Firewall (app rules) + Intrusion Prevention | Yes | macOS 11+ only. Network extension [verified, Norton support] |
| Safe Web browser extension (anti-phishing / link rating) | Yes | **Inconsistent:** let every test spam site through in Edge, patchy in Firefox, best in Chrome but still leaky [verified, Macworld] |
| Norton Private Browser (Chromium-based) | Yes | Another browser to install, a vendor lock-in move |
| Secure VPN | Yes (Standard+) | Basic. Few settings, no split tunnelling on Mac [reported] |
| Dark Web Monitoring | Yes (Standard+) | Mostly a portal/email service. Worked in testing [verified] |
| Password Manager (Norton Password Manager) | Yes (extension + vault) | Basic compared with 1Password/Bitwarden |
| File Cleanup + Startup Manager (utilities) | Yes | Startup Manager is "surface-level" [verified] |
| Cloud Backup | **No (Windows only)** | Marketed in the Deluxe bundle but not on Mac [verified, Norton regional store pages] |
| Parental Controls (Norton Family) | **No native Mac client** | Listed as unsupported on Mac [verified] |
| SafeCam (webcam protection) | **No (Windows only)** | [verified] |
| Genie AI scam assistant / Scam Protection | Partial | Mostly mobile/web chat, described as slow and inconsistent [reported] |
| Privacy Monitor / data-broker removal | Web service (higher tiers) | Not a Mac feature as such |
| LifeLock identity, credit, insurance | Web service (US) | |
| iOS device scanning | No | (Intego offers this) |

**Key takeaway:** About a third of the Norton 360 marketing checklist (Cloud Backup, Parental Controls, SafeCam) **does not exist on Mac.** The Deluxe bundle is sold as cross-platform, so a Mac-only household pays for features it cannot use.

### 1.3 UI structure

- **Main window:** a "My Norton" dashboard with tiles: Device Security, Secure VPN, Dark Web Monitoring, Password Manager, Identity, and later Utilities and Genie. Each tile opens a separate sub-window or a web page. The Mac app wraps several older engines, so it is not one consistent native app.
- **Device Security** has its own panel: Scans, Firewall/Network, Live Update, History/Quarantine, Settings (Clean, Vulnerability Protection, Safe Web).
- **Menu bar icon:** status plus quick actions (Quick Scan, Live Update, open Norton).
- **Onboarding:** asks for Full Disk Access, the system extension, the network extension (VPN), browser extensions and account sign-in. Reviewers call the navigation "somewhat convoluted" [verified, Macworld].
- **Upsell surfaces:** tiles for unpurchased features, "Upgrade" banners, renewal pop-ups, promotions for the Private Browser and extensions, and account/portal redirects.

### 1.4 Known weaknesses and user complaints

1. **Performance:** recurring reports that Norton makes the Mac "sluggish", and that the Mac build feels heavier than the Windows one (Best Buy, Apple Communities, Mac-Forums) [verified, anecdotal]. Labs usually score its performance acceptable, so the complaints tend to concentrate on older Intel Macs and on the impact of the network extension and VPN.
2. **Upsells and nagging:** ads for other Gen/Norton products, renewal pop-ups that interrupt work, tiles for features not owned [verified, ConsumerAffairs/Apple Communities].
3. **Auto-renewal dark patterns:** hard to find the cancel option, sometimes needs a phone call, few reminders before renewal, steep renewal prices, refund disputes and BBB complaints [verified, Norton Community/Best Buy].
4. **Uninstall difficulty:** dragging to the Trash leaves components behind (system extension, launch daemons, network extension, browser extensions, kexts on old versions). The app cannot always open to run its own uninstaller, and the official "RemoveNortonMacFiles" tool is needed. Users report leftovers [verified, Apple Communities/MacRumors/Norton Community].
5. **Detection gaps:** no .zip scanning. In Macworld testing AdWind got through and needed a third-party tool to remove [verified].
6. **Safe Web unreliability** across browsers [verified].
7. **Feature-parity gap** with Windows (backup, parental, SafeCam) [verified].
8. **Privacy and trust:** the parent company Gen Digital owns Avast, which the FTC fined $16.5M (Feb 2024) because its Jumpshot subsidiary sold users' browsing data. The order bans selling browsing data for advertising [verified]. Norton also shipped "Norton Crypto", an opt-out Ethereum miner in 2022 (Windows), and kept a 15% fee [background]. Norton collects a lot of telemetry and pushes users into a cloud account.
9. **Account-first design:** you cannot use it without a Norton account, and much of the configuration lives on a web portal.

### 1.5 Independent lab results (Mac)

- **AV-Comparatives Mac Security Test & Review 2026** (published around May/June 2026): 9 products. Norton AntiVirus Plus, Avast One Free, AVG Free, Bitdefender, ESET HOME Security Essential, Intego ONE Complete, Kaspersky Premium, CrowdStrike and Trellix were **all certified**. Certification requires strong protection and **zero false positives** on the test set. The test covers Mac malware and PUA, plus optional Windows-malware detection, install, UI and alert behaviour [verified]. Secondary-reported detection: Norton 99.9%, Avast/AVG 99.9%, Bitdefender 99.0%, Intego 96.7% (lowest consumer), all with 0 FPs [reported, toolradar].
- **AV-TEST macOS Tahoe (March 2026 home test, 10 products; June 2026 Tahoe 26.3 test, 14 products):** most commercial products score 6/6 for protection. Norton is reported at 6/6/6 [reported]. ESET earned the full 18 points and Avast was "flawless" in June 2026 [verified, news snippet]. Business test: CrowdStrike, Sophos, Symantec, Trellix, Trend Micro [verified].
- **Macworld (Sept 2025 review):** fast scans, strong pre-install blocking, but AdWind got through, no zip scanning and leaky Safe Web. Rated "viable, good value… tries to do too much" [verified].
- **Objective-See / Patrick Wardle:** has long argued that signature-based Mac AV (including XProtect and commercial products) can be beaten by trivial modification such as renaming, repacking or re-signing, and recommends behaviour-based detection: persistence monitoring, outbound firewall, mic/camera monitoring [background + reported]. No Objective-See head-to-head with Norton exists. The critique applies to the whole signature-AV category.

**Interpretation:** Lab detection is **commoditised**. Every major vendor scores about 99–100% on known Mac malware with 0 FPs, so detection rate alone is not a differentiator. What separates products is behaviour-based detection of new threats, transparency, performance, UX honesty and the quality of Mac-specific features.

---

## 2. Competitor comparison

| Product | Engine / detection | Real-time | Firewall | Web protection | Extras | Price (1 Mac, renewal) | Strengths | Weaknesses |
|---|---|---|---|---|---|---|---|---|
| **Norton 360** | Gen signature + cloud + heuristics | Yes | Yes (app + IPS) | Safe Web ext. | VPN, PW mgr, dark web, LifeLock | $95–125+ | Brand, bundle, identity | Upsells, renewal, uninstall, Mac parity gaps, Safe Web leaky |
| **Bitdefender Antivirus for Mac** | BD engine (top-tier), Advanced Threat Defense (behaviour) | Yes | No (Total Security only) | TrafficLight | Safe Files (ransomware folder protection), Time Machine protection, adware removal, limited VPN (200 MB/day) | ~$60–80 | Best lab scores, light, ransomware folder shielding | No firewall in Mac AV, VPN capped, upsells to Total Security |
| **Intego Mac Premium Bundle / ONE** | VirusBarrier (Mac-only) | Yes | **NetBarrier** (best Mac 2-way firewall in a suite) | Web filter in ContentBarrier | ContentBarrier parental controls, Personal Backup, Washing Machine (cleanup), iOS device scanning over USB | ~$70–120 | Mac-native, Macworld 2026 top pick, real parental controls | Lowest AV-C detection 96.7%, dated UI, aggressive discount/renewal emails |
| **Malwarebytes for Mac** | Own engine, strong adware/PUP focus | Premium only | No | Browser Guard (free ext.) | Free on-demand cleaner, Privacy VPN add-on, Identity add-ons | ~$45–80 | Best free cleanup, light, PUP/adware | Not in 2026 lab tests, no firewall, weaker on non-adware |
| **CleanMyMac (MacPaw)** | Moonlock engine (malware module) | Background monitor | No | No | Cleanup, uninstaller, optimisation, app updater | ~$40/yr | Gorgeous UX, Apple-notarised, Moonlock research team | Primarily a cleaner. AV is secondary and not lab-certified |
| **Objective-See (free, open source)** | Behaviour, not signatures | Per tool | **LuLu** (outbound firewall) | No | **KnockKnock** (persistence enumeration + VT), **BlockBlock** (real-time persistence alerts via ESF), **RansomWhere?** (encrypt-burst detection), **OverSight** (mic/camera use alerts), **Netiquette** (network connections), DND, ReiKey (keyloggers/event taps), What's Your Sign, TaskExplorer | Free | Trusted, transparent, catches new and nation-state malware by behaviour | Separate tools, power-user UX, alert fatigue, no signature database, no unified dashboard |
| **Kaspersky Premium for Mac** | Top-tier engine | Yes | Network attack blocker | Web AV | VPN, PW mgr | n/a in US | Excellent detection (AV-C certified) | **Banned in the US** since July/Sept 2024 (Commerce/BIS). Updates cut off for US users, trust issues elsewhere |
| **Sophos Home** | Sophos enterprise engine | Yes | No | Web filtering, parental web filter | Remote web dashboard for up to 10 devices, ransomware (CryptoGuard on Win) | ~$45–60 | Admin-style remote management, free tier | Cloud-dashboard-first, basic Mac UI, fewer features on Mac |
| **Avast One / Free (Gen)** | Gen engine (same core as Norton/AVG) | Yes | Paid tier | Web Shield | VPN, data-breach, cleanup | Free / $50+ | Top lab scores, free | FTC Jumpshot history, heavy upsell, same parent as Norton |
| **ESET HOME Security for macOS** | ESET engine (LiveGrid) | Yes | Yes (Premium) | Web + anti-phishing | Device control, network inspector, password mgr (Premium) | ~$50–70 | Full 18/18 AV-TEST, light footprint, low-nag | Dated UI, Mac version lags Windows |

**Gaps across the market:**
- Nobody combines **lab-grade signatures** (Bitdefender/ESET/Norton) with **Objective-See-grade behaviour monitoring** (persistence, outbound firewall, mic/camera, ransomware burst) in one native, honest app.
- Few products explain *why* something was flagged (code signature, notarisation, team ID, persistence location, parent process).
- No one offers clean, verifiable uninstall or local-first privacy as a selling point.
- Mac-specific threats are under-served: infostealers (AMOS/Atomic, Poseidon, Banshee, Cthulhu), fake app/DMG lures, "paste this into Terminal" ClickFix-style attacks, malicious LaunchAgents, browser-extension hijacks, TCC abuse and abuse of AppleScript/osascript.

---

## 3. How Bastion beats Norton 360

Guiding principle: **Mac-native, honest, behaviour-first, lab-grade.** Detection parity is the minimum requirement. We win on transparency, behaviour detection, performance, and having no dark patterns.

### 3.1 MUST-HAVE (launch blockers: parity plus Norton's worst failures fixed)

| # | Feature | Rationale |
|---|---|---|
| M1 | **Real-time protection via Endpoint Security framework** (AUTH_EXEC/AUTH_OPEN, NOTIFY_CREATE/RENAME), in a system extension, Apple Silicon native | Category requirement. ES gives pre-execution blocking like Norton, without kexts |
| M2 | **Lab-grade signature + YARA + hash reputation engine** with archive/DMG/PKG/zip/xz/7z unpacking, Mach-O/universal binaries, scripts, Office macros | Norton cannot scan .zip (Macworld). Archive and DMG scanning closes that hole. Required to pass AV-TEST/AV-C |
| M3 | **Code-signing / notarisation / Team ID trust model** in every verdict | Cheap, high-signal, cuts false positives. Explains verdicts to users |
| M4 | **Quick / Full / Custom / external-volume / scheduled scans**, with quarantine + restore and an exclusions list | Parity |
| M5 | **Persistence monitoring (BlockBlock-class)**: real-time alerts on new LaunchAgents/Daemons, login items, BTM entries, cron, periodic, shell rc files, browser extensions, authorization plugins | Norton's Startup Manager is "surface-level". This is how new Mac malware is actually caught |
| M6 | **Infostealer/behaviour heuristics**: Keychain/browser credential-store access by unsigned processes, osascript password prompts, `curl \| bash` from Terminal paste, mass file staging to /tmp and exfiltration | The dominant 2024–2026 Mac threat class. Labs increasingly test it |
| M7 | **Ransomware burst detection (RansomWhere-class)**: entropy-plus-rate detection on user files, suspend the process, offer rollback via APFS snapshots | Bitdefender has Safe Files. Norton has nothing visible on Mac |
| M8 | **No dark patterns**: one-click cancel in-app, renewal reminders 30 and 7 days before, renewal price = advertised price, no ads for features you don't own, no third-party product promos | Directly answers Norton's most common complaints |
| M9 | **Clean, verifiable uninstall**: in-app uninstaller plus a signed standalone remover that lists every artefact removed (system extension, network extension, daemons, profiles, browser extensions) and verifies nothing is left | Norton's most persistent support pain |
| M10 | **Performance budget**: under 1% idle CPU, under 150 MB RSS, under 5% overhead on app launch and file copy. Published per release | Answers "Norton made my Mac sluggish". A measurable marketing claim |
| M11 | **Local-first privacy**: no browsing-history collection, opt-in telemetry with a readable payload, hash-only cloud lookups by default, published privacy page and transparency report | Direct contrast with the Gen Digital/Avast FTC history |
| M12 | **Native SwiftUI single-window app + menu bar extra**, one consistent design, guided permission onboarding (FDA, system extension, notifications) with plain-language reasons | Norton's UI is a convoluted, web-wrapped tile maze |
| M13 | **Submission to AV-TEST and AV-Comparatives** by year one, with 0 FPs as a hard release gate | Credibility. Norton's lab scores are its main defensible asset |

### 3.2 SHOULD-HAVE (v1.x: beat Norton's bundle where it matters on Mac)

| # | Feature | Rationale |
|---|---|---|
| S1 | **Two-way application firewall (LuLu/NetBarrier-class)** using a NetworkExtension content filter: per-app outbound rules, unknown-process alerts, block-list mode, live connections view (Netiquette-class) | Norton's Smart Firewall is opaque. Bitdefender Mac has none |
| S2 | **Mic/camera use monitor (OverSight-class)** with the responsible process named | Norton SafeCam is not on Mac at all. Native, cheap, highly visible |
| S3 | **Web/phishing protection** via DNS-level filtering (NEDNSProxy) plus a Safari Web Extension. Works across *all* browsers, not per-browser extensions | Norton Safe Web leaked every spam site in Edge. A network-level filter is browser-agnostic |
| S4 | **Browser-extension auditor** for Safari, Chrome, Firefox, Edge and Arc: flag risky permissions and known-malicious IDs | Common adware and stealer vector, poorly covered by Norton |
| S5 | **Security posture checkup**: SIP, Gatekeeper, FileVault, firewall, XProtect/MRT version, auto-updates, sharing services, TCC grants review (who has FDA, Accessibility, Screen Recording, Input Monitoring) | Turns macOS's built-in defences into a visible score. No competitor does TCC review well |
| S6 | **Explainable alerts**: every detection shows signer, notarisation, parent process tree, file path, persistence location, the action taken, and "why we think this" | Builds trust and reduces support load. Objective-See's strength without the power-user UX |
| S7 | **Breach/dark-web check** via k-anonymity APIs (HIBP-style), with no account required for basic checks | Matches a Norton 360 headline feature without needing a heavy identity portal |
| S8 | **Low-friction false-positive workflow**: one-click "this is safe / report false positive", signed allowlists, developer-friendly (Xcode build products, Homebrew) | Developers are a vocal Mac segment, and AV false positives on dev tools are a top complaint |
| S9 | **Gaming/Focus/Presentation mode** that defers scans and alerts | Parity with Norton's silent mode |

### 3.3 DIFFERENTIATORS (reasons to switch)

| # | Feature | Rationale |
|---|---|---|
| D1 | **Unified behaviour + signature engine**: Objective-See-style behavioural telemetry correlated into a single verdict, e.g. "unsigned binary from a browser download → wrote a LaunchAgent → accessed Keychain = stealer" | No consumer product does this on Mac. It catches new threats that signature-only AV misses (Wardle's critique) |
| D2 | **ClickFix / Terminal-paste guard**: detect when a user pastes an obfuscated `curl`/`base64`/`osascript` one-liner from a web page into Terminal, and warn before execution | Fastest-growing Mac infection vector in 2025–26. Nobody covers it |
| D3 | **APFS snapshot "undo"**: after a remediation, roll back the files the threat touched | Ransomware and stealer cleanup no other Mac AV offers |
| D4 | **Download provenance (quarantine xattr + origin URL)**: show where every app came from, and flag apps from lookalike or sponsored-ad domains | Fake-app lures (fake Arc, Zoom, TradingView DMGs) are the main stealer delivery method |
| D5 | **"Glass box" transparency**: a public detection-rule changelog, an open-source helper tools and uninstaller, a reproducible performance benchmark, and a published telemetry schema | Turns Norton's trust deficit into our moat |
| D6 | **Fair pricing**: generous free tier (on-demand scan + persistence audit), a single honest paid tier for all protection features, family plan, and renewal at the same price. Optional VPN/identity as add-ons only | Norton's 2–3x renewal jump is the most common reason people leave |
| D7 | **Mac-household focus**: iPhone/iPad checkup over USB/Wi-Fi (profiles, jailbreak indicators, iOS version), plus a multi-Mac family dashboard without forcing a cloud account | Intego has an iOS scan, Norton does not. Sophos's dashboard proves demand |
| D8 | **AI-assisted explanations run on-device** (Apple Foundation Models / Core ML) to explain alerts and triage suspicious files privately | Better than Norton Genie (cloud, slow, inconsistent) and stays private |
| D9 | **Developer and power-user mode**: CLI (`bastion scan`, `bastion persist list`), JSON event export, MDM/configuration-profile support, ES event log viewer | Wins the influential technical audience that recommends AV to everyone else |

### 3.4 Explicitly NOT doing (in v1)

- A bundled full VPN, credit monitoring, identity insurance or cloud backup. These are commodity, high-cost and low-trust in a security app, and Norton's versions are mediocre on Mac. Partner with others or offer them as optional add-ons later.
- A custom browser (Norton Private Browser). It locks users in and adds to the attack surface.
- Kernel extensions. ES and NetworkExtension only.

### 3.5 Priority summary

1. **Ship parity detection that passes the labs (M1–M4, M13).**
2. **Fix every Norton complaint by design (M8–M12): honest pricing, clean uninstall, performance, privacy, native UI.**
3. **Behaviour layer (M5–M7, S1–S2, D1–D2): the reason Bastion catches what Norton misses.**
4. **Explainability and Mac-specific depth (S5–S6, D3–D4, D7).**

---

## Sources

- AV-Comparatives, Mac Security Review/Test 2026: https://av-comparatives.org/mac-security-review-test-2026/
- AV-TEST, macOS Tahoe 26.3 test news: https://av-test.org/en/news/test-malware-protection-under-macos-tahoe-263/
- AV-TEST, Business macOS March 2026: https://www.av-test.org/en/antivirus/business-macos/macos-tahoe/march-2026/
- AV-TEST, Home macOS index: https://av-test.org/en/antivirus/home-macos
- Macworld, Norton 360 review: https://www.macworld.com/article/668092/norton-360-review.html
- Macworld, Norton 360 Deluxe review: https://www.macworld.com/article/3563521/norton-360-deluxe-review.html
- Macworld, Best antivirus for Mac: https://www.macworld.com/article/231118/best-antivirus-for-mac.html
- Tom's Guide, Norton 360 Standard (Mac) review: https://www.tomsguide.com/reviews/norton-security-mac
- Norton US pricing / renewal list: https://us.norton.com/pricing
- Norton support (Smart Firewall macOS 11+): https://support.norton.com/sp/en/ca/home/current/solutions/kb20080515115252EN
- Norton regional store (Mac-unsupported features): https://sg.norton.com/downloads , https://in.norton.com/store
- AllAboutCookies, Norton 360 review 2026: https://allaboutcookies.org/norton-360-antivirus-review
- Gizmodo, Norton review: https://gizmodo.com/best-antivirus/norton
- toolradar, Best antivirus for Mac (secondary AV-C figures): https://toolradar.com/blog/best-antivirus-for-mac
- Beebom, Best antivirus for Mac 2026: https://beebom.com/best-antivirus-for-mac
- Macwelt, 10 Mac antivirus solutions compared: https://www.macwelt.de/article/988900/beste-antivirus-fuer-mac-2026.html
- Complaints: Apple Communities https://discussions.apple.com/thread/253067528 ; MacRumors https://forums.macrumors.com/threads/norton-360-issue-unable-to-open-uninstall.2295091 ; Norton Community https://community.norton.com/t/completely-removing-norton-360-from-my-mac/370420 , https://community.norton.com/t/difficulty-canceling-subscription/229944 ; ConsumerAffairs https://www.consumeraffairs.com/computers/norton.html?page=4 ; Best Buy reviews https://bestbuy.com/site/reviews/norton-360-deluxe-5-device-antivirus-internet-security-software-vpn-dark-web-monitoring-1-year-subscription-android-apple-ios-mac-os-windows-digital/6346690?page=6
- FTC / Avast Jumpshot: https://thehackernews.com/2024/02/ftc-slams-avast-with-165-million-fine.html , https://www.techspot.com/news/101997-avast-fined-165-million-ftc-selling-user-browsing.html
- Kaspersky US ban: https://www.tomsguide.com/computing/antivirus/us-government-bans-kaspersky-antivirus-software-what-you-need-to-know
- Objective-See tools and Mac malware reports: https://objective-see.org , https://objective-see.org/downloads/MacMalware_2024.pdf
