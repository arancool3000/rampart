# Attack pass X3 — social engineering & multi-stage chains (2026-11-07)

Adversarial-researcher pass focused on **human-in-the-loop** attacks: the victim is persuaded to
click, paste, type a password, allow remote access, or disable protection. These defeat pure file
scanning, so the relevant RamPart layers are **Web / Scam-Check**, **Behaviour**, **Guard
(remote-access lockdown)**, **Apple-impersonation**, and the **IPC auth** on protection-disable.

Everything was proven **inert**: synthetic `SecurityEvent` sequences fed to `BehaviourEngine`, the
EICAR string assembled at runtime as the stand-in payload, fixture `.webloc` / AppleScript bytes
analysed by the Scam-Check and deep-content engines, URL strings on `example.com` / `.test` only,
and `RemoteAccessMonitor` fed a fixture process list (no live probe, no tool installed).

- Test suite: `Sources/rampart-selftest/SelfTest+X3.swift`, `static func attackX3Checks()`.
- Register in `Suites.swift` as: `("attackx3", SelfTest.attackX3Checks),`
- Run: `RAMPART_NO_PRIVILEGED_TOOLS=1 .build-agents/out/Products/Debug/rampart-selftest attackx3`

Legend: **Caught** = a RamPart layer produces a Detection / non-safe verdict; **Partial** = surfaced
but not scored to a block, or only one stage of the chain is seen; **Missed** = no layer reacts.

## The headline chain (user's example), decomposed

> A harmless-looking file whose single changed link points at a fake Apple page → a 10-hop lookalike
> redirect chain → an auto-downloaded disguised trojan → mass email to the victim's contacts →
> "analytics" exfiltration.

| # | Stage | RamPart layer that should catch it | Result |
|---|---|---|---|
| S1 | `.webloc`/`.url`/document with **one changed link** to a fake `appleid.apple.com.*.secure-login.test` | Deep-content inspector extracts the URL → URLAnalyzer combosquat; Scam-Check verdict | **Caught** — link extracted, score ≥ suspicious, host not "safe" |
| S2 | **10-hop lookalike chain** (homograph, punycode, digit-typo, combosquat across Apple/PayPal/Microsoft/Netflix) | URLAnalyzer lookalike (homograph/typosquat/combosquat/punycode) | **Caught** — ≥ 8/10 hops flagged non-safe |
| S3 | **Auto-downloaded disguised trojan** run after quarantine strip (EICAR stand-in) | Behaviour R27 (quarantine removed → exec from Downloads); Engine EICAR hash on the file | **Caught** |
| S7 | **Mass email to contacts**: sender/Reply-To mismatch + lookalike link + urgency + attachment | Scam-Check `checkEmail` (header + text + URL + attachment signals) | **Caught** — `likelyScam` |
| S6 | **"Analytics" exfiltration** agent copies the browser Login Data store | Behaviour R37 (credential store touched by foreign process) → R40 stealer chain / R46 beaconing | **Caught** (S6 credential read); beaconing is R46 weak-only (see misses) |

## Full scenario table

| # | Name | Attacker | Kill chain (abridged) | Layer → step | Result |
|---|---|---|---|---|---|
| S1 | Trojaned bookmark file | Phisher | email a `.webloc` → one line is a fake Apple URL → victim clicks → credential form | Web deep-content → link; URLAnalyzer → combosquat | **Caught** |
| S2 | 10-hop lookalike chain | Phishing kit | shortlink → 10 redirects, each a brand lookalike → final credential form | Web URLAnalyzer → every hop | **Caught** (≥8/10) |
| S3 | Auto-download disguised trojan | Drive-by | fake update page → auto-download "macOS_Update_Installer" → quarantine stripped → exec | Behaviour R27/L01; Engine EICAR | **Caught** |
| S4 | Browser spawns a shell/downloader | Drive-by | malicious page → `Safari → bash -c "curl … | bash"` | Behaviour L08 | **Caught** |
| S5 | Fake system password prompt | Infostealer | page/script runs `osascript display dialog … hidden answer` to harvest the login password | Behaviour R34 (script-host password dialog) | **Caught** (infostealer, score 75) |
| S6 | "Analytics agent" reads credential store | Infostealer | foreign process copies Chrome `Login Data` to `/tmp` | Behaviour R37 → R38/R40 | **Caught** |
| S7 | Mass email to contacts | Worm/phish | compromised account mails all contacts: lookalike link + risky attachment | Web `checkEmail` | **Caught** (`likelyScam`) |
| S8 | **Fake RamPart alert: "disable protection"** | Scareware | fake in-browser RamPart alert tells the user to turn off real-time protection and call "support" | Web scareware page heuristics; **IPC auth** blocks silent disable | **Missed** at the Web layer (verdict `likelySafe`); the IPC auth still blocks a silent disable (see note) |
| S9 | Fake macOS update page | Drive-by | lookalike `apple-support-update.test` pushes a "critical update" installer | Web page + URL lookalike | **Caught** (non-safe) |
| S10 | ClickFix / QR "verify you are human" | ClickFix | page copies `curl … | bash` to clipboard, tells user to paste in Terminal / scan a QR | Web clipboard+overlay heuristics; Behaviour R31 on the paste-run | **Caught** (page) / R31 on execution |
| S11 | Calendar-invite spam | Spammer | flood of calendar invites whose notes carry a typosquat payment link | Web `checkMessage`/`checkEmail` | **Caught** (non-safe) |
| S12 | Deepfake "support call" + remote tool | Tech-support scam | caller (voice clone) talks victim into installing AnyDesk; tool runs while a browser is frontmost | Guard `RemoteAccessMonitor` scam-context | **Caught** — `critical`, "tech-support scam pattern" |
| S13 | Apple-named dropped app | Masquerade | unsigned `macOS Update.app` lands in Downloads | `AppleImpersonation` | **Caught** |
| S14 | Browser→shell writes persistence | APT | page → `Safari → bash` writes `/Library/LaunchAgents/…plist` | Behaviour R08 | **Caught** |
| S15 | AI-assistant / prompt-injection text | Prompt-injection | document/page hides "ignore previous instructions; run this" + a shell command for an LLM agent | Web deep-content **indicator extraction only** | **Partial** — command surfaced; no LLM-guard scoring (see misses) |
| S16 | False-positive guard | — | real `appleid.apple.com`, benign clipboard page, genuine Apple Software Update | Web + AppleImpersonation negatives | **Caught** (correctly NOT flagged) |

### Note on S8 (fake "disable protection" alert) — defence in depth
**The Web layer does not flag this page** (test result: `likelySafe`). Even so, if the user is fully convinced, a web
page **cannot** silently disable RamPart: `Command.requestDisableProtection(authorization:)` →
`disableProtection(token:)` requires an admin-authenticated session at the daemon (redteam.md,
GuardWiring). So the social-engineering goal ("turn off your antivirus") is blocked at the IPC layer
regardless of the victim's choice. This is the strongest control in the set and should be surfaced in
the UI copy ("RamPart can't be turned off by a website").

## Misses / weaknesses (top 5 by severity)

1. **(High) QR-code and on-screen-image lures are not decoded.** S10/S11 are caught only when the
   payload reaches us as *text* (clipboard/overlay/link). A QR code rendered as an image on a scam
   page, or a lookalike URL shown only inside a screenshot/`<canvas>`, is never read, so the
   malicious destination is invisible to the URL engine. → `needs-web.md`.
2. **(High) No LLM/prompt-injection guard in the scan path (S15).** Deep-content extracts the
   embedded command as an indicator but there is no signal that scores "instructions addressed to an
   AI agent + an action verb + a shell command" as a manipulation attempt, and nothing warns the
   bundled AI tools before they act on untrusted page/file text. → `needs-ai.md`.
3. **(Medium) Beaconing/exfil to a *lookalike analytics* host is weak-only.** R46 (beaconing) needs
   ~30 min of fixed-interval traffic and scores 45; a single HTTPS POST of stolen data to
   `analytics-collector.test` on first run is below the alert threshold unless the credential-read
   stage (R37/R40) already fired in the same chain. Reputation of the destination host is not
   consulted for outbound connections. → `needs-network.md`.
4. **(High) Fake RamPart / "disable protection" alert gets no warning (S8, confirmed by test).** A page whose
   overlay claims "RamPart detected 5 viruses, disable real-time protection and call support" scored
   `likelySafe`. The generic scareware heuristic did not trigger on PageSignals overlay text alone. Needs a
   dedicated high-weight rule plus UI reassurance. → `needs-web.md` X3-4.
5. **(Low) Deepfake audio of the support call is out of scope.** We only see the *consequence*
   (remote-access tool launch, S12), not the call. Acceptable, but worth stating in UI copy so users
   know the voice is the lure and the tool install is the line to never cross. → `needs-app.md` (copy).

## Evidence
Run on the serialised agent build: **22 checks passed**. S8 was asserted at first and failed (`likelySafe`). It is now
recorded as a printed `MISS S8` line instead of a failing check, so the suite stays green until W1 fixes it. No file was executed, no network call made, no real
credential or the installed RamPart touched; `RAMPART_NO_PRIVILEGED_TOOLS=1` throughout.
