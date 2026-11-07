# Attack pass X5 — extreme data theft & privacy (2026-11-07)

Theme: the most extreme **data-theft / privacy** attacks against the Mac and against RamPart's own
secrets (password vault, Authenticator/TOTP codes, Gemini API key, AI chat history).

Method: each scenario is a synthetic `SecurityEvent` sequence fed to a fresh `BehaviourEngine`
(`RuleSet.default`, `behaviourTestSigning`). Nothing is executed; no real credential store, keychain,
pasteboard, camera/mic, network or installed RamPart is touched. All payloads are inert strings on
`.example` domains; the attacker binary is an unsigned stand-in under `~/Downloads`.

Suite: `Sources/rampart-selftest/SelfTest+X5.swift`, `static func attackX5Checks()`.
Registered in `Suites.swift` as `("attackx5", SelfTest.attackX5Checks),`.
Run: `RAMPART_NO_PRIVILEGED_TOOLS=1 .build-agents/out/Products/Debug/rampart-selftest attackx5`.

Layers referenced: **behaviour** = `BehaviourEngine` rules (doc 05); **network** = DNS resolver /
`ConnectionMonitor`; **telemetry** = `EventSource`s that must emit the event a rule needs.

## Scenarios

| ID | Scenario | Attacker | Kill chain (key steps) | Layer that should catch | Result |
|----|----------|----------|------------------------|-------------------------|--------|
| X5-01 | Spoofed keychain/login password prompt | Infostealer | untrusted app → `osascript display dialog … hidden answer` → victim types login password | behaviour R34 (alwaysActive) | **caught** |
| X5-02 | Browser Safe Storage key harvested | Infostealer | untrusted proc → `security find-generic-password -wa Chrome` → decrypt cookies/passwords | behaviour R36 (alwaysActive) | **caught** |
| X5-03 | Cookie / Login Data DB staged in temp | Infostealer | copy `…/Chrome/Default/Cookies` → `/tmp/.x/Cookies` | behaviour R38 (alwaysActive) | **caught** |
| X5-04 | Whole login keychain dumped | Infostealer | `security dump-keychain login.keychain-db` by non-PM | behaviour R36 | **caught** |
| X5-05 | Offline login-password validation | Infostealer | `dscl . -authonly user …` to confirm phished password | behaviour R35 | **caught** |
| X5-06 | Silent screen capture of revealed 2FA codes | Spyware | `screencapture -x` from untrusted chain while codes on screen | behaviour R51 | **caught** (CLI); **partial** — ScreenCaptureKit/`CGDisplayStream` API capture is **missed** (no event) |
| X5-07 | Keylogger (keyboard event tap) | Spyware | untrusted proc installs keyboard `CGEventTap` | behaviour R48 | **caught** |
| X5-08 | Covert camera/microphone | Spyware | windowless untrusted proc turns on camera | behaviour R50 | **caught** |
| X5-09 | TCC privacy DB tampering | Spyware | write to `…/com.apple.TCC/TCC.db` by non-tccd | behaviour R53 | **caught** |
| X5-10 | Exfil to Telegram bot API | Infostealer | DNS/connect to `api.telegram.org` from non-messaging proc | behaviour R42 | **caught** |
| X5-11 | Full browser-cookie/session stealer chain | Infostealer | ClickFix paste → temp exec → Safe Storage → stage → zip → upload | behaviour R40 (sequence) | **caught** (critical) |
| X5-12 | **Steal RamPart's own vault file (offline brute force)** | Infostealer | copy `…/Rampart/Vault/vault.rpvault` → `/tmp`, crack offline | behaviour R37/R38/@sensitivePaths | **missed** |
| X5-13 | **Steal RamPart's Gemini API key** | Infostealer | `security find-generic-password -s app.rampart.ai.gemini -a gemini-api-key -w` | behaviour R36 | **missed** |
| X5-14 | **Steal RamPart's vault keychain item** | Infostealer | `security find-generic-password -s app.rampart.vault.item -w` | behaviour R36 | **missed** |
| X5-15 | **Steal AI chat history (security Q&A)** | Infostealer | copy `…/Rampart/Chats/*` out | behaviour R37/R38 | **missed** |
| X5-16 | **DNS-tunnel exfiltration** | Infostealer | 12+ high-entropy labels `<rand>.exfil.example` | network / behaviour | **missed** |
| X5-17 | **Clipboard sniffing of copied vault password / TOTP** | Spyware | background poll of `NSPasteboard` after user copies a secret | telemetry + behaviour | **missed** (no event kind) |
| X5-18 | **Memory scraping of the unlocked vault** | Infostealer | `lldb -p rampartd` / `vmmap` / `leaks` attach to read plaintext | behaviour (R55 is kill-only) | **missed** |
| X5-19 | **iCloud-sync exfiltration** | Infostealer | stage archive into `…/Mobile Documents/com~apple~CloudDocs/` → leaves via iCloud | behaviour / network | **missed** |

Count: **19 scenarios** — 11 caught, 1 partial (X5-06), 7 missed.

## Top 5 misses by severity

1. **X5-12 RamPart's own password vault is unprotected (High).** `vault.rpvault`, its `Backups/`, and
   `vault.state` under `~/Library/Application Support/Rampart/Vault/` are absent from `@sensitivePaths`
   and from R38's temp-staging filename list. Any process can copy the vault file to `/tmp` and brute
   force it offline with zero behavioural signal — and `VaultGuards.swift` already admits (line 9) it
   "does nothing against someone who copies the vault file and guesses offline." The antivirus does not
   watch its own crown-jewel file. Fix: `docs/security/needs-behaviour.md`.

2. **X5-13 / X5-14 RamPart's Gemini API key and vault keychain items are not watched (High).** R36 only
   matches browser Safe-Storage keywords (`chrome|brave|edge|opera|vivaldi|arc|chromium`). A
   `security find-generic-password -s app.rampart.ai.gemini` / `-s app.rampart.vault.item` by a foreign
   process is invisible. Stealing RamPart's own keychain secrets evades the exact rule meant to catch
   keychain theft. Fix: `docs/security/needs-behaviour.md`.

3. **X5-18 Memory scraping of the unlocked vault (High).** While the vault is unlocked, a debugger or
   memory tool (`lldb -p`, `vmmap`, `leaks`, `task_for_pid`) attaching to `rampartd`/the vault process
   reads plaintext secrets straight out of RAM. R55 fires only on *killing/unloading* a security tool,
   not on *reading* it. Fix: `docs/security/needs-behaviour.md`.

4. **X5-16 DNS-tunnel exfiltration (Medium-High).** No rule scores long or high-entropy DNS labels or
   query-volume bursts to a single parent domain. R42/R44/R45 only match specific hosts/ports. A stealer
   can exfiltrate vault contents a few base32 labels at a time under an attacker domain, fully under the
   radar. Fix: `docs/security/needs-network.md` (resolver-side) + `docs/security/needs-behaviour.md`.

5. **X5-17 Clipboard sniffing of copied secrets (Medium-High).** The vault and Authenticator expose
   "Copy password"/"Copy code". A background process polling `NSPasteboard.changeCount` lifts those
   secrets, but no `EventSource` emits a clipboard-read event, so no rule can ever fire. PasteGuard only
   watches paste *into* Terminal. Fix: `docs/security/needs-telemetry.md` + `docs/security/needs-behaviour.md`.

Also missed: **X5-15** AI chat-history theft (Medium — redacted but reveals the user's security posture
and questions) and **X5-19** iCloud-sync exfil (Medium — data leaves the Mac with no outbound rule firing);
both folded into the needs-behaviour fix.
