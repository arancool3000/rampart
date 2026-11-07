# HX1 hardening: Password vault, Authenticator, Password Checker, per-item Touch ID lock (2026-11-07)

Owner files: `Sources/RampartVault/**`, `Sources/RampartApp/Features/Passwords/**`, `Sources/RampartApp/Features/Authenticator/**`.
Regression tests: `Sources/rampart-selftest/SelfTest+HX1.swift` (`SelfTest.hx1Checks()`).
Suites.swift line for the lead: `("hx1", SelfTest.hx1Checks),`

## Threat model

Assets: the master password, the 256-bit vault key, decrypted items (passwords, TOTP secrets, notes, cards, attachments), the Touch ID wrap (`touchid.json` + Secure Enclave key), exports and backups, the breach-check privacy guarantee.

| Attacker | What they can do | What protects the vault |
|---|---|---|
| Thief / another local user with a copy of the vault file | Offline guessing | PBKDF2-HMAC-SHA256 calibrated to ~300 ms (>= 600k iterations), AES-GCM key wrap with KDF params in the AAD. **Only master-password strength limits offline guessing.** |
| Malware running as the user (vault locked) | Edit/replace any file in `~/Library/Application Support/Rampart/Vault`, plant backups, corrupt `touchid.json`, guess via the app | File HMAC, KDF bounds, rollback mark, guess backoff, symlink refusal, no automatic Touch ID downgrade. It can still delete the state files, wait for an unlock and read process memory, or show a fake prompt: same-user malware can't be fully stopped within macOS rules. |
| Malware as the user (vault unlocked) | Read process memory, read the clipboard | Short clipboard lifetime, concealed/transient markers, no Universal Clipboard. Memory can't be protected from same-user code with ptrace-like access (ad-hoc app, no hardened runtime guarantee). |
| A malicious file the user imports (CSV, `.rpexport`, Aegis/2FAS/Bitwarden JSON, Google migration link, QR) | Crash, hang, memory exhaustion, overwrite existing items | Size caps, iteration caps, parameter validation, fresh IDs on collision, fuzzed parsers. |
| Someone watching the screen (screen share, recording, screenshot tool) | See revealed secrets / codes | `NSWindow.sharingType = .none` while secrets are on screen (best-effort, see limits). |
| Network observer / the breach service | Learn passwords | Only a 5-hex-char SHA-1 prefix is sent, with `Add-Padding`, ephemeral session, no cache. |

## Findings

| # | Severity | File:line | Issue | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | RampartVault/VaultStore.swift:87 (`unwrapKey`) | No limit on wrong master passwords; `verifyMasterPassword` (Show Setup Links, per-item reveal) was an unthrottled oracle. | `UnlockThrottle` (VaultGuards.swift): 5 free tries, then 5 s doubling to 5 min; persisted 0600 + kept in memory (file deletion doesn't reset the running app), future timestamps clamp to now. Shared by unlock, verify and change-password. | Fixed |
| 2 | High | RampartVault/VaultStore.swift:87, VaultCrypto.swift:18-28 | KDF iterations read from the untrusted header were only checked `>= 1000`: a tampered header with 10^11 iterations hung the app for hours; > 2^32 trapped in `UInt32(iterations)`; an empty salt hit `precondition`. | `acceptableKDF` bounds 1,000...20,000,000 and salt 16...64 bytes, checked before any PBKDF2; `pbkdf2` precondition documents the contract. | Fixed |
| 3 | High | RampartVault/ImportExport.swift:145 | `.rpexport` iterations (u32 from the file) unbounded: a hostile export hung the app ~4 billion iterations. | Same bounds; file size cap; decode errors become `badFormat`; attachment cap enforced. | Fixed |
| 4 | High | RampartVault/VaultStore.swift:131 + VaultGuards.swift `RollbackGuard` | Rollback: putting an older genuine vault file (or a backup) in place was accepted silently, undoing password changes or resurrecting revoked secrets. | Anti-rollback mark `vault.state` (highest generation seen per vault ID). Lower generation => `.rolledBack`; the lock screen shows a checkbox "Open this older copy anyway"; RamPart's own Restore lowers the mark deliberately. | Fixed (limit: same-user malware can delete `vault.state`) |
| 5 | Medium | RampartVault/VaultStore.swift:296 | `restore(backup:)` accepted any parseable vault file (a planted vault from another ID) and copied the path again after validating it (TOCTOU). Backups list followed symlinks. | Same vault ID required; the validated bytes are written (no second read); symlinks/non-regular files skipped in `backups()`. | Fixed |
| 6 | Medium | RampartVault/VaultStore.swift:118 | Vault file read without size or symlink check (memory exhaustion, link to another file). | Symlink refused; 512 MB cap before reading and in `parse`. | Fixed |
| 7 | Medium | RampartApp/Features/Passwords/PasswordsModel.swift:126 | Touch ID downgrade: any Secure Enclave failure (including one caused by corrupting `touchid.json`) made the next master unlock silently switch Touch ID to the weaker keychain "compatibility mode". | First failure re-enrols with a fresh SE key. Compatibility mode now only via an explicit "Use Compatibility Mode (weaker)" button in Settings. | Fixed |
| 8 | Medium | RampartVault/VaultStore.swift:188 | Imports (`insert`) overwrote an existing item when the import used the same UUID; attachments weren't size-checked. | Colliding IDs get a fresh UUID; attachment cap enforced. | Fixed |
| 9 | Medium | RampartVault/TOTP.swift:83, Authenticator.swift:100 | Aegis/2FAS/Bitwarden JSON built TOTPs without validation: digits > 19 overflowed (trap), digits < 0 trapped the loop, period 0 divided by zero, negative HOTP counter trapped in `UInt64(_:)`. | `hotp` clamps digits 1...10; `code`/`secondsRemaining` guard period and non-finite dates; `TOTP.isWellFormed` filter in `Authenticator.parse`; safe counter conversion; 2 MB / 2,000-account input caps. | Fixed |
| 10 | Medium | RampartVault/VaultSession.swift:79 | Copied secrets went to Universal Clipboard (synced to the user's other devices). | `prepareForNewContents(with: .currentHostOnly)`. | Fixed |
| 11 | Medium | RampartApp/Features (all secret views) | Revealed passwords, TOTP codes, setup links and QR codes were visible to screenshots and screen sharing. | `CaptureShield` / `.protectedFromCapture()`: `sharingType = .none` on the Passwords and Authenticator windows while unlocked, on the backup/setup-QR/add/import sheets, and on the lock screen and Password Checker while "show password" is on. Ref-counted, restored afterwards. | Fixed (best-effort, see limits) |
| 12 | Low | RampartVault/VaultSession.swift:36 | Auto-lock idle timer was a default-run-loop-mode timer, so it paused while a modal Save/Open panel or menu was open. | Timer added in `.common` modes. | Fixed |
| 13 | Low | RampartVault/VaultModels.swift:177 | `autoLockMinutes`/`clipboardClearSeconds` of 0 or negative silently disabled idle locking / clipboard clearing; `ClipboardGuard.copy(clearAfter: 0)` never cleared. | Clamped on decode (1...1440 min, 5...600 s) and in `ClipboardGuard` / `AutoLock`. | Fixed |
| 14 | Low | PasswordsModel.swift:562, VaultBrowserView.swift:262 | Exports and saved attachments inherited the umask (often 0644). | `writePrivate` sets 0600. | Fixed |
| 15 | Low | PasswordsModel.swift:506 | CSV / `.rpexport` files read whole without a size check. | 50 MB / 512 MB caps before reading. | Fixed |
| 16 | Low | RampartVault/VaultStore.swift:219 | `changeMasterPassword` checked the password against the file on disk, not the open vault. | Password must unwrap the same key as the unlocked vault. | Fixed |
| 17 | Info | VaultBrowserView.swift:397 | "Require Touch ID to view" also accepts the Mac login password (`.deviceOwnerAuthentication`) and the item is already decrypted in memory. | UI copy now says so plainly. | Documented |
| 18 | Info | VaultAudit.swift:57 | Breach check privacy reviewed: only the 5-char upper-case hex SHA-1 prefix is sent, padded responses, ephemeral session. Regression test added. | none needed | Verified |

## Honest limits (also in UI copy)

- Offline brute force of a stolen vault file is limited only by PBKDF2 cost and master-password strength; the backoff only slows guessing through RamPart.
- Same-user malware can delete `vault.state` and `unlock-throttle.json`, wait for an unlock and read memory, or show a fake Touch ID-looking dialog. Swift `String`s (master password fields, decrypted items in SwiftUI state) can't be reliably zeroed.
- `sharingType = .none` is honoured by most screen sharing and legacy capture APIs, but recent macOS versions don't apply it to every ScreenCaptureKit capture, and it can't stop a camera.
- Compatibility (keychain) Touch ID mode is enforced by RamPart's code, not hardware (already stated in Settings).

## Needs owner

None required. Optional for the lead: register the suite (`("hx1", SelfTest.hx1Checks),` in Suites.swift).
