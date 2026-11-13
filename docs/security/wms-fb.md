# wms-fb: cryptography and secrets (2026-11-13)

Owned area: `Sources/RampartVault/**` (vault, Touch ID / Secure Enclave, per-item locks, KDF, Authenticator),
Keychain use everywhere (Gemini, VPN, HIBP, vault key), Guard tokens and HMACs, the quarantine vault's
encryption, and RampartVPN's crypto files (review only, plus fixes). Regression suite: `rampart-selftest wmsfb`
(`Sources/rampart-selftest/SelfTest+WMSfb.swift`).

## Threat model

| Attacker | Can | Must not get |
|---|---|---|
| Thief / other local user with a copy of the vault folder (file, backups, `touchid.json`, state) | Offline guessing of the master password; replaying old files; swapping files between vaults | Any item, the vault key, a way past the KDF cost |
| Same-user malware while the vault is **locked** | Read/write every file in `~/Library/Application Support/Rampart/Vault`, run `LAContext`, write the login keychain under its own ACL | The vault key; a Touch ID unlock with a newly enrolled finger; a silent downgrade of KDF/format |
| Someone who learned an **old** master password and kept an old backup | Open that backup | The **current** vault |
| Anyone reading logs, crash reports, IPC replies, `ps`, the pasteboard | Observe everything RamPart emits | Any secret |
| Root | Everything | Nothing (documented limit for the quarantine/Guard keys, which are root-only files) |

Honest limits (unchanged): no Argon2 without a dependency (PBKDF2-HMAC-SHA256 ≥ 600k, calibrated ~300 ms);
Swift `String`s cannot be zeroised; same-user malware can delete `vault.state` / `unlock-throttle.json` or read
process memory while unlocked; compatibility (keychain) Touch ID mode is enforced by RamPart's code, not hardware;
ad-hoc signing means the keychain ACL is tied to a cdhash that changes on every install.

## What was verified (no change needed)

- Vault: AES-256-GCM per item with AAD = vault id | item id; meta AAD; whole-file HMAC-SHA256 under an HKDF
  sub-key covering magic, version, header and body (deletion, reordering, truncation, replay, version bytes).
  KDF parameters sit in the key-wrap AAD, so lowering the iteration count breaks unwrapping. Header bounds
  (1,000…20,000,000 iterations, 16…64-byte salt). GCM nonces: CryptoKit random 96-bit per seal (verified
  distinct across items and across 24 identical quarantine samples).
- Rollback: `generation` inside the MAC; `vault.state` high-water mark (same-user malware can delete it; limit).
- Touch ID / Secure Enclave: P-256 key agreement key in the SE with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`
  + `[.privateKeyUsage, .biometryCurrentSet]`; ephemeral ECDH → HKDF → AES-GCM wrap with the vault id as AAD; the
  SE refuses the key after an enrolment change, `domainState` is compared as a second signal, and the app then
  re-enrols with a fresh SE key after a master-password unlock. `touchid.json` copied to another Mac is useless.
- Keychain: Gemini key read with UI disabled (`SecKeychainSetUserInteractionAllowed(false)`), header only,
  pipe from `/usr/bin/security` (argv holds service + account), never the URL or a log line. VPN keys
  `AfterFirstUnlockThisDeviceOnly`, reads `kSecUseAuthenticationUISkip`, profile.json never holds a key. HIBP
  key in the login keychain, only a boolean flag in defaults. No RamPart item is `kSecAttrSynchronizable`.
- Guard: `IntegrityKey` root-only 0600 in a 0700 dir (owner/mode/symlink checks); domain-separated MACs
  (`sealed.v2`, `disable-token`); constant-time compares; tokens are 128-bit nonce + uid + expiry + MAC,
  single use, uid-bound, wall- and monotonic-clock expiry. Decoy/canary tags: keyed HMAC, 0600 key file.
- Quarantine vault: 32-byte key file (O_NOFOLLOW, owner, exact size, never regenerated silently), HKDF into
  separate enc/MAC keys, AES-GCM with the id as AAD, HMAC sidecar over exact bytes, SHA-256 re-check on restore.
- RampartVPN: BLAKE2s against RFC 7693 (incl. appendix E self-test and keyed KAT), HChaCha20 / XChaCha20
  vectors, WireGuard initial chaining key/hash, Noise_IKpsk2 structure, counter nonces with a 2048-bit replay
  window, mac1/mac2 constant-time, DH rejects the all-zero shared secret, TAI64N replay check on initiations.
- Logs / IPC / pasteboard: RampartVault, Passwords and Authenticator UI contain no logging at all; IPC carries
  no vault type; `ClipboardGuard` writes concealed + transient + current-host-only and clears on a timer, lock
  and quit. `precondition` messages contain no secret.

## Findings

| # | Severity | Where | Problem | Fix | Status |
|---|---|---|---|---|---|
| 1 | High | `VaultStore.changeMasterPassword` | Only re-wrapped the **same** vault key. Every earlier backup (ten are kept next to the vault; Time Machine keeps more) holds that key under the old password. Someone who learned the old password and kept any old copy could still open the **current** vault after the change: the password change did not lock them out. | A password change now generates a fresh 256-bit vault key, re-encrypts meta and every item, and rotates the file-MAC key. `addKeyRotationObserver` lets Touch ID re-wrap; `backupKeyOpensCurrentVault(backup:password:)` lets the UI/audit prove the separation. | Fixed |
| 2 | Medium | `TouchIDUnlock` (compatibility mode) | `touchid.json` was unauthenticated. Same-user code could rewrite `domainState` to the current value (readable by any process via `LAContext`) or drop it, so a newly enrolled fingerprint would unlock the vault; the enrolment-change check was the only defence in this mode. | Record carries an HMAC-SHA256 tag under a key derived from the vault key (HKDF info `touchid-record`), verified after the key is recovered and before the vault opens; a compat record with no enrolment hash is treated as changed; `enable` refuses compat mode when macOS reports no enrolment state. Legacy SE records without a tag still open (hardware enforces `.biometryCurrentSet`). | Fixed |
| 3 | Medium | `TouchIDUnlock` after #1 | After the key rotation the Touch ID wrap would hold a stale key and fail with "tampered". | `refreshWrap()`: SE mode re-wraps under the SE key's public half with a fresh ephemeral key (no prompt); compat mode updates the keychain item; on any failure Touch ID is turned off rather than left broken. Registered automatically on the store. | Fixed |
| 4 | Low | `VaultStore`, `EncryptedExport` | Master and export passwords were hashed as raw UTF-8: "é" typed as one code point or as e + combining accent (different keyboards, pasted text) gave different keys, locking the user out. | NFC-normalised before PBKDF2; unlock/import try NFC then (only when different) the raw form, as one throttled attempt, so vaults wrapped before this change still open. | Fixed |
| 5 | Low | `EncryptedExport.export` | The library accepted any export password (the UI enforced 10 characters; the CLI/API path did not). | `weakExportPassword` for < 10 characters (tests pass explicit iterations). | Fixed |
| 6 | Low | `VaultStore.changeMasterPassword` | Key equality used `==` (early-exit). Not attacker-observable, but keys should never be compared with a short-circuit. | `SecretKeyBytes.constantTimeEquals`. | Fixed |
| 7 | Low | `ProtectionDisableFlow.issueToken` | `SecRandomCopyBytes` failure was ignored: an all-zero nonce would have been handed out (still MAC'd, but predictable and colliding in the issued map). | Falls back to `SystemRandomNumberGenerator`. | Fixed |
| 8 | Info | `Sealed.open` (Guard) | With `path:` given, a v1 envelope is still accepted (`allowV1` defaults to true), so a legacy v1 envelope valid for file A would verify as file B. Needs write access to root-only 0600 files and a captured v1 envelope, so root only; left as is to avoid breaking the v1→v2 migration. | Noted for the Guard owner. | Residual |

## Tests added (`wmsfb`, 83 checks, all passing; vault 148, hx1 53, guard 111, remediation 86, vpn 126 still green)

Known answers: PBKDF2-HMAC-SHA256 (RFC 7914), HMAC-SHA256 (RFC 4231) through `IntegrityKey`, MAC domain
separation, constant-time compares (vault, Guard, WireGuard), KDF bounds, NFC forms, low-order DH point.
Golden vault: a fixed `.rpvault` written by format v1 opens with its password and yields the expected item,
TOTP code, folder and KDF parameters (format stability); near-miss password refused.
Key rotation: control (pre-change backup key opens the live vault) → change → every backup's key refused, items
re-encrypted, MAC changed, old password dead, replayed pre-change file reported as a rollback, wrong current
password changes nothing and is throttled, observer fires once.
Touch ID record: sealed record verifies; rewritten/stripped enrolment hash, mode, wrapped key, vault id or a
different vault key all fail; JSON round trip; optional SE re-wrap path (`RAMPART_VAULT_SE_TEST=1`).
Negative: version 0, flipped MAC, header flip, appended byte, oversized chunk length, item deleted from the
body, export tag/AAD flips, export version 2, 4-billion-iteration export, weak export password.
Secret scan: a vault filled with marker secrets (item/old/Wi-Fi passwords, TOTP, note, card number, CVV,
custom field, attachment, master password) through upsert, insert, meta update, a wrong password, a
password change and an export; every file under the vault folder (vault, backups, `vault.state`,
`unlock-throttle.json`, export) is scanned for each marker raw, base64 and hex; files 0600, folder 0700;
error texts carry no secret. Quarantine: 24 identical samples → 24 distinct nonces and ciphertexts, plaintext
absent from blobs and sidecars, key 0600, short key refused. Guard tokens: random distinct nonces, one-char
MAC change, uid rewrite, single use, foreign key. Keychain: our item not synchronisable, attribute query
returns no data. Source scans: no `print`/`Logger`/`os_log` in RampartVault, Passwords, Authenticator;
Gemini key only in the header/pipe, never argv, URL or a log line; Touch ID unlock calls the tag check and
uses this-device-only + biometryCurrentSet; VPN profile never serialises keys; VPN items this-device-only.

## Residual risks

- Offline brute force of a stolen vault is bounded only by PBKDF2 cost and the master password (≥ 10 chars,
  rated Fair+). Argon2id would be better; it needs a vetted dependency.
- Old backups still open with the old master password (that is what a backup is). After a suspected
  password leak the user should delete `Vault/Backups` (they age out after ten saves).
- Compatibility Touch ID mode: the key is in the login keychain; any process the ACL trusts can read it.
  The new record tag stops enrolment-hash forgery but not a keychain ACL that the user widens by clicking Allow.
- Memory scraping of an unlocked vault, fake Touch ID dialogs, and deletion of state files by same-user
  malware remain out of scope for a user-mode app without the Endpoint Security entitlement.
- Finding 8 (v1 envelopes) for the Guard owner.
