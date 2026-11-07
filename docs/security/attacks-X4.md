# Attack set X4 — Blind or disable RamPart without the user noticing (2026-11-07)

Adversary goal: silence, cripple or turn off RamPart so later malware runs unobserved, while the user still
believes they are protected. Every scenario below was proven with INERT, synthetic `SecurityEvent`s and scratch
fixtures in `Sources/rampart-selftest/SelfTest+AttackX4.swift` (`SelfTest.attackX4Checks()`), registered in
`Suites.swift` as `("attackx4", SelfTest.attackX4Checks),` (line 26). Run:

```
RAMPART_NO_PRIVILEGED_TOOLS=1 RAMPART_SCRATCH=<scratch> .build-agents/out/Products/Debug/rampart-selftest attackx4
```

No command is executed, no process killed, no live system state changed. Result: **27 checks pass, 0 fail**.

The layer that is supposed to catch "turn the AV off" is **RampartGuard** (`TamperDetector`, `SealedStore`,
`ProtectionDisableFlow`, `SelfDefencePolicy`). Honest limit (from `GuardSupport.swift`): with no Endpoint
Security entitlement RamPart cannot *block* a root process; it aims to make every attempt **detectable, loud, and
auto-undone**. So "caught" here means "raised a Detection / refused", not "prevented".

## Scenario table

| # | Attack | Attacker | Kill chain | Layer that should catch | Result |
|---|---|---|---|---|---|
| 1 | Stop the service | local admin / malware | `launchctl bootout system/app.rampart.daemon` | Guard `TamperDetector.inspectExec` → unloadAttempt | **Caught** (critical) |
| 2 | Kill the daemon | malware | `pkill -9 rampartd` | Guard killAttempt | **Caught** |
| 3 | Kill the watchdog | malware | `killall app.rampart.watchdog` | Guard killAttempt (service names) | **Caught** |
| 4 | Signal without a tool | in-proc exploit | ES `signal` sig 9 → daemon pid | Guard `.other`/signal branch | **Caught** (critical) |
| 5 | Delete the LaunchDaemon plist | admin | unlink `…/app.rampart.daemon.plist` (eslogger unlink) | Guard plistTamper | **Caught** (critical) |
| 6 | Clear immutable flag then delete | admin | `chflags noschg <daemonBinary>` | Guard "immutable flag cleared" | **Caught** (critical) |
| 7 | Revoke our Full Disk Access (named) | admin | `tccutil reset SystemPolicyAllFiles app.rampart.daemon` | Guard resetters | **Caught** |
| 8 | Revoke ALL FDA (unqualified) | admin | `tccutil reset SystemPolicyAllFiles` | Guard resetters | **MISS** — command never names us, `mentionsUs` false |
| 9 | Roll the clock | admin | `systemsetup -setdate …` / `sntp -sS evil` / `date` | (none) | **MISS** — clock tools not in Guard's vocabulary |
| 10 | Corrupt the scan-cache / hash DB | malware | write `…/support/DB/hashes.sqlite` | Guard fileTamper (support root) | **Caught** (high) |
| 11 | Swap the agent job definition | admin | rename prepared plist onto `agent.plist` | Guard plistTamper | **Caught** |
| 12 | Remove our login/background item | admin / Settings pane | BTM `btm_launch_item_remove` for our label | Guard launchItemRemoved | **Caught** (critical) |
| 13 | Blind the scanner on itself | admin peer via IPC | add exclusion covering RamPart's own paths | Guard `exclusionsCoveringSelf` (refused) | **Caught** |
| 14 | Corrupt sealed config / allow-rules | admin | rewrite `config.json` payload out of band | Guard `SealedStore` HMAC + auto-restore | **Caught** |
| 15 | Race the update-hold grace window | malware posing as updater | write a non-RamPart bundle during the 30 s grace | Guard held bundle re-validated at flush | **Caught** — invalid bundle reported |
| 16 | (control) Legit update | RamPart updater | valid bundle after grace | Guard update awareness | **No false alert** |
| 17 | Blind the only exec feed | admin (revoke FDA) | eslogger exits "not permitted"; restart loop stops | Telemetry `EsloggerSource` | **MISS** — recorded in `lastError` only, never surfaced as a Detection/alert |
| 18 | Clock-manipulate time-boxed trust | admin | roll wall clock back during an authenticated session | Guard `ProtectionDisableFlow` | **Partial/miss** — wall-clock only; rollback keeps the exempt session alive |
| 19 | Impersonate RamPart (UI/menu-bar spoof) | malware | run `/tmp/rampartd` (ad-hoc, fake signing id) | Guard (correctly ignores non-targets) | **Partial** — not a kill target; impostor binary not flagged by Guard (needs signing check in app/telemetry) |
| 20 | (control) Self-action | RamPart itself | our installer / our pid touches our files | Guard self-attribution | **Exempt** — no self-inflicted alerts |

## Summary

- Scenarios: **20** (plus 2 controls, 27 assertions total).
- Caught: **13** (scenarios 1–7, 10–16).
- Partial: **2** (18 clock-bounded sessions, 19 impostor binary).
- Missed: **3** (8 unqualified `tccutil reset`, 9 clock change, 17 telemetry-blind not surfaced).

## Top 5 misses by severity

1. **(High) Telemetry-blind is silent (17).** eslogger is the only post-exec feed. When FDA is pulled, the
   source stops and nothing turns "RamPart is now blind" into a user-visible alert. Everything downstream
   (BehaviourEngine, tamper detection) goes quiet — the single best way to disable RamPart unnoticed.
   Fix → `docs/security/needs-telemetry.md`.
2. **(High) Unqualified `tccutil reset SystemPolicyAllFiles` (8).** Removes RamPart's FDA along with everyone
   else's; not detected because the command doesn't name us. Pairs with #17 to blind us permanently.
   Fix → `docs/security/needs-guard.md`.
3. **(Medium) Clock change not detected (9).** Rolling the clock can expire remote-access allowances and
   signature/definition freshness, re-open token windows, and (with #18) pin an exempt session open.
   Fix → `docs/security/needs-guard.md`.
4. **(Medium) Time-boxed trust uses wall clock only (18).** Sessions/tokens/allowances have no monotonic-clock
   floor; a backward jump keeps a tamper-exempt session alive indefinitely. Fix → `docs/security/needs-guard.md`.
5. **(Low) Impostor `rampartd` binary (19).** A decoy from a non-install path with a foreign signing id is not
   flagged, enabling menu-bar / UI spoofing. A signing/path check belongs in the app/telemetry layer.
   Fix → `docs/security/needs-telemetry.md`.
</content>
