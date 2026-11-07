# harden-hx9 — RampartTelemetry + RampartSigning hardening (2026-11-07)

Owner: B4 (telemetry) + B3 files touched are only in RampartSigning that hx9 owns per task brief.
Files owned/edited: `Sources/RampartTelemetry/**`, `Sources/RampartSigning/**`.
Regression tests: `Sources/rampart-selftest/SelfTest+Hx9.swift` → `SelfTest.hx9Checks()`.

## Threat model

Assets: the real-time event stream (exec/file/persistence/xprotect/tcc), the signing verdict that gates
quarantine, and the privacy of what the user copied to the clipboard.

Attackers and entry points:
- Local malware running as the user: floods events to bury a real detection; spawns very short-lived
  processes; execs via unusual interpreters; crafts argv > 1 MB or with NULs/control chars; spoofs argv[0];
  races pid reuse; runs a decoy `rampartd`; revokes Full Disk Access to blind the primary feed.
- A tampered file on disk: swaps/rewrites a binary after it was inspected (cache poisoning); crafts a
  malformed/hostile Mach-O to crash or exhaust the parser; stapled-vs-unstapled / revoked / ad-hoc / fat
  one-bad-slice signing tricks.
- Hostile `eslogger` JSON (fields with control chars, bidi overrides, huge values) aimed at log injection and
  UI spoofing ("attacker text shown as RamPart's voice").

## Findings and fixes

| Sev | File:line | Issue | Fix | Status |
|---|---|---|---|---|
| High | EventHub.swift (ingest token bucket) | A flood of cheap low-priority events drains the per-source token bucket, so the next **high-priority** security event (exec/persistence/xprotect/tcc) is rate-limited and silently dropped — the event-flood evasion. | High-priority events are never dropped by rate limiting: when the bucket is empty they are admitted anyway and counted in `stats.rateLimitExempt`; only low-priority events shed. | Fixed |
| High | EventHub.swift (buffer backpressure) | Under buffer overflow the old code shed the oldest **high** event once low was exhausted, so an exec flood could evict a real detection sitting in the buffer. | Critical events (xprotectDetection, persistenceAdded/Removed, tccRequest, xattrDelete) get a reserved queue delivered first and never shed by normal backpressure; a separate, much larger hard cap (`critBufferCapacity`) is the only safety valve, counted in `stats.criticalDropped`. | Fixed |
| High | EventHub.swift (health) | If `eslogger` dies because FDA was revoked (or any started source stops), the hub only checked `isAvailable` once at startup — it went blind with no signal, staying "green". | Added a health monitor (`healthCheckInterval`, default 15 s) that detects a started source going down, emits a single high-severity "RamPart lost its real-time event feed" Detection via `onDetection`, keeps retrying `start()`, and emits once (not per tick). `SourceHealthReporting` exposes `isRunning`/`lastError`; EsloggerSource conforms. (needs-telemetry #1 / X4.17) | Fixed |
| Med | EsloggerParser.swift:177; ProcessSweepSource.swift; ExecWatchSource.swift | eslogger JSON fields, argv[0], and paths can carry control chars, NULs and Unicode bidi/zero-width overrides → log-line forgery and UI spoofing. | New `TelemetrySanitize.clean` escapes control chars (incl. newline/CR/tab/ESC), escapes NUL, strips bidi/zero-width scalars, and caps length to 4096; applied to every `SecurityEvent.detail` value in the eslogger, procsweep and execwatch sources. | Fixed |
| Med | EventHub.swift (ingest) / SourceHealth.swift | A decoy process named like a RamPart helper (`/tmp/rampartd`, foreign/ad-hoc signing) borrows the user's trust. | `RampartService.impostorReason` flags a process whose name matches a RamPart service but whose path is outside install locations or whose signing id isn't `app.rampart.*`; the hub annotates the exec (`impostor_rampart`) and raises a medium "Process impersonating RamPart" Detection. Daemon extends `config.rampartInstallPaths` with its real path so it never flags itself. (needs-telemetry #2 / X4.19) | Fixed |
| Med | MachOFile.swift:257 | A crafted Mach-O can embed a huge or deeply nested entitlements plist fed straight to `PropertyListSerialization` → memory/CPU exhaustion. | Parse the entitlements blob only when ≤ 256 KiB and cap the extracted key list to 2048 (real entitlements are tiny). The rest of the parser was already fully bounds-checked via `Reader`; fuzz test added. | Fixed |
| Med | SigningCache.swift:48 | TOCTOU / cache poisoning: the stat key is read before computing the verdict; if the file is swapped or rewritten during inspection, a stale verdict could be cached and later served for a swapped-back file. | `value(for:)` re-reads the identity key (path+inode+size+mtime+ctime) **after** computing and caches only if unchanged; otherwise it recomputes next time. (The key already binds inode+mtime+ctime+size, stronger than cdhash+inode+mtime alone against the local-user attacker who cannot forge ctime.) | Fixed |

## Honest limits (documented, not fully solvable under our constraints)

- **No pre-execution block.** Without the Endpoint Security entitlement we observe exec after the fact; a
  sub-sweep-interval process is only caught by `ExecWatchSource` (kqueue `EVFILT_PROC`) if its parent is a
  watched root. UI must not claim prevention.
- **Clipboard fingerprint salt (needs owner: B5).** `ClipFingerprint.bootSalt` uses
  `kern.bootsessionuuid`, which is world-readable, and emits only 32-bit token hashes. A local process that
  reads the salt could dictionary-attack individual `clip_tokens`. This must match
  `RampartBehaviour.ClipboardFingerprint` byte-for-byte, so it can't change unilaterally. **Exact fix for
  B5:** derive the per-token salt from a daemon-private random key stored root-only (as `ClipboardMemory`
  already does with a random 32-byte key) instead of a world-readable sysctl, and widen the output; change
  both implementations together and keep the self-test cross-check. Until then, `ClipboardMemory` (the
  cross-process match path) already uses a random HMAC key and is not reversible.
- **Bundle resource swaps.** `SigningInspector.inspectCached` keys the cache on the main executable, so a
  swap of a *non-executable* bundle resource after inspection is not caught by the cache (fresh inspection
  with `validateResources` would catch it). Recorded as a residual risk; keying every resource is too costly
  for the scan hot path.
- **argv display (needs owner: B10).** Telemetry keeps `process.args` verbatim for behaviour matching; the
  UI layer must escape args when rendering (detail dict is already sanitised).

## Wiring hooks for the lead / B9

- Register the self-test suite: add `("hx9", SelfTest.hx9Checks),` to `Sources/rampart-selftest/Suites.swift`
  `moduleSuites`.
- `rampartd` should set `EventHub.onDetection = { detection in detectionStore.add(detection) }` so feed-lost
  and impostor Detections reach the store and flip the menu-bar protection state to "not protected".
- `rampartd` should set `hub.config.rampartInstallPaths` to include its actual (installed or dev) binary
  directory so the impostor check never fires on the legitimate daemon/CLI.
- Optionally set `hub.config.sourceSilence` (> 0) to also treat a started-but-silent source as blinded.
