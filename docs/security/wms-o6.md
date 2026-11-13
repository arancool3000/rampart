# WMS o6: detection evasion (2026-11-13)

Owner area: RampartTelemetry (eslogger parser, child streams, EventHub, unified log), RampartBehaviour (rules,
ransomware, stories), DeceptionDetector catch logic, MediaGuard log parsing. Regression suite: `rampart-selftest wmso6`
(`Sources/rampart-selftest/SelfTest+WMSo6.swift`).

## Threat model
A malicious program is already running as the user, or as root after a successful lure. It cannot load a kext or ES
client of its own, but it can do the following:
- choose its own file name, argv[0], environment and signing identifier (ad-hoc),
- copy Apple binaries, which keep their Apple signature,
- write anything to the unified log under any subsystem,
- generate floods of cheap events,
- pace its work to stay under thresholds.

RamPart has no ES AUTH, no NetworkExtension and only ad-hoc signing. Everything below happens after the event. Nothing
here blocks execution.

## Findings (all fixed unless stated)

| # | Evasion (MITRE) | Sev | Fix |
|---|---|---|---|
| 1 | Copied or renamed Apple interpreter or LOLBin (`/tmp/.c/upd` = security, osascript, zsh) skips every name-keyed rule and still gets the Apple ×0.2 trust discount (T1036.003) | High | `ProcessNode.shippedName` from the kernel-attested signing ID of platform binaries is used for positive `process/parent/ancestor/sibling` matches, never for exclusions. A relocated Apple tool gets no Apple trust. New builtin **EV1** (strong 65, devSensitive). Python venvs, toolchains and .app bundles are excluded. |
| 2 | Process-name spoofing: system-daemon file name outside system folders, or faked argv[0] (T1036.004/.005) | Med | Parser records `argv0` mismatch. New builtin **EV3**. Login shells (`-zsh`) are ignored. |
| 3 | Code injection at exec via `DYLD_INSERT_LIBRARIES` (env, `env` command, `LSEnvironment` plist edit) (T1574.006, T1647) | High | Parser captures `dyld_env` (and `dyld_exec_path`). New rule **EV2** (scored on the dylib location, not on the host app's signature, because the target is usually a notarized app). Xcode and ASan injection stay quiet. |
| 4 | Forged unified-log lines: any process can log as `com.apple.xprotect` / TCC / BTM / syspolicy, which creates fake XProtect detections (false-positive injection, critical-queue flood) or frames another app as a clipboard reader (T1562.006) | High | Security meaning is taken only when `processImagePath` is a system image. Self-authored lines are marked `log_spoof`, and new rule **EV4** flags them. |
| 5 | MediaGuard spoof: a forged `Active activity attributions changed to []` ends the tracked mic/cam session, and `isSystemExecutable: true` makes the attacker's bundle "system", so it never alerts | High | JSON records are believed only when the process and sender images are system images. |
| 6 | eslogger flooding / backpressure: the `ChildLineStream` backlog (queued `Data` chunks) was unbounded | Med | 64 MB pending cap. Excess is dropped and counted, the stream resyncs at the next newline (no spliced half-lines), and `onGap` fires. |
| 7 | eslogger desync / kernel drops were invisible | Med | `global_seq_num` holes are counted (`seqGaps`, `seq_gap` detail) and backward jumps are counted as `seqResets`. `GapReporter` emits ≤1 `telemetry_gap` per 10 s. |
| 8 | Hub flood: a storm of identical short-lived execs evicts the real exec from the bounded buffer, with no signal that it did | Med | Identical execs (same ppid, image, argv) beyond 32 per 2 s are collapsed. Hub overflow raises `telemetry_gap` in a single never-shed slot, which is delivered after critical and high-priority events. New rule **EV5** (weak 35, log-only) records it. |
| 9 | Adversarial JSON: very deep nesting (stack exhaustion), multi-key `event` wrapper (ambiguous parse), 50k-argument or MB-size argv into every regex, out-of-range numbers | Med | Nesting pre-scan (48 levels), exactly one event key, argv capped (2048 args / 32 KB each / 512 KB total), safe numeric conversion. |
| 10 | Slow-and-low ransomware (1 file every few minutes) and one worker process per file | High | R02 gets a per-actor slow window (25 files / 4 h) and a machine-wide counter (40, excluding the user's signed GUI apps). |
| 11 | Ransomware using a different random extension per file, and "rename-only" hostage (moving documents into a hidden temp folder) | Med | R04 counts appended unfamiliar extensions (20 / 5 min) and mass relocation (20 / 60 s). Encrypt-then-rename-over was already covered by R02 because the content check follows the rename destination. A test now pins it. |
| 12 | Unbounded per-key tables in BehaviourEngine (thresholds, stories, first-seen, beacons) and RansomwareDetector (notes keyed by file name) under floods | Med | Hard caps (`maxTableEntries`, `maxKeys`). |
| 13 | Decoy bypass via Apple tools: a script running `mdimport -d3` / `qlmanage` on a decoy, or an Apple indexer copied to /tmp (it keeps its signature), was exempt | High | On-demand tools are benign only when launchd started them. The signing-ID exemption also requires a system location. |
| 14 | Decoy bypass via a second name: hard link, clone or copyfile of the decoy, then reading the new path | Med | eslogger now subscribes to `link`, `clone`, `copyfile`. The parser keeps source and destination. DeceptionDetector treats these as `.copy`. |
| 15 | Living off the land, extra coverage: timestomping (`touch -t/-r/-d`, T1070.006), JXA shelling out (T1059.007), `chflags hidden` (T1564.001) from an untrusted chain | Low | New weak rules **EV6**, **EV7**, **EV8**. osascript, curl, python, launchctl, defaults and plutil were already covered (R07/R08/R09/R18/R20/R30/R34/L04/L06/L07). |

## MITRE ATT&CK for macOS checklist (defence-evasion and execution focus)
- T1036.003/.004/.005 (EV1, EV3).
- T1574.006 (EV2, R09).
- T1647 (EV2).
- T1562.001 (R55), .006 (EV4, EV5).
- T1070.003 (L11), .004 (R58), .006 (EV6).
- T1564.001 (EV8), .002 (R16b).
- T1553.001 (L01/R27/L06), T1222.002 (M03/L05), T1140 (L04).
- T1059.002/.004/.006/.007 (R34, L07, R30, EV7).
- T1543.001/.004 (R07), T1546.004 (R12), T1053.003 (R11), T1037.002 (R18), T1569.001 (R08).
- T1055 (EV2, R55M), T1555.001/.003 (R36/R37), T1056.002 (R34), T1115 (R59), T1113 (R51), T1123/T1125 (R50).
- T1486 (R01–R05, RW1, slow R02), T1082 (R56).

## Residual risks / gaps (honest)
- **No exec blocking, no ES AUTH.** Every detection is after the fact.
- **Reflective / in-memory loading** (NSCreateObjectFileImageFromMemory, dlopen from memory, T1620) and code run inside an
  already-trusted interpreter (`python3 -c` with ctypes) leave no exec, and no `mmap` telemetry is subscribed. These are
  only visible through their later side effects.
- **Without eslogger (no FDA/root)**, ExecWatch picks roots by `p_comm`. A renamed shell is not a watch root, so its
  short-lived children can be missed by sampling. EV1 and shipped-name matching only work when the signing ID or
  platform flag is known.
- **`senderImagePath` is forgeable** with the `os_log` dso trick, so EV4 only fires on naive spoofers. Classification
  still relies on `processImagePath`, which cannot be forged.
- **Exec-storm collapse only covers identical execs.** An attacker who varies argv still consumes buffer. The overflow
  is then reported (EV5), but individual events can be lost.
- **Ransomware slower than 25 files / 4 h per actor, or 40 / 4 h machine-wide,** is not caught by counting. Canaries
  (R01) and R03 (primed headers) remain the backstop. Mass deletion after exfiltration (no rewrite) is not scored.
- **Engine and ransomware table caps** drop old context under a deliberate flood. That is an accepted trade-off against
  memory exhaustion.
- **The `log_spoof` handling of pasteboard lines** depends on undocumented message wording, as before.
