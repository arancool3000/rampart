# 10 — Testing and evaluation (narrowed scope)

The original research agent was halted mid-write. This version is written from its notes and deliberately
excludes construction of malware-like samples. Real malware is only ever handled in a disposable macOS VM, never in this repo.

## How the labs score Mac products
- **AV-TEST**: Protection, Performance, Usability, 6 points each (18 max). Certification needs at least 10.
  Usability is the false-positive test (about 130k clean files in one report). Blocking a legit app install costs 0.5 points.
  Performance is the slowdown in copying, downloading, installing and launching apps compared with the industry average.
- **AV-Comparatives (2025 Mac test, 9 products, Sequoia)**: certification needs strong protection, zero false positives,
  good performance and working real-time protection. Test machines stay online so cloud features count.
- Sources: av-comparatives.org/mac-security-review-test-2025, av-test.org macOS Sonoma 14.3 / 14.6 reports.

## Safe test inputs
- **EICAR**: 68-byte standard string at file start, optional trailing whitespace, 128 bytes max.
  Assemble it at test time from fragments so no other AV quarantines the repo. Also test it inside a zip.
- **Clean corpus for false positives**: every Mach-O in /usr/bin, /bin, /usr/sbin, /System/Applications and /Applications.
  The target is zero detections from the signature and heuristic engines on Apple-signed and notarized code.
- **Persistence-watcher test**: a LaunchAgent plist labelled `com.bastion.test.<uuid>` whose program is `/usr/bin/true`.
  Expect a "new persistence item" event, then delete the plist during teardown.
- **Quarantine round-trip**: quarantine the EICAR file, verify it's unreadable as EICAR, restore it, and compare hashes.
- **Posture checks**: unit-test the command-output parsers using captured fixture text, not live system state.
- **Network blocklist**: resolve a domain on a test list through the local resolver and expect it to be blocked.

## Test plan (IDs)
| ID | Area | Expected |
|---|---|---|
| T01 | EICAR plain file | Detected by the signature engine |
| T02 | EICAR inside zip | Detected through archive unpacking |
| T03 | EICAR with trailing whitespace | Detected |
| T04 | 129-byte padded EICAR | Not detected (spec compliance) |
| T05 | Clean /usr/bin scan | 0 detections |
| T06 | Clean /Applications scan | 0 detections or only PUA-labelled ones |
| T07 | Test LaunchAgent created | Persistence alert within 5 s |
| T08 | Test LaunchAgent removed | Alert cleared |
| T09 | Quarantine round-trip | Hash matches after restore |
| T10 | Allowlist by hash | Rescan skips the file |
| T11 | Hash DB lookup | Known-bad test hash flagged |
| T12 | Code-sign check | Apple binaries report as valid |
| T13 | Unsigned local build | Reported as unsigned (info only) |
| T14 | Quarantine xattr parse | Origin URL extracted |
| T15 | Posture parser fixtures | Correct pass/fail per check |
| T16 | Blocklist parse (hosts format) | Correct domain count |
| T17 | Blocklist parse (adblock format) | Correct domain count |
| T18 | DNS block | Test domain resolves to 0.0.0.0 |
| T19 | Full-scan performance | Time and peak RSS recorded via `/usr/bin/time -l` |
| T20 | Idle CPU of agent | Under 1% average over 10 min |

## Technique-to-detection-source matrix (MITRE ATT&CK, macOS)
| Technique | Bastion source |
|---|---|
| T1543.001 Launch Agent | Persistence watcher (FSEvents on LaunchAgents dirs) |
| T1543.004 Launch Daemon | Persistence watcher (/Library/LaunchDaemons) |
| T1547.015 Login Items | BTM snapshot diff (`sfltool dumpbtm`) |
| T1053.003 Cron | crontab diff |
| T1546.004 Shell rc files | File watcher on ~/.zshrc and similar |
| T1555.001 Keychain | Unified log stream (securityd) + process heuristics |
| T1059.002 AppleScript | Process monitor (osascript argv) |
| T1059.004 Unix shell | Process monitor (curl pipe sh patterns) |
| T1553.001 Gatekeeper bypass | xattr quarantine removal events |
| T1105 Ingress tool transfer | Download folder watcher + signature scan |
| T1041 Exfil over C2 | Connection monitor (unsigned binaries, webhooks) |
| T1486 Data encrypted for impact | Canary files + write-rate/entropy heuristic |

## Running tests
`swift test` works with Command Line Tools (Swift Testing). Integration tests that touch the real filesystem are gated by `BASTION_INTEGRATION=1`.
