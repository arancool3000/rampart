# Brief for feature-hardening agents (2026-11-07)

Goal from the user: every RamPart feature must be as close to unbreakable as possible. You are a hostile security reviewer AND the fixer for ONE feature area.
Read ARCHITECTURE.md (ZERO POP-UPS RULE above all) and docs/AGENT-BRIEF-SECURITY.md first.

Method
1. Threat-model your feature: assets, attackers (local malware as the user, a malicious website or message, a hostile network, another local user, a tampered file on disk, prompt injection), and entry points.
2. Attack it with automated tests: fuzz parsers, malformed inputs, path traversal and symlink races, TOCTOU, integer overflows, injection (shell, AppleScript, JS, SQL, prompt), replay, downgrade, timing, resource exhaustion, privilege-boundary crossings, unsafe defaults, secrets in logs, crash-on-input, UI spoofing (attacker text shown as RamPart's voice).
3. Fix every real weakness in the files you own. Add regression tests in a NEW file Sources/rampart-selftest/SelfTest+<ID>.swift with `static func <id>Checks()`, and report the Suites.swift line.
4. Write docs/security/harden-<id>.md: a threat model and findings table (severity, file:line, issue, fix, status). Anything outside your files goes in as "needs owner" with an exact fix.

Rules
- Edit only your owned files. Never weaken an existing protection or test.
- Build only with scripts/agent-build.sh (serialised); ignore build errors in files you don't own and retry.
- Attack only fixtures and disposable scratch instances under your scratchpad; never the installed RamPart, never real user data. No sudo, launchctl, pfctl, tccutil, osascript, keychain reads of real items, pasteboard, Touch ID prompts, network beyond mock URLProtocol, or app launches. Inert synthetic fixtures only (EICAR built at runtime, .test domains).
- Honest limits: if something can't be made unbreakable within macOS's rules, say so plainly in the doc and in UI copy; never claim more than is true.
- Time-box: 40 minutes. Don't commit. Final report: findings fixed, needs-owner items, test counts.
