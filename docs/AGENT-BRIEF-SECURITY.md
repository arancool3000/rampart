# Brief for security agents (2026-11-07)

Project: RamPart, a macOS antivirus at /Users/arankeyhan/Rampart. Read ARCHITECTURE.md fully (constraints: Command Line Tools only, no Endpoint Security entitlement, ad-hoc signing; the ZERO POP-UPS RULE), the module(s) you work on, and docs/research/ where relevant.

There are two kinds of security agent:
- **Hardening agents (H1–H10)** add NEW protections. Put new code in the NEW files named in your task. Don't edit existing files unless your task lists them. Write the exact wiring hooks (for rampartd / the app) in your final report; the lead wires them.
- **Audit agents (AU1–AU10)** hunt for weaknesses in existing code: memory/resource exhaustion, path traversal, symlink/TOCTOU races, privilege escalation through the root daemon, injection (shell, AppleScript, JS, prompt), unsafe parsing, crypto misuse, data loss (like the installer bug we just had: it deleted the app because APFS is case-insensitive), information leaks in logs, unauthenticated IPC, unsafe defaults. Fix what you find in the files you own, add regression self-tests, and write a findings table (severity, file:line, issue, fix, status) to docs/security/audit-<your id>.md. Anything outside your files goes in that doc as "needs owner".

Rules for both
- 60 agents work at once. NEVER run `swift build` directly. Build only with `scripts/agent-build.sh --product rampart-selftest` (or `--product RampartApp`). It serialises builds. Ignore build errors in files you don't own, and retry later.
- Tests: add checks to the existing `Sources/rampart-selftest/SelfTest+<Module>.swift` for your module, only inside a new `static func <yourID>Checks()` in a NEW file `Sources/rampart-selftest/SelfTest+<YourID>.swift`. Report the line the lead should add to Suites.swift. Run with `RAMPART_NO_PRIVILEGED_TOOLS=1 .build-agents/out/Products/Debug/rampart-selftest <suite>` once your suite is registered; until then, call your function from a scratch harness if needed.
- ZERO POP-UPS and no live system changes: no sudo, launchctl, pfctl, tmutil, networksetup, osascript, tccutil, keychain reads, pasteboard, camera, mic, or app launches. Use fixtures and dry runs. Never create or download malware. Use synthetic, inert fixtures (EICAR assembled at runtime, com.rampart.test.* names, .test domains).
- Never weaken existing protections or tests. Don't commit. Keep your final report short: findings or features, hooks, test results.
