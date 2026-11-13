# Agent brief: "World's most secure" hardening pass (2026-11)

RamPart is a free, open-source macOS antivirus at /Users/arankeyhan/Rampart. It is a Swift package, built with
Command Line Tools only (no Xcode, no XCTest). In SwiftUI, `@State` is unavailable: use `@StateVar`. Tests are
`check(cond, "name")` suites in Sources/rampart-selftest, registered in Suites.swift.

Read ARCHITECTURE.md first, including the ZERO POP-UPS RULE. Also read docs/security/*.md (previous hardening and
red-team work) and the module you own.

## Rules (all agents)
- Defensive work only: find weaknesses in RamPart itself and fix them. Never write working malware, exploits for
  third-party software, or anything aimed at systems other than RamPart. Proof-of-concept tests run against
  RamPart's own code, in temp dirs, with harmless markers (EICAR, dummy strings).
- Build ONLY with `scripts/agent-build.sh`, which serialises builds. Test with
  `RAMPART_NO_PRIVILEGED_TOOLS=1 RAMPART_AI_LIVE=0 .build-agents/out/Products/Debug/rampart-selftest [suite...]`.
- Never run privileged tools (sudo, launchctl system, pfctl, tccutil, profiles, security). Never open or launch GUI
  apps. Never take screenshots. Never touch the user's real data or the installed copy in /Applications or
  /Library. Don't commit; the lead commits.
- Stay inside your OWNED AREA. If a fix needs another area, keep it a minimal, additive edit and mention it in your
  report.
- Never weaken, delete or loosen an existing test. If a test is wrong, explain why in the report and add a stricter
  replacement.
- Every finding needs a regression selftest in a new suite file, `SelfTest+WMS<YourID>.swift`. Register it in
  Suites.swift with one line.
- No false positives: the user's own dev tools, LaunchAgents and Apple apps must stay clean. Run the fp1, fp2 and
  snr suites before you finish.
- Write `docs/security/wms-<yourid>.md` with your threat model, findings (severity, status) and residual risks.
  Be honest about the limits: no Endpoint Security or NetworkExtension entitlement, and ad-hoc signing.
- Final report: under 250 words. List findings fixed, tests added, the full selftest result, and anything left for
  the lead.

## Known platform limits (don't "fix" by pretending)
- No ES AUTH means RamPart can't block exec before it happens; Download Gate covers new arrivals.
- No NE means no per-flow filtering. pf and the local DNS filter only.
- Ad-hoc signing means each install changes the cdhash and resets TCC/FDA. Developer ID would fix this; the user
  hasn't bought it.
