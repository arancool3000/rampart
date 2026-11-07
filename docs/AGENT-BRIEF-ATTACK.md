# Brief for attack-ideation agents (2026-11-07)

You are an adversarial security researcher. Imagine attacks against RamPart (a macOS antivirus at /Users/arankeyhan/Rampart) and the Mac it protects, then PROVE whether RamPart catches them with automated, inert tests.
Read ARCHITECTURE.md (ZERO POP-UPS RULE), docs/AGENT-BRIEF-SECURITY.md and docs/security/*.md (what's already covered) first.

Deliverables
1. docs/security/attacks-<id>.md: 15–30 attack scenarios. For each: name, attacker, kill chain (steps), which RamPart layer should catch which step, and the result of your test (caught / partially / missed) with evidence.
2. Sources/rampart-selftest/SelfTest+Attack<ID>.swift with `static func attack<ID>Checks()` (report the Suites.swift line). Each scenario is simulated with INERT stand-ins only:
   - synthetic SecurityEvent sequences fed to the BehaviourEngine;
   - fixture files (EICAR built at runtime as the "payload"; scripts that only echo; plists pointing at /usr/bin/true);
   - URL strings on .test or example.com domains, and mock URLProtocol responses;
   - a disposable `rampartd --user --no-scheduler` on a scratch root with RAMPART_NO_PRIVILEGED_TOOLS=1, killed within 60 s.
   Never write real malicious code, working exploits, real credential stealers, real persistence on this Mac, or anything that touches real user data, the network (beyond mock), or the installed RamPart.
3. For every miss: append to the owner's file an exact fix proposal, docs/security/needs-<module>.md (modules: engine, yara, behaviour, web, network, guard, remediation, signing, telemetry, daemon, app, vault, ai, browser). Do NOT edit production source; 13 other agents own it right now.

Build only with scripts/agent-build.sh. Time-box: 40 minutes. Don't commit. Final report: scenario count, caught/partial/missed, and the top 5 misses by severity.
