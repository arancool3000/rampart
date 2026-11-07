import Foundation
import RampartShared

// Quarantine sandbox: checks the generated sandbox-exec profile TEXT only. Nothing is ever run in a sandbox here.
extension SelfTest {
    static func sandboxChecks() {
        let work = "/private/var/folders/xx/T/rampart-q-TEST/work"
        let home = "/Users/rampart-test"
        let exe = work + "/com.rampart.test.tool"
        guard let p = SandboxProfile.generate(workDir: work, allowedExec: [exe], home: home) else {
            check(false, "sandbox: profile generated"); return
        }
        check(p.contains("(version 1)"), "sandbox: versioned profile")
        check(p.contains("(deny default)"), "sandbox: deny by default")
        check(p.contains("(deny network*)"), "sandbox: network denied")
        check(!p.contains("(allow network"), "sandbox: no network allow")
        check(p.contains("(deny process-fork)"), "sandbox: fork denied")
        check(p.contains("(allow process-exec (literal \"\(exe)\"))"), "sandbox: exec only the item")
        check(!p.contains("(allow process-exec*") && !p.contains("(allow process-exec)"), "sandbox: no blanket exec")
        // Writes: the only file-write allow rules are the work dir and /dev/null|zero.
        let writeAllows = p.components(separatedBy: "\n").filter { $0.contains("(allow") && $0.contains("file-write") }
        check(writeAllows.count == 2, "sandbox: two write allow rules")
        check(writeAllows.contains { $0.contains("(subpath \"\(work)\")") }, "sandbox: writes allowed in temp dir")
        check(writeAllows.contains { $0.contains("/dev/null") && !$0.contains("subpath") }, "sandbox: /dev/null literal only")
        check(!p.contains("(allow file-write* (subpath \"/\"))") && !p.contains("(allow file-write*)"), "sandbox: no global write")
        // Sensitive reads denied, and denies come after the broad read allow (later rules win).
        for f in [".ssh", "Library/Keychains", "Documents", "Desktop", "Downloads",
                  "Library/Application Support/Google/Chrome", "Library/Application Support/Firefox", "Library/Safari",
                  "Library/Application Support/Rampart"] {
            check(p.contains("(subpath \"\(home)/\(f)\")"), "sandbox: denies reading ~/\(f)")
        }
        if let allowRead = p.range(of: "(allow file-read*)"), let denyRead = p.range(of: "(deny file-read*") {
            check(allowRead.upperBound <= denyRead.lowerBound, "sandbox: read denies follow the read allow")
        } else { check(false, "sandbox: read rules present") }
        check(p.contains("/Library/Keychains") && p.contains("(subpath \"/Library/Application Support/Rampart\")"), "sandbox: system keychain + vault denied")
        check(!p.contains("(allow mach-lookup)"), "sandbox: mach-lookup is allow-listed, not blanket")
        check(!p.contains("com.apple.coreservices.launchservicesd"), "sandbox: can't reach LaunchServices")
        check(p.contains("deprecated"), "sandbox: profile notes deprecation")

        // Scripts: interpreter + item; /bin/sh trampolines allowed, nothing else.
        if let s = SandboxProfile.generate(workDir: work, allowedExec: ["/bin/sh", work + "/a.sh"], home: home) {
            check(s.contains("(literal \"/bin/sh\")") && s.contains("(literal \"\(work)/a.sh\")"), "sandbox: script exec list")
            check(s.contains("(literal \"/bin/bash\")"), "sandbox: sh trampoline target allowed")
            check(!s.contains("/usr/bin/python3"), "sandbox: no unrelated interpreters")
        } else { check(false, "sandbox: script profile generated") }
        check(SandboxProfile.interpreter(forExtension: "py") == "/usr/bin/python3", "sandbox: .py via python3")
        check(SandboxProfile.interpreter(forExtension: "SH") == "/bin/sh", "sandbox: .sh via sh")
        check(SandboxProfile.interpreter(forExtension: "app") == nil, "sandbox: .app is not a script")
        check(SandboxProfile.interpreter(forShebang: "#!/usr/bin/env python3") == "/usr/bin/python3", "sandbox: env shebang")
        check(SandboxProfile.interpreter(forShebang: "#!/opt/evil/sh") == "/bin/sh", "sandbox: shebang mapped to system interpreter")
        check(SandboxProfile.interpreter(forShebang: "#!/usr/local/bin/node") == nil, "sandbox: unknown interpreter refused")

        // Injection: quotes/newlines in paths can't break out of the SBPL string.
        let evil = work + "/x\")) (allow network*) ((\""
        if let e = SandboxProfile.generate(workDir: work, allowedExec: [evil], home: home) {
            check(!e.contains("(allow network*)") || e.contains("\\\")) (allow network*)"), "sandbox: quote escaped")
            check(e.components(separatedBy: "\n").filter { $0.hasPrefix("(allow network") }.isEmpty, "sandbox: no injected network rule")
        } else { check(true, "sandbox: evil path refused") }
        check(SandboxProfile.generate(workDir: work, allowedExec: [work + "/a\nb"], home: home) == nil, "sandbox: newline refused")
        check(SandboxProfile.generate(workDir: "relative/dir", allowedExec: [exe], home: home) == nil, "sandbox: relative work dir refused")
        check(SandboxProfile.generate(workDir: work, allowedExec: [], home: home) == nil, "sandbox: empty exec list refused")
        check(SandboxProfile.generate(workDir: work, allowedExec: ["tool"], home: home) == nil, "sandbox: relative exec refused")

        // Confirmation rule and names.
        check(!SandboxProfile.confirmationOK("confirmed", confidence: 95), "sandbox: >=90 needs RUN")
        check(SandboxProfile.confirmationOK("RUN", confidence: 95), "sandbox: RUN accepted")
        check(!SandboxProfile.confirmationOK("run", confidence: 90), "sandbox: RUN is case-sensitive")
        check(!SandboxProfile.confirmationOK("confirmed", confidence: nil), "sandbox: unknown confidence needs RUN")
        check(SandboxProfile.confirmationOK("confirmed", confidence: 70), "sandbox: medium needs plain confirm")
        check(!SandboxProfile.confirmationOK("", confidence: 10), "sandbox: empty confirmation refused")
        check(SandboxProfile.safeName("/tmp/../..") != "..", "sandbox: safe name not dot-dot")
        check(!SandboxProfile.safeName("/x/.hidden$(rm)").hasPrefix("."), "sandbox: safe name not hidden")
        check(!SandboxProfile.safeName("/x/a/b\"c").contains("\""), "sandbox: safe name no quotes")
        check(SandboxProfile.timeLimit == 60, "sandbox: 60 s limit")

        // Violation log parsing is scoped to our pids.
        let lines = ["Sandbox: tool(4242) deny(1) file-read-data /Users/rampart-test/.ssh/id_ed25519",
                     "Sandbox: tool(4242) deny(1) network-outbound 1.2.3.4:443",
                     "Sandbox: other(999) deny(1) file-read-data /etc/secret",
                     "tool(4243) deny(1) file-write-create /Users/rampart-test/Desktop/x"]
        let v = SandboxProfile.parseViolations(lines, pids: [4242, 4243])
        check(v.count == 3, "sandbox: parses only our pids")
        check(SandboxProfile.touchedPaths(v) == ["/Users/rampart-test/.ssh/id_ed25519", "/Users/rampart-test/Desktop/x"], "sandbox: touched paths")
    }
}
