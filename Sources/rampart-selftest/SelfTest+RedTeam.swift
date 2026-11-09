import Foundation
import Darwin
import RampartShared
import RampartGuard

// Red-team checks (2026-11-07). Everything runs against a DISPOSABLE `rampartd --user` started here with
// --no-scheduler --no-realtime --no-updates and RAMPART_NO_PRIVILEGED_TOOLS=1, on a scratch root
// (RAMPART_REDTEAM_DIR, default $TMPDIR/rt-<pid>). Nothing touches the installed RamPart.
// Fixtures are inert: EICAR assembled at runtime, com.rampart.test.* names.
// Note: on a machine with RamPart installed, the real daemon may quarantine scratch EICAR files within seconds;
// detection checks then print SKIP instead of failing.

private final class RTDaemon {
    let bin: String, root: URL, sock: String
    var proc: Process?
    init(bin: String, root: URL, sock: String) { self.bin = bin; self.root = root; self.sock = sock }
    var pid: Int32 { proc?.processIdentifier ?? 0 }
    var alive: Bool { proc?.isRunning ?? false }

    @discardableResult func start(socket: String? = nil, wait: Double = 20) -> Bool {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: bin)
        p.arguments = ["--user", "--no-scheduler", "--no-realtime", "--no-updates", "--root", root.path, "--socket", socket ?? sock]
        var env = ProcessInfo.processInfo.environment; env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"; p.environment = env
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return false }
        proc = p
        let deadline = Date().addingTimeInterval(wait)
        while Date() < deadline {
            if !p.isRunning { return false }
            if RT.status(socket ?? sock) { return true }
            usleep(100_000)
        }
        return false
    }
    func stop() {
        guard let p = proc, p.isRunning else { proc = nil; return }
        kill(p.processIdentifier, SIGCONT); p.terminate()
        let d = Date().addingTimeInterval(5)
        while p.isRunning && Date() < d { usleep(50_000) }
        if p.isRunning { kill(p.processIdentifier, SIGKILL) }
        p.waitUntilExit(); proc = nil
    }
    func kill9() { if let p = proc, p.isRunning { kill(p.processIdentifier, SIGKILL); p.waitUntilExit() }; proc = nil }
    func rssMB() -> Double {
        var info = rusage_info_v2()
        let r = withUnsafeMutablePointer(to: &info) { $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V2, $0) } }
        return r == 0 ? Double(info.ri_resident_size) / 1_048_576 : -1
    }
    /// Physical footprint (what Activity Monitor's "Memory" and jetsam count). Resident size also includes clean,
    /// shared and already-freed-but-not-yet-returned malloc pages, so it swings with the allocator, not real use.
    func footprintMB() -> Double {
        var info = rusage_info_v2()
        let r = withUnsafeMutablePointer(to: &info) { $0.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { proc_pid_rusage(pid, RUSAGE_INFO_V2, $0) } }
        return r == 0 ? Double(info.ri_phys_footprint) / 1_048_576 : -1
    }
}

/// Samples a pid's peak RSS in the background.
private final class RSSSampler: @unchecked Sendable {
    private let lock = NSLock(); private var peak = 0.0; private var running = true
    init(_ d: RTDaemon) {
        Thread.detachNewThread { [self] in
            while true {
                lock.lock(); let r = running; lock.unlock(); if !r { return }
                let m = d.rssMB(); lock.lock(); peak = max(peak, m); lock.unlock()
                usleep(100_000)
            }
        }
    }
    func finish() -> Double { lock.lock(); running = false; let p = peak; lock.unlock(); return p }
}

private enum RT {
    static func connect(_ sock: String, timeout: Int = 10) -> Int32 {
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(sock.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return -1 }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { return -1 }
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } } == 0
        guard ok else { close(fd); return -1 }
        var tv = timeval(tv_sec: timeout, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        return fd
    }
    static func call(_ sock: String, _ r: IPCRequest, timeout: Int = 10) -> [IPCResponse] {
        let fd = connect(sock, timeout: timeout); guard fd >= 0 else { return [] }
        defer { close(fd) }
        guard let d = try? IPC.encode(r), IPC.writeFrame(fd: fd, d) else { return [] }
        var out: [IPCResponse] = []
        while let f = IPC.readFrame(fd: fd), let resp = try? JSONDecoder.rampart.decode(IPCResponse.self, from: f) {
            out.append(resp)
            if case .scanProgress = resp { continue }
            break
        }
        return out
    }
    static func status(_ sock: String, timeout: Int = 5) -> Bool {
        if case .status? = call(sock, .status, timeout: timeout).last { return true }; return false
    }
    /// Sends raw bytes, half-closes, and returns the first frame of the reply (nil if the daemon just hung up).
    static func raw(_ sock: String, _ bytes: Data, timeout: Int = 3) -> Data? {
        let fd = connect(sock, timeout: timeout); guard fd >= 0 else { return nil }
        defer { close(fd) }
        _ = IPC.writeFrame(fd: fd, bytes)
        shutdown(fd, SHUT_WR)
        return IPC.readFrame(fd: fd)
    }
    static func frame(_ body: Data) -> Data { var l = UInt32(body.count).bigEndian; return Data(bytes: &l, count: 4) + body }
    static func frameHeader(_ len: UInt32) -> Data { var l = len.bigEndian; return Data(bytes: &l, count: 4) }
    static var eicar: Data {
        Data(["X5O!P%@AP[4\\PZX5", "4(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"].joined().utf8)
    }
}

private struct SplitMix { var s: UInt64; mutating func next() -> UInt64 { s &+= 0x9E3779B97F4A7C15; var z = s
    z = (z ^ (z >> 30)) &* 0xBF58476D1CE4E5B9; z = (z ^ (z >> 27)) &* 0x94D049BB133111EB; return z ^ (z >> 31) }
    mutating func int(_ n: Int) -> Int { Int(next() % UInt64(max(n, 1))) } }

extension SelfTest {
    static func redTeamChecks() {
        redTeamGuardUpdateChecks()   // pure, no daemon
        guard let bin = siblingProduct("rampartd", envOverride: "RAMPART_DAEMON") else { print("SKIP redteam: rampartd unavailable"); return }
        let fm = FileManager.default
        let base = URL(fileURLWithPath: ProcessInfo.processInfo.environment["RAMPART_REDTEAM_DIR"] ?? (SelfTest.fixtureTempDir + "rt-\(getpid())"))
        try? fm.removeItem(at: base)
        defer { if ProcessInfo.processInfo.environment["RAMPART_REDTEAM_KEEP"] != "1" { try? fm.removeItem(at: base) } }
        let root = base.appendingPathComponent("state"), files = base.appendingPathComponent("files")
        for d in [root, files] { try? fm.createDirectory(at: d, withIntermediateDirectories: true) }
        try? Data(#"{"realtime":false,"scheduledQuickScanHours":0,"autoQuarantine":true,"scanArchives":true}"#.utf8).write(to: root.appendingPathComponent("config.json"))
        let sock = base.appendingPathComponent("s").path
        let d = RTDaemon(bin: bin, root: root, sock: sock)
        defer { d.stop() }
        guard d.start() else { check(false, "redteam: scratch daemon starts"); return }
        check(true, "redteam: scratch daemon starts")

        redTeamIPC(d, files: files, base: base)
        redTeamEvasion(d, files: files)
        redTeamProcess(d, files: files, base: base)
        redTeamTamper(d, files: files)
        d.stop()
        if ProcessInfo.processInfo.environment["RAMPART_REDTEAM_KEEP"] != "1" { try? fm.removeItem(at: base) }
    }

    // MARK: 1 + 5. IPC abuse and resource bounds
    private static func redTeamIPC(_ d: RTDaemon, files: URL, base: URL) {
        let sock = d.sock
        let rss0 = d.rssMB()
        // Oversized and truncated frames.
        check(RT.raw(sock, RT.frameHeader(0xFFFF_FFFF) + Data("{}".utf8)) == nil, "redteam ipc: 4 GB length prefix is dropped")
        check(RT.raw(sock, RT.frameHeader(UInt32(IPC.maxFrameLength))) == nil, "redteam ipc: 64 MB length then EOF is dropped")
        for _ in 0..<200 { _ = RT.raw(sock, RT.frameHeader(100) + Data(repeating: 0x7b, count: 10)) }
        check(RT.status(sock), "redteam ipc: alive after oversized + 200 truncated frames")
        // Huge announced lengths held open must not be pre-allocated (slow-body memory DoS).
        let sampler = RSSSampler(d)
        var held: [Int32] = []
        for _ in 0..<40 { let fd = RT.connect(sock); if fd >= 0 { _ = IPC.writeFrame(fd: fd, RT.frameHeader(60 * 1024 * 1024)); held.append(fd) } }
        usleep(1_500_000)
        let rssHeld = d.rssMB()
        held.forEach { close($0) }; held.removeAll()
        check(rssHeld < 400, "redteam ipc: 40 x 60 MB announced frames do not pin memory (RSS \(Int(rssHeld)) MB)")
        // Malformed JSON gets a polite error, not a crash.
        if let r = RT.raw(sock, RT.frame(Data("{not json".utf8))), case .error? = try? JSONDecoder.rampart.decode(IPCResponse.self, from: r) {
            check(true, "redteam ipc: malformed JSON -> error")
        } else { check(false, "redteam ipc: malformed JSON -> error") }
        // Out-of-range / wrong-typed enum payloads.
        let weird = [
            #"{"activity":{"limit":-9223372036854775808}}"#, #"{"activity":{"limit":9223372036854775807}}"#,
            #"{"activity":{"limit":1e400}}"#, #"{"restore":{"id":"not-a-uuid","allow":true}}"#,
            #"{"restore":{"id":"00000000-0000-0000-0000-000000000000","allow":true}}"#,
            #"{"deleteQuarantined":{"id":"00000000-0000-0000-0000-000000000000"}}"#, #"{"bogusCase":{}}"#,
            #"{"status":{},"listDetections":{}}"#, #"{"scan":{"paths":"nope","quick":7}}"#, #"[]"#, #"null"#, #""""#,
            #"{"addAllowRule":{"_0":{"scope":"everything","value":"/","name":""}}}"#,
            #"{"allowRemoteTool":{"id":"com.rampart.test.x","minutes":-99999999}}"#,
            #"{"disableProtection":{"token":"","minutes":2147483647}}"#,
            #"{"sandboxRun":{"id":"00000000-0000-0000-0000-000000000000","confirmation":"RUN"}}"#,
            #"{"forwardEvents":{"_0":[]}}"#, #"{"checkURL":{"url":"\#(String(repeating: "a", count: 200_000)).test"}}"#,
            #"{"scamCheck":{"text":"\#(String(repeating: "x", count: 500_000))","kind":"\u0000"}}"#,
        ]
        var answered = 0
        for w in weird { if RT.raw(sock, RT.frame(Data(w.utf8)), timeout: 10) != nil { answered += 1 } }
        check(answered == weird.count, "redteam ipc: every out-of-range payload answered (\(answered)/\(weird.count))")
        check(RT.status(sock), "redteam ipc: alive after out-of-range payloads")

        // Random-byte fuzz: raw garbage, framed garbage, and byte-flipped valid requests. Deterministic seed.
        let corpus: [IPCRequest] = [.status, .listDetections, .listQuarantine, .activity(limit: 5), .getSettings, .health,
                                    .listAllowRules, .tamperStatus, .remoteAccessReport, .webLookup(host: "x.test")]
        let encoded = corpus.compactMap { try? JSONEncoder.rampart.encode($0) }
        var rng = SplitMix(s: 0x5EED_2026)
        var crashedAt = -1
        let cases = Int(ProcessInfo.processInfo.environment["RAMPART_REDTEAM_FUZZ"] ?? "") ?? 3000
        for i in 0..<cases {
            let kind = rng.int(3)
            var payload: Data
            switch kind {
            case 0: payload = Data((0..<rng.int(300)).map { _ in UInt8(truncatingIfNeeded: rng.next()) })
            case 1: payload = RT.frame(Data((0..<rng.int(2000)).map { _ in UInt8(truncatingIfNeeded: rng.next()) }))
            default:
                var b = encoded[rng.int(encoded.count)]
                for _ in 0..<(1 + rng.int(4)) where !b.isEmpty { b[rng.int(b.count)] = UInt8(truncatingIfNeeded: rng.next()) }
                payload = RT.frame(b)
            }
            _ = RT.raw(sock, payload, timeout: 2)
            if i % 500 == 499, !d.alive { crashedAt = i; break }
        }
        check(crashedAt < 0 && d.alive, "redteam ipc: \(cases) fuzz cases, daemon alive")
        check(RT.status(sock), "redteam ipc: status after fuzz")
        // Connect/disconnect flood.
        for _ in 0..<3000 { let fd = RT.connect(sock); if fd >= 0 { close(fd) } }
        check(RT.status(sock), "redteam ipc: status after 3000 connect/close")
        let peak = sampler.finish()
        check(peak < 400, "redteam resource: peak RSS under fuzz \(Int(peak)) MB (< 400; idle \(Int(rss0)) MB)")

        // Slowloris: 80 idle connections must not lock everyone else out.
        for _ in 0..<80 { let fd = RT.connect(sock); if fd >= 0 { held.append(fd) } }
        usleep(300_000)
        let slowOK = RT.status(sock, timeout: 5)
        held.forEach { close($0) }; held.removeAll()
        check(slowOK, "redteam ipc: status served while 80 idle connections are open (slowloris)")
        usleep(500_000)
        check(RT.status(sock), "redteam ipc: status after slowloris released")

        // Path traversal through restore-to / export: get a quarantined item first.
        let fx = files.appendingPathComponent("com.rampart.test.trav.com")
        try? RT.eicar.write(to: fx)
        _ = RT.call(sock, .scan(paths: [files.path], quick: false), timeout: 60)
        var qid: UUID?
        if case .quarantine(let qs)? = RT.call(sock, .listQuarantine).last { qid = qs.first?.id }
        if let id = qid {
            let existing = base.appendingPathComponent("com.rampart.test.exists.txt")
            try? Data("keep me".utf8).write(to: existing)
            let link = base.appendingPathComponent("com.rampart.test.link")
            try? FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: "/etc")
            let home = NSHomeDirectory()
            let bad = ["/etc/com.rampart.test.x", home + "/../../etc/com.rampart.test.x", home + "/../../private/etc/com.rampart.test.x",
                       existing.path, link.path + "/com.rampart.test.x", "/var/root/com.rampart.test.x", "/Users/Guest/com.rampart.test.x",
                       "/System/com.rampart.test.x", "relative/com.rampart.test.x", "/tmp/com.rampart.test.\u{0}x", ""]
            var refusedRestore = 0, refusedExport = 0
            for p in bad {
                if case .error? = RT.call(sock, .restoreQuarantinedTo(id: id, path: p, allow: true)).last { refusedRestore += 1 }
                if case .error? = RT.call(sock, .exportQuarantined(id: id, path: p)).last { refusedExport += 1 }
            }
            check(refusedRestore == bad.count, "redteam paths: restore-to refuses traversal/system/existing/symlink targets (\(refusedRestore)/\(bad.count))")
            check(refusedExport == bad.count, "redteam paths: export refuses traversal/system/existing/symlink targets (\(refusedExport)/\(bad.count))")
            check((try? String(contentsOf: existing, encoding: .utf8)) == "keep me", "redteam paths: existing file untouched")
            check(!FileManager.default.fileExists(atPath: "/etc/com.rampart.test.x"), "redteam paths: nothing written to /etc")
            if case .error? = RT.call(sock, .sandboxRun(id: id, confirmation: "RUN")).last { check(true, "redteam paths: sandbox run refused under NO_PRIVILEGED_TOOLS") }
            else { check(false, "redteam paths: sandbox run refused under NO_PRIVILEGED_TOOLS") }
            if case .quarantine(let qs)? = RT.call(sock, .listQuarantine).last { check(qs.contains { $0.id == id }, "redteam paths: item still in quarantine after refused restores") }
        } else { print("SKIP redteam paths: no quarantined item (fixture removed by another AV?)") }
        if case .error? = RT.call(sock, .restore(id: UUID(), allow: false)).last { check(true, "redteam paths: restore unknown id -> error") }
        else { check(false, "redteam paths: restore unknown id -> error") }

        // Allow rules that would blind the scanner.
        let broad = ["/", "//", "/Users/", "/System/../", "~", "/users", "/SYSTEM", "/Applications/.", "/private/var/..", "/Library//"]
        var refusedRules = 0
        for v in broad {
            let r = RT.call(sock, .addAllowRule(AllowRuleSpec(scope: .folder, value: v, name: "com.rampart.test.rule"))).last
            if case .error? = r { refusedRules += 1 }
        }
        check(refusedRules == broad.count, "redteam rules: whole-disk/top-level folder allow rules refused incl. case variants (\(refusedRules)/\(broad.count))")
        if case .allowRules(let rs)? = RT.call(sock, .listAllowRules).last {
            for r in rs where r.name == "com.rampart.test.rule" { _ = RT.call(sock, .removeAllowRule(id: r.id)) }
        }

        // Narrow folder rule inside the user's own home stays token-free (path need not exist; nothing is created).
        let narrow = NSHomeDirectory() + "/com.rampart.test.redteam-\(getpid())/sub"
        if case .allowRules(let rs)? = RT.call(sock, .addAllowRule(AllowRuleSpec(scope: .folder, value: narrow, name: "com.rampart.test.rule"))).last {
            check(rs.contains { $0.name == "com.rampart.test.rule" }, "redteam rules: one user-owned subfolder rule needs no token")
            for r in rs where r.name == "com.rampart.test.rule" { _ = RT.call(sock, .removeAllowRule(id: r.id)) }
        } else { check(false, "redteam rules: one user-owned subfolder rule needs no token") }

        // Absurd settings.
        if case .settings(let orig)? = RT.call(sock, .getSettings).last {
            // Broad exclusions need an admin-authenticated session; get one the supported way
            // (requestDisableProtection -> disableProtection(token, minutes: 0) = settings session, no pause).
            var probe = orig; probe.exclusions = orig.exclusions + ["/private/tmp/com.rampart.test.broad"]
            if case .error? = RT.call(sock, .setSettings(probe)).last { check(true, "redteam settings: broad exclusion without a session refused") }
            else { check(false, "redteam settings: broad exclusion without a session refused") }
            if case .disableToken(let t)? = RT.call(sock, .requestDisableProtection(authorization: nil, reason: "redteam")).last,
               case .ok? = RT.call(sock, .disableProtection(token: t, minutes: 0)).last {
                check(true, "redteam settings: settings session obtained")
            } else { check(false, "redteam settings: settings session obtained") }
            var s = orig; s.scheduledScanHour = -5
            if case .settings(let got)? = RT.call(sock, .setSettings(s)).last { check(got.scheduledScanHour == 0, "redteam settings: negative hour clamped (\(got.scheduledScanHour))") }
            else { check(false, "redteam settings: negative hour answered") }
            s.scheduledScanHour = Int.max
            if case .settings(let got)? = RT.call(sock, .setSettings(s)).last { check(got.scheduledScanHour == 23, "redteam settings: huge hour clamped") }
            else { check(false, "redteam settings: huge hour answered") }
            s = orig; s.exclusions = (0..<100_000).map { "/private/tmp/com.rampart.test.excl/\($0)" }
            let t0 = Date()
            let big = RT.call(sock, .setSettings(s), timeout: 60).last
            if case .settings? = big { check(Date().timeIntervalSince(t0) < 30, "redteam settings: 100k exclusions accepted in \(Int(Date().timeIntervalSince(t0))) s") }
            else { check(false, "redteam settings: 100k exclusions answered") }
            let foot = d.footprintMB()
            check(d.alive && foot > 0 && foot < 400, "redteam settings: alive and bounded after 100k exclusions (footprint \(Int(foot)) MB, resident \(Int(d.rssMB())) MB)")
            s = orig; s.exclusions = ["/"]
            if case .settings(let got)? = RT.call(sock, .setSettings(s)).last { check(!got.exclusions.contains("/"), "redteam settings: excluding / refused") }
            else { check(false, "redteam settings: exclude / answered") }
            _ = RT.call(sock, .setSettings(orig), timeout: 30)
        } else { check(false, "redteam settings: getSettings") }
    }

    // MARK: 3. Detection evasion with inert fixtures
    private static func redTeamEvasion(_ d: RTDaemon, files: URL) {
        let sock = d.sock, fm = FileManager.default
        let dir = files.appendingPathComponent("evasion"); try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        func scan(_ paths: [String], timeout: Int = 90) -> (Int, [Detection], Double)? {
            if case .scanFinished(let n, let ds, let s)? = RT.call(sock, .scan(paths: paths, quick: false), timeout: timeout).last { return (n, ds, s) }
            return nil
        }
        // Renamed with other extensions, and trailing-whitespace padding (allowed by the EICAR spec).
        var named: [String] = []
        for ext in ["txt", "jpg", "pdf", "", "dylib", "app.zip"] {
            let u = dir.appendingPathComponent("com.rampart.test.eicar" + (ext.isEmpty ? "" : "." + ext)); try? RT.eicar.write(to: u); named.append(u.path)
        }
        let padded = dir.appendingPathComponent("com.rampart.test.padded.com"); try? (RT.eicar + Data(repeating: 0x20, count: 40) + Data([0x0d, 0x0a, 0x09, 0x1a])).write(to: padded)   // spec: whitespace pad, <= 128 bytes
        let present = named.filter { fm.fileExists(atPath: $0) }
        if present.count == named.count, let r = scan(named + [padded.path]) {
            let hit = Set(r.1.compactMap(\.path))
            check(named.allSatisfy { hit.contains($0) }, "redteam evasion: EICAR found under every extension (\(hit.count)/\(named.count))")
            check(hit.contains(padded.path), "redteam evasion: EICAR + trailing whitespace found")
        } else { print("SKIP redteam evasion: renamed fixtures removed before scan (another AV?)") }

        // Nested zips: depth 1 must be found (scanArchives on); depth 12 must finish without hanging.
        let z = dir.appendingPathComponent("zips"); try? fm.createDirectory(at: z, withIntermediateDirectories: true)
        var inner = z.appendingPathComponent("com.rampart.test.inner.com"); try? RT.eicar.write(to: inner)
        var depth1: String?
        for level in 1...12 {
            let out = z.appendingPathComponent("com.rampart.test.l\(level).zip")
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/zip"); p.currentDirectoryURL = z
            p.arguments = ["-q", "-j", out.path, inner.path]; p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try? p.run(); p.waitUntilExit()
            if level > 1 { try? fm.removeItem(at: inner) } else { try? fm.removeItem(at: inner) }
            if level == 1 { depth1 = out.path; let keep = z.appendingPathComponent("com.rampart.test.keep1.zip"); try? fm.copyItem(at: out, to: keep); depth1 = keep.path }
            inner = out
        }
        let t0 = Date()
        if let r = scan([z.path], timeout: 120) {
            check(Date().timeIntervalSince(t0) < 120, "redteam evasion: 12-deep nested zip scan finishes (\(Int(Date().timeIntervalSince(t0))) s)")
            if let p = depth1, fm.fileExists(atPath: p) || r.1.contains(where: { $0.path == p }) {
                check(r.1.contains { $0.path == p }, "redteam evasion: EICAR inside a zip found")
            }
        } else { check(false, "redteam evasion: nested zip scan answered") }

        // Zip bomb: 1 GB of zeros in a few MB, plus EICAR at depth 1. Scan must stay bounded.
        let bombDir = dir.appendingPathComponent("bomb"); try? fm.createDirectory(at: bombDir, withIntermediateDirectories: true)
        let zeros = bombDir.appendingPathComponent("com.rampart.test.zeros.bin")
        if fm.createFile(atPath: zeros.path, contents: nil), let h = try? FileHandle(forWritingTo: zeros) {
            let mb = Data(count: 1 << 20); for _ in 0..<1024 { h.write(mb) }; try? h.close()
            let bomb = bombDir.appendingPathComponent("com.rampart.test.bomb.zip")
            let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
            p.arguments = ["-q", "-j", "-9", bomb.path, zeros.path]; p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
            try? p.run(); p.waitUntilExit(); try? fm.removeItem(at: zeros)
            let size = ((try? fm.attributesOfItem(atPath: bomb.path))?[.size] as? Int) ?? 0
            let sampler = RSSSampler(d); let t1 = Date()
            let r = scan([bombDir.path], timeout: 180)
            let peak = sampler.finish()
            check(r != nil && Date().timeIntervalSince(t1) < 180, "redteam evasion: zip bomb (\(size / 1024) KB -> 1 GB) scan finishes in \(Int(Date().timeIntervalSince(t1))) s")
            check(peak < 400, "redteam resource: zip bomb peak RSS \(Int(peak)) MB")
            check(d.alive, "redteam evasion: alive after zip bomb")
        }

        // Sparse 20 GB file, symlink loops, unreadable files, a file growing during the scan.
        let misc = dir.appendingPathComponent("misc"); try? fm.createDirectory(at: misc, withIntermediateDirectories: true)
        let sparse = misc.appendingPathComponent("com.rampart.test.sparse.bin")
        fm.createFile(atPath: sparse.path, contents: nil); truncate(sparse.path, 20 << 30)
        try? fm.createSymbolicLink(atPath: misc.appendingPathComponent("loopA").path, withDestinationPath: misc.appendingPathComponent("loopB").path)
        try? fm.createSymbolicLink(atPath: misc.appendingPathComponent("loopB").path, withDestinationPath: misc.appendingPathComponent("loopA").path)
        try? fm.createSymbolicLink(atPath: misc.appendingPathComponent("self").path, withDestinationPath: misc.path)
        try? fm.createSymbolicLink(atPath: misc.appendingPathComponent("etc").path, withDestinationPath: "/etc")
        let locked = misc.appendingPathComponent("com.rampart.test.locked.com"); try? RT.eicar.write(to: locked); chmod(locked.path, 0)
        let lockedDir = misc.appendingPathComponent("lockeddir"); try? fm.createDirectory(at: lockedDir, withIntermediateDirectories: true); chmod(lockedDir.path, 0)
        let growing = misc.appendingPathComponent("com.rampart.test.growing.bin")
        fm.createFile(atPath: growing.path, contents: nil)
        final class Flag: @unchecked Sendable { var stop = false }
        let flag = Flag()
        Thread.detachNewThread {
            guard let h = try? FileHandle(forWritingTo: growing) else { return }
            var n = 0
            while !flag.stop && n < 400 { h.write(Data(repeating: UInt8(n & 0xff), count: 256 * 1024)); if n % 50 == 0 { try? h.truncate(atOffset: 0) }; n += 1; usleep(5000) }
            try? h.close()
        }
        let t2 = Date()
        let r = scan([misc.path, misc.appendingPathComponent("loopA").path, misc.appendingPathComponent("self").path], timeout: 120)
        flag.stop = true
        check(r != nil && Date().timeIntervalSince(t2) < 60, "redteam evasion: sparse/loops/unreadable/growing scan finishes in \(Int(Date().timeIntervalSince(t2))) s")
        check(d.alive, "redteam evasion: alive after misc scan")
        chmod(locked.path, 0o600); chmod(lockedDir.path, 0o700)
        try? fm.removeItem(at: sparse)
    }

    // MARK: 4. Process-level
    private static func redTeamProcess(_ d: RTDaemon, files: URL, base: URL) {
        let sock = d.sock, fm = FileManager.default
        // SIGSTOP / SIGCONT during a scan.
        let pd = files.appendingPathComponent("stopcont"); try? fm.createDirectory(at: pd, withIntermediateDirectories: true)
        for i in 0..<300 { try? Data("com.rampart.test clean \(i)".utf8).write(to: pd.appendingPathComponent("f\(i).txt")) }
        final class Box: @unchecked Sendable { var r: [IPCResponse] = [] }
        let box = Box(); let g = DispatchGroup(); g.enter()
        DispatchQueue.global().async { box.r = RT.call(sock, .scan(paths: [pd.path], quick: false), timeout: 60); g.leave() }
        usleep(50_000); kill(d.pid, SIGSTOP); usleep(2_000_000); kill(d.pid, SIGCONT)
        let finished = g.wait(timeout: .now() + 60) == .success
        if case .scanFinished? = box.r.last, finished { check(true, "redteam process: scan completes after SIGSTOP/SIGCONT") }
        else { check(false, "redteam process: scan completes after SIGSTOP/SIGCONT") }
        check(RT.status(sock), "redteam process: status after SIGSTOP/SIGCONT")

        // Second daemon on the same state root (different socket) must refuse.
        let d2 = RTDaemon(bin: d.bin, root: d.root, sock: base.appendingPathComponent("s2").path)
        let second = d2.start(wait: 8)
        check(!second, "redteam process: second daemon on the same root refuses to start")
        d2.stop()
        // Same socket: must refuse and leave the first one serving.
        let d3 = RTDaemon(bin: d.bin, root: d.root, sock: sock)
        _ = d3.start(wait: 3); usleep(500_000)
        check(!d3.alive, "redteam process: second daemon on the same socket exits")
        d3.stop()
        check(RT.status(sock), "redteam process: first daemon still serving")

        // kill -9 in the middle of state writes, then restart: state must still parse and nothing must be lost.
        guard case .settings(let orig)? = RT.call(sock, .getSettings).last else { check(false, "redteam process: getSettings"); return }
        let hashRule = AllowRuleSpec(scope: .fileHash, value: String(repeating: "ab", count: 32), name: "com.rampart.test.keep")
        _ = RT.call(sock, .addAllowRule(hashRule))
        for round in 0..<5 {
            final class Stop: @unchecked Sendable { var v = false }
            let stop = Stop()
            Thread.detachNewThread {
                var i = 0
                while !stop.v {
                    var s = orig; s.scheduledScanHour = i % 24; s.exclusions = (0..<(i % 50) * 100).map { "/private/tmp/com.rampart.test.x\($0)" }
                    _ = RT.call(sock, .setSettings(s), timeout: 2)
                    _ = RT.call(sock, .addAllowRule(AllowRuleSpec(scope: .fileHash, value: String(format: "%064x", i + round * 100_000), name: "com.rampart.test.churn")), timeout: 2)
                    i += 1
                }
            }
            usleep(useconds_t(200_000 + round * 150_000))
            d.kill9(); stop.v = true; usleep(100_000)
            for f in ["config.json", "allowrules.json", "detections.json", "state.json"] {
                let u = d.root.appendingPathComponent(f)
                if let data = try? Data(contentsOf: u) {
                    check((try? JSONSerialization.jsonObject(with: data)) != nil, "redteam process: \(f) valid JSON after kill -9 (round \(round))")
                }
            }
            check(d.start(), "redteam process: restarts after kill -9 (round \(round))")
        }
        if case .allowRules(let rs)? = RT.call(sock, .listAllowRules).last {
            check(rs.contains { $0.name == "com.rampart.test.keep" }, "redteam process: earlier allow rule survives kill -9 churn")
            for r in rs where r.name.hasPrefix("com.rampart.test.") { _ = RT.call(sock, .removeAllowRule(id: r.id)) }
        } else { check(false, "redteam process: listAllowRules after restart") }
        _ = RT.call(sock, .setSettings(orig), timeout: 30)
    }

    // MARK: 2. Tampering with the instance's state files
    private static func redTeamTamper(_ d: RTDaemon, files: URL) {
        let sock = d.sock, fm = FileManager.default, root = d.root
        // Seed: a detection, a quarantined item, an allow rule, activity rows.
        let fx = files.appendingPathComponent("com.rampart.test.tamper.com"); try? RT.eicar.write(to: fx)
        _ = RT.call(sock, .scan(paths: [fx.path], quick: false), timeout: 60)
        _ = RT.call(sock, .addAllowRule(AllowRuleSpec(scope: .fileHash, value: String(repeating: "cd", count: 32), name: "com.rampart.test.tamper")))
        func detCount() -> Int? { if case .detections(let ds)? = RT.call(sock, .listDetections).last { return ds.count }; return nil }
        func ruleKept() -> Bool { if case .allowRules(let rs)? = RT.call(sock, .listAllowRules).last { return rs.contains { $0.name == "com.rampart.test.tamper" } }; return false }
        let dets0 = detCount() ?? 0
        d.stop()

        func restartCheck(_ what: String, keepRules: Bool = true, keepDets: Bool = true) {
            let up = d.start()
            check(up, "redteam tamper: daemon starts after \(what)")
            guard up else { return }
            check(RT.status(sock), "redteam tamper: status after \(what)")
            if keepRules { check(ruleKept(), "redteam tamper: allow rule kept after \(what)") }
            if keepDets { check((detCount() ?? -1) >= dets0, "redteam tamper: detections kept after \(what)") }
            d.stop()
        }
        let cfg = root.appendingPathComponent("config.json"), rules = root.appendingPathComponent("allowrules.json")
        let dets = root.appendingPathComponent("detections.json"), act = root.appendingPathComponent("activity.jsonl")
        let cfgOrig = try? Data(contentsOf: cfg)
        try? Data("{\"realtime\": tru".utf8).write(to: cfg); restartCheck("corrupt config.json")
        try? Data().write(to: cfg); restartCheck("empty config.json")
        try? Data(#"{"realtime":"yes","scheduledScanHour":-99,"maxFileSizeMB":-1,"exclusions":7}"#.utf8).write(to: cfg); restartCheck("wrong-typed config.json")
        if let c = cfgOrig { try? c.write(to: cfg) }
        // Corrupting detections must not cost the allow rules (and vice versa).
        if let orig = try? Data(contentsOf: dets) {
            try? orig.prefix(orig.count / 2).write(to: dets); restartCheck("truncated detections.json", keepDets: false)
            try? orig.write(to: dets)
        }
        if let orig = try? Data(contentsOf: rules) {
            try? orig.prefix(orig.count / 2).write(to: rules); restartCheck("truncated allowrules.json", keepRules: false)
            try? orig.write(to: rules); restartCheck("restored allowrules.json")
        }
        // Huge activity log (60 MB of junk lines) must not blow up memory at start.
        if let h = { fm.createFile(atPath: act.path, contents: nil); return try? FileHandle(forWritingTo: act) }() {
            let line = Data((String(repeating: "x", count: 1000) + "\n").utf8)
            var chunk = Data(); for _ in 0..<1000 { chunk.append(line) }
            for _ in 0..<60 { h.write(chunk) }; try? h.close()
            let up = d.start()
            check(up && d.rssMB() < 400, "redteam tamper: 60 MB junk activity.jsonl -> starts, RSS \(Int(d.rssMB())) MB")
            if up { if case .activity? = RT.call(sock, .activity(limit: 10)).last { check(true, "redteam tamper: activity answers after junk log") } else { check(false, "redteam tamper: activity answers after junk log") } }
            d.stop()
        }
        // Symlink swap: detections.json -> a victim file outside the state root. The daemon must not write through it.
        let victim = files.appendingPathComponent("com.rampart.test.victim.txt"); try? Data("victim".utf8).write(to: victim)
        if let orig = try? Data(contentsOf: dets) {
            try? fm.removeItem(at: dets); try? fm.createSymbolicLink(atPath: dets.path, withDestinationPath: victim.path)
            if d.start() {
                let fx2 = files.appendingPathComponent("com.rampart.test.tamper2.com"); try? RT.eicar.write(to: fx2)
                _ = RT.call(sock, .scan(paths: [fx2.path], quick: false), timeout: 60)
                d.stop()
            }
            check((try? String(contentsOf: victim, encoding: .utf8)) == "victim", "redteam tamper: symlinked detections.json does not overwrite its target")
            try? fm.removeItem(at: dets); try? orig.write(to: dets)
        }
        // Unreadable config.
        chmod(cfg.path, 0); restartCheck("chmod 000 config.json"); chmod(cfg.path, 0o600)

        // Vault: flip bytes in an item and its metadata; delete the key.
        let items = root.appendingPathComponent("Quarantine/items")
        let names = (try? fm.contentsOfDirectory(atPath: items.path)) ?? []
        let blobs = names.filter { $0.hasSuffix(".rqf") }, metas = names.filter { $0.hasSuffix(".json") }
        guard d.start() else { check(false, "redteam tamper: start before vault tampering"); return }
        var before = 0
        if case .quarantine(let qs)? = RT.call(sock, .listQuarantine).last { before = qs.count }
        d.stop()
        guard before >= 2, blobs.count >= 2 else { print("SKIP redteam vault: need 2 quarantined items, have \(before)"); return }
        // Item 1: flip a ciphertext byte -> restore must fail and nothing be written.
        let id1 = String(blobs[0].dropLast(4)), b1 = items.appendingPathComponent(blobs[0])
        if var blob = try? Data(contentsOf: b1) { blob[blob.count / 2] ^= 0xFF; try? blob.write(to: b1) }
        // Item 2: flip a metadata byte -> must be hidden/refused, not trusted.
        let m2name = metas.first { !$0.hasPrefix(id1) } ?? metas[0]
        let m2 = items.appendingPathComponent(m2name)
        // The signed sidecar stores the metadata as base64 JSON: flip one byte inside the decoded metadata.
        if let raw = try? Data(contentsOf: m2), var obj = (try? JSONSerialization.jsonObject(with: raw)) as? [String: Any],
           let b64 = obj["metadata"] as? String, var md = Data(base64Encoded: b64), let r = md.range(of: Data("com.rampart.test".utf8)) {
            md[r.lowerBound] = UInt8(ascii: "C"); obj["metadata"] = md.base64EncodedString()
            try? JSONSerialization.data(withJSONObject: obj).write(to: m2)
        } else { check(false, "redteam vault: sidecar layout understood (metadata base64)") }
        guard d.start() else { check(false, "redteam tamper: starts with tampered vault"); return }
        var listed: [QuarantineRecord] = []
        if case .quarantine(let qs)? = RT.call(sock, .listQuarantine).last { listed = qs }
        check(!listed.contains { $0.id.uuidString == String(m2name.dropLast(5)) }, "redteam vault: item with tampered metadata is not listed as trusted")
        if let u = UUID(uuidString: id1), listed.contains(where: { $0.id == u }) {
            let rec = listed.first { $0.id == u }!
            let r = RT.call(sock, .restore(id: u, allow: false)).last
            if case .error? = r { check(true, "redteam vault: flipped ciphertext -> restore refused") } else { check(false, "redteam vault: flipped ciphertext -> restore refused") }
            check(!fm.fileExists(atPath: rec.originalPath), "redteam vault: nothing written for a failed restore")
        }
        d.stop()
        // Delete the vault key: daemon must start, must not silently re-key and pretend old items decrypt.
        let key = root.appendingPathComponent("Quarantine/vault.key")
        try? fm.removeItem(at: key)
        let up = d.start()
        check(up, "redteam vault: daemon starts without vault.key")
        if up {
            check(RT.status(sock), "redteam vault: status without vault.key")
            if case .quarantine(let qs)? = RT.call(sock, .listQuarantine).last, let q = qs.first {
                if case .error? = RT.call(sock, .restore(id: q.id, allow: false)).last { check(true, "redteam vault: restore without key refused") }
                else { check(false, "redteam vault: restore without key refused") }
            }
            check(ruleKept(), "redteam vault: allow rules unaffected by vault damage")
            d.stop()
        }
    }

    // MARK: Guard: legitimate update vs swapped binary (lead request 2026-11-07)
    static func redTeamGuardUpdateChecks() {
        let fm = FileManager.default
        let tmp = NSTemporaryDirectory() + "rt-guard-\(getpid())"
        try? fm.removeItem(atPath: tmp); try? fm.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: tmp) }
        let paths = GuardPaths.scratch(tmp)
        func ev(_ kind: SecurityEventKind, pid: Int32 = 1900, path: String? = nil, dest: String? = nil, args: [String] = [], detail: [String: String] = [:]) -> SecurityEvent {
            SecurityEvent(date: Date(), kind: kind, process: ProcessInfoLite(pid: pid, ppid: 1, path: args.first ?? "/bin/sh", args: args, uid: 501, signingID: nil),
                          path: path, destPath: dest, detail: detail, source: "redteam")
        }
        func makeBundle(_ at: String, bundleID: String = RamPartIdentity.appBundleID, daemonID: String = RamPartIdentity.daemonSigningID) -> Bool {
            let helpers = at + "/Contents/Helpers", macos = at + "/Contents/MacOS"
            for dir in [helpers, macos] { try? fm.createDirectory(atPath: dir, withIntermediateDirectories: true) }
            let info = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>CFBundleIdentifier</key><string>\(bundleID)</string><key>CFBundleExecutable</key><string>RamPart</string><key>CFBundlePackageType</key><string>APPL</string></dict></plist>"
            try? Data(info.utf8).write(to: URL(fileURLWithPath: at + "/Contents/Info.plist"))
            for (src, dst) in [("/usr/bin/true", macos + "/RamPart"), ("/usr/bin/true", helpers + "/rampartd"), ("/usr/bin/true", helpers + "/rampart")] {
                try? fm.removeItem(atPath: dst); try? fm.copyItem(atPath: src, toPath: dst)
            }
            func sign(_ args: [String]) -> Bool {
                let p = Process(); p.executableURL = URL(fileURLWithPath: "/usr/bin/codesign"); p.arguments = args
                p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
                do { try p.run() } catch { return false }; p.waitUntilExit(); return p.terminationStatus == 0
            }
            return sign(["--force", "-s", "-", "--identifier", daemonID, helpers + "/rampartd"])
                && sign(["--force", "-s", "-", "--identifier", RamPartIdentity.cliSigningID, helpers + "/rampart"])
                && sign(["--force", "-s", "-", "--identifier", "app.rampart.app.main", macos + "/RamPart"])
                && sign(["--force", "-s", "-", at])
        }
        let staged = tmp + "/.RamPart-new.app"
        guard makeBundle(staged) else { print("SKIP redteam guard: codesign unavailable for fixtures"); return }
        check(RamPartIdentity.isValidBundle(staged), "redteam guard: ad-hoc RamPart fixture bundle validates")

        // Legit update: ditto new bundle, rm -rf old, mv new in, app quit. No alerts.
        let det = TamperDetector(paths: paths, ownPIDs: { [4242] }); det.updateGrace = 0.2
        _ = makeBundle(paths.appBundle)
        var alerts: [Detection] = []
        alerts += det.inspect(ev(.exec, args: ["/usr/bin/ditto", tmp + "/dist/RamPart.app", staged]))
        alerts += det.inspect(ev(.exec, args: ["/usr/bin/osascript", "-e", "quit app \"RamPart\""]))
        alerts += det.inspect(ev(.exec, pid: 1901, args: ["/usr/bin/killall", "RamPart"]))
        alerts += det.inspect(ev(.other, pid: 1901, detail: ["es_event": "signal", "sig": "15", "target_pid": "5555", "target_path": paths.appBundle + "/Contents/MacOS/RamPart"]))
        alerts += det.inspect(ev(.exec, pid: 1902, args: ["/bin/rm", "-rf", paths.appBundle]))
        alerts += det.inspect(ev(.fileDelete, pid: 1902, path: paths.appBundle + "/Contents/Helpers/rampartd"))
        try? fm.removeItem(atPath: paths.appBundle)
        alerts += det.inspect(ev(.exec, pid: 1903, args: ["/bin/mv", staged, paths.appBundle]))
        alerts += det.inspect(ev(.fileRename, pid: 1903, path: staged, dest: paths.appBundle))
        try? fm.moveItem(atPath: staged, toPath: paths.appBundle)
        check(alerts.isEmpty, "redteam guard: legit update + app quit raise nothing immediately (\(alerts.map(\.name)))")
        check(det.pendingCount >= 1, "redteam guard: bundle changes held for the grace period")
        usleep(300_000)
        check(det.flushPending().isEmpty, "redteam guard: legit update -> no alert after grace")

        // Launch plist rewritten with RamPart's own job: no alert. Rewritten to run something else: alert.
        try? fm.createDirectory(atPath: (paths.daemonPlist as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        func writePlist(label: String, program: String) {
            let x = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><plist version=\"1.0\"><dict><key>Label</key><string>\(label)</string><key>ProgramArguments</key><array><string>\(program)</string></array></dict></plist>"
            try? Data(x.utf8).write(to: URL(fileURLWithPath: paths.daemonPlist))
        }
        writePlist(label: paths.daemonLabel, program: paths.daemonBinary)
        check(det.inspect(ev(.fileWrite, pid: 1904, path: paths.daemonPlist)).isEmpty, "redteam guard: plist rewrite with RamPart's job -> no alert")
        check(det.inspect(ev(.exec, pid: 1905, args: ["/usr/bin/plutil", "-convert", "xml1", paths.daemonPlist])).isEmpty && det.flushPending(force: true).isEmpty,
              "redteam guard: plutil on an unchanged RamPart plist -> no alert")
        writePlist(label: paths.daemonLabel, program: tmp + "/com.rampart.test.evil")
        check(det.inspect(ev(.fileWrite, pid: 1906, path: paths.daemonPlist)).first?.severity == .critical, "redteam guard: plist pointed at a foreign program -> critical")
        _ = det.inspect(ev(.exec, pid: 1907, args: ["/usr/bin/defaults", "write", paths.daemonPlist, "Disabled", "-bool", "true"]))
        check(det.flushPending(force: true).count == 1, "redteam guard: defaults write on plist with foreign content -> alert after grace")

        // Swapped-in non-RamPart bundle: alert after the grace period.
        let det2 = TamperDetector(paths: paths, ownPIDs: { [4242] }); det2.updateGrace = 0.2
        try? fm.removeItem(atPath: paths.appBundle)
        _ = makeBundle(paths.appBundle, daemonID: "com.rampart.test.impostor")
        check(!RamPartIdentity.isValidBundle(paths.appBundle), "redteam guard: helper with a foreign identifier fails validation")
        check(det2.inspect(ev(.exec, pid: 1910, args: ["/bin/cp", "/tmp/com.rampart.test.evil", paths.appBundle + "/Contents/Helpers/rampartd"])).isEmpty, "redteam guard: swap held during grace")
        usleep(300_000)
        let late = det2.inspect(ev(.exec, pid: 1911, args: ["/bin/ls"]))
        check(late.count == 1 && late[0].name.contains("fileTamper"), "redteam guard: non-RamPart helper swapped in -> fileTamper alert")
        // Unsigned / modified main binary.
        try? fm.removeItem(atPath: paths.appBundle); _ = makeBundle(paths.appBundle)
        if let h = FileHandle(forUpdatingAtPath: paths.appBundle + "/Contents/Helpers/rampartd") { h.seekToEndOfFile(); h.write(Data("x".utf8)); try? h.close() }
        check(!RamPartIdentity.isValidBundle(paths.appBundle), "redteam guard: modified helper fails signature check")
        _ = det2.inspect(ev(.fileWrite, pid: 1912, path: paths.appBundle + "/Contents/Helpers/rampartd"))
        check(det2.flushPending(force: true).count == 1, "redteam guard: modified helper -> alert")
        let wrongID = tmp + "/Other.app"; _ = makeBundle(wrongID, bundleID: "com.rampart.test.other")
        check(!RamPartIdentity.isValidBundle(wrongID), "redteam guard: wrong bundle ID fails validation")
        // Service removal with the bundle intact still alerts: service must keep running.
        let det3 = TamperDetector(paths: paths, ownPIDs: { [4242] }); det3.updateGrace = 0
        try? fm.removeItem(atPath: paths.appBundle); _ = makeBundle(paths.appBundle)
        det3.serviceAlive = { false }
        _ = det3.inspect(ev(.exec, pid: 1913, args: ["/bin/rm", "-rf", paths.appBundle]))
        check(det3.flushPending(force: true).count == 1, "redteam guard: bundle replaced while service is down -> alert")

        // Kills: the app is not the service; the daemon/watchdog are.
        let k = TamperDetector(paths: paths, ownPIDs: { [4242] })
        check(k.inspect(ev(.exec, pid: 1920, args: ["/usr/bin/killall", "RamPart"])).isEmpty, "redteam guard: killall RamPart (app) -> no alert")
        check(k.inspect(ev(.exec, pid: 1921, args: ["/bin/kill", "5555"])).isEmpty, "redteam guard: kill of a non-service pid -> no alert")
        check(k.inspect(ev(.exec, pid: 1922, args: ["/bin/kill", "-9", "4242"])).count == 1, "redteam guard: kill -9 of the daemon pid -> alert")
        check(k.inspect(ev(.exec, pid: 1923, args: ["/usr/bin/killall", "rampartd"])).count == 1, "redteam guard: killall rampartd -> alert")
        check(k.inspect(ev(.exec, pid: 1924, args: ["/usr/bin/pkill", "-f", "RamPart"])).count == 1, "redteam guard: pkill -f RamPart (matches helper cmdline) -> alert")
        check(k.inspect(ev(.exec, pid: 1925, args: ["/usr/bin/pkill", "-x", "RamPart"])).isEmpty, "redteam guard: pkill -x RamPart (app only) -> no alert")
        check(k.inspect(ev(.other, pid: 1926, detail: ["es_event": "signal", "sig": "9", "target_pid": "77", "target_path": paths.appBundle + "/Contents/Helpers/rampartd"])).count == 1,
              "redteam guard: signal to bundled helper -> alert")
        check(k.inspect(ev(.other, pid: 1927, detail: ["es_event": "signal", "sig": "9", "target_pid": "78", "target_path": paths.watchdogBinary])).count == 1,
              "redteam guard: signal to watchdog -> alert")
    }
}
