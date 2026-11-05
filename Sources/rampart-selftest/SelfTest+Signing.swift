import Foundation
import RampartShared
import RampartSigning

// Owned by the signing build agent (B3).
extension SelfTest {
    static func signing() {
        let det = SigningHeuristicDetector()

        // --- Apple platform binary
        let ls = SigningInspector.inspect(path: "/bin/ls")
        check(ls.info.status == .apple, "signing: /bin/ls is apple (got \(ls.info.status))")
        check(ls.info.signingID == "com.apple.ls", "signing: /bin/ls signing id")
        check(ls.cdhash?.count == 40 || (ls.cdhash?.count ?? 0) >= 40, "signing: /bin/ls cdhash")
        check(det.inspect(FileFacts(path: "/bin/ls", size: 1, kind: .machO, isExecutable: true)).isEmpty, "signing: no evidence for /bin/ls")
        check(det.inspect(FileFacts(path: "/usr/bin/true", size: 1, kind: .fatMachO, isExecutable: true)).isEmpty, "signing: no evidence for /usr/bin/true")

        // --- Mach-O parser on /usr/bin/true
        do {
            let m = try MachOFile(path: "/usr/bin/true")
            check(!m.slices.isEmpty, "macho: true has slices")
            check(m.cpuNames.contains { $0.hasPrefix("arm64") }, "macho: true has arm64 slice (\(m.cpuNames))")
            check(m.slices.allSatisfy { $0.fileType == MachOFile.MH_EXECUTE && $0.is64Bit }, "macho: true is 64-bit MH_EXECUTE")
            check(m.hasCodeSignature, "macho: true has LC_CODE_SIGNATURE")
            check(m.allDylibs.contains { $0.path == "/usr/lib/libSystem.B.dylib" }, "macho: true links libSystem")
            check(m.slices.allSatisfy(\.hasMain), "macho: true has LC_MAIN")
            check(m.slices.first?.codeSignature?.identifier == "com.apple.true", "macho: code directory identifier")
            check(m.userWritableDylibs.isEmpty, "macho: true no user-writable dylibs")
            check(m.slices.allSatisfy { $0.warnings.isEmpty }, "macho: true parsed without warnings")
            print("  /usr/bin/true: fat=\(m.isFat) \(m.cpuNames) cmds=\(m.slices.first?.loadCommands.count ?? 0)")
        } catch { check(false, "macho: parse /usr/bin/true threw \(error)") }
        check((try? MachOFile(data: Data("#!/bin/sh\necho hi\n".utf8))) == nil, "macho: rejects script")
        check((try? MachOFile(data: Data([0xca, 0xfe, 0xba, 0xbe, 0, 0, 0, 52, 0, 0]))) == nil, "macho: rejects java class")
        check((try? MachOFile(data: Data([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1]))) == nil, "macho: rejects truncated header")
        // Malformed: valid header claiming 1000 load commands of bogus size must not crash.
        var bogus = Data([0xcf, 0xfa, 0xed, 0xfe, 0x0c, 0, 0, 1, 0, 0, 0, 0, 2, 0, 0, 0, 0xe8, 3, 0, 0, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        bogus += Data([0x19, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f] + [UInt8](repeating: 0, count: 64))
        if let m = try? MachOFile(data: bogus) { check(!(m.slices.first?.warnings.isEmpty ?? true), "macho: malformed tolerated with warnings") }
        else { check(true, "macho: malformed rejected") }

        // --- Pid variant
        if let me = SigningInspector.inspect(pid: getpid()) {
            check([.adHoc, .unsigned, .unknown, .developerID].contains(me.info.status), "signing: own pid classified (\(me.info.status))")
            check(me.path.hasSuffix("rampart-selftest"), "signing: own pid path")
        } else { check(false, "signing: inspect own pid") }
        if let lp = SigningInspector.inspect(pid: 1) { check(lp.info.status == .apple, "signing: launchd pid 1 is apple (\(lp.info.status))") }

        // --- /Applications
        let apps = ((try? FileManager.default.contentsOfDirectory(atPath: "/Applications")) ?? []).filter { $0.hasSuffix(".app") }.sorted()
        var table: [String] = []
        for a in apps.prefix(25) {
            let p = "/Applications/" + a
            let t0 = Date()
            let r = SigningInspector.inspect(path: p, options: .fast)
            let ev = SigningHeuristicDetector.evaluate(path: p, report: r, macho: nil, provenance: Provenance.read(path: p), isExecutable: true)
            table.append(String(format: "  %-34@ %-11@ team=%-10@ notarized=%-5@ hr=%-5@ ev=%d (%.2fs)", a as NSString,
                                r.info.status.rawValue as NSString, (r.info.teamID ?? "-") as NSString,
                                String(describing: r.info.notarized.map { $0 } as Any) as NSString,
                                String(describing: r.info.hardenedRuntime ?? false) as NSString,
                                SigningHeuristicDetector.combined(ev.map(\.score)), Date().timeIntervalSince(t0)))
            check(r.info.status != .invalid && r.info.status != .revoked, "signing: \(a) not invalid/revoked (\(r.info.status))")
            if r.isTrusted { check(ev.isEmpty, "signing: trusted \(a) gets no evidence") }
        }
        table.forEach { print($0) }
        if FileManager.default.fileExists(atPath: "/Applications/Safari.app") {
            check(SigningInspector.inspect(path: "/Applications/Safari.app", options: .fast).info.status == .apple, "signing: Safari is apple")
        }

        // --- Compiled fixture: ad-hoc (linker signed), stripped (unsigned), tampered (invalid)
        let dir = NSTemporaryDirectory() + "com.rampart.test.signing-\(getpid())/"
        try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: dir) }
        let src = dir + "hello.swift", bin = dir + "com.rampart.test.hello"
        try? "print(\"hello from rampart test\")\n".write(toFile: src, atomically: true, encoding: .utf8)
        if run("/usr/bin/swiftc", ["-o", bin, src]) == 0 {
            let r = SigningInspector.inspect(path: bin)
            check(r.info.status == .adHoc || r.info.status == .unsigned, "signing: swiftc output is adHoc/unsigned (\(r.info.status))")
            check(r.info.teamID == nil, "signing: swiftc output has no team")
            let m = try? MachOFile(path: bin)
            check(m?.slices.first?.codeSignature?.isLinkerSigned == true || m?.slices.first?.codeSignature?.isAdHoc == true, "macho: fixture linker/ad-hoc signed")
            let ev = det.inspect(FileFacts(path: bin, size: 1, kind: .machO, isExecutable: true))
            let c = SigningHeuristicDetector.combined(ev.map(\.score))
            check(!ev.isEmpty && c <= 50 && c >= 20, "signing: adhoc in temp yields capped evidence (\(c))")
            print("  fixture adhoc evidence: \(ev.map { "\($0.title)=\($0.score)" })")

            // Provenance: browser metadata present but quarantine stripped
            let wf = try! PropertyListSerialization.data(fromPropertyList: ["https://example.invalid/x.zip", "https://example.invalid/"], format: .binary, options: 0)
            _ = wf.withUnsafeBytes { setxattr(bin, "com.apple.metadata:kMDItemWhereFroms", $0.baseAddress, wf.count, 0, 0) }
            var pv = Provenance.read(path: bin)
            check(pv.whereFroms.first == "https://example.invalid/x.zip" && pv.quarantineLikelyStripped, "provenance: whereFroms + stripped")
            let ev2 = det.inspect(FileFacts(path: bin, size: 1, kind: .machO, isExecutable: true))
            check(ev2.contains { $0.title == "Quarantine flag removed" } && SigningHeuristicDetector.combined(ev2.map(\.score)) <= 50, "signing: stripped quarantine evidence capped")
            let q = "0083;6ac74a3b;Safari;685C002A-0000-4000-8000-000000000000"
            _ = setxattr(bin, "com.apple.quarantine", q, q.utf8.count, 0, 0)
            pv = Provenance.read(path: bin)
            check(pv.quarantine?.agentName == "Safari" && pv.quarantine?.timestamp == Date(timeIntervalSince1970: 0x6ac74a3b), "provenance: xattr roundtrip")
            check(!pv.quarantineLikelyStripped, "provenance: not stripped when quarantined")

            let stripped = dir + "com.rampart.test.unsigned"
            try? FileManager.default.copyItem(atPath: bin, toPath: stripped)
            if run("/usr/bin/codesign", ["--remove-signature", stripped]) == 0 {
                check(SigningInspector.inspect(path: stripped).info.status == .unsigned, "signing: removed signature -> unsigned")
                check((try? MachOFile(path: stripped))?.hasCodeSignature == false, "macho: stripped has no LC_CODE_SIGNATURE")
            }
            let tampered = dir + "com.rampart.test.tampered"
            try? FileManager.default.copyItem(atPath: bin, toPath: tampered)
            if let fh = FileHandle(forUpdatingAtPath: tampered) {
                try? fh.seek(toOffset: 0x80); fh.write(Data([0x41, 0x41, 0x41, 0x41])); try? fh.close()
                let t = SigningInspector.inspect(path: tampered)
                check(t.info.status == .invalid, "signing: tampered -> invalid (\(t.info.status))")
            }
        } else { check(false, "signing: swiftc fixture compile") }

        // --- Provenance parsing fixtures
        let qq = Provenance.parseQuarantine("0081;5f0e2a1b;Google Chrome;")
        check(qq?.flags == 0x81 && qq?.agentName == "Google Chrome" && qq?.eventID == nil && qq?.isDownload == true, "provenance: parse chrome")
        check(Provenance.parseQuarantine("01c3;6ac74a3b;;")?.userApproved == true, "provenance: user approved flag")
        check(Provenance.parseQuarantine("garbage") == nil, "provenance: rejects garbage")

        // --- Scoring cap and trust rules
        let capped = SigningHeuristicDetector.capCombined([
            Evidence(source: .signing, title: "a", detail: "", score: 50),
            Evidence(source: .signing, title: "b", detail: "", score: 40),
            Evidence(source: .signing, title: "c", detail: "", score: 30)], max: 50)
        check(SigningHeuristicDetector.combined(capped.map(\.score)) <= 50, "signing: cap holds")
        let notarized = SigningReport(path: "/Users/x/Downloads/A.app", info: SigningInfo(status: .developerID, teamID: "ABCDE12345", notarized: true),
                                      cdhash: nil, isPlatformBinary: false, codeFlags: 0, certificateChain: [], validationError: 0,
                                      bundleIdentifier: nil, otherCertificate: false)
        check(SigningHeuristicDetector.evaluate(path: notarized.path, report: notarized, macho: nil,
                                                provenance: Provenance(whereFroms: ["https://x"]), isExecutable: true).isEmpty,
              "signing: notarized Developer ID gets no evidence")
        var revoked = notarized; revoked.info = SigningInfo(status: .revoked)
        let rev = SigningHeuristicDetector.evaluate(path: "/tmp/x", report: revoked, macho: nil, provenance: Provenance(), isExecutable: true)
        check(!rev.isEmpty && SigningHeuristicDetector.combined(rev.map(\.score)) <= 50, "signing: revoked fires, capped")
        var adhocDev = notarized; adhocDev.info = SigningInfo(status: .adHoc)
        check(SigningHeuristicDetector.evaluate(path: "/Users/x/Developer/p/.build/debug/tool", report: adhocDev, macho: nil,
                                                provenance: Provenance(), isExecutable: true).isEmpty, "signing: adhoc in dev path silent")

        // --- Path classes
        check(PathClass.classify("/private/tmp/a") == .temp, "path: /private/tmp is temp")
        check(PathClass.classify("/opt/homebrew/bin/x") == .developer, "path: homebrew is developer")
        check(PathClass.classify("/usr/bin/true") == .system, "path: /usr/bin is system")
        check(PathClass.classify("/usr/local/bin/x") == .userWritable, "path: /usr/local is user-writable")
        check(PathClass.isHidden("/Users/x/Library/.hidden/agent"), "path: hidden in Library")
        check(!PathClass.isHidden("/Users/x/Library/Application Support/x/agent"), "path: normal Library not hidden")

        // --- Cache
        let c0 = SigningInspector.cache.hits
        _ = SigningInspector.inspectCached(path: "/bin/ls"); _ = SigningInspector.inspectCached(path: "/bin/ls")
        check(SigningInspector.cache.hits > c0, "signing: cache hit")
        DispatchQueue.concurrentPerform(iterations: 32) { i in
            _ = SigningInspector.inspectCached(path: i % 2 == 0 ? "/bin/ls" : "/usr/bin/true")
        }
        check(SigningInspector.inspectCached(path: "/usr/bin/true").info.status == .apple, "signing: concurrent cache ok")
    }

    @discardableResult
    private static func run(_ exe: String, _ args: [String]) -> Int32 {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit()
        return p.terminationStatus
    }
}
