import Foundation
import RampartShared
import RampartYara

// Owned by the yara build agent. Add checks with check(cond, "name").
extension SelfTest {
    static func yara() {
        yaraLanguage()
        yaraXProtectAndEICAR()
    }

    private static func ruleNames(_ r: YaraRules, _ data: [UInt8], _ ext: [String: YaraExternal] = [:]) -> Set<String> {
        Set(r.scan(data, externals: ext).matches.map(\.rule))
    }

    static func yaraLanguage() {
        let src = #"""
        import "hash"
        import "macho"
        private rule Hdr { condition: uint32be(0) == 0x41424344 }
        rule Text { strings: $a = "hello" nocase $b = "World" wide $c = "word" fullword condition: $a and $b and $c }
        rule Hex { strings: $h = { 41 ?? 43 [1-3] 46 ( 47 | 48 49 ) 4? } condition: $h }
        rule HexNeg { strings: $h = { 50 ~51 52 } condition: #h == 1 }
        rule Re { strings: $r = /ab[0-9]{2,3}c/ $w = /x.z/ wide condition: $r and $w }
        rule Counts { strings: $a = "ab" condition: #a == 3 and @a[2] == 4 and !a[1] == 2 and #a in (0..5) == 2 }
        rule Ref { condition: Hdr and filesize < 1KB }
        rule Of { strings: $x1 = "q1" $x2 = "q2" $y = "zz" condition: 2 of ($x*) and none of ($y) and any of them }
        rule ForIn { condition: for all i in (0..3) : ( uint8(i) == 0x41 + i ) }
        rule ForOf { strings: $a = "ABCD" $b = "q1" condition: for any of ($a, $b) : ( $ at 0 ) }
        rule Percent { strings: $p1 = "q1" $p2 = "q2" $p3 = "nope" condition: 50% of them }
        rule HashRule { condition: hash.sha256(0, 4) == "e12e115acf4552b2568b55e93cbd39394c4ef81c82447fafc997882a02d23677" }
        rule Arith { condition: (uint16(0) | 0x0100) == 0x4341 and 7 \ 2 == 3 and 7 % 4 == 3 and -1 < 0 and 1 << 4 == 16 }
        rule StrOps { condition: filepath endswith ".bin" and filepath contains "test" and filepath matches /com\.rampart/ }
        rule Unsupported1 { condition: pe.number_of_sections > 1 }
        rule Unsupported2 { strings: $a = "x" xor condition: $a }
        rule DependsOnSkipped { condition: Unsupported1 }
        rule Broken { condition: and and }
        rule NoMatch { strings: $a = "absent-string" condition: $a }
        """#
        let r = YaraRules.compile([YaraSource(namespace: "t", text: src)], externals: ["filepath": .string("")])
        let st = r.stats
        check(st.total == 19, "yara: parsed 19 test rules (got \(st.total))")
        check(st.skipped == 4, "yara: 4 unsupported/broken rules skipped (got \(st.skipped): \(st.sources.first?.skippedReasons.keys.sorted() ?? []))")
        var data = Array("ABCD".utf8)                   // header for Hdr/ForIn/ForOf/HashRule/Arith
        data += Array(" HeLLo ".utf8)
        data += "World".utf8.flatMap { [$0, 0] }
        data += Array(" a word. ".utf8)
        data += [0x41, 0x99, 0x43, 0x00, 0x00, 0x46, 0x48, 0x49, 0x4F]
        data += Array(" P0R PQR ab123c ".utf8)
        data += "xyz".utf8.flatMap { [$0, 0] }
        data += Array(" q1 q2 ".utf8)
        let ms = ruleNames(r, data, ["filepath": .string("/tmp/com.rampart.test.bin")])
        for name in ["Text", "Hex", "HexNeg", "Re", "Ref", "Of", "ForIn", "ForOf", "Percent", "HashRule", "Arith", "StrOps"] {
            check(ms.contains(name), "yara: rule \(name) matches")
        }
        check(!ms.contains("Hdr"), "yara: private rule not reported")
        check(!ms.contains("NoMatch"), "yara: NoMatch does not match")
        // counts / offsets / lengths
        let counts = YaraRules.compile([YaraSource(namespace: "c", text: #"rule Counts { strings: $a = "ab" condition: #a == 3 and @a[2] == 4 and !a[1] == 2 and #a in (0..5) == 2 }"#)])
        check(ruleNames(counts, Array("ab..ab..ab".utf8)).contains("Counts"), "yara: #count @offset !length #in")
        // fullword negative
        let fw = YaraRules.compile([YaraSource(namespace: "f", text: #"rule F { strings: $c = "word" fullword condition: $c }"#)])
        check(ruleNames(fw, Array("swordfish".utf8)).isEmpty, "yara: fullword rejects embedded word")
        // global rule gates its namespace
        let g = YaraRules.compile([YaraSource(namespace: "g", text: #"global rule G { condition: filesize > 10 } rule A { condition: true }"#)])
        check(ruleNames(g, Array("short".utf8)).isEmpty, "yara: failing global rule suppresses namespace")
        check(ruleNames(g, Array("long enough data".utf8)) == ["G", "A"], "yara: passing global rule")
        // timeout produces a flagged result, never a crash
        let slow = YaraRules.compile([YaraSource(namespace: "s", text: #"rule S { condition: for all i in (0..9000000) : ( uint8(i % 4) == 0x41 or i >= 0 ) }"#)])
        let res = slow.scan(Array("AAAA".utf8), options: YaraScanOptions(timeout: 0.2))
        check(res.timedOut, "yara: per-file timeout enforced")
    }

    static func yaraXProtectAndEICAR() {
        let tmp = FileManager.default.temporaryDirectory.appendingPathComponent("com.rampart.test.yara.\(getpid())")
        try? FileManager.default.createDirectory(at: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tmp) }

        let engine = YaraEngine()
        let status = engine.load()
        guard let stats = status.stats else { check(false, "yara: engine loaded"); return }
        print("  XProtect \(status.xprotectVersion ?? "missing") at \(status.xprotectPath ?? "-"); generic rules: \(status.genericRulesPath ?? "missing")")
        for s in stats.sources {
            let pct = s.total > 0 ? Double(s.compiled) * 100 / Double(s.total) : 0
            print("  \(s.namespace): \(s.compiled)/\(s.total) compiled (\(String(format: "%.1f", pct))%), \(s.skipped) skipped")
            for (rule, why) in s.skippedReasons.sorted(by: { $0.key < $1.key }).prefix(8) { print("    skipped \(rule): \(why)") }
        }
        print("  patterns \(stats.patterns), atoms \(stats.atoms), AC states \(stats.automatonStates), unanchored \(stats.unanchoredPatterns), compile \(String(format: "%.2f", stats.compileSeconds)) s")
        check(status.genericRulesPath != nil, "yara: generic rules found")
        if status.xprotectPath != nil {
            let xp = stats.sources.filter { $0.namespace.hasPrefix("xprotect") }
            let total = xp.reduce(0) { $0 + $1.total }, ok = xp.reduce(0) { $0 + $1.compiled }
            check(total > 400, "yara: XProtect rules present (\(total))")
            check(Double(ok) > 0.9 * Double(total), "yara: >90% of XProtect rules compile (\(ok)/\(total))")
        } else {
            print("  NOTE: XProtect bundle not readable; coverage check skipped")
        }

        // EICAR assembled from fragments at runtime.
        let parts = ["X5O!P%@AP[4\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-", "FILE!$H+H*"]
        let eicar = Array(parts.joined().utf8)
        let rules = engine.compiledRules!
        let mem = rules.scan(eicar)
        check(mem.matches.contains { $0.rule == "Rampart_EICAR_Test_File" }, "yara: EICAR matches in memory")
        check(rules.scan(Array("hello world".utf8)).matches.isEmpty, "yara: benign buffer has no matches")
        let f = tmp.appendingPathComponent("com.rampart.test.eicar.com")
        FileManager.default.createFile(atPath: f.path, contents: Data(eicar))
        let ev = engine.inspect(FileFacts(path: f.path, size: UInt64(eicar.count)))
        check(ev.contains { $0.title == "EICAR-Test-File" && $0.score >= 95 && $0.source == .yara }, "yara: EICAR file evidence score>=95")
        // Disguised Mach-O: copy a harmless Apple binary to a .pdf name.
        let fake = tmp.appendingPathComponent("com.rampart.test.invoice.pdf")
        try? FileManager.default.copyItem(atPath: "/bin/echo", toPath: fake.path)
        check(engine.inspect(FileFacts(path: fake.path, size: 0)).contains { $0.title == "Disguised-Executable" }, "yara: Mach-O with .pdf extension flagged")

        // Classification of an XProtect-style match.
        let c = YaraEngine.classify(YaraMatch(rule: "XProtect_MACOS_ADLOAD_D", namespace: "xprotect:XProtect.yara", tags: [], meta: ["description": "MACOS.ADLOAD.D"], strings: []))
        check(c.detectionName == "XProtect.MACOS.ADLOAD.D" && c.category == .adware && c.score >= 95 && c.source == .xprotect, "yara: XProtect name mapping")

        // False-positive sweep + benchmark over /usr/bin and /bin.
        for dir in ["/usr/bin", "/bin"] {
            let files = ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).map { dir + "/" + $0 }
            let t0 = Date()
            var bytes = 0, scanned = 0, hits: [String] = [], timeouts = 0
            for p in files {
                let r = engine.scan(path: p)
                if r.skippedReason != nil { continue }
                scanned += 1; bytes += r.bytesScanned
                if r.timedOut { timeouts += 1 }
                for m in r.matches { hits.append("\(p): \(m.rule)") }
            }
            let dt = Date().timeIntervalSince(t0)
            print(String(format: "  benchmark %@: %d files, %.1f MB in %.2f s (%.1f MB/s), %d timeouts", dir, scanned, Double(bytes) / 1e6, dt, Double(bytes) / 1e6 / max(dt, 0.001), timeouts))
            for h in hits.prefix(10) { print("    FP " + h) }
            check(hits.isEmpty, "yara: zero matches in \(dir) (\(hits.count))")
            check(scanned > 10, "yara: scanned files in \(dir)")
        }
    }
}
