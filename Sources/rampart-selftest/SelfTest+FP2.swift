import Foundation
import RampartShared
import RampartEngine
import RampartSigning

// FP2: "teach what is and isn't a threat" — one fixture per real-world false-positive category seen on the
// user's Mac (2026-11-07), plus genuinely bad fixtures that must still alert.
extension SelfTest {
    static func fp2Checks() {
        ownDataExclusionChecks()
        let fm = FileManager.default
        let home = NSHomeDirectory() + "/RampartSelfTestFP2-\(getpid())"   // fake home: nothing real is touched
        defer { try? fm.removeItem(atPath: home) }
        let apps = home + "/Applications"
        for d in [apps + "/Trusted.app/Contents/Frameworks", apps + "/OpenThing.app/Contents/Frameworks", apps + "/Dropped.app/Contents/MacOS",
                  home + "/Library/Application Support/Code/CachedExtensionVSIXs", home + "/Downloads", home + "/Rampart/.build/debug"] {
            try? fm.createDirectory(atPath: d, withIntermediateDirectories: true)
        }
        func touch(_ p: String) { fm.createFile(atPath: p, contents: Data("x".utf8)) }
        // Signing: Trusted.app is notarized; everything else ad-hoc.
        let signing: (String) -> SigningInfo? = { p in
            p.hasPrefix(apps + "/Trusted.app") ? SigningInfo(status: .developerID, teamID: "ABCDE12345", notarized: true) : SigningInfo(status: .adHoc)
        }
        // Quarantine fixtures without touching xattrs: Downloads = downloaded, never approved; OpenThing approved; Dropped downloaded.
        let qtn: (String) -> UInt32? = { p in
            if p.hasPrefix(home + "/Downloads/") { return 0x0081 }
            if p.hasPrefix(apps + "/OpenThing.app") { return 0x01c1 }
            if p.hasPrefix(apps + "/Dropped.app") { return 0x0083 }
            return nil
        }
        let ctx = FindingTriage.Context(home: home, signing: signing, quarantineFlags: qtn,
                                        appForSupportFolder: { $0 == "Code" ? apps + "/Trusted.app" : nil })
        func sig(_ title: String, _ score: Int = 30) -> Evidence { Evidence(source: .signing, title: title, detail: "fixture", score: score) }
        func det(_ path: String, _ ev: [Evidence]) -> Detection { Scoring.makeDetection(path: path, sha256: nil, evidence: ev)! }
        func isDecision(_ d: Detection) -> Bool {
            guard let out = FindingTriage.apply(d, ctx).0 else { return false }
            return out.confidence >= Scoring.logThreshold
        }

        // 1. False-positive categories: 0 decisions.
        let benign: [(String, Detection)] = [
            ("SwiftPM build output", det(home + "/Rampart/.build/debug/rampartd", [sig("Ad-hoc signed program", 36)])),
            ("agent temp build", det("/private/tmp/claude-501/x/scratchpad/b9dev/.build-release/out/Products/Release/rampart", [sig("Ad-hoc signed program")])),
            ("DerivedData", det(home + "/Library/Developer/Xcode/DerivedData/App-x/Build/Products/Debug/App", [sig("Ad-hoc signed program")])),
            ("cargo target", det(home + "/Code/tool/target/release/tool", [sig("Unsigned program", 35)])),
            ("pyinstaller cache dylib", det(home + "/Library/Application Support/pyinstaller/bincache/PIL/.dylibs/libz.dylib", [sig("Ad-hoc signed program", 20), sig("Hidden location", 20)])),
            ("dylib in notarized app", det(apps + "/Trusted.app/Contents/Frameworks/libfoo.dylib", [sig("Ad-hoc signed program", 36)])),
            ("approved downloaded app dylib", det(apps + "/OpenThing.app/Contents/Frameworks/libzip.dylib",
                                                   [sig("Downloaded unsigned code", 35), sig("Loads libraries from user-writable folders", 20), sig("Ad-hoc signed program")])),
            ("trusted app's support folder", det(home + "/Library/Application Support/Code/CachedExtensionVSIXs/ext-arm64", [sig("Ad-hoc signed program")])),
            ("LibreOffice-style broken signature", det("/Applications/LibreOfficeTest.app/Contents/MacOS/soffice",
                                                        [sig("Broken code signature", 40), sig("Weakened runtime protections", 10)])),
            ("Python framework broken signature", det("/Library/Application Support/Test/Python.framework/Versions/3.12/Python", [sig("Broken code signature", 40)])),
        ]
        for (name, d) in benign { check(!isDecision(d), "fp2: \(name) is not a decision (\(FindingTriage.classify(d, ctx)))") }
        let broken = benign.last!.1
        if case .note = FindingTriage.classify(broken, ctx) { check(true, "fp2: broken signature in a bundle is a note") }
        else { check(false, "fp2: broken signature in a bundle is a note") }

        // 2. Genuinely bad fixtures still alert / stay findings.
        let eicar = Evidence(source: .heuristic, title: EICAR.detectionName, detail: "fixture", score: 100)
        let bad: [(String, Detection)] = [
            ("downloaded ad-hoc binary", det(home + "/Downloads/installer", [sig("Downloaded unsigned code", 35), sig("Ad-hoc signed program")])),
            ("downloaded build-dir binary", det(home + "/Downloads/.build/payload", [sig("Ad-hoc signed program")])),
            ("unapproved downloaded app", det(apps + "/Dropped.app/Contents/MacOS/Dropped", [sig("Downloaded unsigned code", 35)])),
            ("ad-hoc binary in /Users/Shared", det("/Users/Shared/.x/agent", [sig("Ad-hoc signed program")])),
            ("hidden ad-hoc binary in home", det(home + "/.cache/.x/agent", [sig("Ad-hoc signed program", 20), sig("Hidden location", 20)])),
            ("EICAR in a build dir", det(home + "/Rampart/.build/debug/com.rampart.test.eicar.com", [eicar])),
            ("hash hit in a dev folder", det(home + "/Code/x/bin", [Evidence(source: .hash, title: "Known malware hash", detail: "fixture", score: 100), sig("Ad-hoc signed program")])),
            ("revoked dylib in a trusted app", det(apps + "/Trusted.app/Contents/Frameworks/libbad.dylib", [sig("Revoked code signature", 95)])),
            ("behaviour on a dev build", det(home + "/Rampart/.build/debug/tool", [Evidence(source: .behaviour, title: "R12 Reads browser credentials", detail: "fixture", score: 70), sig("Ad-hoc signed program")])),
        ]
        for (name, d) in bad { check(FindingTriage.classify(d, ctx) == .keep && isDecision(d), "fp2: \(name) is still a finding") }
        check(bad.filter { $0.1.confidence >= Scoring.alertThreshold }.count == 4, "fp2: EICAR, hash, revoked and behaviour fixtures still alert")

        // 3. Path helpers.
        check(FindingTriage.outermostApp("/Applications/A.app/Contents/Frameworks/B.app/Contents/MacOS/b") == "/Applications/A.app", "fp2: outermost app bundle")
        check(FindingTriage.developerBuildReason("/usr/local/bin/x", home: home) == nil, "fp2: /usr/local is not a dev folder")
        check(FindingTriage.developerBuildReason(home + "/Documents/a.out", home: home) == nil, "fp2: Documents is not a dev folder")
        check(!FindingTriage.isWeakSigningOnly(det(home + "/x", [Evidence(source: .persistence, title: "R07 New launch item runs untrusted code", detail: "", score: 40)])),
              "fp2: persistence findings are not signing-only")

        // 4. Stale detections: EICAR whose file is gone auto-resolves; existing file stays.
        let gone = Detection(path: home + "/gone/com.rampart.test.eicar.com", sha256: nil, name: EICAR.detectionName, category: .test, severity: .medium, confidence: 100, evidence: [eicar])
        let here = Detection(path: apps, sha256: nil, name: EICAR.detectionName, category: .test, severity: .medium, confidence: 100, evidence: [eicar])
        let isStale: (Detection) -> Bool = { d in
            guard !d.resolved, let p = d.path else { return false }
            var st = stat(); return lstat(p, &st) != 0
        }
        check(isStale(gone) && !isStale(here), "fp2: detection with a deleted file is stale, existing file is not")

        // Optional: dry-run the triage over an exported detection list (`rampart detections --json`), read-only.
        if let file = ProcessInfo.processInfo.environment["RAMPART_FP2_DETECTIONS"],
           let data = FileManager.default.contents(atPath: file), let list = try? JSONDecoder.rampart.decode([Detection].self, from: data) {
            let real = FindingTriage.Context(signing: { SigningInspector.inspectCached(path: $0).info })
            var tally: [String: Int] = [:]
            for d in list where !d.resolved {
                let o: String
                if isStale(d) { o = "resolved: file gone" }
                else {
                    let (out, r) = FindingTriage.apply(d, real)
                    switch r {
                    case .notAFinding: o = "resolved: not a finding"
                    case .note: o = "note"
                    case .keep: o = (out?.confidence ?? 0) >= Scoring.alertThreshold ? "DECISION" : "kept low (\(d.name))"
                    }
                }
                tally[o, default: 0] += 1
                if o.hasPrefix("kept") || o == "DECISION" { print("  keep: \(d.name) \(d.confidence) \(d.path ?? "-")") }
            }
            for (k, v) in tally.sorted(by: { $0.key < $1.key }) { print("fp2 dry-run: \(v) \(k)") }
        }
    }
}

extension SelfTest {
    /// RamPart never scans its own data folders (quarantine items must not be re-detected).
    static func ownDataExclusionChecks() {
        let w = WalkOptions()
        check(w.isExcluded("/Users/someone/Library/Application Support/Rampart/Quarantine/items/x.rqf"), "user data folder excluded")
        check(w.isExcluded("/Users/someone/Library/Application Support/Rampart/abc_bundle.zip.quarantine"), "user data quarantine file excluded")
        check(w.isExcluded("/Library/Application Support/Rampart/Quarantine/x"), "system data folder excluded")
        check(!w.isExcluded("/Users/someone/Library/Application Support/RampartOther/x"), "similar names not excluded")
        check(!w.isExcluded("/Users/someone/Downloads/eicar.com"), "normal paths still scanned")
    }
}
