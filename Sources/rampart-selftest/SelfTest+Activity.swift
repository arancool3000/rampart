import Foundation
import RampartShared

// Protection Activity: every decision type has a plain-English mapping, raw internal strings never reach the
// screen, the tiles count real data, bursts group, old log lines still decode, and every place the daemon and
// app record an entry names its decision type (so a new decision can't be added without a mapping).
extension SelfTest {
    static func activityChecks() {
        let name = Product.name
        // Raw codes and camelCase identifiers must never appear in a title, subtitle or status.
        let banned = ["needs review", "likelyScam", "likelyscam", "fileTamper", "allow rule added", "unloadAttempt", "(93)", "webBlock", "dnsBlocked"]
        func leaks(_ s: String) -> String? {
            let t = s.replacingOccurrences(of: name, with: "Product")
            if let b = banned.first(where: { t.contains($0) }) { return b }
            for w in t.split(whereSeparator: { " ,·:()/\"“”'".contains($0) }) where !w.contains(".") && !w.contains("-") && !w.contains("_") {
                let chars = Array(w)
                // Internal codes are lowerCamelCase ("fileTamper", "likelyScam"); proper names ("AnyDesk") are fine.
                guard chars.first?.isLowercase == true else { continue }
                for i in 1..<max(1, chars.count) where chars[i].isUppercase && chars[i - 1].isLowercase { return String(w) }
            }
            return nil
        }
        func sample(_ ev: ActivityEvent) -> ActivityEntry {
            ActivityEntry(date: Date(timeIntervalSince1970: 1_800_000_000), kind: .system, title: "Sample event", detail: "", outcome: "",
                          severity: .medium, detectionID: UUID(), event: ev, actor: .user,
                          process: ActivityProcess(name: "Helper", path: "/Applications/Helper.app/Contents/MacOS/Helper", signer: "Apple", pid: 42, parentPID: 1, parentName: "launchd"),
                          target: "/Users/test/Downloads/file.zip", rule: ev == .tamper ? "fileTamper" : "StevenBlack", reason: "Because of a test", score: 77, action: nil,
                          count: 1234, found: 1, sha256: String(repeating: "a", count: 64), refID: nil,
                          facts: ["setting": "Web protection", "value": "off", "tool": "AnyDesk", "network": "Cafe Wi-Fi", "label": "com.example.agent", "check": "Firewall", "name": "Tool.app"])
        }

        // 1. Every decision type has a complete, human mapping.
        var unmapped: [String] = []
        for ev in ActivityEvent.allCases {
            let p = ActivityPresenter.present(sample(ev))
            let ok = !p.title.isEmpty && !p.whatHappened.isEmpty && !p.whatWeDid.isEmpty && !p.whatYouCanDo.isEmpty && p.event == ev
                && !p.symbol.isEmpty && !p.burstNoun.isEmpty && !p.facts.isEmpty
            if !ok { unmapped.append(ev.rawValue) }
            for (what, text) in [("title", p.title), ("subtitle", p.subtitle), ("status", p.status)] {
                if let l = leaks(text) { unmapped.append("\(ev.rawValue) \(what) leaks \"\(l)\": \(text)") }
            }
        }
        if ProcessInfo.processInfo.environment["RAMPART_ACTIVITY_DUMP"] == "1" {
            for ev in ActivityEvent.allCases { let p = ActivityPresenter.present(sample(ev)); print("  [\(ev.rawValue)] \(p.title) | \(p.subtitle) | \(p.status)") }
        }
        check(unmapped.isEmpty, "activity: every ActivityEvent has a plain-English title, explanation and facts\(unmapped.isEmpty ? "" : " (\(unmapped.prefix(6).joined(separator: "; ")))")")
        check(Set(ActivityEvent.allCases.map { ActivityPresenter.category($0) }).count >= 8, "activity: events spread over the filter categories")

        // 2. Every kind of older free-text entry still gets a mapping.
        var badKinds: [String] = []
        for k in ActivityEntry.Kind.allCases {
            let e = ActivityEntry(kind: k, title: "Something", detail: "", outcome: "ok")
            let p = ActivityPresenter.present(e)
            if p.title.isEmpty || p.whatHappened.isEmpty { badKinds.append(k.rawValue) }
        }
        check(badKinds.isEmpty, "activity: every stored kind maps to a presentation \(badKinds)")

        // 3. The raw strings from the user's screen are translated.
        let tamper = ActivityPresenter.present(ActivityEntry(kind: .detection, title: "Tampering with \(name): fileTamper", detail: "/Library/Application Support/Rampart/rampartd", outcome: "needs review", severity: .high))
        check(tamper.event == .tamper && tamper.title == "Something tried to change \(name)'s files" && tamper.status == "Needs your review",
              "activity: legacy tamper entry → \"Something tried to change \(name)'s files\" / \"Needs your review\" (\(tamper.title) / \(tamper.status))")
        check(tamper.subtitle.contains("rampartd"), "activity: tamper subtitle names the file")
        let scam = ActivityPresenter.present(ActivityEntry(kind: .webBlock, title: "Fake PayPal sign-in", detail: "https://paypa1-secure.top/login", outcome: "likelyScam (93)", severity: .high))
        check(scam.event == .scamBlocked && scam.title.hasPrefix("Scam link blocked: ") && leaks(scam.status) == nil && scam.status == "Blocked"
              && scam.facts.contains { $0.value.contains("93") }, "activity: legacy \"likelyScam (93)\" → scam link blocked with risk score (\(scam.title) / \(scam.subtitle) / \(scam.status))")
        var brandEntry = ActivityEntry(kind: .webBlock, title: "Fake sign-in page", outcome: "likelyScam (93)", event: .scamBlocked, target: "https://paypa1-secure.top/login", score: 93, facts: ["brand": "PayPal"])
        check(ActivityPresenter.present(brandEntry).title == "Scam link blocked: PayPal lookalike", "activity: scam block title names the imitated brand")
        brandEntry.facts = nil
        check(ActivityPresenter.present(brandEntry).title == "Scam link blocked: paypa1-secure.top", "activity: scam block title falls back to the host")
        let web = ActivityPresenter.present(ActivityEntry(kind: .settings, title: "Web protection off", outcome: "off"))
        check(web.event == .protectionToggled && web.title == "Web protection turned off" && web.status == "Off", "activity: legacy \"off\" → \"Web protection turned off\" (\(web.title))")
        let byYou = ActivityPresenter.present(ActivityEntry(kind: .settings, title: "Web protection off", outcome: "off", event: .protectionToggled, actor: .user, facts: ["setting": "Web protection", "value": "off", "where": "Settings"]))
        check(byYou.title == "Web protection turned off (by you, in Settings)", "activity: settings change says who and where (\(byYou.title))")
        let ai = ActivityPresenter.present(ActivityEntry(kind: .settings, title: "Settings changed", outcome: "saved", event: .settingsChanged, actor: .ai, facts: ["changes": "auto-quarantine off"]))
        check(ai.title.contains("AI assistant") && ai.subtitle.lowercased().contains("auto-quarantine"), "activity: AI-approved change is attributed to the AI assistant")
        let allow = ActivityPresenter.present(ActivityEntry(kind: .settings, title: "Allowed Tool.app", detail: "fileHash: abc", outcome: "allow rule added"))
        check(allow.event == .allowRuleAdded && allow.status == "Allowed", "activity: \"allow rule added\" → \"Allowed\"")
        for raw in ["needs review", "likelyScam (93)", "off", "allow rule added", "will retry", "settings session (10 min)", "locked down (dry run)"] {
            let h = ActivityPresenter.humanOutcome(raw)
            check(!h.isEmpty && h != raw && leaks(h) == nil, "activity: outcome \"\(raw)\" → \"\(h)\"")
        }
        check(ActivityPresenter.present(ActivityEntry(kind: .detection, title: "Unapproved remote access: AnyDesk", outcome: "needs review")).event == .remoteAccessAttempt,
              "activity: remote access detections are their own event")

        // 4. Tiles come from the log: files from scan summaries, blocks from web/DNS/scam verdicts, threats stopped.
        let now = Date()
        let det = UUID()
        let entries: [ActivityEntry] = [
            ActivityEntry(date: now, kind: .scan, title: "Quick scan finished", detail: "18204 files in 41.8 s", outcome: "no threats"),
            ActivityEntry(date: now.addingTimeInterval(-60), kind: .scan, title: "Scan finished", outcome: "1 found", event: .scanFinished, count: 100, found: 1),
            ActivityEntry(date: now.addingTimeInterval(-120), kind: .webBlock, title: "Fake bank", detail: "https://a.example", outcome: "likelyScam (93)"),
            ActivityEntry(date: now.addingTimeInterval(-130), kind: .webBlock, title: "Fake bank 2", detail: "https://b.example", outcome: "likelyScam (88)"),
            ActivityEntry(date: now.addingTimeInterval(-140), kind: .webBlock, title: "Blocked ads.example", detail: "Listed in StevenBlack", outcome: "blocked"),
            ActivityEntry(date: now.addingTimeInterval(-150), kind: .webBlock, title: "Odd page", detail: "https://c.example", outcome: "suspicious (40)"),
            ActivityEntry(date: now.addingTimeInterval(-200), kind: .quarantine, title: "Quarantined X", outcome: "quarantined", detectionID: det),
            ActivityEntry(date: now.addingTimeInterval(-201), kind: .detection, title: "X", outcome: "contained", detectionID: det),
            ActivityEntry(date: now.addingTimeInterval(-300), kind: .realtime, title: "Stopped Y", outcome: "stopped", event: .processStopped),
            ActivityEntry(date: now.addingTimeInterval(-86400 * 20), kind: .scan, title: "Old scan", outcome: "no threats", event: .scanFinished, count: 999_999),
        ]
        let days = ActivityStats.daily(entries, days: 14, now: now)
        let files = days.reduce(0) { $0 + $1.filesChecked }, webB = days.reduce(0) { $0 + $1.webBlocks }
        let dnsB = days.reduce(0) { $0 + $1.dnsBlocks }, thr = days.reduce(0) { $0 + $1.threatsStopped }
        check(days.count == 14 && files == 18_304, "activity tiles: files checked from scan summaries (\(files))")
        check(webB == 2 && dnsB == 1, "activity tiles: scam links and DNS blocks counted, warnings not (\(webB)+\(dnsB))")
        check(thr == 2, "activity tiles: threats stopped counted once per detection (\(thr))")

        // 5. Bursts group: "3 tamper attempts in 1 minute"; distinct events stay separate.
        let t0 = now
        let burst = (0..<3).map { i in ActivityEntry(date: t0.addingTimeInterval(Double(-i) * 15), kind: .tamper, title: "Tampering with \(name): fileTamper",
                                                     outcome: "logged", event: .tamper, rule: i == 2 ? "unloadAttempt" : "fileTamper") }
        let other = ActivityEntry(date: t0.addingTimeInterval(-50), kind: .scan, title: "Quick scan finished", outcome: "no threats", event: .scanFinished, count: 5)
        let late = ActivityEntry(date: t0.addingTimeInterval(-600), kind: .tamper, title: "Tampering with \(name): fileTamper", outcome: "logged", event: .tamper)
        let groups = ActivityGrouping.group(burst + [other, late])
        check(groups.count == 3 && groups[0].entries.count == 3 && groups[0].burstTitle == "3 tamper attempts in 1 minute",
              "activity: tamper burst grouped (\(groups.map { $0.entries.count }) \(groups.first?.burstTitle ?? ""))")

        // 6. Old and future log lines decode.
        let old = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964FF","date":"2026-11-01T10:00:00Z","kind":"webBlock","title":"Blocked x.example","detail":"Listed in hosts","outcome":"blocked","severity":1}"#
        let future = #"{"id":"6F9619FF-8B86-D011-B42D-00C04FC964F0","date":"2026-11-01T10:00:00Z","kind":"teleport","title":"New","detail":"","outcome":"","severity":0,"event":"warpDrive","actor":"robot"}"#
        let dec = JSONDecoder.rampart
        let o = try? dec.decode(ActivityEntry.self, from: Data(old.utf8))
        let f = try? dec.decode(ActivityEntry.self, from: Data(future.utf8))
        check(o?.event == nil && o.map { ActivityPresenter.event(for: $0) } == .dnsBlocked, "activity: entries written before structured fields decode and are inferred")
        check(f?.kind == .system && f?.event == nil && f?.actor == nil, "activity: unknown kind/event/actor never drops an entry")
        let full = sample(.tamper)
        let round = (try? JSONEncoder.rampart.encode(full)).flatMap { try? dec.decode(ActivityEntry.self, from: $0) }
        check(round == full, "activity: structured entries round-trip")

        // 7. Completeness: every recording site names its decision type, so it can't miss a mapping.
        let root = activityRepoRoot()
        func swiftFiles(_ dir: String) -> [String] {
            let en = FileManager.default.enumerator(atPath: root + "/" + dir)
            var out: [String] = []
            while let p = en?.nextObject() as? String { if p.hasSuffix(".swift") { out.append(dir + "/" + p) } }
            return out
        }
        func calls(_ text: String, _ marker: String) -> [String] {
            var out: [String] = []
            var search = text.startIndex
            while let r = text.range(of: marker, range: search..<text.endIndex) {
                var depth = 1, i = r.upperBound
                while i < text.endIndex && depth > 0 { if text[i] == "(" { depth += 1 } else if text[i] == ")" { depth -= 1 }; i = text.index(after: i) }
                out.append(String(text[r.lowerBound..<i])); search = i
            }
            return out
        }
        var missing: [String] = [], sites = 0
        for file in swiftFiles("Sources/rampartd") {
            let text = (try? String(contentsOfFile: root + "/" + file, encoding: .utf8)) ?? ""
            for c in calls(text, "activity.add(") where !c.hasPrefix("activity.add(ActivityEntry") {
                sites += 1
                if !c.contains("event:") { missing.append("\(file): \(c.prefix(70))") }
            }
        }
        for file in swiftFiles("Sources/RampartApp") {
            let text = (try? String(contentsOfFile: root + "/" + file, encoding: .utf8)) ?? ""
            for c in calls(text, "recordActivity(ActivityEntry(") {
                sites += 1
                if !c.contains("event:") { missing.append("\(file): \(c.prefix(70))") }
            }
            if text.contains("activity.insert(ActivityItem(date:") { missing.append("\(file): unstructured activity.insert (lost on the next refresh)") }
            // No secrets: vault/AI entries never carry passwords, prompts or item contents.
            for c in calls(text, "recordActivity(ActivityEntry(") + calls(text, "vaultActivity(") {
                let l = c.lowercased()
                if ["password)", "master)", "prompt", "secret", "totp", ".notes", "item.password", "decoded"].contains(where: { l.contains($0) }) {
                    missing.append("\(file): possible secret in \(c.prefix(70))")
                }
            }
        }
        check(sites >= 40, "activity: found the recording sites (\(sites))")
        check(missing.isEmpty, "activity: every recording site names its ActivityEvent and holds no secrets\(missing.isEmpty ? "" : ": " + missing.prefix(5).joined(separator: " | "))")
        // Coverage of the decision types the daemon and app must record.
        let all = (swiftFiles("Sources/rampartd") + swiftFiles("Sources/RampartApp")).map { (try? String(contentsOfFile: root + "/" + $0, encoding: .utf8)) ?? "" }.joined()
        let required: [ActivityEvent] = [.scanStarted, .scanFinished, .scanCancelled, .scanFailed, .detection, .quarantined, .restored, .deleted, .processStopped,
                                         .dnsBlocked, .scamBlocked, .webWarning, .pasteGuardBlocked, .pasteGuardWarned, .remoteAccessAttempt, .tamper,
                                         .settingsChanged, .protectionToggled, .lockdownStarted, .lockdownLifted, .wifiWarning, .wifiDisconnected,
                                         .definitionsUpdated, .definitionsFailed, .vaultEvent, .authenticatorEvent, .refreshCleanup, .networkScan,
                                         .serviceStarted, .serviceStopped, .allowRuleAdded, .remoteLockdownChanged]
        let uncovered = required.filter { ev in
            !all.contains(".\(ev.rawValue)") && !(ev == .remoteAccessAttempt && all.contains(".remoteAccessAttempt")) && !(ev == .tamper && all.contains("? .tamper"))
        }
        check(uncovered.isEmpty, "activity: every required decision type is recorded somewhere \(uncovered.map(\.rawValue))")

        // 8. Fast with thousands of entries.
        let many = (0..<5000).map { i -> ActivityEntry in
            var e = sample(ActivityEvent.allCases[i % ActivityEvent.allCases.count]); e.id = UUID(); e.date = now.addingTimeInterval(Double(-i) * 7); return e
        }
        let t = Date()
        let ps = many.map(ActivityPresenter.present)
        let texts = zip(ps, many).map { ActivityPresenter.searchText($0, $1).lowercased() }
        let g = ActivityGrouping.group(many, keys: Dictionary(uniqueKeysWithValues: zip(many.map(\.id), ps.map(\.groupKey))))
        let hits = texts.filter { $0.contains("helper") }.count
        let secs = Date().timeIntervalSince(t)
        check(secs < 6 && !g.isEmpty && hits == 5000, "activity: 5,000 entries presented, indexed and grouped in \(String(format: "%.2f", secs)) s; search reaches process names")
    }

    private static func activityRepoRoot() -> String {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<4 { dir.deleteLastPathComponent(); if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) { return dir.path } }
        return FileManager.default.currentDirectoryPath
    }
}
