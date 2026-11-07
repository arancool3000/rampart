import Foundation
import Darwin
import RampartShared
import RampartRefresh

/// RamPart Refresh checks. Everything runs on a fake home built under $RAMPART_SCRATCH (or the temp folder);
/// no real user file is read for cleaning, moved or deleted. Trashing is a dry run or goes to a fake Trash folder.
extension SelfTest {
    static func refreshChecks() {
        let fm = FileManager.default
        let base = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()
        let rootRaw = (base as NSString).appendingPathComponent("refresh-selftest-\(getpid())")
        try? fm.createDirectory(atPath: rootRaw, withIntermediateDirectories: true)
        let root = RefreshSafetyPolicy.realPath(rootRaw) ?? rootRaw   // /tmp → /private/tmp, matches libproc paths
        defer { try? fm.removeItem(atPath: root) }
        let home = root + "/home"
        let now = Date()
        func ago(_ d: Double) -> Date { now.addingTimeInterval(-d * 86400) }
        func write(_ rel: String, _ bytes: Int = 4096, days: Double = 0, fill: UInt8 = 0x41) {
            let p = home + "/" + rel
            try? fm.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            fm.createFile(atPath: p, contents: Data(repeating: fill, count: bytes))
            try? fm.setAttributes([.modificationDate: ago(days)], ofItemAtPath: p)
        }
        func age(_ rel: String, _ days: Double) { try? fm.setAttributes([.modificationDate: ago(days)], ofItemAtPath: home + "/" + rel) }

        // Caches
        write("Library/Caches/com.example.idle/data.bin", 64_000, days: 20)
        write("Library/Caches/com.example.fresh/data.bin", 64_000, days: 0.1)
        write("Library/Caches/com.example.running/data.bin", 64_000, days: 20)
        write("Library/Caches/com.apple.Safari/x", 64_000, days: 20)
        write("Library/Caches/pip/http/x", 64_000, days: 20)
        // Logs / crash reports
        write("Library/Logs/OldApp/old.log", 8000, days: 30)
        write("Library/Logs/OldApp/new.log", 8000, days: 1)
        write("Library/Logs/DiagnosticReports/Thing-2026.ips", 8000, days: 10)
        // Xcode
        write("Library/Developer/Xcode/DerivedData/App-abc/Build/x.o", 100_000, days: 40)
        write("Library/Developer/Xcode/Archives/2025-01-01/App.xcarchive/Info.plist", 9000, days: 300)
        // Projects: idle SwiftPM, active node, idle python
        write("Code/Idle/Package.swift", 100, days: 60)
        write("Code/Idle/Sources/main.swift", 100, days: 60)
        write("Code/Idle/.build/debug/x.o", 200_000, days: 60)
        age("Code/Idle/Sources", 60); age("Code/Idle", 60)
        write("Code/Active/package.json", 100, days: 2)
        write("Code/Active/node_modules/left-pad/index.js", 50_000, days: 2)
        write("Code/OldPy/app.py", 100, days: 90)
        write("Code/OldPy/__pycache__/app.cpython-312.pyc", 30_000, days: 90)
        age("Code/OldPy", 90)
        // Trash, Downloads, Documents
        write(".Trash/old.txt", 5000, days: 3)
        write("Downloads/Installer.dmg", 300_000, days: 200)
        write("Downloads/NewInstaller.dmg", 300_000, days: 10)
        write("Downloads/Archive.zip", 50_000, days: 120)
        write("Downloads/Archive/readme.txt", 100, days: 120)
        write("Downloads/Unextracted.zip", 50_000, days: 120)
        write("Documents/Photo.jpg", 2_000_000, days: 800)
        write("Documents/Copy of Photo.jpg", 2_000_000, days: 10)
        // Leftovers
        write("Library/Application Support/com.gone.app/state.db", 40_000, days: 100)
        write("Library/Application Support/com.present.app/state.db", 40_000, days: 100)
        write("Library/Preferences/com.gone.app.plist", 500, days: 100)
        write("Library/Application Support/com.apple.something/x", 500, days: 100)

        let env = RefreshScanner.Environment(home: home, now: now, runningBundleIDs: ["com.example.running"],
                                             installedBundleIDs: ["com.present.app"], includePersonal: true,
                                             brewDryRunOutput: "", runBrew: false, runSystemTools: false, lastUsed: { _ in nil })
        let scanner = RefreshScanner(env: env)
        let results = scanner.scan(RefreshCategory.allCases.filter { ![.languagePacks, .iosBackups, .mailAttachments].contains($0) })
        func items(_ c: RefreshCategory) -> [RefreshItem] { results.first { $0.category == c }?.items ?? [] }
        func find(_ rel: String) -> RefreshItem? { results.flatMap(\.items).first { $0.path == home + "/" + rel } }

        // Categorisation
        check(items(.appCaches).contains { $0.name == "com.example.idle" }, "refresh: idle app cache found")
        check(!items(.appCaches).contains { $0.name == "com.example.running" }, "refresh: running app's cache skipped")
        check(!items(.appCaches).contains { $0.name.hasPrefix("com.apple.") }, "refresh: Apple caches skipped")
        check(!items(.appCaches).contains { $0.name == "pip" } && items(.packageCaches).contains { $0.path.hasSuffix("Caches/pip") }, "refresh: pip cache in package caches, not counted twice")
        check(items(.oldLogs).map(\.name) == ["old.log"], "refresh: only logs older than 7 days")
        check(items(.crashReports).count == 1, "refresh: crash report found")
        check(find("Library/Developer/Xcode/DerivedData/App-abc") != nil, "refresh: DerivedData found")
        check(find("Code/Idle/.build") != nil, "refresh: idle SwiftPM .build found")
        check(find("Code/Active/node_modules") == nil, "refresh: active project's node_modules skipped")
        check(find("Code/OldPy/__pycache__") != nil, "refresh: idle __pycache__ found")
        check(!items(.projectBuilds).contains { $0.path.contains("/Sources") || $0.path.hasSuffix(".swift") }, "refresh: source code never listed")
        check(items(.trash).count == 1, "refresh: trash item listed")
        check(items(.leftovers).contains { $0.path.hasSuffix("com.gone.app") } && items(.leftovers).contains { $0.path.hasSuffix("com.gone.app.plist") }, "refresh: leftovers of removed app found")
        check(!items(.leftovers).contains { $0.path.contains("com.present.app") || $0.path.contains("com.apple.") }, "refresh: installed/Apple app data not leftovers")
        check(items(.oldDownloads).contains { $0.name == "Installer.dmg" } && !items(.oldDownloads).contains { $0.name == "NewInstaller.dmg" }, "refresh: only old downloads")
        check(RefreshScanner.parseBrewDryRun("Would remove: /opt/homebrew/Cellar/foo/1.0 (12.3MB)\nWould remove: /Users/x/Library/Caches/Homebrew/bar.tar.gz (1KB)\n==> This operation would free approximately 12MB")
              == ["/opt/homebrew/Cellar/foo/1.0", "/Users/x/Library/Caches/Homebrew/bar.tar.gz"], "refresh: brew dry-run parser")
        check(RefreshScanner(env: RefreshScanner.Environment(home: home, includePersonal: false, runBrew: false, runSystemTools: false, lastUsed: { _ in nil }))
              .scan([.oldDownloads, .duplicates, .largeOldFiles]).isEmpty, "refresh: personal folders not read unless allowed")

        // Scoring and default selection
        check(find("Library/Caches/com.example.idle")?.selected == true, "refresh: idle cache pre-selected")
        check(find("Library/Caches/com.example.fresh")?.selected == false, "refresh: cache changed today not pre-selected")
        check(find("Library/Logs/OldApp/old.log")?.selected == true, "refresh: old log pre-selected")
        check(find("Code/Idle/.build")?.selected == true, "refresh: idle build folder pre-selected")
        check(items(.xcode).first { $0.path.contains("/Archives/") }?.selected == false, "refresh: Xcode archives never pre-selected")
        check(find("Downloads/Installer.dmg")?.selected == true, "refresh: old installer pre-selected")
        check(find("Downloads/Archive.zip")?.selected == true && find("Downloads/Unextracted.zip")?.selected == false, "refresh: zip pre-selected only when extracted")
        check(items(.leftovers).allSatisfy { !$0.selected } && items(.trash).allSatisfy { !$0.selected }, "refresh: leftovers and trash never pre-selected")
        check(items(.duplicates).allSatisfy { !$0.selected }, "refresh: duplicates never pre-selected")
        check(results.flatMap(\.items).filter { $0.path.contains("/Documents/") || $0.path.contains("/Desktop/") }.allSatisfy { !$0.selected }, "refresh: Documents/Desktop never pre-selected")
        check(find("Library/Caches/com.example.idle").map { !$0.reason.isEmpty } == true, "refresh: every item explains itself")
        var doc = RefreshItem(path: home + "/Documents/Big.mov", category: .appCaches, bytes: 1 << 31, modified: ago(900), regenerable: true)
        RefreshScorer(home: home, now: now).score(&doc)
        check(!doc.selected, "refresh: hard rule beats a high score in Documents")
        var cloud = RefreshItem(path: home + "/Library/Mobile Documents/com~apple~CloudDocs/x.zip", category: .oldDownloads, bytes: 10, modified: ago(400), regenerable: true)
        RefreshScorer(home: home, now: now).score(&cloud)
        check(!cloud.selected, "refresh: iCloud Drive never pre-selected")

        // Safety refusals
        let policy = RefreshSafetyPolicy(home: home, openFilesOverride: [])
        check(policy.pathRefusal("/System/Library/Caches/x") == .systemPath, "refresh: refuses /System")
        check(policy.pathRefusal("/usr/lib/libz.dylib") == .systemPath, "refresh: refuses /usr")
        check(policy.pathRefusal("/Applications/Safari.app/Contents/Resources/fr.lproj") == .appBundleInternals, "refresh: refuses app bundle internals")
        check(policy.pathRefusal(home + "/Applications/Foo.app/Contents/MacOS/Foo") == .appBundleInternals, "refresh: refuses user app internals")
        check(policy.pathRefusal(home + "/Library/Keychains/login.keychain-db") == .keychain, "refresh: refuses keychains")
        check(policy.pathRefusal(home + "/Library/Mobile Documents/com~apple~CloudDocs/a.txt") == .iCloud, "refresh: refuses iCloud Drive")
        check(policy.pathRefusal(home + "/Library/Application Support/Rampart/vault.db") == .rampartData, "refresh: refuses RamPart data")
        check(policy.pathRefusal(home + "/Documents") == .protectedUserFolder && policy.pathRefusal(home) == .homeItself, "refresh: refuses whole personal folders")
        check(policy.pathRefusal("/etc/hosts") == .outsideHome || policy.pathRefusal("/etc/hosts") == .systemPath, "refresh: refuses outside home")
        check(policy.pathRefusal(home + "/Library/Caches/com.example.idle") == nil, "refresh: allows a normal cache")
        check(!results.flatMap(\.items).contains { policy.pathRefusal($0.path) != nil }, "refresh: scanner never lists refused paths")
        // Symlink in a parent pointing into a refused place.
        try? fm.createDirectory(atPath: home + "/Library/Caches/linkdir", withIntermediateDirectories: true)
        try? fm.createSymbolicLink(atPath: home + "/Library/Caches/linkdir/sys", withDestinationPath: "/System/Library")
        check(policy.refusal(home + "/Library/Caches/linkdir/sys/CoreServices") == .systemPath, "refresh: refuses through a symlinked parent")
        // Open file (live libproc check: this process holds it open).
        write("Library/Caches/com.example.open/locked.bin", 1000, days: 30)
        let openPath = home + "/Library/Caches/com.example.open/locked.bin"
        let live = RefreshSafetyPolicy(home: home)
        if let fh = FileHandle(forReadingAtPath: openPath) {
            check(OpenFiles.snapshot().contains(openPath), "refresh: libproc sees our open file")
            check(live.refusal(openPath) == .openByProcess, "refresh: refuses open file")
            check(live.refusal(home + "/Library/Caches/com.example.open") == .openByProcess, "refresh: refuses folder containing an open file")
            try? fh.close()
        } else { check(false, "refresh: open fixture") }
        check(live.refusal(openPath) == nil, "refresh: allowed once closed")
        // SIP xattr (setting it may itself be refused by the OS; only check when it could be set).
        let sipPath = home + "/Library/Caches/com.example.sip"
        fm.createFile(atPath: sipPath, contents: Data("x".utf8))
        if setxattr(sipPath, "com.apple.rootless", "x", 1, 0, 0) == 0 {
            check(policy.refusal(sipPath) == .rootless, "refresh: refuses com.apple.rootless")
        }

        // Duplicate finder
        let dupDir = root + "/dups"
        try? fm.createDirectory(atPath: dupDir, withIntermediateDirectories: true)
        var blob = Data((0..<300_000).map { UInt8($0 % 251) })
        fm.createFile(atPath: dupDir + "/a.bin", contents: blob)
        fm.createFile(atPath: dupDir + "/b.bin", contents: blob)
        try? fm.createDirectory(atPath: dupDir + "/sub", withIntermediateDirectories: true)
        fm.createFile(atPath: dupDir + "/sub/c.bin", contents: blob)
        try? fm.linkItem(atPath: dupDir + "/a.bin", toPath: dupDir + "/hardlink.bin")
        blob[150_000] ^= 0xFF   // same size, same head and tail, different middle: only the full hash can tell
        fm.createFile(atPath: dupDir + "/middle-differs.bin", contents: blob)
        fm.createFile(atPath: dupDir + "/small.bin", contents: Data(repeating: 1, count: 10))
        fm.createFile(atPath: dupDir + "/small2.bin", contents: Data(repeating: 1, count: 10))
        let groups = DuplicateFinder(minSize: 1024).find(in: [dupDir])
        check(groups.count == 1, "refresh: one duplicate group")
        let g = groups.first
        check(g?.paths.count == 3, "refresh: hard link not a duplicate, 3 copies")
        check(g.map { !$0.paths.contains { $0.contains("middle-differs") } } == true, "refresh: full SHA-256 separates same-size near-copies")
        check(g?.wasted == 600_000, "refresh: wasted bytes")
        check(items(.duplicates).count == 1 && items(.duplicates).first?.path.contains("Copy of Photo") == true, "refresh: scanner keeps the oldest duplicate")

        // Sizes: sparse file counts allocated blocks, not its logical size.
        let sparse = root + "/sparse.bin"
        fm.createFile(atPath: sparse, contents: nil)
        if let fh = FileHandle(forWritingAtPath: sparse) { try? fh.truncate(atOffset: 200 << 20); try? fh.close() }
        let sm = DiskSizer.measure(sparse)
        check(sm.logicalBytes == 200 << 20 && sm.total < 1 << 20, "refresh: sparse file measured by allocation")

        // Dry-run trashing on fixtures: nothing moves.
        let journal = URL(fileURLWithPath: root + "/undo.json")
        let selected = results.flatMap(\.items).filter(\.selected)
        check(!selected.isEmpty, "refresh: something selected")
        let dry = RefreshCleaner(policy: policy, journalURL: journal).clean(selected, dryRun: true)
        check(dry.dryRun && dry.trashed.count == selected.count && dry.failed.isEmpty, "refresh: dry run plans every selected item")
        check(selected.allSatisfy { fm.fileExists(atPath: $0.path) }, "refresh: dry run moved nothing")
        check(!fm.fileExists(atPath: journal.path), "refresh: dry run writes no undo log")
        let bad = [RefreshItem(path: "/System/Library/CoreServices", category: .appCaches, bytes: 1, regenerable: true),
                   RefreshItem(path: "/Applications/Safari.app/Contents/Info.plist", category: .appCaches, bytes: 1, regenerable: true),
                   RefreshItem(path: home + "/Library/Mail/V10", category: .mailAttachments, bytes: 1, regenerable: false)]
        let refusedRun = RefreshCleaner(policy: policy, journalURL: journal, trasher: { _ in check(false, "refresh: trasher must not be called"); return nil })
            .clean(bad, dryRun: false)
        check(refusedRun.refused.count == 3 && refusedRun.trashed.isEmpty, "refresh: cleaner refuses system, app internals and info-only items")

        // Trash + undo into a fake Trash folder (never the real Trash).
        let fakeTrash = root + "/FakeTrash"
        try? fm.createDirectory(atPath: fakeTrash, withIntermediateDirectories: true)
        let cleaner = RefreshCleaner(policy: policy, journalURL: journal, trasher: { url in
            let dest = URL(fileURLWithPath: fakeTrash).appendingPathComponent(UUID().uuidString + "-" + url.lastPathComponent)
            try FileManager.default.moveItem(at: url, to: dest)
            return dest
        })
        let target = selected.filter { $0.category == .appCaches }
        let real = cleaner.clean(target, dryRun: false)
        check(real.trashed.count == target.count && target.allSatisfy { !fm.fileExists(atPath: $0.path) }, "refresh: items moved to (fake) Trash")
        check(cleaner.journal().count == target.count, "refresh: undo log written")
        let undone = cleaner.undo(real.trashed)
        check(undone.restored.count == target.count && target.allSatisfy { fm.fileExists(atPath: $0.path) }, "refresh: undo puts everything back")
        check(cleaner.journal().isEmpty, "refresh: undo log cleared")
        check((try? cleaner.emptyTrash(confirmed: false, trashDir: fakeTrash, dryRun: true)) == nil, "refresh: emptying Trash needs confirmation")

        // Speed
        let mem = SpeedMonitor.memory()
        check(mem.map { $0.total > 0 && $0.used <= $0.total } == true, "refresh: memory stats")
        check(SpeedMonitor.outermostApp("/Applications/Foo.app/Contents/Frameworks/H.framework/Helpers/Foo Helper.app/Contents/MacOS/x") == "/Applications/Foo.app", "refresh: helpers grouped under app")
        let s1 = SpeedMonitor.sampleProcesses()
        check(s1.contains { $0.pid == getpid() && $0.footprint > 0 }, "refresh: process sampling sees self")
        write("Library/LaunchAgents/com.example.agent.plist", 0)
        (["Label": "com.example.agent", "ProgramArguments": ["/nonexistent/tool"], "RunAtLoad": true, "KeepAlive": true] as NSDictionary)
            .write(toFile: home + "/Library/LaunchAgents/com.example.agent.plist", atomically: true)
        let agents = SpeedMonitor.userLaunchAgents(home: home)
        check(agents.count == 1 && agents[0].targetMissing && agents[0].impact == "High", "refresh: launch agent impact")
    }
}
