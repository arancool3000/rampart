import Foundation
import Darwin
import IOKit.ps

// Desktop Mode logic (Sources/RampartApp/Features/Desktop/DesktopLogic.swift, symlinked here):
// launcher discovery on a fake Applications tree, favourites persistence and reordering, search ranking,
// click-through regions, refresh cadence, and the system-info samplers (live reads + pure maths).
extension SelfTest {
    static func desktopChecks() {
        let fm = FileManager.default
        let base = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()
        let root = (base as NSString).appendingPathComponent("desktop-selftest-\(getpid())")
        defer { try? fm.removeItem(atPath: root) }
        func makeApp(_ path: String, id: String?, backgroundOnly: Bool = false) {
            try? fm.createDirectory(atPath: path + "/Contents", withIntermediateDirectories: true)
            var info: [String: Any] = ["CFBundleName": "X"]
            if let id { info["CFBundleIdentifier"] = id }
            if backgroundOnly { info["LSBackgroundOnly"] = true }
            (info as NSDictionary).write(toFile: path + "/Contents/Info.plist", atomically: true)
        }
        let apps = root + "/Applications", sys = root + "/System/Applications", home = root + "/home/Applications"
        makeApp(apps + "/Safari.app", id: "com.apple.Safari")
        makeApp(apps + "/Zed.app", id: "dev.zed.Zed")
        makeApp(apps + "/Utilities/Helper Tool.app", id: "com.example.helper")
        makeApp(apps + "/Vendor/Suite/Deep.app", id: "com.example.deep")          // depth 3: not listed
        makeApp(apps + "/Agent.app", id: "com.example.agent", backgroundOnly: true)
        makeApp(apps + "/.Hidden.app", id: "com.example.hidden")
        makeApp(apps + "/Safari.app/Contents/Nested.app", id: "com.example.nested") // inside a bundle: never
        makeApp(sys + "/Calendar.app", id: "com.apple.iCal")
        makeApp(sys + "/Safari.app", id: "com.apple.Safari")                       // duplicate ID: /Applications wins
        makeApp(sys + "/Utilities/Terminal.app", id: "com.apple.Terminal")
        makeApp(home + "/mine.app", id: nil)
        try? fm.createDirectory(atPath: apps + "/Folder", withIntermediateDirectories: true)
        _ = symlink(sys, apps + "/LinkToSystem")                                    // symlinked folder: not followed
        fm.createFile(atPath: apps + "/notes.txt", contents: Data())

        let found = LauncherCatalog.discover(roots: [apps, sys, home], extras: [root + "/missing/Finder.app"])
        let names = found.map(\.name)
        check(names == ["Calendar", "Helper Tool", "mine", "Safari", "Terminal", "Zed"], "desktop.launcher.discover (\(names))")
        check(found.first { $0.name == "Safari" }?.path == apps + "/Safari.app", "desktop.launcher.dedupeKeepsFirstRoot")
        check(!names.contains("Agent") && !names.contains("Nested") && !names.contains(".Hidden") && !names.contains("Deep"), "desktop.launcher.skips")
        check(found.first { $0.name == "mine" }?.bundleID == nil, "desktop.launcher.noBundleIDOK")
        check(LauncherCatalog.discover(roots: [root + "/nope"], extras: []).isEmpty, "desktop.launcher.missingRoot")
        // The real Mac: /System/Applications always has apps; discovery is quick.
        let t0 = Date()
        let real = LauncherCatalog.discover()
        check(real.count >= 5 && real.contains { $0.path.hasPrefix("/System/Applications/") }, "desktop.launcher.realDiscovery (\(real.count))")
        check(Date().timeIntervalSince(t0) < 3, "desktop.launcher.realDiscoveryFast")

        // Favourites: seed, pin, reorder, persistence, prune.
        let suite = "app.rampart.selftest.desktop.\(getpid())"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = LauncherStore(defaults: defaults)
        var l = store.load()
        check(l == LauncherLayout(), "desktop.fav.emptyDefault")
        l.seedIfNeeded(apps: found)
        check(l.favorites == [apps + "/Safari.app", sys + "/Calendar.app"], "desktop.fav.seedOrder (\(l.favorites))")
        l.unpin(sys + "/Calendar.app"); l.seedIfNeeded(apps: found)
        check(l.favorites == [apps + "/Safari.app"], "desktop.fav.unpinnedDefaultStaysGone")
        l.pin(apps + "/Zed.app"); l.pin(apps + "/Zed.app")
        check(l.favorites == [apps + "/Safari.app", apps + "/Zed.app"], "desktop.fav.pinNoDuplicates")
        l.move(apps + "/Zed.app", before: apps + "/Safari.app", inFavorites: true, allPaths: [])
        check(l.favorites.first == apps + "/Zed.app", "desktop.fav.reorderFavorites")
        var arranged = l.arrange(found)
        check(arranged.favorites.map(\.name) == ["Zed", "Safari"], "desktop.fav.arrangeFavorites")
        check(arranged.others.map(\.name) == ["Calendar", "Helper Tool", "mine", "Terminal"], "desktop.fav.arrangeOthersAlpha")
        // Drag Terminal before Calendar in the grid.
        l.move(sys + "/Utilities/Terminal.app", before: sys + "/Calendar.app", inFavorites: false, allPaths: arranged.others.map(\.path))
        arranged = l.arrange(found)
        check(arranged.others.map(\.name) == ["Terminal", "Calendar", "Helper Tool", "mine"], "desktop.fav.dragReorderGrid (\(arranged.others.map(\.name)))")
        // Drag a favourite into the grid: unpinned.
        l.move(apps + "/Safari.app", before: nil, inFavorites: false, allPaths: arranged.others.map(\.path))
        check(!l.isFavorite(apps + "/Safari.app") && l.arrange(found).others.last?.name == "Safari", "desktop.fav.dragOutUnpins")
        store.save(l)
        let reloaded = LauncherStore(defaults: UserDefaults(suiteName: suite)!).load()
        check(reloaded == l && reloaded.seeded, "desktop.fav.persistsRoundTrip")
        var pruned = reloaded
        check(pruned.prune(existing: Set([apps + "/Zed.app"])) && pruned.favorites == [apps + "/Zed.app"] && pruned.order.isEmpty, "desktop.fav.prune")
        var full = LauncherLayout()
        for i in 0..<40 { full.pin("/A/\(i).app") }
        check(full.favorites.count == LauncherLayout.maxFavorites, "desktop.fav.cap")
        defaults.set(Data("garbage".utf8), forKey: "desktop.launcherLayout")
        check(store.load() == LauncherLayout(), "desktop.fav.corruptFallsBack")

        // Search.
        let items = [DesktopSearchItem(id: "a1", kind: .app, title: "Safari"),
                     DesktopSearchItem(id: "a2", kind: .app, title: "System Settings"),
                     DesktopSearchItem(id: "f1", kind: .action, title: "Quick Scan", keywords: ["malware", "check"]),
                     DesktopSearchItem(id: "f2", kind: .feature, title: "Scam Check", keywords: ["phishing", "link"]),
                     DesktopSearchItem(id: "f3", kind: .feature, title: "Cat & Mouse", keywords: ["decoy", "honeypot"])]
        check(DesktopSearch.rank("saf", in: items).first?.id == "a1", "desktop.search.prefix")
        check(DesktopSearch.rank("qs", in: items).first?.id == "f1", "desktop.search.initials")
        check(DesktopSearch.rank("honey", in: items).map(\.id) == ["f3"], "desktop.search.keywords")
        check(DesktopSearch.rank("sc", in: items).first?.id == "f2", "desktop.search.featuresBeforeAppsOnTie")
        check(DesktopSearch.rank("   ", in: items).isEmpty && DesktopSearch.rank("zzz", in: items).isEmpty, "desktop.search.noMatch")
        check(DesktopSearch.rank("check", in: items).map(\.id).prefix(2).contains("f2"), "desktop.search.wordPrefix")

        // Click-through regions.
        let frame = CGRect(x: 0, y: 0, width: 1000, height: 800)
        let widget = CGRect(x: 100, y: 100, width: 200, height: 100)   // top-left coordinates
        check(DesktopHitRegions.accepts(DesktopHitRegions.toTopLeft(CGPoint(x: 150, y: 650), frame: frame), in: [widget]), "desktop.hit.overWidget")
        check(!DesktopHitRegions.accepts(DesktopHitRegions.toTopLeft(CGPoint(x: 600, y: 300), frame: frame), in: [widget]), "desktop.hit.emptyPassesThrough")
        check(!DesktopHitRegions.accepts(.zero, in: []), "desktop.hit.noWidgets")
        let second = CGRect(x: 1000, y: 0, width: 800, height: 600)
        check(DesktopHitRegions.toTopLeft(CGPoint(x: 1010, y: 590), frame: second) == CGPoint(x: 10, y: 10), "desktop.hit.secondDisplay")

        // Cadence.
        check(DesktopCadence.interval(visible: false, onBattery: false, lowPower: false) == nil, "desktop.cadence.hiddenStops")
        check(DesktopCadence.interval(visible: true, onBattery: false, lowPower: false) == 2, "desktop.cadence.power")
        check(DesktopCadence.interval(visible: true, onBattery: true, lowPower: false) == 5, "desktop.cadence.battery")
        check(DesktopCadence.interval(visible: true, onBattery: false, lowPower: true) == 5, "desktop.cadence.lowPower")

        // Samplers: pure maths.
        let a = CPUTicks(user: 100, system: 50, idle: 850, nice: 0), b = CPUTicks(user: 160, system: 90, idle: 1050, nice: 0)
        check(abs((CPUTicks.usage(from: a, to: b) ?? -1) - 0.333) < 0.01, "desktop.cpu.usage")
        check(CPUTicks.usage(from: a, to: a) == nil && CPUTicks.usage(from: b, to: a) == nil, "desktop.cpu.noAdvance")
        check(MemoryReading.used(internalPages: 100, purgeablePages: 20, wiredPages: 30, compressedPages: 10, pageSize: 16384) == 120 * 16384, "desktop.mem.formula")
        check(MemoryReading.used(internalPages: 5, purgeablePages: 20, wiredPages: 0, compressedPages: 0, pageSize: 4096) == 0, "desktop.mem.noUnderflow")
        check(NetCounters.delta32(4_294_967_000, 200) == 496, "desktop.net.wrap32")
        let r = NetCounters.rates(from: ["en0": .init(received: 1000, sent: 500), "en5": .init(received: 0, sent: 0)],
                                  to: ["en0": .init(received: 3000, sent: 1500), "en7": .init(received: 99999, sent: 9999)], seconds: 2)
        check(r.down == 1000 && r.up == 500, "desktop.net.ratesIgnoreNewInterfaces")
        check(NetCounters.include("en0") && NetCounters.include("pdp_ip0") && !NetCounters.include("utun3") && !NetCounters.include("lo0") && !NetCounters.include("awdl0"), "desktop.net.interfaces")
        check(Uptime.format(3 * 86_400 + 4 * 3600 + 59) == "3d 4h" && Uptime.format(5 * 3600 + 12 * 60) == "5h 12m" && Uptime.format(540) == "9m", "desktop.uptime.format")
        check(DesktopFormat.rate(1_234_567) == "1.2 MB/s" && DesktopFormat.rate(340_000) == "340 KB/s" && DesktopFormat.rate(-5) == "0 KB/s", "desktop.format.rate")
        let batt = BatteryReading.parse([kIOPSTypeKey: kIOPSInternalBatteryType, kIOPSCurrentCapacityKey: 41, kIOPSMaxCapacityKey: 50,
                                         kIOPSIsChargingKey: false, kIOPSPowerSourceStateKey: kIOPSBatteryPowerValue, kIOPSTimeToEmptyKey: 95])
        check(batt == BatteryReading(percent: 82, charging: false, onAC: false, minutesLeft: 95), "desktop.battery.parse")
        let ac = BatteryReading.parse([kIOPSTypeKey: kIOPSInternalBatteryType, kIOPSCurrentCapacityKey: 100, kIOPSMaxCapacityKey: 100,
                                       kIOPSIsChargingKey: false, kIOPSPowerSourceStateKey: kIOPSACPowerValue, kIOPSTimeToEmptyKey: 300])
        check(ac?.onAC == true && ac?.minutesLeft == nil && ac?.percent == 100, "desktop.battery.acNoTimeLeft")
        check(BatteryReading.parse([kIOPSTypeKey: "UPS", kIOPSCurrentCapacityKey: 1, kIOPSMaxCapacityKey: 1]) == nil, "desktop.battery.ignoresUPS")

        // Samplers: live reads on this Mac (values must be plausible; battery may be absent on desktops).
        let c1 = CPUTicks.read()
        usleep(250_000)
        let c2 = CPUTicks.read()
        check(c1 != nil && c2 != nil, "desktop.cpu.read")
        if let c1, let c2, let u = CPUTicks.usage(from: c1, to: c2) { check(u >= 0 && u <= 1, "desktop.cpu.range") }
        let m = MemoryReading.read()
        check(m != nil && m!.total == ProcessInfo.processInfo.physicalMemory && m!.used > 0 && m!.used <= m!.total, "desktop.mem.read")
        let d = DiskReading.read()
        check(d != nil && d!.total > d!.free && d!.fraction > 0 && d!.fraction < 1, "desktop.disk.read")
        let n = NetCounters.readPerInterface()
        check(n.keys.allSatisfy(NetCounters.include), "desktop.net.readFiltered (\(n.keys.sorted()))")
        if let bat = BatteryReading.read() { check((0...100).contains(bat.percent), "desktop.battery.read") }
        let boot = Uptime.bootDate()
        check(boot != nil && boot! < Date() && Date().timeIntervalSince(boot!) < 400 * 86_400, "desktop.uptime.read")
    }
}
