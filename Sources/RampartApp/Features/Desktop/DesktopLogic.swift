import Foundation
import Darwin
import IOKit.ps
import RampartShared

// Desktop Mode: pure logic (no SwiftUI / AppKit). This file is also compiled into rampart-selftest
// (Sources/rampart-selftest/DesktopLogic.swift is a symlink to it), so keep it Foundation + Darwin + IOKit only.

// MARK: - Launcher: app discovery

struct LauncherApp: Codable, Hashable, Identifiable, Sendable {
    var id: String { path }
    let path: String
    let name: String
    let bundleID: String?
}

enum LauncherCatalog {
    /// Where apps live, in priority order (an app found earlier wins a bundle-ID tie).
    /// o8: Apple's sealed /System copy is listed first, so a planted /Applications/Mail.app reusing com.apple.mail
    /// loses the bundle-ID tie to the real one.
    static var defaultRoots: [String] {
        ["/System/Applications", "/Applications", NSHomeDirectory() + "/Applications"]
    }
    /// Apps outside the usual folders that people expect in a launcher.
    static let extras = ["/System/Library/CoreServices/Finder.app"]

    /// Finds `.app` bundles in `roots`, descending into plain sub-folders (e.g. Utilities, vendor folders)
    /// up to `maxDepth`. Never descends into an app bundle, hidden folders or symlinked folders.
    /// Background-only agents are skipped. Duplicates (same bundle ID or path) keep the first root's copy.
    static func discover(roots: [String] = defaultRoots, extras: [String] = extras, maxDepth: Int = 2,
                         fm: FileManager = .default) -> [LauncherApp] {
        var out: [LauncherApp] = []
        var seenIDs = Set<String>(), seenPaths = Set<String>()
        func add(_ path: String) {
            guard seenPaths.insert(path).inserted, let app = describe(appAt: path, fm: fm) else { return }
            if let id = app.bundleID?.lowercased() { guard seenIDs.insert(id).inserted else { return } }
            out.append(app)
        }
        func walk(_ dir: String, depth: Int) {
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { return }
            for n in names.sorted() where !n.hasPrefix(".") {
                let p = (dir as NSString).appendingPathComponent(n)
                if n.lowercased().hasSuffix(".app") {
                    // o8: a symlinked .app is listed only when it points into one of the app folders.
                    if (try? fm.destinationOfSymbolicLink(atPath: p)) != nil, !trustedLocation(p, roots: roots) { continue }
                    add(p); continue
                }
                guard depth < maxDepth else { continue }
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: p, isDirectory: &isDir), isDir.boolValue,
                      (try? fm.destinationOfSymbolicLink(atPath: p)) == nil else { continue }
                walk(p, depth: depth + 1)
            }
        }
        for r in roots { walk(r, depth: 1) }
        for e in extras where fm.fileExists(atPath: e) { add(e) }
        out = dropLookAlikes(out)
        return out.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
    }

    /// Name and bundle ID from the bundle's Info.plist. nil for background-only or malformed bundles.
    static func describe(appAt path: String, fm: FileManager = .default) -> LauncherApp? {
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir), isDir.boolValue else { return nil }
        let plistPath = path + "/Contents/Info.plist"
        let info = (NSDictionary(contentsOfFile: plistPath) as? [String: Any]) ?? [:]
        if (info["LSBackgroundOnly"] as? Bool) == true || (info["LSBackgroundOnly"] as? String) == "1" { return nil }
        let file = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        // Finder shows the file name; fall back to the bundle's display name only if the file name is empty.
        let raw = file.isEmpty ? ((info["CFBundleDisplayName"] as? String) ?? (info["CFBundleName"] as? String) ?? "App") : file
        // o8: one clean line (no bidi overrides, invisible characters or line breaks), bounded.
        let name = SafeText.line(raw, max: 80)
        guard !name.isEmpty else { return nil }
        return LauncherApp(path: path, name: name, bundleID: info["CFBundleIdentifier"] as? String)
    }
}

extension LauncherCatalog {
    /// o8: well-known apps a planted bundle would imitate, with the bundle ID the real one has (prefix match).
    static let protectedApps: [String: String] = [
        "safari": "com.apple.safari", "finder": "com.apple.finder", "systemsettings": "com.apple.systempreferences",
        "rampart": "app.rampart", "googlechrome": "com.google.chrome", "firefox": "org.mozilla.firefox",
        "mail": "com.apple.mail", "messages": "com.apple.mobilesms", "keychainaccess": "com.apple.keychainaccess",
        "terminal": "com.apple.terminal", "1password": "com.1password", "microsoftedge": "com.microsoft.edgemac",
    ]

    /// Lower-case skeleton: diacritics folded, common Cyrillic/Greek/fullwidth look-alikes mapped to Latin,
    /// digits that pose as letters mapped, everything that isn't a letter or digit dropped.
    static func skeleton(_ s: String) -> String {
        let folded = s.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: nil)
        let map: [Character: Character] = ["а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
                                           "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ɑ": "a", "α": "a", "ο": "o", "ρ": "p", "ε": "e",
                                           "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u", "χ": "x", "ꮪ": "s", "ı": "i"]
        var out = ""
        for ch in folded {
            let c = map[ch] ?? ch
            if c.isLetter || c.isNumber { out.append(c) }
        }
        return out.replacingOccurrences(of: "rn", with: "m")
    }

    static func isSystemPath(_ p: String) -> Bool { p.hasPrefix("/System/") }

    /// Drops non-/System apps that look like a /System app or a well-known app but carry a different bundle ID
    /// (fake "Safari", "Sуstem Settings" with a Cyrillic у, "RamPart" from someone else).
    static func dropLookAlikes(_ apps: [LauncherApp]) -> [LauncherApp] {
        var refs = protectedApps
        for a in apps where isSystemPath(a.path) { if let id = a.bundleID?.lowercased() { refs[skeleton(a.name)] = id } }
        return apps.filter { a in
            if isSystemPath(a.path) { return true }
            guard let want = refs[skeleton(a.name)] else { return true }
            let id = a.bundleID?.lowercased() ?? ""
            return id == want || id.hasPrefix(want + ".")
        }
    }

    /// The real location of `path` is inside one of the app folders (or /System).
    static func trustedLocation(_ path: String, roots: [String] = defaultRoots) -> Bool {
        guard let r = realpath(path, nil) else { return false }
        defer { free(r) }
        let real = String(cString: r)
        if real.hasPrefix("/System/") { return true }
        return roots.contains { root in
            guard let rr = realpath(root, nil) else { return false }
            defer { free(rr) }
            return real.hasPrefix(String(cString: rr) + "/")
        }
    }

    /// o8: re-checked at click time, so a bundle swapped after discovery (other bundle ID, now a symlink elsewhere,
    /// or gone) is not launched.
    static func stillSame(_ app: LauncherApp, roots: [String] = defaultRoots, extras: [String] = extras) -> Bool {
        guard extras.contains(app.path) || trustedLocation(app.path, roots: roots),
              let now = describe(appAt: app.path) else { return false }
        return now.bundleID?.lowercased() == app.bundleID?.lowercased() && !dropLookAlikes([now]).isEmpty
    }
}

// MARK: - Launcher: favourites and custom order

/// The user's launcher arrangement, keyed by app path. Pinned favourites keep their order; the rest of the
/// grid follows `order` for apps the user has dragged, then alphabetical.
struct LauncherLayout: Codable, Equatable, Sendable {
    var favorites: [String] = []
    var order: [String] = []
    /// Set once the default favourites were offered, so an unpinned default never comes back.
    var seeded = false

    static let maxFavorites = 16
    static let defaultFavoriteNames = ["Safari", "Mail", "Messages", "Calendar", "Notes", "Photos", "Music", "System Settings"]

    func isFavorite(_ path: String) -> Bool { favorites.contains(path) }

    mutating func pin(_ path: String) {
        guard !favorites.contains(path), favorites.count < Self.maxFavorites else { return }
        favorites.append(path)
    }
    mutating func unpin(_ path: String) { favorites.removeAll { $0 == path } }
    mutating func toggle(_ path: String) { isFavorite(path) ? unpin(path) : pin(path) }

    /// Moves `path` to just before `target` (or to the end when target is nil) inside whichever list holds
    /// `target`. Dragging a non-favourite onto a favourite pins it there; dragging a favourite into the
    /// grid unpins it. `allPaths` is the grid's current visible order (needed to materialise `order`).
    mutating func move(_ path: String, before target: String?, inFavorites: Bool, allPaths: [String]) {
        guard path != target else { return }
        if inFavorites {
            favorites.removeAll { $0 == path }
            if let t = target, let i = favorites.firstIndex(of: t) { favorites.insert(path, at: i) } else { favorites.append(path) }
            if favorites.count > Self.maxFavorites { favorites.removeLast(favorites.count - Self.maxFavorites) }
        } else {
            favorites.removeAll { $0 == path }
            var list = allPaths.filter { $0 != path && !favorites.contains($0) }
            if let t = target, let i = list.firstIndex(of: t) { list.insert(path, at: i) } else { list.append(path) }
            order = list
        }
    }

    /// First run: pin the well-known apps that exist on this Mac.
    mutating func seedIfNeeded(apps: [LauncherApp]) {
        guard !seeded else { return }
        seeded = true
        guard favorites.isEmpty else { return }
        for n in Self.defaultFavoriteNames { if let a = apps.first(where: { $0.name == n }) { pin(a.path) } }
    }

    /// Drops apps that are gone (deleted / moved). Returns true if anything changed.
    @discardableResult mutating func prune(existing: Set<String>) -> Bool {
        let f = favorites.filter(existing.contains), o = order.filter(existing.contains)
        defer { favorites = f; order = o }
        return f != favorites || o != order
    }

    /// Favourites (pinned order) and the remaining apps (custom order first, then alphabetical).
    func arrange(_ apps: [LauncherApp]) -> (favorites: [LauncherApp], others: [LauncherApp]) {
        let byPath = Dictionary(apps.map { ($0.path, $0) }, uniquingKeysWith: { a, _ in a })
        let favs = favorites.compactMap { byPath[$0] }
        let favSet = Set(favorites)
        let rank = Dictionary(order.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        let others = apps.filter { !favSet.contains($0.path) }.enumerated().sorted { l, r in
            switch (rank[l.element.path], rank[r.element.path]) {
            case let (a?, b?): return a < b
            case (_?, nil): return true
            case (nil, _?): return false
            default: return l.offset < r.offset   // keep the catalogue's alphabetical order
            }
        }.map(\.element)
        return (favs, others)
    }
}

/// Persists the layout as JSON in a UserDefaults domain (injectable for tests).
struct LauncherStore {
    let defaults: UserDefaults
    var key = "desktop.launcherLayout"
    func load() -> LauncherLayout {
        guard let d = defaults.data(forKey: key), let l = try? JSONDecoder().decode(LauncherLayout.self, from: d) else { return LauncherLayout() }
        return l
    }
    func save(_ l: LauncherLayout) {
        if let d = try? JSONEncoder().encode(l) { defaults.set(d, forKey: key) }
    }
}

// MARK: - Search (apps + RamPart features)

struct DesktopSearchItem: Identifiable, Hashable, Sendable {
    enum Kind: String, Sendable { case app, feature, action }
    let id: String
    let kind: Kind
    let title: String
    var keywords: [String] = []
}

enum DesktopSearch {
    /// Higher is better; nil = no match. Exact > title prefix > word prefix > initials > substring > keyword.
    static func score(_ query: String, _ item: DesktopSearchItem) -> Int? {
        let q = query.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return nil }
        let t = item.title.lowercased()
        let words = t.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map(String.init)
        var s: Int?
        if t == q { s = 1000 }
        else if t.hasPrefix(q) { s = 800 - min(t.count - q.count, 100) }
        else if words.contains(where: { $0.hasPrefix(q) }) { s = 600 }
        else if q.count >= 2, String(words.compactMap(\.first)).hasPrefix(q) { s = 500 }
        else if t.contains(q) { s = 400 }
        else if item.keywords.contains(where: { $0.lowercased().hasPrefix(q) }) { s = 300 }
        else if q.count >= 3, item.keywords.contains(where: { $0.lowercased().contains(q) }) { s = 200 }
        guard var score = s else { return nil }
        // Ties: RamPart actions and features before apps that merely share a word.
        if item.kind != .app && score < 1000 { score += 5 }
        return score
    }

    static func rank(_ query: String, in items: [DesktopSearchItem], limit: Int = 8) -> [DesktopSearchItem] {
        var scored: [(item: DesktopSearchItem, score: Int)] = []
        for i in items { if let s = score(query, i) { scored.append((i, s)) } }
        scored.sort { l, r in
            if l.score != r.score { return l.score > r.score }
            return l.item.title.localizedStandardCompare(r.item.title) == .orderedAscending
        }
        return Array(scored.prefix(limit).map { $0.item })
    }
}

// MARK: - System info samplers

struct CPUTicks: Equatable, Sendable {
    var user: UInt64, system: UInt64, idle: UInt64, nice: UInt64
    var busy: UInt64 { user &+ system &+ nice }
    var total: UInt64 { busy &+ idle }

    /// Whole-machine load between two samples, 0…1. nil if the counters didn't advance (or went backwards).
    static func usage(from a: CPUTicks, to b: CPUTicks) -> Double? {
        guard b.total > a.total, b.busy >= a.busy else { return nil }
        return min(1, max(0, Double(b.busy - a.busy) / Double(b.total - a.total)))
    }

    static func read() -> CPUTicks? {
        var info = host_cpu_load_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, $0, &count) }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let t = info.cpu_ticks
        return CPUTicks(user: UInt64(t.0), system: UInt64(t.1), idle: UInt64(t.2), nice: UInt64(t.3))
    }
}

struct MemoryReading: Equatable, Sendable {
    var used: UInt64, total: UInt64
    var fraction: Double { total == 0 ? 0 : min(1, Double(used) / Double(total)) }

    /// "Memory Used" as Activity Monitor counts it: app memory (internal − purgeable) + wired + compressed.
    static func used(internalPages: UInt64, purgeablePages: UInt64, wiredPages: UInt64, compressedPages: UInt64, pageSize: UInt64) -> UInt64 {
        let app = internalPages > purgeablePages ? internalPages - purgeablePages : 0
        return (app + wiredPages + compressedPages) * pageSize
    }

    static func read() -> MemoryReading? {
        var vm = vm_statistics64_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &vm) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count) }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let used = Self.used(internalPages: UInt64(vm.internal_page_count), purgeablePages: UInt64(vm.purgeable_count),
                             wiredPages: UInt64(vm.wire_count), compressedPages: UInt64(vm.compressor_page_count),
                             pageSize: UInt64(vm_kernel_page_size))
        let total = ProcessInfo.processInfo.physicalMemory
        return MemoryReading(used: min(used, total), total: total)
    }
}

struct DiskReading: Equatable, Sendable {
    var free: UInt64, total: UInt64
    var used: UInt64 { total > free ? total - free : 0 }
    var fraction: Double { total == 0 ? 0 : Double(used) / Double(total) }

    /// The user's data volume (falls back to /). statfs only: no file contents are read.
    static func read(paths: [String] = ["/System/Volumes/Data", "/"]) -> DiskReading? {
        for p in paths {
            var s = statfs()
            if statfs(p, &s) == 0, s.f_blocks > 0 {
                let bs = UInt64(s.f_bsize)
                return DiskReading(free: UInt64(s.f_bavail) * bs, total: UInt64(s.f_blocks) * bs)
            }
        }
        return nil
    }
}

struct BatteryReading: Equatable, Sendable {
    var percent: Int
    var charging: Bool
    var onAC: Bool
    var minutesLeft: Int?

    /// Parses one IOPowerSources description dictionary. nil if it isn't an internal battery.
    static func parse(_ d: [String: Any]) -> BatteryReading? {
        guard (d[kIOPSTypeKey] as? String) == kIOPSInternalBatteryType,
              (d[kIOPSIsPresentKey] as? Bool) ?? true,
              let cur = d[kIOPSCurrentCapacityKey] as? Int, let max = d[kIOPSMaxCapacityKey] as? Int, max > 0 else { return nil }
        let pct = Swift.max(0, Swift.min(100, Int((Double(cur) / Double(max) * 100).rounded())))
        let charging = (d[kIOPSIsChargingKey] as? Bool) ?? false
        let ac = (d[kIOPSPowerSourceStateKey] as? String) == kIOPSACPowerValue
        let tte = d[kIOPSTimeToEmptyKey] as? Int
        return BatteryReading(percent: pct, charging: charging, onAC: ac, minutesLeft: (tte ?? -1) > 0 && !ac ? tte : nil)
    }

    /// nil on Macs without a battery.
    static func read() -> BatteryReading? {
        guard let blob = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let list = IOPSCopyPowerSourcesList(blob)?.takeRetainedValue() as? [CFTypeRef] else { return nil }
        for ps in list {
            if let d = IOPSGetPowerSourceDescription(blob, ps)?.takeUnretainedValue() as? [String: Any], let r = parse(d) { return r }
        }
        return nil
    }
}

struct NetCounters: Equatable, Sendable {
    var received: UInt64, sent: UInt64

    /// Physical / cellular interfaces only. Tunnels (VPN `utun`, `ipsec`) would double-count traffic that
    /// also crosses en0; AWDL / low-latency WLAN / bridges / loopback aren't internet traffic.
    static func include(_ name: String) -> Bool {
        let skip = ["lo", "utun", "ipsec", "awdl", "llw", "bridge", "gif", "stf", "anpi", "ap", "vmenet", "feth"]
        return !skip.contains { name.hasPrefix($0) }
    }

    /// Delta of a 32-bit interface counter (if_data wraps at 4 GiB).
    static func delta32(_ a: UInt64, _ b: UInt64) -> UInt64 {
        b >= a ? b - a : (b &+ (1 << 32)) &- a
    }

    /// Bytes per second down / up between two samples `seconds` apart.
    static func rates(from a: NetCounters, to b: NetCounters, seconds: Double) -> (down: Double, up: Double) {
        guard seconds > 0.05 else { return (0, 0) }
        return (Double(delta32(a.received, b.received)) / seconds, Double(delta32(a.sent, b.sent)) / seconds)
    }

    /// Sums AF_LINK counters (32-bit, wrapping; each interface's delta is computed separately in `perInterface`).
    static func readPerInterface() -> [String: NetCounters] {
        var out: [String: NetCounters] = [:]
        var head: UnsafeMutablePointer<ifaddrs>?
        guard getifaddrs(&head) == 0 else { return out }
        defer { freeifaddrs(head) }
        var p = head
        while let ifa = p {
            defer { p = ifa.pointee.ifa_next }
            guard let addr = ifa.pointee.ifa_addr, addr.pointee.sa_family == UInt8(AF_LINK),
                  let data = ifa.pointee.ifa_data else { continue }
            let name = String(cString: ifa.pointee.ifa_name)
            guard include(name), (ifa.pointee.ifa_flags & UInt32(IFF_UP)) != 0 else { continue }
            let d = data.assumingMemoryBound(to: if_data.self).pointee
            out[name] = NetCounters(received: UInt64(d.ifi_ibytes), sent: UInt64(d.ifi_obytes))
        }
        return out
    }

    /// Rate across interfaces, wrap-safe per interface. Interfaces that appear or vanish between samples count 0.
    static func rates(from a: [String: NetCounters], to b: [String: NetCounters], seconds: Double) -> (down: Double, up: Double) {
        var down = 0.0, up = 0.0
        for (k, nb) in b { if let na = a[k] { let r = rates(from: na, to: nb, seconds: seconds); down += r.down; up += r.up } }
        return (down, up)
    }
}

enum Uptime {
    static func bootDate() -> Date? {
        var tv = timeval(), size = MemoryLayout<timeval>.size
        var mib: [Int32] = [CTL_KERN, KERN_BOOTTIME]
        guard sysctl(&mib, 2, &tv, &size, nil, 0) == 0, tv.tv_sec > 0 else { return nil }
        return Date(timeIntervalSince1970: Double(tv.tv_sec) + Double(tv.tv_usec) / 1e6)
    }
    /// "3d 4h", "5h 12m", "9m".
    static func format(_ seconds: TimeInterval) -> String {
        let s = max(0, Int(seconds)), d = s / 86_400, h = (s % 86_400) / 3600, m = (s % 3600) / 60
        if d > 0 { return "\(d)d \(h)h" }
        if h > 0 { return "\(h)h \(m)m" }
        return "\(m)m"
    }
}

enum DesktopFormat {
    /// "1.2 MB/s", "340 KB/s", "0 KB/s" (decimal units, like Activity Monitor).
    static func rate(_ bytesPerSecond: Double) -> String {
        let b = max(0, bytesPerSecond)
        if b >= 1e9 { return String(format: "%.1f GB/s", b / 1e9) }
        if b >= 1e6 { return String(format: "%.1f MB/s", b / 1e6) }
        return String(format: "%.0f KB/s", b / 1e3)
    }
    /// RAM is sold in binary units (a "24 GB" Mac has 24 × 1024³ bytes); decimal would show it as 26 GB.
    static func memory(_ n: UInt64) -> String {
        let g = Double(n) / 1_073_741_824
        return g >= 1 ? String(format: "%.0f GB", g) : String(format: "%.0f MB", Double(n) / 1_048_576)
    }

    static func bytes(_ n: UInt64) -> String {
        let b = Double(n)
        if b >= 1e12 { return String(format: "%.1f TB", b / 1e12) }
        if b >= 1e9 { return String(format: "%.0f GB", b / 1e9) }
        return String(format: "%.0f MB", b / 1e6)
    }
}

// MARK: - Click-through regions

/// The interactive layer passes clicks to Finder (desktop icons) everywhere except over a widget.
enum DesktopHitRegions {
    static func accepts(_ p: CGPoint, in rects: [CGRect], slop: CGFloat = 2) -> Bool {
        rects.contains { $0.insetBy(dx: -slop, dy: -slop).contains(p) }
    }
    /// Converts a bottom-left-origin (AppKit screen) point into a top-left-origin point inside `frame`.
    static func toTopLeft(_ p: CGPoint, frame: CGRect) -> CGPoint {
        CGPoint(x: p.x - frame.minX, y: frame.maxY - p.y)
    }
}

// MARK: - Refresh cadence

enum DesktopCadence {
    /// Widget refresh interval: 2 s on power, 5 s on battery; nil (stopped) when the layer isn't visible.
    static func interval(visible: Bool, onBattery: Bool, lowPower: Bool) -> TimeInterval? {
        guard visible else { return nil }
        if lowPower { return 5 }
        return onBattery ? 5 : 2
    }
}
