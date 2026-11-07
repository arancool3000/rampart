import Foundation
import CoreServices

/// Collects cleanable items per category. Everything is injectable so the self-test runs on a scratch "home".
public final class RefreshScanner: @unchecked Sendable {
    public struct Environment: Sendable {
        public var home: String
        public var now: Date
        /// Bundle IDs of running apps: their caches are skipped (an open app may be using them).
        public var runningBundleIDs: Set<String>
        /// Installed app bundle IDs. nil = discover from /Applications, ~/Applications, /System/Applications.
        public var installedBundleIDs: Set<String>?
        /// Folders searched for idle projects. Desktop/Documents only if the user adds them.
        public var projectRoots: [String]
        /// Read Downloads and other personal folders (macOS may ask for access).
        public var includePersonal: Bool
        /// Output of `brew cleanup -n` (nil = run it if Homebrew is installed).
        public var brewDryRunOutput: String?
        public var runBrew: Bool
        /// Last-opened date for a path (Spotlight kMDItemLastUsedDate by default).
        public var lastUsed: @Sendable (String) -> Date?
        public var runSystemTools: Bool

        public init(home: String = NSHomeDirectory(), now: Date = Date(), runningBundleIDs: Set<String> = [],
                    installedBundleIDs: Set<String>? = nil, projectRoots: [String]? = nil, includePersonal: Bool = false,
                    brewDryRunOutput: String? = nil, runBrew: Bool = true, runSystemTools: Bool = true,
                    lastUsed: @escaping @Sendable (String) -> Date? = RefreshScanner.spotlightLastUsed) {
            self.home = RefreshSafetyPolicy.normalize(home); self.now = now; self.runningBundleIDs = runningBundleIDs
            self.installedBundleIDs = installedBundleIDs
            self.projectRoots = projectRoots ?? [RefreshSafetyPolicy.normalize(home)]
            self.includePersonal = includePersonal; self.brewDryRunOutput = brewDryRunOutput; self.runBrew = runBrew
            self.runSystemTools = runSystemTools; self.lastUsed = lastUsed
        }
    }

    public let env: Environment
    public let policy: RefreshSafetyPolicy
    let scorer: RefreshScorer
    let fm = FileManager.default
    private let lock = NSLock()
    private var _cancelled = false
    public var cancelled: Bool { lock.lock(); defer { lock.unlock() }; return _cancelled }
    public func cancel() { lock.lock(); _cancelled = true; lock.unlock() }

    public init(env: Environment, policy: RefreshSafetyPolicy? = nil) {
        self.env = env
        self.policy = policy ?? RefreshSafetyPolicy(home: env.home)
        self.scorer = RefreshScorer(home: env.home, now: env.now)
    }

    var home: String { env.home }
    func h(_ rel: String) -> String { (home as NSString).appendingPathComponent(rel) }
    func children(_ dir: String) -> [String] {
        ((try? fm.contentsOfDirectory(atPath: dir)) ?? []).filter { $0 != ".DS_Store" && $0 != ".localized" }.sorted().map { dir + "/" + $0 }
    }
    func exists(_ p: String) -> Bool { fm.fileExists(atPath: p) }
    func isDir(_ p: String) -> Bool { var d: ObjCBool = false; return fm.fileExists(atPath: p, isDirectory: &d) && d.boolValue }
    func mdate(_ p: String) -> Date? { (try? fm.attributesOfItem(atPath: p))?[.modificationDate] as? Date }
    func days(_ d: Date?) -> Double { d.map { env.now.timeIntervalSince($0) / 86400 } ?? 0 }

    /// Builds an item, measuring it and applying the safety policy's path rules (refused paths never appear).
    func item(_ path: String, _ cat: RefreshCategory, regenerable: Bool, reason: String = "", group: String? = nil, measure: Bool = true) -> RefreshItem? {
        if policy.pathRefusal(path) != nil { return nil }
        let m = measure ? DiskSizer.measure(path, cancelled: { [weak self] in self?.cancelled ?? true }) : DiskSizer.Measure()
        guard !measure || m.total > 0 else { return nil }
        var it = RefreshItem(path: path, category: cat, bytes: m.bytes, sharedBytes: m.sharedBytes,
                             modified: m.newest ?? mdate(path), lastOpened: nil, regenerable: regenerable, groupID: group)
        it.reason = reason
        return it
    }

    // MARK: Run

    public func scan(_ categories: [RefreshCategory] = RefreshCategory.allCases, progress: ((RefreshCategory) -> Void)? = nil) -> [RefreshCategoryResult] {
        var out: [RefreshCategoryResult] = []
        for c in categories {
            if cancelled { break }
            if c.touchesPersonalFolders && !env.includePersonal { continue }
            progress?(c)
            var r = collect(c)
            for i in r.items.indices { scorer.score(&r.items[i]) }
            r.items.sort { $0.bytes > $1.bytes }
            out.append(r)
        }
        return out
    }

    public func collect(_ c: RefreshCategory) -> RefreshCategoryResult {
        switch c {
        case .appCaches: return RefreshCategoryResult(category: c, items: appCaches())
        case .oldLogs: return RefreshCategoryResult(category: c, items: oldLogs())
        case .crashReports: return RefreshCategoryResult(category: c, items: crashReports())
        case .xcode: return RefreshCategoryResult(category: c, items: xcode())
        case .projectBuilds: return RefreshCategoryResult(category: c, items: projectBuilds())
        case .packageCaches: return RefreshCategoryResult(category: c, items: packageCaches())
        case .homebrew: return homebrew()
        case .trash: return RefreshCategoryResult(category: c, items: children(h(".Trash")).compactMap { item($0, .trash, regenerable: false) })
        case .oldDownloads: return RefreshCategoryResult(category: c, items: oldDownloads())
        case .duplicates: return RefreshCategoryResult(category: c, items: duplicates())
        case .largeOldFiles: return RefreshCategoryResult(category: c, items: largeOldFiles())
        case .leftovers: return RefreshCategoryResult(category: c, items: leftovers())
        case .iosBackups: return infoFolder(c, h("Library/Application Support/MobileSync/Backup"))
        case .mailAttachments: return infoFolder(c, h("Library/Containers/com.apple.mail/Data/Library/Mail Downloads"))
        case .languagePacks: return languagePacks()
        case .localSnapshots: return localSnapshots()
        }
    }

    // MARK: Caches, logs, crash reports

    /// Caches handled by their own category (so nothing is counted twice).
    var packageCacheNames: Set<String> { ["pip", "Yarn", "Homebrew", "go-build", "node-gyp", "pnpm", "ms-playwright", "CocoaPods"] }
    static let browserCacheMarkers = ["com.google.Chrome", "Google", "com.brave.Browser", "BraveSoftware", "com.microsoft.edgemac", "Microsoft Edge",
                                      "Firefox", "org.mozilla.firefox", "company.thebrowser.Browser", "Arc", "com.apple.Safari", "com.operasoftware.Opera"]
    static let browserBundleIDs: [String: [String]] = [
        "com.google.Chrome": ["com.google.Chrome", "Google"], "com.brave.Browser": ["com.brave.Browser", "BraveSoftware"],
        "com.microsoft.edgemac": ["com.microsoft.edgemac", "Microsoft Edge"], "org.mozilla.firefox": ["Firefox", "org.mozilla.firefox"],
        "company.thebrowser.Browser": ["company.thebrowser.Browser", "Arc"], "com.operasoftware.Opera": ["com.operasoftware.Opera"],
    ]

    func appCaches() -> [RefreshItem] {
        var runningCacheNames = env.runningBundleIDs
        for (bid, names) in Self.browserBundleIDs where env.runningBundleIDs.contains(bid) { runningCacheNames.formUnion(names) }
        return children(h("Library/Caches")).compactMap { p in
            let n = (p as NSString).lastPathComponent
            if n.hasPrefix("com.apple.") || n == "CloudKit" || n == "FamilyCircle" || n == "GeoServices" || n.hasPrefix("app.rampart") { return nil }
            if packageCacheNames.contains(n) { return nil }
            if runningCacheNames.contains(n) || env.runningBundleIDs.contains(where: { n.lowercased() == $0.lowercased() }) { return nil }
            let browser = Self.browserCacheMarkers.contains(n)
            return item(p, .appCaches, regenerable: true, reason: browser ? "Browser cache only (your profile, history and passwords live elsewhere and are not touched)." : "")
        }
    }

    func oldLogs() -> [RefreshItem] {
        let root = h("Library/Logs")
        var out: [RefreshItem] = []
        guard let e = fm.enumerator(atPath: root) else { return out }
        while let rel = e.nextObject() as? String {
            if rel.hasPrefix("DiagnosticReports") || rel.hasPrefix("Rampart") { e.skipDescendants(); continue }
            let p = root + "/" + rel
            guard !isDir(p) else { continue }
            if days(mdate(p)) > 7, let it = item(p, .oldLogs, regenerable: true) { out.append(it) }
        }
        return out
    }

    func crashReports() -> [RefreshItem] {
        children(h("Library/Logs/DiagnosticReports")).filter { days(mdate($0)) > 1 }.compactMap { item($0, .crashReports, regenerable: true) }
    }

    // MARK: Developer

    func xcode() -> [RefreshItem] {
        var out: [RefreshItem] = []
        let dev = h("Library/Developer")
        out += children(dev + "/Xcode/DerivedData").compactMap { item($0, .xcode, regenerable: true, reason: "Xcode build cache.") }
        for sup in ["iOS DeviceSupport", "watchOS DeviceSupport", "tvOS DeviceSupport", "visionOS DeviceSupport"] {
            out += children(dev + "/Xcode/" + sup).filter { days(mdate($0)) > 90 }
                .compactMap { item($0, .xcode, regenerable: true, reason: "Debug symbols for a device OS version not used in 90+ days; Xcode re-downloads them when needed.") }
        }
        for arch in children(dev + "/Xcode/Archives") {
            out += children(arch).compactMap { item($0, .xcode, regenerable: false, reason: "App archive.") }
        }
        if let it = item(dev + "/CoreSimulator/Caches", .xcode, regenerable: true, reason: "Simulator caches.") { out.append(it) }
        // Simulator devices whose runtime is gone: device.plist says isDeleted / the runtime folder is missing. Shown with low risk.
        for d in children(dev + "/CoreSimulator/Devices") where isDir(d) {
            guard let plist = NSDictionary(contentsOfFile: d + "/device.plist") as? [String: Any] else { continue }
            let available = (plist["isAvailable"] as? Bool) ?? true
            if !available, let it = item(d, .xcode, regenerable: true, reason: "Simulator for an OS runtime that is no longer installed.") { out.append(it) }
        }
        return out
    }

    struct ArtifactRule { let dir: String; let marker: (String) -> Bool; let label: String }
    var artifactRules: [ArtifactRule] {
        [ArtifactRule(dir: ".build", marker: { [fm] p in fm.fileExists(atPath: p + "/Package.swift") }, label: "SwiftPM build folder"),
         ArtifactRule(dir: "node_modules", marker: { [fm] p in fm.fileExists(atPath: p + "/package.json") }, label: "node_modules (npm install restores it)"),
         ArtifactRule(dir: "target", marker: { [fm] p in fm.fileExists(atPath: p + "/Cargo.toml") }, label: "Rust build output"),
         ArtifactRule(dir: "__pycache__", marker: { _ in true }, label: "Python bytecode cache"),
         ArtifactRule(dir: ".venv", marker: { [fm] p in fm.fileExists(atPath: p + "/.venv/pyvenv.cfg") }, label: "Python virtual environment (recreate with pip install)"),
         ArtifactRule(dir: "venv", marker: { [fm] p in fm.fileExists(atPath: p + "/venv/pyvenv.cfg") }, label: "Python virtual environment (recreate with pip install)")]
    }

    /// Newest modification among a project's files, ignoring build artifacts (bounded walk).
    func projectLastTouched(_ project: String) -> Date? {
        let skip: Set<String> = [".build", "node_modules", "target", "__pycache__", ".venv", "venv", ".git", "DerivedData", "dist", "build"]
        var newest = mdate(project)
        var stack = [(project, 0)]
        var visited = 0
        while let (dir, depth) = stack.popLast(), visited < 5000 {
            for c in (try? fm.contentsOfDirectory(atPath: dir)) ?? [] {
                visited += 1
                let p = dir + "/" + c
                if skip.contains(c) { continue }
                if let d = mdate(p), d > (newest ?? .distantPast) { newest = d }
                if depth < 3, isDir(p) { stack.append((p, depth + 1)) }
            }
        }
        return newest
    }

    func projectBuilds() -> [RefreshItem] {
        var out: [RefreshItem] = []
        var seen = Set<String>()
        let banned: Set<String> = ["Library", "Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", ".Trash", "Applications"]
        let rules = artifactRules
        for root in env.projectRoots where isDir(root) {
            let isHome = root == home
            var stack = [(root, 0)]
            while let (dir, depth) = stack.popLast() {
                if cancelled { return out }
                let kids = (try? fm.contentsOfDirectory(atPath: dir)) ?? []
                for k in kids {
                    let p = dir + "/" + k
                    if isHome && depth == 0 && (banned.contains(k) || (k.hasPrefix(".") && k != ".venv")) { continue }
                    guard isDir(p) else { continue }
                    if let rule = rules.first(where: { $0.dir == k }) {
                        if rule.marker(dir), seen.insert(p).inserted {
                            let touched = projectLastTouched(dir)
                            if days(touched) >= 30, var it = item(p, .projectBuilds, regenerable: true, reason: rule.label + ".") {
                                it.reason += " Project last changed \(Int(days(touched))) days ago."
                                out.append(it)
                            }
                        }
                        continue   // never descend into artifacts
                    }
                    if k == ".git" || k.hasSuffix(".app") || k.hasPrefix(".") { continue }
                    if depth < 4 { stack.append((p, depth + 1)) }
                }
            }
        }
        return out
    }

    func packageCaches() -> [RefreshItem] {
        let candidates: [(String, String)] = [
            ("Library/Caches/pip", "pip download cache."), ("Library/Caches/Yarn", "Yarn cache."), (".npm/_cacache", "npm download cache."),
            (".cargo/registry/cache", "Cargo crate downloads."), ("go/pkg/mod/cache/download", "Go module download cache."),
            ("Library/Caches/go-build", "Go build cache."), ("Library/Caches/pnpm", "pnpm cache."), ("Library/Caches/CocoaPods", "CocoaPods cache."),
        ]
        return candidates.compactMap { item(h($0.0), .packageCaches, regenerable: true, reason: $0.1) }
    }

    // MARK: Homebrew (dry run only; RamPart trashes the listed paths itself)

    public static func brewPath() -> String? {
        ["/opt/homebrew/bin/brew", "/usr/local/bin/brew"].first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    /// Parses `brew cleanup -n` output: "Would remove: /path (12.3MB)" lines.
    public static func parseBrewDryRun(_ s: String) -> [String] {
        s.split(separator: "\n").compactMap { line -> String? in
            let l = line.trimmingCharacters(in: .whitespaces)
            guard l.hasPrefix("Would remove: ") else { return nil }
            var rest = String(l.dropFirst("Would remove: ".count))
            if let r = rest.range(of: " (", options: .backwards), rest.hasSuffix(")") { rest = String(rest[..<r.lowerBound]) }
            return rest.isEmpty ? nil : rest
        }
    }

    func homebrew() -> RefreshCategoryResult {
        var output = env.brewDryRunOutput
        if output == nil, env.runBrew, let brew = Self.brewPath() {
            output = Self.run(brew, ["cleanup", "-n"], env: ["HOMEBREW_NO_AUTO_UPDATE": "1", "HOMEBREW_NO_ANALYTICS": "1", "HOMEBREW_NO_ENV_HINTS": "1"], timeout: 60)
        }
        guard let output else { return RefreshCategoryResult(category: .homebrew, items: [], note: Self.brewPath() == nil ? "Homebrew isn't installed." : nil) }
        // Homebrew paths live outside home (/opt/homebrew/Cellar…, ~/Library/Caches/Homebrew). Only the cache under home is cleanable here.
        let items = Self.parseBrewDryRun(output).compactMap { item($0, .homebrew, regenerable: true, reason: "Listed by `brew cleanup -n`.") }
        let outside = Self.parseBrewDryRun(output).count - items.count
        return RefreshCategoryResult(category: .homebrew, items: items,
                                     note: outside > 0 ? "\(outside) older versions live in Homebrew's own folders; run `brew cleanup` in Terminal to remove them." : nil)
    }

    // MARK: Personal folders (only when allowed)

    func oldDownloads() -> [RefreshItem] {
        let dl = h("Downloads")
        let names = Set(((try? fm.contentsOfDirectory(atPath: dl)) ?? []))
        return children(dl).compactMap { p in
            let ext = (p as NSString).pathExtension.lowercased()
            guard ["dmg", "pkg", "mpkg", "iso", "zip", "tar", "gz", "tgz", "xip", "rar", "7z"].contains(ext) else { return nil }
            guard days(mdate(p)) > 90 else { return nil }
            let base = ((p as NSString).lastPathComponent as NSString).deletingPathExtension
            let extracted = names.contains(base) && isDir(dl + "/" + base)
            guard var it = item(p, .oldDownloads, regenerable: extracted) else { return nil }
            it.lastOpened = env.lastUsed(p)
            return it
        }
    }

    public var personalRoots: [String] { ["Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures"].map(h).filter(isDir) }

    func duplicates() -> [RefreshItem] {
        let groups = DuplicateFinder().find(in: personalRoots, cancelled: { [weak self] in self?.cancelled ?? true })
        var out: [RefreshItem] = []
        for g in groups.prefix(500) {
            // Keep the oldest copy; offer the others.
            for p in g.paths.dropFirst() {
                if var it = item(p, .duplicates, regenerable: false, reason: "Same contents as \((g.paths[0] as NSString).lastPathComponent), which is kept.", group: g.sha256) {
                    it.lastOpened = env.lastUsed(p)
                    out.append(it)
                }
            }
        }
        return out
    }

    func largeOldFiles() -> [RefreshItem] {
        var out: [RefreshItem] = []
        let keys: [URLResourceKey] = [.fileSizeKey, .isRegularFileKey, .isPackageKey, .isDirectoryKey]
        for root in personalRoots {
            guard let e = fm.enumerator(at: URL(fileURLWithPath: root), includingPropertiesForKeys: keys, options: [.skipsHiddenFiles], errorHandler: { _, _ in true }) else { continue }
            for case let u as URL in e {
                if cancelled { return out }
                guard let v = try? u.resourceValues(forKeys: Set(keys)) else { continue }
                if v.isDirectory == true { if v.isPackage == true { e.skipDescendants() }; continue }
                guard v.isRegularFile == true, (v.fileSize ?? 0) >= 500 << 20 else { continue }
                let last = env.lastUsed(u.path) ?? mdate(u.path)
                guard days(last) > 365, var it = item(u.path, .largeOldFiles, regenerable: false) else { continue }
                it.lastOpened = last
                out.append(it)
            }
        }
        return out
    }

    // MARK: Leftovers of removed apps

    public static func discoverInstalledBundleIDs(home: String) -> Set<String> {
        var ids = Set<String>()
        let roots = ["/Applications", "/Applications/Utilities", home + "/Applications", "/System/Applications", "/System/Applications/Utilities", "/System/Library/CoreServices"]
        for r in roots {
            for n in (try? FileManager.default.contentsOfDirectory(atPath: r)) ?? [] {
                let app = r + "/" + n
                if n.hasSuffix(".app") {
                    if let id = Bundle(path: app)?.bundleIdentifier { ids.insert(id) }
                    // Helpers, extensions and login items embedded in the app.
                    for sub in ["Contents/Library/LoginItems", "Contents/PlugIns", "Contents/Helpers", "Contents/Library/LaunchServices"] {
                        for h in (try? FileManager.default.contentsOfDirectory(atPath: app + "/" + sub)) ?? [] {
                            if let id = Bundle(path: app + "/" + sub + "/" + h)?.bundleIdentifier { ids.insert(id) }
                        }
                    }
                } else if !n.hasPrefix("."), r == "/Applications" {
                    for m in (try? FileManager.default.contentsOfDirectory(atPath: app)) ?? [] where m.hasSuffix(".app") {
                        if let id = Bundle(path: app + "/" + m)?.bundleIdentifier { ids.insert(id) }
                    }
                }
            }
        }
        return ids
    }

    static func looksLikeBundleID(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        guard parts.count >= 3, let first = parts.first, ["com", "org", "net", "io", "app", "co", "de", "uk", "dev", "me", "us"].contains(first.lowercased()) else { return false }
        return s.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" || $0 == "_" }
    }

    func leftovers() -> [RefreshItem] {
        let installed = (env.installedBundleIDs ?? Self.discoverInstalledBundleIDs(home: home)).union(env.runningBundleIDs)
        let installedLower = Set(installed.map { $0.lowercased() })
        func isInstalled(_ id: String) -> Bool {
            let l = id.lowercased()
            if installedLower.contains(l) { return true }
            // Helpers/related IDs: com.vendor.App.helper belongs to com.vendor.App.
            return installedLower.contains { l.hasPrefix($0 + ".") || $0.hasPrefix(l + ".") }
        }
        var out: [RefreshItem] = []
        let skipVendors = ["com.apple.", "app.rampart", "com.rampart", "group.", "systemgroup."]
        // Containers are listed (names only) but never measured: reading inside another app's container makes macOS ask for permission.
        let places: [(String, Bool)] = [("Library/Application Support", true), ("Library/Preferences", true), ("Library/Caches", true),
                                        ("Library/Saved Application State", true), ("Library/HTTPStorages", true), ("Library/WebKit", true),
                                        ("Library/Containers", false)]
        for (rel, measure) in places {
            for p in children(h(rel)) {
                var name = (p as NSString).lastPathComponent
                for suf in [".plist", ".savedState", ".binarycookies"] where name.hasSuffix(suf) { name = String(name.dropLast(suf.count)) }
                guard Self.looksLikeBundleID(name), !skipVendors.contains(where: { name.lowercased().hasPrefix($0) }) else { continue }
                if isInstalled(name) { continue }
                if var it = item(p, .leftovers, regenerable: false, reason: "No installed app uses \(name).", measure: measure) {
                    if !measure { it.reason += " Size not measured: macOS protects other apps' containers." }
                    out.append(it)
                }
            }
        }
        return out
    }

    // MARK: Info-only

    func infoFolder(_ c: RefreshCategory, _ path: String) -> RefreshCategoryResult {
        guard isDir(path) else { return RefreshCategoryResult(category: c, items: [], note: "None found (or macOS needs Full Disk Access to read them).") }
        let items = children(path).compactMap { p -> RefreshItem? in
            guard var it = item(p, c, regenerable: false) else { return nil }
            it.selected = false
            return it
        }
        return RefreshCategoryResult(category: c, items: items, note: c == .iosBackups ? "Manage backups in Finder › your device › Manage Backups." : "Manage attachments in Mail.")
    }

    func languagePacks() -> RefreshCategoryResult {
        let keep = Set(Locale.preferredLanguages.flatMap { l -> [String] in
            let base = String(l.split(separator: "-").first ?? Substring(l))
            return [l, base, "Base", "en", "English"]
        }.map { $0.lowercased() })
        var total: UInt64 = 0
        var apps = 0
        for n in ((try? fm.contentsOfDirectory(atPath: "/Applications")) ?? []) where n.hasSuffix(".app") {
            if cancelled { break }
            let res = "/Applications/\(n)/Contents/Resources"
            var counted = false
            for l in ((try? fm.contentsOfDirectory(atPath: res)) ?? []) where l.hasSuffix(".lproj") {
                let code = String(l.dropLast(6)).lowercased().replacingOccurrences(of: "_", with: "-")
                if keep.contains(code) || keep.contains(String(code.split(separator: "-").first ?? "")) { continue }
                total += DiskSizer.measure(res + "/" + l, limit: 2000).total
                counted = true
            }
            if counted { apps += 1 }
        }
        return RefreshCategoryResult(category: .languagePacks, items: [],
                                     note: "About \(total.refreshFormatted) of translations you don't use, across \(apps) apps. They stay: removing files inside an app breaks its signature and updates put them back.",
                                     infoBytes: total)
    }

    func localSnapshots() -> RefreshCategoryResult {
        guard env.runSystemTools else { return RefreshCategoryResult(category: .localSnapshots, items: [], note: "Not checked.") }
        let out = Self.run("/usr/bin/tmutil", ["listlocalsnapshotdates", "/"], timeout: 15) ?? ""
        let n = out.split(separator: "\n").filter { $0.first?.isNumber == true }.count
        return RefreshCategoryResult(category: .localSnapshots, items: [],
                                     note: n == 0 ? "No local snapshots right now." : "\(n) local snapshot\(n == 1 ? "" : "s"). macOS removes them automatically when space runs low, and their space counts as “purgeable”.")
    }

    // MARK: Helpers

    /// Runs a read-only tool with a timeout; returns stdout.
    public static func run(_ tool: String, _ args: [String], env extra: [String: String] = [:], timeout: TimeInterval) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = args
        var e = ProcessInfo.processInfo.environment
        for (k, v) in extra { e[k] = v }
        p.environment = e
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(timeout)
        var data = Data()
        let reader = DispatchQueue(label: "refresh.run")
        let done = DispatchSemaphore(value: 0)
        reader.async { data = pipe.fileHandleForReading.readDataToEndOfFile(); done.signal() }
        if done.wait(timeout: .now() + max(0, deadline.timeIntervalSinceNow)) == .timedOut { p.terminate(); return nil }
        p.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

    /// Spotlight's last-opened date. No permission prompt: it's metadata Spotlight already indexed.
    public static let spotlightLastUsed: @Sendable (String) -> Date? = { path in
        guard let md = MDItemCreate(kCFAllocatorDefault, path as CFString) else { return nil }
        return MDItemCopyAttribute(md, kMDItemLastUsedDate) as? Date
    }
}
