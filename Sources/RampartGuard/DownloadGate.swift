import Foundation
import Darwin
import CoreServices
import RampartShared

// Download Gate: check new downloads before they get a chance to run.
//
// HONEST LIMIT: without Apple's Endpoint Security AUTH events RamPart cannot hold an exec until it has decided. The
// gate therefore works on what *arrives*: within about a second of a download finishing (stable size, no partial
// marker) it makes sure macOS's quarantine flag is set (so Gatekeeper checks the file on first open), takes the
// execute permission away from programs and scripts, scans the file, and gives the permission back only to signed,
// notarized, clean code. Anything unsigned stays non-executable and is "Held for your review"; malware is quarantined.
// It never touches anything outside the watched folders and skips developer folders (git repos, build output,
// Homebrew, ~/Code, RamPart's own source tree).

public enum GateVerdict: String, Codable, Sendable, CaseIterable {
    case cleared, held, blocked, allowed, deleted
    public var label: String {
        switch self {
        case .cleared: return "Cleared"; case .held: return "Held for your review"; case .blocked: return "Blocked"
        case .allowed: return "Allowed by you"; case .deleted: return "Moved to Trash"
        }
    }
}

public struct GateItem: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var path: String
    public var name: String
    /// Display name of the watched folder it arrived in ("Downloads", "Desktop", "Mail attachments" …).
    public var folder: String
    public var kind: GateFileKind
    public var verdict: GateVerdict
    public var reason: String
    public var arrived: Date
    public var checked: Date
    /// Seconds from the first file-system event to the decision.
    public var secondsToCheck: Double
    public var size: Int64
    public var signature: GateSignature?
    /// RamPart added the com.apple.quarantine flag (the download arrived without one).
    public var quarantineFlagAdded: Bool = false
    /// Execute bits RamPart removed: path → original mode. Restored on Cleared / Allow.
    public var strippedModes: [String: UInt16] = [:]
    /// wms-o2: identity ("dev:ino") of each file whose execute bits were removed. Allow only restores the bits on that
    /// same inode, so a file swapped in under the same name after the check never gets them.
    public var strippedIDs: [String: String]? = nil
    public var threat: String?
    public var detectionID: UUID?

    public var executeRemoved: Bool { !strippedModes.isEmpty && (verdict == .held || verdict == .blocked) }
}

public struct DownloadGateConfig: Codable, Hashable, Sendable {
    public var enabled = true
    public init() {}
}

public struct DownloadGateStatus: Codable, Hashable, Sendable {
    public var enabled: Bool
    public var running: Bool
    public var watched: [String]
    public var items: [GateItem]
    public var honesty: String
    public var lastError: String?
    public var held: [GateItem] { items.filter { $0.verdict == .held } }
    public init(enabled: Bool, running: Bool, watched: [String], items: [GateItem], honesty: String, lastError: String?) {
        self.enabled = enabled; self.running = running; self.watched = watched; self.items = items; self.honesty = honesty; self.lastError = lastError
    }
}

public enum DownloadGateError: Error, LocalizedError {
    case notFound, notHeld, outsideWatched, failed(String)
    public var errorDescription: String? {
        switch self {
        case .notFound: return "That download is no longer in the list."
        case .notHeld: return "That download isn't waiting for a decision."
        case .outsideWatched: return "RamPart only changes files inside the folders it watches."
        case .failed(let s): return s
        }
    }
}

public final class DownloadGateService: @unchecked Sendable {
    public static let honesty = "RamPart checks each new download within about a second of it finishing. macOS doesn't let apps without Apple's special Endpoint Security permission stop a program before it starts, so if you open something in that first second RamPart can't hold it. It also makes sure macOS Gatekeeper checks every download when you first open it."
    public static let partialSuffixes = [".crdownload", ".download", ".part", ".partial", ".opdownload", ".tmp", ".temp", ".filepart", ".!ut"]
    public static let quarantineAttr = "com.apple.quarantine"
    public static let maxItems = 300

    public let directory: URL
    public let home: String
    /// Watched folder → display name. Only paths under these are ever changed.
    public private(set) var roots: [(path: String, name: String)]
    public var signer: DownloadGateSigning
    /// Engine scan of one file (the daemon injects the ScanCoordinator; archives are unpacked by the engine).
    public var scan: (String) -> Detection? = { _ in nil }
    /// Malicious enough to quarantine (default: the signal-to-noise policy's auto-remediation rule, or EICAR).
    public var isMalicious: (Detection) -> Bool = { DetectionPolicy.mayAutoRemediate($0) || DetectionPolicy.isTestSignature($0) }
    /// Moves the file to RamPart's quarantine. Returns the stored detection id, or nil when it couldn't.
    public var quarantine: (String, Detection) -> UUID? = { _, _ in nil }
    /// Every decision (Activity, app push).
    public var onDecision: ((GateItem) -> Void)?
    public var stableSeconds: TimeInterval = 0.6
    /// "Delete" on a held item (tests inject a plain remove so nothing lands in the real Trash).
    public var trash: (URL) throws -> Void = { try FileManager.default.trashItem(at: $0, resultingItemURL: nil) }
    public var extraSkipPrefixes: [String] = []

    private let queue = DispatchQueue(label: "rampart.downloadgate")
    private var config = DownloadGateConfig()
    private var items: [GateItem] = []
    private var pending: [String: (size: Int64, mtime: Double, lastChange: Date, first: Date)] = [:]
    /// Fingerprints of decided subjects (dev, inode, size, mtime) so our own chmod / xattr events never re-trigger.
    private var decided: [String: String] = [:]
    private var watcher: GateFSWatcher?
    private var timer: DispatchSourceTimer?
    private var ticks = 0
    private var lastError: String?

    public init(directory: URL, home: String = NSHomeDirectory(), signer: DownloadGateSigning = SecDownloadGateSigning(),
                roots: [(path: String, name: String)]? = nil) {
        self.directory = directory
        self.home = home
        self.signer = signer
        self.roots = (roots ?? Self.defaultRoots(home: home)).map { (Self.canonical($0.path), $0.name) }
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? Data(contentsOf: configURL), let c = try? JSONDecoder.rampart.decode(DownloadGateConfig.self, from: d) { config = c }
        if let d = try? Data(contentsOf: itemsURL), let i = try? JSONDecoder.rampart.decode([GateItem].self, from: d) { items = i }
    }

    private var configURL: URL { directory.appendingPathComponent("download-gate-config.json") }
    private var itemsURL: URL { directory.appendingPathComponent("download-gate-items.json") }

    // MARK: folders

    /// Downloads, Desktop, Mail and Messages attachments (AirDrop lands in Downloads), plus Chromium browsers' custom
    /// download folders when they are inside the home folder.
    public static func defaultRoots(home: String) -> [(path: String, name: String)] {
        var r: [(String, String)] = [
            (home + "/Downloads", "Downloads"), (home + "/Desktop", "Desktop"),
            (home + "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads", "Mail attachments"),
            (home + "/Library/Mail Downloads", "Mail attachments"),
            (home + "/Library/Messages/Attachments", "Messages attachments"),
        ]
        for dir in chromiumDownloadFolders(home: home) where !r.contains(where: { $0.0 == dir }) {
            r.append((dir, "Browser downloads (\((dir as NSString).lastPathComponent))"))
        }
        return r
    }

    /// `download.default_directory` from Chrome / Brave / Edge / Arc / Vivaldi preferences. Never the home folder itself.
    public static func chromiumDownloadFolders(home: String) -> [String] {
        let profiles = ["Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Arc/User Data", "Vivaldi"]
        var out: [String] = []
        for p in profiles {
            let prefs = "\(home)/Library/Application Support/\(p)/Default/Preferences"
            guard let d = FileManager.default.contents(atPath: prefs), d.count < 8 << 20,
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let dl = j["download"] as? [String: Any], let dir = dl["default_directory"] as? String else { continue }
            let c = canonical(dir)
            guard c.hasPrefix(canonical(home) + "/"), c != canonical(home), !out.contains(c) else { continue }
            out.append(c)
        }
        return out
    }

    static func canonical(_ p: String) -> String {
        let s = (p as NSString).standardizingPath
        // /var → /private/var etc. (FSEvents reports real paths).
        if let r = realpath(s, nil) { defer { free(r) }; return String(cString: r) }
        return s
    }

    /// The watched folder a path is in (nil = never touch it).
    public func root(of path: String) -> (path: String, name: String)? {
        roots.first { path.hasPrefix($0.path + "/") }
    }

    /// Why a path is left alone (nil = gate it). Developer workflows are never touched.
    public func skipReason(_ path: String) -> String? {
        guard let root = root(of: path) else { return "outside the watched folders" }
        let name = (path as NSString).lastPathComponent
        if name.hasPrefix(".") || name == "Icon\r" { return "hidden file" }
        let lower = name.lowercased()
        if Self.partialSuffixes.contains(where: { lower.hasSuffix($0) }) { return "download still in progress" }
        let devPrefixes = [home + "/Rampart", home + "/Code", "/opt/homebrew", "/usr/local/Homebrew", home + "/Library/Caches/Homebrew",
                           directory.path] + extraSkipPrefixes
        if devPrefixes.map(Self.canonical).contains(where: { path == $0 || path.hasPrefix($0 + "/") }) { return "developer folder" }
        let rel = String(path.dropFirst(root.path.count + 1)).split(separator: "/").map(String.init)
        let devComponents: Set<String> = [".git", ".build", "build", "DerivedData", "node_modules", "Homebrew", "Caskroom", ".venv", "venv", "target", "Pods", ".swiftpm"]
        if rel.dropLast().contains(where: { devComponents.contains($0) }) { return "developer folder" }
        // Inside a git repository (a .git folder or file in any parent up to the watched folder).
        var dir = (path as NSString).deletingLastPathComponent
        while dir.count >= root.path.count {
            if FileManager.default.fileExists(atPath: dir + "/.git") { return "inside a git repository" }
            if dir == root.path { break }
            dir = (dir as NSString).deletingLastPathComponent
        }
        return nil
    }

    /// What gets gated for a changed path: the outermost .app bundle around it, else the path itself.
    public func subject(for path: String) -> String? {
        guard let root = root(of: path) else { return nil }
        let rel = String(path.dropFirst(root.path.count + 1)).split(separator: "/").map(String.init)
        if let i = rel.firstIndex(where: { $0.lowercased().hasSuffix(".app") }) {
            return root.path + "/" + rel[...i].joined(separator: "/")
        }
        return path
    }

    // MARK: lifecycle

    public var isEnabled: Bool { queue.sync { config.enabled } }
    public var isRunning: Bool { queue.sync { watcher != nil } }

    public func start() {
        queue.async { self.startLocked() }
    }
    private func startLocked() {
        guard config.enabled, watcher == nil else { return }
        let existing = roots.map(\.path).filter { FileManager.default.fileExists(atPath: $0) }
        let w = GateFSWatcher(paths: existing, queue: queue) { [weak self] paths in
            for p in paths { self?.noteChangedLocked(p) }
        }
        if w.start() { watcher = w; lastError = nil } else { lastError = "Couldn't watch the download folders (FSEvents)" }
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25)
        t.setEventHandler { [weak self] in self?.tickLocked(now: Date()) }
        t.resume(); timer = t
    }
    public func stop() { queue.sync { stopLocked() } }
    private func stopLocked() { watcher?.stop(); watcher = nil; timer?.cancel(); timer = nil; pending.removeAll() }

    @discardableResult
    public func setEnabled(_ on: Bool) -> DownloadGateStatus {
        queue.sync {
            config.enabled = on
            if let d = try? JSONEncoder.rampart.encode(config) { try? d.write(to: configURL, options: .atomic) }
            if !on { stopLocked() }
        }
        if on { start() }
        return status()
    }

    public func status() -> DownloadGateStatus {
        queue.sync {
            DownloadGateStatus(enabled: config.enabled, running: watcher != nil, watched: roots.filter { FileManager.default.fileExists(atPath: $0.path) }.map { $0.path },
                               items: items, honesty: Self.honesty, lastError: lastError)
        }
    }

    // MARK: events

    /// A file-system event for `path` (FSEvents, or a test).
    public func noteChanged(_ path: String) { queue.sync { noteChangedLocked(Self.canonical(path)) } }

    /// Advances the stability check (the timer calls this every 0.25 s).
    public func tick(now: Date = Date()) { queue.sync { tickLocked(now: now) } }

    private func noteChangedLocked(_ path: String) {
        guard config.enabled, let subj = subject(for: path), skipReason(subj) == nil else { return }
        // A partial download finishing renames "x.crdownload" → "x": the event for "x" arrives on its own.
        let st = Self.stat(subj)
        guard let st else { pending[subj] = nil; return }
        if decided[subj] == st.fingerprint { return }   // our own chmod / xattr, or nothing new
        let now = Date()
        if let p = pending[subj] { pending[subj] = (st.size, st.mtime, now, p.first) }
        else { pending[subj] = (st.size, st.mtime, now, now) }
    }

    private func tickLocked(now: Date) {
        ticks += 1
        if ticks % 8 == 0 { reverifyLocked() }   // about every 2 s
        for (path, p) in pending {
            guard let st = Self.stat(path) else { pending[path] = nil; continue }
            if st.size != p.size || st.mtime != p.mtime { pending[path] = (st.size, st.mtime, now, p.first); continue }
            if now.timeIntervalSince(p.lastChange) < stableSeconds { continue }
            if Self.partialSuffixes.contains(where: { FileManager.default.fileExists(atPath: path + $0) }) { continue }
            pending[path] = nil
            _ = processLocked(path, firstSeen: p.first)
        }
    }

    /// Gate one file now (no stability wait). Used by tests and by the tick once a download is stable.
    @discardableResult
    public func process(_ path: String) -> GateItem? {
        queue.sync {
            guard let subj = subject(for: Self.canonical(path)) else { return nil }
            return processLocked(subj, firstSeen: Date())
        }
    }

    private func processLocked(_ path: String, firstSeen: Date) -> GateItem? {
        guard let root = root(of: path), skipReason(path) == nil else { return nil }
        var lst = Darwin.stat()
        guard lstat(path, &lst) == 0, (lst.st_mode & S_IFMT) != S_IFLNK else { return nil }   // never follow symlinks
        let kind = GateFileKind.classify(path: path)
        let isDir = (lst.st_mode & S_IFMT) == S_IFDIR
        if isDir && kind != .app && kind != .installer { return nil }
        // wms-o2: a link anywhere in the path (e.g. a swapped parent folder) means it isn't really in the watched folder.
        guard GateFS.lstatStrict(path) != nil else { return nil }
        var item = GateItem(path: path, name: (path as NSString).lastPathComponent, folder: root.name, kind: kind, verdict: .cleared,
                            reason: "", arrived: firstSeen, checked: Date(), secondsToCheck: 0, size: Self.stat(path)?.size ?? 0)
        // 1. Gatekeeper must check it on first open.
        item.quarantineFlagAdded = Self.ensureQuarantineFlag(path)
        // 2. No execute permission until it has been checked.
        var afterStrip: [String: Darwin.stat] = [:]
        if kind.isCode {
            let s = Self.stripExecuteFiles(subject: path, kind: kind)
            item.strippedModes = s.modes; item.strippedIDs = s.ids; afterStrip = s.after
        }
        // 3. Scan (the app bundle's executables, or the file; archives are unpacked by the engine).
        let main: (path: String?, anomaly: Bool) = kind == .app ? GateFS.mainExecutable(path) : (nil, false)
        var targets = kind == .app ? Self.bundleExecutables(path) : [path]
        if let m = main.path, !targets.contains(m), GateFS.lstatStrict(m) != nil { targets.insert(m, at: 0) }
        if kind == .app { for f in item.strippedModes.keys.sorted() where !targets.contains(f) && targets.count < 256 { targets.append(f) } }
        var finding: Detection?
        for t in targets { if let d = scan(t), isMalicious(d) { finding = d; break } }
        if var d = finding {
            if d.path == nil { d.path = path }
            item.threat = d.name
            let moveTarget = kind == .app ? path : (d.path ?? path)
            item.detectionID = quarantine(moveTarget, d)
            item.verdict = .blocked
            item.reason = item.detectionID != nil && !FileManager.default.fileExists(atPath: path)
                ? "\(d.name). Moved to quarantine."
                : "\(d.name). RamPart couldn't move it, so it can't run (execute permission removed)."
        } else if kind.isCode {
            let sig = signer.assess(path: path, kind: kind)
            item.signature = sig
            // wms-o2: things that make a good signature meaningless for this copy.
            let changed = afterStrip.contains { f, before in
                guard let now = GateFS.lstatStrict(f) else { return true }
                return now.st_ino != before.st_ino || now.st_dev != before.st_dev || now.st_size != before.st_size
                    || now.st_ctimespec.tv_sec != before.st_ctimespec.tv_sec || now.st_ctimespec.tv_nsec != before.st_ctimespec.tv_nsec
            }
            let hardLinked = !isDir && lst.st_nlink > 1
            if kind == .script && item.strippedModes.isEmpty {
                item.reason = "No threats found. It's a script without permission to run, so it opens as text."
            } else if main.anomaly || changed || hardLinked {
                item.verdict = .held
                item.reason = main.anomaly ? "Its Info.plist points the app at a program outside Contents/MacOS, so RamPart can't vouch for it."
                    : changed ? "It changed while RamPart was checking it, so it can't run until you allow it."
                    : "It has a second name (hard link) somewhere else on disk, so RamPart can't vouch for it. It can't run until you allow it."
            } else if sig.isTrustedToRun {
                Self.restore(item.strippedModes, ids: item.strippedIDs)
                item.reason = "No threats found. \(sig.summary)" + (sig.gatekeeperAccepted == true ? "; Gatekeeper accepts it." : ".")
            } else {
                item.verdict = .held
                item.reason = "\(sig.summary)" + (sig.gatekeeperAccepted == false ? "; Gatekeeper rejects it" : "") +
                    ". No known threat was found, but RamPart can't vouch for who made it, so it can't run until you allow it."
            }
        } else {
            switch kind {
            case .archive: item.reason = "No threats found inside. Apps you unpack from it are checked again when they appear."
            case .diskImage: item.reason = "No threats found. macOS Gatekeeper checks apps from it when you first open them."
            case .installer: item.reason = "No threats found. macOS checks the installer's signature when you open it."
            default: item.reason = "No threats found."
            }
        }
        // wms-o2: re-gating a held item (e.g. after someone put an execute bit back) must keep the original modes, so
        // the periodic re-check and Allow still know which files were stripped.
        if item.verdict == .held || item.verdict == .blocked, let old = items.first(where: { $0.path == path }),
           old.verdict == .held || old.verdict == .blocked {
            var ids = item.strippedIDs ?? [:]
            for (f, m) in old.strippedModes where item.strippedModes[f] == nil {
                guard let now = GateFS.lstatStrict(f), old.strippedIDs?[f] == nil || old.strippedIDs?[f] == GateFS.id(now) else { continue }
                item.strippedModes[f] = m
                if let i = old.strippedIDs?[f] { ids[f] = i }
            }
            item.strippedIDs = ids
        }
        item.checked = Date()
        item.secondsToCheck = max(0, item.checked.timeIntervalSince(firstSeen))
        if let st = Self.stat(path) { decided[path] = st.fingerprint } else { decided[path] = nil }
        record(item)
        onDecision?(item)
        return item
    }

    private func record(_ item: GateItem) {
        items.removeAll { $0.path == item.path || $0.id == item.id }   // a newer download at the same path replaces the old row
        items.insert(item, at: 0)
        if items.count > Self.maxItems { items = Array(items.prefix(Self.maxItems)) }
        if decided.count > 5000 { decided.removeAll() }
        if let d = try? JSONEncoder.rampart.encode(items) { try? d.write(to: itemsURL, options: .atomic) }
    }

    /// wms-o2: re-checks every held or blocked item. If something put an execute bit back (chmod, possibly through
    /// another hard link that FSEvents reports under a different path) or removed the quarantine flag, the gate takes
    /// it away / adds it again. Returns the number of repairs.
    @discardableResult
    public func reverify() -> Int { queue.sync { reverifyLocked() } }

    @discardableResult
    private func reverifyLocked() -> Int {
        var repairs = 0
        for i in items.indices where items[i].verdict == .held || items[i].verdict == .blocked {
            let item = items[i]
            guard root(of: item.path) != nil, GateFS.lstatStrict(item.path) != nil else { continue }
            for (f, _) in item.strippedModes {
                let want = item.strippedIDs?[f]
                if GateFS.setMode(f, expectID: want, { m in m & 0o111 != 0 ? m & ~0o111 & ~0o6000 : nil }).map({ $0.st_mode & 0o111 != 0 }) == true {
                    repairs += 1
                }
            }
            if item.kind.isCode || item.verdict == .blocked {
                let value = String(format: "0081;%08x;RamPart Download Gate;%@", Int(Date().timeIntervalSince1970), UUID().uuidString)
                if GateFS.addXattrIfMissing(item.path, Self.quarantineAttr, value) { repairs += 1 }
            }
            if let st = Self.stat(item.path) { decided[item.path] = st.fingerprint }
        }
        return repairs
    }

    // MARK: decisions

    /// "Allow" gives a held item its execute permission back; "Delete" moves it to the Trash.
    public func decide(id: UUID, allow: Bool) throws -> GateItem {
        try queue.sync {
            guard let i = items.firstIndex(where: { $0.id == id }) else { throw DownloadGateError.notFound }
            var item = items[i]
            guard item.verdict == .held else { throw DownloadGateError.notHeld }
            guard root(of: item.path) != nil else { throw DownloadGateError.outsideWatched }
            var st = Darwin.stat()
            if lstat(item.path, &st) != 0 {
                item.verdict = .deleted; item.reason = "It's no longer there."
            } else if allow {
                Self.restore(item.strippedModes, ids: item.strippedIDs)
                item.verdict = .allowed
                item.reason = "You allowed it. Its permission to run was restored."
            } else {
                do { try trash(URL(fileURLWithPath: item.path)) }
                catch { throw DownloadGateError.failed("Couldn't move it to the Trash: \(error.localizedDescription)") }
                item.verdict = .deleted
                item.reason = "You moved it to the Trash."
            }
            item.checked = Date()
            items[i] = item
            if let s = Self.stat(item.path) { decided[item.path] = s.fingerprint }
            if let d = try? JSONEncoder.rampart.encode(items) { try? d.write(to: itemsURL, options: .atomic) }
            onDecision?(item)
            return item
        }
    }

    // MARK: file helpers

    struct Stat { var size: Int64; var mtime: Double; var fingerprint: String }

    /// Size + mtime; for an .app bundle the sum over its files (so a bundle still being unpacked isn't "stable").
    /// wms-o2: the fingerprint also covers what an attacker can change without touching size or mtime: execute bits
    /// put back with chmod, the quarantine flag removed, and (for apps) the Info.plist's inode change time, which
    /// `touch -r` can't reset. A change to any of them re-gates the item.
    static func stat(_ path: String) -> Stat? {
        var st = Darwin.stat()
        guard lstat(path, &st) == 0 else { return nil }
        var size = Int64(st.st_size)
        var mtime = Double(st.st_mtimespec.tv_sec) + Double(st.st_mtimespec.tv_nsec) / 1e9
        var execs = (st.st_mode & S_IFMT) == S_IFREG && st.st_mode & 0o111 != 0 ? 1 : 0
        var plist = ""
        if (st.st_mode & S_IFMT) == S_IFDIR, let e = FileManager.default.enumerator(atPath: path) {
            var n = 0
            while let rel = e.nextObject() as? String, n < 20_000 {
                n += 1
                var s2 = Darwin.stat()
                if lstat(path + "/" + rel, &s2) == 0 {
                    size += Int64(s2.st_size)
                    mtime = max(mtime, Double(s2.st_mtimespec.tv_sec) + Double(s2.st_mtimespec.tv_nsec) / 1e9)
                    if (s2.st_mode & S_IFMT) == S_IFREG && s2.st_mode & 0o111 != 0 { execs += 1 }
                    if rel == "Contents/Info.plist" { plist = "\(s2.st_ino).\(s2.st_ctimespec.tv_sec).\(s2.st_ctimespec.tv_nsec)" }
                }
            }
        }
        let q = hasQuarantineFlag(path) ? 1 : 0
        return Stat(size: size, mtime: mtime, fingerprint: "\(st.st_dev):\(st.st_ino):\(size):\(mtime):x\(execs):q\(q):p\(plist)")
    }

    /// Adds com.apple.quarantine when missing (never replaces an existing one). Returns true when it added it.
    /// wms-o2: through a descriptor, never following a link in any path component.
    static func ensureQuarantineFlag(_ path: String) -> Bool {
        // flags;hex-time;agent;uuid — 0081 = downloaded, not yet approved by the user.
        let value = String(format: "0081;%08x;RamPart Download Gate;%@", Int(Date().timeIntervalSince1970), UUID().uuidString)
        return GateFS.addXattrIfMissing(path, quarantineAttr, value)
    }

    public static func hasQuarantineFlag(_ path: String) -> Bool { GateFS.hasXattr(path, quarantineAttr) }

    /// The executables of an app bundle: everything regular in Contents/MacOS (and Contents/Helpers).
    static func bundleExecutables(_ app: String) -> [String] {
        var out: [String] = []
        for sub in ["Contents/MacOS", "Contents/Helpers"] {
            let dir = app + "/" + sub
            for n in (try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? [] {
                var st = Darwin.stat()
                if lstat(dir + "/" + n, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG { out.append(dir + "/" + n) }
            }
        }
        return out
    }

    /// Clears every execute bit; returns path → original mode for the files it changed.
    static func stripExecute(subject: String, kind: GateFileKind) -> [String: UInt16] {
        stripExecuteFiles(subject: subject, kind: kind).modes
    }

    /// wms-o2: for an app, every executable file anywhere in the bundle (a payload in Contents/Resources runs just as
    /// well as one in Contents/MacOS). Each chmod goes through a descriptor, never through a link. Also returns each
    /// file's identity and its stat right after the change (to notice a rewrite while the signature is checked).
    static func stripExecuteFiles(subject: String, kind: GateFileKind) -> (modes: [String: UInt16], ids: [String: String], after: [String: Darwin.stat]) {
        let files = kind == .app ? GateFS.executableFiles(under: subject) : [subject]
        var changed: [String: UInt16] = [:], ids: [String: String] = [:], after: [String: Darwin.stat] = [:]
        for f in files {
            guard let before = GateFS.setMode(f, { m in m & 0o111 != 0 ? m & ~0o111 & ~0o6000 : nil }),   // also drops setuid/setgid
                  before.st_mode & 0o111 != 0 else { continue }
            changed[f] = UInt16(before.st_mode & 0o7777)
            ids[f] = GateFS.id(before)
            if let now = GateFS.lstatStrict(f) { after[f] = now }
        }
        return (changed, ids, after)
    }

    /// Gives back execute bits, never setuid/setgid, and (when known) only to the same inode that was stripped.
    static func restore(_ modes: [String: UInt16], ids: [String: String]? = nil) {
        for (f, m) in modes {
            GateFS.setMode(f, expectID: ids?[f]) { _ in mode_t(m) & 0o1777 }
        }
    }
}

/// Minimal FSEvents watcher (file-level events) for the gate's folders.
final class GateFSWatcher {
    private var stream: FSEventStreamRef?
    private let paths: [String]
    private let queue: DispatchQueue
    private let handler: ([String]) -> Void

    init(paths: [String], queue: DispatchQueue, handler: @escaping ([String]) -> Void) {
        self.paths = paths; self.queue = queue; self.handler = handler
    }

    func start() -> Bool {
        guard !paths.isEmpty else { return false }
        var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(), retain: nil, release: nil, copyDescription: nil)
        let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer | kFSEventStreamCreateFlagUseCFTypes)
        guard let s = FSEventStreamCreate(nil, Self.callback, &ctx, paths as CFArray, FSEventStreamEventId(kFSEventStreamEventIdSinceNow), 0.15, flags) else { return false }
        FSEventStreamSetDispatchQueue(s, queue)
        guard FSEventStreamStart(s) else { FSEventStreamInvalidate(s); FSEventStreamRelease(s); return false }
        stream = s
        return true
    }

    func stop() {
        guard let s = stream else { return }
        FSEventStreamStop(s); FSEventStreamInvalidate(s); FSEventStreamRelease(s)
        stream = nil
    }

    private static let callback: FSEventStreamCallback = { _, info, count, pathsPtr, _, _ in
        guard let info else { return }
        let me = Unmanaged<GateFSWatcher>.fromOpaque(info).takeUnretainedValue()
        let arr = unsafeBitCast(pathsPtr, to: NSArray.self)
        var out: [String] = []
        for i in 0..<count { if let p = arr[i] as? String { out.append(p) } }
        me.handler(out)
    }
}
