import Foundation
import RampartShared

/// Turns telemetry events that touch a decoy into catches. Nobody legitimate opens these files, so a touch by
/// anything other than the Apple indexers / backup / Finder / Quick Look (or RamPart itself) is high confidence.
public enum DeceptionAccess: String, Codable, Sendable { case read, write, rename, delete, xattr, mazeWalk, copy }

/// How RamPart knows which program touched a decoy.
public enum DeceptionAttribution: String, Codable, Sendable {
    case eventActor     // the telemetry event named the process (eslogger in the system service, or forwarded by it)
    case openFile       // found holding the decoy open right after the touch
    case commandLine    // likely: a program started moments before whose command line named the decoy
    case unknown        // nothing identified (no Full Disk Access / system service): reported honestly as "something"
}

public struct DeceptionCatch: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var date: Date
    public var decoyPath: String
    public var decoyKind: DecoyKind
    public var access: DeceptionAccess
    public var pid: Int32
    public var processPath: String
    public var processName: String          // sanitised for display (attacker controls the binary name)
    public var signingID: String?
    public var teamID: String?
    public var destPath: String?
    public var mazeDeadEnds: Int
    public var contained: Bool
    public var quarantineID: UUID?
    /// The user opened a bait file with a normal app (e.g. TextEdit via Finder). Calm note, no detection.
    public var userOpened: Bool = false
    /// nil on catches recorded before attribution existed (those always had an actor).
    public var attribution: DeceptionAttribution? = nil
    /// Extra fact shown with the catch (e.g. "happened while RamPart wasn't running").
    public var note: String? = nil
    /// True when RamPart couldn't tell which program it was.
    public var isUnattributed: Bool { attribution == .unknown }
    public init(id: UUID = UUID(), date: Date, decoyPath: String, decoyKind: DecoyKind, access: DeceptionAccess, pid: Int32,
                processPath: String, processName: String, signingID: String?, teamID: String?, destPath: String?,
                mazeDeadEnds: Int = 0, contained: Bool = false, quarantineID: UUID? = nil) {
        self.id = id; self.date = date; self.decoyPath = decoyPath; self.decoyKind = decoyKind; self.access = access
        self.pid = pid; self.processPath = processPath; self.processName = processName; self.signingID = signingID
        self.teamID = teamID; self.destPath = destPath; self.mazeDeadEnds = mazeDeadEnds
        self.contained = contained; self.quarantineID = quarantineID
    }
}

public enum DeceptionBenign {
    /// Apple processes allowed to touch decoys (indexing, backup, sync, preview). Matched by signing id AND
    /// platform-binary status, or by exact system path, so a malware binary named "mdworker" is NOT exempt.
    public static let signingIDs: Set<String> = [
        "com.apple.finder", "com.apple.quicklook.ThumbnailsAgent", "com.apple.quicklook.QuickLookUIService",
        "com.apple.qlmanage", "com.apple.mds", "com.apple.mds_stores", "com.apple.mdworker", "com.apple.mdworker_shared",
        "com.apple.mdimport", "com.apple.mdsync", "com.apple.corespotlightd", "com.apple.backupd", "com.apple.backupd-helper",
        "com.apple.TMHelperAgent", "com.apple.fileproviderd", "com.apple.bird", "com.apple.cloudd", "com.apple.revisiond",
        "com.apple.XprotectFramework.AnalysisService", "com.apple.XProtect", "com.apple.fseventsd", "com.apple.lsd",
        "com.apple.DesktopServicesHelper", "com.apple.iconservicesagent",
    ]
    public static let pathPrefixes = [
        "/System/Library/CoreServices/Finder.app/", "/System/Library/Frameworks/CoreServices.framework/",
        "/System/Library/Frameworks/QuickLook.framework/", "/System/Library/Frameworks/QuickLookUI.framework/",
        "/System/Library/CoreServices/backupd.bundle/", "/System/Library/PrivateFrameworks/QuickLookThumbnailing.framework/",
        "/System/Library/Frameworks/QuickLookThumbnailing.framework/", "/System/Library/CoreServices/XProtect.app/",
        "/Library/Apple/System/Library/CoreServices/XProtect.app/",
    ]
    public static let exactPaths: Set<String> = [
        "/usr/libexec/fseventsd", "/usr/sbin/fseventsd", "/usr/libexec/lsd", "/usr/bin/qlmanage", "/usr/bin/mdimport",
        "/System/Library/PrivateFrameworks/CloudDocsDaemon.framework/Versions/A/Support/bird",
        "/System/Library/PrivateFrameworks/FileProvider.framework/Support/fileproviderd",
        "/System/Library/PrivateFrameworks/GenerationalStorage.framework/Versions/A/Support/revisiond",
    ]

    public static func isBenign(_ p: ProcessInfoLite, ownPaths: [String] = []) -> Bool {
        if ownPaths.contains(where: { !$0.isEmpty && (p.path == $0 || p.path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/")) }) { return true }
        if p.isPlatformBinary, let s = p.signingID, signingIDs.contains(s) { return true }
        // System paths are on the sealed system volume: a path match there cannot be forged by user-level malware.
        if exactPaths.contains(p.path) { return true }
        if p.path.hasPrefix("/System/") || p.path.hasPrefix("/Library/Apple/") {
            return pathPrefixes.contains { p.path.hasPrefix($0) }
        }
        return false
    }
}

/// "Did the user just double-click a bait file?" A signed GUI app bundle launched by LaunchServices (parent launchd),
/// reading (or atomically saving) ONE decoy. Scripts, unsigned or temp-folder code, bulk reads of several decoys,
/// renames to other places and deletes all stay strong alerts.
public enum DeceptionUserOpen {
    static let appRoots = ["/Applications/", "/System/Applications/", "/System/Library/CoreServices/", "/System/Volumes/Preboot/Cryptexes/App/System/Applications/"]
    static let interpreters: Set<String> = ["osascript", "python3", "python", "perl", "ruby", "node", "bash", "sh", "zsh", "curl", "Terminal", "iTerm2", "Script Editor"]
    public static func isUserGUIApp(_ p: ProcessInfoLite) -> Bool {
        guard p.ppid == 1, p.path.contains(".app/Contents/MacOS/"), appRoots.contains(where: { p.path.hasPrefix($0) }) else { return false }
        guard p.isPlatformBinary || p.teamID != nil else { return false }
        return !interpreters.contains((p.path as NSString).lastPathComponent)
    }
    public static func isCalm(_ p: ProcessInfoLite, access: DeceptionAccess, destPath: String?, distinctDecoysByPid: Int) -> Bool {
        guard distinctDecoysByPid <= 1, isUserGUIApp(p) else { return false }
        switch access {
        case .read: return true
        case .write: return destPath == nil
        case .rename:   // an editor's atomic save swaps a temp file in the same folder
            guard let d = destPath else { return false }
            let b = (d as NSString).lastPathComponent
            return b.contains(".sb-") || d.contains("/(A Document Being Saved By ") || d.contains("/.TemporaryItems/") || b.hasSuffix("~")
        default: return false
        }
    }
}

/// Stateful detector: per-pid maze progress, dedupe of repeated catches.
public final class DeceptionDetector: @unchecked Sendable {
    public let registry: DecoyRegistry
    public var ownPaths: [String]
    private let lock = NSLock()
    private var deadEnds: [Int32: Set<String>] = [:]
    private var lastCatch: [String: Date] = [:]   // "pid|path|access" -> date
    private var decoysByPid: [Int32: Set<String>] = [:]

    public init(registry: DecoyRegistry, ownPaths: [String] = []) { self.registry = registry; self.ownPaths = ownPaths }

    static func access(for e: SecurityEvent) -> DeceptionAccess? {
        switch e.kind {
        case .fileClose: return e.detail["modified"] == "1" ? .write : .read
        case .fileWrite, .fileCreate: return .write
        case .fileRename: return .rename
        case .fileDelete: return .delete
        case .xattrDelete: return .xattr
        case .other:
            switch e.detail["es_event"] ?? e.detail["op"] {
            case "open", "read", "mmap", "clone", "copyfile", "readdir", "lookup", "stat": return .read
            case "setextattr": return .xattr
            default: return nil
            }
        default: return nil
        }
    }

    /// Returns a catch for a decoy touch, or nil (not a decoy, benign process, or duplicate within 60 s).
    public func evaluate(_ e: SecurityEvent) -> DeceptionCatch? {
        guard let path = e.path, let acc = Self.access(for: e) else { return nil }
        guard let proc = e.process else { return nil }   // without an actor we cannot attribute (e.g. plain FSEvents)
        if DeceptionBenign.isBenign(proc, ownPaths: ownPaths) { return nil }
        let record = registry.record(at: path) ?? (e.destPath.flatMap { registry.record(at: $0) })
        let inMaze = registry.mazeRoots.contains { path == $0 || path.hasPrefix($0 + "/") }
        guard record != nil || inMaze else { return nil }
        var dead = 0
        var effective = acc
        var distinct = 0
        if let r = record, r.kind.isFile {
            lock.lock()
            var set = decoysByPid[proc.pid] ?? []; set.insert(r.path); decoysByPid[proc.pid] = set; distinct = set.count
            if decoysByPid.count > 4096 { decoysByPid.removeAll(); decoysByPid[proc.pid] = set }
            lock.unlock()
        }
        if inMaze {
            lock.lock()
            var set = deadEnds[proc.pid] ?? []
            let dir = record?.kind == .mazeDir ? path : (path as NSString).deletingLastPathComponent
            if set.count < 10_000 { set.insert(dir) }
            deadEnds[proc.pid] = set; dead = set.count
            if deadEnds.count > 4096 { deadEnds.removeAll(); deadEnds[proc.pid] = set }
            lock.unlock()
            if record?.kind != .mazeNote, record?.kind != .passwordsSheet { effective = .mazeWalk }
        }
        let key = "\(proc.pid)|\(path)|\(effective.rawValue)"
        lock.lock()
        let isDup = lastCatch[key].map { e.date.timeIntervalSince($0) < 60 } ?? false
        if !isDup { lastCatch[key] = e.date; if lastCatch.count > 4096 { lastCatch.removeAll() } }
        lock.unlock()
        // Maze walks report on every 5th new dead end so the timeline isn't flooded.
        if isDup || (effective == .mazeWalk && dead % 5 != 1) { return nil }
        let name = SafeText.line((proc.path as NSString).lastPathComponent, max: 60)
        var c = DeceptionCatch(date: e.date, decoyPath: record?.path ?? path, decoyKind: record?.kind ?? .mazeDir,
                               access: effective, pid: proc.pid, processPath: SafeText.path(proc.path), processName: name.isEmpty ? "unknown" : name,
                               signingID: proc.signingID.map { SafeText.line($0, max: 120) }, teamID: proc.teamID,
                               destPath: e.destPath.map { SafeText.path($0) }, mazeDeadEnds: dead)
        c.attribution = .eventActor
        if !inMaze, DeceptionUserOpen.isCalm(proc, access: effective, destPath: e.destPath, distinctDecoysByPid: distinct) { c.userOpened = true }
        return c
    }

    public func deadEndCount(pid: Int32) -> Int { lock.lock(); defer { lock.unlock() }; return deadEnds[pid]?.count ?? 0 }

    /// The serious, normal-pipeline detection. Humour never changes this: name, severity and confidence are plain.
    public static func detection(for c: DeceptionCatch) -> Detection {
        let what: String
        switch c.access {
        case .read: what = "read"
        case .write: what = "modified"
        case .rename: what = "renamed or moved"
        case .delete: what = "deleted"
        case .xattr: what = "changed attributes of"
        case .mazeWalk: what = "walked the decoy folder maze (\(c.mazeDeadEnds) dead ends)"
        case .copy: what = "copied"
        }
        let exfil = c.access == .rename || c.access == .copy || c.destPath != nil
        let conf = c.access == .mazeWalk ? (c.mazeDeadEnds >= 10 ? 90 : 75) : 96
        var ev = [Evidence(source: .behaviour, title: "Decoy file touched",
                           detail: "\(c.processName) (pid \(c.pid)) \(what) a RamPart decoy at \(c.decoyPath). No legitimate app opens these files.", score: conf)]
        if exfil { ev.append(Evidence(source: .behaviour, title: "Decoy copied or moved", detail: "Destination: \(c.destPath ?? "unknown")", score: 80)) }
        if c.signingID == nil { ev.append(Evidence(source: .signing, title: "Unsigned or unidentified process", detail: c.processPath, score: 30)) }
        let combined = 100 - ev.reduce(1.0) { $0 * (1 - Double($1.score) / 100) } * 100
        return Detection(date: c.date, path: c.processPath, pid: c.pid, name: "Decoy accessed: credential theft behaviour",
                         category: .infostealer, severity: conf >= 90 ? .critical : .high, confidence: Int(combined.rounded(.down)), evidence: ev)
    }
}
