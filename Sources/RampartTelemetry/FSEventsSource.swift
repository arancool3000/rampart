import Foundation
import CoreServices
import RampartShared

/// File-level FSEvents on configurable trees. No pid (FSEvents doesn't carry one): the behaviour engine
/// attributes by correlation. The last event ID is persisted so a restart replays what happened while
/// the daemon was down (only when the volume UUID is unchanged).
public final class FSEventsSource: EventSource, CPUReporting {
    public struct State: Codable, Equatable {
        public var lastEventID: UInt64
        public var deviceUUID: String?
        public var paths: [String]
    }

    public let name = "fsevents"
    public let cpu = CPUMeter()
    public let paths: [String]
    public let latency: CFTimeInterval
    /// Where the last event ID is stored. nil disables persistence.
    public let stateURL: URL?
    /// Resume from the persisted event ID on start (replays history since then).
    public var resume: Bool
    /// Paths (prefixes) whose events are dropped, e.g. our own database directory.
    public var excludedPrefixes: [String]
    /// Minimum seconds between state writes.
    public var persistInterval: TimeInterval = 5

    private var stream: FSEventStreamRef?
    private let queue = DispatchQueue(label: "app.rampart.telemetry.fsevents")
    private var handler: (@Sendable (SecurityEvent) -> Void)?
    private var lastEventID: FSEventStreamEventId = 0
    private var lastPersist = Date.distantPast
    private var deviceUUID: String?
    private var pendingRenameFrom: (path: String, at: Date)?
    public private(set) var mustScanSubDirs: [String] = []
    public private(set) var eventsSeen = 0
    public private(set) var replaying = false
    private let log = RLog.logger("telemetry.fsevents")

    public static var defaultPaths: [String] {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        var p = ["/Applications", "/Users/Shared", "/private/tmp", "/Library/LaunchAgents", "/Library/LaunchDaemons"]
        if getuid() == 0 {
            p.append("/Users")   // every user's Downloads, LaunchAgents, rc files; filtered downstream
        } else {
            p += [home + "/Downloads", home + "/Applications", home + "/Library/LaunchAgents", home + "/Desktop", home + "/Documents"]
        }
        return p
    }

    public static var defaultStateURL: URL { Paths.effectiveRoot.appendingPathComponent("fsevents-state.json") }

    public init(paths: [String] = FSEventsSource.defaultPaths, latency: CFTimeInterval = 0.5,
                stateURL: URL? = FSEventsSource.defaultStateURL, resume: Bool = true, excludedPrefixes: [String] = []) {
        self.paths = paths.map { FSEventsSource.canonical($0) }
        self.latency = latency
        self.stateURL = stateURL
        self.resume = resume
        self.excludedPrefixes = excludedPrefixes.map { FSEventsSource.canonical($0) }
    }

    /// FSEvents reports real paths (/private/tmp, not /tmp).
    /// Uses realpath(3): NSString.resolvingSymlinksInPath strips /private, which FSEvents keeps.
    static func canonical(_ p: String) -> String {
        guard let r = realpath(p, nil) else { return p }
        defer { free(r) }
        return String(cString: r)
    }

    public var isAvailable: Bool { paths.contains { FileManager.default.fileExists(atPath: $0) } }
    public var isRunning: Bool { queue.sync { stream != nil } }
    public var currentEventID: UInt64 { queue.sync { lastEventID } }

    public func loadState() -> State? {
        guard let url = stateURL, let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(State.self, from: data)
    }

    private func persistLocked(force: Bool) {
        guard let url = stateURL, lastEventID != 0 else { return }
        guard force || Date().timeIntervalSince(lastPersist) >= persistInterval else { return }
        lastPersist = Date()
        let st = State(lastEventID: lastEventID, deviceUUID: deviceUUID, paths: paths)
        do {
            try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
            try JSONEncoder().encode(st).write(to: url, options: .atomic)
        } catch {
            log.error("persist failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    static func rootDeviceUUID(for path: String) -> String? {
        var st = stat()
        guard stat(path, &st) == 0, let u = FSEventsCopyUUIDForDevice(st.st_dev) else { return nil }
        return CFUUIDCreateString(nil, u) as String?
    }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        let watch = paths.filter { FileManager.default.fileExists(atPath: $0) }
        guard !watch.isEmpty else { throw CocoaError(.fileNoSuchFile) }
        stop()
        try queue.sync {
            self.handler = handler
            deviceUUID = Self.rootDeviceUUID(for: watch[0])
            var since = FSEventStreamEventId(kFSEventStreamEventIdSinceNow)
            if resume, let st = loadState(), st.lastEventID != 0, st.deviceUUID == deviceUUID, st.deviceUUID != nil,
               st.lastEventID <= FSEventsGetCurrentEventId() {
                since = st.lastEventID
                replaying = true
            }
            var ctx = FSEventStreamContext(version: 0, info: Unmanaged.passUnretained(self).toOpaque(),
                                           retain: nil, release: nil, copyDescription: nil)
            let flags = FSEventStreamCreateFlags(kFSEventStreamCreateFlagFileEvents | kFSEventStreamCreateFlagNoDefer |
                                                 kFSEventStreamCreateFlagUseCFTypes | kFSEventStreamCreateFlagWatchRoot)
            guard let s = FSEventStreamCreate(nil, Self.callback, &ctx, watch as CFArray, since, latency, flags) else {
                throw CocoaError(.featureUnsupported)
            }
            FSEventStreamSetDispatchQueue(s, queue)
            guard FSEventStreamStart(s) else {
                FSEventStreamInvalidate(s); FSEventStreamRelease(s)
                throw CocoaError(.featureUnsupported)
            }
            stream = s
            if since == FSEventStreamEventId(kFSEventStreamEventIdSinceNow) { lastEventID = FSEventsGetCurrentEventId() }
        }
    }

    public func stop() {
        // Flush outside `queue`: FlushSync delivers pending callbacks on `queue` and waits for them,
        // so calling it from inside queue.sync deadlocks whenever events are pending.
        if let s = queue.sync(execute: { stream }) { FSEventStreamFlushSync(s) }
        queue.sync {
            guard let s = stream else { return }
            FSEventStreamStop(s)
            FSEventStreamInvalidate(s)
            FSEventStreamRelease(s)
            stream = nil
            persistLocked(force: true)
            handler = nil
        }
    }

    deinit { stop() }

    private static let callback: FSEventStreamCallback = { _, info, count, pathsPtr, flagsPtr, idsPtr in
        guard let info else { return }
        let me = Unmanaged<FSEventsSource>.fromOpaque(info).takeUnretainedValue()
        let arr = unsafeBitCast(pathsPtr, to: NSArray.self)
        me.cpu.measure {
            for i in 0..<count {
                guard let path = arr[i] as? String else { continue }
                me.handle(path: path, flags: flagsPtr[i], id: idsPtr[i])
            }
            me.persistLocked(force: false)
        }
    }

    /// Runs on `queue`.
    private func handle(path: String, flags f: FSEventStreamEventFlags, id: FSEventStreamEventId) {
        let flags = Int(f)
        if id > lastEventID { lastEventID = id }
        if flags & kFSEventStreamEventFlagHistoryDone != 0 { replaying = false; return }
        if flags & (kFSEventStreamEventFlagMustScanSubDirs | kFSEventStreamEventFlagUserDropped | kFSEventStreamEventFlagKernelDropped) != 0 {
            mustScanSubDirs.append(path)
            if mustScanSubDirs.count > 100 { mustScanSubDirs.removeFirst(mustScanSubDirs.count - 100) }
            handler?(SecurityEvent(kind: .other, path: path, detail: ["fsevent": "must_scan_subdirs"], source: name))
            return
        }
        if flags & kFSEventStreamEventFlagRootChanged != 0 {
            handler?(SecurityEvent(kind: .other, path: path, detail: ["fsevent": "root_changed"], source: name))
            return
        }
        guard flags & kFSEventStreamEventFlagItemIsDir == 0 || flags & kFSEventStreamEventFlagItemCreated != 0 else { return }
        for ex in excludedPrefixes where path.hasPrefix(ex) { return }
        eventsSeen += 1
        let exists = FileManager.default.fileExists(atPath: path)
        var detail: [String: String] = ["event_id": String(id), "flags": String(flags, radix: 16)]
        if flags & kFSEventStreamEventFlagItemIsDir != 0 { detail["is_dir"] = "1" }
        if flags & kFSEventStreamEventFlagItemIsSymlink != 0 { detail["is_symlink"] = "1" }
        if replaying { detail["replay"] = "1" }
        if !exists { detail["exists"] = "0" }
        // FSEvents coalesces flags, so one callback can mean several things. Pick the most specific
        // current-state kind; add xattr info as detail.
        let kind: SecurityEventKind
        if flags & kFSEventStreamEventFlagItemRemoved != 0 && !exists {
            kind = .fileDelete
        } else if flags & kFSEventStreamEventFlagItemRenamed != 0 {
            kind = .fileRename
            if exists {
                // Rename destination. Pair with a recent rename-from in the same directory for the source.
                detail["renamed"] = "to"
                var source = path
                if let from = pendingRenameFrom, Date().timeIntervalSince(from.at) < 2,
                   (from.path as NSString).deletingLastPathComponent == (path as NSString).deletingLastPathComponent {
                    source = from.path
                    if from.path.contains(".sb-") || flags & kFSEventStreamEventFlagItemCreated != 0 { detail["atomic_save"] = "1" }
                }
                pendingRenameFrom = nil
                handler?(SecurityEvent(kind: kind, path: source, destPath: path, detail: detail, source: name))
                return
            }
            detail["renamed"] = "from"
            pendingRenameFrom = (path, Date())
            // A temp file created and renamed away within one coalesced event is an atomic save: the
            // destination event carries the meaning, so don't emit the temp.
            if flags & kFSEventStreamEventFlagItemCreated != 0 { return }
        } else if flags & kFSEventStreamEventFlagItemCreated != 0 && flags & kFSEventStreamEventFlagItemModified == 0 {
            kind = .fileCreate
        } else if flags & (kFSEventStreamEventFlagItemModified | kFSEventStreamEventFlagItemCreated) != 0 {
            kind = .fileWrite
            if flags & kFSEventStreamEventFlagItemCreated != 0 { detail["created"] = "1" }
        } else if flags & kFSEventStreamEventFlagItemXattrMod != 0 {
            kind = .other; detail["fsevent"] = "xattr_mod"
        } else if flags & (kFSEventStreamEventFlagItemInodeMetaMod | kFSEventStreamEventFlagItemChangeOwner) != 0 {
            kind = .other; detail["fsevent"] = "meta_mod"
        } else {
            return
        }
        if flags & kFSEventStreamEventFlagItemXattrMod != 0 { detail["xattr_mod"] = "1" }
        handler?(SecurityEvent(kind: kind, path: path, detail: detail, source: name))
    }
}
