import Foundation
import Darwin
import RampartShared
import RampartGuard

/// System service (root) side of Cat & Mouse. Decoys live in each user's home and are watched by that user's
/// session daemon, which can't see *who* read a file. The root daemon has eslogger: every open/close/rename/
/// delete of a decoy path is forwarded (IPC `forwardEvents`) to the owning user's session daemon, whose
/// DeceptionService turns it into an attributed catch and merges it with its own actor-less touch.
///
/// Safety: a user controls their decoys.json, so only paths inside that user's home that the user owns are
/// accepted (a user can't make root forward events about other people's or system files). The target socket must
/// be a real socket owned by that user, and the peer must run as that user.
final class DecoyForwarder: @unchecked Sendable {
    struct Target { var uid: uid_t; var home: String }
    private let queue = DispatchQueue(label: "app.rampart.decoy-forwarder", qos: .utility)
    private let lock = NSLock()
    private var exact: [String: Target] = [:]
    private var mazeRoots: [(String, Target)] = []
    private var pending: [uid_t: (Target, [SecurityEvent])] = [:]
    private var flushScheduled = false
    private var timer: DispatchSourceTimer?
    private(set) var forwarded = 0
    let usersRoot: String

    init(usersRoot: String = "/Users") { self.usersRoot = usersRoot }

    /// True when the RamPart system service socket exists (root-owned): the session daemon then expects forwarded,
    /// attributed decoy events.
    static var systemServicePresent: Bool {
        var st = stat()
        return lstat(IPC.socketPath, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK && st.st_uid == 0
    }

    func start() {
        refresh()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 30, repeating: 30)
        t.setEventHandler { [weak self] in self?.refresh() }
        t.resume(); timer = t
    }

    static func registryPath(home: String) -> String { home + "/Library/Application Support/Rampart/deception/decoys.json" }
    static func socketPath(home: String) -> String { home + "/Library/Application Support/Rampart/rampart.sock" }

    /// Re-reads every user's decoy registry.
    func refresh() {
        var ex: [String: Target] = [:]
        var roots: [(String, Target)] = []
        let homes = (try? FileManager.default.contentsOfDirectory(atPath: usersRoot)) ?? []
        for name in homes where !name.hasPrefix(".") && name != "Shared" {
            let home = usersRoot + "/" + name
            var hst = stat()
            guard lstat(home, &hst) == 0, (hst.st_mode & S_IFMT) == S_IFDIR, hst.st_uid >= 500 else { continue }
            let t = Target(uid: hst.st_uid, home: home)
            for r in Self.loadRecords(Self.registryPath(home: home), uid: hst.st_uid) where Self.acceptable(r.path, home: home, uid: hst.st_uid) {
                if r.kind == .mazeDir && r.contentSHA256 == "maze-root" { roots.append((r.path, t)) }
                if r.kind != .mazeLink { ex[r.path] = t }
            }
        }
        lock.lock(); exact = ex; mazeRoots = roots; lock.unlock()
    }

    static func loadRecords(_ path: String, uid: uid_t) -> [DecoyRecord] {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_uid == uid, st.st_size < 4 << 20,
              let d = FileManager.default.contents(atPath: path) else { return [] }
        let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
        return (try? dec.decode([DecoyRecord].self, from: d)) ?? []
    }

    /// Inside that home (no `..`), and the thing at the path is owned by that user (or is gone).
    static func acceptable(_ path: String, home: String, uid: uid_t) -> Bool {
        guard path.hasPrefix(home + "/"), !path.contains("/../"), !path.hasSuffix("/.."), !path.contains("\0") else { return false }
        var st = stat()
        if lstat(path, &st) == 0 { return st.st_uid == uid }
        return true
    }

    func target(for path: String) -> Target? {
        lock.lock(); defer { lock.unlock() }
        if let t = exact[path] { return t }
        return mazeRoots.first { path.hasPrefix($0.0 + "/") }?.1
    }

    /// Called for every pipeline event in the system service. Cheap when the event isn't about a decoy.
    func consider(_ e: SecurityEvent) {
        guard e.source == "eslogger", let proc = e.process, proc.pid != getpid() else { return }
        switch e.kind {
        case .fileClose, .fileRename, .fileDelete, .fileWrite, .xattrDelete: break
        case .other: guard ["open", "setextattr", "readdir"].contains(e.detail["es_event"] ?? "") else { return }
        default: return
        }
        guard let t = e.path.flatMap(target(for:)) ?? e.destPath.flatMap(target(for:)) else { return }
        lock.lock()
        var entry = pending[t.uid] ?? (t, [])
        if entry.1.count < 400 { entry.1.append(e) }
        pending[t.uid] = entry
        let schedule = !flushScheduled; flushScheduled = true
        lock.unlock()
        if schedule { queue.asyncAfter(deadline: .now() + 0.3) { [weak self] in self?.flush() } }
    }

    private func flush() {
        lock.lock(); let batches = pending; pending = [:]; flushScheduled = false; lock.unlock()
        for (_, (t, events)) in batches where !events.isEmpty {
            if Self.send(events, to: Self.socketPath(home: t.home), uid: t.uid) { lock.lock(); forwarded += events.count; lock.unlock() }
            else { logWarn("Cat & Mouse: couldn't forward \(events.count) decoy event(s) to uid \(t.uid)'s session service") }
        }
    }

    /// One `forwardEvents` request to a session daemon socket owned by `uid`. 2 s ceiling.
    static func send(_ events: [SecurityEvent], to path: String, uid: uid_t) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFSOCK, st.st_uid == uid else { return false }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var tv = timeval(tv_sec: 2, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return false }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard rc == 0 else { return false }
        var puid: uid_t = 0, pgid: gid_t = 0
        guard getpeereid(fd, &puid, &pgid) == 0, puid == uid else { return false }
        guard let frame = try? IPC.encode(IPCRequest.forwardEvents(events)), IPC.writeFrame(fd: fd, frame) else { return false }
        guard let reply = IPC.readFrame(fd: fd, maxLength: 1 << 20),
              let resp = try? JSONDecoder.rampart.decode(IPCResponse.self, from: reply), case .ok = resp else { return false }
        return true
    }
}
