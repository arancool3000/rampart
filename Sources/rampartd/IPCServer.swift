import Foundation
import RampartShared

/// Unix-domain socket server speaking RampartShared length-prefixed JSON.
/// Root mode: socket 0666 at IPC.socketPath; privileged requests need an admin peer (getpeereid).
/// User mode: socket 0600 in a 0700 folder; only the same uid may connect.
final class IPCServer {
    let path: String
    let router: Router
    let userMode: Bool
    private var listenFD: Int32 = -1
    private let connSem = DispatchSemaphore(value: 64)
    private let connQ = DispatchQueue(label: "app.rampart.ipc.conn", attributes: .concurrent)

    init(path: String, router: Router, userMode: Bool) { self.path = path; self.router = router; self.userMode = userMode }

    enum Err: Error, CustomStringConvertible {
        case sys(String, Int32), alreadyRunning(String), pathTooLong
        var description: String {
            switch self {
            case .sys(let w, let e): return "\(w): \(String(cString: strerror(e)))"
            case .alreadyRunning(let p): return "another rampartd is already listening on \(p)"
            case .pathTooLong: return "socket path too long"
            }
        }
    }

    private static func makeAddr(_ path: String) throws -> sockaddr_un {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw Err.pathTooLong }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            for (i, b) in bytes.enumerated() { raw[i] = b }
            raw[bytes.count] = 0
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        return addr
    }

    /// True if something accepts connections at `path`.
    static func isLive(_ path: String) -> Bool {
        guard var addr = try? makeAddr(path) else { return false }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0); guard fd >= 0 else { return false }
        defer { close(fd) }
        return withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        } == 0
    }

    func start() throws {
        let dir = (path as NSString).deletingLastPathComponent
        if userMode { Util.ensureDir(URL(fileURLWithPath: dir), mode: 0o700) }
        if FileManager.default.fileExists(atPath: path) {
            if Self.isLive(path) { throw Err.alreadyRunning(path) }
            unlink(path)
        }
        var addr = try Self.makeAddr(path)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        guard listenFD >= 0 else { throw Err.sys("socket", errno) }
        _ = fcntl(listenFD, F_SETFD, FD_CLOEXEC)
        // Create the socket with restrictive perms first, then widen if root mode.
        let oldMask = umask(0o177)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        umask(oldMask)
        guard rc == 0 else { throw Err.sys("bind \(path)", errno) }
        chmod(path, userMode ? 0o600 : 0o666)
        guard listen(listenFD, 32) == 0 else { throw Err.sys("listen", errno) }
        let t = Thread { [weak self] in self?.acceptLoop() }
        t.name = "rampartd.accept"; t.start()
        logInfo("IPC listening on \(path) (\(userMode ? "user" : "root") mode)")
    }

    func stop() {
        if listenFD >= 0 { close(listenFD); listenFD = -1 }
        unlink(path)
    }

    private func acceptLoop() {
        while listenFD >= 0 {
            let cfd = accept(listenFD, nil, nil)
            if cfd < 0 { if errno == EINTR { continue }; if listenFD < 0 { return }; usleep(10000); continue }
            _ = fcntl(cfd, F_SETFD, FD_CLOEXEC)
            var one: Int32 = 1
            setsockopt(cfd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            if connSem.wait(timeout: .now()) == .timedOut { close(cfd); continue }
            connQ.async { [self] in
                defer { connSem.signal() }
                serve(cfd)
            }
        }
    }

    private func peer(of fd: Int32) -> Peer? {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return nil }
        var pid: pid_t = 0; var len = socklen_t(MemoryLayout<pid_t>.size)
        getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len)
        return Peer(uid: uid, gid: gid, pid: pid)
    }

    private func serve(_ fd: Int32) {
        var subscription: UUID?
        defer {
            if let s = subscription { router.p.unsubscribe(s) }
            close(fd)
        }
        guard let peer = peer(of: fd) else { logWarn("IPC: getpeereid failed; dropping connection"); return }
        if userMode && peer.uid != getuid() && peer.uid != 0 {
            logWarn("IPC: rejected uid \(peer.uid) (user-mode daemon belongs to uid \(getuid()))")
            _ = IPC.writeFrame(fd: fd, (try? IPC.encode(IPCResponse.error("not permitted"))) ?? Data())
            return
        }
        // Idle timeout for request reads (subscriptions clear it).
        var tv = timeval(tv_sec: 300, tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        let writeLock = NSLock()
        var alive = true
        let send: (IPCResponse) -> Bool = { r in
            writeLock.lock(); defer { writeLock.unlock() }
            guard alive, let data = try? IPC.encode(r) else { return false }
            if !IPC.writeFrame(fd: fd, data) { alive = false }
            return alive
        }
        while let frame = IPC.readFrame(fd: fd) {
            let req: IPCRequest
            do { req = try JSONDecoder.rampart.decode(IPCRequest.self, from: frame) }
            catch { _ = send(.error("malformed request")); return }
            if DLog.shared.verbose { logInfo("IPC \(Router.name(req)) from uid \(peer.uid) pid \(peer.pid)") }
            switch router.handle(req, peer: peer, requireAdminForPrivileged: !userMode, send: send) {
            case .done: continue
            case .keepOpen(let token):
                subscription = token
                tv = timeval(tv_sec: 0, tv_usec: 0)
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                // Block until the peer hangs up; events are pushed by Protection.broadcast.
                var b: UInt8 = 0
                while read(fd, &b, 1) > 0 {}
                writeLock.lock(); alive = false; writeLock.unlock()
                return
            }
        }
    }
}
