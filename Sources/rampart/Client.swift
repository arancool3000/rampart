import Foundation
import RampartShared

/// Talks to rampartd over its Unix socket, or runs requests in-process (--local).
protocol Transport {
    /// Sends a request and delivers responses until a terminal one (or until `onMessage` returns false).
    func request(_ r: IPCRequest, onMessage: @escaping (IPCResponse) -> Bool) throws
}

enum ClientError: LocalizedError {
    case noDaemon, connect(String, String), io
    var errorDescription: String? {
        switch self {
        case .noDaemon: return "rampartd is not running (no socket at \(IPC.socketPath) or \(IPC.userSocketPath)). Start it, or use --local."
        case .connect(let p, let e): return "cannot connect to \(p): \(e)"
        case .io: return "connection to rampartd lost"
        }
    }
}

extension IPCResponse {
    var isTerminal: Bool {
        switch self { case .scanProgress, .event: return false; default: return true }
    }
}

final class SocketTransport: Transport {
    let path: String
    init(path: String) { self.path = path }

    static func trustedPeer(uid: uid_t, me: uid_t = getuid()) -> Bool { uid == 0 || uid == me }

    static func resolve(explicit: String?, user: Bool) throws -> SocketTransport {
        if let e = explicit { return SocketTransport(path: e) }
        if user { return SocketTransport(path: IPC.userSocketPath) }
        for p in [IPC.socketPath, IPC.userSocketPath] where FileManager.default.fileExists(atPath: p) {
            return SocketTransport(path: p)
        }
        throw ClientError.noDaemon
    }

    func connectFD() throws -> Int32 {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { throw ClientError.connect(path, "path too long") }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw ClientError.connect(path, String(cString: strerror(errno))) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if rc != 0 { let e = String(cString: strerror(errno)); close(fd); throw ClientError.connect(path, e) }
        // Only trust a daemon run by root or by us: another local user can't pose as rampartd (fake "clean"
        // verdicts, attacker text shown as RamPart's voice) by squatting a socket path.
        var peerUID: uid_t = 0, peerGID: gid_t = 0
        guard getpeereid(fd, &peerUID, &peerGID) == 0, SocketTransport.trustedPeer(uid: peerUID) else {
            close(fd); throw ClientError.connect(path, "the process on this socket isn't rampartd (owned by another user)")
        }
        // hx8: same socket-file and peer-signature policy as the app (RampartShared.DaemonPeerPolicy).
        if let why = DaemonPeerPolicy.connectedPeerProblem(fd: fd, path: path) {
            close(fd); throw ClientError.connect(path, "the process on this socket isn't rampartd (\(why))")
        }
        return fd
    }

    func request(_ r: IPCRequest, onMessage: @escaping (IPCResponse) -> Bool) throws {
        let fd = try connectFD()
        defer { close(fd) }
        guard IPC.writeFrame(fd: fd, try IPC.encode(r)) else { throw ClientError.io }
        let streaming: Bool = { if case .subscribeEvents = r { return true }; return false }()
        var sawOK = false
        while let frame = IPC.readFrame(fd: fd) {
            let resp = try JSONDecoder.rampart.decode(IPCResponse.self, from: frame)
            if streaming, case .ok = resp, !sawOK { sawOK = true; if !onMessage(resp) { return }; continue }
            if !onMessage(resp) { return }
            if resp.isTerminal && !streaming { return }
            if streaming, case .error = resp { return }
        }
        throw ClientError.io
    }
}

/// In-process execution: same Router/Protection the daemon uses, with per-user (or --root) state.
final class LocalTransport: Transport {
    let protection: Protection
    let router: Router
    init(root: URL?, remediate: Bool) {
        let rt = Runtime(root: root, userMode: getuid() != 0)
        let services = Services.make(runtime: rt, daemon: false)
        protection = Protection(runtime: rt, services: services)
        protection.remediate = remediate
        router = Router(protection)
    }
    func request(_ r: IPCRequest, onMessage: @escaping (IPCResponse) -> Bool) throws {
        if case .subscribeEvents = r { _ = onMessage(.error("events need the daemon")); return }
        var stop = false
        router.handle(r, peer: .local, requireAdminForPrivileged: false) { resp in
            if stop { return false }
            if !onMessage(resp) { stop = true }
            return !stop
        }
    }
}
