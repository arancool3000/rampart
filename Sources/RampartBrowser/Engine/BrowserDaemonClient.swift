import Foundation
import Darwin
import RampartShared

/// Minimal client for rampartd over the RampartShared IPC framing. The browser uses it for two
/// things only: scanning quarantined downloads (`.scan`) and a liveness probe. Root socket first,
/// then the per-user dev socket.
final class BrowserDaemonClient: @unchecked Sendable {
    static let shared = BrowserDaemonClient()
    enum ClientError: LocalizedError {
        case notRunning, closed, daemon(String)
        var errorDescription: String? {
            switch self {
            case .notRunning: return "The \(Product.name) background service isn't running."
            case .closed: return "The connection to the background service closed."
            case .daemon(let m): return m
            }
        }
    }
    let candidatePaths: [String]
    private let queue = DispatchQueue(label: "app.rampart.browser.ipc", qos: .userInitiated, attributes: .concurrent)

    init(paths: [String]? = nil) {
        if let p = paths { candidatePaths = p }
        else if let i = CommandLine.arguments.firstIndex(of: "--socket"), i + 1 < CommandLine.arguments.count { candidatePaths = [CommandLine.arguments[i + 1]] }
        else { candidatePaths = [IPC.socketPath, IPC.userSocketPath] }
    }

    private func openSocket(timeout: TimeInterval?) -> Int32? {
        for path in candidatePaths where FileManager.default.fileExists(atPath: path) {
            let fd = socket(AF_UNIX, SOCK_STREAM, 0)
            if fd < 0 { continue }
            var one: Int32 = 1
            setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            if let timeout {
                var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - floor(timeout)) * 1_000_000))
                setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
                setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            }
            var addr = sockaddr_un()
            addr.sun_family = sa_family_t(AF_UNIX)
            let bytes = Array(path.utf8)
            let cap = MemoryLayout.size(ofValue: addr.sun_path) - 1
            guard bytes.count <= cap else { close(fd); continue }
            withUnsafeMutableBytes(of: &addr.sun_path) { raw in
                for (i, b) in bytes.enumerated() { raw[i] = b }
                raw[bytes.count] = 0
            }
            let len = socklen_t(MemoryLayout<sockaddr_un>.size)
            let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) } }
            if rc == 0 { return fd }
            close(fd)
        }
        return nil
    }

    func isReachable() async -> Bool { (try? await request(.status, timeout: 2)) != nil }

    func request(_ req: IPCRequest, timeout: TimeInterval = 10) async throws -> IPCResponse {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                guard let fd = self.openSocket(timeout: timeout) else { cont.resume(throwing: ClientError.notRunning); return }
                defer { close(fd) }
                do {
                    guard IPC.writeFrame(fd: fd, try IPC.encode(req)) else { throw ClientError.closed }
                    guard let data = IPC.readFrame(fd: fd) else { throw ClientError.closed }
                    let resp = try JSONDecoder.rampart.decode(IPCResponse.self, from: data)
                    if case .error(let m) = resp { throw ClientError.daemon(m) }
                    cont.resume(returning: resp)
                } catch { cont.resume(throwing: error) }
            }
        }
    }

    /// Scans one file through the daemon. Reads the streamed progress frames until `scanFinished`.
    func scan(path: String, timeout: TimeInterval = 120) async throws -> [Detection] {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                guard let fd = self.openSocket(timeout: timeout) else { cont.resume(throwing: ClientError.notRunning); return }
                defer { close(fd) }
                do {
                    guard IPC.writeFrame(fd: fd, try IPC.encode(IPCRequest.scan(paths: [path], quick: false))) else { throw ClientError.closed }
                    while let data = IPC.readFrame(fd: fd) {
                        let resp = try JSONDecoder.rampart.decode(IPCResponse.self, from: data)
                        switch resp {
                        case .error(let m): throw ClientError.daemon(m)
                        case .scanFinished(_, let dets, _): cont.resume(returning: dets); return
                        default: continue
                        }
                    }
                    throw ClientError.closed
                } catch { cont.resume(throwing: error) }
            }
        }
    }
}
