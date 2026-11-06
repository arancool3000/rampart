import Foundation
import Darwin
import RampartShared

/// Talks to rampartd over the length-prefixed JSON Unix-socket protocol defined in RampartShared/IPC.swift.
/// Tries the root daemon socket first (`IPC.socketPath`), then the per-user dev socket (`IPC.userSocketPath`).
/// One connection per request; streaming requests (scan, subscribeEvents) keep their connection open.
final class DaemonClient: @unchecked Sendable {
    enum ClientError: LocalizedError {
        case notRunning, closed, daemon(String), unexpected
        var errorDescription: String? {
            switch self {
            case .notRunning: return "The \(Product.name) background service isn't running."
            case .closed: return "The connection to the background service closed."
            case .daemon(let m): return m
            case .unexpected: return "The background service sent an unexpected reply."
            }
        }
    }

    let candidatePaths: [String]
    private(set) var connectedPath: String?
    private let queue = DispatchQueue(label: "app.rampart.ipc", qos: .userInitiated, attributes: .concurrent)

    init(paths: [String]? = nil) {
        if let p = paths { candidatePaths = p }
        else if let i = CommandLine.arguments.firstIndex(of: "--socket"), i + 1 < CommandLine.arguments.count {
            candidatePaths = [CommandLine.arguments[i + 1]]
        } else {
            candidatePaths = [IPC.socketPath, IPC.userSocketPath]
        }
    }

    /// Opens a connected socket to the first path that accepts, or nil.
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
            let rc = withUnsafePointer(to: &addr) {
                $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, len) }
            }
            if rc == 0 { connectedPath = path; return fd }
            close(fd)
        }
        return nil
    }

    /// Quick liveness probe.
    func isReachable() async -> Bool {
        (try? await request(.status, timeout: 2)) != nil
    }

    /// Single request → single response.
    func request(_ req: IPCRequest, timeout: TimeInterval = 10) async throws -> IPCResponse {
        try await withCheckedThrowingContinuation { cont in
            queue.async {
                guard let fd = self.openSocket(timeout: timeout) else { cont.resume(throwing: ClientError.notRunning); return }
                defer { close(fd) }
                do {
                    let frame = try IPC.encode(req)
                    guard IPC.writeFrame(fd: fd, frame) else { throw ClientError.closed }
                    guard let data = IPC.readFrame(fd: fd) else { throw ClientError.closed }
                    let resp = try JSONDecoder.rampart.decode(IPCResponse.self, from: data)
                    if case .error(let m) = resp { throw ClientError.daemon(m) }
                    cont.resume(returning: resp)
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }
    }

    /// Streaming request. `onMessage` runs on the main actor; return false to stop reading.
    /// Returns a cancel handle that closes the socket.
    @discardableResult
    func stream(_ req: IPCRequest, onMessage: @escaping @MainActor (IPCResponse) -> Bool,
                onEnd: @escaping @MainActor (Error?) -> Void) -> StreamHandle {
        let handle = StreamHandle()
        queue.async {
            guard let fd = self.openSocket(timeout: nil) else {
                DispatchQueue.main.async { MainActor.assumeIsolated { onEnd(ClientError.notRunning) } }
                return
            }
            handle.setFD(fd)
            var endError: Error? = nil
            do {
                guard IPC.writeFrame(fd: fd, try IPC.encode(req)) else { throw ClientError.closed }
                while !handle.isCancelled, let data = IPC.readFrame(fd: fd) {
                    let resp = try JSONDecoder.rampart.decode(IPCResponse.self, from: data)
                    if case .error(let m) = resp { throw ClientError.daemon(m) }
                    let keepGoing = DispatchQueue.main.sync { MainActor.assumeIsolated { onMessage(resp) } }
                    if !keepGoing { break }
                }
            } catch { endError = error }
            handle.cancel()
            let err = endError
            DispatchQueue.main.async { MainActor.assumeIsolated { onEnd(err) } }
        }
        return handle
    }

    final class StreamHandle: @unchecked Sendable {
        private let lock = NSLock()
        private var fd: Int32 = -1
        private var cancelled = false
        var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return cancelled }
        func setFD(_ f: Int32) { lock.lock(); fd = f; lock.unlock() }
        func cancel() {
            lock.lock(); defer { lock.unlock() }
            guard !cancelled else { return }
            cancelled = true
            if fd >= 0 { shutdown(fd, SHUT_RDWR); close(fd); fd = -1 }
        }
    }
}
