import Foundation
import Darwin
import Security
import RampartShared

/// Talks to rampartd over the length-prefixed JSON Unix-socket protocol defined in RampartShared/IPC.swift.
/// Tries the root daemon socket first (`IPC.socketPath`), then the per-user dev socket (`IPC.userSocketPath`).
/// One connection per request; streaming requests (scan, subscribeEvents) keep their connection open.
final class DaemonClient: @unchecked Sendable {
    enum ClientError: LocalizedError {
        case notRunning, closed, daemon(String), unexpected, untrusted, outdated
        var errorDescription: String? {
            switch self {
            case .notRunning: return "The \(Product.name) background service isn't running."
            case .untrusted: return "Something that isn't \(Product.name)'s background service answered on its connection, so \(Product.name) ignored it. Reinstalling \(Product.name) fixes this."
            case .closed: return "The connection to the background service closed."
            case .daemon(let m): return m
            case .outdated: return DaemonClient.outdatedMessage
            case .unexpected: return "The background service sent an unexpected reply."
            }
        }
    }

    static let outdatedMessage = "\(Product.name)'s background service is older than the app. Update it (one password)."
    /// Set when the daemon answered with something this app can't read, or reported an older IPC version.
    nonisolated(unsafe) static var daemonOutdated = false

    /// Decodes a reply. Never surfaces raw DecodingError text: an unreadable reply means an older daemon.
    static func decode(_ data: Data) throws -> IPCResponse {
        do {
            let r = try JSONDecoder.rampart.decode(IPCResponse.self, from: data)
            if case .status(let s) = r { daemonOutdated = (s.ipcVersion ?? 0) < IPC.version }
            if case .error(let m) = r, isDecodeFailureText(m) { daemonOutdated = true; throw ClientError.outdated }
            return r
        } catch is DecodingError {
            daemonOutdated = true
            throw ClientError.outdated
        }
    }

    /// An older daemon that can't read a newer request answers with Foundation's decoding message.
    static func isDecodeFailureText(_ m: String) -> Bool {
        let l = m.lowercased()
        return l.contains("malformed request") || l.contains("couldn’t be read") || l.contains("couldn't be read") || l.contains("is missing") || l.contains("isn’t in the correct format") || l.contains("isn't in the correct format")
    }

    let candidatePaths: [String]
    private(set) var connectedPath: String?
    private let queue = DispatchQueue(label: "app.rampart.ipc", qos: .userInitiated, attributes: .concurrent)

    init(paths: [String]? = nil) {
        if let p = paths { candidatePaths = p }
        else if DaemonPeerTrust.devOverridesAllowed, let i = CommandLine.arguments.firstIndex(of: "--socket"), i + 1 < CommandLine.arguments.count {
            candidatePaths = [CommandLine.arguments[i + 1]]
        } else {
            candidatePaths = [IPC.socketPath, IPC.userSocketPath]
        }
    }

    /// Set when a socket answered but failed the peer check (fake daemon). Surfaced as `.untrusted`.
    private(set) var lastRejection: String?

    /// Opens a connected socket to the first path that accepts AND whose peer is the genuine daemon, or nil.
    /// hx8: nothing (pasted text, URLs, settings, authorization data) is written before the peer is verified.
    private func openSocket(timeout: TimeInterval?) -> Int32? {
        for path in candidatePaths where FileManager.default.fileExists(atPath: path) {
            if let why = DaemonPeerTrust.socketFileProblem(path: path) { lastRejection = why; continue }
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
            if rc == 0 {
                if let why = DaemonPeerTrust.peerProblem(fd: fd, path: path) {
                    lastRejection = why
                    NSLog("RamPart: refused daemon socket %@: %@", path, why)
                    close(fd); continue
                }
                connectedPath = path; lastRejection = nil; return fd
            }
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
                guard let fd = self.openSocket(timeout: timeout) else { cont.resume(throwing: self.lastRejection != nil ? ClientError.untrusted : ClientError.notRunning); return }
                defer { close(fd) }
                do {
                    let frame = try IPC.encode(req)
                    guard IPC.writeFrame(fd: fd, frame) else { throw ClientError.closed }
                    guard let data = IPC.readFrame(fd: fd) else { throw ClientError.closed }
                    let resp = try DaemonClient.decode(data)
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
                let err: ClientError = self.lastRejection != nil ? .untrusted : .notRunning
                DispatchQueue.main.async { MainActor.assumeIsolated { onEnd(err) } }
                return
            }
            handle.setFD(fd)
            var endError: Error? = nil
            do {
                guard IPC.writeFrame(fd: fd, try IPC.encode(req)) else { throw ClientError.closed }
                while !handle.isCancelled, let data = IPC.readFrame(fd: fd) {
                    let resp = try DaemonClient.decode(data)
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

// MARK: - hx8: daemon peer verification

/// Decides whether a daemon socket and the process behind it are really RamPart's daemon.
///
/// - Root socket (`/var/run/rampart.sock`): the socket file must be a real socket (not a symlink) owned by root,
///   and the peer (getpeereid) must be uid 0. A user-level attacker can't satisfy either.
/// - User socket (`~/Library/Application Support/Rampart/rampart.sock`): owned by us, in a folder only we can
///   write, and the peer process (LOCAL_PEERPID → SecCode) must satisfy the bundled helper's designated
///   requirement, after this app's own signature (which seals Contents/Helpers) has been verified.
/// - Any other uid is refused.
///
/// Honest limit: with ad-hoc signing there is no Apple-issued identity. Malware running as you that can
/// rewrite the whole app bundle and re-sign it can still impersonate it; macOS App Management protection is
/// what stops that, not this check.
enum DaemonPeerTrust {
    /// `--socket`, `--helper` and `--daemon-root` are QA flags. A copy installed in /Applications ignores them,
    /// so other software can't relaunch the real app pointed at a fake daemon.
    static var devOverridesAllowed: Bool {
        if CommandLine.arguments.contains("--headless-check") { return true }
        return !Bundle.main.bundlePath.hasPrefix("/Applications/")
    }

    // Pure policies live in RampartShared.DaemonPeerPolicy (shared with the CLI and the secure browser).
    static func socketFileProblem(path: String) -> String? { DaemonPeerPolicy.socketFileProblem(path: path) }
    static func peerProblem(peerUID: uid_t, myUID: uid_t, rootSocket: Bool, signatureOK: () -> Bool) -> String? {
        DaemonPeerPolicy.peerProblem(peerUID: peerUID, myUID: myUID, rootSocket: rootSocket, signatureOK: signatureOK)
    }

    static func peerProblem(fd: Int32, path: String) -> String? {
        var uid: uid_t = 0, gid: gid_t = 0
        guard getpeereid(fd, &uid, &gid) == 0 else { return "can't read peer credentials" }
        return peerProblem(peerUID: uid, myUID: getuid(), rootSocket: path == IPC.socketPath) {
            var pid: pid_t = 0
            var len = socklen_t(MemoryLayout<pid_t>.size)
            guard getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &len) == 0, pid > 0 else { return false }
            return processSatisfiesHelperRequirement(pid: pid)
        }
    }

    static func processSatisfiesHelperRequirement(pid: pid_t) -> Bool {
        guard let req = helperRequirement else { return unsignedDevBuild }
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: pid] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let code else { return false }
        return SecCodeCheckValidity(code, [], req) == errSecSuccess
    }

    /// A bare `swift run` build has no app bundle to anchor trust to; it accepts a same-user peer.
    /// Every packaged copy is an .app with a bundle identifier, so this never applies to a real install.
    static let unsignedDevBuild: Bool = Bundle.main.bundleIdentifier == nil && !Bundle.main.bundlePath.hasSuffix(".app")

    /// The designated requirement of the helper this app trusts, or nil when it can't be established.
    /// Order: QA `--helper` override (dev copies only); else the bundled helper, but only after the app's own
    /// signature, including nested code in Contents/Helpers, verifies.
    static let helperRequirement: SecRequirement? = {
        if devOverridesAllowed, let i = CommandLine.arguments.firstIndex(of: "--helper"), i + 1 < CommandLine.arguments.count {
            return designatedRequirement(ofFile: CommandLine.arguments[i + 1])
        }
        let bundle = Bundle.main.bundleURL
        let helper = bundle.appendingPathComponent("Contents/Helpers/rampartd").path
        guard FileManager.default.fileExists(atPath: helper) else { return nil }
        var app: SecStaticCode?
        guard SecStaticCodeCreateWithPath(bundle as CFURL, [], &app) == errSecSuccess, let app else { return nil }
        let flags = SecCSFlags(rawValue: kSecCSCheckNestedCode | kSecCSStrictValidate)
        guard SecStaticCodeCheckValidity(app, flags, nil) == errSecSuccess else { return nil }
        return designatedRequirement(ofFile: helper)
    }()

    static func designatedRequirement(ofFile path: String) -> SecRequirement? {
        var lst = stat()
        guard lstat(path, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFREG else { return nil }   // no symlinks
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, [], nil) == errSecSuccess else { return nil }
        var req: SecRequirement?
        guard SecCodeCopyDesignatedRequirement(code, [], &req) == errSecSuccess else { return nil }
        return req
    }

    /// Static check used before launching a helper binary.
    static func fileSatisfiesHelperRequirement(_ path: String) -> Bool {
        guard let req = helperRequirement else { return unsignedDevBuild }
        var lst = stat()
        guard lstat(path, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFREG else { return false }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return false }
        return SecStaticCodeCheckValidity(code, [], req) == errSecSuccess
    }
}
