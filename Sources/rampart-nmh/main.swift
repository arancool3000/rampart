import Foundation
import RampartShared
import RampartWeb

// rampart-nmh: native messaging host for the RamPart browser extension (Chrome, Brave, Edge, Arc,
// Chromium). Speaks Chrome's stdio protocol: 32-bit native-endian length + UTF-8 JSON, one object
// per message. Answers verdicts locally with RampartWeb and consults rampartd over IPC when it runs.
//
// Usage:  rampart-nmh                       (launched by the browser; reads stdin until EOF)
//         rampart-nmh --check <url|text>    (prints a JSON report; for scripts and tests)
//         rampart-nmh --version

let args = CommandLine.arguments.dropFirst()
if args.first == "--version" { print(Product.version); exit(0) }

setvbuf(stdout, nil, _IOFBF, 1 << 16)
let service = WebVerdictService(bridge: RampartdBridge())

if args.first == "--check", let input = args.dropFirst().first {
    let report = service.checker.check(input)
    let e = JSONEncoder(); e.outputFormatting = [.prettyPrinted, .sortedKeys]
    FileHandle.standardOutput.write(try! e.encode(report)); print()
    exit(0)
}

func send(_ resp: NMResponse) {
    guard let data = try? NativeMessaging.encode(resp) else { return }
    _ = IPC.writeFrame(fd: STDOUT_FILENO, data)
}

let decoder = JSONDecoder()
// wms-o3: 4 MiB cap (not Chrome's 64 MiB); every request is cleaned by NMRequestSanitizer inside handle().
while let frame = NativeMessaging.readFrame(fd: STDIN_FILENO, maxBytes: NativeMessaging.hostMaxInbound) {
    guard let req = try? decoder.decode(NMRequest.self, from: frame) else {
        var id: String? = nil
        if let any = try? JSONSerialization.jsonObject(with: frame) as? [String: Any] { id = any["id"] as? String ?? (any["id"] as? Int).map(String.init) }
        send(NMResponse(id: NMRequestSanitizer.safeID(id), ok: false, error: "bad request")); continue
    }
    send(service.handle(req))
}
exit(0)

/// Bridge to rampartd using the v4 IPC cases: `.webLookup(host:)` for the daemon's DNS blocklists and
/// `.webVerdict(...)` so warnings appear in Protection Activity. Short timeouts; nil when the daemon is down.
final class RampartdBridge: DaemonBridge, @unchecked Sendable {
    private let lock = NSLock()
    private var lastProbe = Date.distantPast
    private var available = false

    var isAvailable: Bool {
        lock.lock(); defer { lock.unlock() }
        if Date().timeIntervalSince(lastProbe) < 30 { return available }
        lastProbe = Date()
        if case .status? = roundTrip(.status) { available = true } else { available = false }
        return available
    }

    func lookup(host: String) -> BlocklistHit? {
        guard isAvailable, case .webLookup(let data)? = roundTrip(.webLookup(host: host)), let data else { return nil }
        return try? JSONDecoder.rampart.decode(BlocklistHit.self, from: data)
    }

    func report(url: String, verdict: ScamVerdict, score: Int, headline: String) {
        guard isAvailable else { return }
        _ = roundTrip(.webVerdict(url: url, verdict: verdict.rawValue, score: score, headline: headline))
    }

    private func roundTrip(_ req: IPCRequest, timeoutMs: Int32 = 800) -> IPCResponse? {
        let path = FileManager.default.fileExists(atPath: IPC.socketPath) ? IPC.socketPath : IPC.userSocketPath
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Int(timeoutMs / 1000), tv_usec: Int32(timeoutMs % 1000) * 1000)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        guard bytes.count < MemoryLayout.size(ofValue: addr.sun_path) else { return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in for (i, b) in bytes.enumerated() { raw[i] = b }; raw[bytes.count] = 0 }
        let rc = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard rc == 0 else { return nil }
        // wms-fa: same socket-file and peer policy as the app and CLI (RampartShared.DaemonPeerPolicy). Without it a
        // same-user process squatting the user socket could answer every blocklist lookup with "not listed" and
        // swallow every warning the extension reports, while the extension believed RamPart was answering.
        guard DaemonPeerPolicy.connectedPeerProblem(fd: fd, path: path) == nil else { return nil }
        guard let data = try? IPC.encode(req), IPC.writeFrame(fd: fd, data), let resp = IPC.readFrame(fd: fd) else { return nil }
        return try? JSONDecoder.rampart.decode(IPCResponse.self, from: resp)
    }
}
