import Foundation

/// Length-prefixed JSON framing over a Unix domain socket.
public enum IPC {
    public static let socketPath = "/var/run/rampart.sock"
    public static let userSocketPath = NSHomeDirectory() + "/Library/Application Support/Rampart/rampart.sock"

    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let body = try JSONEncoder.rampart.encode(value)
        var len = UInt32(body.count).bigEndian
        return Data(bytes: &len, count: 4) + body
    }

    /// Reads one framed message from a file descriptor. Returns nil on EOF.
    /// Largest frame accepted by default (responses such as long activity lists can be big).
    public static let maxFrameLength = 64 * 1024 * 1024
    /// Suggested cap for requests read by a server: settings with a long exclusion list stay far below this.
    public static let maxRequestLength = 8 * 1024 * 1024

    /// The buffer grows only as bytes actually arrive (in chunks of at most 1 MB), so a peer that announces
    /// a huge length and then sends nothing cannot make the reader allocate it (red-team fix: 40 such
    /// connections used to pin ~2.5 GB in rampartd).
    public static func readFrame(fd: Int32, maxLength: Int = maxFrameLength) -> Data? {
        func readExactly(_ n: Int) -> Data? {
            var out = Data(); out.reserveCapacity(min(n, 64 * 1024))
            var chunk = [UInt8](repeating: 0, count: min(max(n, 1), 1 << 20))
            while out.count < n {
                let want = min(chunk.count, n - out.count)
                let r = chunk.withUnsafeMutableBytes { read(fd, $0.baseAddress!, want) }
                if r < 0 && errno == EINTR { continue }
                if r <= 0 { return nil }
                out.append(contentsOf: chunk[0..<r])
            }
            return out
        }
        guard let head = readExactly(4) else { return nil }
        let len = head.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(as: UInt32.self)) }
        guard Int(len) <= min(maxLength, maxFrameLength) else { return nil }
        return readExactly(Int(len))
    }

    public static func writeFrame(fd: Int32, _ data: Data) -> Bool {
        data.withUnsafeBytes { raw in
            var off = 0
            while off < data.count {
                let w = write(fd, raw.baseAddress! + off, data.count - off)
                if w <= 0 { return false }
                off += w
            }
            return true
        }
    }
}

public extension JSONEncoder {
    static var rampart: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }
}
public extension JSONDecoder {
    static var rampart: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }
}
