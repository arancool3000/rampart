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
    public static func readFrame(fd: Int32) -> Data? {
        func readExactly(_ n: Int) -> Data? {
            var buf = [UInt8](repeating: 0, count: n); var got = 0
            while got < n {
                let r = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress! + got, n - got) }
                if r <= 0 { return nil }
                got += r
            }
            return Data(buf)
        }
        guard let head = readExactly(4) else { return nil }
        let len = head.withUnsafeBytes { $0.load(as: UInt32.self).bigEndian }
        guard len < 64 * 1024 * 1024 else { return nil }
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
