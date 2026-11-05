import Foundation
import RampartShared

/// The EICAR anti-malware test file. The 68-byte string is never stored contiguously in the binary
/// (it is kept XOR-masked and decoded at runtime) so other scanners do not flag Rampart itself.
public enum EICAR {
    private static let mask: UInt8 = 0x5A
    private static let masked: [[UInt8]] = [
        [0x02, 0x6F, 0x15, 0x7B, 0x0A, 0x7F, 0x1A, 0x1B, 0x0A, 0x01, 0x6E, 0x06],
        [0x0A, 0x00, 0x02, 0x6F, 0x6E, 0x72, 0x0A, 0x04, 0x73, 0x6D, 0x19, 0x19],
        [0x73, 0x6D, 0x27, 0x7E, 0x1F, 0x13, 0x19, 0x1B, 0x08, 0x77, 0x09, 0x0E],
        [0x1B, 0x14, 0x1E, 0x1B, 0x08, 0x1E, 0x77, 0x1B, 0x14, 0x0E, 0x13, 0x0C],
        [0x13, 0x08, 0x0F, 0x09, 0x77, 0x0E, 0x1F, 0x09, 0x0E, 0x77, 0x1C, 0x13],
        [0x16, 0x1F, 0x7B, 0x7E, 0x12, 0x71, 0x12, 0x70],
    ]

    /// The 68 canonical EICAR bytes, assembled at runtime.
    public static var bytes: [UInt8] { masked.flatMap { $0.map { $0 ^ mask } } }

    /// Detection name used for EICAR hits.
    public static let detectionName = "EICAR-Test-File"

    /// Maximum total file length permitted by the EICAR specification.
    public static let maxFileLength = 128

    /// True if `data` is a spec-compliant EICAR file: the 68-byte string at offset 0, optionally followed
    /// only by whitespace (space, tab, LF, CR, Ctrl-Z), and at most 128 bytes in total.
    public static func matches<C: Collection>(_ data: C) -> Bool where C.Element == UInt8 {
        let sig = bytes
        guard data.count >= sig.count, data.count <= maxFileLength else { return false }
        var i = data.startIndex
        for b in sig { if data[i] != b { return false }; i = data.index(after: i) }
        while i != data.endIndex {
            switch data[i] { case 0x20, 0x09, 0x0A, 0x0D, 0x1A: break; default: return false }
            i = data.index(after: i)
        }
        return true
    }

    /// Writes an EICAR test file (used by `rampart eicar`). Overwrites any existing file.
    public static func writeTestFile(to url: URL) throws {
        try Data(bytes).write(to: url, options: .atomic)
    }
}

/// Detects the EICAR test file. Cheap: only opens files whose size is 68...128 bytes.
public struct EICARDetector: FileDetector {
    public init() {}
    public var name: String { "eicar" }

    public func inspect(_ facts: FileFacts) -> [Evidence] {
        guard facts.size >= 68, facts.size <= UInt64(EICAR.maxFileLength) else { return [] }
        let fd = open(facts.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return [] }
        defer { close(fd) }
        var buf = [UInt8](repeating: 0, count: EICAR.maxFileLength + 1)
        let n = buf.withUnsafeMutableBytes { pread(fd, $0.baseAddress, $0.count, 0) }
        guard n > 0, EICAR.matches(buf[0..<n]) else { return [] }
        return [Evidence(source: .heuristic, title: EICAR.detectionName,
                         detail: "File is the EICAR anti-malware test string. It is harmless and used to verify that protection works.",
                         score: 100)]
    }
}
