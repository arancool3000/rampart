import Foundation
import Darwin

/// Accumulates the CPU time a source spends in its own work, measured with the per-thread CPU clock
/// around each unit of work. Thread-safe.
public final class CPUMeter: @unchecked Sendable {
    private let lock = NSLock()
    private var nanos: UInt64 = 0
    private var units: UInt64 = 0
    public init() {}

    @inline(__always) static func threadNanos() -> UInt64 { clock_gettime_nsec_np(CLOCK_THREAD_CPUTIME_ID) }

    /// Runs `body` and adds the calling thread's CPU time it used.
    @discardableResult
    public func measure<T>(_ body: () throws -> T) rethrows -> T {
        let t0 = Self.threadNanos()
        defer { let dt = Self.threadNanos() &- t0; lock.lock(); nanos &+= dt; units &+= 1; lock.unlock() }
        return try body()
    }

    /// Total CPU seconds spent so far.
    public var cpuSeconds: Double { lock.lock(); defer { lock.unlock() }; return Double(nanos) / 1e9 }
    public var workUnits: UInt64 { lock.lock(); defer { lock.unlock() }; return units }
    public func reset() { lock.lock(); nanos = 0; units = 0; lock.unlock() }
}

/// Sources that report their own CPU use.
public protocol CPUReporting: AnyObject {
    var cpu: CPUMeter { get }
}

/// Neutralises hostile strings pulled from untrusted telemetry (argv, eslogger JSON fields, paths,
/// profile/xattr names) before they land in a `SecurityEvent.detail` that later reaches logs or UI.
/// Strips control characters and Unicode bidi/zero-width overrides (log injection and UI spoofing —
/// "attacker text shown as RamPart's voice"), escapes NULs, and hard-caps length. The verbatim path is
/// kept separately for file operations; this only guards what gets displayed or logged.
public enum TelemetrySanitize {
    /// Max length of any single sanitized detail value.
    public static let maxLen = 4096
    /// Bidi/override and zero-width scalars that let attacker text masquerade or hide.
    private static let dangerous: Set<Unicode.Scalar> = [
        "\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}",
        "\u{202A}", "\u{202B}", "\u{202C}", "\u{202D}", "\u{202E}",
        "\u{2066}", "\u{2067}", "\u{2068}", "\u{2069}",
    ]

    public static func clean(_ s: String, limit: Int = maxLen) -> String {
        var out = String.UnicodeScalarView()
        out.reserveCapacity(min(s.unicodeScalars.count, limit))
        var n = 0
        for u in s.unicodeScalars {
            if n >= limit { out.append(contentsOf: "…".unicodeScalars); break }
            if u == "\u{0}" { out.append(contentsOf: "\\0".unicodeScalars); n += 2; continue }
            // C0/C1 control chars (incl. newline, tab, CR, ESC) and DEL become visible escapes.
            if u.value < 0x20 || u.value == 0x7F || (u.value >= 0x80 && u.value <= 0x9F) {
                let esc = String(format: "\\x%02x", u.value)
                out.append(contentsOf: esc.unicodeScalars); n += esc.count; continue
            }
            if dangerous.contains(u) { out.append("."); n += 1; continue }
            out.append(u); n += 1
        }
        return String(out)
    }

    /// Sanitize every value of a detail dictionary in place.
    public static func clean(detail: inout [String: String], limit: Int = maxLen) {
        for (k, v) in detail { detail[k] = clean(v, limit: limit) }
    }
}

extension ProcInspector {
    private typealias ResponsibleFn = @convention(c) (pid_t) -> pid_t
    private static let responsibleFn: ResponsibleFn? = {
        guard let h = dlopen(nil, RTLD_NOW), let sym = dlsym(h, "responsibility_get_pid_responsible_for_pid") else { return nil }
        return unsafeBitCast(sym, to: ResponsibleFn.self)
    }()

    /// The "responsible" pid (the app on whose behalf a helper or child runs), via private SPI resolved
    /// with dlsym. nil if unavailable or the same as `pid`.
    public static func responsiblePid(_ pid: Int32) -> Int32? {
        guard let fn = responsibleFn else { return nil }
        let r = fn(pid)
        return r > 0 && r != pid ? r : nil
    }

    /// Child pids of `pid` (libproc; own processes unprivileged, all as root).
    public static func childPids(_ pid: Int32) -> [Int32] {
        var buf = [pid_t](repeating: 0, count: 256)
        let n = buf.withUnsafeMutableBytes { proc_listchildpids(pid, $0.baseAddress, Int32($0.count)) }
        guard n > 0 else { return [] }
        // Returns a count of pids (not bytes) on current macOS; clamp defensively.
        return Array(buf.prefix(min(Int(n), buf.count))).filter { $0 > 0 }
    }
}
