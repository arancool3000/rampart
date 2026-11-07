import Foundation
import RampartShared

/// Engine version; part of the scan-cache key so cached verdicts are invalidated on upgrade.
public enum EngineInfo {
    public static let version = "engine-2"
}

/// Errors raised by the RampartEngine module.
public enum EngineError: Error, CustomStringConvertible, Sendable {
    case posix(op: String, path: String, errno: Int32)
    case notRegularFile(String)
    case database(String)
    case unpackFailed(String)
    case limitExceeded(String)
    case subprocessTimeout(String)
    case feedInvalid(String)

    public var description: String {
        switch self {
        case let .posix(op, path, e): return "\(op) \(path): \(String(cString: strerror(e)))"
        case let .notRegularFile(p): return "not a regular file: \(p)"
        case let .database(m): return "database: \(m)"
        case let .unpackFailed(m): return "unpack failed: \(m)"
        case let .limitExceeded(m): return "limit exceeded: \(m)"
        case let .subprocessTimeout(m): return "timed out: \(m)"
        case let .feedInvalid(m): return "invalid feed: \(m)"
        }
    }
}

/// Thread-safe cancellation flag shared between a scan's caller and its workers.
public final class ScanCancellation: @unchecked Sendable {
    private let lock = NSLock()
    private var flag = false
    public init() {}
    public func cancel() { lock.lock(); flag = true; lock.unlock() }
    public var isCancelled: Bool { lock.lock(); defer { lock.unlock() }; return flag }
}

/// Minimal blocking FIFO with a capacity bound, used to stream walker output to scan workers.
final class BoundedQueue<T>: @unchecked Sendable {
    private let cond = NSCondition()
    private var items: [T] = []
    private var head = 0
    private var closed = false
    private let capacity: Int
    init(capacity: Int) { self.capacity = max(1, capacity) }

    /// Blocks while full. Returns false if the queue was closed.
    @discardableResult
    func push(_ item: T) -> Bool {
        cond.lock(); defer { cond.unlock() }
        while items.count - head >= capacity && !closed { cond.wait() }
        if closed { return false }
        items.append(item)
        cond.signal()
        return true
    }

    /// Blocks while empty. Returns nil once closed and drained.
    func pop() -> T? {
        cond.lock(); defer { cond.unlock() }
        while items.count == head && !closed { cond.wait() }
        if items.count == head { return nil }
        let v = items[head]; head += 1
        if head > 1024 && head * 2 > items.count { items.removeFirst(head); head = 0 }
        cond.broadcast()
        return v
    }

    func close() { cond.lock(); closed = true; cond.broadcast(); cond.unlock() }
}

/// Runs a helper tool with a hard timeout and captured output. Never uses a shell.
enum Subprocess {
    struct Result { var status: Int32; var stdout: Data; var stderr: Data }

    static func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) throws -> Result {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: executable)
        p.arguments = arguments
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        p.standardInput = FileHandle.nullDevice
        var env = ProcessInfo.processInfo.environment
        env["LC_ALL"] = "C"
        p.environment = env
        try p.run()
        let group = DispatchGroup()
        var outData = Data(), errData = Data()
        group.enter()
        DispatchQueue.global().async { outData = out.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        group.enter()
        DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile(); group.leave() }
        group.enter()
        DispatchQueue.global().async { p.waitUntilExit(); group.leave() }
        if group.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate()
            if group.wait(timeout: .now() + 3) == .timedOut { kill(p.processIdentifier, SIGKILL); _ = group.wait(timeout: .now() + 3) }
            throw EngineError.subprocessTimeout("\(executable) \(arguments.joined(separator: " "))")
        }
        return Result(status: p.terminationStatus, stdout: outData, stderr: errData)
    }
}

extension stat {
    var mtimeNanos: Int64 { Int64(st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st_mtimespec.tv_nsec) }
    var ctimeNanos: Int64 { Int64(st_ctimespec.tv_sec) * 1_000_000_000 + Int64(st_ctimespec.tv_nsec) }
    var isRegular: Bool { (st_mode & S_IFMT) == S_IFREG }
    var isDirectory: Bool { (st_mode & S_IFMT) == S_IFDIR }
}

/// `SF_DATALESS` from <sys/stat.h>: an iCloud / File Provider placeholder whose content is not local.
let kSFDataless: UInt32 = 0x4000_0000
