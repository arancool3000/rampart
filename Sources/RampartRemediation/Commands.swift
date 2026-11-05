import Foundation
import RampartShared

/// A typed command line. Always an absolute executable plus an argument array (never `sh -c`).
public struct PrivilegedCommand: Codable, Hashable, Sendable, CustomStringConvertible {
    public var executable: String
    public var arguments: [String]
    public var requiresRoot: Bool
    /// Optional data written to stdin (used by `crontab -`).
    public var stdin: String?
    /// Exit codes treated as success besides 0 (e.g. launchctl bootout of a job that is not loaded).
    public var acceptableExitCodes: [Int32]
    public init(_ executable: String, _ arguments: [String], requiresRoot: Bool = false,
                stdin: String? = nil, acceptableExitCodes: [Int32] = []) {
        self.executable = executable; self.arguments = arguments; self.requiresRoot = requiresRoot
        self.stdin = stdin; self.acceptableExitCodes = acceptableExitCodes
    }
    public var description: String {
        let quoted = arguments.map { a -> String in
            a.isEmpty || a.contains(where: { " \"'$\\".contains($0) }) ? "'" + a.replacingOccurrences(of: "'", with: "'\\''") + "'" : a
        }
        return ([executable] + quoted).joined(separator: " ") + (stdin != nil ? " <<stdin>>" : "")
    }
}

public struct CommandResult: Sendable {
    public var exitCode: Int32
    public var stdout: String
    public var stderr: String
    public var succeeded: Bool
    public init(exitCode: Int32, stdout: String, stderr: String, succeeded: Bool) {
        self.exitCode = exitCode; self.stdout = stdout; self.stderr = stderr; self.succeeded = succeeded
    }
}

/// Executes commands. Inject a fake runner in tests.
public protocol CommandRunner: Sendable {
    func run(_ command: PrivilegedCommand) -> CommandResult
}

public struct ProcessCommandRunner: CommandRunner {
    public var timeout: TimeInterval
    public init(timeout: TimeInterval = 60) { self.timeout = timeout }
    public func run(_ command: PrivilegedCommand) -> CommandResult {
        guard command.executable.hasPrefix("/") else {
            return CommandResult(exitCode: -1, stdout: "", stderr: "executable must be an absolute path", succeeded: false)
        }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: command.executable)
        p.arguments = command.arguments
        let out = Pipe(), err = Pipe(), inp = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = inp
        do { try p.run() } catch {
            return CommandResult(exitCode: -1, stdout: "", stderr: "\(error)", succeeded: false)
        }
        if let s = command.stdin { inp.fileHandleForWriting.write(Data(s.utf8)) }
        try? inp.fileHandleForWriting.close()
        // Read pipes concurrently to avoid deadlock on large output.
        var oData = Data(), eData = Data()
        let g = DispatchGroup()
        g.enter(); DispatchQueue.global().async { oData = out.fileHandleForReading.readDataToEndOfFile(); g.leave() }
        g.enter(); DispatchQueue.global().async { eData = err.fileHandleForReading.readDataToEndOfFile(); g.leave() }
        let deadline = Date().addingTimeInterval(timeout)
        while p.isRunning && Date() < deadline { usleep(20_000) }
        if p.isRunning { p.terminate() }
        p.waitUntilExit()
        g.wait()
        let code = p.terminationStatus
        return CommandResult(exitCode: code, stdout: String(decoding: oData, as: UTF8.self),
                             stderr: String(decoding: eData, as: UTF8.self),
                             succeeded: code == 0 || command.acceptableExitCodes.contains(code))
    }
}

/// Records commands instead of running them; returns success. Useful for previews and tests.
public final class RecordingCommandRunner: CommandRunner, @unchecked Sendable {
    private let lock = NSLock()
    private var _commands: [PrivilegedCommand] = []
    public var stdoutFor: (PrivilegedCommand) -> String
    public init(stdoutFor: @escaping (PrivilegedCommand) -> String = { _ in "" }) { self.stdoutFor = stdoutFor }
    public var commands: [PrivilegedCommand] { lock.lock(); defer { lock.unlock() }; return _commands }
    public func run(_ command: PrivilegedCommand) -> CommandResult {
        lock.lock(); _commands.append(command); lock.unlock()
        return CommandResult(exitCode: 0, stdout: stdoutFor(command), stderr: "", succeeded: true)
    }
}

public enum RemediationError: Error, CustomStringConvertible, Equatable {
    case protectedPath(String)
    case notFound(String)
    case destinationExists(String)
    case integrityFailure(String)
    case ioError(String)
    case browserRunning(String)
    case commandFailed(String)
    case unsupported(String)
    public var description: String {
        switch self {
        case .protectedPath(let s): return "protected path: \(s)"
        case .notFound(let s): return "not found: \(s)"
        case .destinationExists(let s): return "destination already exists: \(s)"
        case .integrityFailure(let s): return "integrity check failed: \(s)"
        case .ioError(let s): return "I/O error: \(s)"
        case .browserRunning(let s): return "browser is running: \(s)"
        case .commandFailed(let s): return "command failed: \(s)"
        case .unsupported(let s): return "unsupported: \(s)"
        }
    }
}

/// Paths remediation must never touch (SIP/SSV locations, home roots).
public enum ProtectedPaths {
    public static let prefixes = ["/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
                                  "/usr/share/", "/Library/Apple/", "/private/var/db/", "/dev/"]
    public static func isProtected(_ path: String) -> Bool {
        let p = normalizePath(path)
        if ["/", "/System", "/Users", "/Applications", "/Library", "/usr", "/bin", "/sbin", "/private", "/var", "/etc", "/tmp"].contains(p) { return true }
        if prefixes.contains(where: { p.hasPrefix($0) }) { return true }
        // Home directory roots and their top-level folders (e.g. ~/Documents).
        let comps = (p as NSString).pathComponents
        if comps.count >= 2, comps[1] == "Users", comps.count <= 4 { return true }
        if p.hasPrefix("/var/root") && comps.count <= 3 { return true }
        // Rampart itself.
        if p.hasPrefix(Paths.supportRoot.path + "/") || p == Paths.supportRoot.path { return true }
        return false
    }
}

/// Removes `.`/`..` and duplicate slashes without rewriting `/private/tmp` to `/tmp` (unlike `standardizingPath`).
public func normalizePath(_ path: String) -> String {
    URL(fileURLWithPath: path).standardized.path
}
