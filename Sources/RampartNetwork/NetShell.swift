import Foundation

/// A shell command that Rampart would run (or did run). Arguments are passed verbatim, never through a shell.
public struct NetCommand: Codable, Hashable, Sendable, CustomStringConvertible {
    public var executable: String
    public var arguments: [String]
    public var requiresRoot: Bool
    public init(_ executable: String, _ arguments: [String], requiresRoot: Bool = true) {
        self.executable = executable; self.arguments = arguments; self.requiresRoot = requiresRoot
    }
    /// Copy-pasteable rendering (quoted), for dry-run previews and logs.
    public var description: String {
        ([executable] + arguments).map { a in
            a.isEmpty || a.contains(where: { " \"'$\\*?<>|&;()".contains($0) })
                ? "'" + a.replacingOccurrences(of: "'", with: "'\\''") + "'" : a
        }.joined(separator: " ")
    }
}

public struct NetCommandResult: Sendable {
    public var command: NetCommand
    public var status: Int32
    public var stdout: String
    public var stderr: String
    public var dryRun: Bool
    public var ok: Bool { status == 0 }
}

enum NetShell {
    /// Runs a binary with a timeout and returns (status, stdout, stderr). Status -1 means it could not run.
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 20) -> (Int32, String, String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return (-1, "", "\(error)") }
        let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
        var errData = Data()
        let g = DispatchGroup(); g.enter()
        DispatchQueue.global().async { errData = err.fileHandleForReading.readDataToEndOfFile(); g.leave() }
        let outData = out.fileHandleForReading.readDataToEndOfFile()
        g.wait()
        p.waitUntilExit()
        killer.cancel()
        return (p.terminationStatus, String(decoding: outData, as: UTF8.self), String(decoding: errData, as: UTF8.self))
    }

    static func execute(_ cmd: NetCommand, dryRun: Bool) -> NetCommandResult {
        if dryRun { return NetCommandResult(command: cmd, status: 0, stdout: "", stderr: "", dryRun: true) }
        let (s, o, e) = run(cmd.executable, cmd.arguments)
        return NetCommandResult(command: cmd, status: s, stdout: o, stderr: e, dryRun: false)
    }
}
