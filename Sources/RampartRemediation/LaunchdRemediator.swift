import Foundation
import RampartShared

public enum LaunchdDomain: Codable, Hashable, Sendable, CustomStringConvertible {
    case system
    case gui(uid: UInt32)
    case user(uid: UInt32)
    public var description: String {
        switch self {
        case .system: return "system"
        case .gui(let u): return "gui/\(u)"
        case .user(let u): return "user/\(u)"
        }
    }
    public var requiresRoot: Bool {
        switch self {
        case .system: return true
        case .gui(let u), .user(let u): return u != getuid()
        }
    }
}

public struct LaunchdJob: Codable, Hashable, Sendable {
    public var label: String
    public var domain: LaunchdDomain
    public var plistPath: String?
    public var program: String?
    public init(label: String, domain: LaunchdDomain, plistPath: String? = nil, program: String? = nil) {
        self.label = label; self.domain = domain; self.plistPath = plistPath; self.program = program
    }
    public var serviceTarget: String { "\(domain)/\(label)" }
}

public struct LaunchdRemediationResult: Codable, Sendable {
    public var dryRun: Bool
    public var commands: [PrivilegedCommand]
    public var undoCommands: [PrivilegedCommand]
    public var wasDisabled: Bool?
    public var errors: [String]
}

/// Stops and disables launchd jobs with `launchctl bootout` + `disable` (modern domain-target syntax).
public final class LaunchdRemediator: @unchecked Sendable {
    public static let launchctl = "/bin/launchctl"
    /// bootout of a job that is not loaded returns 3 (ESRCH) or 113 ("Could not find service"); treat as success.
    public static let notLoadedCodes: [Int32] = [3, 113]
    public let runner: CommandRunner

    public init(runner: CommandRunner = ProcessCommandRunner()) { self.runner = runner }

    /// Builds a job description from a plist file; picks the domain from its location.
    public static func job(fromPlist path: String, consoleUIDs: [UInt32] = [getuid()]) -> [LaunchdJob] {
        guard let d = FileManager.default.contents(atPath: path),
              let pl = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any],
              let label = pl["Label"] as? String else { return [] }
        let program = (pl["Program"] as? String) ?? (pl["ProgramArguments"] as? [String])?.first
        let p = normalizePath(path)
        if p.hasPrefix("/Library/LaunchDaemons/") || p.hasPrefix("/System/Library/LaunchDaemons/") {
            return [LaunchdJob(label: label, domain: .system, plistPath: p, program: program)]
        }
        if p.hasPrefix("/Library/LaunchAgents/") {
            return consoleUIDs.map { LaunchdJob(label: label, domain: .gui(uid: $0), plistPath: p, program: program) }
        }
        // ~/Library/LaunchAgents: domain of the file owner.
        var st = stat()
        let uid = lstat(p, &st) == 0 ? st.st_uid : getuid()
        return [LaunchdJob(label: label, domain: .gui(uid: uid), plistPath: p, program: program)]
    }

    public func commands(for job: LaunchdJob) -> [PrivilegedCommand] {
        let root = job.domain.requiresRoot
        return [
            PrivilegedCommand(Self.launchctl, ["bootout", job.serviceTarget], requiresRoot: root, acceptableExitCodes: Self.notLoadedCodes),
            PrivilegedCommand(Self.launchctl, ["disable", job.serviceTarget], requiresRoot: root),
        ]
    }

    /// Re-enable then bootstrap from the plist (if it still exists or was restored).
    public func undoCommands(for job: LaunchdJob, wasDisabled: Bool = false) -> [PrivilegedCommand] {
        let root = job.domain.requiresRoot
        var c: [PrivilegedCommand] = []
        if !wasDisabled { c.append(PrivilegedCommand(Self.launchctl, ["enable", job.serviceTarget], requiresRoot: root)) }
        if let p = job.plistPath {
            c.append(PrivilegedCommand(Self.launchctl, ["bootstrap", job.domain.description, p], requiresRoot: root,
                                       acceptableExitCodes: [5, 17, 37] /* already loaded */))
        }
        return c
    }

    public func inspectCommand(for job: LaunchdJob) -> PrivilegedCommand {
        PrivilegedCommand(Self.launchctl, ["print-disabled", job.domain.description], requiresRoot: false)
    }

    /// Parses `launchctl print-disabled <domain>` output: `"label" => disabled|enabled|true|false`.
    public static func parseDisabled(_ output: String) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for line in output.split(separator: "\n") {
            let parts = line.components(separatedBy: "=>")
            guard parts.count == 2 else { continue }
            let label = parts[0].trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
            let v = parts[1].trimmingCharacters(in: .whitespaces)
            if v.hasPrefix("disabled") || v.hasPrefix("true") { out[label] = true }
            else if v.hasPrefix("enabled") || v.hasPrefix("false") { out[label] = false }
        }
        return out
    }

    /// Dry-run by default: returns the commands without executing.
    public func remediate(_ job: LaunchdJob, dryRun: Bool = true) -> LaunchdRemediationResult {
        let cmds = commands(for: job)
        var result = LaunchdRemediationResult(dryRun: dryRun, commands: cmds, undoCommands: undoCommands(for: job), wasDisabled: nil, errors: [])
        if dryRun { return result }
        let insp = runner.run(inspectCommand(for: job))
        if insp.succeeded, let was = Self.parseDisabled(insp.stdout)[job.label] {
            result.wasDisabled = was
            result.undoCommands = undoCommands(for: job, wasDisabled: was)
        }
        for c in cmds {
            let r = runner.run(c)
            if !r.succeeded { result.errors.append("\(c): exit \(r.exitCode) \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines))") }
        }
        return result
    }
}
