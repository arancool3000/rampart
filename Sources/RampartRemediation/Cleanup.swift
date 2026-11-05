import Foundation
import RampartShared

/// A file or directory moved aside (not deleted) so an action can be undone.
public struct FileBackup: Codable, Hashable, Sendable {
    public var originalPath: String
    public var backupPath: String
    /// true = original was moved to the backup (so undo moves it back); false = it was copied (undo replaces).
    public var moved: Bool
    public init(originalPath: String, backupPath: String, moved: Bool) {
        self.originalPath = originalPath; self.backupPath = backupPath; self.moved = moved
    }
}

/// Result of a cleanup action: what was there before and how to put it back.
public struct CleanupOutcome: Codable, Sendable {
    public var dryRun: Bool
    public var summary: String
    public var commands: [PrivilegedCommand]
    public var undoCommands: [PrivilegedCommand]
    public var backups: [FileBackup]
    public var beforeState: [String: String]
    public var manualUndo: String?
    public init(dryRun: Bool, summary: String, commands: [PrivilegedCommand] = [], undoCommands: [PrivilegedCommand] = [],
                backups: [FileBackup] = [], beforeState: [String: String] = [:], manualUndo: String? = nil) {
        self.dryRun = dryRun; self.summary = summary; self.commands = commands; self.undoCommands = undoCommands
        self.backups = backups; self.beforeState = beforeState; self.manualUndo = manualUndo
    }
}

enum BackupIO {
    static func moveAside(_ path: String, into dir: URL) throws -> FileBackup {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let dest = dir.appendingPathComponent(UUID().uuidString + "-" + (path as NSString).lastPathComponent).path
        try FileManager.default.moveItem(atPath: path, toPath: dest)
        return FileBackup(originalPath: path, backupPath: dest, moved: true)
    }
    static func copyAside(_ path: String, into dir: URL) throws -> FileBackup {
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let dest = dir.appendingPathComponent(UUID().uuidString + "-" + (path as NSString).lastPathComponent).path
        try FileManager.default.copyItem(atPath: path, toPath: dest)
        return FileBackup(originalPath: path, backupPath: dest, moved: false)
    }
    /// Puts a backup back. Moved items are refused if something now sits at the original path.
    static func restore(_ b: FileBackup) throws {
        let fm = FileManager.default
        if b.moved {
            if fm.fileExists(atPath: b.originalPath) { throw RemediationError.destinationExists(b.originalPath) }
            try fm.createDirectory(atPath: (b.originalPath as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            try fm.moveItem(atPath: b.backupPath, toPath: b.originalPath)
        } else {
            let tmp = b.originalPath + ".rampart-undo-\(UUID().uuidString)"
            try fm.copyItem(atPath: b.backupPath, toPath: tmp)
            guard rename(tmp, b.originalPath) == 0 else { try? fm.removeItem(atPath: tmp); throw RemediationError.ioError("replace \(b.originalPath)") }
        }
    }
}

// MARK: - Login items

/// Legacy "Open at Login" items (System Events). SMAppService/BTM items can only be removed by
/// removing the owning app or its plist; use LaunchdRemediator / QuarantineVault for those.
public final class LoginItemCleaner: @unchecked Sendable {
    public let runner: CommandRunner
    public init(runner: CommandRunner = ProcessCommandRunner()) { self.runner = runner }

    static func appleScriptString(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    public func removeCommand(name: String) -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/osascript", ["-e", "tell application \"System Events\" to delete login item \(Self.appleScriptString(name))"])
    }
    public func addCommand(path: String, hidden: Bool = false) -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/osascript", ["-e",
            "tell application \"System Events\" to make login item at end with properties {path:\(Self.appleScriptString(path)), hidden:\(hidden)}"])
    }

    /// Needs an Automation grant for System Events when not dry-run.
    public func remove(name: String, path: String?, dryRun: Bool = true) throws -> CleanupOutcome {
        let c = removeCommand(name: name)
        var o = CleanupOutcome(dryRun: dryRun, summary: "Remove login item \"\(name)\"", commands: [c],
                               undoCommands: path.map { [addCommand(path: $0)] } ?? [],
                               beforeState: ["name": name, "path": path ?? ""],
                               manualUndo: path == nil ? "Re-add \(name) in System Settings > General > Login Items" : nil)
        if dryRun { return o }
        let r = runner.run(c)
        guard r.succeeded else { throw RemediationError.commandFailed("osascript: \(r.stderr)") }
        o.summary += " (done)"
        return o
    }
}

// MARK: - Configuration profiles

public final class ProfileCleaner: @unchecked Sendable {
    public let runner: CommandRunner
    public init(runner: CommandRunner = ProcessCommandRunner()) { self.runner = runner }

    public func exportCommand() -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/profiles", ["show", "-type", "configuration", "-output", "stdout-xml"], requiresRoot: true)
    }
    public func removeCommand(identifier: String) -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/profiles", ["remove", "-identifier", identifier], requiresRoot: true)
    }

    /// Exports profiles XML into `backupDir` (profiles cannot be reinstalled from the CLI, so undo is manual).
    public func remove(identifier: String, backupDir: URL, dryRun: Bool = true) throws -> CleanupOutcome {
        let manual = "Profiles cannot be installed from the command line. Open the saved export in System Settings > General > Device Management to reinstall."
        var o = CleanupOutcome(dryRun: dryRun, summary: "Remove configuration profile \(identifier)",
                               commands: [exportCommand(), removeCommand(identifier: identifier)],
                               beforeState: ["identifier": identifier], manualUndo: manual)
        if dryRun { return o }
        let ex = runner.run(exportCommand())
        if ex.succeeded {
            try FileManager.default.createDirectory(at: backupDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            let f = backupDir.appendingPathComponent("profiles-\(identifier).xml")
            try Data(ex.stdout.utf8).write(to: f)
            o.beforeState["export"] = f.path
        }
        let r = runner.run(removeCommand(identifier: identifier))
        guard r.succeeded else {
            throw RemediationError.commandFailed("profiles remove: \(r.stderr) (MDM or removal-disallowed profiles cannot be removed)")
        }
        return o
    }
}

// MARK: - Cron

public final class CronCleaner: @unchecked Sendable {
    public let runner: CommandRunner
    public init(runner: CommandRunner = ProcessCommandRunner()) { self.runner = runner }

    func userArgs(_ user: String?) -> [String] { user.map { ["-u", $0] } ?? [] }

    public func listCommand(user: String?) -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/crontab", userArgs(user) + ["-l"], requiresRoot: user != nil, acceptableExitCodes: [1])
    }
    public func writeCommand(user: String?, content: String) -> PrivilegedCommand {
        PrivilegedCommand("/usr/bin/crontab", userArgs(user) + ["-"], requiresRoot: user != nil, stdin: content)
    }

    /// Removes lines for which `matches` is true. Comments and blank lines are kept. Pure; unit-tested.
    public static func filter(_ tab: String, removing matches: (String) -> Bool) -> (kept: String, removed: [String]) {
        var kept: [String] = [], removed: [String] = []
        for line in tab.components(separatedBy: "\n") {
            let t = line.trimmingCharacters(in: .whitespaces)
            if !t.isEmpty && !t.hasPrefix("#") && matches(line) { removed.append(line) } else { kept.append(line) }
        }
        var s = kept.joined(separator: "\n")
        if !s.isEmpty && !s.hasSuffix("\n") { s += "\n" }
        return (s, removed)
    }

    /// Removes cron lines containing any of `substrings` (e.g. the malicious target path).
    public func remove(user: String?, containing substrings: [String], dryRun: Bool = true, currentTab: String? = nil) throws -> CleanupOutcome {
        let tab: String
        if let t = currentTab { tab = t } else {
            let r = runner.run(listCommand(user: user))
            tab = r.exitCode == 0 ? r.stdout : ""
        }
        let (kept, removed) = Self.filter(tab) { line in substrings.contains { line.contains($0) } }
        let write = writeCommand(user: user, content: kept)
        var o = CleanupOutcome(dryRun: dryRun, summary: "Remove \(removed.count) cron line(s) for \(user ?? "current user")",
                               commands: removed.isEmpty ? [] : [write],
                               undoCommands: [writeCommand(user: user, content: tab)],
                               beforeState: ["crontab": tab, "removed": removed.joined(separator: "\n")])
        if dryRun || removed.isEmpty { return o }
        let r = runner.run(write)
        guard r.succeeded else { throw RemediationError.commandFailed("crontab: \(r.stderr)") }
        o.summary += " (done)"
        return o
    }
}

// MARK: - Browser extensions

public enum BrowserFamily: String, Codable, Sendable { case chromium, firefox }

public struct BrowserSpec: Codable, Hashable, Sendable {
    public var name: String
    public var family: BrowserFamily
    /// Relative to the user's home.
    public var dataRoot: String
    /// Substring of the running executable path used to decide whether the browser is open.
    public var processMarker: String
    public static let all: [BrowserSpec] = [
        BrowserSpec(name: "Chrome", family: .chromium, dataRoot: "Library/Application Support/Google/Chrome", processMarker: "/Google Chrome.app/Contents/MacOS/"),
        BrowserSpec(name: "Brave", family: .chromium, dataRoot: "Library/Application Support/BraveSoftware/Brave-Browser", processMarker: "/Brave Browser.app/Contents/MacOS/"),
        BrowserSpec(name: "Edge", family: .chromium, dataRoot: "Library/Application Support/Microsoft Edge", processMarker: "/Microsoft Edge.app/Contents/MacOS/"),
        BrowserSpec(name: "Arc", family: .chromium, dataRoot: "Library/Application Support/Arc/User Data", processMarker: "/Arc.app/Contents/MacOS/"),
        BrowserSpec(name: "Vivaldi", family: .chromium, dataRoot: "Library/Application Support/Vivaldi", processMarker: "/Vivaldi.app/Contents/MacOS/"),
        BrowserSpec(name: "Firefox", family: .firefox, dataRoot: "Library/Application Support/Firefox", processMarker: "/Firefox.app/Contents/MacOS/"),
    ]
    public static func named(_ n: String) -> BrowserSpec? { all.first { $0.name.lowercased() == n.lowercased() } }
}

public final class BrowserExtensionCleaner: @unchecked Sendable {
    public let home: URL
    /// Returns true if the browser is running. Default checks executable paths via libproc.
    public var isRunning: (BrowserSpec) -> Bool

    public init(home: URL = FileManager.default.homeDirectoryForCurrentUser, isRunning: ((BrowserSpec) -> Bool)? = nil) {
        self.home = home
        self.isRunning = isRunning ?? { spec in
            ProcessKiller.allPIDs().contains { ProcessKiller.path(of: $0).contains(spec.processMarker) }
        }
    }

    public func profiles(_ spec: BrowserSpec) -> [URL] {
        let root = home.appendingPathComponent(spec.dataRoot)
        let fm = FileManager.default
        switch spec.family {
        case .chromium:
            let names = (try? fm.contentsOfDirectory(atPath: root.path)) ?? []
            return names.filter { $0 == "Default" || $0.hasPrefix("Profile ") }.map { root.appendingPathComponent($0) }
        case .firefox:
            let ini = (try? String(contentsOf: root.appendingPathComponent("profiles.ini"), encoding: .utf8)) ?? ""
            var out: [URL] = []
            var isRelative = true
            for line in ini.components(separatedBy: .newlines) {
                if line.hasPrefix("[") { isRelative = true }
                if line.hasPrefix("IsRelative=") { isRelative = line.hasSuffix("1") }
                if line.hasPrefix("Path=") {
                    let p = String(line.dropFirst(5))
                    out.append(isRelative ? root.appendingPathComponent(p) : URL(fileURLWithPath: p))
                }
            }
            return out
        }
    }

    /// Removes one extension from one profile. The browser must be closed (it rewrites prefs on exit).
    /// Everything is moved/copied into `backupDir` for undo.
    public func remove(browser spec: BrowserSpec, profile: URL, extensionID: String, backupDir: URL, dryRun: Bool = true) throws -> CleanupOutcome {
        guard !extensionID.isEmpty, !extensionID.contains("/"), !extensionID.contains("..") else {
            throw RemediationError.unsupported("bad extension id")
        }
        if isRunning(spec) { throw RemediationError.browserRunning("\(spec.name) must be closed first") }
        let fm = FileManager.default
        var o = CleanupOutcome(dryRun: dryRun, summary: "Remove \(spec.name) extension \(extensionID) from \(profile.lastPathComponent)",
                               beforeState: ["browser": spec.name, "profile": profile.path, "extension": extensionID])
        var touched: [String] = []
        var jsonEdits: [(String, (inout [String: Any]) -> Bool)] = []
        switch spec.family {
        case .chromium:
            let dir = profile.appendingPathComponent("Extensions").appendingPathComponent(extensionID).path
            if fm.fileExists(atPath: dir) { touched.append(dir) }
            for f in ["Preferences", "Secure Preferences"] {
                jsonEdits.append((profile.appendingPathComponent(f).path, { root in
                    guard var ext = root["extensions"] as? [String: Any], var settings = ext["settings"] as? [String: Any],
                          settings[extensionID] != nil else { return false }
                    settings.removeValue(forKey: extensionID); ext["settings"] = settings
                    if var prot = root["protection"] as? [String: Any], var macs = prot["macs"] as? [String: Any],
                       var me = macs["extensions"] as? [String: Any], var ms = me["settings"] as? [String: Any] {
                        ms.removeValue(forKey: extensionID); me["settings"] = ms; macs["extensions"] = me; prot["macs"] = macs; root["protection"] = prot
                    }
                    root["extensions"] = ext
                    return true
                }))
            }
        case .firefox:
            let xpi = profile.appendingPathComponent("extensions").appendingPathComponent(extensionID + ".xpi").path
            let unpacked = profile.appendingPathComponent("extensions").appendingPathComponent(extensionID).path
            for p in [xpi, unpacked] where fm.fileExists(atPath: p) { touched.append(p) }
            jsonEdits.append((profile.appendingPathComponent("extensions.json").path, { root in
                guard let addons = root["addons"] as? [[String: Any]] else { return false }
                let kept = addons.filter { ($0["id"] as? String) != extensionID }
                guard kept.count != addons.count else { return false }
                root["addons"] = kept
                return true
            }))
        }
        // Work out which JSON files actually change.
        var edits: [(String, Data)] = []
        for (path, edit) in jsonEdits {
            guard let d = fm.contents(atPath: path), var obj = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] else { continue }
            if edit(&obj), let out = try? JSONSerialization.data(withJSONObject: obj) { edits.append((path, out)) }
        }
        o.beforeState["moved"] = touched.joined(separator: "\n")
        o.beforeState["edited"] = edits.map(\.0).joined(separator: "\n")
        if touched.isEmpty && edits.isEmpty { throw RemediationError.notFound("extension \(extensionID) in \(profile.path)") }
        if dryRun { return o }
        for (path, data) in edits {
            o.backups.append(try BackupIO.copyAside(path, into: backupDir))
            let tmp = path + ".rampart-\(UUID().uuidString)"
            try data.write(to: URL(fileURLWithPath: tmp))
            guard rename(tmp, path) == 0 else { try? fm.removeItem(atPath: tmp); throw RemediationError.ioError("replace \(path)") }
        }
        for p in touched { o.backups.append(try BackupIO.moveAside(p, into: backupDir)) }
        o.summary += " (done)"
        return o
    }
}
