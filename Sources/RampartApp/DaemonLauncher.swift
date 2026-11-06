import Foundation
import ServiceManagement
import RampartShared

/// Starts "basic protection": the bundled `Contents/Helpers/rampartd --user` (no root, no install).
///
/// Order of preference when no daemon socket answers:
///  1. SMAppService.agent with the bundled user LaunchAgent, but only for a copy installed in /Applications
///     (registering from a build folder or the scratchpad would leave a stray login item).
///  2. A hidden child process. It keeps running after the app quits when
///     Settings › "Keep protecting when Rampart is closed" is on (default on).
///
/// Development/QA flags (app arguments): `--helper PATH` (helper override), `--socket PATH` (talk only to this
/// socket and pass it to the helper), `--daemon-root DIR` (helper state directory).
@MainActor
final class DaemonLauncher {
    static let shared = DaemonLauncher()

    enum State: Equatable { case idle, starting, running(pid: Int32), agent, failed(String) }

    static let keepRunningKey = "general.keepProtectingWhenClosed"
    static var keepRunningWhenClosed: Bool {
        UserDefaults.standard.object(forKey: keepRunningKey) as? Bool ?? true
    }

    private(set) var child: Process?
    static let agentPlist = "app.rampart.userdaemon.plist"

    private static func arg(_ name: String) -> String? {
        let a = CommandLine.arguments
        guard let i = a.firstIndex(of: name), i + 1 < a.count else { return nil }
        return a[i + 1]
    }
    static var socketOverride: String? { arg("--socket") }
    static var rootOverride: String? { arg("--daemon-root") }

    var helperURL: URL? {
        if let p = Self.arg("--helper") { return FileManager.default.isExecutableFile(atPath: p) ? URL(fileURLWithPath: p) : nil }
        // Headless checks never start a real daemon in the user's Library unless pointed at a scratch root.
        if Headless.active && Self.rootOverride == nil { return nil }
        let u = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/rampartd")
        return FileManager.default.isExecutableFile(atPath: u.path) ? u : nil
    }

    var isInstalledCopy: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    /// Starts the helper if needed and waits up to `timeout` for its socket.
    func launchAndWait(client: DaemonClient, timeout: TimeInterval = 10) async -> State {
        guard let helper = helperURL else { return .failed("No helper binary in this build.") }
        if isInstalledCopy, Self.socketOverride == nil, !Headless.active, registerAgent() {
            if await waitForSocket(client: client, timeout: timeout) { return .agent }
        }
        if let c = child, c.isRunning { return await waitForSocket(client: client, timeout: timeout) ? .running(pid: c.processIdentifier) : .failed("The helper didn't answer.") }

        let p = Process()
        p.executableURL = helper
        var args = ["--user"]
        if let s = Self.socketOverride { args += ["--socket", s] }
        if let r = Self.rootOverride { args += ["--root", r] }
        // QA only: keep a test daemon from watching the user's real folders.
        if CommandLine.arguments.contains("--helper-no-realtime") { args += ["--no-realtime"] }
        // ZERO POP-UPS RULE: test runs never let the daemon schedule work or spawn privileged tools
        // (sfltool, profiles, …), so nothing can show a dialog.
        if Headless.active || CommandLine.arguments.contains("--helper-no-realtime") {
            if !args.contains("--no-scheduler") { args += ["--no-scheduler"] }
            var env = ProcessInfo.processInfo.environment
            env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"
            p.environment = env
        }
        p.arguments = args
        p.standardInput = FileHandle.nullDevice
        let logDir = Self.rootOverride.map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Rampart")
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        let logURL = logDir.appendingPathComponent("rampartd-user.log")
        if !FileManager.default.fileExists(atPath: logURL.path) { FileManager.default.createFile(atPath: logURL.path, contents: nil) }
        if let h = try? FileHandle(forWritingTo: logURL) { h.seekToEndOfFile(); p.standardOutput = h; p.standardError = h }
        do { try p.run() } catch { return .failed("Couldn't start basic protection: \(error.localizedDescription)") }
        child = p
        if await waitForSocket(client: client, timeout: timeout) { return .running(pid: p.processIdentifier) }
        return p.isRunning ? .failed("Basic protection started but isn't answering yet.") : .failed("Basic protection stopped right after starting. See \(logURL.path).")
    }

    private func waitForSocket(client: DaemonClient, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await client.isReachable() { return true }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    private func registerAgent() -> Bool {
        guard #available(macOS 13, *) else { return false }
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/\(Self.agentPlist)")
        guard FileManager.default.fileExists(atPath: plist.path) else { return false }
        let svc = SMAppService.agent(plistName: Self.agentPlist)
        if svc.status == .enabled { return true }
        do { try svc.register(); return svc.status == .enabled } catch { return false }
    }

    /// Called from applicationWillTerminate.
    func appWillTerminate() {
        guard let c = child, c.isRunning else { return }
        if Headless.active || !Self.keepRunningWhenClosed { c.terminate() }
    }

    func stopChild() { if let c = child, c.isRunning { c.terminate() } }
}
