import Foundation
import AppKit
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

    /// hx8: QA flags are ignored by a copy installed in /Applications (see DaemonPeerTrust.devOverridesAllowed).
    private static func arg(_ name: String) -> String? {
        guard DaemonPeerTrust.devOverridesAllowed else { return nil }
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

    /// Where the bundled helper should be. Used to say exactly what's missing.
    var expectedHelperPath: String { Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/rampartd").path }
    var helperMissing: Bool { Self.arg("--helper") == nil && !Headless.active && helperURL == nil }

    var missingHelperMessage: String {
        let path = (expectedHelperPath as NSString).abbreviatingWithTildeInPath
        return "The protection service file is missing from this copy of \(Product.name): \(path). It may have been deleted or not copied. Reinstalling \(Product.name) puts it back."
    }

    /// A downloaded RamPart disk image, newest first: in Downloads or next to this copy of the app.
    var installerDMG: URL? {
        let fm = FileManager.default
        let dirs = [fm.homeDirectoryForCurrentUser.appendingPathComponent("Downloads"), Bundle.main.bundleURL.deletingLastPathComponent()]
        var found: [(URL, Date)] = []
        for d in dirs {
            guard let items = try? fm.contentsOfDirectory(at: d, includingPropertiesForKeys: [.contentModificationDateKey]) else { continue }
            for u in items where u.pathExtension.lowercased() == "dmg" && u.lastPathComponent.lowercased().hasPrefix("rampart") {
                let date = (try? u.resourceValues(forKeys: [.contentModificationDateKey]).contentModificationDate) ?? .distantPast
                found.append((u, date))
            }
        }
        return found.max { $0.1 < $1.1 }?.0
    }

    /// "Reinstall RamPart": reveals the disk image in Finder when we can find one. Returns false otherwise,
    /// so the caller can explain how to get a fresh copy.
    @discardableResult
    func revealInstaller() -> Bool {
        guard let dmg = installerDMG else { return false }
        NSWorkspace.shared.activateFileViewerSelecting([dmg])
        return true
    }

    var isInstalledCopy: Bool { Bundle.main.bundlePath.hasPrefix("/Applications/") }

    /// Starts the helper if needed and waits up to `timeout` for its socket.
    func launchAndWait(client: DaemonClient, timeout: TimeInterval = 10) async -> State {
        guard let helper = helperURL else { return .failed("No helper binary in this build.") }
        // hx8: only ever start the helper this app's signature vouches for (not a swapped or symlinked file).
        guard DaemonPeerTrust.fileSatisfiesHelperRequirement(helper.path) else {
            return .failed("The protection service file in this copy of \(Product.name) has been changed or isn't signed like the app, so it wasn't started. Reinstalling \(Product.name) fixes this.")
        }
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
        // hx8: never pass loader-injection variables on to the helper.
        var env = Self.sanitizedEnvironment(ProcessInfo.processInfo.environment)
        if Headless.active || CommandLine.arguments.contains("--helper-no-realtime") {
            if !args.contains("--no-scheduler") { args += ["--no-scheduler"] }
            env["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"
        }
        p.environment = env
        p.arguments = args
        p.standardInput = FileHandle.nullDevice
        let logDir = Self.rootOverride.map { URL(fileURLWithPath: $0) }
            ?? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Rampart")
        try? FileManager.default.createDirectory(at: logDir, withIntermediateDirectories: true)
        let logURL = logDir.appendingPathComponent("rampartd-user.log")
        // hx8: open with O_NOFOLLOW so a planted symlink can't redirect the helper's output into another file.
        let lfd = open(logURL.path, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0o600)
        if lfd >= 0 { let h = FileHandle(fileDescriptor: lfd, closeOnDealloc: true); p.standardOutput = h; p.standardError = h }
        else { p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice }
        do { try p.run() } catch { return .failed("Couldn't start basic protection: \(error.localizedDescription)") }
        child = p
        if await waitForSocket(client: client, timeout: timeout) { return .running(pid: p.processIdentifier) }
        return p.isRunning ? .failed("Basic protection started but isn't answering yet.") : .failed("Basic protection stopped right after starting. See \(logURL.path).")
    }

    static func sanitizedEnvironment(_ env: [String: String]) -> [String: String] {
        env.filter { k, _ in !k.hasPrefix("DYLD_") && k != "MallocStackLogging" && !k.hasPrefix("__XPC_DYLD") }
    }

    private func waitForSocket(client: DaemonClient, timeout: TimeInterval) async -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if await client.isReachable() { return true }
            try? await Task.sleep(nanoseconds: 250_000_000)
        }
        return false
    }

    /// hx8: the build that last started the user helper. When the app was updated in place, the running helper is
    /// still the old binary (whose signature no longer matches this app's requirement), so it is restarted.
    static let helperBuildKey = "helper.lastBuild"
    static var currentBuild: String {
        (Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "") + "-" + Product.version
    }

    /// Restarts the user helper so it runs the binary inside the (updated) bundle. Never in headless/dev runs.
    func restartAfterUpdate() {
        guard !Headless.active else { return }
        stopChild()
        if #available(macOS 13, *), isInstalledCopy {
            let svc = SMAppService.agent(plistName: Self.agentPlist)
            if svc.status == .enabled { try? svc.unregister(); try? svc.register() }
        }
        UserDefaults.standard.set(Self.currentBuild, forKey: Self.helperBuildKey)
    }

    private func registerAgent() -> Bool {
        guard #available(macOS 13, *) else { return false }
        let plist = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/\(Self.agentPlist)")
        guard FileManager.default.fileExists(atPath: plist.path) else { return false }
        let svc = SMAppService.agent(plistName: Self.agentPlist)
        let last = UserDefaults.standard.string(forKey: Self.helperBuildKey)
        if svc.status == .enabled, let last, last != Self.currentBuild {
            // Updated since the helper was started: restart it on the new binary.
            try? svc.unregister()
            UserDefaults.standard.set(Self.currentBuild, forKey: Self.helperBuildKey)
            do { try svc.register(); return svc.status == .enabled } catch { return false }
        }
        UserDefaults.standard.set(Self.currentBuild, forKey: Self.helperBuildKey)
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
