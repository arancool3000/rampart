import Foundation
import RampartShared

/// One-time privileged install of the system service: runs the bundled CLI `rampart install --gui-auth`,
/// which shows a single macOS administrator prompt. Never runs from a development build: only from a copy
/// installed in /Applications, never in headless mode.
@MainActor
@Observable
final class FullProtectionInstaller {
    static let shared = FullProtectionInstaller()

    enum Phase: Equatable { case idle, waitingForPassword, installing, connecting, done, failed(String) }
    private(set) var phase: Phase = .idle

    var cliURL: URL { Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/rampart") }

    /// Why the button is unavailable, or nil when it can run.
    var unavailableReason: String? {
        if Headless.active { return "Not available in test runs." }
        if !Bundle.main.bundlePath.hasPrefix("/Applications/") { return "Move \(Product.name) to your Applications folder first, then try again." }
        if !FileManager.default.isExecutableFile(atPath: cliURL.path) { return "This copy of \(Product.name) is missing its installer." }
        // The installer must be this bundle's own file, not a symlink out of it.
        if cliURL.resolvingSymlinksInPath().path != cliURL.standardizedFileURL.path { return "This copy of \(Product.name) has a damaged installer. Download it again." }
        return nil
    }

    /// True when the only blocker is that this copy isn't in /Applications.
    var needsMoveToApplications: Bool { !Headless.active && !ApplicationsMover.runsFromApplications }

    /// Shows the drag-to-Applications window (no-op when already in /Applications).
    func showMoveToApplications() { InstallToApplicationsWindow.showIfNeeded() }

    func run() {
        if needsMoveToApplications { showMoveToApplications(); return }
        guard unavailableReason == nil, phase != .waitingForPassword, phase != .installing else { return }
        phase = .waitingForPassword
        let p = Process()
        p.executableURL = cliURL
        p.arguments = ["install", "--gui-auth"]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        p.terminationHandler = { proc in
            let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            let ok = proc.terminationStatus == 0
            Task { @MainActor in FullProtectionInstaller.shared.finished(ok: ok, output: out) }
        }
        do { try p.run() } catch { phase = .failed(error.localizedDescription); return }
        // The CLI is blocked on the macOS prompt until the user answers; after a few seconds assume it's installing.
        Task {
            try? await Task.sleep(nanoseconds: 6_000_000_000)
            if self.phase == .waitingForPassword && p.isRunning { self.phase = .installing }
        }
    }

    private func finished(ok: Bool, output: String) {
        guard ok else {
            // Shown in our UI: keep it short and strip the "rampart: " prefix and control characters.
            var last = output.split(separator: "\n").last.map(String.init) ?? ""
            if last.hasPrefix("rampart: ") { last.removeFirst("rampart: ".count) }
            last = String(last.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7f }.prefix(240))
            phase = .failed(last.lowercased().contains("cancel") ? "The password prompt was cancelled. Nothing was changed." : (last.isEmpty ? "The installer stopped before finishing. Nothing was changed." : last))
            return
        }
        phase = .connecting
        Task {
            // The system service replaces basic protection; reconnect to it.
            DaemonLauncher.shared.stopChild()
            for _ in 0..<40 {
                if FileManager.default.fileExists(atPath: IPC.socketPath), await AppModel.shared.client.isReachable() { break }
                try? await Task.sleep(nanoseconds: 500_000_000)
            }
            await AppModel.shared.retry()
            phase = AppModel.shared.source == .systemService ? .done : .failed("The service was installed but isn't answering yet. It usually starts within a minute.")
        }
    }
}
