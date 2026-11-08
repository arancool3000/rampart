import Foundation
import RampartShared

/// Cat & Mouse notifications are posted by the app's menu bar process (UNUserNotificationCenter needs the app
/// bundle). When a catch happens and no app is subscribed, the session daemon wakes the login agent
/// (`app.rampart.agent`: the app with `--background`, menu bar only, no window, no focus change). It then reads
/// `DeceptionStatus.alerts` and posts what it missed.
///
/// ZERO POP-UPS: never in development. Only an installed copy (inside an .app bundle) in the user's session, never
/// as root, never with RAMPART_NO_PRIVILEGED_TOOLS, at most once every 2 minutes.
enum AgentWake {
    static let agentLabel = "app.rampart.agent"
    nonisolated(unsafe) private static var last = Date.distantPast
    private static let lock = NSLock()

    /// The app bundle this daemon belongs to, when installed inside one.
    static var appBundle: String? {
        let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
        guard let r = exe.range(of: ".app/Contents/") else { return nil }
        return String(exe[..<r.lowerBound]) + ".app"
    }

    static func allowed(noPrivilegedTools: Bool = Privileged.noPrivilegedTools, isRoot: Bool = getuid() == 0, bundle: String? = appBundle) -> Bool {
        !noPrivilegedTools && !isRoot && bundle != nil
    }

    static func wake() {
        guard allowed(), let bundle = appBundle else { return }
        lock.lock()
        guard Date().timeIntervalSince(last) > 120 else { lock.unlock(); return }
        last = Date(); lock.unlock()
        DispatchQueue.global(qos: .utility).async {
            // Registered login agent first; if it isn't registered, start the app the same way (background, hidden).
            if run("/bin/launchctl", ["kickstart", "gui/\(getuid())/\(agentLabel)"]) == 0 { return }
            _ = run("/usr/bin/open", ["-g", "-j", "-a", bundle, "--args", "--background"])
        }
    }

    @discardableResult
    private static func run(_ exe: String, _ args: [String]) -> Int32 {
        let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return -1 }
        p.waitUntilExit(); return p.terminationStatus
    }
}
