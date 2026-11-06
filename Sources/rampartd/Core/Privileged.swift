import Foundation
import RampartShared
import RampartPosture
import RampartRemediation

/// Central gate for tools that can put a dialog on the user's screen (ARCHITECTURE.md "ZERO POP-UPS RULE").
/// Every command rampartd / the CLI spawns goes through `Privileged.check`, via the guarded runners below.
enum Privileged {
    /// `RAMPART_NO_PRIVILEGED_TOOLS=1`: never spawn the tools below, never read the general pasteboard.
    static let noPrivilegedTools: Bool = {
        let v = ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] ?? ""
        return !v.isEmpty && v != "0"
    }()

    /// Tools that can show authorization / permission prompts (or change system state behind one).
    static let bannedTools: Set<String> = ["sfltool", "profiles", "systemextensionsctl", "tccutil", "osascript", "security",
                                           "sudo", "authopen", "dscl", "sysadminctl", "systemsetup", "networksetup", "pfctl", "kextstat"]

    static var isRoot: Bool { getuid() == 0 }

    /// nil when the command may run; otherwise the reason it is refused.
    static func refusal(_ executable: String) -> String? {
        let name = (executable as NSString).lastPathComponent
        guard bannedTools.contains(name) else { return nil }
        if noPrivilegedTools { return "\(name) is disabled (RAMPART_NO_PRIVILEGED_TOOLS=1)" }
        // Without root these tools ask for an administrator password or a permission in a dialog.
        if !isRoot { return "\(name) needs the \(Product.name) system service (it would show a password dialog without root)" }
        return nil
    }

    /// Reading the general pasteboard is allowed only in a user session, never with the env switch.
    static var pasteboardAllowed: Bool { !noPrivilegedTools && !isRoot }
}

/// Posture command runner that refuses gated tools (the check then reports "unknown", which never counts as a fail).
struct GuardedPostureRunner: CommandRunning {
    let inner = ProcessRunner()
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> RampartPosture.CommandResult {
        if let why = Privileged.refusal(executable) {
            return RampartPosture.CommandResult(status: -1, stderr: why, launchFailed: true)
        }
        return inner.run(executable, arguments, timeout: timeout)
    }
}

/// Remediation command runner with the same gate.
struct GuardedRemediationRunner: CommandRunner {
    let inner = ProcessCommandRunner()
    func run(_ command: PrivilegedCommand) -> RampartRemediation.CommandResult {
        if let why = Privileged.refusal(command.executable) {
            return RampartRemediation.CommandResult(exitCode: -1, stdout: "", stderr: why, succeeded: false)
        }
        return inner.run(command)
    }
}
