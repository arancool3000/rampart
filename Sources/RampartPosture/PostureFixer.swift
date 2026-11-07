import Foundation
import RampartShared

/// A privileged fix the daemon may run. `commands` are absolute-path argument arrays (never a shell string).
public struct PostureFix: Codable, Hashable, Sendable {
    public var checkID: String
    public var title: String
    public var commands: [[String]]
    /// Commands that undo the fix, when known.
    public var revertCommands: [[String]]?
    public var requiresRoot: Bool
    /// True: the caller must only show `commands`; nothing may be executed.
    public var dryRun: Bool
    public var note: String
    /// Human-readable preview, one command per line.
    public var preview: String { commands.map { $0.joined(separator: " ") }.joined(separator: "\n") }
}

/// One-click fixes for safe, reversible toggles only (doc 07 §15). This type never executes anything:
/// it returns the exact command for the root daemon (rampartd) to run, then the daemon re-runs the check
/// to verify. FileVault, SIP, Lockdown Mode, Secure Boot etc. are deep-link-only and return nil.
public enum PostureFixer {
    public static let socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    public static let sysadminctl = "/usr/sbin/sysadminctl"
    public static let systemsetup = "/usr/sbin/systemsetup"
    public static let defaults = "/usr/bin/defaults"

    public static let fixableCheckIDs: Set<String> = ["firewall", "stealthMode", "guestAccount", "remoteLogin", "autoUpdates"]

    public static func canFix(_ checkID: String) -> Bool { fixableCheckIDs.contains(checkID) }

    /// The only programs a fix may run (hx10). Executors must refuse any fix for which `isSafe` is false.
    public static let allowedExecutables: Set<String> = [socketfilterfw, sysadminctl, systemsetup, defaults]

    /// True if every command is an argument array (never a shell) for an allow-listed absolute executable, and every
    /// argument is short printable ASCII with no option smuggled through spaces, NULs or line breaks.
    public static func isSafe(_ f: PostureFix) -> Bool {
        guard canFix(f.checkID), !f.commands.isEmpty, f.commands.count <= 16 else { return false }
        for cmd in f.commands + (f.revertCommands ?? []) {
            guard let exe = cmd.first, allowedExecutables.contains(exe), cmd.count <= 12 else { return false }
            for a in cmd.dropFirst() {
                guard !a.isEmpty, a.utf8.count <= 128,
                      a.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f && $0 != "`" && $0 != "$" && $0 != ";" && $0 != "|" && $0 != "&" })
                else { return false }
            }
        }
        return true
    }

    /// The fix for a check, or nil if it isn't a safe one-click toggle. `dryRun` defaults to true.
    public static func fix(for checkID: String, dryRun: Bool = true) -> PostureFix? {
        guard canFix(checkID) else { return nil }   // exact match on a fixed set: caller text never reaches a command
        switch checkID {
        case "firewall":
            return PostureFix(checkID: checkID, title: "Turn on the macOS firewall",
                              commands: [[socketfilterfw, "--setglobalstate", "on"]],
                              revertCommands: [[socketfilterfw, "--setglobalstate", "off"]],
                              requiresRoot: true, dryRun: dryRun, note: "Signed apps keep accepting connections.")
        case "stealthMode":
            return PostureFix(checkID: checkID, title: "Turn on stealth mode",
                              commands: [[socketfilterfw, "--setstealthmode", "on"]],
                              revertCommands: [[socketfilterfw, "--setstealthmode", "off"]],
                              requiresRoot: true, dryRun: dryRun, note: "Only has an effect while the firewall is on.")
        case "guestAccount":
            return PostureFix(checkID: checkID, title: "Turn off the guest account",
                              commands: [[sysadminctl, "-guestAccount", "off"]],
                              revertCommands: [[sysadminctl, "-guestAccount", "on"]],
                              requiresRoot: true, dryRun: dryRun, note: "")
        case "remoteLogin":
            return PostureFix(checkID: checkID, title: "Turn off Remote Login (SSH)",
                              commands: [[systemsetup, "-f", "-setremotelogin", "off"]],
                              revertCommands: [[systemsetup, "-f", "-setremotelogin", "on"]],
                              requiresRoot: true, dryRun: dryRun,
                              note: "The daemon needs Full Disk Access for systemsetup on macOS 13 and later. Open SSH sessions end.")
        case "autoUpdates":
            let su = "/Library/Preferences/com.apple.SoftwareUpdate"
            var cmds = PostureParsers.autoUpdateKeys.map { [defaults, "write", su, $0.key, "-bool", "true"] }
            cmds.append([defaults, "write", "/Library/Preferences/com.apple.commerce", "AutoUpdate", "-bool", "true"])
            return PostureFix(checkID: checkID, title: "Turn on automatic updates",
                              commands: cmds, revertCommands: nil, requiresRoot: true, dryRun: dryRun,
                              note: "Previous values aren't restored automatically; change them in System Settings > General > Software Update.")
        default:
            return nil
        }
    }

    /// Deep link (or instructions) for checks without a one-click fix.
    public static func settingsLink(for checkID: String) -> String? {
        switch checkID {
        case "fileVault": return "x-apple.systempreferences:com.apple.preference.security?FileVault"
        case "firewall", "stealthMode": return "x-apple.systempreferences:com.apple.preference.security?Firewall"
        case "tccReview": return "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
        case "autoUpdates", "osUpToDate", "xprotectFresh": return "x-apple.systempreferences:com.apple.Software-Update-Settings.extension"
        case "remoteLogin", "screenSharing", "fileSharing", "sharingServices", "airDrop":
            return "x-apple.systempreferences:com.apple.Sharing-Settings.extension"
        case "guestAccount", "adminCount": return "x-apple.systempreferences:com.apple.Users-Groups-Settings.extension"
        case "screenLock": return "x-apple.systempreferences:com.apple.Lock-Screen-Settings.extension"
        case "lockdownMode", "gatekeeper": return "x-apple.systempreferences:com.apple.preference.security"
        case "profiles": return "x-apple.systempreferences:com.apple.Profiles-Settings.extension"
        default: return nil
        }
    }
}
