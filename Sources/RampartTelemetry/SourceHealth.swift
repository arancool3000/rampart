import Foundation
import RampartShared

/// Optional richer health signal a source can expose so the hub can tell "running" from "blinded".
/// A source that stops delivering because a permission was revoked (e.g. eslogger loses Full Disk Access)
/// must report `isRunning == false` so `EventHub` can raise a "lost its event feed" Detection instead of
/// silently staying green.
public protocol SourceHealthReporting: AnyObject {
    var isRunning: Bool { get }
    var lastError: String? { get }
}

// EsloggerSource already publishes both; this makes the primary feed observable to the hub.
extension EsloggerSource: SourceHealthReporting {}

/// Knows what RamPart's own privileged/user helpers are called and where they legitimately live, so an
/// impostor binary (e.g. `/tmp/rampartd`) that borrows the name to earn the user's trust can be flagged.
public enum RampartService {
    /// Process names (argv[0] basename / p_comm) RamPart ships.
    public static let names: Set<String> = [
        "rampartd", "rampart", "RampartWatchdog", "rampart-watchdog", "rampart-nmh", "RamPart",
    ]
    /// Path prefixes the real binaries occupy once installed.
    public static let installPrefixes: [String] = [
        "/Library/Application Support/RamPart/", "/Applications/RamPart.app/",
        "/Library/PrivilegedHelperTools/app.rampart", "/usr/local/bin/rampart", "/usr/local/sbin/rampart",
    ]
    /// Legitimate signing-identifier prefix.
    public static let signingPrefix = "app.rampart"

    /// A reason string if a process named like a RamPart helper is NOT an installed, RamPart-signed binary;
    /// nil if it looks legitimate or isn't claiming to be one of ours. `installPaths` lets the daemon add
    /// its real (e.g. development) location so it doesn't flag itself.
    public static func impostorReason(name: String, path: String, signingID: String?,
                                      installPaths: [String] = installPrefixes) -> String? {
        let basename = (path as NSString).lastPathComponent
        guard names.contains(name) || names.contains(basename) else { return nil }
        let installed = !path.isEmpty && installPaths.contains { path.hasPrefix($0) }
        if !installed {
            return "a process named like \(Product.name) is running from \(path.isEmpty ? "an unknown path" : path), not an installed location"
        }
        if let sid = signingID {
            if !sid.hasPrefix(signingPrefix) {
                return "a process named like \(Product.name) is signed as \"\(sid)\", not \(signingPrefix).*"
            }
        } else {
            return "a process named like \(Product.name) is unsigned"
        }
        return nil
    }
}
