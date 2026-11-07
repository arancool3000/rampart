import Foundation
import RampartShared

/// RamPart's own data folders (state, quarantine vault, DB, journal). Never scanned and never reported,
/// whoever asks: the vault holds the very files we detected (EICAR fixtures, malware), encrypted or not.
public enum OwnData {
    /// System root, this user's root, every local user's root (the root daemon sees all of them),
    /// root's own home, and any extra roots (a custom `--root`, the quarantine dir).
    public static func roots(extra: [String] = []) -> [String] {
        var out = [Paths.supportRoot.path, Paths.userRoot.path, "/private/var/root/Library/Application Support/Rampart"]
        for u in (try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? [] where !u.hasPrefix(".") {
            out.append("/Users/\(u)/Library/Application Support/Rampart")
        }
        out += extra.filter { $0.hasPrefix("/") && $0.count > 1 }
        var seen = Set<String>()
        return out.map { ($0 as NSString).standardizingPath }.filter { seen.insert($0).inserted }
    }

    /// True if `path` is inside one of our data folders. Also matches any user's folder by shape, so a home
    /// that wasn't present at start-up (or a non-/Users home) is still covered. Case-insensitive (APFS default).
    public static func contains(_ path: String, extra: [String] = []) -> Bool {
        let p = (path.hasPrefix("/tmp/") || path.hasPrefix("/var/") ? "/private" + path : path)
        let lp = (p as NSString).standardizingPath.lowercased()
        func under(_ root: String) -> Bool {
            let r = (root as NSString).standardizingPath.lowercased()
            return lp == r || lp.hasPrefix(r + "/")
        }
        if roots(extra: extra).contains(where: under) { return true }
        // /<anything>/Library/Application Support/Rampart[/...]
        if let r = lp.range(of: "/library/application support/rampart") {
            let rest = lp[r.upperBound...]
            return rest.isEmpty || rest.hasPrefix("/")
        }
        return false
    }
}
