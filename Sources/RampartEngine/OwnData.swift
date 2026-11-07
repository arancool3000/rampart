import Foundation
import RampartShared

/// RamPart's own data folders (state, quarantine vault, DB, journal). Never scanned and never reported,
/// whoever asks: the vault holds the very files we detected (EICAR fixtures, malware), encrypted or not.
public enum OwnData {
    /// Lowercased, /private-prefixed (/tmp, /var, /etc), no trailing slash. Not `standardizingPath`, which strips /private.
    static func norm(_ p: String) -> String {
        var s = p
        for a in ["/tmp", "/var", "/etc"] where s == a || s.hasPrefix(a + "/") { s = "/private" + s; break }
        while s.count > 1 && s.hasSuffix("/") { s.removeLast() }
        return s.lowercased()
    }

    /// System root, this user's root, every local user's root (the root daemon sees all of them),
    /// root's own home, and any extra roots (a custom `--root`, the quarantine dir).
    /// Computed once per process (lists /Users); `contains` also matches by shape for homes added later.
    static let baseRoots: [String] = {
        var out = [Paths.supportRoot.path, Paths.userRoot.path, "/private/var/root/Library/Application Support/Rampart"]
        for u in (try? FileManager.default.contentsOfDirectory(atPath: "/Users")) ?? [] where !u.hasPrefix(".") {
            out.append("/Users/\(u)/Library/Application Support/Rampart")
        }
        return out
    }()

    public static func roots(extra: [String] = []) -> [String] {
        var out = baseRoots
        out += extra.filter { $0.hasPrefix("/") && $0.count > 1 }
        var seen = Set<String>()
        return out.filter { seen.insert(norm($0)).inserted }
    }

    /// True if `path` is inside one of our data folders. Also matches any user's folder by shape, so a home
    /// that wasn't present at start-up (or a non-/Users home) is still covered. Case-insensitive (APFS default).
    public static func contains(_ path: String, extra: [String] = []) -> Bool {
        let lp = norm(path)
        func under(_ root: String) -> Bool { let r = norm(root); return lp == r || lp.hasPrefix(r + "/") }
        if roots(extra: extra).contains(where: under) { return true }
        // /<anything>/Library/Application Support/Rampart[/...]
        if let r = lp.range(of: "/library/application support/rampart") {
            let rest = lp[r.upperBound...]
            return rest.isEmpty || rest.hasPrefix("/")
        }
        return false
    }
}
