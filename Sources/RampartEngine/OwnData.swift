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
        if isAppleSecurityRuleData(path) { return true }
        // /<anything>/Library/Application Support/Rampart[/...]
        if let r = lp.range(of: "/library/application support/rampart") {
            let rest = lp[r.upperBound...]
            return rest.isEmpty || rest.hasPrefix("/")
        }
        return false
    }

    /// Apple's XProtect rule/data files contain the very byte patterns they detect, so scanning them is a
    /// guaranteed false positive. Exempt a file ONLY if all hold, so malware can't hide by looking like Apple:
    /// - it is inside an XProtect bundle under /Library/Apple or /var/protected/xprotect;
    /// - it is a rule/data file (.yara, .yr, .db, .plist, .bundle metadata), never a Mach-O or script;
    /// - it carries the SIP restricted flag (SF_RESTRICTED), so only Apple-signed updates can write it.
    public static func isAppleSecurityRuleData(_ path: String) -> Bool {
        let lp = norm(path)
        let roots = ["/library/apple/system/library/coreservices/xprotect.bundle/", "/var/protected/xprotect/xprotect.bundle/",
                     "/private/var/protected/xprotect/xprotect.bundle/"]
        guard roots.contains(where: { lp.hasPrefix($0) }) else { return false }
        let ext = (lp as NSString).pathExtension
        guard ["yara", "yr", "db", "plist", "strings", "json"].contains(ext) else { return false }
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }
        if (st.st_flags & UInt32(SF_RESTRICTED)) != 0 { return true }
        // /var/protected copies carry no SIP flag and aren't code-signed: exempt only a root-owned, not group/other
        // writable file that is byte-identical to the SIP-protected copy of the same file under /Library/Apple.
        guard st.st_uid == 0, (st.st_mode & (S_IWGRP | S_IWOTH)) == 0,
              let r = path.range(of: "XProtect.bundle/", options: .caseInsensitive) else { return false }
        let twin = "/Library/Apple/System/Library/CoreServices/XProtect.bundle/" + path[r.upperBound...]
        var tst = stat()
        guard lstat(twin, &tst) == 0, (tst.st_flags & UInt32(SF_RESTRICTED)) != 0, tst.st_size == st.st_size else { return false }
        return sameContents(path, twin)
    }

    private static let cmpLock = NSLock()
    nonisolated(unsafe) private static var cmpCache: [String: (Date, Bool)] = [:]
    /// Byte-for-byte comparison (memory-mapped), cached by modification date.
    static func sameContents(_ a: String, _ b: String) -> Bool {
        let key = a + "|" + b
        let m = (try? FileManager.default.attributesOfItem(atPath: a)[.modificationDate] as? Date) ?? .distantPast
        cmpLock.lock(); if let c = cmpCache[key], c.0 == m { cmpLock.unlock(); return c.1 }; cmpLock.unlock()
        let ok: Bool = {
            guard let da = try? Data(contentsOf: URL(fileURLWithPath: a), options: .alwaysMapped),
                  let db = try? Data(contentsOf: URL(fileURLWithPath: b), options: .alwaysMapped) else { return false }
            return da == db
        }()
        cmpLock.lock(); cmpCache[key] = (m, ok); cmpLock.unlock()
        return ok
    }
}
