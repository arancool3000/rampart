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
        out += registeredRoots()
        out += extra.filter { $0.hasPrefix("/") && $0.count > 1 }
        var seen = Set<String>()
        return out.filter { seen.insert(norm($0)).inserted }
    }

    private static let regLock = NSLock()
    nonisolated(unsafe) private static var registered: [String] = []
    /// Adds a data root for this process (a custom `--root`, a test fixture). Never derived from file contents.
    public static func register(root: String) {
        guard root.hasPrefix("/"), root.count > 1 else { return }
        regLock.lock(); if !registered.contains(root) { registered.append(root) }; regLock.unlock()
    }
    public static func unregister(root: String) { regLock.lock(); registered.removeAll { $0 == root }; regLock.unlock() }
    static func registeredRoots() -> [String] { regLock.lock(); defer { regLock.unlock() }; return registered }

    /// o10: the shape match is anchored to a real home (`/Users/<name>` or root's `/private/var/root`). It used to
    /// match `/<anything>/Library/Application Support/Rampart`, so malware could hide from every scan in
    /// `/tmp/x/Library/Application Support/Rampart/` or on a USB stick with that layout.
    static let homeShape = try! NSRegularExpression(pattern: #"^(/users/[^/]+|/private/var/root)/library/application support/rampart(?=/|$)"#)

    /// The own-data root `path` is under and the normalised path (both lowercased), or nil.
    static func ownRoot(_ path: String, extra: [String] = []) -> (root: String, path: String)? {
        var p = path
        if p.split(separator: "/", omittingEmptySubsequences: false).contains(where: { $0 == ".." || $0 == "." }) {
            p = (p as NSString).standardizingPath
        }
        let lp = norm(p)
        for root in roots(extra: extra) {
            let r = norm(root)
            if lp == r || lp.hasPrefix(r + "/") { return (r, lp) }
        }
        let ns = lp as NSString
        if let m = homeShape.firstMatch(in: lp, range: NSRange(location: 0, length: ns.length)) { return (ns.substring(with: m.range), lp) }
        return nil
    }

    /// True if `path` is inside one of our data folders. Also matches any user's folder by shape, so a home
    /// that wasn't present at start-up is still covered. Case-insensitive (APFS default).
    /// o10: RamPart never keeps programs in its data folders (vault items are encrypted, mode 0600), so a file
    /// there that looks runnable (exec bit, Mach-O or `#!`) is not treated as own data and is scanned like any
    /// other. The vault's transient `staging/` folder (plaintext items mid-quarantine) stays exempt.
    public static func contains(_ path: String, extra: [String] = []) -> Bool {
        if let (root, lp) = ownRoot(path, extra: extra) {
            let rest = lp.count > root.count ? String(lp.dropFirst(root.count)) : ""
            if rest.hasPrefix("/staging/") || rest == "/staging" { return true }
            return !looksRunnable(path)
        }
        return isAppleSecurityRuleData(path)
    }

    /// True for a directory that is one of our data roots (or inside one): walks skip it but sweep it for programs.
    public static func isOwnDataDirectory(_ path: String) -> Bool { ownRoot(path) != nil }

    static let machOMagics: Set<UInt32> = [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca, 0xcafebabf, 0xbfbafeca]

    /// A regular file with an exec bit, a Mach-O / universal header, or a `#!` line. Symlinks are never followed.
    public static func looksRunnable(_ path: String) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }
        if st.st_mode & 0o111 != 0 { return true }
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var b = [UInt8](repeating: 0, count: 4)
        guard read(fd, &b, 4) == 4 else { return false }
        if b[0] == 0x23 && b[1] == 0x21 { return true }
        let be = UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3])
        return machOMagics.contains(be)
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
            // Chunked reads, not mmap: a mapped file that shrinks mid-compare raises SIGBUS and kills the scanner.
            guard let ha = FileHandle(forReadingAtPath: a), let hb = FileHandle(forReadingAtPath: b) else { return false }
            defer { try? ha.close(); try? hb.close() }
            while true {
                // `read(upToCount:)` may return nil or empty Data at end of file.
                let ca = (try? ha.read(upToCount: 1 << 20)) ?? Data(), cb = (try? hb.read(upToCount: 1 << 20)) ?? Data()
                if ca != cb { return false }
                if ca.isEmpty { return true }
            }
        }()
        cmpLock.lock(); cmpCache[key] = (m, ok); cmpLock.unlock()
        return ok
    }
}
