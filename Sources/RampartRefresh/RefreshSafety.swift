import Foundation
import Darwin

/// Why the safety policy refused to touch a path. Checked again at clean time, whatever the scanner said.
public enum RefreshRefusal: String, Sendable, Equatable {
    case systemPath, appBundleInternals, keychain, rampartData, rootless, iCloud
    case openByProcess, outsideHome, protectedUserFolder, missing, symlink, homeItself

    public var explanation: String {
        switch self {
        case .systemPath: return "Part of macOS. RamPart never touches system folders."
        case .appBundleInternals: return "Inside an app. Changing an app's contents breaks its code signature."
        case .keychain: return "A keychain holds your passwords and is never touched."
        case .rampartData: return "RamPart's own data."
        case .rootless: return "Protected by System Integrity Protection."
        case .iCloud: return "Stored in iCloud Drive. Removing it here would remove it on all your devices."
        case .openByProcess: return "An app has this file open right now."
        case .outsideHome: return "Outside your home folder."
        case .protectedUserFolder: return "A top-level personal folder (such as Documents or Desktop) is never removed as a whole."
        case .missing: return "No longer exists."
        case .symlink: return "A link that points somewhere else; the link target is never followed."
        case .homeItself: return "Your home folder."
        }
    }
}

/// The last line of defence. Pure path checks first, then filesystem checks (xattr, open files).
public struct RefreshSafetyPolicy: Sendable {
    public var home: String
    /// Extra roots outside home that tests may use (scratch fixtures). Production leaves this empty.
    public var extraAllowedRoots: [String]
    /// Paths of files currently open by any process we can see. nil = query libproc at check time.
    public var openFilesOverride: Set<String>?

    public init(home: String = NSHomeDirectory(), extraAllowedRoots: [String] = [], openFilesOverride: Set<String>? = nil) {
        self.home = RefreshSafetyPolicy.normalize(home)
        self.extraAllowedRoots = extraAllowedRoots.map { RefreshSafetyPolicy.normalize($0) }
        self.openFilesOverride = openFilesOverride
    }

    static let systemPrefixes = ["/System", "/usr", "/bin", "/sbin", "/private/var/db", "/private/etc", "/Library/Apple",
                                 "/Library/Keychains", "/Library/Security", "/cores", "/dev", "/Volumes/Recovery"]
    static let personalTopFolders = ["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library",
                                     "Applications", "Public", "Sites", "Developer", ".Trash"]

    /// Pure path checks (no filesystem access): used by the scanner, the UI and the tests.
    public func pathRefusal(_ raw: String) -> RefreshRefusal? {
        let p = RefreshSafetyPolicy.normalize(raw)
        let comps = p.split(separator: "/").map(String.init)
        for s in Self.systemPrefixes where p == s || p.hasPrefix(s + "/") { return .systemPath }
        if p == "/" || p == "/Applications" || p == "/Library" || p == "/Users" { return .systemPath }
        if comps.contains(where: { $0.lowercased().hasSuffix(".keychain") || $0.lowercased().hasSuffix(".keychain-db") || $0 == "Keychains" }) { return .keychain }
        // App bundle internals: any path strictly inside a .app (or framework/plugin bundle inside one).
        if let i = comps.firstIndex(where: { $0.hasSuffix(".app") }), i < comps.count - 1 { return .appBundleInternals }
        if p.contains("/Library/Mobile Documents") || p.contains("/Library/CloudStorage/iCloud") || p.contains("com~apple~CloudDocs") { return .iCloud }
        let rampartMarkers = ["/Library/Application Support/Rampart", "/Library/Application Support/RamPart", "/Library/Caches/app.rampart",
                              "/Library/Preferences/app.rampart", "/Library/Logs/Rampart", "/Library/Containers/app.rampart",
                              "/Library/Caches/com.rampart", "/Library/Preferences/com.rampart"]
        if rampartMarkers.contains(where: { p.contains($0) }) { return .rampartData }
        if p == home { return .homeItself }
        let roots = [home] + extraAllowedRoots
        guard let root = roots.first(where: { p.hasPrefix($0 + "/") }) else {
            return p.hasPrefix("/Applications/") ? .appBundleInternals : .outsideHome
        }
        let rel = String(p.dropFirst(root.count + 1))
        if root == home, Self.personalTopFolders.contains(rel) { return .protectedUserFolder }
        if root == home, ["Library/Caches", "Library/Logs", "Library/Application Support", "Library/Preferences",
                          "Library/Containers", "Library/Developer", "Library/Mail"].contains(rel) { return .protectedUserFolder }
        return nil
    }

    /// Full check before anything is moved: path rules, existence, symlinks, SIP xattr (recursively for folders, bounded), open files.
    public func refusal(_ raw: String) -> RefreshRefusal? {
        if let r = pathRefusal(raw) { return r }
        let p = RefreshSafetyPolicy.normalize(raw)
        var st = stat()
        guard lstat(p, &st) == 0 else { return .missing }
        if (st.st_mode & S_IFMT) == S_IFLNK { return nil }   // moving a link moves only the link: allowed, target never followed
        // Resolved location must still pass (catches parent-directory symlinks into /System, iCloud, etc.).
        let resolved = Self.realPath(p) ?? p
        if resolved != p, let r = pathRefusal(resolved) { return r == .homeItself ? .symlink : r }
        if Self.hasRootless(p) { return .rootless }
        let open = openFilesOverride ?? OpenFiles.snapshot()
        let isDir = (st.st_mode & S_IFMT) == S_IFDIR
        if open.contains(p) || open.contains(resolved) { return .openByProcess }
        if isDir {
            let prefix = p + "/", rprefix = resolved + "/"
            if open.contains(where: { $0.hasPrefix(prefix) || $0.hasPrefix(rprefix) }) { return .openByProcess }
            if Self.containsRootless(p, limit: 4000) { return .rootless }
        }
        return nil
    }

    /// Lexical normalisation (".", "..", "//", trailing "/"). Unlike NSString.standardizingPath it keeps "/private",
    /// so paths compare equal to what the kernel and libproc report.
    public static func normalize(_ p: String) -> String {
        var out: [Substring] = []
        for c in p.split(separator: "/", omittingEmptySubsequences: true) {
            if c == "." { continue }
            if c == ".." { if !out.isEmpty { out.removeLast() }; continue }
            out.append(c)
        }
        return "/" + out.joined(separator: "/")
    }

    /// Fully resolved path as the kernel reports it (keeps /private, unlike NSString.resolvingSymlinksInPath).
    public static func realPath(_ p: String) -> String? {
        guard let r = Darwin.realpath(p, nil) else { return nil }
        defer { free(r) }
        return String(cString: r)
    }

    public static func hasRootless(_ p: String) -> Bool {
        getxattr(p, "com.apple.rootless", nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    static func containsRootless(_ dir: String, limit: Int) -> Bool {
        guard let e = FileManager.default.enumerator(atPath: dir) else { return false }
        var n = 0
        while let rel = e.nextObject() as? String {
            n += 1; if n > limit { break }
            if hasRootless(dir + "/" + rel) { return true }
        }
        return false
    }
}

/// Files currently open by processes we can inspect (libproc; the current user's processes when unprivileged).
public enum OpenFiles {
    public static func snapshot() -> Set<String> {
        var out = Set<String>()
        let n = proc_listallpids(nil, 0)
        guard n > 0 else { return out }
        var pids = [Int32](repeating: 0, count: Int(n) + 64)
        let got = pids.withUnsafeMutableBytes { proc_listallpids($0.baseAddress, Int32($0.count)) }
        guard got > 0 else { return out }
        let fdSize = MemoryLayout<proc_fdinfo>.stride
        for pid in pids.prefix(Int(got)) where pid > 0 {
            let bytes = proc_pidinfo(pid, PROC_PIDLISTFDS, 0, nil, 0)
            guard bytes > 0 else { continue }
            var fds = [proc_fdinfo](repeating: proc_fdinfo(), count: Int(bytes) / fdSize + 16)
            let used = fds.withUnsafeMutableBytes { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, $0.baseAddress, Int32($0.count)) }
            guard used > 0 else { continue }
            for fd in fds.prefix(Int(used) / fdSize) where fd.proc_fdtype == UInt32(PROX_FDTYPE_VNODE) {
                var vi = vnode_fdinfowithpath()
                let sz = Int32(MemoryLayout<vnode_fdinfowithpath>.size)
                guard proc_pidfdinfo(pid, fd.proc_fd, PROC_PIDFDVNODEPATHINFO, &vi, sz) == sz else { continue }
                let path = withUnsafeBytes(of: vi.pvip.vip_path) { raw in String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self) }
                if !path.isEmpty { out.insert(path) }
            }
        }
        return out
    }
}
