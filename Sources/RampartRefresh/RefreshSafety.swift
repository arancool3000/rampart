import Foundation
import Darwin

/// Why the safety policy refused to touch a path. Checked again at clean time, whatever the scanner said.
public enum RefreshRefusal: String, Sendable, Equatable {
    case systemPath, appBundleInternals, keychain, rampartData, rootless, iCloud
    case openByProcess, outsideHome, protectedUserFolder, missing, symlink, homeItself
    case rampartDecoy
    /// o8: an item whose path is not where its category's files live (e.g. a "Homebrew" item in Documents).
    case outsideCategory
    /// o8: an iCloud / File Provider placeholder (dataless file or `.name.icloud` stub). Trashing it removes it everywhere.
    case cloudPlaceholder
    /// o8: the item or one of its folders changed between the safety check and the move (symlink swap, replaced item).
    case changedDuringClean

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
        case .rampartDecoy: return "A RamPart Cat & Mouse decoy (or a folder holding one). Turn decoys off in Cat & Mouse to remove them."
        case .outsideCategory: return "Not in the folder this kind of clean-up is allowed to touch."
        case .cloudPlaceholder: return "Kept in iCloud or another cloud service and not downloaded. Removing it here would remove it everywhere."
        case .changedDuringClean: return "It changed while RamPart was cleaning (for example, a folder was replaced by a link), so it was left alone."
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
    /// Cat & Mouse decoys and maze roots (DeceptionService.exclusions): never cleaned, nor any folder holding one.
    public var decoyPaths: [String]

    public init(home: String = NSHomeDirectory(), extraAllowedRoots: [String] = [], openFilesOverride: Set<String>? = nil,
                decoyPaths: [String] = []) {
        self.home = RefreshSafetyPolicy.normalize(home)
        self.decoyPaths = decoyPaths.filter { !$0.isEmpty }.map { RefreshSafetyPolicy.normalize($0) }
        self.extraAllowedRoots = extraAllowedRoots.map { RefreshSafetyPolicy.normalize($0) }
        self.openFilesOverride = openFilesOverride
    }

    static let systemPrefixes = ["/System", "/usr", "/bin", "/sbin", "/private/var/db", "/private/etc", "/Library/Apple",
                                 "/Library/Keychains", "/Library/Security", "/cores", "/dev", "/Volumes/Recovery"]
    static let personalTopFolders = ["Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Library",
                                     "Applications", "Public", "Sites", "Developer", ".Trash"]

    /// Pure path checks (no filesystem access): used by the scanner, the UI and the tests.
    /// o8: every comparison is case-insensitive, because APFS volumes usually are ("~/documents" is ~/Documents).
    public func pathRefusal(_ raw: String) -> RefreshRefusal? {
        let p = RefreshSafetyPolicy.normalize(raw)
        let lp = p.lowercased()
        let comps = lp.split(separator: "/").map(String.init)
        for s in Self.systemPrefixes.map({ $0.lowercased() }) where lp == s || lp.hasPrefix(s + "/") { return .systemPath }
        if ["/", "/applications", "/library", "/users", "/private", "/var", "/etc", "/tmp", "/opt", "/volumes"].contains(lp) { return .systemPath }
        if comps.contains(where: { $0.hasSuffix(".keychain") || $0.hasSuffix(".keychain-db") || $0 == "keychains" }) { return .keychain }
        // App bundle internals: any path strictly inside a .app (or framework/plugin bundle inside one).
        if let i = comps.firstIndex(where: { $0.hasSuffix(".app") }), i < comps.count - 1 { return .appBundleInternals }
        if lp.contains("/library/mobile documents") || lp.contains("/library/cloudstorage") || lp.contains("com~apple~clouddocs") { return .iCloud }
        if let last = comps.last, last.hasPrefix("."), last.hasSuffix(".icloud") { return .cloudPlaceholder }
        let rampartMarkers = ["/library/application support/rampart", "/library/caches/app.rampart", "/library/preferences/app.rampart",
                              "/library/logs/rampart", "/library/containers/app.rampart", "/library/caches/com.rampart",
                              "/library/preferences/com.rampart", "/library/application support/app.rampart",
                              "/library/launchagents/app.rampart", "/library/group containers/app.rampart"]
        if rampartMarkers.contains(where: { lp.contains($0) }) { return .rampartData }
        if decoyPaths.contains(where: { let d = $0.lowercased(); return d == lp || lp.hasPrefix(d + "/") || d.hasPrefix(lp + "/") }) { return .rampartDecoy }
        let lhome = home.lowercased()
        if lp == lhome { return .homeItself }
        let roots = [home] + extraAllowedRoots
        guard let root = roots.first(where: { lp.hasPrefix($0.lowercased() + "/") }) else {
            return lp.hasPrefix("/applications/") ? .appBundleInternals : .outsideHome
        }
        let rel = String(lp.dropFirst(root.count + 1))
        if root == home, Self.personalTopFolders.map({ $0.lowercased() }).contains(rel) { return .protectedUserFolder }
        if root == home, ["library/caches", "library/logs", "library/application support", "library/preferences",
                          "library/containers", "library/developer", "library/mail", "library/group containers",
                          "library/launchagents", "library/logs/diagnosticreports", "library/developer/xcode"].contains(rel) { return .protectedUserFolder }
        return nil
    }

    /// o8: where each category's items may live, relative to home. The cleaner refuses anything else, whatever the
    /// scanner (or a tampered `brew cleanup -n`) claimed. nil = no restriction beyond the path rules (none today).
    public static func categoryRoots(_ c: RefreshCategory) -> [String] {
        switch c {
        case .appCaches: return ["Library/Caches"]
        case .oldLogs: return ["Library/Logs"]
        case .crashReports: return ["Library/Logs/DiagnosticReports"]
        case .xcode: return ["Library/Developer"]
        case .projectBuilds: return [""]
        case .packageCaches: return ["Library/Caches/pip", "Library/Caches/Yarn", ".npm/_cacache", ".cargo/registry/cache",
                                     "go/pkg/mod/cache/download", "Library/Caches/go-build", "Library/Caches/pnpm", "Library/Caches/CocoaPods"]
        case .homebrew: return ["Library/Caches/Homebrew"]
        case .trash: return [".Trash"]
        case .oldDownloads: return ["Downloads"]
        case .duplicates, .largeOldFiles: return ["Downloads", "Desktop", "Documents", "Movies", "Music", "Pictures"]
        case .leftovers: return ["Library/Application Support", "Library/Preferences", "Library/Caches", "Library/Saved Application State",
                                 "Library/HTTPStorages", "Library/WebKit", "Library/Containers"]
        case .iosBackups: return ["Library/Application Support/MobileSync/Backup"]
        case .mailAttachments: return ["Library/Containers/com.apple.mail/Data/Library/Mail Downloads"]
        case .languagePacks, .localSnapshots: return []
        }
    }
    static let buildArtifactNames: Set<String> = [".build", "node_modules", "target", "__pycache__", ".venv", "venv"]

    /// o8: the category allowlist. Pure path check; `extraAllowedRoots` count as home for test fixtures.
    public func categoryRefusal(_ raw: String, _ c: RefreshCategory) -> RefreshRefusal? {
        let lp = RefreshSafetyPolicy.normalize(raw).lowercased()
        let homes = ([home] + extraAllowedRoots).map { $0.lowercased() }
        for h in homes {
            for r in Self.categoryRoots(c) {
                let base = r.isEmpty ? h : h + "/" + r.lowercased()
                // Package caches are offered as whole folders (the listed roots themselves); every other root is a container.
                guard lp.hasPrefix(base + "/") || (c == .packageCaches && lp == base) else { continue }
                if c == .projectBuilds {
                    let last = (lp as NSString).lastPathComponent
                    let top = lp.dropFirst(h.count + 1).split(separator: "/").first.map(String.init) ?? ""
                    guard Self.buildArtifactNames.contains(last), top != "library", top != ".trash" else { continue }
                }
                return nil
            }
        }
        return .outsideCategory
    }

    /// o8: Cat & Mouse decoys when the helper's live list is unavailable: the user-mode registry plus the maze root.
    /// Over-protecting is harmless (Refresh only skips these); missing a decoy is not.
    public static func fallbackDecoyPaths(home: String = NSHomeDirectory()) -> [String] {
        var out = [home + "/Documents/Private"]
        for dir in ["Library/Application Support/RamPart/deception", "Library/Application Support/Rampart/deception"] {
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: home + "/" + dir + "/decoys.json")),
                  let list = try? JSONSerialization.jsonObject(with: d) as? [[String: Any]] else { continue }
            out += list.compactMap { $0["path"] as? String }
        }
        return out
    }

    /// SF_DATALESS: a File Provider / iCloud placeholder whose contents live only in the cloud.
    static let dataless: UInt32 = 0x40000000

    /// Full check before anything is moved: path rules, existence, symlinks, SIP xattr (recursively for folders, bounded), open files.
    public func refusal(_ raw: String) -> RefreshRefusal? {
        if let r = pathRefusal(raw) { return r }
        let p = RefreshSafetyPolicy.normalize(raw)
        var st = stat()
        guard lstat(p, &st) == 0 else { return .missing }
        if st.st_flags & Self.dataless != 0 { return .cloudPlaceholder }
        if (st.st_mode & S_IFMT) == S_IFLNK {
            // Moving a link moves only the link (target never followed), but the folder holding it must itself pass:
            // ~/Library/Caches/x -> ~/Documents must not make ~/Documents/report.pdf cleanable as ".../x/report.pdf".
            let parent = (p as NSString).deletingLastPathComponent
            guard let rp = Self.realPath(parent) else { return .missing }
            if rp != parent, let r = pathRefusal(rp + "/" + (p as NSString).lastPathComponent) { return r == .homeItself ? .symlink : r }
            return nil
        }
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
            if Self.containsDataless(p, limit: 4000) { return .cloudPlaceholder }
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

    /// o8: a folder holding cloud placeholders (dataless files or `.x.icloud` stubs) is never trashed as a whole.
    static func containsDataless(_ dir: String, limit: Int) -> Bool {
        guard let e = FileManager.default.enumerator(atPath: dir) else { return false }
        var n = 0
        while let rel = e.nextObject() as? String {
            n += 1; if n > limit { break }
            let name = (rel as NSString).lastPathComponent
            if name.hasPrefix("."), name.lowercased().hasSuffix(".icloud") { return true }
            var st = stat()
            if lstat(dir + "/" + rel, &st) == 0, st.st_flags & dataless != 0 { return true }
        }
        return false
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
