import Foundation
import Darwin

// Download Gate file operations that never go through a symbolic link (wms-o2).
//
// The gate works on paths the downloading process (or anything else running as the user) can rename at any time.
// Every chmod / xattr change therefore opens the parent folder with O_NOFOLLOW_ANY (no link in ANY component, so a
// swapped "Contents" or "MacOS" folder can't redirect it) and changes the file through a descriptor, checking that it
// is still the same inode the gate recorded.
enum GateFS {
    /// O_NOFOLLOW_ANY (macOS 11+): fail with ELOOP if any path component is a symbolic link.
    static let noFollowAny: Int32 = 0x2000_0000

    static func id(_ st: Darwin.stat) -> String { "\(st.st_dev):\(st.st_ino)" }

    /// The parent folder opened without following any link, plus the last component.
    static func openParent(_ path: String) -> (fd: Int32, name: String)? {
        let name = (path as NSString).lastPathComponent
        guard path.hasPrefix("/"), !name.isEmpty, name != ".", name != "..", !name.contains("\0") else { return nil }
        let fd = open((path as NSString).deletingLastPathComponent, O_RDONLY | O_DIRECTORY | O_CLOEXEC | noFollowAny)
        return fd >= 0 ? (fd, name) : nil
    }

    /// lstat that also refuses a link in any parent component.
    static func lstatStrict(_ path: String) -> Darwin.stat? {
        guard let (dfd, name) = openParent(path) else { return nil }
        defer { close(dfd) }
        var st = Darwin.stat()
        return fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 ? st : nil
    }

    /// Applies `transform` to the mode of the regular file at `path` (never through a link). When `expectID` is set
    /// the file must still be that inode. `transform` returns nil for "leave it". Returns the stat before the change,
    /// or nil when nothing was (or could be) changed safely.
    @discardableResult
    static func setMode(_ path: String, expectID: String? = nil, _ transform: (mode_t) -> mode_t?) -> Darwin.stat? {
        guard let (dfd, name) = openParent(path) else { return nil }
        defer { close(dfd) }
        let fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        if fd >= 0 {
            defer { close(fd) }
            var st = Darwin.stat()
            guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, expectID == nil || id(st) == expectID else { return nil }
            guard let m = transform(st.st_mode & 0o7777) else { return st }
            return fchmod(fd, m) == 0 ? st : nil
        }
        // No read permission (e.g. mode 0111): use the name, still relative to the pinned folder and never a link.
        var st = Darwin.stat()
        guard fstatat(dfd, name, &st, AT_SYMLINK_NOFOLLOW) == 0, st.st_mode & S_IFMT == S_IFREG,
              expectID == nil || id(st) == expectID else { return nil }
        guard let m = transform(st.st_mode & 0o7777) else { return st }
        return fchmodat(dfd, name, m, AT_SYMLINK_NOFOLLOW) == 0 ? st : nil
    }

    /// Opens a file or folder for xattr work without following any link.
    private static func openForXattr(_ path: String) -> Int32 {
        guard let (dfd, name) = openParent(path) else { return -1 }
        defer { close(dfd) }
        return openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
    }

    static func hasXattr(_ path: String, _ attr: String) -> Bool {
        let fd = openForXattr(path)
        if fd >= 0 { defer { close(fd) }; return fgetxattr(fd, attr, nil, 0, 0, 0) >= 0 }
        return lstatStrict(path) != nil && getxattr(path, attr, nil, 0, 0, XATTR_NOFOLLOW) >= 0
    }

    /// Sets `attr` only when missing (XATTR_CREATE), through a descriptor.
    static func addXattrIfMissing(_ path: String, _ attr: String, _ value: String) -> Bool {
        let fd = openForXattr(path)
        if fd >= 0 {
            defer { close(fd) }
            if fgetxattr(fd, attr, nil, 0, 0, 0) >= 0 { return false }
            return value.withCString { fsetxattr(fd, attr, $0, strlen($0), 0, XATTR_CREATE) } == 0
        }
        guard lstatStrict(path) != nil, getxattr(path, attr, nil, 0, 0, XATTR_NOFOLLOW) < 0 else { return false }
        return value.withCString { setxattr(path, attr, $0, strlen($0), 0, XATTR_NOFOLLOW | XATTR_CREATE) } == 0
    }

    /// Reads up to `max` bytes of a regular file without following any link.
    static func readSmall(_ path: String, max: Int = 1 << 20) -> Data? {
        guard let (dfd, name) = openParent(path) else { return nil }
        defer { close(dfd) }
        let fd = openat(dfd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var st = Darwin.stat()
        guard fstat(fd, &st) == 0, st.st_mode & S_IFMT == S_IFREG, st.st_size <= max else { return nil }
        var buf = [UInt8](repeating: 0, count: Int(st.st_size))
        let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
        return n >= 0 ? Data(buf.prefix(n)) : nil
    }

    /// Every regular file below `dir` that has an execute bit (never following links; capped).
    static func executableFiles(under dir: String, maxEntries: Int = 20_000, maxDepth: Int = 32) -> [String] {
        let top = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC | noFollowAny)
        guard top >= 0 else { return [] }
        var out: [String] = []
        var seen = 0
        func walk(_ fd: Int32, _ path: String, _ depth: Int) {
            guard depth <= maxDepth, seen < maxEntries else { return }
            let dupfd = dup(fd)
            guard dupfd >= 0, let d = fdopendir(dupfd) else { if dupfd >= 0 { close(dupfd) }; return }
            var names: [String] = []
            while let e = readdir(d) {
                let n = withUnsafePointer(to: e.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
                if n != "." && n != ".." { names.append(n) }
            }
            closedir(d)
            for n in names.sorted() {
                seen += 1
                if seen > maxEntries { return }
                var st = Darwin.stat()
                guard fstatat(fd, n, &st, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
                let p = path + "/" + n
                switch st.st_mode & S_IFMT {
                case S_IFREG: if st.st_mode & 0o111 != 0 { out.append(p) }
                case S_IFDIR:
                    let sub = openat(fd, n, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    if sub >= 0 { walk(sub, p, depth + 1); close(sub) }
                default: break
                }
            }
        }
        walk(top, dir, 0)
        close(top)
        return out
    }

    /// `CFBundleExecutable` from the bundle's Info.plist (read without following links).
    static func bundleExecutableName(_ app: String) -> String? {
        guard let d = readSmall(app + "/Contents/Info.plist"),
              let p = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { return nil }
        return p["CFBundleExecutable"] as? String
    }

    /// The main executable named by Info.plist, if it is a plain name (no "/" or "..") that points at Contents/MacOS.
    /// Anything else is an anomaly: LaunchServices would run a file the gate didn't look at.
    static func mainExecutable(_ app: String) -> (path: String?, anomaly: Bool) {
        guard let name = bundleExecutableName(app) else { return (nil, false) }
        if name.isEmpty || name.contains("/") || name == "." || name == ".." || name.contains("\0") { return (nil, true) }
        return (app + "/Contents/MacOS/" + name, false)
    }
}
