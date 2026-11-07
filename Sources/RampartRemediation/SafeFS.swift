import Foundation
import Darwin

/// Descriptor-pinned file operations for code that runs as root on paths a user controls (hx3 hardening).
///
/// The pattern: open the parent folder once with O_NOFOLLOW, confirm with F_GETPATH that it is really the folder
/// that was checked (no symlink anywhere in the path), then do every create/rename/unlink relative to that
/// descriptor. Later swaps of any path component can't redirect the operation.
public enum SafeFS {
    /// An open folder plus the real path the kernel reports for it.
    public final class PinnedDir: @unchecked Sendable {
        public let fd: Int32
        public let realPath: String
        init(fd: Int32, realPath: String) { self.fd = fd; self.realPath = realPath }
        deinit { close(fd) }
        public func stat() -> Darwin.stat? { var st = Darwin.stat(); return fstat(fd, &st) == 0 ? st : nil }
    }

    /// "/private/tmp/x" and "/tmp/x" name the same place; anything else that differs is a link.
    public static func samePath(_ a: String, _ b: String) -> Bool {
        a == b || a == "/private" + b || "/private" + a == b
    }

    /// Opens `dir` without following a symlink at any component (checked by comparing F_GETPATH with `dir`).
    public static func pin(_ dir: String) throws -> PinnedDir {
        let norm = normalizePath(dir)
        let fd = open(norm, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { throw RemediationError.ioError("open \(norm): \(String(cString: strerror(errno)))") }
        var buf = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        guard fcntl(fd, F_GETPATH, &buf) == 0 else { close(fd); throw RemediationError.ioError("F_GETPATH \(norm)") }
        let real = String(cString: buf)
        guard samePath(real, norm) else {
            close(fd)
            throw RemediationError.ioError("folder \(norm) resolves to \(real); refusing to work through a link")
        }
        return PinnedDir(fd: fd, realPath: real)
    }

    /// A single safe path component (no "/", not "." or "..", no NUL).
    public static func isPlainName(_ n: String) -> Bool {
        !n.isEmpty && n != "." && n != ".." && !n.contains("/") && !n.contains("\0")
    }

    /// Creates `name` in `dir` exclusively (never follows or replaces), writes `data`, optionally chowns, then
    /// sets `mode`. The owner is set before any content-dependent bits so no window exists with the wrong owner.
    public static func createFile(in dir: PinnedDir, name: String, data: Data, mode: mode_t,
                                  owner: (uid_t, gid_t)? = nil) throws {
        guard isPlainName(name) else { throw RemediationError.ioError("bad file name") }
        let fd = openat(dir.fd, name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else {
            throw errno == EEXIST ? RemediationError.destinationExists(name)
                                  : RemediationError.ioError("create \(name): \(String(cString: strerror(errno)))")
        }
        var ok = true
        if let o = owner, getuid() == 0 { ok = fchown(fd, o.0, o.1) == 0 }
        if ok { ok = data.withUnsafeBytes { data.isEmpty || write(fd, $0.baseAddress, data.count) == data.count } }
        if ok { ok = fchmod(fd, mode & 0o0777) == 0 }   // never setuid/setgid/sticky via this helper
        fsync(fd); close(fd)
        if !ok { unlinkat(dir.fd, name, 0); throw RemediationError.ioError("write \(name)") }
    }

    /// Mode bits for a restored copy. Set-user-ID and set-group-ID are always dropped when the item goes anywhere other
    /// than where it came from, or to a different owner: a restore must never mint a setuid program in a user folder.
    public static func restoredMode(_ mode: mode_t, keepSpecialBits: Bool) -> mode_t {
        keepSpecialBits ? (mode & 0o7777) : (mode & 0o1777)
    }

    /// Visits every entry below `dirfd` without ever following a symlink (openat O_NOFOLLOW + fstatat
    /// AT_SYMLINK_NOFOLLOW). `visit` gets (parent fd, name, lstat). Refuses deeper than `maxDepth` or more than
    /// `maxEntries` entries. Returns the number of entries visited.
    @discardableResult
    public static func walkTree(dirfd: Int32, maxDepth: Int = 64, maxEntries: Int = 200_000,
                                visit: (Int32, String, Darwin.stat) throws -> Void) throws -> Int {
        var count = 0
        func walk(_ fd: Int32, depth: Int) throws {
            guard depth <= maxDepth else { throw RemediationError.unsupported("folder nesting too deep") }
            let dupfd = dup(fd)
            guard dupfd >= 0 else { throw RemediationError.ioError("dup") }
            guard let d = fdopendir(dupfd) else { close(dupfd); throw RemediationError.ioError("fdopendir") }
            var names: [String] = []
            while let e = readdir(d) {
                let n = withUnsafePointer(to: e.pointee.d_name) { $0.withMemoryRebound(to: CChar.self, capacity: 1024) { String(cString: $0) } }
                if n != "." && n != ".." { names.append(n) }
            }
            closedir(d)
            for n in names {
                count += 1
                guard count <= maxEntries else { throw RemediationError.unsupported("too many files") }
                var st = Darwin.stat()
                guard fstatat(fd, n, &st, AT_SYMLINK_NOFOLLOW) == 0 else { continue }
                try visit(fd, n, st)
                if st.st_mode & S_IFMT == S_IFDIR {
                    let sub = openat(fd, n, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                    guard sub >= 0 else { continue }
                    defer { close(sub) }
                    try walk(sub, depth: depth + 1)
                }
            }
        }
        try walk(dirfd, depth: 0)
        return count
    }

    /// Drops setuid/setgid bits and optionally changes the owner of every entry below `dirfd` (never through a link).
    @discardableResult
    public static func sanitizeTree(dirfd: Int32, owner: (uid_t, gid_t)?) throws -> Int {
        try walkTree(dirfd: dirfd) { parent, name, st in
            if let o = owner, getuid() == 0 { fchownat(parent, name, o.0, o.1, AT_SYMLINK_NOFOLLOW) }
            if st.st_mode & S_IFMT != S_IFLNK, st.st_mode & (S_ISUID | S_ISGID) != 0 {
                fchmodat(parent, name, st.st_mode & 0o1777, AT_SYMLINK_NOFOLLOW)
            }
        }
    }

    /// A regular file with more than one hard link may share its inode with a file the caller can't read
    /// (e.g. a link to a root-only file planted in a user folder). Root must not read, chmod or archive it.
    public static func isForeignHardLink(_ st: Darwin.stat, expectedOwner: uid_t) -> Bool {
        st.st_mode & S_IFMT == S_IFREG && st.st_nlink > 1 && st.st_uid != expectedOwner
    }

    /// Runs `tool` with its working directory set from a descriptor (posix_spawn fchdir), so a relative
    /// destination like "." can't be redirected by renaming path components. Returns the exit status.
    public static func runInDir(_ tool: String, _ args: [String], cwdFD: Int32, timeout: TimeInterval = 120) -> Int32 {
        var fa: posix_spawn_file_actions_t? = nil
        posix_spawn_file_actions_init(&fa); defer { posix_spawn_file_actions_destroy(&fa) }
        posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0)
        posix_spawn_file_actions_addopen(&fa, 1, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addopen(&fa, 2, "/dev/null", O_WRONLY, 0)
        posix_spawn_file_actions_addfchdir_np(&fa, cwdFD)
        var attr: posix_spawnattr_t? = nil
        posix_spawnattr_init(&attr); defer { posix_spawnattr_destroy(&attr) }
        posix_spawnattr_setflags(&attr, Int16(POSIX_SPAWN_CLOEXEC_DEFAULT))
        var cargs = ([tool] + args).map { strdup($0) } + [nil]
        defer { cargs.forEach { free($0) } }
        var env: [UnsafeMutablePointer<CChar>?] = [strdup("PATH=/usr/bin:/bin"), nil]
        defer { env.forEach { free($0) } }
        var pid: pid_t = 0
        guard posix_spawn(&pid, tool, &fa, &attr, &cargs, &env) == 0 else { return -1 }
        let deadline = Date().addingTimeInterval(timeout)
        var status: Int32 = 0
        while true {
            let r = waitpid(pid, &status, WNOHANG)
            if r == pid { break }
            if r < 0 { return -1 }
            if Date() > deadline { kill(pid, SIGKILL); _ = waitpid(pid, &status, 0); return -1 }
            usleep(20_000)
        }
        return (status & 0x7f) == 0 ? (status >> 8) & 0xff : -1
    }
}
