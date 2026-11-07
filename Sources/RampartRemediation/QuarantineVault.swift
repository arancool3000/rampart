import Foundation
import CryptoKit
import RampartShared

/// Extended metadata stored next to each quarantined item, signed with HMAC-SHA256.
public struct VaultItemMetadata: Codable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable { case quarantined, restored, purged }
    public var record: QuarantineRecord
    public var groupID: UInt32
    public var flags: UInt32
    public var inode: UInt64
    public var isDirectory: Bool
    /// Extended attributes removed from the sample (name -> raw bytes).
    public var xattrs: [String: Data]
    public var compressed: Bool
    public var status: Status
    public var restoredAt: Date?
    public var restoredTo: String?
    public var formatVersion: Int
}

/// On-disk sidecar: exact signed bytes plus their HMAC, so verification never depends on re-encoding.
struct SignedSidecar: Codable {
    var metadata: Data
    var hmac: String
}

public struct VaultEntry: Sendable {
    public var metadata: VaultItemMetadata
    public var record: QuarantineRecord { metadata.record }
}

/// Encrypted quarantine store.
///
/// Layout under `root`:
/// - `vault.key`   32 random bytes, mode 0600 (root-owned when running as root)
/// - `items/<uuid>.rqf`   AES-GCM sealed box (nonce|ciphertext|tag) of the LZFSE-compressed sample
/// - `items/<uuid>.json`  HMAC-signed `VaultItemMetadata`
public final class QuarantineVault: @unchecked Sendable {
    public let root: URL
    public var itemsDir: URL { root.appendingPathComponent("items") }
    private let lock = NSLock()
    private let encKey: SymmetricKey
    private let macKey: SymmetricKey
    /// Called with (sha256, restoredPath) after a successful restore so the hash can be allow-listed.
    public var allowlistHandler: ((String, String) -> Void)?
    /// Refuse items on SIP/system paths. Tests can turn it off only for paths they create.
    public var enforceProtectedPaths: Bool = true
    private let log = RLog.logger("quarantine")

    /// Default production location: `Paths.effectiveRoot/Quarantine`.
    public static var defaultRoot: URL { Paths.effectiveRoot.appendingPathComponent("Quarantine") }

    public init(root: URL = QuarantineVault.defaultRoot, allowlistHandler: ((String, String) -> Void)? = nil) throws {
        self.root = root
        self.allowlistHandler = allowlistHandler
        let fm = FileManager.default
        try fm.createDirectory(at: root.appendingPathComponent("items"), withIntermediateDirectories: true,
                               attributes: [.posixPermissions: 0o700])
        chmod(root.path, 0o700); chmod(root.appendingPathComponent("items").path, 0o700)
        if getuid() == 0 { chown(root.path, 0, 0); chown(root.appendingPathComponent("items").path, 0, 0) }
        // Keep the vault out of Spotlight.
        let never = root.appendingPathComponent(".metadata_never_index")
        if !fm.fileExists(atPath: never.path) { fm.createFile(atPath: never.path, contents: Data()) }
        let master = try Self.loadOrCreateKey(at: root.appendingPathComponent("vault.key"))
        encKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: master, info: Data("rampart.vault.enc.v1".utf8), outputByteCount: 32)
        macKey = HKDF<SHA256>.deriveKey(inputKeyMaterial: master, info: Data("rampart.vault.mac.v1".utf8), outputByteCount: 32)
    }

    private static func loadOrCreateKey(at url: URL) throws -> SymmetricKey {
        // hx3: never follow a link to the key, and only trust a regular file owned by this process's user.
        let rfd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        if rfd >= 0 {
            defer { close(rfd) }
            var st = stat()
            guard fstat(rfd, &st) == 0, st.st_mode & S_IFMT == S_IFREG else { throw RemediationError.integrityFailure("vault key is not a regular file") }
            guard st.st_uid == getuid() else { throw RemediationError.integrityFailure("vault key has the wrong owner") }
            guard st.st_size == 32 else { throw RemediationError.integrityFailure("vault key has wrong length") }
            var d = Data(count: 32)
            let n = d.withUnsafeMutableBytes { read(rfd, $0.baseAddress, 32) }
            guard n == 32 else { throw RemediationError.integrityFailure("vault key unreadable") }
            if (st.st_mode & 0o077) != 0 { fchmod(rfd, 0o600) }
            return SymmetricKey(data: d)
        }
        if errno == ELOOP { throw RemediationError.integrityFailure("vault key is a symbolic link") }
        let key = SymmetricKey(size: .bits256)
        let bytes = key.withUnsafeBytes { Data($0) }
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw RemediationError.ioError("cannot create vault key: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        let ok = bytes.withUnsafeBytes { write(fd, $0.baseAddress, bytes.count) } == bytes.count
        fsync(fd)
        guard ok else { throw RemediationError.ioError("cannot write vault key") }
        if getuid() == 0 { fchown(fd, 0, 0) }
        return key
    }

    // MARK: - Quarantine

    /// Neutralises and moves `path` into the vault. The original is removed only after the
    /// encrypted copy and the signed sidecar are written, synced and verified.
    ///
    /// hx3: runs as root on user-controlled paths, so every step is pinned to a descriptor of the parent folder
    /// (no symlink in any component), the file is opened with O_NOFOLLOW and must be the inode that was checked,
    /// chmod/chflags go through that descriptor, and foreign hard links (a link to a file owned by someone else,
    /// e.g. a root-only file) are refused so root never reads, chmods or archives another user's data.
    @discardableResult
    public func quarantine(path: String, detectionName: String) throws -> QuarantineRecord {
        lock.lock(); defer { lock.unlock() }
        let p = normalizePath(path)
        if enforceProtectedPaths && ProtectedPaths.isProtected(p) { throw RemediationError.protectedPath(p) }
        if p.hasPrefix(root.path + "/") { throw RemediationError.protectedPath(p) }
        let name = (p as NSString).lastPathComponent
        guard SafeFS.isPlainName(name) else { throw RemediationError.unsupported("bad path \(p)") }
        guard let rp = realpath((p as NSString).deletingLastPathComponent, nil) else { throw RemediationError.notFound(p) }
        let realParent = String(cString: rp); free(rp)
        let real = (realParent as NSString).appendingPathComponent(name)
        if enforceProtectedPaths && ProtectedPaths.isProtected(real) { throw RemediationError.protectedPath(real) }
        let realRoot = root.resolvingSymlinksInPath().path
        if real.hasPrefix(realRoot + "/") || real.hasPrefix(root.path + "/") { throw RemediationError.protectedPath(real) }
        let dir = try SafeFS.pin(realParent)
        guard let dirSt = dir.stat() else { throw RemediationError.ioError("stat \(realParent)") }

        var st = stat()
        guard fstatat(dir.fd, name, &st, AT_SYMLINK_NOFOLLOW) == 0 else { throw RemediationError.notFound(p) }
        let type = st.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR else { throw RemediationError.unsupported("only regular files and bundles/directories: \(p)") }
        let isDir = type == S_IFDIR
        let id = UUID()

        let xattrs: [String: Data]
        let plain: Data
        var staged: (dir: SafeFS.PinnedDir, path: String)?
        if isDir {
            let s = try stageDirectory(dir: dir, name: name, expected: st, id: id)
            staged = s
            do { plain = try archiveDirectory(s.path, id: id) }
            catch { unstage(s.dir, name: name, back: dir); throw error }
            xattrs = [:]
        } else {
            if getuid() == 0, SafeFS.isForeignHardLink(st, expectedOwner: dirSt.st_uid) {
                throw RemediationError.unsupported("\(p) is a hard link to a file owned by someone else; refusing to read it as root")
            }
            let fd = openat(dir.fd, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
            guard fd >= 0 else { throw RemediationError.ioError("open \(p): \(String(cString: strerror(errno)))") }
            defer { close(fd) }
            var fst = stat()
            guard fstat(fd, &fst) == 0, fst.st_dev == st.st_dev, fst.st_ino == st.st_ino, fst.st_mode & S_IFMT == S_IFREG else {
                throw RemediationError.integrityFailure("\(p) changed while it was being quarantined")
            }
            // Clear immutable flags where permitted, then strip exec/setuid bits so nothing can run it mid-move.
            if fst.st_flags & UInt32(UF_IMMUTABLE | UF_APPEND) != 0 { fchflags(fd, fst.st_flags & ~UInt32(UF_IMMUTABLE | UF_APPEND)) }
            fchmod(fd, (fst.st_mode & 0o666 & ~0o022) | 0o400)
            xattrs = Xattr.all(fd: fd)
            guard let d = Self.readAll(fd: fd, max: 4 << 30) else { throw RemediationError.ioError("cannot read \(p)") }
            plain = d
        }
        let sha = SHA256.hash(data: plain).hex
        let compressedData = (try? (plain as NSData).compressed(using: .lzfse) as Data)
        let useCompressed = compressedData != nil && compressedData!.count < plain.count
        let payload = useCompressed ? compressedData! : plain
        let record = QuarantineRecord(id: id, date: Date(), originalPath: p, sha256: sha, size: UInt64(plain.count),
                                      detectionName: detectionName, ownerUID: st.st_uid, mode: st.st_mode)
        let meta = VaultItemMetadata(record: record, groupID: st.st_gid, flags: st.st_flags, inode: UInt64(st.st_ino),
                                     isDirectory: isDir, xattrs: xattrs, compressed: useCompressed, status: .quarantined,
                                     restoredAt: nil, restoredTo: nil, formatVersion: 1)
        do {
            let sealed = try AES.GCM.seal(payload, using: encKey, authenticating: Data(id.uuidString.utf8))
            guard let blob = sealed.combined else { throw RemediationError.ioError("seal failed") }
            try writeAtomically(blob, to: blobURL(id), mode: 0o600)
            try writeSidecar(meta)
            // Verify the stored copy before deleting the original.
            let check = try decrypt(id: id, meta: meta)
            guard SHA256.hash(data: check).hex == sha else { throw RemediationError.integrityFailure("verification after write failed") }
            if let s = staged {
                try? FileManager.default.removeItem(atPath: (s.path as NSString).deletingLastPathComponent)
            } else {
                // Only unlink the entry if it is still the inode we read.
                var now = stat()
                guard fstatat(dir.fd, name, &now, AT_SYMLINK_NOFOLLOW) == 0, now.st_dev == st.st_dev, now.st_ino == st.st_ino else {
                    throw RemediationError.integrityFailure("\(p) was replaced while it was being quarantined")
                }
                if unlinkat(dir.fd, name, 0) != 0 { throw RemediationError.ioError("unlink \(p): \(String(cString: strerror(errno)))") }
            }
        } catch {
            try? FileManager.default.removeItem(at: blobURL(id)); try? FileManager.default.removeItem(at: sidecarURL(id))
            if let s = staged { unstage(s.dir, name: name, back: dir) }
            throw error
        }
        log.info("quarantined \(p, privacy: .public) as \(id.uuidString, privacy: .public)")
        return record
    }

    /// Moves a folder into a root-only staging area (`root/staging/<id>/<name>`) with one atomic renameat, so the
    /// tree can't be swapped or edited while it is archived. Falls back to archiving in place across volumes.
    private func stageDirectory(dir: SafeFS.PinnedDir, name: String, expected st: stat, id: UUID) throws -> (dir: SafeFS.PinnedDir, path: String) {
        let stagingRoot = root.appendingPathComponent("staging").path
        mkdir(stagingRoot, 0o700); chmod(stagingRoot, 0o700)
        let sroot = try SafeFS.pin(stagingRoot)
        guard mkdirat(sroot.fd, id.uuidString, 0o700) == 0 else { throw RemediationError.ioError("cannot create staging folder") }
        let sdir = try SafeFS.pin((stagingRoot as NSString).appendingPathComponent(id.uuidString))
        guard renameatx_np(dir.fd, name, sdir.fd, name, UInt32(RENAME_EXCL)) == 0 else {
            let e = errno
            unlinkat(sroot.fd, id.uuidString, AT_REMOVEDIR)
            throw RemediationError.ioError(e == EXDEV ? "folder is on another volume; move it to your startup disk first"
                                                      : "cannot move folder into the vault: \(String(cString: strerror(e)))")
        }
        var now = stat()
        guard fstatat(sdir.fd, name, &now, AT_SYMLINK_NOFOLLOW) == 0, now.st_mode & S_IFMT == S_IFDIR,
              now.st_dev == st.st_dev, now.st_ino == st.st_ino else {
            unstage(sdir, name: name, back: dir)
            throw RemediationError.integrityFailure("folder was replaced while it was being quarantined")
        }
        // Refuse hard links to files owned by someone else (root would otherwise archive their contents).
        if getuid() == 0 {
            let top = openat(sdir.fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard top >= 0 else { unstage(sdir, name: name, back: dir); throw RemediationError.ioError("open staged folder") }
            defer { close(top) }
            do {
                try SafeFS.walkTree(dirfd: top) { _, n, fst in
                    if SafeFS.isForeignHardLink(fst, expectedOwner: st.st_uid) {
                        throw RemediationError.unsupported("\(n) inside the folder is a hard link to a file owned by someone else")
                    }
                }
            } catch { unstage(sdir, name: name, back: dir); throw error }
        }
        return (sdir, (sdir.realPath as NSString).appendingPathComponent(name))
    }

    /// Puts a staged folder back where it came from (never over something new).
    private func unstage(_ sdir: SafeFS.PinnedDir, name: String, back dir: SafeFS.PinnedDir) {
        if renameatx_np(sdir.fd, name, dir.fd, name, UInt32(RENAME_EXCL)) != 0 {
            log.error("could not move staged folder back; it is kept in \(sdir.realPath, privacy: .public)")
            return
        }
        rmdir(sdir.realPath)
    }

    static func readAll(fd: Int32, max: Int) -> Data? {
        var out = Data()
        var buf = [UInt8](repeating: 0, count: 1 << 20)
        while true {
            let n = buf.withUnsafeMutableBytes { read(fd, $0.baseAddress, $0.count) }
            if n < 0 { if errno == EINTR { continue }; return nil }
            if n == 0 { return out }
            out.append(contentsOf: buf.prefix(n))
            if out.count > max { return nil }
        }
    }

    // MARK: - Restore

    public struct RestoreOptions: Sendable {
        /// Restore to this path instead of the original.
        public var alternatePath: String?
        /// Re-apply `com.apple.quarantine` (off by default; Gatekeeper re-checks anyway).
        public var reapplyQuarantineXattr: Bool
        /// Add the hash to the allow-list via `allowlistHandler`.
        public var allowlist: Bool
        /// Give the restored copy (and everything inside a folder) this owner instead of the recorded one.
        public var ownerUID: uid_t?
        public var ownerGID: gid_t?
        /// Refuse unless the destination folder, as opened, is owned by this uid (checked on the pinned descriptor,
        /// so swapping the folder after the caller's checks doesn't help).
        public var requireParentOwnerUID: uid_t?
        public init(alternatePath: String? = nil, reapplyQuarantineXattr: Bool = false, allowlist: Bool = true,
                    ownerUID: uid_t? = nil, ownerGID: gid_t? = nil, requireParentOwnerUID: uid_t? = nil) {
            self.alternatePath = alternatePath; self.reapplyQuarantineXattr = reapplyQuarantineXattr; self.allowlist = allowlist
            self.ownerUID = ownerUID; self.ownerGID = ownerGID; self.requireParentOwnerUID = requireParentOwnerUID
        }
    }

    /// Restores an item. Verifies sidecar HMAC, GCM tag and SHA-256; never overwrites an existing path.
    @discardableResult
    public func restore(id: UUID, options: RestoreOptions = RestoreOptions()) throws -> String {
        lock.lock(); defer { lock.unlock() }
        var meta = try loadVerified(id)
        guard meta.status == .quarantined else { throw RemediationError.notFound("item \(id) is \(meta.status.rawValue)") }
        let dest = normalizePath(options.alternatePath ?? meta.record.originalPath)
        guard dest.hasPrefix("/") else { throw RemediationError.ioError("destination must be absolute") }
        if enforceProtectedPaths && ProtectedPaths.isProtected(dest) { throw RemediationError.protectedPath(dest) }
        var st = stat()
        if lstat(dest, &st) == 0 { throw RemediationError.destinationExists(dest) }
        let plain = try decrypt(id: id, meta: meta)
        guard SHA256.hash(data: plain).hex == meta.record.sha256 else { throw RemediationError.integrityFailure("sha256 mismatch") }

        let parent = (dest as NSString).deletingLastPathComponent
        if !FileManager.default.fileExists(atPath: parent) {
            try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true)
        }
        // Pin the destination folder (red-team fix): open it once, refuse if it resolves anywhere other than the
        // path that was checked (a symlink swapped in after the caller's checks, e.g. to /Library/LaunchDaemons),
        // and do the final create/rename relative to that descriptor so later swaps cannot redirect the write.
        let pinned = try SafeFS.pin(parent)
        let dfd = pinned.fd
        let realParent = pinned.realPath
        let destName = (dest as NSString).lastPathComponent
        guard SafeFS.isPlainName(destName) else { throw RemediationError.ioError("bad destination name") }
        if enforceProtectedPaths && ProtectedPaths.isProtected((realParent as NSString).appendingPathComponent(destName)) {
            throw RemediationError.protectedPath(dest)
        }
        if let want = options.requireParentOwnerUID {
            guard let pst = pinned.stat(), pst.st_uid == want else {
                throw RemediationError.ioError("you don't own the folder \(realParent)")
            }
        }
        // hx3: anywhere other than the original place, or for a different owner, setuid/setgid bits are dropped.
        let keepSpecial = options.alternatePath == nil && options.ownerUID == nil
        let owner: (uid_t, gid_t) = (options.ownerUID ?? meta.record.ownerUID, options.ownerGID ?? meta.groupID)
        let tmpName = ".rampart-restore-\(id.uuidString)"
        if meta.isDirectory {
            // Root-only private folder inside the destination: the user can't enter it while ditto writes.
            guard mkdirat(dfd, tmpName, 0o700) == 0 else { throw RemediationError.ioError("create \(tmpName): \(String(cString: strerror(errno)))") }
            var cleaned = false
            defer { if !cleaned { try? FileManager.default.removeItem(atPath: (realParent as NSString).appendingPathComponent(tmpName)) } }
            let tfd = openat(dfd, tmpName, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            guard tfd >= 0 else { throw RemediationError.ioError("open \(tmpName)") }
            defer { close(tfd) }
            var tst = stat()
            guard fstat(tfd, &tst) == 0, tst.st_uid == getuid() else { throw RemediationError.ioError("restore folder was replaced") }
            let zip = root.appendingPathComponent("tmp-\(id.uuidString).zip")
            defer { try? FileManager.default.removeItem(at: zip) }
            try writeAtomically(plain, to: zip, mode: 0o600)
            // ditto writes to "." = the descriptor above, so renaming path components can't redirect it.
            guard SafeFS.runInDir("/usr/bin/ditto", ["-x", "-k", zip.path, "."], cwdFD: tfd) == 0 else {
                throw RemediationError.commandFailed("ditto -x failed")
            }
            let name = (meta.record.originalPath as NSString).lastPathComponent
            guard SafeFS.isPlainName(name) else { throw RemediationError.integrityFailure("bad item name") }
            if !keepSpecial || options.ownerUID != nil {
                var top = stat()
                guard fstatat(tfd, name, &top, AT_SYMLINK_NOFOLLOW) == 0, top.st_mode & S_IFMT == S_IFDIR else {
                    throw RemediationError.integrityFailure("unpacked folder missing")
                }
                let sub = openat(tfd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
                guard sub >= 0 else { throw RemediationError.ioError("open unpacked folder") }
                defer { close(sub) }
                let o: (uid_t, gid_t)? = options.ownerUID != nil ? owner : nil
                try SafeFS.sanitizeTree(dirfd: sub, owner: o)
                if let o, getuid() == 0 { fchownat(tfd, name, o.0, o.1, AT_SYMLINK_NOFOLLOW) }
                fchmodat(tfd, name, top.st_mode & 0o1777, AT_SYMLINK_NOFOLLOW)
            }
            guard renameatx_np(tfd, name, dfd, destName, UInt32(RENAME_EXCL)) == 0 else {
                throw errno == EEXIST ? RemediationError.destinationExists(dest) : RemediationError.ioError("rename: \(String(cString: strerror(errno)))")
            }
            if unlinkat(dfd, tmpName, AT_REMOVEDIR) == 0 { cleaned = true }
        } else {
            defer { unlinkat(dfd, tmpName, 0) }
            let fd = openat(dfd, tmpName, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw RemediationError.ioError("create \(tmpName): \(String(cString: strerror(errno)))") }
            if getuid() == 0 { fchown(fd, owner.0, owner.1) }
            let ok = plain.withUnsafeBytes { plain.isEmpty || write(fd, $0.baseAddress, plain.count) == plain.count }
            fsync(fd)
            guard ok else { close(fd); throw RemediationError.ioError("write \(tmpName)") }
            for (name, value) in meta.xattrs where name != "com.apple.quarantine" || options.reapplyQuarantineXattr {
                _ = value.withUnsafeBytes { fsetxattr(fd, name, $0.baseAddress, value.count, 0, 0) }
            }
            fchmod(fd, SafeFS.restoredMode(meta.record.mode, keepSpecialBits: keepSpecial))
            close(fd)
            guard renameatx_np(dfd, tmpName, dfd, destName, UInt32(RENAME_EXCL)) == 0 else {
                throw errno == EEXIST ? RemediationError.destinationExists(dest) : RemediationError.ioError("rename: \(String(cString: strerror(errno)))")
            }
        }
        meta.status = .restored; meta.restoredAt = Date(); meta.restoredTo = dest
        try writeSidecar(meta)
        try? FileManager.default.removeItem(at: blobURL(id))
        if options.allowlist { allowlistHandler?(meta.record.sha256, dest) }
        log.info("restored \(id.uuidString, privacy: .public) to \(dest, privacy: .public)")
        return dest
    }

    // MARK: - List / delete / purge

    /// Items currently held (status quarantined) whose metadata verifies. Tampered items are skipped.
    public func list(includeHistory: Bool = false) -> [QuarantineRecord] {
        entries(includeHistory: includeHistory).map(\.record).sorted { $0.date > $1.date }
    }

    public func entries(includeHistory: Bool = false) -> [VaultEntry] {
        lock.lock(); defer { lock.unlock() }
        let files = (try? FileManager.default.contentsOfDirectory(atPath: itemsDir.path)) ?? []
        return files.filter { $0.hasSuffix(".json") }.compactMap { f -> VaultEntry? in
            guard let id = UUID(uuidString: String(f.dropLast(5))), let m = try? loadVerified(id) else { return nil }
            return (includeHistory || m.status == .quarantined) ? VaultEntry(metadata: m) : nil
        }
    }

    /// IDs whose sidecar fails HMAC verification or cannot be parsed.
    public func tamperedItems() -> [String] {
        lock.lock(); defer { lock.unlock() }
        let files = (try? FileManager.default.contentsOfDirectory(atPath: itemsDir.path)) ?? []
        return files.filter { $0.hasSuffix(".json") }.filter { f in
            guard let id = UUID(uuidString: String(f.dropLast(5))) else { return true }
            return (try? loadVerified(id)) == nil
        }.map { String($0.dropLast(5)) }
    }

    /// Decrypted, verified bytes of a held item (sidecar HMAC, GCM tag with the id as AAD, and SHA-256).
    /// For callers like export and the sandbox, so they never handle the vault key themselves.
    public func verifiedPlaintext(id: UUID) throws -> (VaultItemMetadata, Data) {
        lock.lock(); defer { lock.unlock() }
        let meta = try loadVerified(id)
        guard meta.status == .quarantined else { throw RemediationError.notFound("item \(id) is \(meta.status.rawValue)") }
        let plain = try decrypt(id: id, meta: meta)
        guard SHA256.hash(data: plain).hex == meta.record.sha256 else { throw RemediationError.integrityFailure("sha256 mismatch") }
        return (meta, plain)
    }

    public func metadata(id: UUID) throws -> VaultItemMetadata {
        lock.lock(); defer { lock.unlock() }
        return try loadVerified(id)
    }

    /// Permanently deletes an item: the encrypted copy is unlinked and the history row is kept as purged.
    /// Honest limit: this is not a secure erase. All items share one vault key and APFS may keep old blocks, so
    /// someone with root and the key file could in theory recover a deleted copy from free space.
    public func delete(id: UUID, onlyIfQuarantined: Bool = false) throws {
        lock.lock(); defer { lock.unlock() }
        var meta = try loadVerified(id)
        // hx3: a purge racing a restore must not rewrite the restored item's history as purged.
        if onlyIfQuarantined && meta.status != .quarantined { throw RemediationError.notFound("item \(id) is \(meta.status.rawValue)") }
        try? FileManager.default.removeItem(at: blobURL(id))
        meta.status = .purged
        try writeSidecar(meta)
    }

    /// Purges quarantined items older than `days`. Returns purged IDs.
    @discardableResult
    public func purge(olderThanDays days: Int = 30, now: Date = Date()) -> [UUID] {
        let cutoff = now.addingTimeInterval(-Double(days) * 86_400)
        var purged: [UUID] = []
        for e in entries() where e.record.date < cutoff {
            if (try? delete(id: e.record.id, onlyIfQuarantined: true)) != nil { purged.append(e.record.id) }
        }
        return purged
    }

    // MARK: - Internals

    func blobURL(_ id: UUID) -> URL { itemsDir.appendingPathComponent(id.uuidString + ".rqf") }
    func sidecarURL(_ id: UUID) -> URL { itemsDir.appendingPathComponent(id.uuidString + ".json") }

    private func writeSidecar(_ meta: VaultItemMetadata) throws {
        let body = try JSONEncoder.rampartSorted.encode(meta)
        let mac = HMAC<SHA256>.authenticationCode(for: body, using: macKey)
        let signed = SignedSidecar(metadata: body, hmac: Data(mac).hex)
        try writeAtomically(try JSONEncoder.rampartSorted.encode(signed), to: sidecarURL(meta.record.id), mode: 0o600)
    }

    private func loadVerified(_ id: UUID) throws -> VaultItemMetadata {
        guard let raw = try? Data(contentsOf: sidecarURL(id)) else { throw RemediationError.notFound("item \(id)") }
        guard let signed = try? JSONDecoder.rampart.decode(SignedSidecar.self, from: raw),
              let macBytes = Data(hexString: signed.hmac),
              HMAC<SHA256>.isValidAuthenticationCode(macBytes, authenticating: signed.metadata, using: macKey)
        else { throw RemediationError.integrityFailure("metadata signature invalid for \(id)") }
        let meta = try JSONDecoder.rampart.decode(VaultItemMetadata.self, from: signed.metadata)
        guard meta.record.id == id else { throw RemediationError.integrityFailure("metadata id mismatch") }
        return meta
    }

    private func decrypt(id: UUID, meta: VaultItemMetadata) throws -> Data {
        guard let blob = try? Data(contentsOf: blobURL(id)) else { throw RemediationError.notFound("blob \(id)") }
        let payload: Data
        do {
            let box = try AES.GCM.SealedBox(combined: blob)
            payload = try AES.GCM.open(box, using: encKey, authenticating: Data(id.uuidString.utf8))
        } catch { throw RemediationError.integrityFailure("ciphertext authentication failed") }
        if meta.compressed {
            guard let d = try? (payload as NSData).decompressed(using: .lzfse) as Data else {
                throw RemediationError.integrityFailure("decompression failed")
            }
            return d
        }
        return payload
    }

    private func archiveDirectory(_ path: String, id: UUID) throws -> Data {
        let zip = root.appendingPathComponent("tmp-\(id.uuidString).zip")
        defer { try? FileManager.default.removeItem(at: zip) }
        let r = ProcessCommandRunner().run(PrivilegedCommand("/usr/bin/ditto", ["-c", "-k", "--sequesterRsrc", "--keepParent", path, zip.path]))
        guard r.succeeded, let d = try? Data(contentsOf: zip) else { throw RemediationError.commandFailed("ditto -c: \(r.stderr)") }
        return d
    }

    private func writeAtomically(_ data: Data, to url: URL, mode: mode_t) throws {
        let tmp = url.path + ".tmp-\(UUID().uuidString)"
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw RemediationError.ioError("create \(tmp): \(String(cString: strerror(errno)))") }
        let ok = data.withUnsafeBytes { data.isEmpty || write(fd, $0.baseAddress, data.count) == data.count }
        fsync(fd); close(fd)
        guard ok, rename(tmp, url.path) == 0 else { unlink(tmp); throw RemediationError.ioError("write \(url.path)") }
    }
}

// MARK: - Helpers

enum Xattr {
    static func all(fd: Int32) -> [String: Data] {
        let size = flistxattr(fd, nil, 0, 0)
        guard size > 0 else { return [:] }
        var buf = [CChar](repeating: 0, count: size)
        guard flistxattr(fd, &buf, size, 0) == size else { return [:] }
        var out: [String: Data] = [:]
        for n in buf.split(separator: 0).map({ String(cString: Array($0) + [0]) }) {
            let len = fgetxattr(fd, n, nil, 0, 0, 0)
            guard len >= 0, len <= 1 << 20 else { continue }
            var v = [UInt8](repeating: 0, count: len)
            if len == 0 || fgetxattr(fd, n, &v, len, 0, 0) == len { out[n] = Data(v) }
        }
        return out
    }
    static func all(_ path: String) -> [String: Data] {
        let size = listxattr(path, nil, 0, XATTR_NOFOLLOW)
        guard size > 0 else { return [:] }
        var buf = [CChar](repeating: 0, count: size)
        guard listxattr(path, &buf, size, XATTR_NOFOLLOW) == size else { return [:] }
        var out: [String: Data] = [:]
        let names = buf.split(separator: 0).map { String(cString: Array($0) + [0]) }
        for n in names {
            let len = getxattr(path, n, nil, 0, 0, XATTR_NOFOLLOW)
            guard len >= 0 else { continue }
            var v = [UInt8](repeating: 0, count: len)
            if len == 0 || getxattr(path, n, &v, len, 0, XATTR_NOFOLLOW) == len { out[n] = Data(v) }
        }
        return out
    }
    @discardableResult
    static func set(_ path: String, _ name: String, _ value: Data) -> Bool {
        value.withUnsafeBytes { setxattr(path, name, $0.baseAddress, value.count, 0, XATTR_NOFOLLOW) } == 0
    }
}

extension Sequence where Element == UInt8 {
    var hex: String { map { String(format: "%02x", $0) }.joined() }
}
extension Digest {
    var hex: String { Array(self).hex }
}
extension Data {
    init?(hexString: String) {
        guard hexString.count % 2 == 0 else { return nil }
        var d = Data(capacity: hexString.count / 2)
        var i = hexString.startIndex
        while i < hexString.endIndex {
            let j = hexString.index(i, offsetBy: 2)
            guard let b = UInt8(hexString[i..<j], radix: 16) else { return nil }
            d.append(b); i = j
        }
        self = d
    }
}
extension JSONEncoder {
    static var rampartSorted: JSONEncoder {
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e
    }
}

/// Streams a file's SHA-256 (hex).
public func sha256Hex(ofFileAt path: String) -> String? {
    guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
    defer { try? fh.close() }
    var h = SHA256()
    while true {
        let chunk = fh.readData(ofLength: 1 << 20)
        if chunk.isEmpty { break }
        h.update(data: chunk)
    }
    return h.finalize().hex
}
