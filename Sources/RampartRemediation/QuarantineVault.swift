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
        if let d = try? Data(contentsOf: url) {
            guard d.count == 32 else { throw RemediationError.integrityFailure("vault key has wrong length") }
            var st = stat()
            if lstat(url.path, &st) == 0, (st.st_mode & 0o077) != 0 { chmod(url.path, 0o600) }
            return SymmetricKey(data: d)
        }
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
    @discardableResult
    public func quarantine(path: String, detectionName: String) throws -> QuarantineRecord {
        lock.lock(); defer { lock.unlock() }
        let p = normalizePath(path)
        if enforceProtectedPaths && ProtectedPaths.isProtected(p) { throw RemediationError.protectedPath(p) }
        if p.hasPrefix(root.path + "/") { throw RemediationError.protectedPath(p) }
        var st = stat()
        guard lstat(p, &st) == 0 else { throw RemediationError.notFound(p) }
        let type = st.st_mode & S_IFMT
        guard type == S_IFREG || type == S_IFDIR else { throw RemediationError.unsupported("only regular files and bundles/directories: \(p)") }
        let isDir = type == S_IFDIR
        let id = UUID()

        // Clear immutable flags where permitted, then strip exec/setuid bits so nothing can run it mid-move.
        if st.st_flags & UInt32(UF_IMMUTABLE | UF_APPEND) != 0 { chflags(p, st.st_flags & ~UInt32(UF_IMMUTABLE | UF_APPEND)) }
        if !isDir { chmod(p, st.st_mode & 0o666 & ~0o022 | 0o400) }

        let xattrs = isDir ? [:] : Xattr.all(p)
        let plain: Data
        if isDir {
            plain = try archiveDirectory(p, id: id)
        } else {
            guard let d = FileManager.default.contents(atPath: p) else { throw RemediationError.ioError("cannot read \(p)") }
            plain = d
        }
        let sha = SHA256.hash(data: plain).hex
        let compressedData = (try? (plain as NSData).compressed(using: .lzfse) as Data)
        let useCompressed = compressedData != nil && compressedData!.count < plain.count
        let payload = useCompressed ? compressedData! : plain
        let sealed = try AES.GCM.seal(payload, using: encKey, authenticating: Data(id.uuidString.utf8))
        guard let blob = sealed.combined else { throw RemediationError.ioError("seal failed") }

        let record = QuarantineRecord(id: id, date: Date(), originalPath: p, sha256: sha, size: UInt64(plain.count),
                                      detectionName: detectionName, ownerUID: st.st_uid, mode: st.st_mode)
        let meta = VaultItemMetadata(record: record, groupID: st.st_gid, flags: st.st_flags, inode: UInt64(st.st_ino),
                                     isDirectory: isDir, xattrs: xattrs, compressed: useCompressed, status: .quarantined,
                                     restoredAt: nil, restoredTo: nil, formatVersion: 1)
        try writeAtomically(blob, to: blobURL(id), mode: 0o600)
        try writeSidecar(meta)

        // Verify the stored copy before deleting the original.
        let check = try decrypt(id: id, meta: meta)
        guard SHA256.hash(data: check).hex == sha else {
            try? FileManager.default.removeItem(at: blobURL(id)); try? FileManager.default.removeItem(at: sidecarURL(id))
            throw RemediationError.integrityFailure("verification after write failed")
        }
        do {
            if isDir { try FileManager.default.removeItem(atPath: p) }
            else if unlink(p) != 0 { throw RemediationError.ioError("unlink \(p): \(String(cString: strerror(errno)))") }
        } catch {
            try? FileManager.default.removeItem(at: blobURL(id)); try? FileManager.default.removeItem(at: sidecarURL(id))
            throw error
        }
        log.info("quarantined \(p, privacy: .public) as \(id.uuidString, privacy: .public)")
        return record
    }

    // MARK: - Restore

    public struct RestoreOptions: Sendable {
        /// Restore to this path instead of the original.
        public var alternatePath: String?
        /// Re-apply `com.apple.quarantine` (off by default; Gatekeeper re-checks anyway).
        public var reapplyQuarantineXattr: Bool
        /// Add the hash to the allow-list via `allowlistHandler`.
        public var allowlist: Bool
        public init(alternatePath: String? = nil, reapplyQuarantineXattr: Bool = false, allowlist: Bool = true) {
            self.alternatePath = alternatePath; self.reapplyQuarantineXattr = reapplyQuarantineXattr; self.allowlist = allowlist
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
        let tmp = (parent as NSString).appendingPathComponent(".rampart-restore-\(id.uuidString)")
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        if meta.isDirectory {
            try FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: false)
            let zip = root.appendingPathComponent("tmp-\(id.uuidString).zip")
            defer { try? FileManager.default.removeItem(at: zip) }
            try writeAtomically(plain, to: zip, mode: 0o600)
            let r = ProcessCommandRunner().run(PrivilegedCommand("/usr/bin/ditto", ["-x", "-k", zip.path, tmp]))
            guard r.succeeded else { throw RemediationError.commandFailed("ditto -x: \(r.stderr)") }
            let name = (meta.record.originalPath as NSString).lastPathComponent
            let extracted = (tmp as NSString).appendingPathComponent(name)
            guard renamex_np(extracted, dest, UInt32(RENAME_EXCL)) == 0 else {
                throw errno == EEXIST ? RemediationError.destinationExists(dest) : RemediationError.ioError("rename: \(String(cString: strerror(errno)))")
            }
        } else {
            let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw RemediationError.ioError("create \(tmp): \(String(cString: strerror(errno)))") }
            let ok = plain.withUnsafeBytes { plain.isEmpty || write(fd, $0.baseAddress, plain.count) == plain.count }
            fsync(fd); close(fd)
            guard ok else { throw RemediationError.ioError("write \(tmp)") }
            for (name, value) in meta.xattrs where name != "com.apple.quarantine" || options.reapplyQuarantineXattr {
                Xattr.set(tmp, name, value)
            }
            if getuid() == 0 { lchown(tmp, meta.record.ownerUID, meta.groupID) }
            chmod(tmp, meta.record.mode & 0o7777)
            guard renamex_np(tmp, dest, UInt32(RENAME_EXCL)) == 0 else {
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

    public func metadata(id: UUID) throws -> VaultItemMetadata {
        lock.lock(); defer { lock.unlock() }
        return try loadVerified(id)
    }

    /// Permanently deletes an item (crypto-shred: the ciphertext goes; history row is kept as purged).
    public func delete(id: UUID) throws {
        lock.lock(); defer { lock.unlock() }
        var meta = try loadVerified(id)
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
            if (try? delete(id: e.record.id)) != nil { purged.append(e.record.id) }
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
