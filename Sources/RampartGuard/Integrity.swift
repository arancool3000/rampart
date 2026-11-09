import Foundation
import CryptoKit
import RampartShared

// Integrity: HMAC-sealed config/allow rules, a signed install manifest with per-binary SHA-256,
// sealed backups for restore, and the immutable-flags plan.
//
// Threat model: a non-root script (or a user tricked by a scammer) edits config.json to exclude
// its payload, or swaps a plist. The key is root-only (0600 in a 0700 folder), so only the daemon
// can produce a valid MAC; everything else is detected and reverted from the sealed backup.
// Root can read the key and forge a MAC. That is the documented limit, not a bug.

public enum IntegrityError: Error, Equatable, CustomStringConvertible {
    case missing, notSealed, badEnvelope, macMismatch, keyUnreadable(String)
    public var description: String {
        switch self {
        case .missing: return "file missing"
        case .notSealed: return "file is not a sealed envelope"
        case .badEnvelope: return "sealed envelope is malformed"
        case .macMismatch: return "HMAC does not match (edited outside the daemon)"
        case .keyUnreadable(let s): return "integrity key unreadable: \(s)"
        }
    }
}

/// 32-byte HMAC key stored root-only. Created on first use by the daemon.
public struct IntegrityKey: Sendable {
    public let key: SymmetricKey
    public init(data: Data) { key = SymmetricKey(data: data) }

    /// Loads the key or creates it (0700 dir, 0600 file). Refuses to use a key file that is group/world readable,
    /// a symlink, not a regular file, or owned by someone else, and refuses a key folder another user can write to
    /// (hx5: a pre-created, user-writable Guard folder let a non-root process plant or swap the key).
    public static func loadOrCreate(at path: String) throws -> IntegrityKey {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: dir) {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        var dst = stat()
        guard lstat(dir, &dst) == 0, (dst.st_mode & S_IFMT) == S_IFDIR else { throw IntegrityError.keyUnreadable("\(dir) is not a directory") }
        if dst.st_uid != geteuid() { throw IntegrityError.keyUnreadable("\(dir) is owned by uid \(dst.st_uid), not \(geteuid())") }
        if dst.st_mode & 0o022 != 0 { throw IntegrityError.keyUnreadable("\(dir) is writable by others (mode \(String(dst.st_mode & 0o777, radix: 8)))") }
        var fst = stat()
        if lstat(path, &fst) == 0 {
            guard (fst.st_mode & S_IFMT) == S_IFREG else { throw IntegrityError.keyUnreadable("\(path) is not a regular file") }
            if fst.st_uid != geteuid() { throw IntegrityError.keyUnreadable("\(path) is owned by uid \(fst.st_uid)") }
            if fst.st_mode & 0o077 != 0 { throw IntegrityError.keyUnreadable("\(path) is readable by others (mode \(String(fst.st_mode & 0o777, radix: 8)))") }
            guard let d = fm.contents(atPath: path) else { throw IntegrityError.keyUnreadable("\(path) unreadable") }
            // A key of the wrong size is corruption or tampering; never silently replace it (that would orphan every
            // sealed file and backup). Fail loudly instead.
            guard d.count == 32 else { throw IntegrityError.keyUnreadable("\(path) has \(d.count) bytes, expected 32") }
            return IntegrityKey(data: d)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw IntegrityError.keyUnreadable("SecRandomCopyBytes failed")
        }
        let d = Data(bytes)
        // O_EXCL|O_NOFOLLOW: never write the key through a planted symlink or over a file created in a race.
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw IntegrityError.keyUnreadable("cannot create \(path) (errno \(errno))") }
        defer { close(fd) }
        let n = d.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        guard n == d.count else { throw IntegrityError.keyUnreadable("short write to \(path)") }
        fchmod(fd, 0o600)
        return IntegrityKey(data: d)
    }

    /// Domain-separated MAC (hx5): tokens and sealed files must never share a MAC space, so a value the daemon hands
    /// out (a disable token) can never be replayed as a seal.
    public func mac(domain: String, _ data: Data) -> String {
        var d = Data(("rampart." + domain + "\u{0}").utf8); d.append(data)
        return mac(d)
    }

    public static func constantTimeEqual(_ a: String, _ b: String) -> Bool {
        let x = Array(a.utf8), y = Array(b.utf8)
        guard x.count == y.count else { return false }
        var diff: UInt8 = 0
        for i in 0..<x.count { diff |= x[i] ^ y[i] }
        return diff == 0
    }

    public func mac(_ data: Data) -> String {
        HMAC<SHA256>.authenticationCode(for: data, using: key).map { String(format: "%02x", $0) }.joined()
    }
}

/// Envelope format v1: JSON {"rampart_sealed":1,"mac":"<hex>","payload":"<base64>"}.
/// Envelope format v2 (hx5): {"rampart_sealed":2,"path":"<abs path>","mac":"<hex>","payload":"<base64>"}, where the MAC
/// also covers the path. A valid envelope for allow-rules.json can no longer be copied over config.json (or a backup of
/// one file restored onto another). v1 is still accepted when no path is required, and rewritten as v2 on the next save.
public enum Sealed {
    public static let maxEnvelopeBytes = 64 << 20

    static func v2Input(_ payload: Data, path: String) -> Data {
        var d = Data(GuardPaths.normalize(path).utf8); d.append(0); d.append(payload); return d
    }

    public static func seal(_ payload: Data, key: IntegrityKey, path: String? = nil) -> Data {
        var obj: [String: Any] = ["payload": payload.base64EncodedString()]
        if let path {
            obj["rampart_sealed"] = 2; obj["path"] = GuardPaths.normalize(path)
            obj["mac"] = key.mac(domain: "sealed.v2", v2Input(payload, path: path))
        } else {
            obj["rampart_sealed"] = 1; obj["mac"] = key.mac(payload)
        }
        return (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
    }

    /// `path`: when given, a v2 envelope must be bound to this path; a v1 envelope is accepted only if `allowV1`.
    public static func open(_ envelope: Data, key: IntegrityKey, path: String? = nil, allowV1: Bool = true) -> Result<Data, IntegrityError> {
        guard envelope.count <= maxEnvelopeBytes else { return .failure(.badEnvelope) }
        guard let obj = try? JSONSerialization.jsonObject(with: envelope) as? [String: Any] else { return .failure(.notSealed) }
        guard let version = obj["rampart_sealed"] else { return .failure(.notSealed) }
        guard let mac = obj["mac"] as? String, let b64 = obj["payload"] as? String, let payload = Data(base64Encoded: b64) else {
            return .failure(.badEnvelope)
        }
        let expected: String
        if (version as? Int) == 2 {
            guard let bound = obj["path"] as? String else { return .failure(.badEnvelope) }
            if let path, GuardPaths.normalize(path) != bound { return .failure(.macMismatch) }
            expected = key.mac(domain: "sealed.v2", v2Input(payload, path: bound))
        } else {
            guard allowV1 else { return .failure(.macMismatch) }
            expected = key.mac(payload)
        }
        return IntegrityKey.constantTimeEqual(mac, expected) ? .success(payload) : .failure(.macMismatch)
    }
}

public enum SealedVerdict: Equatable, Sendable {
    case intact(Data)
    case tampered(IntegrityError)
    case missing
    public var isIntact: Bool { if case .intact = self { return true }; return false }
}

/// Writes sealed files atomically and keeps a sealed backup copy for restore.
public final class SealedStore: @unchecked Sendable {
    public let key: IntegrityKey
    public let backupDir: String
    private let log = RLog.logger("guard.integrity")

    public init(key: IntegrityKey, backupDir: String) { self.key = key; self.backupDir = backupDir }

    private func backupPath(for path: String) -> String {
        backupDir + "/" + path.replacingOccurrences(of: "/", with: "_") + ".sealed"
    }

    /// Seals `payload`, writes it to `path` (atomic, 0600) and mirrors it into the backup folder.
    public func write(_ payload: Data, to path: String) throws {
        let fm = FileManager.default
        let env = Sealed.seal(payload, key: key, path: path)
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try env.write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o600)
        try fm.createDirectory(atPath: backupDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try env.write(to: URL(fileURLWithPath: backupPath(for: path)), options: .atomic)
        chmod(backupPath(for: path), 0o600)
    }

    public func verify(_ path: String) -> SealedVerdict {
        guard let d = FileManager.default.contents(atPath: path) else { return .missing }
        switch Sealed.open(d, key: key, path: path) {
        case .success(let p): return .intact(p)
        case .failure(let e): return .tampered(e)
        }
    }

    public func read(_ path: String) -> Data? { if case .intact(let d) = verify(path) { return d }; return nil }

    /// True if a verified backup exists for `path`.
    public func hasBackup(for path: String) -> Bool {
        guard let d = FileManager.default.contents(atPath: backupPath(for: path)) else { return false }
        if case .success = Sealed.open(d, key: key, path: path) { return true }
        return false
    }

    /// Seals a backup of a RAW file (binary, launch plist) without touching the live file. hx5: binaries and plists
    /// are not envelopes on disk, so they must be backed up with this and restored with `restoreRawIfNeeded`.
    public func backupOnly(_ payload: Data, for path: String) throws {
        try FileManager.default.createDirectory(atPath: backupDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Sealed.seal(payload, key: key, path: path).write(to: URL(fileURLWithPath: backupPath(for: path)), options: .atomic)
        chmod(backupPath(for: path), 0o600)
    }

    /// Restores a raw file (binary or plist) from its sealed backup. The bytes written are the backup's payload, and
    /// only if their SHA-256 matches `expectedSHA` when one is given (the sealed manifest entry), so a stale or swapped
    /// backup cannot be planted as a root binary. hx5: `restoreIfNeeded` wrote the JSON envelope over binaries and
    /// plists, leaving launchd with an unrunnable job. Legacy layouts where the live file itself is the envelope
    /// (and the manifest hashed that) are restored as the envelope.
    @discardableResult
    public func restoreRawIfNeeded(_ path: String, expectedSHA: String?, mode: mode_t = 0o644, dryRun: Bool = true) -> Bool {
        guard let env = FileManager.default.contents(atPath: backupPath(for: path)),
              case .success(let payload) = Sealed.open(env, key: key, path: path) else { return false }
        let live = FileManager.default.contents(atPath: path)
        var st = stat()
        let isLink = lstat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFLNK
        if !isLink, let live, live == payload || live == env { return false }   // intact
        let bytes: Data
        if let e = expectedSHA {
            if Self.sha(payload) == e { bytes = payload }
            else if Self.sha(env) == e { bytes = env }
            else { log.error("refusing restore of \(path, privacy: .public): backup does not match the manifest"); return false }
        } else { bytes = payload }
        if dryRun { return true }
        do {
            if isLink { unlink(path) }
            try bytes.write(to: URL(fileURLWithPath: path), options: .atomic)
            chmod(path, mode)
            log.warning("restored \(path, privacy: .public) from sealed backup")
            return true
        } catch {
            log.error("raw restore of \(path, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    static func sha(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

    /// Restores `path` from its sealed backup if the live file is missing or tampered.
    /// Returns the verdict that triggered the restore, or nil when nothing was needed. Never touches an intact file.
    @discardableResult
    public func restoreIfNeeded(_ path: String, dryRun: Bool = true) -> (verdict: SealedVerdict, restored: Bool) {
        let v = verify(path)
        if v.isIntact { return (v, false) }
        guard let backup = FileManager.default.contents(atPath: backupPath(for: path)),
              case .success = Sealed.open(backup, key: key, path: path) else { return (v, false) }
        if dryRun { return (v, true) }
        do {
            try backup.write(to: URL(fileURLWithPath: path), options: .atomic)
            chmod(path, 0o600)
            log.warning("restored \(path, privacy: .public) from sealed backup after: \(String(describing: v), privacy: .public)")
            return (v, true)
        } catch {
            log.error("restore of \(path, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            return (v, false)
        }
    }
}

// MARK: - Install manifest (binary self-hash check)

public struct ManifestMismatch: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable { case missing, hashChanged, unlisted, symlink, unsafeOwnership }
    public var path: String
    public var kind: Kind
    public var expected: String?
    public var actual: String?
    public init(path: String, kind: Kind, expected: String?, actual: String?) {
        self.path = path; self.kind = kind; self.expected = expected; self.actual = actual
    }
}

/// Signed list of installed files and their SHA-256. Written by the installer/daemon at install or update time,
/// verified at daemon start and periodically. A mismatch means the binary on disk is not the one we installed.
public struct InstallManifest: Codable, Hashable, Sendable {
    public var version: String
    public var created: Date
    public var entries: [String: String]   // path -> sha256 hex
    /// Directories that were walked when the manifest was built (hx5). Any regular file found under them at verify
    /// time that is not in `entries` (a dropped dylib, an extra helper) is reported as `unlisted`. Optional for
    /// compatibility with manifests written before this field existed.
    public var roots: [String]?
    public init(version: String = Product.version, created: Date = Date(), entries: [String: String], roots: [String]? = nil) {
        self.version = version; self.created = created; self.entries = entries; self.roots = roots
    }

    public static func sha256(ofFile path: String) -> String? {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? h.close() }
        var hasher = SHA256()
        while true {
            let chunk = h.readData(ofLength: 1 << 20)
            if chunk.isEmpty { break }
            hasher.update(data: chunk)
        }
        return hasher.finalize().map { String(format: "%02x", $0) }.joined()
    }

    /// Hashes every regular file in `paths` (bundles are walked). Missing paths are skipped.
    public static func build(paths: [String], version: String = Product.version) -> InstallManifest {
        var entries: [String: String] = [:]
        var roots: [String] = []
        let fm = FileManager.default
        for root in paths {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: root, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
                roots.append(root)
                guard let e = fm.enumerator(atPath: root) else { continue }
                while let rel = e.nextObject() as? String {
                    let p = root + "/" + rel
                    var d: ObjCBool = false
                    if fm.fileExists(atPath: p, isDirectory: &d), !d.boolValue, let h = sha256(ofFile: p) { entries[p] = h }
                }
            } else if let h = sha256(ofFile: root) {
                entries[root] = h
            }
        }
        return InstallManifest(version: version, entries: entries, roots: roots.isEmpty ? nil : roots)
    }

    /// `requireOwner`: when set (the root daemon passes 0), a listed file owned by another uid, or writable by group or
    /// others, is reported as `unsafeOwnership`: a look-alike can be swapped in by whoever owns it. A listed top-level
    /// path that became a symlink is reported as `symlink` (its target can be flipped after the hash check).
    public func verify(requireOwner: uid_t? = nil) -> [ManifestMismatch] {
        var out: [ManifestMismatch] = []
        let fm = FileManager.default
        for (p, expected) in entries.sorted(by: { $0.key < $1.key }) {
            var st = stat()
            if lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFLNK, !(roots ?? []).contains(where: { p.hasPrefix($0 + "/") }) {
                out.append(ManifestMismatch(path: p, kind: .symlink, expected: expected, actual: nil)); continue
            }
            guard let actual = Self.sha256(ofFile: p) else { out.append(ManifestMismatch(path: p, kind: .missing, expected: expected, actual: nil)); continue }
            if actual != expected { out.append(ManifestMismatch(path: p, kind: .hashChanged, expected: expected, actual: actual)); continue }
            if let owner = requireOwner, stat(p, &st) == 0, st.st_uid != owner || st.st_mode & 0o022 != 0 {
                out.append(ManifestMismatch(path: p, kind: .unsafeOwnership, expected: "uid \(owner), not group/world-writable",
                                            actual: "uid \(st.st_uid) mode \(String(st.st_mode & 0o7777, radix: 8))"))
            }
        }
        for root in roots ?? [] {
            guard let e = fm.enumerator(atPath: root) else { continue }
            var seen = 0
            while let rel = e.nextObject() as? String {
                seen += 1; if seen > 200_000 { break }
                let p = root + "/" + rel
                var st = stat()
                guard lstat(p, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { continue }
                if entries[p] == nil { out.append(ManifestMismatch(path: p, kind: .unlisted, expected: nil, actual: Self.sha256(ofFile: p))) }
            }
        }
        return out
    }

    public func save(to store: SealedStore, path: String) throws {
        try store.write(try JSONEncoder.rampart.encode(self), to: path)
    }
    public static func load(from store: SealedStore, path: String) -> InstallManifest? {
        store.read(path).flatMap { try? JSONDecoder.rampart.decode(InstallManifest.self, from: $0) }
    }
}

// MARK: - Immutable flags plan

/// Generates (never runs) `chflags` commands. `schg` (system immutable) on binaries and plists: even root
/// must clear it first, which is a loud, logged step; `uchg` on config so the daemon can still rewrite it
/// after clearing its own flag. The uninstall/update path must run `unlockCommands` first.
/// Limit: root can `chflags noschg` because macOS runs at securelevel 0; this raises the bar, it is not a wall.
public enum ImmutableFlagsPlan {
    public static let chflags = "/usr/bin/chflags"

    public static func lockCommands(_ paths: GuardPaths) -> [GuardCommand] {
        var out: [GuardCommand] = []
        for p in paths.binaries + paths.plists {
            out.append(GuardCommand(chflags, ["schg", p], note: "system-immutable: even root must clear before editing"))
        }
        for p in [paths.keyFile, paths.manifestFile] {
            out.append(GuardCommand(chflags, ["uchg", p], note: "user-immutable: daemon clears, rewrites, re-locks"))
        }
        return out
    }

    public static func unlockCommands(_ paths: GuardPaths) -> [GuardCommand] {
        (paths.binaries + paths.plists).map { GuardCommand(chflags, ["noschg", $0], note: "uninstall/update: clear system-immutable") }
            + [paths.keyFile, paths.manifestFile].map { GuardCommand(chflags, ["nouchg", $0], note: "uninstall/update: clear user-immutable") }
    }

    /// Shell lines for scripts/uninstall.sh (the lead owns that file; this is what it should contain).
    public static func uninstallScriptLines(_ paths: GuardPaths) -> [String] {
        unlockCommands(paths).map { "\($0.description) 2>/dev/null || true" }
    }

    /// Read-only check: which protected files currently carry schg/uchg. Uses stat(2) st_flags; no command runs.
    public static func currentFlags(_ paths: GuardPaths) -> [String: [String]] {
        var out: [String: [String]] = [:]
        for p in paths.binaries + paths.plists + [paths.keyFile, paths.manifestFile] {
            var st = stat()
            guard stat(p, &st) == 0 else { continue }
            var f: [String] = []
            if st.st_flags & UInt32(SF_IMMUTABLE) != 0 { f.append("schg") }
            if st.st_flags & UInt32(UF_IMMUTABLE) != 0 { f.append("uchg") }
            out[p] = f
        }
        return out
    }
}
