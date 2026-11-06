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

    /// Loads the key or creates it (0700 dir, 0600 file). Refuses to use a key file that is group/world readable.
    public static func loadOrCreate(at path: String) throws -> IntegrityKey {
        let fm = FileManager.default
        let dir = (path as NSString).deletingLastPathComponent
        if !fm.fileExists(atPath: dir) {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        if let d = fm.contents(atPath: path), d.count == 32 {
            if let perms = (try? fm.attributesOfItem(atPath: path))?[.posixPermissions] as? Int, perms & 0o077 != 0 {
                throw IntegrityError.keyUnreadable("\(path) is readable by others (mode \(String(perms, radix: 8)))")
            }
            return IntegrityKey(data: d)
        }
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            throw IntegrityError.keyUnreadable("SecRandomCopyBytes failed")
        }
        let d = Data(bytes)
        guard fm.createFile(atPath: path, contents: d, attributes: [.posixPermissions: 0o600]) else {
            throw IntegrityError.keyUnreadable("cannot create \(path)")
        }
        return IntegrityKey(data: d)
    }

    public func mac(_ data: Data) -> String {
        HMAC<SHA256>.authenticationCode(for: data, using: key).map { String(format: "%02x", $0) }.joined()
    }
}

/// Envelope format: JSON {"rampart_sealed":1,"mac":"<hex>","payload":"<base64>"}.
public enum Sealed {
    public static func seal(_ payload: Data, key: IntegrityKey) -> Data {
        let obj: [String: Any] = ["rampart_sealed": 1, "mac": key.mac(payload), "payload": payload.base64EncodedString()]
        return (try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys])) ?? Data()
    }

    public static func open(_ envelope: Data, key: IntegrityKey) -> Result<Data, IntegrityError> {
        guard let obj = try? JSONSerialization.jsonObject(with: envelope) as? [String: Any] else { return .failure(.notSealed) }
        guard obj["rampart_sealed"] != nil else { return .failure(.notSealed) }
        guard let mac = obj["mac"] as? String, let b64 = obj["payload"] as? String, let payload = Data(base64Encoded: b64) else {
            return .failure(.badEnvelope)
        }
        let expected = key.mac(payload)
        // Constant-time compare.
        guard mac.utf8.count == expected.utf8.count else { return .failure(.macMismatch) }
        var diff: UInt8 = 0
        for (a, b) in zip(mac.utf8, expected.utf8) { diff |= a ^ b }
        return diff == 0 ? .success(payload) : .failure(.macMismatch)
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
        let env = Sealed.seal(payload, key: key)
        try fm.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        try env.write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, 0o600)
        try fm.createDirectory(atPath: backupDir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try env.write(to: URL(fileURLWithPath: backupPath(for: path)), options: .atomic)
        chmod(backupPath(for: path), 0o600)
    }

    public func verify(_ path: String) -> SealedVerdict {
        guard let d = FileManager.default.contents(atPath: path) else { return .missing }
        switch Sealed.open(d, key: key) {
        case .success(let p): return .intact(p)
        case .failure(let e): return .tampered(e)
        }
    }

    public func read(_ path: String) -> Data? { if case .intact(let d) = verify(path) { return d }; return nil }

    /// True if a verified backup exists for `path`.
    public func hasBackup(for path: String) -> Bool {
        guard let d = FileManager.default.contents(atPath: backupPath(for: path)) else { return false }
        if case .success = Sealed.open(d, key: key) { return true }
        return false
    }

    /// Restores `path` from its sealed backup if the live file is missing or tampered.
    /// Returns the verdict that triggered the restore, or nil when nothing was needed. Never touches an intact file.
    @discardableResult
    public func restoreIfNeeded(_ path: String, dryRun: Bool = true) -> (verdict: SealedVerdict, restored: Bool) {
        let v = verify(path)
        if v.isIntact { return (v, false) }
        guard let backup = FileManager.default.contents(atPath: backupPath(for: path)),
              case .success = Sealed.open(backup, key: key) else { return (v, false) }
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
    public enum Kind: String, Codable, Sendable { case missing, hashChanged, unlisted }
    public var path: String
    public var kind: Kind
    public var expected: String?
    public var actual: String?
}

/// Signed list of installed files and their SHA-256. Written by the installer/daemon at install or update time,
/// verified at daemon start and periodically. A mismatch means the binary on disk is not the one we installed.
public struct InstallManifest: Codable, Hashable, Sendable {
    public var version: String
    public var created: Date
    public var entries: [String: String]   // path -> sha256 hex
    public init(version: String = Product.version, created: Date = Date(), entries: [String: String]) {
        self.version = version; self.created = created; self.entries = entries
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
        let fm = FileManager.default
        for root in paths {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: root, isDirectory: &isDir) else { continue }
            if isDir.boolValue {
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
        return InstallManifest(version: version, entries: entries)
    }

    public func verify() -> [ManifestMismatch] {
        var out: [ManifestMismatch] = []
        for (p, expected) in entries.sorted(by: { $0.key < $1.key }) {
            guard let actual = Self.sha256(ofFile: p) else { out.append(ManifestMismatch(path: p, kind: .missing, expected: expected, actual: nil)); continue }
            if actual != expected { out.append(ManifestMismatch(path: p, kind: .hashChanged, expected: expected, actual: actual)) }
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
