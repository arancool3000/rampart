import Foundation
import RampartShared

/// The encrypted vault. Locked at rest always: the file only ever holds ciphertext, and while locked no
/// key or item is kept in memory. All methods are thread-safe; unlocking runs PBKDF2 (~300 ms), so call it
/// off the main thread.
public final class VaultStore: @unchecked Sendable {
    public static var defaultDirectory: URL { Paths.userRoot.appendingPathComponent("Vault", isDirectory: true) }
    public static let maxBackups = 10
    /// Minimum gap between automatic backups made by ordinary saves (risky operations always back up).
    public static let backupInterval: TimeInterval = 10 * 60

    public let directory: URL
    public var fileURL: URL { directory.appendingPathComponent("vault.rpvault") }
    public var backupDirectory: URL { directory.appendingPathComponent("Backups", isDirectory: true) }

    private let mutex = NSRecursiveLock()
    private var vaultKey: SecretKeyBytes?
    private var header: VaultFile.Header?
    private var _items: [UUID: VaultItem] = [:]
    private var _meta = VaultMeta()

    public init(directory: URL = VaultStore.defaultDirectory) { self.directory = directory }

    public var exists: Bool { FileManager.default.fileExists(atPath: fileURL.path) }
    public var isUnlocked: Bool { mutex.withLock { vaultKey != nil } }
    public var vaultID: UUID? {
        mutex.withLock {
            if let header { return header.id }
            return (try? Data(contentsOf: fileURL)).flatMap { try? VaultFile.parse($0).header.vaultID }
        }
    }
    public var kdfIterations: Int? { mutex.withLock { header?.kdf.iterations } }

    public var items: [VaultItem] { mutex.withLock { Array(_items.values) } }
    public var meta: VaultMeta { mutex.withLock { _meta } }
    public func item(_ id: UUID) -> VaultItem? { mutex.withLock { _items[id] } }

    // MARK: Create / unlock / lock

    /// Requirements for a new master password.
    public static func isAcceptableMaster(_ pw: String) -> Bool {
        pw.count >= 10 && PasswordStrength.evaluate(pw).level >= .fair
    }

    /// Creates a new vault. `iterations` is for tests; production calibrates to ~300 ms.
    public func create(masterPassword: String, iterations: Int? = nil) throws {
        try mutex.withLock {
            guard !exists else { throw VaultError.alreadyExists }
            guard iterations != nil || Self.isAcceptableMaster(masterPassword) else { throw VaultError.weakMasterPassword }
            let iters = iterations ?? VaultCrypto.calibrateIterations()
            let key = SecretKeyBytes(SecureRandom.bytes(32))
            let h = try wrapHeader(vaultID: UUID(), vaultKey: key, password: masterPassword, iterations: iters, generation: 0)
            vaultKey = key; header = h; _items = [:]; _meta = VaultMeta()
            try saveLocked(forceBackup: false)
        }
    }

    private func wrapHeader(vaultID: UUID, vaultKey: SecretKeyBytes, password: String, iterations: Int, generation: Int) throws -> VaultFile.Header {
        var h = VaultFile.Header(vaultID: vaultID,
                                 kdf: .init(algorithm: "pbkdf2-hmac-sha256", iterations: iterations, salt: SecureRandom.data(16)),
                                 wrappedKey: Data(), written: Date(), generation: generation)
        let kek = VaultCrypto.pbkdf2(password: password, salt: h.kdf.salt, iterations: iterations)
        defer { kek.wipe() }
        h.wrappedKey = try vaultKey.withBytes { b in
            try VaultCrypto.seal(Data(b), key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(h))
        }
        return h
    }

    public func unlock(masterPassword: String) throws {
        let file = try readFile()
        guard file.header.kdf.algorithm == "pbkdf2-hmac-sha256", file.header.kdf.iterations >= 1000 else {
            throw VaultError.badFormat("unknown key derivation")
        }
        let kek = VaultCrypto.pbkdf2(password: masterPassword, salt: file.header.kdf.salt, iterations: file.header.kdf.iterations)
        defer { kek.wipe() }
        var raw: Data
        do { raw = try VaultCrypto.open(file.header.wrappedKey, key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(file.header)) }
        catch { throw VaultError.wrongPassword }
        let key = SecretKeyBytes(data: raw)
        secureZero(&raw)
        try load(file, key: key)
    }

    /// Re-authentication check (e.g. before revealing setup links). Doesn't change any state.
    public func verifyMasterPassword(_ password: String) -> Bool {
        guard let file = try? readFile() else { return false }
        let kek = VaultCrypto.pbkdf2(password: password, salt: file.header.kdf.salt, iterations: file.header.kdf.iterations)
        defer { kek.wipe() }
        return (try? VaultCrypto.open(file.header.wrappedKey, key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(file.header))) != nil
    }

    /// Unlock with a vault key recovered another way (Touch ID). Verifies the file MAC.
    func unlock(vaultKey key: SecretKeyBytes) throws {
        try load(try readFile(), key: key)
    }

    private func readFile() throws -> VaultFile {
        guard exists else { throw VaultError.noVault }
        let d: Data
        do { d = try Data(contentsOf: fileURL) } catch { throw VaultError.io(error.localizedDescription) }
        return try VaultFile.parse(d)
    }

    private func load(_ file: VaultFile, key: SecretKeyBytes) throws {
        guard file.verify(vaultKey: key) else { throw VaultError.tampered }
        let id = file.header.vaultID
        let ik = VaultFile.itemKey(key, id)
        var items: [UUID: VaultItem] = [:]
        do {
            var m = try VaultCrypto.open(file.body.meta, key: ik, aad: VaultFile.metaAAD(id))
            let meta = try VaultFile.decoder.decode(VaultMeta.self, from: m)
            secureZero(&m)
            for blob in file.body.items {
                var p = try VaultCrypto.open(blob.data, key: ik, aad: VaultFile.itemAAD(id, blob.id))
                let item = try VaultFile.decoder.decode(VaultItem.self, from: p)
                secureZero(&p)
                guard item.id == blob.id else { throw VaultError.tampered }
                items[item.id] = item
            }
            mutex.withLock { vaultKey = key; header = file.header; _items = items; _meta = meta }
        } catch { throw VaultError.tampered }
    }

    /// Drops the key and every decrypted item from memory.
    public func lock() {
        mutex.withLock {
            vaultKey?.wipe()
            vaultKey = nil
            _items = [:]
            _meta = VaultMeta()
        }
    }

    /// The raw vault key, for wrapping by Touch ID. Only while unlocked.
    func currentKey() throws -> SecretKeyBytes {
        try mutex.withLock { guard let k = vaultKey else { throw VaultError.locked }; return SecretKeyBytes(k.withBytes { $0 }) }
    }

    // MARK: Editing

    public func upsert(_ item: VaultItem) throws {
        try mutex.withLock {
            guard vaultKey != nil else { throw VaultError.locked }
            for a in item.attachments where a.data.count > Attachment.maxBytes { throw VaultError.attachmentTooLarge }
            var new = item
            if let old = _items[item.id], old.password != item.password { new.recordHistory(old.password) }
            else if _items[item.id] == nil, !item.password.isEmpty, new.passwordModified == nil { new.passwordModified = Date() }
            new.modified = Date()
            _items[item.id] = new
            try saveLocked(forceBackup: false)
        }
    }

    /// Adds many items with one backup and one write (imports).
    public func insert(_ items: [VaultItem]) throws {
        try mutex.withLock {
            guard vaultKey != nil else { throw VaultError.locked }
            for var i in items {
                if i.passwordModified == nil, !i.password.isEmpty { i.passwordModified = i.modified }
                _items[i.id] = i
            }
            try saveLocked(forceBackup: true)
        }
    }

    public func delete(_ id: UUID) throws {
        try mutex.withLock {
            guard vaultKey != nil else { throw VaultError.locked }
            _items[id] = nil
            try saveLocked(forceBackup: false)
        }
    }

    public func updateMeta(_ change: (inout VaultMeta) -> Void) throws {
        try mutex.withLock {
            guard vaultKey != nil else { throw VaultError.locked }
            change(&_meta)
            let valid = Set(_meta.folders.map(\.id))
            for (id, i) in _items where i.folderID.map({ !valid.contains($0) }) ?? false { _items[id]?.folderID = nil }
            try saveLocked(forceBackup: false)
        }
    }

    public func changeMasterPassword(current: String, new: String, iterations: Int? = nil) throws {
        guard iterations != nil || Self.isAcceptableMaster(new) else { throw VaultError.weakMasterPassword }
        let file = try readFile()
        let kek = VaultCrypto.pbkdf2(password: current, salt: file.header.kdf.salt, iterations: file.header.kdf.iterations)
        defer { kek.wipe() }
        guard (try? VaultCrypto.open(file.header.wrappedKey, key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(file.header))) != nil else {
            throw VaultError.wrongPassword
        }
        let iters = iterations ?? VaultCrypto.calibrateIterations()
        try mutex.withLock {
            guard let key = vaultKey, let h = header else { throw VaultError.locked }
            header = try wrapHeader(vaultID: h.vaultID, vaultKey: key, password: new, iterations: iters, generation: h.generation)
            try saveLocked(forceBackup: true)
        }
    }

    // MARK: Persistence

    private func saveLocked(forceBackup: Bool) throws {
        guard let key = vaultKey, var h = header else { throw VaultError.locked }
        h.generation += 1
        h.written = Date()
        let ik = VaultFile.itemKey(key, h.vaultID)
        var metaPlain = try VaultFile.encoder.encode(_meta)
        defer { secureZero(&metaPlain) }
        var blobs: [VaultFile.Blob] = []
        for item in _items.values.sorted(by: { $0.id.uuidString < $1.id.uuidString }) {
            var p = try VaultFile.encoder.encode(item)
            blobs.append(.init(id: item.id, data: try VaultCrypto.seal(p, key: ik, aad: VaultFile.itemAAD(h.vaultID, item.id))))
            secureZero(&p)
        }
        let body = VaultFile.Body(meta: try VaultCrypto.seal(metaPlain, key: ik, aad: VaultFile.metaAAD(h.vaultID)), items: blobs)
        let data = try VaultFile.serialize(header: h, body: body, vaultKey: key)
        try ensureDirectory(directory)
        try backupIfNeeded(force: forceBackup)
        do {
            try data.write(to: fileURL, options: [.atomic])
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: fileURL.path)
        } catch { throw VaultError.io("Could not save the vault: \(error.localizedDescription)") }
        header = h
    }

    private func ensureDirectory(_ url: URL) throws {
        do {
            try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        } catch { throw VaultError.io(error.localizedDescription) }
    }

    /// Backups are copies of the encrypted file; they need the master password that was current when made.
    public func backups() -> [URL] {
        let fm = FileManager.default
        let urls = (try? fm.contentsOfDirectory(at: backupDirectory, includingPropertiesForKeys: nil)) ?? []
        return urls.filter { $0.pathExtension == "rpvault" }.sorted { $0.lastPathComponent > $1.lastPathComponent }
    }

    private func backupIfNeeded(force: Bool) throws {
        guard exists else { return }
        let fm = FileManager.default
        if !force, let newest = backups().first,
           let d = (try? fm.attributesOfItem(atPath: newest.path))?[.creationDate] as? Date,
           Date().timeIntervalSince(d) < Self.backupInterval { return }
        try ensureDirectory(backupDirectory)
        let f = DateFormatter(); f.dateFormat = "yyyyMMdd-HHmmss-SSS"; f.locale = Locale(identifier: "en_US_POSIX")
        let dest = backupDirectory.appendingPathComponent("vault-\(f.string(from: Date())).rpvault")
        do {
            try fm.copyItem(at: fileURL, to: dest)
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: dest.path)
        } catch { throw VaultError.io("Could not back up the vault: \(error.localizedDescription)") }
        for old in backups().dropFirst(Self.maxBackups) { try? fm.removeItem(at: old) }
    }

    /// Replaces the vault with a backup (after backing up the current file) and locks.
    public func restore(backup: URL) throws {
        _ = try VaultFile.parse(try Data(contentsOf: backup))
        try mutex.withLock {
            try backupIfNeeded(force: true)
            let tmp = directory.appendingPathComponent(".restore.tmp")
            try? FileManager.default.removeItem(at: tmp)
            try FileManager.default.copyItem(at: backup, to: tmp)
            _ = try FileManager.default.replaceItemAt(fileURL, withItemAt: tmp)
            lock()
            header = nil
        }
    }
}

private extension VaultFile.Header { var id: UUID { vaultID } }
