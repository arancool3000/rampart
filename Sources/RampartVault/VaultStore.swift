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

    /// Wrong-master-password backoff (shared by unlock, re-authentication and password change).
    public let throttle: UnlockThrottle
    /// wms-fb: called (off the lock, on the caller's thread) after `changeMasterPassword` gave the vault a new
    /// key, so Touch ID wraps and other key holders can refresh themselves.
    private var rotationObservers: [() -> Void] = []
    var stateURL: URL { directory.appendingPathComponent("vault.state") }
    private var rollback: RollbackGuard { RollbackGuard(url: stateURL) }

    public init(directory: URL = VaultStore.defaultDirectory) {
        self.directory = directory
        throttle = UnlockThrottle(url: directory.appendingPathComponent("unlock-throttle.json"))
    }

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
        let kek = VaultCrypto.pbkdf2(password: VaultCrypto.normalizedPassword(password), salt: h.kdf.salt, iterations: iterations)
        defer { kek.wipe() }
        h.wrappedKey = try vaultKey.withBytes { b in
            try VaultCrypto.seal(Data(b), key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(h))
        }
        return h
    }

    /// Opens the vault. `acceptRollback` is only for the user's explicit "Open Anyway" after `.rolledBack`.
    public func unlock(masterPassword: String, acceptRollback: Bool = false) throws {
        let file = try readFile()
        let key = try unwrapKey(file, password: masterPassword)
        try load(file, key: key, acceptRollback: acceptRollback)
    }

    /// Validates untrusted KDF parameters, applies the wrong-password backoff and unwraps the vault key.
    private func unwrapKey(_ file: VaultFile, password: String) throws -> SecretKeyBytes {
        guard file.header.kdf.algorithm == "pbkdf2-hmac-sha256",
              VaultCrypto.acceptableKDF(iterations: file.header.kdf.iterations, salt: file.header.kdf.salt) else {
            throw VaultError.badFormat("unknown key derivation")
        }
        try throttle.check()
        // NFC form first; the raw form only for vaults wrapped before normalisation (one throttled attempt in all).
        var raw: Data?
        for form in VaultCrypto.passwordForms(password) where raw == nil {
            let kek = VaultCrypto.pbkdf2(password: form, salt: file.header.kdf.salt, iterations: file.header.kdf.iterations)
            defer { kek.wipe() }
            raw = try? VaultCrypto.open(file.header.wrappedKey, key: VaultCrypto.symmetric(kek), aad: VaultFile.wrapAAD(file.header))
        }
        guard var raw else { throttle.recordFailure(); throw VaultError.wrongPassword }
        defer { secureZero(&raw) }
        guard raw.count == 32 else { throw VaultError.tampered }
        throttle.recordSuccess()
        return SecretKeyBytes(data: raw)
    }

    /// wms-fb: true when `backup`, opened with `password`, yields a key that also opens the vault on disk right now.
    /// After `changeMasterPassword` this is false for every earlier backup: the vault key is rotated, so an old
    /// backup plus an old (possibly leaked) master password no longer decrypts the current file.
    public func backupKeyOpensCurrentVault(backup: URL, password: String) throws -> Bool {
        if (try? backup.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw VaultError.badFormat("the backup is a link") }
        let old = try VaultFile.parse(try Data(contentsOf: backup))
        let key = try unwrapKey(old, password: password)
        defer { key.wipe() }
        return try readFile().verify(vaultKey: key)
    }

    /// Registers a callback for vault-key rotation (see `rotationObservers`).
    public func addKeyRotationObserver(_ observer: @escaping () -> Void) {
        mutex.withLock { rotationObservers.append(observer) }
    }

    /// Re-authentication check (e.g. before revealing setup links). Doesn't change any state except the
    /// wrong-password backoff, which it shares with unlock (so it can't be used as an unthrottled oracle).
    public func verifyMasterPassword(_ password: String) -> Bool {
        guard let file = try? readFile(), let key = try? unwrapKey(file, password: password) else { return false }
        key.wipe()
        return true
    }

    /// Unlock with a vault key recovered another way (Touch ID). Verifies the file MAC.
    func unlock(vaultKey key: SecretKeyBytes, acceptRollback: Bool = false) throws {
        try load(try readFile(), key: key, acceptRollback: acceptRollback)
    }

    private func readFile() throws -> VaultFile {
        guard exists else { throw VaultError.noVault }
        let d: Data
        do {
            // Refuse a symlinked vault file (it could point anywhere) and oversized files before reading.
            let v = try fileURL.resourceValues(forKeys: [.isSymbolicLinkKey, .fileSizeKey])
            if v.isSymbolicLink == true { throw VaultError.badFormat("the vault file is a link") }
            if (v.fileSize ?? 0) > VaultFile.maxFileBytes { throw VaultError.badFormat("file too large") }
            d = try Data(contentsOf: fileURL)
        } catch let e as VaultError { throw e } catch { throw VaultError.io(error.localizedDescription) }
        return try VaultFile.parse(d)
    }

    private func load(_ file: VaultFile, key: SecretKeyBytes, acceptRollback: Bool = false) throws {
        guard file.verify(vaultKey: key) else { throw VaultError.tampered }
        let id = file.header.vaultID
        if let expected = rollback.expected(for: id), file.header.generation < expected {
            guard acceptRollback else { throw VaultError.rolledBack(found: file.header.generation, expected: expected) }
            rollback.record(id, generation: file.header.generation, allowLower: true)
        } else {
            rollback.record(id, generation: file.header.generation)
        }
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
        } catch let e as VaultError { throw e } catch { throw VaultError.tampered }
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

    /// Adds many items with one backup and one write (imports). Never overwrites an existing item: an
    /// imported item whose ID is already in the vault gets a fresh ID (an export file can't replace entries).
    public func insert(_ items: [VaultItem]) throws {
        try mutex.withLock {
            guard vaultKey != nil else { throw VaultError.locked }
            for i in items { for a in i.attachments where a.data.count > Attachment.maxBytes { throw VaultError.attachmentTooLarge } }
            for var i in items {
                if _items[i.id] != nil { i.id = UUID() }
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
        let check = try unwrapKey(file, password: current)
        // The password must open the vault that is unlocked right now, not just whatever file is on disk.
        let matches: Bool? = mutex.withLock { vaultKey.map { $0.constantTimeEquals(check) } }
        check.wipe()
        guard let matches else { throw VaultError.locked }
        guard matches else { throw VaultError.tampered }
        let iters = iterations ?? VaultCrypto.calibrateIterations()
        // wms-fb: a new master password also means a NEW vault key. Re-wrapping the old key would leave every
        // earlier backup (same key, old password) able to open the current vault: someone who learned the old
        // password and kept an old copy would not be locked out by the change. Items and meta are re-encrypted
        // under the new key; the file MAC key changes with it. Observers (Touch ID) re-wrap afterwards.
        let observers: [() -> Void] = try mutex.withLock {
            guard let old = vaultKey, let h = header else { throw VaultError.locked }
            let fresh = SecretKeyBytes(SecureRandom.bytes(32))
            let newHeader = try wrapHeader(vaultID: h.vaultID, vaultKey: fresh, password: new, iterations: iters, generation: h.generation)
            let previousHeader = header
            header = newHeader; vaultKey = fresh
            do { try saveLocked(forceBackup: true) } catch { header = previousHeader; vaultKey = old; fresh.wipe(); throw error }
            old.wipe()
            return rotationObservers
        }
        for o in observers { o() }
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
        rollback.record(h.vaultID, generation: h.generation)
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
        return urls.filter { u in
            u.pathExtension == "rpvault" && (try? u.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true
                && (try? u.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true
        }.sorted { $0.lastPathComponent > $1.lastPathComponent }
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
        if (try? backup.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) == true { throw VaultError.badFormat("the backup is a link") }
        let data = try Data(contentsOf: backup)
        let parsed = try VaultFile.parse(data)
        // Only backups of THIS vault: a planted file from another vault would be a phishing / swap vector.
        if let current = vaultID, parsed.header.vaultID != current { throw VaultError.badFormat("that backup belongs to a different vault") }
        try mutex.withLock {
            try backupIfNeeded(force: true)
            let tmp = directory.appendingPathComponent(".restore.tmp")
            try? FileManager.default.removeItem(at: tmp)
            try data.write(to: tmp) // the bytes we validated, not a second read of the path
            _ = try FileManager.default.replaceItemAt(fileURL, withItemAt: tmp)
            // The user chose this older copy: move the anti-rollback mark down to it.
            rollback.record(parsed.header.vaultID, generation: parsed.header.generation, allowLower: true)
            lock()
            header = nil
        }
    }
}

private extension VaultFile.Header { var id: UUID { vaultID } }
