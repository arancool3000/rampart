import Foundation
import SQLite3
import RampartShared

private let SQLITE_TRANSIENT = unsafeBitCast(-1, to: sqlite3_destructor_type.self)

/// A known-malicious SHA-256 entry.
public struct KnownBadHash: Codable, Hashable, Sendable {
    public var sha256: String
    /// Malware family / signature name if the feed provides one.
    public var name: String?
    /// Feed identifier, e.g. "malwarebazaar", "local", "test".
    public var source: String
    public var added: Date
    public init(sha256: String, name: String? = nil, source: String, added: Date = Date()) {
        self.sha256 = sha256.lowercased(); self.name = name; self.source = source; self.added = added
    }
}

/// A user/administrator allowlist entry (by hash).
public struct AllowlistEntry: Codable, Hashable, Sendable {
    public var sha256: String
    public var note: String
    public var added: Date
}

/// Scan-cache row keyed on (device, inode); valid only while size, mtime and ctime match.
public struct ScanCacheEntry: Hashable, Sendable {
    public var device: Int64
    public var inode: UInt64
    public var size: UInt64
    public var mtimeNanos: Int64
    public var ctimeNanos: Int64
    public var sha256: String
    /// Cache version (engine + signatures + detectors) the verdict was computed under.
    public var version: String
    /// Only clean verdicts are cached; detections are always re-evaluated.
    public var clean: Bool
    public init(device: Int64, inode: UInt64, size: UInt64, mtimeNanos: Int64, ctimeNanos: Int64,
                sha256: String, version: String, clean: Bool) {
        self.device = device; self.inode = inode; self.size = size; self.mtimeNanos = mtimeNanos
        self.ctimeNanos = ctimeNanos; self.sha256 = sha256; self.version = version; self.clean = clean
    }
}

/// SQLite store for known-bad hashes, the hash allowlist, the scan cache and small metadata.
/// Thread-safe; all access is serialised on an internal lock with cached prepared statements.
public final class HashDatabase: @unchecked Sendable {
    private var db: OpaquePointer?
    private let lock = NSLock()
    private var statements: [String: OpaquePointer] = [:]
    /// File location, or nil for an in-memory database.
    public let url: URL?

    /// Default location: `<effectiveRoot>/DB/rampart.sqlite` (root daemon: /Library/Application Support/Rampart).
    public static var defaultURL: URL { Paths.effectiveRoot.appendingPathComponent("DB/rampart.sqlite") }

    /// Opens (creating if needed) the database at `url`, in WAL mode.
    public convenience init(url: URL) throws {
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        try self.init(path: url.path, url: url)
    }

    /// Opens a private in-memory database (tests, ephemeral scans).
    public static func inMemory() throws -> HashDatabase { try HashDatabase(path: ":memory:", url: nil) }

    private init(path: String, url: URL?) throws {
        self.url = url
        try open(path)
    }

    deinit {
        for (_, s) in statements { sqlite3_finalize(s) }
        sqlite3_close_v2(db)
    }

    private func open(_ path: String) throws {
        let flags = SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(path, &db, flags, nil) == SQLITE_OK else {
            let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            sqlite3_close_v2(db); db = nil
            throw EngineError.database(msg)
        }
        sqlite3_busy_timeout(db, 5000)
        if path != ":memory:" {
            try exec("PRAGMA journal_mode=WAL")
            chmod(path, 0o600)
        }
        try exec("""
            PRAGMA synchronous=NORMAL;
            CREATE TABLE IF NOT EXISTS bad_hashes(sha256 TEXT PRIMARY KEY, name TEXT, source TEXT NOT NULL, added REAL NOT NULL) WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS bad_hashes_source ON bad_hashes(source, added);
            CREATE TABLE IF NOT EXISTS allowlist(sha256 TEXT PRIMARY KEY, note TEXT NOT NULL, added REAL NOT NULL) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS scan_cache(dev INTEGER NOT NULL, ino INTEGER NOT NULL, size INTEGER NOT NULL,
                mtime INTEGER NOT NULL, ctime INTEGER NOT NULL, sha256 TEXT NOT NULL, version TEXT NOT NULL,
                clean INTEGER NOT NULL, PRIMARY KEY(dev, ino)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID;
            """)
    }

    // MARK: SQL plumbing (call with lock held)

    private func exec(_ sql: String) throws {
        var err: UnsafeMutablePointer<CChar>?
        if sqlite3_exec(db, sql, nil, nil, &err) != SQLITE_OK {
            let msg = err.map { String(cString: $0) } ?? "exec failed"
            sqlite3_free(err)
            throw EngineError.database(msg)
        }
    }

    private func stmt(_ sql: String) throws -> OpaquePointer {
        if let s = statements[sql] { sqlite3_reset(s); sqlite3_clear_bindings(s); return s }
        var s: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &s, nil) == SQLITE_OK, let s else {
            throw EngineError.database(String(cString: sqlite3_errmsg(db)))
        }
        statements[sql] = s
        return s
    }

    private func bind(_ s: OpaquePointer, _ values: [Any?]) {
        for (i, v) in values.enumerated() {
            let idx = Int32(i + 1)
            switch v {
            case nil: sqlite3_bind_null(s, idx)
            case let t as String: sqlite3_bind_text(s, idx, t, -1, SQLITE_TRANSIENT)
            case let n as Int64: sqlite3_bind_int64(s, idx, n)
            case let n as Int: sqlite3_bind_int64(s, idx, Int64(n))
            case let n as UInt64: sqlite3_bind_int64(s, idx, Int64(bitPattern: n))
            case let d as Double: sqlite3_bind_double(s, idx, d)
            case let b as Bool: sqlite3_bind_int(s, idx, b ? 1 : 0)
            default: sqlite3_bind_null(s, idx)
            }
        }
    }

    private func run(_ sql: String, _ values: [Any?] = []) throws {
        let s = try stmt(sql)
        bind(s, values)
        let rc = sqlite3_step(s)
        sqlite3_reset(s)
        guard rc == SQLITE_DONE || rc == SQLITE_ROW else { throw EngineError.database(String(cString: sqlite3_errmsg(db))) }
    }

    private func query<T>(_ sql: String, _ values: [Any?] = [], row: (OpaquePointer) -> T) -> [T] {
        guard let s = try? stmt(sql) else { return [] }
        bind(s, values)
        var out: [T] = []
        while sqlite3_step(s) == SQLITE_ROW { out.append(row(s)) }
        sqlite3_reset(s)
        return out
    }

    private func text(_ s: OpaquePointer, _ i: Int32) -> String? {
        sqlite3_column_text(s, i).map { String(cString: $0) }
    }

    private func transaction(_ body: () throws -> Void) throws {
        try exec("BEGIN IMMEDIATE")
        do { try body(); try exec("COMMIT") } catch { try? exec("ROLLBACK"); throw error }
    }

    private func locked<T>(_ body: () throws -> T) rethrows -> T {
        lock.lock(); defer { lock.unlock() }
        return try body()
    }

    // MARK: Known-bad hashes

    /// Inserts or replaces known-bad hashes in one transaction. Invalid hashes are skipped.
    /// Returns the number of rows written.
    @discardableResult
    public func addKnownBad(_ entries: [KnownBadHash]) throws -> Int {
        try locked {
            var n = 0
            try transaction {
                for e in entries where FileHasher.isSHA256Hex(e.sha256) {
                    try run("INSERT OR REPLACE INTO bad_hashes(sha256,name,source,added) VALUES(?,?,?,?)",
                            [e.sha256.lowercased(), e.name, e.source, e.added.timeIntervalSince1970])
                    n += 1
                }
            }
            return n
        }
    }

    /// Looks up a hash; nil if not known-bad.
    public func knownBad(sha256: String) -> KnownBadHash? {
        locked {
            query("SELECT sha256,name,source,added FROM bad_hashes WHERE sha256=?", [sha256.lowercased()]) { s in
                KnownBadHash(sha256: text(s, 0) ?? "", name: text(s, 1), source: text(s, 2) ?? "",
                             added: Date(timeIntervalSince1970: sqlite3_column_double(s, 3)))
            }.first
        }
    }

    public func removeKnownBad(sha256: String) throws {
        try locked { try run("DELETE FROM bad_hashes WHERE sha256=?", [sha256.lowercased()]) }
    }

    /// Deletes entries of a feed older than `date` (keeps rolling feeds bounded). Returns rows deleted.
    @discardableResult
    public func pruneKnownBad(source: String, olderThan date: Date) throws -> Int {
        try locked {
            try run("DELETE FROM bad_hashes WHERE source=? AND added<?", [source, date.timeIntervalSince1970])
            return Int(sqlite3_changes(db))
        }
    }

    /// Number of known-bad hashes, optionally for one source.
    public func knownBadCount(source: String? = nil) -> Int {
        locked {
            if let source {
                return query("SELECT COUNT(*) FROM bad_hashes WHERE source=?", [source]) { Int(sqlite3_column_int64($0, 0)) }.first ?? 0
            }
            return query("SELECT COUNT(*) FROM bad_hashes") { Int(sqlite3_column_int64($0, 0)) }.first ?? 0
        }
    }

    // MARK: Allowlist

    /// Allowlists a hash: files with this SHA-256 are never reported (T10).
    public func allow(sha256: String, note: String = "") throws {
        try locked {
            try run("INSERT OR REPLACE INTO allowlist(sha256,note,added) VALUES(?,?,?)",
                    [sha256.lowercased(), note, Date().timeIntervalSince1970])
        }
    }

    public func disallow(sha256: String) throws {
        try locked { try run("DELETE FROM allowlist WHERE sha256=?", [sha256.lowercased()]) }
    }

    public func isAllowed(sha256: String) -> Bool {
        locked { !query("SELECT 1 FROM allowlist WHERE sha256=?", [sha256.lowercased()]) { _ in true }.isEmpty }
    }

    public func allowlist() -> [AllowlistEntry] {
        locked {
            query("SELECT sha256,note,added FROM allowlist ORDER BY added DESC") { s in
                AllowlistEntry(sha256: text(s, 0) ?? "", note: text(s, 1) ?? "",
                               added: Date(timeIntervalSince1970: sqlite3_column_double(s, 2)))
            }
        }
    }

    // MARK: Scan cache

    /// Returns the cache row for (device, inode), if any. Callers must compare size/mtime/ctime/version.
    public func cacheEntry(device: Int64, inode: UInt64) -> ScanCacheEntry? {
        locked {
            query("SELECT size,mtime,ctime,sha256,version,clean FROM scan_cache WHERE dev=? AND ino=?",
                  [device, inode]) { s in
                ScanCacheEntry(device: device, inode: inode, size: UInt64(bitPattern: sqlite3_column_int64(s, 0)),
                               mtimeNanos: sqlite3_column_int64(s, 1), ctimeNanos: sqlite3_column_int64(s, 2),
                               sha256: text(s, 3) ?? "", version: text(s, 4) ?? "", clean: sqlite3_column_int(s, 5) != 0)
            }.first
        }
    }

    /// Writes cache rows in one transaction.
    public func storeCache(_ entries: [ScanCacheEntry]) throws {
        guard !entries.isEmpty else { return }
        try locked {
            try transaction {
                for e in entries {
                    try run("INSERT OR REPLACE INTO scan_cache(dev,ino,size,mtime,ctime,sha256,version,clean) VALUES(?,?,?,?,?,?,?,?)",
                            [e.device, e.inode, e.size, e.mtimeNanos, e.ctimeNanos, e.sha256, e.version, e.clean])
                }
            }
        }
    }

    public func clearCache() throws { try locked { try run("DELETE FROM scan_cache") } }

    public func cacheCount() -> Int {
        locked { query("SELECT COUNT(*) FROM scan_cache") { Int(sqlite3_column_int64($0, 0)) }.first ?? 0 }
    }

    // MARK: Metadata

    public func meta(_ key: String) -> String? {
        locked { query("SELECT value FROM meta WHERE key=?", [key]) { text($0, 0) ?? "" }.first }
    }

    public func setMeta(_ key: String, _ value: String) throws {
        try locked { try run("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", [key, value]) }
    }

    /// Monotonic signature generation; bump after any known-bad change so scan-cache verdicts are re-evaluated.
    public var signatureGeneration: Int { Int(meta("signature.generation") ?? "0") ?? 0 }

    @discardableResult
    public func bumpSignatureGeneration() throws -> Int {
        let next = signatureGeneration + 1
        try setMeta("signature.generation", String(next))
        return next
    }

    /// Human-readable signature version for `ProtectionStatus.signatureVersion`.
    public var signatureVersion: String { "\(signatureGeneration).\(knownBadCount())" }
}

/// `FileDetector` that flags files whose SHA-256 is in the known-bad table.
/// Needs `FileFacts.sha256`, which `ScanCoordinator` always fills in.
public struct HashDetector: FileDetector {
    public let database: HashDatabase
    public init(database: HashDatabase) { self.database = database }
    public var name: String { "hash" }

    public func inspect(_ facts: FileFacts) -> [Evidence] {
        guard let sha = facts.sha256, let hit = database.knownBad(sha256: sha) else { return [] }
        let feed = hit.source == "malwarebazaar" ? "abuse.ch MalwareBazaar" : hit.source
        let df = ISO8601DateFormatter(); df.formatOptions = [.withFullDate]
        return [Evidence(source: .hash, title: hit.name.map { "Malware.\($0)" } ?? "Known-Malware-Hash",
                         detail: "SHA-256 \(sha) is listed as malicious by \(feed) (added \(df.string(from: hit.added))).",
                         score: 100)]
    }
}
