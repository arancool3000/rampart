import Foundation

/// Thread-safe bounded cache keyed by path + inode + size + mtime (so a replaced or modified file misses).
public final class SigningCache<Value>: @unchecked Sendable {
    public struct Key: Hashable, Sendable {
        public var path: String
        public var inode: UInt64
        public var size: Int64
        public var mtimeNs: Int64
        public var ctimeNs: Int64
    }

    private var store: [Key: Value] = [:]
    private var order: [Key] = []          // insertion order for FIFO eviction
    private let lock = NSLock()
    public let capacity: Int
    public private(set) var hits = 0
    public private(set) var misses = 0

    public init(capacity: Int = 20_000) { self.capacity = max(16, capacity) }

    /// Key from lstat-free stat(2) of the path; nil if the file cannot be stat'ed.
    public static func key(for path: String) -> Key? {
        var st = stat()
        guard stat(path, &st) == 0 else { return nil }
        return Key(path: path, inode: UInt64(st.st_ino), size: Int64(st.st_size),
                   mtimeNs: Int64(st.st_mtimespec.tv_sec) * 1_000_000_000 + Int64(st.st_mtimespec.tv_nsec),
                   ctimeNs: Int64(st.st_ctimespec.tv_sec) * 1_000_000_000 + Int64(st.st_ctimespec.tv_nsec))
    }

    public func get(_ key: Key) -> Value? {
        lock.lock(); defer { lock.unlock() }
        if let v = store[key] { hits += 1; return v }
        misses += 1; return nil
    }

    public func set(_ key: Key, _ value: Value) {
        lock.lock(); defer { lock.unlock() }
        if store.updateValue(value, forKey: key) == nil { order.append(key) }
        if store.count > capacity {
            let drop = order.count / 4
            for k in order.prefix(drop) { store[k] = nil }
            order.removeFirst(drop)
        }
    }

    /// Returns the cached value for `path` or computes and stores it. Uncacheable paths are computed each time.
    public func value(for path: String, compute: () -> Value) -> Value {
        guard let k = Self.key(for: path) else { return compute() }
        if let v = get(k) { return v }
        let v = compute()
        set(k, v)
        return v
    }

    public var count: Int { lock.lock(); defer { lock.unlock() }; return store.count }
    public func removeAll() { lock.lock(); store.removeAll(); order.removeAll(); lock.unlock() }
}
