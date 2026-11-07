import Foundation

/// Slows down repeated wrong master passwords (online guessing through the app's own UI or API).
///
/// - The first `freeAttempts` failures cost nothing (typos). After that each try must wait
///   `baseDelay * 2^(n - freeAttempts)` seconds, capped at `maxDelay`.
/// - State lives in `unlock-throttle.json` next to the vault (0600) AND in memory, so deleting the file
///   doesn't reset the counter for the running app. A success resets it.
/// - Honest limit: this does nothing against someone who copies the vault file and guesses offline; only the
///   KDF cost and the master password's strength protect against that. Malware running as the user can delete
///   the file between app launches.
public final class UnlockThrottle: @unchecked Sendable {
    public static let freeAttempts = 5
    public static let baseDelay: TimeInterval = 5
    public static let maxDelay: TimeInterval = 300

    struct State: Codable, Equatable { var failures = 0; var last: Date = .distantPast }

    let url: URL
    private let lock = NSLock()
    private var memory = State()
    private let now: () -> Date

    public init(url: URL, now: @escaping () -> Date = Date.init) { self.url = url; self.now = now }

    /// Seconds to wait after `failures` consecutive failures.
    public static func delay(failures: Int) -> TimeInterval {
        guard failures >= freeAttempts else { return 0 }
        let exp = min(failures - freeAttempts, 16)
        return min(maxDelay, baseDelay * pow(2, Double(exp)))
    }

    private func load() -> State {
        var disk = State()
        if let d = try? Data(contentsOf: url), d.count < 4096, let s = try? JSONDecoder().decode(State.self, from: d) { disk = s }
        // Take the stricter of disk and memory.
        var s = disk.failures >= memory.failures ? disk : memory
        // A timestamp in the future (clock moved back, or a forged file) counts as "just now".
        if s.last > now() { s.last = now() }
        s.failures = max(0, min(s.failures, 10_000))
        return s
    }

    private func save(_ s: State) {
        memory = s
        guard let d = try? JSONEncoder().encode(s) else { return }
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true,
                                                 attributes: [.posixPermissions: 0o700])
        try? d.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    /// Throws `.throttled` while a wait is pending.
    public func check() throws {
        try lock.withLock {
            let s = load()
            let wait = Self.delay(failures: s.failures) - now().timeIntervalSince(s.last)
            if wait > 0 { throw VaultError.throttled(Int(wait.rounded(.up))) }
        }
    }

    public func recordFailure() { lock.withLock { var s = load(); s.failures += 1; s.last = now(); save(s) } }

    public func recordSuccess() {
        lock.withLock {
            memory = State()
            if FileManager.default.fileExists(atPath: url.path) { try? FileManager.default.removeItem(at: url) }
        }
    }

    public var failures: Int { lock.withLock { load().failures } }
}

/// Anti-rollback high-water mark: the newest vault generation this Mac has written or opened.
///
/// Every save bumps `Header.generation` (inside the HMAC-protected file). If an attacker swaps in an older but
/// genuine copy (an old backup, a Time Machine copy), its generation is lower than the mark and unlock refuses
/// unless the user explicitly accepts it. Restoring a backup through RamPart moves the mark down on purpose.
/// Honest limit: malware running as the user can delete or edit `vault.state` too; this catches casual or
/// file-only rollbacks (sync conflicts, restored disk images, a swapped file), not a full same-user compromise.
struct RollbackGuard {
    struct State: Codable { var vaultID: UUID; var generation: Int }
    let url: URL

    func expected(for id: UUID) -> Int? {
        guard let d = try? Data(contentsOf: url), d.count < 4096, let s = try? JSONDecoder().decode(State.self, from: d), s.vaultID == id else { return nil }
        return s.generation
    }

    func record(_ id: UUID, generation: Int, allowLower: Bool = false) {
        if !allowLower, let cur = expected(for: id), cur >= generation { return }
        guard let d = try? JSONEncoder().encode(State(vaultID: id, generation: generation)) else { return }
        try? d.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
