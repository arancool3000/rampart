import Foundation
import CryptoKit

/// Replacement for RampartBehaviour's ransomware canary body/names, which used one fixed sentence
/// ("Rampart ransomware protection file...") and fixed names — trivially fingerprinted by ransomware that
/// skips known canaries. Here:
/// - names come from tempting pools that still sort first/last in a folder, chosen per install;
/// - every body is a funny, randomised RTF document (unique per file), padded to ~2 KB of low-entropy text
///   (so the entropy check on an encrypted rewrite still has a clear before/after);
/// - "is this ours?" is answered by a keyed marker kept in RamPart's state, never by a string in the file:
///   HMAC-SHA256(key, "canary|path|sha256(body)"). An attacker reading the file learns nothing that identifies it.
/// - Backward compatible: files holding the old fixed sentence are recognised (`isLegacy`) and can be replaced.
public enum RansomCanaryContent {
    public static let legacyMarker = "Rampart ransomware protection file"

    static let firstNames = ["000 Budget Notes.rtf", "00 Accounts Overview.rtf", "000 Tax Summary.rtf", "00 Insurance Policies.rtf", "000 Family Budget.rtf", "00 Bank Statements Index.rtf"]
    static let lastNames = ["zzz Archive Notes.rtf", "zz Old Statements.rtf", "zzz Contracts Index.rtf", "zz Receipts 2024.rtf", "zzz Scans Index.rtf", "zz Warranty Info.rtf"]

    static let titles = ["Household budget (DRAFT)", "Tax notes - for accountant", "Insurance - policy numbers", "Accounts overview", "Bank statements index", "Archive notes"]
    static let lines = [
        "Groceries: too much. Cat food: not enough, says the cat.",
        "Emergency fund: currently a jar with three buttons and a paperclip.",
        "Note to self: the policy number is on the fridge, under the cat.",
        "Q3 savings plan: stop buying keyboards. (Will not happen.)",
        "Accountant says the cat is not a dependent. Appeal pending.",
        "Rent, utilities, internet, and one (1) suspicious subscription called 'MeowFlix'.",
        "If you are ransomware reading this: hi. You're about to have a very bad day.",
        "Dear encryption routine: this file is a tripwire. The cat is already on the phone.",
        "Fun fact: encrypting this file is the fastest way to get yourself quarantined.",
        "Balance carried forward: one nap, two treats, zero ransom payments.",
    ]

    /// Names for this install: one that sorts first and one that sorts last.
    public static func names(seed: UInt64) -> [String] {
        let a = Int((seed &* 0x9E3779B97F4A7C15) >> 33) % firstNames.count
        let b = Int((seed &* 0xC2B2AE3D27D4EB4F &+ 7) >> 33) % lastNames.count
        return [firstNames[a], lastNames[b]]
    }

    public static func body() -> Data { var g = SystemRandomNumberGenerator(); return body(using: &g) }

    public static func body<R: RandomNumberGenerator>(using rng: inout R) -> Data {
        var parts = [titles.randomElement(using: &rng)!]
        parts += lines.shuffled(using: &rng).prefix(Int.random(in: 4...6, using: &rng))
        parts.append(DecoyContent.signatures.randomElement(using: &rng)!)
        parts.append("ref \(DecoyContent.newCanaryID())")
        func rtfEscape(_ s: String) -> String {
            var o = ""
            for u in s.unicodeScalars {
                switch u {
                case "\\", "{", "}": o += "\\" + String(u)
                case _ where u.value < 128: o.unicodeScalars.append(u)
                default: o += "\\u\(Int16(truncatingIfNeeded: u.value > 0xFFFF ? 0x3F : u.value))?"
                }
            }
            return o
        }
        var text = #"{\rtf1\ansi\deff0 {\fonttbl {\f0 Helvetica;}}\f0\fs24 "# + parts.map(rtfEscape).joined(separator: "\\par\n")
        // Low-entropy padding made of plain ledger-looking rows (not spaces, which were a fingerprint too).
        var row = 1
        while text.utf8.count < 2048 { text += "\\par\nline \(row): 0.00"; row += 1 }
        return Data((text + "\\par}\n").utf8)
    }

    public static func isLegacy(_ d: Data) -> Bool { String(decoding: d.prefix(4096), as: UTF8.self).contains(legacyMarker) }
}

/// Keyed registry of canaries: path -> HMAC(key, path | sha256(body)). Stored in RamPart's state, 0600.
public final class RansomCanaryRegistry: @unchecked Sendable {
    let key: SymmetricKey
    public let url: URL
    private let lock = NSLock()
    private var marks: [String: String] = [:]

    /// Registry + per-install name seed straight from a deception state folder (same `decoy.key` / `canaries.json`
    /// that `DeceptionService` uses). For daemons that plant canaries without running the Cat & Mouse service
    /// (the root daemon): the key lives in that daemon's own state folder, 0600, owned by it.
    public static func load(directory: URL) throws -> (registry: RansomCanaryRegistry, seed: UInt64) {
        let t = try DecoyTagger.loadOrCreateKey(at: directory.appendingPathComponent("decoy.key"))
        return (RansomCanaryRegistry(tagger: t, url: directory.appendingPathComponent("canaries.json")), t.installSeed())
    }

    public init(tagger: DecoyTagger, url: URL) {
        key = tagger.key; self.url = url
        if let d = try? Data(contentsOf: url), let m = try? JSONDecoder().decode([String: String].self, from: d) { marks = m }
    }

    func mark(_ path: String, _ body: Data) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("canary|\(path)|\(deceptionSHA256(body))".utf8), using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }

    /// True only when the file at `path` is exactly what RamPart planted there.
    public func isOurs(_ path: String, body: Data) -> Bool {
        lock.lock(); let m = marks[path]; lock.unlock()
        guard let m, let given = Data(hexString: m) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(given, authenticating: Data("canary|\(path)|\(deceptionSHA256(body))".utf8), using: key)
    }
    public func isOurs(path: String) -> Bool { DecoyPlanter.readNoFollow(path).map { isOurs(path, body: $0) } ?? false }

    public var paths: [String] { lock.lock(); defer { lock.unlock() }; return marks.keys.sorted() }

    func save() {
        lock.lock(); let m = marks; lock.unlock()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? JSONEncoder().encode(m) { try? d.write(to: url, options: .atomic); _ = chmod(url.path, 0o600) }
    }

    /// Plants this install's canaries in each folder (never overwriting), and migrates legacy canaries:
    /// a legacy file still holding the old fixed sentence is removed and replaced by this install's names/bodies.
    /// Returns every canary path now active (for `RansomwareDetector.registerCanary`).
    @discardableResult
    public func plant(in dirs: [String], seed: UInt64, legacyNames: [String] = ["000 Budget Notes.rtf", "zzz Archive Notes.rtf"]) -> [String] {
        var active: [String] = []
        for d in dirs where DecoyPlanter.isRealDirectory(d) {
            for n in legacyNames {
                let p = d + "/" + n
                // Legacy canary (old fixed sentence and fixed name): remove it; this install's names replace it.
                if let old = DecoyPlanter.readNoFollow(p), RansomCanaryContent.isLegacy(old), old.count < 1 << 16 {
                    _ = lchflags(p, 0); _ = unlink(p)
                }
            }
            for n in RansomCanaryContent.names(seed: seed) {
                let p = d + "/" + n
                if active.contains(p) { continue }
                if isOurs(path: p) { active.append(p); continue }
                var st = stat(); if lstat(p, &st) == 0 { continue }   // a user file: leave it alone
                let body = RansomCanaryContent.body()
                if createExclusive(p, body) { remember(p, body); active.append(p) }
            }
        }
        save()
        return active
    }

    /// Removes only canaries that are still byte-for-byte what we planted, or legacy ones.
    @discardableResult
    public func remove(_ candidates: [String]? = nil) -> [String] {
        var removed: [String] = []
        for p in candidates ?? paths {
            guard let d = DecoyPlanter.readNoFollow(p), isOurs(p, body: d) || RansomCanaryContent.isLegacy(d) else { continue }
            _ = lchflags(p, 0)
            if unlink(p) == 0 { removed.append(p) }
            lock.lock(); marks[p] = nil; lock.unlock()
        }
        save()
        return removed
    }

    private func remember(_ p: String, _ body: Data) { lock.lock(); marks[p] = mark(p, body); lock.unlock() }

    private func createExclusive(_ p: String, _ body: Data) -> Bool {
        let fd = open(p, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o644)
        guard fd >= 0 else { return false }
        let ok = body.withUnsafeBytes { write(fd, $0.baseAddress, body.count) } == body.count
        close(fd)
        guard ok else { unlink(p); return false }
        DecoyPlanter.markNoSyncNoBackup(p); _ = lchflags(p, UInt32(UF_HIDDEN))
        return true
    }
}
