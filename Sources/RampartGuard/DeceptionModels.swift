import Foundation
import CryptoKit
import RampartShared

// Cat & Mouse: RamPart's deception mode (decoys, mazes, tarpit). Opt-in, off by default.
//
// HONEST LIMITS (also shown in the UI):
// - Without the Endpoint Security entitlement we see file reads only after they happen, via eslogger
//   (root + Full Disk Access) or FSEvents. We cannot block the read; we detect it, then respond.
// - A decoy only catches code that goes looking for it. It is a tripwire, not a wall.
// - Plain FSEvents does not report reads, only writes/renames/deletes. Read detection needs eslogger.

/// What a decoy pretends to be.
public enum DecoyKind: String, Codable, Sendable, CaseIterable {
    case passwordsSheet      // "All My Passwords.xlsx.txt"
    case cryptoSeed          // "Crypto Wallet Seed.txt"
    case sshKey              // ~/.ssh/id_rsa_backup
    case awsCredentials      // ~/.aws/credentials_old
    case browserLoginData    // decoy browser profile "Login Data"
    case mazeNote            // breadcrumb inside the maze
    case mazeDir             // a maze directory (registered so removal is exact)
    case mazeLink            // a symlink inside the maze (loops stay inside the tree)

    public var isFile: Bool { self != .mazeDir && self != .mazeLink }
}

/// One RamPart-owned decoy. `tag` = HMAC-SHA256(key, path | kind | contentSHA256 | created) proves we made it,
/// so "Remove all decoys" can never delete a file a user (or attacker) put at the same path.
public struct DecoyRecord: Codable, Hashable, Identifiable, Sendable {
    public var id: String { path }
    public var path: String
    public var kind: DecoyKind
    public var contentSHA256: String     // empty for directories; link target for links
    public var created: Date
    public var tag: String
    public var canaryID: String          // appears in the content; lets a leaked copy be traced back
    public init(path: String, kind: DecoyKind, contentSHA256: String, created: Date, tag: String, canaryID: String) {
        self.path = path; self.kind = kind; self.contentSHA256 = contentSHA256
        self.created = created; self.tag = tag; self.canaryID = canaryID
    }
    public var displayName: String { (path as NSString).lastPathComponent }
}

/// Signs and verifies registry entries. The key is 32 random bytes in a 0600 file next to the registry
/// (no Keychain: a fresh binary reading the login keychain pops a dialog).
public struct DecoyTagger: Sendable {
    let key: SymmetricKey
    public init(key: SymmetricKey) { self.key = key }
    public init(keyData: Data) { self.key = SymmetricKey(data: keyData) }

    static func message(path: String, kind: DecoyKind, content: String, created: Date) -> Data {
        Data("rampart-decoy-v1|\(path)|\(kind.rawValue)|\(content)|\(Int(created.timeIntervalSince1970))".utf8)
    }
    public func tag(path: String, kind: DecoyKind, contentSHA256: String, created: Date) -> String {
        let mac = HMAC<SHA256>.authenticationCode(for: Self.message(path: path, kind: kind, content: contentSHA256, created: created), using: key)
        return Data(mac).map { String(format: "%02x", $0) }.joined()
    }
    /// Per-install randomness for decoy names (stable for this install, unpredictable across installs).
    public func installSeed() -> UInt64 {
        let mac = HMAC<SHA256>.authenticationCode(for: Data("rampart-decoy-names".utf8), using: key)
        return Data(mac).prefix(8).reduce(0) { $0 << 8 | UInt64($1) }
    }
    public func verify(_ r: DecoyRecord) -> Bool {
        guard let given = Data(hexString: r.tag) else { return false }
        return HMAC<SHA256>.isValidAuthenticationCode(given, authenticating: Self.message(path: r.path, kind: r.kind, content: r.contentSHA256, created: r.created), using: key)
    }

    /// Loads (or creates) the key file with 0600 permissions; refuses symlinks and wrong sizes.
    public static func loadOrCreateKey(at url: URL) throws -> DecoyTagger {
        let fm = FileManager.default
        var st = stat()
        if lstat(url.path, &st) == 0 {
            guard (st.st_mode & S_IFMT) == S_IFREG, st.st_size == 32, st.st_uid == getuid() else { throw DeceptionError.unsafePath(url.path) }
            return DecoyTagger(keyData: try Data(contentsOf: url))
        }
        try fm.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, 32, &bytes) == errSecSuccess else { throw DeceptionError.io("random") }
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw DeceptionError.io("key create") }
        defer { close(fd) }
        guard write(fd, bytes, 32) == 32 else { throw DeceptionError.io("key write") }
        return DecoyTagger(keyData: Data(bytes))
    }
}

public enum DeceptionError: Error, Equatable, CustomStringConvertible {
    case unsafePath(String), exists(String), io(String), outsideRoot(String), disabled, bindRefused(String)
    public var description: String {
        switch self {
        case .unsafePath(let p): return "unsafe path (symlink, wrong owner or type): \(p)"
        case .exists(let p): return "a file already exists here, leaving it alone: \(p)"
        case .io(let s): return "I/O error: \(s)"
        case .outsideRoot(let p): return "path escapes the decoy tree: \(p)"
        case .disabled: return "Cat & Mouse is off"
        case .bindRefused(let s): return "tarpit bind refused: \(s)"
        }
    }
}

/// JSON registry of every decoy RamPart planted. Atomic writes, 0600.
public final class DecoyRegistry: @unchecked Sendable {
    public let url: URL
    private let lock = NSLock()
    private var records: [String: DecoyRecord] = [:]
    public init(url: URL) {
        self.url = url
        if let d = try? Data(contentsOf: url), let list = try? JSONDecoder.deception.decode([DecoyRecord].self, from: d) {
            for r in list { records[r.path] = r }
        }
    }
    public var all: [DecoyRecord] { lock.lock(); defer { lock.unlock() }; return records.values.sorted { $0.path < $1.path } }
    public func record(at path: String) -> DecoyRecord? { lock.lock(); defer { lock.unlock() }; return records[path] }
    public func add(_ r: DecoyRecord) { lock.lock(); records[r.path] = r; lock.unlock() }
    public func remove(_ path: String) { lock.lock(); records[path] = nil; lock.unlock() }
    public func save() throws {
        let data = try JSONEncoder.deception.encode(all)
        try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: url, options: .atomic)
        _ = chmod(url.path, 0o600)
    }
    /// Longest registered maze root containing `path` (for "is this inside the maze?").
    public var mazeRoots: [String] {
        all.filter { $0.kind == .mazeDir && $0.contentSHA256 == "maze-root" }.map(\.path)
    }
}

extension JSONEncoder {
    static var deception: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e }
}
extension JSONDecoder {
    static var deception: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }
}

extension Data {
    init?(hexString s: String) {
        guard s.count % 2 == 0 else { return nil }
        var out = Data(capacity: s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            guard let b = UInt8(s[i..<j], radix: 16) else { return nil }
            out.append(b); i = j
        }
        self = out
    }
}

func deceptionSHA256(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }

/// Tone of every Cat & Mouse sentence. Serious is plain wording for people who prefer it.
public enum DeceptionTone: String, Codable, Sendable, CaseIterable { case playful, serious }

/// User settings, persisted by the daemon. Every switch defaults to off.
public struct DeceptionConfig: Codable, Hashable, Sendable {
    public var decoysEnabled = false
    public var mazeEnabled = false
    public var tarpitEnabled = false
    /// Who may reach the lure. Loopback by default; local subnet or anywhere are separate explicit choices.
    public var lureScope: LureScope = .loopback
    /// High port that looks juicy ("Backup NAS"). 2222 = fake SSH, 5000/8080 = fake NAS web login, else telnet-style.
    public var tarpitPort: UInt16 = 2222
    /// Decoys are hidden in Finder by default so you don't open them yourself; visible decoys lure humans too.
    public var decoysVisible = false
    public var tone: DeceptionTone = .playful
    public init() {}
}
