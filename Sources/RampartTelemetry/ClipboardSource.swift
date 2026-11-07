import Foundation
import AppKit
import CryptoKit
import RampartShared

/// Classifies clipboard text without keeping it. Pure; safe on any thread.
public enum ClipboardClassifier {
    public enum Class: String, Sendable { case text, command, risky }

    /// (reason, pattern). Case-insensitive. Matches ClickFix / fake-CAPTCHA style lures.
    static let riskyPatterns: [(String, NSRegularExpression)] = [
        ("fetch_pipe_shell", #"\b(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(\S*/)?((ba|z|da|k|tc|c|fi)?sh|python[0-9.]*|perl|ruby|osascript|node)\b"#),
        ("shell_eval_fetch", #"(\b(ba|z|da)?sh\s+-c\s*["']?\s*\$\(\s*(curl|wget)\b|\beval\s*["']?\s*\$\(\s*(curl|wget)\b|\b(ba|z)?sh\s*<\s*\(\s*(curl|wget)\b)"#),
        ("base64_decode", #"\bbase64\s+(-[a-z]*d[a-z]*\b|--decode\b|-D\b)"#),
        ("osascript_e", #"\bosascript\s+(-l\s+\S+\s+)?-e\b"#),
        ("dequarantine", #"\bxattr\s+(-[a-z]*[dc][a-z]*)\b[^\n;|&]*(com\.apple\.quarantine|\s/)|\bxattr\s+-c\b"#),
        ("chmod_exec_tmp", #"\bchmod\s+(\+x|[ugoa]*\+[rw]*x|[0-7]?[0-7]*[1357][0-7]{0,2})\s+["']?(/tmp/|/private/tmp/|/var/folders/|/private/var/folders/|\$TMPDIR|\$\{TMPDIR\}|/Users/Shared/|~/\.|\.?/\.)"#),
    ].map { ($0.0, try! NSRegularExpression(pattern: $0.1, options: [.caseInsensitive])) }

    static let commandWords: Set<String> = [
        "curl", "wget", "bash", "sh", "zsh", "sudo", "python", "python3", "perl", "ruby", "node", "osascript",
        "echo", "cd", "brew", "git", "npm", "npx", "pip", "pip3", "chmod", "chown", "xattr", "open", "defaults",
        "launchctl", "cat", "ls", "rm", "mv", "cp", "mkdir", "export", "eval", "base64", "openssl", "ditto",
        "hdiutil", "installer", "codesign", "spctl", "security", "sqlite3", "tar", "unzip", "nohup", "printf",
        "/bin/bash", "/bin/sh", "/bin/zsh", "/usr/bin/curl",
    ]

    /// Strips zero-width / bidi characters and collapses whitespace.
    public static func normalize(_ s: String) -> String {
        let invisible: Set<Unicode.Scalar> = ["\u{200B}", "\u{200C}", "\u{200D}", "\u{2060}", "\u{FEFF}", "\u{202E}", "\u{202D}", "\u{00A0}"]
        let cleaned = String(String.UnicodeScalarView(s.unicodeScalars.map { invisible.contains($0) ? " " : $0 }))
        return cleaned.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    public static func classify(_ raw: String) -> (cls: Class, reasons: [String]) {
        let s = normalize(raw)
        guard !s.isEmpty else { return (.text, []) }
        let range = NSRange(s.startIndex..., in: s)
        let reasons = riskyPatterns.compactMap { $0.1.firstMatch(in: s, range: range) != nil ? $0.0 : nil }
        if !reasons.isEmpty { return (.risky, reasons) }
        let first = s.split(separator: " ").first.map { String($0).lowercased() } ?? ""
        if commandWords.contains(first) || s.contains(" | ") || s.contains(" && ") { return (.command, []) }
        return (.text, [])
    }

    /// Tokens used for fingerprints: split on whitespace and shell metacharacters, lowercased, ≥ 3 chars.
    public static func tokens(_ s: String) -> Set<String> {
        let seps = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "|;&()<>`\"'$={}\\"))
        return Set(normalize(s).lowercased().components(separatedBy: seps).filter { $0.count >= 3 })
    }
}

/// Byte-for-byte mirror of `RampartBehaviour.ClipboardFingerprint` (telemetry can't import the behaviour
/// module). Produces `detail["clip_tokens"]`: comma-separated first 16 lowercase hex chars of
/// HMAC-SHA256(key: bootSalt, token). `bootSalt` is a private random 256-bit key shared in-process through
/// `RAMPART_CLIPFP_KEY` (not the world-readable boot UUID). The self-test cross-checks both implementations;
/// change them together.
public enum ClipFingerprint {
    public static let keyEnv = "RAMPART_CLIPFP_KEY"
    public static let bootSalt: String = {
        if let v = getenv(keyEnv).map({ String(cString: $0) }), v.count == 64, v.allSatisfy(\.isHexDigit) { return v }
        var bytes = [UInt8](repeating: 0, count: 32)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) != errSecSuccess {
            bytes = (0..<32).map { _ in UInt8.random(in: 0...255) }
        }
        let hex = bytes.map { String(format: "%02x", $0) }.joined()
        setenv(keyEnv, hex, 0)
        if let v = getenv(keyEnv).map({ String(cString: $0) }), v.count == 64 { return v }
        return hex
    }()

    static let separators = CharacterSet.whitespacesAndNewlines.union(CharacterSet(charactersIn: "|;&<>()`\"'{}$"))

    /// Split on whitespace and |;&<>()`"'{}$, lowercase, absolute paths -> last component, drop empty and
    /// "\\", de-duplicate in order.
    public static func tokens(_ text: String) -> [String] {
        var seen = Set<String>(); var out: [String] = []
        for raw in text.components(separatedBy: separators) {
            var t = raw.lowercased()
            if t.hasPrefix("/") && t.count > 1 { t = (t as NSString).lastPathComponent }
            if t.isEmpty || t == "\\" { continue }
            if seen.insert(t).inserted { out.append(t) }
        }
        return out
    }

    public static func hash(_ token: String, salt: String = bootSalt) -> String {
        HMAC<SHA256>.authenticationCode(for: Data(token.utf8), using: SymmetricKey(data: Data(salt.utf8)))
            .prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public static func fingerprint(_ text: String, salt: String = bootSalt) -> String {
        tokens(text).map { hash($0, salt: salt) }.joined(separator: ",")
    }
}

/// In-memory, time-limited record of recent command-like clipboard copies, kept only as salted
/// hashes: one of the whole normalized text and one per token. Never stores or logs the text.
/// `match(args:)` lets the exec path recognise "this command line was pasted from that copy".
/// To match across processes (agent copies, daemon sees exec), construct both with the same `salt`.
public final class ClipboardMemory: @unchecked Sendable {
    public struct Entry: Sendable {
        public let id: UUID
        public let date: Date
        public let cls: ClipboardClassifier.Class
        public let reasons: [String]
        public let sourceApp: String?
        public let textHash: String
        public let tokenFPs: Set<String>
    }
    public struct Match: Sendable {
        public let entry: Entry
        public let overlap: Double     // fraction of the copy's tokens present in the exec
        public let exact: Bool         // an argument (or the joined argv) equals the copied text
    }

    public let ttl: TimeInterval
    private let key: SymmetricKey
    private let lock = NSLock()
    private var entries: [Entry] = []
    public var maxEntries = 64

    public init(ttl: TimeInterval = 600, salt: Data? = nil) {
        self.ttl = ttl
        self.key = SymmetricKey(data: salt ?? Data((0..<32).map { _ in UInt8.random(in: 0...255) }))
    }

    func fp(_ s: String) -> String {
        HMAC<SHA256>.authenticationCode(for: Data(s.utf8), using: key).prefix(8).map { String(format: "%02x", $0) }.joined()
    }

    public func fingerprints(of text: String) -> (textHash: String, tokens: Set<String>) {
        (fp(ClipboardClassifier.normalize(text)), Set(ClipboardClassifier.tokens(text).map(fp)))
    }

    @discardableResult
    public func remember(text: String, cls: ClipboardClassifier.Class, reasons: [String], sourceApp: String?, date: Date = Date()) -> Entry {
        let f = fingerprints(of: text)
        let e = Entry(id: UUID(), date: date, cls: cls, reasons: reasons, sourceApp: sourceApp, textHash: f.textHash, tokenFPs: f.tokens)
        lock.lock(); defer { lock.unlock() }
        pruneLocked(now: date)
        entries.append(e)
        if entries.count > maxEntries { entries.removeFirst(entries.count - maxEntries) }
        return e
    }

    /// Re-creates an entry from a clipboard `SecurityEvent` produced by a memory with the same salt.
    public func ingest(_ ev: SecurityEvent) {
        guard ev.detail["type"] == "clipboard", let h = ev.detail["text_fp"] else { return }
        let toks = Set((ev.detail["token_fps"] ?? "").split(separator: ",").map(String.init))
        let e = Entry(id: UUID(), date: ev.date, cls: ClipboardClassifier.Class(rawValue: ev.detail["class"] ?? "") ?? .command,
                      reasons: (ev.detail["reasons"] ?? "").split(separator: ",").map(String.init),
                      sourceApp: ev.detail["source_app"], textHash: h, tokenFPs: toks)
        lock.lock(); pruneLocked(now: Date()); entries.append(e); lock.unlock()
    }

    private func pruneLocked(now: Date) { entries.removeAll { now.timeIntervalSince($0.date) > ttl } }

    public var count: Int { lock.lock(); defer { lock.unlock() }; pruneLocked(now: Date()); return entries.count }
    public func clear() { lock.lock(); entries.removeAll(); lock.unlock() }

    /// Best matching recent copy for an exec's argv, if any.
    public func match(args: [String], now: Date = Date()) -> Match? {
        lock.lock(); pruneLocked(now: now); let snapshot = entries; lock.unlock()
        guard !snapshot.isEmpty, !args.isEmpty else { return nil }
        let joined = args.joined(separator: " ")
        var hashes = Set(args.map { fp(ClipboardClassifier.normalize($0)) })
        hashes.insert(fp(ClipboardClassifier.normalize(joined)))
        let execTokens = Set(ClipboardClassifier.tokens(joined).map(fp))
        var best: Match?
        for e in snapshot.reversed() {
            let exact = hashes.contains(e.textHash)
            let inter = e.tokenFPs.intersection(execTokens).count
            let overlap = e.tokenFPs.isEmpty ? 0 : Double(inter) / Double(e.tokenFPs.count)
            guard exact || (inter >= 2 && overlap >= 0.5) else { continue }
            if best == nil || (exact && !best!.exact) || overlap > best!.overlap { best = Match(entry: e, overlap: exact ? 1 : overlap, exact: exact) }
        }
        return best
    }
}

/// Per-user clipboard watcher (runs in the session agent, not the root daemon). Polls `changeCount`
/// every `interval`; only on a change does it read the string, classify it, and drop it. Emits
/// `.other` events with `type=clipboard`, `class=command|risky`, `reasons`, `source_app`, `length`,
/// `text_fp`, `token_fps` (salted HMAC prefixes, for `ClipboardMemory`), and `clip_tokens`
/// (`ClipFingerprint`, the format the behaviour engine's R31 rule consumes). Plain text copies (class `text`, e.g. passwords)
/// emit nothing and are not remembered.
///
/// Privacy note: on macOS 15.4+ reading the *general* pasteboard programmatically can show the user a
/// paste-permission prompt. `isAvailable` is false when `accessBehavior == .alwaysDeny`.
public final class ClipboardSource: EventSource, CPUReporting {
    public let name = "clipboard"
    public let interval: TimeInterval
    public let memory: ClipboardMemory
    public let cpu = CPUMeter()
    /// Max characters read; longer copies are ignored (not commands).
    public var maxLength = 16 * 1024
    /// Bundle ID of the app that owned the copy. Default: the pasteboard's `org.nspasteboard.source`
    /// marker if present, else the frontmost application.
    public var frontmostApp: () -> String? = { NSWorkspace.shared.frontmostApplication?.bundleIdentifier }

    private let pasteboard: NSPasteboard
    private let queue = DispatchQueue(label: "app.rampart.telemetry.clipboard", qos: .utility)
    private var timer: DispatchSourceTimer?
    private var handler: (@Sendable (SecurityEvent) -> Void)?
    private var lastChange = -1
    public private(set) var changesSeen = 0

    public init(pasteboard: NSPasteboard = .general, interval: TimeInterval = 0.5, memory: ClipboardMemory = ClipboardMemory()) {
        self.pasteboard = pasteboard
        self.interval = interval
        self.memory = memory
    }

    public var isAvailable: Bool {
        if #available(macOS 15.4, *), pasteboard.name == .general, pasteboard.accessBehavior == .alwaysDeny { return false }
        return true
    }

    public func start(handler: @escaping @Sendable (SecurityEvent) -> Void) throws {
        stop()
        queue.sync {
            self.handler = handler
            lastChange = pasteboard.changeCount   // don't report what was already on the clipboard
            let t = DispatchSource.makeTimerSource(queue: queue)
            t.schedule(deadline: .now() + interval, repeating: interval, leeway: .milliseconds(Int(interval * 200)))
            t.setEventHandler { [weak self] in self?.poll() }
            timer = t
            t.resume()
        }
    }

    public func stop() { queue.sync { timer?.cancel(); timer = nil; handler = nil } }
    deinit { timer?.cancel() }

    /// One poll, synchronously (tests).
    public func pollNow() { queue.sync { poll() } }

    private func poll() {
        cpu.measure {
            let cc = pasteboard.changeCount
            guard cc != lastChange else { return }
            lastChange = cc
            changesSeen += 1
            let app = (pasteboard.string(forType: NSPasteboard.PasteboardType("org.nspasteboard.source"))).flatMap { $0.isEmpty ? nil : $0 }
                ?? frontmostApp()
            // Skip transient/concealed copies (password managers mark these).
            let types = pasteboard.types ?? []
            if types.contains(NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType"))
                || types.contains(NSPasteboard.PasteboardType("org.nspasteboard.TransientType")) { return }
            guard types.contains(.string), var text = pasteboard.string(forType: .string), text.count <= maxLength else { return }
            let (cls, reasons) = ClipboardClassifier.classify(text)
            guard cls != .text else { text = ""; return }
            let entry = memory.remember(text: text, cls: cls, reasons: reasons, sourceApp: app)
            let clipTokens = ClipFingerprint.fingerprint(ClipboardClassifier.normalize(text))
            let length = text.count
            text = ""
            var detail: [String: String] = [
                "type": "clipboard", "class": cls.rawValue, "length": String(length),
                "text_fp": entry.textHash, "token_fps": entry.tokenFPs.sorted().joined(separator: ","),
                "change_count": String(cc), "clip_tokens": clipTokens,
            ]
            if !reasons.isEmpty { detail["reasons"] = reasons.joined(separator: ",") }
            if let app { detail["source_app"] = app }
            handler?(SecurityEvent(kind: .other, detail: detail, source: name))
        }
    }
}
