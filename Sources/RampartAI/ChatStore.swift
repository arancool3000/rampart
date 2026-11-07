import Foundation
import CryptoKit
import RampartShared

// Chat history for the AI Assistant. Holds only redacted text: exactly what was sent to and received from Gemini.
// Encrypted at rest with AES-GCM in ~/Library/Application Support/Rampart/Chats, one file per chat.
// Key: 32 random bytes in `chats.key` (0600) in the same 0700 folder. No Keychain use, so no prompts.

public struct StoredChatMessage: Codable, Hashable, Sendable, Identifiable {
    public enum Kind: String, Codable, Sendable { case text, reply, scam, url, detection, plan, error }
    public var id: UUID
    public var isUser: Bool
    public var date: Date
    public var kind: Kind
    public var title: String?
    public var text: String                 // user text (redacted) or main text of the answer
    public var reply: AssistantReply?
    public var scam: AIScamAssessment?
    public var url: URLExplanation?
    public var detection: DetectionExplanation?
    public var plan: PosturePlan?
    public var sent: String?                // exactly what was sent (already redacted)
    public var redactionSummary: String?
    public var meta: String?
    public init(id: UUID = UUID(), isUser: Bool, date: Date = Date(), kind: Kind, title: String? = nil, text: String,
                reply: AssistantReply? = nil, scam: AIScamAssessment? = nil, url: URLExplanation? = nil,
                detection: DetectionExplanation? = nil, plan: PosturePlan? = nil,
                sent: String? = nil, redactionSummary: String? = nil, meta: String? = nil) {
        self.id = id; self.isUser = isUser; self.date = date; self.kind = kind; self.title = title; self.text = text
        self.reply = reply; self.scam = scam; self.url = url; self.detection = detection; self.plan = plan
        self.sent = sent; self.redactionSummary = redactionSummary; self.meta = meta
    }
}

public struct ChatRecord: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID
    public var title: String
    public var titleIsCustom: Bool
    public var created: Date
    public var updated: Date
    public var pinned: Bool
    public var mode: String                 // "Ask", "Scam Check", "Link Check"
    public var messages: [StoredChatMessage]
    public init(id: UUID = UUID(), title: String = "New Chat", titleIsCustom: Bool = false, created: Date = Date(),
                updated: Date = Date(), pinned: Bool = false, mode: String = "Ask", messages: [StoredChatMessage] = []) {
        self.id = id; self.title = title; self.titleIsCustom = titleIsCustom; self.created = created; self.updated = updated
        self.pinned = pinned; self.mode = mode; self.messages = messages
    }

    /// Case- and diacritic-insensitive search across title and message text.
    public func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if q.isEmpty { return true }
        func has(_ s: String?) -> Bool { s?.range(of: q, options: [.caseInsensitive, .diacriticInsensitive]) != nil }
        return has(title) || messages.contains { m in
            has(m.text) || has(m.title) || m.reply.map { r in has(r.answer) || r.steps.contains(where: has) } == true
                || m.scam.map { s in s.reasons.contains(where: has) || has(s.advice) } == true
                || m.url.map { u in has(u.advice) || u.reasons.contains { has($0.signal) || has($0.explanation) } } == true
                || m.detection.map { d in has(d.whatItMeans) || d.nextSteps.contains(where: has) } == true
                || m.plan.map { p in p.items.contains { has($0.title) || has($0.why) } } == true
        }
    }
}

// MARK: - Titles and grouping

public enum ChatTitle {
    static let fillers = ["can you tell me", "could you tell me", "can you", "could you", "please", "i want to know", "i'd like to know",
                          "tell me", "explain to me", "hey", "hi", "hello", "so", "ok", "okay"]

    /// Short local title from the first question: first sentence, filler removed, ≤ 42 chars on a word boundary.
    public static func make(from question: String, maxLength: Int = 42) -> String {
        var t = question.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespacesAndNewlines)
        while t.contains("  ") { t = t.replacingOccurrences(of: "  ", with: " ") }
        if let r = t.range(of: #"[.?!](\s|$)"#, options: .regularExpression), t.distance(from: t.startIndex, to: r.lowerBound) >= 8 {
            t = String(t[..<r.lowerBound])
        }
        var changed = true
        while changed {
            changed = false
            for f in fillers {
                let lower = t.lowercased()
                if lower.hasPrefix(f + " ") || lower.hasPrefix(f + ",") {
                    t = String(t.dropFirst(f.count)).trimmingCharacters(in: CharacterSet(charactersIn: " ,"))
                    changed = true
                }
            }
        }
        t = t.trimmingCharacters(in: CharacterSet(charactersIn: " ?.!,:;\"'"))
        if t.isEmpty { return "New Chat" }
        if t.count > maxLength {
            let cut = t.prefix(maxLength)
            t = (cut.lastIndex(of: " ").map { String(cut[..<$0]) } ?? String(cut)).trimmingCharacters(in: CharacterSet(charactersIn: " ,;:-")) + "…"
        }
        return t.prefix(1).uppercased() + t.dropFirst()
    }
}

public enum ChatGroup: String, CaseIterable, Sendable {
    case pinned = "Pinned", today = "Today", yesterday = "Yesterday", previous7 = "Previous 7 Days", older = "Older"

    public static func of(_ c: ChatRecord, now: Date = Date(), calendar: Calendar = .current) -> ChatGroup {
        if c.pinned { return .pinned }
        if calendar.isDate(c.updated, inSameDayAs: now) { return .today }
        if let y = calendar.date(byAdding: .day, value: -1, to: now), calendar.isDate(c.updated, inSameDayAs: y) { return .yesterday }
        let startToday = calendar.startOfDay(for: now)
        if let d7 = calendar.date(byAdding: .day, value: -7, to: startToday), c.updated >= d7 { return .previous7 }
        return .older
    }

    /// Groups in display order, newest first inside each group; empty groups omitted.
    public static func grouped(_ chats: [ChatRecord], now: Date = Date(), calendar: Calendar = .current) -> [(ChatGroup, [ChatRecord])] {
        let d = Dictionary(grouping: chats) { of($0, now: now, calendar: calendar) }
        return allCases.compactMap { g in d[g].map { (g, $0.sorted { $0.updated > $1.updated }) } }
    }
}

// MARK: - Encrypted store

public final class ChatStore: @unchecked Sendable {
    public enum StoreError: Error, Equatable { case tampered(String), io(String) }

    public let directory: URL
    private let lock = NSLock()
    private var cachedKey: SymmetricKey?
    /// Files that failed authentication on the last load (tampered or corrupt); never silently decoded.
    public private(set) var unreadable: [String] = []

    public static var defaultDirectory: URL { Paths.userRoot.appendingPathComponent("Chats", isDirectory: true) }
    public init(directory: URL = ChatStore.defaultDirectory) { self.directory = directory }

    private var keyURL: URL { directory.appendingPathComponent("chats.key") }
    private func fileURL(_ id: UUID) -> URL { directory.appendingPathComponent(id.uuidString + ".chat") }

    private func ensureDirectory() throws {
        let fm = FileManager.default
        // Never write chats through a symlinked folder (it could point anywhere).
        if let t = try? fm.attributesOfItem(atPath: directory.path)[.type] as? FileAttributeType, t == .typeSymbolicLink {
            throw StoreError.io("chat folder is a symbolic link")
        }
        if !fm.fileExists(atPath: directory.path) {
            try fm.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        }
        try? fm.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory.path)
    }

    /// Largest chat file read back (a long chat is well under 1 MB); larger files are treated as damaged.
    public static let maxFileBytes = 8 * 1024 * 1024
    /// At most this many chat files are opened per load (resource cap against a flooded folder).
    public static let maxFiles = 2000

    /// Reads a regular file without following a symlink at the final component, capped at `limit` bytes.
    static func readRegular(_ url: URL, limit: Int) -> Data? {
        let fd = Darwin.open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else { return nil }
        let h = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size <= off_t(limit) else { return nil }
        guard let d = try? h.read(upToCount: limit + 1), d.count <= limit else { return nil }
        return d
    }

    private func key(create: Bool) throws -> SymmetricKey? {
        if let k = cachedKey { return k }
        let fm = FileManager.default
        if let d = Self.readRegular(keyURL, limit: 64), d.count == 32 {
            // Keep the key private to this user even if something loosened its mode.
            try? fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: keyURL.path)
            cachedKey = SymmetricKey(data: d); return cachedKey
        }
        guard create else { return nil }
        try ensureDirectory()
        let k = SymmetricKey(size: .bits256)
        let d = k.withUnsafeBytes { Data($0) }
        guard fm.createFile(atPath: keyURL.path, contents: d, attributes: [.posixPermissions: 0o600]) else { throw StoreError.io("key") }
        cachedKey = k
        return k
    }

    /// Seals with the chat id as associated data, so files can't be swapped between chats.
    static func seal(_ chat: ChatRecord, key: SymmetricKey) throws -> Data {
        let enc = JSONEncoder()
        let plain = try enc.encode(chat)
        guard let combined = try AES.GCM.seal(plain, using: key, authenticating: Data(chat.id.uuidString.utf8)).combined else { throw StoreError.io("seal") }
        return Data("RPC1".utf8) + combined
    }

    static func open(_ data: Data, id: UUID, key: SymmetricKey) throws -> ChatRecord {
        guard data.count > 4 + 28, data.prefix(4) == Data("RPC1".utf8) else { throw StoreError.tampered(id.uuidString) }
        do {
            let box = try AES.GCM.SealedBox(combined: data.dropFirst(4))
            let plain = try AES.GCM.open(box, using: key, authenticating: Data(id.uuidString.utf8))
            let dec = JSONDecoder()
            let c = try dec.decode(ChatRecord.self, from: plain)
            guard c.id == id else { throw StoreError.tampered(id.uuidString) }
            return c
        } catch { throw StoreError.tampered(id.uuidString) }
    }

    public func save(_ chat: ChatRecord) throws {
        lock.lock(); defer { lock.unlock() }
        guard let k = try key(create: true) else { throw StoreError.io("key") }
        try ensureDirectory()
        let data = try Self.seal(chat, key: k)
        let url = fileURL(chat.id)
        try data.write(to: url, options: [.atomic])
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    public func load(_ id: UUID) throws -> ChatRecord {
        lock.lock(); defer { lock.unlock() }
        guard let k = try key(create: false), let d = Self.readRegular(fileURL(id), limit: Self.maxFileBytes) else { throw StoreError.io("missing") }
        return try Self.open(d, id: id, key: k)
    }

    /// All readable chats, newest first. Tampered files are listed in `unreadable` and left untouched.
    public func loadAll() -> [ChatRecord] {
        lock.lock(); defer { lock.unlock() }
        unreadable = []
        guard let k = try? key(create: false),
              let names = try? FileManager.default.contentsOfDirectory(atPath: directory.path) else { return [] }
        var out: [ChatRecord] = []
        for n in names.filter({ $0.hasSuffix(".chat") }).prefix(Self.maxFiles) {
            guard let id = UUID(uuidString: String(n.dropLast(5))), fileURL(id).lastPathComponent == n else { unreadable.append(n); continue }
            guard let d = Self.readRegular(fileURL(id), limit: Self.maxFileBytes) else { unreadable.append(n); continue }
            if let c = try? Self.open(d, id: id, key: k) { out.append(c) } else { unreadable.append(n) }
        }
        return out.sorted { $0.updated > $1.updated }
    }

    public func delete(_ id: UUID) {
        lock.lock(); defer { lock.unlock() }
        try? FileManager.default.removeItem(at: fileURL(id))
    }

    /// Deletes every chat and the key (old files become unrecoverable even if a copy exists elsewhere).
    public func deleteAll() {
        lock.lock(); defer { lock.unlock() }
        let fm = FileManager.default
        for n in (try? fm.contentsOfDirectory(atPath: directory.path)) ?? [] where n.hasSuffix(".chat") {
            try? fm.removeItem(at: directory.appendingPathComponent(n))
        }
        try? fm.removeItem(at: keyURL)
        cachedKey = nil
        unreadable = []
    }
}
