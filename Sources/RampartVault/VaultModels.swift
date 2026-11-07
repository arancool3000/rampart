import Foundation
import Security

public enum VaultItemKind: String, Codable, Sendable, CaseIterable, Identifiable {
    case login, secureNote, card, wifi, totp
    public var id: String { rawValue }
    public var label: String {
        switch self {
        case .login: return "Login"
        case .secureNote: return "Secure Note"
        case .card: return "Card"
        case .wifi: return "Wi-Fi"
        case .totp: return "Authenticator"
        }
    }
    public var symbol: String {
        switch self {
        case .login: return "key.fill"
        case .secureNote: return "note.text"
        case .card: return "creditcard.fill"
        case .wifi: return "wifi"
        case .totp: return "clock.badge.checkmark"
        }
    }
}

public struct CardDetails: Codable, Hashable, Sendable {
    public var holder = ""
    public var number = ""
    public var expiryMonth = ""
    public var expiryYear = ""
    public var cvv = ""
    public var pin = ""
    public init() {}
    public var brand: String {
        let d = number.filter(\.isNumber)
        if d.hasPrefix("4") { return "Visa" }
        if let p2 = Int(d.prefix(2)), (51...55).contains(p2) { return "Mastercard" }
        if let p4 = Int(d.prefix(4)), (2221...2720).contains(p4) { return "Mastercard" }
        if d.hasPrefix("34") || d.hasPrefix("37") { return "American Express" }
        if d.hasPrefix("6011") || d.hasPrefix("65") { return "Discover" }
        return "Card"
    }
    public var masked: String { let d = number.filter(\.isNumber); return d.count >= 4 ? "•••• " + d.suffix(4) : "" }
}

public struct WiFiDetails: Codable, Hashable, Sendable {
    public var ssid = ""
    public var security = "WPA2/WPA3 Personal"
    public var hidden = false
    public init() {}
}

public struct CustomField: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var name: String
    public var value: String
    public var concealed: Bool
    public init(name: String, value: String, concealed: Bool = false) { self.name = name; self.value = value; self.concealed = concealed }
}

public struct PasswordHistoryEntry: Codable, Hashable, Sendable {
    public var password: String
    public var replaced: Date
    public init(password: String, replaced: Date) { self.password = password; self.replaced = replaced }
}

public struct Attachment: Codable, Hashable, Sendable, Identifiable {
    public static let maxBytes = 1_048_576
    public var id = UUID()
    public var name: String
    public var data: Data
    public var added = Date()
    public init(name: String, data: Data) { self.name = name; self.data = data }
}

public struct VaultItem: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var kind: VaultItemKind
    public var title: String
    public var folderID: UUID?
    public var tags: [String] = []
    public var favourite = false
    public var created = Date()
    public var modified = Date()

    public var username = ""
    public var password = ""
    public var passwordModified: Date?
    public var urls: [String] = []
    public var notes = ""
    /// Base32 secret or otpauth:// URI.
    public var totpSecret: String?
    public var card: CardDetails?
    public var wifi: WiFiDetails?
    public var customFields: [CustomField] = []
    public var passwordHistory: [PasswordHistoryEntry] = []
    public var attachments: [Attachment] = []

    public init(kind: VaultItemKind, title: String) {
        self.kind = kind; self.title = title
        if kind == .card { card = CardDetails() }
        if kind == .wifi { wifi = WiFiDetails() }
    }

    /// Called by the store when a saved edit changed the password (not per keystroke).
    mutating func recordHistory(_ old: String) {
        passwordModified = Date()
        guard !old.isEmpty else { return }
        passwordHistory.insert(PasswordHistoryEntry(password: old, replaced: Date()), at: 0)
        if passwordHistory.count > 20 { passwordHistory.removeLast(passwordHistory.count - 20) }
    }

    public var totp: TOTP? { totpSecret.flatMap { TOTP(string: $0) } }

    /// Registrable-looking host of the first URL ("accounts.google.com" -> "google.com").
    public var primaryDomain: String? { urls.lazy.compactMap(Self.domain).first }

    public static func domain(_ s: String) -> String? {
        let withScheme = s.contains("://") ? s : "https://" + s
        guard let host = URL(string: withScheme)?.host?.lowercased(), host.contains(".") else { return nil }
        let parts = host.split(separator: ".")
        let twoLevel: Set<String> = ["co.uk", "com.au", "co.jp", "co.nz", "com.br", "co.in", "org.uk", "ac.uk", "gov.uk"]
        if parts.count >= 3, twoLevel.contains(parts.suffix(2).joined(separator: ".")) { return parts.suffix(3).joined(separator: ".") }
        return parts.suffix(2).joined(separator: ".")
    }

    public var subtitle: String {
        switch kind {
        case .login: return username.isEmpty ? (primaryDomain ?? "") : username
        case .card: return card.map { "\($0.brand) \($0.masked)" } ?? ""
        case .wifi: return wifi?.ssid ?? ""
        case .totp: return totp?.issuer ?? username
        case .secureNote: return String(notes.prefix(60)).replacingOccurrences(of: "\n", with: " ")
        }
    }

    public mutating func addAttachment(name: String, data: Data) throws {
        guard data.count <= Attachment.maxBytes else { throw VaultError.attachmentTooLarge }
        attachments.append(Attachment(name: name, data: data))
    }

    /// Searchable text, lowercased (never includes secrets).
    public var searchText: String {
        ([title, username, notes] + urls + tags + [wifi?.ssid ?? "", card?.holder ?? ""]).joined(separator: " ").lowercased()
    }
}

public struct VaultFolder: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var name: String
    public init(name: String) { self.name = name }
}

public struct VaultSettings: Codable, Hashable, Sendable {
    public var autoLockMinutes = 5
    public var lockOnSleep = true
    public var lockOnScreenLock = true
    public var clipboardClearSeconds = 30
    /// On by default (opt-out): send 5-character SHA-1 prefixes to the Pwned Passwords range API.
    public var breachCheckEnabled = true
    /// 1 = automatic breach monitoring default applied (older vaults had the check off by default).
    public var breachDefaultsVersion = 1
    public var generator = PasswordGenerator.Options()
    public var passphrase = PasswordGenerator.PassphraseOptions()
    public init() {}

    enum CodingKeys: String, CodingKey {
        case autoLockMinutes, lockOnSleep, lockOnScreenLock, clipboardClearSeconds, breachCheckEnabled, breachDefaultsVersion, generator, passphrase
    }

    /// Tolerates settings written by older versions (missing keys keep their defaults).
    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = VaultSettings()
        autoLockMinutes = try c.decodeIfPresent(Int.self, forKey: .autoLockMinutes) ?? d.autoLockMinutes
        lockOnSleep = try c.decodeIfPresent(Bool.self, forKey: .lockOnSleep) ?? d.lockOnSleep
        lockOnScreenLock = try c.decodeIfPresent(Bool.self, forKey: .lockOnScreenLock) ?? d.lockOnScreenLock
        clipboardClearSeconds = try c.decodeIfPresent(Int.self, forKey: .clipboardClearSeconds) ?? d.clipboardClearSeconds
        generator = try c.decodeIfPresent(PasswordGenerator.Options.self, forKey: .generator) ?? d.generator
        passphrase = try c.decodeIfPresent(PasswordGenerator.PassphraseOptions.self, forKey: .passphrase) ?? d.passphrase
        let version = try c.decodeIfPresent(Int.self, forKey: .breachDefaultsVersion) ?? 0
        let stored = try c.decodeIfPresent(Bool.self, forKey: .breachCheckEnabled)
        // Before version 1 the check was opt-in and off by default; automatic monitoring is now the default.
        breachCheckEnabled = version >= 1 ? (stored ?? true) : true
        breachDefaultsVersion = 1
    }
}

/// Unencrypted-in-memory metadata that is stored encrypted in the vault file.
public struct VaultMeta: Codable, Hashable, Sendable {
    public var folders: [VaultFolder] = []
    public var settings = VaultSettings()
    public var created = Date()
    /// Hashed breach-check results (see BreachCache).
    public var breachCache = BreachCache()
    /// Display order of authenticator accounts (item ids); unknown items sort after these.
    public var authenticatorOrder: [UUID] = []
    /// Items (besides secure notes, which always are) that require Touch ID or a password to view.
    public var lockedItems: [UUID] = []
    public init() {}

    /// Secure notes and items marked "Require Touch ID to view" stay hidden even while the vault is unlocked.
    public func requiresItemUnlock(_ item: VaultItem) -> Bool { item.kind == .secureNote || lockedItems.contains(item.id) }

    enum CodingKeys: String, CodingKey { case folders, settings, created, breachCache, authenticatorOrder, lockedItems }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        folders = try c.decodeIfPresent([VaultFolder].self, forKey: .folders) ?? []
        settings = try c.decodeIfPresent(VaultSettings.self, forKey: .settings) ?? VaultSettings()
        created = try c.decodeIfPresent(Date.self, forKey: .created) ?? Date()
        breachCache = try c.decodeIfPresent(BreachCache.self, forKey: .breachCache) ?? BreachCache()
        authenticatorOrder = try c.decodeIfPresent([UUID].self, forKey: .authenticatorOrder) ?? []
        lockedItems = try c.decodeIfPresent([UUID].self, forKey: .lockedItems) ?? []
    }
}

public enum VaultError: Error, LocalizedError, Equatable {
    case noVault, alreadyExists, locked, wrongPassword, tampered, unsupportedVersion(Int), badFormat(String)
    case attachmentTooLarge, io(String), weakMasterPassword, biometry(String), biometryChanged, keychain(Int32), cancelled, secureEnclaveFailed(String)

    public var errorDescription: String? {
        switch self {
        case .noVault: return "No vault has been created yet."
        case .alreadyExists: return "A vault already exists."
        case .locked: return "The vault is locked."
        case .wrongPassword: return "That master password is not correct."
        case .tampered: return "The vault file failed its integrity check. It may be damaged or altered. Restore a backup."
        case .unsupportedVersion(let v): return "This vault was written by a newer version of RamPart (format \(v))."
        case .badFormat(let s): return "The vault file is not readable: \(s)."
        case .attachmentTooLarge: return "Attachments can be at most 1 MB."
        case .io(let s): return s
        case .weakMasterPassword: return "Choose a stronger master password (at least 10 characters and rated Fair or better)."
        case .biometry(let s): return s
        case .biometryChanged: return "Your Touch ID fingerprints changed, so Touch ID unlock was turned off. Unlock with your master password to turn it on again."
        case .keychain(let s): return "Keychain error \(s): " + ((SecCopyErrorMessageString(s, nil) as String?) ?? "unknown")
        case .cancelled: return "Cancelled."
        case .secureEnclaveFailed(let s): return "This Mac's security chip couldn't open the vault key (\(s)). Unlock with your master password."
        }
    }
}
