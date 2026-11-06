import Foundation
import Security

/// Thin wrapper over the macOS login keychain (the file-based keychain; this app has no
/// keychain-access-groups entitlement, so the data-protection keychain is unavailable: -34018).
public enum Keychain {
    public static func setGeneric(service: String, account: String, data: Data, label: String? = nil) throws {
        var add: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                  kSecAttrService as String: service, kSecAttrAccount as String: account,
                                  kSecValueData as String: data]
        if let label { add[kSecAttrLabel as String] = label }
        var s = SecItemAdd(add as CFDictionary, nil)
        if s == errSecDuplicateItem {
            let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
            s = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        }
        guard s == errSecSuccess else { throw VaultError.keychain(s) }
    }

    public static func readGeneric(service: String, account: String) throws -> Data? {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
                                kSecAttrAccount as String: account, kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if s == errSecItemNotFound { return nil }
        guard s == errSecSuccess else { throw VaultError.keychain(s) }
        return out as? Data
    }

    @discardableResult
    public static func deleteGeneric(service: String, account: String? = nil) -> Bool {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service]
        if let account { q[kSecAttrAccount as String] = account }
        let s = SecItemDelete(q as CFDictionary)
        return s == errSecSuccess || s == errSecItemNotFound
    }

    /// True when the data-protection keychain refuses us for lack of an entitlement (expected for this app).
    /// Probes with a throwaway item under `service` and removes it if the add unexpectedly succeeds.
    public static func dataProtectionKeychainMissingEntitlement(probeService: String) -> Bool {
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: probeService,
                                kSecAttrAccount as String: "dp-probe", kSecValueData as String: Data([0]),
                                kSecUseDataProtectionKeychain as String: true]
        let s = SecItemAdd(q as CFDictionary, nil)
        if s == errSecSuccess || s == errSecDuplicateItem {
            var d = q; d.removeValue(forKey: kSecValueData as String); SecItemDelete(d as CFDictionary)
            return false
        }
        return s == errSecMissingEntitlement
    }
}

// MARK: - Import from / export to the login keychain

/// One login-keychain entry's public attributes. Listing these never reveals a secret and never prompts.
public struct KeychainEntry: Identifiable, Hashable, Sendable {
    public enum Kind: String, Sendable { case internet, generic }
    public var id: Data { persistentRef }
    public var kind: Kind
    public var label: String
    public var account: String
    /// Server (internet) or service (generic).
    public var server: String
    public var path: String
    public var modified: Date?
    public var persistentRef: Data

    /// Heuristic: hides app tokens and system items that aren't website or user passwords.
    public var looksLikeUserPassword: Bool {
        if kind == .internet { return true }
        let s = server.lowercased()
        let systemPrefixes = ["com.apple.", "apple", "app.rampart", "ids:", "icloud", "safari", "airport", "accountsd", "keychain", "com.google.chrome",
                              "chrome safe storage", "brave", "microsoft", "teams", "slack", "vscode", "github.com/", "gh:", "xcode", "docker", "cloudkit"]
        return !account.isEmpty && !systemPrefixes.contains(where: s.hasPrefix) && !s.contains("token") && !s.contains("safe storage")
    }
}

public enum LoginKeychain {
    public static let exportService = "app.rampart.vault.item"

    /// Lists internet and generic password entries (attributes only, no secrets).
    public static func listEntries() -> [KeychainEntry] {
        var out: [KeychainEntry] = []
        for (cls, kind) in [(kSecClassInternetPassword, KeychainEntry.Kind.internet), (kSecClassGenericPassword, .generic)] {
            let q: [String: Any] = [kSecClass as String: cls, kSecMatchLimit as String: kSecMatchLimitAll,
                                    kSecReturnAttributes as String: true, kSecReturnPersistentRef as String: true]
            var res: CFTypeRef?
            guard SecItemCopyMatching(q as CFDictionary, &res) == errSecSuccess, let arr = res as? [[String: Any]] else { continue }
            for a in arr {
                guard let ref = a[kSecValuePersistentRef as String] as? Data else { continue }
                let server = (a[kSecAttrServer as String] as? String) ?? (a[kSecAttrService as String] as? String) ?? ""
                out.append(KeychainEntry(kind: kind, label: (a[kSecAttrLabel as String] as? String) ?? server,
                                         account: (a[kSecAttrAccount as String] as? String) ?? "", server: server,
                                         path: (a[kSecAttrPath as String] as? String) ?? "",
                                         modified: a[kSecAttrModificationDate as String] as? Date, persistentRef: ref))
            }
        }
        return out.sorted { $0.label.localizedCaseInsensitiveCompare($1.label) == .orderedAscending }
    }

    /// Reads ONE entry's password. macOS shows its own "RamPart wants to use your confidential information"
    /// prompt for items RamPart didn't create; the user can Deny. Call only after the user picked the entry.
    public static func readPassword(_ entry: KeychainEntry) throws -> String {
        let q: [String: Any] = [kSecValuePersistentRef as String: entry.persistentRef, kSecReturnData as String: true,
                                kSecMatchLimit as String: kSecMatchLimitOne]
        var res: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &res)
        if s == errSecUserCanceled || s == errSecAuthFailed { throw VaultError.cancelled }
        guard s == errSecSuccess, let d = res as? Data else { throw VaultError.keychain(s) }
        return String(decoding: d, as: UTF8.self)
    }

    public static func makeItem(from entry: KeychainEntry, password: String) -> VaultItem {
        var item = VaultItem(kind: .login, title: entry.label.isEmpty ? entry.server : entry.label)
        item.username = entry.account
        item.password = password
        if entry.kind == .internet, !entry.server.isEmpty { item.urls = ["https://\(entry.server)\(entry.path)"] }
        item.notes = "Imported from the macOS login keychain."
        item.tags = ["keychain"]
        return item
    }

    /// Saves a login to the login keychain: an internet password when it has a URL (so Safari and other apps
    /// can find it), otherwise a generic password under `app.rampart.vault.item`.
    public static func save(_ item: VaultItem) throws {
        let data = Data(item.password.utf8)
        var q: [String: Any]
        if let first = item.urls.first, let url = URL(string: first.contains("://") ? first : "https://" + first), let host = url.host {
            q = [kSecClass as String: kSecClassInternetPassword, kSecAttrServer as String: host,
                 kSecAttrAccount as String: item.username,
                 kSecAttrProtocol as String: url.scheme == "http" ? kSecAttrProtocolHTTP : kSecAttrProtocolHTTPS]
        } else {
            q = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: exportService,
                 kSecAttrAccount as String: item.username.isEmpty ? item.title : item.username]
        }
        var add = q
        add[kSecValueData as String] = data
        add[kSecAttrLabel as String] = item.title
        var s = SecItemAdd(add as CFDictionary, nil)
        if s == errSecDuplicateItem { s = SecItemUpdate(q as CFDictionary, [kSecValueData as String: data] as CFDictionary) }
        if s == errSecUserCanceled || s == errSecAuthFailed { throw VaultError.cancelled }
        guard s == errSecSuccess else { throw VaultError.keychain(s) }
    }
}
