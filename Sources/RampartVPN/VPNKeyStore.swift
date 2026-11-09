import Foundation
import Security

/// Where VPN secrets live. Never files, never logs.
public protocol VPNKeyStore: AnyObject {
    func set(_ secret: [UInt8], account: String) throws
    func get(account: String) -> [UInt8]?
    func delete(account: String)
    var kind: String { get }
}

public enum VPNKeyStoreError: Error, CustomStringConvertible {
    case keychain(OSStatus)
    public var description: String {
        switch self {
        case .keychain(let s): return "Keychain error \(s): \((SecCopyErrorMessageString(s, nil) as String?) ?? "unknown")"
        }
    }
}

/// Keychain generic passwords under service `app.rampart.vpn` (the root daemon's System keychain when installed).
/// Reads never show UI: if access would need a prompt they fail, and the user imports the config again.
public final class KeychainVPNKeyStore: VPNKeyStore {
    public static let service = "app.rampart.vpn"
    public let service: String
    public var kind: String { "Keychain (\(service))" }
    public init(service: String = KeychainVPNKeyStore.service) { self.service = service }

    func base(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
    }

    public func set(_ secret: [UInt8], account: String) throws {
        delete(account: account)
        var q = base(account)
        q[kSecValueData as String] = Data(secret)
        q[kSecAttrLabel as String] = "RamPart VPN key"
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let s = SecItemAdd(q as CFDictionary, nil)
        guard s == errSecSuccess else { throw VPNKeyStoreError.keychain(s) }
    }

    public func get(account: String) -> [UInt8]? {
        var q = base(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess, let d = out as? Data else { return nil }
        return Array(d)
    }

    public func delete(account: String) { SecItemDelete(base(account) as CFDictionary) }
}

/// In-memory store for development (RAMPART_NO_PRIVILEGED_TOOLS=1, user mode) and self-tests.
public final class MemoryVPNKeyStore: VPNKeyStore {
    private var items: [String: [UInt8]] = [:]
    private let lock = NSLock()
    public var kind: String { "memory (development: forgotten when the service stops)" }
    public init() {}
    public func set(_ secret: [UInt8], account: String) throws { lock.lock(); items[account] = secret; lock.unlock() }
    public func get(account: String) -> [UInt8]? { lock.lock(); defer { lock.unlock() }; return items[account] }
    public func delete(account: String) { lock.lock(); items[account] = nil; lock.unlock() }
}
