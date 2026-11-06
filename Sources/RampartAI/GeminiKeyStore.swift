import Foundation
import Security

/// The Gemini API key lives ONLY in the login Keychain. It is read on demand for each request, placed only in the
/// `x-goog-api-key` header, and never logged, printed, persisted elsewhere or passed in argv.
///
/// Two items, same service `app.rampart.ai.gemini`:
/// - account `gemini-api-key`: the key as the user stored it (e.g. with `/usr/bin/security add-generic-password`).
///   Its ACL trusts `/usr/bin/security`, so reading it through that tool never shows a dialog.
/// - account `gemini-api-key.app`: RamPart's own copy, created by the app with `SecItemAdd`, so its ACL trusts the
///   app's designated requirement. With a stable signing identity, the app reads it without any prompt, ever.
///
/// Pop-up policy (ARCHITECTURE.md "ZERO POP-UPS RULE"): every read is done with Keychain UI disabled. The only way a
/// dialog can appear is `readKey(allowUI: true)`, which the app calls only from an explicit "Allow Keychain Access"
/// button the user presses, with copy explaining the one-time "Always Allow".
public enum GeminiKeyStore {
    public static let service = "app.rampart.ai.gemini"
    public static let account = "gemini-api-key"
    public static let appAccount = "gemini-api-key.app"

    public enum Status: Equatable, Sendable {
        case present          // an item exists (value not read)
        case missing
        case error(Int32)     // OSStatus
        public var label: String {
            switch self {
            case .present: return "Key stored in Keychain"
            case .missing: return "No API key"
            case .error(let s): return "Keychain error \(s)"
            }
        }
    }

    public enum KeyError: Error, Equatable, CustomStringConvertible {
        case missing, interactionNotAllowed, invalidFormat, osStatus(Int32)
        public var description: String {
            switch self {
            case .missing: return "No Gemini API key is stored. Add one in AI Assistant."
            case .interactionNotAllowed: return "RamPart needs one-time permission to read the Gemini key from your Keychain."
            case .invalidFormat: return "The key doesn't look like a Gemini API key."
            case .osStatus(let s): return "Keychain error \(s)."
            }
        }
    }

    private static func query(_ acct: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: acct]
    }

    /// Whether either item exists, by reading attributes only (never decrypts the secret, never prompts).
    public static func status() -> Status {
        var worst: Status = .missing
        for acct in [appAccount, account] {
            var q = query(acct)
            q[kSecReturnAttributes as String] = true
            q[kSecMatchLimit as String] = kSecMatchLimitOne
            var out: CFTypeRef?
            let s = SecItemCopyMatching(q as CFDictionary, &out)
            if s == errSecSuccess { return .present }
            if s != errSecItemNotFound { worst = .error(s) }
        }
        return worst
    }

    private static let uiLock = NSLock()

    /// Reads the key without ever showing UI unless `allowUI` is true (user pressed a button).
    /// Order: app-owned copy (no prompt with a stable signature) -> user's item via `/usr/bin/security` over a pipe
    /// (its creator, so no prompt), then saves the app-owned copy so later reads don't need the tool.
    public static func readKey(allowUI: Bool = false, migrate: Bool = true) throws -> String {
        switch copyData(appAccount, allowUI: allowUI) {
        case .success(let k): return try validated(k)
        case .failure(let e) where e == .invalidFormat: throw e
        case .failure: break
        }
        let k = try validated(readKeyViaSecurityTool())
        if migrate { try? saveAppCopy(k) }
        return k
    }

    private static func copyData(_ acct: String, allowUI: Bool) -> Result<String, KeyError> {
        var q = query(acct)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        if !allowUI { q[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail }
        var out: CFTypeRef?
        uiLock.lock()
        if !allowUI { SecKeychainSetUserInteractionAllowed(false) }
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        if !allowUI { SecKeychainSetUserInteractionAllowed(true) }
        uiLock.unlock()
        switch s {
        case errSecSuccess:
            guard let d = out as? Data, let k = String(data: d, encoding: .utf8) else { return .failure(.invalidFormat) }
            return .success(k)
        case errSecItemNotFound: return .failure(.missing)
        case errSecInteractionNotAllowed, errSecAuthFailed, errSecUserCanceled: return .failure(.interactionNotAllowed)
        default: return .failure(.osStatus(s))
        }
    }

    /// Reads the user's item through `/usr/bin/security` (the item's creator, so no dialog). The secret comes back
    /// over a pipe; argv holds only the service and account names. Use this in development and self-tests.
    public static func readKeyViaSecurityTool() throws -> String {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["find-generic-password", "-s", service, "-a", account, "-w"]
        let outPipe = Pipe(), errPipe = Pipe()
        p.standardOutput = outPipe; p.standardError = errPipe; p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { throw KeyError.interactionNotAllowed }
        let data = outPipe.fileHandleForReading.readDataToEndOfFile()
        _ = errPipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        guard p.terminationStatus == 0, let k = String(data: data, encoding: .utf8) else {
            throw p.terminationStatus == 44 ? KeyError.missing : KeyError.interactionNotAllowed
        }
        return try validated(k)
    }

    /// Light sanity check (no network): printable ASCII, no whitespace inside, plausible length.
    public static func validated(_ raw: String) throws -> String {
        let k = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard isPlausibleKey(k) else { throw KeyError.invalidFormat }
        return k
    }
    public static func isPlausibleKey(_ k: String) -> Bool {
        (20...200).contains(k.count) && k.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" || $0 == ".") }
    }

    /// Writes the app-owned copy. SecItemAdd never prompts; the new item's ACL trusts the calling app.
    static func saveAppCopy(_ k: String) throws {
        _ = SecItemDelete(query(appAccount) as CFDictionary)
        var q = query(appAccount)
        q[kSecValueData as String] = Data(k.utf8)
        q[kSecAttrLabel as String] = "RamPart Gemini API key (app)"
        q[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlocked
        let s = SecItemAdd(q as CFDictionary, nil)
        guard s == errSecSuccess else { throw KeyError.osStatus(s) }
    }

    /// Replaces the key (from the app's "Replace Key" sheet). Stores RamPart's own copy; the user's original item,
    /// if any, is removed through its creator tool so no dialog appears.
    public static func save(_ raw: String) throws {
        let k = try validated(raw)
        try saveAppCopy(k)
        removeOriginalViaSecurityTool()
    }

    /// Removes both items. No dialogs: the app copy is ours, the original is deleted by its creator tool.
    public static func remove() throws {
        let s = SecItemDelete(query(appAccount) as CFDictionary)
        removeOriginalViaSecurityTool()
        guard s == errSecSuccess || s == errSecItemNotFound else { throw KeyError.osStatus(s) }
    }

    private static func removeOriginalViaSecurityTool() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["delete-generic-password", "-s", service, "-a", account]
        p.standardOutput = FileHandle.nullDevice; p.standardError = FileHandle.nullDevice; p.standardInput = FileHandle.nullDevice
        if (try? p.run()) != nil { p.waitUntilExit() }
    }
}
