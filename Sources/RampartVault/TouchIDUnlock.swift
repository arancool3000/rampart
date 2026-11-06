import Foundation
import CryptoKit
import LocalAuthentication
import Security

/// Touch ID unlock for the vault.
///
/// ## Primary design: Secure Enclave, hardware-enforced (`Mode.secureEnclave`)
/// When the user turns Touch ID on (vault already unlocked with the master password):
/// 1. CryptoKit creates a P-256 key-agreement key **inside the Secure Enclave** with access control
///    `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` + `[.privateKeyUsage, .biometryCurrentSet]`.
///    The private key never leaves the SE; we get only `dataRepresentation`, an opaque blob that only
///    this Mac's Secure Enclave can use.
/// 2. An ephemeral P-256 key does ECDH with the SE public key → HKDF-SHA256 → AES-256-GCM wraps the vault key.
/// 3. `touchid.json` in the vault folder (0600) stores the SE blob, the ephemeral public key and the
///    wrapped vault key. Nothing goes in the keychain. The ephemeral private key is discarded.
///
/// To unlock, the Secure Enclave must perform the key agreement, which the hardware allows only after a
/// successful Touch ID match for the **currently enrolled** fingers. Adding or removing a fingerprint
/// invalidates the key permanently (`.biometryCurrentSet`); the user then unlocks with the master
/// password and can turn Touch ID on again. Copying `touchid.json` to another Mac is useless.
/// This works for an ad-hoc signed, non-sandboxed app: CryptoKit SE keys are not keychain items and
/// need no keychain-access-groups entitlement (verified on this Mac).
///
/// Limits (stated honestly in the UI): anyone who can unlock this Mac's Touch ID can open the vault
/// while the file is present; malware running as the user can't read the vault key without a Touch ID
/// match, but it could show its own fake prompt to trick a user, or wait until the vault is unlocked and
/// read process memory. The master password always remains a way in.
///
/// ## Fallback: LocalAuthentication-gated login keychain (`Mode.keychainGated`)
/// Only on Macs without a usable Secure Enclave. The vault key is stored as a generic password
/// (service `app.rampart.vault`) in the file-based login keychain, and RamPart asks LocalAuthentication
/// (`.deviceOwnerAuthenticationWithBiometrics`, falling back to `.deviceOwnerAuthentication`) before
/// reading it. This is **weaker**: the check is enforced by RamPart's code, not by hardware. Any process
/// the keychain's access list trusts (RamPart, or one the user clicks "Allow" for) can read the key
/// without Touch ID, and anyone with the login keychain and its password can extract it. A real
/// `SecAccessControl` + `.biometryCurrentSet` keychain item would need the data-protection keychain and
/// therefore a keychain-access-groups entitlement and provisioning profile, which this app doesn't have
/// (SecItemAdd returns -34018 errSecMissingEntitlement). Enrolment changes are still detected by comparing
/// `evaluatedPolicyDomainState`, and the stored key is deleted when they change.
public final class TouchIDUnlock: @unchecked Sendable {
    public enum Mode: String, Codable, Sendable { case secureEnclave, keychainGated }

    public struct Availability: Sendable {
        public var biometryAvailable: Bool
        public var biometryName: String
        public var secureEnclave: Bool
        public var deviceOwnerAuthAvailable: Bool
        public var reason: String?
        public var preferredMode: Mode? { biometryAvailable ? (secureEnclave ? .secureEnclave : .keychainGated) : nil }
    }

    public static let keychainService = "app.rampart.vault"

    /// Checks support without showing any prompt (`canEvaluatePolicy` only).
    public static func availability() -> Availability {
        let ctx = LAContext()
        var err: NSError?
        let bio = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &err)
        let reason = err.map { e -> String in
            switch LAError.Code(rawValue: e.code) {
            case .biometryNotEnrolled: return "Touch ID has no fingerprints enrolled. Add one in System Settings › Touch ID & Password."
            case .biometryNotAvailable: return "This Mac has no Touch ID sensor available (a closed lid or no Magic Keyboard with Touch ID)."
            case .biometryLockout: return "Touch ID is locked after too many attempts. Unlock your Mac with its password first."
            default: return e.localizedDescription
            }
        }
        var owner: NSError?
        let ownerOK = LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &owner)
        let name: String
        switch ctx.biometryType { case .touchID: name = "Touch ID"; case .faceID: name = "Face ID"; case .opticID: name = "Optic ID"; default: name = "Touch ID" }
        return Availability(biometryAvailable: bio, biometryName: name, secureEnclave: SecureEnclave.isAvailable,
                            deviceOwnerAuthAvailable: ownerOK, reason: bio ? nil : reason)
    }

    struct Record: Codable {
        var version = 1
        var vaultID: UUID
        var mode: Mode
        var seKey: Data?
        var ephemeralPublic: Data?
        var wrapped: Data?
        var domainState: Data?
    }

    public let store: VaultStore
    public init(store: VaultStore) { self.store = store }

    var recordURL: URL { store.directory.appendingPathComponent("touchid.json") }

    private func readRecord() -> Record? {
        guard let d = try? Data(contentsOf: recordURL), let r = try? JSONDecoder().decode(Record.self, from: d),
              r.vaultID == store.vaultID else { return nil }
        return r
    }

    public var isEnabled: Bool { readRecord() != nil }
    public var mode: Mode? { readRecord()?.mode }

    static func domainState(_ ctx: LAContext) -> Data? {
        if #available(macOS 15.0, *) { return ctx.domainState.biometry.stateHash }
        return ctx.evaluatedPolicyDomainState
    }

    static func aad(_ id: UUID) -> Data { Data("rampart.vault.v1|touchid|\(id.uuidString)".utf8) }

    static func kek(shared: SharedSecret, ephemeral: P256.KeyAgreement.PublicKey, se: P256.KeyAgreement.PublicKey) -> SymmetricKey {
        shared.hkdfDerivedSymmetricKey(using: SHA256.self, salt: ephemeral.x963Representation + se.x963Representation,
                                       sharedInfo: Data("rampart.vault.v1.touchid-wrap".utf8), outputByteCount: 32)
    }

    /// Turns Touch ID on for the unlocked vault. Creating the SE key shows no prompt.
    @discardableResult
    public func enable(forceMode: Mode? = nil) throws -> Mode {
        let avail = Self.availability()
        guard avail.biometryAvailable else { throw VaultError.biometry(avail.reason ?? "Touch ID isn't available.") }
        guard let id = store.vaultID else { throw VaultError.noVault }
        let key = try store.currentKey()
        defer { key.wipe() }
        let ctx = LAContext()
        var e: NSError?
        _ = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e)
        let state = Self.domainState(ctx)
        disable()

        var mode = forceMode ?? avail.preferredMode ?? .keychainGated
        var record = Record(vaultID: id, mode: mode, domainState: state)
        if mode == .secureEnclave {
            do {
                var acErr: Unmanaged<CFError>?
                guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                                               [.privateKeyUsage, .biometryCurrentSet], &acErr) else {
                    throw VaultError.biometry("Could not create the Secure Enclave access policy.")
                }
                let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
                let eph = P256.KeyAgreement.PrivateKey()
                let shared = try eph.sharedSecretFromKeyAgreement(with: se.publicKey)
                let kek = Self.kek(shared: shared, ephemeral: eph.publicKey, se: se.publicKey)
                record.seKey = se.dataRepresentation
                record.ephemeralPublic = eph.publicKey.x963Representation
                record.wrapped = try key.withBytes { try AES.GCM.seal(Data($0), using: kek, authenticating: Self.aad(id)).combined }
            } catch {
                // No usable Secure Enclave for this process: fall back, and say so.
                mode = .keychainGated
                record = Record(vaultID: id, mode: mode, domainState: state)
            }
        }
        if mode == .keychainGated {
            try key.withBytes { try Keychain.setGeneric(service: Self.keychainService, account: id.uuidString, data: Data($0), label: "RamPart vault key") }
        }
        let data = try JSONEncoder().encode(record)
        try FileManager.default.createDirectory(at: store.directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try data.write(to: recordURL, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: recordURL.path)
        return mode
    }

    public func disable() {
        if let id = store.vaultID { Keychain.deleteGeneric(service: Self.keychainService, account: id.uuidString) }
        try? FileManager.default.removeItem(at: recordURL)
    }

    /// Shows the system Touch ID sheet and unlocks the vault. Throws `.cancelled` when the user cancels or
    /// chooses "Use Master Password", and `.biometryChanged` after an enrolment change (Touch ID is turned off).
    public func unlock(reason: String = "unlock your RamPart password vault") async throws {
        guard let r = readRecord() else { throw VaultError.biometry("Touch ID unlock is not turned on.") }
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Master Password"
        ctx.localizedCancelTitle = "Cancel"
        do {
            if r.mode == .secureEnclave {
                // The SE key requires biometrics; the device passcode can't satisfy it.
                try await ctx.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, localizedReason: reason)
            } else {
                var e: NSError?
                let policy: LAPolicy = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e)
                    ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
                try await ctx.evaluatePolicy(policy, localizedReason: reason)
            }
        } catch let e as LAError {
            switch e.code {
            case .userCancel, .userFallback, .systemCancel, .appCancel: throw VaultError.cancelled
            default: throw VaultError.biometry(e.localizedDescription)
            }
        }
        if let saved = r.domainState, let now = Self.domainState(ctx), saved != now {
            disable(); throw VaultError.biometryChanged
        }

        let key: SecretKeyBytes
        switch r.mode {
        case .secureEnclave:
            guard let blob = r.seKey, let ephData = r.ephemeralPublic, let wrapped = r.wrapped else { disable(); throw VaultError.biometryChanged }
            do {
                let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: blob, authenticationContext: ctx)
                let eph = try P256.KeyAgreement.PublicKey(x963Representation: ephData)
                let shared = try se.sharedSecretFromKeyAgreement(with: eph)
                var raw = try AES.GCM.open(AES.GCM.SealedBox(combined: wrapped), using: Self.kek(shared: shared, ephemeral: eph, se: se.publicKey),
                                           authenticating: Self.aad(r.vaultID))
                key = SecretKeyBytes(data: raw)
                secureZero(&raw)
            } catch {
                // The SE refuses invalidated keys (fingerprints changed) — fall back to the master password.
                disable(); throw VaultError.biometryChanged
            }
        case .keychainGated:
            guard var raw = try Keychain.readGeneric(service: Self.keychainService, account: r.vaultID.uuidString) else {
                disable(); throw VaultError.biometry("The stored key is missing. Unlock with your master password.")
            }
            key = SecretKeyBytes(data: raw)
            secureZero(&raw)
        }
        try store.unlock(vaultKey: key)
    }

    /// Self-test helper: SE wrap/unwrap round trip with an access control WITHOUT biometry flags,
    /// so no prompt can appear. Returns nil on success or the error text.
    public static func secureEnclaveRoundTripWithoutBiometry() -> String? {
        do {
            guard SecureEnclave.isAvailable else { return "Secure Enclave not available" }
            guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil) else { return "access control" }
            let se = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac)
            let eph = P256.KeyAgreement.PrivateKey()
            let secret = Data(SecureRandom.bytes(32))
            let id = UUID()
            let k1 = kek(shared: try eph.sharedSecretFromKeyAgreement(with: se.publicKey), ephemeral: eph.publicKey, se: se.publicKey)
            let wrapped = try AES.GCM.seal(secret, using: k1, authenticating: aad(id)).combined!
            let se2 = try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: se.dataRepresentation)
            let ephPub = try P256.KeyAgreement.PublicKey(x963Representation: eph.publicKey.x963Representation)
            let k2 = kek(shared: try se2.sharedSecretFromKeyAgreement(with: ephPub), ephemeral: ephPub, se: se2.publicKey)
            let out = try AES.GCM.open(AES.GCM.SealedBox(combined: wrapped), using: k2, authenticating: aad(id))
            return out == secret ? nil : "mismatch"
        } catch { return "\(error)" }
    }
}
