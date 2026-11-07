import Foundation
import CryptoKit
import CommonCrypto

/// Cryptographic primitives for the vault.
///
/// - Master password → key-encryption key (KEK): PBKDF2-HMAC-SHA256 (CommonCrypto), 16-byte random salt,
///   iteration count calibrated on this Mac to about 300 ms and never below 600,000 (OWASP 2023 floor).
/// - Vault key: 256 random bits from `SecRandomCopyBytes`, wrapped with AES-256-GCM under the KEK.
///   Changing the master password only re-wraps it.
/// - Sub-keys via HKDF-SHA256 from the vault key: one for items (AES-256-GCM per item, AAD binds the
///   vault ID and item ID so blobs can't be swapped) and one for the whole-file HMAC-SHA256.
public enum VaultCrypto {
    public static let minimumIterations = 600_000
    public static let targetMilliseconds = 300.0
    /// Upper bound accepted from any file header (calibration never exceeds it). A tampered header with a
    /// huge count would otherwise hang the app for hours or trap converting to UInt32.
    public static let maximumIterations = 20_000_000
    /// Lowest count accepted from a file header (test vaults use 10,000; real ones >= 600,000).
    public static let floorIterations = 1_000

    /// True when KDF parameters read from an untrusted file are safe to run.
    public static func acceptableKDF(iterations: Int, salt: Data) -> Bool {
        (floorIterations...maximumIterations).contains(iterations) && (16...64).contains(salt.count)
    }

    public static func pbkdf2(password: String, salt: Data, iterations: Int, length: Int = 32) -> SecretKeyBytes {
        precondition(iterations > 0 && iterations <= Int(UInt32.max) && !salt.isEmpty, "PBKDF2 parameters out of range")
        var pw = Array(password.utf8)
        defer { secureZero(&pw) }
        var out = [UInt8](repeating: 0, count: length)
        let status = salt.withUnsafeBytes { s in
            pw.withUnsafeBufferPointer { p in
                p.baseAddress!.withMemoryRebound(to: Int8.self, capacity: max(1, pw.count)) { pp in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2), pp, pw.count,
                                         s.bindMemory(to: UInt8.self).baseAddress, salt.count,
                                         CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), UInt32(iterations), &out, length)
                }
            }
        }
        precondition(status == kCCSuccess, "PBKDF2 failed")
        let key = SecretKeyBytes(out)
        secureZero(&out)
        return key
    }

    /// Measures this Mac and returns the iteration count that takes about `targetMilliseconds`.
    public static func calibrateIterations(targetMs: Double = targetMilliseconds) -> Int {
        let probe = 100_000
        let salt = SecureRandom.data(16)
        let t0 = DispatchTime.now().uptimeNanoseconds
        _ = pbkdf2(password: "calibration-probe", salt: salt, iterations: probe)
        let ms = max(1, Double(DispatchTime.now().uptimeNanoseconds - t0) / 1e6)
        let scaled = Int(Double(probe) * targetMs / ms)
        return min(20_000_000, max(minimumIterations, (scaled / 10_000) * 10_000))
    }

    static func hkdf(_ key: SecretKeyBytes, salt: Data, info: String) -> SymmetricKey {
        key.withBytes { b in
            HKDF<SHA256>.deriveKey(inputKeyMaterial: SymmetricKey(data: b), salt: salt, info: Data(info.utf8), outputByteCount: 32)
        }
    }

    static func seal(_ plaintext: Data, key: SymmetricKey, aad: String) throws -> Data {
        guard let combined = try AES.GCM.seal(plaintext, using: key, authenticating: Data(aad.utf8)).combined else {
            throw VaultError.badFormat("seal")
        }
        return combined
    }

    static func open(_ combined: Data, key: SymmetricKey, aad: String) throws -> Data {
        let box = try AES.GCM.SealedBox(combined: combined)
        return try AES.GCM.open(box, using: key, authenticating: Data(aad.utf8))
    }

    static func symmetric(_ k: SecretKeyBytes) -> SymmetricKey { k.withBytes { SymmetricKey(data: $0) } }
}

// MARK: - File format

/// On-disk vault, format version 1:
///
///     magic "RAMPVLT\0" (8) | version u16 BE | headerLen u32 BE | header JSON | bodyLen u32 BE | body JSON | HMAC-SHA256 (32)
///
/// The header holds the KDF parameters and the wrapped vault key (GCM AAD binds vault ID, KDF name,
/// iterations and salt, so downgrading the iteration count breaks unwrapping). The body holds the
/// encrypted metadata and one AES-GCM blob per item. The trailing HMAC covers every preceding byte,
/// so deleting, reordering, replaying or truncating anything is detected after unlock.
struct VaultFile {
    static let magic = Data("RAMPVLT\0".utf8)
    static let currentVersion: UInt16 = 1
    /// Refuse to parse anything bigger (the item cap times the 1 MB attachment cap is far below this).
    static let maxFileBytes = 512 * 1_048_576

    struct KDF: Codable {
        var algorithm: String   // "pbkdf2-hmac-sha256"
        var iterations: Int
        var salt: Data
    }
    struct Header: Codable {
        var vaultID: UUID
        var kdf: KDF
        var wrappedKey: Data
        var written: Date
        var generation: Int
    }
    struct Blob: Codable { var id: UUID; var data: Data }
    struct Body: Codable { var meta: Data; var items: [Blob] }

    var version: UInt16
    var header: Header
    var body: Body
    var mac: Data
    var signedBytes: Data

    static func wrapAAD(_ h: Header) -> String {
        "rampart.vault.v1|key|\(h.vaultID.uuidString)|\(h.kdf.algorithm)|\(h.kdf.iterations)|\(h.kdf.salt.base64EncodedString())"
    }
    static func itemAAD(_ vault: UUID, _ item: UUID) -> String { "rampart.vault.v1|item|\(vault.uuidString)|\(item.uuidString)" }
    static func metaAAD(_ vault: UUID) -> String { "rampart.vault.v1|meta|\(vault.uuidString)" }
    static func macKey(_ vaultKey: SecretKeyBytes, _ id: UUID) -> SymmetricKey {
        VaultCrypto.hkdf(vaultKey, salt: Data(id.uuidString.utf8), info: "rampart.vault.v1.file-mac")
    }
    static func itemKey(_ vaultKey: SecretKeyBytes, _ id: UUID) -> SymmetricKey {
        VaultCrypto.hkdf(vaultKey, salt: Data(id.uuidString.utf8), info: "rampart.vault.v1.items")
    }

    static let encoder: JSONEncoder = { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e }()
    static let decoder: JSONDecoder = { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }()

    static func serialize(header: Header, body: Body, vaultKey: SecretKeyBytes) throws -> Data {
        var out = magic
        out.append(be16(currentVersion))
        let h = try encoder.encode(header), b = try encoder.encode(body)
        out.append(be32(UInt32(h.count))); out.append(h)
        out.append(be32(UInt32(b.count))); out.append(b)
        out.append(Data(HMAC<SHA256>.authenticationCode(for: out, using: macKey(vaultKey, header.vaultID))))
        return out
    }

    static func parse(_ d: Data) throws -> VaultFile {
        let d = Data(d) // rebase indices to 0
        guard d.count <= maxFileBytes else { throw VaultError.badFormat("file too large") }
        guard d.count > 8 + 2 + 4 + 4 + 32, d.prefix(8) == magic else { throw VaultError.badFormat("not a RamPart vault") }
        let version = UInt16(d[8]) << 8 | UInt16(d[9])
        guard version >= 1 else { throw VaultError.badFormat("bad version") }
        guard version <= currentVersion else { throw VaultError.unsupportedVersion(Int(version)) }
        var p = 10
        func readChunk() throws -> Data {
            guard p + 4 <= d.count - 32 else { throw VaultError.tampered }
            let n = Int(d[p]) << 24 | Int(d[p + 1]) << 16 | Int(d[p + 2]) << 8 | Int(d[p + 3])
            p += 4
            guard n >= 0, p + n <= d.count - 32 else { throw VaultError.tampered }
            defer { p += n }
            return d.subdata(in: p..<(p + n))
        }
        let hData = try readChunk(), bData = try readChunk()
        guard p == d.count - 32 else { throw VaultError.tampered }
        do {
            let header = try decoder.decode(Header.self, from: hData)
            let body = try decoder.decode(Body.self, from: bData)
            return VaultFile(version: version, header: header, body: body, mac: d.suffix(32), signedBytes: d.prefix(p))
        } catch { throw VaultError.tampered }
    }

    func verify(vaultKey: SecretKeyBytes) -> Bool {
        HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: signedBytes, using: Self.macKey(vaultKey, header.vaultID))
    }

    static func be16(_ v: UInt16) -> Data { Data([UInt8(v >> 8), UInt8(v & 0xff)]) }
    static func be32(_ v: UInt32) -> Data { Data([UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]) }
}
