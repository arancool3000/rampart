import Foundation
import CryptoKit

// Signed feed manifests for RamPart's OWN definition feeds (wms-fc). Third-party feeds (abuse.ch, HaGeZi, URLhaus)
// cannot be signed by us; they stay behind pinned hosts, TLS 1.2+, no off-host redirects, streamed size caps and
// shape validation. Anything RamPart publishes itself (a curated hash list, an allowlist, a blocklist) ships with a
// detached manifest signed by the release key, so a mirror, a CDN or a man-in-the-middle can neither alter the
// body nor replay an old one.
//
// Format of `<feed-url>.manifest.json` (at most `maxManifestBytes`):
//   {"manifest":"<base64 of the manifest JSON bytes>","signature":"<base64 Ed25519 signature over exactly those
//    bytes>","keyID":"<first 16 hex chars of SHA-256(raw public key)>"}
// Manifest JSON: {"feed":"<id>","version":<int, monotonic>,"created":"<ISO-8601>","sha256":"<hex of body>",
//                 "size":<bytes>,"expires":"<ISO-8601, optional>"}
// The signature is checked BEFORE the manifest is parsed; the body is accepted only if its size and SHA-256 equal
// the manifest's, the feed id matches, the version never goes below the last accepted one (rollback), and `created`
// is neither in the future (skew allowance) nor older than `maxAge` (a replayed stale manifest).
//
// HOOK FOR THE LEAD: generate the release key offline (`FeedSigning.generateKeyPair()` or any Ed25519 tool), keep
// the private key out of the repo, and put the base64 raw public key into `productionPublicKeyBase64`. Until then
// it is nil and `HashFeed.rampartSigned(...)` / `BlocklistUpdater.Source.rampartSigned(...)` return nil, so no
// unsigned "RamPart feed" can ever be configured by accident. Tests use fresh random keys only.
public enum FeedSigning {
    /// Base64 raw 32-byte Ed25519 public key of RamPart's feed release key. nil = RamPart's own feeds are not enabled.
    public static let productionPublicKeyBase64: String? = nil

    public static let maxManifestBytes = 4096
    /// Manifests older than this are treated as replayed/stale and refused (the last known good copy stays).
    public static let defaultMaxAge: TimeInterval = 45 * 86_400
    /// A manifest "created" this far in the future is still accepted (clock skew).
    public static let maxFutureSkew: TimeInterval = 86_400

    public struct Manifest: Codable, Equatable, Sendable {
        public var feed: String
        public var version: Int
        public var created: Date
        public var sha256: String
        public var size: Int
        public var expires: Date?
        public init(feed: String, version: Int, created: Date, sha256: String, size: Int, expires: Date? = nil) {
            self.feed = feed; self.version = version; self.created = created; self.sha256 = sha256; self.size = size; self.expires = expires
        }
    }

    /// What the verifier knew about the previously accepted copy (for rollback protection).
    public struct Previous: Equatable, Sendable {
        public var version: Int
        public var sha256: String?
        public init(version: Int, sha256: String? = nil) { self.version = version; self.sha256 = sha256 }
    }

    public enum Failure: Error, Equatable, CustomStringConvertible {
        case tooLarge, malformed, badKey, badSignature, wrongFeed(String), sizeMismatch, hashMismatch
        case rollback(have: Int, previous: Int), sameVersionDifferentBody, stale(Date), future(Date), expired(Date), badVersion
        public var description: String {
            switch self {
            case .tooLarge: return "manifest larger than \(FeedSigning.maxManifestBytes) bytes"
            case .malformed: return "manifest is not a signed feed manifest"
            case .badKey: return "feed public key is not a valid Ed25519 key"
            case .badSignature: return "feed signature does not verify"
            case .wrongFeed(let f): return "manifest is for feed '\(f)'"
            case .sizeMismatch: return "body size differs from the signed manifest"
            case .hashMismatch: return "body SHA-256 differs from the signed manifest"
            case .rollback(let h, let p): return "feed version \(h) is older than the installed \(p) (rollback)"
            case .sameVersionDifferentBody: return "same feed version with a different body"
            case .stale(let d): return "manifest created \(d) is too old (replayed?)"
            case .future(let d): return "manifest created \(d) is in the future"
            case .expired(let d): return "manifest expired \(d)"
            case .badVersion: return "manifest version must be a positive integer"
            }
        }
    }

    static let iso: ISO8601DateFormatter = { let f = ISO8601DateFormatter(); f.formatOptions = [.withInternetDateTime]; return f }()
    static func encoder() -> JSONEncoder { let e = JSONEncoder(); e.outputFormatting = [.sortedKeys]; e.dateEncodingStrategy = .custom { d, enc in var c = enc.singleValueContainer(); try c.encode(iso.string(from: d)) }; return e }
    static func decoder() -> JSONDecoder {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .custom { dec in
            let s = try dec.singleValueContainer().decode(String.self)
            guard let date = iso.date(from: s) else { throw DecodingError.dataCorrupted(.init(codingPath: dec.codingPath, debugDescription: "bad date")) }
            return date
        }
        return d
    }

    public static func sha256Hex(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
    public static func keyID(publicKeyBase64: String) -> String? {
        guard let raw = Data(base64Encoded: publicKeyBase64), raw.count == 32 else { return nil }
        return String(sha256Hex(raw).prefix(16))
    }

    /// Builds the manifest for `body`.
    public static func manifest(feed: String, version: Int, body: Data, created: Date = Date(), expires: Date? = nil) -> Manifest {
        Manifest(feed: feed, version: version, created: created, sha256: sha256Hex(body), size: body.count, expires: expires)
    }

    /// Signs a manifest. `privateKeyRaw` is the 32-byte Ed25519 seed. Used by the release tooling and by tests; the
    /// daemon never holds a private key.
    public static func sign(_ m: Manifest, privateKeyRaw: Data) throws -> Data {
        let key = try Curve25519.Signing.PrivateKey(rawRepresentation: privateKeyRaw)
        let bytes = try encoder().encode(m)
        let sig = try key.signature(for: bytes)
        let pub = key.publicKey.rawRepresentation.base64EncodedString()
        let env: [String: String] = ["manifest": bytes.base64EncodedString(), "signature": sig.base64EncodedString(),
                                     "keyID": keyID(publicKeyBase64: pub) ?? ""]
        return try JSONSerialization.data(withJSONObject: env, options: [.sortedKeys])
    }

    /// Fresh Ed25519 key pair: (base64 raw private seed, base64 raw public key). For the lead's release tooling.
    public static func generateKeyPair() -> (privateKeyBase64: String, publicKeyBase64: String) {
        let k = Curve25519.Signing.PrivateKey()
        return (k.rawRepresentation.base64EncodedString(), k.publicKey.rawRepresentation.base64EncodedString())
    }

    /// Verifies the signed manifest `signed` for `body`. On success returns the manifest to record (version + sha256).
    public static func verify(signed: Data, body: Data, feed: String, publicKeyBase64: String, previous: Previous? = nil,
                              now: Date = Date(), maxAge: TimeInterval = FeedSigning.defaultMaxAge) -> Result<Manifest, Failure> {
        guard signed.count <= maxManifestBytes else { return .failure(.tooLarge) }
        guard let raw = Data(base64Encoded: publicKeyBase64), raw.count == 32,
              let key = try? Curve25519.Signing.PublicKey(rawRepresentation: raw) else { return .failure(.badKey) }
        guard let obj = try? JSONSerialization.jsonObject(with: signed) as? [String: Any],
              let mb64 = obj["manifest"] as? String, let sb64 = obj["signature"] as? String,
              let mbytes = Data(base64Encoded: mb64), let sig = Data(base64Encoded: sb64), sig.count == 64,
              mbytes.count <= maxManifestBytes else { return .failure(.malformed) }
        // Signature first: nothing inside the manifest is looked at before it proves to come from the release key.
        guard key.isValidSignature(sig, for: mbytes) else { return .failure(.badSignature) }
        guard let m = try? decoder().decode(Manifest.self, from: mbytes) else { return .failure(.malformed) }
        guard m.version > 0 else { return .failure(.badVersion) }
        guard m.feed == feed else { return .failure(.wrongFeed(m.feed)) }
        guard m.size == body.count else { return .failure(.sizeMismatch) }
        guard m.sha256.lowercased() == sha256Hex(body) else { return .failure(.hashMismatch) }
        if m.created > now.addingTimeInterval(maxFutureSkew) { return .failure(.future(m.created)) }
        if m.created < now.addingTimeInterval(-maxAge) { return .failure(.stale(m.created)) }
        if let e = m.expires, e <= now { return .failure(.expired(e)) }
        if let p = previous {
            if m.version < p.version { return .failure(.rollback(have: m.version, previous: p.version)) }
            if m.version == p.version, let ps = p.sha256, ps.lowercased() != m.sha256.lowercased() { return .failure(.sameVersionDifferentBody) }
        }
        return .success(m)
    }

    /// `<url>.manifest.json` next to the feed body.
    public static func defaultManifestURL(for url: URL) -> URL { URL(string: url.absoluteString + ".manifest.json") ?? url }
}
