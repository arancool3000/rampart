import Foundation
import CryptoKit
import RampartShared

/// Have I Been Pwned "Pwned Passwords" k-anonymity range API. Only the first 5 hex chars of the SHA-1
/// leave the device; `Add-Padding: true` hides the true response size.
public final class PwnedPasswords: @unchecked Sendable {
    public enum PwnedError: Error, CustomStringConvertible {
        case http(Int), badBody(String), transport(String)
        public var description: String {
            switch self {
            case .http(let s): return "HTTP \(s)"
            case .badBody(let s): return "unexpected response: \(s)"
            case .transport(let s): return s
            }
        }
    }

    public let baseURL: URL
    private let session: URLSession

    public init(baseURL: URL = URL(string: "https://api.pwnedpasswords.com/range/")!, timeout: TimeInterval = 15) {
        self.baseURL = baseURL
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.urlCache = nil
        session = URLSession(configuration: cfg)
    }

    public static func sha1Hex(_ password: String) -> String {
        Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
    }

    /// Parses `SUFFIX:COUNT` lines and returns the count for `suffix` (0 if absent or padding).
    public static func count(in body: String, suffix: String) -> Int {
        let target = suffix.uppercased()
        for line in body.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":")
            guard parts.count == 2 else { continue }
            if parts[0].trimmingCharacters(in: .whitespaces).uppercased() == target {
                return Int(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)) ?? 0
            }
        }
        return 0
    }

    /// Returns how many times the password appears in breaches (0 = not found).
    public func breachCount(for password: String) async throws -> Int {
        let hash = Self.sha1Hex(password)
        let prefix = String(hash.prefix(5)), suffix = String(hash.dropFirst(5))
        var req = URLRequest(url: baseURL.appendingPathComponent(prefix))
        req.setValue("true", forHTTPHeaderField: "Add-Padding")
        req.setValue("Rampart/\(Product.version)", forHTTPHeaderField: "User-Agent")
        let (data, resp): (Data, URLResponse)
        do { (data, resp) = try await session.data(for: req) } catch { throw PwnedError.transport(error.localizedDescription) }
        guard let http = resp as? HTTPURLResponse else { throw PwnedError.transport("no HTTP response") }
        guard http.statusCode == 200 else { throw PwnedError.http(http.statusCode) }
        let body = String(decoding: data, as: UTF8.self)
        // A real range response is hundreds of 35-hex-char suffix lines; reject HTML filter pages.
        guard let first = body.split(whereSeparator: \.isNewline).first,
              first.split(separator: ":").first?.count == 35 else {
            throw PwnedError.badBody(String(body.prefix(80)))
        }
        return Self.count(in: body, suffix: suffix)
    }

    public func isPwned(_ password: String) async throws -> Bool { try await breachCount(for: password) > 0 }
}
