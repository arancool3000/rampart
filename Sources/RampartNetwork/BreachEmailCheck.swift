import Foundation
import RampartShared

/// Email breach check against Have I Been Pwned v3 (`/breachedaccount`). HIBP's email search needs a paid API key;
/// RamPart ships none, so this runs only with a key the user enters (stored in their login Keychain by the app).
/// Unlike the k-anonymity password check, the email address itself is sent to HIBP: the UI says so.
public struct EmailBreach: Codable, Hashable, Sendable, Identifiable {
    public var id: String { name }
    public var name: String
    public var title: String
    public var domain: String
    public var breachDate: String
    public var pwnCount: Int
    public var dataClasses: [String]
    public var isVerified: Bool
    enum CodingKeys: String, CodingKey {
        case name = "Name", title = "Title", domain = "Domain", breachDate = "BreachDate", pwnCount = "PwnCount"
        case dataClasses = "DataClasses", isVerified = "IsVerified"
    }
    public init(name: String, title: String, domain: String, breachDate: String, pwnCount: Int, dataClasses: [String], isVerified: Bool) {
        self.name = name; self.title = title; self.domain = domain; self.breachDate = breachDate
        self.pwnCount = pwnCount; self.dataClasses = dataClasses; self.isVerified = isVerified
    }
    public init(from d: Decoder) throws {
        let c = try d.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        title = (try? c.decode(String.self, forKey: .title)) ?? name
        domain = (try? c.decode(String.self, forKey: .domain)) ?? ""
        breachDate = (try? c.decode(String.self, forKey: .breachDate)) ?? ""
        pwnCount = (try? c.decode(Int.self, forKey: .pwnCount)) ?? 0
        dataClasses = (try? c.decode([String].self, forKey: .dataClasses)) ?? []
        isVerified = (try? c.decode(Bool.self, forKey: .isVerified)) ?? true
    }
}

public struct EmailBreachResult: Codable, Hashable, Sendable {
    public var email: String
    public var checked: Date
    public var breaches: [EmailBreach]
    public var error: String?
    public init(email: String, checked: Date, breaches: [EmailBreach], error: String? = nil) {
        self.email = email; self.checked = checked; self.breaches = breaches; self.error = error
    }
}

public enum EmailBreachError: Error, CustomStringConvertible, Equatable {
    case noKey, badKey, rateLimited(retryAfter: Int?), invalidEmail, http(Int), network(String)
    public var description: String {
        switch self {
        case .noKey: return "Enter your own Have I Been Pwned API key to check email addresses."
        case .badKey: return "Have I Been Pwned rejected the API key (401). Check it at haveibeenpwned.com/API/Key."
        case .rateLimited(let s): return "Have I Been Pwned asked RamPart to slow down\(s.map { "; try again in \($0) s" } ?? "")."
        case .invalidEmail: return "That doesn't look like an email address."
        case .http(let c): return "Have I Been Pwned answered HTTP \(c)."
        case .network(let s): return "Couldn't reach Have I Been Pwned: \(s)"
        }
    }
}

public final class HIBPEmailClient: @unchecked Sendable {
    public static let caveat = "Have I Been Pwned's email search needs a paid API key (haveibeenpwned.com/API/Key); there is no free API for it, so RamPart doesn't include one. Enter your own key and RamPart checks your addresses once a day. The key stays in your login Keychain. Unlike the password check (which sends only 5 characters of a hash), the email address itself is sent to Have I Been Pwned."
    public static let endpoint = "https://haveibeenpwned.com/api/v3/breachedaccount/"
    private let apiKey: String
    private let session: URLSession

    public init(apiKey: String, session: URLSession? = nil) {
        self.apiKey = apiKey.trimmingCharacters(in: .whitespacesAndNewlines)
        if let session { self.session = session } else {
            let cfg = URLSessionConfiguration.ephemeral
            cfg.timeoutIntervalForRequest = 20; cfg.httpCookieStorage = nil; cfg.urlCache = nil
            self.session = URLSession(configuration: cfg)
        }
    }

    public static func isValidEmail(_ s: String) -> Bool {
        let e = s.trimmingCharacters(in: .whitespaces)
        guard e.count <= 254, let at = e.firstIndex(of: "@"), e.filter({ $0 == "@" }).count == 1 else { return false }
        let local = e[..<at], domain = e[e.index(after: at)...]
        return !local.isEmpty && domain.contains(".") && !domain.hasPrefix(".") && !domain.hasSuffix(".")
            && !e.contains(where: { $0.isWhitespace || $0 == "/" || $0 == "?" || $0 == "#" })
    }

    /// API keys are 32 hex characters.
    public static func isPlausibleKey(_ k: String) -> Bool {
        let t = k.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.count >= 16 && t.count <= 64 && t.allSatisfy { $0.isLetter || $0.isNumber }
    }

    public func request(for email: String) throws -> URLRequest {
        guard !apiKey.isEmpty else { throw EmailBreachError.noKey }
        guard Self.isValidEmail(email) else { throw EmailBreachError.invalidEmail }
        let enc = email.trimmingCharacters(in: .whitespaces).lowercased()
            .addingPercentEncoding(withAllowedCharacters: .alphanumerics.union(CharacterSet(charactersIn: "@.-_+"))) ?? ""
        var r = URLRequest(url: URL(string: Self.endpoint + enc + "?truncateResponse=false")!)
        r.setValue(apiKey, forHTTPHeaderField: "hibp-api-key")
        r.setValue("RamPart-Antivirus", forHTTPHeaderField: "User-Agent")
        r.setValue("application/json", forHTTPHeaderField: "Accept")
        return r
    }

    /// Interprets an HIBP response: 404 = not in any breach.
    public static func interpret(status: Int, data: Data, retryAfter: String?) -> Result<[EmailBreach], EmailBreachError> {
        switch status {
        case 200:
            guard let v = try? JSONDecoder().decode([EmailBreach].self, from: data) else { return .failure(.http(200)) }
            return .success(v.sorted { $0.breachDate > $1.breachDate })
        case 404: return .success([])
        case 401: return .failure(.badKey)
        case 429: return .failure(.rateLimited(retryAfter: retryAfter.flatMap { Int($0) }))
        default: return .failure(.http(status))
        }
    }

    public func check(_ email: String) async -> EmailBreachResult {
        let now = Date()
        do {
            let req = try request(for: email)
            let (data, resp) = try await session.data(for: req)
            let http = resp as? HTTPURLResponse
            switch Self.interpret(status: http?.statusCode ?? 0, data: data, retryAfter: http?.value(forHTTPHeaderField: "retry-after")) {
            case .success(let b): return EmailBreachResult(email: email, checked: now, breaches: b)
            case .failure(let e): return EmailBreachResult(email: email, checked: now, breaches: [], error: e.description)
            }
        } catch let e as EmailBreachError {
            return EmailBreachResult(email: email, checked: now, breaches: [], error: e.description)
        } catch {
            return EmailBreachResult(email: email, checked: now, breaches: [], error: EmailBreachError.network(error.localizedDescription).description)
        }
    }

    /// Breaches in `new` that were not in `old` (to notify only about new ones).
    public static func newBreaches(old: EmailBreachResult?, new: EmailBreachResult) -> [EmailBreach] {
        guard new.error == nil else { return [] }
        let known = Set(old?.breaches.map(\.name) ?? [])
        return new.breaches.filter { !known.contains($0.name) }
    }

    public static func isDue(_ last: EmailBreachResult?, now: Date = Date(), interval: TimeInterval = 24 * 3600) -> Bool {
        guard let last else { return true }
        return now.timeIntervalSince(last.checked) >= (last.error == nil ? interval : 3600)
    }
}
