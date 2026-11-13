import Foundation
import Security
import RampartShared

// MARK: - Wire types (generateContent REST)

public struct GeminiPart: Codable, Hashable, Sendable {
    public var text: String?
    public var thought: Bool?
    public init(text: String) { self.text = text; self.thought = nil }
}
public struct GeminiContent: Codable, Hashable, Sendable {
    public var role: String?
    public var parts: [GeminiPart]
    public init(role: String?, text: String) { self.role = role; self.parts = [GeminiPart(text: text)] }
}
public struct GeminiSafetySetting: Codable, Hashable, Sendable {
    public var category: String
    public var threshold: String
}
public struct GeminiGenerationConfig: Codable, Hashable, Sendable {
    public var responseMimeType: String?
    public var responseJsonSchema: JSONValue?
    public var maxOutputTokens: Int?
    public var candidateCount: Int?
}
public struct GeminiRequest: Codable, Hashable, Sendable {
    public var systemInstruction: GeminiContent?
    public var contents: [GeminiContent]
    public var generationConfig: GeminiGenerationConfig?
    public var safetySettings: [GeminiSafetySetting]?
}
public struct GeminiUsage: Codable, Hashable, Sendable {
    public var promptTokenCount: Int?
    public var candidatesTokenCount: Int?
    public var thoughtsTokenCount: Int?
    public var totalTokenCount: Int?
}
public struct GeminiResponse: Codable, Sendable {
    public struct Candidate: Codable, Sendable {
        public var content: GeminiContent?
        public var finishReason: String?
    }
    public struct PromptFeedback: Codable, Sendable { public var blockReason: String? }
    public var candidates: [Candidate]?
    public var promptFeedback: PromptFeedback?
    public var usageMetadata: GeminiUsage?
    public var modelVersion: String?

    /// Visible answer text (thought-summary parts skipped).
    public var text: String? {
        guard let parts = candidates?.first?.content?.parts else { return nil }
        let t = parts.filter { $0.thought != true }.compactMap(\.text).joined()
        return t.isEmpty ? nil : t
    }
}
struct GeminiErrorEnvelope: Decodable {
    struct Body: Decodable {
        var code: Int?; var message: String?; var status: String?
        var details: [Detail]?
    }
    struct Detail: Decodable { var retryDelay: String? }
    var error: Body
}

// MARK: - Errors (never contain the key)

public enum GeminiError: Error, Equatable, CustomStringConvertible, Sendable {
    case notEnabled
    case noKey(String)
    case invalidModel
    case http(status: Int, message: String)
    case rateLimited
    case blocked(String)
    case emptyResponse(finishReason: String?)
    case badJSON(String)
    case validation(String)
    case network(String)
    case cancelled

    public var description: String {
        switch self {
        case .notEnabled: return "AI Assistant is off. Turn it on in AI Assistant to use this."
        case .noKey(let m): return m
        case .invalidModel: return "The selected model name isn't valid."
        case .http(let s, let m): return s == 400 || s == 403 ? "Gemini rejected the request (\(s)): \(m)" : "Gemini returned an error (\(s)): \(m)"
        case .rateLimited: return "Gemini is busy or the free quota is used up. Try again in a minute."
        case .blocked(let r): return "Gemini declined to answer (\(r))."
        case .emptyResponse(let r): return "Gemini returned no answer" + (r.map { " (\($0))" } ?? "") + "."
        case .badJSON(let m): return "The AI answer wasn't in the expected format (\(m))."
        case .validation(let m): return "The AI answer didn't pass checks (\(m))."
        case .network(let m): return "Couldn't reach Gemini: \(m)"
        case .cancelled: return "Cancelled."
        }
    }
}

// MARK: - Transport (injectable for tests)

public protocol GeminiTransport: Sendable {
    func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse)
}

public struct URLSessionTransport: GeminiTransport {
    /// Largest response body accepted (a generateContent answer is a few KB; 2 MB leaves ample headroom).
    public static let maxResponseBytes = 2 * 1024 * 1024
    let session: URLSession
    /// `protocolClasses` exists for self-tests (mock URLProtocol); production passes nil.
    public init(timeout: TimeInterval = 45, protocolClasses: [AnyClass]? = nil) {
        let c = URLSessionConfiguration.ephemeral          // no cookies, no disk cache
        c.timeoutIntervalForRequest = timeout
        c.timeoutIntervalForResource = timeout * 2
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpCookieStorage = nil
        c.urlCredentialStorage = nil
        c.httpShouldSetCookies = false
        c.waitsForConnectivity = false
        c.tlsMinimumSupportedProtocolVersion = .TLSv12
        if let protocolClasses { c.protocolClasses = protocolClasses }
        session = URLSession(configuration: c, delegate: PinnedHostDelegate(), delegateQueue: nil)
    }
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        try Self.checkPinned(request.url)
        let (bytes, r) = try await session.bytes(for: request)
        guard let h = r as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        // The final URL must still be the pinned https host (redirects are refused by the delegate as well).
        try Self.checkPinned(h.url)
        if h.expectedContentLength > Int64(Self.maxResponseBytes) { bytes.task.cancel(); throw GeminiError.network("the response was too large") }
        var data = Data()
        data.reserveCapacity(min(Self.maxResponseBytes, max(0, Int(h.expectedContentLength))))
        for try await b in bytes {
            data.append(b)
            if data.count > Self.maxResponseBytes { bytes.task.cancel(); throw GeminiError.network("the response was too large") }
        }
        return (data, h)
    }

    /// Only https to the Gemini host on the default port.
    static func checkPinned(_ url: URL?) throws {
        guard let url, url.scheme?.lowercased() == "https", url.host?.lowercased() == GeminiClient.host,
              url.port == nil || url.port == 443, url.user == nil, url.password == nil else {
            throw GeminiError.network("refused a connection that wasn't to \(GeminiClient.host) over HTTPS")
        }
    }
}

/// Refuses every redirect (the API never redirects; a redirect would carry the key header to another URL) and
/// accepts server trust only for the pinned host, evaluated by the system with hostname checking.
final class PinnedHostDelegate: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
    func urlSession(_ session: URLSession, task: URLSessionTask, didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        let space = challenge.protectionSpace
        guard space.authenticationMethod == NSURLAuthenticationMethodServerTrust else {
            // No client certificates, no HTTP auth prompts: the key header is the only credential.
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        guard space.host.lowercased() == GeminiClient.host, let trust = space.serverTrust else {
            completionHandler(.cancelAuthenticationChallenge, nil); return
        }
        SecTrustSetPolicies(trust, SecPolicyCreateSSL(true, GeminiClient.host as CFString))
        var err: CFError?
        if SecTrustEvaluateWithError(trust, &err) { completionHandler(.useCredential, URLCredential(trust: trust)) }
        else { completionHandler(.cancelAuthenticationChallenge, nil) }
    }
}

// MARK: - Client

public struct GeminiResult: Sendable {
    public var text: String
    public var usage: GeminiUsage?
    public var model: String
    public var latency: TimeInterval
    public var attempts: Int
}

public final class GeminiClient: @unchecked Sendable {
    public static let host = "generativelanguage.googleapis.com"
    public static let apiBase = URL(string: "https://generativelanguage.googleapis.com/v1beta/models/")!

    public var maxRetries = 3
    public var baseBackoff: TimeInterval = 0.8
    public var maxBackoff: TimeInterval = 20
    public var timeout: TimeInterval = 45
    let transport: GeminiTransport
    let keyProvider: @Sendable () throws -> String
    let log = RLog.logger("ai")

    public init(transport: GeminiTransport = URLSessionTransport(),
                keyProvider: @escaping @Sendable () throws -> String = { try GeminiKeyStore.readKey() }) {
        self.transport = transport
        self.keyProvider = keyProvider
    }

    /// Default safety settings: block harmful content at medium, but allow security discussion of malware
    /// (DANGEROUS_CONTENT only blocks high) so explanations of detections aren't refused.
    public static let safetySettings: [GeminiSafetySetting] = [
        .init(category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_MEDIUM_AND_ABOVE"),
        .init(category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_MEDIUM_AND_ABOVE"),
        .init(category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_MEDIUM_AND_ABOVE"),
        .init(category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_ONLY_HIGH"),
    ]

    public static func buildRequest(system: String, turns: [GeminiContent], schema: JSONValue?, maxOutputTokens: Int = 1200) -> GeminiRequest {
        GeminiRequest(
            systemInstruction: GeminiContent(role: nil, text: system),
            contents: turns,
            generationConfig: GeminiGenerationConfig(responseMimeType: schema == nil ? "text/plain" : "application/json",
                                                     responseJsonSchema: schema, maxOutputTokens: maxOutputTokens, candidateCount: 1),
            safetySettings: safetySettings)
    }

    /// The HTTP request. The key goes in the `x-goog-api-key` header only; never in the URL.
    /// wms-o5: largest request body sent (prompts are capped per block; this bounds everything else, e.g. history).
    public static let maxRequestBytes = 512 * 1024
    /// wms-o5: hard ceiling on one generate() call including retries and back-off.
    public var overallDeadline: TimeInterval = 120

    public static func urlRequest(model: String, body: GeminiRequest, key: String, timeout: TimeInterval) throws -> URLRequest {
        guard GeminiModel.isValidID(model) else { throw GeminiError.invalidModel }
        // wms-o5: the key goes only into one header; refuse anything that could split the header or isn't a key
        // (the key provider is injectable, so the store's validation alone isn't enough).
        guard GeminiKeyStore.isPlausibleKey(key) else { throw GeminiError.noKey(GeminiKeyStore.KeyError.invalidFormat.description) }
        guard timeout.isFinite, timeout > 0 else { throw GeminiError.network("invalid timeout") }
        let url = apiBase.appendingPathComponent("\(model):generateContent")
        guard url.host == host, url.scheme == "https" else { throw GeminiError.invalidModel }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.setValue(key, forHTTPHeaderField: "x-goog-api-key")
        let data = try JSONEncoder().encode(body)
        guard data.count <= maxRequestBytes else { throw GeminiError.validation("the request was too large to send") }
        r.httpBody = data
        r.timeoutInterval = min(timeout, 120)
        return r
    }

    /// Rough token estimate (≈4 characters per token for English) for showing cost before sending.
    public static func estimateTokens(_ s: String) -> Int { max(1, Int((Double(s.utf8.count) / 4.0).rounded(.up))) }
    public static func estimateTokens(_ req: GeminiRequest) -> Int {
        let chars = (req.systemInstruction?.parts.compactMap(\.text).joined() ?? "") + req.contents.flatMap(\.parts).compactMap(\.text).joined()
        return estimateTokens(chars) + (req.generationConfig?.responseJsonSchema.flatMap { try? JSONEncoder().encode($0) }.map { $0.count / 4 } ?? 0)
    }

    /// Sends one generateContent request with retries on 429/5xx and transient network errors.
    public func generate(model: String, request body: GeminiRequest) async throws -> GeminiResult {
        let key: String
        do { key = try keyProvider() } catch let e as GeminiKeyStore.KeyError { throw GeminiError.noKey(e.description) }
        let req = try Self.urlRequest(model: model, body: body, key: key, timeout: timeout)
        let start = Date()
        var attempt = 0
        while true {
            attempt += 1
            if Task.isCancelled { throw GeminiError.cancelled }
            if Date().timeIntervalSince(start) > overallDeadline { throw GeminiError.network("the request timed out") }
            var retryAfter: TimeInterval?
            let failure: GeminiError
            do {
                let (data, http) = try await transport.send(req)
                guard data.count <= URLSessionTransport.maxResponseBytes else { throw GeminiError.network("the response was too large") }
                if (200..<300).contains(http.statusCode) {
                    let resp: GeminiResponse
                    do { resp = try JSONDecoder().decode(GeminiResponse.self, from: data) } catch { throw GeminiError.badJSON("envelope") }
                    if let br = resp.promptFeedback?.blockReason { throw GeminiError.blocked(br) }
                    guard let text = resp.text else {
                        let fr = resp.candidates?.first?.finishReason
                        if fr == "SAFETY" || fr == "PROHIBITED_CONTENT" || fr == "BLOCKLIST" { throw GeminiError.blocked(fr!) }
                        throw GeminiError.emptyResponse(finishReason: fr)
                    }
                    return GeminiResult(text: text, usage: resp.usageMetadata, model: resp.modelVersion ?? model,
                                        latency: Date().timeIntervalSince(start), attempts: attempt)
                }
                let env = try? JSONDecoder().decode(GeminiErrorEnvelope.self, from: data)
                // Server text is untrusted: never echo the key, strip controls/markup, redact, cap length.
                let rawMsg = String((env?.error.message ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)).prefix(300))
                let msg = Clean.text(Redactor.default.redact(rawMsg.replacingOccurrences(of: key, with: "[KEY]")).text, max: 300)
                retryAfter = Self.retryDelay(header: http.value(forHTTPHeaderField: "Retry-After"), details: env?.error.details?.compactMap(\.retryDelay).first)
                switch http.statusCode {
                case 429: failure = .rateLimited
                case 500, 502, 503, 504: failure = .http(status: http.statusCode, message: msg)
                default: throw GeminiError.http(status: http.statusCode, message: msg)
                }
            } catch let e as GeminiError {
                throw e
            } catch is CancellationError {
                throw GeminiError.cancelled
            } catch let e as URLError {
                if e.code == .cancelled { throw GeminiError.cancelled }
                let transient: [URLError.Code] = [.timedOut, .networkConnectionLost, .cannotConnectToHost, .dnsLookupFailed, .notConnectedToInternet]
                failure = .network(Self.describe(e))
                if !transient.contains(e.code) || e.code == .notConnectedToInternet { throw failure }
            } catch {
                throw GeminiError.network(Clean.text(error.localizedDescription.replacingOccurrences(of: key, with: "[KEY]"), max: 200))
            }
            guard attempt <= maxRetries else { throw failure }
            let backoff = min(maxBackoff, retryAfter ?? baseBackoff * pow(2, Double(attempt - 1)) * Double.random(in: 0.8...1.25))
            log.info("gemini retry \(attempt, privacy: .public) after \(backoff, privacy: .public)s")
            do { try await Task.sleep(nanoseconds: UInt64(backoff * 1_000_000_000)) } catch { throw GeminiError.cancelled }
        }
    }

    /// URLError text without the failing URL or any userInfo (keeps errors short and free of request details).
    static func describe(_ e: URLError) -> String {
        switch e.code {
        case .timedOut: return "the request timed out"
        case .notConnectedToInternet: return "this Mac is offline"
        case .networkConnectionLost: return "the connection dropped"
        case .cannotConnectToHost, .cannotFindHost, .dnsLookupFailed: return "couldn't connect to Google"
        case .serverCertificateUntrusted, .serverCertificateHasBadDate, .serverCertificateNotYetValid, .serverCertificateHasUnknownRoot,
             .clientCertificateRejected, .secureConnectionFailed, .cancelled:
            return "the secure connection to Google couldn't be verified"
        default: return "network error \(e.code.rawValue)"
        }
    }

    /// Parses `Retry-After: 12` or a google.rpc.RetryInfo `retryDelay: "12s"`.
    static func retryDelay(header: String?, details: String?) -> TimeInterval? {
        if let h = header, let s = Double(h.trimmingCharacters(in: .whitespaces)), s.isFinite, s >= 0 { return min(s, 60) }
        if let d = details?.trimmingCharacters(in: .whitespaces), d.hasSuffix("s"), let s = Double(d.dropLast()), s.isFinite, s >= 0 { return min(s, 60) }
        return nil
    }

    /// Generates and decodes structured JSON output.
    public func generateJSON<T: Decodable>(_ type: T.Type, model: String, request: GeminiRequest) async throws -> (T, GeminiResult) {
        let r = try await generate(model: model, request: request)
        return (try Self.decodeJSON(type, from: r.text), r)
    }

    /// Decodes model JSON; tolerates a ```json fence or leading prose even though the schema should prevent it.
    public static func decodeJSON<T: Decodable>(_ type: T.Type, from text: String) throws -> T {
        var t = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if t.hasPrefix("```") {
            t = t.components(separatedBy: "\n").dropFirst().joined(separator: "\n")
            if let r = t.range(of: "```", options: .backwards) { t = String(t[..<r.lowerBound]) }
        }
        if !t.hasPrefix("{"), let a = t.firstIndex(of: "{"), let b = t.lastIndex(of: "}"), a < b { t = String(t[a...b]) }
        do { return try JSONDecoder().decode(T.self, from: Data(t.utf8)) }
        catch let DecodingError.keyNotFound(k, _) { throw GeminiError.badJSON("missing \(k.stringValue)") }
        catch let DecodingError.typeMismatch(_, c) { throw GeminiError.badJSON("wrong type at \(c.codingPath.map(\.stringValue).joined(separator: "."))") }
        catch { throw GeminiError.badJSON("not JSON") }
    }
}
