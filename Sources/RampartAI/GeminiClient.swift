import Foundation
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
    let session: URLSession
    public init(timeout: TimeInterval = 45) {
        let c = URLSessionConfiguration.ephemeral          // no cookies, no disk cache
        c.timeoutIntervalForRequest = timeout
        c.timeoutIntervalForResource = timeout * 2
        c.urlCache = nil
        c.requestCachePolicy = .reloadIgnoringLocalCacheData
        c.httpCookieStorage = nil
        c.waitsForConnectivity = false
        session = URLSession(configuration: c)
    }
    public func send(_ request: URLRequest) async throws -> (Data, HTTPURLResponse) {
        let (d, r) = try await session.data(for: request)
        guard let h = r as? HTTPURLResponse else { throw URLError(.badServerResponse) }
        return (d, h)
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
    public static func urlRequest(model: String, body: GeminiRequest, key: String, timeout: TimeInterval) throws -> URLRequest {
        guard GeminiModel.isValidID(model) else { throw GeminiError.invalidModel }
        let url = apiBase.appendingPathComponent("\(model):generateContent")
        guard url.host == host, url.scheme == "https" else { throw GeminiError.invalidModel }
        var r = URLRequest(url: url, cachePolicy: .reloadIgnoringLocalCacheData, timeoutInterval: timeout)
        r.httpMethod = "POST"
        r.setValue("application/json", forHTTPHeaderField: "Content-Type")
        r.setValue(key, forHTTPHeaderField: "x-goog-api-key")
        r.httpBody = try JSONEncoder().encode(body)
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
            var retryAfter: TimeInterval?
            let failure: GeminiError
            do {
                let (data, http) = try await transport.send(req)
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
                let msg = Redactor.default.redact(String((env?.error.message ?? HTTPURLResponse.localizedString(forStatusCode: http.statusCode)).prefix(300))).text
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
                failure = .network(e.localizedDescription)
                if !transient.contains(e.code) || e.code == .notConnectedToInternet { throw failure }
            } catch {
                throw GeminiError.network(error.localizedDescription)
            }
            guard attempt <= maxRetries else { throw failure }
            let backoff = min(maxBackoff, retryAfter ?? baseBackoff * pow(2, Double(attempt - 1)) * Double.random(in: 0.8...1.25))
            log.info("gemini retry \(attempt, privacy: .public) after \(backoff, privacy: .public)s")
            do { try await Task.sleep(nanoseconds: UInt64(backoff * 1_000_000_000)) } catch { throw GeminiError.cancelled }
        }
    }

    /// Parses `Retry-After: 12` or a google.rpc.RetryInfo `retryDelay: "12s"`.
    static func retryDelay(header: String?, details: String?) -> TimeInterval? {
        if let h = header, let s = Double(h.trimmingCharacters(in: .whitespaces)) { return s }
        if let d = details?.trimmingCharacters(in: .whitespaces), d.hasSuffix("s"), let s = Double(d.dropLast()) { return s }
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
