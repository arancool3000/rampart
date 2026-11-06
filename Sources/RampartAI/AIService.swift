import Foundation
import RampartShared

/// A request that has been fully built and redacted but not yet sent. The UI shows `disclosure`
/// ("what will be sent") before or alongside sending.
public struct AIPrepared<Output: Sendable>: @unchecked Sendable {
    public var tool: String
    public var model: String
    public var request: GeminiRequest
    /// Exactly the user-turn text that goes to Google (system prompt excluded; it's fixed and public in source).
    public var disclosure: String
    public var redaction: Redactor.Result
    public var estimatedTokens: Int
    public var timeout: TimeInterval
    let decode: (String) throws -> Output
}

public struct AIOutcome<Output: Sendable>: Sendable {
    public var output: Output
    public var sentText: String
    public var redactionSummary: String
    public var estimatedTokens: Int
    public var usage: GeminiUsage?
    public var model: String
    public var latency: TimeInterval
}

/// Entry point for every AI tool. Enforces opt-in: nothing is sent unless `AISettings.enabled` is on.
public final class AIService: @unchecked Sendable {
    public let settings: AISettings
    public let client: GeminiClient
    public let redactor: Redactor

    public init(settings: AISettings = .shared, client: GeminiClient = GeminiClient(), redactor: Redactor = .default) {
        self.settings = settings; self.client = client; self.redactor = redactor
    }

    public var keyStatus: GeminiKeyStore.Status { GeminiKeyStore.status() }
    public var isReady: Bool { settings.enabled && keyStatus == .present }

    /// Sends a prepared request. Throws `.notEnabled` if the user hasn't opted in.
    public func run<Output>(_ p: AIPrepared<Output>) async throws -> AIOutcome<Output> {
        guard settings.enabled else { throw GeminiError.notEnabled }
        let r: GeminiResult
        if p.timeout > 0 {
            r = try await withThrowingTaskGroup(of: GeminiResult.self) { g in
                g.addTask { try await self.client.generate(model: p.model, request: p.request) }
                g.addTask { try await Task.sleep(nanoseconds: UInt64(p.timeout * 1e9)); throw GeminiError.network("timed out after \(Int(p.timeout)) s") }
                defer { g.cancelAll() }
                return try await g.next()!
            }
        } else {
            r = try await client.generate(model: p.model, request: p.request)
        }
        let out = try p.decode(r.text)
        return AIOutcome(output: out, sentText: p.disclosure, redactionSummary: p.redaction.summary,
                         estimatedTokens: p.estimatedTokens, usage: r.usage, model: r.model, latency: r.latency)
    }

    // MARK: Builder shared by tools

    func prepare<Raw: Decodable, Output>(tool: String, model: String? = nil, system: String, history: [GeminiContent] = [],
                                         blocks: [(String, String)], instruction: String, schema: JSONValue,
                                         maxOutputTokens: Int = 1200, timeout: TimeInterval = 0,
                                         raw: Raw.Type, validate: @escaping (Raw) throws -> Output) -> AIPrepared<Output> {
        let nonce = PromptKit.nonce()
        var counts: [Redactor.Kind: Int] = [:]
        var parts: [String] = []
        for (label, content) in blocks {
            let r = redactor.redact(content)
            r.counts.forEach { counts[$0.key, default: 0] += $0.value }
            parts.append(PromptKit.block(label, r.text, nonce: nonce))
        }
        let userText = instruction + "\n\n" + parts.joined(separator: "\n\n")
        let req = GeminiClient.buildRequest(system: PromptKit.baseRules + "\n\n" + system,
                                            turns: history + [GeminiContent(role: "user", text: userText)],
                                            schema: schema, maxOutputTokens: maxOutputTokens)
        let historyText = history.map { ($0.role ?? "") + ": " + $0.parts.compactMap(\.text).joined() }.joined(separator: "\n")
        return AIPrepared(tool: tool, model: model ?? settings.modelID, request: req,
                          disclosure: (historyText.isEmpty ? "" : "Earlier conversation:\n" + historyText + "\n\n") + userText,
                          redaction: Redactor.Result(text: userText, counts: counts),
                          estimatedTokens: GeminiClient.estimateTokens(req), timeout: timeout,
                          decode: { text in try validate(try GeminiClient.decodeJSON(Raw.self, from: text)) })
    }
}

// MARK: - Output hygiene: model output is untrusted text, never executed or rendered as markup.

enum Clean {
    static func text(_ s: String?, max: Int = 1200) -> String {
        guard var t = s else { return "" }
        t = String(t.unicodeScalars.filter { $0 == "\n" || !CharacterSet.controlCharacters.contains($0) }.map(Character.init))
        t = t.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "```", with: "")
        t = t.trimmingCharacters(in: .whitespacesAndNewlines)
        return t.count > max ? String(t.prefix(max - 1)) + "…" : t
    }
    static func list(_ a: [String]?, maxItems: Int = 8, maxLen: Int = 400) -> [String] {
        (a ?? []).map { text($0, max: maxLen) }.filter { !$0.isEmpty }.prefix(maxItems).map { $0 }
    }
    static func pick<E: RawRepresentable>(_ s: String?, _ fallback: E) -> E where E.RawValue == String {
        s.flatMap { E(rawValue: $0.trimmingCharacters(in: .whitespaces).lowercased()) } ?? fallback
    }
    static func clamp(_ v: Int?, _ lo: Int, _ hi: Int, default d: Int) -> Int { min(hi, max(lo, v ?? d)) }
}
