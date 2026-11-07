import Foundation
import RampartShared

/// A request that has been fully built and redacted but not yet sent. The UI shows `disclosure`
/// ("what will be sent") before or alongside sending.
public struct AIPrepared<Output: Sendable>: @unchecked Sendable {
    public var tool: String
    public var model: String
    public var request: GeminiRequest
    /// What the user sees under "What was sent": their own content (redacted, without any markers or
    /// instructions) plus a plain summary of the context RamPart added. Never the system prompt or schema.
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

    /// `blocks`: (label, content). Labels in `context` are summarised in the disclosure instead of shown.
    func prepare<Raw: Decodable, Output>(tool: String, model: String? = nil, system: String, history: [GeminiContent] = [],
                                         blocks: [(String, String)], context: [String: String] = [:], instruction: String, schema: JSONValue,
                                         maxOutputTokens: Int = 1200, timeout: TimeInterval = 0,
                                         raw: Raw.Type, validate: @escaping (Raw) throws -> Output) -> AIPrepared<Output> {
        let nonce = PromptKit.nonce()
        var counts: [Redactor.Kind: Int] = [:]
        var parts: [String] = []
        var visible: [String] = []
        var summaries: [String] = []
        for (label, content) in blocks {
            let r = redactor.redact(content)
            r.counts.forEach { counts[$0.key, default: 0] += $0.value }
            parts.append(PromptKit.block(label, r.text, nonce: nonce))
            if let summary = context[label] { summaries.append(summary) } else { visible.append(PromptKit.neutralize(r.text)) }
        }
        let userText = instruction + "\n\n" + parts.joined(separator: "\n\n")
        let req = GeminiClient.buildRequest(system: PromptKit.baseRules + "\n\n" + system,
                                            turns: history + [GeminiContent(role: "user", text: userText)],
                                            schema: schema, maxOutputTokens: maxOutputTokens)
        if !history.isEmpty { summaries.insert("the last \(history.count) message\(history.count == 1 ? "" : "s") of this conversation", at: 0) }
        let tail = "Plus RamPart's instructions" + (summaries.isEmpty ? "" : " and " + Self.list(summaries)) + "."
        let disclosure = (visible.isEmpty ? "" : visible.joined(separator: "\n\n") + "\n\n") + tail
        return AIPrepared(tool: tool, model: model ?? settings.modelID, request: req, disclosure: disclosure,
                          redaction: Redactor.Result(text: userText, counts: counts),
                          estimatedTokens: GeminiClient.estimateTokens(req), timeout: timeout,
                          decode: { text in
                              // Model output is untrusted: refuse answers that echo our markers, nonce or instructions.
                              if PromptKit.leaksPrompt(text, nonce: nonce, prompts: [PromptKit.baseRules, system]) {
                                  throw GeminiError.validation("the answer repeated RamPart's internal instructions")
                              }
                              return try validate(try GeminiClient.decodeJSON(Raw.self, from: text))
                          })
    }

    static func list(_ a: [String]) -> String {
        a.count <= 1 ? (a.first ?? "") : a.dropLast().joined(separator: ", ") + " and " + a.last!
    }

    /// Cleans "What was sent" text saved by older builds (which included markers and the instruction line).
    public static func cleanLegacyDisclosure(_ s: String) -> String {
        guard s.contains("<<<DATA") || s.contains("DATA>>>") else { return s }
        var keep: [String] = []
        var inside = false, label = ""
        for line in s.components(separatedBy: "\n") {
            if line.hasPrefix("<<<DATA ") { inside = true; label = line.split(separator: " ").dropFirst().first.map(String.init) ?? ""; continue }
            if line.hasPrefix("DATA>>>") { inside = false; continue }
            if inside && !["security_score_checks", "local_signals", "source_app"].contains(label) { keep.append(line) }
        }
        let body = keep.joined(separator: "\n").trimmingCharacters(in: .whitespacesAndNewlines)
        return (body.isEmpty ? "" : body + "\n\n") + "Plus RamPart's instructions and context."
    }
}

// MARK: - Output hygiene: model output is untrusted text, never executed or rendered as markup.

enum Clean {
    static func text(_ s: String?, max: Int = 1200) -> String {
        guard var t = s else { return "" }
        t = String(t.unicodeScalars.filter { $0 == "\n" || !CharacterSet.controlCharacters.contains($0) }.map(Character.init))
        t = t.replacingOccurrences(of: "**", with: "").replacingOccurrences(of: "```", with: "")
        t = PromptKit.neutralize(t)
        // Bidi overrides, zero-width and other invisible format characters (Cf) can disguise text; drop them.
        t = String(t.unicodeScalars.filter { $0.properties.generalCategory != .format }.map(Character.init))
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
