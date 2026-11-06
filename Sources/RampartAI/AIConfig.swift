import Foundation
import RampartShared

// RamPart AI: Gemini-powered explanations. Opt-in, user-initiated only, redacted before sending.
//
// API: Gemini REST `POST https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent`
// with the key ONLY in the `x-goog-api-key` header. Structured output via
// `generationConfig.responseMimeType = "application/json"` + `responseJsonSchema`.
// Models (aistudio.google.com/docs/models, checked 2026-11-06):
//   fast default  : gemini-3.5-flash-lite  ("fastest, most cost-effective 3.5 model", Stable)
//   stronger      : gemini-3.8-flash       ("most intelligent Flash model")
//   strongest opt : gemini-4-argon         (flagship reasoning; slower, opt-in only)

public struct GeminiModel: Hashable, Codable, Sendable, Identifiable {
    public var id: String
    public var displayName: String
    public var blurb: String
    public init(id: String, displayName: String, blurb: String) { self.id = id; self.displayName = displayName; self.blurb = blurb }

    public static let fast = GeminiModel(id: "gemini-3.5-flash-lite", displayName: "Fast", blurb: "Gemini 3.5 Flash-Lite: quick answers")
    public static let strong = GeminiModel(id: "gemini-3.8-flash", displayName: "Thorough", blurb: "Gemini 3.8 Flash: more careful reasoning")
    public static let flagship = GeminiModel(id: "gemini-4-argon", displayName: "Deep", blurb: "Gemini 4 Argon: slowest, most capable")
    public static let all: [GeminiModel] = [.fast, .strong, .flagship]

    /// Model ids must be simple path components; anything else is rejected (no URL injection).
    public static func isValidID(_ s: String) -> Bool {
        !s.isEmpty && s.count <= 64 && s.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
    }
}

/// User-facing AI preferences. Never contains the API key (that lives only in the login Keychain).
public final class AISettings: @unchecked Sendable {
    public static let shared = AISettings()
    private let defaults: UserDefaults
    private enum K { static let enabled = "ai.enabled", consentDate = "ai.consentDate", model = "ai.model", strongModel = "ai.strongModel", paste = "ai.pasteCheck" }

    public init(defaults: UserDefaults = UserDefaults(suiteName: Product.bundlePrefix + ".ai") ?? .standard) { self.defaults = defaults }

    /// Off until the user turns it on in the app after reading the disclosure.
    public var enabled: Bool {
        get { defaults.bool(forKey: K.enabled) }
        set {
            defaults.set(newValue, forKey: K.enabled)
            if newValue { defaults.set(Date(), forKey: K.consentDate) } else { defaults.removeObject(forKey: K.consentDate) }
        }
    }
    public var consentDate: Date? { defaults.object(forKey: K.consentDate) as? Date }

    /// Separate opt-in for checking pasted Terminal commands with AI. Only effective while `enabled` is on.
    /// Off by default: it is the one AI feature triggered by an action (paste-and-run) rather than a button press.
    public var pasteCheckEnabled: Bool {
        get { enabled && defaults.bool(forKey: K.paste) }
        set { defaults.set(newValue, forKey: K.paste) }
    }

    /// Default model for chat and explanations (configurable).
    public var modelID: String {
        get { let v = defaults.string(forKey: K.model) ?? GeminiModel.fast.id; return GeminiModel.isValidID(v) ? v : GeminiModel.fast.id }
        set { if GeminiModel.isValidID(newValue) { defaults.set(newValue, forKey: K.model) } }
    }
    /// Model used for heavier tasks (posture plan). Configurable.
    public var strongModelID: String {
        get { let v = defaults.string(forKey: K.strongModel) ?? GeminiModel.strong.id; return GeminiModel.isValidID(v) ? v : GeminiModel.strong.id }
        set { if GeminiModel.isValidID(newValue) { defaults.set(newValue, forKey: K.strongModel) } }
    }

    /// Plain-language disclosure shown before opt-in.
    public static let disclosure = """
    When AI Assistant is on, the text you choose to send (your question, a message you paste for a scam check, \
    a link, or a short summary of a detection or your Security Score checks) is sent to Google's Gemini API to \
    generate an answer. RamPart never sends files, file contents, passwords, your vault or Keychain data, and never \
    sends anything in the background. Emails, phone numbers, card numbers, IBANs, key-like strings and your home \
    folder path are removed first, and you can see exactly what was sent with each message. Google's Gemini API terms \
    apply to what you send. AI answers can be wrong: RamPart's own detections stay in charge.
    """
}
