import Foundation
import Observation
import RampartShared
import RampartAI

/// State for the AI Assistant screen. Owned by the AI agent (A1).
/// Nothing is ever sent automatically: every request starts from a user action (Send, a suggestion chip, Explain).
@MainActor
@Observable
final class AIChatModel {
    static let shared = AIChatModel()

    enum Mode: String, CaseIterable, Identifiable {
        case ask = "Ask", scam = "Scam Check", link = "Link Check"
        var id: String { rawValue }
        var symbol: String { switch self { case .ask: return "bubble.left.and.text.bubble.right"; case .scam: return "envelope.badge.shield.half.filled"; case .link: return "link" } }
        var placeholder: String {
            switch self {
            case .ask: return "Ask about your Mac's security…"
            case .scam: return "Paste a message, email or text you're unsure about…"
            case .link: return "Paste a link to check…"
            }
        }
    }

    enum Payload: Equatable {
        case text(String)
        case reply(AssistantReply)
        case scam(AIScamAssessment)
        case url(URLExplanation)
        case detection(DetectionExplanation)
        case plan(PosturePlan)
        case error(String)
    }

    struct Message: Identifiable, Equatable {
        let id = UUID()
        var isUser: Bool
        var title: String? = nil
        var payload: Payload
        var date = Date()
        /// Exactly what went to Google for this exchange (shown under "What was sent").
        var sent: String? = nil
        var redactionSummary: String? = nil
        var meta: String? = nil
        /// Streaming-style reveal: characters of the main text shown so far.
        var revealed: Int = .max
    }

    var messages: [Message] = []
    var draft = ""
    var mode: Mode = .ask
    var isSending = false
    var enabled: Bool
    var keyStatus: GeminiKeyStore.Status = .missing
    var needsKeychainPermission = false
    var modelID: String

    @ObservationIgnored let settings = AISettings.shared
    @ObservationIgnored lazy var service = AIService(settings: settings)
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var revealTask: Task<Void, Never>?

    init() {
        enabled = AISettings.shared.enabled
        modelID = AISettings.shared.modelID
        refreshKey()
    }

    var pasteCheckEnabled: Bool {
        get { settings.pasteCheckEnabled }
        set { settings.pasteCheckEnabled = newValue }
    }

    func refreshKey() { keyStatus = GeminiKeyStore.status() }

    func setEnabled(_ on: Bool) {
        settings.enabled = on; enabled = on
        if !on { cancel() }
    }

    func setModel(_ id: String) { settings.modelID = id; modelID = settings.modelID }

    func saveKey(_ k: String) throws {
        try GeminiKeyStore.save(k); needsKeychainPermission = false; refreshKey()
    }
    func removeKey() throws { try GeminiKeyStore.remove(); refreshKey() }

    /// The single place a Keychain dialog may appear: the user pressed "Allow Keychain Access".
    func grantKeychainAccess() {
        if (try? GeminiKeyStore.readKey(allowUI: true)) != nil { needsKeychainPermission = false }
        refreshKey()
    }

    // MARK: Preview of what will be sent

    struct Preview { var text: String; var redaction: String; var tokens: Int }

    func preview(posture: [PostureCheck]) -> Preview? {
        let q = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty else { return nil }
        switch mode {
        case .ask:
            let p = SecurityAssistant.prepare(question: q, history: history, posture: posture, service: service)
            return Preview(text: p.disclosure, redaction: p.redaction.summary, tokens: p.estimatedTokens)
        case .scam:
            let p = ScamSecondOpinion.prepare(text: q, service: service)
            return Preview(text: p.disclosure, redaction: p.redaction.summary, tokens: p.estimatedTokens)
        case .link:
            let p = URLReputationExplainer.prepare(url: q, localSignals: URLLocalSignals.basic(q), service: service)
            return Preview(text: p.disclosure, redaction: p.redaction.summary, tokens: p.estimatedTokens)
        }
    }

    private var history: [ChatTurn] {
        messages.suffix(6).compactMap { m in
            switch m.payload {
            case .text(let t) where m.isUser: return ChatTurn(role: .user, text: t)
            case .reply(let r): return ChatTurn(role: .assistant, text: r.answer)
            default: return nil
            }
        }
    }

    // MARK: Actions (all user-initiated)

    func send(posture: [PostureCheck]) {
        let q = draft.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !q.isEmpty, !isSending else { return }
        draft = ""
        let hist = history
        let svc = service
        switch mode {
        case .ask:
            let p = SecurityAssistant.prepare(question: q, history: hist, posture: posture, service: svc)
            run(userText: q, title: nil, prepared: p) { .reply($0) }
        case .scam:
            run(userText: q, title: "Scam check", prepared: ScamSecondOpinion.prepare(text: q, service: svc)) { .scam($0) }
        case .link:
            let p = URLReputationExplainer.prepare(url: q, localSignals: URLLocalSignals.basic(q), service: svc)
            run(userText: q, title: "Link check", prepared: p) { .url($0) }
        }
    }

    func explain(_ d: Detection) {
        run(userText: "Explain “\(d.name)”", title: "Detection explained", prepared: ExplainDetection.prepare(d, service: service)) { .detection($0) }
    }

    func planPosture(_ checks: [PostureCheck]) {
        run(userText: "Turn my Security Score into a plan", title: "Your security plan", prepared: ExplainPosture.prepare(checks, service: service)) { .plan($0) }
    }

    func cancel() { task?.cancel(); task = nil; isSending = false }
    func clear() { cancel(); revealTask?.cancel(); messages = [] }

    private func run<O: Sendable>(userText: String, title: String?, prepared: AIPrepared<O>, wrap: @escaping (O) -> Payload) {
        guard enabled else { return }
        messages.append(Message(isUser: true, payload: .text(userText), sent: prepared.disclosure, redactionSummary: prepared.redaction.summary))
        isSending = true
        let svc = service
        task = Task { [weak self] in
            do {
                let out = try await svc.run(prepared)
                guard let self, !Task.isCancelled else { return }
                let meta = "\(out.model) · \(String(format: "%.1f", out.latency)) s · ~\(out.estimatedTokens) tokens estimated" + (out.usage?.totalTokenCount.map { ", \($0) used" } ?? "")
                self.append(Message(isUser: false, title: title, payload: wrap(out.output), sent: out.sentText, redactionSummary: out.redactionSummary, meta: meta, revealed: 0))
            } catch {
                guard let self else { return }
                if case GeminiError.noKey(let m) = error, m == GeminiKeyStore.KeyError.interactionNotAllowed.description { self.needsKeychainPermission = true }
                let text = (error as? GeminiError)?.description ?? error.localizedDescription
                if (error as? GeminiError) != .cancelled { self.append(Message(isUser: false, payload: .error(text))) }
            }
            self?.isSending = false
        }
    }

    private func append(_ m: Message) {
        messages.append(m)
        guard m.revealed == 0, let idx = messages.indices.last else { return }
        let total = Self.mainText(m.payload).count
        revealTask?.cancel()
        let id = m.id
        revealTask = Task { [weak self] in
            var shown = 0
            while shown < total {
                shown = min(total, shown + max(3, total / 90))
                guard let self, !Task.isCancelled, idx < self.messages.count, self.messages[idx].id == id else { return }
                self.messages[idx].revealed = shown
                try? await Task.sleep(nanoseconds: 16_000_000)
            }
            if let self, idx < self.messages.count, self.messages[idx].id == id { self.messages[idx].revealed = .max }
        }
    }

    static func mainText(_ p: Payload) -> String {
        switch p {
        case .text(let t), .error(let t): return t
        case .reply(let r): return r.answer
        case .scam(let s): return s.summary.isEmpty ? s.advice : s.summary
        case .url(let u): return u.summary
        case .detection(let d): return d.summary + "\n\n" + d.whatItMeans
        case .plan(let p): return p.headline
        }
    }
}
