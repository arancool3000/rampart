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
        var id = UUID()
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
    var mode: Mode = .ask { didSet { if mode != oldValue { updateCurrent { $0.mode = self.mode.rawValue } } } }
    /// All chats (redacted text only), newest first. Persisted encrypted when "Keep chat history" is on.
    var chats: [ChatRecord] = []
    var currentID: UUID?
    var search = ""
    var keepHistory: Bool
    var unreadableChats = 0
    var isSending = false
    var enabled: Bool
    var keyStatus: GeminiKeyStore.Status = .missing
    var needsKeychainPermission = false
    var modelID: String

    @ObservationIgnored let settings = AISettings.shared
    @ObservationIgnored let store = ChatStore()
    @ObservationIgnored let gate = AIActionGate()
    /// Proposal states for the cards (mirrors the gate). Proposals restored from saved chats aren't registered
    /// with the gate, so they can't be applied: they show as expired.
    var actionStates: [UUID: AIActionGate.State] = [:]
    @ObservationIgnored lazy var service = AIService(settings: settings)
    @ObservationIgnored private var task: Task<Void, Never>?
    @ObservationIgnored private var revealTask: Task<Void, Never>?

    init() {
        enabled = AISettings.shared.enabled
        modelID = AISettings.shared.modelID
        keepHistory = AISettings.shared.keepChatHistory
        refreshKey()
        if keepHistory {
            chats = store.loadAll()
            unreadableChats = store.unreadable.count
        }
    }

    // MARK: Chats

    var current: ChatRecord? { chats.first { $0.id == currentID } }

    var filteredGroups: [(ChatGroup, [ChatRecord])] {
        ChatGroup.grouped(chats.filter { $0.matches(search) })
    }

    /// Starts a fresh, empty conversation (the record is created on the first message).
    func newChat(mode: Mode = .ask) {
        cancel(); revealTask?.cancel()
        currentID = nil; messages = []; draft = ""
        self.mode = mode
    }

    func select(_ id: UUID?) {
        guard let id, id != currentID, let c = chats.first(where: { $0.id == id }) else { return }
        cancel(); revealTask?.cancel()
        currentID = id
        messages = c.messages.map(Self.message(from:))
        mode = Mode(rawValue: c.mode) ?? .ask
        draft = ""
    }

    func rename(_ id: UUID, to title: String) {
        let t = title.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return }
        update(id) { $0.title = String(t.prefix(80)); $0.titleIsCustom = true }
    }

    func togglePin(_ id: UUID) { update(id) { $0.pinned.toggle() } }

    func delete(_ id: UUID) {
        if id == currentID { newChat() }
        chats.removeAll { $0.id == id }
        store.delete(id)
    }

    func deleteAllChats() {
        newChat()
        chats = []
        store.deleteAll()
        unreadableChats = 0
    }

    func setKeepHistory(_ on: Bool) {
        settings.keepChatHistory = on; keepHistory = on
        if on { chats.forEach { try? store.save($0) } }
    }

    private func update(_ id: UUID, touch: Bool = false, _ change: (inout ChatRecord) -> Void) {
        guard let i = chats.firstIndex(where: { $0.id == id }) else { return }
        change(&chats[i])
        if touch { chats[i].updated = Date() }
        if keepHistory { try? store.save(chats[i]) }
    }
    private func updateCurrent(_ change: (inout ChatRecord) -> Void) { if let id = currentID { update(id, change) } }

    /// Ensures there is a record for the conversation, titling it from the first (redacted) question.
    private func ensureChat(firstText: String, title: String?) -> UUID {
        if let id = currentID, chats.contains(where: { $0.id == id }) { return id }
        let t: String
        if let title { t = title } else {
            switch mode {
            case .ask: t = ChatTitle.make(from: firstText)
            case .scam: t = "Scam check: " + ChatTitle.make(from: firstText, maxLength: 28)
            case .link: t = "Link: " + (URLComponents(string: firstText.contains("://") ? firstText : "https://" + firstText)?.host ?? ChatTitle.make(from: firstText, maxLength: 30))
            }
        }
        let c = ChatRecord(title: t, mode: mode.rawValue)
        chats.insert(c, at: 0)
        currentID = c.id
        if keepHistory { try? store.save(c) }
        return c.id
    }

    private func record(_ m: Message, in chatID: UUID) {
        update(chatID, touch: true) { $0.messages.append(Self.stored(from: m)) }
    }

    static func stored(from m: Message) -> StoredChatMessage {
        var s = StoredChatMessage(id: m.id, isUser: m.isUser, date: m.date, kind: .text, title: m.title, text: mainText(m.payload),
                                  sent: m.sent, redactionSummary: m.redactionSummary, meta: m.meta)
        switch m.payload {
        case .text: s.kind = .text
        case .error: s.kind = .error
        case .reply(let r): s.kind = .reply; s.reply = r
        case .scam(let x): s.kind = .scam; s.scam = x
        case .url(let x): s.kind = .url; s.url = x
        case .detection(let x): s.kind = .detection; s.detection = x
        case .plan(let x): s.kind = .plan; s.plan = x
        }
        return s
    }

    static func message(from s: StoredChatMessage) -> Message {
        let p: Payload
        switch s.kind {
        case .reply: p = s.reply.map(Payload.reply) ?? .text(s.text)
        case .scam: p = s.scam.map(Payload.scam) ?? .text(s.text)
        case .url: p = s.url.map(Payload.url) ?? .text(s.text)
        case .detection: p = s.detection.map(Payload.detection) ?? .text(s.text)
        case .plan: p = s.plan.map(Payload.plan) ?? .text(s.text)
        case .error: p = .error(s.text)
        case .text: p = .text(s.text)
        }
        return Message(id: s.id, isUser: s.isUser, title: s.title, payload: p, date: s.date, sent: s.sent.map(AIService.cleanLegacyDisclosure),
                       redactionSummary: s.redactionSummary, meta: s.meta, revealed: .max)
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

    /// Earlier Ask turns only: a user question counts only when the assistant answered it as a chat reply.
    /// Pasted scam messages, links, detection requests and RamPart's own result lines never go back to the model
    /// as "the user said", so text from those can't later steer the assistant or its proposals.
    private var history: [ChatTurn] { Self.history(from: messages) }

    static func history(from messages: [Message]) -> [ChatTurn] {
        var out: [ChatTurn] = []
        for (i, m) in messages.enumerated() {
            guard case .reply(let r) = m.payload, !m.isUser, i > 0 else { continue }
            let q = messages[i - 1]
            guard q.isUser, case .text(let t) = q.payload else { continue }
            out.append(ChatTurn(role: .user, text: t))
            out.append(ChatTurn(role: .assistant, text: r.answer))
        }
        return Array(out.suffix(6))
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
            let p = SecurityAssistant.prepare(question: q, history: hist, posture: posture, actionContext: actionContext(posture), service: svc)
            run(userText: q, title: nil, prepared: p) { .reply($0) }
        case .scam:
            run(userText: q, title: "Scam check", prepared: ScamSecondOpinion.prepare(text: q, service: svc)) { .scam($0) }
        case .link:
            let p = URLReputationExplainer.prepare(url: q, localSignals: URLLocalSignals.basic(q), service: svc)
            run(userText: q, title: "Link check", prepared: p) { .url($0) }
        }
    }

    func explain(_ d: Detection) {
        newChat()
        run(userText: "Explain “\(d.name)”", title: "Detection explained", prepared: ExplainDetection.prepare(d, service: service), chatTitle: "Explain: \(d.name)") { .detection($0) }
    }

    func planPosture(_ checks: [PostureCheck]) {
        run(userText: "Turn my Security Score into a plan", title: "Your security plan", prepared: ExplainPosture.prepare(checks, service: service)) { .plan($0) }
    }

    private func actionContext(_ posture: [PostureCheck]) -> AIActionValidator.Context {
        let app = AppModel.shared
        let failing = Set(posture.filter { $0.state == .fail && $0.fixable }.map(\.id)).intersection(AIAction.fixableCheckIDs)
        return AIActionValidator.Context(settings: app.mode == .live ? app.settings : nil, fixableFailing: failing)
    }

    // MARK: Proposed actions (run only from the Apply button)

    func dismissAction(_ id: UUID) { gate.dismiss(id); actionStates[id] = gate.state(id) }

    func applyAction(_ p: AIProposedAction, confirmedLowering: Bool) {
        guard actionStates[p.id] == .pending || { if case .failed = actionStates[p.id] { return true }; return false }() else { return }
        // Only proposals shown in the open conversation can run (never one from another or a restored chat).
        // wms-o5: the exact proposal (id, action, reason) must be on a card in this conversation, and the gate re-checks it.
        guard messages.contains(where: { if case .reply(let r) = $0.payload { return r.actions?.contains { $0 == p } == true }; return false }) else { return }
        actionStates[p.id] = .running
        let gate = gate
        let chatID = currentID
        Task { [weak self] in
            var line: String
            do { line = try await gate.approve(displayed: p, confirmedLowering: confirmedLowering, executor: AppActionExecutor()) }
            catch { line = "Couldn't apply “\(p.title)”: \(error)" }
            guard let self else { return }
            self.actionStates[p.id] = gate.state(p.id)
            if let chatID, self.currentID == chatID {
                let m = Message(isUser: false, payload: .text(line), revealed: .max)
                self.messages.append(m)
                self.record(m, in: chatID)
            }
        }
    }

    func cancel() { task?.cancel(); task = nil; isSending = false }


    private func run<O: Sendable>(userText: String, title: String?, prepared: AIPrepared<O>, chatTitle: String? = nil, wrap: @escaping (O) -> Payload) {
        guard enabled else { return }
        // Only redacted text is shown, kept and stored; the raw input is dropped here.
        let shown = service.redactor.redact(userText).text
        let chatID = ensureChat(firstText: shown, title: chatTitle)
        let userMsg = Message(isUser: true, payload: .text(shown), sent: prepared.disclosure, redactionSummary: prepared.redaction.summary)
        messages.append(userMsg)
        record(userMsg, in: chatID)
        isSending = true
        let svc = service
        task = Task { [weak self] in
            do {
                let out = try await svc.run(prepared)
                guard let self, !Task.isCancelled, self.currentID == chatID else { self?.isSending = false; return }
                let meta = "\(out.model) · \(String(format: "%.1f", out.latency)) s · ~\(out.estimatedTokens) tokens estimated" + (out.usage?.totalTokenCount.map { ", \($0) used" } ?? "")
                let m = Message(isUser: false, title: title, payload: wrap(out.output), sent: out.sentText, redactionSummary: out.redactionSummary, meta: meta, revealed: 0)
                if case .reply(let r) = m.payload, let acts = r.actions {
                    self.gate.register(acts)
                    for a in acts { self.actionStates[a.id] = .pending }
                }
                self.record(m, in: chatID)
                self.append(m)
            } catch {
                guard let self else { return }
                if case GeminiError.noKey(let m) = error, m == GeminiKeyStore.KeyError.interactionNotAllowed.description { self.needsKeychainPermission = true }
                let text = (error as? GeminiError)?.description ?? error.localizedDescription
                if (error as? GeminiError) != .cancelled, self.currentID == chatID {
                    let m = Message(isUser: false, payload: .error(text))
                    self.record(m, in: chatID)
                    self.append(m)
                }
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
