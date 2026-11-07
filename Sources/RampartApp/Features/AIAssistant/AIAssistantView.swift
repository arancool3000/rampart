import SwiftUI
import AppKit
import RampartShared
import RampartAI

/// "AI Assistant" screen (owner: A1). The app agent adds the sidebar entry: `AIAssistantView()`.
/// To explain a detection from elsewhere: `AIChatModel.shared.explain(detection)` then select this screen.
struct AIAssistantView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Bindable private var chat = AIChatModel.shared
    @StateVar private var confirmEnable = false
    @StateVar private var showKeySheet = false
    @StateVar private var confirmRemoveKey = false
    @StateVar private var showPreview = true
    @StateVar private var keyError: String?
    @StateVar private var confirmDeleteAll = false

    var body: some View {
        HStack(spacing: 0) {
            if chat.enabled && chat.keyStatus == .present {
                ChatListColumn(chat: chat)
                    .frame(width: 250)
                Divider()
            }
            conversation
        }
        .navigationTitle("AI Assistant")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                if chat.enabled && chat.keyStatus == .present {
                    Button { chat.newChat() } label: { Label("New Chat", systemImage: "square.and.pencil") }
                        .keyboardShortcut("n", modifiers: .command)
                        .help("New Chat (⌘N)")
                }
            }
        }
        .onAppear { chat.refreshKey() }
        .alert("Turn on AI Assistant?", isPresented: $confirmEnable) {
            Button("Turn On") { chat.setEnabled(true) }
            Button("Cancel", role: .cancel) {}
        } message: { Text(verbatim: AISettings.disclosure) }
        .alert("Remove the Gemini API key?", isPresented: $confirmRemoveKey) {
            Button("Remove", role: .destructive) { do { try chat.removeKey() } catch { keyError = "\(error)" } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("AI features stop working until you add a key again. Nothing else changes.") }
        .alert("Delete all chats?", isPresented: $confirmDeleteAll) {
            Button("Delete All", role: .destructive) { chat.deleteAllChats() }
            Button("Cancel", role: .cancel) {}
        } message: { Text("Every saved conversation and its encryption key are permanently removed from this Mac.") }
        .sheet(isPresented: $showKeySheet) { KeySheet(chat: chat, isPresented: $showKeySheet) }
    }

    private var conversation: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    VStack(alignment: .leading, spacing: Spacing.l) {
                        header
                        if !chat.enabled {
                            optInCard
                        } else if chat.keyStatus != .present {
                            keyMissingCard
                        } else {
                            if chat.needsKeychainPermission { keychainPermissionCard }
                            if chat.messages.isEmpty {
                                if chat.unreadableChats > 0 {
                                    Label("\(chat.unreadableChats) saved chat\(chat.unreadableChats == 1 ? "" : "s") couldn't be opened (damaged or changed outside RamPart) and were left untouched.", systemImage: "exclamationmark.lock")
                                        .font(.callout).foregroundStyle(.secondary)
                                }
                                suggestions
                            }
                            ForEach(chat.messages) { m in
                                MessageRow(message: m, reduceMotion: reduceMotion).id(m.id)
                            }
                            if chat.isSending { ThinkingRow().id("thinking") }
                        }
                    }
                    .contentColumn()
                }
                .onChange(of: chat.messages.count) { _, _ in
                    withAnimation(reduceMotion ? nil : .easeOut(duration: 0.25)) { proxy.scrollTo(chat.messages.last?.id, anchor: .bottom) }
                }
            }
            if chat.enabled && chat.keyStatus == .present { composer }
        }
        .frame(maxWidth: .infinity)
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: Spacing.l) {
            IconBadge(symbol: "sparkles", tint: .rampartTeal, size: 52)
            VStack(alignment: .leading, spacing: 4) {
                Text("AI Assistant").font(.title2.weight(.semibold)).fontDesign(.rounded)
                Text("Plain-language explanations and a second opinion, powered by Google Gemini.")
                    .font(.callout).foregroundStyle(.secondary)
                HStack(spacing: Spacing.s) {
                    keyIndicator
                    if chat.enabled { modelMenu }
                }
                .padding(.top, 2)
            }
            Spacer(minLength: Spacing.m)
            VStack(alignment: .trailing, spacing: 6) {
                Toggle(isOn: Binding(get: { chat.enabled }, set: { on in if on { confirmEnable = true } else { chat.setEnabled(false) } })) {
                    Text(chat.enabled ? "On" : "Off").font(.callout.weight(.medium))
                }
                .toggleStyle(.switch)
                .accessibilityLabel("AI Assistant")
                Menu {
                    Button(chat.keyStatus == .present ? "Replace Key…" : "Add Key…") { showKeySheet = true }
                    if chat.keyStatus == .present { Button("Remove Key…", role: .destructive) { confirmRemoveKey = true } }
                    Divider()
                    Toggle("Check pasted Terminal commands", isOn: Binding(get: { chat.pasteCheckEnabled }, set: { chat.pasteCheckEnabled = $0 }))
                        .disabled(!chat.enabled)
                    Divider()
                    Toggle("Keep chat history", isOn: Binding(get: { chat.keepHistory }, set: { chat.setKeepHistory($0) }))
                    Button("Delete All Chats…", role: .destructive) { confirmDeleteAll = true }
                        .disabled(chat.chats.isEmpty)
                } label: { Label("Settings", systemImage: "gearshape") }
                .menuStyle(.borderlessButton).fixedSize()
            }
        }
        .card(padding: Spacing.l, tint: .rampartTeal)
    }

    private var keyIndicator: some View {
        let (text, symbol, tint): (String, String, Color) = {
            switch chat.keyStatus {
            case .present: return chat.needsKeychainPermission ? ("Key needs permission", "key.fill", .orange) : ("API key in Keychain", "key.fill", .green)
            case .missing: return ("No API key", "key.slash", .orange)
            case .error: return ("Keychain error", "exclamationmark.triangle.fill", .red)
            }
        }()
        return HStack(spacing: 5) {
            Image(systemName: symbol).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
            Text(text).font(.caption.weight(.medium))
        }
        .padding(.horizontal, 8).padding(.vertical, 3)
        .background(tint.opacity(0.13), in: Capsule())
        .accessibilityElement(children: .combine)
    }

    private var modelMenu: some View {
        Menu {
            ForEach(GeminiModel.all) { m in
                Button { chat.setModel(m.id) } label: {
                    if m.id == chat.modelID { Label(m.blurb, systemImage: "checkmark") } else { Text(m.blurb) }
                }
            }
        } label: {
            Text(GeminiModel.all.first { $0.id == chat.modelID }?.displayName ?? chat.modelID).font(.caption.weight(.medium))
        }
        .menuStyle(.borderlessButton).fixedSize()
        .help("Model used for answers. Security plans use the Thorough model.")
    }

    // MARK: Opt-in / key states

    private var optInCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Label("Off until you turn it on", systemImage: "hand.raised.fill").font(.headline)
            Text(verbatim: AISettings.disclosure).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 6) {
                bullet("checkmark.circle.fill", .green, "Only what you type, paste, or ask to explain is sent")
                bullet("checkmark.circle.fill", .green, "Personal details and secrets are removed first, and you can review every message")
                bullet("xmark.circle.fill", .secondary, "Never sends files, file contents, passwords, your vault or Keychain")
                bullet("xmark.circle.fill", .secondary, "Never sends anything in the background")
            }
            Button("Turn On AI Assistant…") { confirmEnable = true }.buttonStyle(GlowButtonStyle()).controlSize(.large).padding(.top, 4)
        }
        .card()
    }

    private func bullet(_ symbol: String, _ tint: Color, _ text: String) -> some View {
        Label { Text(text).font(.callout) } icon: { Image(systemName: symbol).foregroundStyle(tint) }
    }

    private var keyMissingCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Label(chat.keyStatus == .missing ? "Add your Gemini API key" : chat.keyStatus.label, systemImage: "key")
                .font(.headline)
            Text("RamPart stores the key only in your login Keychain and sends it only to Google's Gemini API. Get a key at aistudio.google.com.")
                .font(.callout).foregroundStyle(.secondary)
            Button("Add Key…") { showKeySheet = true }.buttonStyle(GlowButtonStyle())
        }
        .card(tint: .orange)
    }

    private var keychainPermissionCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("One-time Keychain permission", systemImage: "lock.rotation").font(.headline)
            Text("macOS will ask whether RamPart may use the Gemini key in your Keychain. Choose “Always Allow” so it never asks again.")
                .font(.callout).foregroundStyle(.secondary)
            Button("Allow Keychain Access…") { chat.grantKeychainAccess() }.secondaryActionStyle()
        }
        .card(tint: .orange)
    }

    // MARK: Suggestions

    private var suggestions: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Try asking").font(.headline)
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 230), spacing: Spacing.m)], spacing: Spacing.m) {
                if !model.posture.isEmpty {
                    SuggestionChip(symbol: "list.number", title: "Turn my Security Score into a plan", subtitle: "Sends your check names and results") {
                        chat.planPosture(model.posture)
                    }
                }
                if let d = model.detections.first(where: { !$0.resolved }) ?? model.detections.first {
                    SuggestionChip(symbol: "questionmark.bubble", title: "Explain “\(d.name)”", subtitle: "Sends the detection name and evidence only") {
                        chat.explain(d)
                    }
                }
                SuggestionChip(symbol: "lock.laptopcomputer", title: "Should I turn on FileVault?", subtitle: "Ask") {
                    chat.mode = .ask; chat.draft = "Should I turn on FileVault, and how?"
                }
                SuggestionChip(symbol: "envelope.badge.shield.half.filled", title: "Is this message a scam?", subtitle: "Paste it in Scam Check") {
                    chat.mode = .scam; chat.draft = ""
                }
                SuggestionChip(symbol: "link", title: "Why does this link look suspicious?", subtitle: "Paste it in Link Check") {
                    chat.mode = .link; chat.draft = ""
                }
                SuggestionChip(symbol: "app.badge.checkmark", title: "How do I check an app is safe to open?", subtitle: "Ask") {
                    chat.mode = .ask; chat.draft = "How can I tell whether an app I downloaded is safe to open on my Mac?"
                }
            }
        }
    }

    // MARK: Composer

    private var composer: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            if showPreview, let p = chat.preview(posture: model.posture) {
                DisclosureGroup {
                    ScrollView { Text(verbatim: p.text).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading) }
                        .frame(maxHeight: 140)
                } label: {
                    HStack(spacing: 6) {
                        Image(systemName: "eye").foregroundStyle(Color.rampartTeal)
                        Text("Will be sent to Google").font(.caption.weight(.semibold))
                        Text("· Removed: \(p.redaction) · ~\(p.tokens) tokens").font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .padding(.horizontal, Spacing.m).padding(.vertical, 6)
                .background(Color.rampartTeal.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            HStack(alignment: .bottom, spacing: Spacing.s) {
                Picker("Mode", selection: $chat.mode) {
                    ForEach(AIChatModel.Mode.allCases) { m in Label(m.rawValue, systemImage: m.symbol).tag(m) }
                }
                .labelsHidden().pickerStyle(.menu).fixedSize()
                TextField(chat.mode.placeholder, text: $chat.draft, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...6)
                    .padding(.horizontal, 12).padding(.vertical, 8)
                    .background(.background.opacity(0.6), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                    .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(Color.secondary.opacity(0.25)))
                    .onSubmit { chat.send(posture: model.posture) }
                if chat.isSending {
                    Button { chat.cancel() } label: { Image(systemName: "stop.fill") }
                        .buttonStyle(GlowButtonStyle(tint: .secondary)).help("Stop")
                } else {
                    Button { chat.send(posture: model.posture) } label: { Image(systemName: "arrow.up") }
                        .buttonStyle(GlowButtonStyle())
                        .disabled(chat.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .keyboardShortcut(.return, modifiers: .command)
                        .help("Send (⌘↩)")
                }
            }
            Text("AI answers can be wrong. RamPart's own detections stay in charge, and the AI can't change anything on your Mac.")
                .font(.caption2).foregroundStyle(.tertiary)
        }
        .padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.m)
        .frame(maxWidth: 880 + 2 * Spacing.xl)
        .frame(maxWidth: .infinity)
        .background(.bar)
    }
}

// MARK: - Pieces

private struct SuggestionChip: View {
    let symbol: String, title: String, subtitle: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: symbol, size: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.callout.weight(.semibold)).foregroundStyle(.primary).multilineTextAlignment(.leading)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .card(padding: Spacing.m)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .hoverLift()
    }
}

private struct ThinkingRow: View {
    var body: some View {
        HStack(spacing: Spacing.s) {
            ProgressView().controlSize(.small)
            Text("Thinking…").font(.callout).foregroundStyle(.secondary)
        }
        .padding(.leading, 4)
        .accessibilityLabel("Waiting for the AI answer")
    }
}

private struct MessageRow: View {
    let message: AIChatModel.Message
    let reduceMotion: Bool

    var body: some View {
        if message.isUser {
            HStack {
                Spacer(minLength: 80)
                VStack(alignment: .trailing, spacing: 4) {
                    Text(verbatim: AIChatModel.mainText(message.payload))
                        .textSelection(.enabled)
                        .padding(.horizontal, 14).padding(.vertical, 9)
                        .background(LinearGradient(colors: [Color.rampartTeal.opacity(0.9), Color.rampartTeal.opacity(0.7)], startPoint: .top, endPoint: .bottom),
                                    in: RoundedRectangle(cornerRadius: 16, style: .continuous))
                        .foregroundStyle(.white)
                    if let s = message.sent { SentDisclosure(sent: s, redaction: message.redactionSummary, meta: nil) }
                }
            }
        } else {
            HStack(alignment: .top, spacing: Spacing.m) {
                IconBadge(symbol: isError ? "exclamationmark.bubble" : "sparkles", tint: isError ? .orange : .rampartTeal, size: 28)
                VStack(alignment: .leading, spacing: Spacing.s) {
                    if let t = message.title { Text(t).font(.headline).fontDesign(.rounded) }
                    content
                    if let s = message.sent { SentDisclosure(sent: s, redaction: message.redactionSummary, meta: message.meta) }
                }
                .card(padding: Spacing.m, tint: isError ? .orange : nil)
                Spacer(minLength: 40)
            }
        }
    }

    private var isError: Bool { if case .error = message.payload { return true }; return false }
    private var done: Bool { reduceMotion || message.revealed == .max }
    private func revealed(_ s: String) -> String { done ? s : String(s.prefix(message.revealed)) }

    @ViewBuilder private var content: some View {
        switch message.payload {
        case .text(let t), .error(let t):
            Text(verbatim: t).foregroundStyle(isError ? .secondary : .primary)
        case .reply(let r):
            body(revealed(r.answer))
            if done {
                if r.refused { Badge(text: "Declined: outside safe use", tint: .orange) }
                else if !r.onTopic { Badge(text: "Off topic", tint: .secondary) }
                steps(r.steps)
                if let acts = r.actions, !acts.isEmpty {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        ForEach(acts) { a in ActionCard(proposal: a) }
                    }
                    .padding(.top, 2)
                }
                if !r.relatedCheckIDs.isEmpty {
                    HStack { ForEach(r.relatedCheckIDs, id: \.self) { Badge(text: $0, tint: .rampartTeal) } }
                }
            }
        case .scam(let s):
            HStack(spacing: Spacing.s) {
                verdictBadge(scamVerdict(s.verdict))
                Text("\(s.score)/100 scam likelihood").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            }
            body(revealed(AIChatModel.mainText(message.payload)))
            if done { bullets(s.reasons); if !s.advice.isEmpty && !s.summary.isEmpty { body(s.advice) } }
        case .url(let u):
            verdictBadge(urlVerdict(u.verdict))
            body(revealed(u.summary))
            if done {
                ForEach(Array(u.reasons.enumerated()), id: \.offset) { _, r in
                    VStack(alignment: .leading, spacing: 2) {
                        Text(verbatim: r.signal).font(.callout.weight(.semibold))
                        Text(verbatim: r.explanation).font(.callout).foregroundStyle(.secondary)
                    }
                }
                if !u.advice.isEmpty { body(u.advice) }
            }
        case .detection(let d):
            HStack(spacing: Spacing.s) {
                Badge(text: "Risk: \(d.risk.rawValue.capitalized)", tint: riskTint(d.risk))
                Badge(text: "False-alarm chance: \(d.falsePositiveChance.rawValue)", tint: .secondary)
            }
            body(revealed(AIChatModel.mainText(message.payload)))
            if done { steps(d.nextSteps); if !d.reassurance.isEmpty { Label { Text(verbatim: d.reassurance) } icon: { Image(systemName: "checkmark.shield").foregroundStyle(.green) }.font(.callout) } }
        case .plan(let p):
            body(revealed(p.headline))
            if done {
                ForEach(p.items, id: \.checkID) { item in
                    HStack(alignment: .top, spacing: Spacing.s) {
                        Text("\(item.priority)").font(.caption.weight(.bold)).frame(width: 20, height: 20)
                            .background((item.priority == 1 ? Color.orange : item.priority == 2 ? .yellow : .blue).opacity(0.22), in: Circle())
                        VStack(alignment: .leading, spacing: 3) {
                            Text(verbatim: item.title).font(.callout.weight(.semibold))
                            if !item.why.isEmpty { Text(verbatim: item.why).font(.callout).foregroundStyle(.secondary) }
                            steps(item.steps)
                        }
                    }
                }
                if !p.alreadyGood.isEmpty {
                    Label { Text(verbatim: "Already good: " + p.alreadyGood.joined(separator: " · ")) } icon: { Image(systemName: "checkmark.circle.fill").foregroundStyle(.green) }
                        .font(.callout)
                }
            }
        }
    }

    private func body(_ s: String) -> some View { Text(verbatim: s).textSelection(.enabled).fixedSize(horizontal: false, vertical: true) }

    @ViewBuilder private func steps(_ s: [String]) -> some View {
        if !s.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                ForEach(Array(s.enumerated()), id: \.offset) { i, step in
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text("\(i + 1).").font(.callout.monospacedDigit()).foregroundStyle(Color.rampartTeal)
                        Text(verbatim: step).font(.callout).textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }
    private func bullets(_ s: [String]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            ForEach(Array(s.enumerated()), id: \.offset) { _, r in
                HStack(alignment: .firstTextBaseline, spacing: 6) { Text("•").foregroundStyle(.secondary); Text(verbatim: r).font(.callout) }
            }
        }
    }
    private func verdictBadge(_ v: (String, String, Color)) -> some View {
        Label(v.0, systemImage: v.1).font(.callout.weight(.semibold)).foregroundStyle(v.2)
            .padding(.horizontal, 9).padding(.vertical, 3).background(v.2.opacity(0.14), in: Capsule())
    }
    private func scamVerdict(_ v: AIScamAssessment.Verdict) -> (String, String, Color) {
        switch v {
        case .scam: return ("Likely a scam", "exclamationmark.triangle.fill", .orange)
        case .suspicious: return ("Suspicious", "exclamationmark.circle.fill", .yellow)
        case .safe: return ("Looks legitimate", "checkmark.seal.fill", .green)
        case .unclear: return ("Unclear", "questionmark.circle.fill", .secondary)
        }
    }
    private func urlVerdict(_ v: URLExplanation.Verdict) -> (String, String, Color) {
        switch v {
        case .dangerous: return ("Likely dangerous", "exclamationmark.triangle.fill", .orange)
        case .suspicious: return ("Suspicious", "exclamationmark.circle.fill", .yellow)
        case .probably_safe: return ("Probably safe", "checkmark.seal.fill", .green)
        case .unclear: return ("Unclear", "questionmark.circle.fill", .secondary)
        }
    }
    private func riskTint(_ r: DetectionExplanation.Risk) -> Color {
        switch r { case .high: return .orange; case .medium: return .yellow; case .low: return .green; case .unclear: return .secondary }
    }
}

/// Per-message "What was sent" disclosure.
private struct SentDisclosure: View {
    let sent: String
    let redaction: String?
    let meta: String?
    @StateVar private var open = false
    var body: some View {
        DisclosureGroup(isExpanded: $open) {
            VStack(alignment: .leading, spacing: 6) {
                if let redaction { Text("Removed before sending: \(redaction)").font(.caption).foregroundStyle(.secondary) }
                if let meta { Text(meta).font(.caption).foregroundStyle(.tertiary) }
                ScrollView {
                    Text(verbatim: sent).font(.caption.monospaced()).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                }
                .frame(maxHeight: 180)
                .padding(8)
                .background(Color.secondary.opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
        } label: {
            Label("What was sent", systemImage: "eye").font(.caption.weight(.medium)).foregroundStyle(.secondary)
        }
        .frame(maxWidth: 520, alignment: .leading)
    }
}

private struct KeySheet: View {
    let chat: AIChatModel
    @Binding var isPresented: Bool
    @StateVar private var key = ""
    @StateVar private var error: String?
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Label("Gemini API key", systemImage: "key.fill").font(.title3.weight(.semibold))
            Text("Stored only in your login Keychain and sent only to generativelanguage.googleapis.com. RamPart never shows, logs or saves it anywhere else.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            SecureField("Paste your key", text: $key).textFieldStyle(.roundedBorder)
            if let error { Text(error).font(.caption).foregroundStyle(.red) }
            HStack {
                Spacer()
                Button("Cancel") { key = ""; isPresented = false }.keyboardShortcut(.cancelAction)
                Button("Save") {
                    do { try chat.saveKey(key); key = ""; isPresented = false }
                    catch { self.error = (error as? GeminiKeyStore.KeyError)?.description ?? "Couldn't save the key." }
                }
                .keyboardShortcut(.defaultAction)
                .disabled(key.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
        .padding(Spacing.xl)
        .frame(width: 440)
    }
}


// MARK: - Chat list column

private struct ChatListColumn: View {
    @Bindable var chat: AIChatModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var renaming: ChatRecord?
    @StateVar private var renameText = ""
    @StateVar private var deleting: ChatRecord?

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Button { chat.newChat() } label: {
                Label("New Chat", systemImage: "square.and.pencil").frame(maxWidth: .infinity)
            }
            .buttonStyle(GlowButtonStyle())
            .accessibilityHint("Starts a new conversation. Shortcut Command N.")
            .padding(.horizontal, Spacing.m).padding(.top, Spacing.m)

            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                TextField("Search chats", text: $chat.search).textFieldStyle(.plain)
                if !chat.search.isEmpty {
                    Button { chat.search = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                        .buttonStyle(.plain).accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 6)
            .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            .padding(.horizontal, Spacing.m)

            let groups = chat.filteredGroups
            if groups.isEmpty {
                VStack(spacing: Spacing.s) {
                    Image(systemName: chat.search.isEmpty ? "bubble.left.and.bubble.right" : "magnifyingglass").font(.title2).foregroundStyle(.tertiary)
                    Text(chat.search.isEmpty ? "No chats yet" : "No matching chats").font(.callout).foregroundStyle(.secondary)
                    if !chat.keepHistory { Text("History is off: chats aren't saved.").font(.caption).foregroundStyle(.tertiary) }
                }
                .frame(maxWidth: .infinity, maxHeight: .infinity)
            } else {
                List(selection: Binding(get: { chat.currentID }, set: { chat.select($0) })) {
                    ForEach(groups, id: \.0) { group, items in
                        Section(group.rawValue) {
                            ForEach(items) { c in
                                ChatRow(chat: c, selected: c.id == chat.currentID)
                                    .tag(c.id)
                                    .contextMenu { menu(for: c) }
                            }
                        }
                    }
                }
                .listStyle(.sidebar)
                .scrollContentBackground(.hidden)
                .animation(reduceMotion ? nil : .easeOut(duration: 0.2), value: chat.chats.map(\.id))
                .onDeleteCommand { if let c = chat.current { deleting = c } }
                .accessibilityLabel("Chats")
            }
            if !chat.keepHistory && !chat.chats.isEmpty {
                Label("Not saved: history is off", systemImage: "clock.badge.xmark").font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, Spacing.m).padding(.bottom, Spacing.s)
            }
        }
        .background(.ultraThinMaterial.opacity(0.5))
        .alert("Rename Chat", isPresented: Binding(get: { renaming != nil }, set: { if !$0 { renaming = nil } })) {
            TextField("Title", text: $renameText)
            Button("Rename") { if let r = renaming { chat.rename(r.id, to: renameText) }; renaming = nil }
            Button("Cancel", role: .cancel) { renaming = nil }
        }
        .confirmationDialog("Delete “\(deleting?.title ?? "")”?", isPresented: Binding(get: { deleting != nil }, set: { if !$0 { deleting = nil } }), titleVisibility: .visible) {
            Button("Delete Chat", role: .destructive) { if let d = deleting { chat.delete(d.id) }; deleting = nil }
            Button("Cancel", role: .cancel) { deleting = nil }
        } message: { Text("This conversation is permanently removed from this Mac.") }
    }

    @ViewBuilder private func menu(for c: ChatRecord) -> some View {
        Button(c.pinned ? "Unpin" : "Pin") { chat.togglePin(c.id) }
        Button("Rename…") { renameText = c.title; renaming = c }
        Divider()
        Button("Delete…", role: .destructive) { deleting = c }
    }
}

private struct ChatRow: View {
    let chat: ChatRecord
    let selected: Bool
    private var symbol: String {
        switch chat.mode {
        case AIChatModel.Mode.scam.rawValue: return "envelope.badge.shield.half.filled"
        case AIChatModel.Mode.link.rawValue: return "link"
        default: return chat.title.hasPrefix("Explain:") ? "questionmark.bubble" : "bubble.left"
        }
    }
    var body: some View {
        HStack(spacing: Spacing.s) {
            Image(systemName: symbol).foregroundStyle(Color.rampartTeal).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) {
                Text(verbatim: chat.title).font(.callout.weight(selected ? .semibold : .regular)).lineLimit(1)
                Text(Fmt.dayTime(chat.updated)).font(.caption2).foregroundStyle(.secondary)
            }
            Spacer(minLength: 0)
            if chat.pinned { Image(systemName: "pin.fill").font(.caption2).foregroundStyle(.secondary).accessibilityHidden(true) }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(chat.title), \(chat.mode)\(chat.pinned ? ", pinned" : ""), \(Fmt.dayTime(chat.updated))")
        .accessibilityHint("Opens this conversation. Use the context menu to pin, rename or delete.")
    }
}


// MARK: - Proposed action card

/// A change the AI suggested. Nothing runs until the user presses Apply; protection-lowering changes are shown in
/// red and need a second confirmation.
private struct ActionCard: View {
    let proposal: AIProposedAction
    @Bindable private var chat = AIChatModel.shared
    @StateVar private var confirmLowering = false

    private var state: AIActionGate.State? { chat.actionStates[proposal.id] }
    private var tint: Color { proposal.lowersProtection ? .red : .rampartTeal }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: Spacing.s) {
                Image(systemName: proposal.lowersProtection ? "exclamationmark.shield.fill" : "wand.and.stars")
                    .foregroundStyle(tint).symbolRenderingMode(.hierarchical)
                Text(verbatim: proposal.title).font(.callout.weight(.semibold))
                Spacer(minLength: 0)
                statusBadge
            }
            if !proposal.reason.isEmpty { Text(verbatim: proposal.reason).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
            Text(verbatim: proposal.change).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled)
            if let w = proposal.action.warning {
                Label { Text(verbatim: w) } icon: { Image(systemName: "exclamationmark.triangle.fill") }
                    .font(.caption.weight(.medium)).foregroundStyle(.red)
            }
            if canAct {
                HStack(spacing: Spacing.s) {
                    Button(proposal.lowersProtection ? "Apply Anyway…" : "Apply") {
                        if proposal.lowersProtection { confirmLowering = true } else { chat.applyAction(proposal, confirmedLowering: false) }
                    }
                    .buttonStyle(GlowButtonStyle(tint: tint))
                    .accessibilityHint(proposal.lowersProtection ? "Lowers protection. Asks you to confirm." : "Makes this change now.")
                    if state == .pending { Button("Not now") { chat.dismissAction(proposal.id) }.buttonStyle(.borderless) }
                }
                .padding(.top, 2)
            }
        }
        .padding(Spacing.m)
        .background(tint.opacity(0.07), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(tint.opacity(proposal.lowersProtection ? 0.55 : 0.25)))
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Suggested change: \(proposal.title)\(proposal.lowersProtection ? ", lowers protection" : "")")
        .confirmationDialog("\(proposal.title)?", isPresented: $confirmLowering, titleVisibility: .visible) {
            Button(proposal.title, role: .destructive) { chat.applyAction(proposal, confirmedLowering: true) }
            Button("Keep Protection On", role: .cancel) {}
        } message: { Text(verbatim: (proposal.action.warning ?? "") + " You can change this back in Settings.") }
    }

    private var canAct: Bool {
        switch state {
        case .pending?, .failed?: return true
        default: return false
        }
    }

    @ViewBuilder private var statusBadge: some View {
        switch state {
        case .running?: ProgressView().controlSize(.small)
        case .done?: Badge(text: "Applied", tint: .green)
        case .dismissed?: Badge(text: "Not applied", tint: .secondary)
        case .failed?: Badge(text: "Failed", tint: .orange)
        case .pending?: EmptyView()
        case nil: Badge(text: "Expired: ask again", tint: .secondary)
        }
    }
}
