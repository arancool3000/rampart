import SwiftUI
import AppKit
import RampartShared
import RampartAI

/// Content of the floating panel: the pixel robot plus a small glass pill (chat, voice).
struct BotRootView: View {
    private var bot: BotController { BotController.shared }
    private var voice: BotVoice { BotVoice.shared }

    var body: some View {
        VStack(spacing: 4) {
            PixelBotView(state: bot.state, stateStarted: bot.stateStarted, cell: BotController.botCell, paused: bot.occluded)
                .contentShape(Rectangle())
                .onTapGesture { bot.toggleChat() }
                .gesture(DragGesture(minimumDistance: 3, coordinateSpace: .global)
                    .onChanged { _ in bot.dragChanged() }
                    .onEnded { _ in bot.dragEnded() })
                .help("Click to chat. Drag to move. Right-click for quick actions.")
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(Product.name) guard bot, \(bot.accessibilityStatus)")
                .accessibilityHint("Opens a chat with the assistant")
                .accessibilityAddTraits(.isButton)
                .accessibilityAction { bot.toggleChat() }
                .accessibilityAction(named: "Quick Scan") { bot.quickScan() }
                .accessibilityAction(named: "Open \(Product.name)") { bot.openApp() }
                .accessibilityAction(named: "Hide bot") { bot.setEnabled(false) }
            pill
        }
        .frame(width: BotController.panelSize.width, height: BotController.panelSize.height, alignment: .top)
        .contextMenu { BotQuickActions() }
    }

    private var pill: some View {
        HStack(spacing: 2) {
            Button { bot.openChat() } label: {
                Image(systemName: "square.and.pencil").frame(width: 30, height: 24)
            }
            .help("Chat with \(Product.name)")
            .accessibilityLabel("Chat")
            Divider().frame(height: 14)
            Button { bot.openChat(focus: false); voice.toggle() } label: {
                Image(systemName: voice.listening ? "waveform.circle.fill" : "waveform")
                    .symbolEffect(.variableColor.iterative, isActive: voice.listening)
                    .foregroundStyle(voice.listening ? Color.rampartTeal : Color.primary)
                    .frame(width: 30, height: 24)
            }
            .help(voice.listening ? "Stop listening" : "Talk to \(Product.name)")
            .accessibilityLabel(voice.listening ? "Stop listening" : "Voice")
        }
        .buttonStyle(.plain)
        .font(.system(size: 13, weight: .semibold))
        .padding(.horizontal, 6)
        .frame(height: BotController.pillHeight - 4)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(Color.primary.opacity(0.12)))
    }
}

/// Right-click menu on the bot.
struct BotQuickActions: View {
    private var bot: BotController { BotController.shared }
    var body: some View {
        Button("Chat…") { bot.openChat() }
        Divider()
        Button("Quick Scan") { bot.quickScan() }.disabled(AppModel.shared.isScanning)
        Button("Protect Everything") { bot.protectEverything() }
        Button("Super Kill Switch…") { bot.killSwitch() }
        Divider()
        Button("Open \(Product.name)") { bot.openApp() }
        Toggle("Mute Voice Replies", isOn: Binding(get: { bot.voiceMuted }, set: { bot.voiceMuted = $0 }))
        Button("Hide Bot") { bot.setEnabled(false) }
    }
}

/// Short event bubble next to the bot. Click-through (its panel ignores the mouse).
struct BotBubbleView: View {
    private var bot: BotController { BotController.shared }
    var body: some View {
        Text(verbatim: bot.bubble ?? "")
            .font(.system(size: 12, weight: .semibold, design: .rounded))
            .foregroundStyle(.primary)
            .lineLimit(3)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: 220, alignment: .leading)
            .padding(.horizontal, 10).padding(.vertical, 7)
            .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.primary.opacity(0.12)))
            .padding(4)
            .accessibilityHidden(true)   // announced through NSAccessibility instead
    }
}

/// Compact chat popover anchored to the bot. Same conversation, history and approval flow as the AI Assistant.
struct BotChatView: View {
    @Bindable private var chat = AIChatModel.shared
    private var bot: BotController { BotController.shared }
    private var voice: BotVoice { BotVoice.shared }
    @FocusState private var inputFocused: Bool

    var body: some View {
        VStack(spacing: 0) {
            header
            Divider()
            if !chat.enabled || chat.keyStatus != .present { setup } else { conversation }
        }
        .frame(width: 340, height: 440)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 16, style: .continuous))
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(Color.primary.opacity(0.12)))
        .onAppear { chat.refreshKey(); inputFocused = true }
    }

    private var header: some View {
        HStack(spacing: 8) {
            PixelGuardView(size: 26, expression: faceExpression, tile: true)
            VStack(alignment: .leading, spacing: 0) {
                Text("Ask \(Product.name)").font(.headline)
                Text(verbatim: statusLine).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button { bot.voiceMuted.toggle() } label: { Image(systemName: bot.voiceMuted ? "speaker.slash" : "speaker.wave.2") }
                .help(bot.voiceMuted ? "Unmute spoken replies" : "Mute spoken replies")
                .accessibilityLabel(bot.voiceMuted ? "Unmute spoken replies" : "Mute spoken replies")
            Button { bot.openApp(.aiAssistant); bot.closeChat() } label: { Image(systemName: "arrow.up.left.and.arrow.down.right") }
                .help("Open in \(Product.name)").accessibilityLabel("Open full assistant")
            Button { bot.closeChat() } label: { Image(systemName: "xmark") }
                .keyboardShortcut(.cancelAction)
                .help("Close").accessibilityLabel("Close chat")
        }
        .buttonStyle(.borderless)
        .padding(10)
    }

    private var faceExpression: PixelGuard.Expression {
        if voice.listening { return .listening }
        if chat.isSending { return .typing(0) }
        return .neutral
    }

    private var statusLine: String {
        if voice.listening { return "Listening… tap the waveform to send" }
        if chat.isSending { return "Thinking…" }
        return "Gemini · opt-in · asks before changing settings"
    }

    private var setup: some View {
        VStack(spacing: 12) {
            Spacer()
            PixelGuardView(size: 64, expression: .happy)
            Text("Chat with your guard").font(.headline)
            Text("The assistant uses Google Gemini and is off until you turn it on and add your own API key. Nothing is sent without you asking.")
                .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
            Button("Set Up Assistant…") { bot.openApp(.aiAssistant); bot.closeChat() }
                .buttonStyle(.borderedProminent)
            Spacer()
        }
        .padding(20)
    }

    private var conversation: some View {
        VStack(spacing: 0) {
            ScrollViewReader { proxy in
                ScrollView {
                    LazyVStack(alignment: .leading, spacing: 8) {
                        if chat.messages.isEmpty {
                            Text("Ask about your Mac's security, a scary pop-up, or a setting. I'll ask before changing anything.")
                                .font(.callout).foregroundStyle(.secondary).padding(.top, 8)
                        }
                        ForEach(chat.messages.suffix(40)) { m in BotMessageRow(message: m).id(m.id) }
                        if chat.isSending { TypingDots().id("typing") }
                        if let v = voice.notice { Text(verbatim: v).font(.caption).foregroundStyle(.secondary).id("voice") }
                    }
                    .padding(10)
                }
                .onChange(of: chat.messages.count) { _, _ in withAnimation { proxy.scrollTo(chat.messages.last?.id, anchor: .bottom) } }
                .onChange(of: chat.isSending) { _, s in if s { proxy.scrollTo("typing", anchor: .bottom) } }
            }
            Divider()
            HStack(spacing: 6) {
                TextField(voice.listening ? "Listening…" : chat.mode.placeholder, text: voice.listening ? .constant(voice.transcript) : $chat.draft, axis: .vertical)
                    .textFieldStyle(.plain)
                    .lineLimit(1...4)
                    .focused($inputFocused)
                    .onSubmit(sendDraft)
                    .disabled(voice.listening)
                    .accessibilityLabel("Message")
                Button { voice.toggle() } label: { Image(systemName: voice.listening ? "stop.circle.fill" : "waveform") }
                    .buttonStyle(.borderless)
                    .help(voice.listening ? "Stop and send" : "Push to talk")
                    .accessibilityLabel(voice.listening ? "Stop listening and send" : "Talk")
                if chat.isSending {
                    Button { chat.cancel() } label: { Image(systemName: "stop.fill") }.buttonStyle(.borderless).accessibilityLabel("Stop")
                } else {
                    Button(action: sendDraft) { Image(systemName: "arrow.up.circle.fill").font(.title3) }
                        .buttonStyle(.borderless)
                        .disabled(chat.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                        .keyboardShortcut(.defaultAction)
                        .accessibilityLabel("Send")
                }
            }
            .padding(10)
        }
    }

    private func sendDraft() {
        guard !chat.isSending, !chat.draft.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else { return }
        bot.replyBySpeech = false
        chat.send(posture: AppModel.shared.posture)
    }
}

/// One message in the compact chat (plain text; suggested setting changes get the same Apply / Not now approval).
private struct BotMessageRow: View {
    let message: AIChatModel.Message
    var body: some View {
        let full = AIChatModel.mainText(message.payload)
        let text = message.revealed < full.count ? String(full.prefix(message.revealed)) : full
        VStack(alignment: message.isUser ? .trailing : .leading, spacing: 6) {
            Text(verbatim: text.split(separator: "\n", omittingEmptySubsequences: false).map { SafeText.line(String($0), max: 2000) }.joined(separator: "\n"))
                .font(.callout)
                .textSelection(.enabled)
                .fixedSize(horizontal: false, vertical: true)
                .padding(.horizontal, 10).padding(.vertical, 7)
                .background(message.isUser ? Color.rampartTeal.opacity(0.22) : Color.primary.opacity(0.06),
                            in: RoundedRectangle(cornerRadius: 12, style: .continuous))
                .foregroundStyle(isError ? Color.orange : Color.primary)
            if case .reply(let r) = message.payload, let actions = r.actions {
                ForEach(actions) { BotActionRow(proposal: $0) }
            }
        }
        .frame(maxWidth: .infinity, alignment: message.isUser ? .trailing : .leading)
        .accessibilityElement(children: .combine)
        .accessibilityLabel((message.isUser ? "You: " : "\(Product.name): ") + full)
    }
    private var isError: Bool { if case .error = message.payload { return true }; return false }
}

/// Approval for an AI-suggested settings change. Lowering protection needs a second, explicit press.
private struct BotActionRow: View {
    let proposal: AIProposedAction
    @Bindable private var chat = AIChatModel.shared
    @StateVar private var confirm = false
    private var state: AIActionGate.State? { chat.actionStates[proposal.id] }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            Label { Text(verbatim: SafeText.line(proposal.title)) } icon: {
                Image(systemName: proposal.lowersProtection ? "exclamationmark.shield.fill" : "wand.and.stars")
            }
            .font(.callout.weight(.semibold))
            .foregroundStyle(proposal.lowersProtection ? Color.red : Color.primary)
            Text(verbatim: SafeText.line(proposal.change, max: 200)).font(.caption).foregroundStyle(.secondary)
            switch state {
            case .pending?, .failed?:
                HStack {
                    if confirm {
                        Button("Yes, lower protection") { chat.applyAction(proposal, confirmedLowering: true) }.tint(.red)
                        Button("Keep it on") { confirm = false }
                    } else {
                        Button(proposal.lowersProtection ? "Apply Anyway…" : "Apply") {
                            if proposal.lowersProtection { confirm = true } else { chat.applyAction(proposal, confirmedLowering: false) }
                        }
                        if state == .pending { Button("Not now") { chat.dismissAction(proposal.id) } }
                    }
                }
                .controlSize(.small)
                if case .failed(let why)? = state { Text(verbatim: SafeText.line(why, max: 160)).font(.caption).foregroundStyle(.orange) }
            case .running?: ProgressView().controlSize(.small)
            case .done?: Text("Applied").font(.caption.weight(.semibold)).foregroundStyle(.green)
            case .dismissed?: Text("Not applied").font(.caption).foregroundStyle(.secondary)
            case nil: Text("Expired: ask again").font(.caption).foregroundStyle(.secondary)
            }
        }
        .padding(8)
        .background((proposal.lowersProtection ? Color.red : Color.rampartTeal).opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }
}

/// Three pixel boxes lighting up in turn while the assistant types.
private struct TypingDots: View {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        TimelineView(.animation(minimumInterval: 1.0 / 8, paused: reduceMotion)) { tl in
            let k = Int(tl.date.timeIntervalSinceReferenceDate * 4) % 3
            HStack(spacing: 4) {
                ForEach(0..<3, id: \.self) { i in
                    RoundedRectangle(cornerRadius: 2).fill(PixelGuard.Palette.eye.swiftUI.opacity(reduceMotion || i == k ? 1 : 0.3)).frame(width: 7, height: 7)
                }
            }
            .padding(.horizontal, 10).padding(.vertical, 9)
            .background(Color.primary.opacity(0.06), in: RoundedRectangle(cornerRadius: 12, style: .continuous))
        }
        .accessibilityLabel("Thinking")
    }
}

/// Menu bar row: show or hide the floating bot.
struct BotMenuRow: View {
    private var bot: BotController { BotController.shared }
    var body: some View {
        MenuRowButton(title: bot.enabled ? "Hide Guard Bot" : "Show Guard Bot", shortcut: "") { bot.toggle() }
    }
}
