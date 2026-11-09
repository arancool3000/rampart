import SwiftUI
import AppKit
import Observation
import RampartShared
import RampartNetwork

/// The floating Pixel Guard: a small always-on-top, borderless, draggable panel that never takes focus.
/// It snaps to screen edges, remembers where it was, and can be hidden from its own menu, the menu bar or Settings.
/// Events (scan done, threat, Cat & Mouse catch, lockdown, Wi-Fi) come from the existing app models; the chat
/// popover reuses the AI Assistant (Gemini, opt-in) with its history and approval flow.
@MainActor
@Observable
final class BotController {
    static let shared = BotController()

    static let enabledKey = "bot.enabled"
    static let mutedKey = "bot.voiceMuted"
    private static let originKey = "bot.origin"

    private(set) var machine = BotStateMachine()
    private(set) var stateStarted = Date()
    private(set) var bubble: String?
    var chatOpen = false
    var hovering = false
    private(set) var occluded = false
    var state: BotState { machine.state }

    var enabled: Bool {
        get { access(keyPath: \.enabled); return UserDefaults.standard.object(forKey: Self.enabledKey) as? Bool ?? true }
        set { withMutation(keyPath: \.enabled) { UserDefaults.standard.set(newValue, forKey: Self.enabledKey) }; applyEnabled() }
    }
    var voiceMuted: Bool {
        get { access(keyPath: \.voiceMuted); return UserDefaults.standard.bool(forKey: Self.mutedKey) }
        set { withMutation(keyPath: \.voiceMuted) { UserDefaults.standard.set(newValue, forKey: Self.mutedKey) }; if newValue { BotVoice.shared.stopSpeaking() } }
    }

    @ObservationIgnored private var panel: BotPanel?
    @ObservationIgnored private var bubblePanel: NSPanel?
    @ObservationIgnored private var chatPanel: BotChatPanel?
    @ObservationIgnored private var sampler: Timer?
    @ObservationIgnored private var transient: DispatchWorkItem?
    @ObservationIgnored private var bubbleHide: DispatchWorkItem?
    @ObservationIgnored private var snapshot: Snapshot?
    @ObservationIgnored private var started = false
    @ObservationIgnored private var dragStart: (mouse: NSPoint, origin: NSPoint)?
    @ObservationIgnored private var wasSending = false
    @ObservationIgnored var replyBySpeech = false

    static let botCell: CGFloat = 4
    static var botSize: CGSize { PixelBotView.size(cell: botCell) }
    static let pillHeight: CGFloat = 30
    static var panelSize: CGSize { CGSize(width: max(botSize.width, 92), height: botSize.height + pillHeight + 4) }

    // MARK: Lifecycle

    func start() {
        guard !Headless.active, !started else { return }
        started = true
        NotificationCenter.default.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { BotController.shared.reclamp() }
        }
        sampler = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            MainActor.assumeIsolated { BotController.shared.tick() }
        }
        tick()
    }

    func setEnabled(_ on: Bool) { enabled = on }
    func toggle() { enabled.toggle() }

    /// First launch: the bot waits until onboarding is done, then appears (on by default).
    private var mayShow: Bool { enabled && UserDefaults.standard.bool(forKey: "onboarding.done") }

    private func applyEnabled() {
        if mayShow { show() } else { hide() }
    }

    private func show() {
        if panel == nil { makePanel() }
        guard let panel, !panel.isVisible else { return }
        machine = BotStateMachine()
        setState(.assembling)
        panel.orderFrontRegardless()     // never makeKey: the bot doesn't take focus
        let assembly = NSWorkspace.shared.accessibilityDisplayShouldReduceMotion ? 0.05 : 1.45
        DispatchQueue.main.asyncAfter(deadline: .now() + assembly) { [weak self] in self?.send(.assembled) }
    }

    private func hide() {
        closeChat()
        panel?.orderOut(nil)
        bubblePanel?.orderOut(nil)
    }

    private func makePanel() {
        let size = Self.panelSize
        let p = BotPanel(contentRect: NSRect(origin: initialOrigin(size), size: size),
                         styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
        p.isFloatingPanel = true
        p.level = .floating
        p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
        p.hidesOnDeactivate = false
        p.isOpaque = false
        p.backgroundColor = .clear
        p.hasShadow = false
        p.becomesKeyOnlyIfNeeded = true
        p.isReleasedWhenClosed = false
        p.setAccessibilityLabel("\(Product.name) guard bot")
        let host = BotHostingView(rootView: BotRootView())
        host.frame = NSRect(origin: .zero, size: size)
        p.contentView = host
        NotificationCenter.default.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: p, queue: .main) { _ in
            MainActor.assumeIsolated {
                let c = BotController.shared
                c.occluded = !(c.panel?.occlusionState.contains(.visible) ?? false)
            }
        }
        panel = p
    }

    // MARK: Position

    private func initialOrigin(_ size: CGSize) -> NSPoint {
        if let a = UserDefaults.standard.array(forKey: Self.originKey) as? [Double], a.count == 2 {
            let o = NSPoint(x: a[0], y: a[1])
            let frame = NSRect(origin: o, size: size)
            if let screen = NSScreen.screens.first(where: { $0.visibleFrame.intersects(frame) }) {
                return BotGeometry.snapped(frame, in: screen.visibleFrame, threshold: 0)
            }
        }
        let vis = (NSScreen.main ?? NSScreen.screens.first)?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1440, height: 900)
        return BotGeometry.defaultOrigin(size: size, in: vis)
    }

    func dragChanged() {
        guard let panel else { return }
        let mouse = NSEvent.mouseLocation
        if dragStart == nil { dragStart = (mouse, panel.frame.origin); bubblePanel?.orderOut(nil); closeChat() }
        guard let s = dragStart else { return }
        panel.setFrameOrigin(NSPoint(x: s.origin.x + mouse.x - s.mouse.x, y: s.origin.y + mouse.y - s.mouse.y))
    }

    func dragEnded() {
        dragStart = nil
        guard let panel else { return }
        let screen = NSScreen.screens.first(where: { $0.frame.contains(NSEvent.mouseLocation) }) ?? panel.screen ?? NSScreen.main
        guard let vis = screen?.visibleFrame else { return }
        let o = BotGeometry.snapped(panel.frame, in: vis)
        panel.setFrame(NSRect(origin: o, size: panel.frame.size), display: true, animate: !NSWorkspace.shared.accessibilityDisplayShouldReduceMotion)
        UserDefaults.standard.set([Double(o.x), Double(o.y)], forKey: Self.originKey)
    }

    private func reclamp() {
        guard let panel else { return }
        let vis = (panel.screen ?? NSScreen.main)?.visibleFrame ?? panel.frame
        panel.setFrameOrigin(BotGeometry.snapped(panel.frame, in: vis, threshold: 0))
    }

    // MARK: State + bubbles

    func send(_ e: BotEvent) {
        let before = machine.state
        machine.handle(e)
        if machine.state != before { setState(machine.state) }
    }

    private func setState(_ s: BotState) {
        stateStarted = Date()
        transient?.cancel()
        if let d = BotStateMachine.duration(s), !(s == .alert && machine.base == .alert) {
            let w = DispatchWorkItem { [weak self] in self?.send(.transientElapsed) }
            transient = w
            DispatchQueue.main.asyncAfter(deadline: .now() + d, execute: w)
        }
    }

    func say(_ text: String) {
        let t = BotBubble.sanitize(text)
        guard !t.isEmpty, panel?.isVisible == true else { return }
        bubble = t
        showBubblePanel()
        NSAccessibility.post(element: NSApp as Any, notification: .announcementRequested,
                             userInfo: [.announcement: t, .priority: NSAccessibilityPriorityLevel.medium.rawValue])
        bubbleHide?.cancel()
        let w = DispatchWorkItem { [weak self] in self?.bubble = nil; self?.bubblePanel?.orderOut(nil) }
        bubbleHide = w
        DispatchQueue.main.asyncAfter(deadline: .now() + 5, execute: w)
    }

    private func showBubblePanel() {
        guard let panel, !chatOpen else { return }
        if bubblePanel == nil {
            let b = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 220, height: 60), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
            b.level = .floating
            b.isOpaque = false; b.backgroundColor = .clear; b.hasShadow = false
            b.ignoresMouseEvents = true       // never intercepts clicks
            b.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
            b.isReleasedWhenClosed = false
            b.contentView = NSHostingView(rootView: BotBubbleView())
            bubblePanel = b
        }
        guard let b = bubblePanel, let vis = (panel.screen ?? NSScreen.main)?.visibleFrame else { return }
        let fit = b.contentView?.fittingSize ?? NSSize(width: 200, height: 44)
        let size = NSSize(width: min(240, max(80, fit.width)), height: fit.height)
        let left = BotGeometry.opensLeft(panel.frame, in: vis)
        var o = NSPoint(x: left ? panel.frame.minX - size.width + 18 : panel.frame.maxX - 18, y: panel.frame.maxY - 30)
        o.x = min(max(o.x, vis.minX + 4), vis.maxX - size.width - 4)
        o.y = min(max(o.y, vis.minY + 4), vis.maxY - size.height - 4)
        b.setFrame(NSRect(origin: o, size: size), display: true)
        b.orderFrontRegardless()
    }

    // MARK: Chat popover

    func toggleChat() { chatOpen ? closeChat() : openChat() }

    func openChat(focus: Bool = true) {
        guard let panel, let vis = (panel.screen ?? NSScreen.main)?.visibleFrame else { return }
        bubblePanel?.orderOut(nil)
        if chatPanel == nil {
            let c = BotChatPanel(contentRect: NSRect(x: 0, y: 0, width: 340, height: 440), styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: true)
            c.level = .floating
            c.isOpaque = false; c.backgroundColor = .clear; c.hasShadow = true
            c.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary, .ignoresCycle]
            c.hidesOnDeactivate = false
            c.isReleasedWhenClosed = false
            c.contentView = NSHostingView(rootView: BotChatView())
            chatPanel = c
        }
        guard let c = chatPanel else { return }
        let size = NSSize(width: 340, height: 440)
        let left = BotGeometry.opensLeft(panel.frame, in: vis)
        var o = NSPoint(x: left ? panel.frame.minX - size.width - 6 : panel.frame.maxX + 6, y: panel.frame.minY)
        o.x = min(max(o.x, vis.minX + 4), vis.maxX - size.width - 4)
        o.y = min(max(o.y, vis.minY + 4), vis.maxY - size.height - 4)
        c.setFrame(NSRect(origin: o, size: size), display: true)
        chatOpen = true
        // Typing needs the key window. The panel is non-activating, so the frontmost app keeps its activation;
        // this happens only because the user clicked the bot.
        if focus { c.makeKeyAndOrderFront(nil) } else { c.orderFrontRegardless() }
    }

    func closeChat() {
        guard chatOpen else { return }
        chatOpen = false
        chatPanel?.orderOut(nil)
        if BotVoice.shared.listening { BotVoice.shared.stop(send: false) }
        send(.chatEnded)
    }

    // MARK: Quick actions

    func quickScan() {
        guard !AppModel.shared.isScanning else { say("A scan is already running."); return }
        AppModel.shared.startScan(.quick)
        say("Quick Scan started.")
    }
    func protectEverything() { Task { await ProtectEverythingModel.shared.turnOn() }; say("Turning every protection on…") }
    func killSwitch() { Task { await EmergencyModel.shared.killSwitch() } }   // Touch ID / password inside
    func openApp(_ item: SidebarItem? = nil) {
        if let item { AppModel.shared.selection = item }
        AppDelegate.revealMainWindow()
    }

    // MARK: Event sampling (1 Hz, cheap reads of existing models)

    private struct Snapshot {
        var scanning: Bool
        var finishedAt: Date?
        var needsYou: Int
        var latestCatch: UUID?
        var lockdown: Bool
        var wifiKey: String?
        var paused: Bool
    }

    private func tick() {
        if mayShow != (panel?.isVisible ?? false) { applyEnabled() }
        guard panel?.isVisible == true else { return }
        let app = AppModel.shared
        var finishedAt: Date?, found = 0
        if case .finished(let r, let d) = app.scanPhase { finishedAt = r.date; found = d.count }
        let cm = CatAndMouseModel.shared.realCatches.first
        let wifi = PublicWiFiHost.shared.latest
        let wifiRisk = wifi.flatMap { a -> String? in
            (a.decision != .none && !a.trusted) || a.arpSpoofing || a.dnsHijack ? a.networkKey : nil
        }
        let now = Snapshot(scanning: app.isScanning, finishedAt: finishedAt, needsYou: app.needsYouCount,
                           latestCatch: cm?.id, lockdown: EmergencyModel.shared.active || ChromeState.shared.lockdownBadge != nil,
                           wifiKey: wifiRisk, paused: app.pausedUntil != nil)
        defer { snapshot = now; trackChat() }
        guard let old = snapshot else {
            // First look: adopt the current situation quietly (no bubbles for old news).
            if now.needsYou > 0 { send(.threatFound) }
            if now.lockdown { send(.lockdownOn) }
            if now.paused { send(.protectionPaused) }
            if now.scanning { send(.scanStarted) }
            return
        }
        if now.scanning && !old.scanning { send(.scanStarted) }
        if let f = now.finishedAt, f != old.finishedAt {
            send(.scanFinished(threats: found)); say(BotBubble.scanDone(threats: found))
        } else if !now.scanning && old.scanning && now.finishedAt == old.finishedAt {
            send(.scanFinished(threats: 0))
        }
        if now.needsYou > old.needsYou {
            send(.threatFound); say(BotBubble.threat(app.openDetections.first?.name))
        } else if now.needsYou == 0 && old.needsYou > 0 { send(.threatsCleared) }
        if let c = now.latestCatch, c != old.latestCatch {
            send(.catCaught); say(BotBubble.catCaught(cm?.processName))
        }
        if now.lockdown != old.lockdown { send(now.lockdown ? .lockdownOn : .lockdownOff); say(BotBubble.lockdown(now.lockdown)) }
        if let k = now.wifiKey, k != old.wifiKey { send(.wifiWarning); say(BotBubble.wifi(wifi?.ssid)) }
        if now.paused != old.paused { send(now.paused ? .protectionPaused : .protectionResumed); say(now.paused ? BotBubble.paused : BotBubble.resumed) }
    }

    /// Mirrors the AI chat: thinking face while a request runs, a talking face when the answer lands.
    func trackChat() {
        let sending = AIChatModel.shared.isSending
        defer { wasSending = sending }
        if sending && !wasSending { send(.chatThinking) }
        if !sending && wasSending {
            send(.chatAnswered)
            if !chatOpen { say(BotBubble.answerReady) }
            if replyBySpeech, !voiceMuted, let last = AIChatModel.shared.messages.last, !last.isUser {
                BotVoice.shared.speak(AIChatModel.mainText(last.payload))
            }
            replyBySpeech = false
        }
    }

    var accessibilityStatus: String {
        switch state {
        case .assembling, .idle: return "on guard"
        case .scanning: return "scanning"
        case .alert: return "needs your attention"
        case .celebrating: return "caught something"
        case .sleeping: return "protection paused"
        case .happy: return "all clear"
        case .thinking: return "thinking"
        case .talking: return "answering"
        case .listening: return "listening"
        }
    }
}

/// Borderless, non-activating, can't be made main. Becomes key only if a control truly needs it.
final class BotPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// The chat popover window: key (for typing) but never main, and Esc closes it.
final class BotChatPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
    override func cancelOperation(_ sender: Any?) { MainActor.assumeIsolated { BotController.shared.closeChat() } }
}

/// Clicks work on the first press even though the panel isn't key or active.
final class BotHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}
