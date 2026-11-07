import Foundation
import AppKit
import RampartShared
import RampartBehaviour
import RampartAI

/// Adapts the AI service's paste analyzer to PasteGuard's assessor protocol.
struct GeminiPasteAssessor: PasteAIAssessor {
    let analyzer: PasteCommandAnalyzer
    func assess(command: String, decoded: [String], sourceApp: String?) async -> PasteAIVerdict? {
        guard let r = await analyzer.assess(command: command, decoded: decoded, sourceApp: sourceApp),
              let label = PasteAIVerdict.Label(rawValue: r.labelRaw) else { return nil }
        return PasteAIVerdict(label: label, confidence: r.confidence, reasons: r.reasons)
    }
}

/// Runs PasteGuard in the user session (the app process), forwards its events to the daemon in small
/// batches, and publishes its status for the permissions screen. Never runs in headless/test runs
/// (ZERO POP-UPS RULE: no pasteboard access during development).
@MainActor
final class PasteGuardHost {
    static let shared = PasteGuardHost()
    private var guardian: PasteGuard?
    private var pending: [SecurityEvent] = []
    private var flushScheduled = false

    /// hx8: the clipboard is read only in a real, interactive session: never in headless/test runs, never with
    /// RAMPART_NO_PRIVILEGED_TOOLS=1, and not when the user switched PasteGuard off ("pasteGuard.enabled").
    /// PasteGuard itself honours macOS's "Paste from Other Apps" setting and skips concealed/password types.
    static var allowed: Bool {
        !Headless.active && ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] != "1"
            && (UserDefaults.standard.object(forKey: "pasteGuard.enabled") as? Bool ?? true)
    }

    func start() {
        guard Self.allowed, guardian == nil else { return }
        let g = PasteGuard(ai: GeminiPasteAssessor(analyzer: PasteCommandAnalyzer(service: AIChatModel.shared.service)))
        g.onStatusChange = { s in
            Task { @MainActor in PasteGuardStatusBox.shared.status = PasteGuardHost.map(s) }
        }
        g.onEvent = { ev in
            Task { @MainActor in PasteGuardHost.shared.enqueue(ev) }
        }
        g.onDetection = { d in
            Task { @MainActor in AppModel.shared.receivePasteGuard(d) }
        }
        guardian = g
        g.start()
        PasteGuardStatusBox.shared.status = Self.map(g.refreshStatus())
    }

    func refreshStatus() {
        guard let g = guardian else { return }
        PasteGuardStatusBox.shared.status = Self.map(g.refreshStatus())
    }

    func stop() { guardian?.stop(); guardian = nil }

    /// hx8: bounded so a flood of clipboard changes can't grow memory while the daemon is away.
    static let maxPending = 200

    private func enqueue(_ ev: SecurityEvent) {
        pending.append(ev)
        if pending.count > Self.maxPending { pending.removeFirst(pending.count - Self.maxPending) }
        guard !flushScheduled else { return }
        flushScheduled = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
            Task { @MainActor in await PasteGuardHost.shared.flush() }
        }
    }

    private func flush() async {
        flushScheduled = false
        let batch = pending; pending = []
        guard !batch.isEmpty, AppModel.shared.mode == .live else { return }
        _ = try? await AppModel.shared.client.request(.forwardEvents(batch))
    }

    static func map(_ s: PasteGuardStatus) -> PasteGuardStatusBox.Status {
        switch s {
        case .active: return .active
        case .needsPermission: return .needsPermission
        case .denied: return .denied
        case .stopped: return .stopped
        }
    }
}
