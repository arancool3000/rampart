import Foundation
import RampartShared
import RampartAI

/// Runs AI-proposed actions that the user approved, through AppModel and the daemon IPC only.
/// Reached exclusively via `AIActionGate.approve`, which is only called from an Apply button.
struct AppActionExecutor: AIActionExecutor {
    struct Failure: Error, CustomStringConvertible { let description: String }

    func execute(_ action: AIAction) async throws -> String {
        try await MainActor.run { () -> Task<String, Error> in
            Task { @MainActor in try await Self.run(action) }
        }.value
    }

    @MainActor static func run(_ action: AIAction) async throws -> String {
        let model = AppModel.shared
        let offline = Failure(description: "RamPart's protection service isn't connected, so this can't be changed right now.")
        model.lastError = nil
        // Protection Activity: whatever this changes is shown as "by the AI assistant, approved by you".
        model.activityActorOverride = .ai
        defer { model.activityActorOverride = nil }
        model.noteActivityActor()
        // wms-o5: a protection-lowering suggestion needs, besides the second click, a fresh administrator
        // authentication verified by the service (requestDisableProtection -> a 10-minute settings session).
        // Injected text can at most put a red card on screen; it can never lower protection without the admin.
        if action.lowersProtection {
            guard model.mode == .live else { throw offline }
            try await Self.adminConfirm(model.client, title: action.title)
        }
        switch action {
        case .setToggle(.realtimeOn, let on):
            guard model.mode == .live else { throw offline }
            model.setRealtime(on)
        case .setToggle(.webProtection, let on):
            guard model.mode == .live else { throw offline }
            await model.setWebProtection(on)
        case .setToggle, .setScanHour, .addExclusion, .removeExclusion:
            guard model.mode == .live else { throw offline }
            // Read-modify-write against the daemon's current settings (single source of truth).
            guard case .settings(let current) = try await model.client.request(.getSettings) else { throw Failure(description: "Couldn't read the current settings.") }
            guard let next = AIActionValidator.applying(action, to: current) else { throw Failure(description: "Not a settings change.") }
            // wms-o5: an action not flagged as lowering may never produce a weakening write.
            if !action.lowersProtection && AIActionValidator.settingsWeaken(old: current, new: next) {
                throw Failure(description: "This change would lower your protection, so it wasn't applied.")
            }
            let resp = try await model.client.request(.setSettings(next))
            switch resp {
            case .settings(let confirmed): model.settings = confirmed
            case .ok: model.settings = next
            case .error(let e): throw Failure(description: e)
            default: break
            }
        case .fixPosture(let id):
            guard model.mode == .live else { throw offline }
            guard let c = model.posture.first(where: { $0.id == id }) else { throw Failure(description: "That check isn't in your current Security Score.") }
            await model.fix(c)
        case .quickScan:
            model.startScan(.quick)
        case .remoteLockdown(let on):
            guard model.mode == .live else { throw offline }
            model.noteActivityActor(events: [.remoteLockdownChanged])
            if case .error(let e) = try await model.client.request(.setRemoteLockdown(on: on), timeout: 30) { throw Failure(description: e) }
        case .updateDefinitions:
            await model.updateDefinitions()
        }
        if let e = model.lastError { throw Failure(description: e) }
        return action.doneText
    }

    /// Fresh admin prompt (Touch ID or password) -> service-issued token -> settings session. Throws if any step fails.
    @MainActor static func adminConfirm(_ client: DaemonClient, title: String) async throws {
        let purpose = "apply the AI assistant's suggestion: \(SafeText.line(title, max: 80))"
        let o = await EmergencyBridge.withAdminToken(client: client, purpose: purpose) { token in
            do {
                switch try await client.request(.disableProtection(token: token, minutes: 0)) {
                case .ok: return .unsupported          // "no status to show": success for this caller
                case .error(let e): return .error(e)
                default: return .error("Unexpected reply from the protection service.")
                }
            } catch { return .error(error.localizedDescription) }
        }
        if case .error(let e) = o { throw Failure(description: "Administrator confirmation didn't complete: \(e)") }
        if case .status = o { throw Failure(description: "Administrator confirmation didn't complete.") }
    }
}
