import Foundation
import Observation
import RampartShared
import RampartGuard

/// Shared lockdown state for the Emergency screen, the app-wide banner and the menu bar. Polls every 5 s while
/// something on screen observes it (start/stop), and runs the session-side lockdown steps once.
@MainActor
@Observable
final class EmergencyModel {
    static let shared = EmergencyModel()

    var status: EmergencyStatus?
    var unsupported = false
    var error: String?
    var busy = false
    var wifiMessage: String?
    var copied = false
    @ObservationIgnored private var poll: Timer?
    @ObservationIgnored private var observers = 0

    var active: Bool { status?.state.active ?? false }
    var escalated: Bool { status?.escalation != nil }

    func start() {
        observers += 1
        guard poll == nil else { return }
        Task { await refresh() }
        poll = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { _ in Task { @MainActor in await EmergencyModel.shared.refresh() } }
    }
    func stop() {
        observers = max(0, observers - 1)
        if observers == 0 { poll?.invalidate(); poll = nil }
    }

    private var client: DaemonClient { AppModel.shared.client }

    private func apply(_ o: EmergencyBridge.Outcome) async {
        switch o {
        case .status(let s):
            status = s; unsupported = false; error = nil
            let done = EmergencyAppActions.perform(s)
            if !done.isEmpty, case .status(let s2) = await EmergencyBridge.ack(client: client, ids: done) { status = s2 }
        case .unsupported: unsupported = true
        case .error(let e): error = e
        }
    }

    func refresh() async {
        guard AppModel.shared.mode == .live else { unsupported = AppModel.shared.mode != .demo; return }
        await apply(await EmergencyBridge.fetch(client: client))
    }

    func engage(note: String = "") async {
        busy = true; defer { busy = false }
        await apply(await EmergencyBridge.engage(client: client, note: note))
    }

    func rescan() async {
        busy = true; defer { busy = false }
        await apply(await EmergencyBridge.rescan(client: client))
    }

    /// Admin token flow, then lift. `force` = lift before every check passed (still needs the admin password).
    func lift(force: Bool) async {
        busy = true; defer { busy = false }
        switch await EmergencyBridge.adminToken(client: client) {
        case .failure(let why): error = why.message
        case .success(let token): await apply(await EmergencyBridge.lift(client: client, token: token, force: force))
        }
    }

    func turnWiFiOff() { wifiMessage = EmergencyAppActions.turnWiFiOff() ?? "Wi-Fi is off." }

    func copyReport() {
        guard let r = status?.report else { return }
        EmergencyAppActions.copy(r)
        copied = true
        Task { try? await Task.sleep(nanoseconds: 2_000_000_000); copied = false }
    }
}

/// Calm, honest copy in one place.
enum EmergencyCopy {
    static let intro = "If something dangerous is running, Emergency Lockdown isolates this Mac in seconds: it freezes the program, quarantines its files, cuts the network, locks your passwords and blocks remote access. Your own apps keep working."
    static let auto = "Turns on by itself only for confirmed, critical threats (known malware, ransomware, password theft, data being sent out, or attempts to switch \(Product.name) off). Never for notes, test files or things you've allowed."
    static let stays = "Lockdown stays on until the threat is gone: a fresh scan is clean, the file is quarantined, and nothing critical has happened for 2 minutes. It also stays on after a restart. You can always lift it with your administrator password."
    static let limits = "Without Apple's Endpoint Security entitlement \(Product.name) acts right after a program starts, not before. Network containment and process freezing need the installed system service; in other modes each step is recorded but not carried out."
}
