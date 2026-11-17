import Foundation
import Observation
import SwiftUI
import RampartShared
import RampartGuard

/// IPC needed from the lead (RampartShared.IPCRequest / IPCResponse). All carry JSON of RampartGuard.DeceptionStatus:
///   case deceptionStatus                                         -> .deception(Data)
///   case deceptionSetDecoys(on: Bool)                            -> .deception(Data)   // user peer OK (files in their home)
///   case deceptionSetMaze(on: Bool)                              -> .deception(Data)
///   case deceptionRemoveAll                                      -> .deception(Data)
///   case deceptionSetTarpit(on: Bool, port: UInt16, scope: String) -> .deception(Data)  // scope loopback|localSubnet|anywhere; non-loopback: admin peer only
///   case deceptionSetDecoysVisible(Bool)                          -> .deception(Data)
///   case deceptionSetTone(serious: Bool)                         -> .deception(Data)
///   case deceptionEvidence(catchID: UUID)                        -> .deceptionEvidence(Data) // JSON of DeceptionEvidence
/// "Study it in the sandbox" reuses the existing `.sandboxRun(id:confirmation:)` with the catch's quarantineID.
enum CatAndMouseBridge {
    enum Outcome { case status(DeceptionStatus), unsupported, error(String) }

    static func decode(_ data: Data) -> Outcome {
        do { return .status(try JSONDecoder.rampart.decode(DeceptionStatus.self, from: data)) }
        catch { return .error("Could not read the Cat & Mouse status: \(error.localizedDescription)") }
    }
    static func fetch(client: DaemonClient) async -> Outcome {
        if case .deception(let d)? = try? await client.request(.deceptionStatus) { return decode(d) }
        return .unsupported
    }
    static func setDecoys(client: DaemonClient, on: Bool) async -> Outcome {
        if case .deception(let d)? = try? await client.request(.deceptionSetDecoys(on: on)) { return decode(d) }
        return .unsupported
    }
    static func setMaze(client: DaemonClient, on: Bool) async -> Outcome {
        if case .deception(let d)? = try? await client.request(.deceptionSetMaze(on: on)) { return decode(d) }
        return .unsupported
    }
    static func removeAll(client: DaemonClient) async -> Outcome {
        if case .deception(let d)? = try? await client.request(.deceptionRemoveAll) { return decode(d) }
        return .unsupported
    }
    static func setTarpit(client: DaemonClient, on: Bool, port: UInt16, scope: LureScope) async -> Outcome {
        switch try? await client.request(.deceptionSetTarpit(on: on, port: port, scope: scope.rawValue)) {
        case .deception(let d)?: return decode(d)
        case .error(let e)?: return .error("Couldn't change the network lure: \(e)")
        default: return .unsupported
        }
    }
    /// Version-tolerant: a helper built before this request existed can't decode it and answers with an error (or
    /// drops the connection). That is reported as a plain message, not as "Cat & Mouse unsupported".
    static func setDecoysVisible(client: DaemonClient, visible: Bool) async -> Outcome {
        switch try? await client.request(.deceptionSetDecoysVisible(visible: visible)) {
        case .deception(let d)?: return decode(d)
        case .error(let e)?: return .error("Couldn't change decoy visibility: \(e)")
        default: return .error("This RamPart helper is too old to change decoy visibility. Update RamPart and try again.")
        }
    }
    static func setTone(client: DaemonClient, serious: Bool) async -> Outcome {
        if case .deception(let d)? = try? await client.request(.deceptionSetTone(serious: serious)) { return decode(d) }
        return .unsupported
    }
    static func evidence(client: DaemonClient, catchID: UUID) async -> DeceptionEvidence? {
        if case .deceptionEvidence(let d)? = try? await client.request(.deceptionEvidence(catchID: catchID)) {
            return try? JSONDecoder.rampart.decode(DeceptionEvidence.self, from: d) }
        return nil
    }
}

@MainActor
@Observable
final class CatAndMouseModel {
    static let shared = CatAndMouseModel()
    var status: DeceptionStatus?
    var unsupported = false
    var error: String?
    var busy = false
    var evidence: [UUID: DeceptionEvidence] = [:]

    var tone: DeceptionTone {
        status?.config.tone ?? (UserDefaults.standard.bool(forKey: "catMouse.serious") ? .serious : .playful)
    }
    var catches: [DeceptionCatch] { (status?.catches ?? []).sorted { $0.date > $1.date } }
    var realCatches: [DeceptionCatch] { catches.filter { !$0.userOpened } }
    /// Total maze dead ends hit across catches (drives the visual).
    var deadEnds: Int { status?.catches.map(\.mazeDeadEnds).max() ?? 0 }
    /// The maze shows "caught" after any real catch in the last 24 hours (or one that was contained).
    var caughtRecently: Bool { realCatches.contains { $0.contained || Date().timeIntervalSince($0.date) < 86_400 } }

    /// Cat & Mouse runs in the per-user session daemon (decoys live in the home folder). With the system service
    /// installed, the main client talks to root, so Cat & Mouse uses the session daemon's socket directly.
    private static let sessionClient = DaemonClient(paths: [IPC.userSocketPath])
    private var client: DaemonClient { AppModel.shared.health?.mode == "root" ? Self.sessionClient : AppModel.shared.client }

    private func apply(_ o: CatAndMouseBridge.Outcome) {
        switch o {
        case .status(let s): status = s; unsupported = false; error = nil; postNewCatches(s)
        case .unsupported: unsupported = true
        case .error(let e): error = e
        }
    }

    func refresh() async { apply(await CatAndMouseBridge.fetch(client: client)) }
    /// Background check (AppModel's periodic tick): new catches notify even when this screen isn't open.
    /// Quiet when the helper doesn't run Cat & Mouse.
    func backgroundPoll() async {
        let o = await CatAndMouseBridge.fetch(client: client)
        if case .status = o { apply(o) }
    }
    func setDecoys(_ on: Bool) async { busy = true; apply(await CatAndMouseBridge.setDecoys(client: client, on: on)); busy = false }
    func setMaze(_ on: Bool) async { busy = true; apply(await CatAndMouseBridge.setMaze(client: client, on: on)); busy = false }
    func removeAll() async { busy = true; apply(await CatAndMouseBridge.removeAll(client: client)); busy = false }
    func setTarpit(_ on: Bool, scope: LureScope? = nil) async {
        busy = true
        apply(await CatAndMouseBridge.setTarpit(client: client, on: on, port: status?.config.tarpitPort ?? 2222, scope: scope ?? .loopback))   // other scopes: coming soon (root daemon)
        busy = false
    }
    func setDecoysVisible(_ v: Bool) async { busy = true; apply(await CatAndMouseBridge.setDecoysVisible(client: client, visible: v)); busy = false }
    func setTone(_ t: DeceptionTone) async {
        UserDefaults.standard.set(t == .serious, forKey: "catMouse.serious")
        apply(await CatAndMouseBridge.setTone(client: client, serious: t == .serious))
    }
    func loadEvidence(_ c: DeceptionCatch) async {
        if let e = await CatAndMouseBridge.evidence(client: client, catchID: c.id) { evidence[c.id] = e }
    }

    /// Cat & Mouse notifications come from the service as `CatMouseAlert`s (pushed on the event stream and kept in
    /// the status). Each alert id is posted once; alerts missed while the app wasn't running are posted when it
    /// starts (up to 15 minutes old). The notification identifier groups a burst into one notification.
    @ObservationIgnored private var postedAlerts: Set<UUID> = []
    private var lastAlertDate: Date {
        get { UserDefaults.standard.object(forKey: "catMouse.lastAlertDate") as? Date ?? .distantPast }
        set { UserDefaults.standard.set(newValue, forKey: "catMouse.lastAlertDate") }
    }
    var notificationsDenied = false

    func receiveAlert(_ data: Data) {
        guard let a = try? JSONDecoder.rampart.decode(CatMouseAlert.self, from: data) else { return }
        post([a])
        Task { await refresh() }   // the screen (if open) shows the catch at once
    }

    private func postNewCatches(_ s: DeceptionStatus) {
        post(s.alerts ?? [])
        askForNotificationsOnce(s)
    }

    private func post(_ alerts: [CatMouseAlert]) {
        let cutoff = max(lastAlertDate, Date().addingTimeInterval(-900))
        for a in alerts where !postedAlerts.contains(a.id) && a.date > cutoff {
            postedAlerts.insert(a.id)
            Notifier.shared.catMouse(a)
            if a.date > lastAlertDate { lastAlertDate = a.date }
        }
    }

    /// The first time Cat & Mouse is on, ask macOS once for notification permission (never in headless/dev runs).
    private func askForNotificationsOnce(_ s: DeceptionStatus) {
        let on = s.config.decoysEnabled || s.config.mazeEnabled || s.config.tarpitEnabled
        Task {
            let st = await Notifier.shared.authorizationStatus()
            notificationsDenied = on && st == .denied
            guard on, st == .notDetermined, !Headless.active, !UserDefaults.standard.bool(forKey: "catMouse.notifAsked") else { return }
            UserDefaults.standard.set(true, forKey: "catMouse.notifAsked")
            _ = await Notifier.shared.requestAuthorization()
            notificationsDenied = await Notifier.shared.authorizationStatus() == .denied
        }
    }

    func turnOnNotifications() async {
        _ = await Notifier.shared.allowOrOpenSettings()
        notificationsDenied = await Notifier.shared.authorizationStatus() == .denied
    }

    func contain(catchID: UUID) async {
        switch try? await client.request(.deceptionContain(catchID: catchID)) {
        case .deception(let d)?: apply(CatAndMouseBridge.decode(d))
        case .error(let e)?: error = "Couldn't contain it: \(e)"
        default: error = "This RamPart helper can't contain programs from Cat & Mouse yet."
        }
    }

    // Copy shown on the screen, in both tones.
    func headline() -> String {
        let n = realCatches.count
        switch tone {
        case .playful: return n == 0 ? "The cat is waiting. No mice yet." : "The cat has caught \(n) mouse\(n == 1 ? "" : "s")."
        case .serious: return n == 0 ? "No decoy access recorded." : "\(n) decoy access event\(n == 1 ? "" : "s") recorded."
        }
    }
}
