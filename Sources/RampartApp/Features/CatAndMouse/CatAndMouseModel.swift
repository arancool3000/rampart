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
        if case .deception(let d)? = try? await client.request(.deceptionSetTarpit(on: on, port: port, scope: scope.rawValue)) { return decode(d) }
        return .unsupported
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
    @ObservationIgnored private var notified: Set<UUID> = []
    @ObservationIgnored private var primed = false

    var tone: DeceptionTone {
        status?.config.tone ?? (UserDefaults.standard.bool(forKey: "catMouse.serious") ? .serious : .playful)
    }
    var catches: [DeceptionCatch] { (status?.catches ?? []).sorted { $0.date > $1.date } }
    var realCatches: [DeceptionCatch] { catches.filter { !$0.userOpened } }
    /// Total maze dead ends hit across catches (drives the visual).
    var deadEnds: Int { status?.catches.map(\.mazeDeadEnds).max() ?? 0 }

    private var client: DaemonClient { AppModel.shared.client }

    private func apply(_ o: CatAndMouseBridge.Outcome) {
        switch o {
        case .status(let s): status = s; unsupported = false; error = nil; postNewCatches(s)
        case .unsupported: unsupported = true
        case .error(let e): error = e
        }
    }

    func refresh() async { apply(await CatAndMouseBridge.fetch(client: client)) }
    func setDecoys(_ on: Bool) async { busy = true; apply(await CatAndMouseBridge.setDecoys(client: client, on: on)); busy = false }
    func setMaze(_ on: Bool) async { busy = true; apply(await CatAndMouseBridge.setMaze(client: client, on: on)); busy = false }
    func removeAll() async { busy = true; apply(await CatAndMouseBridge.removeAll(client: client)); busy = false }
    func setTarpit(_ on: Bool, scope: LureScope? = nil) async {
        busy = true
        apply(await CatAndMouseBridge.setTarpit(client: client, on: on, port: status?.config.tarpitPort ?? 2222, scope: scope ?? status?.config.lureScope ?? .loopback))
        busy = false
    }
    func setTone(_ t: DeceptionTone) async {
        UserDefaults.standard.set(t == .serious, forKey: "catMouse.serious")
        apply(await CatAndMouseBridge.setTone(client: client, serious: t == .serious))
    }
    func loadEvidence(_ c: DeceptionCatch) async {
        if let e = await CatAndMouseBridge.evidence(client: client, catchID: c.id) { evidence[c.id] = e }
    }

    /// Notifications for catches the user hasn't seen. Uses the threat category (critical), so they are never
    /// rate-limited away; the regular detection alert from rampartd still fires too.
    private func postNewCatches(_ s: DeceptionStatus) {
        let fresh = s.catches.filter { !notified.contains($0.id) }
        notified.formUnion(fresh.map(\.id))
        guard primed else { primed = true; return }   // don't replay history on first load
        for c in fresh.suffix(3) {
            if c.userOpened {   // calm, non-critical note; never an alert
                let m = DeceptionVoice.userOpened(c, tone: s.config.tone)
                Notifier.shared.post(.scan, title: m.title, body: m.body, critical: false); continue
            }
            let m = c.contained ? DeceptionVoice.contained(c, tone: s.config.tone) : DeceptionVoice.caught(c, tone: s.config.tone)
            Notifier.shared.post(.threat, title: m.title, body: m.body, critical: m.severity >= .high)
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
