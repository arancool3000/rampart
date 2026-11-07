import Foundation
import Observation
import RampartShared
import RampartNetwork

/// Hosts RampartNetwork's PublicWiFiGuard in the app process: assesses newly joined Wi-Fi networks and, for
/// open/WEP or attacked networks, disconnects after a grace period unless the user taps "Stay connected".
/// Never started in headless checks or when RAMPART_NO_PRIVILEGED_TOOLS=1 (ZERO POP-UPS RULE).
@MainActor
@Observable
final class PublicWiFiHost {
    static let shared = PublicWiFiHost()

    @ObservationIgnored let guardian = PublicWiFiGuard(settings: .init(), disassociator: CoreWLANDisassociator(allowLive: true))
    private(set) var latest: PublicWiFiAssessment?
    private(set) var pendingDisconnect: (name: String, deadline: Date)?
    @ObservationIgnored private var started = false
    @ObservationIgnored private var notified: Set<String> = []

    static var allowed: Bool {
        !Headless.active && ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] != "1"
    }

    func start() {
        guard Self.allowed, !started else { return }
        started = true
        guardian.onEvent = { event in
            DispatchQueue.main.async { MainActor.assumeIsolated { PublicWiFiHost.shared.handle(event) } }
        }
        guardian.start()
    }

    private func handle(_ event: PublicWiFiGuard.Event) {
        switch event {
        case .assessed(let a):
            latest = a
            // Rechecks repeat the assessment every ~30 s; notify once per network and finding.
            if let d = a.detection, notified.insert(a.networkKey + "|" + d.name).inserted {
                Notifier.shared.threat(d)
                let top = a.evidence.filter { $0.score > 0 }.max { $0.score < $1.score }
                AppModel.shared.recordActivity(ActivityEntry(kind: .wifi, title: d.name, outcome: "warned", severity: d.severity, detectionID: d.id,
                    event: .wifiWarning, actor: .system, rule: top?.title, reason: top.map { $0.detail.isEmpty ? $0.title : $0.detail },
                    score: a.confidence, action: a.decision.isDisconnect ? "Warned you and scheduled a disconnect." : "Warned you.",
                    facts: ["network": networkName(a), "security": String(describing: a.security)]))
            }
        case .disconnectScheduled(_, let name, let reason, let deadline):
            pendingDisconnect = (name, deadline)
            Notifier.shared.wifiDisconnectScheduled(networkName: name, reason: reason)
        case .disconnected(_, let reason):
            AppModel.shared.recordActivity(ActivityEntry(kind: .wifi, title: "Disconnected from \(pendingDisconnect?.name ?? latest.map(networkName) ?? "Wi-Fi")",
                outcome: "disconnected", severity: .medium, event: .wifiDisconnected, actor: .system, reason: reason,
                action: "Disconnected from the network so your traffic couldn't be watched.",
                facts: ["network": pendingDisconnect?.name ?? latest.map(networkName) ?? ""]))
            pendingDisconnect = nil
        case .disconnectCancelled, .disconnectSkipped:
            pendingDisconnect = nil
        }
    }

    private func networkName(_ a: PublicWiFiAssessment) -> String { a.ssid ?? "this Wi-Fi network" }

    func stayConnected() {
        let name = pendingDisconnect?.name ?? latest.map(networkName) ?? ""
        guardian.stayConnected()
        pendingDisconnect = nil
        AppModel.shared.recordActivity(ActivityEntry(kind: .wifi, title: "Stayed connected to \(name)", outcome: "stayed connected",
            event: .wifiStayedConnected, actor: .user, facts: ["network": name]))
    }

    /// The network currently joined, when the guard has assessed it.
    var currentNetworkKey: String? { latest?.networkKey }
    var currentIsTrusted: Bool {
        guard let k = currentNetworkKey else { return false }
        return guardian.store.network(k)?.trusted ?? false
    }

    func setCurrentTrusted(_ trusted: Bool) {
        guard let k = currentNetworkKey else { return }
        guardian.store.setTrusted(k, trusted)
        AppModel.shared.recordActivity(ActivityEntry(kind: .wifi, title: "\(latest.map(networkName) ?? "Wi-Fi") \(trusted ? "trusted" : "not trusted")",
            outcome: trusted ? "trusted" : "not trusted", event: .wifiTrustChanged, actor: .user,
            facts: ["network": latest.map(networkName) ?? "", "value": trusted ? "trusted" : "off"]))
        if trusted, pendingDisconnect != nil { stayConnected() }
        if var l = latest { l.trusted = trusted; latest = l }
    }
}
