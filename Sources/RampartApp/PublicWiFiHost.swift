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
            if let d = a.detection, notified.insert(a.networkKey + "|" + d.name).inserted { Notifier.shared.threat(d) }
        case .disconnectScheduled(_, let name, let reason, let deadline):
            pendingDisconnect = (name, deadline)
            Notifier.shared.wifiDisconnectScheduled(networkName: name, reason: reason)
        case .disconnected, .disconnectCancelled, .disconnectSkipped:
            pendingDisconnect = nil
        }
    }

    func stayConnected() {
        guardian.stayConnected()
        pendingDisconnect = nil
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
        if trusted, pendingDisconnect != nil { stayConnected() }
        if var l = latest { l.trusted = trusted; latest = l }
    }
}
