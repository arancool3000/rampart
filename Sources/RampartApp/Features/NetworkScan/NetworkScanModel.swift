import SwiftUI
import Observation
import RampartShared
import RampartNetwork

/// State for the Network Scan screen. The scan runs in-process (the app target links RampartNetwork) and
/// only when the user presses Scan: nothing is sent before that.
@MainActor
@Observable
final class NetworkScanModel {
    enum State: Equatable { case idle, scanning, done, failed(String) }

    var state: State = .idle
    var progress: NetScanProgress?
    var report: NetScanReport?
    var selectedDeviceID: String?
    var candidates: [(NetSubnet, NetScopeError?)] = []
    var consentShown = false

    @ObservationIgnored private let scanner = NetworkScanner()
    @ObservationIgnored private var task: Task<Void, Never>?

    init() {
        report = scanner.lastReport()
        if let r = report { state = .done; selectedDeviceID = r.gateway?.id }
    }

    var devices: [NetDevice] { report?.devices ?? [] }
    var selectedDevice: NetDevice? { devices.first { $0.id == selectedDeviceID } }
    var isScanning: Bool { state == .scanning }

    /// Which subnet would be scanned, or why nothing can be.
    func refreshCandidates() { candidates = NetworkScanner.candidateSubnets() }
    var eligibleSubnet: NetSubnet? { candidates.first { $0.1 == nil }?.0 }
    var scopeProblem: String? {
        guard eligibleSubnet == nil else { return nil }
        if let (_, err) = candidates.first, let err { return err.description }
        return "No network connection was found."
    }

    func startScan() {
        guard !isScanning else { return }
        state = .scanning
        progress = NetScanProgress(phase: .preparing, fraction: 0, message: "Starting")
        task = Task { [scanner] in
            do {
                let r = try await scanner.scan { p in Task { @MainActor in self.progress = p } }
                self.report = r
                self.state = .done
                AppModel.shared.recordActivity(ActivityEntry(kind: .networkScan, title: "Network scan finished", outcome: r.findings.isEmpty ? "no problems" : "\(r.findings.count) to review",
                    severity: r.findings.isEmpty ? .info : .low, event: .networkScan, actor: .user, target: "\(r.subnet.network)/\(r.subnet.prefix)",
                    count: r.devices.count, found: r.findings.count,
                    facts: ["new devices": r.newDevices.isEmpty ? "" : String(r.newDevices.count)]))
                if self.selectedDevice == nil { self.selectedDeviceID = r.newDevices.first?.id ?? r.gateway?.id }
            } catch {
                self.state = .failed((error as? NetScopeError)?.description ?? error.localizedDescription)
            }
        }
    }

    func cancel() { task?.cancel(); task = nil; if isScanning { state = report == nil ? .idle : .done } }

    func rename(_ id: String, to name: String) {
        scanner.knownDevices.rename(id: id, name: name)
        update(id) { $0.customName = name.isEmpty ? nil : name }
    }

    func setTrusted(_ id: String, _ trusted: Bool) {
        scanner.knownDevices.setTrusted(id: id, trusted)
        update(id) { $0.trusted = trusted; if trusted { $0.isNew = false } }
    }

    private func update(_ id: String, _ change: (inout NetDevice) -> Void) {
        guard var r = report, let i = r.devices.firstIndex(where: { $0.id == id }) else { return }
        change(&r.devices[i])
        r.findings.removeAll { $0.kind == .newDevice && $0.deviceID == id && r.devices[i].trusted }
        r.score = NetScanScoring.score(findings: r.findings, newUntrustedDevices: r.devices.filter { $0.isNew && !$0.trusted && !$0.isThisMac }.count)
        report = r
    }

    func findings(for device: NetDevice) -> [NetFinding] { report?.findings.filter { $0.deviceID == device.id } ?? [] }
    var networkFindings: [NetFinding] { report?.findings.filter { $0.deviceID == nil } ?? [] }
}
