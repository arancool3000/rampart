import Foundation
import Observation
import AppKit
import CoreImage
import RampartShared
import RampartVPN

/// Talks to the daemon's RamPart VPN over IPC `vpn(op:body:)` -> `.vpn(Data)` (JSON of RampartVPN.VPNReply).
enum VPNBridge {
    enum Outcome { case reply(VPNReply), unsupported, error(String) }

    static func call(_ client: DaemonClient, _ op: VPNOp, _ body: VPNRequestBody? = nil, timeout: TimeInterval = 15) async -> Outcome {
        let data = body.flatMap { try? JSONEncoder().encode($0) }
        do {
            switch try await client.request(.vpn(op: op.rawValue, body: data), timeout: timeout) {
            case .vpn(let d):
                let dec = JSONDecoder(); dec.dateDecodingStrategy = .iso8601
                do { return .reply(try dec.decode(VPNReply.self, from: d)) } catch { return .error("Couldn't read the VPN status.") }
            case .error(let m):
                if DaemonClient.isDecodeFailureText(m) || m.lowercased().contains("unknown request") { return .unsupported }
                return .error(m)
            default: return .unsupported
            }
        } catch DaemonClient.ClientError.outdated {
            return .unsupported
        } catch {
            return .error(error.localizedDescription)
        }
    }
}

@MainActor
@Observable
final class VPNModel {
    static let shared = VPNModel()

    var status: VPNStatus?
    var kit: HomeServerKit?
    var warnings: [String] = []
    var error: String?
    var busy = false
    var unsupported = false
    var loaded = false

    func apply(_ o: VPNBridge.Outcome, keepKit: Bool = true) {
        switch o {
        case .reply(let r):
            status = r.status; unsupported = false
            if let k = r.kit { kit = k } else if !keepKit { kit = nil }
            if !r.warnings.isEmpty { warnings = r.warnings }
            error = nil
        case .unsupported: unsupported = true
        case .error(let m): error = SafeText.line(m, max: 400)
        }
        loaded = true
    }

    func refresh(_ client: DaemonClient) async { apply(await VPNBridge.call(client, .status)) }

    func run(_ client: DaemonClient, _ op: VPNOp, _ body: VPNRequestBody? = nil) async {
        busy = true; defer { busy = false }
        apply(await VPNBridge.call(client, op, body, timeout: op == .setupHome ? 30 : 15))
    }

    func connect(_ client: DaemonClient) async {
        VPNAutoConnector.shared.userChose(connected: true)
        await run(client, .connect, VPNRequestBody(reason: "user"))
    }
    func disconnect(_ client: DaemonClient) async {
        VPNAutoConnector.shared.userChose(connected: false)
        await run(client, .disconnect)
    }
    func importText(_ client: DaemonClient, _ text: String, name: String?) async {
        warnings = []
        await run(client, .importConfig, VPNRequestBody(text: text, name: name))
    }
    func setupHome(_ client: DaemonClient, host: String, port: UInt16) async {
        kit = nil
        await run(client, .setupHome, VPNRequestBody(host: host, port: port))
    }
    func setOptions(_ client: DaemonClient, autoConnect: Bool? = nil, killSwitch: Bool? = nil) async {
        await run(client, .setOptions, VPNRequestBody(autoConnect: autoConnect, killSwitch: killSwitch))
    }
    func remove(_ client: DaemonClient) async { kit = nil; await run(client, .remove) }

    /// Reads a WireGuard config from a .conf file or from a QR code image the user picked.
    enum ConfigRead { case success(String), failure(String) }
    static func readConfig(from url: URL) -> ConfigRead {
        let ext = url.pathExtension.lowercased()
        if ["png", "jpg", "jpeg", "heic", "gif", "tiff", "bmp"].contains(ext) {
            guard let img = CIImage(contentsOf: url),
                  let det = CIDetector(ofType: CIDetectorTypeQRCode, context: nil, options: [CIDetectorAccuracy: CIDetectorAccuracyHigh]) else {
                return .failure("Couldn't open that image.")
            }
            let texts = det.features(in: img).compactMap { ($0 as? CIQRCodeFeature)?.messageString }
            guard let t = texts.first(where: { $0.contains("[Interface]") }) else { return .failure("No WireGuard QR code found in that image.") }
            return .success(t)
        }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path), (attrs[.size] as? Int ?? 0) <= 64 * 1024,
              let t = try? String(contentsOf: url, encoding: .utf8) else { return .failure("Couldn't read that file.") }
        return .success(t)
    }
}

/// Auto-connect on untrusted or public Wi-Fi, driven by the public Wi-Fi guard's assessment (PublicWiFiHost).
/// Acts once per network; if you turn the VPN off on a network, it stays off there until you join another one.
@MainActor
final class VPNAutoConnector {
    static let shared = VPNAutoConnector()
    private var started = false
    private var handledNetwork: String?
    private var userOffOn: String?
    private(set) var lastDecision: VPNAutoConnectPolicy.Decision = .none

    func start() {
        guard PublicWiFiHost.allowed, !started else { return }
        started = true
        Task { @MainActor in
            while true {
                await self.evaluate()
                try? await Task.sleep(nanoseconds: 10_000_000_000)
            }
        }
    }

    func userChose(connected: Bool) {
        let key = PublicWiFiHost.shared.currentNetworkKey
        userOffOn = connected ? nil : key
    }

    func evaluate() async {
        guard let a = PublicWiFiHost.shared.latest else { handledNetwork = nil; return }
        let input = VPNAutoConnectPolicy.Input(onWiFi: true, trusted: PublicWiFiHost.shared.currentIsTrusted, insecure: a.security.isInsecure,
                                               captivePortal: a.captivePortal, attacked: a.arpSpoofing || a.dnsHijack,
                                               networkName: a.networkName)
        let decision = VPNAutoConnectPolicy.decide(input)
        lastDecision = decision
        guard case .connect(let reason) = decision, handledNetwork != a.networkKey, userOffOn != a.networkKey else {
            if decision == .none { handledNetwork = nil }
            return
        }
        let client = AppModel.shared.client
        guard case .reply(let r) = await VPNBridge.call(client, .status),
              r.status.options.autoConnect, r.status.profile != nil, !r.status.phase.isActive else { return }
        handledNetwork = a.networkKey
        let outcome = await VPNBridge.call(client, .connect, VPNRequestBody(reason: reason))
        VPNModel.shared.apply(outcome)
        AppModel.shared.recordActivity(ActivityEntry(kind: .wifi, title: "VPN turned on for \(a.networkName)", outcome: "connecting",
            event: .settingsChanged, actor: .system, reason: String(reason.dropFirst("auto: ".count)),
            action: "Connected RamPart VPN to your home server because this network isn't trusted.",
            facts: ["changes": "VPN auto-connect", "network": a.networkName]))
    }
}
