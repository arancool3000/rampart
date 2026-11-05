import Foundation
import CoreWLAN
import RampartShared

/// Wi-Fi security type and ARP-based gateway spoofing detection.
/// SSID/BSSID need Location Services permission (nil otherwise); the security type does not.
public final class WiFiGuard: @unchecked Sendable {
    public struct WiFiStatus: Codable, Sendable {
        public var interface: String?
        public var poweredOn: Bool
        public var associated: Bool
        public var ssid: String?
        public var bssid: String?
        public var security: String
        public var isWeak: Bool          // open, WEP, or legacy WPA/TKIP
        public var rssi: Int?
        public var channel: Int?
    }

    public struct ARPEntry: Codable, Hashable, Sendable {
        public var ip: String
        public var mac: String
        public var interface: String?
        public init(ip: String, mac: String, interface: String? = nil) { self.ip = ip; self.mac = mac; self.interface = interface }
    }

    public struct Alert: Codable, Hashable, Sendable {
        public enum Kind: String, Codable, Sendable { case weakSecurity, gatewayMACChanged, duplicateMAC }
        public var kind: Kind
        public var severity: Severity
        public var message: String

        public var detection: Detection {
            Detection(name: kind == .weakSecurity ? "Insecure Wi-Fi network" : "Possible ARP spoofing",
                      category: .suspicious, severity: severity, confidence: kind == .weakSecurity ? 40 : 70,
                      evidence: [Evidence(source: .network, title: kind.rawValue, detail: message,
                                          score: kind == .weakSecurity ? 40 : 70)])
        }
    }

    private let lock = NSLock()
    /// Learned gateway IP -> MAC (persist across launches with `stateURL`).
    private var learned: [String: String] = [:]
    public let stateURL: URL?

    public init(stateURL: URL? = Paths.effectiveRoot.appendingPathComponent("wifiguard.json")) {
        self.stateURL = stateURL
        if let u = stateURL, let d = try? Data(contentsOf: u),
           let m = try? JSONDecoder().decode([String: String].self, from: d) { learned = m }
    }

    // MARK: CoreWLAN

    public static func securityName(_ s: CWSecurity) -> (String, Bool) {
        switch s {
        case .none: return ("Open", true)
        case .WEP: return ("WEP", true)
        case .dynamicWEP: return ("Dynamic WEP", true)
        case .wpaPersonal: return ("WPA Personal", true)
        case .wpaPersonalMixed: return ("WPA/WPA2 Personal", false)
        case .wpa2Personal: return ("WPA2 Personal", false)
        case .personal: return ("WPA2/WPA3 Personal", false)
        case .wpa3Personal: return ("WPA3 Personal", false)
        case .wpa3Transition: return ("WPA2/WPA3 Transition", false)
        case .wpaEnterprise: return ("WPA Enterprise", true)
        case .wpaEnterpriseMixed: return ("WPA/WPA2 Enterprise", false)
        case .wpa2Enterprise: return ("WPA2 Enterprise", false)
        case .enterprise: return ("Enterprise", false)
        case .wpa3Enterprise: return ("WPA3 Enterprise", false)
        case .OWE: return ("OWE (Enhanced Open)", false)
        case .oweTransition: return ("OWE Transition", false)
        case .unknown: return ("Unknown", false)
        @unknown default: return ("Unknown", false)
        }
    }

    public func currentStatus() -> WiFiStatus? {
        guard let iface = CWWiFiClient.shared().interface() else { return nil }
        let powered = iface.powerOn()
        let sec = iface.security()
        // Not associated reports .unknown and no channel.
        let associated = powered && iface.wlanChannel() != nil
        let (name, weak) = associated ? Self.securityName(sec) : ("Not connected", false)
        return WiFiStatus(interface: iface.interfaceName, poweredOn: powered, associated: associated,
                          ssid: iface.ssid(), bssid: iface.bssid(), security: name, isWeak: associated && weak,
                          rssi: associated ? iface.rssiValue() : nil, channel: iface.wlanChannel()?.channelNumber)
    }

    // MARK: ARP / gateway

    /// Parses `arp -an` lines: `? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]`.
    public static func parseARP(_ text: String) -> [ARPEntry] {
        text.split(whereSeparator: \.isNewline).compactMap { line in
            let s = String(line)
            guard let o = s.firstIndex(of: "("), let c = s.firstIndex(of: ")"), o < c,
                  let atR = s.range(of: " at ") else { return nil }
            let ip = String(s[s.index(after: o)..<c])
            let rest = s[atR.upperBound...].split(separator: " ")
            guard let macRaw = rest.first, macRaw != "(incomplete)" else { return nil }
            let mac = normalizeMAC(String(macRaw))
            guard mac != "ff:ff:ff:ff:ff:ff" else { return nil }
            var iface: String?
            if let i = rest.firstIndex(of: "on"), i + 1 < rest.count { iface = String(rest[i + 1]) }
            return ARPEntry(ip: ip, mac: mac, interface: iface)
        }
    }

    /// arp prints `0:1b:2:...`; pad each octet to two hex digits.
    public static func normalizeMAC(_ m: String) -> String {
        m.lowercased().split(separator: ":").map { $0.count == 1 ? "0" + $0 : String($0) }.joined(separator: ":")
    }

    /// Parses `route -n get default` → gateway IP.
    public static func parseDefaultGateway(_ text: String) -> String? {
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.hasPrefix("gateway:") { return t.dropFirst(8).trimmingCharacters(in: .whitespaces) }
        }
        return nil
    }

    public func defaultGateway() -> String? {
        Self.parseDefaultGateway(NetShell.run("/sbin/route", ["-n", "get", "default"], timeout: 5).1)
    }

    /// Note: on macOS 15+ the ARP table is filtered by Local Network privacy. A process whose responsible
    /// app has not been granted Local Network access (e.g. a CLI launched from an unapproved host) gets an
    /// empty table; launchd daemons running as root are not subject to this.
    public func arpTable() -> [ARPEntry] { Self.parseARP(NetShell.run("/usr/sbin/arp", ["-an"], timeout: 5).1) }

    /// Pure evaluation step (fixture-testable): compares the gateway's MAC to what was learned.
    public func evaluate(gateway: String?, arp: [ARPEntry]) -> [Alert] {
        var alerts: [Alert] = []
        lock.lock(); defer { lock.unlock() }
        if let gw = gateway, let entry = arp.first(where: { $0.ip == gw }) {
            if let known = learned[gw], known != entry.mac {
                alerts.append(Alert(kind: .gatewayMACChanged, severity: .high,
                                    message: "Gateway \(gw) changed MAC from \(known) to \(entry.mac). This can mean ARP spoofing (or a new router)."))
            }
            learned[gw] = entry.mac
            // Another IP claiming the gateway's MAC.
            let dupes = arp.filter { $0.mac == entry.mac && $0.ip != gw && !$0.ip.hasPrefix("169.254.") }
            if !dupes.isEmpty {
                alerts.append(Alert(kind: .duplicateMAC, severity: .medium,
                                    message: "Gateway MAC \(entry.mac) is also used by \(dupes.map(\.ip).joined(separator: ", "))."))
            }
        }
        persist()
        return alerts
    }

    /// Full check: Wi-Fi security + ARP. Call every ~10 s.
    public func check() -> [Alert] {
        var alerts = evaluate(gateway: defaultGateway(), arp: arpTable())
        if let s = currentStatus(), s.isWeak {
            alerts.append(Alert(kind: .weakSecurity, severity: .medium,
                                message: "Connected Wi-Fi uses \(s.security) security. Traffic on this network may be visible to others."))
        }
        return alerts
    }

    /// Forget learned gateways (e.g. user confirmed a new router).
    public func resetLearned() { lock.lock(); learned = [:]; persist(); lock.unlock() }

    private func persist() {
        guard let u = stateURL else { return }
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? JSONEncoder().encode(learned).write(to: u, options: .atomic)
    }
}
