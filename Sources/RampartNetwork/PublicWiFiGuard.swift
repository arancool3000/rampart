import Foundation
import CoreWLAN
import Network
import RampartShared

// Public Wi-Fi guard: when the Mac joins a Wi-Fi network it has not seen before, run a short background
// assessment (security type, captive portal, ARP spoofing of the gateway, DNS hijack, a gentle probe of the
// gateway only) and, if the network is open/WEP or under attack, disconnect after a 10-second grace period
// unless the user taps "Stay connected".
//
// Scope rules:
// - Only the gateway is ever probed (a handful of TCP connects at <= 5/s). Public networks are not ours to scan.
// - Networks the user marks trusted are never disconnected.
// - `CWInterface.disassociate()` is only reachable through `CoreWLANDisassociator(allowLive: true)` and is
//   refused when `RAMPART_NO_PRIVILEGED_TOOLS=1`. Self-tests use a fake disassociator.
// - Everything decision-related is pure (`PublicWiFiGuard.assess` / `decide`) and fixture-testable.

// MARK: - Model

/// Coarse security class of the joined Wi-Fi network.
public enum WiFiSecurityClass: String, Codable, Sendable, CaseIterable {
    case open, wep, wpa1, enhancedOpen, wpa2Personal, wpa3Personal, wpa2Enterprise, wpa3Enterprise, unknown

    /// Traffic readable by others (open, WEP) or crackable (WPA1/TKIP).
    public var isInsecure: Bool { self == .open || self == .wep || self == .wpa1 }
    /// Only these trigger the automatic disconnect on security type alone.
    public var isDisconnectWorthy: Bool { self == .open || self == .wep }
    public var isEnterprise: Bool { self == .wpa2Enterprise || self == .wpa3Enterprise }

    public var label: String {
        switch self {
        case .open: return "Open (no password)"
        case .wep: return "WEP"
        case .wpa1: return "WPA (legacy)"
        case .enhancedOpen: return "Enhanced Open (OWE)"
        case .wpa2Personal: return "WPA2 Personal"
        case .wpa3Personal: return "WPA3 Personal"
        case .wpa2Enterprise: return "WPA2 Enterprise"
        case .wpa3Enterprise: return "WPA3 Enterprise"
        case .unknown: return "Unknown"
        }
    }

    public static func classify(_ s: CWSecurity) -> WiFiSecurityClass {
        switch s {
        case .none: return .open
        case .WEP, .dynamicWEP: return .wep
        case .wpaPersonal, .wpaEnterprise: return .wpa1
        case .OWE, .oweTransition: return .enhancedOpen
        case .wpaPersonalMixed, .wpa2Personal, .personal: return .wpa2Personal
        case .wpa3Personal, .wpa3Transition: return .wpa3Personal
        case .wpaEnterpriseMixed, .wpa2Enterprise, .enterprise: return .wpa2Enterprise
        case .wpa3Enterprise: return .wpa3Enterprise
        case .unknown: return .unknown
        @unknown default: return .unknown
        }
    }
}

/// A network Rampart has seen. `key` is the stable identity (see `PublicWiFiGuard.networkKey`).
public struct KnownWiFiNetwork: Codable, Hashable, Sendable {
    public var key: String
    public var ssid: String?
    public var security: WiFiSecurityClass
    public var gatewayMAC: String?
    public var firstSeen: Date
    public var lastSeen: Date
    /// Home/work network the user trusts: never disconnected, no first-join assessment.
    public var trusted: Bool
    /// User tapped "Stay connected" for this network: no automatic disconnect for its security type.
    public var stayConnected: Bool
    public init(key: String, ssid: String?, security: WiFiSecurityClass, gatewayMAC: String?, firstSeen: Date = Date(),
                lastSeen: Date = Date(), trusted: Bool = false, stayConnected: Bool = false) {
        self.key = key; self.ssid = ssid; self.security = security; self.gatewayMAC = gatewayMAC
        self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.trusted = trusted; self.stayConnected = stayConnected
    }
}

/// Persisted list of networks seen before. JSON file, 0600.
public final class KnownWiFiNetworkStore: @unchecked Sendable {
    private let lock = NSLock()
    private var networks: [String: KnownWiFiNetwork] = [:]
    public let url: URL?
    public static let maxEntries = 500

    public init(url: URL? = Paths.effectiveRoot.appendingPathComponent("known-wifi.json")) {
        self.url = url
        if let u = url, let d = try? Data(contentsOf: u), d.count < 4_000_000,
           let list = try? JSONDecoder().decode([KnownWiFiNetwork].self, from: d) {
            for n in list { networks[n.key] = n }
        }
    }

    public var all: [KnownWiFiNetwork] { lock.lock(); defer { lock.unlock() }; return networks.values.sorted { $0.lastSeen > $1.lastSeen } }
    public func network(_ key: String) -> KnownWiFiNetwork? { lock.lock(); defer { lock.unlock() }; return networks[key] }
    public func contains(_ key: String) -> Bool { network(key) != nil }

    public func upsert(_ n: KnownWiFiNetwork) {
        lock.lock()
        var v = n
        if let old = networks[n.key] { v.firstSeen = old.firstSeen; v.trusted = old.trusted || n.trusted; v.stayConnected = old.stayConnected || n.stayConnected }
        networks[n.key] = v
        if networks.count > Self.maxEntries {   // evict the oldest untrusted entries
            let victims = networks.values.filter { !$0.trusted }.sorted { $0.lastSeen < $1.lastSeen }.prefix(networks.count - Self.maxEntries)
            for x in victims { networks[x.key] = nil }
        }
        persistLocked(); lock.unlock()
    }

    public func setTrusted(_ key: String, _ trusted: Bool) { mutate(key) { $0.trusted = trusted } }
    public func setStayConnected(_ key: String, _ stay: Bool) { mutate(key) { $0.stayConnected = stay } }
    public func forget(_ key: String) { lock.lock(); networks[key] = nil; persistLocked(); lock.unlock() }

    private func mutate(_ key: String, _ f: (inout KnownWiFiNetwork) -> Void) {
        lock.lock(); if var n = networks[key] { f(&n); networks[key] = n; persistLocked() }; lock.unlock()
    }

    private func persistLocked() {
        guard let u = url else { return }
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        guard let d = try? JSONEncoder().encode(Array(networks.values)) else { return }
        if (try? d.write(to: u, options: .atomic)) != nil {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: u.path)
        }
    }
}

/// Everything gathered about the network at one moment. Built live by `PublicWiFiGuard.gatherSnapshot`
/// or by hand from fixtures in self-tests.
public struct PublicWiFiSnapshot: Codable, Sendable {
    public var interface: String?
    public var ssid: String?                 // nil without Location Services permission
    public var bssid: String?
    public var security: WiFiSecurityClass
    public var gateway: String?
    public var arp: [WiFiGuard.ARPEntry]
    public var dnsServers: [String]
    /// Canary host -> addresses the system resolver returned (empty = no answer).
    public var dnsCanaryAnswers: [String: [String]]
    /// HTTP status + body of the captive-portal probe (nil = probe failed / not run).
    public var captiveProbeStatus: Int?
    public var captiveProbeBody: String?
    /// Gateway TCP port -> open?
    public var gatewayPorts: [Int: Bool]
    public init(interface: String? = nil, ssid: String? = nil, bssid: String? = nil, security: WiFiSecurityClass,
                gateway: String? = nil, arp: [WiFiGuard.ARPEntry] = [], dnsServers: [String] = [],
                dnsCanaryAnswers: [String: [String]] = [:], captiveProbeStatus: Int? = nil, captiveProbeBody: String? = nil,
                gatewayPorts: [Int: Bool] = [:]) {
        self.interface = interface; self.ssid = ssid; self.bssid = bssid; self.security = security; self.gateway = gateway
        self.arp = arp; self.dnsServers = dnsServers; self.dnsCanaryAnswers = dnsCanaryAnswers
        self.captiveProbeStatus = captiveProbeStatus; self.captiveProbeBody = captiveProbeBody; self.gatewayPorts = gatewayPorts
    }
    public var gatewayMAC: String? { gateway.flatMap { g in arp.first { $0.ip == g }?.mac } }
}

public struct PublicWiFiSettings: Codable, Hashable, Sendable {
    /// Master switch for automatic disconnects (open/WEP by default; attacks if `disconnectOnAttack`).
    public var disconnectInsecureWiFi: Bool = true
    /// Also disconnect on ARP spoofing or a confirmed DNS hijack (only while `disconnectInsecureWiFi` is on).
    public var disconnectOnAttack: Bool = true
    /// Seconds the "Disconnecting from insecure Wi-Fi… Stay connected" notification is shown first.
    public var graceSeconds: Double = 10
    /// Gentle TCP probe of the gateway only.
    public var probeGateway: Bool = true
    /// Seconds between ARP re-checks while on an untrusted network.
    public var recheckInterval: Double = 30
    public init() {}
}

public enum CanaryVerdict: String, Codable, Sendable { case ok, hijacked, inconclusive }

public struct PublicWiFiAssessment: Codable, Sendable {
    public enum Decision: Codable, Hashable, Sendable {
        case none
        case alertOnly
        case disconnect(reason: String)
        public var isDisconnect: Bool { if case .disconnect = self { return true }; return false }
    }
    public var date: Date
    public var networkKey: String
    public var ssid: String?
    public var security: WiFiSecurityClass
    public var isNewNetwork: Bool
    public var trusted: Bool
    public var captivePortal: Bool?
    public var gatewayMAC: String?
    public var gatewayMACChanged: Bool
    public var duplicateGatewayMAC: [String]
    public var dnsVerdicts: [DNSResolverVerdict]
    public var dnsCanary: CanaryVerdict
    public var gatewayRiskyPorts: [Int]
    public var evidence: [Evidence]
    public var decision: Decision

    public var arpSpoofing: Bool { gatewayMACChanged || !duplicateGatewayMAC.isEmpty }
    public var dnsHijack: Bool { dnsCanary == .hijacked }
    public var confidence: Int {
        let p = evidence.reduce(1.0) { $0 * (1 - Double(min(max($1.score, 0), 100)) / 100) }
        return Int((100 * (1 - p)).rounded())
    }
    public var severity: Severity {
        if arpSpoofing || dnsHijack { return .high }
        if security.isDisconnectWorthy { return .medium }
        if security.isInsecure || !gatewayRiskyPorts.isEmpty || dnsVerdicts.contains(where: { $0.status == .unknown }) { return .low }
        return .info
    }
    public var networkName: String { PublicWiFiGuard.displaySSID(ssid) ?? "this Wi-Fi network" }

    /// One-line summary for notifications / logs (no BSSID, no addresses).
    public var summary: String {
        var parts: [String] = ["\(networkName): \(security.label)"]
        if captivePortal == true { parts.append("captive portal (sign-in page)") }
        if arpSpoofing { parts.append("possible ARP spoofing of the router") }
        if dnsHijack { parts.append("DNS answers look tampered with") }
        else if dnsVerdicts.contains(where: { $0.status == .unknown }) { parts.append("unrecognised DNS server") }
        if !gatewayRiskyPorts.isEmpty { parts.append("router exposes \(gatewayRiskyPorts.map(String.init).joined(separator: ", "))") }
        if parts.count == 1 && !security.isInsecure { parts.append("no problems found") }
        return parts.joined(separator: "; ")
    }

    /// Nil when there is nothing worth showing (evidence-free secure network).
    public var detection: Detection? {
        guard !evidence.isEmpty, severity > .info else { return nil }
        let name = arpSpoofing ? "Possible ARP spoofing on Wi-Fi" : dnsHijack ? "DNS hijack on Wi-Fi" : "Insecure public Wi-Fi"
        return Detection(name: name, category: .suspicious, severity: severity, confidence: confidence, evidence: evidence)
    }
}

/// Performs the actual disassociation. Abstracted so tests never touch Wi-Fi.
public protocol WiFiDisassociating: Sendable {
    /// Returns false if refused / not possible.
    func disassociate(interface: String?) -> Bool
}

/// Real implementation. Must run in the user's session (the app or a LaunchAgent); refuses unless
/// constructed with `allowLive: true` and `RAMPART_NO_PRIVILEGED_TOOLS` is not set.
public struct CoreWLANDisassociator: WiFiDisassociating {
    public let allowLive: Bool
    public init(allowLive: Bool = false) { self.allowLive = allowLive }
    public func disassociate(interface: String?) -> Bool {
        guard allowLive, ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] != "1" else { return false }
        let client = CWWiFiClient.shared()
        guard let iface = interface.flatMap({ client.interface(withName: $0) }) ?? client.interface() else { return false }
        iface.disassociate()
        return true
    }
}

/// Records calls; used by self-tests and dry runs.
public final class DryRunDisassociator: WiFiDisassociating, @unchecked Sendable {
    private let lock = NSLock()
    private var _calls: [String?] = []
    public init() {}
    public var calls: [String?] { lock.lock(); defer { lock.unlock() }; return _calls }
    public func disassociate(interface: String?) -> Bool { lock.lock(); _calls.append(interface); lock.unlock(); return true }
}

// MARK: - Guard

public final class PublicWiFiGuard: @unchecked Sendable {
    public enum Event: Sendable {
        case assessed(PublicWiFiAssessment)
        /// The app shows "Disconnecting from insecure Wi-Fi… [Stay connected]" until `deadline`.
        case disconnectScheduled(networkKey: String, networkName: String, reason: String, deadline: Date)
        case disconnected(networkKey: String, reason: String)
        case disconnectCancelled(networkKey: String)
        case disconnectSkipped(networkKey: String, why: String)
    }

    /// Gateway ports for the gentle probe (connect only, no payloads).
    public static let gatewayProbePorts = [23, 80, 443, 445, 7547, 8080]
    /// Ports worth flagging when open on a public gateway.
    public static let riskyGatewayPorts: Set<Int> = [23, 445, 7547]
    /// Canaries with fixed, well-known answers.
    public static let dnsCanaries: [String: Set<String>] = [
        "one.one.one.one": ["1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001"],
        "dns.google": ["8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"],
    ]
    public static let captiveProbeURL = "http://captive.apple.com/hotspot-detect.html"

    public let store: KnownWiFiNetworkStore
    public var settings: PublicWiFiSettings { get { lock.lock(); defer { lock.unlock() }; return _settings }
                                              set { lock.lock(); _settings = newValue; lock.unlock() } }
    public var onEvent: (@Sendable (Event) -> Void)?

    private let disassociator: WiFiDisassociating
    private let lock = NSLock()
    private var _settings: PublicWiFiSettings
    private let queue = DispatchQueue(label: "app.rampart.publicwifi", qos: .utility)
    private var monitor: NWPathMonitor?
    private var debounce: DispatchWorkItem?
    private var recheckTimer: DispatchSourceTimer?
    private var pending: (key: String, reason: String, interface: String?, item: DispatchWorkItem)?
    /// Network currently joined + its gateway MAC at join time (for in-session spoof detection).
    private var current: (key: String, gatewayMAC: String?)?
    private var lastAssessment: PublicWiFiAssessment?
    /// Recent automatic disconnects per network key (rate limit; in-memory only).
    private var disconnectHistory: [String: [Date]] = [:]

    public init(store: KnownWiFiNetworkStore = KnownWiFiNetworkStore(), settings: PublicWiFiSettings = PublicWiFiSettings(),
                disassociator: WiFiDisassociating = CoreWLANDisassociator()) {
        self.store = store; self._settings = settings; self.disassociator = disassociator
    }

    public var latest: PublicWiFiAssessment? { lock.lock(); defer { lock.unlock() }; return lastAssessment }

    // MARK: Pure logic

    /// SSIDs are attacker-chosen (up to 32 arbitrary bytes). For display they are stripped of control,
    /// bidi-override and zero-width characters, collapsed to one line, capped and quoted, so a network named
    /// e.g. "RamPart: this network is safe" reads as a quoted name, never as RamPart's own words. (hx4)
    public static func displaySSID(_ ssid: String?) -> String? {
        guard let ssid else { return nil }
        let banned: Set<UInt32> = [0x200B, 0x200C, 0x200D, 0x200E, 0x200F, 0x2028, 0x2029, 0x2060, 0xFEFF,
                                   0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x061C]
        var out = String.UnicodeScalarView()
        for u in ssid.unicodeScalars {
            if u.value < 0x20 || (0x7F...0x9F).contains(u.value) { out.append(" "); continue }
            if banned.contains(u.value) { continue }
            out.append(u)
        }
        var t = String(out).split(whereSeparator: \.isWhitespace).joined(separator: " ")
        t = t.replacingOccurrences(of: "\u{201C}", with: "\"").replacingOccurrences(of: "\u{201D}", with: "\"")
        if t.count > 32 { t = String(t.prefix(32)) + "…" }
        guard !t.isEmpty else { return nil }
        return "\u{201C}\(t)\u{201D}"
    }

    /// Automatic disconnects allowed per network per hour. Beyond this a spoofed or flapping network could keep
    /// knocking the Mac off Wi-Fi forever (an attacker on the LAN can fake ARP evidence at will); after the
    /// budget is used RamPart only alerts. (hx4)
    public static let maxAutoDisconnectsPerHour = 2

    /// Pure rate-limit decision (fixture-testable).
    public static func disconnectBudgetExhausted(_ history: [Date], now: Date = Date()) -> Bool {
        history.filter { now.timeIntervalSince($0) < 3600 }.count >= maxAutoDisconnectsPerHour
    }

    /// Stable network identity. SSID when available, else the gateway MAC, else gateway IP + security.
    public static func networkKey(ssid: String?, gatewayMAC: String?, gateway: String?, security: WiFiSecurityClass) -> String {
        if let s = ssid, !s.isEmpty { return "ssid:\(s)|\(security.rawValue)" }
        if let m = gatewayMAC, !m.isEmpty { return "gw:\(m)" }
        return "gwip:\(gateway ?? "none")|\(security.rawValue)"
    }

    /// Apple's probe returns 200 with a body containing "Success" when there is no portal.
    public static func captivePortal(status: Int?, body: String?) -> Bool? {
        guard let st = status else { return nil }
        if st == 200, let b = body, b.contains("Success") { return false }
        return true
    }

    /// Hijacked when at least one canary answered and every answering canary returned only unexpected addresses.
    public static func canaryVerdict(_ answers: [String: [String]]) -> CanaryVerdict {
        var answered = 0, bad = 0
        for (host, addrs) in answers {
            guard let expected = dnsCanaries[host], !addrs.isEmpty else { continue }
            answered += 1
            if Set(addrs.map { $0.lowercased() }).isDisjoint(with: expected) { bad += 1 }
        }
        if answered == 0 { return .inconclusive }
        return bad == answered ? .hijacked : .ok
    }

    public static func duplicateGatewayMAC(gateway: String?, arp: [WiFiGuard.ARPEntry]) -> [String] {
        guard let g = gateway, let mac = arp.first(where: { $0.ip == g })?.mac else { return [] }
        return arp.filter { $0.mac == mac && $0.ip != g && !$0.ip.hasPrefix("169.254.") }.map(\.ip).sorted()
    }

    public static func decide(security: WiFiSecurityClass, arpSpoofing: Bool, dnsHijack: Bool, trusted: Bool,
                              stayConnected: Bool, settings: PublicWiFiSettings) -> PublicWiFiAssessment.Decision {
        let anything = security.isInsecure || arpSpoofing || dnsHijack
        if trusted { return anything ? .alertOnly : .none }
        guard settings.disconnectInsecureWiFi else { return anything ? .alertOnly : .none }
        if settings.disconnectOnAttack && arpSpoofing { return .disconnect(reason: "The router's address looks spoofed (possible ARP spoofing).") }
        if settings.disconnectOnAttack && dnsHijack { return .disconnect(reason: "Website lookups on this network are being redirected (DNS hijack).") }
        if security.isDisconnectWorthy && !stayConnected { return .disconnect(reason: "This Wi-Fi uses \(security.label) security, so others nearby can read your traffic.") }
        return anything ? .alertOnly : .none
    }

    /// Turns a snapshot into an assessment. `known` is the store entry before this join (nil = new network);
    /// `sessionGatewayMAC` is the gateway MAC seen earlier in this session (for re-checks).
    public static func assess(_ s: PublicWiFiSnapshot, known: KnownWiFiNetwork?, sessionGatewayMAC: String? = nil,
                              settings: PublicWiFiSettings, date: Date = Date()) -> PublicWiFiAssessment {
        let mac = s.gatewayMAC
        let key = known?.key ?? networkKey(ssid: s.ssid, gatewayMAC: mac, gateway: s.gateway, security: s.security)
        let trusted = known?.trusted ?? false
        let captive = captivePortal(status: s.captiveProbeStatus, body: s.captiveProbeBody)
        // Gateway MAC change: within this session, or vs the remembered MAC for an SSID-keyed network.
        let reference = sessionGatewayMAC ?? (key.hasPrefix("ssid:") ? known?.gatewayMAC : nil)
        let macChanged = reference != nil && mac != nil && reference != mac
        let dupes = duplicateGatewayMAC(gateway: s.gateway, arp: s.arp)
        let subnetGuess: NetSubnet? = nil
        let verdicts = s.dnsServers.map { DNSResolverCheck.verdict($0, subnet: subnetGuess, gateway: s.gateway) }
        // Captive portals legitimately intercept DNS before sign-in.
        var canary = canaryVerdict(s.dnsCanaryAnswers)
        if canary == .hijacked && captive == true { canary = .inconclusive }
        let risky = s.gatewayPorts.filter { $0.value && riskyGatewayPorts.contains($0.key) }.map(\.key).sorted()

        var ev: [Evidence] = []
        switch s.security {
        case .open: ev.append(Evidence(source: .network, title: "Open Wi-Fi", detail: "\(displaySSID(s.ssid).map { "The network \($0)" } ?? "This network") has no password. Anyone nearby can see unencrypted traffic.", score: 45))
        case .wep: ev.append(Evidence(source: .network, title: "WEP Wi-Fi", detail: "WEP encryption can be broken in minutes.", score: 55))
        case .wpa1: ev.append(Evidence(source: .network, title: "Legacy WPA Wi-Fi", detail: "WPA (TKIP) is outdated and weak.", score: 30))
        default: break
        }
        if captive == true { ev.append(Evidence(source: .network, title: "Captive portal", detail: "This network shows a sign-in page before giving internet access. Only enter details on the portal you expect.", score: 10)) }
        if macChanged { ev.append(Evidence(source: .network, title: "Gateway MAC changed", detail: "The router's hardware address changed from \(reference ?? "?") to \(mac ?? "?").", score: 75)) }
        if !dupes.isEmpty { ev.append(Evidence(source: .network, title: "Duplicate gateway MAC", detail: "Other addresses (\(dupes.joined(separator: ", "))) claim the router's hardware address.", score: 60)) }
        if canary == .hijacked { ev.append(Evidence(source: .network, title: "DNS hijack", detail: "Well-known names resolved to unexpected addresses through this network's DNS.", score: 80)) }
        for v in verdicts where v.status == .unknown {
            ev.append(Evidence(source: .network, title: "Unrecognised DNS server", detail: "Lookups go to \(v.server), which is not the router or a well-known resolver.", score: 20))
        }
        if !risky.isEmpty { ev.append(Evidence(source: .network, title: "Router exposes risky ports", detail: "The gateway accepts connections on \(risky.map(String.init).joined(separator: ", ")).", score: 25)) }

        let decision = decide(security: s.security, arpSpoofing: macChanged || !dupes.isEmpty, dnsHijack: canary == .hijacked,
                              trusted: trusted, stayConnected: known?.stayConnected ?? false, settings: settings)
        return PublicWiFiAssessment(date: date, networkKey: key, ssid: s.ssid, security: s.security, isNewNetwork: known == nil,
                                    trusted: trusted, captivePortal: captive, gatewayMAC: mac, gatewayMACChanged: macChanged,
                                    duplicateGatewayMAC: dupes, dnsVerdicts: verdicts, dnsCanary: canary,
                                    gatewayRiskyPorts: risky, evidence: ev, decision: decision)
    }

    // MARK: Live gathering (daemon / app only; never during development)

    /// Light snapshot: CoreWLAN + route + ARP. No packets beyond what the OS already does.
    public static func lightSnapshot() -> PublicWiFiSnapshot? {
        guard let iface = CWWiFiClient.shared().interface(), iface.powerOn(), iface.wlanChannel() != nil else { return nil }
        let wg = WiFiGuard(stateURL: nil)
        return PublicWiFiSnapshot(interface: iface.interfaceName, ssid: iface.ssid(), bssid: iface.bssid(),
                                  security: WiFiSecurityClass.classify(iface.security()), gateway: wg.defaultGateway(),
                                  arp: wg.arpTable(), dnsServers: DNSResolverCheck.currentServers())
    }

    /// Full first-join snapshot: adds the DNS canary, captive probe and the gentle gateway probe.
    public static func gatherSnapshot(settings: PublicWiFiSettings) async -> PublicWiFiSnapshot? {
        guard var s = lightSnapshot() else { return nil }
        for host in dnsCanaries.keys { s.dnsCanaryAnswers[host] = resolveSystem(host, timeout: 3) }
        (s.captiveProbeStatus, s.captiveProbeBody) = await captiveProbe(timeout: 5)
        let noProbes = ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] == "1"
        // Only probe a private IPv4 gateway (never a public address).
        if settings.probeGateway, !noProbes, let g = s.gateway, let v = IPv4.parse(g), IPv4.isPrivate(v) {
            let limiter = ProbeRateLimiter(rate: 5)
            for p in gatewayProbePorts {
                await limiter.acquire()
                s.gatewayPorts[p] = await TCPProbe.connect(ip: g, port: p, timeout: 1.0) == .open
            }
        }
        return s
    }

    static func resolveSystem(_ host: String, timeout: TimeInterval) -> [String] {
        final class Box: @unchecked Sendable { var v: [String] = [] }
        let box = Box(), sem = DispatchSemaphore(value: 0)
        DispatchQueue.global(qos: .utility).async {
            var hints = addrinfo(); hints.ai_socktype = SOCK_STREAM
            var res: UnsafeMutablePointer<addrinfo>?
            var out: [String] = []
            if getaddrinfo(host, nil, &hints, &res) == 0 {
                var p = res
                while let ai = p {
                    var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                    if getnameinfo(ai.pointee.ai_addr, ai.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                        let a = String(cString: buf)
                        if !out.contains(a) { out.append(a) }
                    }
                    p = ai.pointee.ai_next
                }
                freeaddrinfo(res)
            }
            box.v = out; sem.signal()
        }
        return sem.wait(timeout: .now() + timeout) == .success ? box.v : []
    }

    static func captiveProbe(timeout: TimeInterval) async -> (Int?, String?) {
        guard let url = URL(string: captiveProbeURL) else { return (nil, nil) }
        var req = URLRequest(url: url); req.timeoutInterval = timeout
        let cfg = URLSessionConfiguration.ephemeral; cfg.waitsForConnectivity = false
        let session = URLSession(configuration: cfg)
        defer { session.finishTasksAndInvalidate() }
        guard let (data, resp) = try? await session.data(for: req), let http = resp as? HTTPURLResponse else { return (nil, nil) }
        return (http.statusCode, String(decoding: data.prefix(4096), as: UTF8.self))
    }

    // MARK: Lifecycle

    /// Starts watching network changes. Call from rampartd (root) or the app; never in self-tests.
    public func start() {
        let m = NWPathMonitor(requiredInterfaceType: .wifi)
        m.pathUpdateHandler = { [weak self] path in
            guard let self else { return }
            if path.status == .satisfied { self.scheduleEvaluation(after: 3) } else { self.networkLeft() }
        }
        m.start(queue: queue)
        lock.lock(); monitor = m; lock.unlock()
    }

    public func stop() {
        lock.lock()
        monitor?.cancel(); monitor = nil; debounce?.cancel(); recheckTimer?.cancel(); recheckTimer = nil
        pending?.item.cancel(); pending = nil
        lock.unlock()
    }

    private func scheduleEvaluation(after seconds: Double) {
        let item = DispatchWorkItem { [weak self] in
            Task { await self?.evaluateNow() }
        }
        lock.lock(); debounce?.cancel(); debounce = item; lock.unlock()
        queue.asyncAfter(deadline: .now() + seconds, execute: item)
    }

    private func networkLeft() {
        lock.lock(); current = nil; recheckTimer?.cancel(); recheckTimer = nil; lock.unlock()
    }

    /// Runs the join flow once. New untrusted networks get the full snapshot; known ones only a light check.
    @discardableResult
    public func evaluateNow() async -> PublicWiFiAssessment? {
        guard let light = Self.lightSnapshot() else { networkLeft(); return nil }
        let key = Self.networkKey(ssid: light.ssid, gatewayMAC: light.gatewayMAC, gateway: light.gateway, security: light.security)
        let known = store.network(key)
        lock.lock()
        let sameSession = current?.key == key
        let sessionMAC = sameSession ? current?.gatewayMAC : nil
        lock.unlock()
        if sameSession { return recheck() }
        let snap = known == nil ? (await Self.gatherSnapshot(settings: settings) ?? light) : light
        return handle(snap, known: known, sessionGatewayMAC: sessionMAC)
    }

    /// Periodic ARP re-check on the current network (cheap, no probes).
    @discardableResult
    public func recheck() -> PublicWiFiAssessment? {
        guard let s = Self.lightSnapshot() else { return nil }
        lock.lock(); let cur = current; lock.unlock()
        guard let cur else { return nil }
        return handle(s, known: store.network(cur.key), sessionGatewayMAC: cur.gatewayMAC, quietIfClean: true)
    }

    /// Shared tail of the flow; also the entry point for fixture-driven tests with a fake disassociator.
    @discardableResult
    public func handle(_ s: PublicWiFiSnapshot, known: KnownWiFiNetwork?, sessionGatewayMAC: String? = nil, quietIfClean: Bool = false) -> PublicWiFiAssessment {
        let cfg = settings
        let a = Self.assess(s, known: known, sessionGatewayMAC: sessionGatewayMAC, settings: cfg)
        store.upsert(KnownWiFiNetwork(key: a.networkKey, ssid: s.ssid, security: s.security,
                                      gatewayMAC: sessionGatewayMAC ?? s.gatewayMAC ?? known?.gatewayMAC))
        lock.lock()
        current = (a.networkKey, sessionGatewayMAC ?? s.gatewayMAC)
        lastAssessment = a
        lock.unlock()
        if !(quietIfClean && a.evidence.allSatisfy({ $0.score < 30 })) { onEvent?(.assessed(a)) }
        if case .disconnect(let reason) = a.decision { scheduleDisconnect(key: a.networkKey, name: a.networkName, reason: reason, interface: s.interface, grace: cfg.graceSeconds) }
        if !a.trusted { startRecheckTimer(interval: cfg.recheckInterval) }
        return a
    }

    private func startRecheckTimer(interval: Double) {
        lock.lock(); defer { lock.unlock() }
        guard recheckTimer == nil, monitor != nil else { return }   // only when live-watching
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + interval, repeating: max(10, interval))
        t.setEventHandler { [weak self] in _ = self?.recheck() }
        t.resume(); recheckTimer = t
    }

    // MARK: Disconnect with grace period

    public var hasPendingDisconnect: Bool { lock.lock(); defer { lock.unlock() }; return pending != nil }

    func scheduleDisconnect(key: String, name: String, reason: String, interface: String?, grace: Double) {
        lock.lock()
        if pending?.key == key { lock.unlock(); return }
        if Self.disconnectBudgetExhausted(disconnectHistory[key] ?? []) {
            lock.unlock()
            onEvent?(.disconnectSkipped(networkKey: key, why: "Already disconnected from this network recently; alerting only so a spoofed network can't keep knocking you offline."))
            return
        }
        pending?.item.cancel()
        let item = DispatchWorkItem { [weak self] in self?.fireDisconnect(key: key, reason: reason, interface: interface) }
        pending = (key, reason, interface, item)
        lock.unlock()
        onEvent?(.disconnectScheduled(networkKey: key, networkName: name, reason: reason, deadline: Date().addingTimeInterval(grace)))
        queue.asyncAfter(deadline: .now() + max(0, grace), execute: item)
    }

    /// "Stay connected": cancel and remember the choice for this network's security type.
    public func stayConnected() {
        lock.lock(); let p = pending; pending = nil; lock.unlock()
        guard let p else { return }
        p.item.cancel()
        store.setStayConnected(p.key, true)
        onEvent?(.disconnectCancelled(networkKey: p.key))
    }

    /// Runs the pending disconnect immediately (tests / "Disconnect now" button).
    public func firePendingNow() {
        lock.lock(); let p = pending; lock.unlock()
        guard let p else { return }
        p.item.cancel()
        fireDisconnect(key: p.key, reason: p.reason, interface: p.interface)
    }

    private func fireDisconnect(key: String, reason: String, interface: String?) {
        lock.lock()
        guard pending?.key == key else { lock.unlock(); return }
        pending = nil
        let stillHere = current?.key == key
        lock.unlock()
        // Re-check every guard at fire time: user may have trusted it, moved networks, or flipped the setting.
        let n = store.network(key)
        if n?.trusted == true { onEvent?(.disconnectSkipped(networkKey: key, why: "Network is trusted.")); return }
        if !settings.disconnectInsecureWiFi { onEvent?(.disconnectSkipped(networkKey: key, why: "Disconnecting is turned off.")); return }
        if !stillHere { onEvent?(.disconnectSkipped(networkKey: key, why: "Already on a different network.")); return }
        if disassociator.disassociate(interface: interface) {
            lock.lock(); current = nil
            disconnectHistory[key, default: []].append(Date())
            disconnectHistory[key] = disconnectHistory[key]!.filter { Date().timeIntervalSince($0) < 3600 }
            lock.unlock()
            onEvent?(.disconnected(networkKey: key, reason: reason))
        } else {
            onEvent?(.disconnectSkipped(networkKey: key, why: "This process can't disconnect Wi-Fi (dev mode or no permission)."))
        }
    }
}
