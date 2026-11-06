import Foundation
import RampartShared

// Home-network scanner result types. Owned by N1. Everything here is Codable so the app, the CLI and the
// daemon can pass reports around as JSON.

/// A directly connected IPv4 subnet of this Mac.
public struct NetSubnet: Codable, Hashable, Sendable {
    public var interface: String
    public var address: String          // this Mac's address on the interface
    public var netmask: String
    public var prefix: Int              // CIDR length
    public var network: String          // network address, e.g. 192.168.1.0
    public var gateway: String?
    public var isWiFi: Bool

    public init(interface: String, address: String, netmask: String, prefix: Int, network: String, gateway: String? = nil, isWiFi: Bool = false) {
        self.interface = interface; self.address = address; self.netmask = netmask; self.prefix = prefix
        self.network = network; self.gateway = gateway; self.isWiFi = isWiFi
    }

    public var cidr: String { "\(network)/\(prefix)" }
    /// Usable host addresses (excludes network and broadcast).
    public var hostCount: Int { prefix >= 31 ? (1 << (32 - prefix)) : max(0, (1 << (32 - prefix)) - 2) }
}

/// Why a subnet is refused. The scanner never probes outside the rules encoded here.
public enum NetScopeError: Error, Equatable, Sendable, CustomStringConvertible {
    case notPrivate(String)
    case tooLarge(prefix: Int)
    case linkLocal
    case loopback
    case invalid

    public var description: String {
        switch self {
        case .notPrivate(let n): return "\(n) is not a private (home) network range, so it won't be scanned."
        case .tooLarge(let p): return "/\(p) covers more than 1,022 addresses. RamPart only scans networks of /22 or smaller."
        case .linkLocal: return "Link-local (169.254.x.x) addresses are skipped."
        case .loopback: return "Loopback is not a network."
        case .invalid: return "Not a valid IPv4 subnet."
        }
    }
}

public enum NetDeviceType: String, Codable, Sendable, CaseIterable {
    case router, accessPoint, mac, iPhone, iPad, appleTV, homePod, appleWatch, androidPhone, phone, tablet, computer, laptop,
         printer, camera, tv, streamingStick, speaker, smartPlug, smartLight, hub, thermostat, doorbell, iot, nas, gameConsole,
         raspberryPi, voiceAssistant, unknown

    public var label: String {
        switch self {
        case .router: return "Router"
        case .accessPoint: return "Access point"
        case .mac: return "Mac"
        case .iPhone: return "iPhone"
        case .iPad: return "iPad"
        case .appleTV: return "Apple TV"
        case .homePod: return "HomePod"
        case .appleWatch: return "Apple Watch"
        case .androidPhone: return "Android phone"
        case .phone: return "Phone"
        case .tablet: return "Tablet"
        case .computer: return "Computer"
        case .laptop: return "Laptop"
        case .printer: return "Printer"
        case .camera: return "Camera"
        case .tv: return "TV"
        case .streamingStick: return "Streaming device"
        case .speaker: return "Speaker"
        case .smartPlug: return "Smart plug"
        case .smartLight: return "Smart lighting"
        case .hub: return "Smart-home hub"
        case .thermostat: return "Thermostat"
        case .doorbell: return "Doorbell"
        case .iot: return "Smart device"
        case .nas: return "Network storage"
        case .gameConsole: return "Game console"
        case .raspberryPi: return "Raspberry Pi"
        case .voiceAssistant: return "Voice assistant"
        case .unknown: return "Unknown device"
        }
    }

    /// SF Symbol for the device list and the radar.
    public var symbol: String {
        switch self {
        case .router: return "wifi.router"
        case .accessPoint: return "wifi.square"
        case .mac, .computer: return "desktopcomputer"
        case .laptop: return "laptopcomputer"
        case .iPhone, .phone, .androidPhone: return "iphone"
        case .iPad, .tablet: return "ipad"
        case .appleTV, .streamingStick: return "appletv"
        case .homePod, .speaker: return "homepod"
        case .appleWatch: return "applewatch"
        case .printer: return "printer"
        case .camera: return "web.camera"
        case .tv: return "tv"
        case .smartPlug: return "powerplug"
        case .smartLight: return "lightbulb"
        case .hub: return "homekit"
        case .thermostat: return "thermometer.medium"
        case .doorbell: return "bell"
        case .iot: return "sensor"
        case .nas: return "externaldrive.connected.to.line.below"
        case .gameConsole: return "gamecontroller"
        case .raspberryPi: return "cpu"
        case .voiceAssistant: return "waveform.circle"
        case .unknown: return "questionmark.circle"
        }
    }
}

/// One risky-port check on a device.
public struct NetPortFinding: Codable, Hashable, Identifiable, Sendable {
    public var id: String { "\(proto)/\(port)" }
    public var port: Int
    public var proto: String            // "tcp" or "udp"
    public var service: String          // "Telnet"
    public var severity: Severity
    public var explanation: String
    public var fix: String

    public init(port: Int, proto: String, service: String, severity: Severity, explanation: String, fix: String) {
        self.port = port; self.proto = proto; self.service = service; self.severity = severity
        self.explanation = explanation; self.fix = fix
    }
}

/// A discovered device on the subnet.
public struct NetDevice: Codable, Hashable, Identifiable, Sendable {
    public var id: String               // MAC when known, otherwise "ip:<address>"
    public var ip: String
    public var mac: String?
    public var vendor: String?
    public var hostname: String?        // reverse DNS / mDNS host
    public var mdnsName: String?        // friendly Bonjour instance name ("Living Room TV")
    public var model: String?           // from _device-info TXT or SSDP SERVER header
    public var services: [String]       // Bonjour service types / SSDP ST values
    public var type: NetDeviceType
    public var isGateway: Bool
    public var isThisMac: Bool
    public var openPorts: [NetPortFinding]
    public var discoveredBy: [String]   // "arp", "icmp", "tcp", "mdns", "ssdp"
    public var isNew: Bool              // first time seen since the known-device list was created
    public var trusted: Bool
    public var customName: String?
    public var firstSeen: Date?
    public var lastSeen: Date

    public init(id: String, ip: String, mac: String? = nil, vendor: String? = nil, hostname: String? = nil, mdnsName: String? = nil,
                model: String? = nil, services: [String] = [], type: NetDeviceType = .unknown, isGateway: Bool = false,
                isThisMac: Bool = false, openPorts: [NetPortFinding] = [], discoveredBy: [String] = [], isNew: Bool = false,
                trusted: Bool = false, customName: String? = nil, firstSeen: Date? = nil, lastSeen: Date = Date()) {
        self.id = id; self.ip = ip; self.mac = mac; self.vendor = vendor; self.hostname = hostname; self.mdnsName = mdnsName
        self.model = model; self.services = services; self.type = type; self.isGateway = isGateway; self.isThisMac = isThisMac
        self.openPorts = openPorts; self.discoveredBy = discoveredBy; self.isNew = isNew; self.trusted = trusted
        self.customName = customName; self.firstSeen = firstSeen; self.lastSeen = lastSeen
    }

    /// Best display name: user label > Bonjour name > hostname > vendor + type > IP.
    public var displayName: String {
        if let n = customName, !n.isEmpty { return n }
        if isThisMac { return "This Mac" }
        if let n = mdnsName, !n.isEmpty { return n }
        if let h = hostname, !h.isEmpty { return h.hasSuffix(".local") ? String(h.dropLast(6)) : h }
        if let v = vendor { return type == .unknown ? "\(v) device" : "\(v) \(type.label.lowercased())" }
        return type == .unknown ? ip : type.label
    }

    public var worstSeverity: Severity { openPorts.map(\.severity).max() ?? .info }
}

/// A network-level finding (router, DNS, new device, this Mac).
public struct NetFinding: Codable, Hashable, Identifiable, Sendable {
    public enum Kind: String, Codable, Sendable { case router, dns, upnp, device, newDevice, localListener, wifi, scope }
    public var id: String
    public var kind: Kind
    public var severity: Severity
    public var title: String
    public var detail: String
    public var fix: String
    public var deviceID: String?

    public init(id: String, kind: Kind, severity: Severity, title: String, detail: String, fix: String, deviceID: String? = nil) {
        self.id = id; self.kind = kind; self.severity = severity; self.title = title; self.detail = detail; self.fix = fix; self.deviceID = deviceID
    }
}

public struct DNSResolverVerdict: Codable, Hashable, Sendable {
    public enum Status: String, Codable, Sendable { case router, knownGood, local, unknown }
    public var server: String
    public var status: Status
    public var name: String?            // "Cloudflare", "Quad9", "Your router"
    public init(server: String, status: Status, name: String? = nil) { self.server = server; self.status = status; self.name = name }
}

public struct RouterReport: Codable, Hashable, Sendable {
    public var ip: String
    public var mac: String?
    public var vendor: String?
    public var httpOpen: Bool
    public var httpsOpen: Bool
    public var httpRedirectsToHTTPS: Bool
    public var httpServerHeader: String?
    public var upnpIGD: Bool
    public var upnpLocation: String?
    public var dnsServers: [String]
    public var dnsVerdicts: [DNSResolverVerdict]
    public var gatewayMACChanged: Bool
    public var macChangeDetail: String?

    public init(ip: String, mac: String? = nil, vendor: String? = nil, httpOpen: Bool = false, httpsOpen: Bool = false,
                httpRedirectsToHTTPS: Bool = false, httpServerHeader: String? = nil, upnpIGD: Bool = false, upnpLocation: String? = nil,
                dnsServers: [String] = [], dnsVerdicts: [DNSResolverVerdict] = [], gatewayMACChanged: Bool = false, macChangeDetail: String? = nil) {
        self.ip = ip; self.mac = mac; self.vendor = vendor; self.httpOpen = httpOpen; self.httpsOpen = httpsOpen
        self.httpRedirectsToHTTPS = httpRedirectsToHTTPS; self.httpServerHeader = httpServerHeader; self.upnpIGD = upnpIGD
        self.upnpLocation = upnpLocation; self.dnsServers = dnsServers; self.dnsVerdicts = dnsVerdicts
        self.gatewayMACChanged = gatewayMACChanged; self.macChangeDetail = macChangeDetail
    }

    /// Admin page reachable over plain HTTP with no HTTPS alternative.
    public var adminHTTPOnly: Bool { httpOpen && !httpsOpen && !httpRedirectsToHTTPS }
}

/// A port this Mac is listening on.
public struct LocalListener: Codable, Hashable, Identifiable, Sendable {
    public enum Exposure: String, Codable, Sendable { case loopback, network }
    public enum FirewallVerdict: String, Codable, Sendable { case firewallOff, blocked, allowed, allowedBuiltIn, unknown }
    public var id: String { "\(proto)/\(port)@\(address)" }
    public var port: Int
    public var proto: String
    public var address: String
    public var pid: Int32
    public var processName: String
    public var processPath: String?
    public var signing: SigningInfo.Status
    public var exposure: Exposure
    public var firewall: FirewallVerdict
    public var service: String?

    public init(port: Int, proto: String, address: String, pid: Int32, processName: String, processPath: String?,
                signing: SigningInfo.Status, exposure: Exposure, firewall: FirewallVerdict, service: String? = nil) {
        self.port = port; self.proto = proto; self.address = address; self.pid = pid; self.processName = processName
        self.processPath = processPath; self.signing = signing; self.exposure = exposure; self.firewall = firewall; self.service = service
    }
}

/// Firewall state parsed from `socketfilterfw`.
public struct AppFirewallState: Codable, Hashable, Sendable {
    public var enabled: Bool?
    public var blockAll: Bool?
    public var stealth: Bool?
    public var allowSigned: Bool?
    public var blockedApps: [String]    // app paths/names explicitly blocked
    public var allowedApps: [String]
    public init(enabled: Bool? = nil, blockAll: Bool? = nil, stealth: Bool? = nil, allowSigned: Bool? = nil, blockedApps: [String] = [], allowedApps: [String] = []) {
        self.enabled = enabled; self.blockAll = blockAll; self.stealth = stealth; self.allowSigned = allowSigned
        self.blockedApps = blockedApps; self.allowedApps = allowedApps
    }
}

public struct NetScanProgress: Sendable {
    public enum Phase: String, Sendable { case preparing, discovering, identifying, checkingPorts, checkingRouter, checkingThisMac, finishing }
    public var phase: Phase
    public var fraction: Double
    public var message: String
    public var devicesSoFar: Int
    public init(phase: Phase, fraction: Double, message: String, devicesSoFar: Int = 0) {
        self.phase = phase; self.fraction = fraction; self.message = message; self.devicesSoFar = devicesSoFar
    }
}

public struct NetScanReport: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var date: Date
    public var duration: Double
    public var subnet: NetSubnet
    public var devices: [NetDevice]
    public var router: RouterReport?
    public var localListeners: [LocalListener]
    public var firewall: AppFirewallState
    public var findings: [NetFinding]
    public var score: Int               // 0...100
    public var probesSent: Int
    public var limitations: [String]    // honest notes about what could not be checked
    public var wifiSecurity: String?
    public var wifiWeak: Bool

    public init(id: UUID = UUID(), date: Date = Date(), duration: Double, subnet: NetSubnet, devices: [NetDevice], router: RouterReport?,
                localListeners: [LocalListener], firewall: AppFirewallState, findings: [NetFinding], score: Int, probesSent: Int,
                limitations: [String], wifiSecurity: String? = nil, wifiWeak: Bool = false) {
        self.id = id; self.date = date; self.duration = duration; self.subnet = subnet; self.devices = devices; self.router = router
        self.localListeners = localListeners; self.firewall = firewall; self.findings = findings; self.score = score
        self.probesSent = probesSent; self.limitations = limitations; self.wifiSecurity = wifiSecurity; self.wifiWeak = wifiWeak
    }

    public var newDevices: [NetDevice] { devices.filter { $0.isNew && !$0.isThisMac } }
    public var gateway: NetDevice? { devices.first { $0.isGateway } }
}

/// A device the user has seen before (persisted). Keyed by MAC when known, else by IP.
public struct KnownDevice: Codable, Hashable, Identifiable, Sendable {
    public var id: String
    public var mac: String?
    public var lastIP: String
    public var name: String?
    public var trusted: Bool
    public var vendor: String?
    public var type: NetDeviceType
    public var firstSeen: Date
    public var lastSeen: Date
    public var seenCount: Int

    public init(id: String, mac: String? = nil, lastIP: String, name: String? = nil, trusted: Bool = false, vendor: String? = nil,
                type: NetDeviceType = .unknown, firstSeen: Date = Date(), lastSeen: Date = Date(), seenCount: Int = 1) {
        self.id = id; self.mac = mac; self.lastIP = lastIP; self.name = name; self.trusted = trusted; self.vendor = vendor
        self.type = type; self.firstSeen = firstSeen; self.lastSeen = lastSeen; self.seenCount = seenCount
    }
}

// MARK: - Scoring

public enum NetScanScoring {
    /// 0–100. Starts at 100 and subtracts per finding by severity; several same-kind findings decay so one
    /// chatty printer cannot zero the score. New untrusted devices cost a little (max 10 in total).
    public static func score(findings: [NetFinding], newUntrustedDevices: Int) -> Int {
        var score = 100.0
        var perKind: [NetFinding.Kind: Int] = [:]
        for f in findings.sorted(by: { $0.severity > $1.severity }) where f.kind != .newDevice {
            let n = perKind[f.kind, default: 0]
            perKind[f.kind] = n + 1
            let base: Double
            switch f.severity {
            case .critical: base = 30
            case .high: base = 18
            case .medium: base = 9
            case .low: base = 3
            case .info: base = 0
            }
            score -= base / Double(1 << min(n, 4))   // 1, 1/2, 1/4, ...
        }
        score -= Double(min(newUntrustedDevices, 5)) * 2
        return max(0, min(100, Int(score.rounded())))
    }

    public static func label(for score: Int) -> String {
        switch score {
        case 90...: return "Looks good"
        case 75..<90: return "Mostly fine"
        case 50..<75: return "Needs attention"
        default: return "At risk"
        }
    }
}
