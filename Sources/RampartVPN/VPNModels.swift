import Foundation

/// IPC payloads for `IPCRequest.vpn(op:body:)` -> `IPCResponse.vpn(Data)` (JSON of `VPNReply`).
public enum VPNOp: String, Codable, CaseIterable, Sendable {
    case status, connect, disconnect, importConfig, setupHome, setOptions, remove
    /// Strengthening / read-only ops vs. ones that turn protection down (IPCAuthz level).
    public var weakens: Bool { self == .disconnect || self == .remove || self == .setOptions }
    public var readOnly: Bool { self == .status }
}

public struct VPNRequestBody: Codable, Equatable, Sendable {
    public var text: String?
    public var name: String?
    public var host: String?
    public var port: UInt16?
    public var autoConnect: Bool?
    public var killSwitch: Bool?
    /// connect: "user" or "auto: <why>" (auto connects only when Auto-connect is on).
    public var reason: String?
    public init(text: String? = nil, name: String? = nil, host: String? = nil, port: UInt16? = nil, autoConnect: Bool? = nil,
                killSwitch: Bool? = nil, reason: String? = nil) {
        self.text = text; self.name = name; self.host = host; self.port = port; self.autoConnect = autoConnect
        self.killSwitch = killSwitch; self.reason = reason
    }
}

public enum VPNPhase: String, Codable, Sendable {
    case notConfigured, disconnected, connecting, connected, reconnecting, suspendedForLockdown, failed
    public var label: String {
        switch self {
        case .notConfigured: return "Not set up"
        case .disconnected: return "Off"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .reconnecting: return "Reconnecting…"
        case .suspendedForLockdown: return "Paused by Emergency Lockdown"
        case .failed: return "Couldn't connect"
        }
    }
    public var isActive: Bool { self == .connecting || self == .connected || self == .reconnecting || self == .suspendedForLockdown }
}

public struct VPNOptions: Codable, Equatable, Sendable {
    public var autoConnect = false
    public var killSwitch = false
    public init() {}
}

public struct VPNStatus: Codable, Equatable, Sendable {
    public var phase: VPNPhase = .notConfigured
    public var profile: VPNProfile?
    public var options = VPNOptions()
    public var interface: String?
    public var endpointIP: String?
    public var stats = WGStats()
    public var connectedSince: Date?
    public var lastHandshake: Date?
    public var killSwitchEngaged = false
    public var dnsMode: String?
    public var error: String?
    public var notes: [String] = []
    /// True when RamPart can create the tunnel (installed system service). Otherwise connects are handshake-only tests.
    public var canRouteTraffic = false
    public var dryRunCommands: [String] = []
    public var keyStore: String = ""
    public var lastReason: String?
    public init() {}

    public func handshakeAge(now: Date = Date()) -> TimeInterval? { lastHandshake.map { now.timeIntervalSince($0) } }
}

public struct VPNReply: Codable, Equatable, Sendable {
    public var status: VPNStatus
    public var kit: HomeServerKit?
    public var warnings: [String] = []
    public init(status: VPNStatus, kit: HomeServerKit? = nil, warnings: [String] = []) { self.status = status; self.kit = kit; self.warnings = warnings }
}

/// When to connect automatically, from the public Wi-Fi guard's assessment of the joined network.
public enum VPNAutoConnectPolicy {
    public struct Input: Equatable {
        public var onWiFi: Bool
        public var trusted: Bool
        public var insecure: Bool
        public var captivePortal: Bool?
        public var attacked: Bool
        public var networkName: String
        public init(onWiFi: Bool, trusted: Bool, insecure: Bool, captivePortal: Bool?, attacked: Bool, networkName: String) {
            self.onWiFi = onWiFi; self.trusted = trusted; self.insecure = insecure; self.captivePortal = captivePortal
            self.attacked = attacked; self.networkName = networkName
        }
    }
    public enum Decision: Equatable { case connect(String), wait(String), none }

    public static func decide(_ i: Input) -> Decision {
        guard i.onWiFi else { return .none }
        if i.trusted && !i.attacked { return .none }
        if i.captivePortal == true { return .wait("\(i.networkName) wants you to sign in first; RamPart connects the VPN once you're online.") }
        if i.attacked { return .connect("auto: \(i.networkName) looks tampered with") }
        if i.insecure { return .connect("auto: \(i.networkName) is public Wi-Fi without encryption") }
        return .connect("auto: \(i.networkName) isn't one of your trusted networks")
    }
}
