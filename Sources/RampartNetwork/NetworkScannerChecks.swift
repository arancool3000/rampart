import Foundation
import Darwin
import Security
import RampartShared

// Risk checks: risky-port catalogue, DNS resolver verdicts, application-firewall state, listening ports on
// this Mac, and the known-device list. All parsers are pure and fixture-testable.

// MARK: - Risky ports

public struct RiskyPort: Sendable, Hashable {
    public var port: Int
    public var proto: String
    public var service: String
    public var severity: Severity
    public var explanation: String
    public var fix: String

    public func finding() -> NetPortFinding {
        NetPortFinding(port: port, proto: proto, service: service, severity: severity, explanation: explanation, fix: fix)
    }

    /// The fixed list RamPart checks. Nothing else is probed on other devices.
    public static let catalogue: [RiskyPort] = [
        RiskyPort(port: 21, proto: "tcp", service: "FTP", severity: .high,
                  explanation: "FTP sends usernames, passwords and files without encryption. Anyone on this network can read them.",
                  fix: "Turn FTP off on the device and use SFTP or the device's app instead. If it's a NAS or printer, look for 'FTP' in its settings."),
        RiskyPort(port: 23, proto: "tcp", service: "Telnet", severity: .critical,
                  explanation: "Telnet is an old remote-control service with no encryption. It is the most common way home devices get taken over by botnets.",
                  fix: "Disable Telnet in the device's settings. If there is no option, check for a firmware update or replace the device."),
        RiskyPort(port: 445, proto: "tcp", service: "SMB file sharing", severity: .medium,
                  explanation: "Windows-style file sharing is on. That's normal for a NAS or a Mac with File Sharing, but every device on the network can try to log in.",
                  fix: "Make sure sharing uses a strong password and guest access is off. Turn it off if you don't use it (on a Mac: System Settings > General > Sharing)."),
        RiskyPort(port: 3389, proto: "tcp", service: "Remote Desktop (RDP)", severity: .high,
                  explanation: "Remote Desktop lets someone control this computer over the network. Exposed RDP is a frequent ransomware entry point.",
                  fix: "Turn Remote Desktop off unless you rely on it, and never forward this port on your router. Use a VPN for remote access."),
        RiskyPort(port: 5900, proto: "tcp", service: "VNC / Screen Sharing", severity: .high,
                  explanation: "Screen sharing is on. Weak or reused VNC passwords are easy to guess, and many VNC setups have no encryption.",
                  fix: "Turn off Screen Sharing when you don't need it (on a Mac: System Settings > General > Sharing) and use a long password."),
        RiskyPort(port: 1883, proto: "tcp", service: "MQTT", severity: .medium,
                  explanation: "An MQTT message broker is reachable. Smart-home hubs use it; without a password anyone on the network can read or send device commands.",
                  fix: "Enable authentication on the broker (for Home Assistant / Mosquitto, set a username and password) and avoid exposing it to the internet."),
        RiskyPort(port: 554, proto: "tcp", service: "RTSP video stream", severity: .medium,
                  explanation: "A camera-style video stream is reachable. If it still uses a default password, anyone on the network can watch it.",
                  fix: "Change the camera's password from the default, update its firmware, and disable RTSP if you only use the vendor's app."),
        RiskyPort(port: 8080, proto: "tcp", service: "Web admin (alt HTTP)", severity: .low,
                  explanation: "A web interface is served on port 8080, usually an admin page without encryption.",
                  fix: "Check what's listening here. Change any default password and prefer the HTTPS version of the page."),
        RiskyPort(port: 8443, proto: "tcp", service: "Web admin (alt HTTPS)", severity: .info,
                  explanation: "An HTTPS admin interface is reachable on 8443. Encrypted, but worth a strong password.",
                  fix: "Nothing to do if you recognise the device. Otherwise check what it is and change default credentials."),
        RiskyPort(port: 7547, proto: "tcp", service: "TR-069 (ISP remote management)", severity: .high,
                  explanation: "TR-069 lets an internet provider manage a router remotely. Exposed on the home network, it has been abused by worms to take over routers.",
                  fix: "If your ISP doesn't need it, disable TR-069/CWMP in the router settings. Otherwise make sure the router firmware is current."),
        RiskyPort(port: 9100, proto: "tcp", service: "Raw printing (JetDirect)", severity: .low,
                  explanation: "The printer accepts raw print jobs from anyone on the network. Harmless at home, but it's a reminder printers are rarely updated.",
                  fix: "Update the printer firmware and set an admin password on its web page."),
        RiskyPort(port: 32400, proto: "tcp", service: "Plex Media Server", severity: .info,
                  explanation: "A Plex server is running. Fine on its own; just keep it updated, as older versions had remote exploits.",
                  fix: "Keep Plex up to date and avoid enabling remote access without a strong Plex account password and 2FA."),
        RiskyPort(port: 1900, proto: "udp", service: "UPnP / SSDP", severity: .low,
                  explanation: "The device answers UPnP discovery. On its own that's normal; it only becomes a risk on the router, where UPnP can open ports to the internet.",
                  fix: "For smart devices, nothing to do. For the router, see the UPnP finding below."),
    ]

    public static let tcpPorts: [Int] = catalogue.filter { $0.proto == "tcp" }.map(\.port)
    public static func find(_ port: Int, proto: String = "tcp") -> RiskyPort? { catalogue.first { $0.port == port && $0.proto == proto } }
}

// MARK: - DNS resolvers

public enum DNSResolverCheck {
    /// Public resolvers users commonly pick on purpose.
    public static let knownGood: [String: String] = [
        "1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare (malware filtering)", "1.0.0.2": "Cloudflare (malware filtering)",
        "1.1.1.3": "Cloudflare (family)", "1.0.0.3": "Cloudflare (family)",
        "8.8.8.8": "Google", "8.8.4.4": "Google",
        "9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "9.9.9.11": "Quad9", "149.112.112.11": "Quad9", "9.9.9.10": "Quad9 (unfiltered)",
        "208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS", "208.67.222.123": "OpenDNS FamilyShield", "208.67.220.123": "OpenDNS FamilyShield",
        "94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard", "94.140.14.15": "AdGuard (family)", "94.140.15.16": "AdGuard (family)",
        "76.76.2.0": "Control D", "76.76.10.0": "Control D",
        "185.228.168.9": "CleanBrowsing", "185.228.169.9": "CleanBrowsing", "185.228.168.168": "CleanBrowsing", "185.228.169.168": "CleanBrowsing",
        "45.90.28.0": "NextDNS", "45.90.30.0": "NextDNS",
        "100.100.100.100": "Tailscale MagicDNS",
        "2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare", "2606:4700:4700::1112": "Cloudflare (malware filtering)",
        "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
    ]

    /// Parses `scutil --dns` into the resolver addresses of the default (first) resolver block.
    public static func parseScutil(_ text: String) -> [String] {
        var out: [String] = []
        var inResolver = false, seenResolver1 = false
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("resolver #") {
                if line == "resolver #1" && !seenResolver1 { inResolver = true; seenResolver1 = true }
                else { inResolver = false }
                continue
            }
            if line.hasPrefix("DNS configuration (for scoped queries)") { break }
            guard inResolver, line.hasPrefix("nameserver[") else { continue }
            if let c = line.firstIndex(of: ":") {
                let v = line[line.index(after: c)...].trimmingCharacters(in: .whitespaces)
                if !v.isEmpty && !out.contains(v) { out.append(v) }
            }
        }
        return out
    }

    public static func currentServers() -> [String] {
        parseScutil(NetShell.run("/usr/sbin/scutil", ["--dns"], timeout: 5).1)
    }

    public static func verdict(_ server: String, subnet: NetSubnet?, gateway: String?) -> DNSResolverVerdict {
        if server == "127.0.0.1" || server == "::1" { return DNSResolverVerdict(server: server, status: .local, name: "This Mac (local resolver)") }
        if let g = gateway, server == g { return DNSResolverVerdict(server: server, status: .router, name: "Your router") }
        if let v = IPv4.parse(server) {
            if IPv4.isPrivate(v) || IPv4.isLinkLocal(v) {
                let onSubnet = subnet?.contains(server) == true
                return DNSResolverVerdict(server: server, status: onSubnet ? .router : .local, name: onSubnet ? "A device on your network" : "Private network address")
            }
        } else if server.hasPrefix("fe80:") || server.hasPrefix("fd") || server.hasPrefix("fc") {
            return DNSResolverVerdict(server: server, status: .local, name: "Local IPv6 address")
        }
        if let n = knownGood[server.lowercased()] { return DNSResolverVerdict(server: server, status: .knownGood, name: n) }
        return DNSResolverVerdict(server: server, status: .unknown, name: nil)
    }
}

// MARK: - Application firewall

public enum FirewallCheck {
    static let tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    /// Pure parsers for socketfilterfw output lines.
    public static func parseGlobalState(_ s: String) -> Bool? {
        let l = s.lowercased()
        if l.contains("enabled") && !l.contains("disabled") { return true }
        if l.contains("disabled") { return false }
        return nil
    }
    public static func parseBlockAll(_ s: String) -> Bool? {
        let l = s.lowercased()
        if l.contains("block all") { return !l.contains("disabled") && !l.contains("off") }
        return nil
    }
    public static func parseStealth(_ s: String) -> Bool? {
        let l = s.lowercased()
        if l.contains("stealth mode") { return l.contains("enabled") && !l.contains("disabled") }
        return nil
    }
    public static func parseAllowSigned(_ s: String) -> Bool? {
        let l = s.lowercased()
        if l.contains("automatically allow") { return l.contains("enabled") && !l.contains("disabled") }
        return nil
    }

    /// `--listapps` output: `N :  /path/App.app` followed by `( Allow incoming connections )` / `( Block incoming connections )`.
    public static func parseListApps(_ text: String) -> (allowed: [String], blocked: [String]) {
        var allowed: [String] = [], blocked: [String] = []
        var current: String?
        for raw in text.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if let c = line.range(of: " :  ") ?? line.range(of: " : ") , line.first?.isNumber == true {
                current = String(line[c.upperBound...]).trimmingCharacters(in: .whitespaces)
            } else if line.hasPrefix("(") {
                guard let app = current else { continue }
                if line.lowercased().contains("block") { blocked.append(app) } else if line.lowercased().contains("allow") { allowed.append(app) }
                current = nil
            }
        }
        return (allowed, blocked)
    }

    public static func current() -> AppFirewallState {
        var st = AppFirewallState()
        st.enabled = parseGlobalState(NetShell.run(tool, ["--getglobalstate"], timeout: 5).1)
        st.blockAll = parseBlockAll(NetShell.run(tool, ["--getblockall"], timeout: 5).1)
        st.stealth = parseStealth(NetShell.run(tool, ["--getstealthmode"], timeout: 5).1)
        st.allowSigned = parseAllowSigned(NetShell.run(tool, ["--getallowsigned"], timeout: 5).1)
        let apps = parseListApps(NetShell.run(tool, ["--listapps"], timeout: 8).1)
        st.allowedApps = apps.allowed; st.blockedApps = apps.blocked
        return st
    }

    /// Would the application firewall stop inbound connections to this listener? Pure.
    public static func verdict(for path: String?, signing: SigningInfo.Status, exposure: LocalListener.Exposure, state: AppFirewallState) -> LocalListener.FirewallVerdict {
        guard exposure == .network else { return .allowedBuiltIn }   // loopback never crosses the firewall
        guard state.enabled == true else { return .firewallOff }
        if signing == .apple { return .allowedBuiltIn }               // Apple-signed system services pass
        if let p = path {
            if state.blockedApps.contains(where: { p.hasPrefix($0) || $0.hasPrefix(p) }) { return .blocked }
            if state.allowedApps.contains(where: { p.hasPrefix($0) || $0.hasPrefix(p) }) { return .allowed }
        }
        if state.blockAll == true { return .blocked }
        if state.allowSigned == true && (signing == .developerID || signing == .appStore) { return .allowed }
        return .unknown   // macOS asks the user the first time; not recorded yet
    }
}

// MARK: - Listening ports on this Mac

public enum LocalListenerCheck {
    static let wellKnown: [Int: String] = [
        22: "SSH (Remote Login)", 53: "DNS", 80: "HTTP", 88: "Kerberos", 443: "HTTPS", 445: "SMB file sharing", 548: "AFP file sharing",
        631: "Printing (CUPS)", 3283: "Apple Remote Desktop", 3389: "Remote Desktop", 5000: "AirPlay receiver", 5900: "Screen Sharing",
        7000: "AirPlay", 8080: "Web server", 1883: "MQTT", 32400: "Plex", 5353: "Bonjour (mDNS)", 137: "NetBIOS", 139: "NetBIOS",
        2049: "NFS", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 8000: "Dev web server", 3000: "Dev web server",
        5555: "ADB (Android debug)", 49152: "Dynamic (UPnP/AirPlay)", 62078: "iTunes sync",
    ]

    /// Lightweight signing status via SecStaticCode; no RampartSigning dependency.
    public static func signingStatus(path: String) -> SigningInfo.Status {
        let url = URL(fileURLWithPath: path) as CFURL
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(url, [], &code) == errSecSuccess, let code else { return .unknown }
        var apple: SecRequirement?
        if SecRequirementCreateWithString("anchor apple" as CFString, [], &apple) == errSecSuccess, let apple,
           SecStaticCodeCheckValidity(code, [], apple) == errSecSuccess { return .apple }
        var info: CFDictionary?
        let st = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        guard st == errSecSuccess, let d = info as? [String: Any] else { return .unsigned }
        guard d[kSecCodeInfoIdentifier as String] != nil else { return .unsigned }
        if SecStaticCodeCheckValidity(code, [], nil) != errSecSuccess { return .invalid }
        if let flags = d[kSecCodeInfoFlags as String] as? UInt32, flags & 0x2 != 0 { return .adHoc }   // kSecCodeSignatureAdhoc
        if d[kSecCodeInfoTeamIdentifier as String] != nil { return .developerID }
        return .adHoc
    }

    public static func listeners(firewall: AppFirewallState, monitor: ConnectionMonitor = ConnectionMonitor()) -> [LocalListener] {
        let conns = monitor.snapshot(includeListeners: true)
        var seen = Set<String>()
        var out: [LocalListener] = []
        var signingCache: [String: SigningInfo.Status] = [:]
        for c in conns {
            let listening = c.proto == "tcp" ? c.isListening : (c.proto == "udp" && !c.hasRemote && c.localPort != 0)
            guard listening, c.localPort != 0 else { continue }
            let key = "\(c.proto)/\(c.localPort)@\(c.localAddress)"
            guard !seen.contains(key) else { continue }
            seen.insert(key)
            let addr = c.localAddress
            let exposure: LocalListener.Exposure = (addr == "127.0.0.1" || addr == "::1" || addr.hasPrefix("127.")) ? .loopback : .network
            let path = c.processPath ?? ConnectionMonitor.processPath(c.pid)
            let signing: SigningInfo.Status
            if let p = path {
                if let s = signingCache[p] { signing = s } else { signing = signingStatus(path: p); signingCache[p] = signing }
            } else { signing = .unknown }
            out.append(LocalListener(port: Int(c.localPort), proto: c.proto, address: addr, pid: c.pid, processName: c.processName,
                                     processPath: path, signing: signing, exposure: exposure,
                                     firewall: FirewallCheck.verdict(for: path, signing: signing, exposure: exposure, state: firewall),
                                     service: wellKnown[Int(c.localPort)]))
        }
        return out.sorted { ($0.exposure == .network ? 0 : 1, $0.port, $0.proto) < ($1.exposure == .network ? 0 : 1, $1.port, $1.proto) }
    }
}

// MARK: - Known devices (persisted)

/// Remembers every device seen so a scan can say "new since last time". Users can name and trust devices.
public final class KnownDeviceStore: @unchecked Sendable {
    public let url: URL?
    private var devices: [String: KnownDevice] = [:]
    private let lock = NSLock()
    public private(set) var created: Date

    public init(url: URL? = Paths.effectiveRoot.appendingPathComponent("netscan-known-devices.json")) {
        self.url = url
        created = Date()
        if let u = url, let d = try? Data(contentsOf: u), let file = try? JSONDecoder.rampart.decode(File.self, from: d) {
            devices = Dictionary(uniqueKeysWithValues: file.devices.map { ($0.id, $0) })
            created = file.created
        }
    }

    struct File: Codable { var created: Date; var devices: [KnownDevice] }

    public var all: [KnownDevice] { lock.lock(); defer { lock.unlock() }; return devices.values.sorted { $0.lastSeen > $1.lastSeen } }
    public var isEmpty: Bool { lock.lock(); defer { lock.unlock() }; return devices.isEmpty }

    public func device(id: String) -> KnownDevice? { lock.lock(); defer { lock.unlock() }; return devices[id] }

    /// Merges a scan: marks devices never seen before as new (unless the list was empty, i.e. first scan),
    /// applies user names/trust, and records the sighting. Returns the annotated devices.
    public func merge(_ scanned: [NetDevice], at date: Date = Date()) -> [NetDevice] {
        lock.lock(); defer { lock.unlock() }
        let firstScan = devices.isEmpty
        var out: [NetDevice] = []
        for var d in scanned {
            if var k = devices[d.id] {
                d.isNew = false; d.trusted = k.trusted; d.customName = k.name; d.firstSeen = k.firstSeen
                k.lastSeen = date; k.lastIP = d.ip; k.seenCount += 1
                if k.vendor == nil { k.vendor = d.vendor }
                if k.type == .unknown { k.type = d.type }
                devices[d.id] = k
            } else {
                d.isNew = !firstScan && !d.isThisMac; d.firstSeen = date
                devices[d.id] = KnownDevice(id: d.id, mac: d.mac, lastIP: d.ip, name: nil, trusted: d.isThisMac, vendor: d.vendor,
                                            type: d.type, firstSeen: date, lastSeen: date, seenCount: 1)
            }
            out.append(d)
        }
        persist()
        return out
    }

    public func rename(id: String, name: String?) {
        lock.lock(); defer { lock.unlock() }
        guard var k = devices[id] else { return }
        k.name = (name?.isEmpty ?? true) ? nil : name
        devices[id] = k; persist()
    }

    public func setTrusted(id: String, _ trusted: Bool) {
        lock.lock(); defer { lock.unlock() }
        guard var k = devices[id] else { return }
        k.trusted = trusted; devices[id] = k; persist()
    }

    public func forget(id: String) { lock.lock(); devices[id] = nil; persist(); lock.unlock() }
    public func reset() { lock.lock(); devices = [:]; created = Date(); persist(); lock.unlock() }

    private func persist() {
        guard let u = url else { return }
        try? FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
        try? JSONEncoder.rampart.encode(File(created: created, devices: Array(devices.values))).write(to: u, options: .atomic)
    }
}
