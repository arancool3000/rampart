import Foundation

/// A parsed wg-quick configuration (one [Interface], one [Peer]: the user's own server).
/// Secrets (private key, preshared key) are carried here only in memory; `VPNProfile` is what is stored on disk.
public struct WGQuickConfig: Equatable {
    public var privateKey: [UInt8]
    public var addresses: [String] = []
    public var dnsServers: [String] = []
    public var dnsSearch: [String] = []
    public var mtu: Int?
    public var listenPort: UInt16?
    public var peerPublicKey: [UInt8]
    public var presharedKey: [UInt8] = []
    public var endpointHost: String
    public var endpointPort: UInt16
    public var allowedIPs: [String] = []
    public var persistentKeepalive: Int?
    /// Lines RamPart understood but will not act on (PostUp scripts, Table, FwMark, ...).
    public var warnings: [String] = []

    public init(privateKey: [UInt8], peerPublicKey: [UInt8], endpointHost: String, endpointPort: UInt16) {
        self.privateKey = privateKey; self.peerPublicKey = peerPublicKey; self.endpointHost = endpointHost; self.endpointPort = endpointPort
    }

    public enum ParseError: Error, CustomStringConvertible, Equatable {
        case empty, missing(String), invalid(String), multiplePeers, notAConfig
        public var description: String {
            switch self {
            case .empty: return "The configuration is empty."
            case .missing(let k): return "The configuration has no \(k)."
            case .invalid(let k): return "The configuration's \(k) isn't valid."
            case .multiplePeers: return "This configuration has more than one [Peer]. RamPart VPN connects to one server, so keep just your home server's [Peer] section."
            case .notAConfig: return "That doesn't look like a WireGuard configuration (it needs [Interface] and [Peer] sections)."
            }
        }
    }

    static let ignoredKeys: Set<String> = ["preup", "postup", "predown", "postdown", "saveconfig", "table", "fwmark"]

    public static func parse(_ text: String) throws -> WGQuickConfig {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw ParseError.empty }
        guard text.utf8.count <= 64 * 1024 else { throw ParseError.invalid("size") }
        var section = ""
        var iface: [String: [String]] = [:]
        var peers: [[String: [String]]] = []
        var warnings: [String] = []
        for raw in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline) {
            var line = String(raw)
            if let h = line.firstIndex(of: "#") { line = String(line[..<h]) }
            line = line.trimmingCharacters(in: .whitespaces)
            if line.isEmpty { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                section = line.dropFirst().dropLast().trimmingCharacters(in: .whitespaces).lowercased()
                if section == "peer" { peers.append([:]) }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { throw ParseError.invalid("line \"\(line.prefix(40))\"") }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            if ignoredKeys.contains(key) {
                warnings.append("Ignored \(line[..<eq].trimmingCharacters(in: .whitespaces)): RamPart never runs scripts or custom routing tables from a configuration.")
                continue
            }
            let values = ["address", "dns", "allowedips"].contains(key)
                ? value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
                : [value]
            switch section {
            case "interface": iface[key, default: []] += values
            case "peer": peers[peers.count - 1][key, default: []] += values
            default: throw ParseError.notAConfig
            }
        }
        guard !iface.isEmpty || !peers.isEmpty else { throw ParseError.notAConfig }
        guard peers.count <= 1 else { throw ParseError.multiplePeers }
        guard let peer = peers.first else { throw ParseError.missing("[Peer] section") }

        guard let pkS = iface["privatekey"]?.first else { throw ParseError.missing("PrivateKey") }
        guard let pk = WGKey.decode(pkS) else { throw ParseError.invalid("PrivateKey") }
        guard let pubS = peer["publickey"]?.first else { throw ParseError.missing("peer PublicKey") }
        guard let pub = WGKey.decode(pubS) else { throw ParseError.invalid("peer PublicKey") }
        guard let epS = peer["endpoint"]?.first else { throw ParseError.missing("Endpoint (your server's address and port)") }
        guard let ep = parseEndpoint(epS) else { throw ParseError.invalid("Endpoint") }

        var c = WGQuickConfig(privateKey: pk, peerPublicKey: pub, endpointHost: ep.host, endpointPort: ep.port)
        c.warnings = warnings
        // Every value that reaches ifconfig / route / scutil / pf must be a plain literal: `IPPrefix.parseAddress`
        // alone accepted "1.2.3.4%anything here" (zone suffix) and kept the raw text, which then went into the
        // kill-switch pf rule and the scutil script (WMS-o9). Counts are capped (each route is a process spawn).
        guard (iface["address"] ?? []).count <= Self.maxAddresses, (iface["dns"] ?? []).count <= Self.maxDNS,
              (peer["allowedips"] ?? []).count <= Self.maxAllowedIPs else { throw ParseError.invalid("size") }
        for a in iface["address"] ?? [] {
            guard IPPrefix.isStrictPrefix(a), IPPrefix.hostAddress(a) != nil else { throw ParseError.invalid("Address \(Self.shown(a))") }
            c.addresses.append(a)
        }
        guard !c.addresses.isEmpty else { throw ParseError.missing("Address") }
        for d in iface["dns"] ?? [] {
            if let ip = IPPrefix.strictLiteral(d) { c.dnsServers.append(IPPrefix.format(ip)) }
            else if isHostname(d) { c.dnsSearch.append(d) }
            else { throw ParseError.invalid("DNS \(Self.shown(d))") }
        }
        if let m = iface["mtu"]?.first {
            guard let v = Int(m), (576...9000).contains(v) else { throw ParseError.invalid("MTU") }
            c.mtu = v
        }
        if let p = iface["listenport"]?.first {
            guard let v = UInt16(p) else { throw ParseError.invalid("ListenPort") }
            c.listenPort = v
        }
        if let psk = peer["presharedkey"]?.first {
            guard let k = WGKey.decode(psk) else { throw ParseError.invalid("PresharedKey") }
            c.presharedKey = k
        }
        for a in peer["allowedips"] ?? [] {
            guard IPPrefix.isStrictPrefix(a), IPPrefix(a) != nil else { throw ParseError.invalid("AllowedIPs \(Self.shown(a))") }
            c.allowedIPs.append(a)
        }
        guard !c.allowedIPs.isEmpty else { throw ParseError.missing("AllowedIPs") }
        if let k = peer["persistentkeepalive"]?.first, k.lowercased() != "off" {
            guard let v = Int(k), (0...65535).contains(v) else { throw ParseError.invalid("PersistentKeepalive") }
            c.persistentKeepalive = v == 0 ? nil : v
        }
        for (k, _) in iface where !["privatekey", "address", "dns", "mtu", "listenport"].contains(k) {
            c.warnings.append("Ignored unknown [Interface] setting \(k).")
        }
        for (k, _) in peer where !["publickey", "presharedkey", "endpoint", "allowedips", "persistentkeepalive"].contains(k) {
            c.warnings.append("Ignored unknown [Peer] setting \(k).")
        }
        return c
    }

    static let maxAddresses = 16, maxDNS = 16, maxAllowedIPs = 256

    /// Error text: never echo a long or control-character-laden value back.
    static func shown(_ s: String) -> String {
        String(String.UnicodeScalarView(s.unicodeScalars.filter { $0.value >= 0x20 && $0.value != 0x7F }).prefix(40))
    }

    /// Port: 1-65535, ASCII digits only (UInt16("+1") would parse).
    static func strictPort<S: StringProtocol>(_ s: S) -> UInt16? {
        guard (1...5).contains(s.count), s.allSatisfy({ $0.isASCII && $0.isNumber }), let p = UInt16(s), p > 0 else { return nil }
        return p
    }

    /// Host is either a strict IP literal (returned in canonical form) or a DNS name.
    public static func parseEndpoint(_ s: String) -> (host: String, port: UInt16)? {
        let t = s.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("[") {
            guard let close = t.firstIndex(of: "]"), t[t.index(after: close)...].hasPrefix(":"),
                  let port = strictPort(t[t.index(close, offsetBy: 2)...]) else { return nil }
            let host = String(t[t.index(after: t.startIndex)..<close])
            guard let ip = IPPrefix.strictLiteral(host), ip.count == 16 else { return nil }
            return (IPPrefix.format(ip), port)
        }
        guard let colon = t.lastIndex(of: ":"), let port = strictPort(t[t.index(after: colon)...]) else { return nil }
        let host = String(t[..<colon])
        guard !host.contains(":") else { return nil }
        if let ip = IPPrefix.strictLiteral(host) { return (IPPrefix.format(ip), port) }
        return isHostname(host) && !host.allSatisfy({ $0.isNumber || $0 == "." }) ? (host, port) : nil
    }

    public static func isHostname(_ s: String) -> Bool {
        guard !s.isEmpty, s.utf8.count <= 253 else { return false }
        return s.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { label in
            !label.isEmpty && label.count <= 63 && !label.hasPrefix("-") && !label.hasSuffix("-")
                && label.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
        }
    }

    public var publicKey: [UInt8]? { try? WGCrypto.publicKey(privateKey) }
    public var mtuOrDefault: Int { mtu ?? 1420 }

    public var isFullTunnel: (v4: Bool, v6: Bool) {
        (allowedIPs.contains { IPPrefix($0)?.length == 0 && IPPrefix($0)?.isIPv6 == false },
         allowedIPs.contains { IPPrefix($0)?.length == 0 && IPPrefix($0)?.isIPv6 == true })
    }

    /// wg-quick text. `redactSecrets` replaces keys with placeholders (for display and logs).
    public func render(redactSecrets: Bool = false) -> String {
        var s = "[Interface]\n"
        s += "PrivateKey = \(redactSecrets ? "(kept in your Keychain)" : WGKey.base64(privateKey))\n"
        s += "Address = \(addresses.joined(separator: ", "))\n"
        if !(dnsServers + dnsSearch).isEmpty { s += "DNS = \((dnsServers + dnsSearch).joined(separator: ", "))\n" }
        if let mtu { s += "MTU = \(mtu)\n" }
        if let listenPort { s += "ListenPort = \(listenPort)\n" }
        s += "\n[Peer]\nPublicKey = \(WGKey.base64(peerPublicKey))\n"
        if !presharedKey.isEmpty { s += "PresharedKey = \(redactSecrets ? "(kept in your Keychain)" : WGKey.base64(presharedKey))\n" }
        s += "Endpoint = \(endpointHost.contains(":") ? "[\(endpointHost)]" : endpointHost):\(endpointPort)\n"
        s += "AllowedIPs = \(allowedIPs.joined(separator: ", "))\n"
        if let k = persistentKeepalive { s += "PersistentKeepalive = \(k)\n" }
        return s
    }
}

/// What is stored on disk (vpn/profile.json): never a private or preshared key.
public struct VPNProfile: Codable, Equatable, Sendable {
    public var id: String
    public var name: String
    public var addresses: [String]
    public var dnsServers: [String]
    public var dnsSearch: [String]
    public var mtu: Int?
    public var listenPort: UInt16?
    public var peerPublicKey: String
    public var hasPresharedKey: Bool
    public var endpointHost: String
    public var endpointPort: UInt16
    public var allowedIPs: [String]
    public var persistentKeepalive: Int?
    public var publicKey: String
    public var createdBy: String   // "import" | "homeServer"
    public var created: Date

    public init(id: String = UUID().uuidString, name: String, config c: WGQuickConfig, createdBy: String, created: Date = Date()) {
        self.id = id; self.name = name
        addresses = c.addresses; dnsServers = c.dnsServers; dnsSearch = c.dnsSearch; mtu = c.mtu; listenPort = c.listenPort
        peerPublicKey = WGKey.base64(c.peerPublicKey); hasPresharedKey = !c.presharedKey.isEmpty
        endpointHost = c.endpointHost; endpointPort = c.endpointPort; allowedIPs = c.allowedIPs
        persistentKeepalive = c.persistentKeepalive
        publicKey = c.publicKey.map(WGKey.base64) ?? ""
        self.createdBy = createdBy; self.created = created
    }

    /// Rebuilds the full config with secrets from the key store.
    public func config(privateKey: [UInt8], presharedKey: [UInt8]) -> WGQuickConfig? {
        guard let pub = WGKey.decode(peerPublicKey) else { return nil }
        var c = WGQuickConfig(privateKey: privateKey, peerPublicKey: pub, endpointHost: endpointHost, endpointPort: endpointPort)
        c.addresses = addresses; c.dnsServers = dnsServers; c.dnsSearch = dnsSearch; c.mtu = mtu; c.listenPort = listenPort
        c.presharedKey = presharedKey; c.allowedIPs = allowedIPs; c.persistentKeepalive = persistentKeepalive
        return c
    }
}

extension IPPrefix {
    /// An IPv4 / IPv6 literal made only of hex digits, '.' and ':' (no zone "%...", brackets or spaces), or nil.
    public static func strictLiteral(_ s: String) -> [UInt8]? {
        guard !s.isEmpty, s.utf8.count <= 45, s.allSatisfy({ $0.isASCII && ($0.isHexDigit || $0 == "." || $0 == ":") }) else { return nil }
        return parseAddress(s)
    }
    /// "literal" or "literal/len" with a plain decimal length.
    public static func isStrictPrefix(_ s: String) -> Bool {
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first, strictLiteral(String(first)) != nil else { return false }
        return parts.count == 1 || ((1...3).contains(parts[1].count) && parts[1].allSatisfy { $0.isASCII && $0.isNumber })
    }
}
