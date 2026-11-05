import Foundation
import RampartShared

/// Generates a pf anchor + IP table and the pfctl commands to load them. Never touches /etc/pf.conf.
/// Commands execute only when `dryRun == false` (root daemon).
public final class PFManager: @unchecked Sendable {
    public static let pfctl = "/sbin/pfctl"
    public let anchor: String
    public let table: String
    public let directory: URL
    public var dryRun: Bool
    /// Also drop outbound DNS that is not to the local resolver (aggressive; off by default).
    public var forceLocalDNS: Bool
    /// Block DoT (tcp/853) to stop resolver bypass.
    public var blockDoT: Bool

    public init(anchor: String = "com.apple/250.Rampart", table: String = "rampart_block",
                directory: URL = Paths.effectiveRoot.appendingPathComponent("pf"),
                dryRun: Bool = true, forceLocalDNS: Bool = false, blockDoT: Bool = false) {
        self.anchor = anchor; self.table = table; self.directory = directory; self.dryRun = dryRun
        self.forceLocalDNS = forceLocalDNS; self.blockDoT = blockDoT
    }

    public var anchorURL: URL { directory.appendingPathComponent("rampart.anchor") }
    public var tableURL: URL { directory.appendingPathComponent("block_ips.txt") }
    public var tokenURL: URL { directory.appendingPathComponent("pf.token") }

    public func anchorRules() -> String {
        var r = """
        # Rampart pf anchor (generated; loaded with pfctl -a \(anchor))
        table <\(table)> persist file "\(tableURL.path)"
        block drop out quick log proto { tcp udp } from any to <\(table)>
        block drop in quick log from <\(table)> to any

        """
        if blockDoT { r += "block drop out quick proto tcp from any to any port 853\n" }
        if forceLocalDNS {
            r += "pass out quick proto { tcp udp } from any to { 127.0.0.1, ::1 } port 53\n"
            r += "block drop out quick proto { tcp udp } from any to any port 53\n"
        }
        return r
    }

    // MARK: IP parsing / sanitising

    /// Accepts IPv4/IPv6 addresses and CIDRs. Rejects private, loopback, link-local, multicast,
    /// unspecified and default routes so a feed can never cut off the LAN.
    public static func sanitize(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespaces)
        let parts = s.split(separator: "/", maxSplits: 1)
        guard let first = parts.first, let bytes = DNSWire.addressBytes(String(first)) else { return nil }
        if parts.count == 2 {
            guard let p = Int(parts[1]) else { return nil }
            let minPrefix = bytes.count == 4 ? 8 : 16
            guard p >= minPrefix, p <= bytes.count * 8 else { return nil }
        }
        if bytes.count == 4 {
            let (a, b) = (bytes[0], bytes[1])
            if a == 0 || a == 10 || a == 127 || a >= 224 { return nil }
            if a == 169 && b == 254 { return nil }
            if a == 172 && (16...31).contains(b) { return nil }
            if a == 192 && b == 168 { return nil }
            if a == 100 && (64...127).contains(b) { return nil }   // CGNAT
        } else {
            if bytes.allSatisfy({ $0 == 0 }) || bytes == [UInt8](repeating: 0, count: 15) + [1] { return nil }
            if bytes[0] == 0xFF || bytes[0] & 0xFE == 0xFC || (bytes[0] == 0xFE && bytes[1] & 0xC0 == 0x80) { return nil }
        }
        return s
    }

    /// Parses Feodo/FireHOL style text (one IP/CIDR per line, `#`/`;` comments) and Spamhaus DROP JSON lines
    /// (`{"cidr":"1.2.3.0/24",...}`).
    public static func parseIPList(_ text: String) -> [String] {
        var out: [String] = []
        var seen = Set<String>()
        text.enumerateLines { line, _ in
            var l = line.trimmingCharacters(in: .whitespaces)
            if l.hasPrefix("{") {
                guard let d = l.data(using: .utf8),
                      let obj = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                      let c = obj["cidr"] as? String else { return }
                l = c
            }
            if let i = l.firstIndex(where: { $0 == "#" || $0 == ";" }) { l = String(l[..<i]) }
            l = l.split(whereSeparator: { $0 == " " || $0 == "\t" }).first.map(String.init) ?? ""
            if let ok = sanitize(l), seen.insert(ok).inserted { out.append(ok) }
        }
        return out
    }

    public func tableContents(_ ips: [String]) -> String {
        ips.compactMap(Self.sanitize).joined(separator: "\n") + "\n"
    }

    // MARK: Files and commands

    /// Writes anchor + table files (always; they are inert until loaded).
    public func writeFiles(ips: [String]) throws {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try anchorRules().write(to: anchorURL, atomically: true, encoding: .utf8)
        try tableContents(ips).write(to: tableURL, atomically: true, encoding: .utf8)
    }

    public func loadCommands() -> [NetCommand] {
        [NetCommand(Self.pfctl, ["-a", anchor, "-f", anchorURL.path]),
         NetCommand(Self.pfctl, ["-E"])]   // reference-counted enable; token parsed from output
    }
    public func replaceTableCommand() -> NetCommand {
        NetCommand(Self.pfctl, ["-a", anchor, "-t", table, "-T", "replace", "-f", tableURL.path])
    }
    public func showCommands() -> [NetCommand] {
        [NetCommand(Self.pfctl, ["-a", anchor, "-s", "rules"]),
         NetCommand(Self.pfctl, ["-a", anchor, "-t", table, "-T", "show"])]
    }
    public func unloadCommands(token: String?) -> [NetCommand] {
        var c = [NetCommand(Self.pfctl, ["-a", anchor, "-F", "all"])]
        if let token { c.append(NetCommand(Self.pfctl, ["-X", token])) }
        return c
    }

    /// Extracts the enable token from `pfctl -E` output ("Token : 1234567890").
    public static func parseToken(_ output: String) -> String? {
        for line in output.split(whereSeparator: \.isNewline) where line.lowercased().contains("token") {
            if let v = line.split(separator: ":").last?.trimmingCharacters(in: .whitespaces), !v.isEmpty, v.allSatisfy(\.isNumber) {
                return v
            }
        }
        return nil
    }

    @discardableResult
    public func apply(ips: [String]) throws -> [NetCommandResult] {
        try writeFiles(ips: ips)
        var results: [NetCommandResult] = []
        for c in loadCommands() {
            let r = NetShell.execute(c, dryRun: dryRun)
            if !dryRun, c.arguments == ["-E"], let t = Self.parseToken(r.stdout + r.stderr) {
                try? t.write(to: tokenURL, atomically: true, encoding: .utf8)
            }
            results.append(r)
        }
        results.append(NetShell.execute(replaceTableCommand(), dryRun: dryRun))
        return results
    }

    @discardableResult
    public func remove() -> [NetCommandResult] {
        let token = try? String(contentsOf: tokenURL, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
        let r = unloadCommands(token: token).map { NetShell.execute($0, dryRun: dryRun) }
        if !dryRun { try? FileManager.default.removeItem(at: tokenURL) }
        return r
    }
}
