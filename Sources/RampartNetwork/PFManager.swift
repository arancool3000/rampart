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
        // Hardening (hx4): names and paths are interpolated into pf.conf syntax and pfctl arguments, so anything
        // that could break out of a rule (newline, quote, brace, space) falls back to the safe defaults.
        self.anchor = Self.isSafeAnchor(anchor) ? anchor : "com.apple/250.Rampart"
        self.table = Self.isSafeTable(table) ? table : "rampart_block"
        self.directory = Self.isSafePath(directory.path) ? directory
            : Paths.effectiveRoot.appendingPathComponent("pf")
        self.dryRun = dryRun
        self.forceLocalDNS = forceLocalDNS; self.blockDoT = blockDoT
    }

    public static func isSafeAnchor(_ s: String) -> Bool {
        !s.isEmpty && s.count <= 64 && !s.hasPrefix("/") && !s.hasPrefix("-") && !s.contains("..")
            && s.unicodeScalars.allSatisfy { CharacterSet.alphanumerics.contains($0) && $0.isASCII || "._/-".unicodeScalars.contains($0) }
    }
    public static func isSafeTable(_ s: String) -> Bool {
        guard let f = s.unicodeScalars.first, f.isASCII, CharacterSet.letters.contains(f) || f == "_" else { return false }
        return s.count <= 31 && s.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_") }
    }
    public static func isSafePath(_ s: String) -> Bool {
        s.hasPrefix("/") && !s.unicodeScalars.contains { $0.value < 0x20 || $0.value == 0x7F || "\"'{}<>$`\\".unicodeScalars.contains($0) }
    }

    /// Never block these: the DoH upstreams (a bad feed must not take DNS down with it).
    public static let protectedAddresses: [String] = DoHClient.bootstrapAddresses.values.flatMap { $0 }

    /// Ranges a feed may never cover (in whole or part): this-network, RFC 1918, loopback, link-local, CGNAT,
    /// multicast/reserved, and the IPv6 equivalents including IPv4-mapped space.
    static let reservedRanges: [([UInt8], Int)] = [
        ([0, 0, 0, 0], 8), ([10, 0, 0, 0], 8), ([127, 0, 0, 0], 8), ([169, 254, 0, 0], 16), ([172, 16, 0, 0], 12),
        ([192, 168, 0, 0], 16), ([100, 64, 0, 0], 10), ([224, 0, 0, 0], 3),
        ([UInt8](repeating: 0, count: 16), 128), ([UInt8](repeating: 0, count: 15) + [1], 128),
        ([UInt8](repeating: 0, count: 10) + [0xFF, 0xFF, 0, 0, 0, 0], 96), ([UInt8](repeating: 0, count: 16), 96),
        ([0xFC] + [UInt8](repeating: 0, count: 15), 7), ([0xFE, 0x80] + [UInt8](repeating: 0, count: 14), 10),
        ([0xFF] + [UInt8](repeating: 0, count: 15), 8),
    ]

    /// Two prefixes overlap iff they agree on the first min(prefix) bits.
    static func overlaps(_ a: [UInt8], _ pa: Int, _ b: [UInt8], _ pb: Int) -> Bool {
        guard a.count == b.count else { return false }
        let bits = min(pa, pb)
        for i in 0..<a.count {
            let take = max(0, min(8, bits - i * 8))
            if take == 0 { break }
            let mask: UInt8 = take == 8 ? 0xFF : ~(0xFF >> UInt8(take))
            if a[i] & mask != b[i] & mask { return false }
        }
        return true
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
        guard s.count <= 64 else { return nil }
        let parts = s.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard let first = parts.first, var bytes = DNSWire.addressBytes(String(first)) else { return nil }
        let full = bytes.count * 8
        var prefix = full
        if parts.count == 2 {
            // Digits only (Int() would accept "+24").
            guard !parts[1].isEmpty, parts[1].count <= 3, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
                  let p = Int(parts[1]) else { return nil }
            let minPrefix = bytes.count == 4 ? 8 : 16
            guard p >= minPrefix, p <= full else { return nil }
            prefix = p
        }
        // Canonicalise: clear host bits.
        for i in 0..<bytes.count {
            let keep = max(0, min(8, prefix - i * 8))
            bytes[i] &= keep == 8 ? 0xFF : (keep == 0 ? 0 : ~(0xFF >> UInt8(keep)))
        }
        for (net, p) in reservedRanges where overlaps(bytes, prefix, net, p) { return nil }
        for a in protectedAddresses {
            if let pb = DNSWire.addressBytes(a), overlaps(bytes, prefix, pb, pb.count * 8) { return nil }
        }
        let text = DNSWire.addressString(bytes)
        guard !text.isEmpty else { return nil }
        return prefix == full ? text : "\(text)/\(prefix)"
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
