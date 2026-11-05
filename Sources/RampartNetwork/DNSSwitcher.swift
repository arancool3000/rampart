import Foundation
import RampartShared

/// Points every network service's DNS at the local filter and restores the originals.
/// Only reads (`-listallnetworkservices`, `-getdnsservers`) run unconditionally; changes are returned as
/// command lists and executed only when `dryRun == false` (root daemon). The original configuration is
/// saved to disk first so a watchdog can restore it if the resolver dies.
public final class DNSSwitcher: @unchecked Sendable {
    public struct ServiceDNS: Codable, Hashable, Sendable {
        public var service: String
        public var enabled: Bool
        /// Empty = DHCP-provided ("There aren't any DNS Servers set").
        public var servers: [String]
        public init(service: String, enabled: Bool, servers: [String]) {
            self.service = service; self.enabled = enabled; self.servers = servers
        }
    }

    public struct Snapshot: Codable, Sendable {
        public var date: Date
        public var services: [ServiceDNS]
    }

    public static let networksetup = "/usr/sbin/networksetup"
    public let resolverAddresses: [String]
    public let snapshotURL: URL
    public var dryRun: Bool

    public init(resolverAddresses: [String] = ["127.0.0.1", "::1"],
                snapshotURL: URL = Paths.effectiveRoot.appendingPathComponent("dns-original.json"),
                dryRun: Bool = true) {
        self.resolverAddresses = resolverAddresses; self.snapshotURL = snapshotURL; self.dryRun = dryRun
    }

    // MARK: Parsing (pure, fixture-tested)

    /// Parses `networksetup -listallnetworkservices`. A leading `*` marks a disabled service.
    public static func parseServices(_ text: String) -> [(name: String, enabled: Bool)] {
        text.split(separator: "\n", omittingEmptySubsequences: true).compactMap { raw in
            let line = String(raw)
            if line.hasPrefix("An asterisk") { return nil }
            if line.hasPrefix("*") { return (String(line.dropFirst()).trimmingCharacters(in: .whitespaces), false) }
            let t = line.trimmingCharacters(in: .whitespaces)
            return t.isEmpty ? nil : (t, true)
        }
    }

    /// Parses `networksetup -getdnsservers <svc>`.
    public static func parseDNSServers(_ text: String) -> [String] {
        if text.contains("aren't any DNS Servers") || text.contains("not a recognized network service") { return [] }
        return text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { DNSWire.addressBytes($0) != nil }
    }

    // MARK: Reading

    public func currentConfiguration() -> [ServiceDNS] {
        let (s, out, _) = NetShell.run(Self.networksetup, ["-listallnetworkservices"])
        guard s == 0 else { return [] }
        return Self.parseServices(out).map { svc in
            let (_, dns, _) = NetShell.run(Self.networksetup, ["-getdnsservers", svc.name])
            return ServiceDNS(service: svc.name, enabled: svc.enabled, servers: Self.parseDNSServers(dns))
        }
    }

    public func isPointingAtUs(_ c: [ServiceDNS]) -> Bool {
        let enabled = c.filter(\.enabled)
        return !enabled.isEmpty && enabled.allSatisfy { $0.servers.first.map(resolverAddresses.contains) ?? false }
    }

    // MARK: Command generation

    public static let flushCommands = [
        NetCommand("/usr/bin/dscacheutil", ["-flushcache"]),
        NetCommand("/usr/bin/killall", ["-HUP", "mDNSResponder"]),
    ]

    public func applyCommands(for services: [ServiceDNS]) -> [NetCommand] {
        services.filter(\.enabled).map {
            NetCommand(Self.networksetup, ["-setdnsservers", $0.service] + resolverAddresses)
        } + Self.flushCommands
    }

    /// Commands that restore `snapshot` (services with no saved servers go back to DHCP via `empty`).
    public func restoreCommands(for snapshot: [ServiceDNS]) -> [NetCommand] {
        snapshot.filter(\.enabled).map { svc in
            // Never "restore" to ourselves (e.g. snapshot taken while already switched).
            let servers = svc.servers.filter { !resolverAddresses.contains($0) }
            return NetCommand(Self.networksetup, ["-setdnsservers", svc.service] + (servers.isEmpty ? ["empty"] : servers))
        } + Self.flushCommands
    }

    // MARK: Snapshot persistence

    public func saveSnapshot(_ services: [ServiceDNS]) throws {
        try FileManager.default.createDirectory(at: snapshotURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder.rampart.encode(Snapshot(date: Date(), services: services)).write(to: snapshotURL, options: .atomic)
    }

    public func loadSnapshot() -> Snapshot? {
        (try? Data(contentsOf: snapshotURL)).flatMap { try? JSONDecoder.rampart.decode(Snapshot.self, from: $0) }
    }

    // MARK: Apply / restore

    /// Saves the original configuration (unless one is already saved and we are already applied), then switches.
    @discardableResult
    public func apply() throws -> [NetCommandResult] {
        let current = currentConfiguration()
        // Dry runs never write the snapshot (the watchdog trusts it). Never overwrite a snapshot with "us".
        if !dryRun, !(isPointingAtUs(current) && loadSnapshot() != nil) { try saveSnapshot(current) }
        return applyCommands(for: current).map { NetShell.execute($0, dryRun: dryRun) }
    }

    /// Restores from the saved snapshot (watchdog / uninstall path). Falls back to DHCP for all services.
    @discardableResult
    public func restore() -> [NetCommandResult] {
        let services = loadSnapshot()?.services
            ?? currentConfiguration().map { ServiceDNS(service: $0.service, enabled: $0.enabled, servers: []) }
        let results = restoreCommands(for: services).map { NetShell.execute($0, dryRun: dryRun) }
        if !dryRun, results.allSatisfy(\.ok) { try? FileManager.default.removeItem(at: snapshotURL) }
        return results
    }
}
