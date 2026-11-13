import Foundation
import RampartShared

// App Firewall without a Network Extension: per-app connection listing (libproc), byte counts (nettop), host names
// from the DNS answer cache, and "block this app" as pf rules for the destinations the app uses plus DNS blocks for
// the names it resolved. Existing connections are cut with `pfctl -k` (state kill). Honest limit: blocking is by
// destination, so an app that moves to new servers can get through until RamPart sees and adds them.

public enum FirewallDecision: String, Codable, Sendable { case allow, block, askLater }

public struct AppEndpoint: Codable, Hashable, Sendable {
    public var proto: String
    public var localAddress: String
    public var localPort: UInt16
    public var remoteAddress: String
    public var remotePort: UInt16
    public var host: String?
    /// Always nil: RamPart ships no offline IP-to-country database (and won't send your connections to a web API).
    public var country: String?
    public var state: String?
}

public struct AppTraffic: Codable, Hashable, Identifiable, Sendable {
    public var id: String { key }
    /// Bundle path for apps (helpers roll up to their outer .app), else the executable path, else the process name.
    public var key: String
    public var name: String
    public var path: String?
    public var signing: String          // SigningInfo.Status raw value
    public var signerLabel: String
    public var teamID: String?
    public var pids: [Int32]
    public var endpoints: [AppEndpoint]
    public var bytesIn: UInt64
    public var bytesOut: UInt64
    public var decision: FirewallDecision?
    public var untrusted: Bool
}

public struct FirewallPrompt: Codable, Hashable, Identifiable, Sendable {
    public var id: UUID
    public var key: String
    public var name: String
    public var path: String?
    public var signerLabel: String
    public var host: String?
    public var address: String
    public var port: UInt16
    public var date: Date
}

public struct FirewallRule: Codable, Hashable, Sendable {
    public var key: String
    public var name: String
    public var decision: FirewallDecision
    public var date: Date
    /// askLater: no new prompt for this app before this time.
    public var until: Date?
    public var blockedAddresses: [String] = []
    public var blockedDomains: [String] = []
    /// Destinations not blocked, with the reason ("shared with Safari", "local network").
    public var notes: [String] = []
}

public struct AppBlockPlan: Codable, Sendable {
    public var key: String
    public var name: String
    public var addresses: [String]
    public var domains: [String]
    public var sharedAddresses: [String]
    public var sharedDomains: [String]
    public var localAddresses: [String]
    public var killCommands: [NetCommand]
    /// o4: destinations macOS or RamPart rely on (never blocked, whatever app also used them).
    public var protectedAddresses: [String]? = nil
    public var protectedDomains: [String]? = nil
}

public struct AppFirewallStatus: Codable, Sendable {
    public var apps: [AppTraffic]
    public var prompts: [FirewallPrompt]
    public var rules: [FirewallRule]
    /// pf rules really load (root daemon, no RAMPART_NO_PRIVILEGED_TOOLS); otherwise every command is a dry run.
    public var enforcing: Bool
    public var lastCommands: [String]
    public var note: String?
    public var updated: Date
    public static let limitation = "Blocks by destination; an app that changes servers may get through. Full per-app blocking needs Apple's Network Extension permission."
    public static let countryNote = "Country isn't shown: RamPart has no offline location database and won't send your connections to an online service."
}

public final class AppFirewall: @unchecked Sendable {
    public typealias SignerLookup = (String) -> SigningInfo?

    private struct State: Codable {
        var rules: [String: FirewallRule] = [:]
        var seen: [String: Date] = [:]
        var addresses: [String: [String]] = [:]   // app key -> remote addresses seen (most recent last)
        var domains: [String: [String]] = [:]     // app key -> host names seen
        var names: [String: String] = [:]
    }

    public let stateURL: URL
    public let pf: PFManager
    public let dryRun: Bool
    private let signer: SignerLookup
    private let lock = NSLock()
    private var state = State()
    private var ipToHost: [String: String] = [:]
    private var lastApps: [AppTraffic] = []
    private var prompts: [FirewallPrompt] = []
    private var lastCommands: [String] = []
    private var lastNote: String?
    private var baselined = false
    static let historyCap = 256

    /// - Parameters:
    ///   - dryRun: true unless running as the real root daemon with privileged tools allowed.
    public init(stateURL: URL, pfDirectory: URL, dryRun: Bool, signer: @escaping SignerLookup) {
        self.stateURL = stateURL; self.dryRun = dryRun; self.signer = signer
        pf = PFManager(anchor: "com.apple/251.RampartFirewall", table: "rampart_appfw", directory: pfDirectory, dryRun: dryRun)
        if let d = try? Data(contentsOf: stateURL), let s = try? JSONDecoder.rampart.decode(State.self, from: d) {
            state = s; baselined = !s.seen.isEmpty
        }
    }

    // MARK: DNS answer cache

    /// Feed every DNS answer (from the local filter's query log): address -> the name that resolved to it.
    public func noteDNS(name: String, answers: [String]) {
        guard !name.isEmpty else { return }
        lock.lock(); defer { lock.unlock() }
        for a in answers where DNSWire.addressBytes(a) != nil { ipToHost[a] = name }
        if ipToHost.count > 30_000 { ipToHost.removeAll(keepingCapacity: true) }
    }

    public func host(for address: String) -> String? { lock.lock(); defer { lock.unlock() }; return ipToHost[address] }

    // MARK: Grouping

    /// Rolls helpers up to their outermost .app bundle.
    public static func appKey(path: String?, name: String) -> String {
        guard let path, !path.isEmpty else { return name }
        if let r = path.range(of: ".app/") { return String(path[..<r.lowerBound]) + ".app" }
        return path
    }

    public static func displayName(key: String, fallback: String) -> String {
        guard key.hasPrefix("/") else { return fallback }
        let last = (key as NSString).lastPathComponent
        return last.hasSuffix(".app") ? String(last.dropLast(4)) : last
    }

    public static func signerLabel(_ s: SigningInfo?) -> String {
        guard let s else { return "Unknown" }
        switch s.status {
        case .apple: return "Apple"
        case .developerID: return "Developer ID" + (s.teamID.map { " (\($0))" } ?? "")
        case .appStore: return "App Store" + (s.teamID.map { " (\($0))" } ?? "")
        case .adHoc: return "Ad-hoc signed (no developer identity)"
        case .unsigned: return "Unsigned"
        case .invalid: return "Invalid signature"
        case .revoked: return "Revoked certificate"
        case .unknown: return "Unknown"
        }
    }

    public static func isUntrusted(_ s: SigningInfo?) -> Bool {
        guard let s else { return false }
        return [.unsigned, .adHoc, .invalid, .revoked].contains(s.status)
    }

    /// Never offered for blocking: macOS itself and RamPart.
    /// o4: only the SIP-protected system paths count as macOS (`/usr/local` is user/Homebrew-writable), and only
    /// RamPart's installed locations count as RamPart. A name match anywhere (`~/Downloads/Rampart.app`,
    /// `/tmp/x/rampartd`) used to make malware unblockable just by naming itself after RamPart.
    public static func protectedKey(_ key: String) -> String? {
        let path = key.hasPrefix("/") ? (key as NSString).standardizingPath : key
        if path.contains("/../") || path.hasSuffix("/..") { return nil }
        let systemPrefixes = ["/System/", "/usr/", "/sbin/", "/bin/", "/Library/Apple/"]
        if systemPrefixes.contains(where: path.hasPrefix), !path.hasPrefix("/usr/local/") {
            return "Blocking parts of macOS could break networking for everything."
        }
        let low = path.lowercased()
        if low == "/applications/rampart.app" || low.hasPrefix("/library/privilegedhelpertools/app.rampart.") {
            return "RamPart can't block itself."
        }
        return nil
    }

    /// o4: names macOS and RamPart need (Apple services, OCSP/updates/time/captive portal, the DoH upstreams, the
    /// feed hosts and RamPart's own services). Blocks are global (DNS + pf, no per-app filtering), so blocking an
    /// app that also touched one of these would break the whole Mac or RamPart itself.
    public static let protectedDomainSuffixes: [String] = [
        "apple.com", "icloud.com", "icloud-content.com", "mzstatic.com", "cdn-apple.com", "aaplimg.com", "apple-dns.net",
        "apple-cloudkit.com", "apple.news", "me.com", "itunes.com", "push-apple.com.akadns.net", "apple.com.akadns.net",
        "cloudflare-dns.com", "quad9.net", "dns.google",
        "cdn.jsdelivr.net", "malware-filter.gitlab.io", "abuse.ch", "pwnedpasswords.com", "haveibeenpwned.com",
        "generativelanguage.googleapis.com", "raw.githubusercontent.com",
    ]

    public static func isProtectedDomain(_ raw: String) -> Bool {
        let n = DNSWire.normalize(raw)
        if DoHClient.bootstrapAddresses[n] != nil { return true }
        return protectedDomainSuffixes.contains { n == $0 || n.hasSuffix("." + $0) }
    }

    /// o4: run-time protected addresses (the original DNS servers the watchdog restores to, VPN endpoints).
    public var extraProtectedAddresses: [String] {
        get { lock.lock(); defer { lock.unlock() }; return pf.alsoProtect }
        set { lock.lock(); pf.alsoProtect = newValue; lock.unlock() }
    }

    /// Apple's own 17.0.0.0/8, the DoH upstreams and public resolvers, run-time extras, and any address the DNS
    /// log ties to a protected name.
    func isProtectedAddressLocked(_ a: String) -> Bool {
        if let b = DNSWire.addressBytes(a), b.count == 4, b[0] == 17 { return true }
        if PFManager.sanitize(a) != nil, PFManager.sanitize(a, protecting: pf.alsoProtect) == nil { return true }
        if PFManager.protectedAddresses.contains(a) { return true }
        if let h = ipToHost[a], Self.isProtectedDomain(h) { return true }
        return false
    }

    static func isLocal(_ address: String) -> Bool { PFManager.sanitize(address) == nil }

    /// `nettop -P -L 1 -x -J bytes_in,bytes_out` CSV: `name.pid,bytes_in,bytes_out,` -> pid: (in, out).
    public static func parseNettop(_ text: String) -> [Int32: (UInt64, UInt64)] {
        var out: [Int32: (UInt64, UInt64)] = [:]
        for line in text.split(whereSeparator: \.isNewline) {
            let f = line.split(separator: ",", omittingEmptySubsequences: false)
            guard f.count >= 3, let dot = f[0].lastIndex(of: "."), let pid = Int32(f[0][f[0].index(after: dot)...]),
                  let bi = UInt64(f[1].trimmingCharacters(in: .whitespaces)), let bo = UInt64(f[2].trimmingCharacters(in: .whitespaces)) else { continue }
            out[pid] = (bi, bo)
        }
        return out
    }

    /// Per-process byte totals (unprivileged, no prompt). Empty if nettop is unavailable.
    public static func byteCounts() -> [Int32: (UInt64, UInt64)] {
        guard FileManager.default.isExecutableFile(atPath: "/usr/bin/nettop") else { return [:] }
        let (_, out, _) = NetShell.run("/usr/bin/nettop", ["-P", "-L", "1", "-x", "-J", "bytes_in,bytes_out"], timeout: 10)
        return parseNettop(out)
    }

    // MARK: Tick

    /// Groups a connection snapshot by app, updates history, extends blocks to new destinations and returns
    /// prompts for unknown untrusted apps connecting out for the first time.
    @discardableResult
    public func update(connections: [NetworkConnection], bytes: [Int32: (UInt64, UInt64)] = [:], now: Date = Date()) -> [FirewallPrompt] {
        let remote = connections.filter { $0.hasRemote && !$0.isListening && $0.remoteAddress != "127.0.0.1" && $0.remoteAddress != "::1" }
        var groups: [String: [NetworkConnection]] = [:]
        for c in remote { groups[Self.appKey(path: c.processPath, name: c.processName), default: []].append(c) }

        var apps: [AppTraffic] = []
        var newPrompts: [FirewallPrompt] = []
        var blockedNewDestinations = false
        lock.lock()
        // Expire "ask later".
        for (k, r) in state.rules where r.decision == .askLater && (r.until ?? .distantPast) < now { state.rules[k] = nil }
        for (key, conns) in groups {
            let first = conns[0]
            let sig = first.processPath.map(signer) ?? nil
            let name = Self.displayName(key: key, fallback: first.processName)
            state.names[key] = name
            var eps: [AppEndpoint] = []
            var seenEP = Set<String>()
            for c in conns {
                let ep = AppEndpoint(proto: c.proto, localAddress: c.localAddress, localPort: c.localPort, remoteAddress: c.remoteAddress,
                                     remotePort: c.remotePort, host: ipToHost[c.remoteAddress], country: nil, state: c.state)
                if seenEP.insert("\(ep.proto)|\(ep.remoteAddress)|\(ep.remotePort)|\(ep.localPort)").inserted { eps.append(ep) }
                Self.remember(&state.addresses[key, default: []], c.remoteAddress)
                if let h = ep.host { Self.remember(&state.domains[key, default: []], h) }
            }
            let pids = Array(Set(conns.map(\.pid))).sorted()
            var bi: UInt64 = 0, bo: UInt64 = 0
            for p in pids { if let b = bytes[p] { bi &+= b.0; bo &+= b.1 } }
            let untrusted = Self.isUntrusted(sig)
            let rule = state.rules[key]
            apps.append(AppTraffic(key: key, name: name, path: first.processPath, signing: (sig?.status ?? .unknown).rawValue,
                                   signerLabel: Self.signerLabel(sig), teamID: sig?.teamID, pids: pids, endpoints: eps,
                                   bytesIn: bi, bytesOut: bo, decision: rule?.decision, untrusted: untrusted))
            // A blocked app that reached a new destination: add it (best effort; see `limitation`).
            if rule?.decision == .block, eps.contains(where: { !(rule?.blockedAddresses.contains($0.remoteAddress) ?? true) && !Self.isLocal($0.remoteAddress) }) {
                blockedNewDestinations = true
            }
            let firstTime = state.seen[key] == nil
            if firstTime { state.seen[key] = now }
            if baselined, firstTime, untrusted, rule == nil, Self.protectedKey(key) == nil,
               !prompts.contains(where: { $0.key == key }) {
                let c = conns.first { !Self.isLocal($0.remoteAddress) } ?? first
                let p = FirewallPrompt(id: UUID(), key: key, name: name, path: first.processPath, signerLabel: Self.signerLabel(sig),
                                       host: ipToHost[c.remoteAddress], address: c.remoteAddress, port: c.remotePort, date: now)
                prompts.append(p); newPrompts.append(p)
            }
        }
        if prompts.count > 50 { prompts.removeFirst(prompts.count - 50) }
        baselined = true
        lastApps = apps.sorted { ($0.untrusted ? 0 : 1, $0.name.lowercased()) < ($1.untrusted ? 0 : 1, $1.name.lowercased()) }
        lock.unlock()
        if blockedNewDestinations { _ = try? reapply(now: now) }
        save()
        return newPrompts
    }

    static func remember(_ list: inout [String], _ v: String) {
        if let i = list.firstIndex(of: v) { list.remove(at: i) }
        list.append(v)
        if list.count > historyCap { list.removeFirst(list.count - historyCap) }
    }

    // MARK: Decisions

    /// What blocking `key` would do (no side effects).
    public func plan(key: String) -> AppBlockPlan {
        lock.lock(); defer { lock.unlock() }
        return planLocked(key: key)
    }

    private func planLocked(key: String) -> AppBlockPlan {
        let mine = state.addresses[key] ?? [], myDomains = state.domains[key] ?? []
        // Destinations other (not blocked) apps also use: blocking them would cut those apps off too.
        var othersAddr = Set<String>(), othersDom = Set<String>()
        for (k, v) in state.addresses where k != key && state.rules[k]?.decision != .block { othersAddr.formUnion(v) }
        for (k, v) in state.domains where k != key && state.rules[k]?.decision != .block { othersDom.formUnion(v) }
        var addrs: [String] = [], shared: [String] = [], local: [String] = [], prot: [String] = []
        for a in mine {
            if isProtectedAddressLocked(a) { prot.append(a) } else if Self.isLocal(a) { local.append(a) }
            else if othersAddr.contains(a) { shared.append(a) } else { addrs.append(a) }
        }
        var doms: [String] = [], sharedD: [String] = [], protD: [String] = []
        for d in myDomains {
            guard DomainBlocklist.normalizeDomain(Substring(d)) != nil else { continue }
            if Self.isProtectedDomain(d) { protD.append(d) }
            else if othersDom.contains(d) { sharedD.append(d) } else { doms.append(d) }
        }
        let live = lastApps.first { $0.key == key }?.endpoints ?? []
        let kills = live.filter { addrs.contains($0.remoteAddress) }.flatMap { Self.killCommands(local: $0.localAddress, remote: $0.remoteAddress) }
        return AppBlockPlan(key: key, name: state.names[key] ?? Self.displayName(key: key, fallback: key), addresses: addrs, domains: doms,
                            sharedAddresses: shared, sharedDomains: sharedD, localAddresses: local, killCommands: kills,
                            protectedAddresses: prot, protectedDomains: protD)
    }

    /// `pfctl -k <local> -k <remote>` kills the pf state of an already-open connection so the new block applies to it.
    public static func killCommands(local: String, remote: String) -> [NetCommand] {
        guard DNSWire.addressBytes(remote) != nil, PFManager.sanitize(remote) != nil else { return [] }
        let l = DNSWire.addressBytes(local) != nil && local != "0.0.0.0" && local != "::" ? local : (remote.contains(":") ? "::/0" : "0.0.0.0/0")
        return [NetCommand(PFManager.pfctl, ["-k", l, "-k", remote])]
    }

    public enum DecisionError: Error, CustomStringConvertible {
        case refused(String)
        public var description: String { if case .refused(let s) = self { return s }; return "refused" }
    }

    /// Applies Allow / Block / Ask later for an app (prompted or picked from the list).
    @discardableResult
    public func decide(key: String, decision: FirewallDecision, now: Date = Date()) throws -> AppFirewallStatus {
        if decision == .block, let why = Self.protectedKey(key) { throw DecisionError.refused(why) }
        // o4: Apple-signed software (Safari, Mail, ...) is part of macOS for networking purposes too.
        if decision == .block, key.hasPrefix("/"), signer(key)?.status == .apple {
            throw DecisionError.refused("Blocking Apple software could break networking for everything.")
        }
        lock.lock()
        prompts.removeAll { $0.key == key }
        let name = state.names[key] ?? Self.displayName(key: key, fallback: key)
        switch decision {
        case .allow:
            state.rules[key] = FirewallRule(key: key, name: name, decision: .allow, date: now)
        case .askLater:
            state.rules[key] = FirewallRule(key: key, name: name, decision: .askLater, date: now, until: now.addingTimeInterval(24 * 3600))
        case .block:
            state.rules[key] = FirewallRule(key: key, name: name, decision: .block, date: now)
        }
        lock.unlock()
        try reapply(now: now, killFor: decision == .block ? key : nil)
        save()
        return status()
    }

    /// Removes any rule for an app (it may be prompted again later).
    @discardableResult
    public func forget(key: String) throws -> AppFirewallStatus {
        lock.lock(); state.rules[key] = nil; lock.unlock()
        try reapply(now: Date()); save()
        return status()
    }

    /// Recomputes every blocked app's destinations, writes and loads the pf table, kills live states for `killFor`
    /// (and for new destinations of blocked apps) and returns the DNS domains to block (via `onDomains`).
    public var onDomains: ((_ domainToApp: [String: String]) -> Void)?

    @discardableResult
    func reapply(now: Date, killFor: String? = nil) throws -> [NetCommandResult] {
        lock.lock()
        var ips = Set<String>(), domains: [String: String] = [:], kills: [NetCommand] = []
        for (k, r) in state.rules where r.decision == .block {
            let p = planLocked(key: k)
            var rule = r
            let newlyAdded = p.addresses.filter { !r.blockedAddresses.contains($0) }
            rule.blockedAddresses = p.addresses; rule.blockedDomains = p.domains
            rule.notes = p.sharedAddresses.map { "\($0): also used by another app, not blocked" }
                + p.sharedDomains.map { "\($0): also used by another app, not blocked" }
                + p.localAddresses.map { "\($0): local network address, never blocked" }
                + (p.protectedAddresses ?? []).map { "\($0): used by macOS or RamPart, never blocked" }
                + (p.protectedDomains ?? []).map { "\($0): used by macOS or RamPart, never blocked" }
            state.rules[k] = rule
            ips.formUnion(p.addresses)
            for d in p.domains { domains[d] = r.name }
            let live = lastApps.first { $0.key == k }?.endpoints ?? []
            let killSet = k == killFor ? Set(p.addresses) : Set(newlyAdded)
            kills += live.filter { killSet.contains($0.remoteAddress) }.flatMap { Self.killCommands(local: $0.localAddress, remote: $0.remoteAddress) }
        }
        lock.unlock()
        var results: [NetCommandResult]
        if ips.isEmpty { results = pf.remove() } else { results = try pf.apply(ips: ips.sorted()) }
        results += kills.map { NetShell.execute($0, dryRun: dryRun) }
        onDomains?(domains)
        lock.lock()
        lastCommands = results.map { ($0.dryRun ? "[dry run] " : ($0.ok ? "" : "[failed] ")) + $0.command.description }
        lastNote = results.first { !$0.dryRun && !$0.ok }.map { "pf: \($0.stderr.trimmingCharacters(in: .whitespacesAndNewlines).prefix(200))" }
        lock.unlock()
        return results
    }

    /// Daemon start: load the pf table for saved Block rules (no state kills).
    @discardableResult
    public func reapplyAll() -> [NetCommandResult] { (try? reapply(now: Date())) ?? [] }

    /// Daemon shutdown / uninstall: unload the firewall anchor (rules stay saved and are re-applied at start).
    @discardableResult
    public func unloadAll() -> [NetCommandResult] { pf.remove() }

    /// Domains the firewall currently blocks (domain -> app name).
    public func blockedDomains() -> [String: String] {
        lock.lock(); defer { lock.unlock() }
        var out: [String: String] = [:]
        for r in state.rules.values where r.decision == .block { for d in r.blockedDomains { out[d] = r.name } }
        return out
    }

    public func status(now: Date = Date()) -> AppFirewallStatus {
        lock.lock(); defer { lock.unlock() }
        return AppFirewallStatus(apps: lastApps, prompts: prompts, rules: state.rules.values.sorted { $0.date > $1.date },
                                 enforcing: !dryRun, lastCommands: lastCommands,
                                 note: lastNote ?? (dryRun ? "Preview mode: the pf commands are shown but not run (needs the RamPart system service)." : nil),
                                 updated: now)
    }

    private func save() {
        lock.lock(); let s = state; lock.unlock()
        try? FileManager.default.createDirectory(at: stateURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder.rampart.encode(s) { try? d.write(to: stateURL, options: .atomic) }
    }
}
