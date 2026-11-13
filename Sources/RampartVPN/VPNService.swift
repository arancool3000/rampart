import Foundation

/// RamPart VPN in the root daemon: profile + options on disk (no secrets), keys in the key store, one WireGuard
/// tunnel to the user's own server. Without the installed system service (development, user mode,
/// RAMPART_NO_PRIVILEGED_TOOLS=1) a connect is a handshake-only test: no utun, routes, DNS or pf changes, and the
/// commands that would run are listed in the status.
public final class VPNService {
    public struct Hooks {
        /// RamPart's DNS filter (127.0.0.1) is on.
        public var dnsFilterActive: () -> Bool = { false }
        /// Emergency Lockdown has cut the network: the VPN steps aside so the lockdown allow-list works.
        public var lockdownNetworkActive: () -> Bool = { false }
        public var log: (String) -> Void = { _ in }
        public var activity: (_ title: String, _ detail: String) -> Void = { _, _ in }
        public init() {}
    }

    /// I/O factories (real sockets / utun by default; in-memory in tests).
    public struct Factories {
        public var makeTunnel: (DispatchQueue) throws -> TunnelPacketIO
        public var makeSocket: (_ ipv6: Bool, _ port: UInt16, _ boundInterface: String?, DispatchQueue) throws -> TunnelDatagramIO
        public var resolve: (String, UInt16) -> WGEndpoint?
        public init(makeTunnel: @escaping (DispatchQueue) throws -> TunnelPacketIO,
                    makeSocket: @escaping (Bool, UInt16, String?, DispatchQueue) throws -> TunnelDatagramIO,
                    resolve: @escaping (String, UInt16) -> WGEndpoint?) {
            self.makeTunnel = makeTunnel; self.makeSocket = makeSocket; self.resolve = resolve
        }
        public static func system(live: Bool) -> Factories {
            Factories(makeTunnel: { q in live ? try UTunDevice(queue: q) as TunnelPacketIO : MemoryPacketIO(name: "utunN") },
                      makeSocket: { v6, port, ifn, q in try UDPSocketIO(ipv6: v6, port: port, boundInterface: ifn, queue: q) },
                      resolve: EndpointResolver.resolve)
        }
    }

    final class Active {
        let peer: WireGuardPeer
        let tun: TunnelPacketIO
        var udp: TunnelDatagramIO
        var plan: VPNNetworkPlan
        var physicalInterface: String?
        var pfToken: String?
        var routesUp = false
        var dnsUp = false
        init(peer: WireGuardPeer, tun: TunnelPacketIO, udp: TunnelDatagramIO, plan: VPNNetworkPlan) {
            self.peer = peer; self.tun = tun; self.udp = udp; self.plan = plan
        }
    }

    public let directory: URL
    public let keyStore: VPNKeyStore
    public let runner: VPNCommandRunner
    public let live: Bool
    public var hooks: Hooks
    let factories: Factories
    let queue = DispatchQueue(label: "app.rampart.vpn")
    let now: () -> Date

    private var status = VPNStatus()
    private var active: Active?
    private var timer: DispatchSourceTimer?
    private var lastHealthCheck = Date.distantPast
    private var lastDNSFilterState: Bool?
    private var gaveUpCount = 0

    public init(directory: URL, keyStore: VPNKeyStore, runner: VPNCommandRunner, live: Bool, hooks: Hooks = Hooks(),
                factories: Factories? = nil, now: @escaping () -> Date = Date.init) {
        self.directory = directory; self.keyStore = keyStore; self.runner = runner; self.live = live
        self.hooks = hooks; self.factories = factories ?? .system(live: live); self.now = now
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        status.profile = loadJSON(VPNProfile.self, "profile.json")
        status.options = loadJSON(VPNOptions.self, "options.json") ?? VPNOptions()
        status.phase = status.profile == nil ? .notConfigured : .disconnected
        status.canRouteTraffic = live
        status.keyStore = keyStore.kind
    }

    var profileURL: URL { directory.appendingPathComponent("profile.json") }

    func loadJSON<T: Decodable>(_ t: T.Type, _ name: String) -> T? {
        guard let d = try? Data(contentsOf: directory.appendingPathComponent(name)) else { return nil }
        return try? JSONDecoder.vpn.decode(T.self, from: d)
    }
    func saveJSON<T: Encodable>(_ v: T, _ name: String) {
        let url = directory.appendingPathComponent(name)
        guard let d = try? JSONEncoder.vpn.encode(v) else { return }
        try? d.write(to: url, options: .atomic)
        _ = chmod(url.path, 0o600)
    }

    // MARK: public API (thread-safe)

    public func currentStatus() -> VPNStatus { queue.sync { snapshot() } }

    private func snapshot() -> VPNStatus {
        var s = status
        if let a = active {
            s.stats = a.peer.stats
            s.lastHandshake = a.peer.lastHandshake
            s.interface = live ? a.tun.name : nil
            s.endpointIP = a.plan.endpointIP
        }
        return s
    }

    /// One entry point for IPC.
    public func handle(op: VPNOp, body: VPNRequestBody?) throws -> VPNReply {
        let b = body ?? VPNRequestBody()
        switch op {
        case .status: return VPNReply(status: currentStatus())
        case .connect: try connect(reason: b.reason ?? "user"); return VPNReply(status: currentStatus())
        case .disconnect: disconnect(reason: "You turned the VPN off."); return VPNReply(status: currentStatus())
        case .importConfig:
            guard let t = b.text else { throw VPNError.message("Paste or choose a WireGuard configuration.") }
            let w = try importConfig(text: t, name: b.name)
            return VPNReply(status: currentStatus(), warnings: w)
        case .setupHome:
            guard let h = b.host else { throw VPNError.message("Enter your home server's address.") }
            let kit = try setupHomeServer(host: h, port: b.port ?? HomeServerSetup.defaultPort)
            return VPNReply(status: currentStatus(), kit: kit)
        case .setOptions:
            setOptions(autoConnect: b.autoConnect, killSwitch: b.killSwitch)
            return VPNReply(status: currentStatus())
        case .remove:
            removeProfile(); return VPNReply(status: currentStatus())
        }
    }

    public enum VPNError: Error, CustomStringConvertible, LocalizedError {
        case message(String)
        public var description: String { if case .message(let m) = self { return m }; return "" }
        public var errorDescription: String? { description }
    }

    /// Imports wg-quick text (also the text of a WireGuard QR code). Returns warnings for ignored lines.
    @discardableResult
    public func importConfig(text: String, name: String?, createdBy: String = "import") throws -> [String] {
        let c: WGQuickConfig
        do { c = try WGQuickConfig.parse(text) } catch let e as WGQuickConfig.ParseError { throw VPNError.message(e.description) }
        try store(c, name: name?.trimmingCharacters(in: .whitespaces).nonEmpty ?? "Home server", createdBy: createdBy)
        hooks.activity("VPN configuration imported", "Server \(c.endpointHost):\(c.endpointPort)")
        return c.warnings
    }

    func store(_ c: WGQuickConfig, name: String, createdBy: String) throws {
        let profile = VPNProfile(name: String(name.prefix(60)), config: c, createdBy: createdBy, created: now())
        try queue.sync {
            if active != nil { tearDown(reason: "replaced configuration") }
            if let old = status.profile { keyStore.delete(account: old.id); keyStore.delete(account: old.id + ".psk") }
            do {
                try keyStore.set(c.privateKey, account: profile.id)
                if !c.presharedKey.isEmpty { try keyStore.set(c.presharedKey, account: profile.id + ".psk") }
            } catch { throw VPNError.message("Couldn't save the VPN key in the Keychain: \(error)") }
            saveJSON(profile, "profile.json")
            status.profile = profile
            status.phase = .disconnected
            status.error = nil
        }
    }

    public func setupHomeServer(host: String, port: UInt16) throws -> HomeServerKit {
        let r: HomeServerSetup.Result
        do { r = try HomeServerSetup.generate(endpointHost: host, port: port) }
        catch let e as HomeServerSetup.SetupError { throw VPNError.message(e.description) }
        try store(r.clientConfig, name: "Home server (\(host))", createdBy: "homeServer")
        hooks.activity("VPN home server set up", "New keys for \(host):\(port); server config shown once")
        return r.kit
    }

    public func setOptions(autoConnect: Bool?, killSwitch: Bool?) {
        queue.sync {
            if let a = autoConnect { status.options.autoConnect = a }
            if let k = killSwitch, k != status.options.killSwitch {
                status.options.killSwitch = k
                if let a = active { k ? engageKillSwitch(a) : releaseKillSwitch(a) }
            }
            saveJSON(status.options, "options.json")
        }
        hooks.activity("VPN settings changed", "Auto-connect \(autoConnect.map { $0 ? "on" : "off" } ?? "unchanged"), kill switch \(killSwitch.map { $0 ? "on" : "off" } ?? "unchanged")")
    }

    public func removeProfile() {
        queue.sync {
            if active != nil { tearDown(reason: "configuration removed") }
            if let p = status.profile { keyStore.delete(account: p.id); keyStore.delete(account: p.id + ".psk") }
            try? FileManager.default.removeItem(at: profileURL)
            status = VPNStatus(); status.options = loadJSON(VPNOptions.self, "options.json") ?? VPNOptions()
            status.canRouteTraffic = live; status.keyStore = keyStore.kind
        }
        hooks.activity("VPN configuration removed", "")
    }

    public func connect(reason: String) throws {
        try queue.sync {
            guard let profile = status.profile else { throw VPNError.message("Set up your home server or import a configuration first.") }
            if reason.hasPrefix("auto"), !status.options.autoConnect { throw VPNError.message("Auto-connect is off.") }
            if active != nil { return }
            guard let priv = keyStore.get(account: profile.id) else {
                status.phase = .failed
                status.error = "This Mac's VPN key isn't in the \(keyStore.kind) any more. Import the configuration again (or run server setup again)."
                throw VPNError.message(status.error!)
            }
            let psk = profile.hasPresharedKey ? (keyStore.get(account: profile.id + ".psk") ?? []) : []
            guard let cfg = profile.config(privateKey: priv, presharedKey: psk) else { throw VPNError.message("The saved configuration is damaged. Import it again.") }
            status.phase = .connecting; status.error = nil; status.lastReason = reason; status.notes = []
            queue.async { self.bringUp(cfg) }
        }
        hooks.activity(reason.hasPrefix("auto") ? "VPN connecting automatically" : "VPN connecting", reason)
    }

    public func disconnect(reason: String) {
        queue.sync { if active != nil || status.phase.isActive || status.phase == .failed { tearDown(reason: reason) } }
        hooks.activity("VPN disconnected", reason)
    }

    /// SIGTERM / Super Kill Switch: everything off, nothing left behind (routes, DNS, pf).
    public func shutdown() { queue.sync { tearDown(reason: "RamPart stopped the VPN") } }

    /// What a live tunnel changed outside its own utun (which the kernel destroys, with its routes, when the
    /// process dies). Written at bring-up, removed at tear-down; a leftover file means the last run crashed.
    struct SystemState: Codable, Equatable {
        var endpointIP: String
        var endpointHostRoute: Bool
    }
    static let stateFile = "system-state.json"

    /// At daemon start: remove DNS keys, pf rules and the endpoint host route a crashed previous run may have left.
    /// (Before WMS-o9 the endpoint's host route via the old gateway survived a crash and pinned that address to a
    /// network the Mac may since have left.)
    public func cleanupStale() {
        guard live else { return }
        queue.sync { sweepStaleState() }
    }

    /// The stale-state sweep itself (also what `cleanupStale` runs when live); exposed for self-tests with a dry runner.
    public func sweepStaleState() {
        _ = runner.run(VPNNetworkPlan.dnsDownCommand())
        for c in VPNNetworkPlan.killSwitchUnloadCommands(token: nil) { _ = runner.run(c) }
        if let st = loadJSON(SystemState.self, Self.stateFile) {
            if st.endpointHostRoute, let ip = IPPrefix.strictLiteral(st.endpointIP) {
                let ep = IPPrefix.format(ip)
                _ = runner.run(VPNCommand(VPNCommand.route, ["-q", "-n", "delete", ep.contains(":") ? "-inet6" : "-inet", ep], tolerateFailure: true))
            }
            try? FileManager.default.removeItem(at: directory.appendingPathComponent(Self.stateFile))
        }
    }

    // MARK: bring-up / tear-down (on queue)

    private func run(_ cmds: [VPNCommand]) -> String? {
        for c in cmds {
            if !runner.isLive { status.dryRunCommands.append(c.description) }
            let r = runner.run(c)
            if r.status != 0 && !c.tolerateFailure && runner.isLive {
                return "\(c.description) failed: \(r.output.trimmingCharacters(in: .whitespacesAndNewlines).prefix(200))"
            }
        }
        return nil
    }

    private func defaultRoutes() -> (g4: String?, g6: String?, iface: String?) {
        let cmds = VPNNetworkPlan.defaultRouteCommands()
        let r4 = VPNNetworkPlan.parseRouteGet(runner.run(cmds[0]).output)
        let r6 = VPNNetworkPlan.parseRouteGet(runner.run(cmds[1]).output)
        let iface4 = r4.interface.flatMap { $0.hasPrefix("utun") ? nil : $0 }
        return (r4.gateway, r6.gateway, iface4 ?? r6.interface.flatMap { $0.hasPrefix("utun") ? nil : $0 })
    }

    private func bringUp(_ cfg: WGQuickConfig) {
        guard status.phase == .connecting, active == nil else { return }
        status.dryRunCommands = []
        guard let ep = factories.resolve(cfg.endpointHost, cfg.endpointPort) else {
            var msg = "Couldn't find your server \(cfg.endpointHost)."
            if cfg.endpointHost.hasSuffix(".local") { msg += " Names ending in .local only work on your home network; use your home's public address or a dynamic DNS name to connect from elsewhere." }
            fail(msg); return
        }
        let routes = defaultRoutes()
        do {
            let udp = try factories.makeSocket(ep.host.contains(":"), cfg.listenPort ?? 0, routes.iface, queue)
            let tun = try factories.makeTunnel(queue)
            let peer = try WireGuardPeer(privateKey: cfg.privateKey, peer: WGPeerConfig(
                publicKey: cfg.peerPublicKey, presharedKey: cfg.presharedKey, endpoint: ep,
                allowedIPs: cfg.allowedIPs.compactMap(IPPrefix.init), persistentKeepalive: cfg.persistentKeepalive), now: now)
            let dnsFilter = hooks.dnsFilterActive()
            lastDNSFilterState = dnsFilter
            let plan = VPNNetworkPlan(interface: tun.name, config: cfg, endpointIP: ep.host, localUDPPort: udp.localPort,
                                      gateway4: routes.g4, gateway6: routes.g6, dnsFilterActive: dnsFilter, killSwitch: status.options.killSwitch)
            let a = Active(peer: peer, tun: tun, udp: udp, plan: plan)
            a.physicalInterface = routes.iface
            active = a
            peer.sendUDP = { [weak a] b, e in a?.udp.send(b, to: e) }
            peer.deliverPacket = { [weak a] p in a?.tun.write(p) }
            peer.onEvent = { [weak self] e in self?.peerEvent(e) }
            udp.start { [weak a] b, e in a?.peer.receiveUDP(b, from: e) }
            tun.start { [weak a] p in a?.peer.sendPacket(p) }
            if let err = run(plan.addressCommands()) { fail(err); return }
            if !hooks.lockdownNetworkActive() {
                if let err = bringUpRoutesAndDNS(a) { fail(err); return }
            } else {
                status.phase = .suspendedForLockdown
            }
            if status.options.killSwitch { engageKillSwitch(a) }
            status.dnsMode = dnsModeText(plan)
            if !live {
                status.notes.append("Test mode: RamPart checks the handshake with your server but doesn't route your traffic. Routing needs RamPart's system service (installed with your password).")
            }
            gaveUpCount = 0
            peer.initiateHandshake()
            startTimer()
            hooks.log("vpn: connecting to \(ep) via \(live ? tun.name : "dry run") (local udp \(udp.localPort))")
        } catch {
            fail("Couldn't start the tunnel: \(error)")
        }
    }

    private func dnsModeText(_ plan: VPNNetworkPlan) -> String {
        if plan.dnsFilterActive { return "RamPart's DNS filter, forwarding over the tunnel" }
        if plan.effectiveDNS.isEmpty { return "Unchanged (the configuration sets no DNS server)" }
        return plan.effectiveDNS.joined(separator: ", ") + " through the tunnel"
    }

    private func bringUpRoutesAndDNS(_ a: Active) -> String? {
        saveJSON(SystemState(endpointIP: a.plan.endpointIP, endpointHostRoute: a.plan.endpointCoveredByTunnel), Self.stateFile)
        if let err = run(a.plan.routeUpCommands()) { return err }
        a.routesUp = true
        if let dns = a.plan.dnsUpCommand() {
            if let err = run([dns]) { return err }
            a.dnsUp = true
        }
        return nil
    }

    private func takeDownRoutesAndDNS(_ a: Active) {
        if a.dnsUp { _ = run([VPNNetworkPlan.dnsDownCommand()]); a.dnsUp = false }
        if a.routesUp { _ = run(a.plan.routeDownCommands()); a.routesUp = false }
    }

    private func engageKillSwitch(_ a: Active) {
        var plan = a.plan; plan.killSwitch = true; a.plan = plan
        let cmds = plan.killSwitchLoadCommands()
        let r = runner.run(cmds[0]); if !runner.isLive { status.dryRunCommands.append(cmds[0].description) }
        a.pfToken = VPNNetworkPlan.parsePFToken(r.output) ?? a.pfToken
        if let err = run([cmds[1]]) { status.notes.append("Kill switch couldn't be turned on: \(err)"); return }
        status.killSwitchEngaged = true
    }

    private func releaseKillSwitch(_ a: Active?) {
        _ = run(VPNNetworkPlan.killSwitchUnloadCommands(token: a?.pfToken))
        a?.pfToken = nil
        status.killSwitchEngaged = false
    }

    private func fail(_ message: String) {
        hooks.log("vpn: \(message)")
        tearDown(reason: message, keepError: true)
        status.phase = .failed
        status.error = message
    }

    private func tearDown(reason: String, keepError: Bool = false) {
        timer?.cancel(); timer = nil
        if let a = active {
            if a.pfToken != nil || status.killSwitchEngaged { releaseKillSwitch(a) }
            takeDownRoutesAndDNS(a)
            a.peer.reset()
            a.udp.close(); a.tun.close()
            status.stats = a.peer.stats
        } else if status.killSwitchEngaged { releaseKillSwitch(nil) }
        active = nil
        try? FileManager.default.removeItem(at: directory.appendingPathComponent(Self.stateFile))
        status.phase = status.profile == nil ? .notConfigured : .disconnected
        status.connectedSince = nil
        status.killSwitchEngaged = false
        if !keepError { status.error = nil }
        status.lastReason = reason
    }

    private func peerEvent(_ e: WireGuardPeer.Event) {
        switch e {
        case .handshakeComplete:
            if status.phase != .connected && status.phase != .suspendedForLockdown {
                status.phase = .connected
                if status.connectedSince == nil { status.connectedSince = now() }
                status.error = nil
                gaveUpCount = 0
                hooks.log("vpn: handshake complete")
            }
        case .handshakeGaveUp:
            gaveUpCount += 1
            guard let a = active else { return }
            status.phase = .reconnecting
            status.error = "Can't reach your server at \(a.plan.config.endpointHost):\(a.plan.config.endpointPort). Check that it's on, that WireGuard is running and that the router forwards UDP port \(a.plan.config.endpointPort)."
                + (status.options.killSwitch ? " The kill switch is blocking other traffic until the VPN is back." : "")
            a.peer.initiateHandshake()   // keep trying (whitepaper: give up only on the queued packets)
        case .keysExpired:
            if status.phase == .connected { status.phase = .reconnecting }
        case .cookieReceived:
            break
        }
    }

    private func startTimer() {
        timer?.cancel()
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 0.25, repeating: 0.25)
        t.setEventHandler { [weak self] in self?.tickLocked() }
        t.resume(); timer = t
    }

    /// Timers and health checks; tests call `tick()`.
    public func tick() { queue.sync { tickLocked() } }

    private func tickLocked() {
        guard let a = active else { return }
        a.peer.tick()
        let t = now()
        guard t.timeIntervalSince(lastHealthCheck) >= 2 else { return }
        lastHealthCheck = t
        // Emergency Lockdown: step aside (routes + DNS off) so its allow-list works; come back when it is lifted.
        let lockdown = hooks.lockdownNetworkActive()
        if lockdown && status.phase != .suspendedForLockdown {
            takeDownRoutesAndDNS(a)
            status.phase = .suspendedForLockdown
            hooks.activity("VPN paused by Emergency Lockdown", "The lockdown's network block takes priority")
        } else if !lockdown && status.phase == .suspendedForLockdown {
            if let err = bringUpRoutesAndDNS(a) { fail(err); return }
            status.phase = a.peer.hasUsableSession ? .connected : .connecting
            a.peer.initiateHandshake()
        }
        // DNS filter turned on/off while connected: re-point DNS.
        let filter = hooks.dnsFilterActive()
        if filter != lastDNSFilterState, status.phase != .suspendedForLockdown {
            lastDNSFilterState = filter
            var plan = a.plan; plan.dnsFilterActive = filter; a.plan = plan
            if a.dnsUp { _ = run([VPNNetworkPlan.dnsDownCommand()]); a.dnsUp = false }
            if let dns = plan.dnsUpCommand(), run([dns]) == nil { a.dnsUp = true }
            status.dnsMode = dnsModeText(plan)
        }
        // Network change (Wi-Fi to Ethernet, new Wi-Fi): rebind the UDP socket to the new interface and rekey.
        if live, status.phase != .suspendedForLockdown {
            let r = defaultRoutes()
            if let ifn = r.iface, ifn != a.physicalInterface { roam(a, to: ifn, gateway4: r.g4, gateway6: r.g6) }
        }
    }

    private func roam(_ a: Active, to ifn: String, gateway4: String?, gateway6: String?) {
        hooks.log("vpn: network changed (\(a.physicalInterface ?? "none") -> \(ifn)); rebinding")
        do {
            let udp = try factories.makeSocket(a.plan.endpointIP.contains(":"), a.plan.config.listenPort ?? 0, ifn, queue)
            if a.routesUp { _ = run(a.plan.routeDownCommands().filter { $0.arguments.contains(a.plan.endpointIP) }) }
            a.udp.close(); a.udp = udp
            udp.start { [weak a] b, e in a?.peer.receiveUDP(b, from: e) }
            var plan = a.plan; plan.gateway4 = gateway4; plan.gateway6 = gateway6; plan.localUDPPort = udp.localPort; a.plan = plan
            a.physicalInterface = ifn
            if a.routesUp { _ = run(plan.routeUpCommands().filter { $0.arguments.contains(plan.endpointIP) }) }
            if status.killSwitchEngaged { _ = run([plan.killSwitchLoadCommands()[1]]) }
            a.peer.initiateHandshake(retransmit: true)
        } catch {
            status.notes.append("Couldn't move the VPN to the new network: \(error)")
        }
    }

    /// Test hook: run a closure on the service queue.
    public func sync<T>(_ body: () throws -> T) rethrows -> T { try queue.sync(execute: body) }
}

extension String { var nonEmpty: String? { isEmpty ? nil : self } }

extension JSONEncoder {
    static var vpn: JSONEncoder { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; e.outputFormatting = [.sortedKeys]; return e }
}
extension JSONDecoder {
    static var vpn: JSONDecoder { let d = JSONDecoder(); d.dateDecodingStrategy = .iso8601; return d }
}
