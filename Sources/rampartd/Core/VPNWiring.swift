import Foundation
import RampartShared
import RampartVPN

/// RamPart VPN in the daemon (RampartVPN.VPNService). Only the installed root daemon without
/// RAMPART_NO_PRIVILEGED_TOOLS creates a utun, changes routes / DNS / pf and uses the Keychain (`app.rampart.vpn`).
/// Everywhere else the service runs in test mode: a real handshake over an unprivileged UDP socket, system changes
/// only listed, keys kept in memory.
enum VPNWiring {
    static var service: VPNService?

    static func live(_ p: Protection) -> Bool { !p.runtime.userMode && getuid() == 0 && !Privileged.noPrivilegedTools }

    static func start(_ p: Protection) {
        let live = live(p)
        var hooks = VPNService.Hooks()
        hooks.dnsFilterActive = { p.services.web?.isOn ?? false }
        hooks.lockdownNetworkActive = { Emergency.ctl(p).state.isNetworkBlocked }
        hooks.log = { logInfo(LogRedact.clean($0)) }
        hooks.activity = { title, detail in
            p.activity.add(.system, title, detail: LogRedact.clean(detail, max: 300), outcome: title.contains("disconnected") ? "off" : "",
                           event: .settingsChanged, actor: detail.hasPrefix("auto") ? .system : .user, facts: ["changes": title])
        }
        let s = VPNService(directory: p.runtime.root.appendingPathComponent("vpn"),
                           keyStore: live ? KeychainVPNKeyStore() : MemoryVPNKeyStore(),
                           runner: live ? LiveVPNRunner() : DryRunVPNRunner(), live: live, hooks: hooks)
        s.cleanupStale()
        service = s
        p.services.wiring.append("vpn: RampartVPN WireGuard client (\(live ? "utun + routes + scutil DNS + pf kill switch" : "test mode: handshake only, no system changes"))")
    }

    /// IPC `vpn(op:body:)` -> JSON of VPNReply.
    static func handle(op: String, body: Data?) throws -> Data {
        guard let s = service else { throw ServiceError.unavailable("RamPart VPN") }
        guard let o = VPNOp(rawValue: op) else { throw ServiceError.failed("unknown VPN request") }
        guard (body?.count ?? 0) <= 256 * 1024 else { throw ServiceError.failed("VPN request too large") }
        let b = try body.map { try JSONDecoder().decode(VPNRequestBody.self, from: $0) }
        let reply = try s.handle(op: o, body: b)
        let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601
        return try e.encode(reply)
    }

    /// Super Kill Switch and SIGTERM.
    static func stop(_ why: String) -> String {
        guard let s = service else { return "VPN not running" }
        let wasOn = s.currentStatus().phase.isActive
        s.shutdown()
        return wasOn ? "VPN disconnected (\(why))" : "VPN was off"
    }
}

extension VPNWiring {
    /// `sudo rampart killswitch` with the service unreachable: the tunnel died with the service, but its DNS keys and
    /// pf kill-switch rules may remain. (The anchor is also flushed by unloadAnchors, it contains "Rampart".)
    static func offlineCleanup(dryRun: Bool) -> String {
        let cmds = [VPNNetworkPlan.dnsDownCommand()] + VPNNetworkPlan.killSwitchUnloadCommands(token: nil)
        if dryRun { return cmds.map { "would run: \($0)" }.joined(separator: "; ") }
        let r = LiveVPNRunner()
        return cmds.map { c in "\(c): \(r.run(c).status == 0 ? "ok" : "not needed")" }.joined(separator: "; ")
    }
}
