import Foundation
import RampartShared
import RampartTelemetry
import RampartBehaviour
import RampartGuard
import AppKit

// Daemon-only wiring: real-time event sources through RampartTelemetry.EventHub,
// on-write scanning, and the behaviour engine (when RampartBehaviour is available).

final class HubFeed: EventFeed {
    let hub: EventHub
    init(hub: EventHub) { self.hub = hub }
    var status: [String: Bool] { hub.sourceStatus }
    func start(handler: @escaping (SecurityEvent) -> Void) { hub.start(handler: handler) }
    func stop() { hub.stop() }
}

enum DaemonWiring {
    static var hub: EventHub?
    static var deception: DeceptionService?

    /// PasteGuard is the one pasteboard reader per session. It runs only in the user's own session
    /// (never as root) and only when macOS lets us read the pasteboard without asking
    /// (`accessBehavior == .alwaysAllow`), so the user never sees repeated paste-permission prompts.
    static func pasteGuardCompanion(runtime: Runtime) -> RealtimePipeline.Companion? {
        guard Privileged.pasteboardAllowed else { return nil }
        if #available(macOS 15.4, *) {
            guard NSPasteboard.general.accessBehavior == .alwaysAllow else {
                logInfo("clipboard guard off: pasteboard access is not 'always allow' for this process")
                return nil
            }
        }
        var cfg = PasteGuardConfig(); cfg.aiEnabled = false
        let guardian = PasteGuard(config: cfg)
        return RealtimePipeline.Companion(name: "pasteguard", start: { onDetection, inject in
            guardian.onDetection = { d in onDetection(d) }
            guardian.onEvent = { e in DaemonWiring.hub?.ingest(e) ?? inject(e) }
            guardian.start()
        }, stop: { guardian.stop() })
    }

    static func install() {
        Integrations.onDNSAnswer = { ip, host in DNSAnswerCache.shared.record(ip: ip, host: host) }
        Integrations.daemonHook = { s, runtime in
            var cfg = EventHub.Config()
            cfg.ingestRemoteClipboard = true          // clipboard events come from PasteGuard (single reader)
            // hx9: the folder this daemon (and the CLI next to it) actually runs from is never an impostor.
            let exeDir = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().deletingLastPathComponent().path
            if !cfg.rampartInstallPaths.contains(exeDir) { cfg.rampartInstallPaths.append(exeDir) }
            let hub = EventHub(config: cfg)
            hub.clipboardMemory = ClipboardMemory()
            let isRoot = getuid() == 0 && !runtime.userMode
            if isRoot { hub.add(EsloggerSource()) }   // needs root + Full Disk Access
            hub.add(FSEventsSource(paths: runtime.watchPaths,
                                   stateURL: runtime.root.appendingPathComponent("fsevents-state.json"),
                                   excludedPrefixes: runtime.ownDataRoots))
            hub.add(ProcessSweepSource(interval: isRoot ? 0.5 : 1.0))
            hub.add(UnifiedLogSource())
            hub.add(ExecWatchSource())
            hub.add(SocketSource(interval: 2))
            DaemonWiring.hub = hub
            s.sourceCPU = { hub.cpuBySource }
            DaemonHooks.ingestClipboard = { e in hub.ingest(e) }
            let pipeline = RealtimePipeline(runtime: runtime, feed: HubFeed(hub: hub), scanner: s.scanner)
            let behaviourNote = BehaviourWiring.attach(pipeline, services: s, runtime: runtime)
            if let pg = pasteGuardCompanion(runtime: runtime) { pipeline.companions.append(pg) }
            // Tamper detection sees every event alongside the behaviour engine.
            if let g = s.guardian {
                let behaviour = pipeline.behaviour
                pipeline.behaviour = { ev in (behaviour?(ev) ?? []) + g.inspect(ev) }
            }
            // Deep protection: threat-chain rules see every event; deep content + Apple impersonation run in scans
            // and in on-write scans (registered as scan detectors); link-chain checks are served over IPC.
            let deep = DeepProtectionService(root: runtime.root, blocklists: s.webCheck.map { [$0.provider] } ?? [])
            s.deep = deep
            if let engine = s.scanner as? EngineScanService { for d in deep.fileDetectors { engine.coord.register(d) } }
            let prior = pipeline.behaviour
            pipeline.behaviour = { ev in (prior?(ev) ?? []) + deep.ingest(ev) }
            // Cat & Mouse: decoys live in the user's own home, so the service runs in the user-session daemon only.
            if runtime.userMode {
                let exe = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
                let app = exe.components(separatedBy: ".app/").first.map { $0 + ".app" } ?? exe
                if let dec = try? DeceptionService(directory: runtime.root.appendingPathComponent("deception"), home: NSHomeDirectory(), ownPaths: [app, exe]) {
                    dec.readDetectionAvailable = isRoot   // eslogger (reads) only as root; FSEvents can't see reads
                    s.deception = dec
                    let prior2 = pipeline.behaviour
                    pipeline.behaviour = { ev in (prior2?(ev) ?? []) + dec.handle(ev) }
                    if let engine = s.scanner as? EngineScanService { engine.extraExclusions = { dec.exclusions } }
                    DaemonWiring.deception = dec
                }
            }
            s.realtime = pipeline
            s.onDNSEvent = { [weak pipeline] e in pipeline?.inject(e) }
            s.wiring.append("realtime: RampartTelemetry.EventHub [\(isRoot ? "eslogger, " : "")fsevents, procsweep, unifiedlog, execwatch, sockets\(pipeline.companions.isEmpty ? "" : ", pasteguard")] -> on-write scan (+deep content, apple-impersonation)\(behaviourNote), threat-chain")
        }
    }
}
