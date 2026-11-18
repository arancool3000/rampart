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
    static var forwarder: DecoyForwarder?

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
            hub.add(ProcessSweepSource(interval: isRoot ? 1.0 : 1.5))
            hub.add(UnifiedLogSource())
            hub.add(ExecWatchSource())
            hub.add(SocketSource(interval: 4))
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
                // init applies the saved settings: decoy watchers (kqueue + access-time reads) and the lure start now.
                // Dev only (scripts/catmouse-demo.sh --scratch): RAMPART_DECEPTION_HOME plants into a scratch home, with a
                // short settle window and a fast lure. Honoured only together with RAMPART_NO_PRIVILEGED_TOOLS=1.
                let env = ProcessInfo.processInfo.environment
                var decHome = NSHomeDirectory()
                var devDemo = false
                if Privileged.noPrivilegedTools, let h = env["RAMPART_DECEPTION_HOME"], h.hasPrefix("/") {
                    var st = stat()
                    if lstat(h, &st) == 0, (st.st_mode & S_IFMT) == S_IFDIR, st.st_uid == getuid() { decHome = h; devDemo = true; DeceptionService.tarpitLineDelay = 0.3 }
                }
                if let dec = try? DeceptionService(directory: runtime.root.appendingPathComponent("deception"), home: decHome, ownPaths: [app, exe], applyPersisted: false) {
                    if devDemo { dec.watcher.settleSeconds = 3 }
                    dec.applyPersistedConfig()
                    dec.readDetectionAvailable = true   // decoy access times (DecoyWatcher), no eslogger needed
                    // The system service forwards eslogger events for decoys (DecoyForwarder): then the actor is known.
                    dec.attributionAvailable = isRoot || DecoyForwarder.systemServicePresent
                    s.deception = dec
                    let prior2 = pipeline.behaviour
                    pipeline.behaviour = { ev in (prior2?(ev) ?? []) + dec.handle(ev) }
                    if let engine = s.scanner as? EngineScanService { engine.extraExclusions = { dec.exclusions } }
                    DaemonWiring.deception = dec
                }
            }
            // System service: eslogger sees who opens a decoy; forward those events to the owning user's session daemon
            // (which runs Cat & Mouse) so its catches name the program. The session daemon merges them with its own
            // actor-less touches, so nothing is reported twice.
            if isRoot {
                let fwd = DecoyForwarder()
                fwd.start()
                let prior3 = pipeline.behaviour
                pipeline.behaviour = { ev in fwd.consider(ev); return prior3?(ev) ?? [] }
                DaemonWiring.forwarder = fwd
                if let engine = s.scanner as? EngineScanService {
                    let previous = engine.extraExclusions
                    engine.extraExclusions = { (previous?() ?? []) + fwd.scanExclusions }
                }
            }
            s.realtime = pipeline
            s.onDNSEvent = { [weak pipeline] e in pipeline?.inject(e) }
            s.wiring.append("realtime: RampartTelemetry.EventHub [\(isRoot ? "eslogger, " : "")fsevents, procsweep, unifiedlog, execwatch, sockets\(pipeline.companions.isEmpty ? "" : ", pasteguard")] -> on-write scan (+deep content, apple-impersonation)\(behaviourNote), threat-chain")
        }
    }
}
