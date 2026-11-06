import Foundation
import RampartShared
import RampartTelemetry
import RampartBehaviour
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
        Integrations.daemonHook = { s, runtime in
            var cfg = EventHub.Config()
            cfg.ingestRemoteClipboard = true          // clipboard events come from PasteGuard (single reader)
            let hub = EventHub(config: cfg)
            hub.clipboardMemory = ClipboardMemory()
            let isRoot = getuid() == 0 && !runtime.userMode
            if isRoot { hub.add(EsloggerSource()) }   // needs root + Full Disk Access
            hub.add(FSEventsSource(paths: runtime.watchPaths,
                                   stateURL: runtime.root.appendingPathComponent("fsevents-state.json"),
                                   excludedPrefixes: [runtime.root.path, runtime.quarantineDir.path]))
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
            s.realtime = pipeline
            s.onDNSEvent = { [weak pipeline] e in pipeline?.inject(e) }
            s.wiring.append("realtime: RampartTelemetry.EventHub [\(isRoot ? "eslogger, " : "")fsevents, procsweep, unifiedlog, execwatch, sockets\(pipeline.companions.isEmpty ? "" : ", pasteguard")] -> on-write scan\(behaviourNote)")
        }
    }
}
