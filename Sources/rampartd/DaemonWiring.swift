import Foundation
import RampartShared
import RampartTelemetry

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
    static func install() {
        Integrations.daemonHook = { s, runtime in
            let hub = EventHub()
            let isRoot = getuid() == 0 && !runtime.userMode
            if isRoot { hub.add(EsloggerSource()) }   // needs root + Full Disk Access
            hub.add(FSEventsSource(paths: runtime.watchPaths,
                                   stateURL: runtime.root.appendingPathComponent("fsevents-state.json"),
                                   excludedPrefixes: [runtime.root.path, runtime.quarantineDir.path]))
            hub.add(ProcessSweepSource(interval: isRoot ? 0.5 : 1.0))
            hub.add(UnifiedLogSource())
            let pipeline = RealtimePipeline(runtime: runtime, feed: HubFeed(hub: hub), scanner: s.scanner)
            let behaviourNote = BehaviourWiring.attach(pipeline, services: s, runtime: runtime)
            s.realtime = pipeline
            s.wiring.append("realtime: RampartTelemetry.EventHub [\(isRoot ? "eslogger, " : "")fsevents, procsweep, unifiedlog] -> on-write scan\(behaviourNote)")
        }
    }
}
