import Foundation
import RampartShared

// rampartd — Rampart protection daemon.
//   As root (LaunchDaemon): state in /Library/Application Support/Rampart, socket /var/run/rampart.sock.
//   --user (development): state in ~/Library/Application Support/Rampart, socket next to it, no privileged actions.

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

let usage = """
usage: rampartd [--user] [--root DIR] [--socket PATH] [--verbose] [--no-realtime] [--no-scheduler] [--updates]
       rampartd --version | --print-config | --help
  --user          development mode: run unprivileged with per-user state and socket
  --root DIR      state directory override (tests)
  --socket PATH   socket path override
  --no-realtime   do not start event sources
  --no-scheduler  do not run scheduled scans/updates
  --updates       allow scheduled network signature updates in --user mode (always on as root)
"""

var args = Array(CommandLine.arguments.dropFirst())
func flag(_ f: String) -> Bool { if let i = args.firstIndex(of: f) { args.remove(at: i); return true }; return false }
func option(_ f: String) -> String? {
    guard let i = args.firstIndex(of: f), i + 1 < args.count else { return nil }
    let v = args[i + 1]; args.removeSubrange(i...i + 1); return v
}

if flag("--help") || flag("-h") { print(usage); exit(0) }
if flag("--version") { print("rampartd \(Product.version)"); exit(0) }
let userMode = flag("--user")
let verbose = flag("--verbose") || flag("-v")
let noRealtime = flag("--no-realtime")
let noScheduler = flag("--no-scheduler")
let allowUpdates = flag("--updates")
let printConfig = flag("--print-config")
let rootOverride = option("--root").map { URL(fileURLWithPath: ($0 as NSString).expandingTildeInPath) }
let socketOverride = option("--socket")
if !args.isEmpty { FileHandle.standardError.write(Data("rampartd: unknown arguments \(args)\n\(usage)\n".utf8)); exit(64) }

if getuid() != 0 && !userMode {
    FileHandle.standardError.write(Data("rampartd: must run as root (LaunchDaemon) or with --user for development\n".utf8))
    exit(77)
}

let runtime = Runtime(root: rootOverride, userMode: userMode || getuid() != 0, socketPath: socketOverride)
if printConfig {
    let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    print(String(data: try! enc.encode(runtime.config), encoding: .utf8)!)
    exit(0)
}
DLog.shared.verbose = verbose
DLog.shared.openFile(runtime.logFile)
logInfo("rampartd \(Product.version) starting pid=\(getpid()) uid=\(getuid()) root=\(runtime.root.path) mode=\(runtime.userMode ? "user" : "system")")

DaemonWiring.install()
let services = Services.make(runtime: runtime, daemon: true)
for w in services.wiring { logInfo("wired \(w)") }
let protection = Protection(runtime: runtime, services: services)
let router = Router(protection)
let server = IPCServer(path: runtime.socketPath, router: router, userMode: runtime.userMode)
do { try server.start() } catch {
    logError("IPC server failed: \(error)")
    exit(1)
}

let scheduler = Scheduler(protection, allowNetworkUpdates: !runtime.userMode || allowUpdates)
if let rt = services.realtime as? RealtimePipeline { rt.onPersistenceEvent = { scheduler.persistenceChanged() } }
if runtime.config.realtime && !noRealtime, let rt = services.realtime {
    rt.start(onEvent: { _ in }, onDetection: { protection.handle($0) })
}
if runtime.config.webProtection, let web = services.web {
    do { try web.setOn(true) } catch { logWarn("web protection failed to start: \(error.localizedDescription)") }
}
if !noScheduler { scheduler.start() }
for w in services.warmups { DispatchQueue.global(qos: .utility).async(execute: w) }

// Signals: TERM/INT -> clean shutdown; HUP -> reload config.
var signalSources: [DispatchSourceSignal] = []
func onSignal(_ sig: Int32, _ handler: @escaping () -> Void) {
    signal(sig, SIG_IGN)
    let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    s.setEventHandler(handler: handler); s.resume(); signalSources.append(s)
}
func shutdown(_ why: String) {
    logInfo("shutting down (\(why))")
    scheduler.stop()
    services.realtime?.stop()
    if let w = services.web, w.isOn { try? w.setOn(false) }
    server.stop()
    exit(0)
}
onSignal(SIGTERM) { shutdown("SIGTERM") }
onSignal(SIGINT) { shutdown("SIGINT") }
onSignal(SIGHUP) {
    let ok = runtime.reloadConfig()
    logInfo("SIGHUP: config reload \(ok ? "ok" : "failed/kept")")
}

logInfo("ready")
dispatchMain()
