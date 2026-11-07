import Foundation
import RampartShared

// rampartd — Rampart protection daemon.
//   As root (LaunchDaemon): state in /Library/Application Support/Rampart, socket /var/run/rampart.sock.
//   --user (development): state in ~/Library/Application Support/Rampart, socket next to it, no privileged actions.

setvbuf(stdout, nil, _IOLBF, 0)
signal(SIGPIPE, SIG_IGN)

let usage = """
usage: rampartd [--user] [--root DIR] [--socket PATH] [--verbose] [--no-realtime] [--no-scheduler] [--no-updates]
       rampartd --version | --print-config | --help
  --user          no-root mode: protects this user's files (FSEvents, process sweep, unified log, behaviour,
                  on-write scans, scheduled scans, user quarantine) and never changes system settings
  --root DIR      state directory override (tests)
  --socket PATH   socket path override
  --no-realtime   do not start event sources
  --no-scheduler  do not run scheduled scans/updates
  --scheduler     run the scheduler even from a development build (off by default outside an installed copy)
env RAMPART_NO_PRIVILEGED_TOOLS=1: never spawn sfltool/profiles/systemextensionsctl/tccutil/osascript/security/sudo
                and never read the pasteboard
  --no-updates    never download signature/blocklist updates on schedule
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
var noScheduler = flag("--no-scheduler")
let forceScheduler = flag("--scheduler")
_ = flag("--updates")   // accepted for compatibility; updates are on unless --no-updates
let noUpdates = flag("--no-updates")
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
// One daemon per state root (red-team fix): two instances on the same root both wrote config, detections and the vault.
let stateLockFD: Int32 = {
    try? FileManager.default.createDirectory(at: runtime.root, withIntermediateDirectories: true)
    let path = runtime.root.appendingPathComponent("rampartd.lock").path
    let fd = open(path, O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard fd >= 0, flock(fd, LOCK_EX | LOCK_NB) == 0 else {
        FileHandle.standardError.write(Data("rampartd: another rampartd is using \(runtime.root.path)\n".utf8))
        exit(75)
    }
    _ = ftruncate(fd, 0); let pid = Data("\(getpid())\n".utf8); _ = pid.withUnsafeBytes { write(fd, $0.baseAddress, pid.count) }
    return fd   // held open (and locked) for the life of the process
}()
_ = stateLockFD
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

let scheduler = Scheduler(protection, allowNetworkUpdates: !noUpdates)
if let rt = services.realtime as? RealtimePipeline { rt.onPersistenceEvent = { scheduler.persistenceChanged() } }
if runtime.config.realtime && !noRealtime { protection.startRealtime() }
services.behaviour?.apply(learningMode: runtime.config.learningMode, developerMode: runtime.config.developerMode)
protection.applyCanaries()
DetectionReevaluator.run(protection, engine: BehaviourWiring.engine)
if let g = services.guardian {
    g.onDetection = { protection.handle($0) }
    g.startMonitor()
}
protection.activity.add(.system, "\(Product.name) protection started",
                        detail: runtime.userMode ? "User mode: protecting your files without system changes" : "System service",
                        outcome: protection.services.realtime?.isRunning == true ? "real-time on" : "real-time off")
if runtime.config.webProtection, !runtime.userMode, let web = services.web {
    do { try web.setOn(true) } catch { logWarn("web protection failed to start: \(error.localizedDescription)") }
}
// The scheduler runs only for installed copies (LaunchDaemon / app bundle) or with --scheduler,
// and never with RAMPART_NO_PRIVILEGED_TOOLS unless --scheduler is given explicitly.
let exePath = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
let installed = exePath.hasPrefix("/Library/PrivilegedHelperTools/") || exePath.contains(".app/Contents/")
if !forceScheduler && (!installed || Privileged.noPrivilegedTools) { noScheduler = true }
if Privileged.noPrivilegedTools { logInfo("RAMPART_NO_PRIVILEGED_TOOLS=1: no prompting tools, no pasteboard reads") }
if !noScheduler { scheduler.start() } else { logInfo("scheduler off") }
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
    protection.activity.add(.system, "\(Product.name) protection stopped", detail: why)
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
