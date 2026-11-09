import Foundation
import RampartShared
import Security
import RampartGuard
import RampartNetwork

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

// hx7: as root, run only as the installed, root-owned helper (defence in depth against a manual misinstall that would
// let a user-writable binary run as root). `--root`/`--user` development runs are never root.
if getuid() == 0 && !userMode {
    let me = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path
    var why: String? = nil
    if me != "/Library/PrivilegedHelperTools/\(Product.daemonLabel)" { why = "not running from /Library/PrivilegedHelperTools/\(Product.daemonLabel) (\(me))" }
    for p in [me, (me as NSString).deletingLastPathComponent] where why == nil {
        var st = stat()
        if lstat(p, &st) != 0 || st.st_uid != 0 || st.st_mode & 0o022 != 0 { why = "\(p) is not root-owned or is writable by others" }
    }
    if let why {
        FileHandle.standardError.write(Data("rampartd: refusing to run as root: \(why)\n".utf8))
        exit(78)
    }
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
    // A user helper left running from a REPLACED copy of the app holds the lock forever (it never restarts by itself).
    // User mode only: stop it when StaleHelperPolicy agrees (same uid, our signing identity and signer, started before
    // our binary was installed, same path or its copy is gone), then take over.
    if fd >= 0, flock(fd, LOCK_EX | LOCK_NB) != 0, runtime.userMode, getuid() != 0,
       let holder = StaleHelperPolicy.lockHolder(stateRoot: runtime.root.path) {
        let me = CommandLine.arguments[0].hasPrefix("/") ? CommandLine.arguments[0] : (Bundle.main.executablePath ?? "")
        if let facts = StaleHelperPolicy.selfFacts(binary: me) {
            let d = StaleHelperPolicy.stopIfStale(pid: holder, me: facts)
            FileHandle.standardError.write(Data("rampartd: lock held by pid \(holder): \(d.shouldStop ? "stopped" : "kept"), \(d.why)\n".utf8))
            if d.shouldStop { for _ in 0..<30 where flock(fd, LOCK_EX | LOCK_NB) != 0 { usleep(100_000) } }
        }
    }
    guard fd >= 0, flock(fd, LOCK_EX | LOCK_NB) == 0 else {
        FileHandle.standardError.write(Data("rampartd: another rampartd is using \(runtime.root.path)\n".utf8))
        exit(75)
    }
    _ = ftruncate(fd, 0); let pid = Data("\(getpid())\n".utf8); _ = pid.withUnsafeBytes { write(fd, $0.baseAddress, pid.count) }
    return fd   // held open (and locked) for the life of the process
}()
_ = stateLockFD
// State-file hardening (hx10): as the system service, the state folder must not be writable by anyone but root and the
// files holding detections, activity, allow rules, policy and keys are 0600 even if an older version left them looser.
if getuid() == 0 && !runtime.userMode {
    var st = stat()
    if lstat(runtime.root.path, &st) == 0 {
        if st.st_uid != 0 { _ = chown(runtime.root.path, 0, 0) }
        if st.st_mode & 0o022 != 0 { _ = chmod(runtime.root.path, mode_t(st.st_mode & 0o755)) }
    }
    for f in ["detections.json", "state.json", "activity.jsonl", "allowrules.json", "remote-policy.json", "guard.key", "rampartd.lock"] {
        let path = runtime.root.appendingPathComponent(f).path
        if lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_mode & 0o077 != 0 { _ = chmod(path, 0o600) }
    }
}
DLog.shared.verbose = verbose
DLog.shared.openFile(runtime.logFile)
logInfo("rampartd \(Product.version) starting pid=\(getpid()) uid=\(getuid()) root=\(runtime.root.path) mode=\(runtime.userMode ? "user" : "system")")

// b5x: one private clipboard-fingerprint key per state root (0600), shared in-process by PasteGuard, the behaviour
// engine and EventHub through RAMPART_CLIPFP_KEY, and stable across restarts so stored clip tokens stay comparable.
if getenv("RAMPART_CLIPFP_KEY") == nil {
    let path = runtime.root.appendingPathComponent("clipfp.key")
    var hex = SecureStore.read(path).flatMap { String(data: $0, encoding: .utf8) }?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
    if hex.count != 64 || !hex.allSatisfy(\.isHexDigit) {
        var bytes = [UInt8](repeating: 0, count: 32)
        if SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess {
            hex = bytes.map { String(format: "%02x", $0) }.joined()
            try? SecureStore.write(Data(hex.utf8), to: path)
        } else { hex = "" }
    }
    if hex.count == 64 { setenv("RAMPART_CLIPFP_KEY", hex, 1) }
}
DaemonWiring.install()
let services = Services.make(runtime: runtime, daemon: true)
// hx4 N1: before anything else, give DNS back if a previous run died while it pointed at us.
(services.web as? WebProtection)?.recoverAtLaunch()
for w in services.wiring { logInfo("wired \(w)") }
let protection = Protection(runtime: runtime, services: services)
// hx9: feed-lost / impostor detections from the event hub, and DoH pin failures, reach the detection store.
DaemonWiring.hub?.onDetection = { protection.handle($0) }
// A telemetry source that is down / not permitted (missing Full Disk Access) is a health note, logged once per problem.
DaemonHooks.healthNotes = { DaemonWiring.hub?.healthNotes ?? [] }
DaemonWiring.hub?.onHealthNote = { n in
    guard n.count == 1 else { return }
    protection.activity.add(.system, n.message, detail: n.detail, outcome: "needs attention", severity: .low, event: .other, actor: .system)
}
(services.web as? WebProtection)?.onDetection = { protection.handle($0) }
// Emergency Lockdown: re-applies a persisted lockdown and starts its watch timer.
Emergency.start(protection)
// RamPart VPN: removes DNS keys / pf rules a crashed run left behind; connects only when asked (or auto-connect).
VPNWiring.start(protection)
// Cat & Mouse: messages to Activity, lure detections to the store, emergencies to the lockdown trigger.
if let dec = DaemonWiring.deception {
    dec.notify = { m in protection.activity.add(.detection, m.title, detail: m.body, outcome: "decoy", severity: m.severity, event: .deceptionEvent, actor: .system) }
    dec.onLureDetection = { d in protection.handle(d) }
    dec.onDetection = { d in protection.handle(d) }   // watcher catches with a certain, still-running actor
    // Every catch / lure knock becomes a notification posted by the app's menu bar process. When no app is listening,
    // wake the login agent (menu bar only, no window); it posts what it missed from `status().alerts`.
    dec.onAlert = { a in
        if let d = try? JSONEncoder.rampart.encode(a) { protection.broadcastDeceptionAlert(d) }
        if protection.subscriberCount == 0 { AgentWake.wake() }
    }
    // An automatic signal (not a manual lockdown): it goes through the corroboration policy and never cuts the network alone.
    dec.onEmergency = { why in
        Emergency.automatic(protection, reason: EmergencyTriggerReason(kind: .deception, summary: "Cat & Mouse: " + why, confidence: 90), detection: nil)
    }
}
// App Firewall: an unknown, untrusted app connected out for the first time -> in-app prompt / notification (never a system dialog).
services.netGuard?.onPrompts = { prompts in
    for p in prompts {
        protection.activity.add(.settings, "New app on the internet: \(p.name)", detail: "\(p.signerLabel) · \(p.host ?? p.address)",
                                outcome: "waiting for your choice", severity: .low, event: .other, actor: .system, target: p.host ?? p.address)
    }
    if let d = try? JSONEncoder.rampart.encode(NetGuardPush(prompts: prompts)) { protection.broadcastNetGuard(d) }
}
// Download Gate + Camera & Microphone Guard (user-session daemon only).
FeatureServices.start(protection)
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
                        outcome: protection.services.realtime?.isRunning == true ? "real-time on" : "real-time off",
                        event: .serviceStarted, actor: .system,
                        facts: ["real-time protection": protection.services.realtime?.isRunning == true ? "On" : "Off",
                                "mode": runtime.userMode ? "User mode" : "System service"])
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
    protection.activity.add(.system, "\(Product.name) protection stopped", detail: why, event: .serviceStopped, actor: .system)
    scheduler.stop()
    // The emergency pf anchor never outlives the daemon (SIGTERM, bootout, uninstall), like DNS below.
    Emergency.shutdown(protection)
    _ = VPNWiring.stop("service stopping")
    services.realtime?.stop()
    FeatureServices.mediaGuard?.stop(); FeatureServices.downloadGate?.stop()
    services.netGuard?.stop()   // unloads the App Firewall pf anchor (re-applied at the next start)
    if let w = services.web, w.isOn { try? w.setOn(false) }
    (services.web as? WebProtection)?.restoreOnExit()
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
