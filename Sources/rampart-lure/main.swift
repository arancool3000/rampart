import Foundation
import Darwin
import os
import RampartGuard

// rampart-lure: the Cat & Mouse network lure helper (containment layers 1-6 and 8 live here).
// It is started only by the installed root daemon, via the launchd plist from `LureContainment.plan`, after the user
// turned the lure on and confirmed it; that plist runs it under sandbox-exec as the login-less _rampartlure account.
// The helper never spawns anything, never reads or writes files, and refuses to run as root.
// Attempts are reported as one JSON line each to the unified log (subsystem app.rampart.lure) for the daemon to pick up.

let log = Logger(subsystem: "app.rampart.lure", category: "lure")
func fail(_ msg: String, _ code: Int32) -> Never {
    FileHandle.standardError.write(Data("rampart-lure: \(msg)\n".utf8))
    log.error("\(msg, privacy: .public)")
    exit(code)
}

if getuid() == 0 || geteuid() == 0 { fail("refusing to run as root (layer 1: the lure is never privileged)", 77) }

let args: LureHelperArgs
do { args = try LureHelperArgs.parse(Array(CommandLine.arguments.dropFirst())) } catch { fail("\(error)", 64) }

let server: TarpitServer
do {
    server = try TarpitServer(port: args.port, scope: args.scope, localSubnets: args.localSubnets, confirmedAnywhere: args.confirmedAnywhere)
} catch { fail("\(error)", 78) }

let encoder = JSONEncoder()
encoder.dateEncodingStrategy = .iso8601
server.onAttempt = { a in
    guard let d = try? encoder.encode(a) else { return }
    log.notice("attempt \(String(decoding: d, as: UTF8.self), privacy: .public)")
}

do { try server.start() } catch { fail("\(error)", 75) }
log.notice("listening on \(server.bindAddress, privacy: .public):\(server.boundPort) scope=\(args.scope.rawValue, privacy: .public)")

// Kill switch: launchd bootout sends SIGTERM.
signal(SIGTERM, SIG_IGN); signal(SIGINT, SIG_IGN)
var sources: [DispatchSourceSignal] = []
for sig in [SIGTERM, SIGINT] {
    let s = DispatchSource.makeSignalSource(signal: sig, queue: .main)
    s.setEventHandler { server.stop(); exit(0) }
    s.resume(); sources.append(s)
}
dispatchMain()
