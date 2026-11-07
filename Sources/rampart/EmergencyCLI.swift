import Foundation
import RampartShared
import RampartGuard

/// `sudo rampart emergency off` and `sudo rampart killswitch`: work with plain sudo even if the app is gone and the
/// service is hung or dead. A root peer is authorized by the daemon; when the daemon can't answer within a few
/// seconds the same steps run here directly as root.
enum EmergencyCLI {
    static func run(_ command: String, _ args: [String], json: Bool, socketPath: String?, user: Bool) -> Never {
        let sub = command == "killswitch" ? "killswitch" : (args.first ?? "status")
        switch sub {
        case "status":
            switch request(.emergencyStatus, socketPath: socketPath, user: user, timeout: 5) {
            case .emergency(let d)?:
                if json { print(String(decoding: d, as: UTF8.self)); exit(0) }
                guard let st = try? JSONDecoder.rampart.decode(EmergencyStatus.self, from: d) else { fail("unreadable status") }
                print(st.state.active ? "Lockdown ON: \(EmergencyNotice.plainReason(st.state))" : "No lockdown.")
                if st.state.active { print("Internet: \(st.state.isNetworkBlocked ? "blocked" : "on")\(st.networkSecondsLeft.map { " (restores itself in \($0) s)" } ?? "")") }
                if st.state.active { print("Lift it: \(EmergencyStatus.sudoEscape)") }
                exit(0)
            case .error(let m)?: fail(m)
            default: fail("the \(Product.name) service didn't answer. If the internet is blocked, run: \(EmergencyStatus.sudoEscape)")
            }
        case "off", "lift":
            guard getuid() == 0 else { fail("run it with sudo: \(EmergencyStatus.sudoEscape)") }
            var lines: [String] = []
            switch request(.liftEmergencyLockdown(token: "", force: true), socketPath: socketPath, user: user, timeout: 10) {
            case .emergency?: lines.append("Service: lockdown lifted.")
            case .error(let m)?: lines.append("Service: \(m)")
            default: lines.append("Service: no answer; cleaning up directly.")
            }
            // Always also clean up directly (idempotent): anchor flushed, frozen processes resumed, state lifted.
            lines += Emergency.offline(stateRoot: Paths.supportRoot, dryRun: Privileged.noPrivilegedTools)
            if json { emitList(lines) } else { lines.forEach { print($0) }; print("Internet restored.") }
            exit(0)
        case "killswitch":
            guard getuid() == 0 || Privileged.noPrivilegedTools else { fail("run it with sudo: sudo rampart killswitch") }
            var report: KillSwitch.Report?
            if case .killSwitch(let d)? = request(.killSwitch(token: nil), socketPath: socketPath, user: user, timeout: 3) {
                report = try? JSONDecoder.rampart.decode(KillSwitch.Report.self, from: d)
            }
            // The service didn't answer within 3 s (hung, dead, crash-looping, mismatched): run the plain-tool steps
            // directly as root (this also stops the service).
            if report == nil { report = KillSwitchExec.runOffline(stateRoot: Paths.supportRoot) }
            let r = report!
            if json { let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]; print(String(decoding: (try? enc.encode(r)) ?? Data(), as: UTF8.self)); exit(0) }
            print(KillSwitch.copy)
            for s in r.steps { print("  \(s.ok ? "ok    " : "FAILED") \(s.title)\(s.detail.isEmpty ? "" : " — \(s.detail.prefix(300))")") }
            print(r.summary)
            exit(0)
        default:
            fail("usage: rampart emergency [status|off]  |  sudo rampart killswitch")
        }
    }

    private static func emitList(_ l: [String]) {
        print(String(decoding: (try? JSONSerialization.data(withJSONObject: ["steps": l], options: [.prettyPrinted])) ?? Data(), as: UTF8.self))
    }

    /// One request with a hard timeout; nil when there is no daemon, no answer in time, or a broken connection.
    static func request(_ r: IPCRequest, socketPath: String?, user: Bool, timeout: TimeInterval) -> IPCResponse? {
        guard let t = try? SocketTransport.resolve(explicit: socketPath, user: user) else { return nil }
        let done = DispatchSemaphore(value: 0)
        let box = NSLock(); var out: IPCResponse?
        DispatchQueue.global().async {
            try? t.request(r) { resp in
                if resp.isTerminal { box.lock(); out = resp; box.unlock(); return false }
                return true
            }
            done.signal()
        }
        guard done.wait(timeout: .now() + timeout) == .success else { return nil }
        box.lock(); defer { box.unlock() }; return out
    }
}
