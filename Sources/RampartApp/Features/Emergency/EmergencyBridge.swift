import Foundation
import AppKit
import CoreWLAN
import Security
import LocalAuthentication
import RampartShared
import RampartGuard

/// IPC needed from the lead (RampartShared.IPCRequest / IPCResponse), all answered with `.emergency(Data)`
/// (JSON of RampartGuard.EmergencyStatus):
///   case emergencyStatus
///   case emergencyLockdown(reason: String)                 // not privileged: locking down is the safe direction
///   case emergencyRescan
///   case liftEmergencyLockdown(token: String, force: Bool) // privileged; token from requestDisableProtection
///   case emergencyAck(actionIDs: [String])                 // app reports vault locked / clipboard cleared / alert shown
///   response: case emergency(Data)
/// Until those exist, every call returns `.unsupported` and the screen explains it calmly.
@MainActor
enum EmergencyBridge {
    struct Failure: Error { var message: String }
    enum Outcome { case status(EmergencyStatus), unsupported, error(String) }

    static func decode(_ data: Data) -> Outcome {
        do { return .status(try JSONDecoder.rampart.decode(EmergencyStatus.self, from: data)) }
        catch { return .error("Could not read the lockdown status: \(error.localizedDescription)") }
    }

    private static func call(_ client: DaemonClient, _ make: () -> IPCRequest?) async -> Outcome {
        guard let req = make() else { return .unsupported }
        do {
            let r = try await client.request(req, timeout: 120)
            return outcome(r)
        } catch { return .error(error.localizedDescription) }
    }

    /// Switch-over point: once `.emergency(Data)` exists, add `case .emergency(let d): return decode(d)`.
    static func outcome(_ r: IPCResponse) -> Outcome {
        switch r {
        case .error(let e): return .error(e)
        case .emergency(let d): return decode(d)
        default: return .unsupported
        }
    }

    // Switch-over: replace each `nil` with the request shown in the comment.
    static func fetch(client: DaemonClient) async -> Outcome { await call(client) { .emergencyStatus } }
    static func engage(client: DaemonClient, note: String) async -> Outcome { await call(client) { .emergencyLockdown(reason: note) } }
    static func rescan(client: DaemonClient) async -> Outcome { await call(client) { .emergencyRescan } }
    static func ack(client: DaemonClient, ids: [String]) async -> Outcome { await call(client) { .emergencyAck(actionIDs: ids) } }
    static func lift(client: DaemonClient, token: String, force: Bool) async -> Outcome {
        await call(client) { .liftEmergencyLockdown(token: token, force: force) }
    }

    static func keepBlocking(client: DaemonClient) async -> Outcome { await call(client) { .emergencyNetwork(keep: true, token: nil) } }
    static func restoreNetwork(client: DaemonClient, token: String) async -> Outcome {
        await call(client) { .emergencyNetwork(keep: false, token: token) }
    }

    /// Super Kill Switch path A: the daemon, with a 3 s ceiling (a hung service must not hold the user offline).
    static func killSwitch(client: DaemonClient, token: String) async -> Result<KillSwitch.Report, Failure> {
        do {
            switch try await client.request(.killSwitch(token: token), timeout: 3) {
            case .killSwitch(let d):
                guard let r = try? JSONDecoder.rampart.decode(KillSwitch.Report.self, from: d) else { return .failure(Failure(message: "unreadable reply")) }
                return .success(r)
            case .error(let e): return .failure(Failure(message: e))
            default: return .failure(Failure(message: "The service is too old for the kill switch."))
            }
        } catch { return .failure(Failure(message: error.localizedDescription)) }
    }

    /// Admin-authenticated call (lift, restore internet, kill switch). User incident 2026-11-09: Touch ID succeeded once
    /// and the lift still failed; afterwards the app never asked again and showed "administrator authentication is
    /// required". Root cause: the AuthorizationRef was freed (`defer AuthorizationFree`) before the service read its
    /// external form, so the service could never verify it; and the right stayed cached, so later clicks didn't prompt.
    /// Now every call: a fresh prompt (Touch ID or password) → a fresh token → the call → the authorization is freed
    /// with its rights destroyed. Nothing (token, failure, credential) is reused between clicks.
    static func withAdminToken(client: DaemonClient, purpose: String, _ body: (String) async -> Outcome) async -> Outcome {
        func ask(_ auth: Data?) async -> Result<String, EmergencyBridge.Failure> {
            do {
                switch try await client.request(.requestDisableProtection(authorization: auth, reason: purpose)) {
                case .disableToken(let t): return .success(t)
                case .error(let e): return .failure(Failure(message: e))
                default: return .failure(Failure(message: "Unexpected reply from \(Product.name)."))
                }
            } catch { return .failure(Failure(message: error.localizedDescription)) }
        }
        // Headless / dev runs (zero pop-ups): no prompt; only a user-mode service accepts that.
        guard EmergencyAppActions.sessionActionsAllowed else {
            switch await ask(nil) {
            case .success(let t): return await body(t)
            case .failure(let f): return .error(f.message)
            }
        }
        let handle: AdminAuthHandle
        switch AdminAuthorization.obtain(prompt: "\(Product.name) needs an administrator to \(purpose).") {
        case .failure(let f): return .error(f.message)
        case .success(let h): handle = h
        }
        defer { handle.release() }   // only after the service has redeemed the token
        switch await ask(handle.form) {
        case .failure(let f): return .error(f.message)
        case .success(let t): return await body(t)
        }
    }
}

/// An admin authorization kept alive until the service has used it, then freed with its rights destroyed so the
/// next action prompts again.
final class AdminAuthHandle: @unchecked Sendable {
    let form: Data
    private var ref: AuthorizationRef?
    private let lock = NSLock()
    init(ref: AuthorizationRef, form: Data) { self.ref = ref; self.form = form }
    func release() {
        lock.lock(); let r = ref; ref = nil; lock.unlock()
        if let r { AuthorizationFree(r, [.destroyRights]) }
    }
    deinit { release() }
}

/// AuthorizationServices: shows the standard admin sheet (Touch ID or password). Called only after the user clicks
/// (never at launch, never in headless runs, never with RAMPART_NO_PRIVILEGED_TOOLS).
@MainActor
enum AdminAuthorization {
    /// Last AuthorizationCopyRights result, so a failure isn't misreported as "cancelled".
    static var lastStatus: OSStatus = errAuthorizationSuccess

    static func message(for status: OSStatus) -> String {
        switch status {
        case errAuthorizationCanceled: return "Administrator authentication was cancelled. Nothing was changed; press the button again to retry."
        case errAuthorizationDenied: return "macOS refused the administrator authentication (wrong password, or this account isn't an administrator). Nothing was changed."
        case errAuthorizationInteractionNotAllowed: return "macOS couldn't show the administrator prompt. Bring \(Product.name) to the front and try again, or run in Terminal: \(EmergencyStatus.sudoEscape)"
        default: return "macOS didn't complete the administrator prompt (code \(status)). Try again, use Super Kill Switch, or run in Terminal: \(EmergencyStatus.sudoEscape)"
        }
    }

    static func obtain(prompt: String) -> Result<AdminAuthHandle, EmergencyBridge.Failure> {
        guard EmergencyAppActions.sessionActionsAllowed else { return .failure(.init(message: "Not available in this build.")) }
        // The sheet only appears for the frontmost app; RamPart often runs as a menu bar (background) app.
        NSApp.activate(ignoringOtherApps: true)
        var ref: AuthorizationRef?
        // A brand-new authorization every time: no credential from an earlier click is reused.
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else {
            return .failure(.init(message: "macOS couldn't start an administrator authorization. Try again."))
        }
        func obtain(_ name: String) -> OSStatus {
            name.withCString { c in
                prompt.withCString { pc in
                    var item = AuthorizationItem(name: c, valueLength: 0, value: nil, flags: 0)
                    var envItem = AuthorizationItem(name: kAuthorizationEnvironmentPrompt, valueLength: strlen(pc),
                                                    value: UnsafeMutableRawPointer(mutating: pc), flags: 0)
                    return withUnsafeMutablePointer(to: &item) { ip in
                        withUnsafeMutablePointer(to: &envItem) { ep in
                            var rights = AuthorizationRights(count: 1, items: ip)
                            var env = AuthorizationEnvironment(count: 1, items: ep)
                            return AuthorizationCopyRights(ref, &rights, &env, [.interactionAllowed, .extendRights, .preAuthorize], nil)
                        }
                    }
                }
            }
        }
        // The daemon accepts RamPart's own right or, failing that, the standard admin right.
        var st = obtain(ProtectionDisableFlow.rightName)
        if st != errAuthorizationSuccess && st != errAuthorizationCanceled { st = obtain(ProtectionDisableFlow.fallbackRight) }
        lastStatus = st
        guard st == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            return .failure(.init(message: message(for: st)))
        }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &form) == errAuthorizationSuccess else {
            AuthorizationFree(ref, [.destroyRights])
            return .failure(.init(message: "macOS couldn't hand the administrator authorization to \(Product.name). Try again."))
        }
        return .success(AdminAuthHandle(ref: ref, form: withUnsafeBytes(of: &form) { Data($0) }))
    }
}

/// Lockdown steps that belong to the user's session. ZERO POP-UPS: none of these runs in headless/dev runs.
@MainActor
enum EmergencyAppActions {
    static var sessionActionsAllowed: Bool {
        !Headless.active && ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] != "1"
    }

    /// Runs the app-side actions once per lockdown; returns the action ids done (reported back with emergencyAck).
    static func perform(_ st: EmergencyStatus) -> [String] {
        guard st.state.active, sessionActionsAllowed else { return [] }
        var done: [String] = []
        let pending = Set(st.state.actions.filter { $0.runner == .app && !st.state.appActionsDone.contains($0.id) }.map(\.kind))
        // The notification itself is posted by EmergencyModel.apply for every transition (EmergencyNotice).
        if pending.contains(.alert) { done.append(EmergencyAction.Kind.alert.rawValue) }
        if pending.contains(.lockVault) { PasswordsModel.shared.lock(); done.append(EmergencyAction.Kind.lockVault.rawValue) }
        if pending.contains(.clearClipboard) { NSPasteboard.general.clearContents(); done.append(EmergencyAction.Kind.clearClipboard.rawValue) }
        return done
    }

    /// Wi-Fi off via CoreWLAN. Only ever called from the escalation screen's button.
    static func turnWiFiOff() -> String? {
        guard sessionActionsAllowed else { return "Not available in this build." }
        guard let iface = CWWiFiClient.shared().interface() else { return "No Wi-Fi interface found." }
        do { try iface.setPower(false); return nil } catch { return "macOS refused: \(error.localizedDescription). Use the Wi-Fi menu in the menu bar." }
    }

    static func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}


/// Super Kill Switch user-presence gate: Touch ID, or the Mac's password when Touch ID isn't available.
/// Runs only from a button click (never at launch, never headless, never with RAMPART_NO_PRIVILEGED_TOOLS).
@MainActor
enum KillSwitchAuth {
    static func confirm() async -> Bool {
        guard EmergencyAppActions.sessionActionsAllowed else { return false }
        let ctx = LAContext()
        var e: NSError?
        let policy: LAPolicy = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &e)
            ? .deviceOwnerAuthenticationWithBiometrics : .deviceOwnerAuthentication
        ctx.localizedFallbackTitle = "Use Password"
        do { return try await ctx.evaluatePolicy(policy, localizedReason: "turn off everything \(Product.name) is doing to your network") }
        catch {
            if policy == .deviceOwnerAuthenticationWithBiometrics, (error as? LAError)?.code == .userFallback {
                return (try? await LAContext().evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "turn off everything \(Product.name) is doing to your network")) ?? false
            }
            return false
        }
    }
}

/// Super Kill Switch path B: when the service doesn't answer within 3 s (hung, dead, crash-looping, mismatched), run
/// the bundled, signed killswitch.sh from inside this verified app bundle through the macOS administrator prompt
/// (which offers Touch ID). The ONE documented exception to the zero pop-ups rule: the user pressed the button.
/// With RAMPART_NO_PRIVILEGED_TOOLS (tests) it runs the script in dry-run mode without any prompt.
enum KillSwitchScript {
    struct Result { var ok: Bool; var output: String }

    /// The script, only from this app's own signed bundle (its code signature must validate).
    static func locate(bundle: String = Bundle.main.bundlePath) -> String? {
        guard let p = KillSwitch.bundledScript(inBundle: bundle) else { return nil }
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: bundle) as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures), nil) == errSecSuccess else { return nil }
        return p
    }

    static func run(script: String, dryRun: Bool) -> Result {
        let proc = Process(); let pipe = Pipe()
        if dryRun {
            proc.executableURL = URL(fileURLWithPath: "/bin/sh")
            proc.arguments = [script, "--dry-run"]
        } else {
            let sh = "/bin/sh '" + script.replacingOccurrences(of: "'", with: "'\\''") + "'"
            let shell = sh.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            proc.arguments = ["-e", "do shell script \"\(shell)\" with administrator privileges with prompt \"\(Product.name) Super Kill Switch: turn off everything \(Product.name) is doing to your network.\""]
        }
        proc.standardOutput = pipe; proc.standardError = pipe
        do { try proc.run() } catch { return Result(ok: false, output: error.localizedDescription) }
        proc.waitUntilExit()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        return Result(ok: proc.terminationStatus == 0, output: out)
    }
}
