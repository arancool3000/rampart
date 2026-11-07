import Foundation
import AppKit
import CoreWLAN
import Security
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

    /// Step 1 of the existing admin token flow. Asks without a password first (user mode accepts that); only if
    /// the system service insists does it show the macOS admin password sheet. Runs only from a button click.
    static func adminToken(client: DaemonClient) async -> Result<String, EmergencyBridge.Failure> {
        func ask(_ auth: Data?) async -> Result<String, EmergencyBridge.Failure> {
            do {
                switch try await client.request(.requestDisableProtection(authorization: auth, reason: "lift emergency lockdown")) {
                case .disableToken(let t): return .success(t)
                case .error(let e): return .failure(Failure(message: e))
                default: return .failure(Failure(message: "Unexpected reply from \(Product.name)."))
                }
            } catch { return .failure(Failure(message: error.localizedDescription)) }
        }
        let first = await ask(nil)
        if case .success = first { return first }
        guard let form = AdminAuthorization.externalForm() else { return .failure(Failure(message: "Administrator authentication was cancelled.")) }
        return await ask(form)
    }
}

/// AuthorizationServices: shows the standard admin password sheet. Called only after the user clicks "Lift lockdown"
/// (never at launch, never in headless runs, never with RAMPART_NO_PRIVILEGED_TOOLS).
@MainActor
enum AdminAuthorization {
    static func externalForm() -> Data? {
        guard EmergencyAppActions.sessionActionsAllowed else { return nil }
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return nil }
        defer { AuthorizationFree(ref, []) }
        func obtain(_ name: String) -> OSStatus {
            name.withCString { c in
                var item = AuthorizationItem(name: c, valueLength: 0, value: nil, flags: 0)
                return withUnsafeMutablePointer(to: &item) { ip in
                    var rights = AuthorizationRights(count: 1, items: ip)
                    return AuthorizationCopyRights(ref, &rights, nil, [.interactionAllowed, .extendRights, .preAuthorize], nil)
                }
            }
        }
        // The daemon accepts RamPart's own right or, failing that, the standard admin right.
        var st = obtain(ProtectionDisableFlow.rightName)
        if st != errAuthorizationSuccess && st != errAuthorizationCanceled { st = obtain(ProtectionDisableFlow.fallbackRight) }
        guard st == errAuthorizationSuccess else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &form) == errAuthorizationSuccess else { return nil }
        return withUnsafeBytes(of: &form) { Data($0) }
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
        if pending.contains(.alert) {
            Notifier.shared.post(.threat, title: "Emergency lockdown is on",
                                 body: st.state.reason?.summary ?? "\(Product.name) has isolated this Mac.", critical: true)
            done.append(EmergencyAction.Kind.alert.rawValue)
        }
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
