import Foundation
import Security
import RampartShared
import RampartGuard

/// hx10 #14: the CLI side of the admin-confirmed settings session. The root daemon refuses protection-weakening
/// calls from the CLI (`realtime off`, `allow`, `remote lockdown off`, broad exclusions, ...) unless this very process
/// holds a settings session: requestDisableProtection(authorization:) -> disableProtection(token, minutes: 0).
/// The macOS administrator prompt appears only when a person runs the command in a terminal, never in scripts,
/// never without a TTY and never with RAMPART_NO_PRIVILEGED_TOOLS=1.
enum CLISettingsSession {
    static func isSessionDenial(_ m: String) -> Bool {
        m.contains("needs administrator confirmation")
    }

    static var interactive: Bool {
        isatty(STDIN_FILENO) != 0 && isatty(STDERR_FILENO) != 0
            && ProcessInfo.processInfo.environment["RAMPART_NO_PRIVILEGED_TOOLS"] != "1"
    }

    static func open(call: (IPCRequest) -> IPCResponse) -> Result<Void, Failure> {
        guard interactive else {
            return .failure(Failure("Run this command in a terminal to confirm with an administrator password, or use the \(Product.name) app."))
        }
        FileHandle.standardError.write(Data("\(Product.name) needs an administrator to confirm this change.\n".utf8))
        guard let form = externalForm() else { return .failure(Failure("Administrator confirmation was cancelled.")) }
        guard case .disableToken(let token) = call(.requestDisableProtection(authorization: form, reason: "command line settings change")) else {
            return .failure(Failure("\(Product.name) did not accept the administrator confirmation."))
        }
        guard case .ok = call(.disableProtection(token: token, minutes: 0)) else {
            return .failure(Failure("\(Product.name) could not open a settings session."))
        }
        return .success(())
    }

    struct Failure: Error, CustomStringConvertible { var description: String; init(_ s: String) { description = s } }

    /// AuthorizationServices: the standard macOS administrator prompt (RamPart's own right, else system.privilege.admin).
    static func externalForm() -> Data? {
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
        var st = obtain(ProtectionDisableFlow.rightName)
        if st != errAuthorizationSuccess && st != errAuthorizationCanceled { st = obtain(ProtectionDisableFlow.fallbackRight) }
        guard st == errAuthorizationSuccess else { return nil }
        var form = AuthorizationExternalForm()
        guard AuthorizationMakeExternalForm(ref, &form) == errAuthorizationSuccess else { return nil }
        return withUnsafeBytes(of: &form) { Data($0) }
    }
}
