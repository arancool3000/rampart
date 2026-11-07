import Foundation
import Security
import RampartShared

// Telling a legitimate RamPart update apart from tampering (red-team fix, 2026-11-07).
// The lead's update path (`ditto` a new bundle next to the old one, `rm -rf` the old one, `mv` the new one in)
// used to raise fileTamper. Bundle changes are now held for a short grace period and only reported if, once the
// dust settles, /Applications/RamPart.app is not a valid RamPart build. Launch plist rewrites are reported only
// when the new content is not RamPart's own job definition.
public enum RamPartIdentity {
    public static let appBundleID = "app.rampart.app"
    public static let daemonSigningID = "app.rampart.daemon"
    public static let cliSigningID = "app.rampart.cli"

    public struct CodeInfo: Sendable { public let valid: Bool; public let identifier: String?; public let teamID: String? }

    /// Static signature check of a file or bundle (same as `codesign --verify`; reads the disk only, never prompts).
    public static func codeInfo(_ path: String) -> CodeInfo {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return CodeInfo(valid: false, identifier: nil, teamID: nil)
        }
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate), nil) == errSecSuccess
        var info: CFDictionary?
        SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let d = (info as? [String: Any]) ?? [:]
        return CodeInfo(valid: valid, identifier: d[kSecCodeInfoIdentifier as String] as? String,
                        teamID: d[kSecCodeInfoTeamIdentifier as String] as? String)
    }

    /// True if `bundle` is a genuine RamPart build: bundle ID app.rampart.app, a valid app signature, and helpers
    /// `Contents/Helpers/rampartd` + `rampart` that verify and carry RamPart's signing identifiers. When the bundle is
    /// signed with a Team ID and `trustedTeamIDs` is non-empty, every piece must carry one of those Team IDs.
    public static func isValidBundle(_ bundle: String, trustedTeamIDs: Set<String> = []) -> Bool {
        let infoPlist = bundle + "/Contents/Info.plist"
        guard let data = FileManager.default.contents(atPath: infoPlist), data.count < 1 << 20,
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              plist["CFBundleIdentifier"] as? String == appBundleID else { return false }
        let app = codeInfo(bundle)
        let daemon = codeInfo(bundle + "/Contents/Helpers/rampartd")
        let cli = codeInfo(bundle + "/Contents/Helpers/rampart")
        guard app.valid, daemon.valid, cli.valid,
              daemon.identifier == daemonSigningID, cli.identifier == cliSigningID else { return false }
        let teams = [app.teamID, daemon.teamID, cli.teamID]
        if let t = app.teamID, !t.isEmpty {
            if !trustedTeamIDs.isEmpty && !trustedTeamIDs.contains(t) { return false }
            if teams.contains(where: { $0 != t }) { return false }
        } else if teams.contains(where: { ($0 ?? "").isEmpty == false }) {
            return false   // mixed ad-hoc app with team-signed helpers: not a build we produce
        }
        return true
    }

    /// True if the plist at `path` is one of RamPart's own job definitions: its Label is ours and the program it
    /// runs lives in a RamPart install path.
    public static func isOurPlist(_ path: String, paths: GuardPaths) -> Bool {
        guard let data = FileManager.default.contents(atPath: path), data.count < 1 << 20,
              let p = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let label = p["Label"] as? String, paths.labels.contains(label) else { return false }
        let program = (p["Program"] as? String) ?? ((p["ProgramArguments"] as? [String])?.first) ?? ""
        guard !program.isEmpty else { return false }
        return paths.isServiceBinary(program)
    }
}

public extension GuardPaths {
    /// The long-running service binaries (daemon, watchdog, the bundled user-mode helper). The app's own UI process
    /// is not a service: quitting or killing it is not tampering.
    func isServiceBinary(_ path: String) -> Bool {
        let p = Self.normalize(path)
        if [daemonBinary, watchdogBinary].map(Self.normalize).contains(p) { return true }
        let helpers = Self.normalize(appBundle) + "/Contents/Helpers/"
        return p.hasPrefix(helpers)
    }
    func isInAppBundle(_ path: String) -> Bool {
        let p = Self.normalize(path), b = Self.normalize(appBundle)
        return p == b || p.hasPrefix(b + "/")
    }
    /// Process names the service runs under (for pkill / killall matching).
    var serviceNames: [String] {
        ["rampartd", (daemonBinary as NSString).lastPathComponent, (watchdogBinary as NSString).lastPathComponent]
    }
    var serviceCommandLines: [String] {
        [daemonBinary, watchdogBinary, appBundle + "/Contents/Helpers/rampartd"]
    }
}
