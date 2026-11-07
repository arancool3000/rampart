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

    /// Arguments that would neuter the service if an attacker added them to the job.
    public static let neuteringArguments: Set<String> = ["--no-scheduler", "--dry-run", "--user", "--disable", "--monitor-only", "--help", "--version"]

    /// True if the plist at `path` is one of RamPart's own job definitions: its Label is ours, the program it runs is
    /// exactly one of RamPart's service executables, and nothing in it disables or neuters the job.
    /// hx5: a plist with our Label could previously set Disabled, KeepAlive=false, DYLD_INSERT_LIBRARIES,
    /// RAMPART_NO_PRIVILEGED_TOOLS=1, a non-root UserName, extra neutering arguments, or a Program anywhere under
    /// Contents/Helpers/ and still be accepted silently.
    public static func isOurPlist(_ path: String, paths: GuardPaths) -> Bool {
        var st = stat()
        guard lstat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return false }   // no symlinked plists
        guard let data = FileManager.default.contents(atPath: path), data.count < 1 << 20,
              let p = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else { return false }
        return isOurJob(p, paths: paths)
    }

    public static func isOurJob(_ p: [String: Any], paths: GuardPaths) -> Bool {
        guard let label = p["Label"] as? String, paths.labels.contains(label) else { return false }
        let args = (p["ProgramArguments"] as? [String]) ?? []
        if p["ProgramArguments"] != nil && p["ProgramArguments"] as? [String] == nil { return false }
        let program = (p["Program"] as? String) ?? args.first ?? ""
        guard !program.isEmpty, (program as NSString).isAbsolutePath, paths.isJobExecutable(program) else { return false }
        if p["Program"] != nil, let a0 = args.first, (a0 as NSString).isAbsolutePath, !paths.isJobExecutable(a0) { return false }
        if args.dropFirst().contains(where: { a in neuteringArguments.contains(a) || neuteringArguments.contains { a.hasPrefix($0 + "=") } }) { return false }
        if (p["Disabled"] as? Bool) == true { return false }
        if let k = p["KeepAlive"] as? Bool, k == false { return false }
        if let user = p["UserName"] as? String, label != paths.agentLabel, user != "root" { return false }
        if let env = p["EnvironmentVariables"] as? [String: Any] {
            for (k, v) in env {
                let u = k.uppercased()
                if u.hasPrefix("DYLD_") || u.hasPrefix("RAMPART_") || u == "MallocStackLogging".uppercased() { return false }
                _ = v
            }
        }
        if p["inetdCompatibility"] != nil || p["LaunchOnlyOnce"] as? Bool == true { return false }
        return true
    }

    /// Genuine-build check that a look-alike cannot pass. `isValidBundle` alone trusts signing identifiers, and with
    /// ad-hoc signing anyone can sign anything as `app.rampart.daemon`. This also requires either a trusted Team ID on
    /// every piece, or that the helper binaries match the sealed install manifest (the pin written at install/update).
    /// With neither a trusted Team ID nor a manifest entry, the bundle is NOT treated as genuine (fail closed).
    public static func isGenuineBundle(_ bundle: String, trustedTeamIDs: Set<String>, manifest: InstallManifest?) -> Bool {
        guard isValidBundle(bundle, trustedTeamIDs: trustedTeamIDs) else { return false }
        let app = codeInfo(bundle)
        if let t = app.teamID, !t.isEmpty, trustedTeamIDs.contains(t) { return true }
        guard let m = manifest else { return false }
        let helpers = [bundle + "/Contents/Helpers/rampartd", bundle + "/Contents/Helpers/rampart"]
        var pinned = 0
        for h in helpers {
            let key = m.entries.keys.first { GuardPaths.normalize($0) == GuardPaths.normalize(h) }
            guard let key, let expected = m.entries[key] else { continue }
            pinned += 1
            guard InstallManifest.sha256(ofFile: h) == expected else { return false }
        }
        return pinned == helpers.count
    }
}

public extension GuardPaths {
    /// The long-running service binaries (daemon, watchdog, the bundled user-mode helper). The app's own UI process
    /// is not a service: quitting or killing it is not tampering.
    func isServiceBinary(_ path: String) -> Bool {
        let p = Self.normalize(path)
        if [daemonBinary, watchdogBinary, sentinelBinary].map(Self.normalize).contains(p) { return true }
        let helpers = Self.normalize(appBundle) + "/Contents/Helpers/"
        return p.hasPrefix(helpers)
    }
    func isInAppBundle(_ path: String) -> Bool {
        let p = Self.normalize(path), b = Self.normalize(appBundle)
        return p == b || p.hasPrefix(b + "/")
    }
    /// Process names the service runs under (for pkill / killall matching).
    var serviceNames: [String] {
        ["rampartd", (daemonBinary as NSString).lastPathComponent, (watchdogBinary as NSString).lastPathComponent,
         (sentinelBinary as NSString).lastPathComponent]
    }
    var serviceCommandLines: [String] {
        [daemonBinary, watchdogBinary, sentinelBinary, appBundle + "/Contents/Helpers/rampartd"]
    }
    /// Exact executables a RamPart launch job may run (hx5: `isOurPlist` used to accept anything under
    /// Contents/Helpers/, so a plist pointed at a dropped `Helpers/evil` ran it as root without an alert).
    var jobExecutables: [String] {
        [daemonBinary, watchdogBinary, sentinelBinary, appBundle + "/Contents/Helpers/rampartd", appBundle + "/Contents/Helpers/rampart",
         appBundle + "/Contents/MacOS/Rampart"]
    }
    /// APFS is case-insensitive by default: compare executables case-insensitively.
    func isJobExecutable(_ path: String) -> Bool {
        let p = Self.normalize(path).lowercased()
        return jobExecutables.contains { Self.normalize($0).lowercased() == p }
    }
}
