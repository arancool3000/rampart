import Foundation
import RampartShared

/// What a check needs to give a definite answer. Without it the check reports `unknown`.
public enum PostureRequirement: String, Codable, Sendable {
    case admin, fullDiskAccess, network
}

/// Static description of one posture check (doc 07 §15).
public struct PostureCheckSpec: Sendable {
    public let id: String
    public let title: String
    public let weight: Int
    public let requires: Set<PostureRequirement>
    let evaluate: @Sendable (PostureContext) -> ParseOutcome
}

/// Shared per-scan state handed to each check.
public final class PostureContext: @unchecked Sendable {
    public let runner: CommandRunning
    public let env: PostureEnvironment
    public let commandTimeout: TimeInterval
    public let hasFullDiskAccess: Bool
    /// Home of the logged-in (console) user: user-domain preferences are read from here, also when running as root.
    public let userHome: String

    init(runner: CommandRunning, env: PostureEnvironment, commandTimeout: TimeInterval, hasFullDiskAccess: Bool, userHome: String) {
        self.runner = runner; self.env = env; self.commandTimeout = commandTimeout
        self.hasFullDiskAccess = hasFullDiskAccess; self.userHome = userHome
    }

    public func run(_ exe: String, _ args: [String]) -> CommandResult { runner.run(exe, args, timeout: commandTimeout) }

    /// Combined output when the command ran (any exit status), nil if it timed out or couldn't launch.
    public func output(_ exe: String, _ args: [String]) -> String? {
        let r = run(exe, args); return r.usable ? r.combined : nil
    }

    /// stdout of a successful (`exit 0`) command, else nil.
    public func success(_ exe: String, _ args: [String]) -> String? {
        let r = run(exe, args); return r.usable && r.status == 0 ? r.stdout.trimmingCharacters(in: .whitespacesAndNewlines) : nil
    }

    /// Reads a key from a user-domain preference. Unprivileged: `defaults read`; as root: the console user's plist file.
    public func userDefault(_ domain: String, _ key: String) -> String? {
        if env.isRoot {
            let path = userHome + "/Library/Preferences/\(domain).plist"
            guard let d = PostureParsers.plistDictionary(env.readFile(path)), let v = d[key] else { return nil }
            if let n = v as? NSNumber { return n.stringValue }
            return "\(v)"
        }
        return success("/usr/bin/defaults", ["read", domain, key])
    }

    /// A system plist as a dictionary, via `defaults export` (goes through cfprefsd, so never stale).
    public func systemPlist(_ path: String) -> [String: Any]? {
        let r = run("/usr/bin/defaults", ["export", path, "-"])
        guard r.usable, r.status == 0 else { return nil }
        return PostureParsers.plistDictionary(Data(r.stdout.utf8))
    }
}

public struct PostureReport: Codable, Sendable {
    public var checks: [PostureCheck]
    public var score: SecurityScore
    public var requirements: [String: [PostureRequirement]]
    /// IDs of unknown checks that would work with admin (daemon) or Full Disk Access.
    public var needsPermission: [String]
    public var isRoot: Bool
    public var hasFullDiskAccess: Bool
    public var duration: TimeInterval
    public var date: Date
}

/// Runs the ~25 posture checks concurrently, each command with its own timeout, under an overall deadline.
public final class PostureScanner: @unchecked Sendable {
    public let runner: CommandRunning
    public let environment: PostureEnvironment
    public var commandTimeout: TimeInterval
    public var overallDeadline: TimeInterval
    public var hasFullDiskAccess: Bool?
    public var userHome: String?

    public init(runner: CommandRunning = ProcessRunner(), environment: PostureEnvironment = .live(),
                commandTimeout: TimeInterval = 4, overallDeadline: TimeInterval = 9) {
        self.runner = runner; self.environment = environment
        self.commandTimeout = commandTimeout; self.overallDeadline = overallDeadline
    }

    public static var specs: [PostureCheckSpec] { PostureChecks.all }

    /// Scans and returns the checks only (for `IPCResponse.posture`).
    public func checks(ignoring: Set<String> = []) -> [PostureCheck] { scan(ignoring: ignoring).checks }

    public func scan(ignoring: Set<String> = []) -> PostureReport {
        let start = Date()
        let env = environment
        let home = userHome ?? PostureScanner.consoleUserHome(env: env)
        let fda = hasFullDiskAccess ?? FullDiskAccess.isGranted(home: home)
        let ctx = PostureContext(runner: runner, env: env, commandTimeout: commandTimeout, hasFullDiskAccess: fda, userHome: home)
        let specs = PostureScanner.specs

        final class Slots: @unchecked Sendable {
            let lock = NSLock(); var values: [ParseOutcome?]
            init(_ n: Int) { values = Array(repeating: nil, count: n) }
        }
        let slots = Slots(specs.count)
        let group = DispatchGroup()
        let q = DispatchQueue(label: "app.rampart.posture", qos: .userInitiated, attributes: .concurrent)
        for (i, spec) in specs.enumerated() {
            group.enter()
            q.async {
                let o = spec.evaluate(ctx)
                slots.lock.lock(); slots.values[i] = o; slots.lock.unlock()
                group.leave()
            }
        }
        _ = group.wait(timeout: .now() + overallDeadline)
        slots.lock.lock(); let outcomes = slots.values; slots.lock.unlock()

        var checks: [PostureCheck] = []
        var needs: [String] = []
        var reqs: [String: [PostureRequirement]] = [:]
        for (i, spec) in specs.enumerated() {
            var o = outcomes[i] ?? .unknown("This check took too long and was skipped.")
            if o.state == .unknown {
                let missingAdmin = spec.requires.contains(.admin) && !env.isRoot
                let missingFDA = spec.requires.contains(.fullDiskAccess) && !fda
                if missingAdmin || missingFDA { needs.append(spec.id) }
                if missingAdmin && o.detail == ParseOutcome.unknown().detail { o.detail = "Needs the Rampart helper (admin) to check." }
            }
            reqs[spec.id] = spec.requires.sorted { $0.rawValue < $1.rawValue }
            let fixable = o.state == .fail && PostureFixer.canFix(spec.id)
            checks.append(PostureCheck(id: spec.id, title: spec.title, state: o.state, weight: spec.weight, detail: o.detail,
                                       fixable: fixable, fixHint: PostureChecks.fixHint(spec.id, fixable: fixable)))
        }
        return PostureReport(checks: checks, score: SecurityScore.compute(checks, ignoring: ignoring), requirements: reqs,
                             needsPermission: needs, isRoot: env.isRoot, hasFullDiskAccess: fda,
                             duration: Date().timeIntervalSince(start), date: start)
    }

    /// Home of the console user when running as root (daemon); otherwise the environment's home.
    static func consoleUserHome(env: PostureEnvironment) -> String {
        guard env.isRoot,
              let owner = (try? FileManager.default.attributesOfItem(atPath: "/dev/console"))?[.ownerAccountName] as? String,
              owner != "root", let home = NSHomeDirectoryForUser(owner) else { return env.home }
        return home
    }
}

/// The check table (doc 07 §15). Weights are the doc's (they sum to 112, not 100; the score renormalises over known checks). Lockdown Mode is a +2 bonus, Rosetta and firmware password are 0.
public enum PostureChecks {
    static let fw = PostureFixer.socketfilterfw
    static let launchctl = "/bin/launchctl"

    static func spec(_ id: String, _ title: String, _ weight: Int, _ requires: Set<PostureRequirement> = [],
                     _ eval: @escaping @Sendable (PostureContext) -> ParseOutcome) -> PostureCheckSpec {
        PostureCheckSpec(id: id, title: title, weight: weight, requires: requires, evaluate: eval)
    }

    static func parse(_ s: String?, _ f: (String) -> ParseOutcome) -> ParseOutcome { s.map(f) ?? .unknown() }

    public static let all: [PostureCheckSpec] = [
        spec("fileVault", "FileVault disk encryption", 12) { c in parse(c.output("/usr/bin/fdesetup", ["status"]), PostureParsers.fileVault) },
        spec("sip", "System Integrity Protection", 12) { c in parse(c.output("/usr/bin/csrutil", ["status"]), PostureParsers.sip) },
        spec("ssv", "Sealed system volume", 10) { c in parse(c.output("/usr/bin/csrutil", ["authenticated-root", "status"]), PostureParsers.ssv) },
        spec("gatekeeper", "Gatekeeper", 8) { c in parse(c.output("/usr/sbin/spctl", ["--status"]), PostureParsers.gatekeeper) },
        spec("firewall", "Firewall", 8) { c in parse(c.output(fw, ["--getglobalstate"]), PostureParsers.firewall) },
        spec("stealthMode", "Firewall stealth mode", 3) { c in parse(c.output(fw, ["--getstealthmode"]), PostureParsers.stealthMode) },
        spec("autoUpdates", "Automatic updates", 8) { c in
            PostureParsers.autoUpdates(softwareUpdate: c.systemPlist("/Library/Preferences/com.apple.SoftwareUpdate"),
                                       appStoreAutoUpdate: c.success("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.commerce", "AutoUpdate"]))
        },
        spec("osUpToDate", "macOS updates", 8) { c in
            PostureParsers.osUpToDate(softwareUpdate: c.systemPlist("/Library/Preferences/com.apple.SoftwareUpdate"),
                                      currentVersion: c.output("/usr/bin/sw_vers", []).flatMap(PostureParsers.productVersion))
        },
        spec("xprotectFresh", "XProtect definitions", 4) { c in
            let bundles = ["/var/protected/xprotect/XProtect.bundle/Contents/Info.plist",
                           "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"].map { p in
                (version: PostureParsers.plistDictionary(c.env.readFile(p))?["CFBundleShortVersionString"] as? String,
                 modified: c.env.modificationDate(p))
            }
            return PostureParsers.xprotectFreshness(bundles: bundles, now: c.env.now)
        },
        spec("screenLock", "Password after sleep or screen saver", 6) { c in
            parse(c.output("/usr/sbin/sysadminctl", ["-screenLock", "status"]), { PostureParsers.screenLock($0) })
        },
        spec("guestAccount", "Guest account", 3) { c in
            PostureParsers.guestAccount(sysadminctl: c.output("/usr/sbin/sysadminctl", ["-guestAccount", "status"]),
                                        guestEnabledDefault: c.success("/usr/bin/defaults", ["read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]))
        },
        spec("remoteLogin", "Remote Login (SSH)", 5) { c in
            let svc = c.output(launchctl, ["print", "system/com.openssh.sshd"])
            if let s = svc, PostureParsers.launchdService(s) != .unknown { return PostureParsers.remoteLogin(service: s, disabled: [:]) }
            let dis = c.output(launchctl, ["print-disabled", "system"]).map(PostureParsers.disabledServices) ?? [:]
            return PostureParsers.remoteLogin(service: svc, disabled: dis)
        },
        spec("screenSharing", "Screen Sharing and Remote Management", 5) { c in
            PostureParsers.screenSharing(service: c.output(launchctl, ["print", "system/com.apple.screensharing"]),
                                         remoteManagementFlagExists: c.env.fileExists("/Library/Application Support/Apple/Remote Desktop/RemoteManagement.launchd"))
        },
        spec("fileSharing", "File Sharing", 3) { c in
            PostureParsers.fileSharing(service: c.output(launchctl, ["print", "system/com.apple.smbd"]))
        },
        spec("sharingServices", "Other sharing services", 3) { c in
            let natPath = "/Library/Preferences/SystemConfiguration/com.apple.nat.plist"
            let natData = c.env.readFile(natPath)
            return PostureParsers.sharingServices(
                remoteAppleEvents: c.output(launchctl, ["print", "system/com.apple.AEServer"]),
                natPlist: PostureParsers.plistDictionary(natData), natPlistMissing: !c.env.fileExists(natPath),
                cupsctl: c.success("/usr/sbin/cupsctl", []),
                mediaSharing: c.userDefault("com.apple.amp.mediasharingd", "home-sharing-enabled") ?? "0",
                contentCaching: c.output("/usr/bin/AssetCacheManagerUtil", ["status"]))
        },
        spec("airDrop", "AirDrop", 2) { c in PostureParsers.airDrop(c.userDefault("com.apple.sharingd", "DiscoverableMode")) },
        spec("lockdownMode", "Lockdown Mode (bonus)", 2) { c in
            let sys = PostureParsers.plistDictionary(c.env.readFile("/Library/Preferences/.GlobalPreferences.plist"))?["LDMGlobalEnabled"]
            let user = c.userDefault(".GlobalPreferences", "LDMGlobalEnabled")
            return PostureParsers.lockdownMode(user ?? (PostureParsers.boolValue(sys) == true ? "1" : nil))
        },
        spec("adminCount", "Administrator accounts", 4) { c in
            parse(c.output("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"]), PostureParsers.adminCount)
        },
        spec("secureKeyboard", "Terminal Secure Keyboard Entry", 1) { c in
            PostureParsers.secureKeyboardEntry(c.userDefault("com.apple.Terminal", "SecureKeyboardEntry"))
        },
        spec("rosetta", "Rosetta (Intel app support)", 0) { c in
            guard c.env.isAppleSilicon else { return PostureParsers.rosetta(pgrepStatus: nil, oahDirExists: false, isAppleSilicon: false) }
            let r = c.run("/usr/bin/pgrep", ["-x", "oahd"])
            return PostureParsers.rosetta(pgrepStatus: r.usable ? r.status : nil,
                                          oahDirExists: c.env.fileExists("/Library/Apple/usr/libexec/oah"), isAppleSilicon: true)
        },
        spec("outdatedApps", "Third-party apps are up to date", 5, [.network]) { _ in
            .unknown("Not checked yet: needs an app version feed.")
        },
        spec("tccReview", "App permissions review", 4, [.fullDiskAccess]) { c in
            let r = TCCReview.review(home: c.userHome)
            switch r.status {
            case .ok: return .init(r.findings.isEmpty ? .pass : .fail, r.message)
            case .needsFullDiskAccess: return .unknown("Needs Full Disk Access to review app permissions.")
            case .notFound, .error: return .unknown(r.message)
            }
        },
        spec("secureBoot", "Startup security (Secure Boot)", 3, [.admin]) { c in
            guard c.env.isAppleSilicon else { return .unknown("Startup security on Intel Macs isn't checked yet.") }
            guard c.env.isRoot else { return .unknown("Needs the Rampart helper (admin) to check.") }
            return parse(c.output("/usr/bin/bputil", ["-d"]), PostureParsers.secureBoot)
        },
        spec("profiles", "Configuration profiles", 3) { c in
            parse(c.output("/usr/bin/profiles", c.env.isRoot ? ["list", "-all"] : ["list"]), PostureParsers.profiles)
        },
        spec("trustedRoots", "Added trusted certificates", 2) { c in
            parse(c.output("/usr/bin/security", ["dump-trust-settings", "-d"]), PostureParsers.trustedRoots)
        },
        spec("firmwarePassword", "Firmware password (Intel only)", 0, [.admin]) { c in
            guard !c.env.isAppleSilicon else { return .init(.notApplicable, "Not used on Apple silicon; startup security covers this.") }
            guard c.env.isRoot else { return .unknown("Needs the Rampart helper (admin) to check.") }
            return parse(c.output("/usr/sbin/firmwarepasswd", ["-check"]), PostureParsers.firmwarePassword)
        },
    ]

    static func fixHint(_ id: String, fixable: Bool) -> String {
        if fixable { return PostureFixer.fix(for: id).map { $0.title + "." } ?? "" }
        switch id {
        case "fileVault": return "Turn on FileVault in System Settings > Privacy & Security."
        case "sip": return "Turn SIP back on from macOS Recovery (csrutil enable)."
        case "ssv": return "Turn the sealed system volume back on from macOS Recovery (csrutil authenticated-root enable)."
        case "gatekeeper": return "Allow apps from the App Store and identified developers in Privacy & Security."
        case "firewall": return "Turn on the firewall in System Settings > Network > Firewall."
        case "stealthMode": return "Turn on stealth mode in Firewall options."
        case "autoUpdates": return "Turn on automatic updates in System Settings > General > Software Update."
        case "osUpToDate": return "Install the update in System Settings > General > Software Update."
        case "xprotectFresh": return "Make sure \"Install Security Responses and system files\" is on."
        case "screenLock": return "Set \"Require password\" to 5 minutes or less in Lock Screen settings."
        case "guestAccount": return "Turn off the guest user in Users & Groups."
        case "remoteLogin", "screenSharing", "fileSharing", "sharingServices": return "Turn off sharing you don't use in System Settings > General > Sharing."
        case "airDrop": return "Set AirDrop to Contacts Only in Control Centre."
        case "lockdownMode": return "Optional. Only for people who may be personally targeted."
        case "adminCount": return "Use a standard account day to day, and keep one admin account."
        case "secureKeyboard": return "In Terminal, choose Terminal > Secure Keyboard Entry."
        case "tccReview": return "Remove permissions you don't recognise in Privacy & Security."
        case "secureBoot": return "Set Full Security in Startup Security Utility (macOS Recovery)."
        case "profiles": return "Remove profiles you don't recognise in System Settings > General > Device Management."
        case "trustedRoots": return "Remove certificates you don't recognise in Keychain Access."
        default: return ""
        }
    }
}
