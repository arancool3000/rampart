import Foundation
import RampartShared

/// Ten independent containment layers around the network lure ("10 firewalls"). Each one alone should stop an
/// attacker who fully controls the lure process from reaching the rest of the Mac; together they are defence in depth.
/// Everything here is GENERATED (profiles, pf anchor, launchd plist, commands) and returned as a dry-run plan;
/// rampartd applies it only when the user turns the lure on. Honest note: any listening port adds a little attack
/// surface. The lure is opt-in for that reason and the UI says so.
public struct ContainmentLayer: Codable, Hashable, Sendable, Identifiable {
    public var id: Int
    public var name: String
    public var detail: String
}

public struct LurePlan: Codable, Sendable {
    public var port: UInt16
    public var proto: LureProtocol
    public var scope: LureScope
    public var helperUser: String
    public var workDir: String
    public var sandboxProfile: String
    public var pfAnchor: String
    public var launchdPlist: Data
    public var commands: [GuardCommand]      // install (dry-run by default)
    public var killCommands: [GuardCommand]  // kill switch
    public var layers: [ContainmentLayer]
}

public enum LureContainment {
    public static let label = "app.rampart.lure"
    public static let anchor = "app.rampart/lure"
    /// Dedicated, login-less, no-home service account the installer creates (falls back to `nobody`).
    public static let helperUser = "_rampartlure"

    public static let layers: [ContainmentLayer] = [
        .init(id: 1, name: "Separate unprivileged process", detail: "The lure is its own helper running as the login-less _rampartlure account (or nobody), never root and never you."),
        .init(id: 2, name: "Strict sandbox", detail: "sandbox-exec deny-by-default profile: no file reads outside its empty folder and system libraries, no file writes, no exec or fork, no outbound network, no IPC."),
        .init(id: 3, name: "Empty jail folder", detail: "Its working folder is empty, root-owned and read-only; there is nothing to find or change."),
        .init(id: 4, name: "Synthetic data only", detail: "Every reply comes from a fixed table of fake banners and jokes. No real file, password or setting is ever read."),
        .init(id: 5, name: "Fixed tiny state machine", detail: "Login prompt, password prompt, deny, close. Input is never parsed as a command, never echoed and never reaches a shell."),
        .init(id: 6, name: "Length, rate and time caps", detail: "256-byte lines, 4 KB per session, 24 lines, 6 connections per address per minute, 8 at once, 20 s idle and 120 s hard timeouts."),
        .init(id: 7, name: "Packet filter anchor", detail: "pf lets in only the lure port and blocks every outbound packet from the lure's account."),
        .init(id: 8, name: "Local subnet only", detail: "By default it answers this Mac (and, if you choose, your local network) only; the internet needs a separate explicit opt-in."),
        .init(id: 9, name: "Kill switch and watchdog", detail: "CPU, memory and launchd limits, plus a watchdog that kills the lure on any anomaly: a sandbox denial, a child process, an outbound connection."),
        .init(id: 10, name: "Logged, alerted, Emergency-ready", detail: "Every attempt is logged and alerted in RamPart; an escape-like anomaly triggers Emergency Lockdown."),
    ]

    /// Layer 2. Deny by default; inbound on the one port only. Paths are validated (no quotes / parens injection).
    /// Verified by running the helper under this exact profile (WMS-o9): it serves and logs, and a probe in its
    /// place could not read, write, stat home files, fork, exec, connect out, open kernel-control / routing sockets,
    /// list processes or read the host name.
    /// - logging: os_log needs `com.apple.logd`; without it every attempt line was silently lost (layer 10 broken).
    /// - metadata: only the paths the helper loads from (an unrestricted `file-read-metadata` let it stat any file).
    /// - no `system-socket`: it allowed AF_SYSTEM (kernel control, ntstat) and AF_ROUTE sockets the lure never needs.
    /// - sysctl: process table, host name and network sysctls are denied (information leaks after a compromise).
    public static func sandboxProfile(port: UInt16, workDir: String, helperPath: String) -> String {
        precondition(safePath(workDir) && safePath(helperPath))
        return """
        (version 1)
        (deny default)
        (deny process-exec*)
        (deny process-fork)
        (deny network-outbound)
        (deny file-write*)
        (allow process-exec (literal "\(helperPath)"))
        (allow file-read* (subpath "/usr/lib") (subpath "/System/Library/Frameworks") (subpath "/System/Library/PrivateFrameworks")
                          (subpath "/System/Cryptexes") (literal "/") (literal "/dev/urandom") (literal "/dev/null") (literal "/private/var/db/timezone/localtime")
                          (subpath "/System/Volumes/Preboot/Cryptexes") (subpath "/private/var/db/dyld") (subpath "/System/Library/dyld")
                          (literal "\(helperPath)") (subpath "\(workDir)"))
        (allow file-read-metadata (literal "/") (literal "/private") (literal "/private/var") (literal "/private/var/db")
                          (subpath "/usr/lib") (subpath "/System") (subpath "/private/var/db/dyld") (subpath "/private/var/db/timezone")
                          (literal "/dev/urandom") (literal "/dev/null") (literal "\(helperPath)") (subpath "\(workDir)"))
        (allow sysctl-read)
        (deny sysctl-read (sysctl-name-prefix "kern.proc") (sysctl-name "kern.hostname") (sysctl-name-prefix "net."))
        (allow mach-lookup (global-name "com.apple.logd") (global-name "com.apple.system.logger"))
        (allow network-bind (local tcp "*:\(port)"))
        (allow network-inbound (local tcp "*:\(port)"))
        """
    }

    /// Layer 7. Only the lure port in; nothing out from the helper's account. Layer 8 mirrored at packet level.
    public static func pfAnchor(port: UInt16, scope: LureScope, localSubnets: [String]) -> String {
        // Only canonical a.b.c.d/nn survives: the old filter checked just the part before "/", so a subnet string
        // like "192.168.1.0/24 }\npass in all" reached the root-loaded anchor (pf rule injection).
        let subnets = localSubnets.compactMap(LureAccessFilter.canonicalCIDR)
        var r = ["# RamPart lure anchor (generated). Load: pfctl -a \(anchor) -f <file>"]
        r.append("block out quick user \(helperUser)")
        switch scope {
        case .loopback:
            r.append("block in quick on ! lo0 proto tcp to any port \(port)")
        case .localSubnet:
            r.append("table <rampart_lure_ok> const { \(subnets.isEmpty ? "127.0.0.1" : subnets.joined(separator: ", ")) }")
            r.append("pass in quick proto tcp from <rampart_lure_ok> to any port \(port) flags S/SA keep state (max-src-conn 8, max-src-conn-rate 6/60)")
            r.append("block in quick proto tcp to any port \(port)")
        case .anywhere:
            r.append("pass in quick proto tcp to any port \(port) flags S/SA keep state (max-src-conn 8, max-src-conn-rate 6/60)")
        }
        return r.joined(separator: "\n") + "\n"
    }

    /// Layers 1, 3, 9 at the launchd level: own account, empty working dir, hard resource limits, no respawn storm.
    public static func launchdPlist(port: UInt16, scope: LureScope, workDir: String, helperPath: String, profilePath: String,
                                    localSubnets: [String] = []) throws -> Data {
        let dict: [String: Any] = [
            "Label": label,
            "ProgramArguments": ["/usr/bin/sandbox-exec", "-f", profilePath, helperPath]
                + LureHelperArgs(port: port, scope: scope, localSubnets: localSubnets, confirmedAnywhere: scope == .anywhere).arguments,
            "UserName": helperUser, "GroupName": helperUser,
            "WorkingDirectory": workDir,
            "RunAtLoad": true, "KeepAlive": false, "ThrottleInterval": 30,
            "Umask": 0o077,
            "EnvironmentVariables": ["PATH": "/nonexistent", "RAMPART_NO_PRIVILEGED_TOOLS": "1"],
            "SoftResourceLimits": ["CPU": 600, "Data": 64 << 20, "NumberOfFiles": 32, "NumberOfProcesses": 1, "FileSize": 0, "Core": 0],
            "HardResourceLimits": ["CPU": 900, "Data": 96 << 20, "NumberOfFiles": 48, "NumberOfProcesses": 1, "FileSize": 0, "Core": 0],
            "ProcessType": "Background", "LowPriorityIO": true,
        ]
        return try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
    }

    public static func plan(port: UInt16, scope: LureScope, localSubnets: [String],
                            helperPath: String = "/Library/Application Support/RamPart/bin/rampart-lure",
                            baseDir: String = "/Library/Application Support/RamPart/lure") throws -> LurePlan {
        guard port >= 1024 else { throw DeceptionError.bindRefused("lure uses unprivileged high ports only") }
        guard safePath(helperPath), safePath(baseDir) else { throw DeceptionError.unsafePath(baseDir) }
        let work = baseDir + "/jail", profile = baseDir + "/lure.sb", anchorFile = baseDir + "/lure.pf"
        let plist = baseDir + "/\(label).plist"
        let cmds = [
            GuardCommand("/bin/mkdir", ["-p", "-m", "0555", work], note: "empty, root-owned, read-only jail folder"),
            GuardCommand("/usr/sbin/chown", ["root:wheel", work, baseDir]),
            GuardCommand("/sbin/pfctl", ["-a", anchor, "-f", anchorFile], note: "only the lure port in, nothing out"),
            GuardCommand("/bin/launchctl", ["bootstrap", "system", plist], note: "start the sandboxed helper"),
        ]
        let kill = [
            GuardCommand("/bin/launchctl", ["bootout", "system/\(label)"], acceptableExitCodes: [3, 113], note: "kill switch"),
            GuardCommand("/sbin/pfctl", ["-a", anchor, "-F", "all"], note: "drop the lure's pf rules"),
        ]
        return LurePlan(port: port, proto: LureProtocol.forPort(port), scope: scope, helperUser: helperUser, workDir: work,
                        sandboxProfile: sandboxProfile(port: port, workDir: work, helperPath: helperPath),
                        pfAnchor: pfAnchor(port: port, scope: scope, localSubnets: localSubnets),
                        launchdPlist: try launchdPlist(port: port, scope: scope, workDir: work, helperPath: helperPath, profilePath: profile,
                                                                   localSubnets: localSubnets),
                        commands: cmds, killCommands: kill, layers: layers)
    }

    /// Paths embedded in SBPL / plists: absolute, no quotes, parens, backslashes, newlines or "..".
    static func safePath(_ p: String) -> Bool {
        p.hasPrefix("/") && !p.contains("..") && !p.contains(where: { "\"()\\;\n\r\0".contains($0) })
    }

    /// Layer 10: the alert for an attempt (normal pipeline; network source, high severity).
    public static func detection(for a: TarpitAttempt) -> Detection {
        Detection(date: a.date, name: "Network lure contacted", category: .suspicious, severity: .high, confidence: a.credentialAttempts > 0 ? 85 : 70,
                  evidence: [Evidence(source: .network, title: "Connection to the RamPart lure",
                                      detail: "\(a.remote) connected to the fake \(a.proto.rawValue) service on port \(a.port)\(a.credentialAttempts > 0 ? " and tried \(a.credentialAttempts) password(s)" : ""). Nothing real is behind it.",
                                      score: a.credentialAttempts > 0 ? 85 : 70)])
    }
}


/// Command line of the `rampart-lure` helper (what the launchd plist passes; parsed by the helper's main).
/// `--lure` is required so running the binary by accident does nothing.
public struct LureHelperArgs: Equatable, Sendable {
    public var port: UInt16
    public var scope: LureScope
    public var localSubnets: [String]
    /// Only ever true when the root daemon generated a plan for scope `.anywhere`, which the app asks for only after
    /// the user explicitly confirmed exposing the lure to the internet.
    public var confirmedAnywhere: Bool
    public init(port: UInt16, scope: LureScope, localSubnets: [String] = [], confirmedAnywhere: Bool = false) {
        self.port = port; self.scope = scope; self.localSubnets = localSubnets; self.confirmedAnywhere = confirmedAnywhere
    }

    public var arguments: [String] {
        var a = ["--lure", "--port", String(port), "--scope", scope.rawValue]
        for s in localSubnets.compactMap(LureAccessFilter.canonicalCIDR) { a += ["--subnet", s] }
        if confirmedAnywhere && scope == .anywhere { a.append("--confirmed-anywhere") }
        return a
    }

    public enum ParseError: Error, Equatable, CustomStringConvertible {
        case notLure, bad(String)
        public var description: String {
            switch self { case .notLure: return "rampart-lure runs only as RamPart's sandboxed lure helper (--lure)"; case .bad(let s): return s }
        }
    }

    public static func parse(_ argv: [String]) throws -> LureHelperArgs {
        guard argv.contains("--lure") else { throw ParseError.notLure }
        var port: UInt16?, scope = LureScope.loopback, subnets: [String] = [], anywhere = false
        var i = 0
        func value() throws -> String {
            i += 1; guard i < argv.count else { throw ParseError.bad("missing value for \(argv[i - 1])") }; return argv[i]
        }
        while i < argv.count {
            switch argv[i] {
            case "--lure": break
            case "--port":
                guard let p = UInt16(try value()), p >= 1024 else { throw ParseError.bad("the lure port must be 1024-65535") }
                port = p
            case "--scope":
                let v = try value(); guard let s = LureScope(rawValue: v) else { throw ParseError.bad("unknown scope \(v)") }; scope = s
            case "--subnet":
                let v = try value()
                guard let c = LureAccessFilter.canonicalCIDR(v) else { throw ParseError.bad("bad subnet \(SafeText.line(v, max: 40))") }
                subnets.append(c)
            case "--confirmed-anywhere": anywhere = true
            default: throw ParseError.bad("unknown argument \(argv[i])")
            }
            i += 1
        }
        guard let port else { throw ParseError.bad("--port is required") }
        if scope == .anywhere && !anywhere { throw ParseError.bad("scope anywhere needs --confirmed-anywhere") }
        return LureHelperArgs(port: port, scope: scope, localSubnets: subnets, confirmedAnywhere: anywhere)
    }
}
