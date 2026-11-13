import Foundation
import Security
import RampartShared
import RampartNetwork

// Root-daemon authorization matrix (hardening hx10). Pure and self-contained so rampart-selftest can compile it
// (Sources/rampart-selftest/IPCAuthz.swift is a symlink to this file) and test every cell.
// Nothing here can show UI: Security.framework code-signing queries are read-only and never prompt.

/// What a request needs, from least to most.
enum AuthzLevel: Int, Comparable, CaseIterable, CustomStringConvertible {
    /// Any local peer whose credentials the kernel reported (root, the console user, other local users).
    case anyLocal
    /// Root, the console user, or an administrator: reads that reveal other users' paths, URLs and events.
    case sessionUser
    /// Root, or an administrator using RamPart's own signed app or CLI: actions that strengthen or maintain protection.
    case adminClient
    /// Like `adminClient`, and the action weakens protection: from the CLI it additionally needs an
    /// administrator-authenticated settings session; the GUI app (which a script cannot drive without an
    /// Accessibility grant) may do it directly.
    case adminClientWeakening

    static func < (a: AuthzLevel, b: AuthzLevel) -> Bool { a.rawValue < b.rawValue }
    var description: String {
        switch self {
        case .anyLocal: return "anyLocal"; case .sessionUser: return "sessionUser"
        case .adminClient: return "adminClient"; case .adminClientWeakening: return "adminClientWeakening"
        }
    }
}

/// The RamPart binaries that may make privileged calls, by code-signing identifier.
enum RampartClientKind: String, CaseIterable { case app, cli, nmh, daemon }

/// Code identity of the peer process, read through its audit token (not its pid, which can be reused).
struct ClientIdentity: Equatable {
    var identifier: String
    var teamID: String?
    var cdhash: String
    var path: String
    /// Static signature (strict) and dynamic validity both passed.
    var valid: Bool
    var hardenedRuntime: Bool
    var linkerSignedOnly: Bool
    /// get-task-allow, disable-library-validation, allow-dyld-environment-variables, allow-unsigned-executable-memory.
    var dangerousEntitlements: [String]

    static let identifiers: [String: RampartClientKind] = [
        Product.bundlePrefix + ".app": .app, Product.bundlePrefix + ".cli": .cli,
        Product.bundlePrefix + ".nmh": .nmh, Product.bundlePrefix + ".daemon": .daemon,
    ]
    static let dangerousEntitlementKeys = ["com.apple.security.get-task-allow",
                                           "com.apple.security.cs.disable-library-validation",
                                           "com.apple.security.cs.allow-dyld-environment-variables",
                                           "com.apple.security.cs.allow-unsigned-executable-memory"]

    /// The RamPart client this is, or nil when it must not be trusted for privileged calls.
    /// `daemonTeamID`: the daemon's own Team ID (when RamPart is signed with a real identity the client must match it).
    /// `pinnedCDHashes`: optional install-time allow-list (trusted-clients.json); when non-nil the cdhash must be in it.
    func trustedKind(daemonTeamID: String?, pinnedCDHashes: Set<String>?) -> RampartClientKind? {
        guard valid, hardenedRuntime, !linkerSignedOnly, dangerousEntitlements.isEmpty,
              let kind = Self.identifiers[identifier] else { return nil }
        if let t = daemonTeamID, !t.isEmpty, teamID != t { return nil }
        if let pins = pinnedCDHashes, !pins.contains(cdhash.lowercased()) { return nil }
        return kind
    }

    /// Reads the identity of the process behind `token`. nil if it exited, exec'd since connecting, or is unsigned.
    static func of(auditToken token: audit_token_t) -> ClientIdentity? {
        var tok = token
        let data = Data(bytes: &tok, count: MemoryLayout<audit_token_t>.size)
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, [kSecGuestAttributeAudit: data] as CFDictionary, [], &code) == errSecSuccess,
              let code else { return nil }
        return of(code: code)
    }

    static func ofSelf() -> ClientIdentity? {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else { return nil }
        return of(code: code)
    }

    static func of(code: SecCode) -> ClientIdentity? {
        var st: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &st) == errSecSuccess, let st else { return nil }
        var infoCF: CFDictionary?
        guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &infoCF) == errSecSuccess,
              let info = infoCF as? [String: Any] else { return nil }
        let dynamicOK = SecCodeCheckValidity(code, [], nil) == errSecSuccess
        let staticOK = SecStaticCodeCheckValidity(st, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let ents = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let bad = dangerousEntitlementKeys.filter { (ents[$0] as? Bool) == true }
        let cd = (info[kSecCodeInfoUnique as String] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() } ?? ""
        var path = ""
        var url: CFURL?
        if SecCodeCopyPath(st, [], &url) == errSecSuccess, let url { path = (url as URL).path }
        return ClientIdentity(identifier: info[kSecCodeInfoIdentifier as String] as? String ?? "",
                              teamID: info[kSecCodeInfoTeamIdentifier as String] as? String,
                              cdhash: cd, path: path, valid: dynamicOK && staticOK && !cd.isEmpty,
                              hardenedRuntime: flags & 0x10000 != 0, linkerSignedOnly: flags & 0x20000 != 0,
                              dangerousEntitlements: bad)
    }

    /// Static signature facts of a file on disk (strict validation; never prompts). nil when unsigned or unreadable.
    static func ofFile(_ path: String) -> ClientIdentity? {
        var lst = stat()
        guard lstat(path, &lst) == 0, (lst.st_mode & S_IFMT) == S_IFREG else { return nil }   // no symlinks
        var st: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &st) == errSecSuccess, let st else { return nil }
        var infoCF: CFDictionary?
        guard SecCodeCopySigningInformation(st, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation), &infoCF) == errSecSuccess,
              let info = infoCF as? [String: Any] else { return nil }
        let staticOK = SecStaticCodeCheckValidity(st, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let ents = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] ?? [:]
        let cd = (info[kSecCodeInfoUnique as String] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() } ?? ""
        return ClientIdentity(identifier: info[kSecCodeInfoIdentifier as String] as? String ?? "",
                              teamID: info[kSecCodeInfoTeamIdentifier as String] as? String, cdhash: cd, path: path,
                              valid: staticOK && !cd.isEmpty, hardenedRuntime: flags & 0x10000 != 0, linkerSignedOnly: flags & 0x20000 != 0,
                              dangerousEntitlements: dangerousEntitlementKeys.filter { (ents[$0] as? Bool) == true })
    }

    /// Install-time pins: `<root>/trusted-clients.json` = ["<cdhash hex>", ...]. Used only when the file is a regular
    /// root-owned file that nobody else can write; otherwise ignored (nil = no pinning).
    static func loadPins(_ path: String) -> Set<String>? {
        var s = stat()
        guard lstat(path, &s) == 0, (s.st_mode & S_IFMT) == S_IFREG, s.st_uid == 0, s.st_mode & 0o022 == 0,
              let d = FileManager.default.contents(atPath: path),
              let list = try? JSONDecoder().decode([String].self, from: d) else { return nil }
        return Set(list.map { $0.lowercased() })
    }
}

/// Who is calling, as the matrix sees it.
struct AuthzCaller {
    /// False when the kernel could not report the peer's credentials (the connection is dropped before this).
    var credentialed = true
    var uid: uid_t
    var isAdmin: Bool
    var isConsole: Bool
    /// The verified RamPart client kind, nil for anything else (scripts, raw sockets, re-signed copies).
    var client: RampartClientKind?
    /// An administrator-authenticated settings session bound to this very process.
    var hasSettingsSession = false

    var isRoot: Bool { credentialed && uid == 0 }

    /// The column of the matrix, for reports and tests.
    enum Column: String, CaseIterable { case root, consoleAdmin, consoleStandard, otherAdmin, otherStandard, unauthenticated }
    var column: Column {
        if !credentialed { return .unauthenticated }
        if uid == 0 { return .root }
        switch (isConsole, isAdmin) {
        case (true, true): return .consoleAdmin
        case (true, false): return .consoleStandard
        case (false, true): return .otherAdmin
        case (false, false): return .otherStandard
        }
    }

    /// uid owning /dev/console (0 at the login window: then nobody is "the console user").
    static func consoleUID() -> uid_t? {
        var s = stat()
        guard stat("/dev/console", &s) == 0, s.st_uid != 0 else { return nil }
        return s.st_uid
    }
}

enum IPCAuthz {
    /// Forwarded session events may only describe the forwarding user's own processes and files (a standard user
    /// must not make the root daemon kill another user's process or quarantine another user's file). Root peers
    /// are trusted. Returns nil to drop the event.
    static func sanitizeForwarded(_ e: SecurityEvent, peerUID: uid_t) -> SecurityEvent? {
        var e = e
        if peerUID == 0 { return e }
        if var pr = e.process {
            guard let facts = procFacts(pid: pr.pid), facts.uid == peerUID else { return nil }
            pr.uid = facts.uid; pr.isPlatformBinary = false; pr.signingID = nil; pr.teamID = nil
            // wms-fa: the image path and parent come from the kernel, never from the peer. A forged path
            // ("/Applications/Safari.app/...", a root-owned binary) or a forged parent ("the browser spawned me") would
            // otherwise steer the behaviour rules' lineage, trust multipliers and the kill target.
            if let real = executablePath(pid: pr.pid) { pr.path = real } else { return nil }
            pr.ppid = facts.ppid
            e.process = pr
        }
        for path in [e.path, e.destPath].compactMap({ $0 }) {
            var st = stat()
            if lstat(path, &st) == 0, st.st_uid != peerUID { return nil }
        }
        e.detail = e.detail.filter { $0.key.utf8.count <= 64 && $0.value.utf8.count <= 4096 }
        return e
    }

    static func ownerUID(pid: Int32) -> uid_t? { procFacts(pid: pid)?.uid }

    /// Kernel-reported owner and parent of a live process (sysctl), nil when it is gone.
    static func procFacts(pid: Int32) -> (uid: uid_t, ppid: pid_t)? {
        guard pid > 0 else { return nil }
        var info = kinfo_proc(); var size = MemoryLayout<kinfo_proc>.stride
        var mib: [Int32] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid]
        guard sysctl(&mib, 4, &info, &size, nil, 0) == 0, size > 0 else { return nil }
        return (info.kp_eproc.e_ucred.cr_uid, info.kp_eproc.e_ppid)
    }

    /// Kernel-reported executable path of a live process (proc_pidpath).
    static func executablePath(pid: Int32) -> String? {
        guard pid > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: 4 * Int(MAXPATHLEN))
        let n = proc_pidpath(pid, &buf, UInt32(buf.count))
        return n > 0 ? String(cString: buf) : nil
    }

    /// wms-fa: who may inject telemetry. Root (the system service forwarding decoy events) always; otherwise only a
    /// verified RamPart client (the app's PasteGuard) while client checks are on. A raw-socket script used to be able
    /// to feed forged "ransomware burst" events about its own processes and files into the root daemon's behaviour
    /// engine, which can end in an automatic Emergency Lockdown that cuts the whole Mac's network. nil = allowed.
    static func forwardDenial(peerUID: uid_t, client: RampartClientKind?, clientChecks: Bool) -> String? {
        if peerUID == 0 || !clientChecks { return nil }
        if client == .app || client == .cli || client == .daemon { return nil }
        return "'forwardEvents' is accepted only from \(Product.name)'s own app or service"
    }

    /// wms-fa: the user-session helper applies the client-identity gate only when it is itself a packaged RamPart
    /// build (hardened runtime, strict signature, identifier `app.rampart.daemon`). A `swift build` development
    /// binary (linker-signed, not hardened) keeps the old same-uid-only behaviour, because its clients are
    /// development binaries too. Every shipped copy is packaged by scripts/build.sh.
    static func userModeClientChecks(selfIdentity me: ClientIdentity?) -> Bool {
        guard let me, me.valid, me.hardenedRuntime, !me.linkerSignedOnly, me.dangerousEntitlements.isEmpty else { return false }
        return me.identifier == Product.bundlePrefix + ".daemon"
    }

    /// wms-fa: cdhash pins for the user-session helper: the app and CLI that ship in the same bundle
    /// (`<bundle>/Contents/MacOS/Rampart`, `<bundle>/Contents/Helpers/rampart`). With ad-hoc signing an identifier is
    /// forgeable, a cdhash is not: only the binaries built with this very helper may make privileged calls to it.
    /// nil when the helper is not inside a bundle or no sibling verifies (identifier-only trust then applies).
    static func siblingClientPins(executable: String, appName: String = Product.name) -> Set<String>? {
        let exe = URL(fileURLWithPath: executable).resolvingSymlinksInPath().path
        guard let r = exe.range(of: ".app/Contents/") else { return nil }
        let bundle = String(exe[..<r.lowerBound]) + ".app"
        var pins = Set<String>()
        for (rel, kind) in [("/Contents/MacOS/\(appName)", RampartClientKind.app), ("/Contents/Helpers/rampart", .cli)] {
            guard let id = ClientIdentity.ofFile(bundle + rel), id.trustedKind(daemonTeamID: nil, pinnedCDHashes: nil) == kind else { continue }
            pins.insert(id.cdhash.lowercased())
        }
        return pins.isEmpty ? nil : pins
    }

    /// Posture check ids are short ASCII identifiers; anything else never reaches the fixer, the log or Activity.
    static func isValidCheckID(_ id: String) -> Bool {
        id.utf8.count <= 40 && !id.isEmpty && id.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "_" || $0 == "-") }
    }

    /// A settings session belongs to the process that redeemed the token (pid + pidversion from its audit token).
    static func sameProcess(ownerPID: pid_t, ownerVersion: UInt32?, pid: pid_t, version: UInt32?) -> Bool {
        guard ownerPID == pid, ownerPID > 0 else { return false }
        return ownerVersion == version
    }

    /// The level each request needs on the root daemon. `settingsWeakens` says whether a setSettings would turn
    /// a protection off (computed by the router against the current settings).
    static func level(_ r: IPCRequest, settingsWeakens: Bool = true) -> AuthzLevel {
        switch r {
        case .status, .health, .checkURL, .checkURLChain, .scamCheck, .webLookup, .scan, .forwardEvents:
            return .anyLocal
        case .deceptionStatus, .deceptionEvidence, .deceptionContain:
            return .sessionUser
        case .downloadGateStatus, .mediaGuardStatus:
            return .sessionUser
        case .downloadGateSetEnabled(let on), .mediaGuardSetEnabled(let on):
            return on ? .adminClient : .adminClientWeakening
        case .downloadGateDecide(_, let allow):
            return allow ? .adminClientWeakening : .adminClient
        case .mediaGuardTrust(_, let trusted):
            return trusted ? .adminClientWeakening : .adminClient
        case .mediaGuardStop, .mediaGuardSetTone:
            return .adminClient
        case .deceptionSetDecoys(let on), .deceptionSetMaze(let on):
            return on ? .adminClient : .adminClientWeakening
        case .deceptionRemoveAll:
            return .adminClientWeakening
        case .deceptionSetTarpit, .deceptionSetTone, .deceptionSetDecoysVisible:
            return .adminClient
        case .netGuard(let d):
            switch NetGuardCommand.access(of: d) {
            case .anyLocal: return .anyLocal
            case .read: return .sessionUser
            case .change: return settingsWeakens ? .adminClientWeakening : .adminClient
            }
        case .emergencyStatus, .emergencyRescan, .emergencyAck:
            return .sessionUser
        case .vpn(let op, _):
            // RamPart VPN: status for the session; connecting to the configuration the user already imported
            // strengthens. Everything else is weakening (wms-fa): importing or setting up a configuration points ALL of
            // the Mac's traffic and DNS at a new WireGuard endpoint, so from the CLI it needs administrator confirmation
            // (malware running the real CLI must not be able to route the user through its own server); disconnect,
            // remove and option changes (kill switch off) turn protection down. Unknown ops get the strictest level.
            switch op {
            case "status": return .sessionUser
            case "connect": return .adminClient
            default: return .adminClientWeakening
            }
        case .emergencyLockdown:
            // Locking down is the safe direction, but it suspends processes and cuts the network: RamPart's own clients only.
            return .adminClient
        case .emergencyNetwork:
            // Restoring the internet is checked again by the admin token in Emergency. "Keep blocking" is the safe
            // direction, but it makes a 10-minute automatic block permanent (an administrator must authenticate to
            // undo it), so it is RamPart's own clients only too (wms-fa; it used to be sessionUser).
            return .adminClient
        case .killSwitch:
            // RamPart's own app or CLI, plus the admin token (Touch ID / password) checked in KillSwitchExec. Not
            // .adminClientWeakening: the token itself is the user-presence proof, the app holds no settings session.
            return .adminClient
        case .liftEmergencyLockdown:
            return .adminClientWeakening
        case .listDetections, .listQuarantine, .posture, .persistence, .activity, .connections, .wifi, .networkStats,
             .getSettings, .previewRemediation, .listAllowRules, .remoteAccessReport, .tamperStatus, .subscribeEvents,
             .pauseScan, .cancelScan, .webVerdict:
            return .sessionUser
        case .quarantine, .deleteQuarantined, .fixPosture, .updateSignatures, .remediate, .removeAllowRule,
             .revokeRemoteTool, .requestDisableProtection, .disableProtection, .requestUninstall, .uninstall:
            return .adminClient
        case .setRealtime(let on), .setWebProtection(let on), .setRemoteLockdown(let on):
            return on ? .adminClient : .adminClientWeakening
        case .setSettings:
            return settingsWeakens ? .adminClientWeakening : .adminClient
        case .allow, .addAllowRule, .allowRemoteTool, .restore, .restoreQuarantinedTo, .exportQuarantined, .sandboxRun:
            return .adminClientWeakening
        }
    }

    /// nil = allowed; otherwise the refusal sent to the peer.
    ///
    /// `userMode` (wms-fa): the user-session helper. Its socket already admits only its owner and root, so the
    /// administrator and console columns do not apply (a standard user owns their own helper), but the client-identity
    /// gate does: Download Gate, Camera & Microphone Guard, Cat & Mouse, the user vault and real-time protection
    /// used to be switchable by any same-user process with a ten-line script.
    static func denial(_ level: AuthzLevel, _ c: AuthzCaller, name: String, userMode: Bool = false) -> String? {
        guard c.credentialed else { return "'\(name)' refused: the caller could not be identified" }
        if c.isRoot { return nil }
        if userMode {
            guard level >= .adminClient else { return nil }
            guard let k = c.client, k == .app || k == .cli else {
                return "'\(name)' is accepted only from \(Product.name)'s own app or command line tool"
            }
            if level == .adminClientWeakening, k == .cli, !c.hasSettingsSession {
                return "'\(name)' turns a protection off; from the command line it needs administrator confirmation first (authenticate, then retry)"
            }
            return nil
        }
        switch level {
        case .anyLocal:
            return nil
        case .sessionUser:
            return (c.isConsole || c.isAdmin) ? nil : "'\(name)' is available only to the logged-in console user or an administrator"
        case .adminClient, .adminClientWeakening:
            guard c.isAdmin else { return "'\(name)' requires an administrator account" }
            guard let k = c.client, k == .app || k == .cli else {
                return "'\(name)' is accepted only from \(Product.name)'s own app or command line tool"
            }
            if level == .adminClientWeakening, k == .cli, !c.hasSettingsSession {
                return "'\(name)' turns a protection off; from the command line it needs administrator confirmation first (authenticate, then retry)"
            }
            return nil
        }
    }

    /// True if applying `new` over `old` turns any protection off or shrinks what is scanned.
    static func settingsWeaken(old: RampartSettings, new: RampartSettings) -> Bool {
        if old.realtimeOn && !new.realtimeOn { return true }
        if old.autoQuarantine && !new.autoQuarantine { return true }
        if old.scanArchives && !new.scanArchives { return true }
        if old.scheduledQuickScan && !new.scheduledQuickScan { return true }
        if old.notifyThreats && !new.notifyThreats { return true }
        if old.webProtection && !new.webProtection { return true }
        if old.autoUpdate && !new.autoUpdate { return true }
        if old.blockTrackers && !new.blockTrackers { return true }
        if !old.learningMode && new.learningMode { return true }      // learning mode suppresses behaviour alerts
        if !old.developerMode && new.developerMode { return true }    // developer mode relaxes behaviour rules
        if old.ransomwareCanaries && !new.ransomwareCanaries { return true }
        // wms-fa: any new exclusion hides files from the scanner, so it is weakening (the CLI needs administrator
        // confirmation; the app may do it directly). Broad paths are additionally gated per path by the router.
        if !Set(new.exclusions).isSubset(of: Set(old.exclusions)) { return true }
        return false
    }
}

/// Makes attacker-influenced text safe to write into the log file or show as an activity entry:
/// no control, line-break or bidi-override characters (no forged log lines, no reversed text), bounded length,
/// and secrets (tokens, passwords, keys) replaced.
enum LogRedact {
    static func clean(_ s: String, max: Int = 300) -> String {
        var out = String.UnicodeScalarView()
        var n = 0
        for u in s.unicodeScalars {
            if n >= max { break }
            let v = u.value
            let control = v < 0x20 || (0x7f...0x9f).contains(v)
            let bidi = (0x202a...0x202e).contains(v) || (0x2066...0x2069).contains(v) || v == 0x200e || v == 0x200f || v == 0x061c
            let invisible = (0x200b...0x200d).contains(v) || v == 0xfeff || v == 0x2028 || v == 0x2029
            if control || bidi || invisible { out.append(" "); } else { out.append(u) }
            n += 1
        }
        var r = String(out)
        if s.unicodeScalars.count > max { r += "…" }
        return redactSecrets(r)
    }

    /// Disable/uninstall tokens (hex.uid.epoch.mac), key=value secrets, bearer tokens, long hex/base64 blobs
    /// (except 64-hex SHA-256 values, which are file identities the user needs to see).
    static func redactSecrets(_ s: String) -> String {
        // SHA-256 values are protected first (they would otherwise look like a hex or base64 blob).
        var shas: [String] = []
        let ns = NSMutableString(string: s.replacingOccurrences(of: "\u{E000}", with: " "))
        if let re = try? NSRegularExpression(pattern: #"\b[0-9a-fA-F]{64}\b"#) {
            for m in re.matches(in: ns as String, range: NSRange(location: 0, length: ns.length)).reversed() {
                shas.insert(ns.substring(with: m.range), at: 0)
                ns.replaceCharacters(in: m.range, with: "\u{E000}")
            }
        }
        var r = ns as String
        let patterns: [(String, String)] = [
            (#"\b[0-9a-f]{32}\.\d+\.\d+\.[0-9A-Za-z+/=_-]{16,}"#, "<token>"),
            (#"(?i)\bbearer\s+\S+"#, "Bearer <redacted>"),
            (#"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|key|authorization)\s*[:=]\s*(?!Bearer <redacted>)\S+"#, "$1=<redacted>"),
            (#"\bAIza[0-9A-Za-z_-]{20,}"#, "<api-key>"),
            (#"\b[0-9A-Fa-f]{40,}\b"#, "<hex>"),
            (#"[A-Za-z0-9+/]{48,}={0,2}"#, "<blob>"),
        ]
        for (p, t) in patterns { r = r.replacingOccurrences(of: p, with: t, options: .regularExpression) }
        for sha in shas { if let i = r.range(of: "\u{E000}") { r.replaceSubrange(i, with: sha) } }
        return r
    }
}

/// Daemon state files (hx10): written as a fresh 0600 temp file (O_EXCL | O_NOFOLLOW, fchmod so the umask never
/// matters, root:wheel as root), fsynced, then renamed over the target, so there is no window in which the file is
/// world-readable and a planted symlink is replaced rather than followed. Reads refuse symlinks and oversized files
/// and tighten loose permissions left by older versions.
enum SecureStore {
    static let maxRead = 64 << 20

    static func write(_ data: Data, to url: URL, mode: mode_t = 0o600) throws {
        let dir = url.deletingLastPathComponent().path
        let tmp = dir + "/." + url.lastPathComponent + ".tmp-" + UUID().uuidString
        let fd = open(tmp, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode)
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var ok = fchmod(fd, mode) == 0
        if getuid() == 0 { ok = ok && fchown(fd, 0, 0) == 0 }
        ok = ok && data.withUnsafeBytes { raw -> Bool in
            var off = 0
            while off < raw.count {
                let w = Darwin.write(fd, raw.baseAddress! + off, raw.count - off)
                if w < 0 && errno == EINTR { continue }
                if w <= 0 { return false }
                off += w
            }
            return true
        }
        ok = ok && fsync(fd) == 0
        close(fd)
        guard ok, rename(tmp, url.path) == 0 else {
            let e = errno; unlink(tmp)
            throw POSIXError(POSIXErrorCode(rawValue: e) ?? .EIO)
        }
    }

    static func writeJSON<T: Encodable>(_ value: T, to url: URL, mode: mode_t = 0o600) throws {
        let enc = JSONEncoder.rampart; enc.outputFormatting = [.prettyPrinted, .sortedKeys]
        try write(try enc.encode(value), to: url, mode: mode)
    }

    /// nil if missing, a symlink, not a regular file, or larger than `maxRead`. Group/other bits beyond `mode` are removed.
    static func read(_ url: URL, mode: mode_t = 0o600) -> Data? {
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
        guard fd >= 0 else {
            return nil   // ENOENT, or ELOOP for a planted symlink
        }
        defer { close(fd) }
        var st = stat()
        guard fstat(fd, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG, st.st_size <= maxRead else { return nil }
        if (st.st_mode & 0o777) & ~mode != 0 { _ = fchmod(fd, mode) }
        var out = Data(); out.reserveCapacity(Int(st.st_size))
        var buf = [UInt8](repeating: 0, count: 1 << 16)
        while out.count <= maxRead {
            let r = buf.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress!, $0.count) }
            if r < 0 && errno == EINTR { continue }
            if r <= 0 { break }
            out.append(contentsOf: buf[0..<r])
        }
        return out.count <= maxRead ? out : nil
    }
}
