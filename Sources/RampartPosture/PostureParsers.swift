import Foundation
import RampartShared

/// Result of interpreting one command's output.
public struct ParseOutcome: Equatable, Sendable {
    public var state: PostureCheck.State
    public var detail: String
    public init(_ state: PostureCheck.State, _ detail: String) { self.state = state; self.detail = detail }
    public static func unknown(_ why: String = "Couldn't read this setting.") -> ParseOutcome { .init(.unknown, why) }
}

/// What `launchctl print system/<label>` says about a service.
public enum LaunchdServiceState: Equatable, Sendable {
    case notLoaded
    case loaded(running: Bool)
    case unknown
}

/// Pure parsers for every posture command. No I/O here; all are tested on fixture strings.
public enum PostureParsers {

    static func lower(_ s: String) -> String { s.lowercased() }

    static func firstMatch(_ pattern: String, in s: String) -> [String]? {
        guard let re = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        let ns = s as NSString
        guard let m = re.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return (0..<m.numberOfRanges).map { m.range(at: $0).location == NSNotFound ? "" : ns.substring(with: m.range(at: $0)) }
    }

    // MARK: 1 FileVault — `fdesetup status`
    public static func fileVault(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("decryption in progress") { return .init(.fail, "FileVault is being turned off (decrypting).") }
        if l.contains("filevault is on") {
            if l.contains("encryption in progress") { return .init(.pass, "FileVault is on (encryption still in progress).") }
            return .init(.pass, "FileVault is on.")
        }
        if l.contains("deferred enablement") || l.contains("deferred filevault") {
            return .init(.fail, "FileVault will turn on at the next logout (pending).")
        }
        if l.contains("filevault is off") { return .init(.fail, "FileVault is off. Your disk isn't encrypted at rest.") }
        return .unknown()
    }

    // MARK: 2 SIP — `csrutil status`
    public static func sip(_ s: String) -> ParseOutcome {
        let l = lower(s)
        guard l.contains("system integrity protection") else { return .unknown() }
        if l.contains("custom configuration") { return .init(.fail, "System Integrity Protection is partly disabled (custom configuration).") }
        if l.contains("status: enabled") { return .init(.pass, "System Integrity Protection is on.") }
        if l.contains("status: disabled") { return .init(.fail, "System Integrity Protection is off. Malware could modify system files.") }
        return .unknown()
    }

    // MARK: 3 Gatekeeper — `spctl --status`
    public static func gatekeeper(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("assessments enabled") { return .init(.pass, "Gatekeeper checks apps before they open.") }
        if l.contains("assessments disabled") { return .init(.fail, "Gatekeeper is off. Apps from anywhere can open without a check.") }
        return .unknown()
    }

    // MARK: 4 Firewall — `socketfilterfw --getglobalstate`
    public static func firewall(_ s: String) -> ParseOutcome {
        if let m = firstMatch(#"state\s*=\s*(\d)"#, in: s), let v = Int(m[1]) {
            switch v {
            case 0: return .init(.fail, "The macOS firewall is off.")
            case 2: return .init(.pass, "The firewall is on and blocks all incoming connections.")
            default: return .init(.pass, "The macOS firewall is on.")
            }
        }
        let l = lower(s)
        if l.contains("firewall is enabled") || l.contains("firewall is on") { return .init(.pass, "The macOS firewall is on.") }
        if l.contains("firewall is disabled") || l.contains("firewall is off") { return .init(.fail, "The macOS firewall is off.") }
        return .unknown()
    }

    // MARK: 5 Stealth — `socketfilterfw --getstealthmode`
    public static func stealthMode(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("stealth mode is on") || l.contains("stealth mode enabled") {
            return .init(.pass, "Stealth mode is on. Your Mac doesn't answer probes such as ping.")
        }
        if l.contains("stealth mode is off") || l.contains("stealth mode disabled") {
            return .init(.fail, "Stealth mode is off. Your Mac answers network probes such as ping.")
        }
        return .unknown()
    }

    // MARK: plist helpers
    public static func plistDictionary(_ data: Data?) -> [String: Any]? {
        guard let data, !data.isEmpty,
              let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else { return nil }
        return obj as? [String: Any]
    }

    static func boolValue(_ v: Any?) -> Bool? {
        switch v {
        case let b as Bool: return b
        case let n as NSNumber: return n.intValue != 0
        case let s as String:
            switch s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() {
            case "1", "true", "yes": return true
            case "0", "false", "no": return false
            default: return nil
            }
        default: return nil
        }
    }

    // MARK: 6 Automatic updates — com.apple.SoftwareUpdate plist + `defaults read com.apple.commerce AutoUpdate`
    public static let autoUpdateKeys: [(key: String, label: String)] = [
        ("AutomaticCheckEnabled", "check for updates"),
        ("AutomaticDownload", "download updates"),
        ("AutomaticallyInstallMacOSUpdates", "install macOS updates"),
        ("CriticalUpdateInstall", "install security responses and system files"),
        ("ConfigDataInstall", "install XProtect and security data"),
    ]

    public static func autoUpdates(softwareUpdate: [String: Any]?, appStoreAutoUpdate: String?) -> ParseOutcome {
        guard let su = softwareUpdate else { return .unknown("Couldn't read the Software Update settings.") }
        var off: [String] = []
        for (key, label) in autoUpdateKeys where boolValue(su[key]) == false { off.append(label) }   // missing key = default (on)
        if let a = appStoreAutoUpdate, boolValue(a) == false { off.append("update App Store apps") }
        if off.isEmpty { return .init(.pass, "Automatic updates are on, including security data.") }
        return .init(.fail, "Automatic updates are off for: " + off.joined(separator: ", ") + ".")
    }

    // MARK: 7 OS up to date — RecommendedUpdates in com.apple.SoftwareUpdate, `sw_vers`
    public static func productVersion(swVers s: String) -> String? {
        firstMatch(#"ProductVersion:\s*([0-9.]+)"#, in: s)?[1]
    }

    public static func osUpToDate(softwareUpdate: [String: Any]?, currentVersion: String?) -> ParseOutcome {
        guard let su = softwareUpdate else { return .unknown("Couldn't read the Software Update settings.") }
        let currentMajor = currentVersion.flatMap { $0.split(separator: ".").first.map(String.init) }
        let recs = su["RecommendedUpdates"] as? [[String: Any]] ?? []
        var pending: [String] = []
        for r in recs {
            let name = (r["Display Name"] as? String) ?? (r["Identifier"] as? String) ?? "Update"
            let ident = (r["Identifier"] as? String) ?? ""
            let version = (r["Display Version"] as? String) ?? ""
            let isOS = ident.hasPrefix("MSU_UPDATE") || name.hasPrefix("macOS") || (boolValue(r["MobileSoftwareUpdate"]) ?? false)
            let isSecurity = name.localizedCaseInsensitiveContains("security")
            guard isOS || isSecurity else { continue }   // Command Line Tools etc. don't count
            if isOS, !isSecurity, let cm = currentMajor, let um = version.split(separator: ".").first.map(String.init), um != cm {
                continue   // a new major release is optional; only same-major updates carry security fixes we expect
            }
            pending.append(version.isEmpty || name.contains(version) ? name : "\(name) \(version)")
        }
        if !pending.isEmpty { return .init(.fail, "Update available: " + pending.joined(separator: ", ") + ".") }
        if su["RecommendedUpdates"] == nil && su["LastSuccessfulDate"] == nil && su["LastFullSuccessfulDate"] == nil {
            return .unknown("Software Update hasn't checked for updates yet.")
        }
        return .init(.pass, "macOS \(currentVersion ?? "") is up to date.".replacingOccurrences(of: "  ", with: " "))
    }

    // MARK: 8 XProtect freshness — bundle Info.plist versions and modification dates
    public static func xprotectFreshness(bundles: [(version: String?, modified: Date?)], now: Date, maxAgeDays: Int = 30) -> ParseOutcome {
        let dated = bundles.compactMap { b in b.modified.map { (b.version, $0) } }
        guard let newest = dated.max(by: { $0.1 < $1.1 }) else { return .unknown("Couldn't find XProtect.") }
        let days = Int(now.timeIntervalSince(newest.1) / 86_400)
        let ver = newest.0.map { "version \($0)" } ?? "unknown version"
        if days <= maxAgeDays { return .init(.pass, "XProtect \(ver), updated \(days == 0 ? "today" : "\(days) day\(days == 1 ? "" : "s") ago").") }
        return .init(.fail, "XProtect \(ver) was last updated \(days) days ago.")
    }

    // MARK: 9 Screen lock — `sysadminctl -screenLock status` (answer goes to stderr)
    public static func screenLock(_ s: String, maxDelaySeconds: Int = 300) -> ParseOutcome {
        let l = lower(s)
        if l.contains("screenlock delay is immediate") { return .init(.pass, "A password is required immediately after sleep or the screen saver.") }
        if let m = firstMatch(#"screenlock delay is (\d+) seconds?"#, in: s), let secs = Int(m[1]) {
            let human = secs % 60 == 0 && secs >= 60 ? "\(secs / 60) minute\(secs == 60 ? "" : "s")" : "\(secs) seconds"
            if secs <= maxDelaySeconds { return .init(.pass, "A password is required \(secs == 0 ? "immediately" : "after \(human)").") }
            return .init(.fail, "A password is only required after \(human). 5 minutes or less is safer.")
        }
        if l.contains("screenlock is off") || l.contains("screenlock is disabled") || l.contains("screenlock delay is off") {
            return .init(.fail, "No password is required after sleep or the screen saver.")
        }
        return .unknown()
    }

    // MARK: 10 Guest — `sysadminctl -guestAccount status`, fallback loginwindow GuestEnabled
    public static func guestAccount(sysadminctl: String?, guestEnabledDefault: String?) -> ParseOutcome {
        if let s = sysadminctl.map(lower) {
            if s.contains("guest account disabled") { return .init(.pass, "The guest account is off.") }
            if s.contains("guest account enabled") { return .init(.fail, "The guest account is on. Anyone can log in without a password.") }
        }
        if let g = guestEnabledDefault, let b = boolValue(g) {
            return b ? .init(.fail, "The guest account is on. Anyone can log in without a password.") : .init(.pass, "The guest account is off.")
        }
        return .unknown()
    }

    // MARK: 11–14 launchd — `launchctl print system/<label>`, `launchctl print-disabled system`
    public static func launchdService(_ s: String) -> LaunchdServiceState {
        let l = lower(s)
        if l.contains("could not find service") { return .notLoaded }
        if l.contains("state = ") || l.contains("path = ") {
            return .loaded(running: l.contains("state = running"))
        }
        return .unknown
    }

    /// Map label -> disabled. Handles both `"x" => disabled` (13+) and `"x" => true` (older).
    public static func disabledServices(_ s: String) -> [String: Bool] {
        var out: [String: Bool] = [:]
        for line in s.split(separator: "\n") {
            guard let m = firstMatch(#"^\s*"([^"]+)"\s*=>\s*(\w+)"#, in: String(line)) else { continue }
            switch m[2].lowercased() {
            case "disabled", "true": out[m[1]] = true
            case "enabled", "false": out[m[1]] = false
            default: break
            }
        }
        return out
    }

    public static func remoteLogin(service: String?, disabled: [String: Bool]) -> ParseOutcome {
        let st = service.map(launchdService) ?? .unknown
        switch st {
        case .loaded: return .init(.fail, "Remote Login (SSH) is on. Others can log in to this Mac over the network.")
        case .notLoaded: return .init(.pass, "Remote Login (SSH) is off.")
        case .unknown:
            if disabled["com.openssh.sshd"] == true { return .init(.pass, "Remote Login (SSH) is off.") }
            return .unknown()
        }
    }

    public static func screenSharing(service: String?, remoteManagementFlagExists: Bool) -> ParseOutcome {
        if remoteManagementFlagExists { return .init(.fail, "Remote Management (Apple Remote Desktop) is on.") }
        switch service.map(launchdService) ?? .unknown {
        case .loaded: return .init(.fail, "Screen Sharing is on.")
        case .notLoaded: return .init(.pass, "Screen Sharing and Remote Management are off.")
        case .unknown: return .unknown()
        }
    }

    public static func fileSharing(service: String?) -> ParseOutcome {
        switch service.map(launchdService) ?? .unknown {
        case .loaded: return .init(.fail, "File Sharing (SMB) is on.")
        case .notLoaded: return .init(.pass, "File Sharing is off.")
        case .unknown: return .unknown()
        }
    }

    /// Group of "other sharing" services. nil input = couldn't read that one.
    public static func sharingServices(remoteAppleEvents: String?, natPlist: [String: Any]?, natPlistMissing: Bool,
                                       cupsctl: String?, mediaSharing: String?, contentCaching: String?) -> ParseOutcome {
        var on: [String] = [], known = 0
        if let ae = remoteAppleEvents {
            switch launchdService(ae) {
            case .loaded: on.append("Remote Apple Events"); known += 1
            case .notLoaded: known += 1
            case .unknown: break
            }
        }
        if let nat = natPlist {
            known += 1
            if let d = nat["NAT"] as? [String: Any], boolValue(d["Enabled"]) == true { on.append("Internet Sharing") }
        } else if natPlistMissing { known += 1 }
        if let c = cupsctl, c.contains("_share_printers=") {
            known += 1
            if c.contains("_share_printers=1") { on.append("Printer Sharing") }
        }
        if let m = mediaSharing {
            known += 1
            if boolValue(m) == true { on.append("Media Sharing") }
        }
        if let cc = contentCaching, let a = firstMatch(#"Activated:\s*(\w+)"#, in: cc) {
            known += 1
            if boolValue(a[1]) == true { on.append("Content Caching") }
        }
        if !on.isEmpty { return .init(.fail, "Turned on: " + on.joined(separator: ", ") + ".") }
        if known == 0 { return .unknown() }
        return .init(.pass, "Remote Apple Events, Internet, Printer and Media Sharing are off.")
    }

    // MARK: 15 AirDrop — `defaults read com.apple.sharingd DiscoverableMode`
    public static func airDrop(_ s: String?) -> ParseOutcome {
        guard let v = s?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty, !v.hasPrefix("Error") else {
            return .init(.pass, "AirDrop is set to Contacts Only (default).")
        }
        switch v.lowercased() {
        case "everyone": return .init(.fail, "AirDrop accepts files from everyone nearby.")
        case "contacts only": return .init(.pass, "AirDrop is set to Contacts Only.")
        case "off": return .init(.pass, "AirDrop receiving is off.")
        default: return .unknown("AirDrop mode \"\(v)\" isn't recognised.")
        }
    }

    // MARK: 16 Lockdown Mode — `defaults read .GlobalPreferences LDMGlobalEnabled` (bonus, never penalised)
    public static func lockdownMode(_ s: String?) -> ParseOutcome {
        if let s, boolValue(s) == true { return .init(.pass, "Lockdown Mode is on.") }
        return .init(.notApplicable, "Lockdown Mode is off. It's only needed if you might be personally targeted.")
    }

    // MARK: 17 Admin count — `dscl . -read /Groups/admin GroupMembership`
    public static func adminMembers(_ s: String) -> [String]? {
        guard let line = s.split(separator: "\n").first(where: { $0.hasPrefix("GroupMembership:") }) else { return nil }
        return line.dropFirst("GroupMembership:".count).split(whereSeparator: { $0 == " " || $0 == "\t" })
            .map(String.init).filter { $0 != "root" && !$0.hasPrefix("_") }
    }

    public static func adminCount(_ s: String) -> ParseOutcome {
        guard let admins = adminMembers(s) else { return .unknown() }
        if admins.count <= 1 { return .init(.pass, admins.isEmpty ? "No human administrator accounts found." : "One administrator account (\(admins[0])).") }
        return .init(.fail, "\(admins.count) administrator accounts: \(admins.joined(separator: ", ")). Fewer admin accounts means fewer ways in.")
    }

    // MARK: 18 Secure Keyboard Entry — `defaults read -app Terminal SecureKeyboardEntry`
    public static func secureKeyboardEntry(_ s: String?) -> ParseOutcome {
        if let s, boolValue(s) == true { return .init(.pass, "Terminal uses Secure Keyboard Entry.") }
        return .init(.fail, "Terminal's Secure Keyboard Entry is off, so other apps could read what you type there.")
    }

    // MARK: 19 Rosetta — `pgrep oahd`, /Library/Apple/usr/libexec/oah (info only)
    public static func rosetta(pgrepStatus: Int32?, oahDirExists: Bool, isAppleSilicon: Bool) -> ParseOutcome {
        guard isAppleSilicon else { return .init(.notApplicable, "Rosetta is only used on Apple silicon.") }
        if pgrepStatus == 0 { return .init(.notApplicable, "Rosetta is installed and running, so Intel apps (and Intel malware) can run. Info only.") }
        if oahDirExists { return .init(.notApplicable, "Rosetta is installed. Info only.") }
        return .init(.notApplicable, "Rosetta isn't installed.")
    }

    // MARK: 22 Secure boot — `bputil -d` (root)
    public static func secureBoot(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("permissive security") { return .init(.fail, "Startup security is set to Permissive Security.") }
        if l.contains("reduced security") { return .init(.fail, "Startup security is set to Reduced Security.") }
        if l.contains("full security") { return .init(.pass, "Startup security is set to Full Security.") }
        return .unknown()
    }

    // MARK: 23 Configuration profiles — `profiles list`
    public static let benignProfilePrefixes = ["com.apple.ManagedSettings."]   // Screen Time

    public static func profileIdentifiers(_ s: String) -> [String] {
        s.split(separator: "\n").compactMap { line in
            guard let r = line.range(of: "profileIdentifier:") else { return nil }
            let id = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
            return id.isEmpty ? nil : id
        }
    }

    public static func profiles(_ s: String) -> ParseOutcome {
        let l = lower(s)
        let ids = profileIdentifiers(s)
        if ids.isEmpty {
            if l.contains("no configuration profiles") || l.contains("there are 0 ") || s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                return .init(.pass, "No configuration profiles are installed.")
            }
            return .unknown()
        }
        let unexpected = ids.filter { id in !benignProfilePrefixes.contains { id.hasPrefix($0) } }
        if unexpected.isEmpty { return .init(.pass, "Only Apple system profiles (Screen Time) are installed.") }
        return .init(.fail, "Review these profiles: " + unexpected.joined(separator: ", ") + ". Profiles can change browser, proxy and DNS settings.")
    }

    // MARK: 24 Trusted root certificates — `security dump-trust-settings -d`
    /// TLS-inspecting web filters commonly installed by schools and employers.
    public static let knownOrgFilterCertMarkers = ["securly", "goguardian", "lightspeed", "zscaler", "netskope", "umbrella",
                                                   "forcepoint", "contentkeeper", "iboss", "smoothwall", "fortinet", "fortigate",
                                                   "palo alto", "linewize", "blocksi"]

    public static func trustedCertNames(_ s: String) -> [String] {
        s.split(separator: "\n").compactMap { line in
            guard let m = firstMatch(#"^Cert\s+\d+:\s*(.+)$"#, in: String(line)) else { return nil }
            return m[1].trimmingCharacters(in: .whitespaces)
        }
    }

    public static func trustedRoots(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("no trust settings were found") { return .init(.pass, "No extra trusted root certificates have been added.") }
        let names = trustedCertNames(s)
        if names.isEmpty {
            if l.contains("number of trusted certs = 0") { return .init(.pass, "No extra trusted root certificates have been added.") }
            return .unknown()
        }
        let org = names.filter { n in knownOrgFilterCertMarkers.contains { n.lowercased().contains($0) } }
        let other = names.filter { !org.contains($0) }
        if other.isEmpty {
            return .init(.pass, "Trusted certificate added by your organization's web filter: \(org.joined(separator: ", ")).")
        }
        return .init(.fail, "Extra trusted root certificates: \(other.joined(separator: ", ")). These can read secure web traffic.")
    }

    // MARK: 25 Firmware password (Intel) — `firmwarepasswd -check`
    public static func firmwarePassword(_ s: String) -> ParseOutcome {
        let l = lower(s)
        if l.contains("password enabled: yes") { return .init(.pass, "A firmware password is set.") }
        if l.contains("password enabled: no") { return .init(.fail, "No firmware password is set.") }
        return .unknown()
    }
}
