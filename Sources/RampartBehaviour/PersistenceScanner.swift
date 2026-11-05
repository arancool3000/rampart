import Foundation
import CryptoKit
import RampartShared

/// A persistence item plus the parsed details the scorer needs.
public struct PersistenceRecord: Codable, Hashable, Sendable, Identifiable {
    public var item: PersistenceItem
    public var arguments: [String]
    public var environment: [String: String]
    /// Kind-specific facts: runAtLoad, keepAlive, startInterval, teamID, developer, permissions, fromWebstore,
    /// installLocation, version, uid, disposition, suspiciousLines, nativeHost, script, ...
    public var attributes: [String: String]
    /// Content hash used by the differ to spot changes.
    public var fingerprint: String
    public var id: String { item.id }

    public init(item: PersistenceItem, arguments: [String] = [], environment: [String: String] = [:],
                attributes: [String: String] = [:], fingerprint: String = "") {
        self.item = item; self.arguments = arguments; self.environment = environment
        self.attributes = attributes
        self.fingerprint = fingerprint.isEmpty ? Hashing.sha256(item.label + "|" + (item.target ?? "") + "|" + arguments.joined(separator: " ")
            + "|" + environment.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")
            + "|" + attributes.sorted { $0.key < $1.key }.map { "\($0.key)=\($0.value)" }.joined(separator: ",")) : fingerprint
    }
}

enum Hashing {
    static func sha256(_ s: String) -> String { sha256(Data(s.utf8)) }
    static func sha256(_ d: Data) -> String { SHA256.hash(data: d).map { String(format: "%02x", $0) }.joined() }
    static func fileHash(_ p: String) -> String? { FileManager.default.contents(atPath: p).map { sha256($0) } }
}

public struct PersistenceScanConfig: Sendable {
    public var home: String
    public var launchAgentDirs: [String]
    public var launchDaemonDirs: [String]
    public var kinds: Set<PersistenceItem.Kind>
    /// Run sfltool / profiles / systemextensionsctl / crontab. Off in unit fixtures.
    public var runCommands: Bool
    public var commandTimeout: TimeInterval
    public var resolveSigning: Bool

    public static let allKinds: Set<PersistenceItem.Kind> = [.launchAgent, .launchDaemon, .loginItem, .btm, .cron, .periodic,
                                                             .shellRC, .profile, .browserExtension, .systemExtension, .sshKey, .other]

    public init(home: String = FileManager.default.homeDirectoryForCurrentUser.path, includeSystemLaunchd: Bool = false,
                kinds: Set<PersistenceItem.Kind> = PersistenceScanConfig.allKinds, runCommands: Bool = true,
                commandTimeout: TimeInterval = 20, resolveSigning: Bool = true) {
        self.home = home
        self.launchAgentDirs = [home + "/Library/LaunchAgents", "/Library/LaunchAgents"] + (includeSystemLaunchd ? ["/System/Library/LaunchAgents"] : [])
        self.launchDaemonDirs = ["/Library/LaunchDaemons"] + (includeSystemLaunchd ? ["/System/Library/LaunchDaemons"] : [])
        self.kinds = kinds; self.runCommands = runCommands; self.commandTimeout = commandTimeout
        self.resolveSigning = resolveSigning
    }
}

/// KnockKnock-style enumerator of every `PersistenceItem.Kind`.
public final class PersistenceScanner: @unchecked Sendable {
    public var config: PersistenceScanConfig
    private let signing: SigningProvider?
    private let fm = FileManager.default

    public init(config: PersistenceScanConfig = PersistenceScanConfig(), signing: SigningProvider? = nil) {
        self.config = config; self.signing = signing
    }

    /// Plain items (the shared IPC type).
    public func scan() -> [PersistenceItem] { scanRecords().map(\.item) }

    /// Full records, de-duplicated by id and sorted.
    public func scanRecords() -> [PersistenceRecord] {
        let k = config.kinds
        var out: [PersistenceRecord] = []
        if k.contains(.launchAgent) { for d in config.launchAgentDirs { out += launchd(dir: d, kind: .launchAgent) } }
        if k.contains(.launchDaemon) { for d in config.launchDaemonDirs { out += launchd(dir: d, kind: .launchDaemon) } }
        if (k.contains(.btm) || k.contains(.loginItem)) && config.runCommands,
           let r = Shell.run("/usr/bin/sfltool", ["dumpbtm"], timeout: config.commandTimeout) {
            out += Self.parseBTM(r.out).filter { k.contains($0.item.kind) }
        }
        if k.contains(.cron) { out += cron() }
        if k.contains(.periodic) { out += periodic() }
        if k.contains(.shellRC) { out += shellRC() }
        if k.contains(.profile) && config.runCommands {
            var args = ["list"]; if getuid() == 0 { args.append("-all") }
            if let r = Shell.run("/usr/bin/profiles", args, timeout: config.commandTimeout) { out += Self.parseProfiles(r.out) }
        }
        if k.contains(.browserExtension) { out += browserExtensions() }
        if k.contains(.systemExtension) && config.runCommands,
           let r = Shell.run("/usr/bin/systemextensionsctl", ["list"], timeout: config.commandTimeout) {
            out += Self.parseSystemExtensions(r.out)
        }
        if k.contains(.sshKey) { out += sshKeys() }
        if k.contains(.other) { out += others() }

        var seen = Set<String>()
        var result: [PersistenceRecord] = []
        for var r in out where seen.insert(r.id).inserted {
            if config.resolveSigning, r.item.signing == nil, let t = r.item.target, t.hasPrefix("/"), let signing {
                r.item.signing = signing(t)
            }
            result.append(r)
        }
        return result.sorted { $0.id < $1.id }
    }

    // MARK: launchd

    func launchd(dir: String, kind: PersistenceItem.Kind) -> [PersistenceRecord] {
        guard let names = try? fm.contentsOfDirectory(atPath: dir) else { return [] }
        return names.filter { $0.hasSuffix(".plist") }.sorted().compactMap { n in
            let p = (dir as NSString).appendingPathComponent(n)
            return Self.parseLaunchdPlist(path: p, kind: kind)
        }
    }

    public static func parseLaunchdPlist(path: String, kind: PersistenceItem.Kind) -> PersistenceRecord? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return parseLaunchdPlist(data: data, path: path, kind: kind)
    }

    public static func parseLaunchdPlist(data: Data, path: String, kind: PersistenceItem.Kind) -> PersistenceRecord? {
        let fileName = ((path as NSString).lastPathComponent as NSString).deletingPathExtension
        var attrs: [String: String] = [:]
        guard let obj = try? PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any] else {
            attrs["parseError"] = "1"
            return PersistenceRecord(item: PersistenceItem(kind: kind, label: fileName, location: path),
                                     attributes: attrs, fingerprint: Hashing.sha256(data))
        }
        let label = obj["Label"] as? String ?? fileName
        let program = obj["Program"] as? String
        let args = (obj["ProgramArguments"] as? [Any])?.compactMap { $0 as? String } ?? []
        let env = (obj["EnvironmentVariables"] as? [String: Any])?.compactMapValues { "\($0)" } ?? [:]
        let target = program ?? args.first
        if let v = obj["RunAtLoad"] as? Bool { attrs["runAtLoad"] = v ? "1" : "0" }
        if let v = obj["KeepAlive"] { attrs["keepAlive"] = (v as? Bool).map { $0 ? "1" : "0" } ?? "conditional" }
        if let v = obj["StartInterval"] as? Int { attrs["startInterval"] = String(v) }
        if obj["StartCalendarInterval"] != nil { attrs["calendar"] = "1" }
        if let w = obj["WatchPaths"] as? [String] { attrs["watchPaths"] = w.joined(separator: ",") }
        if let d = obj["Disabled"] as? Bool { attrs["disabled"] = d ? "1" : "0" }
        if let a = obj["AssociatedBundleIdentifiers"] { attrs["bundleIDs"] = "\(a)" }
        if label != fileName { attrs["labelMismatch"] = "1" }
        if let t = target, ["sh", "bash", "zsh", "python", "python3", "perl", "ruby", "osascript", "node"].contains(PathUtil.basename(t)) {
            // Interpreter job: the script it runs is the real target.
            if let script = args.dropFirst().first(where: { !$0.hasPrefix("-") }) { attrs["script"] = script }
            if args.contains("-c") || args.contains("-e") { attrs["inline"] = "1" }
        }
        return PersistenceRecord(item: PersistenceItem(kind: kind, label: label, location: path, target: target),
                                 arguments: args, environment: env, attributes: attrs, fingerprint: Hashing.sha256(data))
    }

    // MARK: BTM

    /// Parses `sfltool dumpbtm`. Developer-group header entries (no executable) are skipped.
    public static func parseBTM(_ text: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        var uid = "?"
        var cur: [String: String] = [:]
        func flush() {
            defer { cur = [:] }
            guard let uuid = cur["UUID"] else { return }
            let type = cur["Type"] ?? ""
            if type.hasPrefix("developer") { return }
            let name = cur["Name"] ?? cur["Identifier"] ?? uuid
            let url = cur["URL"].flatMap { $0 == "(null)" ? nil : $0 }
            var exe = cur["Executable Path"].flatMap { $0 == "(null)" ? nil : $0 }
            if let e = exe, !e.hasPrefix("/"), let u = url, u.hasPrefix("/") { exe = (u as NSString).appendingPathComponent(e) }
            if exe == nil, let u = url, u.hasSuffix(".app") { exe = u }
            let kind: PersistenceItem.Kind = type.hasPrefix("login item") || type.hasPrefix("app ") || type == "app" ? .loginItem : .btm
            var attrs: [String: String] = ["uid": uid, "type": type, "uuid": uuid]
            for (k, a) in [("Developer Name", "developer"), ("Team Identifier", "teamID"), ("Disposition", "disposition"),
                           ("Identifier", "identifier"), ("Parent Identifier", "parent"), ("Assoc. Bundle IDs", "bundleIDs"),
                           ("Flags", "flags")] {
                if let v = cur[k] { attrs[a] = v }
            }
            let location = url ?? "btm:\(uid):\(uuid)"
            // Key by UUID so two records sharing a plist URL (e.g. legacy agent + daemon) stay distinct.
            let rec = PersistenceRecord(item: PersistenceItem(kind: kind, label: name, location: location + (url != nil ? "#" + uuid : ""), target: exe),
                                        attributes: attrs)
            out.append(rec)
        }
        for raw in text.components(separatedBy: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Records for UID") {
                flush()
                uid = line.replacingOccurrences(of: "Records for UID", with: "").split(separator: ":").first
                    .map { $0.trimmingCharacters(in: .whitespaces) } ?? "?"
                continue
            }
            if line.hasPrefix("#"), line.hasSuffix(":"), Int(line.dropFirst().dropLast()) != nil { flush(); continue }
            guard let colon = line.range(of: ": ") else { continue }
            let key = String(line[..<colon.lowerBound]).trimmingCharacters(in: .whitespaces)
            let value = String(line[colon.upperBound...]).trimmingCharacters(in: .whitespaces)
            if cur[key] == nil { cur[key] = value }
        }
        flush()
        return out
    }

    // MARK: cron / periodic

    func cron() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        if config.runCommands, let r = Shell.run("/usr/bin/crontab", ["-l"], timeout: config.commandTimeout), r.status == 0 {
            out += Self.parseCrontab(r.out, source: "crontab:" + NSUserName())
        }
        for f in ["/etc/crontab"] + files(in: "/usr/lib/cron/tabs") + files(in: "/usr/lib/cron/jobs") {
            if let s = try? String(contentsOfFile: f, encoding: .utf8) { out += Self.parseCrontab(s, source: f) }
        }
        return out
    }

    public static func parseCrontab(_ text: String, source: String) -> [PersistenceRecord] {
        text.components(separatedBy: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            // VAR=value lines are environment, not jobs.
            if let eq = line.firstIndex(of: "="), !line[..<eq].contains(" ") { return nil }
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            let cmdFields = line.hasPrefix("@") ? fields.dropFirst(1) : fields.dropFirst(5)
            let command = cmdFields.joined(separator: " ")
            let target = cmdFields.first.map(String.init).flatMap { $0.hasPrefix("/") || $0.hasPrefix("~") ? $0 : nil }
            return PersistenceRecord(item: PersistenceItem(kind: .cron, label: command.isEmpty ? line : command,
                                                           location: source + "#" + String(Hashing.sha256(line).prefix(12)), target: target),
                                     attributes: ["line": line])
        }
    }

    func periodic() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        var paths: [String] = []
        for d in ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly"] { paths += files(in: d) }
        for d in files(in: "/usr/local/etc/periodic", dirsOnly: true) { paths += files(in: d) }
        paths += ["/etc/periodic.conf", "/etc/periodic.conf.local", "/etc/daily.local", "/etc/weekly.local", "/etc/monthly.local"]
            .filter { fm.fileExists(atPath: $0) }
        for p in paths {
            out.append(PersistenceRecord(item: PersistenceItem(kind: .periodic, label: PathUtil.basename(p), location: p, target: p),
                                         fingerprint: Hashing.fileHash(p) ?? ""))
        }
        return out
    }

    // MARK: shell rc

    public static func rcFiles(home: String) -> [String] {
        [".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".bash_login", ".profile"].map { home + "/" + $0 }
            + ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/bashrc", "/etc/zlogin"]
    }

    func shellRC() -> [PersistenceRecord] {
        Self.rcFiles(home: config.home).compactMap { p in
            guard let s = try? String(contentsOfFile: p, encoding: .utf8) else { return nil }
            let bad = Self.suspiciousShellLines(s)
            var attrs: [String: String] = ["lines": String(s.components(separatedBy: "\n").count)]
            if !bad.isEmpty { attrs["suspiciousLines"] = bad.joined(separator: "\n") }
            return PersistenceRecord(item: PersistenceItem(kind: .shellRC, label: PathUtil.basename(p), location: p),
                                     attributes: attrs, fingerprint: Hashing.sha256(s))
        }
    }

    static let shellLinePatterns: [(String, String)] = [
        (#"\b(curl|wget)\b[^#]*(\||\$\(|`)|(\$\(|`)\s*(curl|wget)\b"#, "downloads remote content into the shell"),
        (#"base64\s+(-d|--decode|-D)|openssl\s+(enc|base64)\s.*-d"#, "decodes an encoded blob"),
        (#"(^|[\s;&|(])(/private)?/(tmp|var/folders|Users/Shared)/\S+"#, "runs something from a temp or shared folder"),
        (#"export\s+DYLD_|^\s*DYLD_[A-Z_]+="#, "sets DYLD_* (dylib injection)"),
        (#"alias\s+(sudo|ssh|su|login)="#, "overrides sudo/ssh with an alias"),
        (#"(nohup|disown|\s&\s*$).*/\.[A-Za-z0-9_-]+/"#, "starts a background job from a hidden folder"),
        (#"\bosascript\b.*-e"#, "runs inline AppleScript at shell start"),
        (#"\b(nc|ncat|socat)\b.*\s-e\s"#, "opens a reverse shell"),
        (#"/dev/tcp/"#, "opens a raw TCP connection"),
    ]

    /// Lines that fetch, decode, exec from hidden/temp paths, export DYLD_*, or alias sudo/ssh.
    public static func suspiciousShellLines(_ text: String) -> [String] {
        text.components(separatedBy: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            return shellLineReason(line) != nil ? line : nil
        }
    }

    static func shellLineReason(_ line: String) -> String? {
        for (p, why) in shellLinePatterns where RegexCache.shared.matches(p, line) { return why }
        return nil
    }

    // MARK: profiles

    public static func parseProfiles(_ text: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for line in text.components(separatedBy: "\n") {
            guard let r = line.range(of: "profileIdentifier:") else { continue }
            let id = line[r.upperBound...].trimmingCharacters(in: .whitespaces)
            guard !id.isEmpty else { continue }
            let scope = line.hasPrefix("_computerlevel") ? "computer" : String(line.split(separator: "[").first ?? "user")
            out.append(PersistenceRecord(item: PersistenceItem(kind: .profile, label: id, location: "profile:" + id),
                                         attributes: ["scope": scope, "identifier": id]))
        }
        return out
    }

    // MARK: system extensions

    public static func parseSystemExtensions(_ text: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        var category = ""
        for raw in text.components(separatedBy: "\n") {
            if raw.hasPrefix("--- ") { category = String(raw.dropFirst(4).split(separator: " ").first ?? ""); continue }
            let cols = raw.components(separatedBy: "\t")
            guard cols.count >= 6, cols[0] != "enabled" else { continue }
            let team = cols[2].trimmingCharacters(in: .whitespaces)
            let bidVer = cols[3]
            let bundleID = String(bidVer.split(separator: " ").first ?? "")
            let version = bidVer.range(of: "(").map { String(bidVer[$0.upperBound...].dropLast()) } ?? ""
            let name = cols[4]
            let state = cols[5...].joined(separator: " ")
            guard !bundleID.isEmpty else { continue }
            out.append(PersistenceRecord(item: PersistenceItem(kind: .systemExtension, label: name,
                                                               location: "sysext:\(team).\(bundleID)"),
                                         attributes: ["teamID": team, "bundleID": bundleID, "version": version, "state": state,
                                                      "category": category, "enabled": cols[0] == "*" ? "1" : "0",
                                                      "active": cols[1] == "*" ? "1" : "0"]))
        }
        return out
    }

    // MARK: browser extensions

    static let chromiumVendors: [(String, String)] = [
        ("Chrome", "Google/Chrome"), ("Brave", "BraveSoftware/Brave-Browser"), ("Edge", "Microsoft Edge"),
        ("Arc", "Arc/User Data"), ("Vivaldi", "Vivaldi"), ("Chromium", "Chromium"),
    ]

    func browserExtensions() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let appSupport = config.home + "/Library/Application Support"
        for (browser, rel) in Self.chromiumVendors {
            let root = appSupport + "/" + rel
            for profile in files(in: root, dirsOnly: true).map(PathUtil.basename)
            where profile == "Default" || profile.hasPrefix("Profile ") || profile == "Guest Profile" {
                out += Self.chromiumExtensions(profileDir: root + "/" + profile, browser: browser)
            }
        }
        let ffRoot = appSupport + "/Firefox/Profiles"
        for p in files(in: ffRoot, dirsOnly: true) { out += Self.firefoxExtensions(profileDir: p) }
        return out
    }

    static func chromiumExtensions(profileDir: String, browser: String) -> [PersistenceRecord] {
        let fm = FileManager.default
        let extRoot = profileDir + "/Extensions"
        guard let ids = try? fm.contentsOfDirectory(atPath: extRoot) else { return [] }
        // extensions.settings from (Secure) Preferences: from_webstore, location, state
        var settings: [String: [String: Any]] = [:]
        for prefName in ["Secure Preferences", "Preferences"] {
            guard let d = fm.contents(atPath: profileDir + "/" + prefName),
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let ext = j["extensions"] as? [String: Any], let s = ext["settings"] as? [String: Any] else { continue }
            for (k, v) in s { if settings[k] == nil, let vv = v as? [String: Any] { settings[k] = vv } }
        }
        let profileName = PathUtil.basename(profileDir)
        var out: [PersistenceRecord] = []
        for id in ids.sorted() where id.count == 32 {
            let dir = extRoot + "/" + id
            guard let versions = try? fm.contentsOfDirectory(atPath: dir),
                  let ver = versions.filter({ fm.fileExists(atPath: dir + "/" + $0 + "/manifest.json") })
                    .sorted(by: { $0.compare($1, options: .numeric) == .orderedAscending }).last else { continue }
            let vdir = dir + "/" + ver
            guard let md = fm.contents(atPath: vdir + "/manifest.json"),
                  let m = try? JSONSerialization.jsonObject(with: md) as? [String: Any] else { continue }
            let name = resolveMessage(m["name"] as? String ?? id, extDir: vdir, defaultLocale: m["default_locale"] as? String)
            var perms = (m["permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
            perms += (m["host_permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
            if let cs = m["content_scripts"] as? [[String: Any]] {
                for c in cs { perms += (c["matches"] as? [String]) ?? [] }
            }
            var attrs: [String: String] = ["browser": browser, "profile": profileName, "extensionID": id, "version": ver,
                                           "permissions": Array(Set(perms)).sorted().joined(separator: ",")]
            if let u = m["update_url"] as? String { attrs["updateURL"] = u }
            if let s = settings[id] {
                if let w = s["from_webstore"] as? Bool { attrs["fromWebstore"] = w ? "1" : "0" }
                if let l = s["location"] as? Int { attrs["installLocation"] = String(l) }
                if let st = s["state"] as? Int { attrs["state"] = String(st) }
            }
            if attrs["fromWebstore"] == nil, let u = attrs["updateURL"] {
                attrs["fromWebstore"] = (u.contains("clients2.google.com") || u.contains("edge.microsoft.com")) ? "1" : "0"
            }
            out.append(PersistenceRecord(item: PersistenceItem(kind: .browserExtension, label: "\(browser) (\(profileName)): \(name)",
                                                               location: dir),
                                         attributes: attrs, fingerprint: Hashing.sha256(md)))
        }
        return out
    }

    /// Resolves "__MSG_key__" names from _locales/<locale>/messages.json.
    static func resolveMessage(_ s: String, extDir: String, defaultLocale: String?) -> String {
        guard s.hasPrefix("__MSG_"), s.hasSuffix("__") else { return s }
        let key = String(s.dropFirst(6).dropLast(2))
        for loc in [defaultLocale, "en", "en_US", "en_GB"].compactMap({ $0 }) {
            guard let d = FileManager.default.contents(atPath: "\(extDir)/_locales/\(loc)/messages.json"),
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { continue }
            if let entry = j.first(where: { $0.key.lowercased() == key.lowercased() })?.value as? [String: Any],
               let m = entry["message"] as? String { return m }
        }
        return key
    }

    static func firefoxExtensions(profileDir: String) -> [PersistenceRecord] {
        guard let d = FileManager.default.contents(atPath: profileDir + "/extensions.json"),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let addons = j["addons"] as? [[String: Any]] else { return [] }
        return parseFirefoxAddons(addons, profileDir: profileDir)
    }

    public static func parseFirefoxAddons(_ addons: [[String: Any]], profileDir: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for a in addons {
            guard (a["type"] as? String) == "extension", let id = a["id"] as? String else { continue }
            let loc = a["location"] as? String ?? ""
            if loc.hasPrefix("app-builtin") || loc.hasPrefix("app-system") { continue }
            let name = (a["defaultLocale"] as? [String: Any])?["name"] as? String ?? id
            var perms: [String] = []
            if let up = a["userPermissions"] as? [String: Any] {
                perms += (up["permissions"] as? [String]) ?? []; perms += (up["origins"] as? [String]) ?? []
            }
            let src = a["sourceURI"] as? String ?? ""
            let attrs: [String: String] = ["browser": "Firefox", "profile": PathUtil.basename(profileDir), "extensionID": id,
                                           "version": a["version"] as? String ?? "", "installLocation": loc,
                                           "permissions": perms.sorted().joined(separator: ","),
                                           "fromWebstore": src.contains("addons.mozilla.org") || src.contains("addons.cdn.mozilla.net") || src.isEmpty && loc == "app-profile" && (a["signedState"] as? Int ?? 0) > 0 ? "1" : "0",
                                           "active": (a["active"] as? Bool ?? false) ? "1" : "0"]
            let path = a["path"] as? String ?? profileDir + "/extensions/\(id).xpi"
            out.append(PersistenceRecord(item: PersistenceItem(kind: .browserExtension, label: "Firefox: \(name)", location: path),
                                         attributes: attrs))
        }
        return out
    }

    // MARK: ssh

    func sshKeys() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for f in ["authorized_keys", "authorized_keys2"] {
            let p = config.home + "/.ssh/" + f
            if let s = try? String(contentsOfFile: p, encoding: .utf8) { out += Self.parseAuthorizedKeys(s, path: p) }
        }
        return out
    }

    public static func parseAuthorizedKeys(_ text: String, path: String) -> [PersistenceRecord] {
        text.components(separatedBy: "\n").compactMap { raw in
            let line = raw.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, !line.hasPrefix("#") else { return nil }
            let toks = line.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
            guard let ti = toks.firstIndex(where: { $0.hasPrefix("ssh-") || $0.hasPrefix("ecdsa-") || $0.hasPrefix("sk-") }),
                  ti + 1 < toks.count else { return nil }
            let blob = toks[ti + 1]
            let fp: String
            if let d = Data(base64Encoded: blob) {
                fp = "SHA256:" + Data(SHA256.hash(data: d)).base64EncodedString().replacingOccurrences(of: "=", with: "")
            } else { fp = "SHA256?" + String(Hashing.sha256(blob).prefix(16)) }
            let comment = toks.dropFirst(ti + 2).joined(separator: " ")
            var attrs = ["keyType": toks[ti], "fingerprint": fp]
            if ti > 0 { attrs["options"] = toks[..<ti].joined(separator: " ") }
            if !comment.isEmpty { attrs["comment"] = comment }
            return PersistenceRecord(item: PersistenceItem(kind: .sshKey, label: comment.isEmpty ? "\(toks[ti]) \(fp)" : comment,
                                                           location: path + "#" + fp), attributes: attrs)
        }
    }

    // MARK: other (native messaging hosts, auth plugins, startup items, login hooks)

    func others() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let appSupport = config.home + "/Library/Application Support"
        var nmhDirs = Self.chromiumVendors.map { appSupport + "/" + $0.1 + "/NativeMessagingHosts" }
        nmhDirs += [appSupport + "/Mozilla/NativeMessagingHosts", "/Library/Google/Chrome/NativeMessagingHosts",
                    "/Library/Application Support/Mozilla/NativeMessagingHosts", "/Library/Microsoft/Edge/NativeMessagingHosts"]
        for d in nmhDirs { for f in files(in: d) where f.hasSuffix(".json") { if let r = Self.parseNativeHost(path: f) { out.append(r) } } }
        for d in ["/Library/Security/SecurityAgentPlugins", "/Library/DirectoryServices/PlugIns", "/Library/StartupItems"] {
            for b in files(in: d, includeDirs: true) {
                out.append(PersistenceRecord(item: PersistenceItem(kind: .other, label: PathUtil.basename(b), location: b, target: b),
                                             attributes: ["class": PathUtil.basename(d)]))
            }
        }
        for plist in ["/var/root/Library/Preferences/com.apple.loginwindow.plist", "/Library/Preferences/com.apple.loginwindow.plist"] {
            guard let d = fm.contents(atPath: plist),
                  let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { continue }
            for k in ["LoginHook", "LogoutHook"] {
                if let v = o[k] as? String {
                    out.append(PersistenceRecord(item: PersistenceItem(kind: .other, label: k, location: plist + "#" + k, target: v),
                                                 attributes: ["class": "loginHook"]))
                }
            }
        }
        return out
    }

    public static func parseNativeHost(path: String) -> PersistenceRecord? {
        guard let d = FileManager.default.contents(atPath: path),
              let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any] else { return nil }
        let name = j["name"] as? String ?? PathUtil.basename(path)
        let exe = j["path"] as? String
        var attrs: [String: String] = ["class": "nativeMessagingHost", "nativeHost": "1"]
        if let o = j["allowed_origins"] as? [String] { attrs["origins"] = o.joined(separator: ",") }
        if let o = j["allowed_extensions"] as? [String] { attrs["origins"] = o.joined(separator: ",") }
        return PersistenceRecord(item: PersistenceItem(kind: .other, label: name, location: path, target: exe),
                                 attributes: attrs, fingerprint: Hashing.sha256(d))
    }

    // MARK: fs helpers

    private func files(in dir: String, dirsOnly: Bool = false, includeDirs: Bool = false) -> [String] {
        guard let names = try? fm.contentsOfDirectory(atPath: dir) else { return [] }
        return names.filter { !$0.hasPrefix(".") }.sorted().compactMap { n in
            let p = (dir as NSString).appendingPathComponent(n)
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: p, isDirectory: &isDir) else { return nil }
            if dirsOnly { return isDir.boolValue ? p : nil }
            if isDir.boolValue && !includeDirs { return nil }
            return p
        }
    }
}

public extension PersistenceScanner {
    /// Extensions of one Chromium profile directory (public for fixtures and on-demand scans).
    static func chromiumExtensionRecords(profileDir: String, browser: String) -> [PersistenceRecord] {
        chromiumExtensions(profileDir: profileDir, browser: browser)
    }
}
