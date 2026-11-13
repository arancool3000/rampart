import Foundation
import RampartShared

/// wms-o10: extra persistence and stealth collectors. All read-only file reads (no tools, no prompts).
///
/// Quiet by design: every record carries `attributes["collector"]`, and the snapshot remembers which collectors
/// ran (`PersistenceSnapshot.collectors`). A collector that is new since the stored baseline only seeds the
/// baseline; it never reports what was already there as "added". After that, only changes are assessed, and the
/// assessor (`PersistenceAssessor.assessO10`) alerts only on known-bad content in those changes.
extension PersistenceScanner {
    /// Collector IDs added by this file. Bump an ID (e.g. "sysconfig2") when a collector's record shape changes.
    public static let o10CollectorIDs: [String] = [
        "sysconfig", "shellExtra", "sshExtra", "plugins", "kext", "folderActions", "emond", "relaunch", "lsenv",
        "chromiumExtra", "browserPolicy", "safari", "hiddenItems",
    ]

    func o10Records(kinds k: Set<PersistenceItem.Kind>) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let home = config.home
        if k.contains(.other) {
            out += Self.systemConfigRecords(home: home)
            out += Self.pluginRecords(home: home)
            out += Self.kextRecords()
            out += Self.folderActionRecords(home: home)
            out += Self.emondRecords()
            out += Self.relaunchRecords(home: home)
            out += Self.lsEnvironmentRecords(home: home)
            out += Self.hiddenAuthItems()
        }
        if k.contains(.shellRC) { out += Self.extraShellRecords(home: home) }
        if k.contains(.sshKey), home != "/var/root", home != "/private/var/root" {
            for f in ["authorized_keys", "authorized_keys2"] {
                let p = "/var/root/.ssh/" + f
                if let s = try? String(contentsOfFile: p, encoding: .utf8) {
                    out += Self.parseAuthorizedKeys(s, path: p).map { Self.tag($0, "sshExtra") }
                }
            }
        }
        if k.contains(.browserExtension) {
            out += Self.chromiumUnpackedAndExternal(home: home)
            out += Self.browserPolicyRecords(home: home)
            out += Self.safariExtensionRecords(home: home)
        }
        return out
    }

    // MARK: helpers

    static func tag(_ r: PersistenceRecord, _ collector: String) -> PersistenceRecord {
        var attrs = r.attributes; attrs["collector"] = collector
        return PersistenceRecord(item: r.item, arguments: r.arguments, environment: r.environment, attributes: attrs,
                                 fingerprint: r.fingerprint)
    }

    static func record(_ kind: PersistenceItem.Kind, label: String, location: String, target: String? = nil,
                       collector: String, attrs: [String: String], fingerprint: String = "") -> PersistenceRecord {
        var a = attrs; a["collector"] = collector
        return PersistenceRecord(item: PersistenceItem(kind: kind, label: label, location: location, target: target),
                                 attributes: a, fingerprint: fingerprint)
    }

    /// Directory entries (including hidden ones), sorted, as full paths.
    static func entries(_ dir: String) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir)) ?? []).sorted().map { (dir as NSString).appendingPathComponent($0) }
    }

    static func isDir(_ p: String) -> Bool {
        var d: ObjCBool = false
        return FileManager.default.fileExists(atPath: p, isDirectory: &d) && d.boolValue
    }

    static func nonCommentLines(_ text: String, comment: Character = "#") -> [String] {
        text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty && $0.first != comment }
    }

    // MARK: system configuration (P03): sudoers, PAM, hosts, resolver, sshd, ssh rc

    /// Files hashed by the sysconfig collector, with their area. Unreadable files (sudoers as non-root) are skipped.
    static func systemConfigFiles(home: String) -> [(path: String, area: String)] {
        var out: [(String, String)] = [("/etc/sudoers", "sudoers"), ("/etc/hosts", "hosts"), ("/etc/ssh/sshd_config", "sshd"),
                                       ("/etc/ssh/sshrc", "sshrc"), (home + "/.ssh/rc", "sshrc"), (home + "/.ssh/environment", "sshrc")]
        for p in entries("/etc/sudoers.d") where !isDir(p) { out.append((p, "sudoers")) }
        for p in entries("/etc/pam.d") where !isDir(p) { out.append((p, "pam")) }
        for p in entries("/etc/resolver") where !isDir(p) { out.append((p, "resolver")) }
        for p in entries("/etc/ssh/sshd_config.d") where !isDir(p) { out.append((p, "sshd")) }
        return out
    }

    static func systemConfigRecords(home: String) -> [PersistenceRecord] {
        systemConfigFiles(home: home).compactMap { f in
            guard let d = FileManager.default.contents(atPath: f.path) else { return nil }
            let text = String(decoding: d.prefix(4 << 20), as: UTF8.self)
            let risky = riskyConfigLines(area: f.area, path: f.path, text: text)
            var attrs = ["class": "sysconfig", "area": f.area]
            if !risky.isEmpty { attrs["riskyLines"] = risky.prefix(20).joined(separator: "\n") }
            return record(.other, label: "\(f.area): \(PathUtil.basename(f.path))", location: f.path, collector: "sysconfig",
                          attrs: attrs, fingerprint: Hashing.sha256(d))
        }
    }

    /// Known-bad lines, each as "<reason>: <line>". Pure function (fixtures).
    public static func riskyConfigLines(area: String, path: String, text: String) -> [String] {
        switch area {
        case "sudoers": return nonCommentLinesKeepingIncludes(text).compactMap { l in sudoersReason(l).map { "\($0): \(l)" } }
        case "pam": return nonCommentLines(text).compactMap { l in pamReason(l).map { "\($0): \(l)" } }
        case "hosts": return hostsRisks(text)
        case "resolver": return resolverRisks(domain: PathUtil.basename(path), text: text)
        case "sshd": return nonCommentLines(text).compactMap { l in sshdReason(l).map { "\($0): \(l)" } }
        case "sshrc": return nonCommentLines(text).prefix(5).map { "runs at every SSH login: \($0)" }
        default: return []
        }
    }

    /// sudoers comments start with "#", except the "#include" / "#includedir" directives.
    static func nonCommentLinesKeepingIncludes(_ text: String) -> [String] {
        text.components(separatedBy: "\n").map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && (!$0.hasPrefix("#") || $0.hasPrefix("#include")) }
    }

    static let sudoersPatterns: [(String, String)] = [
        (#"NOPASSWD\s*:\s*ALL\s*$"#, "passwordless root for every command"),
        (#"!\s*authenticate\b"#, "turns off sudo's password check"),
        (#"timestamp_timeout\s*=\s*-"#, "makes a sudo login never expire"),
        (#"env_keep\s*\+?=.*\b(DYLD_\w*|LD_\w*|PYTHONPATH|PYTHONSTARTUP|PERL5LIB|PERL5OPT|RUBYLIB|RUBYOPT|BASH_ENV|NODE_OPTIONS|ENV)\b"#, "keeps code-injection variables for root"),
        (#"^[#@]include(dir)?\s+(?!/(private/)?etc/)"#, "loads sudo rules from outside /etc"),
        (#"^(?!root\b|%admin\b|Defaults\b|[#@])\S+\s+ALL\s*=\s*\(\s*ALL(\s*:\s*ALL)?\s*\)\s*(NOPASSWD\s*:\s*)?ALL\s*$"#, "gives an extra user or group full root"),
    ]

    static func sudoersReason(_ line: String) -> String? {
        for (p, why) in sudoersPatterns where RegexCache.shared.matches(p, line) { return why }
        return nil
    }

    /// PAM modules people add on purpose (Touch ID / Apple Watch for sudo).
    static let benignPAMModules: Set<String> = ["pam_tid.so", "pam_tid.so.2", "pam_reattach.so", "pam_watchid.so", "pam_watchid.so.2"]

    static func pamReason(_ line: String) -> String? {
        let t = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
        guard t.count >= 3 else { return nil }
        let type = t[0].lowercased(), control = t[1].lowercased()
        // Controls in brackets ([success=done ...]) contain spaces; find the module token.
        guard let module = t.dropFirst(1).first(where: { $0.contains(".so") || $0.hasPrefix("/") }) else { return nil }
        let base = PathUtil.basename(module)
        if base.hasPrefix("pam_permit"), type.hasSuffix("auth"), control == "sufficient" || control.contains("done") || control.contains("ok") {
            return "accepts any password"
        }
        if base.hasPrefix("pam_exec") { return "runs a program during authentication" }
        if module.hasPrefix("/"), !module.hasPrefix("/usr/lib/pam/"), !benignPAMModules.contains(base) {
            return "loads a third-party PAM module"
        }
        return nil
    }

    /// Update, revocation and security-tool domains: blocking or redirecting them is never benign.
    static let securityDomains = [
        "swscan.apple.com", "swdist.apple.com", "swcdn.apple.com", "mesu.apple.com", "gdmf.apple.com", "updates.cdn-apple.com",
        "xprotect.apple.com", "configuration.apple.com", "ocsp.apple.com", "ocsp2.apple.com", "valid.apple.com", "crl.apple.com",
        "api.apple-cloudkit.com",
    ]
    /// Security vendors: only the site itself counts (ad-block lists routinely block their telemetry subdomains).
    static let securityVendorSites = ["virustotal.com", "malwarebytes.com", "objective-see.org", "objective-see.com"]
    /// High-value sites: pointing them at a real (non-loopback) address is a phishing/pharming redirect.
    static let highValueDomains = [
        "apple.com", "icloud.com", "google.com", "gmail.com", "googleapis.com", "microsoft.com", "live.com", "office.com",
        "microsoftonline.com", "github.com", "paypal.com", "amazon.com", "facebook.com", "instagram.com", "x.com", "twitter.com",
        "binance.com", "coinbase.com", "kraken.com", "metamask.io", "ledger.com", "blockchain.com", "chase.com",
        "bankofamerica.com", "wellsfargo.com", "hsbc.com", "barclays.co.uk", "stripe.com", "dropbox.com", "okta.com",
    ]

    static func domainMatches(_ host: String, _ list: [String]) -> String? {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return list.first { h == $0 || h.hasSuffix("." + $0) }
    }

    /// Loopback, unspecified, private, link-local and CGNAT (Tailscale) addresses.
    public static func isLocalAddress(_ ip: String) -> Bool {
        let s = ip.lowercased()
        if s == "0.0.0.0" || s == "::" || s == "::1" || s.hasPrefix("127.") || s.hasPrefix("10.") || s.hasPrefix("192.168.")
            || s.hasPrefix("169.254.") || s.hasPrefix("fe80:") || s.hasPrefix("fc") || s.hasPrefix("fd") { return true }
        let o = s.split(separator: ".").compactMap { Int($0) }
        if o.count == 4 {
            if o[0] == 172 && (16...31).contains(o[1]) { return true }
            if o[0] == 100 && (64...127).contains(o[1]) { return true }
        }
        return false
    }

    static func hostsRisks(_ text: String) -> [String] {
        var out: [String] = []
        for raw in text.components(separatedBy: "\n") {
            let line = raw.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init)?
                .trimmingCharacters(in: .whitespaces) ?? ""
            let t = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard t.count >= 2 else { continue }
            let ip = t[0]
            for host in t.dropFirst() {
                let h = host.lowercased()
                let vendor = securityVendorSites.first { h == $0 || h == "www." + $0 || h == "downloads." + $0 }
                if let d = domainMatches(host, securityDomains) ?? vendor {
                    out.append("blocks or redirects the security service \(d): \(line)"); break
                }
                if !isLocalAddress(ip), let d = domainMatches(host, highValueDomains) {
                    out.append("sends \(d) to another server (\(ip)): \(line)"); break
                }
            }
            if out.count >= 20 { break }
        }
        return out
    }

    static func resolverRisks(domain: String, text: String) -> [String] {
        let servers = nonCommentLines(text).compactMap { l -> String? in
            let t = l.split(whereSeparator: { $0 == " " || $0 == "\t" })
            return t.count >= 2 && t[0] == "nameserver" ? String(t[1]) : nil
        }
        let remote = servers.filter { !isLocalAddress($0) }
        guard !remote.isEmpty else { return [] }
        let d = domain.lowercased()
        if let m = domainMatches(d, securityDomains + securityVendorSites + highValueDomains) {
            return ["sends DNS for \(m) to \(remote.joined(separator: ", "))"]
        }
        if !d.contains("."), !["local", "localhost", "test", "internal", "lan", "home", "corp", "intranet"].contains(d) {
            return ["sends every .\(d) lookup to \(remote.joined(separator: ", "))"]
        }
        return []
    }

    static let sshdPatterns: [(String, String)] = [
        (#"^AuthorizedKeysCommand\s+(?!none\b)\S"#, "gets login keys from a program"),
        (#"^AuthorizedKeysFile\s+(?!.*\.ssh/authorized_keys)"#, "reads login keys from an unusual file"),
        (#"^PermitRootLogin\s+yes\b"#, "allows root to log in over SSH"),
        (#"^PermitEmptyPasswords\s+yes\b"#, "allows empty passwords over SSH"),
        (#"^PermitUserEnvironment\s+yes\b"#, "lets SSH logins set environment variables (DYLD_*)"),
    ]

    static func sshdReason(_ line: String) -> String? {
        for (p, why) in sshdPatterns where RegexCache.shared.matches(p, line) { return why }
        return nil
    }

    // MARK: shells (fish, oh-my-zsh custom, logout files)

    public static func extraShellFiles(home: String) -> [String] {
        var out = [home + "/.config/fish/config.fish", home + "/.bash_logout", "/etc/zlogout", "/etc/bashrc_Apple_Terminal",
                   "/etc/zshrc_Apple_Terminal", "/opt/homebrew/etc/fish/config.fish", "/usr/local/etc/fish/config.fish",
                   home + "/.config/fish/functions/fish_prompt.fish", home + "/.config/fish/functions/fish_greeting.fish"]
        for d in [home + "/.config/fish/conf.d", "/opt/homebrew/etc/fish/conf.d", "/usr/local/etc/fish/conf.d",
                  "/opt/homebrew/share/fish/vendor_conf.d", "/usr/local/share/fish/vendor_conf.d"] {
            out += entries(d).filter { $0.hasSuffix(".fish") }
        }
        out += entries(home + "/.oh-my-zsh/custom").filter { $0.hasSuffix(".zsh") }
        return out
    }

    static func extraShellRecords(home: String) -> [PersistenceRecord] {
        extraShellFiles(home: home).compactMap { p in
            guard let s = try? String(contentsOfFile: p, encoding: .utf8) else { return nil }
            let bad = suspiciousShellLines(s)
            var attrs: [String: String] = ["lines": String(s.components(separatedBy: "\n").count)]
            if !bad.isEmpty { attrs["suspiciousLines"] = bad.joined(separator: "\n") }
            return record(.shellRC, label: PathUtil.basename(p), location: p, collector: "shellExtra", attrs: attrs,
                          fingerprint: Hashing.sha256(s))
        }
    }

    // MARK: plug-ins loaded by system processes

    /// (folder, extension, kind) for bundles that Spotlight, Quick Look, the screen saver, the Dock, coreaudiod and
    /// friends load into their own process.
    static func pluginFolders(home: String) -> [(String, String, String)] {
        var out: [(String, String, String)] = []
        for base in ["/Library", home + "/Library"] {
            out += [(base + "/Spotlight", "mdimporter", "Spotlight importer"), (base + "/QuickLook", "qlgenerator", "Quick Look generator"),
                    (base + "/Screen Savers", "saver", "screen saver"), (base + "/ColorPickers", "colorPicker", "colour picker"),
                    (base + "/Input Methods", "app", "input method"), (base + "/PreferencePanes", "prefPane", "preference pane"),
                    (base + "/Internet Plug-Ins", "plugin", "internet plug-in"), (base + "/Contextual Menu Items", "plugin", "contextual menu item")]
        }
        out += [("/Library/Audio/Plug-Ins/HAL", "driver", "audio driver"), ("/Library/Audio/Plug-Ins/HAL", "plugin", "audio driver")]
        for apps in ["/Applications", home + "/Applications"] {
            for app in entries(apps) where app.hasSuffix(".app") {
                out.append((app + "/Contents/PlugIns", "docktileplugin", "Dock tile plug-in"))
            }
        }
        return out
    }

    static func pluginRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for (dir, ext, what) in pluginFolders(home: home) {
            for b in entries(dir) where (b as NSString).pathExtension.lowercased() == ext.lowercased() {
                var attrs = ["class": "plugin", "pluginType": what]
                if PathUtil.basename(b).hasPrefix(".") { attrs["hidden"] = "1" }
                out.append(record(.other, label: "\(what): \(PathUtil.basename(b))", location: b, target: b, collector: "plugins",
                                  attrs: attrs, fingerprint: bundleFingerprint(b)))
            }
        }
        return out
    }

    /// Info.plist + main executable size/mtime (cheap; a swapped binary changes it).
    static func bundleFingerprint(_ b: String) -> String {
        let info = b + "/Contents/Info.plist"
        var parts = [b]
        if let d = FileManager.default.contents(atPath: info) {
            parts.append(Hashing.sha256(d))
            if let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any], let exe = o["CFBundleExecutable"] as? String {
                var st = stat()
                if lstat(b + "/Contents/MacOS/" + exe, &st) == 0 { parts.append("\(st.st_size):\(st.st_mtimespec.tv_sec)") }
            }
        }
        return Hashing.sha256(parts.joined(separator: "|"))
    }

    static func kextRecords() -> [PersistenceRecord] {
        entries("/Library/Extensions").filter { $0.hasSuffix(".kext") }.map { k in
            var attrs = ["class": "kext"]
            if let id = bundleID(atAppPath: k) { attrs["bundleID"] = id }
            return record(.other, label: "Kernel extension: \(PathUtil.basename(k))", location: k, target: k, collector: "kext",
                          attrs: attrs, fingerprint: bundleFingerprint(k))
        }
    }

    // MARK: Folder Actions, emond, re-opened apps, LaunchServices environment

    static func folderActionRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let disp = home + "/Library/Preferences/com.apple.FolderActionsDispatcher.plist"
        if let d = FileManager.default.contents(atPath: disp) {
            let o = (try? PropertyListSerialization.propertyList(from: d, format: nil)) as? [String: Any]
            let enabled = (o?["folderActionsEnabled"] as? Bool) == true
            out.append(record(.other, label: "Folder Actions", location: disp, collector: "folderActions",
                              attrs: ["class": "folderActions", "enabled": enabled ? "1" : "0"], fingerprint: Hashing.sha256(d)))
        }
        for dir in [home + "/Library/Scripts/Folder Action Scripts", "/Library/Scripts/Folder Action Scripts"] {
            for s in entries(dir) {
                out.append(record(.other, label: "Folder Action script: \(PathUtil.basename(s))", location: s, target: s,
                                  collector: "folderActions", attrs: ["class": "folderActionScript", "scope": dir.hasPrefix("/Library") ? "system" : "user"],
                                  fingerprint: Hashing.fileHash(s) ?? ""))
            }
        }
        return out
    }

    static func emondRecords() -> [PersistenceRecord] {
        (entries("/etc/emond.d/rules") + entries("/private/var/db/emondClients")).filter { !isDir($0) }.map { p in
            record(.other, label: "emond: \(PathUtil.basename(p))", location: p, target: p, collector: "emond",
                   attrs: ["class": "emond"], fingerprint: Hashing.fileHash(p) ?? "")
        }
    }

    /// Apps macOS re-opens at login (TALAppsToRelaunchAtLogin). Normal apps churn constantly, so only apps in a
    /// temporary, hidden or shared folder become records (known-bad only).
    static func relaunchRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for p in entries(home + "/Library/Preferences/ByHost") where PathUtil.basename(p).hasPrefix("com.apple.loginwindow.") && p.hasSuffix(".plist") {
            guard let d = FileManager.default.contents(atPath: p),
                  let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any],
                  let apps = o["TALAppsToRelaunchAtLogin"] as? [[String: Any]] else { continue }
            out += relaunchRecords(apps: apps, plist: p)
        }
        return out
    }

    public static func relaunchRecords(apps: [[String: Any]], plist: String) -> [PersistenceRecord] {
        apps.compactMap { a in
            guard let path = a["Path"] as? String, path.hasPrefix("/") else { return nil }
            let c = PathClass.classify(path)
            guard c.isSuspiciousLocation else { return nil }
            return record(.other, label: "Re-opened at login: \(PathUtil.basename(path))", location: plist + "#" + path, target: path,
                          collector: "relaunch", attrs: ["class": "relaunch", "bundleID": a["BundleID"] as? String ?? "", "where": c.rawValue])
        }
    }

    /// Apps whose Info.plist LSEnvironment sets DYLD_* (LaunchServices injects it into the app at every launch),
    /// plus the legacy ~/.MacOSX/environment.plist. Only offending entries become records.
    static func lsEnvironmentRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for apps in ["/Applications", "/Applications/Utilities", home + "/Applications"] {
            for app in entries(apps) where app.hasSuffix(".app") {
                guard let d = FileManager.default.contents(atPath: app + "/Contents/Info.plist"),
                      let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any],
                      let env = o["LSEnvironment"] as? [String: Any] else { continue }
                if let r = lsEnvironmentRecord(env: env, location: app + "/Contents/Info.plist", label: PathUtil.basename(app)) { out.append(r) }
            }
        }
        let legacy = home + "/.MacOSX/environment.plist"
        if let d = FileManager.default.contents(atPath: legacy),
           let env = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any],
           let r = lsEnvironmentRecord(env: env, location: legacy, label: "login environment") { out.append(r) }
        return out
    }

    public static func lsEnvironmentRecord(env: [String: Any], location: String, label: String) -> PersistenceRecord? {
        let dyld = env.filter { $0.key.uppercased().hasPrefix("DYLD_") }.mapValues { "\($0)" }
        guard !dyld.isEmpty else { return nil }
        var r = record(.other, label: "\(label) sets \(dyld.keys.sorted().joined(separator: ", "))", location: location,
                       target: dyld.values.sorted().first, collector: "lsenv", attrs: ["class": "lsenv"])
        r.environment = dyld
        return r
    }

    /// Hidden (dot-named) bundles in the authorization / directory-services / StartupItems folders, which the older
    /// enumerator skipped. SecurityAgent loads plug-ins by name, so a ".name.bundle" works just as well.
    static func hiddenAuthItems() -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for d in ["/Library/Security/SecurityAgentPlugins", "/Library/DirectoryServices/PlugIns", "/Library/StartupItems"] {
            for b in entries(d) where PathUtil.basename(b).hasPrefix(".") && PathUtil.basename(b) != ".DS_Store" {
                out.append(record(.other, label: PathUtil.basename(b), location: b, target: b, collector: "hiddenItems",
                                  attrs: ["class": PathUtil.basename(d), "hidden": "1"]))
            }
        }
        return out
    }

    // MARK: browsers (P02): unpacked + External Extensions + policy force-installs + Safari inventory

    static func chromiumUnpackedAndExternal(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let appSupport = home + "/Library/Application Support"
        for (browser, rel) in chromiumVendors {
            let root = appSupport + "/" + rel
            for profile in entries(root).filter(isDir) {
                let name = PathUtil.basename(profile)
                guard name == "Default" || name.hasPrefix("Profile ") || name == "Guest Profile" else { continue }
                out += chromiumUnpacked(profileDir: profile, browser: browser, home: home)
            }
            out += externalExtensions(dir: root + "/External Extensions", browser: browser)
        }
        for (browser, dir) in [("Chrome", "/Library/Application Support/Google/Chrome/External Extensions"),
                               ("Brave", "/Library/Application Support/BraveSoftware/Brave-Browser/External Extensions"),
                               ("Edge", "/Library/Application Support/Microsoft/Edge/External Extensions"),
                               ("Chromium", "/Library/Application Support/Chromium/External Extensions")] {
            out += externalExtensions(dir: dir, browser: browser)
        }
        return out
    }

    /// Entries in (Secure) Preferences → extensions.settings with location 4 (unpacked) and an absolute path.
    public static func chromiumUnpacked(profileDir: String, browser: String, home: String) -> [PersistenceRecord] {
        var settings: [String: [String: Any]] = [:]
        for prefName in ["Secure Preferences", "Preferences"] {
            guard let d = FileManager.default.contents(atPath: profileDir + "/" + prefName),
                  let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
                  let ext = j["extensions"] as? [String: Any], let s = ext["settings"] as? [String: Any] else { continue }
            for (k, v) in s { if settings[k] == nil, let vv = v as? [String: Any] { settings[k] = vv } }
        }
        let profileName = PathUtil.basename(profileDir)
        var out: [PersistenceRecord] = []
        for (id, s) in settings.sorted(by: { $0.key < $1.key }) {
            guard (s["location"] as? Int) == 4, let path = s["path"] as? String, path.hasPrefix("/") else { continue }
            var perms: [String] = []
            var name = (s["manifest"] as? [String: Any])?["name"] as? String ?? id
            if let md = FileManager.default.contents(atPath: path + "/manifest.json"),
               let m = try? JSONSerialization.jsonObject(with: md) as? [String: Any] {
                name = resolveMessage(m["name"] as? String ?? name, extDir: path, defaultLocale: m["default_locale"] as? String)
                perms += (m["permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
                perms += (m["host_permissions"] as? [Any])?.compactMap { $0 as? String } ?? []
                for c in (m["content_scripts"] as? [[String: Any]]) ?? [] { perms += (c["matches"] as? [String]) ?? [] }
            }
            var attrs = ["browser": browser, "profile": profileName, "extensionID": id, "installLocation": "4", "unpacked": "1",
                         "fromWebstore": "0", "path": path, "permissions": Array(Set(perms)).sorted().joined(separator: ",")]
            if isDeveloperUnpacked(path, home: home) { attrs["devUnpacked"] = "1" }
            out.append(record(.browserExtension, label: "\(browser) (\(profileName)): \(name) (unpacked)", location: path,
                              collector: "chromiumExtra", attrs: attrs))
        }
        return out
    }

    /// An unpacked extension a developer loaded from their own project folder (not hidden, temp, shared, Downloads
    /// or Library, where Adload-style droppers put theirs).
    public static func isDeveloperUnpacked(_ path: String, home: String) -> Bool {
        guard path.hasPrefix(home + "/") else { return false }
        switch PathClass.classify(path) {
        case .home, .developer: return true
        default: return false
        }
    }

    public static func externalExtensions(dir: String, browser: String) -> [PersistenceRecord] {
        entries(dir).filter { $0.hasSuffix(".json") }.compactMap { f in
            guard let d = FileManager.default.contents(atPath: f) else { return nil }
            let j = (try? JSONSerialization.jsonObject(with: d)) as? [String: Any] ?? [:]
            let id = ((PathUtil.basename(f)) as NSString).deletingPathExtension
            let update = j["external_update_url"] as? String ?? ""
            let crx = j["external_crx"] as? String
            let store = crx == nil && (update.hasPrefix("https://clients2.google.com/") || update.hasPrefix("https://edge.microsoft.com/"))
            var attrs = ["browser": browser, "extensionID": id, "installLocation": "external", "fromWebstore": store ? "1" : "0"]
            if !update.isEmpty { attrs["updateURL"] = update }
            if let crx { attrs["crx"] = crx }
            return record(.browserExtension, label: "\(browser): external extension \(id)", location: f, target: crx,
                          collector: "chromiumExtra", attrs: attrs, fingerprint: Hashing.sha256(d))
        }
    }

    /// ExtensionInstallForcelist written to plain (non-MDM) preference files.
    static func browserPolicyRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        for (browser, domain) in [("Chrome", "com.google.Chrome"), ("Brave", "com.brave.Browser"), ("Edge", "com.microsoft.Edge"),
                                  ("Chromium", "org.chromium.Chromium")] {
            for p in ["/Library/Preferences/\(domain).plist", home + "/Library/Preferences/\(domain).plist"] {
                guard let d = FileManager.default.contents(atPath: p),
                      let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { continue }
                out += forceInstallRecords(policy: o, plist: p, browser: browser)
            }
        }
        return out
    }

    public static func forceInstallRecords(policy o: [String: Any], plist: String, browser: String) -> [PersistenceRecord] {
        ((o["ExtensionInstallForcelist"] as? [Any]) ?? []).compactMap { $0 as? String }.map { entry in
            let id = String(entry.split(separator: ";").first ?? Substring(entry))
            return record(.browserExtension, label: "\(browser): force-installed extension \(id)", location: plist + "#" + id,
                          collector: "browserPolicy", attrs: ["browser": browser, "extensionID": id, "installLocation": "5", "policyEntry": entry])
        }
    }

    /// Inventory only: Safari only runs extensions shipped inside signed apps, so these are listed, not alerted.
    static func safariExtensionRecords(home: String) -> [PersistenceRecord] {
        var out: [PersistenceRecord] = []
        let base = home + "/Library/Containers/com.apple.Safari/Data/Library/Safari"
        for (kind, rel) in [("app extension", "/AppExtensions/Extensions.plist"), ("web extension", "/WebExtensions/Extensions.plist")] {
            guard let d = FileManager.default.contents(atPath: base + rel),
                  let o = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { continue }
            out += safariRecords(plist: o, path: base + rel, kind: kind)
        }
        return out
    }

    public static func safariRecords(plist o: [String: Any], path: String, kind: String) -> [PersistenceRecord] {
        o.keys.sorted().map { key in
            let v = o[key] as? [String: Any] ?? [:]
            var attrs = ["browser": "Safari", "extensionID": key, "safariKind": kind, "enabled": (v["Enabled"] as? Bool) == true ? "1" : "0"]
            if let open = key.range(of: " ("), key.hasSuffix(")") { attrs["teamID"] = String(key[open.upperBound...].dropLast()) }
            return record(.browserExtension, label: "Safari: \(key)", location: path + "#" + key, collector: "safari", attrs: attrs)
        }
    }
}

// MARK: assessment

extension PersistenceAssessor {
    /// RamPart's own data folder in any home (it never launches programs from there).
    static func isInRampartDataFolder(_ path: String) -> Bool {
        let l = path.lowercased()
        return l.contains("/library/application support/rampart/")
    }

    /// Findings for the o10 record classes. `nil` means "not an o10 class, use the normal rules".
    func assessO10(_ r: PersistenceRecord, previous: PersistenceRecord?) -> [PersistenceFinding]? {
        let it = r.item
        let cls = r.attributes["class"] ?? ""
        switch cls {
        case "sysconfig":
            let now = Set((r.attributes["riskyLines"] ?? "").components(separatedBy: "\n").filter { !$0.isEmpty })
            let before = Set((previous?.attributes["riskyLines"] ?? "").components(separatedBy: "\n").filter { !$0.isEmpty })
            guard let first = now.subtracting(before).sorted().first else { return [] }
            let area = r.attributes["area"] ?? ""
            let rule = ["sudoers": "R16", "pam": "R16", "hosts": "RP1", "resolver": "RP1", "sshd": "RP2", "sshrc": "RP2"][area] ?? "R16"
            return [PersistenceFinding(ruleID: rule, detail: "\(it.location) changed: \(String(first.prefix(240)))", targetPath: nil)]
        case "plugin", "kext":
            let t = it.target ?? it.location
            let tc = trust(t)
            var why: [String] = []
            if tc.isUntrusted { why.append("signature: \(tc.rawValue)") }
            if r.attributes["hidden"] == "1" { why.append("hidden name") }
            if getxattr(t, "com.apple.quarantine", nil, 0, 0, 0) >= 0 && tc.isUntrusted { why.append("downloaded and never approved") }
            guard !why.isEmpty, tc != .apple, tc != .notarized, tc != .appStore else { return [] }
            let what = cls == "kext" ? "Kernel extension" : (r.attributes["pluginType"] ?? "Plug-in").capitalizedFirst
            return [PersistenceFinding(ruleID: "RP3", detail: "\(what) \(PathUtil.basename(t)) was added [\(why.joined(separator: ", "))]; macOS loads it into a system process.", targetPath: t)]
        case "folderActions":
            guard r.attributes["enabled"] == "1" else { return [] }
            return [PersistenceFinding(ruleID: "RP4", detail: "Folder Actions are on and their configuration changed (\(it.location)).", targetPath: nil)]
        case "folderActionScript":
            guard r.attributes["scope"] == "user" || previous == nil else { return [] }
            return [PersistenceFinding(ruleID: "RP4", detail: "Folder Action script \(PathUtil.basename(it.location)) was added.", targetPath: it.target)]
        case "emond":
            return [PersistenceFinding(ruleID: "R11", detail: "Event Monitor (emond) rule or client \(PathUtil.basename(it.location)) was added or changed.", targetPath: it.target)]
        case "relaunch":
            return [PersistenceFinding(ruleID: "RP6", detail: "macOS will re-open \(it.target ?? "?") at login, from a \(r.attributes["where"] ?? "suspicious") folder.", targetPath: it.target)]
        case "lsenv":
            return [PersistenceFinding(ruleID: "RP5", detail: "\(it.label) via \(it.location): every launch loads \(r.environment.values.sorted().joined(separator: ", ")).", targetPath: it.target)]
        default:
            return nil
        }
    }
}

private extension String {
    var capitalizedFirst: String { prefix(1).uppercased() + dropFirst() }
}
