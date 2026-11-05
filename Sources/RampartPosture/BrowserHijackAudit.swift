import Foundation

/// One browser setting that controls where searches or new windows go.
public struct BrowserSettingFinding: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case searchEngine, homepage, startupPage, policySearchEngine, policyHomepage, policyStartupPage, policyForcedExtension
    }
    public enum Verdict: String, Codable, Sendable, Comparable {
        case ok, unrecognized, suspicious
        public static func < (a: Verdict, b: Verdict) -> Bool {
            let o: [Verdict] = [.ok, .unrecognized, .suspicious]; return o.firstIndex(of: a)! < o.firstIndex(of: b)!
        }
    }
    public var browser: String
    public var profile: String
    public var source: String       // file the value came from
    public var kind: Kind
    public var value: String
    public var verdict: Verdict
    public var reason: String
    public init(browser: String, profile: String, source: String, kind: Kind, value: String, verdict: Verdict, reason: String) {
        self.browser = browser; self.profile = profile; self.source = source; self.kind = kind
        self.value = value; self.verdict = verdict; self.reason = reason
    }
}

public struct BrowserAuditResult: Codable, Sendable {
    public var findings: [BrowserSettingFinding]
    public var browsersChecked: [String]
    /// browser -> why it couldn't be read (e.g. "Needs Full Disk Access").
    public var unreadable: [String: String]
    public var flagged: [BrowserSettingFinding] { findings.filter { $0.verdict != .ok } }
    public var suspicious: [BrowserSettingFinding] { findings.filter { $0.verdict == .suspicious } }
}

/// Audits default search engine, homepage and startup pages of Chromium browsers, Firefox and Safari,
/// plus browser policies (a common way adware pins a search engine). Read-only.
public enum BrowserHijackAudit {

    public static let chromiumBrowsers: [(name: String, root: String)] = [
        ("Chrome", "Library/Application Support/Google/Chrome"),
        ("Chrome Beta", "Library/Application Support/Google/Chrome Beta"),
        ("Chromium", "Library/Application Support/Chromium"),
        ("Brave", "Library/Application Support/BraveSoftware/Brave-Browser"),
        ("Edge", "Library/Application Support/Microsoft Edge"),
        ("Arc", "Library/Application Support/Arc/User Data"),
        ("Vivaldi", "Library/Application Support/Vivaldi"),
        ("Opera", "Library/Application Support/com.operasoftware.Opera"),
    ]

    public static let policyDomains: [(browser: String, domain: String)] = [
        ("Chrome", "com.google.Chrome"), ("Edge", "com.microsoft.Edge"), ("Brave", "com.brave.Browser"),
    ]

    // MARK: URL classification (pure)

    static let knownSearchHosts = ["google.", "bing.com", "duckduckgo.com", "search.yahoo.", "yahoo.co.jp", "ecosia.org",
                                   "search.brave.com", "startpage.com", "qwant.com", "kagi.com", "baidu.com", "yandex.",
                                   "naver.com", "perplexity.ai", "chatgpt.com", "you.com", "seznam.cz", "sogou.com",
                                   "mojeek.com", "swisscows.com", "ya.ru"]

    /// Substrings seen in browser-hijacker search redirectors (Adload, Bundlore, Pirrit, Search Baron and friends).
    static let hijackerMarkers = ["/yhs/", "yhs-", "hspart=", "searchbaron", "search-operator", "searchmine", "safefinder",
                                  "search.myway", "mysearch.", "searchalgo", "chill-tab", "searchy.", "searchmarquis",
                                  "search-checker", "searchitnow", "searchsafer", "search.tapufind", "nearbyme",
                                  "akamaihd.net/search", "search.anysearch", "search.heasyspeedtest", "fastsearch.",
                                  "searchtrendz", "search.handy-tab", "mybrowser-search", "search-redirect", "redirect.php?q="]

    static func host(_ s: String) -> String? {
        let withScheme = s.contains("://") ? s : "https://" + s
        return URLComponents(string: withScheme.replacingOccurrences(of: "{searchTerms}", with: "x"))?.host?.lowercased()
    }

    public static func classifySearchURL(_ url: String) -> (BrowserSettingFinding.Verdict, String) {
        let l = url.lowercased()
        if let m = hijackerMarkers.first(where: { l.contains($0) }) {
            return (.suspicious, "This search address matches a known search hijacker pattern (\(m)).")
        }
        guard let h = host(url) else { return (.unrecognized, "The search address couldn't be read.") }
        if knownSearchHosts.contains(where: { h == $0 || h.hasPrefix($0) || h.contains("." + $0) || ($0.hasSuffix(".") && h.contains($0)) }) {
            return (.ok, "A well-known search engine.")
        }
        return (.unrecognized, "Searches go to \(h), which isn't a well-known search engine.")
    }

    public static func classifyPage(_ url: String) -> (BrowserSettingFinding.Verdict, String) {
        let l = url.lowercased()
        if let m = hijackerMarkers.first(where: { l.contains($0) }) {
            return (.suspicious, "This page matches a known browser hijacker pattern (\(m)).")
        }
        return (.ok, "")
    }

    // MARK: Chromium (pure)

    public static func chromiumSettings(preferences data: Data, browser: String, profile: String, source: String) -> [BrowserSettingFinding] {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [] }
        var out: [BrowserSettingFinding] = []
        if let dsp = root["default_search_provider_data"] as? [String: Any],
           let t = dsp["template_url_data"] as? [String: Any], let url = t["url"] as? String, !url.isEmpty {
            let name = (t["short_name"] as? String) ?? (t["keyword"] as? String) ?? ""
            let (v, r) = classifySearchURL(url)
            out.append(.init(browser: browser, profile: profile, source: source, kind: .searchEngine,
                             value: name.isEmpty ? url : "\(name) (\(url))", verdict: v, reason: r))
        }
        let newTab = (root["homepage_is_newtabpage"] as? Bool) ?? true
        if let hp = root["homepage"] as? String, !hp.isEmpty, !newTab {
            let (v, r) = classifyPage(hp)
            out.append(.init(browser: browser, profile: profile, source: source, kind: .homepage, value: hp, verdict: v, reason: r))
        }
        if let session = root["session"] as? [String: Any], (session["restore_on_startup"] as? Int) == 4,
           let urls = session["startup_urls"] as? [String] {
            for u in urls {
                let (v, r) = classifyPage(u)
                out.append(.init(browser: browser, profile: profile, source: source, kind: .startupPage, value: u, verdict: v, reason: r))
            }
        }
        return out
    }

    // MARK: Browser policies (pure)

    public static func policySettings(_ plist: [String: Any], browser: String, source: String, managedByOrganization: Bool) -> [BrowserSettingFinding] {
        var out: [BrowserSettingFinding] = []
        let who = managedByOrganization ? "Set by a configuration profile (organization or installed profile)."
                                        : "Forced by a policy file any admin installer can write; adware uses this."
        func floor(_ v: BrowserSettingFinding.Verdict) -> BrowserSettingFinding.Verdict { managedByOrganization ? v : max(v, .unrecognized) }
        if let url = plist["DefaultSearchProviderSearchURL"] as? String {
            let (v, r) = classifySearchURL(url)
            out.append(.init(browser: browser, profile: "policy", source: source, kind: .policySearchEngine, value: url,
                             verdict: floor(v), reason: v == .ok ? who : r))
        }
        if let hp = plist["HomepageLocation"] as? String {
            let (v, r) = classifyPage(hp)
            out.append(.init(browser: browser, profile: "policy", source: source, kind: .policyHomepage, value: hp,
                             verdict: floor(v), reason: v == .ok ? who : r))
        }
        for u in plist["RestoreOnStartupURLs"] as? [String] ?? [] {
            let (v, r) = classifyPage(u)
            out.append(.init(browser: browser, profile: "policy", source: source, kind: .policyStartupPage, value: u,
                             verdict: floor(v), reason: v == .ok ? who : r))
        }
        for e in plist["ExtensionInstallForcelist"] as? [String] ?? [] {
            out.append(.init(browser: browser, profile: "policy", source: source, kind: .policyForcedExtension, value: e,
                             verdict: floor(.ok), reason: "Extension installed by policy. " + who))
        }
        return out
    }

    // MARK: Firefox (pure)

    /// Profile folders listed in profiles.ini (relative paths resolved against the Firefox root).
    public static func firefoxProfilePaths(profilesINI: String, firefoxRoot: String) -> [String] {
        var out: [String] = []
        var path: String?, relative = true
        func flush() {
            if let p = path { out.append(relative ? firefoxRoot + "/" + p : p) }
            path = nil; relative = true
        }
        for raw in profilesINI.split(whereSeparator: \.isNewline) {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("[") { flush(); continue }
            if line.hasPrefix("Path=") { path = String(line.dropFirst(5)) }
            if line.hasPrefix("IsRelative=") { relative = line.hasSuffix("1") }
        }
        flush()
        return Array(NSOrderedSet(array: out)) as? [String] ?? out
    }

    /// `user_pref("name", value);` lines → [name: unquoted value].
    public static func firefoxPrefs(_ prefsJS: String) -> [String: String] {
        var out: [String: String] = [:]
        guard let re = try? NSRegularExpression(pattern: #"^\s*user_pref\(\s*"([^"]+)"\s*,\s*(.*?)\s*\)\s*;"#, options: [.anchorsMatchLines]) else { return out }
        let ns = prefsJS as NSString
        for m in re.matches(in: prefsJS, range: NSRange(location: 0, length: ns.length)) {
            var v = ns.substring(with: m.range(at: 2))
            if v.hasPrefix("\"") && v.hasSuffix("\"") && v.count >= 2 {
                v = String(v.dropFirst().dropLast()).replacingOccurrences(of: "\\\"", with: "\"").replacingOccurrences(of: "\\\\", with: "\\")
            }
            out[ns.substring(with: m.range(at: 1))] = v
        }
        return out
    }

    public static func firefoxPrefSettings(_ prefs: [String: String], profile: String, source: String) -> [BrowserSettingFinding] {
        var out: [BrowserSettingFinding] = []
        if let hp = prefs["browser.startup.homepage"], !hp.isEmpty, !hp.hasPrefix("about:"), !hp.hasPrefix("chrome://") {
            for u in hp.split(separator: "|").map(String.init) {
                let (v, r) = classifyPage(u)
                out.append(.init(browser: "Firefox", profile: profile, source: source, kind: .homepage, value: u, verdict: v, reason: r))
            }
        }
        if let k = prefs["keyword.URL"], !k.isEmpty {   // legacy hijack vector
            let (v, r) = classifySearchURL(k)
            out.append(.init(browser: "Firefox", profile: profile, source: source, kind: .searchEngine, value: k, verdict: v, reason: r))
        }
        return out
    }

    /// Decodes Mozilla's `mozLz40\0` container (8-byte magic, 4-byte LE size, raw LZ4 block).
    public static func decodeMozLz4(_ data: Data) -> Data? {
        let bytes = [UInt8](data)
        let magic: [UInt8] = Array("mozLz40".utf8) + [0]
        guard bytes.count >= 12, Array(bytes[0..<8]) == magic else { return nil }
        let size = Int(bytes[8]) | Int(bytes[9]) << 8 | Int(bytes[10]) << 16 | Int(bytes[11]) << 24
        guard size <= 64 * 1024 * 1024 else { return nil }
        return lz4BlockDecode(Array(bytes[12...]), expectedSize: size)
    }

    /// Minimal LZ4 block decoder (bounds-checked).
    public static func lz4BlockDecode(_ src: [UInt8], expectedSize: Int) -> Data? {
        var out = [UInt8](); out.reserveCapacity(expectedSize)
        var i = 0
        while i < src.count {
            let token = Int(src[i]); i += 1
            var lit = token >> 4
            if lit == 15 {
                while true { guard i < src.count else { return nil }; let b = Int(src[i]); i += 1; lit += b; if b != 255 { break } }
            }
            guard i + lit <= src.count else { return nil }
            out.append(contentsOf: src[i..<(i + lit)]); i += lit
            if i >= src.count { break }   // last sequence has literals only
            guard i + 1 < src.count else { return nil }
            let offset = Int(src[i]) | Int(src[i + 1]) << 8; i += 2
            guard offset > 0, offset <= out.count else { return nil }
            var mlen = token & 15
            if mlen == 15 {
                while true { guard i < src.count else { return nil }; let b = Int(src[i]); i += 1; mlen += b; if b != 255 { break } }
            }
            mlen += 4
            guard out.count + mlen <= max(expectedSize, out.count + mlen) else { return nil }
            let start = out.count - offset
            for k in 0..<mlen { out.append(out[start + k]) }
            if out.count > 64 * 1024 * 1024 { return nil }
        }
        return Data(out)
    }

    /// Default engine from Firefox's decoded search.json. Returns nil when the built-in default is in use.
    public static func firefoxSearchSettings(searchJSON data: Data, profile: String, source: String) -> [BrowserSettingFinding] {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return [] }
        let engines = root["engines"] as? [[String: Any]] ?? []
        let meta = root["metaData"] as? [String: Any] ?? [:]
        let defaultID = meta["defaultEngineId"] as? String
        let currentName = meta["current"] as? String
        guard let engine = engines.first(where: { e in
            (defaultID != nil && (e["id"] as? String) == defaultID) || (currentName != nil && (e["_name"] as? String) == currentName)
        }) else { return [] }
        let name = (engine["_name"] as? String) ?? "?"
        let loadPath = (engine["_loadPath"] as? String) ?? ""
        let urls = engine["_urls"] as? [[String: Any]] ?? []
        let template = urls.first(where: { ($0["type"] as? String).map { $0 == "text/html" } ?? true })?["template"] as? String
        if loadPath.hasPrefix("[app]") && template == nil {
            return [.init(browser: "Firefox", profile: profile, source: source, kind: .searchEngine, value: name, verdict: .ok, reason: "Built-in search engine.")]
        }
        let (v, r) = template.map(classifySearchURL) ?? (.unrecognized, "Search engine added by an add-on or user.")
        return [.init(browser: "Firefox", profile: profile, source: source, kind: .searchEngine,
                      value: template.map { "\(name) (\($0))" } ?? name, verdict: v, reason: r)]
    }

    public static func firefoxPolicySettings(policiesJSON data: Data, source: String) -> [BrowserSettingFinding] {
        guard let root = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any],
              let p = root["policies"] as? [String: Any] else { return [] }
        var out: [BrowserSettingFinding] = []
        let why = "Set by Firefox's policies.json, which hijackers sometimes write."
        if let hp = p["Homepage"] as? [String: Any], let u = hp["URL"] as? String {
            let (v, r) = classifyPage(u)
            out.append(.init(browser: "Firefox", profile: "policy", source: source, kind: .policyHomepage, value: u,
                             verdict: max(v, .unrecognized), reason: v == .ok ? why : r))
        }
        if let se = p["SearchEngines"] as? [String: Any] {
            for add in se["Add"] as? [[String: Any]] ?? [] {
                let u = (add["URLTemplate"] as? String) ?? ""
                let (v, r) = classifySearchURL(u)
                out.append(.init(browser: "Firefox", profile: "policy", source: source, kind: .policySearchEngine,
                                 value: "\((add["Name"] as? String) ?? "?") (\(u))", verdict: max(v, .unrecognized), reason: v == .ok ? why : r))
            }
            if let d = se["Default"] as? String {
                out.append(.init(browser: "Firefox", profile: "policy", source: source, kind: .policySearchEngine,
                                 value: "Default: \(d)", verdict: .unrecognized, reason: why))
            }
        }
        if let ext = p["Extensions"] as? [String: Any], let inst = ext["Install"] as? [String] {
            for e in inst {
                out.append(.init(browser: "Firefox", profile: "policy", source: source, kind: .policyForcedExtension,
                                 value: e, verdict: .unrecognized, reason: why))
            }
        }
        return out
    }

    // MARK: Safari (pure)

    public static func safariSettings(_ plist: [String: Any], source: String) -> [BrowserSettingFinding] {
        var out: [BrowserSettingFinding] = []
        if let hp = plist["HomePage"] as? String, !hp.isEmpty {
            let (v, r) = classifyPage(hp)
            out.append(.init(browser: "Safari", profile: "Default", source: source, kind: .homepage, value: hp, verdict: v, reason: r))
        }
        if let se = (plist["SearchProviderShortName"] as? String) ?? (plist["SearchProviderIdentifier"] as? String) {
            // Safari only allows Apple-approved engines; hijacks come through extensions or profiles.
            out.append(.init(browser: "Safari", profile: "Default", source: source, kind: .searchEngine, value: se,
                             verdict: .ok, reason: "Safari only allows built-in search engines."))
        }
        return out
    }

    // MARK: Live audit (I/O)

    public static func audit(home: String = FileManager.default.homeDirectoryForCurrentUser.path,
                             userName: String = NSUserName(), systemRoot: String = "") -> BrowserAuditResult {
        let fm = FileManager.default
        var findings: [BrowserSettingFinding] = [], checked: [String] = [], unreadable: [String: String] = [:]

        for (name, rel) in chromiumBrowsers {
            let root = home + "/" + rel
            guard let entries = try? fm.contentsOfDirectory(atPath: root) else { continue }
            var any = false
            for dir in entries.sorted() where dir == "Default" || dir.hasPrefix("Profile ") {
                let prefs = root + "/" + dir + "/Preferences"
                guard let data = fm.contents(atPath: prefs) else { continue }
                any = true
                findings += chromiumSettings(preferences: data, browser: name, profile: dir, source: prefs)
            }
            if any { checked.append(name) }
        }

        for (browser, domain) in policyDomains {
            let candidates = [(systemRoot + "/Library/Managed Preferences/\(domain).plist", true),
                              (systemRoot + "/Library/Managed Preferences/\(userName)/\(domain).plist", true),
                              (systemRoot + "/Library/Preferences/\(domain).plist", false)]
            for (path, managed) in candidates {
                guard let d = PostureParsers.plistDictionary(fm.contents(atPath: path)) else { continue }
                findings += policySettings(d, browser: browser, source: path, managedByOrganization: managed)
            }
        }

        let ffRoot = home + "/Library/Application Support/Firefox"
        if let ini = fm.contents(atPath: ffRoot + "/profiles.ini").map({ String(decoding: $0, as: UTF8.self) }) {
            checked.append("Firefox")
            for p in firefoxProfilePaths(profilesINI: ini, firefoxRoot: ffRoot) {
                let profile = (p as NSString).lastPathComponent
                if let js = fm.contents(atPath: p + "/prefs.js") {
                    findings += firefoxPrefSettings(firefoxPrefs(String(decoding: js, as: UTF8.self)), profile: profile, source: p + "/prefs.js")
                }
                if let lz = fm.contents(atPath: p + "/search.json.mozlz4"), let json = decodeMozLz4(lz) {
                    findings += firefoxSearchSettings(searchJSON: json, profile: profile, source: p + "/search.json.mozlz4")
                }
            }
        }
        for app in ["/Applications/Firefox.app", home + "/Applications/Firefox.app"] {
            let pol = systemRoot + app + "/Contents/Resources/distribution/policies.json"
            if let d = fm.contents(atPath: pol) { findings += firefoxPolicySettings(policiesJSON: d, source: pol) }
        }

        let safari = home + "/Library/Containers/com.apple.Safari/Data/Library/Preferences/com.apple.Safari.plist"
        if fm.fileExists(atPath: home + "/Library/Containers/com.apple.Safari") || fm.fileExists(atPath: safari) {
            let fd = open(safari, O_RDONLY)
            if fd >= 0 {
                close(fd)
                if let d = PostureParsers.plistDictionary(fm.contents(atPath: safari)) {
                    checked.append("Safari"); findings += safariSettings(d, source: safari)
                }
            } else if errno == EPERM || errno == EACCES {
                unreadable["Safari"] = "Needs Full Disk Access"
            }
        }
        return BrowserAuditResult(findings: findings, browsersChecked: checked, unreadable: unreadable)
    }
}
