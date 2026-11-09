import Foundation
import RampartShared

// MARK: - DNS policy hook (consulted by DNSFilterServer before the blocklist answer is used)

public enum DNSPolicyDecision: Equatable, Sendable {
    /// Use the blocklist verdict as is.
    case useList
    /// Resolve normally even though a list matched (the list's category is switched off right now).
    case pass
    /// Block with this rule / source label.
    case block(rule: String, source: String)
    /// Answer with a CNAME to `target` plus the target's addresses (SafeSearch).
    case rewrite(target: String, rule: String)
}

public protocol DNSPolicy: AnyObject, Sendable {
    func decide(name: String, type: UInt16, listVerdict: DomainBlocklist.Verdict, now: Date) -> DNSPolicyDecision
}

// MARK: - Categories

/// Content-filter categories. Malware and phishing reuse the always-loaded security feeds (HaGeZi TIF, URLhaus);
/// the others download a HaGeZi category list (cached, refreshed every 12 hours) the first time they are switched on.
public enum ContentCategory: String, Codable, CaseIterable, Sendable {
    case malware, phishing, trackers, adult, gambling, social

    public var title: String {
        switch self {
        case .malware: return "Malware"
        case .phishing: return "Phishing & scams"
        case .trackers: return "Trackers & ads"
        case .adult: return "Adult content"
        case .gambling: return "Gambling"
        case .social: return "Social media"
        }
    }
    public var detail: String {
        switch self {
        case .malware: return "Sites that spread malware (URLhaus)."
        case .phishing: return "Phishing, scam and threat-intelligence domains (HaGeZi TIF)."
        case .trackers: return "Advertising and tracking domains (HaGeZi Pro). May break a few sites; allow them in Rules."
        case .adult: return "Pornography and other adult sites (HaGeZi NSFW)."
        case .gambling: return "Betting, casino and lottery sites (HaGeZi Gambling)."
        case .social: return "Facebook, Instagram, TikTok, X, Snapchat, Reddit and similar (HaGeZi Social + built-in list)."
        }
    }
    /// Sources in the main security feeds whose blocks belong to this category.
    public var securityListIDs: [String] {
        switch self {
        case .malware: return ["urlhaus", "urlhaus-official"]
        case .phishing: return ["hagezi-tif"]
        default: return []
        }
    }
    /// Downloadable list for this category (nil: covered by the security feeds).
    public var source: BlocklistUpdater.Source? {
        func hz(_ file: String, min: Int) -> BlocklistUpdater.Source {
            BlocklistUpdater.Source(id: "cat-\(rawValue)",
                                    url: URL(string: "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard/\(file)-onlydomains.txt")!,
                                    format: .plain, minimumEntries: min, refreshInterval: 12 * 3600)
        }
        switch self {
        case .malware, .phishing: return nil
        case .trackers: return hz("pro", min: 20_000)
        case .adult: return hz("nsfw", min: 5_000)
        case .gambling: return hz("gambling", min: 5_000)
        case .social: return hz("social", min: 50)
        }
    }
    /// Built-in seed so the category works before (or without) its download.
    public var seedDomains: [String] {
        switch self {
        case .social:
            return ["facebook.com", "fb.com", "fbcdn.net", "messenger.com", "instagram.com", "cdninstagram.com", "tiktok.com",
                    "tiktokcdn.com", "tiktokv.com", "musical.ly", "x.com", "twitter.com", "twimg.com", "t.co", "snapchat.com",
                    "sc-cdn.net", "reddit.com", "redd.it", "redditmedia.com", "pinterest.com", "pinimg.com", "tumblr.com",
                    "threads.net", "threads.com", "bsky.app", "linkedin.com", "discord.com", "discord.gg", "twitch.tv", "vk.com"]
        case .trackers:
            return ["doubleclick.net", "google-analytics.com", "googletagmanager.com", "googlesyndication.com",
                    "googleadservices.com", "scorecardresearch.com", "hotjar.com", "mixpanel.com", "segment.io",
                    "amplitude.com", "criteo.com", "taboola.com", "outbrain.com", "adnxs.com", "quantserve.com", "app-measurement.com"]
        default: return []
        }
    }
}

// MARK: - Schedules

/// A daily time window in local time (minutes after midnight). `end < start` wraps past midnight (22:00–07:00).
/// `weekdays` uses Calendar weekday numbers (1 = Sunday … 7 = Saturday); empty means every day. For a window that
/// wraps, the weekday is the day the window *starts*.
public struct FilterWindow: Codable, Hashable, Sendable {
    public var start: Int
    public var end: Int
    public var weekdays: [Int]
    public init(start: Int, end: Int, weekdays: [Int] = []) {
        self.start = max(0, min(1439, start)); self.end = max(0, min(1440, end)); self.weekdays = weekdays.filter { (1...7).contains($0) }
    }
    public init(_ startHM: (Int, Int), _ endHM: (Int, Int), weekdays: [Int] = []) {
        self.init(start: startHM.0 * 60 + startHM.1, end: endHM.0 * 60 + endHM.1, weekdays: weekdays)
    }

    public func contains(_ date: Date, calendar: Calendar = .current) -> Bool {
        let c = calendar.dateComponents([.hour, .minute, .weekday], from: date)
        let m = (c.hour ?? 0) * 60 + (c.minute ?? 0)
        let wd = c.weekday ?? 1
        func dayOK(_ d: Int) -> Bool { weekdays.isEmpty || weekdays.contains(d) }
        if start == end { return false }
        if start < end { return m >= start && m < end && dayOK(wd) }
        if m >= start { return dayOK(wd) }                      // evening part, started today
        if m < end { return dayOK(wd == 1 ? 7 : wd - 1) }       // morning part, started yesterday
        return false
    }

    public var label: String {
        func hm(_ v: Int) -> String { String(format: "%02d:%02d", (v / 60) % 24, v % 60) }
        let days = weekdays.isEmpty ? "every day" : weekdays.sorted().map { ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][$0 - 1] }.joined(separator: ", ")
        return "\(hm(start))–\(hm(end)), \(days)"
    }
}

public struct CategoryRule: Codable, Hashable, Sendable {
    public enum Mode: String, Codable, Sendable { case off, always, scheduled }
    public var mode: Mode
    public var windows: [FilterWindow]
    public init(mode: Mode, windows: [FilterWindow] = []) { self.mode = mode; self.windows = windows }

    public func isActive(at date: Date, calendar: Calendar = .current) -> Bool {
        switch mode {
        case .off: return false
        case .always: return true
        case .scheduled: return windows.contains { $0.contains(date, calendar: calendar) }
        }
    }
}

public struct ContentFilterConfig: Codable, Hashable, Sendable {
    public var rules: [String: CategoryRule]
    /// Force SafeSearch on Google, Bing and DuckDuckGo, and YouTube Restricted Mode.
    public var safeSearch: Bool
    /// YouTube: strict (true) or moderate (false) restricted mode.
    public var youtubeStrict: Bool

    public init(rules: [String: CategoryRule] = [:], safeSearch: Bool = false, youtubeStrict: Bool = false) {
        self.rules = rules; self.safeSearch = safeSearch; self.youtubeStrict = youtubeStrict
    }
    /// Malware and phishing on; everything else off until the user opts in.
    public static let defaults = ContentFilterConfig(rules: [
        ContentCategory.malware.rawValue: CategoryRule(mode: .always),
        ContentCategory.phishing.rawValue: CategoryRule(mode: .always),
    ])

    public func rule(_ c: ContentCategory) -> CategoryRule {
        rules[c.rawValue] ?? (c == .malware || c == .phishing ? CategoryRule(mode: .always) : CategoryRule(mode: .off))
    }
    public func isActive(_ c: ContentCategory, at date: Date = Date(), calendar: Calendar = .current) -> Bool {
        rule(c).isActive(at: date, calendar: calendar)
    }
    /// Categories whose list must be downloaded (anything not off).
    public var wantedDownloads: [ContentCategory] {
        ContentCategory.allCases.filter { $0.source != nil && rule($0).mode != .off }
    }
    /// Weakening = any category or SafeSearch that was on becomes off (or loses schedule windows).
    public static func weakens(old: ContentFilterConfig, new: ContentFilterConfig) -> Bool {
        if old.safeSearch && !new.safeSearch { return true }
        if old.safeSearch && new.safeSearch && old.youtubeStrict && !new.youtubeStrict { return true }
        for c in ContentCategory.allCases {
            let o = old.rule(c), n = new.rule(c)
            if o.mode == .always && n.mode != .always { return true }
            if o.mode == .scheduled && n.mode == .off { return true }
            if o.mode == .scheduled && n.mode == .scheduled && !Set(o.windows).isSubset(of: Set(n.windows)) { return true }
        }
        return false
    }
}

// MARK: - SafeSearch

public enum SafeSearch {
    public static let googleTarget = "forcesafesearch.google.com"
    public static let bingTarget = "strict.bing.com"
    public static let duckTarget = "safe.duckduckgo.com"
    public static let youtubeStrictTarget = "restrict.youtube.com"
    public static let youtubeModerateTarget = "restrictmoderate.youtube.com"

    static let youtubeNames: Set<String> = ["youtube.com", "www.youtube.com", "m.youtube.com", "youtubei.googleapis.com",
                                            "youtube.googleapis.com", "www.youtube-nocookie.com", "music.youtube.com"]
    static let bingNames: Set<String> = ["bing.com", "www.bing.com"]
    static let duckNames: Set<String> = ["duckduckgo.com", "www.duckduckgo.com", "start.duckduckgo.com", "html.duckduckgo.com", "lite.duckduckgo.com"]

    /// Google search hosts: google.<tld>, www.google.<tld>, with 1- or 2-label public suffixes (google.co.uk).
    public static func isGoogleSearch(_ name: String) -> Bool {
        var labels = name.split(separator: ".")
        if labels.first == "www" { labels.removeFirst() }
        guard labels.count >= 2, labels.count <= 3, labels[0] == "google" else { return false }
        let suffix = labels.dropFirst()
        if suffix.count == 2 { return ["co", "com", "ac", "or", "ne", "org", "net", "gov", "edu"].contains(String(suffix.first!)) && suffix.last!.count == 2 }
        return suffix.first!.count >= 2 && suffix.first!.allSatisfy(\.isLetter)
    }

    /// The SafeSearch host a name must be answered with, or nil.
    public static func target(for rawName: String, youtubeStrict: Bool) -> String? {
        let name = DNSWire.normalize(rawName)
        if youtubeNames.contains(name) { return youtubeStrict ? youtubeStrictTarget : youtubeModerateTarget }
        if isGoogleSearch(name) { return googleTarget }
        if bingNames.contains(name) { return bingTarget }
        if duckNames.contains(name) { return duckTarget }
        return nil
    }
}

// MARK: - Policy

/// Content filter + parental schedules + SafeSearch + app-firewall domain blocks, consulted per DNS query.
/// Thread-safe; swap config / lists at any time.
public final class ContentFilterPolicy: DNSPolicy, @unchecked Sendable {
    private let lock = NSLock()
    private var _config: ContentFilterConfig
    private var categoryList = DomainBlocklist()
    private var firewallList = DomainBlocklist()
    private let calendar: Calendar
    /// Called (outside the lock) for every SafeSearch rewrite and category block; for the privacy report.
    public var onDecision: (@Sendable (String, DNSPolicyDecision, ContentCategory?) -> Void)?

    public init(config: ContentFilterConfig = .defaults, calendar: Calendar = .current) {
        self._config = config; self.calendar = calendar
        categoryList = Self.seedList()
    }

    public var config: ContentFilterConfig {
        get { lock.lock(); defer { lock.unlock() }; return _config }
        set { lock.lock(); _config = newValue; lock.unlock() }
    }

    static func seedList() -> DomainBlocklist {
        let l = DomainBlocklist()
        for c in ContentCategory.allCases { for d in c.seedDomains { l.add(d, source: "cat-" + c.rawValue) } }
        return l
    }

    /// Rebuilds the category list from the seeds plus every downloaded category file in `directory`.
    public func loadCategoryLists(updater: BlocklistUpdater) {
        let l = Self.seedList()
        for s in updater.sources {
            let url = updater.listURL(s)
            let size = (try? FileManager.default.attributesOfItem(atPath: url.path)[.size] as? Int) ?? 0
            guard size > 0, size <= BlocklistUpdater.maxBytes, let data = try? Data(contentsOf: url) else { continue }
            l.load(text: String(decoding: data, as: UTF8.self), format: s.format, source: s.id, acceptAllowRules: false)
        }
        lock.lock(); categoryList = l; lock.unlock()
    }

    /// Domains blocked by the app firewall (domain -> app name).
    public func setFirewallDomains(_ domains: [String: String]) {
        let l = DomainBlocklist()
        for (d, app) in domains { l.add(d, source: "app-firewall:" + app) }
        lock.lock(); firewallList = l; lock.unlock()
    }

    public var categoryDomainCount: Int { lock.lock(); defer { lock.unlock() }; return categoryList.blockedCount }

    /// Which category list (if any) a name is on, regardless of whether the category is switched on.
    public func category(of name: String) -> ContentCategory? {
        lock.lock(); let l = categoryList; lock.unlock()
        if case .blocked(_, let src) = l.verdict(for: name) { return ContentCategory(rawValue: String(src.dropFirst(4))) }
        return nil
    }

    public static func category(forListSource src: String?) -> ContentCategory? {
        guard let src else { return nil }
        if src.hasPrefix("category:") { return ContentCategory(rawValue: String(src.dropFirst(9))) }
        return ContentCategory.allCases.first { $0.securityListIDs.contains(src) }
    }

    public func decide(name: String, type: UInt16, listVerdict: DomainBlocklist.Verdict, now: Date) -> DNSPolicyDecision {
        lock.lock(); let cfg = _config, cats = categoryList, fw = firewallList; lock.unlock()
        let d = decide(name: name, listVerdict: listVerdict, now: now, cfg: cfg, cats: cats, fw: fw)
        if let cb = onDecision, d != .useList {
            var cat: ContentCategory?
            if case .block(_, let s) = d { cat = Self.category(forListSource: s) }
            cb(name, d, cat)
        }
        return d
    }

    func decide(name: String, listVerdict: DomainBlocklist.Verdict, now: Date, cfg: ContentFilterConfig,
                cats: DomainBlocklist, fw: DomainBlocklist) -> DNSPolicyDecision {
        // The user's own allowlist always wins.
        if case .allowlisted = listVerdict { return .useList }
        if case .blocked(let rule, let src) = fw.verdict(for: name) { return .block(rule: rule, source: src) }
        if cfg.safeSearch, let t = SafeSearch.target(for: name, youtubeStrict: cfg.youtubeStrict), t != DNSWire.normalize(name) {
            return .rewrite(target: t, rule: "safesearch")
        }
        if case .blocked(_, let src) = listVerdict,
           let cat = ContentCategory.allCases.first(where: { $0.securityListIDs.contains(src) }),
           !cfg.isActive(cat, at: now, calendar: calendar) {
            // A malware/phishing block whose category the user switched off.
            return .pass
        }
        if case .blocked = listVerdict { return .useList }
        if case .blocked(let rule, let src) = cats.verdict(for: name),
           let cat = ContentCategory(rawValue: String(src.dropFirst(4))), cfg.isActive(cat, at: now, calendar: calendar) {
            return .block(rule: rule, source: "category:" + cat.rawValue)
        }
        return .useList
    }
}

extension BlocklistUpdater {
    /// An updater for the category lists the config wants (stored next to, not inside, the security feeds).
    public static func categoryUpdater(for config: ContentFilterConfig, directory: URL) -> BlocklistUpdater {
        BlocklistUpdater(sources: ContentCategory.allCases.filter { config.rule($0).mode != .off }.compactMap(\.source),
                         directory: directory)
    }
}
