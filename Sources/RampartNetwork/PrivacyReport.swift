import Foundation
import RampartShared

/// Weekly privacy report built from the local DNS filter: trackers blocked (or only seen, when tracker blocking is
/// off), the companies behind them, category blocks, SafeSearch rewrites and which apps talked to trackers.
public struct PrivacyReport: Codable, Sendable {
    public struct Item: Codable, Hashable, Sendable { public var name: String; public var count: Int }
    public var generated: Date
    public var days: Int
    public var trackerBlockingOn: Bool
    public var trackersBlocked: Int
    public var trackersSeen: Int
    public var trackersByDay: [Int]
    public var topTrackers: [Item]
    public var topCompanies: [Item]
    public var categoryBlocks: [Item]
    public var appsContactingTrackers: [Item]
    public var safeSearchRewrites: Int
    public var note: String?
}

/// Known tracker owners by registrable-domain suffix (small, offline).
public enum TrackerCompanies {
    static let table: [(String, String)] = [
        ("doubleclick.net", "Google"), ("google-analytics.com", "Google"), ("googletagmanager.com", "Google"),
        ("googlesyndication.com", "Google"), ("googleadservices.com", "Google"), ("app-measurement.com", "Google"),
        ("googletagservices.com", "Google"), ("2mdn.net", "Google"), ("facebook.net", "Meta"), ("facebook.com", "Meta"),
        ("fbcdn.net", "Meta"), ("instagram.com", "Meta"), ("graph.facebook.com", "Meta"), ("ads-twitter.com", "X"),
        ("analytics.twitter.com", "X"), ("ads.linkedin.com", "Microsoft"), ("bat.bing.com", "Microsoft"), ("clarity.ms", "Microsoft"),
        ("scorecardresearch.com", "Comscore"), ("hotjar.com", "Hotjar"), ("hotjar.io", "Hotjar"), ("mixpanel.com", "Mixpanel"),
        ("segment.io", "Twilio Segment"), ("segment.com", "Twilio Segment"), ("amplitude.com", "Amplitude"), ("criteo.com", "Criteo"),
        ("criteo.net", "Criteo"), ("taboola.com", "Taboola"), ("outbrain.com", "Outbrain"), ("adnxs.com", "Microsoft Xandr"),
        ("quantserve.com", "Quantcast"), ("amazon-adsystem.com", "Amazon"), ("tiktok.com", "ByteDance"), ("byteoversea.com", "ByteDance"),
        ("adsrvr.org", "The Trade Desk"), ("rubiconproject.com", "Magnite"), ("pubmatic.com", "PubMatic"), ("branch.io", "Branch"),
        ("appsflyer.com", "AppsFlyer"), ("adjust.com", "Adjust"), ("newrelic.com", "New Relic"), ("nr-data.net", "New Relic"),
        ("sentry.io", "Sentry"), ("yandex.ru", "Yandex"), ("mc.yandex.ru", "Yandex"), ("snapchat.com", "Snap"), ("pinterest.com", "Pinterest"),
    ]
    public static func company(for domain: String) -> String? {
        let d = domain.lowercased()
        var best: (Int, String)?
        for (suffix, co) in table where d == suffix || d.hasSuffix("." + suffix) {
            if best == nil || suffix.count > best!.0 { best = (suffix.count, co) }
        }
        return best?.1
    }
}

/// Persisted daily counters behind the report. Bounded: 62 days, 400 tracker names per day.
public final class PrivacyLedger: @unchecked Sendable {
    struct Day: Codable {
        var trackersBlocked: [String: Int] = [:]
        var trackersSeen: [String: Int] = [:]
        var categories: [String: Int] = [:]
        var apps: [String: Int] = [:]
        var safeSearch = 0
    }
    private let url: URL?
    private let lock = NSLock()
    private var days: [String: Day] = [:]
    private var dirty = 0
    static let fmt: DateFormatter = {
        let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; f.locale = Locale(identifier: "en_US_POSIX"); return f
    }()

    public init(url: URL?) {
        self.url = url
        if let url, let d = try? Data(contentsOf: url), let v = try? JSONDecoder.rampart.decode([String: Day].self, from: d) { days = v }
    }

    private func bump(_ m: inout [String: Int], _ k: String, cap: Int = 400) {
        if m[k] == nil && m.count >= cap { return }
        m[k, default: 0] += 1
    }

    /// One DNS query outcome. `trackerCategory`: the name is on the tracker list. `blockedCategory`: the category
    /// that blocked it (nil when it was not blocked by a category).
    public func record(name: String, blocked: Bool, isTracker: Bool, blockedCategory: ContentCategory?, safeSearch: Bool = false, date: Date = Date()) {
        let k = Self.fmt.string(from: date)
        lock.lock()
        var d = days[k] ?? Day()
        if isTracker { if blocked { bump(&d.trackersBlocked, name) } else { bump(&d.trackersSeen, name) } }
        if let c = blockedCategory { d.categories[c.rawValue, default: 0] += 1 }
        if safeSearch { d.safeSearch += 1 }
        days[k] = d
        dirty += 1
        let flush = dirty >= 50
        lock.unlock()
        if flush { save() }
    }

    /// An app had an open connection to a tracker host (counted once per app+host per call site's dedupe).
    public func recordApp(_ app: String, date: Date = Date()) {
        let k = Self.fmt.string(from: date)
        lock.lock(); var d = days[k] ?? Day(); bump(&d.apps, app, cap: 200); days[k] = d; dirty += 1; lock.unlock()
    }

    public func save() {
        guard let url else { return }
        lock.lock()
        let cutoff = Self.fmt.string(from: Date().addingTimeInterval(-62 * 86400))
        days = days.filter { $0.key >= cutoff }
        let snapshot = days; dirty = 0
        lock.unlock()
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder.rampart.encode(snapshot) { try? d.write(to: url, options: .atomic) }
    }

    public func report(days n: Int = 7, trackerBlockingOn: Bool, now: Date = Date(), calendar: Calendar = .current) -> PrivacyReport {
        lock.lock(); let all = days; lock.unlock()
        var blocked: [String: Int] = [:], seen: [String: Int] = [:], cats: [String: Int] = [:], apps: [String: Int] = [:]
        var byDay: [Int] = [], ss = 0
        for back in (0..<n).reversed() {
            let date = calendar.date(byAdding: .day, value: -back, to: now)!
            let d = all[Self.fmt.string(from: date)] ?? Day()
            byDay.append(d.trackersBlocked.values.reduce(0, +))
            d.trackersBlocked.forEach { blocked[$0.key, default: 0] += $0.value }
            d.trackersSeen.forEach { seen[$0.key, default: 0] += $0.value }
            d.categories.forEach { cats[$0.key, default: 0] += $0.value }
            d.apps.forEach { apps[$0.key, default: 0] += $0.value }
            ss += d.safeSearch
        }
        func top(_ m: [String: Int], _ k: Int = 10) -> [PrivacyReport.Item] {
            m.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(k).map { PrivacyReport.Item(name: $0.key, count: $0.value) }
        }
        var companies: [String: Int] = [:]
        for (dom, c) in blocked.merging(seen, uniquingKeysWith: +) { companies[TrackerCompanies.company(for: dom) ?? "Other", default: 0] += c }
        let catItems = top(cats, 10).map { PrivacyReport.Item(name: ContentCategory(rawValue: $0.name)?.title ?? $0.name, count: $0.count) }
        let tb = blocked.values.reduce(0, +), tsn = seen.values.reduce(0, +)
        var note: String?
        if !trackerBlockingOn {
            note = tsn > 0 ? "Tracker blocking is off: these trackers were contacted, not blocked. Turn on “Trackers & ads” to block them."
                           : "Tracker blocking is off. Turn on “Trackers & ads” in Content filter to block and count trackers."
        }
        return PrivacyReport(generated: now, days: n, trackerBlockingOn: trackerBlockingOn, trackersBlocked: tb, trackersSeen: tsn,
                             trackersByDay: byDay, topTrackers: top(trackerBlockingOn ? blocked : blocked.merging(seen, uniquingKeysWith: +)),
                             topCompanies: top(companies.filter { $0.key != "Other" }, 8) + (companies["Other"].map { [PrivacyReport.Item(name: "Other", count: $0)] } ?? []),
                             categoryBlocks: catItems, appsContactingTrackers: top(apps, 8), safeSearchRewrites: ss, note: note)
    }
}

/// Per-site tracker count for the browser extension: which of a page's third-party hosts are trackers.
public enum TrackerClassifier {
    public struct Result: Codable, Sendable {
        public var trackers: [String]
        public var companies: [String]
        public var count: Int { trackers.count }
    }
    public static func classify(hosts: [String], pageHost: String?, policy: ContentFilterPolicy) -> Result {
        var out: [String] = [], cos = Set<String>()
        let page = pageHost.map(DNSWire.normalize)
        for raw in Set(hosts.prefix(500)) {
            let h = DNSWire.normalize(raw)
            guard !h.isEmpty, h != page, DomainBlocklist.normalizeDomain(Substring(h)) != nil else { continue }
            if policy.category(of: h) == .trackers {
                out.append(h)
                if let c = TrackerCompanies.company(for: h) { cos.insert(c) }
            }
        }
        return Result(trackers: out.sorted(), companies: cos.sorted())
    }
}
