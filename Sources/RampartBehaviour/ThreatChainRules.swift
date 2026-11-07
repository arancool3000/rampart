import Foundation
import RampartShared

/// Behaviour rules for the later stages of the "fake Apple link -> disguised trojan" chain:
///  TC1 contacts harvesting, TC2 driving Mail/Outlook to send, TC3 SMTP burst (mass-mailing),
///  TC4 Apple-ish exfil domain, TC5 large upload to a domain first seen today,
///  TC6 browser download from a lookalike domain executed within N seconds.
/// Stateful, thread-safe, fed the same SecurityEvents as BehaviourEngine. Detector code (not DSL) because
/// TC3/TC5/TC6 need counters and cross-event joins.
///
/// Event detail keys consumed (all optional; missing keys simply don't fire):
///  networkConnect: remote_ip, remote_port, remote_host / host, bytes_out
///  dnsQuery:       query / host
///  fileCreate/fileWrite/fileClose/fileRename: path (destPath for rename), modified ("0" = read-only close),
///                  origin_url / quarantine_origin / where_from (download origin)
///  tccRequest:     service (kTCCServiceAddressBook)
public final class ThreatChainDetector: @unchecked Sendable {
    public struct Config: Sendable {
        public var smtpBurstCount = 5
        public var smtpWindow: TimeInterval = 120
        public var uploadThresholdBytes: Int64 = 20 << 20
        public var downloadExecWindow: TimeInterval = 120
        public var dedupeWindow: TimeInterval = 600
        public init() {}
    }
    public var config: Config
    /// True when a host is a lookalike/impersonation domain. Wired to URLAnalyzer by rampartd.
    public var isLookalikeHost: @Sendable (String) -> Bool
    /// First time this registrable domain was seen anywhere. Wired to FileSeenDomainStore by rampartd.
    public var firstSeen: @Sendable (String) -> Date
    /// Signing lookup for impersonation scoring (optional).
    public var signing: (@Sendable (String) -> SigningInfo?)?

    let lock = NSLock()
    var smtp: [String: [(Date, String)]] = [:]           // process identity -> (time, remote)
    var uploads: [String: Int64] = [:]                   // identity|domain -> bytes
    var downloads: [String: (Date, String)] = [:]        // downloaded path -> (time, origin host)
    var fired: [String: Date] = [:]
    var ipHosts: [String: String] = [:]                  // remote ip -> last DNS name seen

    public init(config: Config = Config(), isLookalikeHost: @escaping @Sendable (String) -> Bool = { _ in false },
                firstSeen: @escaping @Sendable (String) -> Date = { _ in .distantPast }) {
        self.config = config; self.isLookalikeHost = isLookalikeHost; self.firstSeen = firstSeen
    }

    // MARK: identity helpers

    static let mailClients: [(signingID: String, pathSuffix: String)] = [
        ("com.apple.mail", "/Mail.app/Contents/MacOS/Mail"),
        ("com.microsoft.Outlook", "/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook"),
        ("com.apple.MailServiceAgent", ""), ("com.apple.mail.MailServiceAgent", ""), ("com.apple.email.maild", ""),
        ("it.bloop.airmail2", ""), ("com.readdle.smartemail-Mac", ""), ("com.mimestream.Mimestream", ""),
        ("org.mozilla.thunderbird", "/Thunderbird.app/Contents/MacOS/thunderbird"), ("com.postbox-inc.postbox", ""),
        ("com.canarymail.mac", ""), ("com.freron.MailMate", ""), ("com.superhuman.electron", ""), ("com.spark.desktop", ""),
    ]
    /// Mail clients: by signing ID (with team ID or platform for Apple) and path. Name alone is not trusted.
    func isMailClient(_ p: ProcessInfoLite) -> Bool {
        for m in Self.mailClients {
            if p.signingID == m.signingID {
                if m.signingID.hasPrefix("com.apple.") { if p.isPlatformBinary || signing?(p.path)?.status == .apple { return true } }
                else if p.teamID != nil || (signing?(p.path).map { $0.status == .developerID || $0.status == .appStore } ?? false) { return true }
            }
            if !m.pathSuffix.isEmpty, p.path.hasSuffix(m.pathSuffix), p.path.hasPrefix("/Applications/") || p.path.hasPrefix("/System/Applications/") {
                if p.isPlatformBinary || p.teamID != nil { return true }
            }
        }
        return false
    }

    static let contactsReaders: Set<String> = ["com.apple.AddressBook", "com.apple.AddressBook.ContactsAccountsService",
        "com.apple.contactsd", "com.apple.AddressBookSourceSync", "com.apple.AddressBook.abd", "com.apple.mail", "com.apple.MobileSMS",
        "com.apple.iCal", "com.apple.calaccessd", "com.apple.suggestd", "com.apple.mdworker.shared", "com.apple.mds", "com.apple.backupd",
        "com.apple.CloudDocs.iCloudDriveFileProvider", "com.apple.photoanalysisd", "com.apple.FaceTime", "com.apple.Spotlight",
        "com.apple.contacts.donation-agent", "com.apple.siriknowledged", "com.apple.knowledge-agent", "com.apple.CallHistorySyncHelper"]

    func isAppleSystem(_ p: ProcessInfoLite) -> Bool {
        p.isPlatformBinary || (p.signingID?.hasPrefix("com.apple.") == true && signing?(p.path)?.status == .apple)
    }

    static func isContactsPath(_ path: String) -> Bool {
        path.contains("/Library/Application Support/AddressBook/") && (path.hasSuffix(".abcddb") || path.hasSuffix(".abcddb-wal")
            || path.hasSuffix(".abcdp") || path.hasSuffix(".abbu") || path.contains("/Sources/"))
            || path.contains("/Library/Containers/com.apple.AddressBook/") || path.hasSuffix("/Contacts.sqlitedb")
    }

    static let appleDomains: Set<String> = ["apple.com", "icloud.com", "icloud-content.com", "apple-cloudkit.com", "mzstatic.com",
                                             "cdn-apple.com", "aaplimg.com", "apple.news", "me.com", "mac.com", "itunes.com", "apple-dns.net",
                                             "apple.co", "appleiphonecell.com", "apple-mapkit.com", "apple-livephotoskit.com", "swcdn.apple.com"]
    static let appleishTokens = ["apple", "icloud", "itunes", "appstore", "aapl", "xprotect", "macos", "siri", "iphone"]

    static func registrable(_ host: String) -> String {
        let l = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: ".")).split(separator: ".")
        guard l.count >= 2 else { return host.lowercased() }
        let two = l.suffix(2).joined(separator: ".")
        if ["co.uk", "com.au", "co.jp", "com.br", "co.nz", "com.cn"].contains(two), l.count >= 3 { return l.suffix(3).joined(separator: ".") }
        return two
    }

    /// "apple-analytics.test", "icloud-stats.top", "metrics.app1e.xyz" -> true; *.apple.com -> false.
    public static func isAppleishNonApple(_ host: String) -> Bool {
        let h = host.lowercased()
        let reg = registrable(h)
        if appleDomains.contains(reg) { return false }
        let folded = h.replacingOccurrences(of: "1", with: "l").replacingOccurrences(of: "0", with: "o")
        return appleishTokens.contains { folded.contains($0) }
    }

    func hostFor(_ e: SecurityEvent) -> String? {
        if let h = e.detail["remote_host"] ?? e.detail["host"] ?? e.detail["query"] ?? e.detail["domain"], !h.isEmpty { return h.lowercased() }
        if let ip = e.detail["remote_ip"] { return ipHosts[ip] }
        return nil
    }

    func identity(_ p: ProcessInfoLite?) -> String { p.map { $0.signingID ?? $0.path } ?? "?" }

    // MARK: ingest

    public func ingest(_ e: SecurityEvent) -> [Detection] {
        lock.lock(); defer { lock.unlock() }
        var out: [Detection] = []
        func emit(_ rule: String, _ name: String, _ cat: ThreatCategory, _ evs: [Evidence], path: String?, pid: Int32?) {
            let key = rule + "|" + identity(e.process) + "|" + (path ?? "")
            if let t = fired[key], e.date.timeIntervalSince(t) < config.dedupeWindow { return }
            fired[key] = e.date
            var p = 1.0; for x in evs { p *= 1 - Double(x.score) / 100 }
            let conf = Int((100 * (1 - p)).rounded())
            let sev: Severity = conf >= 90 ? .critical : conf >= 60 ? .high : conf >= 30 ? .medium : .low
            out.append(Detection(date: e.date, path: path, pid: pid, name: name, category: cat, severity: sev, confidence: conf, evidence: evs))
        }
        let p = e.process
        let impersonation = p.flatMap { AppleImpersonation.assess(process: $0, signing: signing?($0.path)) }

        switch e.kind {
        case .dnsQuery:
            if let q = e.detail["query"] ?? e.detail["host"], let ips = e.detail["answers"] {
                for ip in ips.split(separator: ",") { ipHosts[String(ip).trimmingCharacters(in: .whitespaces)] = q.lowercased() }
            }
            fallthrough
        case .networkConnect:
            guard let p else { break }
            let port = Int(e.detail["remote_port"] ?? "") ?? 0
            let remote = (hostFor(e) ?? e.detail["remote_ip"] ?? "?")
            // TC3 SMTP / submission burst by a non-mail process
            if e.kind == .networkConnect, [25, 465, 587].contains(port), !isMailClient(p) {
                var list = (smtp[identity(p)] ?? []).filter { e.date.timeIntervalSince($0.0) <= config.smtpWindow }
                list.append((e.date, remote)); smtp[identity(p)] = list
                if list.count >= config.smtpBurstCount {
                    var ev = [Evidence(source: .behaviour, title: "Mass-mailing: many outgoing mail connections",
                        detail: "\(p.path) opened \(list.count) SMTP/submission connections (port \(port)) in \(Int(config.smtpWindow)) s; it is not a mail app. Worms email themselves to your contacts this way.", score: 75)]
                    if let i = impersonation { ev.append(i) }
                    emit("TC3", "Mass-mailing behaviour", .malware, ev, path: p.path, pid: p.pid)
                }
            }
            // TC4 disguised exfil: Apple-ish domain that isn't Apple
            if let host = hostFor(e), Self.isAppleishNonApple(host) {
                let base = isAppleSystem(p) ? 40 : 70
                var ev = [Evidence(source: .network, title: "Talks to a fake Apple domain",
                    detail: "\(p.path) contacted \(host), which borrows Apple's name but is not an Apple domain. Malware disguises its 'analytics' uploads this way.", score: base)]
                if let i = impersonation { ev.append(i) }
                emit("TC4", "Disguised exfiltration", .infostealer, ev, path: p.path, pid: p.pid)
            }
            // TC5 large upload to a domain first seen today
            if let bytesS = e.detail["bytes_out"], let bytes = Int64(bytesS), bytes > 0, let host = hostFor(e) {
                let reg = Self.registrable(host)
                guard !Self.appleDomains.contains(reg) else { break }
                let k = identity(p) + "|" + reg
                uploads[k, default: 0] += bytes
                let fresh = Calendar.current.isDate(firstSeen(reg), inSameDayAs: e.date) || e.date.timeIntervalSince(firstSeen(reg)) < 86400
                if fresh, uploads[k]! >= config.uploadThresholdBytes {
                    var ev = [Evidence(source: .network, title: "Large upload to a brand-new domain",
                        detail: "\(p.path) sent \(uploads[k]! >> 20) MB to \(reg), a domain this Mac first saw today.", score: isAppleSystem(p) ? 25 : 65)]
                    if let i = impersonation { ev.append(i) }
                    emit("TC5", "Possible data exfiltration", .infostealer, ev, path: p.path, pid: p.pid)
                }
            }
        case .fileClose, .fileWrite, .fileCreate, .other:
            if let path = e.path, Self.isContactsPath(path), let p {
                // TC1 contacts harvesting by a non-Apple, non-mail process
                let allowed = (p.signingID.map(Self.contactsReaders.contains) ?? false) && isAppleSystem(p)
                if !allowed && !isAppleSystem(p) && !isMailClient(p) {
                    var ev = [Evidence(source: .behaviour, title: "Reads your Contacts database",
                        detail: "\(p.path) opened \(path). Apps that harvest contacts usually do it to spam or spread to them.", score: 55)]
                    if let i = impersonation { ev.append(i) }
                    emit("TC1", "Contacts harvesting", .infostealer, ev, path: p.path, pid: p.pid)
                }
            }
            // TC6 part 1: remember downloads from lookalike origins
            if e.kind != .fileClose || e.detail["modified"] == "1", let path = e.destPath ?? e.path,
               let origin = e.detail["origin_url"] ?? e.detail["quarantine_origin"] ?? e.detail["where_from"],
               let host = URL(string: origin)?.host?.lowercased() ?? (origin.contains("/") ? nil : origin.lowercased()),
               isLookalikeHost(host) {
                downloads[path] = (e.date, host)
                downloads = downloads.filter { e.date.timeIntervalSince($0.value.0) < 3600 }
            }
        case .tccRequest:
            if let p, (e.detail["service"] ?? "").contains("AddressBook"), !isAppleSystem(p), !isMailClient(p) {
                emit("TC1", "Contacts harvesting", .infostealer, [Evidence(source: .behaviour, title: "Asks for your Contacts",
                    detail: "\(p.path) requested Contacts access (\(e.detail["service"] ?? "")).", score: 35)] + (impersonation.map { [$0] } ?? []), path: p.path, pid: p.pid)
            }
        case .exec:
            guard let p else { break }
            // TC2 driving Mail/Outlook to send
            let args = p.args.joined(separator: " ")
            let lower = args.lowercased()
            if (p.path.hasSuffix("/osascript") || lower.contains("osascript")),
               lower.contains("application \"mail\"") || lower.contains("application \"microsoft outlook\"") || lower.contains("application id \"com.apple.mail\""),
               lower.contains("send") || lower.contains("outgoing message") {
                emit("TC2", "Mass-mailing behaviour", .malware, [Evidence(source: .behaviour, title: "Script makes Mail send messages",
                    detail: "\(p.path) runs AppleScript that drives Mail/Outlook to send: \(args.prefix(160))", score: 70)], path: p.path, pid: p.pid)
            }
            if let target = e.detail["ae_target"], ["com.apple.mail", "com.microsoft.outlook"].contains(target.lowercased()),
               (e.detail["ae_event"] ?? "").lowercased().contains("send"), !isMailClient(p) {
                emit("TC2", "Mass-mailing behaviour", .malware, [Evidence(source: .behaviour, title: "App makes Mail send messages",
                    detail: "\(p.path) sent a 'send' Apple Event to \(target).", score: 70)], path: p.path, pid: p.pid)
            }
            // TC6 part 2: exec of (or from inside) a recent lookalike download
            let candidates = [p.path] + p.args.prefix(3).filter { $0.hasPrefix("/") }
            for (dl, info) in downloads where e.date.timeIntervalSince(info.0) <= config.downloadExecWindow && e.date >= info.0 {
                if candidates.contains(where: { $0 == dl || $0.hasPrefix(dl.hasSuffix("/") ? dl : dl + "/") }) {
                    var ev = [Evidence(source: .behaviour, title: "Ran a download from a lookalike site within seconds",
                        detail: "\(dl) came from \(info.1) (a lookalike domain) and was started \(Int(e.date.timeIntervalSince(info.0))) s after download.", score: 85)]
                    if let i = impersonation { ev.append(i) }
                    emit("TC6", "Drive-by download executed", .malware, ev, path: dl, pid: p.pid)
                    break
                }
            }
        default: break
        }
        return out
    }
}
