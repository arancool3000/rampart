import Foundation
import Compression
import RampartShared

// Deep content inspection for innocent-looking files (H: "one changed link" defence).
// Extracts every URL, domain, IP and command line from plists, link files, terminal files,
// Shortcuts, HTML/JS, PDF, Office (OOXML) relationships, scripts and Mach-O strings, then runs them
// through URLAnalyzer and an injected dangerous-command classifier (PasteClassifier in rampartd,
// RampartWeb cannot import RampartBehaviour). Pure parsing: nothing is executed, opened or fetched.

public struct ExtractedIndicator: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable { case url, domain, ip, command, scheme, action }
    public var kind: Kind
    public var value: String
    /// Exact location: "key:ProgramArguments[2]", "offset:0x1f3", "zip:word/_rels/document.xml.rels@0x40".
    public var location: String
    public init(kind: Kind, value: String, location: String) { self.kind = kind; self.value = value; self.location = location }
}

public struct DeepInspectionReport: Codable, Sendable {
    public var path: String
    public var format: String
    public var indicators: [ExtractedIndicator]
    public var evidence: [Evidence]
    public var urlReports: [URLReport]
    public var score: Int { Self.combine(evidence.map(\.score)) }
    static func combine(_ s: [Int]) -> Int {
        var p = 1.0; for x in s { p *= 1 - Double(max(0, min(100, x))) / 100 }; return Int((100 * (1 - p)).rounded())
    }
}

public struct DeepContentInspector: Sendable {
    public typealias CommandClassifier = @Sendable (String) -> (score: Int, reasons: [String])
    public enum Format: String, Sendable { case plist, webloc, urlFile, terminal, shellScript, appleScript, python, shortcut, html, pdf, office, machO, text }

    public var analyzer: URLAnalyzer
    public var classifyCommand: CommandClassifier?
    public var maxBytes = 16 << 20         // read cap per file
    public var maxZipEntryBytes = 4 << 20
    public var maxIndicators = 500

    public init(analyzer: URLAnalyzer = URLAnalyzer(), classifyCommand: CommandClassifier? = nil) {
        self.analyzer = analyzer; self.classifyCommand = classifyCommand
    }

    /// Extensions that are worth deep-inspecting on write (the daemon filters FS events with this).
    public static let interestingExtensions: Set<String> = [
        "plist", "webloc", "inetloc", "fileloc", "url", "terminal", "command", "tool", "sh", "zsh", "bash",
        "applescript", "scpt", "py", "shortcut", "wflow", "html", "htm", "xhtml", "svg", "js", "mjs", "pdf",
        "docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "dotm", "txt", "rtf",
    ]
    public static func isInteresting(path: String) -> Bool {
        let ext = (path as NSString).pathExtension.lowercased()
        if interestingExtensions.contains(ext) { return true }
        return (path as NSString).lastPathComponent == "Info.plist"
    }

    // MARK: entry points

    public func inspect(path: String) -> DeepInspectionReport? {
        guard let fh = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? fh.close() }
        guard let data = try? fh.read(upToCount: maxBytes), !data.isEmpty else { return nil }
        return inspect(data: data, name: path)
    }

    public func inspect(data: Data, name: String) -> DeepInspectionReport {
        let fmt = Self.detectFormat(data: data, name: name)
        var c = Collector(limit: maxIndicators)
        switch fmt {
        case .plist, .webloc, .terminal, .shortcut: inspectPlist(data, name: name, format: fmt, into: &c)
        case .urlFile: inspectINI(data, into: &c)
        case .pdf: inspectPDF(data, into: &c)
        case .office: inspectZip(data, into: &c)
        case .machO: inspectStrings(data, into: &c)
        case .html: inspectText(data, isHTML: true, into: &c)
        case .shellScript, .python, .appleScript, .text:
            inspectText(data, isHTML: false, into: &c)
            if fmt == .shellScript { c.add(.command, Self.text(data).trimmingCharacters(in: .whitespacesAndNewlines), "offset:0x0 (whole script)") }
        }
        return evaluate(c, format: fmt, name: name)
    }

    public static func detectFormat(data: Data, name: String) -> Format {
        let ext = (name as NSString).pathExtension.lowercased()
        let head = [UInt8](data.prefix(8))
        if head.count >= 4 {
            let m = UInt32(head[0]) << 24 | UInt32(head[1]) << 16 | UInt32(head[2]) << 8 | UInt32(head[3])
            if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xbebafeca].contains(m) { return .machO }
            if head[0] == 0x25, head[1] == 0x50, head[2] == 0x44, head[3] == 0x46 { return .pdf }        // %PDF
            if head[0] == 0x50, head[1] == 0x4b, head[2] == 3, head[3] == 4 { return ext == "shortcut" ? .shortcut : .office }
        }
        switch ext {
        case "webloc", "inetloc", "fileloc": return .webloc
        case "url": return .urlFile
        case "terminal": return .terminal
        case "shortcut", "wflow": return .shortcut
        case "plist": return .plist
        case "command", "tool", "sh", "zsh", "bash": return .shellScript
        case "applescript", "scpt": return .appleScript
        case "py": return .python
        case "html", "htm", "xhtml", "svg", "js", "mjs": return .html
        default: break
        }
        if data.starts(with: Data("bplist".utf8)) || data.prefix(200).range(of: Data("<plist".utf8)) != nil { return .plist }
        if data.starts(with: Data("#!".utf8)) {
            let line = text(data.prefix(80))
            if line.contains("python") { return .python }
            if line.contains("osascript") { return .appleScript }
            return .shellScript
        }
        if data.prefix(512).range(of: Data("<html".utf8)) != nil || data.prefix(512).range(of: Data("<!DOCTYPE".utf8)) != nil { return .html }
        if name.hasSuffix("Info.plist") { return .plist }
        return .text
    }

    // MARK: collectors

    struct Collector {
        var limit: Int
        var items: [ExtractedIndicator] = []
        var seen: Set<String> = []
        var extra: [Evidence] = []
        mutating func add(_ k: ExtractedIndicator.Kind, _ v: String, _ loc: String) {
            let v = v.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !v.isEmpty, items.count < limit, seen.insert(k.rawValue + "|" + v + "|" + loc).inserted else { return }
            items.append(ExtractedIndicator(kind: k, value: String(v.prefix(2048)), location: loc))
        }
    }

    static func text(_ d: Data) -> String { String(decoding: d, as: UTF8.self) }

    static let urlRegex = try! NSRegularExpression(pattern: #"(?i)\b(?:https?|ftp|file|smb|afp|vnc|ssh|javascript|data|x-apple-[a-z.-]+|itms(?:-[a-z]+)?|macappstores?|applescript|shortcuts):(?://)?[^\s"'<>()\[\]{}\\^`|]{2,}"#)
    static let ipRegex = try! NSRegularExpression(pattern: #"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"#)
    /// Bare domains that carry a brand keyword ("icloud-verify.test", "apple-analytics.top"). Kept narrow to
    /// avoid reverse-DNS identifiers (com.apple.foo) and code tokens.
    static let brandDomainRegex = try! NSRegularExpression(pattern: #"(?i)(?<![\w.@/-])((?:[a-z0-9-]+\.)*[a-z0-9-]*(?:apple|icloud|itunes|appstore|microsoft|office365|outlook|onedrive)[a-z0-9-]*\.(?:[a-z0-9-]+\.)*[a-z]{2,24})(?![\w-])"#)
    static let shellCallRegexes: [NSRegularExpression] = [
        #"do\s+shell\s+script\s+"((?:[^"\\]|\\.)*)""#,                           // AppleScript
        #"(?:os\.system|os\.popen|subprocess\.(?:run|call|Popen|check_output))\(\s*[rbuf]?["']([^"']+)["']"#, // Python
        #"(?:/bin/(?:ba|z)?sh|/usr/bin/env\s+\w+)\s+-c\s+["']?([^"'\n]{4,})"#,
        #"(?m)^\s*((?:curl|wget|osascript|bash|sh|zsh|python3?|chmod|xattr|launchctl|open)\s[^\n]{4,})$"#,
    ].map { try! NSRegularExpression(pattern: $0) }

    func scanString(_ s: String, baseOffset: Int?, keyPath: String?, into c: inout Collector, commands: Bool) {
        let ns = s as NSString
        func loc(_ r: NSRange) -> String {
            if let kp = keyPath { return "key:" + kp }
            let off = (baseOffset ?? 0) + ns.substring(to: r.location).utf8.count
            let line = ns.substring(to: r.location).reduce(1) { $1 == "\n" ? $0 + 1 : $0 }
            return String(format: "offset:0x%x (line %d)", off, line)
        }
        let full = NSRange(location: 0, length: ns.length)
        for m in Self.urlRegex.matches(in: s, range: full) {
            var u = ns.substring(with: m.range)
            while let last = u.last, ".,;:!?'\"".contains(last) { u.removeLast() }
            c.add(.url, u, loc(m.range))
        }
        for m in Self.ipRegex.matches(in: s, range: full) { c.add(.ip, ns.substring(with: m.range), loc(m.range)) }
        for m in Self.brandDomainRegex.matches(in: s, range: full) {
            let d = ns.substring(with: m.range(at: 1)).lowercased()
            let first = d.split(separator: ".").first.map(String.init) ?? ""
            if ["com", "org", "net", "io", "group", "app"].contains(first) { continue }   // reverse-DNS identifier
            if s.contains("://" + d) || s.contains("@" + d) { continue }                // already a URL
            c.add(.domain, d, loc(m.range))
        }
        if commands {
            for re in Self.shellCallRegexes {
                for m in re.matches(in: s, range: full) where m.numberOfRanges > 1 {
                    let cmd = ns.substring(with: m.range(at: 1)).replacingOccurrences(of: "\\\"", with: "\"")
                    c.add(.command, cmd, loc(m.range))
                }
            }
        }
    }

    // MARK: formats

    func inspectPlist(_ data: Data, name: String, format: Format, into c: inout Collector) {
        guard let obj = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) else {
            inspectText(data, isHTML: false, into: &c); return     // signed Shortcuts (AEA) etc.: strings only
        }
        let isLaunchItem = (obj as? [String: Any]).map { $0["Label"] != nil && ($0["ProgramArguments"] != nil || $0["Program"] != nil) } ?? false
        func walk(_ v: Any, _ kp: String, _ key: String?) {
            switch v {
            case let d as [String: Any]:
                for (k, x) in d.sorted(by: { $0.key < $1.key }) { walk(x, kp.isEmpty ? k : kp + "." + k, k) }
                if let args = d["ProgramArguments"] as? [String], !args.isEmpty {
                    c.add(.command, args.map { $0.contains(" ") ? "'\($0)'" : $0 }.joined(separator: " "), "key:" + (kp.isEmpty ? "" : kp + ".") + "ProgramArguments")
                }
            case let a as [Any]:
                for (i, x) in a.enumerated() { walk(x, "\(kp)[\(i)]", key) }
            case let s as String:
                scanString(s, baseOffset: nil, keyPath: kp, into: &c, commands: true)
                switch key {
                case "Program" where isLaunchItem: c.add(.command, s, "key:" + kp)
                case "CommandString", "WFShellScript", "WFAppleScript", "WFJavaScript", "Script", "Command":
                    c.add(.command, s, "key:" + kp)
                case "SUFeedURL":
                    if s.lowercased().hasPrefix("http://") {
                        c.extra.append(Evidence(source: .heuristic, title: "App update feed over plain http",
                            detail: "SUFeedURL \(s) at key:\(kp) can be swapped on the network to deliver a fake update.", score: 40))
                    }
                case "CFBundleURLSchemes":
                    c.add(.scheme, s, "key:" + kp)
                    if ["http", "https", "file", "ftp", "x-apple-systempreferences"].contains(s.lowercased()) {
                        c.extra.append(Evidence(source: .heuristic, title: "App claims the \(s): URL scheme",
                            detail: "CFBundleURLSchemes at key:\(kp) registers \(s): so links could open in this app instead of the browser.", score: 30))
                    }
                default: break
                }
            case let d as Data where d.count < 1 << 20:
                // Nested plists (Shortcuts, Office-in-plist) and binary blobs: string scan
                if let inner = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil) { walk(inner, kp + "<data>", nil) }
                else { scanString(Self.printableStrings(d).map(\.1).joined(separator: "\n"), baseOffset: nil, keyPath: kp, into: &c, commands: true) }
            default: break
            }
        }
        walk(obj, "", nil)
    }

    func inspectINI(_ data: Data, into c: inout Collector) {
        let s = Self.text(data)
        var off = 0
        for (i, line) in s.components(separatedBy: "\n").enumerated() {
            let t = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if let eq = t.firstIndex(of: "="), ["url", "iconfile", "baseurl"].contains(t[..<eq].lowercased()) {
                c.add(.url, String(t[t.index(after: eq)...]), String(format: "offset:0x%x (line %d, %@)", off, i + 1, String(t[..<eq])))
            } else {
                scanString(line, baseOffset: off, keyPath: nil, into: &c, commands: false)
            }
            off += line.utf8.count + 1
        }
    }

    func inspectPDF(_ data: Data, into c: inout Collector) {
        // Literal-string actions only (no stream decompression of object streams; strings scan covers the rest).
        let s = String(decoding: data, as: Unicode.ASCII.self)   // byte-for-byte, offsets stay exact
        let ns = s as NSString
        let full = NSRange(location: 0, length: ns.length)
        let patterns: [(String, ExtractedIndicator.Kind, String)] = [
            (#"/URI\s*\(((?:[^()\\]|\\.)*)\)"#, .url, "/URI"),
            (#"/Launch\b[^>]*?/F\s*\(((?:[^()\\]|\\.)*)\)"#, .command, "/Launch"),
            (#"/Win\s*<<[^>]*?/F\s*\(((?:[^()\\]|\\.)*)\)"#, .command, "/Launch/Win"),
            (#"/(?:JS|JavaScript)\s*\(((?:[^()\\]|\\.){1,4000})\)"#, .action, "/JavaScript"),
        ]
        for (p, kind, label) in patterns {
            let re = try! NSRegularExpression(pattern: p, options: [.dotMatchesLineSeparators])
            for m in re.matches(in: s, range: full) {
                let v = ns.substring(with: m.range(at: 1)).replacingOccurrences(of: "\\(", with: "(").replacingOccurrences(of: "\\)", with: ")")
                let loc = String(format: "offset:0x%x (%@)", m.range.location, label)
                c.add(kind, kind == .action ? "\(label): \(v.prefix(200))" : v, loc)
                if kind == .action { scanString(v, baseOffset: m.range(at: 1).location, keyPath: nil, into: &c, commands: false) }
            }
        }
        if ns.range(of: "/Launch").location != NSNotFound {
            let off = ns.range(of: "/Launch").location
            c.extra.append(Evidence(source: .heuristic, title: "PDF can launch a program",
                detail: String(format: "A /Launch action at offset:0x%x asks the reader to run a file or command.", off), score: 60))
        }
        if ns.range(of: "/OpenAction").location != NSNotFound, s.range(of: "/JavaScript") != nil || s.range(of: "/JS") != nil {
            let off = ns.range(of: "/OpenAction").location
            c.extra.append(Evidence(source: .heuristic, title: "PDF runs script when opened",
                detail: String(format: "/OpenAction at offset:0x%x with embedded JavaScript.", off), score: 30))
        }
        // Remaining literal URLs anywhere (annotations, XMP)
        scanString(s, baseOffset: 0, keyPath: nil, into: &c, commands: false)
    }

    func inspectText(_ data: Data, isHTML: Bool, into c: inout Collector) {
        let s = Self.text(data)
        scanString(s, baseOffset: 0, keyPath: nil, into: &c, commands: true)
        guard isHTML else { return }
        let ns = s as NSString
        let full = NSRange(location: 0, length: ns.length)
        for (re, label) in [(RedirectChainInspector.metaRefreshRegex, "meta-refresh"), (RedirectChainInspector.jsLocationRegex, "js-location")] {
            for m in re.matches(in: s, range: full) {
                let off = ns.substring(to: m.range.location).utf8.count
                c.add(.action, "\(label) -> \(ns.substring(with: m.range(at: 1)))", String(format: "offset:0x%x (%@)", off, label))
            }
        }
    }

    func inspectStrings(_ data: Data, into c: inout Collector) {
        for (off, str) in Self.printableStrings(data, minLength: 6) {
            scanString(str, baseOffset: off, keyPath: nil, into: &c, commands: true)
        }
    }

    /// (offset, string) for every printable ASCII run.
    static func printableStrings(_ data: Data, minLength: Int = 6) -> [(Int, String)] {
        var out: [(Int, String)] = []
        var start = -1
        data.withUnsafeBytes { (p: UnsafeRawBufferPointer) in
            for i in 0...p.count {
                let b: UInt8 = i < p.count ? p[i] : 0
                if b >= 0x20 && b < 0x7f || b == 0x09 { if start < 0 { start = i } }
                else if start >= 0 {
                    if i - start >= minLength, out.count < 200_000 {
                        out.append((start, String(decoding: UnsafeRawBufferPointer(rebasing: p[start..<i]), as: UTF8.self)))
                    }
                    start = -1
                }
            }
        }
        return out
    }

    // MARK: ZIP (OOXML relationships, signed Shortcuts are not zip)

    func inspectZip(_ data: Data, into c: inout Collector) {
        for e in Self.zipEntries(data, maxEntryBytes: maxZipEntryBytes) {
            let lower = e.name.lowercased()
            guard lower.hasSuffix(".rels") || lower.hasSuffix(".xml") || lower.hasSuffix(".vba") || lower.hasSuffix(".bin") || lower.hasSuffix(".plist") else { continue }
            let s = Self.text(e.data)
            if lower.hasSuffix(".rels") {
                let re = try! NSRegularExpression(pattern: #"<Relationship\b[^>]*?Target\s*=\s*"([^"]+)"[^>]*>"#)
                let ns = s as NSString
                for m in re.matches(in: s, range: NSRange(location: 0, length: ns.length)) {
                    let tag = ns.substring(with: m.range)
                    guard tag.contains("TargetMode=\"External\"") || ns.substring(with: m.range(at: 1)).contains("://") else { continue }
                    let target = ns.substring(with: m.range(at: 1)).replacingOccurrences(of: "&amp;", with: "&")
                    let off = ns.substring(to: m.range.location).utf8.count
                    c.add(.url, target, String(format: "zip:%@@0x%x", e.name, off))
                    if tag.contains("attachedTemplate") || tag.contains("oleObject") || tag.contains("frame") {
                        c.extra.append(Evidence(source: .heuristic, title: "Document loads a remote template or object",
                            detail: "\(e.name) points to \(target) (remote template injection pulls code when opened).", score: 45))
                    }
                }
            } else if lower.hasSuffix(".bin") || lower.hasSuffix(".vba") {
                for (off, str) in Self.printableStrings(e.data) {
                    var sub = Collector(limit: 50)
                    scanString(str, baseOffset: off, keyPath: nil, into: &sub, commands: true)
                    for i in sub.items { c.add(i.kind, i.value, "zip:\(e.name)@" + i.location) }
                }
                if lower.contains("vbaproject") {
                    c.extra.append(Evidence(source: .heuristic, title: "Document contains macros", detail: "\(e.name) is a VBA macro project.", score: 25))
                }
            }
        }
    }

    struct ZipEntry { var name: String; var data: Data }

    static func zipEntries(_ d: Data, maxEntryBytes: Int, maxEntries: Int = 2000) -> [ZipEntry] {
        let b = [UInt8](d)
        func u16(_ o: Int) -> Int { o + 2 <= b.count ? Int(b[o]) | Int(b[o + 1]) << 8 : 0 }
        func u32(_ o: Int) -> Int { o + 4 <= b.count ? u16(o) | u16(o + 2) << 16 : 0 }
        guard b.count > 22 else { return [] }
        var eocd = -1
        var i = b.count - 22
        while i >= max(0, b.count - 65_557) { if u32(i) == 0x06054b50 { eocd = i; break }; i -= 1 }
        guard eocd >= 0 else { return [] }
        let count = min(u16(eocd + 10), maxEntries)
        var p = u32(eocd + 16)
        var out: [ZipEntry] = []
        for _ in 0..<count {
            guard p + 46 <= b.count, u32(p) == 0x02014b50 else { break }
            let method = u16(p + 10), csize = u32(p + 20), usize = u32(p + 24)
            let nlen = u16(p + 28), elen = u16(p + 30), clen = u16(p + 32), lho = u32(p + 42)
            guard p + 46 + nlen <= b.count else { break }
            let name = String(decoding: b[(p + 46)..<(p + 46 + nlen)], as: UTF8.self)
            p += 46 + nlen + elen + clen
            guard lho + 30 <= b.count, u32(lho) == 0x04034b50, usize <= maxEntryBytes else { continue }
            let dataStart = lho + 30 + u16(lho + 26) + u16(lho + 28)
            guard dataStart >= 0, dataStart + csize <= b.count else { continue }
            let comp = Data(b[dataStart..<(dataStart + csize)])
            if method == 0 { out.append(ZipEntry(name: name, data: comp)) }
            else if method == 8, usize > 0 {
                var dst = [UInt8](repeating: 0, count: usize)
                let n = comp.withUnsafeBytes { src in
                    compression_decode_buffer(&dst, usize, src.bindMemory(to: UInt8.self).baseAddress!, csize, nil, COMPRESSION_ZLIB)
                }
                if n > 0 { out.append(ZipEntry(name: name, data: Data(dst[0..<n]))) }
            }
        }
        return out
    }

    // MARK: evaluation

    static let innocentFormats: Set<Format> = [.plist, .webloc, .urlFile, .terminal, .shortcut, .pdf, .office, .text]

    func evaluate(_ c: Collector, format: Format, name: String) -> DeepInspectionReport {
        var ev = c.extra
        var reports: [URLReport] = []
        let file = (name as NSString).lastPathComponent
        var seenHosts: Set<String> = []
        for ind in c.items {
            switch ind.kind {
            case .url, .domain:
                let raw = ind.kind == .domain ? "https://" + ind.value : ind.value
                let lower = raw.lowercased()
                guard lower.hasPrefix("http") || lower.hasPrefix("javascript:") || lower.hasPrefix("data:") || lower.hasPrefix("ftp") else {
                    if lower.hasPrefix("file:") || lower.hasPrefix("smb:") || lower.hasPrefix("afp:") || lower.hasPrefix("vnc:") {
                        if format == .webloc || format == .urlFile {
                            ev.append(Evidence(source: .heuristic, title: "Link file opens a local or network file",
                                detail: "\(file) points to \(ind.value) at \(ind.location); a link file that opens a file share or local program is a known trick.", score: 45))
                        }
                    }
                    continue
                }
                let r = analyzer.analyze(raw)
                let hostKey = (r.asciiHost ?? raw) + (r.brandMatch ?? "")
                guard seenHosts.insert(hostKey).inserted || r.score >= 60 else { continue }
                reports.append(r)
                var score = r.score
                var brand = r.brandMatch
                if brand == nil, let reg = r.registrableDomain, !BrandList.isLegitimate(registrableDomain: reg),
                   let label = reg.split(separator: ".").first {
                    // Combosquat the analyzer scored low ("icloud-sync.test"): a brand keyword in someone else's domain.
                    let parts = Confusables.skeleton(String(label)).split(whereSeparator: { $0 == "-" || $0 == "_" }).map(String.init)
                    if let b = parts.lazy.filter({ $0.count >= 5 }).compactMap({ BrandList.brand(forKeyword: $0) }).first, parts.count > 1 {
                        brand = b.name; score = max(score, Self.innocentFormats.contains(format) ? 60 : 50)
                    }
                }
                if r.brandMatch != nil, r.verdict != .likelySafe {
                    // A brand lookalike hidden inside a file that looks harmless is the attack in the user's threat model.
                    score = max(score, Self.innocentFormats.contains(format) ? 75 : 65)
                }
                guard score >= 30 else { continue }
                let why = r.signals.filter { $0.score > 0 }.sorted { $0.score > $1.score }.prefix(3).map(\.title).joined(separator: "; ")
                let title = brand.map { "Lookalike \($0) link inside \(file)" } ?? "Risky link inside \(file)"
                ev.append(Evidence(source: .heuristic, title: title,
                                   detail: "\(ind.value.prefix(200)) at \(ind.location). \(why)", score: min(88, score)))
            case .command:
                guard let classify = classifyCommand else { continue }
                let (s, reasons) = classify(ind.value)
                guard s >= 30 else { continue }
                ev.append(Evidence(source: .heuristic, title: "Dangerous command inside \(file)",
                                   detail: "\(ind.value.prefix(200)) at \(ind.location): \(reasons.prefix(3).joined(separator: "; "))", score: min(88, s)))
            case .ip, .scheme, .action:
                continue
            }
        }
        // Keep the strongest evidence per title to avoid one file producing hundreds of rows.
        var best: [String: Evidence] = [:]
        for e in ev where (best[e.title]?.score ?? -1) < e.score { best[e.title] = e }
        let outEv = best.values.sorted { $0.score > $1.score }
        return DeepInspectionReport(path: name, format: format.rawValue, indicators: c.items, evidence: Array(outEv.prefix(20)), urlReports: reports)
    }
}

/// FileDetector adapter for ScanCoordinator / on-write scans.
public struct DeepContentDetector: FileDetector {
    public let name = "deep-content"
    public let inspector: DeepContentInspector
    public init(inspector: DeepContentInspector) { self.inspector = inspector }
    public func inspect(_ facts: FileFacts) -> [Evidence] {
        let interesting = DeepContentInspector.isInteresting(path: facts.path) || facts.kind == .plist || facts.kind == .script
            || ((facts.kind == .machO || facts.kind == .fatMachO) && facts.signing?.status != .apple)
        guard interesting, facts.size > 0, facts.size <= 64 << 20 else { return [] }
        return inspector.inspect(path: facts.path)?.evidence ?? []
    }
}
