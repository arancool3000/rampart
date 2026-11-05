import Foundation

/// Domain blocklist with suffix semantics (a block on `bad.com` also blocks `x.bad.com`).
/// Storage: bulk lists go into a compact sorted table of reversed-label keys in one byte buffer
/// (~1.7M HaGeZi TIF domains fit in tens of MB); manual entries and the allowlist use a reversed-label trie.
/// Lookups walk the name's label suffixes. Allowlist entries override blocks for the entry and all subdomains.
/// Thread-safe.
public final class DomainBlocklist: @unchecked Sendable {
    public enum Format: String, Codable, Sendable { case hosts, adblock, plain, auto }

    public enum Verdict: Equatable, Sendable {
        case allowed
        case allowlisted(rule: String)
        case blocked(rule: String, source: String)
    }

    public struct ParseStats: Equatable, Sendable {
        public var added = 0, allowAdded = 0, skipped = 0, lines = 0
    }

    private final class Node {
        var children: [Substring: Node] = [:]
        var source: Int32 = -1      // index into `sources`, -1 = not terminal
    }

    private let lock = NSLock()
    private var blockRoot = Node()
    private var allowRoot = Node()
    private var sources: [String] = []
    private var sourceIndex: [String: Int32] = [:]
    private var table = SuffixTable()
    private var trieBlocked = 0
    public private(set) var allowedCount = 0
    public var blockedCount: Int { lock.lock(); defer { lock.unlock() }; return trieBlocked + table.count }

    public init() {}

    static let ignoredNames: Set<String> = [
        "localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "ip6-loopback",
        "ip6-localnet", "ip6-mcastprefix", "ip6-allnodes", "ip6-allrouters", "ip6-allhosts", "0.0.0.0",
    ]

    /// Lowercases, strips `*.`/leading/trailing dots and validates the hostname charset (ASCII / punycode only).
    public static func normalizeDomain(_ raw: Substring) -> String? {
        var s = raw.trimmingCharacters(in: .whitespaces).lowercased()
        if s.hasPrefix("*.") { s.removeFirst(2) }
        while s.hasPrefix(".") { s.removeFirst() }
        while s.hasSuffix(".") { s.removeLast() }
        guard !s.isEmpty, s.count <= 253, s.contains("."), !ignoredNames.contains(s) else { return nil }
        for c in s.utf8 {
            let ok = (c >= 97 && c <= 122) || (c >= 48 && c <= 57) || c == 45 || c == 46 || c == 95
            if !ok { return nil }
        }
        if s.contains("..") { return nil }
        // Bare IPv4 addresses are not domains.
        if s.split(separator: ".").allSatisfy({ $0.allSatisfy(\.isNumber) }) { return nil }
        return s
    }

    // MARK: Mutation

    public func add(_ domain: String, source: String = "manual") {
        guard let d = Self.normalizeDomain(Substring(domain)) else { return }
        lock.lock(); defer { lock.unlock() }
        if insert(d, into: blockRoot, source: index(of: source)) { trieBlocked += 1 }
    }

    public func allow(_ domain: String) {
        guard let d = Self.normalizeDomain(Substring(domain)) else { return }
        lock.lock(); defer { lock.unlock() }
        if insert(d, into: allowRoot, source: index(of: "allowlist")) { allowedCount += 1 }
    }

    public func removeAll() {
        lock.lock(); defer { lock.unlock() }
        blockRoot = Node(); allowRoot = Node(); sources = []; sourceIndex = [:]
        table = SuffixTable(); trieBlocked = 0; allowedCount = 0
    }

    /// Parses list text. `auto` detects per line: hosts (`0.0.0.0 x`), adblock (`||x^`, `@@||x^` = allow), plain (`x`, `*.x`).
    @discardableResult
    public func load(text: String, format: Format = .auto, source: String) -> ParseStats {
        var stats = ParseStats()
        var blob: [UInt8] = [], offsets: [UInt32] = [0], allows: [String] = []
        text.enumerateLines { line, _ in
            stats.lines += 1
            switch Self.parseLine(Substring(line), format: format) {
            case .block(let d):
                blob += SuffixTable.reversedKey(d); offsets.append(UInt32(blob.count))
            case .allow(let d): allows.append(d)
            case .skip: stats.skipped += 1
            case .ignore: break
            }
        }
        lock.lock(); defer { lock.unlock() }
        let idx = index(of: source), allowIdx = index(of: "allowlist")
        let before = table.count
        table = SuffixTable.merged(table, newBlob: blob, newOffsets: offsets, source: idx)
        stats.added = table.count - before
        for d in allows where insert(d, into: allowRoot, source: allowIdx) { allowedCount += 1; stats.allowAdded += 1 }
        return stats
    }

    @discardableResult
    public func load(contentsOf url: URL, format: Format = .auto, source: String? = nil) throws -> ParseStats {
        let data = try Data(contentsOf: url)
        return load(text: String(decoding: data, as: UTF8.self), format: format, source: source ?? url.lastPathComponent)
    }

    enum LineResult: Equatable { case block(String), allow(String), skip, ignore }

    static func parseLine(_ raw: Substring, format: Format) -> LineResult {
        var line = raw.trimmingCharacters(in: .whitespaces)[...]
        if line.isEmpty || line.hasPrefix("#") || line.hasPrefix("!") || line.hasPrefix("[") { return .ignore }
        // Adblock cosmetic/scriptlet rules (`example.com##.banner`, `#@#`, `#?#`, `#$#`) are not DNS rules.
        if line.contains("##") || line.contains("#@#") || line.contains("#?#") || line.contains("#$#") { return .skip }
        // Inline comments must be preceded by whitespace (hosts style: `0.0.0.0 x # note`).
        if let r = line.range(of: " #") ?? line.range(of: "\t#") { line = line[..<r.lowerBound] }
        line = line.trimmingCharacters(in: .whitespaces)[...]
        if line.isEmpty { return .ignore }

        let isAdblock = line.hasPrefix("||") || line.hasPrefix("@@||")
        if format == .adblock || (format == .auto && isAdblock) {
            var allow = false
            if line.hasPrefix("@@") { allow = true; line = line.dropFirst(2) }
            guard line.hasPrefix("||") else { return .skip }
            line = line.dropFirst(2)
            if let dollar = line.firstIndex(of: "$") {
                // Only accept option-free or `$important` DNS rules; anything else is a cosmetic/URL rule.
                let opts = line[line.index(after: dollar)...]
                guard opts == "important" else { return .skip }
                line = line[..<dollar]
            }
            guard line.hasSuffix("^") else { return .skip }
            line = line.dropLast()
            if line.contains("/") || line.contains("*") { return .skip }
            guard let d = normalizeDomain(line) else { return .skip }
            return allow ? .allow(d) : .block(d)
        }

        let fields = line.split(whereSeparator: { $0 == " " || $0 == "\t" })
        if fields.count >= 2 || format == .hosts {
            // hosts: first field is an IP; take the first hostname (lists put one per line).
            guard fields.count >= 2, DNSWire.addressBytes(String(fields[0])) != nil else { return .skip }
            guard let d = normalizeDomain(fields[1]) else { return .skip }
            return .block(d)
        }
        guard let d = normalizeDomain(fields[0]) else { return .skip }
        return .block(d)
    }

    // MARK: Lookup

    public func verdict(for name: String) -> Verdict {
        let n = DNSWire.normalize(name)
        lock.lock(); defer { lock.unlock() }
        if let (rule, _) = match(n, in: allowRoot) { return .allowlisted(rule: rule) }
        if let (rule, src) = match(n, in: blockRoot) { return .blocked(rule: rule, source: sources[Int(src)]) }
        if let (rule, src) = table.match(n) { return .blocked(rule: rule, source: sources[Int(src)]) }
        return .allowed
    }

    public func isBlocked(_ name: String) -> Bool {
        if case .blocked = verdict(for: name) { return true }
        return false
    }

    // MARK: Internals (call with lock held)

    private func index(of source: String) -> Int32 {
        if let i = sourceIndex[source] { return i }
        sources.append(source)
        let i = Int32(sources.count - 1); sourceIndex[source] = i
        return i
    }

    /// Returns true if a new terminal was created.
    private func insert(_ domain: String, into root: Node, source: Int32) -> Bool {
        var node = root
        for label in domain.split(separator: ".").reversed() {
            if node.source >= 0 { return false }   // a parent is already blocked: subdomain is redundant
            if let next = node.children[label] { node = next } else {
                let next = Node(); node.children[label] = next; node = next
            }
        }
        if node.source >= 0 { return false }
        node.source = source
        node.children = [:]   // children are now redundant
        return true
    }

    private func match(_ name: String, in root: Node) -> (String, Int32)? {
        let labels = name.split(separator: ".")
        var node = root
        var depth = 0
        for label in labels.reversed() {
            guard let next = node.children[label] else { return nil }
            node = next; depth += 1
            if node.source >= 0 {
                return (labels.suffix(depth).joined(separator: "."), node.source)
            }
        }
        return nil
    }
}

/// Immutable sorted table of reversed-label keys ("com.example.ads") packed into one buffer.
struct SuffixTable {
    private(set) var blob: [UInt8] = []
    private(set) var offsets: [UInt32] = [0]     // count + 1 entries
    private(set) var sources: [Int32] = []
    var count: Int { sources.count }

    static func reversedKey(_ domain: String) -> [UInt8] {
        Array(domain.split(separator: ".").reversed().joined(separator: ".").utf8)
    }

    /// Merges new keys (unsorted, possibly duplicated) into `old`. Existing keys keep their original source.
    static func merged(_ old: SuffixTable, newBlob: [UInt8], newOffsets: [UInt32], source: Int32) -> SuffixTable {
        var blob = old.blob
        var offs = old.offsets
        var srcs = old.sources
        let base = UInt32(blob.count)
        blob += newBlob
        for o in newOffsets.dropFirst() { offs.append(base + o) }
        srcs += [Int32](repeating: source, count: newOffsets.count - 1)
        let n = srcs.count
        var order = [Int32](0..<Int32(n))
        return blob.withUnsafeBufferPointer { b -> SuffixTable in
            offs.withUnsafeBufferPointer { o -> SuffixTable in
                func cmp(_ i: Int32, _ j: Int32) -> Int32 {
                    let (s1, e1) = (Int(o[Int(i)]), Int(o[Int(i) + 1])), (s2, e2) = (Int(o[Int(j)]), Int(o[Int(j) + 1]))
                    let l1 = e1 - s1, l2 = e2 - s2
                    let c = memcmp(b.baseAddress! + s1, b.baseAddress! + s2, min(l1, l2))
                    if c != 0 { return c }
                    return Int32(l1 - l2)
                }
                // Stable on ties so the earlier (older) source wins during dedupe.
                order.sort { a, c in let r = cmp(a, c); return r < 0 || (r == 0 && a < c) }
                var out = SuffixTable()
                out.blob.reserveCapacity(blob.count)
                var last: Int32 = -1
                for i in order {
                    if last >= 0, cmp(last, i) == 0 { continue }
                    last = i
                    out.blob.append(contentsOf: b[Int(o[Int(i)])..<Int(o[Int(i) + 1])])
                    out.offsets.append(UInt32(out.blob.count))
                    out.sources.append(srcs[Int(i)])
                }
                return out
            }
        }
    }

    private func find(_ key: ArraySlice<UInt8>) -> Int? {
        var lo = 0, hi = count - 1
        return blob.withUnsafeBufferPointer { b -> Int? in
            key.withUnsafeBufferPointer { k -> Int? in
                while lo <= hi {
                    let mid = (lo + hi) / 2
                    let s = Int(offsets[mid]), l = Int(offsets[mid + 1]) - s
                    var c = memcmp(b.baseAddress! + s, k.baseAddress!, min(l, k.count))
                    if c == 0 { c = Int32(l - k.count) }
                    if c == 0 { return mid }
                    if c < 0 { lo = mid + 1 } else { hi = mid - 1 }
                }
                return nil
            }
        }
    }

    /// Shortest blocked suffix of `name` (already normalised), as (rule, source).
    func match(_ name: String) -> (String, Int32)? {
        guard count > 0 else { return nil }
        let key = Self.reversedKey(name)
        var i = 0
        while i <= key.count {
            if i == key.count || key[i] == UInt8(ascii: ".") {
                if let idx = find(key[0..<i]) {
                    let rule = String(decoding: key[0..<i], as: UTF8.self).split(separator: ".").reversed().joined(separator: ".")
                    return (rule, sources[idx])
                }
            }
            i += 1
        }
        return nil
    }
}
