import Foundation
import CryptoKit

public struct YaraScanOptions: Sendable {
    /// Files larger than this are not scanned (result has `skippedReason`).
    public var maxFileSize: UInt64
    /// Per-file wall-clock budget; scans that exceed it stop and report `timedOut`.
    public var timeout: TimeInterval
    /// Per-string match cap (YARA's is 1,000,000; lower keeps memory bounded).
    public var maxMatchesPerString: Int
    public init(maxFileSize: UInt64 = 100 * 1024 * 1024, timeout: TimeInterval = 5, maxMatchesPerString: Int = 10_000) {
        self.maxFileSize = maxFileSize; self.timeout = timeout; self.maxMatchesPerString = maxMatchesPerString
    }
}

public struct YaraStringMatch: Sendable, Hashable, Codable {
    public var identifier: String
    public var offset: Int
    public var length: Int
}

public struct YaraMatch: Sendable, Hashable, Codable {
    public var rule: String
    public var namespace: String
    public var tags: [String]
    public var meta: [String: String]
    public var strings: [YaraStringMatch]     // first few matches per string
    public init(rule: String, namespace: String, tags: [String] = [], meta: [String: String] = [:], strings: [YaraStringMatch] = []) {
        self.rule = rule; self.namespace = namespace; self.tags = tags; self.meta = meta; self.strings = strings
    }
}

public struct YaraScanResult: Sendable {
    public var matches: [YaraMatch]
    public var timedOut: Bool
    public var skippedReason: String?
    public var bytesScanned: Int
    public var seconds: Double
}

struct SMatch { var off: Int; var len: Int }

private struct TimedOut: Error {}

extension YaraRules {
    /// Scans a file. The file is memory-mapped read-only; files over `options.maxFileSize` are skipped.
    public func scanFile(atPath path: String, options: YaraScanOptions = .init(), externals: [String: YaraExternal] = [:]) -> YaraScanResult {
        let t0 = Date()
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
        guard fd >= 0 else { return YaraScanResult(matches: [], timedOut: false, skippedReason: "open failed: \(String(cString: strerror(errno)))", bytesScanned: 0, seconds: 0) }
        defer { close(fd) }
        var sb = stat()
        guard fstat(fd, &sb) == 0 else { return YaraScanResult(matches: [], timedOut: false, skippedReason: "stat failed", bytesScanned: 0, seconds: 0) }
        guard (sb.st_mode & S_IFMT) == S_IFREG else { return YaraScanResult(matches: [], timedOut: false, skippedReason: "not a regular file", bytesScanned: 0, seconds: 0) }
        let size = Int(sb.st_size)
        if UInt64(size) > options.maxFileSize {
            return YaraScanResult(matches: [], timedOut: false, skippedReason: "file larger than \(options.maxFileSize) bytes", bytesScanned: 0, seconds: 0)
        }
        if size == 0 {
            return [UInt8]().withUnsafeBufferPointer { scan($0, options: options, externals: externals, start: t0) }
        }
        guard let p = mmap(nil, size, PROT_READ, MAP_PRIVATE, fd, 0), p != MAP_FAILED else {
            return YaraScanResult(matches: [], timedOut: false, skippedReason: "mmap failed", bytesScanned: 0, seconds: 0)
        }
        defer { munmap(p, size) }
        let buf = UnsafeBufferPointer(start: p.assumingMemoryBound(to: UInt8.self), count: size)
        return scan(buf, options: options, externals: externals, start: t0)
    }

    /// Scans an in-memory buffer.
    public func scan(_ data: [UInt8], options: YaraScanOptions = .init(), externals: [String: YaraExternal] = [:]) -> YaraScanResult {
        data.withUnsafeBufferPointer { scan($0, options: options, externals: externals, start: Date()) }
    }

    func scan(_ data: UnsafeBufferPointer<UInt8>, options: YaraScanOptions, externals: [String: YaraExternal], start: Date) -> YaraScanResult {
        let ctx = ScanContext(rules: self, data: data, options: options, externals: externals, start: start)
        var timedOut = false
        do {
            try ctx.searchStrings()
            try ctx.evaluate()
        } catch { timedOut = true }
        let matches = timedOut ? [] : ctx.collectMatches()
        return YaraScanResult(matches: matches, timedOut: timedOut, skippedReason: nil, bytesScanned: data.count,
                              seconds: Date().timeIntervalSince(start))
    }
}

/// Per-scan mutable state. Never shared across threads.
final class ScanContext {
    let r: YaraRules
    let data: UnsafeBufferPointer<UInt8>
    let n: Int
    let options: YaraScanOptions
    let externals: [String: YaraExternal]
    let deadline: Date
    var matches: [[SMatch]]
    var lastTried: [Int]
    var results: [Bool]
    var slots: [Int64]
    var current: [Int] = []
    var hashCache: [String: [UInt8]] = [:]
    var macho: MachOInfo??
    var budgetCounter = 0
    var hexBudget = 0

    init(rules: YaraRules, data: UnsafeBufferPointer<UInt8>, options: YaraScanOptions, externals: [String: YaraExternal], start: Date) {
        r = rules; self.data = data; n = data.count; self.options = options
        var ext = rules.defaultExternals
        for (k, v) in externals { ext[k] = v }
        self.externals = ext
        deadline = start.addingTimeInterval(options.timeout)
        matches = Array(repeating: [], count: rules.strings.count)
        lastTried = Array(repeating: -1, count: rules.patterns.count)
        results = Array(repeating: false, count: rules.rules.count)
        slots = Array(repeating: 0, count: max(1, rules.maxSlots))
    }

    @inline(__always) func tick(_ cost: Int = 1) throws {
        budgetCounter &+= cost
        if budgetCounter >= 1 << 16 {
            budgetCounter = 0
            if Date() > deadline { throw TimedOut() }
        }
    }

    // MARK: String search

    static let fold: [UInt8] = (0...255).map { lowerByte(UInt8($0)) }

    func searchStrings() throws {
        guard !r.patterns.isEmpty, n > 0 else { return }
        let fold = ScanContext.fold
        try r.acNext.withUnsafeBufferPointer { next in
            try r.acOutCount.withUnsafeBufferPointer { outCount in
                try fold.withUnsafeBufferPointer { fold in
                    var s = 0
                    var i = 0
                    while i < n {
                        let chunkEnd = min(n, i + (1 << 18))
                        while i < chunkEnd {
                            s = Int(next[s << 8 | Int(fold[Int(data[i])])])
                            if outCount[s] != 0 { try onHit(state: s, end: i) }
                            i += 1
                        }
                        if Date() > deadline { throw TimedOut() }
                    }
                }
            }
        }
        for p in r.unanchored { try fullScan(p) }
        for k in matches.indices where matches[k].count > 1 {
            matches[k].sort { $0.off < $1.off }
            var out: [SMatch] = []
            out.reserveCapacity(matches[k].count)
            for m in matches[k] where out.last?.off != m.off { out.append(m) }
            matches[k] = out
        }
    }

    func onHit(state s: Int, end i: Int) throws {
        let start = Int(r.acOutStart[s]), cnt = Int(r.acOutCount[s])
        for k in start..<(start + cnt) {
            let atom = Int(r.acOutAtoms[k])
            for pid32 in r.atomPatterns[atom] {
                let pid = Int(pid32)
                let p = r.patterns[pid]
                let atomStart = i - p.atomLen + 1
                let hi = atomStart - p.dMin
                if hi < 0 || hi <= lastTried[pid] { continue }
                var lo = p.dMax == Int.max ? 0 : atomStart - p.dMax
                lo = max(lo, lastTried[pid] + 1, 0)
                lastTried[pid] = hi
                if matches[p.stringID].count >= options.maxMatchesPerString { continue }
                if lo > hi { continue }
                for st in lo...hi {
                    if p.firstByte >= 0 && Int(data[st]) != p.firstByte && !(p.isNocaseLiteral && lowerByte(data[st]) == lowerByte(UInt8(p.firstByte))) { continue }
                    try tick()
                    if let len = try verify(p, at: st) { matches[p.stringID].append(SMatch(off: st, len: len)) }
                }
            }
        }
    }

    func fullScan(_ pid: Int) throws {
        let p = r.patterns[pid]
        var st = 0
        while st < n {
            if p.firstByte >= 0 {
                guard let q = memchr(data.baseAddress! + st, Int32(p.firstByte), n - st) else { break }
                st = data.baseAddress!.distance(to: q.assumingMemoryBound(to: UInt8.self))
            }
            try tick()
            if let len = try verify(p, at: st) {
                matches[p.stringID].append(SMatch(off: st, len: len))
                if matches[p.stringID].count >= options.maxMatchesPerString { break }
            }
            st += 1
        }
    }

    /// Verifies a pattern anchored at `st`; returns the match length.
    func verify(_ p: Pattern, at st: Int) throws -> Int? {
        var len: Int?
        switch p.kind {
        case .literal(let bytes, let nocase):
            let m = bytes.count
            guard st + m <= n else { return nil }
            if nocase {
                for j in 0..<m where lowerByte(data[st + j]) != lowerByte(bytes[j]) { return nil }
            } else {
                for j in 0..<m where data[st + j] != bytes[j] { return nil }
            }
            len = m
        case .hex(let elems):
            hexBudget = 200_000
            len = hexMatch(elems, 0, st) { $0 }.map { $0 - st }
            try tick(200_000 - max(0, hexBudget))
        case .regex(let prog):
            var budget = 200_000
            len = prog.match(data, at: st, wide: p.wide, budget: &budget).map { $0 - st }
            try tick(200_000 - max(0, budget))
        }
        guard let l = len else { return nil }
        if p.fullword {
            let w = p.wide ? 2 : 1
            if st - w >= 0 && isWordByte(data[st - w]) && (!p.wide || data[st - 1] == 0) { return nil }
            if st + l < n && isWordByte(data[st + l]) && (!p.wide || (st + l + 1 < n && data[st + l + 1] == 0)) { return nil }
        }
        return l
    }

    func hexMatch(_ e: [HexElem], _ i0: Int, _ pos0: Int, _ k: (Int) -> Int?) -> Int? {
        var i = i0, pos = pos0
        while i < e.count {
            hexBudget -= 1
            if hexBudget < 0 { return nil }
            switch e[i] {
            case .bytes(let v, let m, let neg):
                let c = v.count
                guard pos + c <= n else { return nil }
                for j in 0..<c {
                    let eq = (data[pos + j] & m[j]) == v[j]
                    if eq == neg[j] { return nil }
                }
                pos += c
                i += 1
            case .jump(let mn, let mx):
                let upper = mx == Int.max ? n - pos : min(mx, n - pos)
                if mn > upper { return nil }
                var fb = -1
                if i + 1 < e.count, case .bytes(let v, let m, let neg) = e[i + 1], m[0] == 0xFF, !neg[0] { fb = Int(v[0]) }
                for j in mn...upper {
                    if fb >= 0 && (pos + j >= n || Int(data[pos + j]) != fb) { continue }
                    if let r = hexMatch(e, i + 1, pos + j, k) { return r }
                    if hexBudget < 0 { return nil }
                }
                return nil
            case .alt(let branches):
                for b in branches {
                    if let r = hexMatch(b, 0, pos, { p in self.hexMatch(e, i + 1, p, k) }) { return r }
                    if hexBudget < 0 { return nil }
                }
                return nil
            }
        }
        return k(pos)
    }

    // MARK: Evaluation

    func evaluate() throws {
        var globalFailed: Set<String> = []
        for (idx, rule) in r.rules.enumerated() {
            if globalFailed.contains(rule.namespace) { results[idx] = false; continue }
            results[idx] = try eval(rule.condition).truthy
            if rule.isGlobal && !results[idx] { globalFailed.insert(rule.namespace) }
        }
        if !globalFailed.isEmpty {
            for (idx, rule) in r.rules.enumerated() where globalFailed.contains(rule.namespace) { results[idx] = false }
        }
    }

    func collectMatches() -> [YaraMatch] {
        var out: [YaraMatch] = []
        for (idx, rule) in r.rules.enumerated() where results[idx] && !rule.isPrivate {
            var sm: [YaraStringMatch] = []
            for sid in rule.stringIDs {
                for m in matches[sid].prefix(4) { sm.append(YaraStringMatch(identifier: r.strings[sid].identifier, offset: m.off, length: m.len)) }
            }
            let info = r.ruleInfos[idx]
            out.append(YaraMatch(rule: rule.name, namespace: rule.namespace, tags: rule.tags, meta: info.meta, strings: sm))
        }
        return out
    }

    @inline(__always) func sid(_ id: Int) -> Int { id >= 0 ? id : (current.last ?? 0) }

    func found(_ id: Int, lo: Int64? = nil, hi: Int64? = nil) -> Bool {
        let ms = matches[sid(id)]
        guard let lo = lo, let hi = hi else { return !ms.isEmpty }
        return ms.contains { Int64($0.off) >= lo && Int64($0.off) <= hi }
    }

    func compareValues(_ op: CmpOp, _ a: YValue, _ b: YValue) -> YValue {
        if let x = a.int, let y = b.int {
            switch op {
            case .eq: return .bool(x == y)
            case .ne: return .bool(x != y)
            case .lt: return .bool(x < y)
            case .le: return .bool(x <= y)
            case .gt: return .bool(x > y)
            case .ge: return .bool(x >= y)
            }
        }
        if case .str(let x) = a, case .str(let y) = b {
            switch op {
            case .eq: return .bool(x == y)
            case .ne: return .bool(x != y)
            case .lt: return .bool(x.lexicographicallyPrecedes(y))
            case .le: return .bool(!y.lexicographicallyPrecedes(x))
            case .gt: return .bool(y.lexicographicallyPrecedes(x))
            case .ge: return .bool(!x.lexicographicallyPrecedes(y))
            }
        }
        return .undefined
    }

    func quantify(_ q: Quantifier, total: Int, _ test: (Int) throws -> Bool) throws -> Bool {
        switch q {
        case .all:
            guard total > 0 else { return false }
            for k in 0..<total where try !test(k) { return false }
            return true
        case .any:
            for k in 0..<total where try test(k) { return true }
            return false
        case .none:
            for k in 0..<total where try test(k) { return false }
            return true
        case .count(let e), .percent(let e):
            guard var need = try eval(e).int else { return false }
            if case .percent = q { need = Int64((Double(need) * Double(total) / 100.0).rounded(.up)) }
            if need <= 0 {
                for k in 0..<total where try test(k) { return false }
                return true
            }
            if need > total { return false }
            var c: Int64 = 0
            for k in 0..<total where try test(k) { c += 1; if c >= need { return true } }
            return false
        }
    }

    func readInt(_ rd: IntReader, be: Bool, _ off: Int64) -> YValue {
        let sz = rd.size
        guard off >= 0, off <= Int64(n - sz) else { return .undefined }
        let o = Int(off)
        var v: UInt64 = 0
        for j in 0..<sz {
            let b = UInt64(data[o + j])
            v |= be ? b << UInt64(8 * (sz - 1 - j)) : b << UInt64(8 * j)
        }
        if rd.signed {
            let shift = UInt64(64 - 8 * sz)
            return .int(Int64(bitPattern: v << shift) >> Int64(shift))
        }
        return .int(Int64(v))
    }

    func hashBytes(_ fn: HashFn, _ bytes: UnsafeRawBufferPointer) -> [UInt8] {
        func hex<D: Sequence>(_ d: D) -> [UInt8] where D.Element == UInt8 { Array(d.map { String(format: "%02x", $0) }.joined().utf8) }
        switch fn {
        case .md5: return hex(Insecure.MD5.hash(data: bytes))
        case .sha1: return hex(Insecure.SHA1.hash(data: bytes))
        case .sha256: return hex(SHA256.hash(data: bytes))
        case .crc32: return []
        }
    }

    func crc32(_ bytes: UnsafeRawBufferPointer) -> Int64 {
        var c: UInt32 = 0xFFFFFFFF
        for b in bytes { c ^= UInt32(b); for _ in 0..<8 { c = (c >> 1) ^ (0xEDB88320 & (0 &- (c & 1))) } }
        return Int64(~c)
    }

    func eval(_ e: Expr) throws -> YValue {
        try tick()
        switch e {
        case .boolLit(let b): return .bool(b)
        case .intLit(let i): return .int(i)
        case .strLit(let s): return .str(s)
        case .filesize: return .int(Int64(n))
        case .stringFound(let id): return .bool(found(id))
        case .stringAt(let id, let ex):
            guard let o = try eval(ex).int else { return .undefined }
            return .bool(matches[sid(id)].contains { Int64($0.off) == o })
        case .stringIn(let id, let a, let b):
            guard let lo = try eval(a).int, let hi = try eval(b).int else { return .undefined }
            return .bool(found(id, lo: lo, hi: hi))
        case .stringCount(let id): return .int(Int64(matches[sid(id)].count))
        case .stringCountIn(let id, let a, let b):
            guard let lo = try eval(a).int, let hi = try eval(b).int else { return .undefined }
            return .int(Int64(matches[sid(id)].filter { Int64($0.off) >= lo && Int64($0.off) <= hi }.count))
        case .stringOffset(let id, let ix), .stringLength(let id, let ix):
            guard let k = try eval(ix).int else { return .undefined }
            let ms = matches[sid(id)]
            guard k >= 1, k <= Int64(ms.count) else { return .undefined }
            if case .stringOffset = e { return .int(Int64(ms[Int(k) - 1].off)) }
            return .int(Int64(ms[Int(k) - 1].len))
        case .ruleRef(let i): return .bool(results[i])
        case .not(let x):
            let v = try eval(x)
            if case .undefined = v { return .undefined }
            return .bool(!v.truthy)
        case .and(let xs):
            for x in xs where try !eval(x).truthy { return .bool(false) }
            return .bool(true)
        case .or(let xs):
            for x in xs where try eval(x).truthy { return .bool(true) }
            return .bool(false)
        case .cmp(let op, let a, let b):
            return compareValues(op, try eval(a), try eval(b))
        case .arith(let op, let a, let b):
            guard let x = try eval(a).int, let y = try eval(b).int else { return .undefined }
            switch op {
            case .add: return .int(x &+ y)
            case .sub: return .int(x &- y)
            case .mul: return .int(x &* y)
            case .div: return y == 0 ? .undefined : .int(x / y)
            case .mod: return y == 0 ? .undefined : .int(x % y)
            case .band: return .int(x & y)
            case .bor: return .int(x | y)
            case .bxor: return .int(x ^ y)
            case .shl: return y < 0 ? .undefined : .int(y >= 64 ? 0 : x << y)
            case .shr: return y < 0 ? .undefined : .int(y >= 64 ? 0 : x >> y)
            }
        case .neg(let x): guard let v = try eval(x).int else { return .undefined }; return .int(0 &- v)
        case .bitnot(let x): guard let v = try eval(x).int else { return .undefined }; return .int(~v)
        case .readInt(let rd, let be, let off):
            guard let o = try eval(off).int else { return .undefined }
            return readInt(rd, be: be, o)
        case .ofStrings(let q, let ids, let range, let at):
            var lo: Int64? = nil, hi: Int64? = nil, atOff: Int64? = nil
            if let (a, b) = range { guard let x = try eval(a).int, let y = try eval(b).int else { return .undefined }; lo = x; hi = y }
            if let a = at { guard let x = try eval(a).int else { return .undefined }; atOff = x }
            return .bool(try quantify(q, total: ids.count) { k in
                if let o = atOff { return self.matches[ids[k]].contains { Int64($0.off) == o } }
                return self.found(ids[k], lo: lo, hi: hi)
            })
        case .ofRules(let q, let ids):
            return .bool(try quantify(q, total: ids.count) { self.results[ids[$0]] })
        case .forOf(let q, let ids, let body):
            return .bool(try quantify(q, total: ids.count) { k in
                self.current.append(ids[k]); defer { self.current.removeLast() }
                return try self.eval(body).truthy
            })
        case .forIn(let q, let slot, let iter, let body):
            switch iter {
            case .range(let a, let b):
                guard let lo = try eval(a).int, let hi = try eval(b).int else { return .bool(false) }
                guard hi >= lo, hi - lo < 10_000_000 else { return .bool(false) }
                return .bool(try quantify(q, total: Int(hi - lo + 1)) { k in
                    self.slots[slot] = lo + Int64(k)
                    return try self.eval(body).truthy
                })
            case .list(let items):
                return .bool(try quantify(q, total: items.count) { k in
                    guard let v = try self.eval(items[k]).int else { return false }
                    self.slots[slot] = v
                    return try self.eval(body).truthy
                })
            }
        case .variable(let slot): return .int(slots[slot])
        case .hash(let fn, let a, let b):
            guard let off = try eval(a).int, let len = try eval(b).int, off >= 0, len >= 0, off + len <= Int64(n) else { return .undefined }
            let slice = UnsafeRawBufferPointer(rebasing: UnsafeRawBufferPointer(data)[Int(off)..<Int(off + len)])
            if fn == .crc32 { return .int(crc32(slice)) }
            let key = "\(fn.rawValue):\(off):\(len)"
            if let c = hashCache[key] { return .str(c) }
            let h = hashBytes(fn, slice)
            try tick(Int(len) / 64)
            hashCache[key] = h
            return .str(h)
        case .hashString(let fn, let a):
            guard case .str(let s) = try eval(a) else { return .undefined }
            if fn == .crc32 { return .int(s.withUnsafeBytes { crc32($0) }) }
            return .str(s.withUnsafeBytes { hashBytes(fn, $0) })
        case .strOp(let op, let a, let b):
            guard case .str(var x) = try eval(a), case .str(var y) = try eval(b) else { return .undefined }
            if [.icontains, .istartswith, .iendswith, .iequals].contains(op) { x = x.map(lowerByte); y = y.map(lowerByte) }
            switch op {
            case .contains, .icontains:
                if y.isEmpty { return .bool(true) }
                guard x.count >= y.count else { return .bool(false) }
                for s in 0...(x.count - y.count) where x[s..<s + y.count].elementsEqual(y) { return .bool(true) }
                return .bool(false)
            case .startswith, .istartswith: return .bool(x.starts(with: y))
            case .endswith, .iendswith: return .bool(x.count >= y.count && x[(x.count - y.count)...].elementsEqual(y))
            case .iequals: return .bool(x == y)
            }
        case .matches(let a, let prog):
            guard case .str(let x) = try eval(a) else { return .undefined }
            return .bool(prog.search(x))
        case .external(let name):
            switch externals[name] {
            case .int(let i)?: return .int(i)
            case .bool(let b)?: return .bool(b)
            case .string(let s)?: return .str(Array(s.utf8))
            case nil: return .undefined
            }
        case .machoField(let name):
            if macho == nil { macho = .some(MachOInfo.parse(data)) }
            guard let info = macho!, let v = info.values[name] else { return .undefined }
            return .int(v)
        case .defined(let x):
            if case .undefined = try eval(x) { return .bool(false) }
            return .bool(true)
        }
    }
}

extension Pattern {
    var isNocaseLiteral: Bool { if case .literal(_, true) = kind { return true }; return false }
}
