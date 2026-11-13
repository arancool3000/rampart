import Foundation

/// Byte-oriented regular expressions with YARA syntax, compiled to a small backtracking VM.
/// Operates on raw bytes (no String conversion), supports `wide` matching (each char followed by 0x00),
/// and enforces a step budget so pathological patterns cannot hang a scan.
struct RegexError: Error, CustomStringConvertible { let description: String }

indirect enum RNode {
    case lit(UInt8)
    case set(ByteSet)
    case any(dotall: Bool)
    case concat([RNode])
    case alt([RNode])
    case rep(RNode, min: Int, max: Int?, greedy: Bool)
    case bol, eol, wordB, nonWordB
}

struct ByteSet: Hashable {
    var w: (UInt64, UInt64, UInt64, UInt64) = (0, 0, 0, 0)
    static func == (a: ByteSet, b: ByteSet) -> Bool { a.w == b.w }
    func hash(into h: inout Hasher) { h.combine(w.0); h.combine(w.1); h.combine(w.2); h.combine(w.3) }
    @inline(__always) func contains(_ b: UInt8) -> Bool {
        let bit = UInt64(1) << UInt64(b & 63)
        switch b >> 6 {
        case 0: return w.0 & bit != 0
        case 1: return w.1 & bit != 0
        case 2: return w.2 & bit != 0
        default: return w.3 & bit != 0
        }
    }
    mutating func insert(_ b: UInt8) {
        let bit = UInt64(1) << UInt64(b & 63)
        switch b >> 6 {
        case 0: w.0 |= bit
        case 1: w.1 |= bit
        case 2: w.2 |= bit
        default: w.3 |= bit
        }
    }
    mutating func insertRange(_ a: UInt8, _ b: UInt8) { if a <= b { for c in a...b { insert(c) } } }
    mutating func invert() { w = (~w.0, ~w.1, ~w.2, ~w.3) }
    mutating func formUnion(_ o: ByteSet) { w = (w.0 | o.w.0, w.1 | o.w.1, w.2 | o.w.2, w.3 | o.w.3) }
    var count: Int { w.0.nonzeroBitCount + w.1.nonzeroBitCount + w.2.nonzeroBitCount + w.3.nonzeroBitCount }
    var members: [UInt8] { (0...255).compactMap { contains(UInt8($0)) ? UInt8($0) : nil } }

    static let word: ByteSet = { var s = ByteSet(); s.insertRange(0x30, 0x39); s.insertRange(0x41, 0x5A); s.insertRange(0x61, 0x7A); s.insert(0x5F); return s }()
    static let digit: ByteSet = { var s = ByteSet(); s.insertRange(0x30, 0x39); return s }()
    static let space: ByteSet = { var s = ByteSet(); for c: UInt8 in [0x20, 0x09, 0x0A, 0x0B, 0x0C, 0x0D] { s.insert(c) }; return s }()
}

@inline(__always) func isAlpha(_ c: UInt8) -> Bool { (c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) }
@inline(__always) func lowerByte(_ c: UInt8) -> UInt8 { (c >= 0x41 && c <= 0x5A) ? c | 0x20 : c }
@inline(__always) func isWordByte(_ c: UInt8) -> Bool { ByteSet.word.contains(c) }

// MARK: - Parser

private struct RegexParser {
    let s: [UInt8]
    var i = 0
    let nocase: Bool
    let dotall: Bool
    /// Group nesting so far (bounded: deep nesting would overflow the stack in the parser and tree walks).
    var depth = 0

    init(_ s: [UInt8], nocase: Bool, dotall: Bool) { self.s = s; self.nocase = nocase; self.dotall = dotall }

    var atEnd: Bool { i >= s.count }
    func peek() -> UInt8? { i < s.count ? s[i] : nil }

    mutating func parseAlt() throws -> RNode {
        var branches = [try parseConcat()]
        while peek() == UInt8(ascii: "|") { i += 1; branches.append(try parseConcat()) }
        return branches.count == 1 ? branches[0] : .alt(branches)
    }

    mutating func parseConcat() throws -> RNode {
        var items: [RNode] = []
        while let c = peek(), c != UInt8(ascii: "|"), c != UInt8(ascii: ")") {
            var atom = try parseAtom()
            atom = try parseQuantifiers(atom)
            items.append(atom)
        }
        return items.count == 1 ? items[0] : .concat(items)
    }

    mutating func parseQuantifiers(_ base: RNode) throws -> RNode {
        var node = base
        while let c = peek() {
            var mn = 0, mx: Int? = nil
            if c == UInt8(ascii: "*") { i += 1 }
            else if c == UInt8(ascii: "+") { i += 1; mn = 1 }
            else if c == UInt8(ascii: "?") { i += 1; mx = 1 }
            else if c == UInt8(ascii: "{") {
                // {n}, {n,}, {,m}, {n,m}; if not a valid quantifier treat '{' literally
                let save = i
                i += 1
                let a = readInt()
                var b: Int?? = .none
                if peek() == UInt8(ascii: ",") { i += 1; b = .some(readInt()) }
                guard peek() == UInt8(ascii: "}"), a != nil || b != nil else { i = save; return node }
                i += 1
                mn = a ?? 0
                switch b { case .none: mx = mn; case .some(let v): mx = v }
                if let m = mx, m < mn { throw RegexError(description: "bad repeat range") }
                if mn > 1000 || (mx ?? 0) > 1000 { throw RegexError(description: "repeat too large") }
            } else { break }
            var greedy = true
            if peek() == UInt8(ascii: "?") { i += 1; greedy = false }
            node = .rep(node, min: mn, max: mx, greedy: greedy)
        }
        return node
    }

    mutating func readInt() -> Int? {
        var v = 0, any = false
        while let c = peek(), c >= 0x30, c <= 0x39 { v = v * 10 + Int(c - 0x30); i += 1; any = true; if v > 100000 { break } }
        return any ? v : nil
    }

    func litNode(_ c: UInt8) -> RNode {
        if nocase && isAlpha(c) { var set = ByteSet(); set.insert(c | 0x20); set.insert(c & ~0x20); return .set(set) }
        return .lit(c)
    }

    func caseFold(_ set: ByteSet) -> ByteSet {
        guard nocase else { return set }
        var out = set
        for c in set.members where isAlpha(c) { out.insert(c | 0x20); out.insert(c & ~0x20) }
        return out
    }

    mutating func parseAtom() throws -> RNode {
        let c = s[i]; i += 1
        switch c {
        case UInt8(ascii: "("):
            if peek() == UInt8(ascii: "?") {
                // (?: ...) non-capturing group is the only extension we accept
                guard i + 1 < s.count, s[i + 1] == UInt8(ascii: ":") else { throw RegexError(description: "unsupported group extension") }
                i += 2
            }
            depth += 1
            defer { depth -= 1 }
            if depth > 64 { throw RegexError(description: "groups nested too deeply") }
            let inner = try parseAlt()
            guard peek() == UInt8(ascii: ")") else { throw RegexError(description: "missing )") }
            i += 1
            return inner
        case UInt8(ascii: "["): return .set(caseFold(try parseClass()))
        case UInt8(ascii: "."): return .any(dotall: dotall)
        case UInt8(ascii: "^"): return .bol
        case UInt8(ascii: "$"): return .eol
        case UInt8(ascii: "\\"):
            guard let e = peek() else { throw RegexError(description: "trailing backslash") }
            i += 1
            switch e {
            case UInt8(ascii: "w"): return .set(ByteSet.word)
            case UInt8(ascii: "W"): var s = ByteSet.word; s.invert(); return .set(s)
            case UInt8(ascii: "d"): return .set(ByteSet.digit)
            case UInt8(ascii: "D"): var s = ByteSet.digit; s.invert(); return .set(s)
            case UInt8(ascii: "s"): return .set(ByteSet.space)
            case UInt8(ascii: "S"): var s = ByteSet.space; s.invert(); return .set(s)
            case UInt8(ascii: "b"): return .wordB
            case UInt8(ascii: "B"): return .nonWordB
            default: return litNode(try escapeByte(e))
            }
        case UInt8(ascii: "*"), UInt8(ascii: "+"), UInt8(ascii: "?"):
            throw RegexError(description: "quantifier without operand")
        default:
            return litNode(c)
        }
    }

    mutating func escapeByte(_ e: UInt8) throws -> UInt8 {
        switch e {
        case UInt8(ascii: "n"): return 0x0A
        case UInt8(ascii: "t"): return 0x09
        case UInt8(ascii: "r"): return 0x0D
        case UInt8(ascii: "f"): return 0x0C
        case UInt8(ascii: "a"): return 0x07
        case UInt8(ascii: "x"):
            guard i + 1 < s.count, let h = hexVal(s[i]), let l = hexVal(s[i + 1]) else { throw RegexError(description: "bad \\x escape") }
            i += 2
            return h << 4 | l
        default:
            if isWordByte(e) && !(e >= 0x30 && e <= 0x39) { throw RegexError(description: "unsupported escape \\\(Character(UnicodeScalar(e)))") }
            return e
        }
    }

    mutating func parseClass() throws -> ByteSet {
        var set = ByteSet()
        var negate = false
        if peek() == UInt8(ascii: "^") { negate = true; i += 1 }
        var first = true
        while true {
            guard let c = peek() else { throw RegexError(description: "unterminated class") }
            if c == UInt8(ascii: "]") && !first { i += 1; break }
            first = false
            i += 1
            var lo: UInt8
            if c == UInt8(ascii: "\\") {
                guard let e = peek() else { throw RegexError(description: "bad class escape") }
                i += 1
                switch e {
                case UInt8(ascii: "w"): set.formUnion(.word); continue
                case UInt8(ascii: "d"): set.formUnion(.digit); continue
                case UInt8(ascii: "s"): set.formUnion(.space); continue
                case UInt8(ascii: "W"): var x = ByteSet.word; x.invert(); set.formUnion(x); continue
                case UInt8(ascii: "D"): var x = ByteSet.digit; x.invert(); set.formUnion(x); continue
                case UInt8(ascii: "S"): var x = ByteSet.space; x.invert(); set.formUnion(x); continue
                default: lo = try escapeByte(e)
                }
            } else { lo = c }
            if peek() == UInt8(ascii: "-"), i + 1 < s.count, s[i + 1] != UInt8(ascii: "]") {
                i += 1
                var hi = s[i]; i += 1
                if hi == UInt8(ascii: "\\") { guard let e = peek() else { throw RegexError(description: "bad range") }; i += 1; hi = try escapeByte(e) }
                guard lo <= hi else { throw RegexError(description: "bad class range") }
                set.insertRange(lo, hi)
            } else { set.insert(lo) }
        }
        if negate { set.invert() }
        return set
    }
}

@inline(__always) func hexVal(_ c: UInt8) -> UInt8? {
    switch c {
    case 0x30...0x39: return c - 0x30
    case 0x41...0x46: return c - 0x41 + 10
    case 0x61...0x66: return c - 0x61 + 10
    default: return nil
    }
}

// MARK: - Program

enum RInst {
    case byte(UInt8)
    case set(ByteSet)
    case any
    case anyNoNL
    case split(Int, Int)     // try first, backtrack to second
    case jmp(Int)
    case match
    case bol, eol, wordB, nonWordB
}

/// A literal sub-sequence that every match must contain, used as an Aho–Corasick atom.
struct RegexAtom {
    var chars: [UInt8]          // case-folded literal chars (one per regex char; widen before use)
    var minPre: Int             // min chars before the atom
    var maxPre: Int?            // max chars before the atom (nil = unbounded)
}

final class RegexProgram: @unchecked Sendable {
    let insts: [RInst]
    let source: String
    let atoms: [RegexAtom]       // candidate atoms, best first
    let firstSet: ByteSet?       // possible first bytes (nil = anything / anchors)

    init(source: [UInt8], nocase: Bool, dotall: Bool) throws {
        self.source = String(decoding: source, as: UTF8.self)
        var p = RegexParser(source, nocase: nocase, dotall: dotall)
        let node = try p.parseAlt()
        guard p.atEnd else { throw RegexError(description: "unbalanced )") }
        var out: [RInst] = []
        try RegexProgram.emit(node, &out)
        out.append(.match)
        guard out.count < 50_000 else { throw RegexError(description: "regex too large") }
        insts = out
        atoms = RegexProgram.atomCandidates(node)
        firstSet = RegexProgram.first(node)
    }

    private static func emit(_ n: RNode, _ out: inout [RInst]) throws {
        if out.count > 50_000 { throw RegexError(description: "regex too large") }
        switch n {
        case .lit(let c): out.append(.byte(c))
        case .set(let s): out.append(.set(s))
        case .any(let dotall): out.append(dotall ? .any : .anyNoNL)
        case .bol: out.append(.bol)
        case .eol: out.append(.eol)
        case .wordB: out.append(.wordB)
        case .nonWordB: out.append(.nonWordB)
        case .concat(let items): for x in items { try emit(x, &out) }
        case .alt(let branches):
            var jumps: [Int] = []
            for (k, b) in branches.enumerated() {
                if k < branches.count - 1 {
                    let sp = out.count; out.append(.split(0, 0))
                    try emit(b, &out)
                    jumps.append(out.count); out.append(.jmp(0))
                    out[sp] = .split(sp + 1, out.count)
                } else { try emit(b, &out) }
            }
            for j in jumps { out[j] = .jmp(out.count) }
        case .rep(let x, let mn, let mx, let greedy):
            for _ in 0..<mn { try emit(x, &out) }
            if let mx = mx {
                var splits: [Int] = []
                for _ in mn..<mx {
                    splits.append(out.count); out.append(.split(0, 0))
                    try emit(x, &out)
                }
                let end = out.count
                for sp in splits { out[sp] = greedy ? .split(sp + 1, end) : .split(end, sp + 1) }
            } else {
                let loop = out.count; out.append(.split(0, 0))
                try emit(x, &out)
                out.append(.jmp(loop))
                let end = out.count
                out[loop] = greedy ? .split(loop + 1, end) : .split(end, loop + 1)
            }
        }
    }

    // Length bounds in chars.
    static func minLen(_ n: RNode) -> Int {
        switch n {
        case .lit, .set, .any: return 1
        case .bol, .eol, .wordB, .nonWordB: return 0
        case .concat(let xs): return xs.reduce(0) { $0 + minLen($1) }
        case .alt(let xs): return xs.map(minLen).min() ?? 0
        case .rep(let x, let mn, _, _): return mn * minLen(x)
        }
    }
    static func maxLen(_ n: RNode) -> Int? {
        switch n {
        case .lit, .set, .any: return 1
        case .bol, .eol, .wordB, .nonWordB: return 0
        case .concat(let xs):
            var t = 0
            for x in xs { guard let m = maxLen(x) else { return nil }; t += m }
            return t
        case .alt(let xs):
            var t = 0
            for x in xs { guard let m = maxLen(x) else { return nil }; t = max(t, m) }
            return t
        case .rep(let x, _, let mx, _):
            guard let mx = mx, let m = maxLen(x) else { return nil }
            return mx * m
        }
    }

    /// Case-folded literal for a node, if it matches exactly one char (modulo case).
    private static func literal(_ n: RNode) -> UInt8? {
        switch n {
        case .lit(let c): return lowerByte(c)
        case .set(let s):
            if s.count == 1 { return lowerByte(s.members[0]) }
            if s.count == 2 { let m = s.members; if isAlpha(m[0]) && lowerByte(m[0]) == lowerByte(m[1]) { return lowerByte(m[0]) } }
            return nil
        default: return nil
        }
    }

    private static func atomCandidates(_ node: RNode) -> [RegexAtom] {
        var out: [RegexAtom] = []
        collect(node, minPre: 0, maxPre: 0, into: &out)
        return out.sorted { atomScore($0.chars, range: ($0.maxPre ?? 1_000_000) - $0.minPre) > atomScore($1.chars, range: ($1.maxPre ?? 1_000_000) - $1.minPre) }
    }

    private static func collect(_ node: RNode, minPre: Int, maxPre: Int?, into out: inout [RegexAtom]) {
        let items: [RNode]
        switch node {
        case .concat(let xs): items = xs
        case .rep(let x, let mn, _, _) where mn >= 1: collect(x, minPre: minPre, maxPre: maxPre, into: &out); return
        default: items = [node]
        }
        var mn = minPre, mx = maxPre
        var run: [UInt8] = [], runMin = 0, runMax: Int? = 0
        func flush() { if !run.isEmpty { out.append(RegexAtom(chars: run, minPre: runMin, maxPre: runMax)); run = [] } }
        for item in items {
            if let c = literal(item) {
                if run.isEmpty { runMin = mn; runMax = mx }
                run.append(c)
            } else {
                flush()
                switch item {
                case .concat: collect(item, minPre: mn, maxPre: mx, into: &out)
                case .rep(let x, let rmin, _, _) where rmin >= 1: collect(x, minPre: mn, maxPre: mx, into: &out)
                default: break
                }
            }
            mn += minLen(item)
            if let a = mx, let b = maxLen(item) { mx = a + b } else { mx = nil }
        }
        flush()
    }

    private static func first(_ n: RNode) -> ByteSet? {
        switch n {
        case .lit(let c): var s = ByteSet(); s.insert(c); return s
        case .set(let s): return s
        case .any: return nil
        case .concat(let xs):
            guard let f = xs.first else { return nil }
            if minLen(f) == 0 { return nil }
            return first(f)
        case .alt(let xs):
            var s = ByteSet()
            for x in xs { guard let f = first(x) else { return nil }; s.formUnion(f) }
            return s
        case .rep(let x, let mn, _, _): return mn >= 1 ? first(x) : nil
        default: return nil
        }
    }

    /// Anchored match at `start`. Returns the end offset or nil. `budget` is decremented per VM step.
    func match(_ data: UnsafeBufferPointer<UInt8>, at start: Int, wide: Bool, budget: inout Int) -> Int? {
        let n = data.count
        let step = wide ? 2 : 1
        var stack: [(Int, Int)] = []
        var pc = 0, pos = start
        while true {
            budget -= 1
            if budget < 0 { return nil }
            var ok = true
            switch insts[pc] {
            case .byte(let c):
                if pos < n && data[pos] == c && (!wide || (pos + 1 < n && data[pos + 1] == 0)) { pos += step; pc += 1 } else { ok = false }
            case .set(let s):
                if pos < n && s.contains(data[pos]) && (!wide || (pos + 1 < n && data[pos + 1] == 0)) { pos += step; pc += 1 } else { ok = false }
            case .any:
                if pos + step <= n && (!wide || data[pos + 1] == 0) { pos += step; pc += 1 } else { ok = false }
            case .anyNoNL:
                if pos + step <= n && data[pos] != 0x0A && (!wide || data[pos + 1] == 0) { pos += step; pc += 1 } else { ok = false }
            case .split(let a, let b):
                if stack.count > 100_000 { return nil }
                stack.append((b, pos)); pc = a
            case .jmp(let a): pc = a
            case .match: return pos
            case .bol: if pos == 0 { pc += 1 } else { ok = false }
            case .eol: if pos == n { pc += 1 } else { ok = false }
            case .wordB, .nonWordB:
                let before = pos - step >= 0 && isWordByte(data[pos - step])
                let after = pos < n && isWordByte(data[pos])
                let isB = before != after
                if case .wordB = insts[pc] { ok = isB } else { ok = !isB }
                if ok { pc += 1 }
            }
            if !ok {
                guard let (p2, s2) = stack.popLast() else { return nil }
                pc = p2; pos = s2
            }
        }
    }

    /// Unanchored search used by the `matches` operator.
    func search(_ bytes: [UInt8]) -> Bool {
        bytes.withUnsafeBufferPointer { buf in
            var budget = 2_000_000
            for start in 0...buf.count {
                if let f = firstSet, start < buf.count, !f.contains(buf[start]) { continue }
                if match(buf, at: start, wide: false, budget: &budget) != nil { return true }
                if budget <= 0 { return false }
            }
            return false
        }
    }
}

/// Heuristic atom quality: rare, varied bytes score higher; a variable distance to the match start costs a little.
func atomScore(_ bytes: [UInt8], range: Int) -> Int {
    var q = 0
    var seen = Set<UInt8>()
    for b in bytes {
        switch b {
        case 0x00, 0xFF, 0x20, 0xCC, 0x90, 0x48, 0x89, 0x8B, 0x0A, 0x0D: q += 2
        case 0x41...0x5A, 0x61...0x7A: q += 4
        default: q += 5
        }
        seen.insert(b)
    }
    if seen.count == 1 && bytes.count > 1 { q = 2 }
    if range > 0 { q -= min(4, Int(log2(Double(range + 1)))) }
    return q
}
