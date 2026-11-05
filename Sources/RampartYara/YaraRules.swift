import Foundation

/// One rule source to compile (each source is its own namespace).
public struct YaraSource: Sendable {
    public var namespace: String
    public var text: String
    public init(namespace: String, text: String) { self.namespace = namespace; self.text = text }
}

/// Compile statistics across all sources.
public struct YaraCompileStats: Sendable, Codable {
    public var sources: [YaraSourceStats]
    public var patterns: Int
    public var atoms: Int
    public var automatonStates: Int
    public var unanchoredPatterns: Int
    public var compileSeconds: Double
    public var total: Int { sources.reduce(0) { $0 + $1.total } }
    public var compiled: Int { sources.reduce(0) { $0 + $1.compiled } }
    public var skipped: Int { sources.reduce(0) { $0 + $1.skipped } }
}

enum PatternKind {
    case literal([UInt8], nocase: Bool)
    case hex([HexElem])
    case regex(RegexProgram)
}

struct Pattern {
    var stringID: Int
    var kind: PatternKind
    var wide: Bool
    var fullword: Bool
    var atomLen: Int
    var dMin: Int
    var dMax: Int          // Int.max = unbounded
    var firstByte: Int     // -1 if unknown; prefilter for unanchored scans
}

let maxAtomLen = 4

/// Immutable, thread-safe compiled rule set. Build with `YaraRules.compile`.
public final class YaraRules: @unchecked Sendable {
    let strings: [StringDef]
    let rules: [ParsedRule]
    let patterns: [Pattern]
    let patternsByString: [[Int]]
    let maxSlots: Int
    let defaultExternals: [String: YaraExternal]
    // Aho–Corasick DFA over case-folded bytes.
    let acNext: [Int32]
    let acOutStart: [Int32]
    let acOutCount: [Int32]
    let acOutAtoms: [Int32]
    let atomPatterns: [[Int32]]
    let unanchored: [Int]
    public let stats: YaraCompileStats

    /// Public view of compiled rules (name, namespace, private, meta) in evaluation order.
    public struct RuleInfo: Sendable {
        public let name: String
        public let namespace: String
        public let isPrivate: Bool
        public let tags: [String]
        public let meta: [String: String]
    }
    public let ruleInfos: [RuleInfo]

    /// Compiles sources rule-by-rule; rules that fail to parse or use unsupported features are skipped and counted.
    public static func compile(_ sources: [YaraSource], externals: [String: YaraExternal] = [:]) -> YaraRules {
        let t0 = Date()
        var st = CompileState()
        st.externals = externals
        var srcStats: [YaraSourceStats] = []
        for s in sources {
            var p = YaraParser(source: Array(s.text.utf8), namespace: s.namespace)
            srcStats.append(p.parseAll(into: &st))
        }
        return YaraRules(state: st, sourceStats: srcStats, start: t0)
    }

    private init(state st: CompileState, sourceStats: [YaraSourceStats], start t0: Date) {
        strings = st.strings
        rules = st.rules
        defaultExternals = st.externals
        maxSlots = st.rules.map(\.slotCount).max() ?? 0
        ruleInfos = st.rules.map { r in
            RuleInfo(name: r.name, namespace: r.namespace, isPrivate: r.isPrivate, tags: r.tags,
                     meta: Dictionary(r.meta.map { ($0.0, $0.1.description) }, uniquingKeysWith: { a, _ in a }))
        }

        // Patterns and atoms
        var pats: [Pattern] = []
        var byString = Array(repeating: [Int](), count: st.strings.count)
        var atomIndex: [[UInt8]: Int] = [:]
        var atomList: [[UInt8]] = []
        var atomPats: [[Int32]] = []
        var unanch: [Int] = []
        func add(_ p: Pattern, atom: [UInt8]?) {
            let id = pats.count
            pats.append(p)
            byString[p.stringID].append(id)
            if let a = atom, !a.isEmpty {
                let folded = a.map(lowerByte)
                let ai: Int
                if let x = atomIndex[folded] { ai = x } else { ai = atomList.count; atomIndex[folded] = ai; atomList.append(folded); atomPats.append([]) }
                atomPats[ai].append(Int32(id))
            } else { unanch.append(id) }
        }
        for (sid, s) in st.strings.enumerated() {
            let fullword = s.modifiers.contains(.fullword)
            switch s.body {
            case .text(let bytes):
                var variants: [([UInt8], Bool)] = []
                if s.modifiers.contains(.ascii) { variants.append((bytes, false)) }
                if s.modifiers.contains(.wide) { variants.append((bytes.flatMap { [$0, 0] }, true)) }
                for (enc, wide) in variants {
                    let (off, len) = YaraRules.bestWindow(enc)
                    add(Pattern(stringID: sid, kind: .literal(enc, nocase: s.modifiers.contains(.nocase)), wide: wide, fullword: fullword,
                                atomLen: len, dMin: off, dMax: off, firstByte: Int(enc[0])), atom: Array(enc[off..<off + len]))
                }
            case .hex(let elems):
                let (atom, dmin, dmax) = YaraRules.hexAtom(elems)
                var fb = -1
                if case .bytes(let v, let m, let n) = elems[0], m[0] == 0xFF, !n[0] { fb = Int(v[0]) }
                add(Pattern(stringID: sid, kind: .hex(elems), wide: false, fullword: false, atomLen: atom?.count ?? 0,
                            dMin: dmin, dMax: dmax, firstByte: fb), atom: atom)
            case .regex(let prog):
                var variants: [Bool] = []
                if s.modifiers.contains(.ascii) { variants.append(false) }
                if s.modifiers.contains(.wide) { variants.append(true) }
                for wide in variants {
                    let step = wide ? 2 : 1
                    var atom: [UInt8]? = nil
                    var dmin = 0, dmax = 0
                    if let best = prog.atoms.first {
                        var chars = best.chars
                        // pick best window inside the literal run
                        let enc = wide ? chars.flatMap { [$0, 0] } : chars
                        let (off, len) = YaraRules.bestWindow(enc)
                        chars = Array(enc[off..<off + len])
                        atom = chars
                        dmin = best.minPre * step + off
                        dmax = best.maxPre.map { $0 * step + off } ?? Int.max
                    }
                    add(Pattern(stringID: sid, kind: .regex(prog), wide: wide, fullword: fullword, atomLen: atom?.count ?? 0,
                                dMin: dmin, dMax: dmax, firstByte: -1), atom: atom)
                }
            }
        }
        patterns = pats
        patternsByString = byString
        atomPatterns = atomPats
        unanchored = unanch

        // Build the Aho–Corasick DFA.
        var next: [Int32] = Array(repeating: -1, count: 256)
        var own: [[Int32]] = [[]]
        for (ai, a) in atomList.enumerated() {
            var s = 0
            for b in a {
                let k = s << 8 | Int(b)
                if next[k] < 0 {
                    next[k] = Int32(own.count)
                    own.append([])
                    next.append(contentsOf: repeatElement(-1, count: 256))
                }
                s = Int(next[k])
            }
            own[s].append(Int32(ai))
        }
        let nStates = own.count
        var fail = Array(repeating: 0, count: nStates)
        var outs = own
        var queue: [Int] = []
        queue.reserveCapacity(nStates)
        for c in 0..<256 {
            let t = next[c]
            if t < 0 { next[c] = 0 } else { fail[Int(t)] = 0; queue.append(Int(t)) }
        }
        var qi = 0
        while qi < queue.count {
            let s = queue[qi]; qi += 1
            if !outs[fail[s]].isEmpty { outs[s] += outs[fail[s]] }
            for c in 0..<256 {
                let k = s << 8 | c
                let t = next[k]
                let fk = Int(next[fail[s] << 8 | c])
                if t < 0 { next[k] = Int32(fk) } else { fail[Int(t)] = fk; queue.append(Int(t)) }
            }
        }
        var oStart = [Int32](repeating: 0, count: nStates), oCount = [Int32](repeating: 0, count: nStates), oAtoms: [Int32] = []
        for s in 0..<nStates {
            oStart[s] = Int32(oAtoms.count); oCount[s] = Int32(outs[s].count); oAtoms += outs[s]
        }
        acNext = next; acOutStart = oStart; acOutCount = oCount; acOutAtoms = oAtoms

        stats = YaraCompileStats(sources: sourceStats, patterns: pats.count, atoms: atomList.count, automatonStates: nStates,
                                 unanchoredPatterns: unanch.count, compileSeconds: Date().timeIntervalSince(t0))
    }

    /// Best window (offset, length ≤ maxAtomLen) of a fully known byte run.
    static func bestWindow(_ bytes: [UInt8]) -> (Int, Int) {
        let len = min(maxAtomLen, bytes.count)
        var best = 0, bestScore = Int.min
        for off in 0...(bytes.count - len) {
            let sc = atomScore(Array(bytes[off..<off + len]), range: 0)
            if sc > bestScore { bestScore = sc; best = off }
        }
        return (best, len)
    }

    static func hexLen(_ elems: [HexElem]) -> (Int, Int) {
        var mn = 0, mx = 0
        for e in elems {
            switch e {
            case .bytes(let v, _, _): mn += v.count; mx = sat(mx, v.count)
            case .jump(let a, let b): mn += a; mx = sat(mx, b)
            case .alt(let bs):
                let ls = bs.map(hexLen)
                mn += ls.map(\.0).min() ?? 0
                mx = sat(mx, ls.map(\.1).max() ?? 0)
            }
        }
        return (mn, mx)
    }

    static func sat(_ a: Int, _ b: Int) -> Int { (a == Int.max || b == Int.max) ? Int.max : a + b }

    /// Picks the best fully-specified window in the top-level sequence; returns (atom, dMin, dMax).
    static func hexAtom(_ elems: [HexElem]) -> ([UInt8]?, Int, Int) {
        var mn = 0, mx = 0
        var best: ([UInt8], Int, Int)? = nil
        var bestScore = Int.min
        for e in elems {
            switch e {
            case .bytes(let v, let m, let n):
                var k = 0
                while k < v.count {
                    guard m[k] == 0xFF && !n[k] else { k += 1; continue }
                    var end = k
                    while end < v.count && m[end] == 0xFF && !n[end] { end += 1 }
                    let run = Array(v[k..<end])
                    let len = min(maxAtomLen, run.count)
                    for off in 0...(run.count - len) {
                        let w = Array(run[off..<off + len])
                        let range = mx == Int.max ? 1 << 20 : mx - mn
                        let sc = atomScore(w, range: range)
                        if sc > bestScore { bestScore = sc; best = (w, mn + k + off, sat(mx, k + off)) }
                    }
                    k = end
                }
                mn += v.count; mx = sat(mx, v.count)
            case .jump(let a, let b): mn += a; mx = sat(mx, b)
            case .alt(let bs):
                let ls = bs.map(hexLen)
                mn += ls.map(\.0).min() ?? 0
                mx = sat(mx, ls.map(\.1).max() ?? 0)
            }
        }
        guard let b = best else { return (nil, 0, 0) }
        return (b.0, b.1, b.2)
    }
}
