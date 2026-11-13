import Foundation

struct YaraSyntaxError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

/// Shared compile-time state across all sources/namespaces.
struct CompileState {
    var strings: [StringDef] = []
    var rules: [ParsedRule] = []
    var ruleIndex: [String: [String: Int]] = [:]      // namespace -> name -> index
    var skippedRules: [String: Set<String>] = [:]      // namespace -> names
    var externals: [String: YaraExternal] = [:]
}

/// Result of compiling one source.
public struct YaraSourceStats: Sendable, Codable {
    public var namespace: String
    public var total: Int
    public var compiled: Int
    public var skipped: Int
    public var skippedReasons: [String: String]      // rule name -> reason
}

// MARK: - Condition tokens

enum Tok: Equatable {
    case ident(String)
    case strId(String)        // "$a", "$", "$a*", "$*"
    case countId(String)      // "#a" or "#"
    case offId(String)        // "@a" or "@"
    case lenId(String)        // "!a" or "!"
    case int(Int64)
    case str([UInt8])
    case regex([UInt8], nocase: Bool, dotall: Bool)
    case punct(String)
    case eof
}

/// Recursive-descent parser for YARA source with rule-by-rule error tolerance.
struct YaraParser {
    let src: [UInt8]
    var pos = 0
    let namespace: String
    var imports = Set<String>()

    init(source: [UInt8], namespace: String) { self.src = source; self.namespace = namespace }

    // MARK: Low-level scanning

    var atEnd: Bool { pos >= src.count }
    func peekByte(_ off: Int = 0) -> UInt8? { pos + off < src.count ? src[pos + off] : nil }

    mutating func skipWS() {
        while pos < src.count {
            let c = src[pos]
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D || c == 0x0C || c == 0x0B { pos += 1; continue }
            if c == UInt8(ascii: "/"), pos + 1 < src.count {
                if src[pos + 1] == UInt8(ascii: "/") {
                    while pos < src.count && src[pos] != 0x0A { pos += 1 }
                    continue
                }
                if src[pos + 1] == UInt8(ascii: "*") {
                    pos += 2
                    while pos + 1 < src.count && !(src[pos] == UInt8(ascii: "*") && src[pos + 1] == UInt8(ascii: "/")) { pos += 1 }
                    pos = min(src.count, pos + 2)
                    continue
                }
            }
            break
        }
    }

    static func isIdentStart(_ c: UInt8) -> Bool { isAlpha(c) || c == UInt8(ascii: "_") }
    static func isIdentChar(_ c: UInt8) -> Bool { isWordByte(c) }

    mutating func readIdent() -> String? {
        skipWS()
        guard let c = peekByte(), YaraParser.isIdentStart(c) else { return nil }
        let start = pos
        while let d = peekByte(), YaraParser.isIdentChar(d) { pos += 1 }
        return String(decoding: src[start..<pos], as: UTF8.self)
    }

    mutating func expect(_ ch: Character) throws {
        skipWS()
        guard let c = peekByte(), c == ch.asciiValue! else {
            throw YaraSyntaxError("expected '\(ch)' near offset \(pos)")
        }
        pos += 1
    }

    mutating func lookIdent() -> String? {
        let save = pos
        let id = readIdent()
        pos = save
        return id
    }

    /// Reads a double-quoted string with YARA escapes.
    mutating func readQuoted() throws -> [UInt8] {
        skipWS()
        guard peekByte() == UInt8(ascii: "\"") else { throw YaraSyntaxError("expected string") }
        pos += 1
        var out: [UInt8] = []
        while true {
            guard let c = peekByte() else { throw YaraSyntaxError("unterminated string") }
            pos += 1
            if c == UInt8(ascii: "\"") { break }
            if c == 0x0A { throw YaraSyntaxError("newline in string") }
            if c == UInt8(ascii: "\\") {
                guard let e = peekByte() else { throw YaraSyntaxError("bad escape") }
                pos += 1
                switch e {
                case UInt8(ascii: "\""): out.append(0x22)
                case UInt8(ascii: "\\"): out.append(0x5C)
                case UInt8(ascii: "t"): out.append(0x09)
                case UInt8(ascii: "n"): out.append(0x0A)
                case UInt8(ascii: "r"): out.append(0x0D)
                case UInt8(ascii: "x"):
                    guard let a = peekByte(), let b = peekByte(1), let h = hexVal(a), let l = hexVal(b) else { throw YaraSyntaxError("bad \\x escape") }
                    pos += 2
                    out.append(h << 4 | l)
                default: throw YaraSyntaxError("unknown escape \\\(Character(UnicodeScalar(e)))")
                }
            } else { out.append(c) }
        }
        return out
    }

    /// Reads `/.../flags`; pos must be at the opening slash.
    mutating func readRegexLiteral() throws -> ([UInt8], Bool, Bool) {
        guard peekByte() == UInt8(ascii: "/") else { throw YaraSyntaxError("expected regex") }
        pos += 1
        var out: [UInt8] = []
        while true {
            guard let c = peekByte() else { throw YaraSyntaxError("unterminated regex") }
            pos += 1
            if c == 0x0A { throw YaraSyntaxError("newline in regex") }
            if c == UInt8(ascii: "\\") {
                guard let e = peekByte() else { throw YaraSyntaxError("bad regex escape") }
                pos += 1
                if e == UInt8(ascii: "/") { out.append(e) } else { out.append(c); out.append(e) }
                continue
            }
            if c == UInt8(ascii: "/") { break }
            out.append(c)
        }
        var nocase = false, dotall = false
        while let f = peekByte() {
            if f == UInt8(ascii: "i") { nocase = true; pos += 1 }
            else if f == UInt8(ascii: "s") { dotall = true; pos += 1 }
            else { break }
        }
        return (out, nocase, dotall)
    }

    // MARK: Top level

    /// Parses every rule; failures are recorded per rule and never abort the whole source.
    mutating func parseAll(into st: inout CompileState) -> YaraSourceStats {
        var stats = YaraSourceStats(namespace: namespace, total: 0, compiled: 0, skipped: 0, skippedReasons: [:])
        if st.ruleIndex[namespace] == nil { st.ruleIndex[namespace] = [:] }
        if st.skippedRules[namespace] == nil { st.skippedRules[namespace] = [] }
        while true {
            skipWS()
            if atEnd { break }
            let start = pos
            guard let word = lookIdent() else {
                // garbage: skip to next rule
                pos = nextRuleStart(after: pos)
                continue
            }
            if word == "import" {
                _ = readIdent()
                if let name = try? readQuoted() { imports.insert(String(decoding: name, as: UTF8.self)) }
                continue
            }
            if word == "include" {
                _ = readIdent(); _ = try? readQuoted()
                continue
            }
            // rule header
            var isPrivate = false, isGlobal = false
            var name = "?"
            do {
                while let w = lookIdent(), w == "private" || w == "global" {
                    _ = readIdent()
                    if w == "private" { isPrivate = true } else { isGlobal = true }
                }
                guard readIdent() == "rule" else { throw YaraSyntaxError("expected 'rule'") }
                guard let n = readIdent() else { throw YaraSyntaxError("expected rule name") }
                name = n
                stats.total += 1
                if st.ruleIndex[namespace]![name] != nil { throw YaraSyntaxError("duplicate rule name") }
                let rule = try parseRuleBody(name: name, isPrivate: isPrivate, isGlobal: isGlobal, st: &st)
                st.ruleIndex[namespace]![name] = st.rules.count
                st.rules.append(rule)
                stats.compiled += 1
            } catch {
                if name == "?" { stats.total += 1 }
                stats.skipped += 1
                stats.skippedReasons[name] = String(describing: error)
                st.skippedRules[namespace]!.insert(name)
                pos = nextRuleStart(after: start + 1)
            }
        }
        return stats
    }

    /// Finds the next line that starts a rule/import declaration.
    func nextRuleStart(after p: Int) -> Int {
        var i = p
        while i < src.count {
            // move to line start
            while i < src.count && src[i] != 0x0A { i += 1 }
            i += 1
            var j = i
            while j < src.count && (src[j] == 0x20 || src[j] == 0x09) { j += 1 }
            for kw in ["rule", "private", "global", "import"] {
                let k = Array(kw.utf8)
                if j + k.count < src.count && Array(src[j..<j + k.count]) == k && !YaraParser.isIdentChar(src[j + k.count]) { return j }
            }
        }
        return src.count
    }

    // MARK: Rule body

    mutating func parseRuleBody(name: String, isPrivate: Bool, isGlobal: Bool, st: inout CompileState) throws -> ParsedRule {
        var tags: [String] = []
        skipWS()
        if peekByte() == UInt8(ascii: ":") {
            pos += 1
            while let t = lookIdent() { _ = readIdent(); tags.append(t) }
        }
        try expect("{")
        var meta: [(String, YaraMetaValue)] = []
        var localStrings: [StringDef] = []
        var condition: Expr?
        var ctx = RuleContext(base: st.strings.count)
        while true {
            skipWS()
            if peekByte() == UInt8(ascii: "}") { pos += 1; break }
            guard let section = readIdent() else { throw YaraSyntaxError("expected section near offset \(pos)") }
            try expect(":")
            switch section {
            case "meta":
                while let key = lookIdent(), !["strings", "condition"].contains(key) {
                    _ = readIdent()
                    try expect("=")
                    skipWS()
                    if peekByte() == UInt8(ascii: "\"") {
                        meta.append((key, .string(String(decoding: try readQuoted(), as: UTF8.self))))
                    } else if let w = lookIdent(), w == "true" || w == "false" {
                        _ = readIdent(); meta.append((key, .bool(w == "true")))
                    } else {
                        var neg = false
                        if peekByte() == UInt8(ascii: "-") { neg = true; pos += 1 }
                        let v = try readNumberRaw()
                        meta.append((key, .int(neg ? -v : v)))
                    }
                }
            case "strings":
                while true {
                    skipWS()
                    guard peekByte() == UInt8(ascii: "$") else { break }
                    pos += 1
                    var id = "$"
                    while let d = peekByte(), YaraParser.isIdentChar(d) { id.append(Character(UnicodeScalar(d))); pos += 1 }
                    if id != "$" && localStrings.contains(where: { $0.identifier == id }) { throw YaraSyntaxError("duplicate string \(id)") }
                    try expect("=")
                    localStrings.append(try parseStringValue(id))
                }
                ctx.strings = localStrings
            case "condition":
                ctx.strings = localStrings
                var toks = try tokenizeCondition()
                toks.append(.eof)
                var cp = ConditionParser(toks: toks, ctx: ctx, namespace: namespace, imports: imports, st: st)
                condition = try cp.parseExpression()
                guard cp.toks[cp.i] == .eof else { throw YaraSyntaxError("unexpected token \(cp.toks[cp.i]) in condition") }
                ctx = cp.ctx
            default:
                throw YaraSyntaxError("unknown section \(section)")
            }
        }
        guard let cond = condition else { throw YaraSyntaxError("missing condition") }
        let ids = Array(st.strings.count..<(st.strings.count + localStrings.count))
        st.strings.append(contentsOf: localStrings)
        return ParsedRule(name: name, tags: tags, meta: meta, isPrivate: isPrivate, isGlobal: isGlobal,
                          stringIDs: ids, condition: cond, namespace: namespace, slotCount: ctx.maxSlots)
    }

    mutating func readNumberRaw() throws -> Int64 {
        skipWS()
        let start = pos
        while let c = peekByte(), YaraParser.isIdentChar(c) { pos += 1 }
        let text = String(decoding: src[start..<pos], as: UTF8.self)
        guard let v = YaraParser.parseNumber(text) else { throw YaraSyntaxError("bad number \(text)") }
        return v
    }

    static func parseNumber(_ t: String) -> Int64? {
        var s = t, mult: Int64 = 1
        if s.hasSuffix("KB") { mult = 1024; s.removeLast(2) } else if s.hasSuffix("MB") { mult = 1024 * 1024; s.removeLast(2) }
        let v: Int64?
        if s.hasPrefix("0x") || s.hasPrefix("0X") { v = Int64(s.dropFirst(2), radix: 16) }
        else if s.hasPrefix("0o") { v = Int64(s.dropFirst(2), radix: 8) }
        else { v = Int64(s) }
        return v.map { $0 &* mult }
    }

    // MARK: String definitions

    mutating func parseStringValue(_ id: String) throws -> StringDef {
        skipWS()
        guard let c = peekByte() else { throw YaraSyntaxError("missing string value") }
        if c == UInt8(ascii: "\"") {
            let bytes = try readQuoted()
            guard !bytes.isEmpty else { throw YaraSyntaxError("empty string") }
            var mods = try readModifiers(allowed: ["ascii", "wide", "nocase", "fullword", "private"])
            if !mods.contains(.wide) { mods.insert(.ascii) }
            return StringDef(identifier: id, body: .text(bytes), modifiers: mods)
        }
        if c == UInt8(ascii: "{") {
            pos += 1
            var hp = HexParser(src: src, pos: pos)
            let elems = try hp.parseSeq(topLevel: true)
            pos = hp.pos
            let mods = try readModifiers(allowed: ["private"])
            try HexParser.validate(elems)
            return StringDef(identifier: id, body: .hex(elems), modifiers: mods.union(.ascii))
        }
        if c == UInt8(ascii: "/") {
            let (body, nc, dotall) = try readRegexLiteral()
            var mods = try readModifiers(allowed: ["ascii", "wide", "nocase", "fullword", "private"])
            if !mods.contains(.wide) { mods.insert(.ascii) }
            if nc { mods.insert(.nocase) }
            do {
                let prog = try RegexProgram(source: body, nocase: mods.contains(.nocase), dotall: dotall)
                return StringDef(identifier: id, body: .regex(prog), modifiers: mods)
            } catch { throw YaraSyntaxError("regex \(id): \(error)") }
        }
        throw YaraSyntaxError("bad string value for \(id)")
    }

    mutating func readModifiers(allowed: Set<String>) throws -> StringModifiers {
        var m: StringModifiers = []
        while let w = lookIdent() {
            if ["meta", "strings", "condition"].contains(w) {
                // a section name follows only if it's succeeded by ':'
                let save = pos; _ = readIdent(); skipWS()
                let isSection = peekByte() == UInt8(ascii: ":")
                pos = save
                if isSection { break }
            }
            guard allowed.contains(w) else {
                if ["xor", "base64", "base64wide"].contains(w) { throw YaraSyntaxError("unsupported string modifier \(w)") }
                if ["ascii", "wide", "nocase", "fullword", "private"].contains(w) { throw YaraSyntaxError("modifier \(w) not allowed here") }
                break
            }
            _ = readIdent()
            switch w {
            case "ascii": m.insert(.ascii)
            case "wide": m.insert(.wide)
            case "nocase": m.insert(.nocase)
            case "fullword": m.insert(.fullword)
            default: m.insert(.privateString)
            }
        }
        return m
    }

    // MARK: Condition tokenizer

    mutating func tokenizeCondition() throws -> [Tok] {
        var toks: [Tok] = []
        while true {
            skipWS()
            guard let c = peekByte() else { throw YaraSyntaxError("unterminated condition") }
            if c == UInt8(ascii: "}") { break }  // rule end; consumed by caller
            if YaraParser.isIdentStart(c) {
                let id = readIdent()!
                toks.append(.ident(id))
                if id == "matches" {
                    skipWS()
                    if peekByte() == UInt8(ascii: "/") {
                        let (b, nc, da) = try readRegexLiteral()
                        toks.append(.regex(b, nocase: nc, dotall: da))
                    }
                }
                continue
            }
            if c >= 0x30 && c <= 0x39 {
                let start = pos
                while let d = peekByte(), YaraParser.isIdentChar(d) { pos += 1 }
                let text = String(decoding: src[start..<pos], as: UTF8.self)
                if peekByte() == UInt8(ascii: "."), peekByte(1) != UInt8(ascii: ".") { throw YaraSyntaxError("float literals unsupported") }
                guard let v = YaraParser.parseNumber(text) else { throw YaraSyntaxError("bad number \(text)") }
                toks.append(.int(v)); continue
            }
            if c == UInt8(ascii: "\"") { toks.append(.str(try readQuoted())); continue }
            if c == UInt8(ascii: "$") || c == UInt8(ascii: "#") || c == UInt8(ascii: "@") || (c == UInt8(ascii: "!") && peekByte(1) != UInt8(ascii: "=")) {
                pos += 1
                var name = ""
                while let d = peekByte(), YaraParser.isIdentChar(d) { name.append(Character(UnicodeScalar(d))); pos += 1 }
                switch c {
                case UInt8(ascii: "$"):
                    if peekByte() == UInt8(ascii: "*") { pos += 1; name += "*" }
                    toks.append(.strId("$" + name))
                case UInt8(ascii: "#"): toks.append(.countId("$" + name))
                case UInt8(ascii: "@"): toks.append(.offId("$" + name))
                default: toks.append(.lenId("$" + name))
                }
                continue
            }
            let two = pos + 1 < src.count ? String(decoding: src[pos...pos + 1], as: UTF8.self) : ""
            if ["==", "!=", "<=", ">=", "<<", ">>", ".."].contains(two) { toks.append(.punct(two)); pos += 2; continue }
            let one = String(Character(UnicodeScalar(c)))
            if "<>()[],:+-*\\%&|^~.".contains(one) { toks.append(.punct(one)); pos += 1; continue }
            throw YaraSyntaxError("unexpected character '\(one)' in condition")
        }
        return toks
    }
}

// MARK: - Hex strings

struct HexParser {
    let src: [UInt8]
    var pos: Int
    /// Nested alternative groups so far (bounded: deep nesting would overflow the stack when parsing/matching).
    var depth = 0

    mutating func skip() {
        while pos < src.count {
            let c = src[pos]
            if c == 0x20 || c == 0x09 || c == 0x0A || c == 0x0D { pos += 1; continue }
            if c == UInt8(ascii: "/"), pos + 1 < src.count, src[pos + 1] == UInt8(ascii: "/") {
                while pos < src.count && src[pos] != 0x0A { pos += 1 }; continue
            }
            if c == UInt8(ascii: "/"), pos + 1 < src.count, src[pos + 1] == UInt8(ascii: "*") {
                pos += 2
                while pos + 1 < src.count && !(src[pos] == UInt8(ascii: "*") && src[pos + 1] == UInt8(ascii: "/")) { pos += 1 }
                pos = min(src.count, pos + 2); continue
            }
            break
        }
    }

    func nib(_ c: UInt8) throws -> (UInt8, UInt8) {
        if c == UInt8(ascii: "?") { return (0, 0) }
        guard let v = hexVal(c) else { throw YaraSyntaxError("bad hex digit '\(Character(UnicodeScalar(c)))'") }
        return (v, 0xF)
    }

    /// Parses a sequence until '}' (top level) or '|' / ')' (inside alternatives).
    mutating func parseSeq(topLevel: Bool) throws -> [HexElem] {
        var out: [HexElem] = []
        var vals: [UInt8] = [], masks: [UInt8] = [], negs: [Bool] = []
        func flush() { if !vals.isEmpty { out.append(.bytes(values: vals, masks: masks, negate: negs)); vals = []; masks = []; negs = [] } }
        while true {
            skip()
            guard pos < src.count else { throw YaraSyntaxError("unterminated hex string") }
            let c = src[pos]
            if c == UInt8(ascii: "}") {
                guard topLevel else { throw YaraSyntaxError("unterminated alternative") }
                pos += 1; break
            }
            if c == UInt8(ascii: "|") || c == UInt8(ascii: ")") {
                guard !topLevel else { throw YaraSyntaxError("unexpected '\(Character(UnicodeScalar(c)))'") }
                break
            }
            if c == UInt8(ascii: "[") {
                pos += 1; skip()
                var lo = 0, hi = Int.max
                let a = readInt(); skip()
                if pos < src.count && src[pos] == UInt8(ascii: "-") {
                    pos += 1; skip()
                    lo = a ?? 0
                    if let b = readInt() { hi = b }
                } else {
                    guard let a = a else { throw YaraSyntaxError("bad jump") }
                    lo = a; hi = a
                }
                skip()
                guard pos < src.count, src[pos] == UInt8(ascii: "]") else { throw YaraSyntaxError("bad jump") }
                pos += 1
                guard lo <= hi else { throw YaraSyntaxError("bad jump range") }
                flush()
                out.append(.jump(min: lo, max: hi))
                continue
            }
            if c == UInt8(ascii: "(") {
                pos += 1
                depth += 1
                defer { depth -= 1 }
                if depth > 32 { throw YaraSyntaxError("hex alternatives nested too deeply") }
                flush()
                var branches: [[HexElem]] = []
                while true {
                    branches.append(try parseSeq(topLevel: false))
                    guard pos < src.count else { throw YaraSyntaxError("unterminated alternative") }
                    if src[pos] == UInt8(ascii: "|") { pos += 1; continue }
                    pos += 1 // ')'
                    break
                }
                out.append(.alt(branches))
                continue
            }
            var neg = false
            if c == UInt8(ascii: "~") { neg = true; pos += 1 }
            guard pos + 1 < src.count else { throw YaraSyntaxError("bad hex byte") }
            let (h, hm) = try nib(src[pos]), (l, lm) = try nib(src[pos + 1])
            pos += 2
            vals.append(h << 4 | l); masks.append(hm << 4 | lm); negs.append(neg)
        }
        flush()
        return out
    }

    mutating func readInt() -> Int? {
        var v = 0, any = false
        // Saturates: `[99999999999999999999]` in a hex jump must not overflow (trap) the rule compiler.
        while pos < src.count, src[pos] >= 0x30, src[pos] <= 0x39 { v = min(v, 1 << 40) * 10 + Int(src[pos] - 0x30); pos += 1; any = true }
        return any ? v : nil
    }

    static func validate(_ elems: [HexElem]) throws {
        guard !elems.isEmpty else { throw YaraSyntaxError("empty hex string") }
        if case .jump = elems.first! { throw YaraSyntaxError("hex string starts with a jump") }
        if case .jump = elems.last! { throw YaraSyntaxError("hex string ends with a jump") }
    }
}

// MARK: - Condition parser

struct RuleContext {
    var base: Int                       // global id of the rule's first string
    var strings: [StringDef] = []
    var scopes: [[String: Int]] = []    // loop variables -> slot
    var nextSlot = 0
    var maxSlots = 0
    var inForOf = 0

    init(base: Int) { self.base = base }

    func stringID(_ name: String) throws -> Int {
        if name == "$" { guard inForOf > 0 else { throw YaraSyntaxError("anonymous $ outside for..of") }; return -1 }
        guard let i = strings.firstIndex(where: { $0.identifier == name }) else { throw YaraSyntaxError("undefined string \(name)") }
        return base + i
    }

    func stringSet(_ pattern: String) throws -> [Int] {
        if pattern.hasSuffix("*") {
            let prefix = String(pattern.dropLast())
            let ids = strings.indices.filter { prefix == "$" || strings[$0].identifier.hasPrefix(prefix) }.map { base + $0 }
            guard !ids.isEmpty else { throw YaraSyntaxError("no strings match \(pattern)") }
            return ids
        }
        return [try stringID(pattern)]
    }

    func variable(_ name: String) -> Int? {
        for s in scopes.reversed() { if let v = s[name] { return v } }
        return nil
    }
}

struct ConditionParser {
    let toks: [Tok]
    var i = 0
    var ctx: RuleContext
    let namespace: String
    let imports: Set<String>
    let st: CompileState

    init(toks: [Tok], ctx: RuleContext, namespace: String, imports: Set<String>, st: CompileState) {
        self.toks = toks; self.ctx = ctx; self.namespace = namespace; self.imports = imports; self.st = st
    }

    /// Expression nesting so far. Deep trees (`((((…`, `not not …`, `1+1+…+1`) would overflow the stack while
    /// parsing, evaluating or freeing them on a 512 KB scan thread, so they are rejected.
    var depth = 0
    /// Budget 64: a parenthesised sub-expression costs 4 (it re-enters ~15 parser frames, ~20 KB of stack in a
    /// debug build), a unary/`not` or a link in an operator chain costs 1. So at most 16 nested parentheses.
    static let maxDepth = 64
    mutating func deeper(_ cost: Int = 1) throws { depth += cost; if depth > Self.maxDepth { throw YaraSyntaxError("expression nested too deeply") } }

    var cur: Tok { toks[i] }
    func peek(_ k: Int = 1) -> Tok { i + k < toks.count ? toks[i + k] : .eof }
    mutating func advance() { if i < toks.count - 1 { i += 1 } }
    func isIdent(_ s: String, _ t: Tok? = nil) -> Bool { if case .ident(let x) = (t ?? cur) { return x == s }; return false }
    func isPunct(_ s: String, _ t: Tok? = nil) -> Bool { if case .punct(let x) = (t ?? cur) { return x == s }; return false }
    mutating func expectPunct(_ s: String) throws { guard isPunct(s) else { throw YaraSyntaxError("expected '\(s)' got \(cur)") }; advance() }
    mutating func expectIdent(_ s: String) throws { guard isIdent(s) else { throw YaraSyntaxError("expected '\(s)' got \(cur)") }; advance() }

    mutating func parseExpression() throws -> Expr { let d = depth; defer { depth = d }; try deeper(4); return try parseOr() }

    mutating func parseOr() throws -> Expr {
        var xs = [try parseAnd()]
        while isIdent("or") { advance(); xs.append(try parseAnd()) }
        return xs.count == 1 ? xs[0] : .or(xs)
    }

    mutating func parseAnd() throws -> Expr {
        var xs = [try parseNot()]
        while isIdent("and") { advance(); xs.append(try parseNot()) }
        return xs.count == 1 ? xs[0] : .and(xs)
    }

    mutating func parseNot() throws -> Expr {
        let d = depth; defer { depth = d }
        if isIdent("not") { advance(); try deeper(); return .not(try parseNot()) }
        if isIdent("defined") { advance(); try deeper(); return .defined(try parseNot()) }
        return try parseEquality()
    }

    mutating func parseEquality() throws -> Expr {
        var lhs = try parseRelational()
        let d = depth; defer { depth = d }
        while true {
            if isPunct("==") || isPunct("!=") { try deeper() }
            if isPunct("==") { advance(); lhs = .cmp(.eq, lhs, try parseRelational()); continue }
            if isPunct("!=") { advance(); lhs = .cmp(.ne, lhs, try parseRelational()); continue }
            if case .ident(let w) = cur {
                let ops: [String: StrOp] = ["contains": .contains, "icontains": .icontains, "startswith": .startswith,
                                            "istartswith": .istartswith, "endswith": .endswith, "iendswith": .iendswith, "iequals": .iequals]
                if let op = ops[w] { advance(); try deeper(); lhs = .strOp(op, lhs, try parseRelational()); continue }
                if w == "matches" {
                    advance(); try deeper()
                    guard case .regex(let b, let nc, let da) = cur else { throw YaraSyntaxError("expected regex after matches") }
                    advance()
                    lhs = .matches(lhs, try RegexProgram(source: b, nocase: nc, dotall: da))
                    continue
                }
            }
            return lhs
        }
    }

    mutating func parseRelational() throws -> Expr {
        var lhs = try parseOfOrArith()
        let d = depth; defer { depth = d }
        while true {
            let op: CmpOp
            if isPunct("<") { op = .lt } else if isPunct("<=") { op = .le } else if isPunct(">") { op = .gt } else if isPunct(">=") { op = .ge } else { return lhs }
            advance(); try deeper()
            lhs = .cmp(op, lhs, try parseOfOrArith())
        }
    }

    /// Arithmetic expression, or `<expr> of <set>` / `<expr>% of <set>`.
    mutating func parseOfOrArith() throws -> Expr {
        let e = try parseBitOr()
        if isIdent("of") { return try parseOfRest(.count(e)) }
        if isPunct("%"), isIdent("of", peek()) { advance(); return try parseOfRest(.percent(e)) }
        return e
    }

    mutating func parseBitOr() throws -> Expr {
        var l = try parseBitXor()
        let d = depth; defer { depth = d }
        while isPunct("|") { advance(); try deeper(); l = .arith(.bor, l, try parseBitXor()) }
        return l
    }
    mutating func parseBitXor() throws -> Expr {
        var l = try parseBitAnd()
        let d = depth; defer { depth = d }
        while isPunct("^") { advance(); try deeper(); l = .arith(.bxor, l, try parseBitAnd()) }
        return l
    }
    mutating func parseBitAnd() throws -> Expr {
        var l = try parseShift()
        let d = depth; defer { depth = d }
        while isPunct("&") { advance(); try deeper(); l = .arith(.band, l, try parseShift()) }
        return l
    }
    mutating func parseShift() throws -> Expr {
        var l = try parseAdd()
        let d = depth; defer { depth = d }
        while true {
            if isPunct("<<") { advance(); try deeper(); l = .arith(.shl, l, try parseAdd()) }
            else if isPunct(">>") { advance(); try deeper(); l = .arith(.shr, l, try parseAdd()) }
            else { return l }
        }
    }
    mutating func parseAdd() throws -> Expr {
        var l = try parseMul()
        let d = depth; defer { depth = d }
        while true {
            if isPunct("+") { advance(); try deeper(); l = .arith(.add, l, try parseMul()) }
            else if isPunct("-") { advance(); try deeper(); l = .arith(.sub, l, try parseMul()) }
            else { return l }
        }
    }
    mutating func parseMul() throws -> Expr {
        var l = try parseUnary()
        let d = depth; defer { depth = d }
        while true {
            if isPunct("*") { advance(); try deeper(); l = .arith(.mul, l, try parseUnary()) }
            else if isPunct("\\") { advance(); try deeper(); l = .arith(.div, l, try parseUnary()) }
            else if isPunct("%") && !isIdent("of", peek()) { advance(); try deeper(); l = .arith(.mod, l, try parseUnary()) }
            else { return l }
        }
    }
    mutating func parseUnary() throws -> Expr {
        let d = depth; defer { depth = d }
        if isPunct("-") { advance(); try deeper(); return .neg(try parseUnary()) }
        if isPunct("~") { advance(); try deeper(); return .bitnot(try parseUnary()) }
        return try parsePrimary()
    }

    mutating func parseRange() throws -> (Expr, Expr) {
        try expectPunct("(")
        let lo = try parseBitOr()
        try expectPunct("..")
        let hi = try parseBitOr()
        try expectPunct(")")
        return (lo, hi)
    }

    mutating func parseIndex() throws -> Expr {
        if isPunct("[") {
            advance()
            let e = try parseBitOr()
            try expectPunct("]")
            return e
        }
        return .intLit(1)
    }

    static let intFuncs: [String: (IntReader, Bool)] = [
        "uint8": (.u8, false), "uint16": (.u16, false), "uint32": (.u32, false),
        "int8": (.i8, false), "int16": (.i16, false), "int32": (.i32, false),
        "uint8be": (.u8, true), "uint16be": (.u16, true), "uint32be": (.u32, true),
        "int8be": (.i8, true), "int16be": (.i16, true), "int32be": (.i32, true),
    ]

    mutating func parsePrimary() throws -> Expr {
        let t = cur
        switch t {
        case .int(let v):
            advance()
            return .intLit(v)
        case .str(let s):
            advance()
            return .strLit(s)
        case .punct("("):
            advance()
            let e = try parseExpression()
            try expectPunct(")")
            return e
        case .strId(let name):
            advance()
            let id = try ctx.stringID(name)
            if isIdent("at") { advance(); return .stringAt(id, try parseBitOr()) }
            if isIdent("in") { advance(); let (lo, hi) = try parseRange(); return .stringIn(id, lo, hi) }
            return .stringFound(id)
        case .countId(let name):
            advance()
            let id = try ctx.stringID(name)
            if isIdent("in") { advance(); let (lo, hi) = try parseRange(); return .stringCountIn(id, lo, hi) }
            return .stringCount(id)
        case .offId(let name):
            advance()
            return .stringOffset(try ctx.stringID(name), try parseIndex())
        case .lenId(let name):
            advance()
            return .stringLength(try ctx.stringID(name), try parseIndex())
        case .ident(let w):
            return try parseIdentPrimary(w)
        default:
            throw YaraSyntaxError("unexpected token \(t)")
        }
    }

    mutating func parseIdentPrimary(_ w: String) throws -> Expr {
        switch w {
        case "true": advance(); return .boolLit(true)
        case "false": advance(); return .boolLit(false)
        case "filesize": advance(); return .filesize
        case "entrypoint": throw YaraSyntaxError("entrypoint is unsupported")
        case "all", "any", "none":
            advance()
            let q: Quantifier = w == "all" ? .all : (w == "any" ? .any : .none)
            guard isIdent("of") else { throw YaraSyntaxError("expected 'of' after \(w)") }
            return try parseOfRest(q)
        case "for":
            advance()
            return try parseFor()
        default: break
        }
        if let (reader, be) = ConditionParser.intFuncs[w] {
            advance()
            try expectPunct("(")
            let off = try parseBitOr()
            try expectPunct(")")
            return .readInt(reader, bigEndian: be, off)
        }
        if let slot = ctx.variable(w) { advance(); return .variable(slot) }
        if let idx = st.ruleIndex[namespace]?[w] { advance(); return .ruleRef(idx) }
        if st.skippedRules[namespace]?.contains(w) == true { throw YaraSyntaxError("depends on skipped rule \(w)") }
        if isPunct(".", peek()) {
            guard imports.contains(w) else { throw YaraSyntaxError("module \(w) not imported") }
            advance(); advance()
            guard case .ident(let member) = cur else { throw YaraSyntaxError("expected member of \(w)") }
            advance()
            switch w {
            case "hash": return try parseHashCall(member)
            case "macho": return try parseMacho(member)
            default: throw YaraSyntaxError("module \(w) is unsupported")
            }
        }
        if st.externals[w] != nil { advance(); return .external(w) }
        throw YaraSyntaxError("undefined identifier \(w)")
    }

    mutating func parseHashCall(_ fn: String) throws -> Expr {
        guard let h = HashFn(rawValue: fn) else { throw YaraSyntaxError("hash.\(fn) unsupported") }
        try expectPunct("(")
        let a = try parseBitOr()
        if isPunct(",") {
            advance()
            let b = try parseBitOr()
            try expectPunct(")")
            return .hash(h, a, b)
        }
        try expectPunct(")")
        return .hashString(h, a)
    }

    mutating func parseMacho(_ member: String) throws -> Expr {
        if let c = MachOInfo.constants[member] { return .intLit(c) }
        guard MachOInfo.fields.contains(member) else { throw YaraSyntaxError("macho.\(member) unsupported") }
        if isPunct("(") || isPunct("[") || isPunct(".") { throw YaraSyntaxError("macho.\(member) indexing unsupported") }
        return .machoField(member)
    }

    /// After a quantifier: `of` set [in range | at expr].
    mutating func parseOfRest(_ q: Quantifier) throws -> Expr {
        try expectIdent("of")
        if isIdent("them") {
            advance()
            guard !ctx.strings.isEmpty else { throw YaraSyntaxError("'them' with no strings") }
            let ids = Array(ctx.base..<(ctx.base + ctx.strings.count))
            return try ofTail(q, ids)
        }
        try expectPunct("(")
        // rule set or string set
        if case .ident = cur {
            var rules: [Int] = []
            while true {
                guard case .ident(let name) = cur else { throw YaraSyntaxError("bad rule set") }
                advance()
                if isPunct("*") {
                    advance()
                    let names = (st.ruleIndex[namespace] ?? [:]).filter { $0.key.hasPrefix(name) }.map(\.value).sorted()
                    guard !names.isEmpty else { throw YaraSyntaxError("no rules match \(name)*") }
                    rules += names
                } else {
                    guard let idx = st.ruleIndex[namespace]?[name] else { throw YaraSyntaxError("undefined rule \(name)") }
                    rules.append(idx)
                }
                if isPunct(",") { advance(); continue }
                break
            }
            try expectPunct(")")
            return .ofRules(q, rules)
        }
        var ids: [Int] = []
        while true {
            guard case .strId(let name) = cur else { throw YaraSyntaxError("bad string set near \(cur)") }
            advance()
            ids += try ctx.stringSet(name)
            if isPunct(",") { advance(); continue }
            break
        }
        try expectPunct(")")
        return try ofTail(q, ids)
    }

    mutating func ofTail(_ q: Quantifier, _ ids: [Int]) throws -> Expr {
        if isIdent("in") { advance(); let r = try parseRange(); return .ofStrings(q, ids, inRange: r, at: nil) }
        if isIdent("at") { advance(); return .ofStrings(q, ids, inRange: nil, at: try parseBitOr()) }
        return .ofStrings(q, ids, inRange: nil, at: nil)
    }

    mutating func parseQuantifier() throws -> Quantifier {
        if isIdent("all") { advance(); return .all }
        if isIdent("any") { advance(); return .any }
        if isIdent("none") { advance(); return .none }
        let e = try parseBitOr()
        if isPunct("%") { advance(); return .percent(e) }
        return .count(e)
    }

    mutating func parseFor() throws -> Expr {
        let q = try parseQuantifier()
        if isIdent("of") {
            advance()
            var ids: [Int]
            if isIdent("them") {
                advance()
                ids = Array(ctx.base..<(ctx.base + ctx.strings.count))
            } else {
                try expectPunct("(")
                ids = []
                while true {
                    guard case .strId(let name) = cur else { throw YaraSyntaxError("bad string set") }
                    advance()
                    ids += try ctx.stringSet(name)
                    if isPunct(",") { advance(); continue }
                    break
                }
                try expectPunct(")")
            }
            try expectPunct(":")
            try expectPunct("(")
            ctx.inForOf += 1
            let body = try parseExpression()
            ctx.inForOf -= 1
            try expectPunct(")")
            return .forOf(q, ids, body)
        }
        guard case .ident(let v) = cur else { throw YaraSyntaxError("expected loop variable") }
        advance()
        if isPunct(",") { throw YaraSyntaxError("multi-variable for loops unsupported") }
        try expectIdent("in")
        let iter: ForIterable
        try expectPunct("(")
        let first = try parseBitOr()
        if isPunct("..") {
            advance()
            let hi = try parseBitOr()
            iter = .range(first, hi)
        } else {
            var items = [first]
            while isPunct(",") { advance(); items.append(try parseBitOr()) }
            iter = .list(items)
        }
        try expectPunct(")")
        try expectPunct(":")
        try expectPunct("(")
        let slot = ctx.nextSlot
        ctx.nextSlot += 1
        ctx.maxSlots = max(ctx.maxSlots, ctx.nextSlot)
        ctx.scopes.append([v: slot])
        let body = try parseExpression()
        ctx.scopes.removeLast()
        ctx.nextSlot -= 1
        try expectPunct(")")
        return .forIn(q, slot: slot, iter, body)
    }
}
