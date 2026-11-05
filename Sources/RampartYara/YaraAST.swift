import Foundation

// Native, pure-Swift YARA-compatible rule engine: abstract syntax shared by parser, compiler and scanner.

/// Value of a meta field.
public enum YaraMetaValue: Hashable, Sendable, CustomStringConvertible {
    case string(String), int(Int64), bool(Bool)
    public var description: String {
        switch self {
        case .string(let s): return s
        case .int(let i): return String(i)
        case .bool(let b): return b ? "true" : "false"
        }
    }
}

/// Value of an external variable supplied per scan (e.g. `filepath`).
public enum YaraExternal: Hashable, Sendable {
    case int(Int64), bool(Bool), string(String)
}

/// Runtime value inside condition evaluation. `undefined` propagates like YARA's UNDEFINED.
enum YValue {
    case int(Int64)
    case bool(Bool)
    case str([UInt8])
    case undefined

    var truthy: Bool {
        switch self {
        case .int(let i): return i != 0
        case .bool(let b): return b
        case .str(let s): return !s.isEmpty
        case .undefined: return false
        }
    }
    var int: Int64? {
        switch self {
        case .int(let i): return i
        case .bool(let b): return b ? 1 : 0
        default: return nil
        }
    }
}

// MARK: - Strings

struct StringModifiers: OptionSet, Hashable {
    let rawValue: UInt8
    static let ascii = StringModifiers(rawValue: 1)
    static let wide = StringModifiers(rawValue: 2)
    static let nocase = StringModifiers(rawValue: 4)
    static let fullword = StringModifiers(rawValue: 8)
    static let privateString = StringModifiers(rawValue: 16)
}

/// One element of a hex string.
indirect enum HexElem {
    /// Run of bytes; `masks[i] == 0` is a full wildcard, `negate[i]` implements `~XX`.
    case bytes(values: [UInt8], masks: [UInt8], negate: [Bool])
    case jump(min: Int, max: Int)          // max == Int.max for unbounded
    case alt([[HexElem]])
}

enum StringBody {
    case text([UInt8])
    case hex([HexElem])
    case regex(RegexProgram)
}

struct StringDef {
    var identifier: String       // "$a", or "$" for anonymous
    var body: StringBody
    var modifiers: StringModifiers
}

// MARK: - Conditions

enum Quantifier {
    case all, any, none
    case count(Expr)
    case percent(Expr)
}

enum CmpOp { case eq, ne, lt, le, gt, ge }
enum ArithOp { case add, sub, mul, div, mod, band, bor, bxor, shl, shr }
enum StrOp { case contains, icontains, startswith, istartswith, endswith, iendswith, iequals }
enum HashFn: String { case md5, sha1, sha256, crc32 }

enum IntReader {
    case u8, u16, u32, i8, i16, i32
    var size: Int {
        switch self { case .u8, .i8: return 1; case .u16, .i16: return 2; case .u32, .i32: return 4 }
    }
    var signed: Bool {
        switch self { case .i8, .i16, .i32: return true; default: return false }
    }
}

enum ForIterable {
    case range(Expr, Expr)
    case list([Expr])
}

/// Condition expression. String ids are global indexes into `CompiledRules.strings`;
/// `-1` means "the string currently bound by an enclosing `for ... of` loop" (anonymous `$`, `#`, `@`, `!`).
indirect enum Expr {
    case boolLit(Bool)
    case intLit(Int64)
    case strLit([UInt8])
    case filesize
    case stringFound(Int)
    case stringAt(Int, Expr)
    case stringIn(Int, Expr, Expr)
    case stringCount(Int)
    case stringCountIn(Int, Expr, Expr)
    case stringOffset(Int, Expr)
    case stringLength(Int, Expr)
    case ruleRef(Int)
    case not(Expr)
    case and([Expr])
    case or([Expr])
    case cmp(CmpOp, Expr, Expr)
    case arith(ArithOp, Expr, Expr)
    case neg(Expr)
    case bitnot(Expr)
    case readInt(IntReader, bigEndian: Bool, Expr)
    case ofStrings(Quantifier, [Int], inRange: (Expr, Expr)?, at: Expr?)
    case ofRules(Quantifier, [Int])
    case forOf(Quantifier, [Int], Expr)
    case forIn(Quantifier, slot: Int, ForIterable, Expr)
    case variable(Int)
    case hash(HashFn, Expr, Expr)
    case hashString(HashFn, Expr)
    case strOp(StrOp, Expr, Expr)
    case matches(Expr, RegexProgram)
    case external(String)
    case machoField(String)
    case defined(Expr)
}

// MARK: - Rules

struct ParsedRule {
    var name: String
    var tags: [String]
    var meta: [(String, YaraMetaValue)]
    var isPrivate: Bool
    var isGlobal: Bool
    var stringIDs: [Int]          // global string ids owned by this rule
    var condition: Expr
    var namespace: String
    var slotCount: Int
}
