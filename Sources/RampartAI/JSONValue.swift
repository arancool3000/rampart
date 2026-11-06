import Foundation

/// Minimal JSON tree used for response schemas and fixtures.
public indirect enum JSONValue: Codable, Hashable, Sendable, ExpressibleByStringLiteral, ExpressibleByIntegerLiteral,
                                ExpressibleByBooleanLiteral, ExpressibleByArrayLiteral, ExpressibleByDictionaryLiteral {
    case string(String), number(Double), bool(Bool), array([JSONValue]), object([String: JSONValue]), null

    public init(stringLiteral v: String) { self = .string(v) }
    public init(integerLiteral v: Int) { self = .number(Double(v)) }
    public init(booleanLiteral v: Bool) { self = .bool(v) }
    public init(arrayLiteral e: JSONValue...) { self = .array(e) }
    public init(dictionaryLiteral e: (String, JSONValue)...) { self = .object(Dictionary(e, uniquingKeysWith: { $1 })) }

    public init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if c.decodeNil() { self = .null }
        else if let b = try? c.decode(Bool.self) { self = .bool(b) }
        else if let n = try? c.decode(Double.self) { self = .number(n) }
        else if let s = try? c.decode(String.self) { self = .string(s) }
        else if let a = try? c.decode([JSONValue].self) { self = .array(a) }
        else { self = .object(try c.decode([String: JSONValue].self)) }
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch self {
        case .string(let s): try c.encode(s)
        case .number(let n): if n.rounded() == n && abs(n) < 1e15 { try c.encode(Int(n)) } else { try c.encode(n) }
        case .bool(let b): try c.encode(b)
        case .array(let a): try c.encode(a)
        case .object(let o): try c.encode(o)
        case .null: try c.encodeNil()
        }
    }

    public subscript(key: String) -> JSONValue? { if case .object(let o) = self { return o[key] }; return nil }

    // Schema helpers (JSON Schema subset accepted by Gemini's responseJsonSchema).
    public static func str(_ desc: String, enum values: [String]? = nil) -> JSONValue {
        var o: [String: JSONValue] = ["type": "string", "description": .string(desc)]
        if let values { o["enum"] = .array(values.map { .string($0) }) }
        return .object(o)
    }
    public static func int(_ desc: String, min: Int, max: Int) -> JSONValue {
        ["type": "integer", "description": .string(desc), "minimum": .number(Double(min)), "maximum": .number(Double(max))]
    }
    public static func bool(_ desc: String) -> JSONValue { ["type": "boolean", "description": .string(desc)] }
    public static func list(_ items: JSONValue, _ desc: String, maxItems: Int) -> JSONValue {
        ["type": "array", "description": .string(desc), "items": items, "maxItems": .number(Double(maxItems))]
    }
    public static func obj(_ props: [String: JSONValue], required: [String]? = nil, order: [String]? = nil) -> JSONValue {
        var o: [String: JSONValue] = ["type": "object", "properties": .object(props),
                                      "required": .array((required ?? props.keys.sorted()).map { .string($0) })]
        if let order { o["propertyOrdering"] = .array(order.map { .string($0) }) }
        return .object(o)
    }
}
