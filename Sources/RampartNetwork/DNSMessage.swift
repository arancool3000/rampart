import Foundation

/// DNS record types used by Rampart (RFC 1035 / 3596 / 9460). Unknown types are carried as raw UInt16.
public enum DNSType {
    public static let a: UInt16 = 1
    public static let ns: UInt16 = 2
    public static let cname: UInt16 = 5
    public static let soa: UInt16 = 6
    public static let ptr: UInt16 = 12
    public static let mx: UInt16 = 15
    public static let txt: UInt16 = 16
    public static let aaaa: UInt16 = 28
    public static let srv: UInt16 = 33
    public static let opt: UInt16 = 41
    public static let svcb: UInt16 = 64
    public static let https: UInt16 = 65
    public static let any: UInt16 = 255

    public static func name(_ t: UInt16) -> String {
        switch t {
        case a: return "A"; case ns: return "NS"; case cname: return "CNAME"; case soa: return "SOA"
        case ptr: return "PTR"; case mx: return "MX"; case txt: return "TXT"; case aaaa: return "AAAA"
        case srv: return "SRV"; case opt: return "OPT"; case svcb: return "SVCB"; case https: return "HTTPS"
        case any: return "ANY"; default: return "TYPE\(t)"
        }
    }
}

public enum DNSRCode {
    public static let noError: UInt8 = 0
    public static let formErr: UInt8 = 1
    public static let servFail: UInt8 = 2
    public static let nxDomain: UInt8 = 3
    public static let notImp: UInt8 = 4
    public static let refused: UInt8 = 5
}

public enum DNSParseError: Error, Equatable {
    case truncated, badLabel, pointerLoop, nameTooLong
}

public struct DNSQuestion: Hashable, Sendable {
    public var name: String      // lowercase, no trailing dot
    public var type: UInt16
    public var qclass: UInt16
    public init(name: String, type: UInt16, qclass: UInt16 = 1) {
        self.name = DNSWire.normalize(name); self.type = type; self.qclass = qclass
    }
}

public struct DNSResourceRecord: Sendable {
    public var name: String
    public var type: UInt16
    public var rclass: UInt16
    public var ttl: UInt32
    public var rdata: Data
    /// Byte offset of the TTL field inside the message it was parsed from (for TTL rewriting).
    public var ttlOffset: Int
    /// Decoded value for A/AAAA (address text) and CNAME/NS/PTR (target name). nil otherwise.
    public var value: String?
    public init(name: String, type: UInt16, rclass: UInt16 = 1, ttl: UInt32, rdata: Data, value: String? = nil) {
        self.name = DNSWire.normalize(name); self.type = type; self.rclass = rclass; self.ttl = ttl
        self.rdata = rdata; self.ttlOffset = -1; self.value = value
    }
}

/// A parsed DNS message (RFC 1035 section 4).
public struct DNSMessage: Sendable {
    public var id: UInt16
    public var flags: UInt16
    public var questions: [DNSQuestion] = []
    public var answers: [DNSResourceRecord] = []
    public var authorities: [DNSResourceRecord] = []
    public var additionals: [DNSResourceRecord] = []

    public init(id: UInt16, flags: UInt16) { self.id = id; self.flags = flags }

    public var isResponse: Bool { flags & 0x8000 != 0 }
    public var opcode: UInt8 { UInt8((flags >> 11) & 0xF) }
    public var truncated: Bool { flags & 0x0200 != 0 }
    public var recursionDesired: Bool { flags & 0x0100 != 0 }
    public var rcode: UInt8 { UInt8(flags & 0xF) }

    /// EDNS0 UDP payload size advertised in an OPT record, if any.
    public var ednsPayloadSize: Int? {
        additionals.first(where: { $0.type == DNSType.opt }).map { max(512, Int($0.rclass)) }
    }

    public static func parse(_ data: Data) throws -> DNSMessage {
        let b = [UInt8](data)
        guard b.count >= 12 else { throw DNSParseError.truncated }
        func u16(_ o: Int) -> UInt16 { UInt16(b[o]) << 8 | UInt16(b[o + 1]) }
        var m = DNSMessage(id: u16(0), flags: u16(2))
        let qd = Int(u16(4)), an = Int(u16(6)), ns = Int(u16(8)), ar = Int(u16(10))
        var off = 12
        for _ in 0..<qd {
            let (name, next) = try DNSWire.readName(b, at: off)
            guard next + 4 <= b.count else { throw DNSParseError.truncated }
            m.questions.append(DNSQuestion(name: name, type: u16(next), qclass: u16(next + 2)))
            off = next + 4
        }
        func readRR() throws -> DNSResourceRecord {
            let (name, next) = try DNSWire.readName(b, at: off)
            guard next + 10 <= b.count else { throw DNSParseError.truncated }
            let type = u16(next), cls = u16(next + 2)
            let ttl = UInt32(u16(next + 4)) << 16 | UInt32(u16(next + 6))
            let rdlen = Int(u16(next + 8))
            let start = next + 10
            guard start + rdlen <= b.count else { throw DNSParseError.truncated }
            var rr = DNSResourceRecord(name: name, type: type, rclass: cls, ttl: ttl,
                                       rdata: Data(b[start..<(start + rdlen)]))
            rr.ttlOffset = next + 4
            switch type {
            case DNSType.a where rdlen == 4, DNSType.aaaa where rdlen == 16:
                rr.value = DNSWire.addressString(Array(b[start..<(start + rdlen)]))
            case DNSType.cname, DNSType.ns, DNSType.ptr:
                rr.value = try? DNSWire.readName(b, at: start).0
            default: break
            }
            off = start + rdlen
            return rr
        }
        for _ in 0..<an { m.answers.append(try readRR()) }
        for _ in 0..<ns { m.authorities.append(try readRR()) }
        for _ in 0..<ar { m.additionals.append(try readRR()) }
        return m
    }

    /// Serialises without name compression.
    public func serialize() -> Data {
        var out = [UInt8]()
        func put16(_ v: UInt16) { out.append(UInt8(v >> 8)); out.append(UInt8(v & 0xFF)) }
        func put32(_ v: UInt32) { put16(UInt16(v >> 16)); put16(UInt16(v & 0xFFFF)) }
        put16(id); put16(flags)
        put16(UInt16(questions.count)); put16(UInt16(answers.count))
        put16(UInt16(authorities.count)); put16(UInt16(additionals.count))
        for q in questions { out += DNSWire.encodeName(q.name); put16(q.type); put16(q.qclass) }
        for rr in answers + authorities + additionals {
            out += DNSWire.encodeName(rr.name); put16(rr.type); put16(rr.rclass); put32(rr.ttl)
            put16(UInt16(rr.rdata.count)); out += rr.rdata
        }
        return Data(out)
    }
}

public enum DNSWire {
    public static func normalize(_ name: String) -> String {
        var s = name.lowercased()
        while s.hasSuffix("."), !s.hasSuffix("\\.") || s.hasSuffix("\\\\.") { s.removeLast() }
        return s
    }

    /// Reads a possibly compressed name. Returns the name and the offset just past it in the original stream.
    /// Hardening (hx4): compression pointers must point strictly backwards (RFC 1035 4.1.4 "prior occurrence"),
    /// which makes loops impossible; the jump count and 255-byte wire length are still capped. Label bytes
    /// that would change the meaning of the text form are escaped in RFC 4343 presentation format: an embedded
    /// `.` becomes `\.`, a backslash `\\`, and control bytes `\DDD`, so a single label such as
    /// "evil.example" can never masquerade as two labels, and attacker bytes cannot inject newlines into logs/UI.
    public static func readName(_ b: [UInt8], at start: Int) throws -> (String, Int) {
        var labels: [String] = []
        var off = start, end = -1, jumps = 0, total = 0
        while true {
            guard off >= 0, off < b.count else { throw DNSParseError.truncated }
            let len = Int(b[off])
            if len == 0 { off += 1; total += 1; break }
            if len & 0xC0 == 0xC0 {
                guard off + 1 < b.count else { throw DNSParseError.truncated }
                let ptr = (len & 0x3F) << 8 | Int(b[off + 1])
                if end < 0 { end = off + 2 }
                jumps += 1
                guard jumps < 64, ptr < off, ptr < b.count else { throw DNSParseError.pointerLoop }
                off = ptr; continue
            }
            guard len & 0xC0 == 0 else { throw DNSParseError.badLabel }
            guard off + 1 + len <= b.count else { throw DNSParseError.truncated }
            total += len + 1
            guard total <= 255 else { throw DNSParseError.nameTooLong }
            labels.append(escapeLabel(b[(off + 1)...(off + len)]))
            off += 1 + len
        }
        guard total <= 255 else { throw DNSParseError.nameTooLong }
        return (labels.joined(separator: "."), end >= 0 ? end : off)
    }

    /// RFC 4343 presentation escaping of one label (lowercased ASCII; UTF-8 bytes kept for mDNS names).
    static func escapeLabel(_ bytes: ArraySlice<UInt8>) -> String {
        var out = [UInt8](); out.reserveCapacity(bytes.count)
        for var c in bytes {
            if c >= 0x41 && c <= 0x5A { c += 0x20 }
            if c == 0x2E || c == 0x5C { out.append(0x5C); out.append(c) }
            else if c < 0x20 || c == 0x7F {
                out.append(0x5C); out += Array(String(format: "%03d", Int(c)).utf8)
            } else { out.append(c) }
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Splits presentation text into wire labels, undoing `\.`, `\\` and `\DDD` escapes.
    static func wireLabels(_ name: String) -> [[UInt8]] {
        let b = Array(name.utf8)
        var labels: [[UInt8]] = [], cur: [UInt8] = [], i = 0
        while i < b.count {
            let c = b[i]
            if c == 0x5C, i + 1 < b.count {
                if i + 3 < b.count, (b[i+1...i+3]).allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }),
                   let v = Int(String(decoding: b[i+1...i+3], as: UTF8.self)), v <= 255 {
                    cur.append(UInt8(v)); i += 4; continue
                }
                cur.append(b[i + 1]); i += 2; continue
            }
            if c == 0x2E { if !cur.isEmpty { labels.append(cur) }; cur = []; i += 1; continue }
            cur.append(c); i += 1
        }
        if !cur.isEmpty { labels.append(cur) }
        return labels
    }

    public static func encodeName(_ name: String) -> [UInt8] {
        var out = [UInt8]()
        for label in wireLabels(normalize(name)) {
            let bytes = Array(label.prefix(63))
            guard out.count + bytes.count + 2 <= 255 else { break }
            out.append(UInt8(bytes.count)); out += bytes
        }
        out.append(0)
        return out
    }

    static func addressString(_ bytes: [UInt8]) -> String {
        var buf = [CChar](repeating: 0, count: 64)
        let family = bytes.count == 4 ? AF_INET : AF_INET6
        return bytes.withUnsafeBytes { raw in
            inet_ntop(family, raw.baseAddress, &buf, socklen_t(buf.count)) != nil
                ? String(cString: buf) : ""
        }
    }

    static func addressBytes(_ text: String) -> [UInt8]? {
        var v4 = in_addr(), v6 = in6_addr()
        if inet_pton(AF_INET, text, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        if inet_pton(AF_INET6, text, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    /// Builds a standard recursive query.
    public static func buildQuery(name: String, type: UInt16, id: UInt16 = UInt16.random(in: 0...UInt16.max)) -> Data {
        var m = DNSMessage(id: id, flags: 0x0100)
        m.questions = [DNSQuestion(name: name, type: type)]
        return m.serialize()
    }

    /// Response flags derived from a query: QR=1, opcode and RD copied, RA=1, given rcode.
    static func responseFlags(for query: DNSMessage, rcode: UInt8) -> UInt16 {
        0x8000 | (query.flags & 0x7900) | 0x0080 | UInt16(rcode & 0xF)
    }

    /// Answer for a blocked name. `nullAddress` gives 0.0.0.0 / :: for A/AAAA and NODATA for other types.
    public static func buildBlockedResponse(for query: DNSMessage, mode: DNSFilterConfig.BlockMode, ttl: UInt32) -> Data {
        var r = DNSMessage(id: query.id, flags: responseFlags(for: query, rcode: mode == .nxdomain ? DNSRCode.nxDomain : DNSRCode.noError))
        r.questions = Array(query.questions.prefix(1))
        if mode == .nullAddress, let q = r.questions.first, q.qclass == 1 {
            if q.type == DNSType.a {
                r.answers = [DNSResourceRecord(name: q.name, type: DNSType.a, ttl: ttl, rdata: Data([0, 0, 0, 0]), value: "0.0.0.0")]
            } else if q.type == DNSType.aaaa {
                r.answers = [DNSResourceRecord(name: q.name, type: DNSType.aaaa, ttl: ttl, rdata: Data(count: 16), value: "::")]
            }
        }
        return r.serialize()
    }

    /// Header + question with the given rcode (used for NXDOMAIN canaries, SERVFAIL, NOTIMP).
    public static func buildError(for query: DNSMessage, rcode: UInt8) -> Data {
        var r = DNSMessage(id: query.id, flags: responseFlags(for: query, rcode: rcode))
        r.questions = Array(query.questions.prefix(1))
        return r.serialize()
    }

    /// FORMERR for something we could not parse beyond the header.
    static func buildFormErr(raw: Data) -> Data? {
        guard raw.count >= 12 else { return nil }
        let b = [UInt8](raw)
        return Data([b[0], b[1], 0x80 | (b[2] & 0x79), 0x80 | DNSRCode.formErr, 0, 0, 0, 0, 0, 0, 0, 0])
    }

    /// Rewrites the message ID in place.
    static func withID(_ data: Data, _ id: UInt16) -> Data {
        var d = data
        guard d.count >= 2 else { return d }
        d[d.startIndex] = UInt8(id >> 8); d[d.startIndex + 1] = UInt8(id & 0xFF)
        return d
    }

    /// If `data` exceeds `limit` bytes, returns header + question with TC set (client retries over TCP).
    static func truncateIfNeeded(_ data: Data, limit: Int, query: DNSMessage) -> Data {
        guard data.count > limit else { return data }
        var r = DNSMessage(id: query.id, flags: 0)
        if let parsed = try? DNSMessage.parse(data) { r.flags = parsed.flags } else { r.flags = responseFlags(for: query, rcode: 0) }
        r.flags |= 0x0200
        r.questions = Array(query.questions.prefix(1))
        return r.serialize()
    }
}
