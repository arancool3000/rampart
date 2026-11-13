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
        // o4: clamp to 512...4096 (RFC 6891 / DNS flag day 2020); a client asking for 65,535 gets 4096.
        additionals.first(where: { $0.type == DNSType.opt }).map { min(4096, max(512, Int($0.rclass))) }
    }

    /// True when the client's OPT record sets the DNSSEC OK bit.
    public var dnssecOK: Bool {
        additionals.first(where: { $0.type == DNSType.opt }).map { $0.ttl & 0x8000 != 0 } ?? false
    }

    /// o4: structural checks a standard query must pass (RFC 6891 6.1.1: at most one OPT, only in the additional
    /// section, owned by the root). Queries carrying answer/authority records are refused as well: they are never
    /// needed for opcode 0 and only give an attacker more bytes to smuggle upstream.
    public var isWellFormedQuery: Bool {
        guard answers.isEmpty, authorities.isEmpty else { return false }
        let opts = additionals.filter { $0.type == DNSType.opt }
        guard opts.count <= 1 else { return false }
        if let o = opts.first, !o.name.isEmpty { return false }
        return true
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

    /// o4: the query RamPart sends upstream for `query`. It is rebuilt from the question alone (the client's other
    /// records, EDNS options such as Client Subnet, and odd header bits are never forwarded). RD is set, CD is
    /// cleared so the upstream always validates DNSSEC (a client-set CD would accept answers the upstream rejected),
    /// and, if the client sent EDNS, a fresh OPT advertises 4096 bytes keeping only the client's DO bit.
    public static func upstreamQuery(for query: DNSMessage) -> Data {
        var m = DNSMessage(id: query.id, flags: 0x0100)
        m.questions = Array(query.questions.prefix(1))
        // OPT only when the client spoke EDNS (RFC 6891 7: no OPT in a reply to a query without one).
        if query.additionals.contains(where: { $0.type == DNSType.opt }) {
            m.additionals = [DNSResourceRecord(name: "", type: DNSType.opt, rclass: 4096,
                                               ttl: query.dnssecOK ? 0x8000 : 0, rdata: Data())]
        }
        return m.serialize()
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


/// o4: DNS-rebinding guard. A public name must never resolve to this Mac, the LAN or link-local space, otherwise
/// a web page can rename itself to 127.0.0.1 / 192.168.x.x and talk to local services (routers, dev servers,
/// RamPart-local ports) with the page's own origin. Private answers from the public DoH upstream are stripped
/// unless the name is a local-only name or a well-known developer "points at localhost" domain, or the user
/// allowlisted it.
public enum DNSRebindGuard {
    /// Local-only suffixes (RFC 6761/6762/8375 and common LAN names) plus developer domains that resolve to
    /// loopback/LAN on purpose (no false positives for the user's own dev tools).
    public static let exemptSuffixes: [String] = [
        "localhost", "local", "lan", "home.arpa", "internal", "localdomain", "home", "corp", "intranet", "private",
        "in-addr.arpa", "ip6.arpa", "plex.direct", "lvh.me", "localtest.me", "nip.io", "sslip.io",
        "localhost.direct", "traefik.me", "ts.net",
    ]

    public static func isExempt(_ rawName: String) -> Bool {
        let name = DNSWire.normalize(rawName)
        if !name.contains(".") { return true }   // single-label names are local by definition
        return exemptSuffixes.contains { name == $0 || name.hasSuffix("." + $0) }
    }

    /// Loopback, unspecified, RFC 1918, link-local, multicast/reserved, ULA/site-local, and IPv4 embedded in
    /// mapped/compatible/NAT64 IPv6 forms. CGNAT (100.64/10) is not included: VPN overlays use it for public names.
    public static func isPrivate(_ b: [UInt8]) -> Bool {
        if b.count == 4 {
            switch b[0] {
            case 0, 10, 127: return true
            case 169: return b[1] == 254
            case 172: return b[1] & 0xF0 == 16
            case 192: return b[1] == 168 || (b[1] == 0 && b[2] == 0)
            default: return b[0] >= 224
            }
        }
        guard b.count == 16 else { return true }
        if b.allSatisfy({ $0 == 0 }) { return true }                                   // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return true }            // ::1
        if b[0] & 0xFE == 0xFC { return true }                                          // fc00::/7
        if b[0] == 0xFE && (b[1] & 0xC0 == 0x80 || b[1] & 0xC0 == 0xC0) { return true } // fe80::/10, fec0::/10
        if b[0] == 0xFF { return true }                                                 // multicast
        let embedded = Array(b[12..<16])
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF { return isPrivate(embedded) } // ::ffff:a.b.c.d
        if b[0..<12].allSatisfy({ $0 == 0 }) { return isPrivate(embedded) }                                   // ::a.b.c.d
        if b[0...11] == [0, 0x64, 0xFF, 0x9B, 0, 0, 0, 0, 0, 0, 0, 0] { return isPrivate(embedded) }        // 64:ff9b::/96
        return false
    }

    public static func isPrivate(address: String) -> Bool { DNSWire.addressBytes(address).map(isPrivate) ?? false }

    /// SVCB/HTTPS (RFC 9460) rdata: true when an ipv4hint/ipv6hint carries a private address, or the rdata
    /// cannot be parsed (an unparseable record is never trusted).
    static func svcbHasPrivateHint(_ rdata: Data) -> Bool {
        let r = [UInt8](rdata)
        guard r.count >= 3 else { return true }
        guard let (_, afterName) = try? DNSWire.readName(r, at: 2) else { return true }
        var off = afterName
        while off < r.count {
            guard off + 4 <= r.count else { return true }
            let key = Int(r[off]) << 8 | Int(r[off + 1]), len = Int(r[off + 2]) << 8 | Int(r[off + 3])
            let v = off + 4
            guard v + len <= r.count else { return true }
            if key == 4 || key == 6 {
                let w = key == 4 ? 4 : 16
                guard len % w == 0 else { return true }
                var i = v
                while i < v + len { if isPrivate(Array(r[i..<(i + w)])) { return true }; i += w }
            }
            off = v + len
        }
        return false
    }

    /// Returns the response with every private address record removed (A, AAAA, SVCB/HTTPS with private hints,
    /// and private glue in the additional section), plus the stripped values; nil when nothing needed stripping.
    /// CNAMEs are kept (re-encoded, since their rdata may hold compression pointers into the original message).
    public static func strip(_ data: Data, question: DNSQuestion) -> (Data, [String])? {
        guard !isExempt(question.name), let m = try? DNSMessage.parse(data) else { return nil }
        var stripped: [String] = []
        func bad(_ rr: DNSResourceRecord) -> Bool {
            switch rr.type {
            case DNSType.a where rr.rdata.count == 4, DNSType.aaaa where rr.rdata.count == 16:
                if isPrivate([UInt8](rr.rdata)) { stripped.append(rr.value ?? "?"); return true }
            case DNSType.svcb, DNSType.https:
                if svcbHasPrivateHint(rr.rdata) { stripped.append(DNSType.name(rr.type) + " hint"); return true }
            default: break
            }
            return false
        }
        let keep = m.answers.filter { !bad($0) }
        let addl = m.additionals.filter { !bad($0) }
        guard !stripped.isEmpty else { return nil }
        var out = DNSMessage(id: m.id, flags: m.flags)
        out.questions = m.questions
        for rr in keep {
            switch rr.type {
            case DNSType.a, DNSType.aaaa, DNSType.svcb, DNSType.https:
                out.answers.append(rr)
            case DNSType.cname:
                guard let v = rr.value, !v.isEmpty else { continue }
                var c = rr; c.rdata = Data(DNSWire.encodeName(v)); out.answers.append(c)
            default: continue   // other types may carry compressed rdata; drop rather than corrupt
            }
        }
        out.additionals = addl.filter { $0.type == DNSType.opt }
        return (out.serialize(), stripped)
    }
}
