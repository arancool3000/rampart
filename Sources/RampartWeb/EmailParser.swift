import Foundation

/// Minimal RFC 5322 / MIME parser: enough to pull headers, the text and HTML bodies and attachment
/// names out of a pasted raw email or a dropped .eml file. Tolerant of partial input (headers only).
public struct ParsedEmail: Sendable {
    public struct Address: Sendable, Hashable {
        public var displayName: String?
        public var address: String?
        public var domain: String? { address?.split(separator: "@").last.map { String($0).lowercased() } }
    }
    public var headers: [(name: String, value: String)] = []
    public var plainText: String = ""
    public var html: String? = nil
    public var attachments: [String] = []

    public var subject: String { header("Subject") }
    public var from: Address { ParsedEmail.parseAddress(header("From")) }
    public var replyTo: Address { ParsedEmail.parseAddress(header("Reply-To")) }
    public var returnPath: Address { ParsedEmail.parseAddress(header("Return-Path")) }

    public func header(_ name: String) -> String {
        headers.filter { $0.name.caseInsensitiveCompare(name) == .orderedSame }.map(\.value).joined(separator: " ")
    }

    static let headerLine = try! NSRegularExpression(pattern: #"^[A-Za-z][A-Za-z0-9-]{0,40}:\s"#, options: [.anchorsMatchLines])

    /// True when the text starts with several header lines (From:, Subject:, Received:, ...).
    public static func looksLikeRawEmail(_ text: String) -> Bool {
        let head = text.split(separator: "\n", maxSplits: 25, omittingEmptySubsequences: false).prefix(25)
        var count = 0, known = 0
        for line in head {
            let l = String(line)
            if l.isEmpty { break }
            if headerLine.firstMatch(in: l, range: NSRange(location: 0, length: (l as NSString).length)) != nil {
                count += 1
                let name = l.prefix { $0 != ":" }.lowercased()
                if ["from", "to", "subject", "received", "date", "message-id", "return-path", "authentication-results", "dkim-signature", "reply-to", "mime-version", "content-type", "received-spf", "x-mailer", "delivered-to"].contains(name) { known += 1 }
            }
        }
        return known >= 2 && count >= 3
    }

    public init(raw: String) {
        let normalized = raw.replacingOccurrences(of: "\r\n", with: "\n")
        let (head, body) = ParsedEmail.splitHeadBody(normalized)
        headers = ParsedEmail.parseHeaders(head)
        let ct = header("Content-Type")
        let cte = header("Content-Transfer-Encoding").lowercased()
        parseBody(body, contentType: ct, encoding: cte, depth: 0)
        if plainText.isEmpty, let html { plainText = PageAnalyzer.visibleText(html) }
        plainText = plainText.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    static func splitHeadBody(_ s: String) -> (String, String) {
        if let r = s.range(of: "\n\n") { return (String(s[..<r.lowerBound]), String(s[r.upperBound...])) }
        // Headers only, or body without a blank line: treat lines that don't look like headers as body.
        let lines = s.split(separator: "\n", omittingEmptySubsequences: false)
        var i = 0
        while i < lines.count {
            let l = String(lines[i])
            let isHeader = headerLine.firstMatch(in: l, range: NSRange(location: 0, length: (l as NSString).length)) != nil
            let isFold = l.hasPrefix(" ") || l.hasPrefix("\t")
            if !isHeader && !isFold { break }
            i += 1
        }
        return (lines[..<i].joined(separator: "\n"), lines[i...].joined(separator: "\n"))
    }

    static func parseHeaders(_ head: String) -> [(String, String)] {
        var out: [(String, String)] = []
        for line in head.split(separator: "\n", omittingEmptySubsequences: false) {
            if line.hasPrefix(" ") || line.hasPrefix("\t"), !out.isEmpty {
                out[out.count - 1].1 += " " + line.trimmingCharacters(in: .whitespaces)
            } else if let c = line.firstIndex(of: ":") {
                out.append((String(line[..<c]), decodeRFC2047(String(line[line.index(after: c)...]).trimmingCharacters(in: .whitespaces))))
            }
        }
        return out
    }

    mutating func parseBody(_ body: String, contentType: String, encoding: String, depth: Int) {
        let ctLower = contentType.lowercased()
        if ctLower.contains("multipart/"), depth < 6, let boundary = ParsedEmail.param("boundary", in: contentType) {
            let parts = body.components(separatedBy: "--" + boundary)
            for part in parts.dropFirst() {
                let p = part.trimmingCharacters(in: .whitespacesAndNewlines)
                if p == "--" || p.isEmpty || p.hasPrefix("--\n") { continue }
                let (h, b) = ParsedEmail.splitHeadBody(p.hasPrefix("\n") ? String(p.dropFirst()) : p)
                let hdrs = ParsedEmail.parseHeaders(h)
                let pct = hdrs.first { $0.0.caseInsensitiveCompare("Content-Type") == .orderedSame }?.1 ?? "text/plain"
                let penc = hdrs.first { $0.0.caseInsensitiveCompare("Content-Transfer-Encoding") == .orderedSame }?.1.lowercased() ?? ""
                let disp = hdrs.first { $0.0.caseInsensitiveCompare("Content-Disposition") == .orderedSame }?.1 ?? ""
                if disp.lowercased().contains("attachment") || (!pct.lowercased().hasPrefix("text/") && !pct.lowercased().hasPrefix("multipart/")) {
                    if let n = ParsedEmail.param("filename", in: disp) ?? ParsedEmail.param("name", in: pct) { attachments.append(n) }
                    continue
                }
                parseBody(b, contentType: pct, encoding: penc, depth: depth + 1)
            }
            return
        }
        var decoded = body
        if encoding.contains("quoted-printable") { decoded = ParsedEmail.decodeQuotedPrintable(body) }
        else if encoding.contains("base64") {
            let clean = body.filter { !$0.isWhitespace }
            if let d = Data(base64Encoded: clean), let s = String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1) { decoded = s }
        }
        if ctLower.contains("text/html") { html = (html ?? "") + decoded }
        else if plainText.isEmpty || ctLower.contains("text/plain") { plainText += decoded }
    }

    static func param(_ name: String, in headerValue: String) -> String? {
        let re = try! NSRegularExpression(pattern: "(?i)\\b" + name + "\\*?=\\s*\"?([^\";]+)\"?")
        let ns = headerValue as NSString
        guard let m = re.firstMatch(in: headerValue, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return ns.substring(with: m.range(at: 1)).trimmingCharacters(in: .whitespaces)
    }

    public static func decodeQuotedPrintable(_ s: String) -> String {
        var bytes: [UInt8] = []
        let u = Array(s.utf8)
        var i = 0
        while i < u.count {
            if u[i] == UInt8(ascii: "=") {
                if i + 1 < u.count, u[i + 1] == UInt8(ascii: "\n") { i += 2; continue }
                if i + 2 < u.count, let h = UInt8(String(bytes: u[(i + 1)...(i + 2)], encoding: .ascii) ?? "", radix: 16) { bytes.append(h); i += 3; continue }
            }
            bytes.append(u[i]); i += 1
        }
        return String(decoding: bytes, as: UTF8.self)
    }

    static let rfc2047 = try! NSRegularExpression(pattern: #"=\?([^?]+)\?([bBqQ])\?([^?]*)\?="#)
    public static func decodeRFC2047(_ s: String) -> String {
        let ns = s as NSString
        var out = s
        for m in rfc2047.matches(in: s, range: NSRange(location: 0, length: ns.length)).reversed() {
            let enc = ns.substring(with: m.range(at: 2)).uppercased(), payload = ns.substring(with: m.range(at: 3))
            var text: String? = nil
            if enc == "B", let d = Data(base64Encoded: payload) { text = String(data: d, encoding: .utf8) ?? String(data: d, encoding: .isoLatin1) }
            if enc == "Q" { text = decodeQuotedPrintable(payload.replacingOccurrences(of: "_", with: " ")) }
            if let text { out = (out as NSString).replacingCharacters(in: m.range, with: text) }
        }
        return out
    }

    static let emailRegex = try! NSRegularExpression(pattern: #"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"#)
    public static func firstEmail(in s: String) -> String? {
        let ns = s as NSString
        guard let m = emailRegex.firstMatch(in: s, range: NSRange(location: 0, length: ns.length)) else { return nil }
        return ns.substring(with: m.range)
    }

    /// `"Apple Support" <no-reply@example.test>` → (Apple Support, no-reply@example.test)
    public static func parseAddress(_ raw: String) -> Address {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return Address(displayName: nil, address: nil) }
        if let lt = s.lastIndex(of: "<"), let gt = s[lt...].firstIndex(of: ">") {
            let addr = String(s[s.index(after: lt)..<gt]).trimmingCharacters(in: .whitespaces)
            var name = String(s[..<lt]).trimmingCharacters(in: .whitespaces)
            if name.hasPrefix("\""), name.hasSuffix("\""), name.count >= 2 { name = String(name.dropFirst().dropLast()) }
            return Address(displayName: name.isEmpty ? nil : name, address: addr.lowercased())
        }
        if let e = firstEmail(in: s) {
            let name = s.replacingOccurrences(of: e, with: "").trimmingCharacters(in: CharacterSet(charactersIn: " \"()<>"))
            return Address(displayName: name.isEmpty ? nil : name, address: e.lowercased())
        }
        return Address(displayName: s, address: nil)
    }
}
