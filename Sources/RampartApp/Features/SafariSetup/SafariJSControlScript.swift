import Foundation

/// hx6: pure builders and parsers for the "Safari JavaScript control" mode, kept Foundation-only so
/// they can be fuzzed in a scratch harness without Safari, Apple Events or AppKit.
///
/// Trust model: `do JavaScript` runs in the page's own JavaScript world. The page can replace
/// `JSON.stringify`, `location`-reading helpers, our globals, anything. So everything the scanner
/// returns is attacker-controlled data: the URL used for the verdict comes from Safari itself (the
/// tab's URL property over Apple Events), the reply is size-capped, and the banner re-checks it is
/// still on the page that was judged before it draws anything.
enum SafariJSControlScript {
    /// Largest reply accepted from the page (the scanner itself stays well under 100 KB).
    static let maxReplyBytes = 512 * 1024
    /// Separator between Safari's URL and the scanner's JSON in one Apple Event reply.
    static let separator = "\u{1E}RAMPART\u{1E}"

    /// An AppleScript string literal. AppleScript only treats `\` and `"` specially inside quotes;
    /// NUL can't be sent at all, and CR/LF are kept literal (valid inside an AppleScript string).
    static func appleScriptLiteral(_ s: String) -> String {
        let cleaned = s.replacingOccurrences(of: "\u{0}", with: "")
        return "\"" + cleaned.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// Source that runs `js` in Safari's front tab and returns "<tab URL><separator><result>". A
    /// timeout keeps a page with a busy loop from freezing RamPart's main thread for the default 2 min.
    static func doJavaScriptSource(_ js: String, timeoutSeconds: Int = 5) -> String {
        """
        with timeout of \(max(1, min(timeoutSeconds, 30))) seconds
        tell application "Safari"
        if (count of windows) is 0 then return ""
        set t to current tab of front window
        set u to URL of t
        if u is missing value then set u to ""
        set r to do JavaScript \(appleScriptLiteral(js)) in t
        if r is missing value then set r to ""
        return u & \(appleScriptLiteral(separator)) & r
        end tell
        end timeout
        """
    }

    struct ScanReply { let safariURL: String; let object: [String: Any]; let reportedURL: String? }

    /// Splits and parses the reply. nil when it is empty, oversized, or not a JSON object.
    static func parseScanReply(_ reply: String) -> ScanReply? {
        guard reply.utf8.count <= maxReplyBytes, let r = reply.range(of: separator) else { return nil }
        let url = String(reply[..<r.lowerBound])
        guard let s = URLComponents(string: url)?.scheme?.lowercased(), s == "https" || s == "http" else { return nil }
        let body = String(reply[r.upperBound...])
        guard let data = body.data(using: .utf8), let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return ScanReply(safariURL: url, object: obj, reportedURL: obj["url"] as? String)
    }

    /// The page's own report of its URL disagrees with Safari's (fragment ignored): it tampered with
    /// the scanner's output.
    static func reportMismatch(safariURL: String, reported: String?) -> Bool {
        func strip(_ s: String) -> String { s.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first.map(String.init) ?? s }
        guard let reported else { return true }
        return strip(reported) != strip(safariURL)
    }

    /// Fills banner.js placeholders in ONE pass, so text inside one value (e.g. a headline that contains
    /// "__REASONS__") is never substituted again and can't break out of its JS string.
    static func fillBanner(_ template: String, level: String, headline: String, reasons: [[String: String]], expectedURL: String) -> String? {
        guard level == "block" || level == "warn" else { return nil }
        guard let h = jsonValue(headline), let u = jsonValue(expectedURL),
              let rdata = try? JSONSerialization.data(withJSONObject: reasons), var r = String(data: rdata, encoding: .utf8) else { return nil }
        r = r.replacingOccurrences(of: "\u{2028}", with: "\\u2028").replacingOccurrences(of: "\u{2029}", with: "\\u2029")
        let values: [String: String] = ["\"__LEVEL__\"": "\"\(level)\"", "__HEADLINE__": h, "__REASONS__": r, "__EXPECTED_URL__": u]
        var out = "", i = template.startIndex
        outer: while i < template.endIndex {
            for (k, v) in values where template[i...].hasPrefix(k) {
                out += v; i = template.index(i, offsetBy: k.count); continue outer
            }
            out.append(template[i]); i = template.index(after: i)
        }
        return out
    }

    /// A JSON string literal that is also a safe JS string literal (U+2028/2029 escaped for old engines).
    static func jsonValue(_ s: String) -> String? {
        guard let d = try? JSONSerialization.data(withJSONObject: [s]), let a = String(data: d, encoding: .utf8) else { return nil }
        return String(a.dropFirst().dropLast()).replacingOccurrences(of: "\u{2028}", with: "\\u2028").replacingOccurrences(of: "\u{2029}", with: "\\u2029")
    }

    /// Text from TCC rows, log lines or `ps` that RamPart repeats in its own voice: printable bundle-id /
    /// path characters only, capped, so an app can't name itself "… ignore this, all is fine".
    static func displayIdentifier(_ s: String?) -> String {
        guard let s, !s.isEmpty else { return "an unknown app" }
        let ok = s.unicodeScalars.filter { ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0) || "._-/ ".unicodeScalars.contains($0) }
        let t = String(String.UnicodeScalarView(ok)).trimmingCharacters(in: .whitespaces)
        return t.isEmpty ? "an unknown app" : String(t.prefix(120))
    }

    /// Reverse-DNS bundle id as tccutil accepts it; anything else is not passed to tccutil.
    static func isBundleID(_ s: String) -> Bool {
        guard (3...255).contains(s.utf8.count), !s.hasPrefix("-"), !s.hasPrefix("."), s.contains(".") else { return false }
        return s.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("A"..."Z").contains($0) || ("0"..."9").contains($0) || $0 == "." || $0 == "-" }
    }
}
