import Foundation
import RampartShared

/// Finds scripts that unpack code at run time ("runs only when decompressed"):
///  - shell pipelines that feed an embedded, appended or downloaded blob through a decoder/decompressor into
///    an interpreter (`tail -n +N "$0" | gunzip | sh`, `base64 -D | gunzip | bash`, `uudecode`, `eval "$(… | base64 -d)"`),
///  - Python / JavaScript / Ruby / Perl / AppleScript code that decompresses or base64-decodes data and hands
///    it to exec / eval / compile / Function / `do shell script`,
///  - scripts with a binary payload appended after `exit` or an `__ARCHIVE__`-style marker.
/// The embedded payload is extracted (bounded) so the scanner can check it recursively; the pattern itself
/// becomes explained evidence. Downloaded blobs (`curl … | base64 -d | sh`) can't be extracted: only the pattern is reported.
public enum EmbeddedPayload {
    public static let decodeRunTitle = "Script unpacks hidden code and runs it"
    public static let appendedTitle = "Script carries an appended payload"
    public static let selfExtractTitle = "Self-extracting script"

    /// Script text examined per file.
    public static let maxScriptBytes = 4 << 20
    /// Maximum number of payloads extracted from one script.
    public static let maxPayloads = 6

    public struct Payload: Sendable {
        public var label: String
        public var data: Data
    }

    public struct Result: Sendable {
        public var evidence: [Evidence] = []
        public var payloads: [Payload] = []
        public var isEmpty: Bool { evidence.isEmpty && payloads.isEmpty }
    }

    static let scriptExtensions: Set<String> = [
        "sh", "bash", "zsh", "ksh", "csh", "fish", "command", "tool", "run", "py", "pyw", "js", "mjs", "cjs", "jsx", "rb", "pl", "pm",
        "php", "applescript", "jxa", "osa", "lua", "tcl", "ps1",
    ]

    /// Whether a file is worth analysing (script kind, script extension, or an executable text file).
    /// `nested`: a decoded / decompressed payload (no meaningful name or mode bits).
    public static func applies(kind: FileKind, path: String, executable: Bool, header: [UInt8], nested: Bool = false) -> Bool {
        if kind == .script { return true }
        if scriptExtensions.contains(ScanTriage.pathExtension(path)) { return true }
        guard executable || nested, kind == .other, !header.isEmpty else { return false }
        let printable = header.prefix(256).filter { $0 == 9 || $0 == 10 || $0 == 13 || (32..<127).contains($0) }.count
        return printable * 10 >= min(256, header.count) * 9
    }

    // MARK: patterns

    private static func rx(_ s: String, caseSensitive: Bool = false) -> NSRegularExpression {
        try! NSRegularExpression(pattern: s, options: caseSensitive ? [.anchorsMatchLines] : [.caseInsensitive, .anchorsMatchLines])
    }
    /// Shell decoders / decompressors.
    static let shellDecoder = #"(base64\s+(-[a-z]*d\b|-D\b|--decode)|\bb64decode\b|\bgunzip\b|\bgzip\s+-[a-z]*d|\bzcat\b|\bgzcat\b|\bbunzip2\b|\bbzip2\s+-[a-z]*d|\bbzcat\b|\bxz\s+-[a-z]*d|\bunxz\b|\bxzcat\b|\blzma\s+-[a-z]*d|\bzstd\s+-[a-z]*d|\bunzstd\b|\buudecode\b|\bopenssl\s+(enc\s+)?[^|;]*-d\b|\bopenssl\s+base64\s+-d|\bxxd\s+-r|\bcompression_tool\s+-decode|\baa\s+extract|\bperl\s+-[a-z]*e\s*.{0,40}unpack)"#
    /// `… | sh` style interpreter at the end of a pipe.
    static let shellPipeInterp = #"\|\s*(sudo\s+(-\S+\s+)*)?(\S*/)?(env\s+)?(sh|bash|zsh|ksh|dash|fish|python[0-9.]*|perl|ruby|osascript|node|php|tclsh|source|\.)(\s|$|;|\)|")"#
    static let shellPipeRun = rx(shellDecoder + #"[^\n]*"# + shellPipeInterp)
    /// `eval "$(… base64 -d …)"`, `bash <(… gunzip …)`, `sh -c "$(…uudecode…)"`, `source <(…)`.
    static let shellEvalRun = rx(#"(\beval\b|\bsource\b|^\s*\.|\b(sh|bash|zsh)\s+(-c\s+)?)\s*["']?(\$\(|<\(|`)[^\n]*"# + shellDecoder)
    /// Reads its own file ("$0") from an offset.
    static let selfRead = rx(#"\b(tail|sed|awk|dd|head|cut|perl|grep|uudecode)\b[^\n|]*("\$0"|\$0\b|\$\{0\}|BASH_SOURCE|\$SCRIPT_?PATH|\$THIS_?(PATH|FILE)|\$ME\b)"#)
    static let tailOffset = rx(#"\btail\s+(-n\s*\+?|-\+|\+)(\d{1,7})\s+[^\n|]*("\$0"|\$0\b|\$\{0\}|BASH_SOURCE)"#)
    static let tailBytes = rx(#"\btail\s+-c\s*\+?(\d{1,10})\s+[^\n|]*("\$0"|\$0\b|\$\{0\})"#)
    /// Payload marker lines.
    static let markerLine = rx(#"^(__[A-Z0-9_]{3,40}__|[A-Z_]{4,30}:)[ \t]*\r?$"#)
    static let exitLine = rx(#"^[ \t]*exit([ \t]+[0-9$?]+)?[ \t]*;?[ \t]*\r?$"#)
    /// Marker named by sed/awk ("sed '1,/^__PAYLOAD__$/d' "$0"").
    static let namedMarker = rx(#"/\^?([A-Za-z0-9_:#=-]{4,40})\$?/"#)

    /// In-language decode/decompress + exec (Python, JS, Ruby, Perl, PHP, AppleScript).
    static let langDecoder = #"((zlib|gzip|bz2|lzma)\.(decompress|open)|zlib\.decompressobj|base64\.(b64|b32|b16|a85|b85|urlsafe_b64)decode|\bb64decode|\bdecodebytes|marshal\.loads|codecs\.decode|bytes\.fromhex|unhexlify|\binflate\w*|\bgunzip\w*|\bunzipSync|brotliDecompress\w*|pako\.\w+|LZString\.\w+|\batob\s*\(|Buffer\.from\s*\([^)]{0,200}(base64|hex)|Zlib::(Inflate|GzipReader)|Base64\.(strict_|urlsafe_)?decode64|unpack1?\s*\(\s*['"][mu]|\.unpack\(['"]m|\buncompress\s*\(|Compress::Zlib|IO::Uncompress|MIME::Base64|decode_base64|gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)"#
    static let compressionWords = #"(zlib|gzip|bz2|lzma|decompress|inflate|gunzip|unzip|brotli|pako|LZString|Zlib::|uncompress|Compress::|IO::Uncompress|gzinflate|gzuncompress|gzdecode|marshal)"#
    /// Code-running calls. Case-sensitive and the call parenthesis is required ("function inflate(" is not a sink).
    static let langSink = #"(?<![\w$])(exec|eval|compile|Function|new\s+Function|vm\.run\w*|runInThisContext|runInNewContext|instance_eval|class_eval|module_eval|system|create_function)\s*\("#
    /// Sink call whose argument (no quotes / statement end in between) contains a decoder.
    static let langInline = rx(langSink + #"\s*[^;"'\n`]{0,160}?"# + langDecoder, caseSensitive: true)
    /// `x = decode(...)` then, within 6 lines, `exec(x)`.
    static let langTwoStep = rx(#"^[ \t]*\$?([A-Za-z_][A-Za-z0-9_]{0,40})\s*=\s*[^\n]{0,400}"# + langDecoder + #"[^\n]*\n(?:[^\n]*\n){0,6}?[^\n]*"# + langSink + #"\s*\$?\1\b"#, caseSensitive: true)
    static let compressionRx = rx(compressionWords)

    /// Base64 runs worth decoding (inside quotes, heredocs or assignments).
    static let base64Blob = rx(#"[A-Za-z0-9+/]{64,}={0,2}"#)
    static let uuBegin = rx(#"^begin(-base64)?\s+[0-7]{3,4}\s+\S+"#)

    // MARK: analysis

    /// Analyses `path` (text up to `maxScriptBytes`; payloads capped at `cap` bytes each).
    public static func analyze(path: String, size: UInt64, cap: UInt64) -> Result {
        guard let h = FileHandle(forReadingAtPath: path) else { return Result() }
        defer { try? h.close() }
        let head = (try? h.read(upToCount: maxScriptBytes)) ?? Data()
        return analyze(data: head, totalSize: size, cap: cap) { off, len in
            guard (try? h.seek(toOffset: off)) != nil else { return nil }
            return try? h.read(upToCount: len)
        }
    }

    /// Analysis core. `readRange(offset, length)` fetches bytes past the in-memory head (appended payloads).
    public static func analyze(data head: Data, totalSize: UInt64, cap: UInt64,
                               readRange: (UInt64, Int) -> Data?) -> Result {
        var r = Result()
        // ISO Latin-1 keeps one character per byte, so match offsets are byte offsets.
        guard let text = String(data: head, encoding: .isoLatin1), !text.isEmpty else { return r }
        let ns = text as NSString
        let full = NSRange(location: 0, length: ns.length)
        // Only the text part is pattern-matched: stop at the first NUL-heavy region.
        let textEnd = textPrefixLength(head)
        let textRange = NSRange(location: 0, length: min(textEnd, ns.length))
        let lower = text.prefix(textEnd).lowercased()
        let decoderHints = ["base64", "b64", "gunzip", "gzip", "zcat", "bzip2", "bunzip", "bzcat", "xz", "zstd", "uudecode", "openssl", "xxd",
                            "decompress", "inflate", "zlib", "atob", "marshal", "unpack", "uncompress", "fromhex", "unhexlify",
                            "lzstring", "pako", "decode64", "compression_tool", "aa extract", "begin "]
        let selfHints = ["$0", "${0}", "bash_source", "script_path", "scriptpath", "this_path", "this_file", "$me"]
        let hasDecoder = decoderHints.contains(where: lower.contains)
        let hasSelf = selfHints.contains(where: lower.contains)
        let binaryTail = textEnd < head.count || totalSize > UInt64(head.count)
        guard hasDecoder || hasSelf || binaryTail else { return r }

        let shellRun = hasDecoder ? (firstMatch(shellPipeRun, ns, textRange) ?? firstMatch(shellEvalRun, ns, textRange)) : nil
        let selfReads = hasSelf ? firstMatch(selfRead, ns, textRange) : nil
        let langRun = hasDecoder && shellRun == nil ? (firstMatch(langInline, ns, textRange) ?? firstMatch(langTwoStep, ns, textRange)) : nil
        let lookForAppended = selfReads != nil || binaryTail

        // Appended payload: explicit tail offset, marker line, or `exit` followed by binary.
        var appended: (offset: Int, why: String)?
        if lookForAppended, let m = tailOffset.firstMatch(in: text, range: textRange), let n = Int(ns.substring(with: m.range(at: 2))), n > 1 {
            if let off = offsetOfLine(n, in: head), off < Int(totalSize) { appended = (off, "line \(n) onward, read by `tail` from the script itself") }
        }
        if lookForAppended, appended == nil, let m = tailBytes.firstMatch(in: text, range: textRange), let n = UInt64(ns.substring(with: m.range(at: 1))),
           n > 0, n < totalSize {
            appended = (Int(totalSize - n), "the last \(n) bytes, read by `tail -c` from the script itself")
        }
        if appended == nil, selfReads != nil, let m = namedMarker.firstMatch(in: text, range: textRange) {
            let marker = ns.substring(with: m.range(at: 1))
            if let off = lineAfter(marker: marker, in: ns, range: textRange) { appended = (off, "everything after the \(marker) marker") }
        }
        if lookForAppended, appended == nil {
            for m in markerLine.matches(in: text, range: full) {
                let end = lineEnd(ns, m.range)
                if end < Int(totalSize) && isBinaryOrBlob(head, from: end) {
                    appended = (end, "everything after the \(ns.substring(with: m.range).trimmingCharacters(in: .whitespacesAndNewlines)) marker"); break
                }
            }
        }
        if binaryTail, appended == nil {
            for m in exitLine.matches(in: text, range: textRange) {
                let end = lineEnd(ns, m.range)
                if end < Int(totalSize), totalSize - UInt64(end) >= 64, isBinary(head, from: end) {
                    appended = (end, "binary data after an `exit` line"); break
                }
            }
        }

        // Payload extraction (only when there is a reason to look: a decode/run pattern, a self-read or an appended blob).
        if let a = appended {
            let len = Int(min(cap, totalSize - UInt64(a.offset)))
            var blob: Data?
            if a.offset + len <= head.count { blob = head.subdata(in: a.offset..<(a.offset + len)) }
            else { blob = readRange(UInt64(a.offset), len) }
            if let blob, !blob.isEmpty {
                r.payloads.append(Payload(label: "appended payload", data: blob))
                if let decoded = decodeTextBlob(blob, cap: cap), decoded != blob {
                    r.payloads.append(Payload(label: "decoded appended payload", data: decoded))
                }
            }
        }
        if shellRun != nil || langRun != nil || selfReads != nil || appended != nil {
            for m in base64Blob.matches(in: text, range: textRange).sorted(by: { $0.range.length > $1.range.length }).prefix(maxPayloads) {
                guard r.payloads.count < maxPayloads else { break }
                let s = ns.substring(with: m.range)
                if let d = Data(base64Encoded: padBase64(s)), d.count >= 16, UInt64(d.count) <= cap {
                    r.payloads.append(Payload(label: "base64 blob at byte \(m.range.location)", data: d))
                }
            }
            for m in uuBegin.matches(in: text, range: textRange).prefix(2) where r.payloads.count < maxPayloads {
                if let d = uudecode(ns.substring(from: m.range.location), cap: cap), !d.isEmpty {
                    r.payloads.append(Payload(label: "uuencoded block at byte \(m.range.location)", data: d))
                }
            }
        }

        // Evidence.
        if let run = shellRun ?? langRun {
            let snippet = clip(ns.substring(with: run))
            let compressed = compressionRx.firstMatch(in: snippet, range: NSRange(location: 0, length: (snippet as NSString).length)) != nil
            let embedded = appended != nil || selfReads != nil || !r.payloads.isEmpty
            var score = shellRun != nil ? 45 : (compressed ? 50 : 35)
            if embedded { score += 10 }
            let lang = shellRun != nil ? "shell" : "script"
            var detail = "This \(lang) file decodes\(compressed ? " and decompresses" : "") data and passes the result straight to an interpreter (\"\(snippet)\"). "
            detail += "Code that only exists after it is unpacked at run time can't be read by a normal scan — a common way to hide malware."
            if embedded { detail += " The hidden payload is carried inside this file; RamPart extracted it and scanned it too." }
            else { detail += " The payload comes from elsewhere (for example a download), so RamPart could only check the pattern." }
            r.evidence.append(Evidence(source: .heuristic, title: decodeRunTitle, detail: detail, score: score))
        } else if let a = appended {
            let selfExtract = selfReads != nil
            r.evidence.append(Evidence(source: .heuristic, title: selfExtract ? selfExtractTitle : appendedTitle,
                                       detail: "This script carries data inside itself (\(a.why)). Installers sometimes do this; malware uses it to hide its real program. "
                                           + "RamPart extracted the payload and scanned it.",
                                       score: selfExtract ? 15 : 20))
        }
        return r
    }

    // MARK: helpers

    static func firstMatch(_ re: NSRegularExpression, _ ns: NSString, _ range: NSRange) -> NSRange? {
        re.firstMatch(in: ns as String, range: range)?.range
    }

    static func clip(_ s: String) -> String {
        let one = s.replacingOccurrences(of: "\n", with: " ").trimmingCharacters(in: .whitespaces)
        return one.count > 120 ? String(one.prefix(117)) + "…" : one
    }

    /// Length of the leading text part: stops at the first line that contains NUL or is mostly control bytes
    /// (a script with an appended binary payload).
    static func textPrefixLength(_ d: Data) -> Int {
        var lineStart = 0, bad = 0, i = 0
        let n = d.count
        while i < n {
            let b = d[d.startIndex + i]
            if b == 0 { return lineStart }
            if b < 9 || (b > 13 && b < 32 && b != 27) { bad += 1 }
            if b == 10 || i - lineStart >= 4096 {
                let len = i - lineStart + 1
                if bad * 10 > len { return lineStart }
                lineStart = i + 1; bad = 0
            }
            i += 1
        }
        let len = n - lineStart
        return len > 0 && bad * 10 > len ? lineStart : n
    }

    static func isBinary(_ d: Data, from off: Int) -> Bool {
        guard off < d.count else { return false }
        let end = min(d.count, off + 512)
        var bad = 0
        for j in off..<end { let b = d[d.startIndex + j]; if b == 0 || b < 9 || (b > 13 && b < 32) || b >= 127 { bad += 1 } }
        return bad * 10 >= (end - off)
    }

    /// Binary data, or a long run of base64 text (typical "__PAYLOAD__\n<base64>").
    static func isBinaryOrBlob(_ d: Data, from off: Int) -> Bool {
        if isBinary(d, from: off) { return true }
        let end = min(d.count, off + 256)
        guard end - off >= 48 else { return false }
        let chunk = d[(d.startIndex + off)..<(d.startIndex + end)]
        return chunk.allSatisfy { b in (65...90).contains(b) || (97...122).contains(b) || (48...57).contains(b) || b == 43 || b == 47 || b == 61 || b == 10 || b == 13 }
    }

    static func offsetOfLine(_ n: Int, in d: Data) -> Int? {
        var line = 1, i = 0
        if n == 1 { return 0 }
        for b in d { i += 1; if b == 10 { line += 1; if line == n { return i } } }
        return nil
    }

    static func lineEnd(_ ns: NSString, _ r: NSRange) -> Int {
        let e = NSMaxRange(r)
        return e < ns.length && ns.character(at: e) == 10 ? e + 1 : (e < ns.length - 1 && ns.character(at: e) == 13 ? e + 2 : e)
    }

    static func lineAfter(marker: String, in ns: NSString, range: NSRange) -> Int? {
        var search = NSRange(location: 0, length: ns.length)
        while true {
            let r = ns.range(of: marker, options: [], range: search)
            guard r.location != NSNotFound else { return nil }
            let lineStart = r.location == 0 || ns.character(at: r.location - 1) == 10
            let le = NSMaxRange(r)
            let lineEndsHere = le >= ns.length || ns.character(at: le) == 10 || ns.character(at: le) == 13
            if lineStart && lineEndsHere { return lineEnd(ns, r) }
            search = NSRange(location: le, length: ns.length - le)
        }
    }

    static func padBase64(_ s: String) -> String {
        let rem = s.count % 4
        return rem == 0 ? s : s + String(repeating: "=", count: 4 - rem)
    }

    /// A text payload that is one base64 document (line-wrapped allowed) → its bytes.
    static func decodeTextBlob(_ d: Data, cap: UInt64) -> Data? {
        guard d.count >= 24, d.count <= Int(clamping: cap) * 2 else { return nil }
        let allowed = d.allSatisfy { b in (65...90).contains(b) || (97...122).contains(b) || (48...57).contains(b) || [43, 47, 61, 10, 13, 32, 9].contains(b) }
        guard allowed, let s = String(data: d, encoding: .ascii) else { return nil }
        return Data(base64Encoded: s, options: .ignoreUnknownCharacters)
    }

    /// Test hook for the uudecoder.
    public static func uudecodeForTest(_ s: String) -> Data? { uudecode(s, cap: 1 << 20) }

    /// Minimal uudecode (traditional "begin 644 name" … "end"); `begin-base64` blocks use base64.
    static func uudecode(_ text: String, cap: UInt64) -> Data? {
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: CharacterSet(charactersIn: "\r")) }
        guard let first = lines.first else { return nil }
        lines.removeFirst()
        if first.hasPrefix("begin-base64") {
            let body = lines.prefix { $0 != "====" && $0 != "end" }.joined()
            return Data(base64Encoded: padBase64(body))
        }
        var out = Data()
        for l in lines {
            if l == "end" || l == "`" { break }
            let bytes = Array(l.utf8)
            guard let lenByte = bytes.first else { continue }
            let n = Int((lenByte &- 32) & 0x3F)
            if n == 0 { continue }
            var chunk: [UInt8] = []
            var i = 1
            while i + 3 < bytes.count + 1 && chunk.count < n {
                func v(_ k: Int) -> UInt8 { k < bytes.count ? (bytes[k] &- 32) & 0x3F : 0 }
                let a = v(i), b = v(i + 1), c = v(i + 2), d = v(i + 3)
                chunk.append(a << 2 | b >> 4); chunk.append(b << 4 | c >> 2); chunk.append(c << 6 | d)
                i += 4
            }
            out.append(contentsOf: chunk.prefix(n))
            if UInt64(out.count) > cap { return nil }
        }
        return out
    }
}
