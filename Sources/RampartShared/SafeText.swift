import Foundation

/// hx8: attacker-controlled text (file and process names, Wi-Fi names, evidence, daemon strings) is shown as a
/// single plain line: no control or bidi-override characters (which can make "gpj.exe" read as "exe.jpg"),
/// no invisible characters, no line breaks that could fake a second RamPart sentence, and a bounded length.
/// SwiftUI `Text(String)` never parses Markdown, so links and **bold** stay literal text.
public enum SafeText {
    public static func isUnsafeScalar(_ u: Unicode.Scalar) -> Bool {
        switch u.value {
        case 0x00...0x1F, 0x7F...0x9F: return true                         // C0/C1 controls incl. CR/LF/TAB
        case 0x200B, 0x200E, 0x200F, 0x2028...0x202E, 0x2060...0x206F: return true // zero-width space, LRM/RLM, line/para sep, bidi embeds/overrides/isolates (ZWJ/ZWNJ kept for emoji and scripts)
        case 0xFEFF, 0xFFF9...0xFFFB: return true                           // BOM, interlinear annotation
        case 0x061C, 0x180E: return true                                     // Arabic letter mark, Mongolian vowel separator
        case 0xE0000...0xE007F: return true                                  // tag characters
        default: return false
        }
    }

    public static func line(_ s: String, max: Int = 120) -> String {
        var out = String.UnicodeScalarView()
        var lastWasSpace = false
        for u in s.unicodeScalars {
            let space = u == "\n" || u == "\r" || u == "\t" || u.properties.isWhitespace
            if space { if !lastWasSpace && !out.isEmpty { out.append(" ") }; lastWasSpace = true; continue }
            if isUnsafeScalar(u) { continue }
            out.append(u); lastWasSpace = false
        }
        var r = String(out)
        while r.hasSuffix(" ") { r.removeLast() }
        let limit = Swift.max(1, max)
        if r.count > limit { r = String(r.prefix(limit - 1)) + "…" }
        return r
    }

    /// File paths: same cleaning, longer limit, truncated in the middle so the file name stays visible.
    public static func path(_ s: String, max: Int = 240) -> String {
        let clean = line(s, max: Int.max - 1)
        guard clean.count > max, max > 8 else { return clean }
        let head = (max - 1) / 3, tail = max - 1 - head
        return String(clean.prefix(head)) + "…" + String(clean.suffix(tail))
    }
}
