import Foundation

/// wms-o5: one canonical form of untrusted text for pattern matching (prompt-injection detectors, PasteGuard).
/// Attackers dodge ASCII regexes with look-alike letters (Cyrillic "і", "о", "е"), fullwidth forms ("ｉｇｎｏｒｅ"),
/// diacritics ("ïgnore"), and invisible characters between letters ("ig\u{200B}nore"). Folding removes all of that
/// so the same patterns see the same words. Use it ONLY for matching: never show or execute the folded text.
public enum TextFold {
    /// Common confusables: Cyrillic, Greek and a few symbols that render like Latin letters.
    static let confusables: [Unicode.Scalar: String] = {
        let pairs: [(UInt32, String)] = [
            // Cyrillic lower
            (0x0430, "a"), (0x0432, "b"), (0x0441, "c"), (0x0435, "e"), (0x04BB, "h"), (0x0456, "i"), (0x0458, "j"),
            (0x043A, "k"), (0x043C, "m"), (0x043D, "h"), (0x043E, "o"), (0x0440, "p"), (0x0455, "s"), (0x0442, "t"),
            (0x0443, "y"), (0x0445, "x"), (0x0501, "d"), (0x051B, "q"), (0x051D, "w"), (0x0491, "r"), (0x04CF, "l"),
            // Cyrillic upper
            (0x0410, "a"), (0x0412, "b"), (0x0421, "c"), (0x0415, "e"), (0x041D, "h"), (0x0406, "i"), (0x0408, "j"),
            (0x041A, "k"), (0x041C, "m"), (0x041E, "o"), (0x0420, "p"), (0x0405, "s"), (0x0422, "t"), (0x0423, "y"),
            (0x0425, "x"), (0x04AE, "y"), (0x0417, "3"),
            // Greek
            (0x03B1, "a"), (0x03B2, "b"), (0x03B5, "e"), (0x03B9, "i"), (0x03BA, "k"), (0x03BD, "v"), (0x03BF, "o"),
            (0x03C1, "p"), (0x03C4, "t"), (0x03C5, "u"), (0x03C7, "x"), (0x0391, "a"), (0x0392, "b"), (0x0395, "e"),
            (0x0396, "z"), (0x0397, "h"), (0x0399, "i"), (0x039A, "k"), (0x039C, "m"), (0x039D, "n"), (0x039F, "o"),
            (0x03A1, "p"), (0x03A4, "t"), (0x03A5, "y"), (0x03A7, "x"),
            // Latin look-alikes and symbols
            (0x0131, "i"), (0x0269, "i"), (0x0261, "g"), (0x01C3, "!"), (0x2010, "-"), (0x2011, "-"), (0x2012, "-"),
            (0x2013, "-"), (0x2014, "-"), (0x2212, "-"), (0x2018, "'"), (0x2019, "'"), (0x201C, "\""), (0x201D, "\""),
            (0x2044, "/"), (0x2215, "/"), (0x29F8, "/"), (0x2223, "|"), (0x01C0, "|"), (0x00A0, " "), (0x2009, " "),
            (0x200A, " "), (0x202F, " "), (0x205F, " "), (0x3000, " "),
        ]
        var m: [Unicode.Scalar: String] = [:]
        for (u, s) in pairs { if let sc = Unicode.Scalar(u) { m[sc] = s } }
        return m
    }()

    /// True for characters a reader can't see: format (Cf) characters (zero-width, bidi controls, soft hyphen,
    /// word joiner), Unicode tag characters and variation selectors.
    public static func isInvisible(_ u: Unicode.Scalar) -> Bool {
        u.properties.generalCategory == .format || (0xE0000...0xE007F).contains(u.value)
            || (0xFE00...0xFE0F).contains(u.value) || (0xE0100...0xE01EF).contains(u.value) || u.value == 0x115F
            || u.value == 0x1160 || u.value == 0x3164 || u.value == 0xFFA0
    }

    /// Lower-cased, compatibility-normalised (NFKC: fullwidth and styled letters become ASCII), diacritics removed,
    /// confusables mapped to Latin, invisible characters dropped. Line breaks are kept.
    public static func forMatching(_ s: String) -> String {
        let visible = String(String.UnicodeScalarView(s.unicodeScalars.filter { !isInvisible($0) }))
        let nfkc = visible.precomposedStringWithCompatibilityMapping
        var out = String.UnicodeScalarView()
        for u in nfkc.unicodeScalars {
            if let m = confusables[u] { out.append(contentsOf: m.unicodeScalars) } else { out.append(u) }
        }
        return String(out).folding(options: [.diacriticInsensitive, .caseInsensitive, .widthInsensitive], locale: nil)
    }

    /// True when the text holds characters that hide or reorder what a reader sees: bidi overrides or isolates,
    /// Unicode tag characters, or any zero-width character. Normal shell commands never contain these.
    public static func hasHiddenOrBidi(_ s: String) -> Bool {
        s.unicodeScalars.contains { u in
            switch u.value {
            case 0x202A...0x202E, 0x2066...0x2069, 0x200E, 0x200F, 0x061C, 0xE0000...0xE007F,
                 0x200B, 0x2060, 0xFEFF, 0x180E, 0x00AD: return true   // ZWJ/ZWNJ excluded: emoji and some scripts use them
            default: return false
            }
        }
    }

    /// True when the text mixes Latin letters with Cyrillic or Greek look-alikes inside one word (e.g. "сurl").
    public static func hasMixedScriptWord(_ s: String) -> Bool {
        for word in s.split(whereSeparator: { !$0.isLetter }) {
            var latin = false, confusable = false
            for u in word.unicodeScalars {
                if u.isASCII { latin = true } else if confusables[u] != nil { confusable = true }
                if latin && confusable { return true }
            }
        }
        return false
    }
}
