import Foundation
import RampartShared

/// hx2 X3-2: local, deterministic prompt-injection signals for Scam Check. A copy of RampartAI's
/// `PromptKit.injectionSignals` core patterns and hidden-text check (RampartWeb can't import RampartAI);
/// keep the two in step. Lowering requests ("turn off your antivirus") are scored by the page/lexicon rules instead.
enum AIInjection {
    private static let corePatterns: [String] = [
        #"(ignore|disregard|forget|override|bypass)\s+(all\s+|any\s+|the\s+|your\s+|previous\s+|prior\s+)*(previous|prior|above|earlier|system|safety)?\s*(instructions|prompts?|rules|guidelines|directives)"#,
        #"\b(you are|you're|act as|pretend to be|roleplay as)\s+(now\s+)?(an?\s+|the\s+)?(ai|assistant|chatgpt|gemini|claude|llm|language model|rampart|dan)\b"#,
        #"\b(classify|mark|label|report|treat|rate|flag|consider|call|declare)\s+(this|it|the (command|message|email|text|link|url|file|site|page))\s+(as\s+)?(safe|benign|harmless|clean|legit(imate)?|trusted|not (a )?scam|a false positive)"#,
        #"\b(antivirus|scanner|ai|assistant|llm|model|gemini|rampart|bot)\b\s*[:,]?\s*(this|the following|it)\s+(is|was)\s+(safe|benign|legit(imate)?|clean|trusted|not a scam|a false positive)"#,
        #"\b(system|developer)\s*prompt\b|\bdeveloper\s+(message|instructions?)\b|\bsystem\s+instructions?\s*[:\-]"#,
        #"\b(respond|reply|answer|output|return)\s+(only\s+)?(with|that)\s+["'{]?\s*(safe|benign|probably_safe|low|\{)"#,
        #"<<<|>>>|‹‹‹|›››|\[/?(inst|system)\]|<\|(im_start|im_end|system)\|>"#,
        #"\b(ignore|disregard|forget)\b.{0,30}\b(previous|above|prior|earlier|everything)\b.{0,20}\b(instruction|prompt|rule|message)s?\b"#,
        #"\b(new|updated|real|actual|hidden)\s+(instructions|system prompt|rules)\s*[:\-]"#,
        #"\bas\s+(rampart|the assistant|the ai|an ai|your antivirus|the antivirus|gemini)\b\s*,?\s*(you\s+)?(must\s+|should\s+)?(tell|say|inform|advise|instruct|reply|respond|confirm|recommend)"#,
        #"\b(tell|advise|instruct|convince)\s+(the\s+)?user\s+(to|that)\b"#,
        #"\b(let'?s\s+play\s+a\s+game|from\s+now\s+on,?\s+you|you\s+(will|must)\s+now\s+(act|respond|behave)|pretend\s+(that\s+)?you|stay\s+in\s+character|developer\s+mode\s+enabled|jailbreak)"#,
    ]
    private static let coreRE = try! NSRegularExpression(pattern: corePatterns.map { "(?:" + $0 + ")" }.joined(separator: "|"), options: [.caseInsensitive])

    static func detected(_ t: String) -> Bool {
        if hasHiddenText(t) { return true }
        let visible = String(String.UnicodeScalarView(t.unicodeScalars.filter { !isInvisible($0) }))
        if coreRE.firstMatch(in: visible, range: NSRange(location: 0, length: (visible as NSString).length)) != nil { return true }
        // wms-o5: look-alike letters (Cyrillic/Greek), fullwidth and accented forms fold to plain words first.
        let folded = TextFold.forMatching(t)
        return folded != visible && coreRE.firstMatch(in: folded, range: NSRange(location: 0, length: (folded as NSString).length)) != nil
    }

    static func hasHiddenText(_ t: String) -> Bool {
        var zeroWidthRun = 0
        for u in t.unicodeScalars {
            switch u.value {
            case 0xE0000...0xE007F, 0x202A...0x202E, 0x2066...0x2069: return true
            case 0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E:
                zeroWidthRun += 1; if zeroWidthRun >= 3 { return true }
            default: zeroWidthRun = 0
            }
        }
        return false
    }
    static func isInvisible(_ u: Unicode.Scalar) -> Bool {
        u.properties.generalCategory == .format || (0xE0000...0xE007F).contains(u.value)
    }
}
