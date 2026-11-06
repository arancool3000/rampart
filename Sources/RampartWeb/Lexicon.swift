import Foundation

/// Language pack for the message analyser. Each pattern is a case-insensitive regular expression
/// over the plain text of a message. Add a language by registering another `ScamLexicon`;
/// the engine picks the pack by detected dominant language and always includes `shared`
/// (language-independent patterns like gift-card brand names and tool names).
public struct ScamPattern: Sendable {
    public let id: String
    public let category: ScamSignal.Category
    public let title: String
    public let explanation: String
    public let score: Int
    public let regex: NSRegularExpression
    public init(_ id: String, _ category: ScamSignal.Category, _ score: Int, _ title: String, _ explanation: String, _ pattern: String) {
        self.id = id; self.category = category; self.score = score; self.title = title; self.explanation = explanation
        self.regex = try! NSRegularExpression(pattern: pattern, options: [.caseInsensitive, .dotMatchesLineSeparators])
    }
}

public struct ScamLexicon: Sendable {
    public let language: String          // BCP-47
    public let patterns: [ScamPattern]
    public let tips: [ScamSignal.Category: String]
    public init(language: String, patterns: [ScamPattern], tips: [ScamSignal.Category: String]) {
        self.language = language; self.patterns = patterns; self.tips = tips
    }
}

public enum LexiconRegistry {
    nonisolated(unsafe) private static var packs: [String: ScamLexicon] = ["en": .english]
    private static let lock = NSLock()

    public static func register(_ pack: ScamLexicon) { lock.lock(); packs[pack.language] = pack; lock.unlock() }
    public static func pack(for language: String) -> ScamLexicon? { lock.lock(); defer { lock.unlock() }; return packs[language] ?? packs[String(language.prefix(2))] }
    public static var languages: [String] { lock.lock(); defer { lock.unlock() }; return packs.keys.sorted() }

    /// Dominant language of the text ("en" when unsure or unsupported).
    public static func detectLanguage(_ text: String) -> String {
        let tagger = NSLinguisticTagger(tagSchemes: [.language], options: 0)
        tagger.string = text
        if let lang = tagger.dominantLanguage, pack(for: lang) != nil { return String(lang.prefix(2)) }
        return "en"
    }
}

extension ScamLexicon {
    /// Language-independent patterns: brand/tool names, codes, crypto addresses.
    public static let shared = ScamLexicon(language: "und", patterns: [
        ScamPattern("shared.remote.tool", .remoteAccess, 70, "Mentions a remote-control tool",
                    "AnyDesk, TeamViewer and similar tools let someone else take over your Mac. Support staff from real companies never ask you to install them.",
                    #"\b(anydesk|teamviewer|ultraviewer|supremo|logmein|rustdesk|zoho\s*assist|splashtop|connectwise|screenconnect|quick\s*assist|go\s*to\s*assist|gotoassist|ammyy)\b"#),
        ScamPattern("shared.payment.giftcard", .payment, 85, "Asks for gift cards",
                    "No company, bank, government office or police force takes payment in gift cards. This is the surest sign of a scam.",
                    #"\b(buy|purchase|get|pay|paid|payment|send|load|codes?|numbers?|photo|picture|redeem|with|using|in|settle|fine|fee|worth)\b.{0,50}\b(gift\s*cards?|itunes\s*cards?|google\s*play\s*cards?|steam\s*cards?|razer\s*gold|apple\s*(store\s*)?cards?|vanilla\s*(visa|cards?)|ebay\s*cards?|amazon\s*cards?|target\s*cards?|sephora\s*cards?)\b|\b(gift\s*cards?|itunes\s*cards?|google\s*play\s*cards?|steam\s*cards?|razer\s*gold|apple\s*(store\s*)?cards?|vanilla\s*(visa|cards?)|ebay\s*cards?|amazon\s*cards?|target\s*cards?|sephora\s*cards?)\b.{0,60}\b(codes?|numbers?|scratch|send|photo|picture|pin|back|buy|pay|fine|fee|settle|worth|store|purchase)\b|\bscratch\s*(off\s*)?the\s*(back|code|silver)\b"#),
        ScamPattern("shared.payment.crypto", .payment, 65, "Asks for cryptocurrency",
                    "Crypto payments can't be reversed. Legitimate bills, fines and refunds are never settled in Bitcoin or through a crypto ATM.",
                    #"\b(bitcoin|btc|ethereum|usdt|tether|crypto\s*(atm|kiosk|wallet)|coin\s*(atm|kiosk)|send\s+\w+\s+to\s+(this|my|the)\s+wallet)\b|\b(bc1q[a-z0-9]{20,}|0x[a-fA-F0-9]{40}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"#),
        ScamPattern("shared.payment.wire", .payment, 55, "Asks for a wire or untraceable transfer",
                    "Wire transfers, Western Union, MoneyGram and payment apps to strangers can't be recalled once sent.",
                    #"\b(wire\s*transfer|western\s*union|moneygram|money\s*gram|bank\s*transfer\s+(now|today|immediately)|zelle\s+(me|us|to)|cash\s*app\s+(me|us|to)|venmo\s+(me|us|to))\b"#),
        ScamPattern("shared.credentials.2fa", .credentials, 80, "Asks for a security code",
                    "One-time codes exist so that only you can sign in. Anyone asking you to read one out, or type it into their link, is trying to get into your account.",
                    #"\b((one[-\s]?time|verification|security|authentication|2fa|two[-\s]?factor|otp|sms|text(ed)?|6[-\s]?digit)\s*(pass)?codes?)\b.{0,80}\b(send|share|read|tell|give|enter|reply|provide|confirm|forward)|\b(send|share|read|tell|give|enter|reply\s+with|provide|forward)\b.{0,60}\b((one[-\s]?time|verification|security|authentication|2fa|two[-\s]?factor|otp|6[-\s]?digit)\s*(pass)?codes?)\b"#),
        ScamPattern("shared.credentials.password", .credentials, 65, "Asks for your password or PIN",
                    "Real companies never ask for your password, PIN or full card details by message.",
                    #"\b(confirm|verify|enter|provide|send|update|reply\s+with|share)\b.{0,40}\b(your\s+)?(password|passcode|pin\s*(number|code)?|social\s*security\s*(number)?|ssn|national\s*insurance|card\s*(number|details)|cvv|cvc|security\s*code\s+on\s+the\s+back|seed\s*phrase|recovery\s*phrase|private\s*key|secret\s*phrase|12[-\s]?word|24[-\s]?word)\b"#),
        ScamPattern("shared.credentials.seed", .credentials, 90, "Asks for a wallet recovery phrase",
                    "Your seed phrase is the wallet. Whoever has it owns everything in it. No support team, upgrade or validation ever needs it.",
                    #"\b(seed|recovery|secret|mnemonic|backup)\s*(phrase|words?)\b|\b(12|24)[-\s]?words?\b.{0,30}\b(phrase|wallet|enter|import|validate|sync)"#),
    ], tips: [:])

    public static let english = ScamLexicon(language: "en", patterns: [
        // Urgency and pressure
        ScamPattern("en.urgency.deadline", .urgency, 35, "Pressures you to act immediately",
                    "Scams create a deadline so you don't stop to think or check with someone. Real organisations give you time.",
                    #"\b(within\s+(the\s+next\s+)?(\d+|one|two|twelve|twenty[-\s]four|forty[-\s]eight)\s*(hours?|hrs|minutes?|mins?)|(act|respond|reply|call|confirm|verify|update|pay|click)\s+(now|immediately|right\s+away|today|asap|urgently|without\s+delay|at\s+once)|immediate\s+(action|attention|response)\s+(is\s+)?(required|needed)|action\s+(is\s+)?required|urgent(ly)?|time[-\s]sensitive|final\s+(notice|warning|reminder)|last\s+chance|expires?\s+(today|tonight|within)|before\s+(it'?s\s+too\s+late|midnight)|don'?t\s+delay|right\s+now|do\s+not\s+ignore)\b"#),
        ScamPattern("en.urgency.threat", .urgency, 45, "Threatens consequences",
                    "Threats of arrest, lawsuits, account closure or lost access are used to frighten you into paying or clicking. Real notices don't read like this.",
                    #"\b(account\s+(will\s+be|has\s+been|is)\s+(suspended|locked|closed|terminated|disabled|restricted|deactivated|limited|blocked|compromised|hacked)|(suspend|lock|close|terminate|disable|restrict|deactivate)\s+your\s+account|your\s+(data|photos|files|account)\s+will\s+be\s+(deleted|lost|erased|removed)|lose\s+access|failure\s+to\s+(respond|comply|pay|verify))\b"#),
        ScamPattern("en.urgency.threat.legal", .urgency, 50, "Threatens arrest or legal action",
                    "Police, courts and tax offices don't announce arrests by text or email. The threat exists only to scare you into paying.",
                    #"\b(arrest\s+warrant|warrant\s+for\s+your\s+arrest|legal\s+action|lawsuit|prosecut(ed|ion)|court\s+summons|be\s+arrested|police\s+(will|are\s+on)|permanently\s+(lose|deleted|closed))\b"#),
        ScamPattern("en.urgency.threat.activity", .urgency, 40, "Claims suspicious activity on your account",
                    "“Unusual sign-in” and “unauthorised transaction” alerts with a link are the most common phishing opener. Check in the real app instead.",
                    #"\b(unauthori[sz]ed\s+(access|login|sign[-\s]?in|transaction|purchase|activity)|suspicious\s+(activity|login|sign[-\s]?in|transaction)|unusual\s+(activity|sign[-\s]?in|login))\b"#),
        ScamPattern("en.urgency.secrecy", .urgency, 50, "Asks you to keep it secret",
                    "Scammers tell you not to tell family, friends or your bank because any of them would spot the scam.",
                    #"\b(do\s+not\s+(tell|inform|discuss|share\s+this\s+with|contact\s+(your\s+)?bank|hang\s+up)|don'?t\s+(tell|inform|discuss|share\s+this\s+with|contact\s+(your\s+)?bank|hang\s+up)|keep\s+(this|it)\s+(confidential|secret|between\s+us|private)|tell\s+no\s*one|(stay|remain)\s+on\s+the\s+(line|phone|call))\b"#),
        ScamPattern("en.urgency.keep_calling", .urgency, 35, "Pushes you to call a number right away",
                    "Numbers in unexpected messages lead to the scammers, not the company. Look up the number on the company's own website or card.",
                    #"\b(call\s+(us\s+)?(now|immediately|today|urgently|this\s+number|the\s+number\s+below|toll[-\s]?free)|contact\s+(us|support)\s+(immediately|now|urgently|within)|call\s+back\s+(immediately|now|asap))\b"#),

        // Tech support / scareware
        ScamPattern("en.techsupport.alert", .techSupport, 70, "Fake security alert wording",
                    "“Your Mac is infected / Apple Security alert / Windows Defender” pop-ups and messages are scare tactics. Apple and Microsoft never contact you this way.",
                    #"\b((apple|microsoft|windows|mac(os)?|google|norton|mcafee)\s*(security|support|defender|protection|technician|help\s*desk)\s*(alert|warning|center|team|department)?|your\s+(mac|computer|pc|device|iphone|system)\s+(is|has\s+been|may\s+be)\s+(infected|compromised|hacked|at\s+risk|blocked|locked|in\s+danger)|(virus|malware|spyware|trojan|hacker)s?\s+(has\s+been\s+|have\s+been\s+|was\s+|were\s+)?(detected|found)|(\d+|several|multiple)\s+(viruses|threats|infections|trojans)\s+(found|detected)|(pornographic|illegal)\s+(spyware|content|site|material)|(error|threat)\s*(code|id)\s*[:#]?\s*[A-Z0-9x-]{4,}|do\s+not\s+(shut\s*down|restart|turn\s+off|close\s+this)\s+(your\s+)?(computer|mac|pc|window|browser)|license\s+key\s+(has\s+)?(expired|been\s+blocked)|renew(al)?\s+(of\s+)?(your\s+)?(norton|mcafee|antivirus|geek\s*squad|subscription)|(your|the)\s+(subscription|plan)\s+(has\s+been|was|is)\s+(auto[-\s]?)?renewed|auto[-\s]?renew(al|ed)\s+(for|of|at)\s+\$?\d+|charged?\s+\$?\d{2,4}(\.\d{2})?\s+(for|to)\s+(your\s+)?(subscription|renewal|annual|plan)|has\s+been\s+(debited|charged)\s+\$?\d+)\b"#),
        ScamPattern("en.techsupport.callnumber", .techSupport, 55, "Phone number next to a warning",
                    "Genuine alerts from your Mac never show a phone number to call. Only scam pop-ups do.",
                    #"(call|dial|phone|contact|reach)\s+(us|support|now|immediately|the\s+helpline|toll[-\s]?free)?\s*(at|on|:)?\s*\(?\+?\d[\d\s().-]{8,}\d"#),
        ScamPattern("en.techsupport.remote", .remoteAccess, 60, "Wants to connect to your Mac",
                    "Letting someone “fix” or “check” your Mac remotely hands it over completely.",
                    #"\b(remote(ly)?\s+(access|connect|session|assist(ance)?|control|support)|connect\s+to\s+your\s+(computer|mac|device|screen)|share\s+your\s+screen|let\s+(us|our\s+technician|me)\s+(access|fix|check|clean)\s+(your|the)\s+(computer|mac|device)|install\s+(this|the|our)\s+(tool|software|app|program)\s+(so|to\s+(allow|let|fix)))\b"#),
        ScamPattern("en.techsupport.refund_remote", .lure, 55, "Refund that needs your bank screen",
                    "“Refund” scams ask you to log in to your bank while they watch, then claim they sent too much and must be repaid.",
                    #"\b(refund|reimburse|overpaid|over[-\s]?payment|sent\s+(you\s+)?too\s+much|accidentally\s+(sent|transferred|refunded))\b.{0,120}\b(log\s*in|sign\s*in|bank\s+account|screen|return\s+the\s+(difference|extra|excess)|send\s+back)\b"#),

        // Smishing: delivery, bank, tax, toll
        ScamPattern("en.smishing.delivery", .smishing, 55, "Fake delivery notice",
                    "Couriers don't text asking for fees or address confirmation via a link. Check tracking in the courier's own app or site.",
                    #"\b((package|parcel|delivery|shipment|order|item)\s+((is|was|has\s+been)\s+)?(on\s+hold|held|pending|delayed|could\s+not\s+be\s+delivered|undeliverable|returned|waiting|awaiting|unclaimed|suspended|failed)|(unable|failed|we\s+were\s+unable|attempt(ed)?)\s+to\s+deliver|(delivery|shipping|customs|redelivery|handling)\s+(fee|charge|cost|payment)\s+(of\s+)?[$£€]?\d|incomplete\s+(address|delivery\s+(details|information))|(confirm|update|verify)\s+your\s+(address|delivery\s+(details|information|address)|shipping\s+(details|address))|reschedule\s+(your\s+)?(delivery|redelivery)|pay\s+[$£€]?\d+(\.\d+)?\s+(to\s+)?(release|reschedule|receive)|tracking\s+(number|id)\s*[:#]?\s*[a-z0-9]{6,})\b"#),
        ScamPattern("en.smishing.bank", .smishing, 50, "Bank alert pattern",
                    "Banks don't send links asking you to confirm transactions or re-register a device. Use the app or the number on your card.",
                    #"\b((new|unrecognised|unrecognized|unknown)\s+(device|payee|login|sign[-\s]?in)|(payment|transaction|purchase|transfer|charge)\s+(of\s+)?[$£€]\s?\d[\d,]*(\.\d\d)?\s+(to|at|from|was|has|is|on|pending|declined|attempted)|(attempted|pending|unusual|suspicious|declined|flagged)\s+(payment|transaction|purchase|transfer|charge|login)|did\s+you\s+(make|authori[sz]e|attempt|request)\s+(this|a)|(reply|respond|text)\s+(with\s+)?(y|yes|n|no)\b|if\s+this\s+was(n'?t|\s+not)\s+you|(online\s+banking|mobile\s+banking|your\s+(account|card))\s+(has\s+been|is|was)\s+(frozen|restricted|suspended|locked|temporarily\s+(suspended|disabled|locked))|security\s+(team|department)\s+(has|have)\s+(detected|flagged|noticed|identified|blocked))\b"#),
        ScamPattern("en.smishing.tax", .smishing, 55, "Tax or government refund / debt pattern",
                    "Tax offices and government agencies don't text or email about refunds and fines with links. They write letters, and you can check in your official account.",
                    #"\b(tax\s+(refund|rebate|return|bill|debt|overpayment|credit|relief|payment)|(hmrc|irs|revenue|ssa|social\s+security|medicare|dvla|gov\.uk|government|federal|benefit|stimulus|grant|rebate|cost\s+of\s+living)\s*(payment|refund|rebate|notice|claim|office|number)?s?\b.{0,80}\b(claim|refund|rebate|eligible|owed|due|entitled|receive|payment|suspended|pay\s+now|outstanding|penalty|fine|action)|(you\s+are\s+(eligible|entitled|owed)|outstanding\s+(tax|debt|balance|payment)|unpaid\s+(tax|fine|penalty|invoice)|(fine|penalty)\s+(of\s+)?[$£€]\d|(enforcement|collections?)\s+(action|agency|officer|department)|(benefit|payment)s?\s+(has|have)\s+been\s+(stopped|suspended|cancelled|canceled)))\b"#),
        ScamPattern("en.smishing.toll", .smishing, 70, "Unpaid toll / traffic fine pattern",
                    "Toll and parking agencies don't text payment links. These texts are a very common scam.",
                    #"\b((toll|e-?z\s*pass|ezpass|fastrak|sunpass|fast\s*trak|road\s+charge|congestion\s+charge|parking|traffic)\s*(road|service|bill|fee|charge|violation|fine|ticket|notice|invoice|balance|penalty)s?|unpaid\s+(toll|parking|traffic|fine|ticket)|outstanding\s+toll|(late|penalty)\s+fee\s+of|(small|minor)\s+(outstanding\s+)?(toll|balance|fee|charge|amount)\s+(of\s+)?[$£€]\d|vehicle\s+(record|registration)\s+(will\s+be|has\s+been)\s+(suspended|flagged))\b"#),
        ScamPattern("en.smishing.account_generic", .smishing, 35, "Generic 'verify your account' link",
                    "Messages that ask you to “verify” or “update” via a link, with no detail about what or why, are nearly always phishing.",
                    #"\b(verify|confirm|validate|update|re-?activate|restore|unlock|secure|re-?verify|re-?confirm)\s+(your\s+)?(account|identity|information|details|email|profile|billing|payment\s+(method|details|information)|card|membership|subscription|mailbox|wallet|login)\b"#),
        ScamPattern("en.smishing.mailbox", .smishing, 40, "Mailbox / storage scare",
                    "“Your mailbox is full / storage exceeded / password expires today” emails lead to fake sign-in pages that steal your password.",
                    #"\b((mailbox|storage|inbox|quota|email\s+account|icloud\s+storage|drive\s+storage|onedrive)\s+(is\s+)?(full|almost\s+full|exceeded|over\s+(its|the)\s+limit|at\s+\d+\s*%|running\s+out|about\s+to\s+expire)|password\s+(will\s+)?expires?\s+(today|tomorrow|in\s+\d+|soon)|(keep|retain)\s+(your\s+)?(same|current)\s+password|pending\s+(messages?|emails?)\s+(could\s+not|failed|were\s+not)|undelivered\s+(mail|messages?)|(incoming\s+)?(mail|messages?)\s+(are\s+)?(being\s+)?(held|blocked|quarantined))\b"#),

        // Lures
        ScamPattern("en.lure.prize", .lure, 60, "Prize, winnings or giveaway",
                    "You can't win a competition you didn't enter. “Claim your prize” messages collect fees, bank details or card numbers.",
                    #"\b(you(\s+have|'ve)\s+(been\s+)?(won|selected|chosen|picked)|congratulations|winner|(claim|collect|redeem)\s+(your\s+)?(prize|reward|winnings|gift|bonus|voucher|cash|money|free\s+\w+)|(lucky|grand)\s+(winner|draw|prize)|lottery|sweepstakes|jackpot|(prize|reward|gift)\s+(of|worth)\s+[$£€]?\d|free\s+(iphone|ipad|macbook|gift\s*card|airpods|samsung|playstation|ps5|xbox|voucher|\$\d+)|giveaway|you\s+have\s+\d+\s+(reward|loyalty)\s+points\s+(expiring|about\s+to\s+expire)|(reward|loyalty)\s+points\s+(are\s+)?(expiring|will\s+expire))\b"#),
        ScamPattern("en.lure.refund", .lure, 45, "Refund or overpayment lure",
                    "Unexpected refunds are bait. The “form” collects your card and bank details.",
                    #"\b((refund|reimbursement|compensation|rebate|overcharge)\s+(of\s+)?[$£€]?\s?\d|(eligible|entitled|qualify|approved)\s+(for|to\s+(receive|claim))\s+(a\s+)?(refund|compensation|reimbursement|rebate|payout|settlement)|(claim|request|process|receive)\s+(your\s+)?(refund|compensation|reimbursement|payout|settlement)|refund\s+(is\s+)?(pending|waiting|ready|available|has\s+been\s+(approved|issued|processed)))\b"#),
        ScamPattern("en.lure.job", .lure, 40, "Too-good job or easy-money offer",
                    "Jobs that pay hundreds a day for liking posts, reviewing products or “processing payments” are recruitment for fraud or money laundering.",
                    #"\b((earn|make|get\s+paid)\s+[$£€]\d{2,}[\d,]*\s*(k|,000)?\s*(per|a|/|each|every)?\s*(day|daily|hour|hr|week|weekly)|work\s+from\s+home\s+(and\s+)?(earn|make)|part[-\s]?time\s+(job|work|position)\s+(offer|opportunity|available)|(like|rate|review)\s+(videos|products|posts|hotels)\s+(and|to)\s+(earn|get\s+paid|make)|(no\s+experience|only\s+\d+\s+(hours?|minutes?)\s+(a|per)\s+day)|(hr|recruit(er|ment))\s+(manager|team|department)\s+(from|at|of)|your\s+(resume|cv)\s+(was|has\s+been)\s+(selected|shortlisted|reviewed)|(commission|salary)\s+(of|up\s+to)\s+[$£€]\d|(payment|money)\s+(processing|handling)\s+(agent|job|position))\b"#),
        ScamPattern("en.lure.romance_invest", .lure, 50, "Investment or 'guaranteed returns' pitch",
                    "Guaranteed profits, insider platforms and “my uncle works at the exchange” are the openers of investment and romance-investment scams.",
                    #"\b(guaranteed\s+(returns?|profits?|income|daily\s+(returns?|profits?))|(double|triple|\d+x)\s+your\s+(money|investment|bitcoin|crypto)|(\d{2,3}\s*%)\s+(return|profit|roi)\s+(in|per|within|every|daily|weekly|monthly)|(risk[-\s]?free|zero\s+risk)\s+(investment|trading|returns?)|(investment|trading|mining)\s+(platform|opportunity|program|scheme)\s+(that|with|which)|(forex|crypto|bitcoin|gold)\s+(signals|trading\s+(group|mentor|expert))|(wrong\s+number|is\s+this\s+(john|sarah|the\s+vet|lisa))|my\s+(uncle|aunt|mentor|friend)\s+(works\s+at|is\s+an?\s+(analyst|insider|trader))|withdraw(al)?\s+(fee|tax|is\s+(blocked|locked|pending))\s+(of|until)\b)"#),
        ScamPattern("en.lure.family_emergency", .lure, 60, "Family emergency / 'new number' pattern",
                    "“Hi Mum, this is my new number, I need money urgently” messages impersonate relatives. Call the old number to check.",
                    #"\b((hi|hello|hey)\s+(mum|mom|dad|mother|father|grandma|grandpa|nan|gran|nana|papa|auntie|uncle)\b.{0,160}\b(new\s+(number|phone)|phone\s+(broke|is\s+broken|fell|got\s+(stolen|damaged|lost))|lost\s+my\s+phone|(need|send|transfer)\s+(some\s+)?(money|cash|[$£€]\d))|(this\s+is\s+my\s+new\s+number|i\s+(have\s+)?(a\s+)?new\s+(number|phone)|(save|delete)\s+(this|my\s+old)\s+number)\b.{0,120}\b(money|pay|bill|urgent|transfer|bank|can'?t\s+(call|talk)|emergency|bail|hospital|accident|arrested))"#),
        ScamPattern("en.lure.sextortion", .lure, 75, "Blackmail / sextortion script",
                    "These are sent to millions of people at once; the sender has nothing. Don't pay, don't reply, change any password they quoted.",
                    #"\b((recorded|have|has)\s+(a\s+)?(video|footage|recording)\s+of\s+you|webcam|(adult|porn|xxx)\s*(site|website|video)s?|(malware|trojan|rat)\s+(on|in|installed\s+on)\s+your\s+(device|computer|phone)|(send|post|share|release|publish)\s+(it|the\s+video|this\s+video|the\s+footage|the\s+recording)\s+to\s+(all\s+)?(your\s+)?(contacts|friends|family|colleagues)|i\s+(know|have)\s+your\s+password|(your|the)\s+password\s+is\s*[:\s]\s*\S+|you\s+have\s+\d+\s+hours\s+to\s+(pay|send|transfer))\b"#),
        ScamPattern("en.lure.invoice", .lure, 35, "Unexpected invoice or receipt",
                    "Fake invoices for orders you didn't place make you call “to cancel”, where the real scam starts.",
                    #"\b(thank\s+you\s+for\s+(your\s+)?(purchase|order|payment)\s+of\s+[$£€]?\d{2,}|(has|have)\s+been\s+(successfully\s+)?(charged|debited|billed)\s+[$£€]?\d|invoice\s+(is\s+)?attached|(to\s+)?cancel\s+(this|the|your)\s+(order|subscription|charge|transaction|purchase)[,.]?\s+(please\s+)?(call|contact|reach))\b"#),
        ScamPattern("en.lure.shellcommand", .pageClickFix, 85, "Tells you to paste a command into Terminal",
                    "No website or support agent should ever ask you to open Terminal and paste a command. This installs malware.",
                    #"\b((open|launch|press|go\s+to)\s+(the\s+)?(terminal|command\s+prompt|cmd|powershell|run\s+(dialog|box)|spotlight)\b.{0,160}\b(paste|⌘\s*\+?\s*v|cmd\s*\+\s*v|ctrl\s*\+\s*v|press\s+(enter|return))|(cmd|command|⌘)\s*(\+|-|\s)\s*(space|v|shift)\b|win(dows)?\s*(key)?\s*\+\s*r\b|ctrl\s*\+\s*v\b|(curl|wget|bash|sh|osascript|powershell|mshta|base64|echo)\s+[^\n]{0,80}(\|\s*(bash|sh|zsh|python|osascript)|-c\s+["'])|verify\s+you\s+are\s+(a\s+)?human\b.{0,200}\b(terminal|command|paste|run)\b)"#),

        // Sender / wording cues
        ScamPattern("en.sender.generic", .sender, 15, "Doesn't use your name",
                    "Mass scam messages open with “Dear customer” because the sender doesn't know who you are.",
                    #"^\s*(dear|hello|hi|greetings|attention)\s*[,:]?\s*(customer|user|member|client|account\s+holder|valued\s+(customer|member|client)|sir\s*/?\s*madam|beneficiary|winner|friend|subscriber|email\s+user|account\s+owner|cardholder|taxpayer|citizen)\b"#),
        ScamPattern("en.sender.badlink", .link, 30, "'Click here' style link prompt",
                    "Vague link text hides where the link really goes. Hover or long-press to see the address, and prefer typing the site yourself.",
                    #"\b(click\s+(here|below|the\s+(link|button)\s+below|on\s+the\s+link)|tap\s+(here|below|the\s+link)|follow\s+(this|the)\s+link|open\s+(the\s+)?(attached|attachment)|see\s+(the\s+)?attached|login\s+here|sign\s+in\s+here|visit\s+(the\s+)?link)\b"#),
        ScamPattern("en.sender.unsubscribe_bait", .sender, 10, "Pressure to confirm by replying",
                    "Replying tells the sender your number or address is live, which invites more scams.",
                    #"\b(reply\s+(stop|yes|y|no|n|confirm|ok)\b|text\s+(back|yes|y)\b|respond\s+with\s+(yes|y)\b)"#),
    ], tips: [
        .urgency: "Slow down. Anyone who needs you to act in the next few minutes is trying to stop you thinking.",
        .payment: "Nobody legitimate takes gift cards, crypto or wire transfers for bills, fines or “security”.",
        .credentials: "Never share one-time codes, passwords or recovery phrases, whoever asks.",
        .techSupport: "Close the page or message. Apple and Microsoft never show phone numbers in alerts.",
        .remoteAccess: "Don't install remote-control tools at someone else's request. If you already did, uninstall it and change passwords.",
        .smishing: "Don't use the link. Open the company's app or type its address yourself.",
        .lure: "If you didn't enter, you didn't win. Unexpected refunds and jobs need no link to claim.",
        .sender: "Check the actual email address, not the display name, and compare it with past genuine mail.",
        .authentication: "Failed SPF, DKIM or DMARC means the sending server wasn't allowed to send for that domain.",
        .link: "Hover over links before clicking. The address bar, not the page design, tells you where you are.",
        .lookalike: "Look at the part just before .com / .co.uk. That's the real owner, whatever comes before it.",
        .urlStructure: "Odd-looking addresses (IP numbers, @ signs, many dots, shorteners) deserve a second look.",
        .pageClickFix: "Never paste anything into Terminal that a website told you to. No CAPTCHA works that way.",
        .pageClipboard: "This page quietly writes to your clipboard. Don't paste anywhere without checking what you copied.",
        .pageDrainer: "Connecting your wallet and signing an unexpected approval can empty it in one click.",
        .pageScareware: "Fake virus alerts are just web pages. Close the tab (⌘W) or quit the browser; nothing is installed.",
        .pageCredentialForm: "Before typing a password, check the address bar shows the company's real domain.",
        .blocklist: "This site is on a list of known phishing or malware sites. Don't enter anything.",
    ])
}
