import Foundation

/// Bundled list of frequently impersonated brands with their legitimate registrable domains.
/// Lookalike checks compare the registrable label of a host against `keywords`; a host whose
/// registrable domain is in `domains` is the real thing and never flagged.
public struct Brand: Hashable, Sendable {
    public let name: String
    public let keywords: [String]      // labels that identify the brand (lowercase, ASCII)
    public let domains: [String]       // registrable domains that are genuinely the brand
    public init(name: String, keywords: [String], domains: [String]) { self.name = name; self.keywords = keywords; self.domains = domains }
}

public enum BrandList {
    public static let brands: [Brand] = [
        Brand(name: "Apple", keywords: ["apple", "icloud", "appleid", "itunes"], domains: ["apple.com", "icloud.com", "apple.co", "itunes.com", "me.com", "mac.com", "apple.news"]),
        Brand(name: "Microsoft", keywords: ["microsoft", "office365", "outlook", "onedrive", "sharepoint", "hotmail", "live", "msn", "xbox", "azure"],
              domains: ["microsoft.com", "office.com", "office365.com", "outlook.com", "live.com", "hotmail.com", "msn.com", "onedrive.com", "sharepoint.com", "microsoftonline.com", "xbox.com", "azure.com", "windows.com", "skype.com", "bing.com", "linkedin.com", "github.com", "visualstudio.com", "aka.ms"]),
        Brand(name: "Google", keywords: ["google", "gmail", "youtube", "googledrive"], domains: ["google.com", "gmail.com", "youtube.com", "goo.gl", "googleapis.com", "withgoogle.com", "google.co.uk", "googleusercontent.com", "gstatic.com", "android.com", "blogspot.com", "g.co", "youtu.be"]),
        Brand(name: "Amazon", keywords: ["amazon", "amzn", "prime", "aws"], domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.ca", "amazon.fr", "amazon.it", "amazon.es", "amazon.co.jp", "amzn.to", "amzn.com", "amazonaws.com", "primevideo.com", "aws.amazon.com", "audible.com"]),
        Brand(name: "PayPal", keywords: ["paypal"], domains: ["paypal.com", "paypal.me", "paypal.co.uk", "paypalobjects.com"]),
        Brand(name: "Netflix", keywords: ["netflix"], domains: ["netflix.com", "nflx.com"]),
        Brand(name: "Facebook", keywords: ["facebook", "instagram", "whatsapp", "messenger", "meta"], domains: ["facebook.com", "fb.com", "fb.me", "instagram.com", "whatsapp.com", "messenger.com", "meta.com", "fbcdn.net", "threads.net"]),
        Brand(name: "DHL", keywords: ["dhl"], domains: ["dhl.com", "dhl.de", "dhl.co.uk", "dhlparcel.co.uk", "dhlexpress.com"]),
        Brand(name: "FedEx", keywords: ["fedex"], domains: ["fedex.com"]),
        Brand(name: "UPS", keywords: ["ups"], domains: ["ups.com"]),
        Brand(name: "USPS", keywords: ["usps"], domains: ["usps.com", "usps.gov"]),
        Brand(name: "Royal Mail", keywords: ["royalmail"], domains: ["royalmail.com", "royalmail.co.uk"]),
        Brand(name: "Evri", keywords: ["evri", "hermes"], domains: ["evri.com", "myhermes.co.uk"]),
        Brand(name: "Chase", keywords: ["chase"], domains: ["chase.com", "jpmorganchase.com", "jpmorgan.com"]),
        Brand(name: "Bank of America", keywords: ["bankofamerica", "bofa"], domains: ["bankofamerica.com", "bofa.com"]),
        Brand(name: "Wells Fargo", keywords: ["wellsfargo"], domains: ["wellsfargo.com", "wf.com"]),
        Brand(name: "Citi", keywords: ["citibank", "citi"], domains: ["citi.com", "citibank.com", "citigroup.com"]),
        Brand(name: "HSBC", keywords: ["hsbc"], domains: ["hsbc.com", "hsbc.co.uk", "hsbc.com.hk"]),
        Brand(name: "Barclays", keywords: ["barclays"], domains: ["barclays.co.uk", "barclays.com", "barclaycard.co.uk"]),
        Brand(name: "Lloyds", keywords: ["lloyds", "lloydsbank"], domains: ["lloydsbank.com", "lloydsbank.co.uk", "lloydsbankinggroup.com"]),
        Brand(name: "NatWest", keywords: ["natwest"], domains: ["natwest.com", "natwestgroup.com"]),
        Brand(name: "Santander", keywords: ["santander"], domains: ["santander.com", "santander.co.uk", "santanderbank.com"]),
        Brand(name: "Monzo", keywords: ["monzo"], domains: ["monzo.com"]),
        Brand(name: "Revolut", keywords: ["revolut"], domains: ["revolut.com"]),
        Brand(name: "Wise", keywords: ["transferwise"], domains: ["wise.com", "transferwise.com"]),
        Brand(name: "Coinbase", keywords: ["coinbase"], domains: ["coinbase.com", "cb.com"]),
        Brand(name: "Binance", keywords: ["binance"], domains: ["binance.com", "binance.us"]),
        Brand(name: "Kraken", keywords: ["kraken"], domains: ["kraken.com"]),
        Brand(name: "MetaMask", keywords: ["metamask"], domains: ["metamask.io"]),
        Brand(name: "Ledger", keywords: ["ledger"], domains: ["ledger.com"]),
        Brand(name: "Trezor", keywords: ["trezor"], domains: ["trezor.io"]),
        Brand(name: "OpenSea", keywords: ["opensea"], domains: ["opensea.io"]),
        Brand(name: "Uniswap", keywords: ["uniswap"], domains: ["uniswap.org"]),
        Brand(name: "Dropbox", keywords: ["dropbox"], domains: ["dropbox.com", "dropboxusercontent.com"]),
        Brand(name: "DocuSign", keywords: ["docusign"], domains: ["docusign.com", "docusign.net"]),
        Brand(name: "Adobe", keywords: ["adobe"], domains: ["adobe.com", "adobelogin.com", "acrobat.com"]),
        Brand(name: "Zoom", keywords: ["zoom"], domains: ["zoom.us", "zoom.com"]),
        Brand(name: "Slack", keywords: ["slack"], domains: ["slack.com", "slack-edge.com"]),
        Brand(name: "Spotify", keywords: ["spotify"], domains: ["spotify.com", "scdn.co"]),
        Brand(name: "eBay", keywords: ["ebay"], domains: ["ebay.com", "ebay.co.uk", "ebay.de"]),
        Brand(name: "Etsy", keywords: ["etsy"], domains: ["etsy.com"]),
        Brand(name: "Walmart", keywords: ["walmart"], domains: ["walmart.com"]),
        Brand(name: "Costco", keywords: ["costco"], domains: ["costco.com"]),
        Brand(name: "Target", keywords: ["target"], domains: ["target.com"]),
        Brand(name: "Best Buy", keywords: ["bestbuy"], domains: ["bestbuy.com"]),
        Brand(name: "Steam", keywords: ["steampowered", "steamcommunity"], domains: ["steampowered.com", "steamcommunity.com", "steamgames.com"]),
        Brand(name: "Discord", keywords: ["discord"], domains: ["discord.com", "discord.gg", "discordapp.com"]),
        Brand(name: "Telegram", keywords: ["telegram"], domains: ["telegram.org", "t.me", "telegram.me"]),
        Brand(name: "Twitter / X", keywords: ["twitter"], domains: ["twitter.com", "x.com", "t.co"]),
        Brand(name: "TikTok", keywords: ["tiktok"], domains: ["tiktok.com"]),
        Brand(name: "Snapchat", keywords: ["snapchat"], domains: ["snapchat.com"]),
        Brand(name: "Yahoo", keywords: ["yahoo"], domains: ["yahoo.com", "yahoo.co.uk", "aol.com"]),
        Brand(name: "Twilio / Authy", keywords: ["authy"], domains: ["authy.com", "twilio.com"]),
        Brand(name: "Okta", keywords: ["okta"], domains: ["okta.com", "oktapreview.com"]),
        Brand(name: "Cloudflare", keywords: ["cloudflare"], domains: ["cloudflare.com", "cloudflare-dns.com", "cloudflareinsights.com"]),
        Brand(name: "IRS", keywords: ["irs"], domains: ["irs.gov"]),
        Brand(name: "HMRC", keywords: ["hmrc"], domains: ["hmrc.gov.uk", "gov.uk", "tax.service.gov.uk"]),
        Brand(name: "GOV.UK", keywords: ["govuk", "dvla"], domains: ["gov.uk", "service.gov.uk"]),
        Brand(name: "Social Security", keywords: ["ssa"], domains: ["ssa.gov"]),
        Brand(name: "E-ZPass", keywords: ["ezpass", "ezdrivema", "sunpass", "fastrak"], domains: ["e-zpassny.com", "ezpass.com", "ezdrivema.com", "sunpass.com", "bayareafastrak.org", "thetollroads.com"]),
        Brand(name: "Norton", keywords: ["norton", "lifelock"], domains: ["norton.com", "lifelock.com", "nortonlifelock.com"]),
        Brand(name: "McAfee", keywords: ["mcafee"], domains: ["mcafee.com"]),
        Brand(name: "Geek Squad", keywords: ["geeksquad"], domains: ["geeksquad.com", "bestbuy.com"]),
        Brand(name: "Verizon", keywords: ["verizon"], domains: ["verizon.com", "verizonwireless.com", "vzw.com"]),
        Brand(name: "AT&T", keywords: ["att"], domains: ["att.com", "att.net"]),
        Brand(name: "T-Mobile", keywords: ["tmobile"], domains: ["t-mobile.com", "tmobile.com"]),
        Brand(name: "Vodafone", keywords: ["vodafone"], domains: ["vodafone.com", "vodafone.co.uk"]),
        Brand(name: "O2", keywords: ["o2"], domains: ["o2.co.uk", "o2.com"]),
        Brand(name: "EE", keywords: ["ee"], domains: ["ee.co.uk"]),
        Brand(name: "Venmo", keywords: ["venmo"], domains: ["venmo.com"]),
        Brand(name: "Zelle", keywords: ["zelle"], domains: ["zellepay.com", "zelle.com"]),
        Brand(name: "Cash App", keywords: ["cashapp"], domains: ["cash.app", "squareup.com", "block.xyz"]),
        Brand(name: "Stripe", keywords: ["stripe"], domains: ["stripe.com"]),
        Brand(name: "Shopify", keywords: ["shopify"], domains: ["shopify.com", "myshopify.com"]),
        Brand(name: "Intuit", keywords: ["intuit", "quickbooks", "turbotax"], domains: ["intuit.com", "quickbooks.com", "turbotax.com"]),
        Brand(name: "American Express", keywords: ["americanexpress", "amex"], domains: ["americanexpress.com", "amex.com"]),
        Brand(name: "Capital One", keywords: ["capitalone"], domains: ["capitalone.com"]),
        Brand(name: "Booking.com", keywords: ["booking"], domains: ["booking.com"]),
        Brand(name: "Airbnb", keywords: ["airbnb"], domains: ["airbnb.com", "airbnb.co.uk"]),
        Brand(name: "Uber", keywords: ["uber"], domains: ["uber.com"]),
        Brand(name: "1Password", keywords: ["1password"], domains: ["1password.com", "1password.eu"]),
        Brand(name: "LastPass", keywords: ["lastpass"], domains: ["lastpass.com"]),
        Brand(name: "Bitwarden", keywords: ["bitwarden"], domains: ["bitwarden.com"]),
    ]

    static let keywordIndex: [String: Brand] = {
        var m: [String: Brand] = [:]
        for b in brands { for k in b.keywords { m[k] = b } }
        return m
    }()
    static let legitimateDomains: Set<String> = Set(brands.flatMap(\.domains))

    public static func brand(forKeyword k: String) -> Brand? { keywordIndex[k] }
    public static func isLegitimate(registrableDomain: String) -> Bool { legitimateDomains.contains(registrableDomain) }
}

/// Minimal public-suffix knowledge: enough to pick the registrable domain for common hosts
/// without shipping the full PSL. Unknown two-part suffixes fall back to "last two labels".
public enum PublicSuffix {
    static let twoPartSuffixes: Set<String> = [
        "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "gov.uk", "ac.uk", "nhs.uk", "sch.uk",
        "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "org.nz", "govt.nz",
        "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "co.kr", "or.kr", "com.br", "org.br", "gov.br",
        "com.mx", "com.ar", "com.tr", "com.cn", "net.cn", "org.cn", "com.hk", "com.sg", "com.my",
        "co.in", "net.in", "org.in", "co.za", "org.za", "com.ng", "com.eg", "co.il", "com.sa", "com.ua",
        "com.pl", "co.id", "com.ph", "com.vn", "com.tw", "co.th", "com.pk", "com.bd",
        "github.io", "gitlab.io", "pages.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
        "herokuapp.com", "azurewebsites.net", "cloudfront.net", "blob.core.windows.net", "s3.amazonaws.com",
        "weebly.com", "wixsite.com", "webflow.io", "glitch.me", "repl.co", "workers.dev", "r2.dev",
        "godaddysites.com", "square.site", "myshopify.com", "blogspot.com", "wordpress.com", "notion.site",
        "duckdns.org", "no-ip.org", "ddns.net", "000webhostapp.com", "ipfs.io", "ipfs.dweb.link",
    ]
    /// Hosting platforms where any subdomain belongs to a different, unvetted owner.
    public static let sharedHostingSuffixes: Set<String> = [
        "github.io", "gitlab.io", "pages.dev", "web.app", "firebaseapp.com", "netlify.app", "vercel.app",
        "herokuapp.com", "azurewebsites.net", "cloudfront.net", "weebly.com", "wixsite.com", "webflow.io",
        "glitch.me", "repl.co", "workers.dev", "r2.dev", "godaddysites.com", "square.site", "blogspot.com",
        "wordpress.com", "notion.site", "duckdns.org", "no-ip.org", "ddns.net", "000webhostapp.com", "ipfs.io",
    ]

    /// `registrable("login.secure.paypal.co.uk")` → `("paypal.co.uk", "paypal", "co.uk")`.
    public static func split(_ host: String) -> (registrable: String, label: String, suffix: String)? {
        let labels = host.split(separator: ".").map(String.init)
        guard labels.count >= 2 else { return nil }
        let last2 = labels.suffix(2).joined(separator: ".")
        if twoPartSuffixes.contains(last2) {
            guard labels.count >= 3 else { return nil }
            let label = labels[labels.count - 3]
            return (label + "." + last2, label, last2)
        }
        let label = labels[labels.count - 2]
        return (last2, label, labels[labels.count - 1])
    }
}

/// Unicode confusables: maps characters from other scripts (and some Latin look-alikes) to the
/// ASCII letter they imitate. Not the full UTS #39 table, but the characters actually used in
/// homograph attacks on brand names. `skeleton()` also folds digits that mimic letters.
public enum Confusables {
    static let map: [Character: String] = [
        // Cyrillic
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s", "һ": "h",
        "ԁ": "d", "ɡ": "g", "ԛ": "q", "ԝ": "w", "ӏ": "l", "ь": "b", "т": "t", "к": "k", "м": "m", "н": "h", "в": "b", "г": "r",
        "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t", "Х": "x", "У": "y",
        // Greek
        "α": "a", "ο": "o", "ν": "v", "ρ": "p", "τ": "t", "ι": "i", "κ": "k", "χ": "x", "υ": "u", "ε": "e", "η": "n", "ω": "w",
        "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o", "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x",
        // Latin with diacritics / special letters
        "ɑ": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a", "å": "a", "ā": "a", "ą": "a",
        "ç": "c", "ć": "c", "č": "c", "ċ": "c", "ď": "d", "đ": "d",
        "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e", "ė": "e", "ę": "e", "ě": "e",
        "ğ": "g", "ģ": "g", "ġ": "g", "ĥ": "h", "ħ": "h",
        "ì": "i", "í": "i", "î": "i", "ï": "i", "ī": "i", "į": "i", "ı": "i", "ĩ": "i",
        "ĵ": "j", "ķ": "k", "ĺ": "l", "ļ": "l", "ľ": "l", "ł": "l", "ŀ": "l",
        "ñ": "n", "ń": "n", "ņ": "n", "ň": "n", "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o", "ő": "o",
        "ŕ": "r", "ř": "r", "ś": "s", "š": "s", "ş": "s", "ș": "s", "ţ": "t", "ť": "t", "ț": "t",
        "ù": "u", "ú": "u", "û": "u", "ü": "u", "ū": "u", "ů": "u", "ű": "u", "ų": "u", "ŵ": "w", "ý": "y", "ÿ": "y", "ŷ": "y",
        "ź": "z", "ż": "z", "ž": "z", "ß": "ss", "æ": "ae", "œ": "oe",
        // Fullwidth / mathematical / other look-alikes
        "ａ": "a", "ｅ": "e", "ｏ": "o", "ｐ": "p", "ｌ": "l", "ｉ": "i",
        "ⅼ": "l", "ⅰ": "i", "ⅴ": "v", "ⅹ": "x", "ⅽ": "c", "ⅾ": "d", "ⅿ": "m",
        "ℓ": "l", "ℹ": "i", "ℯ": "e", "ℴ": "o", "ꓲ": "i", "ꓳ": "o", "ꓑ": "p", "ꓚ": "c", "ꓔ": "t", "ꓭ": "b",
    ]

    /// Lowercase, strip diacritics via the table, map confusables to ASCII.
    public static func skeleton(_ s: String) -> String {
        var out = ""
        out.reserveCapacity(s.count)
        for ch in s {
            if let m = map[ch] { out += m; continue }
            if ch.isASCII { out.append(Character(ch.lowercased())); continue }
            // Generic fallback: strip combining marks, keep the base letter if ASCII.
            let folded = String(ch).folding(options: [.diacriticInsensitive, .caseInsensitive], locale: nil)
            if folded.count == 1, let f = folded.first, f.isASCII { out.append(f) } else { out.append(ch) }
        }
        return out
    }

    /// Folds digit/letter substitutions typosquatters use: paypa1 → paypal, g00gle → google, rn → m, vv → w.
    public static func typoFold(_ s: String) -> String {
        var t = s.lowercased()
        t = t.replacingOccurrences(of: "rn", with: "m")
        t = t.replacingOccurrences(of: "vv", with: "w")
        t = t.replacingOccurrences(of: "cl", with: "d")
        let digitMap: [Character: Character] = ["0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "|": "l", "!": "i"]
        return String(t.map { digitMap[$0] ?? $0 })
    }

    /// True if the string mixes Latin letters with letters from another script (classic homograph).
    public static func isMixedScript(_ s: String) -> Bool {
        var latin = false, other = false
        for u in s.unicodeScalars where u.properties.isAlphabetic {
            if u.isASCII || (u.value >= 0x00C0 && u.value <= 0x024F) { latin = true } else { other = true }
        }
        return latin && other
    }

    public static func hasNonASCII(_ s: String) -> Bool { s.unicodeScalars.contains { !$0.isASCII } }
}

/// RFC 3492 Punycode decoder/encoder, used for `xn--` labels. Pure Swift, no ICU dependency.
public enum Punycode {
    private static let base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 128

    private static func adapt(_ delta: Int, _ numPoints: Int, _ first: Bool) -> Int {
        var delta = first ? delta / damp : delta / 2
        delta += delta / numPoints
        var k = 0
        while delta > ((base - tMin) * tMax) / 2 { delta /= base - tMin; k += base }
        return k + (base - tMin + 1) * delta / (delta + skew)
    }

    private static func digit(_ c: UInt8) -> Int? {
        switch c {
        case 48...57: return Int(c) - 22        // 0-9 → 26..35
        case 65...90: return Int(c) - 65
        case 97...122: return Int(c) - 97
        default: return nil
        }
    }

    /// Decodes one label without the `xn--` prefix. Returns nil on malformed input.
    public static func decode(_ input: String) -> String? {
        var output: [UInt32] = []
        let bytes = Array(input.utf8)
        var pos = 0
        if let lastDelim = bytes.lastIndex(of: UInt8(ascii: "-")) {
            for b in bytes[..<lastDelim] { guard b < 128 else { return nil }; output.append(UInt32(b)) }
            pos = lastDelim + 1
        }
        var n = initialN, i = 0, bias = initialBias
        while pos < bytes.count {
            let oldi = i
            var w = 1, k = base
            while true {
                guard pos < bytes.count, let d = digit(bytes[pos]) else { return nil }
                pos += 1
                i += d * w
                let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                if d < t { break }
                w *= base - t
                k += base
                if i > 0x10FFFF { return nil }
            }
            bias = adapt(i - oldi, output.count + 1, oldi == 0)
            n += i / (output.count + 1)
            i %= output.count + 1
            guard n <= 0x10FFFF, Unicode.Scalar(UInt32(n)) != nil else { return nil }
            output.insert(UInt32(n), at: i)
            i += 1
        }
        var s = ""
        for cp in output { guard let u = Unicode.Scalar(cp) else { return nil }; s.unicodeScalars.append(u) }
        return s
    }

    /// Encodes one Unicode label (without the prefix). Returns nil if the label is pure ASCII.
    public static func encode(_ input: String) -> String? {
        let scalars = input.unicodeScalars.map { Int($0.value) }
        guard scalars.contains(where: { $0 >= 128 }) else { return nil }
        var output = scalars.filter { $0 < 128 }.map { Character(Unicode.Scalar(UInt8($0))) }
        let b = output.count
        if b > 0 { output.append("-") }
        var n = initialN, delta = 0, bias = initialBias, h = b
        while h < scalars.count {
            let m = scalars.filter { $0 >= n }.min()!
            delta += (m - n) * (h + 1)
            n = m
            for c in scalars {
                if c < n { delta += 1 }
                if c == n {
                    var q = delta, k = base
                    while true {
                        let t = k <= bias ? tMin : (k >= bias + tMax ? tMax : k - bias)
                        if q < t { break }
                        let dgt = t + (q - t) % (base - t)
                        output.append(Character(Unicode.Scalar(UInt8(dgt < 26 ? dgt + 97 : dgt + 22))))
                        q = (q - t) / (base - t)
                        k += base
                    }
                    output.append(Character(Unicode.Scalar(UInt8(q < 26 ? q + 97 : q + 22))))
                    bias = adapt(delta, h + 1, h == b)
                    delta = 0
                    h += 1
                }
            }
            delta += 1; n += 1
        }
        return String(output)
    }

    /// `xn--pple-43d.com` → `аpple.com` (label-wise).
    public static func decodeHost(_ host: String) -> String {
        host.split(separator: ".", omittingEmptySubsequences: false).map { label -> String in
            let l = String(label)
            if l.lowercased().hasPrefix("xn--"), let d = decode(String(l.dropFirst(4))) { return d }
            return l
        }.joined(separator: ".")
    }

    /// `аpple.com` → `xn--pple-43d.com`.
    public static func encodeHost(_ host: String) -> String {
        host.split(separator: ".", omittingEmptySubsequences: false).map { label -> String in
            let l = String(label)
            if let e = encode(l) { return "xn--" + e }
            return l
        }.joined(separator: ".")
    }
}
