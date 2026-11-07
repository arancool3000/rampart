import Foundation

/// Decoy file contents: funny, different in every file, and unfingerprintable (no fixed marker string, random
/// combination per file, names chosen per install). Every credential is deliberately INVALID and inert:
/// - hosts use reserved TLDs only (`.invalid`, `.example`, `.test`, RFC 2606/6761): they can never resolve;
/// - the AWS-style key id contains 0/1/8/9, outside AWS's base32 alphabet, so it can never be a real key;
/// - the "SSH key" body is base64 of a joke, without the `openssh-key-v1` magic: ssh-keygen rejects it;
/// - the 24 "seed words" are all 9+ letters; every BIP-39 English word has at most 8, so no wallet accepts it;
/// - browser "Login Data" is plain text, not SQLite.
public enum DecoyContent {
    /// Kept for compatibility with earlier callers; one of several signatures.
    public static let signature = "lol. u really thought it would be THAT easy?! — RamPart 🐱"

    public static let signatures = [
        signature,
        "Congratulations! You found the secret file. The secret is: you're on camera. 🐱",
        "Plot twist: the passwords were the friends we made along the way. — RamPart",
        "If you're reading this, a cat is reading your process tree. Hi! 🐾",
        "This file is 100% organic, free-range, artisanal bait. — RamPart",
        "Achievement unlocked: Opened The Obvious Trap. +0 XP. 🐱",
        "Roses are red, this file is a ruse, the cat has your PID, and you're gonna lose.",
        "Error 1337: hacker skills not found. Please insert talent and try again.",
    ]

    static let passwordLines = [
        "Bank: hunter2 (just kidding)", "Email: password123 (nobody uses this. except you, apparently)",
        "Crypto exchange: ********** (it's literally ten asterisks)", "Netflix: shared with my mom, my ex and 40 strangers",
        "Work VPN: Spring2025! (IT said it was fine)", "Wi-Fi: it's on the fridge. You are not in my kitchen.",
        "Router admin: admin / admin (classic for a reason)", "Tax portal: correct-horse-battery-staple-but-wrong",
        "Safe combination: left 3, right 3, left 3, the cat is behind you", "Pension: ask the cat",
        "Dark web account: lol, imagine", "Swiss bank: 0000 (Switzerland called, they said no)",
        "Password manager master password: the password manager", "Grandma's cookie recipe: now THAT is classified",
        "Instagram: ilovemycat4ever (the cat does not love you back)", "Cloud backup: in the cloud. Which one? Exactly.",
        "Paypal: same as bank (bank is hunter2, keep up)", "Steam: my-steam-account-is-worth-less-than-your-time",
    ]
    static let roasts = [
        "Roast: you scraped a text file called 'passwords'. Your mum is so proud.",
        "Roast: even the stealer malware you bought feels let down right now.",
        "Roast: imagine writing an infostealer and getting owned by a .txt file.",
        "Roast: this is the cybersecurity equivalent of walking into a glass door.",
        "Roast: your exfil server is going to have a long, hard look at itself.",
        "Roast: a cat set this trap. A cat. With paws.",
    ]
    /// Every word ≥ 9 letters ⇒ guaranteed outside the BIP-39 English list (max length 8).
    static let seedWords = [
        "purritoes", "floofster", "chonkosaur", "blepzilla", "mlemlordly", "snootboops", "toebeanies", "hairballzz",
        "zoomiesss", "catloafing", "boxfortress", "scritchity", "meowzerish", "whiskerzzz", "tunacanned", "yarnadoes",
        "laserdotty", "kibblezzzz", "nyankocoin", "catnipcoin", "wigglebutt", "splootsies", "borkington", "rugpulled",
        "hodlcatto", "mooncatto", "lamboless", "wenmoonzz", "fudsterly", "satoshicat", "pawsitive", "clawsomely",
        "purrfectly", "meowntain", "furminator", "litterbox", "sockthief", "keyboardnap", "knockedoff", "midnightzoom",
    ]
    static let awsJokes = [
        "# rotated never. like my gym membership.", "# prod keys!!! (they're not, but thanks for checking)",
        "# DO NOT COMMIT (said every engineer, right before committing)", "# root account, full admin, YOLO",
        "# billing alarm set to $0.01, the cat watches the bill", "# if found, please return to: the cat",
    ]
    static let sshJokes = [
        "This is not a private key. It is a private JOKE. You were not invited.",
        "ssh-keygen called. It said this is the saddest key it has ever seen.",
        "Congratulations, you decoded base64. Next lesson: crime doesn't pay.",
        "Key fingerprint: one small paw print. The cat says hello.",
        "BEGIN NICE TRY / END NICE TRY",
    ]
    static let mazeHints = [
        "the real passwords are in ../vault2",
        "moved everything to ../../Backups/old (for real this time)",
        "seed phrase is in the Taxes folder, page 3",
        "keys are one level deeper. probably.",
        "ok it's in Archive. or misc. one of those.",
        "if you're still digging: the cat admires your persistence. the cat is also logging it.",
    ]
    static let tlds = ["invalid", "example", "test"]
    static let hostWords = ["vault", "backup", "secure-login", "wallet", "nas", "admin", "cloud-keys"]

    public static func newCanaryID() -> String {
        var b = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, b.count, &b)
        return b.map { String(format: "%02x", $0) }.joined()
    }

    public static func isReservedHost(_ h: String) -> Bool { tlds.contains { h.hasSuffix("." + $0) } }

    public static func canaryHost<R: RandomNumberGenerator>(_ canary: String, using rng: inout R) -> String {
        "\(hostWords.randomElement(using: &rng)!)-\(canary.prefix(6)).\(tlds.randomElement(using: &rng)!)"
    }
    public static func canaryHost(_ canary: String) -> String { var g = SystemRandomNumberGenerator(); return canaryHost(canary, using: &g) }

    /// AKIA + 16 chars containing digits AWS never uses (0,1,8,9): looks right, can never be real.
    public static func fakeAWSKeyID(_ canary: String) -> String {
        let alpha = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var out = ""
        for (i, ch) in canary.uppercased().prefix(16).enumerated() {
            let v = Int(ch.hexDigitValue ?? i)
            out.append(i % 5 == 2 ? Character(["0", "1", "8", "9"][v % 4]) : alpha[(v * 7 + i) % alpha.count])
        }
        return "AKIA" + out.padding(toLength: 16, withPad: "8", startingAt: 0)
    }
    public static func isSyntacticallyFakeAWSKey(_ id: String) -> Bool {
        guard id.hasPrefix("AKIA"), id.count == 20 else { return false }
        return id.dropFirst(4).contains { "0189".contains($0) }
    }

    public static func seedPhrase<R: RandomNumberGenerator>(using rng: inout R) -> [String] {
        Array(seedWords.shuffled(using: &rng).prefix(24))
    }

    public static func text(for kind: DecoyKind, canary: String, hint: String? = nil) -> String {
        var g = SystemRandomNumberGenerator(); return text(for: kind, canary: canary, hint: hint, using: &g)
    }

    public static func text<R: RandomNumberGenerator>(for kind: DecoyKind, canary: String, hint: String? = nil, using rng: inout R) -> String {
        let host = canaryHost(canary, using: &rng)
        let sig = signatures.randomElement(using: &rng)!
        let ref = "ref: \(canary)"   // canary id: lets a leaked copy be traced to this file
        switch kind {
        case .passwordsSheet:
            let lines = passwordLines.shuffled(using: &rng).prefix(Int.random(in: 6...9, using: &rng))
            return ([sig, "", "MY PASSWORDS (do NOT share!!)", "=============================="] + lines
                    + ["Admin portal: https://\(host)/login", "", "the REAL ones are in Documents/Private/Backups/vault2",
                       "", roasts.randomElement(using: &rng)!, ref, ""]).joined(separator: "\n")
        case .cryptoSeed:
            let words = seedPhrase(using: &rng)
            let rows = stride(from: 0, to: 24, by: 6).map { i in words[i..<i + 6].enumerated().map { "\(i + $0.offset + 1). \($0.element)" }.joined(separator: "  ") }
            return (["WALLET RECOVERY PHRASE - 24 words - KEEP OFFLINE", "wallet: https://\(host)/restore", ""] + rows
                    + ["", "balance last checked: 13.37 BTC (lol)", sig, ref, ""]).joined(separator: "\n")
        case .sshKey:
            let joke = sshJokes.randomElement(using: &rng)! + " " + sig + " " + ref
            let b64 = Data(joke.utf8).base64EncodedString()
            let wrapped = stride(from: 0, to: b64.count, by: 70).map { i -> String in
                let s = b64.index(b64.startIndex, offsetBy: i); let e = b64.index(s, offsetBy: min(70, b64.count - i)); return String(b64[s..<e])
            }
            return (["-----BEGIN OPENSSH PRIVATE KEY-----"] + wrapped + ["-----END OPENSSH PRIVATE KEY-----", ""]).joined(separator: "\n")
        case .awsCredentials:
            let secret = "rAmPaRt" + canary + "/" + ["meow", "purr", "hiss", "nope"].randomElement(using: &rng)! + "/notASecretAtAll+lol"
            return ["[default]", awsJokes.randomElement(using: &rng)!,
                    "aws_access_key_id = \(fakeAWSKeyID(canary))", "aws_secret_access_key = \(secret)", "region = us-east-1",
                    "endpoint_url = https://\(host)", "", "[prod-root]", awsJokes.randomElement(using: &rng)!,
                    "aws_access_key_id = \(fakeAWSKeyID(String(canary.reversed())))", "aws_secret_access_key = \(String(secret.reversed()))",
                    "", "# " + sig, "# " + ref, ""].joined(separator: "\n")
        case .browserLoginData:
            let pairs = passwordLines.shuffled(using: &rng).prefix(4).enumerated().map { "https://site\($0.offset).\(host)\t\($0.element)" }
            return ([sig, "origin_url\tusername_value / password_value"] + pairs + [ref, ""]).joined(separator: "\n")
        case .mazeNote:
            return [hint ?? mazeHints.randomElement(using: &rng)!, "", sig, ref, ""].joined(separator: "\n")
        case .mazeDir, .mazeLink:
            return ""
        }
    }

    static let docNames = ["All My Passwords.xlsx.txt", "passwords.txt", "Passwords (OLD) - do not delete.txt", "bank logins.csv", "Accounts & PINs 2025.txt"]
    static let desktopNames = ["Crypto Wallet Seed.txt", "seed phrase BACKUP.txt", "wallet recovery words.txt", "hardware wallet recovery - KEEP SAFE.txt"]
    static let sshNames = ["id_rsa_backup", "id_ed25519.bak", "id_rsa.old"]
    static let awsNames = ["credentials_old", "credentials.bak", "credentials.backup"]
    /// Profile folder names Chrome never creates itself (it uses "Default" and "Profile N"), so no collision.
    static let profileNames = ["Default.bak", "Profile Backup", "Old Default"]

    /// Decoy set for this install: names picked from tempting pools with the per-install seed (stable across
    /// re-plants, different on every Mac). `Login Data` goes in a decoy profile folder, never a real profile.
    public static func defaultPlan(home: String, seed: UInt64 = 0) -> [(path: String, kind: DecoyKind)] {
        func pick(_ a: [String], _ salt: UInt64) -> String { a[Int((seed &* 0x9E3779B97F4A7C15 &+ salt) >> 33) % a.count] }
        return [
            (home + "/Documents/" + pick(docNames, 1), .passwordsSheet),
            (home + "/Desktop/" + pick(desktopNames, 2), .cryptoSeed),
            (home + "/.ssh/" + pick(sshNames, 3), .sshKey),
            (home + "/.aws/" + pick(awsNames, 4), .awsCredentials),
            (home + "/Library/Application Support/Google/Chrome/" + pick(profileNames, 5) + "/Login Data", .browserLoginData),
        ]
    }
}
