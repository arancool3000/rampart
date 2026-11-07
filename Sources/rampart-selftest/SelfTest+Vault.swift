import Foundation
import RampartShared
import RampartVault

// Vault suite. Obeys the ZERO POP-UPS RULE: no LocalAuthentication evaluatePolicy, no pasteboard,
// no reads of pre-existing login-keychain items. The only keychain item touched is one this run creates
// under `app.rampart.vault.selftest` and deletes again. The Secure Enclave round trip (access control
// without biometry flags, so it cannot prompt) runs only with RAMPART_VAULT_SE_TEST=1.
extension SelfTest {
    static func vault() {
        let env = ProcessInfo.processInfo.environment
        let base = URL(fileURLWithPath: env["RAMPART_VAULT_TEST_DIR"]
                       ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad/vault")
        let dir = base.appendingPathComponent("run-\(UUID().uuidString.prefix(8))")
        defer { try? FileManager.default.removeItem(at: dir) }

        vaultCrypto(dir)
        vaultGenerator()
        vaultStrength()
        vaultTOTP()
        vaultCSV(dir)
        vaultAudit()
        vaultBreachMonitor()
        vaultAuthenticator()
        vaultKeychain()
        vaultTouchID(env)
    }

    static func vaultCrypto(_ dir: URL) {
        let store = VaultStore(directory: dir.appendingPathComponent("v1"))
        let pw = "correct horse battery staple 42"
        check((try? store.create(masterPassword: pw, iterations: 10_000)) != nil, "vault: create")
        var item = VaultItem(kind: .login, title: "Example")
        item.username = "alice@example.com"; item.password = "s3cret-Original"; item.urls = ["https://login.example.com/"]
        try? item.addAttachment(name: "a.bin", data: Data(repeating: 7, count: 1000))
        check((try? item.addAttachment(name: "big", data: Data(count: Attachment.maxBytes + 1))) == nil, "vault: attachment > 1 MB rejected")
        check((try? store.upsert(item)) != nil, "vault: upsert")
        item.password = "s3cret-Changed"
        try? store.upsert(item)
        check(store.item(item.id)?.passwordHistory.first?.password == "s3cret-Original", "vault: password history")
        try? store.updateMeta { $0.folders.append(VaultFolder(name: "Work")) }

        // Plaintext never on disk.
        let raw = (try? Data(contentsOf: store.fileURL)) ?? Data()
        check(raw.prefix(8) == Data("RAMPVLT\0".utf8) && raw[8] == 0 && raw[9] == 1, "vault: magic + format version 1")
        check(raw.range(of: Data("s3cret".utf8)) == nil && raw.range(of: Data("alice".utf8)) == nil, "vault: no plaintext in file")

        store.lock()
        check(!store.isUnlocked && store.items.isEmpty, "vault: lock clears memory")
        check((try? store.unlock(masterPassword: "wrong password")) == nil, "vault: wrong password fails")
        do { try store.unlock(masterPassword: "nope") } catch { check(error as? VaultError == .wrongPassword, "vault: wrong password error") }
        check((try? store.unlock(masterPassword: pw)) != nil, "vault: unlock")
        let back = store.item(item.id)
        check(back?.password == "s3cret-Changed" && back?.attachments.first?.data.count == 1000 && store.meta.folders.first?.name == "Work",
              "vault: crypto round trip")
        check(store.kdfIterations == 10_000, "vault: kdf params stored")

        // Tamper: flip one byte in the body; and truncate.
        var tampered = raw
        tampered[tampered.count - 100] ^= 0x01
        let tdir = dir.appendingPathComponent("t")
        try? FileManager.default.createDirectory(at: tdir, withIntermediateDirectories: true)
        let tstore = VaultStore(directory: tdir)
        try? tampered.write(to: tstore.fileURL)
        do { try tstore.unlock(masterPassword: pw); check(false, "vault: tamper detected") }
        catch { check(error as? VaultError == .tampered, "vault: tamper detected") }
        try? raw.prefix(raw.count - 10).write(to: tstore.fileURL)
        check((try? tstore.unlock(masterPassword: pw)) == nil, "vault: truncation detected")
        // Future version refused.
        var future = raw; future[9] = 9
        try? future.write(to: tstore.fileURL)
        do { try tstore.unlock(masterPassword: pw) } catch { check(error as? VaultError == .unsupportedVersion(9), "vault: newer format refused") }
        // Header downgrade of iterations breaks unwrapping (AAD-bound).
        if let r = raw.range(of: Data("\"iterations\":10000".utf8)) {
            var d = raw; d.replaceSubrange(r, with: Data("\"iterations\":10001".utf8))
            try? d.write(to: tstore.fileURL)
            check((try? tstore.unlock(masterPassword: pw)) == nil, "vault: kdf header tamper detected")
        } else { check(false, "vault: header contains iterations") }

        // Change master password; old one stops working.
        check((try? store.changeMasterPassword(current: pw, new: "another long passphrase 99", iterations: 10_000)) != nil, "vault: change master")
        store.lock()
        check((try? store.unlock(masterPassword: pw)) == nil && (try? store.unlock(masterPassword: "another long passphrase 99")) != nil, "vault: new master works")
        check(!store.backups().isEmpty && store.backups().count <= VaultStore.maxBackups, "vault: encrypted backups kept")
        check(((try? FileManager.default.attributesOfItem(atPath: store.fileURL.path))?[.posixPermissions] as? Int) == 0o600, "vault: file mode 0600")

        // Encrypted export.
        if let exp = try? EncryptedExport.export(items: store.items, folders: store.meta.folders, password: "export pw", iterations: 10_000) {
            check(exp.range(of: Data("s3cret".utf8)) == nil, "vault: export encrypted")
            check((try? EncryptedExport.import(exp, password: "export pw"))?.items.count == 1, "vault: export round trip")
            check((try? EncryptedExport.import(exp, password: "bad")) == nil, "vault: export wrong password")
        } else { check(false, "vault: export") }

        let iters = VaultCrypto.calibrateIterations()
        check(iters >= VaultCrypto.minimumIterations, "vault: PBKDF2 calibration >= 600k (got \(iters))")
        print("   PBKDF2 calibrated iterations for ~300 ms: \(iters)")
        check(!VaultStore.isAcceptableMaster("password1") && VaultStore.isAcceptableMaster("Velvet-Harbor-Pancake-91"), "vault: master password policy")
    }

    static func vaultGenerator() {
        // Rejection limit is the largest multiple of n below 2^32.
        for n: UInt32 in [3, 10, 62, 94, 4338] {
            let l = SecureRandom.rejectionLimit(n)
            check(l % UInt64(n) == 0 && l <= (1 << 32) && (1 << 32) - l < UInt64(n), "gen: rejection limit n=\(n)")
        }
        // Chi-square over a non-power-of-two alphabet.
        let n = 62, samples = 310_000
        var counts = [Int](repeating: 0, count: n)
        for _ in 0..<samples { counts[SecureRandom.uniform(n)] += 1 }
        let e = Double(samples) / Double(n)
        let chi = counts.reduce(0.0) { $0 + pow(Double($1) - e, 2) / e }
        check(chi < 120, "gen: uniform chi-square df=61 (\(Int(chi)))")
        // n=3 with 1-byte modulo would give 86/85/85; check the first bucket isn't favoured.
        var c3 = [0, 0, 0]
        for _ in 0..<300_000 { c3[SecureRandom.uniform(3)] += 1 }
        check(c3.allSatisfy { abs($0 - 100_000) < 1500 }, "gen: n=3 unbiased \(c3)")

        var o = PasswordGenerator.Options(); o.length = 24; o.excludeAmbiguous = true
        let r = PasswordGenerator.random(o)
        check(r.password.count == 24 && !r.password.contains(where: PasswordGenerator.ambiguous.contains), "gen: length + no ambiguous")
        check(r.password.contains(where: \.isLowercase) && r.password.contains(where: \.isUppercase) && r.password.contains(where: \.isNumber), "gen: each set present")
        check(r.entropyBits > 140 && r.entropyBits < 24 * log2(94), "gen: entropy (\(Int(r.entropyBits)))")
        let p = PasswordGenerator.passphrase()
        check(p.password.split(separator: "-").count == 5 && p.entropyBits > 60, "gen: passphrase")
        let pin = PasswordGenerator.pin(length: 6)
        check(pin.password.count == 6 && pin.password.allSatisfy(\.isNumber), "gen: pin")
        let words = PasswordGenerator.wordlistCount
        check(words >= 4000, "gen: wordlist >= 4000 (\(words))")
        var seen = Set<String>()
        for _ in 0..<2000 { seen.insert(PasswordGenerator.random().password) }
        check(seen.count == 2000, "gen: no repeats")
    }

    static func vaultStrength() {
        let weak = PasswordStrength.evaluate("password1")
        check(weak.level == .veryWeak && weak.warning != nil, "strength: common password")
        check(PasswordStrength.evaluate("qwerty12345").level <= .weak, "strength: keyboard + sequence")
        check(PasswordStrength.evaluate("P@ssw0rd2024").level <= .weak, "strength: leet word + year")
        check(PasswordStrength.evaluate("aaaaaaaaaaaa").level == .veryWeak, "strength: repeat")
        let strong = PasswordStrength.evaluate("vT9#qLm2!xR7&kWp")
        check(strong.level >= .strong && strong.offlineFastSeconds > 3e7, "strength: random 16 strong")
        check(PasswordStrength.describe(seconds: 0.2) == "instantly" && PasswordStrength.describe(seconds: 7200) == "2 hours", "strength: time text")
    }

    static func vaultTOTP() {
        // RFC 6238 Appendix B.
        let s1 = Data("12345678901234567890".utf8)
        let s256 = Data("12345678901234567890123456789012".utf8)
        let s512 = Data("1234567890123456789012345678901234567890123456789012345678901234".utf8)
        let vectors: [(Double, String, String, String)] = [
            (59, "94287082", "46119246", "90693936"), (1111111109, "07081804", "68084774", "25091201"),
            (1111111111, "14050471", "67062674", "99943326"), (1234567890, "89005924", "91819424", "93441116"),
            (2000000000, "69279037", "90698825", "38618901"), (20000000000, "65353130", "77737706", "47863826")]
        for (t, a, b, c) in vectors {
            let d = Date(timeIntervalSince1970: t)
            check(TOTP(secret: s1, digits: 8, algorithm: .sha1).code(at: d) == a, "totp sha1 \(Int(t))")
            check(TOTP(secret: s256, digits: 8, algorithm: .sha256).code(at: d) == b, "totp sha256 \(Int(t))")
            check(TOTP(secret: s512, digits: 8, algorithm: .sha512).code(at: d) == c, "totp sha512 \(Int(t))")
        }
        check(Base32.decode(Base32.encode(s1)) == s1, "totp: base32 round trip")
        let uri = "otpauth://totp/Example:alice@example.com?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=Example&digits=8"
        let t = TOTP(string: uri)
        check(t?.secret == s1 && t?.digits == 8 && t?.issuer == "Example" && t?.account == "alice@example.com", "totp: otpauth uri")
    }

    static func vaultCSV(_ dir: URL) {
        let chrome = "name,url,username,password,note\r\nGitHub,https://github.com/login,octo,\"pa,ss\"\"word\",\"multi\nline\"\r\n,,,,\r\n"
        let r = CSVImporter.parse(chrome)
        check(r.source == .chrome && r.items.count == 1 && r.skipped == 1, "csv: chrome")
        check(r.items.first?.password == "pa,ss\"word" && r.items.first?.notes == "multi\nline", "csv: quoting")
        let ff = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\",\"timeLastUsed\",\"timePasswordChanged\"\n\"https://www.mozilla.org\",\"fox\",\"pw1\",,\"https://www.mozilla.org\",\"{x}\",\"1600000000000\",\"1600000000000\",\"1600000000000\"\n"
        let f = CSVImporter.parse(ff)
        check(f.source == .firefox && f.items.first?.title == "mozilla.org" && f.items.first?.passwordModified == Date(timeIntervalSince1970: 1_600_000_000), "csv: firefox")
        let bw = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\nWork,1,login,Mail,,,0,https://mail.example.com,bob,pw2,JBSWY3DPEHPK3PXP\n,,note,Secret note,hello,,,,,,\n"
        let b = CSVImporter.parse(bw)
        check(b.source == .bitwarden && b.items.count == 2 && b.items[0].favourite && b.items[0].totp != nil && b.items[1].kind == .secureNote && b.folders == ["Work"], "csv: bitwarden")
        var meta = VaultMeta()
        let applied = CSVImporter.applyFolders(b, into: &meta)
        check(meta.folders.first?.name == "Work" && applied[0].folderID == meta.folders.first?.id && applied[0].tags.isEmpty, "csv: folders applied")
        let op = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\nBank,https://bank.example,carol,pw3,,true,false,finance;money,n\n"
        let o = CSVImporter.parse(op)
        check(o.source == .onePassword && o.items.first?.tags == ["finance", "money"] && o.items.first?.favourite == true, "csv: 1password")
    }

    static func vaultAudit() {
        var a = VaultItem(kind: .login, title: "GitHub"); a.urls = ["https://github.com"]; a.password = "password1"
        var b = VaultItem(kind: .login, title: "Other"); b.urls = ["https://other.example"]; b.password = "password1"
        var c = VaultItem(kind: .login, title: "Good"); c.urls = ["https://good.example"]; c.password = "Kq8#vW2m!zR4pL9x"
        c.passwordModified = Date(timeIntervalSinceNow: -400 * 86400)
        let audit = VaultAudit.run(items: [a, b, c], breachCounts: [a.id: 5])
        check(Set(audit.items(.weak)) == [a.id, b.id], "audit: weak")
        check(Set(audit.items(.reused)) == [a.id, b.id], "audit: reused")
        check(audit.items(.old) == [c.id], "audit: old")
        check(audit.items(.no2FA) == [a.id], "audit: no 2FA")
        check(audit.items(.breached) == [a.id], "audit: breached")
        check(audit.score < 60, "audit: score drops (\(audit.score))")
        check(VaultAudit.run(items: [c].map { var x = $0; x.passwordModified = Date(); return x }).score == 100, "audit: clean = 100")
        check(BreachChecker.sha1Hex("password") == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", "breach: sha1")
        check(BreachChecker.count(in: "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n0000000000000000000000000000000000A:0", suffix: "1e4c9b93f3f0682250b6cf8331b7ee68fd8") == 3861493, "breach: range parse")
    }

    /// Automatic breach monitoring with a fake range fetcher (no network).
    static func vaultBreachMonitor() {
        final class Log: @unchecked Sendable { let lock = NSLock(); var prefixes: [String] = [] }
        let log = Log()
        let pwnedHash = BreachChecker.sha1Hex("password")      // 5BAA6…
        let checker = BreachChecker(fetcher: { prefix in
            log.lock.withLock { log.prefixes.append(prefix) }
            var lines = ["0000000000000000000000000000000000A:0"]
            if prefix == String(pwnedHash.prefix(5)) { lines.append(String(pwnedHash.dropFirst(5)) + ":3861493") }
            return lines.joined(separator: "\r\n")
        })
        let strong = "Kq8#vW2m!zR4pL9x-unique"
        var cache = BreachCache()
        let now = Date()
        let r = waitTask(Task { await BreachMonitor.sweep(["password", strong, "password"], cache: cache, checker: checker, now: now) })
        check(r?.checked == 2 && r?.found == 1 && r?.failure == nil, "breach: sweep checks distinct passwords once")
        let sent = log.lock.withLock { log.prefixes }
        check(sent.count == 2 && sent.allSatisfy { $0.count == 5 && $0.allSatisfy(\.isHexDigit) }, "breach: only 5 hex chars leave the Mac")
        for (k, v) in r?.updates ?? [:] { cache.entries[k] = v }
        check(cache.result(for: "password")?.count == 3861493 && cache.result(for: strong)?.count == 0, "breach: cached results")
        check(BreachMonitor.describe(count: 3861493).hasPrefix("Found in known breaches") && BreachMonitor.describe(count: 0) == "Not found in known breaches", "breach: wording")
        // Cache keys are salted HMACs, not the password or its SHA-1.
        let key = cache.key("password")
        check(key.count == 64 && !key.uppercased().contains(pwnedHash.prefix(10)) && !key.contains("password"), "breach: cache key is salted hash")
        check(BreachCache(salt: Data(repeating: 1, count: 32)).key("x") != BreachCache(salt: Data(repeating: 2, count: 32)).key("x"), "breach: per-vault salt")
        // Throttle: nothing due within a day; due again after 25 h.
        check(BreachMonitor.due(["password", strong], cache: cache, now: now.addingTimeInterval(3600)).isEmpty, "breach: throttled within a day")
        check(BreachMonitor.due(["password", strong], cache: cache, now: now.addingTimeInterval(25 * 3600)).count == 2, "breach: due after a day")
        check(BreachMonitor.due(["new one"], cache: cache, now: now) == ["new one"], "breach: new password is due")
        // Second sweep in the same day fetches nothing.
        checker.clearCache()
        _ = waitTask(Task { await BreachMonitor.sweep(["password", strong], cache: cache, checker: checker, now: now.addingTimeInterval(60)) })
        check(log.lock.withLock { log.prefixes.count } == 2, "breach: no refetch while fresh")
        // Item counts feed the dashboard.
        var a = VaultItem(kind: .login, title: "A"); a.password = "password"
        var b = VaultItem(kind: .login, title: "B"); b.password = strong
        let counts = BreachMonitor.counts(items: [a, b], cache: cache)
        check(counts[a.id] == 3861493 && counts[b.id] == 0, "breach: counts per item")
        check(VaultAudit.run(items: [a, b], breachCounts: counts).items(.breached) == [a.id], "breach: watchtower breached list")
        cache.prune(keeping: [strong])
        check(cache.result(for: "password") == nil && cache.result(for: strong) != nil, "breach: prune removed passwords")
        // Failures stop the sweep and are reported.
        let failing = BreachChecker(fetcher: { _ in throw VaultError.io("offline") })
        let f = waitTask(Task { await BreachMonitor.sweep(["x1", "x2"], cache: BreachCache(), checker: failing) })
        check(f?.failure != nil && f?.checked == 0, "breach: failure reported")
        // HTML filter page rejected.
        let html = BreachChecker(fetcher: { _ in "<html>blocked</html>" })
        let h = waitTask(Task { await BreachMonitor.sweep(["x1"], cache: BreachCache(), checker: html) })
        check(h?.failure != nil, "breach: web filter page rejected")
        // Older vault settings (opt-in era, no new keys) migrate to automatic monitoring; an explicit opt-out sticks.
        let old = #"{"autoLockMinutes":15,"lockOnSleep":true,"lockOnScreenLock":true,"clipboardClearSeconds":30,"breachCheckEnabled":false,"generator":{"length":20,"lowercase":true,"uppercase":true,"digits":true,"symbols":true,"excludeAmbiguous":false,"requireEachSet":true},"passphrase":{"words":5,"separator":"-","capitalize":true,"includeDigit":true}}"#
        let migrated = try? JSONDecoder().decode(VaultSettings.self, from: Data(old.utf8))
        check(migrated?.breachCheckEnabled == true && migrated?.autoLockMinutes == 15, "breach: old settings migrate to on")
        var off = VaultSettings(); off.breachCheckEnabled = false
        let rt = (try? JSONEncoder().encode(off)).flatMap { try? JSONDecoder().decode(VaultSettings.self, from: $0) }
        check(rt?.breachCheckEnabled == false, "breach: opt-out persists")
        let oldMeta = #"{"folders":[],"settings":\#(old),"created":0}"#
        check((try? JSONDecoder().decode(VaultMeta.self, from: Data(oldMeta.utf8))) != nil, "breach: old meta without cache decodes")
        // Strength explanation.
        check(PasswordStrength.known(entropyBits: 10).crackTimeSentence.contains("instantly"), "strength: weak cracks instantly")
        check(PasswordStrength.known(entropyBits: 80).crackTimeSentence.contains("million years"), "strength: 80 bits ~ millions of years (\(PasswordStrength.known(entropyBits: 80).crackTimeSentence))")
        check(PasswordStrength.describeLong(seconds: 1e40).contains("age of the universe"), "strength: astronomically long")
        // Generator history: memory only, last 10, newest first, no duplicates.
        var hist = GeneratorHistory()
        for i in 0..<12 { hist.add("pw\(i)") }
        hist.add("pw11")
        check(hist.entries.count == 10 && hist.entries.first?.password == "pw11" && !hist.entries.contains { $0.password == "pw0" }, "generator: history keeps last 10")
        hist.clear(); check(hist.entries.isEmpty, "generator: history clears")
        // Pronounceable, presets, site rules.
        let pr = PasswordGenerator.pronounceable()
        let letters = Array(pr.password.prefix(14).lowercased())
        check(pr.password.count == 16 && letters.enumerated().allSatisfy { i, c in (i % 2 == 0 ? PasswordGenerator.syllableConsonants : PasswordGenerator.syllableVowels).contains(c) }
              && pr.password.suffix(2).allSatisfy(\.isNumber) && pr.entropyBits > 40, "generator: pronounceable (\(Int(pr.entropyBits)) bits)")
        check(PasswordGenerator.passphrasePresets.count >= 3 && PasswordGenerator.passphrase(PasswordGenerator.passphrasePresets[0].options).password.split(separator: " ").count == 5, "generator: passphrase presets")
        var go = PasswordGenerator.Options(); go.length = 30
        let r16 = PasswordGenerator.random(go, rule: PasswordGenerator.siteRules[1])
        check(r16.password.count == 16, "generator: max-length rule")
        let noSym = PasswordGenerator.random(go, rule: PasswordGenerator.siteRules[3])
        check(noSym.password.allSatisfy { $0.isLetter || $0.isNumber }, "generator: no-symbols rule")
        let lim = PasswordGenerator.random(go, rule: PasswordGenerator.siteRules[4])
        check(lim.password.allSatisfy { $0.isLetter || $0.isNumber || "!@#$%&*".contains($0) } && lim.password.contains { "!@#$%&*".contains($0) }, "generator: limited-symbols rule")
        // Passkey suggestions do not count as problems.
        var g = VaultItem(kind: .login, title: "GitHub"); g.urls = ["https://github.com"]; g.password = strong; g.totpSecret = "JBSWY3DPEHPK3PXP"
        let pa = VaultAudit.run(items: [g])
        check(pa.items(.passkey) == [g.id] && pa.problemItemCount == 0 && pa.score == 100, "audit: passkey is an opportunity, not a problem")
    }

    /// Authenticator: otpauth parsing, Keyring paste, Google migration protobuf, HOTP vectors, dedupe.
    static func vaultAuthenticator() {
        let s1 = Data("12345678901234567890".utf8), b32 = Base32.encode(s1)
        // RFC 4226 Appendix D HOTP vectors.
        let hotp = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
        for (c, want) in hotp.enumerated() {
            check(TOTP.hotp(secret: s1, counter: UInt64(c), digits: 6, algorithm: .sha1) == want, "hotp vector \(c)")
        }
        let h = TOTP(string: "otpauth://hotp/Corp:bob?secret=\(b32)&counter=7")
        check(h?.kind == .hotp && h?.counter == 7 && h?.code() == "162583", "authenticator: hotp uri + counter")
        check(h.flatMap { TOTP(string: $0.uri) } == h, "authenticator: hotp uri round trip")
        // Labels, URL-encoding, issuer param precedence, params.
        let enc = TOTP(string: "otpauth://totp/ACME%20Co:jane%40example.com?secret=\(b32.lowercased())&algorithm=sha256&digits=8&period=60")
        check(enc?.issuer == "ACME Co" && enc?.account == "jane@example.com" && enc?.algorithm == .sha256 && enc?.digits == 8 && enc?.period == 60, "authenticator: encoded label + params")
        let pref = TOTP(string: "otpauth://totp/Old:alice?secret=\(b32)&issuer=New%20Name")
        check(pref?.issuer == "New Name" && pref?.account == "alice", "authenticator: issuer param wins")
        check(TOTP(string: "otpauth://totp/alice?secret=\(b32)")?.issuer == nil, "authenticator: account-only label")
        check(TOTP(string: "otpauth://totp/x?secret=NOT*BASE32") == nil, "authenticator: bad base32 rejected")
        check(TOTP(string: "otpauth://totp/x?secret=\(b32)&algorithm=MD5") == nil, "authenticator: unknown algorithm rejected")
        check(TOTP(string: "otpauth://totp/x?secret=\(b32)&digits=4") == nil, "authenticator: 4 digits rejected")
        check(TOTP(string: "otpauth://steam/x?secret=\(b32)") == nil, "authenticator: unknown type rejected")
        let plus = TOTP(secret: s1, issuer: "A+B", account: "me")
        check(TOTP(string: plus.uri)?.issuer == "A+B", "authenticator: '+' survives round trip")
        // Keyring-style "Copy all": one link per line, blank lines and junk reported.
        let paste = """
        otpauth://totp/GitHub:octo?secret=\(b32)&issuer=GitHub

        otpauth://totp/Google:me%40gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google&period=30&digits=6&algorithm=SHA1
          otpauth://totp/Discord:me?secret=GEZDGNBVGY3TQOJQ
        hello
        """
        let pr = Authenticator.parse(paste)
        check(pr.accounts.map { $0.issuer ?? "" } == ["GitHub", "Google", "Discord"] && pr.errors.count == 1, "authenticator: keyring multi-line paste")
        // Dedupe by issuer + account + secret (case-insensitive names).
        var dupe = pr.accounts[0]; dupe.issuer = "github"; dupe.account = "OCTO"
        let d = Authenticator.dedupe([dupe, pr.accounts[1], pr.accounts[1]], against: [pr.accounts[0]])
        check(d.kept.count == 1 && d.duplicates == 2, "authenticator: dedupe")
        var other = pr.accounts[0]; other.secret = Data(repeating: 9, count: 20)
        check(Authenticator.dedupe([other], against: [pr.accounts[0]]).kept.count == 1, "authenticator: same name, different secret kept")
        check(!Authenticator.warnings(TOTP(secret: Data(count: 5))).isEmpty && Authenticator.warnings(TOTP(secret: s1)).isEmpty, "authenticator: weak params warned")
        // Google Authenticator migration fixture built by hand (protobuf).
        func varint(_ v: UInt64) -> [UInt8] { var v = v, o: [UInt8] = []; repeat { var b = UInt8(v & 0x7f); v >>= 7; if v > 0 { b |= 0x80 }; o.append(b) } while v > 0; return o }
        func field(_ n: Int, _ bytes: [UInt8]) -> [UInt8] { varint(UInt64(n << 3 | 2)) + varint(UInt64(bytes.count)) + bytes }
        func vfield(_ n: Int, _ v: UInt64) -> [UInt8] { varint(UInt64(n << 3)) + varint(v) }
        let otp1 = field(1, Array(s1)) + field(2, Array("Example:alice@example.com".utf8)) + field(3, Array("Example".utf8)) + vfield(4, 1) + vfield(5, 1) + vfield(6, 2)
        let otp2 = field(1, Array(s1)) + field(2, Array("bob".utf8)) + vfield(4, 2) + vfield(5, 2) + vfield(6, 1) + vfield(7, 3)
        let payload = field(1, otp1) + field(1, otp2) + vfield(2, 1) + vfield(3, 1) + vfield(4, 0) + vfield(5, 12345)
        let b64 = Data(payload).base64EncodedString().addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? ""
        let mig = Authenticator.parse("otpauth-migration://offline?data=\(b64)").accounts
        check(mig.count == 2 && mig[0].issuer == "Example" && mig[0].account == "alice@example.com" && mig[0].secret == s1 && mig[0].kind == .totp && mig[0].digits == 6,
              "authenticator: google migration totp")
        check(mig.count == 2 && mig[1].kind == .hotp && mig[1].counter == 3 && mig[1].algorithm == .sha256 && mig[1].digits == 8 && mig[1].account == "bob",
              "authenticator: google migration hotp")
        check(GoogleMigration.decodePayload(Data([0x0a, 0xff])) == nil, "authenticator: truncated protobuf rejected")
        // JSON exports.
        let aegis = #"{"version":1,"db":{"version":2,"entries":[{"type":"totp","name":"me","issuer":"Aegis Site","info":{"secret":"\#(b32)","algo":"SHA1","digits":6,"period":30}}]}}"#
        check(Authenticator.parse(aegis).accounts.first?.issuer == "Aegis Site", "authenticator: aegis json")
        let twofas = #"{"services":[{"name":"2FAS Site","secret":"\#(b32)","otp":{"account":"me","digits":6,"period":30,"algorithm":"SHA1","tokenType":"TOTP"}}]}"#
        check(Authenticator.parse(twofas).accounts.first?.account == "me", "authenticator: 2fas json")
        let bw = #"{"items":[{"name":"BW","login":{"username":"u","totp":"\#(b32)"}}]}"#
        check(Authenticator.parse(bw).accounts.first?.issuer == "BW", "authenticator: bitwarden json")
        // Stored as an encrypted vault item.
        let item = Authenticator.makeItem(pr.accounts[0])
        check(item.kind == .totp && item.totp?.secret == s1 && item.title == "GitHub", "authenticator: vault item")
        // Per-item lock: secure notes always, others when marked.
        var lm = VaultMeta(); let note = VaultItem(kind: .secureNote, title: "n"); let login = VaultItem(kind: .login, title: "l")
        check(lm.requiresItemUnlock(note) && !lm.requiresItemUnlock(login), "item lock: notes locked by default")
        lm.lockedItems = [login.id]
        let lmRT = (try? JSONEncoder().encode(lm)).flatMap { try? JSONDecoder().decode(VaultMeta.self, from: $0) }
        check(lmRT?.requiresItemUnlock(login) == true, "item lock: marked item persists")
    }

    static func vaultKeychain() {
        // Only an item this run creates and deletes. Never reads anything else.
        let service = "app.rampart.vault.selftest", account = "selftest-\(UUID().uuidString)"
        defer { Keychain.deleteGeneric(service: service, account: account) }
        let secret = Data(SecureRandom.bytes(32))
        check((try? Keychain.setGeneric(service: service, account: account, data: secret)) != nil, "keychain: add test item")
        check((try? Keychain.readGeneric(service: service, account: account)) == secret, "keychain: read back")
        let secret2 = Data(SecureRandom.bytes(32))
        check((try? Keychain.setGeneric(service: service, account: account, data: secret2)) != nil
              && (try? Keychain.readGeneric(service: service, account: account)) == secret2, "keychain: update")
        check(Keychain.deleteGeneric(service: service, account: account) && (try? Keychain.readGeneric(service: service, account: account)) == .some(nil), "keychain: delete")
        // The data-protection keychain needs an entitlement we don't have: expect -34018 (no dialog).
        let missing = Keychain.dataProtectionKeychainMissingEntitlement(probeService: service)
        print("   data-protection keychain missing entitlement: \(missing)")
        check(true, "keychain: data-protection probe ran")
    }

    static func vaultTouchID(_ env: [String: String]) {
        // canEvaluatePolicy only; never evaluatePolicy.
        let a = TouchIDUnlock.availability()
        print("   biometry available: \(a.biometryAvailable) (\(a.biometryName)), Secure Enclave: \(a.secureEnclave), preferred mode: \(a.preferredMode?.rawValue ?? "none")")
        check(a.biometryAvailable || a.reason != nil, "touchid: availability explained")
        if env["RAMPART_VAULT_SE_TEST"] == "1" {
            let err = TouchIDUnlock.secureEnclaveRoundTripWithoutBiometry()
            check(err == nil, "touchid: SE wrap/unwrap round trip \(err ?? "")")
        }
    }
}
