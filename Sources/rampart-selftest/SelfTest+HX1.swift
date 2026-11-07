import Foundation
import RampartShared
import RampartVault

// HX1 hardening regression checks for the vault, authenticator and password checker.
// ZERO POP-UPS: no LocalAuthentication, no pasteboard, no keychain, no network (mock fetcher only).
// Everything runs on throwaway vaults in the scratchpad (or RAMPART_VAULT_TEST_DIR).
extension SelfTest {
    static func hx1Checks() {
        let env = ProcessInfo.processInfo.environment
        let base = URL(fileURLWithPath: env["RAMPART_VAULT_TEST_DIR"]
                       ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad/vault")
        let dir = base.appendingPathComponent("hx1-\(UUID().uuidString.prefix(8))")
        defer { try? FileManager.default.removeItem(at: dir) }
        hx1KDFBounds(dir)
        hx1Throttle(dir)
        hx1Rollback(dir)
        hx1ImportSafety(dir)
        hx1TOTPFuzz()
        hx1ParserFuzz()
        hx1Settings()
        hx1Breach()
    }

    /// Splits a vault file into (header JSON, rest-after-header) and rebuilds it with a new header.
    private static func hx1ReplaceHeader(_ raw: Data, _ edit: (inout [String: Any]) -> Void) -> Data? {
        let d = Data(raw)
        guard d.count > 14 else { return nil }
        let n = Int(d[10]) << 24 | Int(d[11]) << 16 | Int(d[12]) << 8 | Int(d[13])
        guard 14 + n <= d.count, var h = try? JSONSerialization.jsonObject(with: d.subdata(in: 14..<(14 + n))) as? [String: Any] else { return nil }
        edit(&h)
        guard let nh = try? JSONSerialization.data(withJSONObject: h) else { return nil }
        var out = d.prefix(10)
        let c = UInt32(nh.count)
        out.append(contentsOf: [UInt8(c >> 24), UInt8((c >> 16) & 0xff), UInt8((c >> 8) & 0xff), UInt8(c & 0xff)])
        out.append(nh); out.append(d.suffix(from: 14 + n))
        return out
    }

    static func hx1KDFBounds(_ dir: URL) {
        let pw = "hx1 correct horse battery 7"
        let src = VaultStore(directory: dir.appendingPathComponent("kdf-src"))
        guard (try? src.create(masterPassword: pw, iterations: 10_000)) != nil, let raw = try? Data(contentsOf: src.fileURL) else {
            check(false, "hx1: kdf fixture"); return
        }
        let t = VaultStore(directory: dir.appendingPathComponent("kdf-t"))
        try? FileManager.default.createDirectory(at: t.directory, withIntermediateDirectories: true)
        let cases: [(String, (inout [String: Any]) -> Void)] = [
            ("huge iterations", { h in var k = h["kdf"] as! [String: Any]; k["iterations"] = 99_999_999_999; h["kdf"] = k }),
            ("UInt32 overflow iterations", { h in var k = h["kdf"] as! [String: Any]; k["iterations"] = 5_000_000_000; h["kdf"] = k }),
            ("zero iterations", { h in var k = h["kdf"] as! [String: Any]; k["iterations"] = 0; h["kdf"] = k }),
            ("negative iterations", { h in var k = h["kdf"] as! [String: Any]; k["iterations"] = -1; h["kdf"] = k }),
            ("empty salt", { h in var k = h["kdf"] as! [String: Any]; k["salt"] = ""; h["kdf"] = k }),
            ("other KDF", { h in var k = h["kdf"] as! [String: Any]; k["algorithm"] = "none"; h["kdf"] = k }),
        ]
        for (name, edit) in cases {
            guard let d = hx1ReplaceHeader(raw, edit) else { check(false, "hx1: rebuild \(name)"); continue }
            try? d.write(to: t.fileURL)
            let t0 = Date()
            var err: Error?
            do { try t.unlock(masterPassword: pw) } catch { err = error }
            let fast = Date().timeIntervalSince(t0) < 2
            if case VaultError.badFormat? = err as? VaultError { check(fast, "hx1: \(name) refused quickly") }
            else { check(false, "hx1: \(name) refused (got \(String(describing: err)))") }
            check(!t.verifyMasterPassword(pw), "hx1: \(name) verify refused")
        }
        // Format downgrade: version 0 and a forged older version are refused.
        var v0 = raw; v0[9] = 0
        try? v0.write(to: t.fileURL)
        check((try? t.unlock(masterPassword: pw)) == nil, "hx1: format version 0 refused")
        // Oversized file refused before reading.
        try? FileManager.default.removeItem(at: t.fileURL)
        FileManager.default.createFile(atPath: t.fileURL.path, contents: Data(raw.prefix(64)))
        if let h = FileHandle(forWritingAtPath: t.fileURL.path) {
            try? h.truncate(atOffset: 600 * 1_048_576); try? h.close()
            do { try t.unlock(masterPassword: pw); check(false, "hx1: oversized vault refused") }
            catch { check(error as? VaultError == .badFormat("file too large"), "hx1: oversized vault refused (\(error))") }
            try? FileManager.default.removeItem(at: t.fileURL)
        }
        // Symlinked vault file refused.
        try? FileManager.default.createSymbolicLink(at: t.fileURL, withDestinationURL: src.fileURL)
        check((try? t.unlock(masterPassword: pw)) == nil, "hx1: symlinked vault file refused")
        try? FileManager.default.removeItem(at: t.fileURL)
        // Hostile export header with ~4 billion iterations is refused instantly.
        if var exp = try? EncryptedExport.export(items: [], folders: [], password: "export password 1", iterations: 10_000) {
            exp[10] = 0xff; exp[11] = 0xff; exp[12] = 0xff; exp[13] = 0xff
            let t0 = Date()
            check((try? EncryptedExport.import(exp, password: "export password 1")) == nil && Date().timeIntervalSince(t0) < 2, "hx1: export huge iterations refused quickly")
        } else { check(false, "hx1: export fixture") }
    }

    static func hx1Throttle(_ dir: URL) {
        var clock = Date(timeIntervalSince1970: 1_800_000_000)
        let url = dir.appendingPathComponent("thr/unlock-throttle.json")
        let th = UnlockThrottle(url: url, now: { clock })
        check(UnlockThrottle.delay(failures: 4) == 0 && UnlockThrottle.delay(failures: 5) == 5 && UnlockThrottle.delay(failures: 6) == 10
              && UnlockThrottle.delay(failures: 100) == UnlockThrottle.maxDelay, "hx1: backoff schedule")
        for _ in 0..<5 { th.recordFailure() }
        var throttled = false
        do { try th.check() } catch VaultError.throttled(let s) { throttled = s == 5 } catch {}
        check(throttled, "hx1: throttled after 5 failures")
        // Deleting the file doesn't reset the running app's counter.
        try? FileManager.default.removeItem(at: url)
        check((try? th.check()) == nil, "hx1: deleting throttle file doesn't reset it")
        clock += 6
        check((try? th.check()) != nil, "hx1: wait expires")
        // A forged future timestamp counts as now, not as forever.
        try? Data(#"{"failures":6,"last":1e12}"#.utf8).write(to: url)
        let th2 = UnlockThrottle(url: url, now: { clock })
        do { try th2.check(); check(false, "hx1: future timestamp still throttles") }
        catch VaultError.throttled(let s) { check(s <= 10, "hx1: future timestamp bounded (\(s) s)") } catch { check(false, "hx1: throttle error type") }
        th2.recordSuccess()
        check((try? th2.check()) != nil && th2.failures == 0, "hx1: success resets")

        // Store level: wrong passwords and verifyMasterPassword share the backoff.
        let pw = "hx1 throttle master pass 3"
        let store = VaultStore(directory: dir.appendingPathComponent("thr-store"))
        guard (try? store.create(masterPassword: pw, iterations: 10_000)) != nil else { check(false, "hx1: throttle store"); return }
        store.lock()
        for _ in 0..<3 { _ = try? store.unlock(masterPassword: "wrong one") }
        for _ in 0..<2 { _ = store.verifyMasterPassword("wrong two") }
        var gotThrottle = false
        do { try store.unlock(masterPassword: pw) } catch VaultError.throttled { gotThrottle = true } catch {}
        check(gotThrottle && !store.isUnlocked, "hx1: correct password refused while throttled (no oracle)")
        check(!store.verifyMasterPassword(pw), "hx1: verifyMasterPassword throttled too")
        store.throttle.recordSuccess()
        check((try? store.unlock(masterPassword: pw)) != nil && store.throttle.failures == 0, "hx1: unlock after wait resets counter")
        let perms = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.posixPermissions] as? Int
        check(perms == nil || perms == 0o600, "hx1: throttle file 0600")
    }

    static func hx1Rollback(_ dir: URL) {
        let pw = "hx1 rollback master pass 5"
        let store = VaultStore(directory: dir.appendingPathComponent("rb"))
        guard (try? store.create(masterPassword: pw, iterations: 10_000)) != nil else { check(false, "hx1: rollback store"); return }
        var a = VaultItem(kind: .login, title: "A"); a.password = "old-password-1"
        try? store.upsert(a)
        let old = (try? Data(contentsOf: store.fileURL)) ?? Data()
        a.password = "new-password-2"
        try? store.upsert(a)
        store.lock()
        try? old.write(to: store.fileURL)
        var rolled = false
        do { try store.unlock(masterPassword: pw) } catch VaultError.rolledBack(let f, let e) { rolled = f < e } catch {}
        check(rolled && !store.isUnlocked, "hx1: older genuine copy detected as rollback")
        check((try? store.unlock(masterPassword: pw, acceptRollback: true)) != nil && store.item(a.id)?.password == "old-password-1", "hx1: explicit Open Anyway works")
        store.lock()
        check((try? store.unlock(masterPassword: pw)) != nil, "hx1: accepted rollback lowers the mark")
        // Restoring a backup through RamPart is allowed.
        try? store.upsert(a)
        if let b = store.backups().last {
            check((try? store.restore(backup: b)) != nil && (try? store.unlock(masterPassword: pw)) != nil, "hx1: restore backup then unlock")
        } else { check(false, "hx1: backup exists") }
        // A backup from a different vault is refused.
        let other = VaultStore(directory: dir.appendingPathComponent("rb-other"))
        try? other.create(masterPassword: pw, iterations: 10_000)
        check((try? store.restore(backup: other.fileURL)) == nil, "hx1: foreign vault backup refused")
        // Symlinks in the backup folder are ignored.
        let link = store.backupDirectory.appendingPathComponent("vault-99999999-999999-999.rpvault")
        try? FileManager.default.createSymbolicLink(at: link, withDestinationURL: other.fileURL)
        check(!store.backups().contains(where: { $0.lastPathComponent == link.lastPathComponent }), "hx1: symlinked backup ignored")
    }

    static func hx1ImportSafety(_ dir: URL) {
        let store = VaultStore(directory: dir.appendingPathComponent("imp"))
        guard (try? store.create(masterPassword: "hx1 import master pass 1", iterations: 10_000)) != nil else { check(false, "hx1: import store"); return }
        var mine = VaultItem(kind: .login, title: "Bank"); mine.password = "keep-me"
        try? store.upsert(mine)
        var evil = VaultItem(kind: .login, title: "Bank"); evil.id = mine.id; evil.password = "attacker"
        try? store.insert([evil])
        check(store.item(mine.id)?.password == "keep-me" && store.items.count == 2, "hx1: import can't overwrite an existing item")
        var big = VaultItem(kind: .secureNote, title: "big")
        big.attachments = [Attachment(name: "x", data: Data(count: Attachment.maxBytes + 1))]
        check((try? store.insert([big])) == nil, "hx1: oversized attachment refused on import")
    }

    static func hx1TOTPFuzz() {
        // Direct construction with hostile parameters must not trap.
        for (d, p) in [(0, 30), (-3, 30), (100, 30), (Int.max, 30), (6, 0), (6, -30), (6, Int.min)] {
            let t = TOTP(secret: Data("12345678901234567890".utf8), digits: d, period: p)
            _ = t.code(at: Date()); _ = t.secondsRemaining(at: Date())
            _ = t.code(at: Date(timeIntervalSince1970: .infinity)); _ = t.code(at: Date(timeIntervalSince1970: -1e300))
            check(!t.isWellFormed, "hx1: TOTP digits=\(d) period=\(p) flagged")
        }
        check(TOTP(secret: Data(), digits: 6, period: 30).code().count == 6, "hx1: empty secret doesn't trap")
        // Aegis / 2FAS JSON with hostile values: filtered, no crash.
        let aegis = #"{"db":{"entries":[{"type":"totp","name":"a","issuer":"x","info":{"secret":"JBSWY3DPEHPK3PXP","digits":100,"period":0}},{"type":"hotp","name":"b","info":{"secret":"JBSWY3DPEHPK3PXP","counter":-5}},{"type":"totp","name":"ok","info":{"secret":"JBSWY3DPEHPK3PXP"}}]}}"#
        let r = Authenticator.parse(aegis)
        check(r.accounts.allSatisfy(\.isWellFormed) && r.accounts.contains { $0.account == "ok" } && !r.accounts.contains { $0.account == "a" },
              "hx1: Aegis hostile entries filtered")
        check(r.accounts.first { $0.account == "b" }?.counter == 0, "hx1: negative HOTP counter becomes 0")
        let twofas = #"{"services":[{"secret":"JBSWY3DPEHPK3PXP","name":"z","otp":{"digits":"-1","period":"999999","tokenType":"HOTP","counter":"-9"}}]}"#
        check(Authenticator.parse(twofas).accounts.isEmpty, "hx1: 2FAS hostile entry filtered")
        // Input cap.
        check(Authenticator.parse(String(repeating: "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP\n", count: 60_000)).accounts.isEmpty, "hx1: oversized paste refused")
    }

    static func hx1ParserFuzz() {
        var rng = SystemRandomNumberGenerator()
        func randBytes(_ n: Int) -> [UInt8] { (0..<n).map { _ in UInt8.random(in: 0...255, using: &rng) } }
        // Google migration protobuf: random and mutated payloads.
        let good = GoogleMigration.decodePayload(Data([0x0a, 0x10, 0x0a, 0x0a] + Array("1234567890".utf8) + [0x12, 0x02, 0x61, 0x62])) ?? []
        check(good.count == 1, "hx1: migration seed decodes")
        for i in 0..<3000 {
            var b = randBytes(Int.random(in: 0...64, using: &rng))
            if i % 2 == 0 { b = [0x0a, UInt8.random(in: 0...255, using: &rng)] + b }
            _ = GoogleMigration.decodePayload(Data(b))
        }
        // Varint length near UInt64.max must not trap.
        _ = GoogleMigration.decodePayload(Data([0x0a, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01]))
        _ = GoogleMigration.decode("otpauth-migration://offline?data=" + String(repeating: "A", count: 5000))
        // otpauth URIs.
        let alphabet = Array("otpauth://totp/hotp:?&=secret=JBSWY3DPEHPK3PXP%digits=period=algorithm=counter=-0123456789 /\u{0}é")
        for _ in 0..<3000 {
            let s = "otpauth://" + String((0..<Int.random(in: 0...80, using: &rng)).map { _ in alphabet.randomElement(using: &rng)! })
            if let t = TOTP(string: s) { _ = t.code(); _ = t.secondsRemaining(); _ = t.uri; check(t.isWellFormed, "hx1: parsed otpauth is well formed") }
        }
        // CSV with random structure.
        let csvChars = Array("\",\n\r\u{FEFF}ab\"\"x,")
        for _ in 0..<1000 {
            _ = CSVImporter.parse("name,url,username,password\n" + String((0..<Int.random(in: 0...200, using: &rng)).map { _ in csvChars.randomElement(using: &rng)! }))
        }
        // Random bytes as an export or a vault file.
        for _ in 0..<500 {
            let b = Data(Array("RAMPEXP\0".utf8) + [0, 1, 0, 0, 0x27, 0x10] + randBytes(Int.random(in: 0...80, using: &rng)))
            _ = try? EncryptedExport.import(b, password: "x")
        }
        check(true, "hx1: parser fuzz ran without trapping")
    }

    static func hx1Settings() {
        let s = try? JSONDecoder().decode(VaultSettings.self, from: Data(#"{"autoLockMinutes":0,"clipboardClearSeconds":0}"#.utf8))
        check(s?.autoLockMinutes == 1 && s?.clipboardClearSeconds == 5, "hx1: zero auto-lock / clipboard clamped on")
        let s2 = try? JSONDecoder().decode(VaultSettings.self, from: Data(#"{"autoLockMinutes":-5,"clipboardClearSeconds":999999}"#.utf8))
        check(s2?.autoLockMinutes == 1 && s2?.clipboardClearSeconds == 600, "hx1: settings bounds")
        check(ClipboardGuard.clearRange.lowerBound >= 5 && ClipboardGuard.clearRange.upperBound <= 600, "hx1: clipboard clear range")
    }

    static func hx1Breach() {
        final class Box: @unchecked Sendable { var prefixes: [String] = [] }
        let box = Box()
        let checker = BreachChecker(fetcher: { p in box.prefixes.append(p); return String(repeating: "0", count: 35) + ":1\n" })
        let sem = DispatchSemaphore(value: 0)
        Task { _ = try? await checker.breachCount(for: "hunter2-hx1"); sem.signal() }
        sem.wait()
        let hex = Set("0123456789ABCDEF")
        check(box.prefixes.count == 1 && box.prefixes[0].count == 5 && box.prefixes[0].allSatisfy(hex.contains), "hx1: breach check sends only a 5-char hex prefix")
        check(!box.prefixes[0].contains("hunter"), "hx1: password never sent")
    }
}
