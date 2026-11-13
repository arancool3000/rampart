import Foundation
import CryptoKit
import Security
import RampartShared
import RampartVault
import RampartGuard
import RampartRemediation
import RampartVPN

// wms-fb: cryptography and secrets. Known-answer tests, negative tests, key rotation on master-password change,
// Touch ID record integrity, and "no secret ever reaches a state file, log call or command line" scans.
// Obeys the ZERO POP-UPS RULE: no evaluatePolicy, no pasteboard, only keychain items this run creates.
extension SelfTest {
    static func wmsFbChecks() {
        let base = URL(fileURLWithPath: ProcessInfo.processInfo.environment["RAMPART_VAULT_TEST_DIR"]
                       ?? "/private/tmp/claude-501/-Users-arankeyhan/ab330a0d-96bf-4eec-a6ed-51d815d3bfd2/scratchpad/wmsfb")
        let dir = base.appendingPathComponent("run-\(UUID().uuidString.prefix(8))")
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        wmsFbKnownAnswers()
        wmsFbGoldenVault(dir)
        wmsFbKeyRotation(dir)
        wmsFbTouchIDRecord()
        wmsFbNormalisationAndExport(dir)
        wmsFbNegativeFormat(dir)
        wmsFbSecretScan(dir)
        wmsFbQuarantineNonces(dir)
        wmsFbGuardTokens()
        wmsFbKeychainAttributes()
        wmsFbSourceScan()
    }

    // MARK: Known answers

    static func wmsFbKnownAnswers() {
        // PBKDF2-HMAC-SHA256 (RFC 7914 section 11).
        let k1 = VaultCrypto.pbkdf2(password: "passwd", salt: Data("salt".utf8), iterations: 1, length: 64)
        check(k1.withBytes { WGKey.hex($0) } == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783",
              "wmsfb: PBKDF2 KAT c=1")
        let k2 = VaultCrypto.pbkdf2(password: "Password", salt: Data("NaCl".utf8), iterations: 80_000, length: 64)
        check(k2.withBytes { WGKey.hex($0) } == "4ddcd8f60b98be21830cee5ef22701f9641a4418d04c0414aeff08876b34ab56a1d425a1225833549adb841b51c9b3176a272bdebba1d078478f62b397f33c8d",
              "wmsfb: PBKDF2 KAT c=80000")
        k1.wipe(); k2.wipe()
        check(k1.count == 0, "wmsfb: SecretKeyBytes.wipe empties the buffer")
        // HMAC-SHA256 (RFC 4231 test case 2) through the Guard integrity key.
        let jefe = IntegrityKey(data: Data("Jefe".utf8))
        check(jefe.mac(Data("what do ya want for nothing?".utf8)) == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "wmsfb: HMAC-SHA256 KAT")
        check(jefe.mac(domain: "a", Data("x".utf8)) != jefe.mac(domain: "b", Data("x".utf8)) && jefe.mac(domain: "a", Data("x".utf8)) != jefe.mac(Data("x".utf8)),
              "wmsfb: MAC domains are separated")
        // Constant-time compares agree with == and reject length differences.
        let a = SecretKeyBytes([1, 2, 3, 4]), b = SecretKeyBytes([1, 2, 3, 4]), c = SecretKeyBytes([1, 2, 3, 5]), d = SecretKeyBytes([1, 2, 3])
        check(a.constantTimeEquals(b) && !a.constantTimeEquals(c) && !a.constantTimeEquals(d), "wmsfb: constant-time key compare")
        check(IntegrityKey.constantTimeEqual("abc", "abc") && !IntegrityKey.constantTimeEqual("abc", "abd") && !IntegrityKey.constantTimeEqual("ab", "abc"), "wmsfb: constant-time string compare")
        check(WGCrypto.equal([1, 2], [1, 2]) && !WGCrypto.equal([1, 2], [1, 3]) && !WGCrypto.equal([1], [1, 2]), "wmsfb: wg constant-time compare")
        // KDF parameter bounds from an untrusted header.
        check(!VaultCrypto.acceptableKDF(iterations: 999, salt: Data(count: 16)) && !VaultCrypto.acceptableKDF(iterations: 20_000_001, salt: Data(count: 16))
              && !VaultCrypto.acceptableKDF(iterations: 10_000, salt: Data(count: 15)) && VaultCrypto.acceptableKDF(iterations: 600_000, salt: Data(count: 16)),
              "wmsfb: KDF bounds")
        // Unicode: NFC first, raw form only when it differs.
        let decomposed = "Cafe\u{0301}", composed = "Caf\u{00E9}"
        let forms = VaultCrypto.passwordForms(decomposed).map { Array($0.utf8) }
        check(VaultCrypto.passwordForms(composed).count == 1 && forms == [Array(composed.utf8), Array(decomposed.utf8)], "wmsfb: password forms NFC first")
        check(Array(composed.utf8) != Array(decomposed.utf8) && composed == decomposed, "wmsfb: canonically equal strings differ as KDF input")
        // Wireguard DH rejects the all-zero shared secret (low-order point) instead of using it.
        let priv = WGCrypto.generatePrivateKey()
        check((try? WGCrypto.dh(priv, [UInt8](repeating: 0, count: 32))) == nil, "wmsfb: wg dh rejects zero point")
    }

    // MARK: Format known answer (a vault written by this format, fixed forever)

    static let wmsFbGolden = """
    UkFNUFZMVAAAAQAAAR97ImdlbmVyYXRpb24iOjMsImtkZiI6eyJhbGdvcml0aG0iOiJwYmtkZjItaG1hYy1zaGEyNTYiLCJpdGVyYXRpb25zIjoxMDAwLCJz
    YWx0Ijoid1BxMlc3clM0cSsxanFobEFtbXc2QT09In0sInZhdWx0SUQiOiI2QTM3MEU2OS1ENTQ1LTRBQ0EtODI1Qi0wNjQ5MDE0RTJCREIiLCJ3cmFwcGVk
    S2V5IjoiYzlUUEx1c2d5SnZING5STHhiT3BOekE1Q0o0OGl1RHp2WjE1MEMrMmZjR24rd3M2blhlQzNZM1pmTU8ybkdGWUF4NHlvQkZEZVd5bkhoVVYiLCJ3
    cml0dGVuIjoiMjAyNi0xMS0xM1QxMjoxMDowNFoifQAABet7Iml0ZW1zIjpbeyJkYXRhIjoiM2h1SmlCaUFEckVENWpMdFhvZkNiQitIc1Y0N0NIK1pOeHlp
    NXN0QXg4NXZPTllBYUhQRXlpeHo3UHpUYVY5Mk0rOXdqa1FMXC9YYnhPMUxoVWxNN1wvcGRKWTZ6XC9uN29zd0t5c0RJcFc5SHl2WEZBNys4c0hVVFNzRitp
    SEJZU3RKUE50b2l3dFNrRlFhNEJHY0N3a1VEMWtsXC9IU2lBS2RYK1UwOUcwbDhVVEtQd21yT0NsY2hTd21CZyszeVwvd1JBK29GOGlxbWJxQThadGpKK2ZM
    eGlzUEFla0lZMHhWbXlMeHlmNjFMK2lCRk9RYjhrSWRKS1NYQkdMbFkzanBTS3FDTjR5ZGRcL0lveVwvaXNQTHhaYlBQTFNwc2xFMTU4Vm16eVpuYWc4VGRo
    NURwakNlZDVwSW00c3pEV1J1UlJ1VDBDeHlmRG14RUk3akV1STlkMmhlbHlENnQ2SlVmZmdPS2FsQVZDcGNGUDMrYnNYc25qM1wvdnl2RnRMWjdBVnVGZnBs
    NEpsdzZMdkp5M3owWmpvUHdhWHFJNk5TZFloTE0rdFpFYXllT3hUZmF2R2IxUCtPS3g5UGdKN281cWdqeG8wdWl6N2RVSm9DV2lQTHZCVGlqVDBcLzI0N1wv
    QlJKd1wvdmlwQ1AybjY5dVI3NTFwS1k5N3pzMDFCaVRDR0JWRDEzeVhweWZJM0FsV2ExWHdNbHdvaDc0ZVUyY2JDT0VZbFVFeldGYWlRRGNTNW0xeXJCWWdo
    eTNiRUE9PSIsImlkIjoiOUI2MTA4MUEtRENEOC00MTVFLUJDNkQtMTMzNzA0MzlBMDg2In1dLCJtZXRhIjoia0Y5ait5MTFsSFlzUkkreFJ1QjdwWGx4Y08z
    SHZGN3dcL3p0WDd2UTJ5eGN4Z24xMzltb1RUZEh2dUVzTGQyT3BrWTJXRjJTSFZTd0d1Q2pwRGJXbWtDdER2b0x2UlhvU2tnZVNrd0RBM3J5MnFkZWhkNldE
    a2ZFQUZ5YkVVV2dmV0pycjBuT0NJWm1QK25qZE91TWZJeW52U01VWWk3eGhnZXVuSHZWa2J4U2JNcmM2UERRcXVzQmc3UCtJVU1QOGxzVmtaMSsxU0hjejNa
    Z3BJQkw5MVpGTVhPZ2hMOFwvTXRxVTM0dGkrZUViQWo1SWZ0cWNhMUtvclZkTkJnVmxrczJKcDI1RWJRbmEyOVwvbWtnV3VPd3B5QVwvaHJqbldjZ1pONGV6
    K3dkN2srQmprQWVaXC9sNVVxUSsyS3ZTSW0wSGNXbHU3QzFiVFAzUXBpU2hSSWl0cW02RkJyK1lJZTRKRFFxUzE4MXFuZ3N4K1preEdFa3RNVjFhVEtVckhD
    Qjh6M0R1bEx6VEM1ZzNFREF1eDR4SjVyV0xUdUVDXC91Z1Y2SktvaGlpNzJ2cUl4ZFY1ZDkyTlJIUDdhY1wvXC9xSzhxNGdwZVNCMnF2emdWYmVQY1JpRCtn
    VjJcL0x3eklscThNYmM5NzYzeXZOcVwvTUtFQ0dXRUFmRDRCQW5IaUNNT0dlTDBHNitOXC9Mb3lLVW9zNmdZekhxQkIxeFpYeVhnMnlPQnJjdUdpMmxCWTN3
    MkE4MWVlbitUUlp2a0wxamVBNklhT2NXM0hNSVZTOGdGOXExR0VUM2lRaXA1XC9oazFGXC9BTGFBaWt0Q3h0dzNRSFpcL0NMRGJMOHFYUmxaUnpmUlc2MEJT
    NmoxQnc2TlVDYjZQcGxCN09YeGprOUpVUWJlVGVaeG1nN3hJcXVBZHpXdWdISXJtNmZuK1RtRG11ZFEzbXYzU0Q0SFhOMlk0ekxueTBySktHZjJFXC9NdHow
    Z1VjaVZmSFFkOE9WNzhlK2NXUnZQQmtSM3FXWTUwZFRmOExMYmdoTmg3ZEFzM2d2Sm5JRTRzSkphNjRTWnZDYjZoeVVlQUVWaWdiSXBNZ05MajdySUlIeWZK
    NFU3VHpGdDNTNU9DTkRVdz09In3uBEf7Qrs1nILl1uPy+9erA7LJezwV0a6KLSytXGqsMQ==
    """

    static func wmsFbGoldenVault(_ dir: URL) {
        let d = dir.appendingPathComponent("golden")
        try? FileManager.default.createDirectory(at: d, withIntermediateDirectories: true)
        let store = VaultStore(directory: d)
        guard let data = Data(base64Encoded: wmsFbGolden.filter { !$0.isWhitespace }) else { check(false, "wmsfb: golden fixture decodes"); return }
        try? data.write(to: store.fileURL)
        do {
            try store.unlock(masterPassword: "wms-fb-golden-password")
            let item = store.items.first
            check(item?.title == "Golden" && item?.username == "gold@example.com" && item?.password == "golden-secret-77" && item?.totp?.code(at: Date(timeIntervalSince1970: 59)) == "287082",
                  "wmsfb: golden vault opens with the expected contents (format is stable)")
            check(store.kdfIterations == 1000 && store.meta.folders.first?.name == "Gold" , "wmsfb: golden vault header and meta")
        } catch { check(false, "wmsfb: golden vault opens (\(error))") }
        store.lock()
        check((try? store.unlock(masterPassword: "wms-fb-golden-passworD")) == nil, "wmsfb: golden vault refuses a near-miss password")
    }

    // MARK: Key rotation on master-password change

    /// Minimal reader for the documented file layout (magic | version | hlen | header | blen | body | mac).
    static func wmsFbBody(_ raw: Data) -> [String: Any]? {
        let d = Data(raw)
        guard d.count > 50 else { return nil }
        func u32(_ p: Int) -> Int { Int(d[p]) << 24 | Int(d[p + 1]) << 16 | Int(d[p + 2]) << 8 | Int(d[p + 3]) }
        let hl = u32(10), bl = u32(14 + hl)
        guard 18 + hl + bl + 32 == d.count else { return nil }
        return (try? JSONSerialization.jsonObject(with: d.subdata(in: (18 + hl)..<(18 + hl + bl)))) as? [String: Any]
    }
    static func wmsFbBlobs(_ raw: Data) -> [Data] {
        ((wmsFbBody(raw)?["items"] as? [[String: Any]]) ?? []).compactMap { ($0["data"] as? String).flatMap { Data(base64Encoded: $0) } }
    }

    static func wmsFbKeyRotation(_ dir: URL) {
        let d = dir.appendingPathComponent("rotate")
        let store = VaultStore(directory: d)
        let pw1 = "first master passphrase 11", pw2 = "second master passphrase 22"
        check((try? store.create(masterPassword: pw1, iterations: 10_000)) != nil, "wmsfb: rotation vault created")
        var a = VaultItem(kind: .login, title: "A"); a.password = "rotate-secret-A"
        var b = VaultItem(kind: .login, title: "B"); b.password = "rotate-secret-B"
        try? store.insert([a, b])                       // forced backup: same key as the live file
        guard let before = store.backups().first else { check(false, "wmsfb: backup before rotation"); return }
        check((try? store.backupKeyOpensCurrentVault(backup: before, password: pw1)) == true, "wmsfb: before the change a backup's key opens the live vault (control)")
        let oldRaw = (try? Data(contentsOf: store.fileURL)) ?? Data()
        let oldBlobs = wmsFbBlobs(oldRaw)
        check(oldBlobs.count == 2 && Set(oldBlobs.map { $0.prefix(12) }).count == 2, "wmsfb: per-item GCM nonces are distinct")

        var fired = 0
        store.addKeyRotationObserver { fired += 1 }
        check((try? store.changeMasterPassword(current: pw1, new: pw2, iterations: 10_000)) != nil, "wmsfb: master password changed")
        check(fired == 1, "wmsfb: rotation observer fired once")
        check(store.item(a.id)?.password == "rotate-secret-A" && store.item(b.id)?.password == "rotate-secret-B", "wmsfb: items intact after rotation")
        // Every earlier backup opens with the old password but its key no longer fits the live file.
        for bk in store.backups() {
            check((try? store.backupKeyOpensCurrentVault(backup: bk, password: pw1)) == false, "wmsfb: old backup + old password no longer opens the current vault (\(bk.lastPathComponent))")
        }
        let newRaw = (try? Data(contentsOf: store.fileURL)) ?? Data()
        let newBlobs = wmsFbBlobs(newRaw)
        check(newBlobs.count == 2 && Set(newBlobs).isDisjoint(with: oldBlobs), "wmsfb: items re-encrypted under the new key")
        check(oldRaw.suffix(32) != newRaw.suffix(32), "wmsfb: file MAC key rotated")
        // The new password is the only way in; the generation moved on (a put-back old file is a rollback).
        store.lock()
        check((try? store.unlock(masterPassword: pw1)) == nil && (try? store.unlock(masterPassword: pw2)) != nil, "wmsfb: only the new password unlocks")
        store.lock()
        try? oldRaw.write(to: store.fileURL)
        do { try store.unlock(masterPassword: pw1); check(false, "wmsfb: replayed pre-rotation file is flagged as a rollback") }
        catch { if case VaultError.rolledBack = error { check(true, "wmsfb: replayed pre-rotation file is flagged as a rollback") } else { check(false, "wmsfb: replayed pre-rotation file is flagged as a rollback (\(error))") } }
        // A wrong current password is throttled like an unlock and does not rotate anything.
        try? newRaw.write(to: store.fileURL)
        try? store.unlock(masterPassword: pw2, acceptRollback: true)
        let gen = (try? Data(contentsOf: store.fileURL)) ?? Data()
        check((try? store.changeMasterPassword(current: "not it", new: "third master passphrase 33", iterations: 10_000)) == nil
              && (try? Data(contentsOf: store.fileURL)) == gen && store.throttle.failures == 1, "wmsfb: wrong current password changes nothing and counts as a failure")
    }

    // MARK: Touch ID record integrity (no prompt: pure MAC logic)

    static func wmsFbTouchIDRecord() {
        let key = SecretKeyBytes(SecureRandom.bytes(32)), other = SecretKeyBytes(SecureRandom.bytes(32))
        let id = UUID()
        let r = TouchIDUnlock.Record(vaultID: id, mode: .keychainGated, domainState: Data([1, 2, 3]))
        check(!TouchIDUnlock.isAuthentic(r, vaultKey: key), "wmsfb: touchid record without a tag is not authentic")
        let sealed = TouchIDUnlock.sealed(r, vaultKey: key)
        check(TouchIDUnlock.isAuthentic(sealed, vaultKey: key), "wmsfb: sealed touchid record verifies")
        check(!TouchIDUnlock.isAuthentic(sealed, vaultKey: other), "wmsfb: touchid record bound to the vault key")
        var forged = sealed; forged.domainState = Data([9, 9, 9])
        check(!TouchIDUnlock.isAuthentic(forged, vaultKey: key), "wmsfb: rewritten enrolment hash detected")
        var stripped = sealed; stripped.domainState = nil
        check(!TouchIDUnlock.isAuthentic(stripped, vaultKey: key), "wmsfb: stripped enrolment hash detected")
        var mode = sealed; mode.mode = .secureEnclave
        check(!TouchIDUnlock.isAuthentic(mode, vaultKey: key), "wmsfb: mode swap detected")
        var wrapped = sealed; wrapped.wrapped = Data([0])
        check(!TouchIDUnlock.isAuthentic(wrapped, vaultKey: key), "wmsfb: wrapped-key swap detected")
        var vid = sealed; vid.vaultID = UUID()
        check(!TouchIDUnlock.isAuthentic(vid, vaultKey: key), "wmsfb: vault id swap detected")
        // Round trip through JSON (what touchid.json holds).
        let rt = (try? JSONEncoder().encode(sealed)).flatMap { try? JSONDecoder().decode(TouchIDUnlock.Record.self, from: $0) }
        check(rt.map { TouchIDUnlock.isAuthentic($0, vaultKey: key) } == true, "wmsfb: touchid record survives JSON")
        // The SE round trip (no biometry flags, so no prompt) also exercises "load blob, read public key, re-wrap".
        if ProcessInfo.processInfo.environment["RAMPART_VAULT_SE_TEST"] == "1" {
            let err = TouchIDUnlock.secureEnclaveRoundTripWithoutBiometry()
            check(err == nil, "wmsfb: SE re-wrap path \(err ?? "")")
        }
    }

    // MARK: Unicode normalisation + export

    static func wmsFbNormalisationAndExport(_ dir: URL) {
        let d = dir.appendingPathComponent("nfc")
        let store = VaultStore(directory: d)
        let composed = "Caf\u{00E9}-Latte-Secure-123", decomposed = "Cafe\u{0301}-Latte-Secure-123"
        check((try? store.create(masterPassword: composed, iterations: 10_000)) != nil, "wmsfb: vault with accented master")
        store.lock()
        check((try? store.unlock(masterPassword: decomposed)) != nil, "wmsfb: decomposed form of the same password unlocks")
        check(store.throttle.failures == 0, "wmsfb: NFC retry costs no throttle failure")
        // Export: weak password refused by the library, strong one round-trips in either Unicode form.
        var it = VaultItem(kind: .login, title: "E"); it.password = "export-secret-9"
        do { _ = try EncryptedExport.export(items: [it], folders: [], password: "short"); check(false, "wmsfb: weak export password refused") }
        catch { check(error as? VaultError == .weakExportPassword, "wmsfb: weak export password refused") }
        guard let exp = try? EncryptedExport.export(items: [it], folders: [], password: composed, iterations: 10_000) else { check(false, "wmsfb: export"); return }
        check((try? EncryptedExport.import(exp, password: decomposed))?.items.first?.password == "export-secret-9", "wmsfb: export opens with the decomposed password")
        var flipped = exp; flipped[flipped.count - 5] ^= 0x40
        check((try? EncryptedExport.import(flipped, password: composed)) == nil, "wmsfb: export tag covers the ciphertext")
        var headerFlip = exp; headerFlip[29] ^= 0x01    // last salt byte: AAD
        check((try? EncryptedExport.import(headerFlip, password: composed)) == nil, "wmsfb: export header is authenticated")
        var v2 = exp; v2[9] = 2
        do { _ = try EncryptedExport.import(v2, password: composed); check(false, "wmsfb: export version 2 refused") }
        catch { check(error as? VaultError == .unsupportedVersion(2), "wmsfb: export version 2 refused") }
        var huge = exp; huge[10] = 0xff; huge[11] = 0xff; huge[12] = 0xff; huge[13] = 0xff
        do { _ = try EncryptedExport.import(huge, password: composed); check(false, "wmsfb: export with 4 billion iterations refused") }
        catch { if case VaultError.badFormat = error { check(true, "wmsfb: export with 4 billion iterations refused") } else { check(false, "wmsfb: export with 4 billion iterations refused") } }
    }

    // MARK: Negative format tests

    static func wmsFbNegativeFormat(_ dir: URL) {
        let d = dir.appendingPathComponent("neg")
        let store = VaultStore(directory: d)
        let pw = "negative tests passphrase 44"
        try? store.create(masterPassword: pw, iterations: 10_000)
        var x = VaultItem(kind: .login, title: "X"); x.password = "neg-secret"
        try? store.upsert(x)
        let raw = (try? Data(contentsOf: store.fileURL)) ?? Data()
        store.lock()
        func attempt(_ data: Data, _ name: String, _ expect: (Error) -> Bool) {
            let t = VaultStore(directory: dir.appendingPathComponent("neg-\(UUID().uuidString.prefix(6))"))
            try? FileManager.default.createDirectory(at: t.directory, withIntermediateDirectories: true)
            try? data.write(to: t.fileURL)
            do { try t.unlock(masterPassword: pw); check(false, name) } catch { check(expect(error), "\(name) (\(error))") }
        }
        var v0 = raw; v0[8] = 0; v0[9] = 0
        attempt(v0, "wmsfb: version 0 refused") { if case VaultError.badFormat = $0 { return true }; return false }
        var mac = raw; mac[raw.count - 1] ^= 0x01
        attempt(mac, "wmsfb: flipped MAC byte refused") { $0 as? VaultError == .tampered }
        var header = raw; header[20] ^= 0x01            // inside the header JSON (covered by the file MAC and/or AAD)
        attempt(header, "wmsfb: header byte flip refused") { ($0 as? VaultError) == .tampered || ($0 as? VaultError) == .wrongPassword || { if case VaultError.badFormat = $0 { return true }; return false }($0) }
        attempt(raw + Data([0]), "wmsfb: appended byte refused") { $0 as? VaultError == .tampered }
        attempt(Data("RAMPVLT\0".utf8) + Data([0, 1]) + Data([0xff, 0xff, 0xff, 0xff]) + Data(count: 40), "wmsfb: oversized chunk length refused") { $0 as? VaultError == .tampered }
        // Item deletion inside the body: re-serialise the body with the item removed; the whole-file MAC catches it.
        if var body = wmsFbBody(raw), let items = body["items"] as? [[String: Any]], items.count == 1 {
            body["items"] = []
            if let nb = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) {
                func be32(_ v: Int) -> Data { Data([UInt8(v >> 24 & 0xff), UInt8(v >> 16 & 0xff), UInt8(v >> 8 & 0xff), UInt8(v & 0xff)]) }
                let hl = Int(raw[10]) << 24 | Int(raw[11]) << 16 | Int(raw[12]) << 8 | Int(raw[13])
                let rebuilt = raw.prefix(14 + hl) + be32(nb.count) + nb + raw.suffix(32)
                attempt(rebuilt, "wmsfb: silently deleted item detected by the file MAC") { $0 as? VaultError == .tampered }
            }
        } else { check(false, "wmsfb: body parses for the deletion test") }
        // Rollback guard state belongs to this vault only.
        check((try? store.unlock(masterPassword: pw)) != nil, "wmsfb: original still opens")
    }

    // MARK: Secret never reaches a state file

    static func wmsFbSecretScan(_ dir: URL) {
        let d = dir.appendingPathComponent("scan")
        let store = VaultStore(directory: d)
        let master = "Marker-Master-Pw-5f1c9e-long"
        let markers: [String: String] = [
            "item password": "MARKER-item-pw-7a2b3c",
            "totp secret": "JBSWY3DPEHPK3PXPJBSWY3DP",
            "note": "MARKER-note-3c4d5e-confidential",
            "card": "4111222233334444",
            "cvv": "MARKERCVV",
            "attachment": "MARKER-attachment-bytes-6f7a8b-9c0d1e2f",
            "wifi": "MARKER-wifi-key-2b3c",
            "custom field": "MARKER-custom-value-4d5e",
            "history": "MARKER-old-pw-1a2b",
            "master": master,
        ]
        check((try? store.create(masterPassword: master, iterations: 10_000)) != nil, "wmsfb: scan vault created")
        var login = VaultItem(kind: .login, title: "Scan"); login.username = "scan@example.com"; login.password = markers["history"]!
        login.totpSecret = markers["totp secret"]!; login.notes = markers["note"]!
        login.customFields = [CustomField(name: "api", value: markers["custom field"]!, concealed: true)]
        try? login.addAttachment(name: "a.txt", data: Data(markers["attachment"]!.utf8))
        try? store.upsert(login)
        login.password = markers["item password"]!      // records the old one in history
        try? store.upsert(login)
        var card = VaultItem(kind: .card, title: "Card"); card.card?.number = markers["card"]!; card.card?.cvv = markers["cvv"]!
        try? store.upsert(card)
        var wifi = VaultItem(kind: .wifi, title: "Wi-Fi"); wifi.password = markers["wifi"]!; wifi.wifi?.ssid = "HomeNet"
        try? store.insert([wifi])
        try? store.updateMeta { $0.lockedItems = [login.id] }
        try? store.changeMasterPassword(current: master, new: master + "-2", iterations: 10_000)
        let export = (try? EncryptedExport.export(items: store.items, folders: [], password: master, iterations: 10_000)) ?? Data()
        try? export.write(to: d.appendingPathComponent("export.rpexport"))
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: d.appendingPathComponent("export.rpexport").path)   // as the app's writePrivate does
        store.lock()
        _ = store.verifyMasterPassword("wrong-\(master)")   // last: a success would delete the throttle file again

        // Every file under the vault folder (vault, backups, state, throttle, export): raw, base64 and hex forms.
        var files: [URL] = []
        if let e = FileManager.default.enumerator(at: d, includingPropertiesForKeys: [.isRegularFileKey]) {
            for case let u as URL in e where (try? u.resourceValues(forKeys: [.isRegularFileKey]).isRegularFile) == true { files.append(u) }
        }
        check(files.count >= 4 && files.contains { $0.lastPathComponent == "vault.state" } && files.contains { $0.lastPathComponent == "unlock-throttle.json" },
              "wmsfb: scan covers vault, backups, state and throttle files (\(files.count))")
        var leaks: [String] = []
        for u in files {
            guard let data = try? Data(contentsOf: u) else { leaks.append("unreadable \(u.lastPathComponent)"); continue }
            let lower = String(decoding: data, as: UTF8.self).lowercased()
            for (what, m) in markers {
                let forms = [Data(m.utf8), Data(m.utf8).base64EncodedData(), Data(m.utf8.map { String(format: "%02x", $0) }.joined().utf8)]
                if forms.contains(where: { data.range(of: $0) != nil }) || lower.contains(m.lowercased()) { leaks.append("\(what) in \(u.lastPathComponent)") }
            }
        }
        check(leaks.isEmpty, "wmsfb: no secret (raw, base64 or hex) in any vault state file\(leaks.isEmpty ? "" : ": " + leaks.joined(separator: ", "))")
        // Throttle and rollback state carry only counters.
        let throttle = String(decoding: (try? Data(contentsOf: d.appendingPathComponent("unlock-throttle.json"))) ?? Data(), as: UTF8.self)
        let state = String(decoding: (try? Data(contentsOf: d.appendingPathComponent("vault.state"))) ?? Data(), as: UTF8.self)
        check(throttle.contains("failures") && !throttle.contains("wrong") && state.contains("generation"), "wmsfb: state files hold counters only")
        // Modes: everything 0600 in a 0700 folder.
        let modes = files.compactMap { (try? FileManager.default.attributesOfItem(atPath: $0.path))?[.posixPermissions] as? Int }
        check(modes.count == files.count && modes.allSatisfy { $0 & 0o077 == 0 }, "wmsfb: vault files are 0600")
        check(((try? FileManager.default.attributesOfItem(atPath: d.path))?[.posixPermissions] as? Int).map { $0 & 0o077 == 0 } == true, "wmsfb: vault folder is 0700")
        // Error descriptions never echo a password (they are logged by the app as activity details).
        let texts = [VaultError.wrongPassword, .tampered, .throttled(5), .rolledBack(found: 1, expected: 2), .weakMasterPassword, .weakExportPassword].map { $0.errorDescription ?? "" }
        check(!texts.joined().contains(master), "wmsfb: error text carries no secret")
    }

    // MARK: Quarantine vault: nonce uniqueness, plaintext never on disk

    static func wmsFbQuarantineNonces(_ dir: URL) {
        let q = dir.appendingPathComponent("q")
        let src = dir.appendingPathComponent("qsrc")
        try? FileManager.default.createDirectory(at: src, withIntermediateDirectories: true)
        guard let vault = try? QuarantineVault(root: q) else { check(false, "wmsfb: quarantine vault opens"); return }
        vault.enforceProtectedPaths = false
        let marker = "QUARANTINE-MARKER-PLAINTEXT-0a1b2c3d"
        var ids: [UUID] = []
        for i in 0..<24 {
            let f = src.appendingPathComponent("s\(i).txt")
            try? Data((marker + String(repeating: "x", count: 100)).utf8).write(to: f)   // identical content: nonces must still differ
            if let r = try? vault.quarantine(path: f.path, detectionName: "com.rampart.test.marker") { ids.append(r.id) }
        }
        check(ids.count == 24, "wmsfb: 24 identical files quarantined")
        let blobs = ids.compactMap { try? Data(contentsOf: q.appendingPathComponent("items/\($0.uuidString).rqf")) }
        check(blobs.count == 24 && Set(blobs.map { $0.prefix(12) }).count == 24, "wmsfb: AES-GCM nonces distinct across identical samples")
        check(Set(blobs).count == 24, "wmsfb: identical samples give different ciphertexts")
        check(!blobs.contains { $0.range(of: Data(marker.utf8)) != nil }, "wmsfb: sample plaintext never in a quarantine blob")
        let sidecars = ids.compactMap { try? Data(contentsOf: q.appendingPathComponent("items/\($0.uuidString).json")) }
        check(!sidecars.contains { $0.range(of: Data(marker.utf8)) != nil }, "wmsfb: sample plaintext never in a sidecar")
        let keyMode = (try? FileManager.default.attributesOfItem(atPath: q.appendingPathComponent("vault.key").path))?[.posixPermissions] as? Int
        check(keyMode.map { $0 & 0o077 == 0 } == true, "wmsfb: quarantine key is 0600")
        // Key file length tampering is refused rather than silently regenerated (that would orphan every item).
        try? Data(count: 31).write(to: q.appendingPathComponent("vault.key"))
        check((try? QuarantineVault(root: q)) == nil, "wmsfb: short quarantine key refused")
    }

    // MARK: Guard disable tokens

    static func wmsFbGuardTokens() {
        let flow = ProtectionDisableFlow(key: IntegrityKey(data: Data(repeating: 3, count: 32)))
        guard case .success(let t1) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true),
              case .success(let t2) = flow.issueToken(peerUID: 501, isAdmin: true, authorizationOK: true) else { check(false, "wmsfb: tokens issued"); return }
        let n1 = t1.split(separator: ".")[0], n2 = t2.split(separator: ".")[0]
        check(n1 != n2 && n1.count == 32 && n1 != String(repeating: "0", count: 32), "wmsfb: token nonces are random and distinct")
        var parts = t1.split(separator: ".").map(String.init)
        let last = parts[3].removeLast(); parts[3].append(last == "a" ? "b" : "a")
        func failure(_ r: Result<Void, ProtectionDisableFlow.Failure>) -> ProtectionDisableFlow.Failure? { if case .failure(let f) = r { return f }; return nil }
        check(failure(flow.redeem(parts.joined(separator: "."), peerUID: 501)) == .tokenInvalid, "wmsfb: one-character MAC change rejected")
        var up = t1.split(separator: ".").map(String.init); up[1] = "0"
        check(failure(flow.redeem(up.joined(separator: "."), peerUID: 0)) == .tokenInvalid, "wmsfb: uid rewrite rejected")
        check(failure(flow.redeem(t1, peerUID: 501)) == nil && failure(flow.redeem(t1, peerUID: 501)) == .tokenInvalid, "wmsfb: token is single-use")
        // A different integrity key never validates the same token.
        let other = ProtectionDisableFlow(key: IntegrityKey(data: Data(repeating: 4, count: 32)))
        check(failure(other.redeem(t2, peerUID: 501)) == .tokenInvalid, "wmsfb: token bound to the daemon's key")
    }

    // MARK: Keychain item attributes (only an item this run creates)

    static func wmsFbKeychainAttributes() {
        let service = "app.rampart.vault.selftest", account = "wmsfb-\(UUID().uuidString)"
        defer { Keychain.deleteGeneric(service: service, account: account) }
        guard (try? Keychain.setGeneric(service: service, account: account, data: Data([1, 2, 3]), label: "wmsfb")) != nil else { check(false, "wmsfb: keychain add"); return }
        let q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account,
                                kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitOne]
        var out: CFTypeRef?
        let s = SecItemCopyMatching(q as CFDictionary, &out)
        let attrs = out as? [String: Any] ?? [:]
        let sync = (attrs[kSecAttrSynchronizable as String] as? Bool) ?? ((attrs[kSecAttrSynchronizable as String] as? Int).map { $0 != 0 }) ?? false
        check(s == errSecSuccess && !sync, "wmsfb: RamPart keychain items are not iCloud-synchronisable")
        check(attrs[kSecValueData as String] == nil, "wmsfb: attribute query returns no secret")
    }

    // MARK: Source scans: no logging, no secret in argv

    static func wmsFbSourceScan() {
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<4 { dir.deleteLastPathComponent(); if FileManager.default.fileExists(atPath: dir.appendingPathComponent("Package.swift").path) { break } }
        let root = dir.path
        func read(_ p: String) -> String { (try? String(contentsOfFile: root + "/" + p, encoding: .utf8)) ?? "" }
        func swiftFiles(_ sub: String) -> [String] {
            let e = FileManager.default.enumerator(atPath: root + "/" + sub)
            return (e?.allObjects as? [String] ?? []).filter { $0.hasSuffix(".swift") }.map { sub + "/" + $0 }
        }
        let banned = ["print(", "NSLog(", "Logger(", "os_log(", "RLog.", "debugPrint(", "dump("]
        var hits: [String] = []
        for f in swiftFiles("Sources/RampartVault") + swiftFiles("Sources/RampartApp/Features/Passwords") + swiftFiles("Sources/RampartApp/Features/Authenticator") {
            let text = read(f)
            for (n, line) in text.split(separator: "\n", omittingEmptySubsequences: false).enumerated() {
                let l = line.trimmingCharacters(in: .whitespaces)
                if l.hasPrefix("//") { continue }
                if banned.contains(where: { l.contains($0) }) { hits.append("\(f):\(n + 1)") }
            }
        }
        check(!swiftFiles("Sources/RampartVault").isEmpty, "wmsfb: source tree located")
        check(hits.isEmpty, "wmsfb: no logging or printing in vault, passwords or authenticator code\(hits.isEmpty ? "" : ": " + hits.prefix(5).joined(separator: ", "))")
        // Gemini: the key travels in a header and over a pipe; argv names only the service and account.
        let gk = read("Sources/RampartAI/GeminiKeyStore.swift"), gc = read("Sources/RampartAI/GeminiClient.swift")
        check(gk.contains("p.arguments = [\"find-generic-password\", \"-s\", service, \"-a\", account, \"-w\"]") && !gk.contains("add-generic-password\", ")
              && !gk.contains("\"-w\", k") && !gk.contains("\"-w\", key"), "wmsfb: gemini key never in a command line")
        let gcLogLines = gc.split(separator: "\n").filter { $0.contains("log.") }
        check(!gcLogLines.contains { $0.contains("key") || $0.contains("apiKey") }, "wmsfb: gemini client never logs the key")
        check(gc.contains("x-goog-api-key") && !gc.contains("?key="), "wmsfb: gemini key in a header, not the URL")
        // Touch ID unlock verifies the record tag and refuses a compat record without an enrolment hash.
        let tid = read("Sources/RampartVault/TouchIDUnlock.swift")
        check(tid.contains("Self.isAuthentic(r, vaultKey: key)") && tid.contains("r.mode == .keychainGated, r.domainState == nil"), "wmsfb: touchid unlock checks record tag and enrolment hash")
        check(tid.contains("kSecAttrAccessibleWhenUnlockedThisDeviceOnly") && tid.contains(".biometryCurrentSet"), "wmsfb: SE key is this-device-only and bound to the current fingerprint set")
        // VPN: keys only through the key store; the profile on disk never holds them.
        let vs = read("Sources/RampartVPN/VPNService.swift"), wc = read("Sources/RampartVPN/WGConfig.swift")
        check(!vs.contains("saveJSON(c,") && !vs.contains("saveJSON(cfg") && wc.contains("never a private or preshared key"), "wmsfb: vpn secrets never serialised to the profile")
        check(read("Sources/RampartVPN/VPNKeyStore.swift").contains("kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly"), "wmsfb: vpn keychain items are this-device-only")
    }
}
