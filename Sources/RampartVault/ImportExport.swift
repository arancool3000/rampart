import Foundation
import CryptoKit

/// RFC 4180 CSV parser (quoted fields, doubled quotes, embedded newlines, CRLF, BOM).
public enum CSV {
    public static func parse(_ text: String) -> [[String]] {
        var rows: [[String]] = [], row: [String] = [], field = ""
        var inQuotes = false, fieldStarted = false
        var it = Array(text.hasPrefix("\u{FEFF}") ? String(text.dropFirst()) : text)
        var i = 0
        while i < it.count {
            let c = it[i]
            if inQuotes {
                if c == "\"" {
                    if i + 1 < it.count, it[i + 1] == "\"" { field.append("\""); i += 1 } else { inQuotes = false }
                } else { field.append(c) }
            } else {
                switch c {
                case "\"" where !fieldStarted || field.isEmpty: inQuotes = true; fieldStarted = true
                case ",": row.append(field); field = ""; fieldStarted = false
                case "\r\n", "\n", "\r":
                    row.append(field); field = ""; fieldStarted = false
                    if !(row.count == 1 && row[0].isEmpty) { rows.append(row) }
                    row = []
                default: field.append(c); fieldStarted = true
                }
            }
            i += 1
        }
        if fieldStarted || !field.isEmpty || !row.isEmpty { row.append(field); rows.append(row) }
        for k in it.indices { it[k] = " " } // drop our copy of the plaintext promptly
        return rows
    }
}

/// Imports password-manager CSV exports. Detects Chrome/Edge/Brave, Firefox, Bitwarden, 1Password,
/// Safari/Passwords.app and generic `url,username,password` files by their header row.
public enum CSVImporter {
    public enum Source: String, Sendable { case chrome = "Chrome", firefox = "Firefox", bitwarden = "Bitwarden", onePassword = "1Password", safari = "Safari / Passwords", generic = "CSV" }

    public struct Result: Sendable {
        public var source: Source
        public var items: [VaultItem]
        public var folders: [String]
        public var skipped: Int
    }

    public static func detect(header: [String]) -> Source {
        let h = Set(header.map { $0.lowercased().trimmingCharacters(in: .whitespaces) })
        if h.contains("login_password") || h.contains("login_uri") { return .bitwarden }
        if h.contains("httprealm") || h.contains("formactionorigin") || h.contains("timepasswordchanged") { return .firefox }
        if h.contains("otpauth") && h.contains("title") && h.contains("archived") { return .onePassword }
        if h.contains("otpauth") && h.contains("title") { return .safari }
        if h.contains("name") && h.contains("url") && h.contains("username") && h.contains("password") { return .chrome }
        return .generic
    }

    public static func parse(_ text: String) -> Result {
        var rows = CSV.parse(text)
        guard !rows.isEmpty else { return Result(source: .generic, items: [], folders: [], skipped: 0) }
        let header = rows.removeFirst().map { $0.lowercased().trimmingCharacters(in: .whitespaces) }
        let source = detect(header: header)
        func col(_ names: String...) -> Int? { names.lazy.compactMap { header.firstIndex(of: $0) }.first }
        let cTitle = col("name", "title")
        let cURL = col("login_uri", "url", "website", "uri")
        let cUser = col("login_username", "username", "user", "email", "login")
        let cPass = col("login_password", "password")
        let cNotes = col("notes", "note", "extra", "comments")
        let cTOTP = col("login_totp", "otpauth", "totp")
        let cFolder = col("folder", "grouping", "group")
        let cFav = col("favorite", "favourite", "fav")
        let cType = col("type")
        let cTags = col("tags")
        let cChanged = col("timepasswordchanged")
        var items: [VaultItem] = [], folders: Set<String> = [], skipped = 0
        for r in rows {
            func v(_ c: Int?) -> String { c.flatMap { $0 < r.count ? r[$0] : nil }?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "" }
            let type = v(cType).lowercased()
            let isNote = type == "note" || type == "securenote"
            let url = v(cURL), user = v(cUser), pass = v(cPass)
            if !isNote && url.isEmpty && user.isEmpty && pass.isEmpty { skipped += 1; continue }
            var title = v(cTitle)
            if title.isEmpty { title = VaultItem.domain(url) ?? (url.isEmpty ? "Imported item" : url) }
            var item = VaultItem(kind: isNote ? .secureNote : .login, title: title)
            item.username = user
            item.password = pass
            if !url.isEmpty { item.urls = url.split(separator: "\n").map { String($0).trimmingCharacters(in: .whitespaces) } }
            item.notes = v(cNotes)
            let t = v(cTOTP); if !t.isEmpty { item.totpSecret = t }
            let fav = v(cFav).lowercased(); item.favourite = fav == "1" || fav == "true" || fav == "yes"
            let tags = v(cTags); if !tags.isEmpty { item.tags = tags.split(whereSeparator: { $0 == ";" || $0 == "," }).map { $0.trimmingCharacters(in: .whitespaces) } }
            if let ms = Double(v(cChanged)), ms > 0 { item.passwordModified = Date(timeIntervalSince1970: ms / 1000) }
            let folder = v(cFolder)
            if !folder.isEmpty { folders.insert(folder); item.tags.append("folder:" + folder) }
            items.append(item)
        }
        rows = []
        return Result(source: source, items: items, folders: folders.sorted(), skipped: skipped)
    }

    /// Converts `folder:` tags created by `parse` into real folders in the vault meta.
    public static func applyFolders(_ result: Result, into meta: inout VaultMeta) -> [VaultItem] {
        var byName = Dictionary(meta.folders.map { ($0.name, $0.id) }, uniquingKeysWith: { a, _ in a })
        for name in result.folders where byName[name] == nil {
            let f = VaultFolder(name: name); meta.folders.append(f); byName[name] = f.id
        }
        return result.items.map { i in
            var i = i
            if let t = i.tags.first(where: { $0.hasPrefix("folder:") }) { i.folderID = byName[String(t.dropFirst(7))]; i.tags.removeAll { $0 == t } }
            return i
        }
    }
}

/// Password-protected export file (`.rpexport`): "RAMPEXP\0" | version u16 | iterations u32 | salt 16 |
/// AES-256-GCM(JSON items), with the header bytes as AAD. Key: PBKDF2-HMAC-SHA256 from the export password.
public enum EncryptedExport {
    static let magic = Data("RAMPEXP\0".utf8)
    struct Payload: Codable { var exported: Date; var items: [VaultItem]; var folders: [VaultFolder] }

    public static func export(items: [VaultItem], folders: [VaultFolder], password: String, iterations: Int? = nil) throws -> Data {
        let iters = iterations ?? VaultCrypto.calibrateIterations()
        let salt = SecureRandom.data(16)
        var head = magic
        head.append(VaultFile.be16(1)); head.append(VaultFile.be32(UInt32(iters))); head.append(salt)
        let key = VaultCrypto.pbkdf2(password: password, salt: salt, iterations: iters)
        defer { key.wipe() }
        var plain = try VaultFile.encoder.encode(Payload(exported: Date(), items: items, folders: folders))
        defer { secureZero(&plain) }
        guard let sealed = try AES.GCM.seal(plain, using: VaultCrypto.symmetric(key), authenticating: head).combined else { throw VaultError.badFormat("seal") }
        return head + sealed
    }

    public static func `import`(_ data: Data, password: String) throws -> (items: [VaultItem], folders: [VaultFolder]) {
        let d = Data(data)
        guard d.count > 30, d.prefix(8) == magic else { throw VaultError.badFormat("not a RamPart export") }
        let version = Int(d[8]) << 8 | Int(d[9])
        guard version == 1 else { throw VaultError.unsupportedVersion(version) }
        let iters = Int(d[10]) << 24 | Int(d[11]) << 16 | Int(d[12]) << 8 | Int(d[13])
        guard iters >= 1000 else { throw VaultError.badFormat("bad parameters") }
        let head = d.prefix(30), salt = d.subdata(in: 14..<30)
        let key = VaultCrypto.pbkdf2(password: password, salt: salt, iterations: iters)
        defer { key.wipe() }
        var plain: Data
        do { plain = try AES.GCM.open(AES.GCM.SealedBox(combined: d.suffix(from: 30)), using: VaultCrypto.symmetric(key), authenticating: head) }
        catch { throw VaultError.wrongPassword }
        defer { secureZero(&plain) }
        let p = try VaultFile.decoder.decode(Payload.self, from: plain)
        return (p.items, p.folders)
    }
}
