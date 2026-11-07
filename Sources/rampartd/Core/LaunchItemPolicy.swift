import Foundation
import Security
import RampartShared
import RampartBehaviour

/// False-positive policy for launch items (user report: RamPart's own plists and the user's own agents flagged as
/// "Suspicious login item").
/// - RamPart's own plists are exempt only when Program/ProgramArguments[0] is one of our installed binaries AND that
///   binary verifies (strict signature, our identifier, and a trusted Team ID or a pinned/own cdhash). Never by label.
/// - A user's own LaunchAgent with no real malicious signal becomes a note ("New login item: review"), not a threat.
enum LaunchItemPolicy {
    static let ownIdentifiers: Set<String> = ["app.rampart.daemon", "app.rampart.agent", "app.rampart.app", "app.rampart.cli",
                                              "app.rampart.watchdog", "app.rampart.sentinel"]
    static let ownBinaryPrefixes = ["/Library/PrivilegedHelperTools/app.rampart.", "/Applications/RamPart.app/Contents/", "/Applications/Rampart.app/Contents/"]

    struct Signature { var identifier: String; var teamID: String?; var cdhash: String; var valid: Bool }

    static func signature(of path: String) -> Signature? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else { return nil }
        let valid = SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate), nil) == errSecSuccess
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
              let d = info as? [String: Any] else { return nil }
        let cd = (d[kSecCodeInfoUnique as String] as? Data).map { $0.map { String(format: "%02x", $0) }.joined() } ?? ""
        return Signature(identifier: d[kSecCodeInfoIdentifier as String] as? String ?? "", teamID: d[kSecCodeInfoTeamIdentifier as String] as? String,
                         cdhash: cd, valid: valid && !cd.isEmpty)
    }

    /// cdhashes we trust for our own binaries: the running daemon's own, install-time pins and the install identity.
    static func trustedCDHashes(root: URL) -> Set<String> {
        var out = Set<String>()
        if let me = signature(of: URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath().path), me.valid { out.insert(me.cdhash) }
        if let pins = ClientIdentity.loadPins(root.appendingPathComponent("trusted-clients.json").path) { out.formUnion(pins) }
        let idPath = root.appendingPathComponent("install-identity.plist").path
        var st = stat()
        if lstat(idPath, &st) == 0, st.st_uid == 0, st.st_mode & 0o022 == 0,
           let d = FileManager.default.contents(atPath: idPath),
           let pl = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] {
            for k in ["appCDHash", "daemonCDHash"] {
                for part in (pl[k] as? String ?? "").split(separator: ",") { out.insert(String(part.split(separator: "=").last ?? "").lowercased()) }
            }
        }
        return out
    }

    /// Our own installed binary, verified (not just named like ours).
    static func isVerifiedOwnBinary(_ path: String, trustedCDHashes: Set<String>, ownTeamID: String?) -> Bool {
        let p = (path as NSString).standardizingPath
        guard ownBinaryPrefixes.contains(where: { p.hasPrefix($0) }), let s = signature(of: p), s.valid,
              ownIdentifiers.contains(s.identifier) || s.identifier.hasPrefix("app.rampart.") else { return false }
        if let t = ownTeamID, !t.isEmpty, s.teamID == t { return true }
        return trustedCDHashes.contains(s.cdhash.lowercased())
    }

    /// A launchd plist of ours whose program is our verified binary.
    static func isGenuineOwnPlist(_ plist: String, trustedCDHashes: Set<String>, ownTeamID: String?) -> Bool {
        let kind: PersistenceItem.Kind = plist.contains("/LaunchDaemons/") ? .launchDaemon : .launchAgent
        guard let r = PersistenceScanner.parseLaunchdPlist(path: plist, kind: kind) else { return false }
        guard let exe = r.item.target ?? r.arguments.first else { return false }
        return isVerifiedOwnBinary(exe, trustedCDHashes: trustedCDHashes, ownTeamID: ownTeamID)
    }

    // MARK: user agents

    static let maliciousArg = try! NSRegularExpression(pattern: #"(?i)(curl|wget)\b[^|;]*\|\s*(ba|z)?sh\b|\bbase64\s+(-d|--decode|-D)\b|\bosascript\s+-e\b|\beval\b|\bpython3?\s+-c\b|\bperl\s+-e\b|\bnohup\b|\bnc\s+-|/dev/tcp/|\bmkfifo\b|\\x[0-9a-f]{2}"#)

    /// True when a LaunchAgent in the user's own Library looks like ordinary user automation: no hidden path, no
    /// download-and-run or obfuscated arguments, no program in a temp folder, and the program isn't unsigned in /tmp.
    static func isBenignUserAgent(plist: String, target: String?, arguments: [String], home: String) -> Bool {
        guard plist.hasPrefix(home + "/Library/LaunchAgents/") else { return false }
        let exe = target ?? arguments.first ?? ""
        let all = ([exe] + arguments).joined(separator: " ")
        let tempRoots = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/private/var/folders/", "/Users/Shared/"]
        if tempRoots.contains(where: { all.contains($0) }) { return false }
        // Hidden path components (".something") in the program or arguments, except the usual dot-folders of tools.
        let allowedDot: Set<String> = [".local", ".nvm", ".pyenv", ".rbenv", ".cargo", ".deno", ".bun", ".config", ".venv", ".npm-global", ".volta"]
        for comp in all.split(whereSeparator: { $0 == "/" || $0 == " " }) where comp.hasPrefix(".") && comp.count > 1 && comp != ".." {
            if !allowedDot.contains(String(comp)) { return false }
        }
        if maliciousArg.firstMatch(in: all, range: NSRange(location: 0, length: (all as NSString).length)) != nil { return false }
        if all.count > 4000 { return false }
        return true
    }

    // MARK: login items (Background Task Management)

    enum LoginItemVerdict: Equatable {
        /// Real malicious indicators (each a plain sentence).
        case threat([String])
        /// A new login item worth knowing about, not a threat.
        case note(String)
        /// The program couldn't be identified (`btm:<uid>:<uuid>` with no path).
        case unresolved
    }

    static let tempRoots = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/var/folders/", "/private/var/folders/", "/Users/Shared/"]
    static let allowedDot: Set<String> = [".local", ".nvm", ".pyenv", ".rbenv", ".cargo", ".deno", ".bun", ".config", ".venv", ".npm-global", ".volta"]

    /// Human name for a login item: its BTM name unless that is just an id, else the app or program name.
    static func displayName(label: String, target: String?) -> String {
        let uuidLike = label.range(of: #"^[0-9A-Fa-f-]{32,36}$"#, options: .regularExpression) != nil
        if !label.isEmpty, !uuidLike, !label.hasPrefix("btm:") { return label }
        guard let t = target else { return "Unidentified login item" }
        if let r = t.range(of: ".app", options: .backwards) { return ((String(t[..<r.lowerBound])) as NSString).lastPathComponent }
        return (t as NSString).lastPathComponent
    }

    /// Only real malicious indicators make a login item a threat: hidden or obfuscated, running from a temp folder or
    /// Downloads, download-and-run arguments, an unsigned program in an odd location, a revoked signature, or a
    /// `com.apple.` name on code Apple didn't sign. Signed and notarized developers and the user's own scripts in their
    /// home folder are notes.
    static func assessLoginItem(label: String, target: String?, arguments: [String], home: String, signing: SigningInfo?) -> LoginItemVerdict {
        guard let exe = target, exe.hasPrefix("/") else { return .unresolved }
        let p = exe.hasPrefix("/tmp/") ? "/private" + exe : exe
        let all = ([exe] + arguments).joined(separator: " ")
        var bad: [String] = []
        if tempRoots.contains(where: { all.contains($0) }) { bad.append("runs from a temporary or shared folder") }
        if p.contains("/Downloads/") { bad.append("runs from Downloads") }
        if all.split(whereSeparator: { $0 == "/" || $0 == " " }).contains(where: { $0.hasPrefix(".") && $0.count > 1 && $0 != ".." && !allowedDot.contains(String($0)) }) {
            bad.append("hidden path")
        }
        if maliciousArg.firstMatch(in: all, range: NSRange(location: 0, length: (all as NSString).length)) != nil || all.count > 4000 {
            bad.append("downloads and runs code, or uses obfuscated arguments")
        }
        let status = signing?.status
        if status == .revoked { bad.append("Apple revoked its signature") }
        let normalPlace = ["/Applications/", "/System/", "/usr/", "/opt/homebrew/", "/opt/local/", "/Library/Application Support/"].contains { p.hasPrefix($0) }
            || (p.hasPrefix(home + "/") && !p.contains("/Downloads/"))
        if [.unsigned, .adHoc, .invalid].contains(status), !normalPlace { bad.append("unsigned program in an unusual location") }
        let appleName = label.lowercased().hasPrefix("com.apple.") || (signing?.signingID?.hasPrefix("com.apple.") == true)
        if appleName, status != nil, status != .apple { bad.append("uses an Apple name but isn't signed by Apple") }
        if !bad.isEmpty { return .threat(bad) }
        if let s = signing, s.status == .apple || s.status == .appStore || (s.status == .developerID && s.notarized == true) {
            return .note(s.status == .apple ? "signed by Apple" : "signed and notarized" + (s.teamID.map { " (team \($0))" } ?? ""))
        }
        if p.hasPrefix(home + "/") { return .note("your own program or script in your home folder") }
        return .note("new login item with no warning signs")
    }

    /// Applies the login-item verdict to a finding about a BTM / login item record.
    static func applyLoginItem(_ d: Detection, record r: PersistenceRecord, home: String, signing: SigningInfo?) -> Detection {
        let name = displayName(label: r.item.label, target: r.item.target)
        let signer = signing.map { s in s.teamID.map { "\(s.status.rawValue), team \($0)" } ?? s.status.rawValue } ?? "unknown"
        switch assessLoginItem(label: r.item.label, target: r.item.target, arguments: r.arguments, home: home, signing: signing) {
        case .unresolved:
            var n = asNote(d)
            n.name = "Login item (program unknown): \(name)"
            n.evidence.append(Evidence(source: .persistence, title: "Note", detail: "macOS lists this background item without a program path, so \(Product.name) can't check it. Not a threat decision.", score: 0))
            return n
        case .note(let why):
            var n = asNote(d)
            n.path = r.item.target ?? d.path
            n.name = "New login item: \(name)"
            n.evidence.append(Evidence(source: .persistence, title: "Note", detail: "\(name) runs \(r.item.target ?? "?") (signer: \(signer)); \(why). Not a threat decision.", score: 0))
            return n
        case .threat(let reasons):
            var t = d
            t.path = r.item.target ?? d.path
            t.name = "Login item with warning signs: \(name)"
            t.evidence.append(Evidence(source: .persistence, title: "Login item warning signs",
                                       detail: "\(name) runs \(r.item.target ?? "?") (signer: \(signer)): \(reasons.joined(separator: "; ")).",
                                       score: min(90, 60 + 10 * reasons.count)))
            var remain = 1.0
            for e in t.evidence { remain *= 1 - Double(min(100, max(0, e.score))) / 100 }
            t.confidence = max(t.confidence, Int((100 * (1 - remain)).rounded()))
            t.severity = max(t.severity, t.confidence >= 75 ? .high : .medium)
            return t
        }
    }

    /// The note version of a persistence finding (kept for "Review notes", not a decision).
    static func asNote(_ d: Detection) -> Detection {
        var n = d
        n.confidence = min(d.confidence, 25); n.severity = .low
        if !n.name.hasPrefix("New login item") { n.name = "New login item: review" }
        return n
    }
}
