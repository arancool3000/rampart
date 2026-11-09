import Foundation
import Darwin
import Security

// Download Gate: what kind of file arrived, and who signed it. Read-only Security.framework queries; nothing here
// can show UI (SecStaticCode and the Gatekeeper assessment never prompt).

/// What a downloaded item is, from its magic bytes (and name for containers).
public enum GateFileKind: String, Codable, Sendable, CaseIterable {
    case app          // .app bundle (directory)
    case machO        // Mach-O executable / dylib / bundle (thin or fat)
    case script       // starts with "#!"
    case archive      // zip / tar / gzip / bzip2 / xz / 7z / rar / xip
    case diskImage    // .dmg / .sparseimage
    case installer    // .pkg / .mpkg (xar)
    case document     // everything else

    /// Things that can run code when opened (Mach-O, scripts, apps).
    public var isCode: Bool { self == .app || self == .machO || self == .script }
    public var label: String {
        switch self {
        case .app: return "App"; case .machO: return "Program"; case .script: return "Script"; case .archive: return "Archive"
        case .diskImage: return "Disk image"; case .installer: return "Installer package"; case .document: return "File"
        }
    }

    public static func classify(path: String) -> GateFileKind {
        let lower = path.lowercased()
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else { return .document }
        if isDir.boolValue {
            if lower.hasSuffix(".app") { return .app }
            if lower.hasSuffix(".pkg") || lower.hasSuffix(".mpkg") { return .installer }
            return .document
        }
        let head = Self.head(path, 8)
        if head.count >= 4 {
            let be = UInt32(head[0]) << 24 | UInt32(head[1]) << 16 | UInt32(head[2]) << 8 | UInt32(head[3])
            // MH_MAGIC(_64), MH_CIGAM(_64), FAT_MAGIC(_64), FAT_CIGAM(_64)
            if [0xfeedface, 0xfeedfacf, 0xcefaedfe, 0xcffaedfe, 0xcafebabe, 0xcafebabf, 0xbebafeca, 0xbfbafeca].contains(be) {
                // 0xcafebabe is also a Java class file: those have a large minor/major version, fat headers a small arch count.
                if be == 0xcafebabe, head.count >= 8 {
                    let n = UInt32(head[4]) << 24 | UInt32(head[5]) << 16 | UInt32(head[6]) << 8 | UInt32(head[7])
                    if n > 30 { return .document }
                }
                return .machO
            }
        }
        if head.count >= 2, head[0] == 0x23, head[1] == 0x21 { return .script }   // "#!"
        if head.count >= 4, head[0] == 0x78, head[1] == 0x61, head[2] == 0x72, head[3] == 0x21 {  // "xar!"
            return lower.hasSuffix(".xip") ? .archive : .installer
        }
        for ext in [".dmg", ".sparseimage", ".sparsebundle"] where lower.hasSuffix(ext) { return .diskImage }
        if head.count >= 4, head[0] == 0x50, head[1] == 0x4b, head[2] == 0x03 || head[2] == 0x05, head[3] == 0x04 || head[3] == 0x06 { return .archive }
        if head.count >= 2, head[0] == 0x1f, head[1] == 0x8b { return .archive }                       // gzip
        if head.count >= 3, head[0] == 0x42, head[1] == 0x5a, head[2] == 0x68 { return .archive }      // bzip2
        if head.count >= 6, head[0] == 0xfd, head[1] == 0x37, head[2] == 0x7a, head[3] == 0x58 { return .archive }  // xz
        if head.count >= 6, head[0] == 0x37, head[1] == 0x7a, head[2] == 0xbc, head[3] == 0xaf { return .archive }  // 7z
        if head.count >= 4, head[0] == 0x52, head[1] == 0x61, head[2] == 0x72, head[3] == 0x21 { return .archive }  // rar
        for ext in [".zip", ".tar", ".tgz", ".tbz", ".txz", ".gz", ".bz2", ".xz", ".7z", ".rar"] where lower.hasSuffix(ext) { return .archive }
        for ext in [".command", ".tool", ".sh", ".zsh", ".bash", ".py", ".pl", ".rb"] where lower.hasSuffix(ext) {
            return Self.isExecutable(path) ? .script : .document
        }
        return .document
    }

    static func head(_ path: String, _ n: Int) -> [UInt8] {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return [] }
        defer { close(fd) }
        var buf = [UInt8](repeating: 0, count: n)
        let r = read(fd, &buf, n)
        return r > 0 ? Array(buf.prefix(r)) : []
    }

    static func isExecutable(_ path: String) -> Bool {
        var st = stat()
        return lstat(path, &st) == 0 && (st.st_mode & 0o111) != 0
    }
}

/// Signature verdict for a downloaded program or app.
public struct GateSignature: Codable, Hashable, Sendable {
    public enum Kind: String, Codable, Sendable {
        case unsigned, adHoc, invalid, revoked, apple, appStore, developerID, otherCertificate, notCode
    }
    public var kind: Kind
    public var teamID: String?
    public var signingID: String?
    /// nil = not checked / not applicable.
    public var notarized: Bool?
    /// Gatekeeper's own verdict (SecAssessment, execute operation). nil = not available.
    public var gatekeeperAccepted: Bool?
    public var detail: String = ""

    public init(kind: Kind, teamID: String? = nil, signingID: String? = nil, notarized: Bool? = nil,
                gatekeeperAccepted: Bool? = nil, detail: String = "") {
        self.kind = kind; self.teamID = teamID; self.signingID = signingID; self.notarized = notarized
        self.gatekeeperAccepted = gatekeeperAccepted; self.detail = detail
    }

    /// Clean + this ⇒ the execute bits come back. Apple / App Store, or a notarized Developer ID that Gatekeeper
    /// (when it could be asked) did not reject.
    public var isTrustedToRun: Bool {
        if gatekeeperAccepted == false { return false }
        switch kind {
        case .apple, .appStore: return true
        case .developerID: return notarized == true
        default: return false
        }
    }

    public var summary: String {
        switch kind {
        case .unsigned: return "Not signed"
        case .adHoc: return "Ad-hoc signed (no developer identity)"
        case .invalid: return "Signature is broken or the file was modified"
        case .revoked: return "Apple revoked this developer's certificate"
        case .apple: return "Signed by Apple"
        case .appStore: return "From the App Store"
        case .developerID:
            return "Developer ID\(teamID.map { " (\($0))" } ?? "")" + (notarized == true ? ", notarized by Apple" : ", not notarized")
        case .otherCertificate: return "Signed with a certificate Apple doesn't vouch for"
        case .notCode: return "Not a program"
        }
    }
}

/// Read-only signature checks. Injectable so selftests never depend on the network or on Gatekeeper's database.
public protocol DownloadGateSigning: Sendable {
    func assess(path: String, kind: GateFileKind) -> GateSignature
}

/// Security.framework implementation: SecStaticCode validity + designated Apple requirements + the "notarized"
/// requirement (stapled ticket, else Apple's online ticket lookup), and for .app bundles the Gatekeeper assessment.
public struct SecDownloadGateSigning: DownloadGateSigning {
    public var allowNetwork: Bool
    public var useGatekeeperAssessment: Bool
    public init(allowNetwork: Bool = true, useGatekeeperAssessment: Bool = true) {
        self.allowNetwork = allowNetwork; self.useGatekeeperAssessment = useGatekeeperAssessment
    }

    private static func req(_ s: String) -> SecRequirement? {
        var r: SecRequirement?
        return SecRequirementCreateWithString(s as CFString, [], &r) == errSecSuccess ? r : nil
    }
    nonisolated(unsafe) static let reqApple = req("anchor apple")
    nonisolated(unsafe) static let reqAppStore = req("anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists")
    nonisolated(unsafe) static let reqDeveloperID = req("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists")
    nonisolated(unsafe) static let reqNotarized = req("notarized")

    public func assess(path: String, kind: GateFileKind) -> GateSignature {
        guard kind == .app || kind == .machO else {
            return GateSignature(kind: kind == .script ? .unsigned : .notCode, detail: kind == .script ? "Scripts can't carry a code signature" : "")
        }
        var code: SecStaticCode?
        let st = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard st == errSecSuccess, let sc = code else {
            return GateSignature(kind: st == errSecCSUnsigned ? .unsigned : .invalid, detail: "SecStaticCodeCreateWithPath \(st)")
        }
        var flags: UInt32 = kSecCSCheckAllArchitectures | kSecCSStrictValidate
        if kind == .app { flags |= kSecCSCheckNestedCode }
        if !allowNetwork { flags |= 1 << 29 }   // kSecCSNoNetworkAccess
        let cs = SecCSFlags(rawValue: flags)
        var err: Unmanaged<CFError>?
        let valid = SecStaticCodeCheckValidityWithErrors(sc, cs, nil, &err)
        err?.release()
        var info: CFDictionary?
        var teamID: String?, signingID: String?, codeFlags: UInt32 = 0
        if SecCodeCopySigningInformation(sc, SecCSFlags(rawValue: kSecCSSigningInformation), &info) == errSecSuccess,
           let d = info as? [String: Any] {
            teamID = d[kSecCodeInfoTeamIdentifier as String] as? String
            signingID = d[kSecCodeInfoIdentifier as String] as? String
            codeFlags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        }
        if valid == errSecCSUnsigned { return GateSignature(kind: .unsigned) }
        if valid == errSecCSRevokedNotarization {
            return GateSignature(kind: .revoked, teamID: teamID, signingID: signingID, notarized: false, detail: "status \(valid)")
        }
        guard valid == errSecSuccess else {
            return GateSignature(kind: .invalid, teamID: teamID, signingID: signingID, detail: "validity \(valid)")
        }
        if codeFlags & 0x0002 != 0 {   // kSecCodeSignatureAdhoc
            return GateSignature(kind: .adHoc, signingID: signingID)
        }
        func meets(_ r: SecRequirement?) -> OSStatus { r.map { SecStaticCodeCheckValidity(sc, cs, $0) } ?? errSecParam }
        var sig: GateSignature
        if meets(Self.reqApple) == errSecSuccess { sig = GateSignature(kind: .apple, teamID: teamID, signingID: signingID, notarized: true) }
        else if meets(Self.reqAppStore) == errSecSuccess { sig = GateSignature(kind: .appStore, teamID: teamID, signingID: signingID, notarized: true) }
        else if meets(Self.reqDeveloperID) == errSecSuccess {
            let n = meets(Self.reqNotarized)
            if n == errSecCSRevokedNotarization { return GateSignature(kind: .revoked, teamID: teamID, signingID: signingID, notarized: false) }
            sig = GateSignature(kind: .developerID, teamID: teamID, signingID: signingID, notarized: n == errSecSuccess)
        } else { sig = GateSignature(kind: .otherCertificate, teamID: teamID, signingID: signingID) }
        if kind == .app && useGatekeeperAssessment { sig.gatekeeperAccepted = GatekeeperAssessment.execute(path: path) }
        return sig
    }
}

/// Gatekeeper's verdict through Security.framework's SecAssessment (the API `spctl --assess` uses). The header
/// isn't in the Command Line Tools SDK, so the symbols are looked up at run time; nil when unavailable.
public enum GatekeeperAssessment {
    private typealias CreateFn = @convention(c) (CFURL, UInt32, CFDictionary?, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFTypeRef>?
    private typealias CopyResultFn = @convention(c) (CFTypeRef, UInt32, UnsafeMutablePointer<Unmanaged<CFError>?>?) -> Unmanaged<CFDictionary>?

    private static func constant(_ name: String) -> CFString? {
        guard let p = dlsym(UnsafeMutableRawPointer(bitPattern: -2), name) else { return nil }   // RTLD_DEFAULT
        return p.assumingMemoryBound(to: CFString?.self).pointee
    }

    /// true = accepted, false = rejected, nil = the API isn't reachable.
    public static func execute(path: String) -> Bool? {
        let rtldDefault = UnsafeMutableRawPointer(bitPattern: -2)
        guard let c = dlsym(rtldDefault, "SecAssessmentCreate"), let r = dlsym(rtldDefault, "SecAssessmentCopyResult"),
              let opKey = constant("kSecAssessmentContextKeyOperation"), let opExec = constant("kSecAssessmentOperationTypeExecute"),
              let verdictKey = constant("kSecAssessmentAssessmentVerdict") else { return nil }
        let create = unsafeBitCast(c, to: CreateFn.self)
        let copyResult = unsafeBitCast(r, to: CopyResultFn.self)
        let ctx = [opKey: opExec] as CFDictionary
        var err: Unmanaged<CFError>?
        guard let a = create(URL(fileURLWithPath: path) as CFURL, 0, ctx, &err) else { err?.release(); return false }
        let assessment = a.takeRetainedValue()
        guard let res = copyResult(assessment, 0, nil)?.takeRetainedValue() as? [String: Any] else { return nil }
        return (res[verdictKey as String] as? NSNumber)?.boolValue
    }
}
