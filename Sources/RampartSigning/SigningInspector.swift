import Foundation
import Security
import RampartShared

/// Full signing verdict. `info` is the shared-contract summary; the rest is extra detail for scoring and UI.
public struct SigningReport: Codable, Hashable, Sendable {
    public var path: String
    public var info: SigningInfo
    public var cdhash: String?
    public var isPlatformBinary: Bool
    public var codeFlags: UInt32
    public var certificateChain: [String]      // leaf first, common names
    public var validationError: Int32          // OSStatus of the validity check (0 = valid)
    public var bundleIdentifier: String?
    /// Signed with a certificate that doesn't chain to Apple (self-signed / enterprise). Status is `.unknown`.
    public var otherCertificate: Bool

    public init(path: String, info: SigningInfo, cdhash: String? = nil, isPlatformBinary: Bool = false, codeFlags: UInt32 = 0,
                certificateChain: [String] = [], validationError: Int32 = 0, bundleIdentifier: String? = nil,
                otherCertificate: Bool = false) {
        self.path = path; self.info = info; self.cdhash = cdhash; self.isPlatformBinary = isPlatformBinary
        self.codeFlags = codeFlags; self.certificateChain = certificateChain; self.validationError = validationError
        self.bundleIdentifier = bundleIdentifier; self.otherCertificate = otherCertificate
    }
    /// True when SigningInfo.status is a trusted, Apple-vetted state (platform, App Store, notarized Developer ID).
    public var isTrusted: Bool {
        switch info.status {
        case .apple, .appStore: return true
        case .developerID: return info.notarized == true
        default: return false
        }
    }
    /// Entitlements that matter for heuristics.
    public var riskyEntitlements: [String] { info.entitlements.filter { SigningInspector.riskyEntitlementKeys.contains($0) } }
    /// Signature identifier doesn't match the bundle ID (repackaged apps).
    public var identifierMismatch: Bool {
        guard let b = bundleIdentifier, let s = info.signingID, info.status != .adHoc else { return false }
        return b != s
    }
}

public enum SigningInspector {
    public struct Options: Sendable {
        /// Validate bundle resources (slow for large apps, catches tampered resources).
        public var validateResources = true
        /// Validate nested code (frameworks/helpers). Slow; off by default.
        public var checkNestedCode = false
        /// Allow online checks (revocation / notarization ticket lookup). Off = local only.
        public var allowNetwork = false
        public init(validateResources: Bool = true, checkNestedCode: Bool = false, allowNetwork: Bool = false) {
            self.validateResources = validateResources; self.checkNestedCode = checkNestedCode; self.allowNetwork = allowNetwork
        }
        public static let standard = Options()
        public static let fast = Options(validateResources: false)
    }

    static let riskyEntitlementKeys: Set<String> = [
        "com.apple.security.get-task-allow",
        "com.apple.security.cs.disable-library-validation",
        "com.apple.security.cs.allow-dyld-environment-variables",
        "com.apple.security.cs.allow-unsigned-executable-memory",
        "com.apple.security.cs.disable-executable-page-protection",
        "com.apple.security.cs.debugger",
    ]

    // Requirements compiled once.
    private static func req(_ s: String) -> SecRequirement? {
        var r: SecRequirement?
        return SecRequirementCreateWithString(s as CFString, [], &r) == errSecSuccess ? r : nil
    }
    nonisolated(unsafe) static let reqApple = req("anchor apple")
    nonisolated(unsafe) static let reqAppStore = req("anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.9] exists")
    nonisolated(unsafe) static let reqDeveloperID = req("anchor apple generic and certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists")
    nonisolated(unsafe) static let reqAppleGeneric = req("anchor apple generic")
    nonisolated(unsafe) static let reqNotarized = req("notarized")

    /// Shared cache keyed by path + inode + size + mtime/ctime.
    public static let cache = SigningCache<SigningReport>(capacity: 20_000)

    /// Cached inspection (Options.standard). Use for scanning.
    public static func inspectCached(path: String) -> SigningReport {
        cache.value(for: cacheTarget(path)) { inspect(path: path) }
    }

    /// Inspect a file or bundle on disk.
    public static func inspect(path: String, options: Options = .standard) -> SigningReport {
        var empty = SigningReport(path: path, info: SigningInfo(status: .unknown), cdhash: nil, isPlatformBinary: false,
                                  codeFlags: 0, certificateChain: [], validationError: 0,
                                  bundleIdentifier: nil, otherCertificate: false)
        var code: SecStaticCode?
        let st = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard st == errSecSuccess, let sc = code else {
            empty.validationError = st
            empty.info.status = st == errSecCSUnsigned ? .unsigned : .unknown
            return empty
        }
        var flags: UInt32 = kSecCSCheckAllArchitectures | kSecCSStrictValidate
        if !options.validateResources { flags |= kSecCSDoNotValidateResources }
        if options.checkNestedCode { flags |= kSecCSCheckNestedCode }
        if !options.allowNetwork { flags |= 1 << 29 /* kSecCSNoNetworkAccess */ }
        let cs = SecCSFlags(rawValue: flags)
        var err: Unmanaged<CFError>?
        let valid = SecStaticCodeCheckValidityWithErrors(sc, cs, nil, &err)
        err?.release()
        return classify(path: path, staticCode: sc, validity: valid) { r in
            SecStaticCodeCheckValidity(sc, cs, r)
        }
    }

    /// Inspect a running process via the kernel's view of its code (SecCodeCopyGuestWithAttributes).
    /// Other users' processes need root. Returns nil if the pid is gone or not accessible.
    public static func inspect(pid: pid_t) -> SigningReport? {
        var code: SecCode?
        let attrs = [kSecGuestAttributePid: NSNumber(value: pid)] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &code) == errSecSuccess, let dc = code else { return nil }
        var path = ""
        var sc: SecStaticCode?
        if SecCodeCopyStaticCode(dc, [], &sc) == errSecSuccess, let s = sc {
            var url: CFURL?
            if SecCodeCopyPath(s, [], &url) == errSecSuccess, let u = url { path = (u as URL).path }
        }
        let valid = SecCodeCheckValidity(dc, [], nil)
        // A SecCode is accepted wherever a SecStaticCode is (documented); the CF types are toll-free here.
        let asStatic = unsafeBitCast(dc, to: SecStaticCode.self)
        var report = classify(path: path, staticCode: asStatic, validity: valid, dynamic: true) { r in
            SecCodeCheckValidity(dc, [], r)
        }
        // The kernel status word: CS_VALID (0x1) cleared means the running image was invalidated.
        do {
            var info: CFDictionary?
            if SecCodeCopySigningInformation(asStatic, SecCSFlags(rawValue: kSecCSDynamicInformation), &info) == errSecSuccess,
               let d = info as? [String: Any], let status = d[kSecCodeInfoStatus as String] as? NSNumber,
               report.info.status != .unsigned, status.uint32Value & 0x1 == 0 {
                report.info.status = .invalid
            }
        }
        return report
    }

    // MARK: - Classification

    private static func classify(path: String, staticCode sc: SecStaticCode, validity: OSStatus, dynamic: Bool = false,
                                 check: (SecRequirement?) -> OSStatus) -> SigningReport {
        var report = SigningReport(path: path, info: SigningInfo(status: .unknown), cdhash: nil, isPlatformBinary: false,
                                   codeFlags: 0, certificateChain: [], validationError: validity,
                                   bundleIdentifier: nil, otherCertificate: false)
        var infoRef: CFDictionary?
        let infoFlags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        if SecCodeCopySigningInformation(sc, infoFlags, &infoRef) == errSecSuccess, let d = infoRef as? [String: Any] {
            report.info.signingID = d[kSecCodeInfoIdentifier as String] as? String
            report.info.teamID = d[kSecCodeInfoTeamIdentifier as String] as? String
            report.codeFlags = (d[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
            report.info.hardenedRuntime = report.codeFlags & 0x10000 /* kSecCodeSignatureRuntime */ != 0
            if let u = d[kSecCodeInfoUnique as String] as? Data { report.cdhash = u.map { String(format: "%02x", $0) }.joined() }
            if let ent = d[kSecCodeInfoEntitlementsDict as String] as? [String: Any] { report.info.entitlements = ent.keys.sorted() }
            if let plat = d[kSecCodeInfoPlatformIdentifier as String] as? NSNumber, plat.intValue != 0 { report.isPlatformBinary = true }
            if let certs = d[kSecCodeInfoCertificates as String] as? [SecCertificate] {
                report.certificateChain = certs.map { c in
                    var cn: CFString?
                    SecCertificateCopyCommonName(c, &cn)
                    return (cn as String?) ?? "?"
                }
            }
            if let plist = d[kSecCodeInfoPList as String] as? [String: Any] {
                report.bundleIdentifier = plist["CFBundleIdentifier"] as? String
            }
        }
        if report.info.teamID == nil, report.info.signingID == nil, report.codeFlags == 0, report.cdhash == nil, validity == errSecCSUnsigned {
            report.info.status = .unsigned
            return report
        }

        switch validity {
        case errSecSuccess: break
        case errSecCSUnsigned:
            report.info.status = .unsigned; return report
        case errSecCSRevokedNotarization, OSStatus(CSSMERR_TP_CERT_REVOKED):
            report.info.status = .revoked; return report
        default:
            report.info.status = .invalid; return report
        }

        if report.codeFlags & 0x2 /* kSecCodeSignatureAdhoc */ != 0 || report.certificateChain.isEmpty {
            report.info.status = report.isPlatformBinary ? .apple : .adHoc
            return report
        }
        if check(reqApple) == errSecSuccess {
            report.info.status = .apple
            return report
        }
        if check(reqAppStore) == errSecSuccess {
            report.info.status = .appStore
            return report
        }
        if check(reqDeveloperID) == errSecSuccess {
            report.info.status = .developerID
            let n = check(reqNotarized)
            if n == errSecCSRevokedNotarization { report.info.status = .revoked; report.info.notarized = false }
            else { report.info.notarized = n == errSecSuccess }
            return report
        }
        if check(reqAppleGeneric) == errSecSuccess {
            // Apple-issued but neither App Store nor Developer ID (e.g. Apple Development / TestFlight).
            report.info.status = .developerID
            report.info.notarized = check(reqNotarized) == errSecSuccess
            return report
        }
        report.otherCertificate = true   // self-signed or untrusted chain
        report.info.status = .unknown
        return report
    }

    /// For bundles, cache on the main executable (bundle dir mtime doesn't change when the binary is swapped).
    static func cacheTarget(_ path: String) -> String {
        if path.hasSuffix(".app") || path.hasSuffix(".app/") || path.hasSuffix(".bundle") || path.hasSuffix(".framework")
            || path.hasSuffix(".xpc") || path.hasSuffix(".appex") || path.hasSuffix(".systemextension") {
            if let exe = Bundle(path: path)?.executablePath { return exe }
        }
        return path
    }
}
