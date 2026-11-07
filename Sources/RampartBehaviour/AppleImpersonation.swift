import Foundation
import RampartShared

/// Apple impersonation: code or launch items that *look* like Apple (com.apple.* identifiers,
/// "Software Update", "XProtect", "iCloud"...) but are not Apple-signed, or live outside SIP-protected
/// locations. Pure function over facts the caller already has (SigningInfo / isPlatformBinary).
public enum AppleImpersonation {
    /// Exact names of Apple system processes/apps that malware likes to borrow (lowercased, no extension).
    public static let appleProcessNames: Set<String> = [
        "softwareupdated", "softwareupdate", "software update", "xprotect", "xprotectservice", "xprotectremediator",
        "xprotectupdater", "mrt", "applemobiledeviceservice", "icloud", "icloudhelper", "cloudd", "bird", "nsurlsessiond",
        "trustd", "syspolicyd", "launchd", "kernel_task", "windowserver", "loginwindow", "finder", "dock", "systemuiserver",
        "coreservicesd", "mdworker", "mds", "mds_stores", "analyticsd", "apsd", "accountsd", "securityd", "keychain access",
        "system preferences", "system settings", "safari", "mail", "contacts", "apple", "appleid", "app store", "itunes",
        "itunes helper", "itunehelper", "gatekeeper", "com.apple.updater", "spotlight", "siri", "findmy", "find my",
    ]
    /// Tokens that make a name Apple-ish when combined with others ("Apple Security Update", "iCloud-Sync").
    public static let appleTokens = ["apple", "icloud", "itunes", "xprotect", "appstore", "app store", "macos update",
                                      "software update", "softwareupdate", "gatekeeper", "appleid", "siri", "safari update"]

    /// SIP-protected (or Apple-only) roots. Apple code legitimately lives under these.
    public static let protectedRoots = ["/System/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/lib/", "/bin/", "/sbin/",
                                        "/Library/Apple/", "/private/var/db/com.apple.xpc.roleaccountd.staging/", "/Library/Developer/CommandLineTools/",
                                        "/Applications/Safari.app/", "/Library/Application Support/Apple/"]
    /// Places Apple-signed (App Store / Apple software) apps may also live outside SIP.
    public static let appleAppRoots = ["/Applications/", "/System/Applications/", "/Library/Apple/", "/Library/Printers/", "/Library/Developer/"]

    public static func isProtectedPath(_ p: String) -> Bool { protectedRoots.contains { p.hasPrefix($0) } }

    public struct Subject: Sendable {
        public var path: String
        public var name: String?          // process / bundle display name
        public var bundleID: String?
        public var signingID: String?
        public var label: String?          // launchd Label
        public var isLaunchItem: Bool
        public var signing: SigningInfo?
        public var isPlatformBinary: Bool
        public init(path: String, name: String? = nil, bundleID: String? = nil, signingID: String? = nil, label: String? = nil,
                    isLaunchItem: Bool = false, signing: SigningInfo? = nil, isPlatformBinary: Bool = false) {
            self.path = path; self.name = name; self.bundleID = bundleID; self.signingID = signingID; self.label = label
            self.isLaunchItem = isLaunchItem; self.signing = signing; self.isPlatformBinary = isPlatformBinary
        }
    }

    /// What makes the subject Apple-looking, strongest first; nil if nothing does.
    public static func appleLook(_ s: Subject) -> (strong: Bool, why: String)? {
        for (k, v) in [("bundle ID", s.bundleID), ("signing ID", s.signingID), ("launchd label", s.label)] {
            if let v = v?.lowercased(), v.hasPrefix("com.apple.") || v == "com.apple" { return (true, "\(k) \(v)") }
        }
        let base = ((s.name ?? (s.path as NSString).lastPathComponent) as NSString).deletingPathExtension
        let norm = fold(base)
        if appleProcessNames.contains(norm) { return (true, "name \"\(base)\" copies an Apple system component") }
        if let t = appleTokens.first(where: { tok in
            guard let r = norm.range(of: tok) else { return false }
            let before = r.lowerBound == norm.startIndex ? nil : norm[norm.index(before: r.lowerBound)]
            if let b = before, b.isLetter { return false }                    // "pineapple"
            return !norm[r.lowerBound...].hasPrefix("applet") && !norm[r.lowerBound...].hasPrefix("applesauce")
        }) { return (false, "name \"\(base)\" contains \"\(t)\"") }
        // Folder disguise: ~/Library/Apple/..., /tmp/com.apple.x/...
        if let comp = s.path.split(separator: "/").map(String.init).dropLast().last(where: { $0.lowercased().hasPrefix("com.apple.") || fold($0) == "apple" }),
           !isProtectedPath(s.path) {
            return (false, "folder \"\(comp)\" imitates Apple")
        }
        return nil
    }

    /// Folds homoglyphs/separators so "App1e", "Аpple" (Cyrillic), "Software_Update" match.
    static func fold(_ s: String) -> String {
        var t = s.lowercased().replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        let map: [Character: Character] = ["а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "і": "i", "ӏ": "l", "1": "l", "0": "o", "ı": "i", "ⅼ": "l"]
        t = String(t.map { map[$0] ?? $0 })
        // "app1e" -> "apple" after map; collapse "app le", "i cloud"
        for (a, b) in [("app le", "apple"), ("i cloud", "icloud"), ("x protect", "xprotect")] { t = t.replacingOccurrences(of: a, with: b) }
        return t.trimmingCharacters(in: .whitespaces)
    }

    public static func isAppleSigned(_ s: Subject) -> Bool {
        if s.isPlatformBinary { return true }
        if s.signing?.status == .apple { return true }
        return false
    }

    /// Evidence (score >= 80 for strong impersonation by non-Apple code), or nil.
    public static func assess(_ s: Subject) -> Evidence? {
        guard let look = appleLook(s) else { return nil }
        let signed = isAppleSigned(s)
        let status = s.isPlatformBinary ? "Apple platform binary" : (s.signing?.status.rawValue ?? "unknown signature")
        let where_ = isProtectedPath(s.path) ? "a protected system folder" : "\((s.path as NSString).deletingLastPathComponent)"
        if !signed {
            // Unknown signing (nil) is not proof of anything: score as weaker unless it's in a user-writable place.
            let unknown = s.signing == nil || s.signing?.status == .unknown
            if unknown && isProtectedPath(s.path) { return nil }
            var score: Int
            if look.strong { score = 85 } else {
                switch s.signing?.status {
                case .developerID?, .appStore?: score = (s.signing?.notarized ?? false) ? 35 : 55   // third-party "iCloud backup" tools exist
                default: score = 80
                }
            }
            if s.isLaunchItem && look.strong { score = 88 }
            if unknown && !look.strong { score = min(score, 60) }
            return Evidence(source: .signing, title: "Pretends to be Apple",
                            detail: "\(look.why), but it is not signed by Apple (\(status)) and lives in \(where_): \(s.path)", score: score)
        }
        // Apple-signed: only a launch item or binary copied out of the protected area is odd (LOLBin masquerade).
        if !isProtectedPath(s.path) && !appleAppRoots.contains(where: { s.path.hasPrefix($0) }) {
            return Evidence(source: .signing, title: "Apple component outside system folders",
                            detail: "\(look.why); Apple-signed code normally runs from SIP-protected folders, but this copy is at \(s.path).", score: s.isLaunchItem ? 50 : 40)
        }
        return nil
    }

    public static func assess(process p: ProcessInfoLite, signing: SigningInfo? = nil) -> Evidence? {
        assess(Subject(path: p.path, signingID: p.signingID, signing: signing, isPlatformBinary: p.isPlatformBinary))
    }

    /// Launch item: the plist is Apple-looking by label; the *target* signing decides.
    public static func assess(item: PersistenceItem, targetIsPlatform: Bool = false) -> Evidence? {
        guard item.kind == .launchAgent || item.kind == .launchDaemon || item.kind == .loginItem || item.kind == .btm else { return nil }
        let plistApple = item.label.lowercased().hasPrefix("com.apple.")
        // Real com.apple launch plists live in /System/Library; a com.apple.* plist in /Library or ~/Library is odd on its own.
        let target = item.target ?? item.location
        let s = Subject(path: target, label: item.label, isLaunchItem: true, signing: item.signing, isPlatformBinary: targetIsPlatform)
        if var e = assess(s) {
            e.detail += " (launch item \(item.location))"
            return e
        }
        if plistApple && !item.location.hasPrefix("/System/") && !isAppleSigned(s) {
            return Evidence(source: .persistence, title: "Pretends to be Apple",
                            detail: "Launch item label \(item.label) in \(item.location) runs \(target), which is not Apple-signed.", score: 85)
        }
        return nil
    }
}

/// FileDetector: bundles / Mach-O files with Apple-looking names or identifiers (uses FileFacts.signing).
public struct AppleImpersonationDetector: FileDetector {
    public let name = "apple-impersonation"
    public init() {}
    public func inspect(_ f: FileFacts) -> [Evidence] {
        guard f.kind == .machO || f.kind == .fatMachO || f.kind == .appBundle || (f.kind == .plist && f.path.contains("/Launch")) else { return [] }
        var s = AppleImpersonation.Subject(path: f.path, signingID: f.signing?.signingID, signing: f.signing)
        if f.kind == .appBundle {
            let info = (try? Data(contentsOf: URL(fileURLWithPath: f.path + "/Contents/Info.plist"))).flatMap {
                try? PropertyListSerialization.propertyList(from: $0, options: [], format: nil) as? [String: Any] }
            s.bundleID = info?["CFBundleIdentifier"] as? String
            s.name = (info?["CFBundleDisplayName"] as? String) ?? (info?["CFBundleName"] as? String)
        } else if f.kind == .plist {
            guard let d = try? Data(contentsOf: URL(fileURLWithPath: f.path), options: .mappedIfSafe), d.count < 1 << 20,
                  let p = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil) as? [String: Any],
                  let label = p["Label"] as? String else { return [] }
            let target = (p["Program"] as? String) ?? (p["ProgramArguments"] as? [String])?.first ?? f.path
            // Signing of the target is unknown here: label-only judgement, handled conservatively.
            guard label.lowercased().hasPrefix("com.apple."), !f.path.hasPrefix("/System/") else { return [] }
            if AppleImpersonation.isProtectedPath(target) { return [] }  // points at real Apple code (still odd; persistence scanner judges signing)
            return [Evidence(source: .persistence, title: "Pretends to be Apple",
                             detail: "Launch item \(f.path) uses Apple's label \(label) but runs \(target) from outside system folders.", score: 82)]
        }
        return AppleImpersonation.assess(s).map { [$0] } ?? []
    }
}
