import Foundation
import Darwin
import RampartShared

/// Decides whether a weak, signing-only finding is a real decision for the user, a note, or not a finding.
/// Rules (user-approved, 2026-11-07):
///  - Code inside an installed app bundle, or an app's Application Support folder, whose parent app is
///    trusted (Apple / App Store / notarized Developer ID, or installed and not blocked by Gatekeeper) is not a finding.
///  - Ad-hoc, linker-signed or unsigned binaries the user built (dev folders, build dirs, agent temp dirs, tool
///    caches) are not findings unless they were downloaded (quarantine xattr).
///  - "Broken code signature" on a bundle that modifies its own resources is a note at most.
/// Strong evidence (hash, YARA, XProtect, EICAR, revoked, behaviour/persistence) is never touched.
public enum FindingTriage {
    /// Bump when these rules change so stored detections are re-evaluated.
    public static let policyVersion = 2

    public enum Outcome: Equatable, Sendable {
        case keep
        /// Kept as an info-level note (confidence capped below the log threshold).
        case note(String)
        /// Not a finding: not recorded; stored copies are resolved.
        case notAFinding(String)
    }

    /// Titles of weak signing evidence this triage may discount.
    public static let weakSigningTitles: Set<String> = [
        "Ad-hoc signed program", "Unsigned program", "Broken code signature", "Downloaded unsigned code",
        "Loads libraries from user-writable folders", "Weakened runtime protections", "Unsigned script",
        "Linker-signed program", "Hidden location",
    ]
    static let brokenTitles: Set<String> = ["Broken code signature", "Weakened runtime protections"]

    public struct Context {
        public var home: String
        public var signing: (String) -> SigningInfo?
        /// Raw quarantine flags of a path, nil if no `com.apple.quarantine` xattr.
        public var quarantineFlags: (String) -> UInt32?
        /// Installed app bundles (path) whose name / bundle id matches an Application Support folder name.
        public var appForSupportFolder: (String) -> String?
        public init(home: String = NSHomeDirectory(), signing: @escaping (String) -> SigningInfo?,
                    quarantineFlags: @escaping (String) -> UInt32? = FindingTriage.quarantineFlags,
                    appForSupportFolder: ((String) -> String?)? = nil) {
            self.home = home; self.signing = signing; self.quarantineFlags = quarantineFlags
            self.appForSupportFolder = appForSupportFolder ?? InstalledApps.shared.app(named:)
        }
    }

    /// True if every piece of evidence is weak signing evidence (the only thing triage may discount).
    public static func isWeakSigningOnly(_ d: Detection) -> Bool {
        !d.evidence.isEmpty && d.evidence.allSatisfy { e in
            e.source == .signing && !Scoring.isRevokedSigning(e) && e.score < 60 && weakSigningTitles.contains(e.title)
        }
    }

    public static func classify(_ d: Detection, _ ctx: Context) -> Outcome {
        guard isWeakSigningOnly(d), let raw = d.path else { return .keep }
        let path = (raw as NSString).standardizingPath
        let downloaded = isDownloaded(path, ctx)
        // 1. Developer builds.
        if !downloaded, let why = developerBuildReason(path, home: ctx.home) { return .notAFinding("developer build (\(why))") }
        // 2. Inside a trusted app bundle.
        if let app = outermostApp(path), let why = trustedApp(app, ctx) {
            if !downloaded || ctx.quarantineFlags(app).map({ $0 & 0x0040 != 0 }) == true || isTrustedSigned(app, ctx) {
                return .notAFinding("part of \((app as NSString).lastPathComponent) (\(why))")
            }
        }
        // 3. An app's Application Support folder.
        if let (folder, app) = supportFolderApp(path, ctx), let why = trustedApp(app, ctx), !downloaded {
            return .notAFinding("\(folder) data of \((app as NSString).lastPathComponent) (\(why))")
        }
        // 4. Broken signature inside a bundle / support folder: the app modified its own resources.
        if d.evidence.allSatisfy({ brokenTitles.contains($0.title) }),
           outermostApp(path) != nil || path.contains("/Application Support/") || path.contains(".framework/")
            || path.contains(".bundle/") || path.contains(".plugin/") || path.contains(".ilmbplugin/") {
            return .note("bundle files changed after signing (typical for apps that update their own resources)")
        }
        return .keep
    }

    /// Applies the outcome: nil = drop, otherwise the (possibly downgraded) detection.
    public static func apply(_ d: Detection, _ ctx: Context) -> (Detection?, Outcome) {
        let o = classify(d, ctx)
        switch o {
        case .keep: return (d, o)
        case .notAFinding: return (nil, o)
        case .note(let why):
            var n = d
            n.confidence = min(n.confidence, Scoring.logThreshold - 1)
            n.severity = .info
            if !n.evidence.contains(where: { $0.title == "Note" }) {
                n.evidence.append(Evidence(source: .signing, title: "Note", detail: "Not a threat decision: \(why).", score: 0))
            }
            return (n, o)
        }
    }

    // MARK: rules

    public static func developerBuildReason(_ path: String, home: String) -> String? {
        let p = path.hasPrefix("/tmp/") ? "/private" + path : path
        for marker in ["/.build/", "/DerivedData/", "/node_modules/", "/target/debug/", "/target/release/", "/.cargo/", "/go/pkg/", "/.rustup/", "/dist-newstyle/"]
            where p.contains(marker) { return marker.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }
        if let r = p.range(of: "/.build-"), p[r.upperBound...].contains("/") { return ".build-*" }
        if p.hasPrefix("/private/tmp/claude-") || p.hasPrefix("/private/var/folders/") && p.contains("/claude-") { return "agent workspace" }
        let devRoots = ["Rampart", "Code", "Developer", "Projects", "src", "dev", "repos", "git", "go"].map { home + "/" + $0 + "/" }
        if let r = devRoots.first(where: { p.hasPrefix($0) }) { return "~/" + r.dropFirst(home.count + 1).dropLast() }
        for cache in ["/Library/Application Support/pyinstaller/", "/Library/Caches/pyinstaller/", "/Library/Developer/", "/.npm/", "/.pyenv/", "/.swiftpm/"]
            where p.hasPrefix(home + cache) { return cache.trimmingCharacters(in: CharacterSet(charactersIn: "/")) }
        return nil
    }

    /// Outermost `.app` bundle containing `path` (or `path` itself if it is one).
    public static func outermostApp(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app", options: .backwards) : nil) else { return nil }
        return String(path[..<r.upperBound]).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
            .withLeadingSlash
    }

    static func supportFolderApp(_ path: String, _ ctx: Context) -> (String, String)? {
        for base in [ctx.home + "/Library/Application Support/", "/Library/Application Support/"] where path.hasPrefix(base) {
            let folder = path.dropFirst(base.count).split(separator: "/").first.map(String.init) ?? ""
            guard !folder.isEmpty, let app = ctx.appForSupportFolder(folder) else { return nil }
            return (folder, app)
        }
        return nil
    }

    static func isTrustedSigned(_ app: String, _ ctx: Context) -> Bool {
        ctx.signing(app).map(Scoring.isTrusted) ?? false
    }

    /// Why the app is trusted, or nil. Trusted = Apple/App Store/notarized, or installed in an Applications folder
    /// and not blocked (no quarantine, or a quarantine the user approved through Gatekeeper).
    static func trustedApp(_ app: String, _ ctx: Context) -> String? {
        if let s = ctx.signing(app) {
            if Scoring.isTrusted(s) { return s.status == .apple ? "Apple" : s.teamID.map { "notarized, team \($0)" } ?? "notarized" }
            if s.status == .revoked { return nil }
        }
        let installed = app.hasPrefix("/Applications/") || app.hasPrefix(ctx.home + "/Applications/")
        guard installed else { return nil }
        if let f = ctx.quarantineFlags(app) { return f & 0x0040 != 0 ? "installed, opened by you" : nil }
        return "installed app"
    }

    static func isDownloaded(_ path: String, _ ctx: Context) -> Bool {
        guard let f = ctx.quarantineFlags(path) else { return false }
        return f & 0x0040 == 0   // downloaded and never approved by the user
    }

    public static func quarantineFlags(_ path: String) -> UInt32? {
        var buf = [UInt8](repeating: 0, count: 256)
        let n = getxattr(path, "com.apple.quarantine", &buf, buf.count, 0, 0)
        guard n > 0, let s = String(bytes: buf[0..<n], encoding: .utf8) else { return nil }
        return UInt32(s.split(separator: ";").first ?? "", radix: 16)
    }
}

private extension String {
    var withLeadingSlash: String { hasPrefix("/") ? self : "/" + self }
}

/// Cached index of installed apps (/Applications, ~/Applications, one level of subfolders) by lowercased
/// display name, bundle name and last bundle-id component.
public final class InstalledApps: @unchecked Sendable {
    public static let shared = InstalledApps()
    private let lock = NSLock()
    private var index: [String: String]?
    private var built = Date.distantPast

    public func app(named folder: String) -> String? {
        lock.lock(); defer { lock.unlock() }
        if index == nil || Date().timeIntervalSince(built) > 600 { index = Self.build(); built = Date() }
        let key = folder.lowercased()
        if let hit = index?[key] { return hit }
        // "Sikarugir" -> "Sikarugir Creator.app": a whole-word prefix of an installed app's name.
        guard key.count >= 4 else { return nil }
        return index?.filter { $0.key.hasPrefix(key + " ") }.min { $0.key < $1.key }?.value
    }

    static func build() -> [String: String] {
        var out: [String: String] = [:]
        let fm = FileManager.default
        var dirs = ["/Applications", NSHomeDirectory() + "/Applications"]
        for d in dirs {
            for e in (try? fm.contentsOfDirectory(atPath: d)) ?? [] where !e.hasSuffix(".app") && !e.hasPrefix(".") { dirs.append(d + "/" + e) }
        }
        for d in dirs {
            for e in (try? fm.contentsOfDirectory(atPath: d)) ?? [] where e.hasSuffix(".app") {
                let app = d + "/" + e
                var keys = [String(e.dropLast(4)).lowercased()]
                if let info = NSDictionary(contentsOfFile: app + "/Contents/Info.plist") {
                    for k in ["CFBundleName", "CFBundleExecutable"] { if let v = info[k] as? String { keys.append(v.lowercased()) } }
                    if let id = info["CFBundleIdentifier"] as? String {
                        keys.append(id.lowercased())
                        if let last = id.split(separator: ".").last { keys.append(String(last).lowercased()) }
                    }
                }
                for k in keys where k.count >= 3 && out[k] == nil { out[k] = app }
            }
        }
        return out
    }
}
