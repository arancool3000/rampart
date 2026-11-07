import Foundation
import Darwin
import RampartShared

/// Turns "we couldn't look inside this container" into honest evidence instead of a silent clean verdict.
///
/// Base: a low-severity, log-only note (score 30). The score rises with context that makes a hidden
/// payload more likely: program-type names inside, a double extension ("invoice.pdf.zip", "photo.jpg.app"),
/// a download / Mail / Messages origin, or an archive bomb. Quiet, trusted locations (Apple system folders,
/// Xcode / Command Line Tools, Homebrew's Cellar) produce no note unless one of those risk signals is present.
public enum ContainerRisk {
    public static let noteTitle = "Couldn't look inside archive"
    public static let encryptedTitle = "Password-protected archive (contents not checked)"
    public static let bombTitle = "Archive bomb (refused to unpack)"

    /// Base score of the plain "couldn't look inside" note: logged, never an alert on its own.
    public static let baseScore = 30
    /// Highest score this module ever assigns (stays below auto-quarantine).
    public static let maxScore = 75

    /// Names that run code when opened.
    public static let programExtensions: Set<String> = [
        "app", "command", "tool", "terminal", "sh", "bash", "zsh", "csh", "ksh", "fish", "py", "pyc", "pyw", "pl", "rb", "php",
        "js", "jse", "mjs", "vbs", "vbe", "wsf", "ps1", "bat", "cmd", "exe", "scr", "msi", "com", "pif", "cpl", "dll", "jar", "pkg",
        "mpkg", "dmg", "scpt", "scptd", "applescript", "osa", "jxa", "workflow", "action", "dylib", "so", "bundle", "plugin",
        "kext", "hta", "lnk", "iso", "img", "run", "bin", "elf", "apk", "xpi", "crx", "docm", "xlsm", "pptm", "url", "webloc",
        "inetloc", "desktop", "service", "lua", "tcl", "fileloc",
    ]
    /// Names a lure pretends to be.
    public static let decoyExtensions: Set<String> = [
        "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "csv", "odt", "pages", "numbers", "key",
        "jpg", "jpeg", "png", "gif", "heic", "bmp", "tif", "tiff", "webp", "mp3", "mp4", "mov", "m4a", "wav", "avi", "mkv", "html", "htm",
    ]
    static let archiveExtensions: Set<String> = [
        "zip", "rar", "7z", "tar", "gz", "tgz", "bz2", "xz", "z", "zst", "lz4", "lzma", "cpio", "xar", "aar", "yaa", "dmg", "pkg", "iso",
    ]
    /// Containers that are normally nested several levels deep in benign software (Java, Python, Office).
    static let benignNestingExtensions: Set<String> = [
        "jar", "war", "ear", "aar", "whl", "egg", "nupkg", "vsix", "apk", "docx", "xlsx", "pptx", "odt", "ods", "odp", "epub", "ipa", "crx", "xpi",
    ]

    /// Locations whose unreadable containers are a fact of life (test corpora, toolchains, Apple data).
    public static func isQuietLocation(_ path: String) -> Bool {
        let p = path.hasPrefix("/tmp/") ? "/private" + path : path
        let roots = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Developer/", "/Library/Apple/", "/Applications/Xcode",
                     "/opt/homebrew/Cellar/", "/opt/homebrew/Library/", "/usr/local/Cellar/", "/Library/Frameworks/Python.framework/",
                     "/private/var/db/", "/Library/Updates/"]
        if roots.contains(where: { p.hasPrefix($0) }) { return true }
        for m in ["/site-packages/", "/dist-packages/", "/node_modules/", "/.git/", "/Library/Caches/Homebrew/", "/.cargo/registry/",
                  "/.gradle/caches/", "/.m2/repository/", "/Library/Developer/", "/.rustup/", "/.pyenv/"] where p.contains(m) { return true }
        return false
    }

    static func ext(_ name: String) -> String { ScanTriage.pathExtension(name) }

    /// Member names that would run code (".app/" bundles count once), most telling first. Capped at 5.
    public static func riskyMembers(_ names: [String]) -> [String] {
        var out: [String] = []
        var seenApps = Set<String>()
        for raw in names {
            let n = raw.hasSuffix("/") ? String(raw.dropLast()) : raw
            if let r = n.range(of: ".app/") ?? (n.hasSuffix(".app") ? n.range(of: ".app", options: .backwards) : nil) {
                let app = String(n[..<r.upperBound]).trimmingCharacters(in: CharacterSet(charactersIn: "/"))
                if seenApps.insert(app).inserted { out.append(app) }
            } else if programExtensions.contains(ext(n)) || hasDoubleExtension((n as NSString).lastPathComponent) {
                out.append(n)
            }
            if out.count >= 5 { break }
        }
        return out
    }

    /// "report.pdf.zip", "photo.jpg.command", "invoice.pdf      .app": a decoy extension directly before a
    /// program or archive extension.
    public static func hasDoubleExtension(_ name: String) -> Bool {
        let parts = name.lowercased().split(separator: ".").map { $0.trimmingCharacters(in: .whitespaces) }
        guard parts.count >= 3 else { return false }
        let last = parts[parts.count - 1], prev = parts[parts.count - 2]
        return decoyExtensions.contains(prev) && (programExtensions.contains(last) || archiveExtensions.contains(last))
    }

    /// Download origin from `com.apple.quarantine` ("flags;time;agent;uuid") and location.
    public struct Origin: Equatable, Sendable {
        public var quarantined = false
        public var agent: String?
        public var inDownloads = false
        public var fromMessaging: Bool {
            guard let a = agent?.lowercased() else { return false }
            return a.contains("mail") || a.contains("messages") || a.contains("imessage") || a.contains("whatsapp")
                || a.contains("telegram") || a.contains("signal") || a.contains("discord") || a.contains("slack")
        }
        public var isRisky: Bool { quarantined || inDownloads }
        public var text: String? {
            if quarantined, let agent, !agent.isEmpty { return "downloaded by \(agent)" }
            if quarantined { return "downloaded from the internet" }
            if inDownloads { return "in your Downloads folder" }
            return nil
        }
        public init(quarantined: Bool = false, agent: String? = nil, inDownloads: Bool = false) {
            self.quarantined = quarantined; self.agent = agent; self.inDownloads = inDownloads
        }
    }

    public static func origin(of path: String) -> Origin {
        var o = Origin()
        o.inDownloads = path.contains("/Downloads/") || path.contains("/Mail Downloads/") || path.contains("/Library/Messages/Attachments/")
        var buf = [UInt8](repeating: 0, count: 512)
        let n = getxattr(path, "com.apple.quarantine", &buf, buf.count, 0, 0)
        if n > 0 {
            o.quarantined = true
            let f = String(decoding: buf[0..<n], as: UTF8.self).split(separator: ";", omittingEmptySubsequences: false)
            if f.count >= 3 { o.agent = String(f[2]).trimmingCharacters(in: .whitespaces).prefix(60).description }
        }
        if o.agent?.isEmpty == true { o.agent = nil }
        return o
    }

    /// The real on-disk path a scan display path refers to ("/x/a.zip!/b.tgz!/c" -> "/x/a.zip").
    public static func outerPath(_ displayPath: String) -> String {
        displayPath.range(of: "!/").map { String(displayPath[..<$0.lowerBound]) } ?? displayPath
    }

    /// Evidence for a container we could not open, or nil when it's in a quiet location with no risk signal.
    public static func evidence(for e: ContainerUnreadable, displayPath: String, origin: Origin) -> Evidence? {
        let name = (displayPath as NSString).lastPathComponent
        var score = e.reason == .bomb ? 45 : baseScore
        var why: [String] = []
        let risky = riskyMembers(e.memberNames)
        if !risky.isEmpty {
            score += 20
            why.append("it lists program-type items inside (\(risky.prefix(3).joined(separator: ", ")))")
        }
        // A double extension anywhere in the chain counts ("bill.pdf.zip!/x.tgz").
        let chain = displayPath.components(separatedBy: "!/").map { ($0 as NSString).lastPathComponent }
        if let dbl = chain.first(where: hasDoubleExtension) {
            score += 15
            why.append("its name \"\(dbl)\" hides its real type behind a document extension")
        }
        if let o = origin.text {
            if origin.fromMessaging || origin.quarantined || !why.isEmpty || e.reason == .encrypted {
                score += origin.fromMessaging ? 15 : 10
                why.append("it was \(o)")
            }
        }
        if e.reason == .encrypted && origin.isRisky {
            score += 5
            why.append("password-protected downloads are a common way to slip malware past scanners")
        }
        let quiet = isQuietLocation(outerPath(displayPath)) && !origin.isRisky
        if why.isEmpty && (quiet || (e.reason == .tooDeep && benignNestingExtensions.contains(ext(name)))) { return nil }
        score = min(score, maxScore)

        let what: String
        switch e.reason {
        case .encrypted: what = "it is password-protected"
        case .tooLarge: what = "it is too large to unpack safely (\(e.detail))"
        case .bomb: what = "it would expand to an unsafe size (\(e.detail)) — a trick used to crash or blind scanners"
        case .tooManyFiles: what = "it holds too many files to unpack safely (\(e.detail))"
        case .tooDeep: what = "it is nested inside too many other archives (\(e.detail))"
        case .corrupt: what = "it is damaged or truncated"
        case .unsupported: what = "it uses a format RamPart can't open (\(e.detail))"
        case .timedOut: what = "unpacking it took too long"
        }
        let title = e.reason == .encrypted ? encryptedTitle : e.reason == .bomb ? bombTitle : noteTitle
        var detail = "RamPart couldn't look inside this \(e.format.displayName) because \(what), so anything inside was not checked."
        if !why.isEmpty { detail += " It deserves extra care because " + why.joined(separator: "; ") + "." }
        else { detail += " That alone is not a sign of malware." }
        detail += " If you open it, RamPart scans what comes out when it is unpacked and run."
        return Evidence(source: .heuristic, title: title, detail: detail, score: score)
    }
}
