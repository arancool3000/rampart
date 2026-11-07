import Foundation
import RampartWeb

// Pure download policy: every download is quarantined first; what happens next depends on the
// file class and on the RamPart engine's verdict (via the daemon when it is running).

public enum DownloadClass: String, Sendable, CaseIterable {
    case executable, diskImage, installer, archive, script, document, media, other

    public static func classify(filename: String, mimeType: String?) -> DownloadClass {
        let ext = (filename as NSString).pathExtension.lowercased()
        switch ext {
        case "app", "command", "tool", "action", "workflow", "terminal", "dylib", "bundle", "kext", "plugin", "exe", "msi", "bat", "cmd", "scpt", "applescript", "jar", "appimage",
             // hx6: more things macOS will run or install on a double-click
             "scptd", "osax", "prefpane", "saver", "qlgenerator", "mdimporter", "xpc", "appex", "systemextension", "mobileconfig", "configprofile", "provisionprofile", "wflow", "service", "widget", "dext", "so", "o", "elf", "bin", "run", "out":
            return .executable
        case "dmg", "iso", "img", "sparseimage", "sparsebundle", "cdr": return .diskImage
        case "pkg", "mpkg", "xip": return .installer
        case "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "lz", "zst", "cpgz", "pax", "aar", "cpio", "lzma", "lha", "lzh", "cab", "arj", "tbz", "tbz2", "txz": return .archive
        case "sh", "zsh", "bash", "py", "rb", "pl", "php", "js", "mjs", "ps1", "vbs", "hta", "lnk", "url", "webloc", "inetloc", "fileloc",
             // hx6: script-bearing documents and HTML (opened from disk it runs as file://)
             "docm", "xlsm", "pptm", "dotm", "xltm", "potm", "html", "htm", "xhtml", "shtml", "mht", "mhtml", "svgz", "swf", "jnlp", "desktop", "ksh", "csh", "tcsh", "fish", "lua", "tcl", "pyc", "pyw", "jse", "wsf", "wsh", "ps1xml", "psm1", "reg", "scr", "pif", "com", "cpl", "msc", "iso9660": return .script
        case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "pages", "numbers", "key", "epub": return .document
        case "jpg", "jpeg", "png", "gif", "webp", "heic", "mp3", "mp4", "mov", "m4a", "wav", "aac": return .media
        case "svg": return .script   // hx6: SVG can carry script and opens in a browser from disk
        default: break
        }
        if let m = mimeType?.lowercased() {
            if m.contains("svg") { return .script }   // hx6: SVG carries script
            if m.hasPrefix("image/") || m.hasPrefix("audio/") || m.hasPrefix("video/") { return .media }
            if m.contains("html") || m.contains("javascript") || m.contains("x-sh") || m.contains("x-python") || m.contains("svg") { return .script }
            if m.hasPrefix("text/") || m == "application/pdf" { return .document }
            if m == "application/x-apple-diskimage" { return .diskImage }
            if m.contains("octet-stream") || m.contains("x-mach") || m.contains("executable") { return .executable }
        }
        return .other
    }

    public var label: String {
        switch self {
        case .executable: return "Application"
        case .diskImage: return "Disk image"
        case .installer: return "Installer package"
        case .archive: return "Archive"
        case .script: return "Script"
        case .document: return "Document"
        case .media: return "Media"
        case .other: return "File"
        }
    }
    /// Classes that can run code when opened.
    public var canExecute: Bool { [.executable, .diskImage, .installer, .script].contains(self) }
}

public enum ScanOutcome: Equatable, Sendable {
    case clean
    case infected(name: String)
    case unavailable           // daemon not running; file stays quarantined with a label
}

public enum DownloadAction: Equatable, Sendable {
    /// Move to ~/Downloads, keep com.apple.quarantine; Finder shows the usual Gatekeeper prompt.
    case release
    /// Keep in the RamPart vault folder and show the user why; they can delete or (if clean) release.
    case holdForConfirmation(reason: String)
    /// Keep in the vault, exec bits stripped; only "Delete" is offered.
    case blocked(reason: String)
}

public struct DownloadPolicy: Sendable {
    /// Executables that the engine could not scan stay held, documents are released with a note.
    public var holdExecutablesWhenUnscanned = true
    /// In Banking mode, downloads that can execute are always held.
    public var bankingMode = false
    public init(bankingMode: Bool = false) { self.bankingMode = bankingMode }

    public func decide(class cls: DownloadClass, outcome: ScanOutcome, fromRiskySite: Bool) -> DownloadAction {
        switch outcome {
        case .infected(let name):
            return .blocked(reason: "RamPart found \(name) in this file. It was never opened and its permissions were removed.")
        case .unavailable:
            if cls.canExecute, holdExecutablesWhenUnscanned {
                return .holdForConfirmation(reason: "The RamPart background service isn't running, so this \(cls.label.lowercased()) couldn't be scanned. It stays quarantined until you decide.")
            }
            if fromRiskySite { return .holdForConfirmation(reason: "This file came from a site RamPart flagged and couldn't be scanned.") }
            return .release
        case .clean:
            if fromRiskySite && cls.canExecute {
                return .holdForConfirmation(reason: "The scan found nothing, but this \(cls.label.lowercased()) came from a site RamPart flagged. Open it only if you expected it.")
            }
            if bankingMode && cls.canExecute {
                return .holdForConfirmation(reason: "Banking mode keeps \(cls.label.lowercased())s quarantined. Open it from the RamPart app once you've finished your session.")
            }
            return .release
        }
    }

    /// `com.apple.quarantine` xattr value: flags;timestamp-hex;agent;uuid. Flag 0x0083 marks a
    /// user-approved-later download, the same way Safari does, so Gatekeeper still checks it.
    public static func quarantineAttribute(agent: String = "RamPart Secure Browser", date: Date = Date(), uuid: UUID = UUID()) -> String {
        String(format: "0083;%08x;%@;%@", UInt32(date.timeIntervalSince1970), agent, uuid.uuidString)
    }

    /// A file name that is safe to write under the vault: no path separators, no leading dots, bounded length.
    /// hx6: also no NUL / control / bidi-override / zero-width characters (so "invoice\u{202E}fdp.app" can't
    /// render as "invoiceppa.pdf"), no trailing dots or spaces (which hide the real extension), and at most
    /// 240 UTF-8 bytes so APFS's 255-byte limit can't make the write fail. The real extension is kept.
    public static func safeFilename(_ suggested: String) -> String {
        var s = String(String.UnicodeScalarView(suggested.unicodeScalars.filter { u in
            switch u.properties.generalCategory {
            case .format, .control, .lineSeparator, .paragraphSeparator, .privateUse, .unassigned, .surrogate: return false
            default: return u != "\u{FFFD}"
            }
        }))
        s = s.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_").replacingOccurrences(of: "\\", with: "_")
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasPrefix(".") || s.hasPrefix("-") || s.hasPrefix(" ") { s.removeFirst() }
        while s.hasSuffix(".") || s.hasSuffix(" ") { s.removeLast() }
        if s.isEmpty { s = "download" }
        if s.utf8.count > 240 {
            let ext = (s as NSString).pathExtension
            var base = ext.isEmpty || ext.utf8.count > 16 ? s : String(s.dropLast(ext.count + 1))
            let budget = 240 - (ext.isEmpty || ext.utf8.count > 16 ? 0 : ext.utf8.count + 1)
            while base.utf8.count > budget { base.removeLast() }
            s = (ext.isEmpty || ext.utf8.count > 16) ? base : base + "." + ext
        }
        return s
    }

    /// hx6: is the place a download came from risky? Looks at every hop that led to it (main-frame
    /// redirects and the download's own HTTP redirects), not only the page the tab showed: a malvertising
    /// chain usually starts on a clean site and ends at a look-alike host serving the file.
    public static func isRiskySource(hops: [URLFacts], redirectCount: Int) -> Bool {
        if redirectCount >= maxCleanRedirects { return true }
        return hops.contains { f in
            f.blocklistHit != nil || f.scamVerdict != .likelySafe || (f.brandMatch != nil && !f.allowlisted)
        }
    }
    /// Redirects a download may follow before RamPart treats the source as risky, and the hard cap.
    public static let maxCleanRedirects = 5
    public static let maxRedirects = 10
}
