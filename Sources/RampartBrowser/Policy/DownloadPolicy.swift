import Foundation

// Pure download policy: every download is quarantined first; what happens next depends on the
// file class and on the RamPart engine's verdict (via the daemon when it is running).

public enum DownloadClass: String, Sendable, CaseIterable {
    case executable, diskImage, installer, archive, script, document, media, other

    public static func classify(filename: String, mimeType: String?) -> DownloadClass {
        let ext = (filename as NSString).pathExtension.lowercased()
        switch ext {
        case "app", "command", "tool", "action", "workflow", "terminal", "dylib", "bundle", "kext", "plugin", "exe", "msi", "bat", "cmd", "scpt", "applescript", "jar", "appimage":
            return .executable
        case "dmg", "iso", "img", "sparseimage", "sparsebundle", "cdr": return .diskImage
        case "pkg", "mpkg", "xip": return .installer
        case "zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "lz", "zst": return .archive
        case "sh", "zsh", "bash", "py", "rb", "pl", "php", "js", "mjs", "ps1", "vbs", "hta", "lnk", "url", "webloc", "inetloc", "fileloc": return .script
        case "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "rtf", "txt", "csv", "pages", "numbers", "key", "epub": return .document
        case "jpg", "jpeg", "png", "gif", "webp", "heic", "svg", "mp3", "mp4", "mov", "m4a", "wav", "aac": return .media
        default: break
        }
        if let m = mimeType?.lowercased() {
            if m.hasPrefix("image/") || m.hasPrefix("audio/") || m.hasPrefix("video/") { return .media }
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
    public static func safeFilename(_ suggested: String) -> String {
        var s = suggested.replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: ":", with: "_")
        s = s.trimmingCharacters(in: .whitespacesAndNewlines)
        while s.hasPrefix(".") { s.removeFirst() }
        if s.isEmpty { s = "download" }
        if s.count > 180 { s = String(s.suffix(180)) }
        return s
    }
}
