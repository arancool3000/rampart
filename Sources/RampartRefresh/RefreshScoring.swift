import Foundation

/// Scores each item 0–100 for "safe to remove without the user thinking about it" and picks the default selection.
/// The score is explainable: every factor adds a sentence to `reason`.
public struct RefreshScorer: Sendable {
    public var home: String
    public var now: Date
    /// Items scoring at or above this are pre-selected (only in categories that allow it).
    public static let selectThreshold = 70

    public init(home: String = NSHomeDirectory(), now: Date = Date()) {
        self.home = RefreshSafetyPolicy.normalize(home); self.now = now
    }

    /// Locations that are never pre-selected, whatever the score.
    public func isPersonalLocation(_ path: String) -> Bool {
        let p = RefreshSafetyPolicy.normalize(path)
        let personal = ["Desktop", "Documents", "Pictures", "Movies", "Music"].map { home + "/" + $0 }
        if personal.contains(where: { p == $0 || p.hasPrefix($0 + "/") }) { return true }
        if p.contains("/Library/Mobile Documents") || p.contains("/Library/CloudStorage") { return true }
        if p.contains(".photoslibrary") { return true }
        return false
    }

    static let documentExtensions: Set<String> = ["pdf", "doc", "docx", "pages", "key", "numbers", "xls", "xlsx", "ppt", "pptx", "txt",
                                                  "rtf", "md", "jpg", "jpeg", "png", "heic", "heif", "gif", "tiff", "raw", "cr2", "nef",
                                                  "dng", "mov", "mp4", "m4v", "mp3", "m4a", "wav", "aiff", "psd", "sketch", "fig", "epub"]
    public static func isDocumentOrMedia(_ path: String) -> Bool {
        documentExtensions.contains((path as NSString).pathExtension.lowercased())
    }

    func days(_ d: Date?) -> Double? { d.map { now.timeIntervalSince($0) / 86400 } }

    public func score(_ item: inout RefreshItem) {
        var s = 0
        var why: [String] = []
        let cat = item.category
        switch cat.risk {
        case .safe: s += 45
        case .low: s += 35
        case .review: s += 5
        case .infoOnly: s = 0
        }
        if item.regenerable { s += 25; why.append(regenerableReason(cat)) }
        if let age = days(item.modified) {
            if age > 365 { s += 15; why.append("Not changed in over a year.") }
            else if age > 90 { s += 12; why.append("Not changed in \(Int(age)) days.") }
            else if age > 30 { s += 10; why.append("Not changed in \(Int(age)) days.") }
            else if age < 1 { s -= 20; why.append("Changed in the last day, so it may be in use.") }
        }
        if let lo = days(item.lastOpened) {
            if lo > 365 { s += 8; why.append("Last opened over a year ago.") }
            else if lo < 7 { s -= 15; why.append("Opened in the last week.") }
        }
        if item.bytes > 1 << 30 { s += 3 }
        if item.sharedBytes > 0 && item.bytes == 0 { s -= 10; why.append("Shares its space with a copy (APFS clone), so removing it may free little.") }
        let p = item.path
        if p.hasPrefix(home + "/Library/Caches/") || p.hasPrefix(home + "/Library/Logs/") { s += 5 }

        var allowSelect = cat.risk <= .low && cat.actionable
        // Hard rules: these are never pre-selected.
        if isPersonalLocation(p) { allowSelect = false; s = min(s, 40); why.append("In a personal folder, so it's your call.") }
        if Self.isDocumentOrMedia(p) && !item.regenerable { allowSelect = false; s = min(s, 40); why.append("Looks like a document or photo, so it's never pre-selected.") }
        // Category-specific exceptions.
        switch cat {
        case .oldDownloads:
            let ext = (p as NSString).pathExtension.lowercased()
            let old = (days(item.modified) ?? 0) > 90 && (days(item.lastOpened) ?? 999) > 30
            if old, ["dmg", "pkg", "mpkg", "iso"].contains(ext) { allowSelect = true; s = max(s, 72); why.append("An installer older than 90 days; you can download it again.") }
            if old, item.regenerable, ["zip", "tar", "gz", "tgz", "xip", "rar", "7z"].contains(ext) { allowSelect = true; s = max(s, 72); why.append("Already extracted next to the archive.") }
        case .xcode where p.contains("/Xcode/Archives/"):
            allowSelect = false; why.append("Archives hold the symbols needed to read crash reports from builds you shipped.")
        case .trash:
            allowSelect = false
        case .duplicates, .largeOldFiles, .leftovers:
            allowSelect = false
        default: break
        }
        // Personal locations and iCloud win over every category exception.
        if isPersonalLocation(p) { allowSelect = false }
        item.score = max(0, min(100, s))
        item.selected = allowSelect && item.score >= Self.selectThreshold
        if item.reason.isEmpty { item.reason = why.joined(separator: " ") }
        else { item.reason += " " + why.joined(separator: " ") }
    }

    func regenerableReason(_ c: RefreshCategory) -> String {
        switch c {
        case .appCaches: return "The app rebuilds this cache automatically."
        case .oldLogs, .crashReports: return "Diagnostic data that nothing depends on."
        case .xcode: return "Xcode recreates this when needed."
        case .projectBuilds: return "Build output: your next build or install recreates it."
        case .packageCaches, .homebrew: return "Downloaded again if a project needs it."
        case .oldDownloads: return "Its contents are already extracted beside it."
        default: return "Can be recreated."
        }
    }
}
