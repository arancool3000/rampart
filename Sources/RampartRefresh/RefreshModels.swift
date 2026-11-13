import Foundation
import RampartShared

/// RamPart Refresh: storage and speed optimiser. Everything here is honest and conservative:
/// items go to the Trash (never permanent delete), a preview comes first, and the safety policy
/// can refuse any path regardless of what the scanner or the user selected.

public enum RefreshRisk: Int, Codable, Sendable, Comparable, CaseIterable {
    /// Regenerated automatically by the app or tool that made it.
    case safe = 0
    /// Safe to remove, but you may lose a convenience (e.g. a slower first build, a re-download).
    case low = 1
    /// Your own files: only you can decide.
    case review = 2
    /// Shown for information only. RamPart never removes these.
    case infoOnly = 3

    public static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    public var label: String {
        switch self {
        case .safe: return "Safe"
        case .low: return "Low risk"
        case .review: return "Review"
        case .infoOnly: return "Info only"
        }
    }
}

public enum RefreshCategory: String, Codable, Sendable, CaseIterable, Identifiable {
    case appCaches, oldLogs, crashReports
    case xcode, projectBuilds, packageCaches, homebrew
    case trash, oldDownloads, duplicates, largeOldFiles, leftovers
    case iosBackups, mailAttachments, languagePacks, localSnapshots

    public var id: String { rawValue }

    public var title: String {
        switch self {
        case .appCaches: return "App caches"
        case .oldLogs: return "Old logs"
        case .crashReports: return "Crash reports"
        case .xcode: return "Xcode leftovers"
        case .projectBuilds: return "Build folders in idle projects"
        case .packageCaches: return "Package manager caches"
        case .homebrew: return "Homebrew cleanup"
        case .trash: return "Trash"
        case .oldDownloads: return "Old downloads"
        case .duplicates: return "Duplicate files"
        case .largeOldFiles: return "Large files you haven't opened in a year"
        case .leftovers: return "Leftovers of removed apps"
        case .iosBackups: return "iPhone and iPad backups"
        case .mailAttachments: return "Mail attachments"
        case .languagePacks: return "App language files"
        case .localSnapshots: return "Time Machine local snapshots"
        }
    }

    public var symbol: String {
        switch self {
        case .appCaches: return "shippingbox"
        case .oldLogs: return "doc.text"
        case .crashReports: return "exclamationmark.triangle"
        case .xcode: return "hammer"
        case .projectBuilds: return "folder.badge.gearshape"
        case .packageCaches: return "cube.box"
        case .homebrew: return "mug"
        case .trash: return "trash"
        case .oldDownloads: return "arrow.down.circle"
        case .duplicates: return "doc.on.doc"
        case .largeOldFiles: return "externaldrive.badge.timemachine"
        case .leftovers: return "app.dashed"
        case .iosBackups: return "iphone"
        case .mailAttachments: return "paperclip"
        case .languagePacks: return "globe"
        case .localSnapshots: return "clock.arrow.circlepath"
        }
    }

    /// Plain-language explanation of what the category is and why it is (or isn't) safe.
    public var explanation: String {
        switch self {
        case .appCaches: return "Temporary files apps keep to load faster. Apps rebuild them as needed. Caches of apps that are open right now, Apple's own system caches and browser profiles are left alone."
        case .oldLogs: return "Diagnostic logs older than 7 days. Apps write new ones when they need them."
        case .crashReports: return "Reports written when an app crashed. Useful only if you plan to send them to a developer."
        case .xcode: return "DerivedData is rebuilt on the next build. Device support files are downloaded again when you connect that device. Archives contain the symbols you need to read crash reports from shipped builds, so they are never pre-selected."
        case .projectBuilds: return "Build output (.build, node_modules, Rust target, __pycache__, virtual environments) in projects you haven't touched for 30 days. Your source code is never touched; a rebuild or `npm install` brings them back."
        case .packageCaches: return "Downloaded packages kept by pip, npm, Yarn, Cargo and Go. They are fetched again the next time a project needs them."
        case .homebrew: return "Old versions and downloads that `brew cleanup` would remove (from a dry run). RamPart moves them to the Trash instead of deleting them."
        case .trash: return "Items already in your Trash. Emptying the Trash is the only permanent action in Refresh and always asks first."
        case .oldDownloads: return "Installers, disk images and archives in Downloads older than 90 days. Archives are pre-selected only when you already extracted them next to the archive."
        case .duplicates: return "Files with identical contents (checked by size, then a partial hash, then a full SHA-256). One copy is always kept; nothing is pre-selected."
        case .largeOldFiles: return "Big files you haven't opened in over a year, based on Spotlight's last-opened date. These are your files, so nothing is pre-selected."
        case .leftovers: return "Support files and preferences belonging to apps that are no longer installed. Review before removing: some belong to command-line tools or plug-ins."
        case .iosBackups: return "Device backups made by Finder. Shown so you can manage them in Finder; RamPart never removes them."
        case .mailAttachments: return "Attachments Mail downloaded. Shown for information; manage them in Mail. RamPart never removes them."
        case .languagePacks: return "Translations inside apps. Removing them would break the app's code signature, so RamPart only shows their size."
        case .localSnapshots: return "Time Machine keeps local snapshots and macOS deletes them automatically when space is needed. Shown for information only."
        }
    }

    public var risk: RefreshRisk {
        switch self {
        case .appCaches, .oldLogs, .crashReports, .packageCaches, .homebrew: return .safe
        case .xcode, .projectBuilds, .trash: return .low
        case .oldDownloads, .duplicates, .largeOldFiles, .leftovers: return .review
        case .iosBackups, .mailAttachments, .languagePacks, .localSnapshots: return .infoOnly
        }
    }

    /// Categories that read personal folders (Downloads, Documents…). macOS may ask for access, so they run only on request.
    public var touchesPersonalFolders: Bool { [.oldDownloads, .duplicates, .largeOldFiles].contains(self) }
    /// Whether RamPart can act on items in this category at all.
    public var actionable: Bool { risk != .infoOnly }
}

/// One thing that could be cleaned (a file or a folder moved to the Trash as a unit).
public struct RefreshItem: Codable, Hashable, Identifiable, Sendable {
    public var id: String { path }
    public var path: String
    public var category: RefreshCategory
    /// Bytes actually freed on disk (allocated size, sparse-aware). Clone-shared bytes are excluded.
    public var bytes: UInt64
    /// Bytes shared with APFS clones: removing this item may not free them.
    public var sharedBytes: UInt64
    public var modified: Date?
    public var lastOpened: Date?
    public var regenerable: Bool
    public var score: Int = 0
    public var selected: Bool = false
    /// Why this item is safe (or why it is not pre-selected).
    public var reason: String = ""
    /// Duplicate group, if any.
    public var groupID: String?

    public init(path: String, category: RefreshCategory, bytes: UInt64, sharedBytes: UInt64 = 0, modified: Date? = nil,
                lastOpened: Date? = nil, regenerable: Bool, groupID: String? = nil) {
        self.path = path; self.category = category; self.bytes = bytes; self.sharedBytes = sharedBytes
        self.modified = modified; self.lastOpened = lastOpened; self.regenerable = regenerable; self.groupID = groupID
    }

    public var name: String { (path as NSString).lastPathComponent }
}

public struct RefreshCategoryResult: Codable, Hashable, Identifiable, Sendable {
    public var id: RefreshCategory { category }
    public var category: RefreshCategory
    public var items: [RefreshItem]
    /// For info-only categories with no per-item list (snapshots, language packs).
    public var note: String?
    public var infoBytes: UInt64 = 0

    public init(category: RefreshCategory, items: [RefreshItem], note: String? = nil, infoBytes: UInt64 = 0) {
        self.category = category; self.items = items; self.note = note; self.infoBytes = infoBytes
    }
    public var totalBytes: UInt64 { items.reduce(infoBytes) { $0 + $1.bytes } }
    public var selectedBytes: UInt64 { items.filter(\.selected).reduce(0) { $0 + $1.bytes } }
}

/// Undo journal entry: where the item went in the Trash.
public struct RefreshUndoEntry: Codable, Hashable, Sendable, Identifiable {
    public var id: String { original }
    public var original: String
    public var trashed: String
    public var bytes: UInt64
    public var date: Date
    public init(original: String, trashed: String, bytes: UInt64, date: Date) {
        self.original = original; self.trashed = trashed; self.bytes = bytes; self.date = date
    }
}

public struct RefreshOutcome: Sendable {
    public var trashed: [RefreshUndoEntry] = []
    public var refused: [(path: String, reason: RefreshRefusal)] = []
    public var failed: [(path: String, error: String)] = []
    public var dryRun: Bool
    public var freedBytes: UInt64 { trashed.reduce(0) { $0 + $1.bytes } }
    public init(dryRun: Bool) { self.dryRun = dryRun }
}

public extension UInt64 {
    var refreshFormatted: String { ByteCountFormatter.string(fromByteCount: Int64(clamping: self), countStyle: .file) }
}
