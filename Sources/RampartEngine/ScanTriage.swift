import Foundation
import RampartShared

/// Decides how much work a file found by a directory walk gets, from its sniffed type, mode bits,
/// extension, quarantine flag and location. Only multi-file scans triage: `scanFile` (real-time,
/// on-write, explicitly named files) always takes the full path, so a dropped file is fully checked
/// when it is written and only re-checks of unchanged inert content are cut down here.
public enum ScanTriage {
    /// Work plan for one file.
    public struct Plan: Equatable, Sendable {
        /// SHA-256 + hash DB + allowlist.
        public var hash: Bool
        /// YARA (XProtect + Rampart rules).
        public var yara: Bool
        /// Full treatment (archives expanded, cache row marked full).
        public var full: Bool
        public static let full = Plan(hash: true, yara: true, full: true)
    }

    /// Light files at most this big are still hashed (cheap) so hash-feed hits on odd types still apply.
    public static let lightHashLimit: UInt64 = 256 << 10
    /// XProtect's text-targeting script rules all require `filesize < 1MB`; bigger inert files can't match them.
    public static let lightYaraLimit: UInt64 = 1 << 20

    /// Kinds that can execute or carry a payload.
    public static func isPayloadKind(_ k: FileKind) -> Bool {
        switch k {
        case .machO, .fatMachO, .script, .appBundle, .dmg, .pkg, .zip, .archive, .document: return true
        case .plist, .other: return false
        }
    }

    /// Extensions that run in an interpreter, browser or loader even without a header magic or exec bit.
    public static let payloadExtensions: Set<String> = [
        "js", "mjs", "cjs", "jsx", "jse", "html", "htm", "xhtml", "hta", "svg", "command", "tool", "terminal",
        "sh", "bash", "zsh", "csh", "ksh", "fish", "py", "pyw", "pyc", "pl", "pm", "rb", "php", "lua", "tcl",
        "applescript", "scpt", "osa", "jxa", "vbs", "vbe", "wsf", "ps1", "bat", "cmd", "jar", "class",
        "dylib", "so", "bundle", "node", "kext", "plugin", "exe", "dll", "scr", "msi", "cpl", "sys", "lnk",
        "workflow", "action", "app", "pkg", "mpkg", "dmg", "iso", "img", "zip", "jar", "apk", "xpi", "crx",
        "docm", "xlsm", "pptm", "dotm", "xlam", "one", "chm", "url", "webloc", "inetloc", "desktop", "service",
    ]

    /// Extensions whose content no interpreter executes: source/headers, media, fonts, static libraries.
    /// Without an exec bit these get no YARA pass at all.
    public static let inertExtensions: Set<String> = [
        "h", "hh", "hpp", "hxx", "inc", "ipp", "tcc", "c", "cc", "cpp", "cxx", "m", "mm", "s", "asm", "swift", "rs",
        "go", "java", "kt", "cs", "d", "ld", "map", "o", "obj", "a", "lib", "la", "dsym", "tbd", "modulemap", "swiftinterface",
        "swiftmodule", "swiftdoc", "pcm", "gch", "pch", "hex", "elf", "eep", "ihex",
        "png", "jpg", "jpeg", "gif", "heic", "heif", "tif", "tiff", "bmp", "webp", "ico", "icns", "psd", "raw", "dng", "cr2", "nef",
        "mp3", "m4a", "aac", "wav", "aif", "aiff", "flac", "ogg", "opus", "caf", "mid", "midi",
        "mp4", "m4v", "mov", "avi", "mkv", "webm", "mpg", "mpeg", "3gp",
        "ttf", "otf", "ttc", "woff", "woff2", "pfb", "afm",
        "strings", "stringsdict", "nib", "car", "lproj", "sqlite-wal", "sqlite-shm", "db-wal", "db-shm", "idx", "pack",
    ]

    /// Directories that are heavy and low-risk: only executables, scripts and archives inside them are checked.
    public static let lowRiskMarkers: [String] = [
        "/Library/Caches/", ".photoslibrary/", "/.git/objects/", "/node_modules/", "/Arduino15/packages/", "/Arduino15/staging/",
        "/.cargo/registry/", "/.npm/_cacache/", "/.gradle/caches/", "/.m2/repository/", "/Library/Containers/com.apple.mail/Data/Library/Mail Downloads/",
    ]

    /// True if `path` lies in a heavy, low-risk tree (Mail stores count, except their attachment folders).
    public static func isLowRiskTree(_ path: String) -> Bool {
        for m in lowRiskMarkers where path.contains(m) { return true }
        if path.contains("/Library/Mail/") && !path.contains("/Attachments/") { return true }
        return false
    }

    /// Launch-related folders whose plists are persistence and always fully checked.
    public static func isLaunchFolder(_ path: String) -> Bool {
        path.contains("/LaunchAgents/") || path.contains("/LaunchDaemons/") || path.contains("/StartupItems/")
            || path.contains("/Library/Managed Preferences/")
    }

    /// Header magics the sniffer leaves as `.other` but that still carry payloads (PE, ELF, compiled AppleScript/JXA).
    static func payloadHeader(_ h: [UInt8]) -> Bool {
        if h.count >= 2 && h[0] == 0x4D && h[1] == 0x5A { return true }                                 // "MZ"
        if h.count >= 4 && h[0] == 0x7F && h[1] == 0x45 && h[2] == 0x4C && h[3] == 0x46 { return true } // ELF
        if h.count >= 7 && Array(h[0..<7]) == Array("FasdUAS".utf8) { return true }                     // compiled AppleScript
        if h.count >= 8 && Array(h[0..<8]) == Array("JsOsaDAS".utf8) { return true }                    // compiled JXA
        return false
    }

    /// Plans the work for one walked file.
    /// - quarantined: evaluated lazily (one getxattr) only when the cheaper signals say "inert".
    public static func plan(path: String, kind: FileKind, header: [UInt8], size: UInt64, executable: Bool,
                            quarantined: () -> Bool) -> Plan {
        if executable || isPayloadKind(kind) || payloadHeader(header) { return .full }
        if kind == .plist && isLaunchFolder(path) { return .full }
        let ext = pathExtension(path)
        if payloadExtensions.contains(ext) { return .full }
        if path.contains(".app/Contents/MacOS/") { return .full }
        if quarantined() { return .full }
        if isLowRiskTree(path) { return Plan(hash: true, yara: false, full: false) }
        let inert = kind == .plist || inertExtensions.contains(ext)
        // Every file is hashed in full (hashing is cheap and keeps hash-feed hits on any type); only YARA is triaged.
        return Plan(hash: true, yara: !inert && size < lightYaraLimit, full: false)
    }

    static func pathExtension(_ path: String) -> String {
        guard let slash = path.lastIndex(of: "/").map({ path.index(after: $0) }) ?? Optional(path.startIndex),
              let dot = path[slash...].lastIndex(of: "."), dot != slash else { return "" }
        return path[path.index(after: dot)...].lowercased()
    }

    /// True if the open file carries a `com.apple.quarantine` xattr (Gatekeeper download flag).
    static func hasQuarantine(fd: Int32) -> Bool {
        fgetxattr(fd, "com.apple.quarantine", nil, 0, 0, 0) >= 0
    }
}
