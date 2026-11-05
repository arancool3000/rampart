import Foundation
import RampartShared

/// Path -> signing facts. Injected so this module does not depend on RampartSigning.
public typealias SigningProvider = @Sendable (String) -> SigningInfo?

/// Coarse location class of a path; drives context multipliers and several rules.
public enum PathClass: String, Codable, Sendable, CaseIterable {
    case system          // /System, /usr (not /usr/local), /bin, /sbin, /Library/Apple
    case applications    // /Applications, ~/Applications
    case temp            // /tmp, /private/tmp, /private/var/folders/*/T|C|0, /var/tmp
    case hidden          // a dot-directory or dot-file somewhere in the path (outside well-known ones)
    case usersShared     // /Users/Shared
    case volume          // /Volumes/* (mounted DMG / external disk)
    case translocated    // App Translocation
    case downloads       // ~/Downloads
    case library         // ~/Library, /Library
    case home            // anything else under /Users/<name>
    case other

    /// Dot-directories that are normal developer / tool locations; they do not make a path "hidden".
    static let benignDotDirs: Set<String> = [
        ".Trash", ".git", ".build", ".cargo", ".rustup", ".npm", ".nvm", ".pyenv", ".rbenv", ".local", ".config",
        ".cache", ".vscode", ".vscode-server", ".cursor", ".docker", ".gradle", ".m2", ".swiftpm", ".bun", ".deno",
        ".oh-my-zsh", ".zsh", ".nix-profile", ".gem", ".conda", ".pnpm-store", ".yarn", ".volta", ".sdkman",
        ".claude", ".codex", ".gnupg", ".ssh", ".aws", ".kube", ".terraform.d", ".android", ".lima", ".colima",
    ]

    public static func classify(_ rawPath: String) -> PathClass {
        let p = rawPath
        if p.contains("/AppTranslocation/") { return .translocated }
        if p.hasPrefix("/tmp/") || p.hasPrefix("/private/tmp/") || p.hasPrefix("/var/tmp/") || p.hasPrefix("/private/var/tmp/") {
            return .temp
        }
        if p.hasPrefix("/private/var/folders/") || p.hasPrefix("/var/folders/") {
            // /var/folders/xx/yyyy/X/ is the code-signing clone area used by Chrome etc.; treat as system-ish.
            let comps = p.split(separator: "/")
            let idx = comps.firstIndex(of: "folders").map { $0 + 3 } ?? comps.count
            if idx < comps.count, comps[idx] == "X" { return .other }
            return .temp
        }
        if p.hasPrefix("/Users/Shared/") { return .usersShared }
        if p.hasPrefix("/Volumes/") { return .volume }
        if p.hasPrefix("/System/") || p.hasPrefix("/bin/") || p.hasPrefix("/sbin/") || p.hasPrefix("/Library/Apple/")
            || (p.hasPrefix("/usr/") && !p.hasPrefix("/usr/local/")) || p.hasPrefix("/private/var/db/") {
            return .system
        }
        if isHidden(p) { return .hidden }
        if p.hasPrefix("/Applications/") { return .applications }
        if p.hasPrefix("/Users/") {
            let comps = p.split(separator: "/")
            if comps.count >= 3 {
                switch comps[2] {
                case "Applications": return .applications
                case "Downloads": return .downloads
                case "Library": return .library
                default: return .home
                }
            }
            return .home
        }
        if p.hasPrefix("/Library/") { return .library }
        return .other
    }

    static func isHidden(_ p: String) -> Bool {
        let comps = p.split(separator: "/")
        // Ignore the final component when it is a well-known dotfile (handled by shell rc rules instead).
        for (i, c) in comps.enumerated() where c.hasPrefix(".") && c.count > 1 {
            if benignDotDirs.contains(String(c)) { continue }
            if i == comps.count - 1 { return true }       // hidden file itself
            return true
        }
        return false
    }

    /// Classes that count as "temp or hidden" for the ×1.3 multiplier and R29.
    public var isSuspiciousLocation: Bool { self == .temp || self == .hidden || self == .usersShared }
}

enum PathUtil {
    static let home = FileManager.default.homeDirectoryForCurrentUser.path

    static func basename(_ p: String) -> String { (p as NSString).lastPathComponent }
    static func dirname(_ p: String) -> String { (p as NSString).deletingLastPathComponent }
    static func ext(_ p: String) -> String { (p as NSString).pathExtension.lowercased() }

    static func expand(_ p: String, cwd: String? = nil) -> String {
        var s = p
        if s.hasPrefix("~/") { s = home + s.dropFirst(1) }
        if !s.hasPrefix("/"), let cwd, !s.isEmpty { s = (cwd as NSString).appendingPathComponent(s) }
        return (s as NSString).standardizingPath
    }

    /// Strips "/private" so /private/tmp and /tmp compare equal.
    static func canonical(_ p: String) -> String {
        if p.hasPrefix("/private/tmp/") || p.hasPrefix("/private/var/") || p.hasPrefix("/private/etc/") {
            return String(p.dropFirst("/private".count))
        }
        return p
    }

    /// Absolute-looking path arguments (strips curl-style "@" and "name=@" prefixes).
    static func pathArgs(_ args: [String], cwd: String?) -> [String] {
        var out: [String] = []
        for a in args.dropFirst() {
            var t = a
            if let r = t.range(of: "=@") { t = String(t[r.upperBound...]) }
            if t.hasPrefix("@") { t.removeFirst() }
            if t.hasPrefix("-") || t.isEmpty { continue }
            if t.hasPrefix("/") || t.hasPrefix("~/") || (cwd != nil && t.contains("/") && !t.contains("://")) {
                out.append(canonical(expand(t, cwd: cwd)))
            } else if cwd != nil && !t.contains("://") && t.count < 256 && !t.contains(" ") {
                out.append(canonical(expand(t, cwd: cwd)))
            }
        }
        return out
    }
}

/// Normalised argv text for pattern matching: joined, whitespace-collapsed, simple escapes decoded.
enum ArgvText {
    static func normalise(_ args: [String]) -> String {
        var s = args.joined(separator: " ")
        if s.contains("\\x") {
            // decode \xHH sequences, which loaders use to hide words like "curl"
            var out = ""; var it = s.makeIterator(); var pending: [Character] = []
            while let c = it.next() {
                pending.append(c)
                if pending.count == 1 { if c != "\\" { out.append(c); pending.removeAll() }; continue }
                if pending.count == 2 { if c != "x" { out.append(contentsOf: pending); pending.removeAll() }; continue }
                if pending.count == 4 {
                    let hex = String(pending[2...3])
                    if let v = UInt8(hex, radix: 16), v >= 0x20, v < 0x7f { out.append(Character(UnicodeScalar(v))) }
                    else { out.append(contentsOf: pending) }
                    pending.removeAll()
                }
            }
            out.append(contentsOf: pending)
            s = out
        }
        s = s.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\t", with: " ")
        while s.contains("  ") { s = s.replacingOccurrences(of: "  ", with: " ") }
        return s
    }
}

/// Thread-safe compiled-regex cache. Patterns are case-insensitive.
final class RegexCache: @unchecked Sendable {
    static let shared = RegexCache()
    private var cache: [String: NSRegularExpression] = [:]
    private let lock = NSLock()

    func regex(_ pattern: String) -> NSRegularExpression? {
        lock.lock(); defer { lock.unlock() }
        if let r = cache[pattern] { return r }
        guard let r = try? NSRegularExpression(pattern: pattern, options: [.caseInsensitive]) else { return nil }
        cache[pattern] = r
        return r
    }

    func matches(_ pattern: String, _ s: String) -> Bool {
        guard let r = regex(pattern) else { return false }
        return r.firstMatch(in: s, range: NSRange(s.startIndex..., in: s)) != nil
    }

    /// Whole-string match (used for process/ancestor names).
    func fullMatch(_ pattern: String, _ s: String) -> Bool { matches("^(?:" + pattern + ")$", s) }
}

/// Runs a command-line tool with a timeout; returns stdout (nil if it could not run).
enum Shell {
    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 15) -> (status: Int32, out: String)? {
        guard FileManager.default.isExecutableFile(atPath: path) else { return nil }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        p.arguments = args
        let out = Pipe(); p.standardOutput = out; p.standardError = Pipe()
        p.standardInput = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        var data = Data()
        let group = DispatchGroup(); group.enter()
        DispatchQueue.global().async {
            data = out.fileHandleForReading.readDataToEndOfFile(); group.leave()
        }
        if group.wait(timeout: .now() + timeout) == .timedOut {
            p.terminate(); _ = group.wait(timeout: .now() + 2)
        }
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}
