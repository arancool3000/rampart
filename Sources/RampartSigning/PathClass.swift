import Foundation

/// Path classification used by the signing heuristics. Prefix-based (a root daemon cannot use access(2)
/// to ask "could the user write here"), so it errs on the side of "trusted" for system locations.
public enum PathClass: String, Sendable {
    case system          // /System, /usr (not /usr/local), /bin, /sbin, /Library/Apple, /Applications (Apple), cryptex
    case applications    // /Applications, ~/Applications
    case developer       // Homebrew, Xcode DerivedData, toolchains, build folders: ad-hoc/unsigned is normal here
    case temp            // /tmp, /var/folders, /Users/Shared ...
    case userWritable    // anything else under a home folder, /usr/local (non-Homebrew), /opt (non-Homebrew)
    case other

    public static func classify(_ rawPath: String) -> PathClass {
        let p = normalize(rawPath)
        if isDeveloper(p) { return .developer }
        if tempPrefixes.contains(where: { p.hasPrefix($0) }) { return .temp }
        if p.hasPrefix("/Applications/") || p.range(of: #"^/Users/[^/]+/Applications/"#, options: .regularExpression) != nil {
            return .applications
        }
        if systemPrefixes.contains(where: { p.hasPrefix($0) }) && !p.hasPrefix("/usr/local/") { return .system }
        if p.hasPrefix("/Users/") || p.hasPrefix("/usr/local/") || p.hasPrefix("/opt/") || p.hasPrefix("/Volumes/") { return .userWritable }
        return .other
    }

    /// True for locations a non-admin user (or Homebrew) can typically write: home folders, temp, /usr/local, /opt.
    public static func isUserWritable(_ path: String) -> Bool {
        let p = normalize(path)
        return p.hasPrefix("/Users/") || p.hasPrefix("/usr/local/") || p.hasPrefix("/opt/")
            || tempPrefixes.contains { p.hasPrefix($0) }
    }

    /// Hidden location: a dot-directory under ~/Library, or a dot-file executable anywhere in a home folder.
    public static func isHidden(_ rawPath: String) -> Bool {
        let p = normalize(rawPath)
        guard p.hasPrefix("/Users/") || tempPrefixes.contains(where: { p.hasPrefix($0) }) else { return false }
        let comps = p.split(separator: "/").map(String.init)
        guard comps.count >= 3 else { return false }
        // Skip /Users/<name>; dot-dirs directly in home (.cargo, .npm, .vscode...) are mostly tool caches,
        // so only count hidden components below ~/Library or the file name itself.
        if comps.last?.hasPrefix(".") == true { return true }
        if comps.count > 3, comps[2] == "Library" {
            return comps[3..<(comps.count - 1)].contains { $0.hasPrefix(".") && $0 != "." && $0 != ".." }
        }
        return false
    }

    public static func isInDownloads(_ path: String) -> Bool {
        normalize(path).range(of: #"^/Users/[^/]+/Downloads/"#, options: .regularExpression) != nil
    }

    static func normalize(_ p: String) -> String {
        var s = (p as NSString).standardizingPath
        if s.hasPrefix("/private/var/") || s.hasPrefix("/private/tmp/") || s.hasPrefix("/private/etc/") { s = String(s.dropFirst(8)) }
        return s
    }

    static let systemPrefixes = ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/", "/private/var/db/",
                                 "/var/db/", "/Library/Developer/CommandLineTools/"]
    static let tempPrefixes = ["/tmp/", "/var/tmp/", "/var/folders/", "/Users/Shared/"]

    static let developerMarkers = ["/Library/Developer/", "/DerivedData/", "/.build/", "/node_modules/", "/target/debug/",
                                   "/target/release/", "/.cargo/", "/.rustup/", "/go/pkg/", "/.swiftpm/", "/.pyenv/",
                                   "/.nvm/", "/.rbenv/", "/.gradle/", "/.m2/", "/.venv/", "/venv/", "/site-packages/",
                                   "/.vscode/extensions/", "/.cursor/extensions/", "/build/Debug/", "/build/Release/"]
    static func isDeveloper(_ p: String) -> Bool {
        if p.hasPrefix("/opt/homebrew/") || p.hasPrefix("/usr/local/Cellar/") || p.hasPrefix("/usr/local/Homebrew/")
            || p.hasPrefix("/usr/local/Caskroom/") || p.hasPrefix("/Library/Developer/") || p.hasPrefix("/opt/local/") { return true }
        if p.range(of: #"^/Users/[^/]+/(Developer|Projects|src|code|dev|git|GitHub|repos)/"#, options: .regularExpression) != nil { return true }
        return developerMarkers.contains { p.contains($0) }
    }
}
