import Foundation

/// wms-o3 (fingerprinting): WKWebView's default user agent has no "Version/x Safari/y" suffix, which singles
/// RamPart Secure Browser users out (and some sites treat it as an in-app web view). The browser presents
/// itself as the Safari installed on this Mac. Pure, so `--selftest` covers it.
enum UserAgentPolicy {
    static let fallbackVersion = "18.0"
    static let webKitToken = "605.1.15"   // WebKit freezes this token in Safari's UA

    /// "Version/<v> Safari/605.1.15". `version` is Safari's CFBundleShortVersionString; anything that isn't
    /// a plain dotted number (a tampered plist, say) falls back to a fixed value rather than reaching the UA.
    static func applicationName(safariVersion version: String?) -> String {
        let v = (version ?? "").trimmingCharacters(in: .whitespaces)
        let ok = !v.isEmpty && v.count <= 12 && v.split(separator: ".", omittingEmptySubsequences: false).allSatisfy { !$0.isEmpty && $0.allSatisfy(\.isASCII) && $0.allSatisfy(\.isNumber) }
        return "Version/\(ok ? v : fallbackVersion) Safari/\(webKitToken)"
    }

    static func installedSafariVersion() -> String? {
        let url = URL(fileURLWithPath: "/Applications/Safari.app/Contents/Info.plist")
        guard let d = try? Data(contentsOf: url),
              let p = try? PropertyListSerialization.propertyList(from: d, format: nil) as? [String: Any] else { return nil }
        return p["CFBundleShortVersionString"] as? String
    }

    static var current: String { applicationName(safariVersion: installedSafariVersion()) }
}
