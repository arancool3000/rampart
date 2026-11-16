import Foundation
import RampartShared

/// While Desktop Mode is on, hides Finder's desktop files and macOS's own desktop widgets so only RamPart's layer
/// shows. These are the same switches as System Settings › Desktop & Dock ("Show Items" / "Show Widgets").
/// The user's original values are saved first and put back when Desktop Mode turns off, at next launch if
/// RamPart quit while it was on, and by `restoreIfNeeded()` from anywhere.
enum DesktopCleaner {
    static let domain = "com.apple.WindowManager" as CFString
    static let keys = ["StandardHideDesktopIcons", "StandardHideWidgets", "StageManagerHideWidgets", "HideDesktop"]
    static let savedKey = "desktop.cleaner.saved"   // [key: Bool] of the user's values, present only while applied

    /// Values to write while clean: everything hidden.
    static func cleanValues() -> [String: Bool] { Dictionary(uniqueKeysWithValues: keys.map { ($0, true) }) }

    /// What to restore given saved originals (missing key → it was unset → false, the macOS default).
    static func restoreValues(_ saved: [String: Bool]) -> [String: Bool] {
        Dictionary(uniqueKeysWithValues: keys.map { ($0, saved[$0] ?? false) })
    }

    static func apply() {
        guard !Headless.active else { return }
        let d = UserDefaults.standard
        if d.dictionary(forKey: savedKey) == nil {
            var saved: [String: Bool] = [:]
            for k in keys { saved[k] = CFPreferencesCopyAppValue(k as CFString, domain) as? Bool ?? false }
            d.set(saved, forKey: savedKey)
        }
        write(cleanValues())
    }

    static func restoreIfNeeded() {
        guard !Headless.active, let saved = UserDefaults.standard.dictionary(forKey: savedKey) as? [String: Bool] else { return }
        write(restoreValues(saved))
        UserDefaults.standard.removeObject(forKey: savedKey)
    }

    private static func write(_ v: [String: Bool]) {
        for (k, b) in v { CFPreferencesSetAppValue(k as CFString, b as CFBoolean, domain) }
        CFPreferencesAppSynchronize(domain)
        // WindowManager listens for this when System Settings flips the same switches.
        DistributedNotificationCenter.default().postNotificationName(.init("com.apple.WindowManager.PreferencesChanged"), object: nil, deliverImmediately: true)
    }
}
