import Foundation
import AppKit
import UserNotifications
import RampartShared

/// UNUserNotificationCenter wrapper. Threats always notify (they can be downgraded to banners in System Settings).
/// Everything else is rate-limited to one non-critical notification per hour and honours per-category toggles.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()

    enum Category: String { case threat = "app.rampart.threat", scan = "app.rampart.scan", network = "app.rampart.network", update = "app.rampart.update", weekly = "app.rampart.weekly", wifi = "app.rampart.wifi" }

    private let defaults = UserDefaults.standard
    private var lastNonCritical: Date? {
        get { defaults.object(forKey: "notif.lastNonCritical") as? Date }
        set { defaults.set(newValue, forKey: "notif.lastNonCritical") }
    }
    private var recentThreatIDs: [UUID: Date] = [:]
    private(set) var authorized: Bool? = nil

    /// UNUserNotificationCenter crashes if the process has no bundle identifier (e.g. bare `swift run`).
    private var center: UNUserNotificationCenter? { Bundle.main.bundleIdentifier == nil ? nil : UNUserNotificationCenter.current() }

    func configure() {
        guard let center else { return }
        center.delegate = self
        let review = UNNotificationAction(identifier: "review", title: "Review", options: [.foreground])
        let allow = UNNotificationAction(identifier: "allow", title: "Allow…", options: [.foreground])
        let threat = UNNotificationCategory(identifier: Category.threat.rawValue, actions: [review, allow], intentIdentifiers: [])
        let stay = UNNotificationAction(identifier: "stayConnected", title: "Stay connected", options: [])
        let wifi = UNNotificationCategory(identifier: Category.wifi.rawValue, actions: [stay], intentIdentifiers: [])
        center.setNotificationCategories([threat, wifi])
        center.getNotificationSettings { s in
            let ok = s.authorizationStatus == .authorized || s.authorizationStatus == .provisional
            DispatchQueue.main.async { MainActor.assumeIsolated { Notifier.shared.authorized = ok } }
        }
    }

    func authorizationStatus() async -> UNAuthorizationStatus? {
        guard let center else { return nil }
        return await center.notificationSettings().authorizationStatus
    }

    /// The "Allow…" button: asks macOS when it hasn't asked yet; otherwise only System Settings can change it.
    /// Returns true when notifications are now allowed.
    @discardableResult
    func allowOrOpenSettings() async -> Bool {
        let status = await authorizationStatus()
        if status == .notDetermined { return await requestAuthorization() }
        if status == .authorized || status == .provisional { authorized = true; return true }
        let id = Bundle.main.bundleIdentifier ?? "app.rampart.app"
        let candidates = ["x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(id)",
                          "x-apple.systempreferences:com.apple.Notifications-Settings.extension",
                          "x-apple.systempreferences:com.apple.preference.notifications"]
        for c in candidates {
            if let url = URL(string: c), NSWorkspace.shared.open(url) { break }
        }
        return false
    }

    func requestAuthorization() async -> Bool {
        guard let center else { return false }
        let ok = (try? await center.requestAuthorization(options: [.alert, .sound, .badge])) ?? false
        authorized = ok
        return ok
    }

    func threat(_ d: Detection) {
        guard AppModel.shared.settings.notifyThreats else { return }
        // De-duplicate repeated reports of the same detection within 10 minutes.
        if let last = recentThreatIDs[d.id], Date().timeIntervalSince(last) < 600 { return }
        recentThreatIDs[d.id] = Date()
        let name = d.path.map { ($0 as NSString).lastPathComponent } ?? d.name
        if d.category == .ransomware {
            post(.threat, title: "\(Product.name) stopped suspicious file changes", body: "\"\(name)\" started changing many files. It's been stopped.", critical: true)
        } else if d.resolved {
            post(.threat, title: "\(Product.name) blocked a threat", body: "\"\(name)\" was moved to quarantine. No action needed unless you recognize it.", critical: true)
        } else {
            post(.threat, title: "1 item needs your attention", body: "\(Product.name) stopped \"\(name)\". Open \(Product.name) to choose what to do next.", critical: true)
        }
    }

    func scanFinished(_ r: ScanRecord) {
        guard AppModel.shared.settings.notifyInfo else { return }
        let body = r.found == 0 ? "No threats found. Checked \(Fmt.count(r.scanned)) files." : "Found \(r.found) item\(r.found == 1 ? "" : "s"). They've been moved to quarantine."
        post(.scan, title: "\(r.kind.title) finished", body: body, critical: false)
    }

    func post(_ cat: Category, title: String, body: String, critical: Bool) {
        if !critical {
            if let last = lastNonCritical, Date().timeIntervalSince(last) < 3600 { return }   // max 1/hour
            lastNonCritical = Date()
        }
        guard let center else { return }
        let c = UNMutableNotificationContent()
        c.title = title
        c.body = body
        c.threadIdentifier = cat.rawValue
        c.categoryIdentifier = cat.rawValue
        if critical { c.interruptionLevel = .timeSensitive } else { c.interruptionLevel = .passive }
        if defaults.bool(forKey: "notif.sounds") { c.sound = .default }
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)) { _ in }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    /// "Disconnecting from insecure Wi-Fi…" with a "Stay connected" action (PublicWiFiGuard grace period).
    func wifiDisconnectScheduled(networkName: String, reason: String) {
        post(.wifi, title: "Disconnecting from insecure Wi-Fi…", body: "\(networkName): \(reason) Choose Stay connected to keep using it.", critical: true)
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        if response.actionIdentifier == "stayConnected" {
            await MainActor.run { PublicWiFiHost.shared.stayConnected() }
            return
        }
        let isThreat = response.notification.request.content.categoryIdentifier == Category.threat.rawValue
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            if isThreat { AppModel.shared.selection = .threats }
        }
    }
}
