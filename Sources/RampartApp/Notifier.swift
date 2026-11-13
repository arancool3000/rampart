import Foundation
import AppKit
import UserNotifications
import RampartShared
import RampartGuard

/// UNUserNotificationCenter wrapper. Threats always notify (they can be downgraded to banners in System Settings).
/// Everything else is rate-limited to one non-critical notification per hour and honours per-category toggles.
@MainActor
final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    static let shared = Notifier()

    enum Category: String { case threat = "app.rampart.threat", scan = "app.rampart.scan", network = "app.rampart.network", update = "app.rampart.update", weekly = "app.rampart.weekly", wifi = "app.rampart.wifi", lockdown = "app.rampart.lockdown", catMouse = "app.rampart.catmouse", catMouseContain = "app.rampart.catmouse.contain" }

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
        let restore = UNNotificationAction(identifier: "restoreInternet", title: EmergencyNotice.restoreAction, options: [.foreground])
        let details = UNNotificationAction(identifier: "lockdownDetails", title: EmergencyNotice.detailsAction, options: [.foreground])
        let lockdown = UNNotificationCategory(identifier: Category.lockdown.rawValue, actions: [restore, details], intentIdentifiers: [])
        let catDetails = UNNotificationAction(identifier: "catDetails", title: "Details", options: [.foreground])
        let catContain = UNNotificationAction(identifier: "catContain", title: "Contain it", options: [.destructive])
        let cat = UNNotificationCategory(identifier: Category.catMouse.rawValue, actions: [catDetails], intentIdentifiers: [])
        let catC = UNNotificationCategory(identifier: Category.catMouseContain.rawValue, actions: [catDetails, catContain], intentIdentifiers: [])
        center.setNotificationCategories([threat, wifi, lockdown, cat, catC])
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
        // hx8: the name comes from the file system or the detection; one clean, short, quoted line.
        let name = SafeText.line(d.path.map { ($0 as NSString).lastPathComponent } ?? d.name, max: 60)
        if d.category == .ransomware {
            post(.threat, title: "\(Product.name) stopped suspicious file changes", body: "\"\(name)\" started changing many files. It's been stopped.", critical: true)
        } else if d.resolved {
            post(.threat, title: "\(Product.name) blocked a threat", body: "\"\(name)\" was moved to quarantine. No action needed unless you recognize it.", critical: true)
        } else {
            post(.threat, title: "1 item needs your attention", body: "\(Product.name) stopped \"\(name)\". Open \(Product.name) to choose what to do next.", critical: true)
        }
    }

    /// Cat & Mouse: one notification per story (same identifier ⇒ a burst replaces it with a growing count).
    /// Never rate-limited. "Contain it" only while the named program is still running.
    func catMouse(_ a: CatMouseAlert) {
        guard let center else { return }
        let c = UNMutableNotificationContent()
        c.title = SafeText.line(a.title, max: 120)   // o8: process and file names inside come from the attacker
        c.body = SafeText.line(a.body, max: 400)
        c.threadIdentifier = Category.catMouse.rawValue
        let running = a.pid.map { $0 > 1 && kill($0, 0) == 0 } ?? false
        c.categoryIdentifier = (running && !a.calm ? Category.catMouseContain : Category.catMouse).rawValue
        var info: [String: String] = ["alertID": a.id.uuidString]
        if let id = a.catchID { info["catchID"] = id.uuidString }
        c.userInfo = info
        c.interruptionLevel = a.calm ? .passive : (a.timeSensitive ? .timeSensitive : .active)
        if !a.calm, defaults.bool(forKey: "notif.sounds") || a.timeSensitive { c.sound = .default }
        center.add(UNNotificationRequest(identifier: a.identifier, content: c, trigger: nil)) { _ in }
    }

    func scanFinished(_ r: ScanRecord) {
        guard AppModel.shared.settings.notifyInfo else { return }
        let body = r.found == 0 ? "No threats found. Checked \(Fmt.count(r.scanned)) files." : "Found \(r.found) item\(r.found == 1 ? "" : "s"). They've been moved to quarantine."
        post(.scan, title: "\(r.kind.title) finished", body: body, critical: false)
    }

    func post(_ cat: Category, title: String, body: String, critical: Bool, userInfo: [String: String] = [:]) {
        if !critical {
            if let last = lastNonCritical, Date().timeIntervalSince(last) < 3600 { return }   // max 1/hour
            lastNonCritical = Date()
        }
        guard let center else { return }
        let c = UNMutableNotificationContent()
        // o8: defence in depth; every caller already cleans the untrusted part, this keeps a forgotten one from
        // adding a fake second line ("All clear") or bidi tricks to the banner.
        c.title = SafeText.line(title, max: 120)
        c.body = SafeText.line(body, max: 400)
        c.threadIdentifier = cat.rawValue
        c.categoryIdentifier = cat.rawValue
        if !userInfo.isEmpty { c.userInfo = userInfo }
        if critical { c.interruptionLevel = .timeSensitive } else { c.interruptionLevel = .passive }
        if defaults.bool(forKey: "notif.sounds") { c.sound = .default }
        center.add(UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)) { _ in }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }

    /// Lockdown on / internet blocked / internet restored: always time-sensitive, never rate-limited.
    /// The notification is the ONLY user-visible signal when no window is open (user incident 2026-11-07).
    func lockdown(_ n: EmergencyNotice) {
        lastLockdownNotice = n
        post(.lockdown, title: n.title, body: n.body, critical: true)
        // Notifications off: bring the app forward on the Emergency screen instead (never in headless/dev runs).
        if authorized == false, EmergencyAppActions.sessionActionsAllowed, n.kind == .engaged || n.kind == .networkBlocked {
            AppModel.shared.selection = .emergency
            NSApp.activate(ignoringOtherApps: true)
        }
    }
    private(set) var lastLockdownNotice: EmergencyNotice?

    /// "Disconnecting from insecure Wi-Fi…" with a "Stay connected" action (PublicWiFiGuard grace period).
    func wifiDisconnectScheduled(networkName: String, reason: String) {
        // hx8: the network name is chosen by whoever runs the access point. Clean it and keep it short so it
        // can't carry a second, fake RamPart sentence.
        let name = SafeText.line(networkName, max: 32)
        let token = UUID().uuidString
        wifiActionToken = token
        post(.wifi, title: "Disconnecting from insecure Wi-Fi…", body: "\"\(name)\": \(SafeText.line(reason, max: 140)) Choose Stay connected to keep using it.",
             critical: true, userInfo: ["wifiToken": token])
    }

    /// hx8: "Stay connected" is honoured only for the newest Wi-Fi notification while its disconnect is pending.
    private(set) var wifiActionToken: String?

    static func shouldHonourStayConnected(category: String, token: String?, expected: String?, pending: Bool) -> Bool {
        guard category == Category.wifi.rawValue, pending, let token, let expected else { return false }
        return token == expected
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        if response.actionIdentifier == "stayConnected" {
            let category = response.notification.request.content.categoryIdentifier
            let token = response.notification.request.content.userInfo["wifiToken"] as? String
            await MainActor.run {
                let n = Notifier.shared
                guard Notifier.shouldHonourStayConnected(category: category, token: token, expected: n.wifiActionToken,
                                                         pending: PublicWiFiHost.shared.pendingDisconnect != nil) else { return }
                n.wifiActionToken = nil
                PublicWiFiHost.shared.stayConnected()
            }
            return
        }
        if ["restoreInternet", "lockdownDetails"].contains(response.actionIdentifier)
            || response.notification.request.content.categoryIdentifier == Category.lockdown.rawValue {
            let restore = response.actionIdentifier == "restoreInternet"
            await MainActor.run {
                NSApp.activate(ignoringOtherApps: true)
                AppModel.shared.selection = .emergency
                if restore { Task { await EmergencyModel.shared.killSwitch() } }
            }
            return
        }
        let cat = response.notification.request.content.categoryIdentifier
        let info = response.notification.request.content.userInfo, act = response.actionIdentifier
        if await MainActor.run(body: { MediaGuardNotifications.handle(category: cat, action: act, userInfo: info) }) { return }   // Camera & Mic, Download Gate
        if cat == Category.catMouse.rawValue || cat == Category.catMouseContain.rawValue {
            let action = response.actionIdentifier
            let catchID = (response.notification.request.content.userInfo["catchID"] as? String).flatMap(UUID.init(uuidString:))
            await MainActor.run {
                if action == "catContain", let id = catchID {
                    Task { await CatAndMouseModel.shared.contain(catchID: id) }
                } else if action == "catDetails" || action == UNNotificationDefaultActionIdentifier {
                    NSApp.activate(ignoringOtherApps: true)
                    AppModel.shared.selection = .catAndMouse
                }
            }
            return
        }
        guard response.actionIdentifier == UNNotificationDefaultActionIdentifier || ["review", "allow"].contains(response.actionIdentifier) else { return }
        let isThreat = response.notification.request.content.categoryIdentifier == Category.threat.rawValue
        let route = info["route"] as? String
        await MainActor.run {
            NSApp.activate(ignoringOtherApps: true)
            if isThreat { AppModel.shared.selection = .threats }
            if route == "appFirewall" { AppModel.shared.selection = .appFirewall }   // App Firewall first-connection prompt
        }
    }
}
