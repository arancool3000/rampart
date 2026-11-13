import Foundation
import Observation
import SwiftUI
import UserNotifications
import RampartShared
import RampartGuard

// Download Gate + Camera & Microphone Guard: app-side state. Both services run in the user-session daemon
// (rampartd/Core/FeatureServices.swift); status changes and alerts are pushed on the event stream.

@MainActor
@Observable
final class DownloadGateModel {
    static let shared = DownloadGateModel()
    var status: DownloadGateStatus?
    var unsupported = false
    var error: String?
    var busy = false

    private var client: DaemonClient { AppModel.shared.client }
    @ObservationIgnored private var notified: Set<UUID> = []
    @ObservationIgnored private var primed = false

    var held: [GateItem] { (status?.items ?? []).filter { $0.verdict == .held } }
    var blocked: [GateItem] { (status?.items ?? []).filter { $0.verdict == .blocked } }
    var cleared: [GateItem] { (status?.items ?? []).filter { [.cleared, .allowed, .deleted].contains($0.verdict) } }

    private func apply(_ r: IPCResponse?) {
        switch r {
        case .downloadGate(let d)?: receive(d)
        case .error(let e)?: error = e
        default: unsupported = true
        }
    }

    func refresh() async { apply(try? await client.request(.downloadGateStatus)) }
    func backgroundPoll() async {
        if case .downloadGate(let d)? = try? await client.request(.downloadGateStatus) { receive(d) }
    }
    func setEnabled(_ on: Bool) async { busy = true; apply(try? await client.request(.downloadGateSetEnabled(on: on))); busy = false }
    func decide(_ id: UUID, allow: Bool) async {
        busy = true
        AppModel.shared.noteActivityActor(place: "Download Gate")
        apply(try? await client.request(.downloadGateDecide(id: id, allow: allow)))
        busy = false
    }

    /// Status from a reply or a push. New held / blocked files notify once (not the ones already there at launch).
    func receive(_ d: Data) {
        guard let s = try? JSONDecoder.rampart.decode(DownloadGateStatus.self, from: d) else { return }
        status = s; unsupported = false; error = nil
        let fresh = s.items.filter { ($0.verdict == .held || $0.verdict == .blocked) && !notified.contains($0.id) }
        for i in fresh {
            notified.insert(i.id)
            guard primed, Date().timeIntervalSince(i.checked) < 600 else { continue }
            let name = SafeText.line(i.name, max: 60)
            if i.verdict == .blocked {
                Notifier.shared.post(.threat, title: "\(Product.name) blocked a download", body: "\"\(name)\": \(i.threat ?? "malware"). It was moved to quarantine before it could run.",
                                     critical: true, userInfo: ["route": SidebarItem.downloadGate.rawValue])
            } else {
                Notifier.shared.post(.threat, title: "Held for your review", body: "\"\(name)\" isn't signed by a developer Apple knows, so it can't run until you allow it.",
                                     critical: true, userInfo: ["route": SidebarItem.downloadGate.rawValue])
            }
        }
        primed = true
    }
}

@MainActor
@Observable
final class MediaGuardModel {
    static let shared = MediaGuardModel()
    var status: MediaGuardStatus?
    var unsupported = false
    var error: String?
    var busy = false
    /// App id waiting for the "Stop it" confirmation (the screen shows the dialog).
    var confirmStop: String?

    private var client: DaemonClient { AppModel.shared.client }
    @ObservationIgnored private var posted: Set<UUID> = []

    var cameraOn: Bool { status?.cameraOn ?? false }
    var micOn: Bool { status?.micOn ?? false }
    var tone: DeceptionTone { status?.config.tone ?? .playful }

    private func apply(_ r: IPCResponse?) {
        switch r {
        case .mediaGuard(let d)?: receiveStatus(d)
        case .error(let e)?: error = e
        default: unsupported = true
        }
    }

    func refresh() async { apply(try? await client.request(.mediaGuardStatus)) }
    func backgroundPoll() async {
        if case .mediaGuard(let d)? = try? await client.request(.mediaGuardStatus) { receiveStatus(d) }
    }
    func setEnabled(_ on: Bool) async { busy = true; apply(try? await client.request(.mediaGuardSetEnabled(on: on))); busy = false }
    func setTone(serious: Bool) async { apply(try? await client.request(.mediaGuardSetTone(serious: serious))) }
    func trust(_ appID: String, _ trusted: Bool) async {
        AppModel.shared.noteActivityActor(place: "Camera & Mic")
        apply(try? await client.request(.mediaGuardTrust(appID: appID, trusted: trusted)))
    }
    func stop(_ appID: String) async {
        busy = true
        AppModel.shared.noteActivityActor(place: "Camera & Mic")
        apply(try? await client.request(.mediaGuardStop(appID: appID)))
        busy = false
    }

    func receiveStatus(_ d: Data) {
        guard let s = try? JSONDecoder.rampart.decode(MediaGuardStatus.self, from: d) else { return }
        status = s; unsupported = false; error = nil
        MediaIndicator.shared.update(s)
        for a in s.alerts where !posted.contains(a.id) {   // alerts missed while no app was listening (15 min)
            posted.insert(a.id)
            if Date().timeIntervalSince(a.date) < 900 { MediaGuardNotifications.post(a) }
        }
    }

    func receiveAlert(_ d: Data) {
        guard let a = try? JSONDecoder.rampart.decode(MediaGuardAlert.self, from: d), !posted.contains(a.id) else { return }
        posted.insert(a.id)
        MediaGuardNotifications.post(a)
        Task { await refresh() }
    }

    /// Notification actions: "Trust this app" acts at once; "Stop it…" opens the app to confirm.
    func handleNotification(action: String, appID: String?) {
        NSApp.activate(ignoringOtherApps: true)
        AppModel.shared.selection = .mediaGuard
        guard let appID else { return }
        if action == MediaGuardNotifications.trustAction { Task { await trust(appID, true) } }
        if action == MediaGuardNotifications.stopAction { confirmStop = appID }
    }
}

/// Time-sensitive notification per camera / microphone alert (one per app + device; a repeat replaces it).
enum MediaGuardNotifications {
    static let category = "app.rampart.mediaguard"
    static let categoryStop = "app.rampart.mediaguard.stop"
    static let stopAction = "mediaStop", trustAction = "mediaTrust", detailsAction = "mediaDetails"
    nonisolated(unsafe) private static var registered = false

    @MainActor static func post(_ a: MediaGuardAlert) {
        guard Bundle.main.bundleIdentifier != nil, !Headless.active else { return }
        let center = UNUserNotificationCenter.current()
        if !registered {
            registered = true
            let details = UNNotificationAction(identifier: detailsAction, title: "Details", options: [.foreground])
            let trust = UNNotificationAction(identifier: trustAction, title: "Trust this app", options: [])
            let stop = UNNotificationAction(identifier: stopAction, title: "Stop it…", options: [.foreground, .destructive])
            let plain = UNNotificationCategory(identifier: category, actions: [details, trust], intentIdentifiers: [])
            let withStop = UNNotificationCategory(identifier: categoryStop, actions: [stop, trust, details], intentIdentifiers: [])
            center.getNotificationCategories { cats in
                center.setNotificationCategories(cats.filter { ![category, categoryStop].contains($0.identifier) }.union([plain, withStop]))
            }
        }
        let c = UNMutableNotificationContent()
        c.title = SafeText.line(a.title, max: 120)   // o8: the app name inside is chosen by whoever built that app
        c.body = SafeText.line(a.body, max: 400)
        c.threadIdentifier = category
        c.categoryIdentifier = a.canStop ? categoryStop : category
        c.userInfo = ["appID": a.appID, "route": SidebarItem.mediaGuard.rawValue]
        c.interruptionLevel = a.timeSensitive ? .timeSensitive : .active
        c.sound = .default
        center.add(UNNotificationRequest(identifier: a.identifier, content: c, trigger: nil)) { _ in }
    }

    /// Called from Notifier's delegate. Returns true when it handled the response.
    @MainActor static func handle(category: String, action: String, userInfo: [AnyHashable: Any]) -> Bool {
        if category == Self.category || category == categoryStop {
            MediaGuardModel.shared.handleNotification(action: action, appID: userInfo["appID"] as? String)
            return true
        }
        if let route = userInfo["route"] as? String, let item = SidebarItem(rawValue: route), action == UNNotificationDefaultActionIdentifier {
            NSApp.activate(ignoringOtherApps: true)
            AppModel.shared.selection = item
            return true
        }
        return false
    }
}

enum Durations {
    static func text(_ secs: TimeInterval) -> String {
        let s = Int(secs.rounded())
        if s < 60 { return "\(s) s" }
        if s < 3600 { return "\(s / 60) min" + (s % 60 > 0 ? " \(s % 60) s" : "") }
        return "\(s / 3600) h \(s % 3600 / 60) min"
    }
}

/// Live camera / microphone indicator state, kept tiny so the menu bar label only re-renders when it changes.
@MainActor
@Observable
final class MediaIndicator {
    static let shared = MediaIndicator()
    private(set) var camera = false
    private(set) var microphone = false
    private(set) var apps: [String] = []
    var active: Bool { camera || microphone }
    func update(_ s: MediaGuardStatus) {
        let names = Array(Set(s.active.map { SafeText.line($0.appName, max: 40) })).sorted()
        if camera != s.cameraOn { camera = s.cameraOn }
        if microphone != s.micOn { microphone = s.micOn }
        if apps != names { apps = names }
    }
}

/// Menu bar / in-app indicator: a small camera or mic glyph while either is on.
struct MediaInUseBadge: View {
    let indicator = MediaIndicator.shared
    var compact = true
    var body: some View {
        if indicator.active {
            HStack(spacing: 3) {
                if indicator.camera { Image(systemName: "video.fill") }
                if indicator.microphone { Image(systemName: "mic.fill") }
                if !compact, !indicator.apps.isEmpty { Text(indicator.apps.joined(separator: ", ")).lineLimit(1) }
            }
            .accessibilityLabel("\(indicator.camera ? "Camera" : "Microphone") in use\(indicator.apps.isEmpty ? "" : " by " + indicator.apps.joined(separator: ", "))")
        }
    }
}
