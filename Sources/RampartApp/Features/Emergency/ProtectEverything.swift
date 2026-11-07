import SwiftUI
import AppKit
import RampartShared
import RampartGuard

/// "Protect Everything": one switch that turns every protection on through the existing IPC calls, shows a
/// checklist of what turned on and what still needs a permission or admin step, and can go back to how things were.
@MainActor
@Observable
final class ProtectEverythingModel {
    static let shared = ProtectEverythingModel()
    var steps: [ProtectStep] = []
    var busy = false
    var error: String?
    var savedPrevious: ProtectSnapshot? { Self.loadPrevious() }
    var isOn: Bool { Self.loadPrevious() != nil }

    private static let key = "protectEverything.previous"
    private static func loadPrevious() -> ProtectSnapshot? {
        UserDefaults.standard.data(forKey: key).flatMap { try? JSONDecoder.rampart.decode(ProtectSnapshot.self, from: $0) }
    }
    private static func savePrevious(_ s: ProtectSnapshot?) {
        if let s, let d = try? JSONEncoder.rampart.encode(s) { UserDefaults.standard.set(d, forKey: key) } else { UserDefaults.standard.removeObject(forKey: key) }
    }

    private var app: AppModel { AppModel.shared }

    /// Current state from existing IPC replies and the session hosts.
    func snapshot() async -> ProtectSnapshot {
        var remote: Bool?
        var tamper = false
        if app.mode == .live {
            if case .remoteAccess(let d)? = try? await app.client.request(.remoteAccessReport),
               let r = try? JSONDecoder.rampart.decode(RemoteAccessReportDTO.self, from: d) { remote = r.lockdownEnabled }
            if case .tamper(let d)? = try? await app.client.request(.tamperStatus),
               let o = try? JSONSerialization.jsonObject(with: d) as? [String: Any] { tamper = (o["mode"] as? String) == "enforcing" }
        }
        let paste: String = {
            guard PublicWiFiHost.allowed else { return "unavailable" }
            switch PasteGuardStatusBox.shared.status {
            case .active?: return "active"
            case .needsPermission?: return "needsPermission"
            case .denied?: return "denied"
            case .stopped?, nil: return "stopped"
            }
        }()
        return ProtectSnapshot(settings: app.settings, remoteLockdown: remote, webProtectionAvailable: app.webProtectionAvailable && app.health?.mode == "root",
                               postureFailing: app.posture.filter { $0.state == .fail }.map(\.id), pasteGuard: paste,
                               publicWiFiGuardOn: PublicWiFiHost.allowed, publicWiFiDisconnect: true, tamperEnforcing: tamper,
                               breachChecksOn: PasswordsModel.shared.lastBreachSweep != nil, systemService: app.health?.mode == "root")
    }

    func refresh() async { steps = ProtectEverythingPlanner.plan(await snapshot()) }

    func turnOn() async {
        busy = true; defer { busy = false }
        error = nil
        let before = await snapshot()
        if Self.loadPrevious() == nil { Self.savePrevious(before) }
        let plan = ProtectEverythingPlanner.plan(before)
        app.updateSettings { $0 = ProtectEverythingPlanner.everythingOn($0, webAvailable: before.webProtectionAvailable) }
        for s in plan where s.status == .willTurnOn {
            switch s.via {
            case .setRealtime: app.setRealtime(true)
            case .setWebProtection: await app.setWebProtection(true)
            case .setRemoteLockdown: await request(.setRemoteLockdown(on: true))
            case .fixPosture: await request(.fixPosture(checkID: s.id == .firewall ? "firewall" : "stealthMode"), timeout: 60)
            case .appLocal:
                if s.id == .pasteGuard { PasteGuardHost.shared.start() }
                if s.id == .publicWiFiGuard { PublicWiFiHost.shared.start() }
            case .settings, .none: break
            }
        }
        try? await Task.sleep(nanoseconds: 600_000_000)
        let after = ProtectEverythingPlanner.plan(await snapshot())
        steps = after.map { s in
            var s = s
            if s.status == .alreadyOn, plan.first(where: { $0.id == s.id })?.status == .willTurnOn { s.status = .turnedOn }
            if s.status == .willTurnOn, plan.first(where: { $0.id == s.id })?.status == .willTurnOn { s.status = .failed }
            return s
        }
        app.activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Protect Everything turned on", outcome: "\(steps.filter { $0.status == .turnedOn }.count) turned on"), at: 0)
    }

    /// Back to the state saved when the switch went on. macOS firewall fixes stay (turn them off in System Settings).
    func turnOff() async {
        guard let prev = Self.loadPrevious() else { return }
        busy = true; defer { busy = false }
        app.updateSettings { $0 = ProtectEverythingPlanner.revert(current: $0, previous: prev.settings) }
        if prev.settings.realtimeOn != app.settings.realtimeOn { app.setRealtime(prev.settings.realtimeOn) }
        if !prev.settings.webProtection, app.status.webProtectionOn { await app.setWebProtection(false) }
        if prev.remoteLockdown == false { await request(.setRemoteLockdown(on: false)) }
        if prev.pasteGuard == "stopped" { PasteGuardHost.shared.stop() }
        Self.savePrevious(nil)
        await refresh()
        app.activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Protect Everything turned off", outcome: "Previous settings restored"), at: 0)
    }

    private func request(_ r: IPCRequest, timeout: TimeInterval = 10) async {
        guard app.mode == .live else { return }
        do { if case .error(let e) = try await app.client.request(r, timeout: timeout) { error = e } } catch { self.error = error.localizedDescription }
    }

    /// The button for a step that needs the user. Opens things only on click.
    func grant(_ s: ProtectStep) {
        switch s.id {
        case .pasteGuard:
            if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Privacy_Accessibility") { NSWorkspace.shared.open(u) }
        case .breachChecks: app.selection = .passwords
        case .firewall, .stealthMode:
            if app.health?.mode == "root" { Task { await request(.fixPosture(checkID: s.id == .firewall ? "firewall" : "stealthMode"), timeout: 60); await refresh() } }
            else if let u = URL(string: "x-apple.systempreferences:com.apple.preference.security?Firewall") { NSWorkspace.shared.open(u) }
        case .webProtection, .tamperProtection: FullProtectionInstaller.shared.run()
        default: break
        }
    }
}

struct ProtectEverythingView: View {
    private var m: ProtectEverythingModel { ProtectEverythingModel.shared }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text("Protect Everything").font(.title3.weight(.semibold)).fontDesign(.rounded)
                    Text("One switch for every protection \(Product.name) has. Turn it off to go back to exactly how things were.")
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if m.busy { ProgressView().controlSize(.small) }
                Toggle("Protect Everything", isOn: Binding(get: { m.isOn }, set: { on in Task { on ? await m.turnOn() : await m.turnOff() } }))
                    .toggleStyle(.switch).labelsHidden().disabled(m.busy)
                    .accessibilityLabel("Protect Everything")
            }
            if let e = m.error { Text(SafeText.line(e, max: 240)).font(.caption).foregroundStyle(Color.statusAction) }
            ForEach(m.steps) { s in row(s) }
        }
        .card()
        .task { await m.refresh() }
    }

    private func row(_ s: ProtectStep) -> some View {
        let (icon, tint, label): (String, Color, String) = {
            switch s.status {
            case .alreadyOn: return ("checkmark.circle.fill", .statusProtected, "On")
            case .turnedOn: return ("checkmark.circle.fill", .statusProtected, "Turned on")
            case .willTurnOn: return ("circle", .secondary, "Off")
            case .needsPermission: return ("hand.raised.circle", .statusAttention, "Needs permission")
            case .needsAdmin: return ("person.badge.key", .statusAttention, "Needs admin")
            case .unavailable: return ("minus.circle", .secondary, "Not available")
            case .failed: return ("exclamationmark.triangle", .statusAttention, "Didn't turn on")
            }
        }()
        return HStack(alignment: .firstTextBaseline, spacing: Spacing.m) {
            Image(systemName: icon).foregroundStyle(tint).frame(width: 18).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(s.title)
                if !s.note.isEmpty { Text(SafeText.line(s.note, max: 240)).font(.caption).foregroundStyle(.secondary) }
            }
            Spacer()
            if s.needsUser || s.status == .failed {
                Button(s.status == .needsAdmin ? "Set Up…" : "Grant…") { m.grant(s) }.controlSize(.small)
            }
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}
