import SwiftUI
import AppKit
import ApplicationServices
import UserNotifications
import RampartShared

/// "Set up RamPart": every permission in one place, granted in one sitting.
/// Detection polls every second while visible. In headless/test runs nothing is ever requested or opened
/// (ZERO POP-UPS RULE); the checklist only renders its current state.
@MainActor
@Observable
final class PermissionsModel {
    enum Status: Equatable { case granted, needed, optional, unknown }
    enum Row: String, CaseIterable, Identifiable {
        case admin, fullDisk, notifications, paste, localNetwork, accessibility
        var id: String { rawValue }
        var title: String {
            switch self {
            case .admin: return "Admin access"
            case .fullDisk: return "Full Disk Access"
            case .notifications: return "Notifications"
            case .paste: return "Paste from Other Apps"
            case .localNetwork: return "Local Network"
            case .accessibility: return "Accessibility"
            }
        }
        var reason: String {
            switch self {
            case .admin: return "One password prompt installs the system service for web protection and system-wide monitoring."
            case .fullDisk: return "Lets \(Product.name) check protected folders like Mail and Messages for threats."
            case .notifications: return "So \(Product.name) can tell you when it blocks a threat."
            case .paste: return "Set to Allow so Paste Guard can check commands you copy before you run them, and Scam Check can read pasted text."
            case .localNetwork: return "Lets Network Scan find the devices on your Wi-Fi."
            case .accessibility: return "Lets \(Product.name) set up Safari protection for you with one button."
            }
        }
        var symbol: String {
            switch self {
            case .admin: return "lock.shield"; case .fullDisk: return "internaldrive"; case .notifications: return "bell.badge"
            case .paste: return "doc.on.clipboard"; case .localNetwork: return "network"; case .accessibility: return "accessibility"
            }
        }
        var settingsURL: URL? {
            let base = "x-apple.systempreferences:com.apple.preference.security?"
            switch self {
            case .admin: return nil
            case .fullDisk: return URL(string: base + "Privacy_AllFiles")
            case .notifications: return URL(string: "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=\(Bundle.main.bundleIdentifier ?? "app.rampart.app")")
            case .paste: return URL(string: base + "Privacy_Pasteboard")
            case .localNetwork: return URL(string: base + "Privacy_LocalNetwork")
            case .accessibility: return URL(string: base + "Privacy_Accessibility")
            }
        }
    }

    static let networkScanEnabledKey = "features.networkScan.enabled"
    static let safariSetupEnabledKey = "features.safariSetup.enabled"

    private(set) var statuses: [Row: Status] = [:]
    private(set) var walking: Row?        // "Grant all remaining" in progress
    @ObservationIgnored private var timer: Timer?
    @ObservationIgnored private var visibleCount = 0
    @ObservationIgnored private var notifStatus: UNAuthorizationStatus?

    var rows: [Row] {
        Row.allCases.filter { r in
            switch r {
            case .localNetwork: return UserDefaults.standard.bool(forKey: Self.networkScanEnabledKey)
            case .accessibility: return UserDefaults.standard.bool(forKey: Self.safariSetupEnabledKey)
            default: return true
            }
        }
    }
    var remaining: [Row] { rows.filter { statuses[$0] == .needed } }

    func status(_ r: Row) -> Status { statuses[r] ?? .unknown }

    func appear() {
        visibleCount += 1
        refresh()
        guard timer == nil, !Headless.active else { return }
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { _ in
            MainActor.assumeIsolated { PermissionsModel.shared.refresh() }
        }
    }
    func disappear() {
        visibleCount = max(0, visibleCount - 1)
        if visibleCount == 0 { timer?.invalidate(); timer = nil; walking = nil }
    }

    static let shared = PermissionsModel()

    func refresh() {
        var s: [Row: Status] = [:]
        let model = AppModel.shared
        s[.admin] = model.source == .systemService ? .granted : .needed
        s[.fullDisk] = Headless.active ? .needed : (FDAProbe.check() ? .granted : .needed)
        if Headless.active || Bundle.main.bundleIdentifier == nil {
            s[.notifications] = .needed
        } else {
            switch notifStatus {
            case .authorized?, .provisional?, .ephemeral?: s[.notifications] = .granted
            case nil: s[.notifications] = .unknown
            default: s[.notifications] = .needed
            }
            UNUserNotificationCenter.current().getNotificationSettings { st in
                let a = st.authorizationStatus
                DispatchQueue.main.async { MainActor.assumeIsolated { PermissionsModel.shared.notifStatus = a } }
            }
        }
        // Reading accessBehavior is a status check only; it never touches the pasteboard's contents.
        if Headless.active {
            s[.paste] = .needed
        } else if let pg = PasteGuardStatusBox.shared.status, pg != .stopped {
            s[.paste] = pg == .active ? .granted : .needed
        } else if #available(macOS 15.4, *) {
            s[.paste] = NSPasteboard.general.accessBehavior == .alwaysAllow ? .granted : .needed
        } else {
            s[.paste] = .granted   // older macOS doesn't ask
        }
        s[.localNetwork] = .optional   // macOS offers no status API; checked in System Settings
        s[.accessibility] = Headless.active ? .needed : (AXIsProcessTrusted() ? .granted : .needed)
        if s != statuses { statuses = s }
        if let w = walking, status(w) == .granted { advanceWalk() }
    }

    /// Opens exactly the right place for one row. No-op in test runs.
    func grant(_ r: Row) {
        guard !Headless.active else { return }
        switch r {
        case .admin:
            FullProtectionInstaller.shared.run()
        case .notifications where notifStatus == .notDetermined:
            Task { _ = await Notifier.shared.requestAuthorization(); refresh() }
        default:
            if let u = r.settingsURL { NSWorkspace.shared.open(u) }
        }
    }

    func grantAllRemaining() {
        guard !Headless.active, let first = remaining.first else { return }
        walking = first
        grant(first)
    }

    func skipCurrent() { advanceWalk() }

    private func advanceWalk() {
        guard let w = walking else { return }
        let rest = remaining.filter { $0 != w }
        let order = rows
        let next = rest.first { (order.firstIndex(of: $0) ?? 0) > (order.firstIndex(of: w) ?? 0) } ?? rest.first
        walking = next
        if let next { grant(next) }
    }
}

struct PermissionsChecklistView: View {
    var showsHeader = true
    private let perms = PermissionsModel.shared
    @Environment(AppModel.self) private var model
    @StateVar private var showInstall = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            if showsHeader {
                Text("Set up \(Product.name)").font(.title2.weight(.bold)).fontDesign(.rounded)
            }
            Text("macOS asks for each permission separately so no app can take everything with one click.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            VStack(spacing: 0) {
                ForEach(Array(perms.rows.enumerated()), id: \.element) { i, r in
                    if i > 0 { Divider().padding(.leading, 48) }
                    row(r)
                }
            }
            .card(padding: Spacing.s)
            HStack {
                let left = perms.remaining.count
                Text(left == 0 ? "Everything's set up." : "\(left) left to grant")
                    .font(.callout).foregroundStyle(.secondary)
                Spacer()
                if perms.walking != nil {
                    Button("Skip This One") { perms.skipCurrent() }
                }
                Button(perms.walking == nil ? "Grant All Remaining" : "Waiting for macOS…") { perms.grantAllRemaining() }
                    .buttonStyle(GlowButtonStyle())
                    .disabled(left == 0 || perms.walking != nil)
            }
        }
        .onAppear { perms.appear() }
        .onDisappear { perms.disappear() }
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
    }

    @ViewBuilder private func row(_ r: PermissionsModel.Row) -> some View {
        let st = perms.status(r)
        HStack(spacing: Spacing.m) {
            IconBadge(symbol: r.symbol, tint: st == .granted ? .statusProtected : .rampartTeal, size: 32)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(r.title).font(.body.weight(.medium))
                    if perms.walking == r { ProgressView().controlSize(.mini) }
                }
                Text(r.reason).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            switch st {
            case .granted:
                StatusLabel(text: "Granted", symbol: "checkmark.circle.fill", tint: .statusProtected).font(.callout)
            case .optional:
                StatusLabel(text: "Optional", symbol: "circle.dashed", tint: .secondary).font(.callout)
                Button("Open") { perms.grant(r) }.controlSize(.small)
            case .needed, .unknown:
                StatusLabel(text: st == .unknown ? "Checking…" : "Needed", symbol: "circle", tint: .secondary).font(.callout)
                Button("Grant") { if r == .admin { showInstall = true } else { perms.grant(r) } }.controlSize(.small)
            }
        }
        .padding(Spacing.s)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(r.title): \(st == .granted ? "granted" : st == .optional ? "optional" : "needed"). \(r.reason)")
    }
}

/// Sheet wrapper used from Settings.
struct PermissionsSheet: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            PermissionsChecklistView()
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl)
        .frame(width: 600)
    }
}
