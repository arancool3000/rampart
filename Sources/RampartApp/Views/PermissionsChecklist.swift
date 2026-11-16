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
        /// Where to click in System Settings, as a breadcrumb for the mini illustration.
        var settingsPath: [String] {
            switch self {
            case .admin: return ["Password prompt", "Install"]
            case .fullDisk: return ["Privacy & Security", "Full Disk Access"]
            case .notifications: return ["Notifications", Product.name]
            case .paste: return ["Privacy & Security", "Paste from Other Apps"]
            case .localNetwork: return ["Privacy & Security", "Local Network"]
            case .accessibility: return ["Privacy & Security", "Accessibility"]
            }
        }
        /// What happens without it, plainly.
        var withoutIt: String {
            switch self {
            case .admin: return "Without it, scanning still works, but web protection stays off."
            case .fullDisk: return "Without it, protected folders are skipped during scans."
            case .notifications: return "Without it, you'll only see blocks when you open \(Product.name)."
            case .paste: return "Without it, Paste Guard and Scam Check can't see what you copy."
            case .localNetwork: return "Without it, Network Scan can't list nearby devices."
            case .accessibility: return "Without it, you can still turn on Safari protection by hand."
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
        if s[.fullDisk] == .granted, PermissionGuidePanel.shared.isShowing { PermissionGuidePanel.shared.finish() }
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
            if r == .fullDisk && status(.fullDisk) != .granted { PermissionGuidePanel.shared.show() }
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
    @StateVar private var expanded: PermissionsModel.Row?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            if showsHeader {
                Text("Set up \(Product.name)").font(.title2.weight(.bold)).fontDesign(.monospaced)
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
            HStack(spacing: Spacing.s) {
                let left = perms.remaining.count
                let total = max(perms.rows.count, 1)
                PermissionsProgressRing(fraction: Double(perms.rows.count - left) / Double(total), done: left == 0)
                    .accessibilityHidden(true)
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
                .animation(reduceMotion ? nil : .easeOut(duration: 0.3), value: st)
            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 6) {
                    Text(r.title).font(.body.weight(.medium))
                    if perms.walking == r { ProgressView().controlSize(.mini) }
                }
                Text(r.reason).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                if st != .granted {
                    Button {
                        withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) { expanded = expanded == r ? nil : r }
                    } label: {
                        Label(expanded == r ? "Hide details" : "Why, and where to click",
                              systemImage: expanded == r ? "chevron.down" : "chevron.right")
                            .font(.caption).labelStyle(.titleAndIcon)
                    }
                    .buttonStyle(.plain).foregroundStyle(Color.rampartTeal)
                    .help("Shows where this setting lives in System Settings")
                    if expanded == r {
                        SettingsPathIllustration(path: r.settingsPath)
                            .padding(.top, 2)
                            .transition(.opacity)
                        Text(r.withoutIt).font(.caption).foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            Spacer()
            switch st {
            case .granted:
                StatusLabel(text: "Granted", symbol: "checkmark.circle.fill", tint: .statusProtected).font(.callout)
                    .transition(reduceMotion ? .opacity : .scale(scale: 0.85).combined(with: .opacity))
            case .optional:
                StatusLabel(text: "Optional", symbol: "circle.dashed", tint: .secondary).font(.callout)
                Button("Open") { perms.grant(r) }.controlSize(.small)
            case .needed, .unknown:
                StatusLabel(text: st == .unknown ? "Checking…" : "Needed", symbol: "circle", tint: .secondary).font(.callout)
                Button("Grant") { if r == .admin { showInstall = true } else { perms.grant(r) } }.controlSize(.small)
            }
        }
        .padding(Spacing.s)
        .animation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.7), value: st)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(r.title): \(st == .granted ? "granted" : st == .optional ? "optional" : "needed"). \(r.reason)")
    }
}

/// A small, static sketch of a System Settings window: sidebar item on the left, the switch to turn on at right.
private struct SettingsPathIllustration: View {
    let path: [String]
    var body: some View {
        HStack(spacing: 0) {
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 3) {
                    ForEach(0..<3, id: \.self) { i in
                        Circle().fill([Color.red, .yellow, .green][i].opacity(0.6)).frame(width: 5, height: 5)
                    }
                }
                .padding(.bottom, 2)
                Text(path.first ?? "")
                    .font(.system(size: 9, weight: .semibold))
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(RoundedRectangle(cornerRadius: 3).fill(Color.accentColor.opacity(0.25)))
                RoundedRectangle(cornerRadius: 2).fill(.quaternary).frame(width: 50, height: 4)
            }
            .padding(6)
            .frame(width: 110, alignment: .leading)
            .background(.quaternary.opacity(0.5))
            VStack(alignment: .leading, spacing: 4) {
                Text(path.last ?? "").font(.system(size: 9, weight: .semibold))
                HStack(spacing: 4) {
                    RoundedRectangle(cornerRadius: 2).fill(Color.rampartTeal).frame(width: 8, height: 8)
                    Text(Product.name).font(.system(size: 9))
                    Spacer(minLength: 6)
                    Capsule().fill(Color.statusProtected).frame(width: 16, height: 9)
                        .overlay(alignment: .trailing) { Circle().fill(.white).frame(width: 7, height: 7).padding(1) }
                        .overlay { Capsule().stroke(Color.rampartTeal, lineWidth: 1.5).padding(-3) }
                }
            }
            .padding(6)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxWidth: 260)
        .clipShape(RoundedRectangle(cornerRadius: 6))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(.quaternary))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("In System Settings, open \(path.joined(separator: ", then ")), and turn on \(Product.name).")
    }
}

/// Footer progress ring: fills as permissions are granted, settles to a check when done.
private struct PermissionsProgressRing: View {
    let fraction: Double
    let done: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        ZStack {
            Circle().stroke(.quaternary, lineWidth: 3)
            Circle().trim(from: 0, to: max(0, min(1, fraction)))
                .stroke(done ? Color.statusProtected : Color.rampartTeal, style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            if done {
                Image(systemName: "checkmark").font(.system(size: 8, weight: .bold)).foregroundStyle(Color.statusProtected)
                    .transition(.scale.combined(with: .opacity))
            }
        }
        .frame(width: 18, height: 18)
        .animation(reduceMotion ? nil : .easeOut(duration: 0.4), value: fraction)
        .animation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.6), value: done)
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
