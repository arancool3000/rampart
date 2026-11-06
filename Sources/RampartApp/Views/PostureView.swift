import SwiftUI
import AppKit
import RampartShared

struct PostureView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var showIgnored = false

    static func symbol(for c: PostureCheck) -> String {
        let id = c.id.lowercased()
        if id.contains("filevault") { return "lock.laptopcomputer" }
        if id.contains("firewall") { return "shield.checkered" }
        if id.contains("gatekeeper") || id.contains("sip") { return "checkmark.shield" }
        if id.contains("update") || id.contains("outdated") { return "arrow.down.circle" }
        if id.contains("lockdown") { return "lock.shield" }
        if id.contains("screen") { return "lock.display" }
        if id.contains("ssh") || id.contains("sharing") { return "rectangle.connected.to.line.below" }
        if id.contains("airdrop") { return "airplayaudio" }
        if id.contains("guest") || id.contains("admin") { return "person.2" }
        return "gearshape"
    }

    private var active: [PostureCheck] { model.posture.filter { !model.ignoredChecks.contains($0.id) } }
    private var ignored: [PostureCheck] { model.posture.filter { model.ignoredChecks.contains($0.id) } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                summary
                group("macOS protections", active)
                startupItems
                if !ignored.isEmpty {
                    DisclosureGroup("Ignored (\(ignored.count))", isExpanded: $showIgnored) {
                        Text("Ignored items don't count toward your score.").font(.callout).foregroundStyle(.secondary)
                        ForEach(ignored) { c in
                            HStack {
                                Text(c.title)
                                Spacer()
                                Button("Stop Ignoring") { model.ignoredChecks.remove(c.id) }.controlSize(.small)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                    .card()
                }
            }
            .contentColumn()
        }
        .navigationTitle("Privacy & Posture")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { Task { await model.refresh() } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
            }
        }
    }

    private var summary: some View {
        let score = model.securityScore
        let failing = model.failingChecks.count
        return HStack(spacing: Spacing.xl) {
            ScoreRing(score: score, size: 88, lineWidth: 9)
            VStack(alignment: .leading, spacing: 4) {
                Text(failing == 0 ? "Your Mac's settings look good" : "\(failing) setting\(failing == 1 ? "" : "s") could make your Mac more secure")
                    .font(.title2.weight(.semibold))
                Text("Your score reflects settings you can change on this Mac. It never depends on what you've bought.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
        }
        .card(padding: Spacing.xl)
        .accessibilityElement(children: .combine)
    }

    private func group(_ title: String, _ checks: [PostureCheck]) -> some View {
        let order: [PostureCheck.State: Int] = [.fail: 0, .unknown: 1, .pass: 2, .notApplicable: 3]
        let sorted = checks.sorted { (order[$0.state] ?? 9, -$0.weight) < (order[$1.state] ?? 9, -$1.weight) }
        return VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader(title)
            VStack(spacing: 0) {
                ForEach(Array(sorted.enumerated()), id: \.element.id) { i, c in
                    if i > 0 { Divider() }
                    PostureRow(check: c)
                }
            }
            .card(padding: Spacing.s)
        }
    }

    private var startupItems: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Startup & background items")
            VStack(spacing: 0) {
                if model.persistence.isEmpty {
                    Text("Login items and launch agents will be listed when the background service reports them.")
                        .foregroundStyle(.secondary).padding(Spacing.m).frame(maxWidth: .infinity, alignment: .leading)
                }
                ForEach(Array(model.persistence.enumerated()), id: \.element.id) { i, p in
                    if i > 0 { Divider() }
                    HStack(spacing: Spacing.m) {
                        Image(systemName: p.kind == .browserExtension ? "puzzlepiece.extension" : "power").foregroundStyle(.secondary).frame(width: 24)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(p.label).font(.body.weight(.medium))
                            Text(p.location.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                                .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Text(kindLabel(p.kind)).font(.callout).foregroundStyle(.secondary)
                        signingBadge(p.signing)
                    }
                    .padding(Spacing.s)
                    .accessibilityElement(children: .combine)
                }
            }
            .card(padding: Spacing.s)
        }
    }

    private func kindLabel(_ k: PersistenceItem.Kind) -> String {
        switch k {
        case .launchAgent: return "Launch agent"; case .launchDaemon: return "Launch daemon"; case .loginItem: return "Login item"
        case .browserExtension: return "Browser extension"; case .profile: return "Profile"; case .cron: return "Scheduled job"
        default: return k.rawValue
        }
    }

    @ViewBuilder private func signingBadge(_ s: SigningInfo?) -> some View {
        switch s?.status {
        case .apple?: Badge(text: "Apple", tint: .green)
        case .developerID?, .appStore?: Badge(text: s?.notarized == true ? "Notarized" : "Signed", tint: .green)
        case .unsigned?, .adHoc?: Badge(text: "Not signed", tint: .yellow)
        case .invalid?, .revoked?: Badge(text: "Invalid signature", tint: .red)
        default: Badge(text: "—")
        }
    }
}

struct PostureRow: View {
    let check: PostureCheck
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL

    private var stateInfo: (String, String, Color) {
        switch check.state {
        case .pass: return ("checkmark.circle.fill", "Good", .statusProtected)
        case .fail: return ("exclamationmark.circle.fill", "Recommended", .statusAttention)
        case .unknown: return ("questionmark.circle", "Couldn't check", .secondary)
        case .notApplicable: return ("minus.circle", "Info", .secondary)
        }
    }

    var body: some View {
        let (sym, label, tint) = stateInfo
        HStack(spacing: Spacing.m) {
            Image(systemName: PostureView.symbol(for: check)).font(.title3).foregroundStyle(.secondary).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title).font(.body.weight(.medium))
                Text(check.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            StatusLabel(text: label, symbol: sym, tint: tint).font(.callout).frame(minWidth: 120, alignment: .leading)
            Group {
                if check.state == .fail {
                    if model.fixingChecks.contains(check.id) {
                        ProgressView().controlSize(.small)
                    } else if check.fixable {
                        Button("Fix") { Task { await model.fix(check) } }.buttonStyle(GlowButtonStyle())
                            .help(check.fixHint)
                    } else {
                        Button("Open Settings") { openSettings() }.help(check.fixHint)
                    }
                } else { Color.clear }
            }
            .frame(width: 120, alignment: .trailing)
            if check.state == .fail {
                Menu {
                    Button("Ignore") { model.ignoredChecks.insert(check.id) }
                } label: { Image(systemName: "ellipsis") }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                    .accessibilityLabel("More options for \(check.title)")
            } else {
                Color.clear.frame(width: 16)
            }
        }
        .padding(Spacing.s)
        .accessibilityElement(children: .contain)
    }

    private func openSettings() {
        let id = check.id.lowercased()
        let url: String
        if id.contains("outdated") { url = "macappstore://showUpdatesPage" }
        else if id.contains("update") { url = "x-apple.systempreferences:com.apple.Software-Update-Settings.extension" }
        else if id.contains("sharing") || id.contains("ssh") { url = "x-apple.systempreferences:com.apple.Sharing-Settings.extension" }
        else { url = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension" }
        if let u = URL(string: url) { openURL(u) }
    }
}
