import SwiftUI
import AppKit
import RampartShared

/// Remote Access: "blocked until you allow". Lists Apple sharing services and remote-control tools found on this
/// Mac, with per-tool Allow / Allow for 1 hour / Block, plus the tamper-protection status and honest limits.
struct RemoteAccessView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var screen = RemoteAccessScreenModel()
    @StateVar private var showDetails = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                hero
                if screen.unsupported { unsupportedCard }
                if let e = screen.error { Text(SafeText.line(e, max: 240)).foregroundStyle(Color.statusAction).card(tint: .statusAction) }
                if let r = screen.report {
                    toolsSection("Remote-control apps", r.findings.filter { !$0.isAppleService }, report: r)
                    toolsSection("macOS sharing services", r.findings.filter { $0.isAppleService }, report: r)
                    inboundSection(r)
                    firewallSection(r)
                }
                scamCard
                tamperCard
                limitsCard
            }
            .contentColumn()
        }
        .navigationTitle("Remote Access")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { Task { await screen.refresh(client: model.client) } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
                    .disabled(screen.loading)
            }
        }
        .task { await screen.refresh(client: model.client) }
    }

    // MARK: Hero

    private var lockdownOn: Bool { screen.report?.lockdownEnabled ?? true }
    private var unapproved: Int { screen.report?.activeUnapproved.count ?? 0 }

    private var hero: some View {
        let tint: Color = !lockdownOn ? .statusAttention : unapproved > 0 ? .statusAction : .statusProtected
        let title = !lockdownOn ? "Remote access lockdown is off"
            : unapproved > 0 ? "\(unapproved) remote-access tool\(unapproved == 1 ? "" : "s") blocked"
            : RemoteAccessCopy.headline
        return HStack(spacing: Spacing.xl) {
            ShieldHero(symbol: lockdownOn ? "lock.shield" : "lock.open", tint: tint, breathe: lockdownOn && unapproved == 0, size: 110)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text(title).font(.title2.weight(.semibold)).fontDesign(.monospaced)
                Text(RemoteAccessCopy.body).foregroundStyle(.secondary)
                HStack(spacing: Spacing.m) {
                    Toggle("Lockdown", isOn: Binding(get: { lockdownOn }, set: { on in Task { await screen.setLockdown(on, client: model.client) } }))
                        .toggleStyle(.switch)
                        .disabled(screen.report == nil)
                    if let r = screen.report { Text("Checked \(Fmt.ago(r.generatedAt))").font(.caption).foregroundStyle(.secondary) }
                }
            }
            Spacer()
        }
        .card(padding: Spacing.xl, tint: tint)
        .accessibilityElement(children: .combine)
    }

    private var unsupportedCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            StatusLabel(text: "Waiting for the background service", symbol: "clock", tint: .statusInfo)
                .font(.headline)
            Text("The remote-access report arrives from \(Product.name)'s background service. This build of the service doesn't publish it yet, so nothing is shown here until it does. Nothing on this screen is sample data.")
                .foregroundStyle(.secondary)
        }
        .card()
    }

    // MARK: Tools

    private func toolsSection(_ title: String, _ items: [RemoteToolFindingDTO], report: RemoteAccessReportDTO) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader(title)
            if items.isEmpty {
                Text(title.hasPrefix("macOS") ? "No sharing service is turned on." : "No remote-control app is installed or running.")
                    .foregroundStyle(.secondary).card()
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(items.enumerated()), id: \.element.id) { i, f in
                        if i > 0 { Divider() }
                        RemoteToolRow(finding: f, busy: screen.busyTool == f.toolID,
                                      allow: { minutes in Task { await screen.allow(f, minutes: minutes, client: model.client) } },
                                      block: { Task { await screen.revoke(f, client: model.client) } })
                    }
                }
                .card(padding: Spacing.s)
            }
        }
    }

    private func inboundSection(_ r: RemoteAccessReportDTO) -> some View {
        Group {
            if !r.inbound.isEmpty || !r.unknownListeners.isEmpty {
                VStack(alignment: .leading, spacing: Spacing.m) {
                    SectionHeader("Active sessions and listeners")
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        ForEach(r.inbound) { c in
                            StatusLabel(text: "\(SafeText.line(c.processName, max: 64)) has an inbound session from \(SafeText.line(c.remoteAddress, max: 64)) on port \(c.localPort)", symbol: "arrow.down.left.circle", tint: .statusAction)
                        }
                        ForEach(r.unknownListeners, id: \.self) { l in
                            StatusLabel(text: "\(l.process.isEmpty ? "An unidentified process" : SafeText.line(l.process, max: 64)) is listening on remote-access port \(l.port)", symbol: "questionmark.circle", tint: .statusAttention)
                        }
                    }
                    .card()
                }
            }
        }
    }

    private func firewallSection(_ r: RemoteAccessReportDTO) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Inbound firewall")
            VStack(alignment: .leading, spacing: Spacing.xs) {
                if r.blockedPorts.isEmpty {
                    StatusLabel(text: "No ports are being dropped", symbol: "network", tint: .secondary)
                } else {
                    StatusLabel(text: "Dropping inbound connections on \(r.blockedPorts.count) remote-access ports", symbol: "network.badge.shield.half.filled", tint: .rampartTeal)
                    Text(r.blockedPorts.map(String.init).joined(separator: ", ")).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
                Text("Ports of tools you allow are opened again automatically; the rule set is loaded in a separate firewall anchor and removed on uninstall.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .card()
        }
    }

    // MARK: Copy cards

    private var scamCard: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            IconBadge(symbol: "exclamationmark.bubble", tint: .amber)
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("Why this matters").font(.headline)
                Text(RemoteAccessCopy.scam).foregroundStyle(.secondary)
            }
        }
        .card()
    }

    private var tamperCard: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            IconBadge(symbol: "checkmark.shield", tint: .rampartTeal)
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("\(Product.name) protects itself too").font(.headline)
                Text(RemoteAccessCopy.tamper).foregroundStyle(.secondary)
            }
        }
        .card()
    }

    private var limitsCard: some View {
        DisclosureGroup(isExpanded: $showDetails) {
            Text(RemoteAccessCopy.limit).foregroundStyle(.secondary).padding(.top, Spacing.xs)
        } label: {
            Label("What this can and can't do", systemImage: "info.circle").font(.headline)
        }
        .card()
    }
}

private extension Color { static let amber = Palette.amber }

struct RemoteToolRow: View {
    let finding: RemoteToolFindingDTO
    let busy: Bool
    let allow: (Int?) -> Void
    let block: () -> Void

    private var tint: Color {
        if !finding.active { return .secondary }
        if finding.allowed { return .statusProtected }
        switch finding.severity { case .critical, .high: return .statusAction; case .medium: return .statusAttention; default: return .statusInfo }
    }
    private var symbol: String { finding.allowed ? "checkmark.circle" : finding.active ? "hand.raised.circle" : "circle.dashed" }
    private var stateText: String {
        if !finding.active { return finding.isAppleService ? "Off" : "Installed, not running" }
        if finding.allowed {
            if let u = finding.allowedUntil { return "Allowed until \(u.formatted(date: .omitted, time: .shortened))" }
            return "Allowed"
        }
        if finding.scamContext { return "Blocked: " + SafeText.line(finding.scamReason, max: 200) }
        return finding.isAppleService ? "Turned off by \(Product.name)" : "Blocked (suspended)"
    }

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            Image(systemName: symbol).foregroundStyle(tint).symbolRenderingMode(.hierarchical).font(.title3).frame(width: 24)
            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: Spacing.s) {
                    Text(SafeText.line(finding.name, max: 64)).font(.headline)
                    if finding.scamContext { Badge(text: "Scam pattern", tint: .statusAction) }
                    if finding.inboundSessions > 0 { Badge(text: "\(finding.inboundSessions) active session\(finding.inboundSessions == 1 ? "" : "s")", tint: .statusAction) }
                }
                Text(stateText).font(.callout).foregroundStyle(.secondary)
                if !finding.matchedBy.isEmpty || !finding.listeningPorts.isEmpty {
                    Text(SafeText.line(([finding.matchedBy.joined(separator: ", ")] + (finding.listeningPorts.isEmpty ? [] : ["listening on " + finding.listeningPorts.map(String.init).joined(separator: ", ")]))
                        .filter { !$0.isEmpty }.joined(separator: " · "), max: 240))
                        .font(.caption).foregroundStyle(.tertiary)
                }
            }
            Spacer()
            if busy {
                ProgressView().controlSize(.small)
            } else if finding.allowed {
                Button("Block") { block() }.secondaryActionStyle().controlSize(.small)
            } else {
                Menu {
                    Button("Allow for 1 hour") { allow(60) }
                    Button("Allow for 8 hours") { allow(480) }
                    Button("Always allow") { allow(nil) }
                } label: { Text("Allow…") }
                .menuStyle(.borderlessButton).fixedSize().controlSize(.small)
            }
        }
        .padding(.vertical, Spacing.s).padding(.horizontal, Spacing.s)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(SafeText.line(finding.name, max: 64)): \(stateText)")
    }
}
