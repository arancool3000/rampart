import SwiftUI
import RampartShared
import RampartGuard

/// Emergency screen: Protect Everything at the top, then Emergency Lockdown (idle, active, or escalation).
struct EmergencyView: View {
    @StateVar private var confirmEngage = false
    @StateVar private var confirmForce = false
    private var m: EmergencyModel { EmergencyModel.shared }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                if let s = m.status, let esc = s.escalation, s.state.active {
                    EmergencyEscalationView(escalation: esc, report: s.report)
                }
                if m.active, let s = m.status { activeSection(s) } else { idleSection }
                if m.unsupported {
                    Text("Emergency Lockdown needs the \(Product.name) background service with this feature. It isn't connected yet, so nothing here can switch on by itself.")
                        .foregroundStyle(.secondary).card()
                }
                if let e = m.error { Text(SafeText.line(e, max: 240)).foregroundStyle(Color.statusAction).card(tint: .statusAction) }
                ProtectEverythingView()
                honestCard
            }
            .contentColumn()
        }
        .navigationTitle("Emergency")
        .onAppear { m.start() }
        .onDisappear { m.stop() }
        .confirmationDialog("Lock down this Mac now?", isPresented: $confirmEngage) {
            Button("Emergency Lockdown", role: .destructive) { Task { await m.engage(note: "manual") } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("The internet is cut off except for \(Product.name)'s encrypted DNS and Apple updates, remote access is blocked and your password vault locks. Lifting it needs your administrator password.")
        }
        .confirmationDialog("Lift lockdown before every check has passed?", isPresented: $confirmForce) {
            Button("Lift Anyway", role: .destructive) { Task { await m.lift(force: true) } }
            Button("Keep Lockdown", role: .cancel) {}
        } message: { Text("The threat may still be active. Only do this if you're sure, or if you need the network to get help.") }
    }

    private var idleSection: some View {
        HStack(alignment: .top, spacing: Spacing.xl) {
            ShieldHero(symbol: "lock.shield", tint: .statusProtected, breathe: false, size: 96)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("Emergency Lockdown").font(.title2.weight(.semibold)).fontDesign(.rounded)
                Text(EmergencyCopy.intro).foregroundStyle(.secondary)
                Text(EmergencyCopy.auto).font(.callout).foregroundStyle(.secondary)
                Button(role: .destructive) { confirmEngage = true } label: { Label("Emergency Lockdown", systemImage: "exclamationmark.octagon") }
                    .controlSize(.large).disabled(m.busy || m.unsupported)
                    .keyboardShortcut("l", modifiers: [.command, .shift])
                    .help("Isolate this Mac now (⇧⌘L)")
                    .accessibilityHint("Asks for confirmation first")
            }
        }
        .card()
    }

    private func activeSection(_ s: EmergencyStatus) -> some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.l) {
                Image(systemName: "lock.trianglebadge.exclamationmark.fill").font(.system(size: 40)).foregroundStyle(Color.statusAction)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text("This Mac is locked down").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text(SafeText.line(s.state.reason?.summary ?? "", max: 240)).foregroundStyle(.secondary)
                    if let d = s.state.startedAt { Text("Since \(Fmt.ago(d)) · \(SafeText.line(s.mode, max: 40))").font(.caption).foregroundStyle(.secondary) }
                }
            }
            Text(EmergencyCopy.stays).font(.callout).foregroundStyle(.secondary)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("What \(Product.name) did").font(.headline)
                ForEach(s.state.actions) { a in actionRow(a) }
            }
            if let r = s.readiness {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("Before lifting").font(.headline)
                    ForEach(r.items, id: \.title) { i in
                        Label(SafeText.line(i.title), systemImage: i.met ? "checkmark.circle.fill" : "circle")
                            .foregroundStyle(i.met ? Color.statusProtected : .secondary)
                    }
                    if r.secondsUntilQuiet > 0 { Text("Quiet period: \(r.secondsUntilQuiet) s left").font(.caption).foregroundStyle(.secondary) }
                }
                HStack(spacing: Spacing.m) {
                    Button { Task { await m.rescan() } } label: { Label("Re-scan Now", systemImage: "magnifyingglass") }.disabled(m.busy)
                    if r.ready {
                        Button { Task { await m.lift(force: false) } } label: { Label("Lift Lockdown", systemImage: "lock.open") }
                            .primaryActionStyle().disabled(m.busy)
                    } else {
                        Button("Lift Anyway…") { confirmForce = true }.disabled(m.busy)
                            .help("Needs your administrator password")
                    }
                    if m.busy { ProgressView().controlSize(.small) }
                }
            }
            DisclosureGroup("Incident details") {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text(s.report.split(separator: "\n", omittingEmptySubsequences: false).map { SafeText.line(String($0), max: 400) }.joined(separator: "\n")).font(.system(.caption, design: .monospaced)).textSelection(.enabled).frame(maxWidth: .infinity, alignment: .leading)
                    Button(m.copied ? "Copied" : "Copy Incident Details") { m.copyReport() }
                }
            }
        }
        .card(tint: .statusAction)
    }

    private func actionRow(_ a: EmergencyAction) -> some View {
        let (icon, tint): (String, Color) = {
            switch a.state {
            case .done: return ("checkmark.circle.fill", .statusProtected)
            case .dryRun: return ("doc.text", .secondary)
            case .failed: return ("exclamationmark.triangle.fill", .statusAttention)
            case .skipped: return ("minus.circle", .secondary)
            case .undone: return ("arrow.uturn.backward.circle", .secondary)
            case .planned: return ("clock", .secondary)
            }
        }()
        return HStack(alignment: .top, spacing: Spacing.m) {
            Image(systemName: icon).foregroundStyle(tint).frame(width: 18).accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(SafeText.line(a.title)).font(.body.weight(.medium))
                Text(SafeText.path(a.result.isEmpty ? a.detail : a.result, max: 400)).font(.caption).foregroundStyle(.secondary)
                if a.undoable { Text("Undo: \(SafeText.line(a.undoNote, max: 240))").font(.caption2).foregroundStyle(.tertiary) }
            }
            Spacer()
            Text(a.state == .dryRun ? "recorded" : a.state.rawValue).font(.caption).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }

    private var honestCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("What lockdown can and can't do", systemImage: "info.circle").font(.headline)
            Text(EmergencyStatus.encryptionNote).foregroundStyle(.secondary)
            Text(EmergencyCopy.limits).foregroundStyle(.secondary)
        }
        .card()
    }
}

/// Shown when RamPart couldn't fully stop the threat. Calm, three steps, nothing sent anywhere.
struct EmergencyEscalationView: View {
    let escalation: EmergencyEscalation
    let report: String
    private var m: EmergencyModel { EmergencyModel.shared }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text(SafeText.line(escalation.headline, max: 160)).font(.title2.weight(.semibold)).fontDesign(.rounded)
            Text("To stay safe:").font(.headline)
            HStack(alignment: .firstTextBaseline, spacing: Spacing.m) {
                Text("1.").bold()
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    Text("Turn off Wi-Fi now.")
                    Button { m.turnWiFiOff() } label: { Label("Turn Wi-Fi Off", systemImage: "wifi.slash") }.primaryActionStyle()
                    if let w = m.wifiMessage { Text(SafeText.line(w, max: 240)).font(.caption).foregroundStyle(.secondary) }
                    Text("If you use a network cable, unplug it.").font(.caption).foregroundStyle(.secondary)
                }
            }
            HStack(alignment: .firstTextBaseline, spacing: Spacing.m) { Text("2.").bold(); Text("Save your work and shut down your Mac.") }
            HStack(alignment: .firstTextBaseline, spacing: Spacing.m) {
                Text("3.").bold()
                Text("Contact a professional (Apple Support or a trusted repair shop). Don't enter passwords on this Mac until it's checked.")
            }
            VStack(alignment: .leading, spacing: Spacing.xs) {
                Text("Why").font(.subheadline.weight(.semibold))
                ForEach(escalation.signals, id: \.self) { s in Text("• " + SafeText.line(EmergencyEscalation.describe(s), max: 240)).font(.callout).foregroundStyle(.secondary) }
            }
            HStack {
                Button(m.copied ? "Copied" : "Copy Incident Details") { m.copyReport() }
                Text("An evidence report for whoever helps you. Nothing is sent anywhere.").font(.caption).foregroundStyle(.secondary)
            }
        }
        .card(tint: .statusAttention)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(Product.name) couldn't fully stop this")
    }
}

/// App-wide banner while lockdown is on (overlay at the top of RootView; also safe in full-screen spaces since it
/// lives inside the app window). Tapping it opens the Emergency screen.
struct EmergencyBanner: View {
    var open: () -> Void
    private var m: EmergencyModel { EmergencyModel.shared }

    var body: some View {
        Group {
            if m.active {
                Button(action: open) {
                    HStack(spacing: Spacing.m) {
                        Image(systemName: m.escalated ? "exclamationmark.triangle.fill" : "lock.fill").accessibilityHidden(true)
                        Text(m.escalated ? "\(Product.name) couldn't fully stop a threat. Open for next steps."
                                         : "Emergency lockdown is on. \(m.status?.state.reason?.summary ?? "")")
                            .lineLimit(1)
                        Spacer()
                        Text("Details").bold()
                    }
                    .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s)
                    .foregroundStyle(.white)
                    .background(m.escalated ? Color.orange : Color.statusAction)
                }
                .buttonStyle(.plain)
                .accessibilityLabel("Emergency lockdown is on. Open details.")
                .transition(.move(edge: .top).combined(with: .opacity))
            }
        }
        .onAppear { m.start() }
        .onDisappear { m.stop() }
    }
}

/// Compact menu bar row.
struct EmergencyMenuItem: View {
    var open: () -> Void
    private var m: EmergencyModel { EmergencyModel.shared }
    var body: some View {
        Button(action: open) {
            Label(m.active ? "Lockdown On — Details…" : "Emergency Lockdown…", systemImage: m.active ? "lock.fill" : "exclamationmark.octagon")
        }
        .onAppear { m.start() }
        .onDisappear { m.stop() }
    }
}
