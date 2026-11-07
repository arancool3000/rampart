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
                if m.showSudoEscape { SudoEscapeCard() }
                if m.active, let s = m.status { activeSection(s) } else { idleSection }
                if m.killSwitchVisible || m.active { KillSwitchCard() }
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
            triggerDetails(s)
            networkRow(s)
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
                    // Lifting always works with the administrator password; the checklist is advice only.
                    Button { if r.ready { Task { await m.lift(force: false) } } else { confirmForce = true } } label: { Label("Lift Lockdown", systemImage: "lock.open") }
                        .primaryActionStyle().disabled(m.busy)
                        .help("Needs your administrator password")
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

    /// What triggered it, which process or file, and why: in plain words.
    private func triggerDetails(_ s: EmergencyStatus) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Text("What triggered it").font(.headline)
            if let r = s.state.reason {
                Text(r.kind == .manual ? "You turned it on." : "Turned on automatically (\(r.kind.rawValue)).").font(.callout)
                if let n = r.detectionName { Text("Detection: \(SafeText.line(n, max: 200)) (confidence \(r.confidence)%)").font(.callout).foregroundStyle(.secondary) }
                if let p = r.path { Text("File: \(SafeText.path(p, max: 300))").font(.callout).foregroundStyle(.secondary).textSelection(.enabled) }
                if let pid = r.pid { Text("Process ID: \(pid)").font(.callout).foregroundStyle(.secondary) }
            }
            if let w = s.state.networkWhy, !w.isEmpty { Text("Why: \(SafeText.line(w, max: 300))").font(.callout).foregroundStyle(.secondary) }
        }
    }

    private func networkRow(_ s: EmergencyStatus) -> some View {
        HStack(spacing: Spacing.m) {
            if m.networkBlocked {
                Label(m.countdownText.map { "Internet blocked · restores itself in \($0)" } ?? "Internet blocked", systemImage: "wifi.slash")
                    .font(.callout.weight(.semibold))
                Spacer()
                if m.secondsLeft != nil { Button("Keep Blocking") { Task { await m.keepBlocking() } }.disabled(m.busy) }
                Button { Task { await m.restoreInternet() } } label: { Label("Restore Internet Now", systemImage: "wifi") }
                    .controlSize(.large).primaryActionStyle().disabled(m.busy)
                    .help("Needs your administrator password")
            } else {
                Label("Internet is on", systemImage: "wifi").font(.callout).foregroundStyle(.secondary)
            }
        }
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
            if m.active || m.showSudoEscape {
                VStack(alignment: .leading, spacing: Spacing.xs) {
                    HStack(spacing: Spacing.m) {
                        Image(systemName: m.escalated ? "exclamationmark.triangle.fill" : "lock.fill").accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(m.escalated ? "\(Product.name) couldn't fully stop a threat."
                                             : "Emergency Lockdown: \(m.status.map { EmergencyNotice.plainReason($0.state) } ?? "")")
                                .lineLimit(2).font(.callout.weight(.semibold))
                            Text(m.networkBlocked ? "Internet blocked" + (m.countdownText.map { " · restores itself in \($0)" } ?? "") : "Internet is on")
                                .font(.caption)
                        }
                        Spacer()
                        if m.networkBlocked {
                            Button { Task { await m.restoreInternet() } } label: { Label("Restore internet now", systemImage: "wifi").font(.body.weight(.bold)) }
                                .controlSize(.large).buttonStyle(.borderedProminent).tint(.white).foregroundStyle(Color.statusAction).disabled(m.busy)
                            if m.secondsLeft != nil { Button("Keep blocking") { Task { await m.keepBlocking() } }.buttonStyle(.bordered).disabled(m.busy) }
                        }
                        KillSwitchButton(compact: true)
                        Button("Details", action: open).buttonStyle(.bordered)
                    }
                    if m.showSudoEscape {
                        Text("Can't reach the \(Product.name) service. To get back online, run in Terminal: \(EmergencyStatus.sudoEscape)")
                            .font(.caption.weight(.semibold)).textSelection(.enabled)
                    }
                }
                .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s)
                .foregroundStyle(.white)
                .background(m.escalated ? Color.orange : Color.statusAction)
                .accessibilityElement(children: .contain)
                .accessibilityLabel("Emergency lockdown is on")
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
        VStack(alignment: .leading, spacing: 4) {
        Button(action: open) {
            Label(m.active ? "Lockdown On\(m.countdownText.map { " · internet back in \($0)" } ?? "") — Details…" : "Emergency Lockdown…",
                  systemImage: m.active ? "lock.fill" : "exclamationmark.octagon")
        }
        if m.networkBlocked { Button("Restore Internet Now") { Task { await m.restoreInternet() } } }
        if m.killSwitchVisible || m.active { KillSwitchButton(compact: true) }
        if m.showSudoEscape { Text("Service unreachable. In Terminal: \(EmergencyStatus.sudoEscape)").font(.caption).textSelection(.enabled) }
        }
        .onAppear { m.start() }
        .onDisappear { m.stop() }
    }
}


/// Red "Super Kill Switch" button (Touch ID or the Mac password first). Shown on the Emergency page, the lockdown
/// banner and the menu bar menu whenever lockdown or web protection is on, or the service can't be reached.
struct KillSwitchButton: View {
    var compact = false
    private var m: EmergencyModel { EmergencyModel.shared }
    var body: some View {
        Button(role: .destructive) { Task { await m.killSwitch() } } label: {
            Label("Super Kill Switch", systemImage: "power")
                .font(compact ? .callout.weight(.bold) : .body.weight(.bold))
        }
        .buttonStyle(.borderedProminent).tint(.red)
        .controlSize(compact ? .regular : .large)
        .disabled(m.busy)
        .help(KillSwitch.copy)
        .accessibilityHint("Asks for Touch ID or your password")
    }
}

struct KillSwitchCard: View {
    private var m: EmergencyModel { EmergencyModel.shared }
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("Super Kill Switch", systemImage: "power").font(.headline)
            Text(KillSwitch.copy).foregroundStyle(.secondary)
            KillSwitchButton()
            if let r = m.killSwitchReport {
                Text(r.split(separator: "\n", omittingEmptySubsequences: false).map { SafeText.line(String($0), max: 300) }.joined(separator: "\n"))
                    .font(.caption).textSelection(.enabled)
            }
        }
        .card(tint: .red)
    }
}

/// Dead-man safety: the app can't reach the service while a network lockdown was last seen active.
struct SudoEscapeCard: View {
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("Can't reach the \(Product.name) service", systemImage: "exclamationmark.triangle.fill").font(.headline)
            Text("If websites don't load, open Terminal and run this command (it asks for your Mac password):").foregroundStyle(.secondary)
            Text(EmergencyStatus.sudoEscape).font(.system(.body, design: .monospaced)).textSelection(.enabled)
            Text("Or press Super Kill Switch below.").font(.caption).foregroundStyle(.secondary)
        }
        .card(tint: .statusAction)
    }
}
