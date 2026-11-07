import SwiftUI
import RampartShared
import AppKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @StateVar private var showQuitInfo = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            top
            if !model.isScanning {
                HStack(spacing: Spacing.s) {
                    Button { model.startScan(.quick) } label: { Label("Quick Scan", systemImage: "bolt.fill").frame(maxWidth: .infinity) }
                        .buttonStyle(GlowButtonStyle())
                        .keyboardShortcut("r", modifiers: .command)
                        .help("Check the places malware usually hides (⌘R)")
                    Button { openMain() } label: { Text("Open \(Product.name)").frame(maxWidth: .infinity) }
                        .secondaryActionStyle()
                        .keyboardShortcut("o", modifiers: .command)
                        .help("Open the main window (⌘O)")
                }
                .controlSize(.large)
            }
            VStack(spacing: 0) {
                TimelineView(.periodic(from: .now, by: 60)) { ctx in
                    infoRow("magnifyingglass", "Last scan", lastScan(now: ctx.date))
                }
                .help(lastScanDate.map { "Last scan: \(Fmt.dayTime($0))" } ?? "No scan has run yet")
                Divider().padding(.leading, 34)
                infoRow("arrow.triangle.2.circlepath", "Definitions", Fmt.ago(model.definitionsUpdated))
                Divider().padding(.leading, 34)
                infoRow("hand.raised.fill", "Network", "\(model.blockedToday) blocked today")
                Divider().padding(.leading, 34)
                infoRow("shield.lefthalf.filled", "Protection", model.mode == .live ? (model.source == .basic ? "Basic (no install)" : "System service") : (model.isDemo ? "Developer demo" : "Not running"))
            }
            .font(.callout)
            .card(padding: Spacing.s)
            VStack(alignment: .leading, spacing: 2) {
                Menu {
                    if let until = model.pausedUntil {
                        Button { model.setRealtime(true) } label: { Label("Resume Now", systemImage: "play.fill") }
                        Text("Resumes automatically at \(until.formatted(date: .omitted, time: .shortened))")
                        Divider()
                    }
                    Section("Pause for") {
                        Button("15 minutes") { model.setRealtime(false, pauseFor: 15) }
                        Button("1 hour") { model.setRealtime(false, pauseFor: 60) }
                        Button("4 hours") { model.setRealtime(false, pauseFor: 240) }
                        Button("Until tomorrow") { model.setRealtime(false, pauseFor: minutesUntilTomorrow) }
                    }
                } label: {
                    Label(model.pausedUntil == nil ? "Pause Protection" : "Paused · Resume or Extend", systemImage: model.pausedUntil == nil ? "pause.circle" : "play.circle")
                }
                .menuStyle(.borderlessButton)
                .disabled(model.mode == .live)
                .help(model.mode == .live ? "Pausing is managed by the system service in Settings" : "Temporarily pause real-time protection; it resumes on its own")
                .accessibilityHint("Real-time protection resumes automatically after the chosen time")
                .padding(.horizontal, 8).padding(.vertical, 4)
                MenuRowButton(title: "Settings…", shortcut: "⌘,") { NSApp.activate(ignoringOtherApps: true); openSettings() }
                MenuRowButton(title: "Quit \(Product.name)", shortcut: "⌘Q") { showQuitInfo = true }
                if showQuitInfo {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        Text("Real-time protection keeps running in the background. To stop it, turn off protection in Settings.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        HStack { Spacer(); Button("Cancel") { showQuitInfo = false }.keyboardShortcut(.cancelAction); Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut(.defaultAction) }
                    }
                    .padding(Spacing.s)
                    .transition(reduceMotion ? .opacity : .opacity.combined(with: .move(edge: .top)))
                }
            }
            .animation(reduceMotion ? nil : .easeOut(duration: 0.18), value: showQuitInfo)
            .background {
                // Hidden keyboard shortcuts for the popover.
                Button("") { NSApp.activate(ignoringOtherApps: true); openSettings() }.keyboardShortcut(",", modifiers: .command).hidden()
                Button("") { showQuitInfo = true }.keyboardShortcut("q", modifiers: .command).hidden()
            }
        }
        .padding(Spacing.m)
        .frame(width: 330)
        .background(AppBackdrop())
        .onAppear { if !Headless.active { AnimationGate.shared.popoverVisible = true } }
        .onDisappear { AnimationGate.shared.popoverVisible = false }
    }

    @ViewBuilder private var top: some View {
        if let p = model.scanProgress {
            HStack(spacing: Spacing.m) {
            RadarView(fraction: p.fraction, paused: p.paused, size: 74)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("\(p.kind.title) · \(p.fraction.map { "\(Int($0 * 100))%" } ?? "Finding files…")").font(.headline).monospacedDigit()
                if let f = p.fraction { ProgressView(value: f).tint(Color.rampartTeal) } else { ProgressView().progressViewStyle(.linear).tint(Color.rampartTeal) }
                Text(p.current).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                HStack {
                    if model.mode != .live { Button(p.paused ? "Resume" : "Pause") { model.togglePause() } }
                    Button("Stop") { model.stopScan() }
                }
                .controlSize(.small)
            }
            }
            .card(padding: Spacing.m)
        } else {
            let (sym, tint, title) = heroLine
            let calm: Bool = { if case .protected = model.overall { return true }; if case .recommendations = model.overall { return true }; return false }()
            VStack(alignment: .leading, spacing: Spacing.s) {
                HStack(spacing: Spacing.m) {
                    if calm {
                        StatusMark(size: 56, badge: "checkmark.circle.fill", tint: .statusProtected)
                    } else if model.isOffline {
                        StatusMark(size: 56, badge: "xmark.circle.fill", tint: .statusAction, dimmed: true)
                    } else if model.mode == .connecting {
                        RamPartMark(size: 56)
                    } else {
                        ShieldHero(symbol: sym, tint: tint == .secondary ? .gray : tint, breathe: false, size: 64)
                    }
                    VStack(alignment: .leading, spacing: 2) {
                        Text(title).font(.headline).fontDesign(.rounded).fixedSize(horizontal: false, vertical: true)
                            .revealText(on: title, typewriter: true, duration: 0.5)
                            if model.hasData {
                            Text("Score \(model.securityScore) · \(AppModel.scoreLabel(model.securityScore))").font(.callout).foregroundStyle(.secondary)
                        }
                    }
                    Spacer(minLength: 0)
                    if model.hasData { ScoreRing(score: model.securityScore, size: 46, lineWidth: 5) }
                }
                if model.isOffline {
                    Button { Task { await model.retry() } } label: { Text("Retry").frame(maxWidth: .infinity) }
                        .buttonStyle(GlowButtonStyle()).controlSize(.large)
                }
                if case .threat = model.overall {
                    Button { model.selection = .threats; openMain() } label: { Text("Review").frame(maxWidth: .infinity) }
                        .buttonStyle(GlowButtonStyle()).controlSize(.large)
                }
            }
            .card(padding: Spacing.m, tint: tint == .secondary ? .gray : tint)
            .accessibilityElement(children: .combine)
        }
    }

    private var heroLine: (String, Color, String) {
        switch model.overall {
        case .threat(let n): return ("xmark.shield.fill", .statusAction, n == 1 ? "1 item needs your attention" : "\(n) items need your attention")
        case .off: return ("shield.slash", .statusAction, "Real-time protection is off")
        case .serviceDown: return ("shield.slash", .statusAction, "Protection service isn't running")
        case .starting: return ("shield.lefthalf.filled", .secondary, "Starting protection…")
        case .paused: return ("pause.circle.fill", .secondary, "Protection paused")
        case .limited: return ("exclamationmark.shield.fill", .statusAttention, "Protection is limited")
        default: return ("checkmark.shield.fill", .statusProtected, "Your Mac is protected")
        }
    }

    private var lastScanDate: Date? { model.scanHistory.first?.date ?? model.status.lastScan }

    private func lastScan(now: Date) -> String {
        guard let d = lastScanDate else { return "Not yet" }
        let rel = now.timeIntervalSince(d) < 60 ? "Just now" : RelativeDateTimeFormatter.short.localizedString(for: d, relativeTo: now)
        if let r = model.scanHistory.first { return "\(rel) · \(r.found == 0 ? "Clean" : "\(r.found) found")" }
        return rel
    }

    private var minutesUntilTomorrow: Int {
        let cal = Calendar.current
        let start = cal.startOfDay(for: cal.date(byAdding: .day, value: 1, to: .now) ?? .now)
        let morning = cal.date(byAdding: .hour, value: 8, to: start) ?? start
        return max(60, Int(morning.timeIntervalSinceNow / 60))
    }

    private func infoRow(_ symbol: String, _ k: String, _ v: String) -> some View {
        HStack(spacing: Spacing.s) {
            Image(systemName: symbol).foregroundStyle(Color.rampartTeal).frame(width: 22)
            Text(k).foregroundStyle(.secondary)
            Spacer()
            Text(v).fontWeight(.medium)
        }
        .padding(.horizontal, 6).padding(.vertical, 7)
        .accessibilityElement(children: .combine)
    }

    private func openMain() {
        NSApp.setActivationPolicy(.regular)
        openWindow(id: "main")
        NSApp.activate(ignoringOtherApps: true)
    }
}

private extension RelativeDateTimeFormatter {
    static let short: RelativeDateTimeFormatter = { let f = RelativeDateTimeFormatter(); f.unitsStyle = .full; return f }()
}

struct MenuRowButton: View {
    let title: String
    let shortcut: String
    let action: () -> Void
    @StateVar private var hover = false
    var body: some View {
        Button(action: action) {
            HStack { Text(title); Spacer(); Text(shortcut).foregroundStyle(.secondary) }
                .padding(.horizontal, 8).padding(.vertical, 5)
                .background(hover ? Color.rampartTeal.opacity(0.15) : .clear, in: RoundedRectangle(cornerRadius: 6, style: .continuous))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .onHover { hover = $0 }
        .accessibilityLabel(title)
        .accessibilityHint("Keyboard shortcut \(shortcut)")
    }
}
