import SwiftUI
import RampartShared
import AppKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @StateVar private var showQuitInfo = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            top
            if !model.isScanning {
                HStack(spacing: Spacing.s) {
                    Button { model.startScan(.quick) } label: { Label("Quick Scan", systemImage: "bolt.fill").frame(maxWidth: .infinity) }
                        .buttonStyle(GlowButtonStyle())
                    Button { openMain() } label: { Text("Open \(Product.name)").frame(maxWidth: .infinity) }
                        .secondaryActionStyle()
                }
                .controlSize(.large)
            }
            VStack(spacing: 0) {
                infoRow("magnifyingglass", "Last scan", lastScan)
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
                Menu("Pause Protection") {
                    Button("For 15 minutes") { model.setRealtime(false, pauseFor: 15) }
                    Button("For 1 hour") { model.setRealtime(false, pauseFor: 60) }
                    if model.pausedUntil != nil { Button("Resume Now") { model.setRealtime(true) } }
                }
                .menuStyle(.borderlessButton)
                .disabled(model.mode == .live)
                .padding(.horizontal, 8).padding(.vertical, 4)
                MenuRowButton(title: "Settings…", shortcut: "⌘,") { NSApp.activate(ignoringOtherApps: true); openSettings() }
                MenuRowButton(title: "Quit \(Product.name)", shortcut: "⌘Q") { showQuitInfo = true }
                if showQuitInfo {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        Text("Real-time protection keeps running in the background. To stop it, turn off protection in Settings.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        HStack { Spacer(); Button("Cancel") { showQuitInfo = false }; Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut(.defaultAction) }
                    }
                    .padding(Spacing.s)
                }
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
                Text("\(p.kind.title) · \(p.fraction.map { "\(Int($0 * 100))%" } ?? "Starting")").font(.headline).monospacedDigit()
                ProgressView(value: p.fraction ?? 0).tint(Color.rampartTeal)
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

    private var lastScan: String {
        if let r = model.scanHistory.first { return "\(Fmt.dayTime(r.date)) · \(r.found == 0 ? "Clean" : "\(r.found) found")" }
        return model.status.lastScan.map(Fmt.dayTime) ?? "Not yet"
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
    }
}
