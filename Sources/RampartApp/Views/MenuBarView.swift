import SwiftUI
import AppKit

struct MenuBarView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openSettings) private var openSettings
    @StateVar private var showQuitInfo = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            top.padding(Spacing.l)
            Divider()
            if !model.isScanning {
                HStack(spacing: Spacing.s) {
                    Button { model.startScan(.quick) } label: { Label("Quick Scan", systemImage: "bolt").frame(maxWidth: .infinity) }
                        .primaryActionStyle()
                    Button { openMain() } label: { Text("Open Rampart").frame(maxWidth: .infinity) }
                        .secondaryActionStyle()
                }
                .controlSize(.large)
                .padding(Spacing.m)
                Divider()
            }
            VStack(alignment: .leading, spacing: 6) {
                infoRow("Last scan", lastScan)
                infoRow("Definitions", Fmt.ago(model.definitionsUpdated))
                infoRow("Network", "\(model.blockedToday) blocked today")
                if model.isDemo { infoRow("Mode", "Demo · sample data") }
            }
            .font(.callout)
            .padding(Spacing.l)
            Divider()
            VStack(alignment: .leading, spacing: 2) {
                Menu("Pause Protection") {
                    Button("For 15 minutes") { model.setRealtime(false, pauseFor: 15) }
                    Button("For 1 hour") { model.setRealtime(false, pauseFor: 60) }
                    if model.pausedUntil != nil { Button("Resume Now") { model.setRealtime(true) } }
                }
                .menuStyle(.borderlessButton)
                .disabled(model.mode == .live)
                .padding(.horizontal, 6).padding(.vertical, 4)
                MenuRowButton(title: "Settings…", shortcut: "⌘,") { NSApp.activate(ignoringOtherApps: true); openSettings() }
                MenuRowButton(title: "Quit Rampart", shortcut: "⌘Q") { showQuitInfo = true }
                if showQuitInfo {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        Text("Real-time protection keeps running in the background. To stop it, turn off protection in Settings.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        HStack { Spacer(); Button("Cancel") { showQuitInfo = false }; Button("Quit") { NSApp.terminate(nil) }.keyboardShortcut(.defaultAction) }
                    }
                    .padding(Spacing.s)
                }
            }
            .padding(Spacing.s)
        }
        .frame(width: 320)
    }

    @ViewBuilder private var top: some View {
        if let p = model.scanProgress {
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
        } else {
            let (sym, tint, title) = heroLine
            HStack(spacing: Spacing.m) {
                Image(systemName: sym).font(.system(size: 30)).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.headline)
                    Text("Score \(model.securityScore) · \(AppModel.scoreLabel(model.securityScore))").font(.callout).foregroundStyle(.secondary)
                }
                Spacer()
                if case .threat = model.overall {
                    Button("Review") { model.selection = .threats; openMain() }.buttonStyle(.borderedProminent)
                }
            }
            .accessibilityElement(children: .combine)
        }
    }

    private var heroLine: (String, Color, String) {
        switch model.overall {
        case .threat(let n): return ("xmark.shield.fill", .statusAction, n == 1 ? "1 item needs your attention" : "\(n) items need your attention")
        case .off: return ("shield.slash", .statusAction, "Real-time protection is off")
        case .paused: return ("pause.circle.fill", .secondary, "Protection paused")
        case .limited: return ("exclamationmark.shield.fill", .statusAttention, "Protection is limited")
        default: return ("checkmark.shield.fill", .statusProtected, "Your Mac is protected")
        }
    }

    private var lastScan: String {
        if let r = model.scanHistory.first { return "\(Fmt.dayTime(r.date)) · \(r.found == 0 ? "Clean" : "\(r.found) found")" }
        return model.status.lastScan.map(Fmt.dayTime) ?? "Not yet"
    }

    private func infoRow(_ k: String, _ v: String) -> some View {
        HStack { Text(k).foregroundStyle(.secondary); Spacer(); Text(v) }.accessibilityElement(children: .combine)
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
