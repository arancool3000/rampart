import SwiftUI
import RampartShared

// MARK: - Live feed: terminal-style event stream

/// The last events as a scrolling terminal log: timestamp, tag, title. New lines slide in; a cursor blinks
/// and a REC light pulses while the desktop is visible.
struct DesktopLiveFeed: View {
    @Environment(AppModel.self) private var model
    @Environment(DesktopMode.self) private var desktop
    private static let time: DateFormatter = { let f = DateFormatter(); f.dateFormat = "HH:mm:ss"; return f }()

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                PulsingDot(color: Palette.coral, running: desktop.visible)
                Text("LIVE FEED").font(DS.Font.eyebrow).tracking(1.2).foregroundStyle(.white.opacity(0.62))
                Spacer()
                Button("All") { DesktopMode.shared.openMain(.activity) }.buttonStyle(.borderless)
                    .font(DS.Font.caption.weight(.semibold)).foregroundStyle(Palette.teal)
            }
            VStack(alignment: .leading, spacing: 3) {
                if model.activity.isEmpty {
                    line(time: Self.time.string(from: Date()), tag: "SYS", tint: Palette.teal, text: "watching…")
                }
                ForEach(model.activity.prefix(6)) { a in
                    line(time: Self.time.string(from: a.date), tag: tag(a.kind), tint: tint(a.kind), text: a.presentation.title)
                        .transition(.asymmetric(insertion: .move(edge: .top).combined(with: .opacity), removal: .opacity))
                }
                HStack(spacing: 4) {
                    Text(">").foregroundStyle(Palette.teal)
                    BlinkingCursor(running: desktop.visible)
                }
                .font(.system(size: 11, design: .monospaced))
            }
            .animation(.easeOut(duration: 0.35), value: model.activity.first?.id)
            .padding(8)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.black.opacity(0.35), in: RoundedRectangle(cornerRadius: 6))
            .overlay(RoundedRectangle(cornerRadius: 6).strokeBorder(Palette.teal.opacity(0.15), lineWidth: 1))
        }
        .desktopCard(padding: DS.Space.m + 2)
    }

    private func line(time: String, tag: String, tint: Color, text: String) -> some View {
        HStack(spacing: 6) {
            Text(time).foregroundStyle(.white.opacity(0.35))
            Text(tag).foregroundStyle(tint).frame(width: 30, alignment: .leading)
            Text(text).foregroundStyle(.white.opacity(0.85)).lineLimit(1).truncationMode(.middle)
        }
        .font(.system(size: 11, design: .monospaced))
    }

    private func tag(_ k: ActivityItem.Kind) -> String {
        switch k { case .threat: return "THR"; case .network: return "NET"; case .scan: return "SCN"; case .update: return "UPD"; case .settings: return "CFG"; case .protection: return "SYS" }
    }
    private func tint(_ k: ActivityItem.Kind) -> Color {
        switch k { case .threat: return Palette.coral; case .network: return Palette.amber; case .scan: return Palette.mint
        case .update: return Color(red: 0.55, green: 0.6, blue: 1); case .settings: return .white.opacity(0.6); case .protection: return Palette.teal }
    }
}

// MARK: - Defense grid: every shield with a status light

struct DesktopDefenseGrid: View {
    @Environment(AppModel.self) private var model
    @Environment(DesktopMode.self) private var desktop
    private let cm = CatAndMouseModel.shared

    private struct Row: Identifiable { let id: String; let label: String; let on: Bool?; let item: SidebarItem? }

    private var rows: [Row] {
        let live = model.mode == .live
        let fw = model.posture.first { $0.id == "firewall" }.map { $0.state == .pass }
        return [
            Row(id: "rt", label: "Real-time scanning", on: live ? model.status.realtimeOn : nil, item: .dashboard),
            Row(id: "fda", label: "Full Disk Access", on: live ? model.fullDiskAccess : nil, item: .settings),
            Row(id: "web", label: "Web protection", on: live ? model.status.webProtectionOn : nil, item: .network),
            Row(id: "fw", label: "macOS firewall", on: fw, item: .posture),
            Row(id: "cm", label: "Cat & Mouse decoys", on: cm.status.map { _ in true } ?? false, item: .catAndMouse),
        ]
    }

    var body: some View {
        let r = rows
        let online = r.filter { $0.on == true }.count
        VStack(alignment: .leading, spacing: DS.Space.s) {
            HStack(spacing: 6) {
                Image(systemName: "shield.lefthalf.filled").font(.caption.weight(.semibold)).foregroundStyle(Palette.teal)
                Text("DEFENSE GRID").font(DS.Font.eyebrow).tracking(1.2).foregroundStyle(.white.opacity(0.62))
                Spacer()
                Text("\(online)/\(r.count) ONLINE").font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                    .foregroundStyle(online == r.count ? Palette.mint : Palette.amber)
            }
            VStack(spacing: 5) {
                ForEach(r) { row in
                    Button { if let i = row.item { DesktopMode.shared.openMain(i) } } label: {
                        HStack(spacing: 8) {
                            StatusLED(color: row.on == true ? Palette.mint : (row.on == false ? Palette.amber : .white.opacity(0.3)))
                            Text(row.label).font(.system(size: 12, design: .monospaced)).foregroundStyle(.white.opacity(0.85))
                            Spacer()
                            Text(row.on == true ? "ON" : (row.on == false ? "OFF" : "--"))
                                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                                .foregroundStyle(row.on == true ? Palette.mint : (row.on == false ? Palette.amber : .white.opacity(0.4)))
                        }
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .overlay { ScanSweep(running: desktop.visible) }
        }
        .desktopCard(padding: DS.Space.m + 2)
    }
}

// MARK: - Small animated parts (all stop when the desktop isn't visible)

struct StatusLED: View {
    var color: Color
    var body: some View {
        Circle().fill(color).frame(width: 7, height: 7)
            .shadow(color: color.opacity(0.9), radius: 4)
            .accessibilityHidden(true)
    }
}

struct PulsingDot: View {
    var color: Color
    var running: Bool
    @StateVar private var on = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        Circle().fill(color).frame(width: 7, height: 7)
            .shadow(color: color, radius: on ? 5 : 1)
            .opacity(on ? 1 : 0.35)
            .onAppear { restart() }
            .onChange(of: running) { _, _ in restart() }
            .accessibilityHidden(true)
    }
    private func restart() {
        guard running, !reduceMotion else { on = true; return }
        withAnimation(.easeInOut(duration: 0.9).repeatForever(autoreverses: true)) { on.toggle() }
    }
}

struct BlinkingCursor: View {
    var running: Bool
    @StateVar private var on = true
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        Rectangle().fill(Palette.teal).frame(width: 7, height: 12)
            .opacity(on ? 0.9 : 0)
            .onAppear { restart() }
            .onChange(of: running) { _, _ in restart() }
            .accessibilityHidden(true)
    }
    private func restart() {
        guard running, !reduceMotion else { on = true; return }
        withAnimation(.linear(duration: 0.01).delay(0.55).repeatForever(autoreverses: true)) { on.toggle() }
    }
}

/// A thin bright bar sweeping down over the rows, like a scanner.
struct ScanSweep: View {
    var running: Bool
    @StateVar private var y: CGFloat = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        GeometryReader { g in
            LinearGradient(colors: [Palette.teal.opacity(0), Palette.teal.opacity(0.22), Palette.teal.opacity(0)], startPoint: .top, endPoint: .bottom)
                .frame(height: 18)
                .offset(y: y * (g.size.height + 18) - 18)
                .onAppear { restart() }
                .onChange(of: running) { _, _ in restart() }
        }
        .clipped()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
    private func restart() {
        guard running, !reduceMotion else { y = -1; return }
        y = 0
        withAnimation(.linear(duration: 3.2).repeatForever(autoreverses: false)) { y = 1 }
    }
}
