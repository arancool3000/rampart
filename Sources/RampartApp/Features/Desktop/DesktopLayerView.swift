import SwiftUI
import AppKit
import RampartShared
import RampartGuard

// MARK: - Shared pieces

/// Widget frames, collected so the layer can pass clicks on empty space through to Finder.
struct DesktopHitKey: PreferenceKey {
    static var defaultValue: [CGRect] { [] }
    static func reduce(value: inout [CGRect], nextValue: () -> [CGRect]) { value += nextValue() }
}

extension View {
    /// Marks this view as interactive on the desktop layer (clicks land here, not on the desktop below).
    func desktopHit() -> some View {
        background(GeometryReader { g in Color.clear.preference(key: DesktopHitKey.self, value: [g.frame(in: .named("desktop"))]) })
    }
    /// Frosted card that blurs the wallpaper behind it.
    func desktopCard(padding: CGFloat = DS.Space.l) -> some View { modifier(DesktopCardModifier(padding: padding)) }
}

struct DesktopCardModifier: ViewModifier {
    var padding: CGFloat
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: DS.Radius.panel, style: .continuous)
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                ZStack {
                    if Headless.active { shape.fill(Color(red: 0.06, green: 0.10, blue: 0.16).opacity(0.82)) }
                    // A behind-window blur over the animated backdrop re-blurs every frame; use a plain tint there.
                    else if DesktopMode.shared.backdrop == .full { shape.fill(Color(red: 0.03, green: 0.06, blue: 0.11).opacity(0.78)) }
                    else { BehindWindowBlur().clipShape(shape); shape.fill(Color.black.opacity(0.22)) }
                    shape.fill(LinearGradient(colors: [Color.white.opacity(0.07), .clear], startPoint: .top, endPoint: .center))
                }
            }
            .overlay { shape.strokeBorder(LinearGradient(colors: [Color.white.opacity(0.22), Color.white.opacity(0.05)], startPoint: .top, endPoint: .bottom), lineWidth: 1) }
            .shadow(color: .black.opacity(0.25), radius: 18, y: 8)
            .desktopHit()
    }
}

/// Real behind-window blur (the wallpaper shows through, softened).
struct BehindWindowBlur: NSViewRepresentable {
    var material: NSVisualEffectView.Material = .hudWindow
    func makeNSView(context: Context) -> NSVisualEffectView {
        let v = NSVisualEffectView()
        v.material = material; v.blendingMode = .behindWindow; v.state = .active
        return v
    }
    func updateNSView(_ v: NSVisualEffectView, context: Context) { v.material = material }
}

struct DesktopSectionTitle: View {
    let title: String
    var symbol: String? = nil
    var trailing: AnyView? = nil
    var body: some View {
        HStack(spacing: 6) {
            if let symbol { Image(systemName: symbol).font(.caption.weight(.semibold)).foregroundStyle(Palette.teal) }
            Text(title.uppercased()).font(DS.Font.eyebrow).tracking(1.2).foregroundStyle(.white.opacity(0.62))
            Spacer(minLength: 0)
            if let trailing { trailing }
        }
        .accessibilityAddTraits(.isHeader)
    }
}

// MARK: - Backdrop (below the desktop icons)

struct DesktopBackdropView: View {
    @Environment(DesktopMode.self) private var desktop
    var body: some View {
        ZStack {
            switch desktop.backdrop {
            case .glass: Color.clear
            case .tinted:
                LinearGradient(colors: [Palette.navy.opacity(0.62), Palette.deepTeal.opacity(0.42)], startPoint: .topLeading, endPoint: .bottomTrailing)
            case .full:
                RampartAnimatedBackdrop(running: desktop.visible)
            }
            // A soft vignette keeps white text readable on bright wallpapers.
            if desktop.backdrop != .full {
                LinearGradient(colors: [Color.black.opacity(0.28), .clear, .clear, Color.black.opacity(0.22)], startPoint: .top, endPoint: .bottom)
            }
        }
        .ignoresSafeArea()
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

// MARK: - The layer

struct DesktopLayerView: View {
    let screenNumber: Int
    let primary: Bool
    /// Previews: force the welcome card on or off.
    var welcomeOverride: Bool? = nil
    @Environment(DesktopMode.self) private var desktop
    @StateVar private var appeared = Headless.active

    var body: some View {
        GeometryReader { geo in
            let compact = !primary || geo.size.width < 1100
            ZStack(alignment: .top) {
                HStack(alignment: .top, spacing: DS.Space.l) {
                    VStack(alignment: .leading, spacing: DS.Space.l) {
                        DesktopClock()
                        DesktopProtectionCard()
                        if !compact { DesktopQuickActions() }
                        if compact { DesktopSystemGrid() }
                        Spacer(minLength: 0)
                    }
                    .frame(width: 340)
                    .modifier(Entrance(appeared: appeared, delay: 0))
                    if !compact {
                        VStack(spacing: DS.Space.l) {
                            DesktopSearchBar()
                                .zIndex(2)
                            if desktop.launcherOpen {
                                DesktopLauncher()
                                    .zIndex(1)
                                    .transition(.opacity.combined(with: .move(edge: .top)))
                            }
                        }
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
                        .modifier(Entrance(appeared: appeared, delay: 0.06))
                        VStack(spacing: DS.Space.l) {
                            DesktopSystemGrid()
                            DesktopActivityCard()
                            DesktopCatchesCard()
                            Spacer(minLength: 0)
                            // Bottom-right is kept clear for the floating RamPart bot.
                            Color.clear.frame(height: DS.botClearance).accessibilityHidden(true)
                        }
                        .frame(width: 310)
                        .modifier(Entrance(appeared: appeared, delay: 0.12))
                    } else {
                        Spacer(minLength: 0)
                    }
                }
                .padding(DS.Space.xl)
                if primary && welcomeOverride == true {   // live: shown in its own window (DesktopMode.showWelcome)
                    DesktopWelcomeCard().frame(maxWidth: 560).padding(.top, 120).zIndex(5)
                }
            }
            .frame(width: geo.size.width, height: geo.size.height)
        }
        .coordinateSpace(name: "desktop")
        .onPreferenceChange(DesktopHitKey.self) { rects in
            let n = screenNumber
            MainActor.assumeIsolated { DesktopMode.shared.setHitRects(rects, for: n) }
        }
        .foregroundStyle(.white)
        .onAppear {
            guard !appeared else { return }
            withAnimation(.easeOut(duration: 0.5)) { appeared = true }
        }
    }

    /// Fade and a small rise. No bounce.
    struct Entrance: ViewModifier {
        let appeared: Bool
        let delay: Double
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        func body(content: Content) -> some View {
            content
                .opacity(appeared ? 1 : 0)
                .offset(y: appeared || reduceMotion ? 0 : 10)
                .animation(reduceMotion ? .easeOut(duration: 0.2) : .easeOut(duration: 0.55).delay(delay), value: appeared)
        }
    }
}

// MARK: - Clock

struct DesktopClock: View {
    var body: some View {
        TimelineView(.everyMinute) { ctx in
            VStack(alignment: .leading, spacing: 2) {
                Text(ctx.date.formatted(date: .omitted, time: .shortened))
                    .font(.system(size: 76, weight: .thin, design: .rounded))
                    .monospacedDigit()
                Text(ctx.date.formatted(.dateTime.weekday(.wide).day().month(.wide)))
                    .font(.system(size: 20, weight: .medium, design: .rounded))
                    .foregroundStyle(.white.opacity(0.85))
                Text(Self.greeting(ctx.date)).font(DS.Font.body).foregroundStyle(.white.opacity(0.6))
            }
            .shadow(color: .black.opacity(0.35), radius: 10, y: 2)
        }
        .accessibilityElement(children: .combine)
    }
    static func greeting(_ d: Date) -> String {
        switch Calendar.current.component(.hour, from: d) {
        case 5..<12: return "Good morning"
        case 12..<18: return "Good afternoon"
        default: return "Good evening"
        }
    }
}

// MARK: - Protection

struct DesktopProtectionCard: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        let s = DashboardStatus(model)
        VStack(alignment: .leading, spacing: DS.Space.m) {
            HStack(spacing: DS.Space.m) {
                StatusMark(size: 54, badge: s.badge, tint: s.tint, dimmed: s.dimmed)
                VStack(alignment: .leading, spacing: 2) {
                    Text(s.title).font(DS.Font.headline).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                    Text(s.short).font(DS.Font.caption).foregroundStyle(.white.opacity(0.65)).lineLimit(2)
                }
                Spacer(minLength: 0)
                if model.hasData { ScoreRing(score: model.securityScore, size: 66, lineWidth: 7) }
            }
            if let p = model.scanProgress {
                VStack(alignment: .leading, spacing: 4) {
                    ProgressView(value: p.total > 0 ? min(1, Double(p.scanned) / Double(p.total)) : nil)
                        .tint(Palette.teal)
                    HStack {
                        Text("Scanning · \(Fmt.count(p.scanned)) files").font(DS.Font.caption).monospacedDigit()
                        Spacer()
                        Button("Stop") { model.stopScan() }.buttonStyle(.borderless).font(DS.Font.caption.weight(.semibold))
                    }
                    .foregroundStyle(.white.opacity(0.75))
                }
            }
            needsYou
        }
        .desktopCard()
        .accessibilityElement(children: .contain)
    }

    @ViewBuilder private var needsYou: some View {
        let n = model.needsYouCount
        let recs = model.recommendations.count
        Button {
            if n > 0 { DesktopMode.shared.openMain(.threats) }
            else if recs > 0 { DesktopMode.shared.openMain(.posture) }
            else { DesktopMode.shared.openMain(.dashboard) }
        } label: {
            HStack(spacing: DS.Space.s) {
                Image(systemName: n > 0 ? "exclamationmark.circle.fill" : (recs > 0 ? "lightbulb.fill" : "checkmark.circle.fill"))
                    .foregroundStyle(n > 0 ? Palette.coral : (recs > 0 ? Palette.amber : Palette.mint))
                Text(n > 0 ? "Review \(n == 1 ? "it" : "them") in \(Product.name)" : (recs > 0 ? "\(recs) suggestion\(recs == 1 ? "" : "s") to raise your score" : "Nothing needs you"))
                    .font(DS.Font.callout.weight(.medium))
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.white.opacity(0.5))
            }
            .padding(.horizontal, DS.Space.m).padding(.vertical, DS.Space.s)
            .background(Color.white.opacity(n > 0 ? 0.12 : 0.06), in: RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous))
            .contentShape(RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous))
        }
        .buttonStyle(DesktopPressStyle())
        .help("Open \(Product.name)")
    }
}

/// The status words shared by the dashboard hero and the desktop card.
struct DashboardStatus {
    let title: String, short: String, badge: String, tint: Color, dimmed: Bool
    @MainActor init(_ model: AppModel) {
        switch model.overall {
        case .protected: (title, short, badge, tint, dimmed) = ("Your Mac is protected", "Real-time protection is on.", "checkmark.circle.fill", .statusProtected, false)
        case .recommendations(let n): (title, short, badge, tint, dimmed) = ("Your Mac is protected", "\(n) setting\(n == 1 ? "" : "s") could be safer.", "checkmark.circle.fill", .statusProtected, false)
        case .threat(let n): (title, short, badge, tint, dimmed) = (n == 1 ? "1 item needs you" : "\(n) items need you", "\(Product.name) stopped it. Choose what to do.", "exclamationmark.circle.fill", .statusAction, false)
        case .off: (title, short, badge, tint, dimmed) = ("Protection is off", "Files aren't being checked.", "xmark.circle.fill", .statusAction, true)
        case .limited: (title, short, badge, tint, dimmed) = ("Limited scanning", "Needs Full Disk Access.", "exclamationmark.circle.fill", .statusAttention, false)
        case .paused(let until): (title, short, badge, tint, dimmed) = ("Protection paused", "Resumes at \(until.formatted(date: .omitted, time: .shortened)).", "pause.circle.fill", .gray, true)
        case .starting: (title, short, badge, tint, dimmed) = ("Starting protection…", "One moment.", "clock.fill", .rampartTeal, false)
        case .serviceDown: (title, short, badge, tint, dimmed) = ("Protection isn't running", "Open \(Product.name) to fix it.", "xmark.circle.fill", .statusAction, true)
        }
    }
}

struct DesktopPressStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .opacity(configuration.isPressed ? 0.75 : 1)
            .scaleEffect(configuration.isPressed ? 0.985 : 1)
            .animation(.easeOut(duration: 0.12), value: configuration.isPressed)
    }
}

// MARK: - Quick actions

struct DesktopQuickActions: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            DesktopSectionTitle(title: "Quick actions", symbol: "bolt.fill")
            LazyVGrid(columns: [GridItem(.flexible(), spacing: DS.Space.s), GridItem(.flexible(), spacing: DS.Space.s)], spacing: DS.Space.s) {
                ForEach(DesktopAction.allCases) { a in
                    Button { a.perform() } label: {
                        VStack(alignment: .leading, spacing: 6) {
                            Image(systemName: a.symbol).font(.system(size: 17, weight: .semibold)).foregroundStyle(a.tint)
                                .frame(width: 34, height: 34)
                                .background(a.tint.opacity(0.16), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                            Text(a == .quickScan && model.isScanning ? "Scanning…" : a.title).font(DS.Font.callout.weight(.semibold)).lineLimit(1)
                            Text(a.subtitle).font(DS.Font.caption).foregroundStyle(.white.opacity(0.55)).lineLimit(1)
                        }
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(DS.Space.m)
                        .background(Color.white.opacity(0.06), in: RoundedRectangle(cornerRadius: DS.Radius.tile, style: .continuous))
                        .overlay(RoundedRectangle(cornerRadius: DS.Radius.tile, style: .continuous).strokeBorder(Color.white.opacity(0.08)))
                        .contentShape(RoundedRectangle(cornerRadius: DS.Radius.tile, style: .continuous))
                    }
                    .buttonStyle(DesktopPressStyle())
                    .disabled(a == .quickScan && model.isScanning)
                    .help(a == .quickScan ? "Run a Quick Scan now" : "Opens \(a.title) in \(Product.name)")
                }
            }
        }
        .desktopCard()
    }
}

// MARK: - System widgets

struct DesktopSystemGrid: View {
    private let info = DesktopInfo.shared
    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            DesktopSectionTitle(title: "This Mac", symbol: "desktopcomputer")
            Grid(horizontalSpacing: DS.Space.s, verticalSpacing: DS.Space.s) {
                GridRow {
                    Meter(title: "CPU", value: info.cpu.map { "\(Int(($0 * 100).rounded()))%" } ?? "–", fraction: info.cpu, tint: Palette.teal, history: info.cpuHistory)
                    Meter(title: "Memory", value: info.memory.map { "\(Int(($0.fraction * 100).rounded()))%" } ?? "–", fraction: info.memory?.fraction, tint: Palette.mint,
                          caption: info.memory.map { "\(DesktopFormat.bytes($0.used)) of \(DesktopFormat.bytes($0.total))" })
                }
                GridRow {
                    Meter(title: "Disk", value: info.disk.map { "\(DesktopFormat.bytes($0.free)) free" } ?? "–", fraction: info.disk?.fraction, tint: Color(red: 0.55, green: 0.6, blue: 1),
                          caption: info.disk.map { "of \(DesktopFormat.bytes($0.total))" })
                    Meter(title: info.battery == nil ? "Power" : "Battery",
                          value: info.battery.map { "\($0.percent)%" } ?? "Adapter",
                          fraction: info.battery.map { Double($0.percent) / 100 }, tint: (info.battery?.percent ?? 100) <= 20 ? Palette.coral : Palette.amber,
                          caption: info.battery.map { b in b.charging ? "Charging" : (b.onAC ? "On power adapter" : (b.minutesLeft.map { "\($0 / 60)h \($0 % 60)m left" } ?? "On battery")) } ?? "No battery")
                }
                GridRow {
                    Meter(title: "Network", value: "↓ \(DesktopFormat.rate(info.down))", fraction: nil, tint: Palette.teal, history: info.netHistory,
                          caption: "↑ \(DesktopFormat.rate(info.up))")
                    Meter(title: "Wi-Fi", value: wifiValue, fraction: nil, tint: (info.wifi?.weak ?? false) ? Palette.amber : Palette.mint,
                          caption: info.wifi.map { $0.connected ? $0.security : "Off or not connected" } ?? "No Wi-Fi")
                        .help(info.wifi?.connected == true && info.wifi?.name == nil ? "macOS shows Wi-Fi names only to apps with Location access. \(Product.name) doesn't ask for it." : "")
                }
            }
            HStack {
                Image(systemName: "clock.arrow.circlepath").foregroundStyle(.white.opacity(0.5))
                Text("Up \(info.bootDate.map { Uptime.format(Date().timeIntervalSince($0)) } ?? "–")").monospacedDigit()
                Spacer()
                Text(info.interval.map { "Live · every \(Int($0)) s" } ?? "Paused").foregroundStyle(.white.opacity(0.45))
            }
            .font(DS.Font.caption).foregroundStyle(.white.opacity(0.7))
        }
        .desktopCard()
    }

    private var wifiValue: String {
        guard let w = info.wifi else { return "–" }
        guard w.connected else { return "Off" }
        return w.name ?? "Connected"
    }

    struct Meter: View {
        let title: String
        let value: String
        let fraction: Double?
        let tint: Color
        var history: [Double] = []
        var caption: String? = nil
        var body: some View {
            VStack(alignment: .leading, spacing: 4) {
                Text(title).font(DS.Font.caption).foregroundStyle(.white.opacity(0.6))
                Text(value).font(.system(size: 17, weight: .semibold, design: .rounded)).monospacedDigit().lineLimit(1).minimumScaleFactor(0.7)
                    .contentTransition(.numericText())
                    .animation(.easeOut(duration: 0.3), value: value)
                if let f = fraction {
                    GeometryReader { g in
                        ZStack(alignment: .leading) {
                            Capsule().fill(Color.white.opacity(0.1))
                            Capsule().fill(LinearGradient(colors: [tint.opacity(0.7), tint], startPoint: .leading, endPoint: .trailing))
                                .frame(width: max(4, g.size.width * min(1, max(0, f))))
                                .animation(.easeOut(duration: 0.5), value: f)
                        }
                    }
                    .frame(height: 5)
                } else if history.count > 2 {
                    MiniLine(values: history, tint: tint).frame(height: 14)
                } else {
                    Color.clear.frame(height: 5)
                }
                if let caption { Text(caption).font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.5)).lineLimit(1).minimumScaleFactor(0.8) }
            }
            .frame(maxWidth: .infinity, minHeight: 74, alignment: .topLeading)
            .padding(DS.Space.s + 2)
            .background(Color.white.opacity(0.05), in: RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous))
            .accessibilityElement(children: .combine)
        }
    }

    /// A tiny line chart drawn with a Path (no Charts overhead per tick).
    struct MiniLine: View {
        let values: [Double]
        let tint: Color
        var body: some View {
            GeometryReader { g in
                let maxV = max(values.max() ?? 1, 0.0001)
                Path { p in
                    for (i, v) in values.enumerated() {
                        let pt = CGPoint(x: g.size.width * CGFloat(i) / CGFloat(max(values.count - 1, 1)), y: g.size.height * (1 - CGFloat(v / maxV)))
                        i == 0 ? p.move(to: pt) : p.addLine(to: pt)
                    }
                }
                .stroke(tint, style: StrokeStyle(lineWidth: 1.5, lineCap: .round, lineJoin: .round))
            }
            .accessibilityHidden(true)
        }
    }
}

// MARK: - Activity and catches

struct DesktopActivityCard: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            DesktopSectionTitle(title: "Recent activity", symbol: "clock.arrow.circlepath", trailing: AnyView(
                Button("All") { DesktopMode.shared.openMain(.activity) }.buttonStyle(.borderless).font(DS.Font.caption.weight(.semibold)).foregroundStyle(Palette.teal)))
            if model.activity.isEmpty {
                Text("Nothing yet. \(Product.name) lists what it checks and blocks here.").font(DS.Font.caption).foregroundStyle(.white.opacity(0.6))
            }
            ForEach(model.activity.prefix(4)) { a in
                HStack(spacing: DS.Space.s) {
                    Image(systemName: a.kind.symbol).font(.caption).foregroundStyle(.white.opacity(0.6)).frame(width: 16)
                    Text(a.title).font(DS.Font.caption).lineLimit(1).truncationMode(.middle)
                    Spacer(minLength: 4)
                    Text(Fmt.ago(a.date)).font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.45)).lineLimit(1)
                }
            }
        }
        .desktopCard(padding: DS.Space.m + 2)
    }
}

struct DesktopCatchesCard: View {
    private let cm = CatAndMouseModel.shared
    var body: some View {
        let catches = cm.realCatches
        VStack(alignment: .leading, spacing: DS.Space.s) {
            DesktopSectionTitle(title: "Cat & Mouse", symbol: "cat.fill", trailing: AnyView(
                Button("Open") { DesktopMode.shared.openMain(.catAndMouse) }.buttonStyle(.borderless).font(DS.Font.caption.weight(.semibold)).foregroundStyle(Palette.teal)))
            if catches.isEmpty {
                Text(cm.status == nil ? "Decoys catch snoops that open files they shouldn't." : "No one has touched the decoys.")
                    .font(DS.Font.caption).foregroundStyle(.white.opacity(0.6))
            } else {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    CountUpNumber(value: catches.count).font(.system(size: 26, weight: .bold, design: .rounded))
                    Text(catches.count == 1 ? "catch" : "catches").font(DS.Font.caption).foregroundStyle(.white.opacity(0.6))
                }
                ForEach(catches.prefix(2)) { c in
                    HStack(spacing: DS.Space.s) {
                        Image(systemName: c.contained ? "lock.fill" : "eye.fill").font(.caption).foregroundStyle(c.contained ? Palette.mint : Palette.amber)
                        Text(c.processName.isEmpty ? "Something" : c.processName).font(DS.Font.caption.weight(.medium)).lineLimit(1)
                        Text((c.decoyPath as NSString).lastPathComponent).font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.5)).lineLimit(1).truncationMode(.middle)
                        Spacer(minLength: 4)
                        Text(Fmt.ago(c.date)).font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.45)).lineLimit(1)
                    }
                }
            }
        }
        .desktopCard(padding: DS.Space.m + 2)
    }
}

// MARK: - Welcome (first time on; in-app, never a system dialog)

struct DesktopWelcomeCard: View {
    @Environment(DesktopMode.self) private var desktop
    var body: some View {
        @Bindable var desktop = desktop
        VStack(alignment: .leading, spacing: DS.Space.m) {
            HStack(spacing: DS.Space.m) {
                RamPartMark(size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Welcome to Desktop Mode").font(DS.Font.title)
                    Text("Your desktop is now a \(Product.name) command centre.").font(DS.Font.callout).foregroundStyle(.white.opacity(0.7))
                }
            }
            VStack(alignment: .leading, spacing: 6) {
                bullet("cursorarrow.click", "Your desktop still works: click empty space to use desktop icons and Finder as usual.")
                bullet("rectangle.on.rectangle", "Icons that sit under a widget are covered. Drag them aside, or turn off desktop items in System Settings › Desktop & Dock.")
                bullet("keyboard", "Turn it on or off with \(DesktopMode.shortcutLabel), from the menu bar or in Settings.")
                bullet("leaf", "Widgets refresh only while you can see them.")
            }
            Picker("Background", selection: $desktop.backdrop) {
                ForEach(DesktopBackdropStyle.allCases) { Text($0.title).tag($0) }
            }
            .pickerStyle(.segmented)
            HStack {
                Button("Turn Off") { desktop.setOn(false) }.buttonStyle(.bordered)
                Spacer()
                Button("Got It") { withAnimation(.easeOut(duration: 0.25)) { desktop.welcomeSeen = true } }
                    .buttonStyle(GlowButtonStyle()).controlSize(.large)
            }
        }
        .padding(DS.Space.xl)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: DS.Radius.panel, style: .continuous).fill(Color(red: 0.05, green: 0.08, blue: 0.13)))
        .overlay { RoundedRectangle(cornerRadius: DS.Radius.panel, style: .continuous).strokeBorder(Color.white.opacity(0.15), lineWidth: 1) }
        .shadow(color: .black.opacity(0.35), radius: 18, y: 8)
        // Solid, not frosted: it floats over other widgets, which a behind-window blur can't hide.
        .desktopHit()
        .transition(.opacity)
    }
    private func bullet(_ s: String, _ t: String) -> some View {
        HStack(alignment: .top, spacing: DS.Space.s) {
            Image(systemName: s).foregroundStyle(Palette.teal).frame(width: 20)
            Text(t).font(DS.Font.callout).foregroundStyle(.white.opacity(0.85)).fixedSize(horizontal: false, vertical: true)
        }
    }
}
