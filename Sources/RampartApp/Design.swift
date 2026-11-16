import SwiftUI
import AppKit
import Charts
import Observation

// MARK: - Palette

enum Palette {
    static let navy = Color(red: 0.027, green: 0.051, blue: 0.110)
    static let midnight = Color(red: 0.039, green: 0.090, blue: 0.180)
    static let abyss = Color(red: 0.020, green: 0.130, blue: 0.200)
    static let deepTeal = Color(red: 0.016, green: 0.235, blue: 0.290)
    static let teal = Color(red: 0.090, green: 0.720, blue: 0.800)
    static let mint = Color(red: 0.330, green: 0.900, blue: 0.760)
    static let amber = Color(red: 1.000, green: 0.760, blue: 0.250)
    static let coral = Color(red: 1.000, green: 0.420, blue: 0.380)

    /// Two-stop gradient for a status/score colour.
    static func gradient(for score: Int) -> [Color] {
        switch score {
        case 75...: return [Palette.teal, Palette.mint]
        case 50..<75: return [Palette.amber, .yellow]
        default: return [Palette.coral, .red]
        }
    }
}

// MARK: - Animation gate: animations run only while a window that shows them is actually visible.

@MainActor
@Observable
final class AnimationGate {
    static let shared = AnimationGate()
    private(set) var mainVisible = false
    var popoverVisible = false
    /// `--animate` forces animations on (used to measure their worst-case cost in headless mode).
    let forced = CommandLine.arguments.contains("--animate")
    var live: Bool { forced || mainVisible || popoverVisible }
    @ObservationIgnored private var started = false

    func start() {
        guard !started else { return }
        started = true
        for n in [NSWindow.didChangeOcclusionStateNotification, NSWindow.willCloseNotification, NSWindow.didMiniaturizeNotification,
                  NSWindow.didDeminiaturizeNotification, NSApplication.didHideNotification, NSApplication.didUnhideNotification] {
            NotificationCenter.default.addObserver(forName: n, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { AnimationGate.shared.recompute() }
            }
        }
        recompute()
    }

    func recompute() {
        let v = !Headless.active && NSApp.windows.contains {
            $0.identifier?.rawValue.contains("main") == true && $0.isVisible && !$0.isMiniaturized && $0.occlusionState.contains(.visible)
        }
        if v != mainVisible { mainVisible = v }
    }
}

// MARK: - Backdrop (content layer; static, so it costs nothing at idle)

struct AppBackdrop: View {
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    private var dark: [Color] {
        [Palette.navy, Palette.midnight, Palette.abyss,
         Palette.midnight, Color(red: 0.03, green: 0.12, blue: 0.21), Palette.deepTeal.opacity(0.95),
         Palette.navy, Palette.midnight, Color(red: 0.02, green: 0.17, blue: 0.23)]
    }
    private var light: [Color] {
        [Color(red: 0.965, green: 0.975, blue: 0.990), Color(red: 0.935, green: 0.965, blue: 0.980), Color(red: 0.880, green: 0.955, blue: 0.965),
         Color(red: 0.955, green: 0.970, blue: 0.985), Color(red: 0.920, green: 0.960, blue: 0.975), Color(red: 0.860, green: 0.945, blue: 0.955),
         Color(red: 0.970, green: 0.978, blue: 0.990), Color(red: 0.945, green: 0.968, blue: 0.982), Color(red: 0.900, green: 0.955, blue: 0.965)]
    }

    var body: some View {
        Group {
            if reduceTransparency {
                Color(nsColor: .windowBackgroundColor)
            } else if #available(macOS 15, *) {
                ZStack {
                    MeshGradient(width: 3, height: 3,
                                 points: [[0, 0], [0.5, 0], [1, 0], [0, 0.5], [0.58, 0.46], [1, 0.42], [0, 1], [0.45, 1], [1, 1]],
                                 colors: scheme == .dark ? dark : light)
                    TechGrid(dark: scheme == .dark)
                }
            } else {
                ZStack {
                    LinearGradient(colors: scheme == .dark ? [Palette.navy, Palette.midnight] : [light[0], light[4]], startPoint: .topLeading, endPoint: .bottomTrailing)
                    RadialGradient(colors: [(scheme == .dark ? Palette.deepTeal : light[5]).opacity(0.9), .clear], center: .bottomTrailing, startRadius: 0, endRadius: 700)
                }
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }
}

/// Static circuit-board grid: fine lines every 24 pt, brighter every 96 pt, node dots on the major crossings,
/// faint scanlines. Drawn once per size change (no animation), so it costs nothing while idle.
struct TechGrid: View {
    var dark: Bool
    var body: some View {
        Canvas(rendersAsynchronously: true) { ctx, size in
            let line = dark ? Color(red: 0.39, green: 0.95, blue: 0.81) : Color(red: 0.05, green: 0.45, blue: 0.5)
            var minor = Path(), major = Path(), dots = Path()
            var x: CGFloat = 0
            while x <= size.width {
                (Int(x) % 96 == 0 ? { major.addRect(CGRect(x: x, y: 0, width: 1, height: size.height)) } : { minor.addRect(CGRect(x: x, y: 0, width: 1, height: size.height)) })()
                x += 24
            }
            var y: CGFloat = 0
            while y <= size.height {
                (Int(y) % 96 == 0 ? { major.addRect(CGRect(x: 0, y: y, width: size.width, height: 1)) } : { minor.addRect(CGRect(x: 0, y: y, width: size.width, height: 1)) })()
                y += 24
            }
            for gx in stride(from: 0, through: size.width, by: 96) { for gy in stride(from: 0, through: size.height, by: 96) {
                dots.addRect(CGRect(x: gx - 1, y: gy - 1, width: 3, height: 3)) } }
            ctx.fill(minor, with: .color(line.opacity(dark ? 0.035 : 0.04)))
            ctx.fill(major, with: .color(line.opacity(dark ? 0.07 : 0.07)))
            ctx.fill(dots, with: .color(line.opacity(dark ? 0.25 : 0.2)))
            if dark {
                var scan = Path()
                stride(from: 0, to: size.height, by: 3).forEach { scan.addRect(CGRect(x: 0, y: $0, width: size.width, height: 1)) }
                ctx.fill(scan, with: .color(Color.black.opacity(0.12)))
            }
            // fade the grid out toward the bottom-right so content stays calm
            ctx.fill(Path(CGRect(origin: .zero, size: size)), with: .radialGradient(Gradient(colors: [.clear, (dark ? Color.black : Color.white).opacity(0.35)]),
                     center: CGPoint(x: size.width * 0.3, y: size.height * 0.2), startRadius: 0, endRadius: max(size.width, size.height)))
        }
        .allowsHitTesting(false)
        .drawingGroup()
    }
}

// MARK: - Cards

struct CardModifier: ViewModifier {
    var padding: CGFloat = Spacing.l
    var tint: Color? = nil
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 8, style: .continuous)
        let isDark = scheme == .dark
        let accent = tint ?? .rampartTeal
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                ZStack {
                    if reduceTransparency {
                        shape.fill(Color(nsColor: .controlBackgroundColor))
                    } else {
                        shape.fill(isDark ? Color(red: 0.03, green: 0.07, blue: 0.12).opacity(0.72) : Color.white.opacity(0.82))
                        // faint scan glow from the top edge
                        shape.fill(LinearGradient(colors: [accent.opacity(isDark ? 0.07 : 0.05), .clear], startPoint: .top, endPoint: .init(x: 0.5, y: 0.35)))
                        if let tint {
                            shape.fill(LinearGradient(colors: [tint.opacity(isDark ? 0.10 : 0.08), tint.opacity(0)], startPoint: .topLeading, endPoint: .bottomTrailing))
                        }
                    }
                }
                .shadow(color: isDark ? .clear : Color.black.opacity(0.06), radius: 10, y: 3)
            }
            .overlay {
                shape.strokeBorder(
                    LinearGradient(colors: isDark ? [accent.opacity(0.38), accent.opacity(0.08), Color.white.opacity(0.05)]
                                                  : [accent.opacity(0.35), Color.black.opacity(0.06)],
                                   startPoint: .topLeading, endPoint: .bottomTrailing),
                    lineWidth: 1)
            }
            .overlay { HUDCorners(color: accent.opacity(isDark ? 0.85 : 0.6)) }
    }
}

/// Targeting-bracket corners for HUD panels.
struct HUDCorners: View {
    var color: Color = .rampartTeal
    var length: CGFloat = 12
    var inset: CGFloat = -1
    var body: some View {
        GeometryReader { g in
            Path { p in
                let w = g.size.width, h = g.size.height, l = length, i = inset
                p.move(to: CGPoint(x: i, y: i + l)); p.addLine(to: CGPoint(x: i, y: i)); p.addLine(to: CGPoint(x: i + l, y: i))
                p.move(to: CGPoint(x: w - i - l, y: i)); p.addLine(to: CGPoint(x: w - i, y: i)); p.addLine(to: CGPoint(x: w - i, y: i + l))
                p.move(to: CGPoint(x: w - i, y: h - i - l)); p.addLine(to: CGPoint(x: w - i, y: h - i)); p.addLine(to: CGPoint(x: w - i - l, y: h - i))
                p.move(to: CGPoint(x: i + l, y: h - i)); p.addLine(to: CGPoint(x: i, y: h - i)); p.addLine(to: CGPoint(x: i, y: h - i - l))
            }
            .stroke(color, style: StrokeStyle(lineWidth: 1.5, lineCap: .square))
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

extension View {
    func card(padding: CGFloat = Spacing.l, tint: Color? = nil) -> some View { modifier(CardModifier(padding: padding, tint: tint)) }
    func roundedDesign() -> some View { self.fontDesign(.monospaced) }
}

/// Rounded-square gradient icon (tiles, scan cards, onboarding).
struct IconBadge: View {
    let symbol: String
    var tint: Color = .rampartTeal
    var size: CGFloat = 36
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.18, style: .continuous)
                .fill(tint.opacity(0.14))
            RoundedRectangle(cornerRadius: size * 0.18, style: .continuous)
                .strokeBorder(tint.opacity(0.7), lineWidth: 1)
                .shadow(color: tint.opacity(0.6), radius: 4)
            Image(systemName: symbol)
                .font(.system(size: size * 0.46, weight: .semibold))
                .foregroundStyle(tint)
                .shadow(color: tint.opacity(0.7), radius: 3)
                .symbolRenderingMode(.hierarchical)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// Hover lift for clickable cards. No scale under Reduce Motion.
struct HoverLift: ViewModifier {
    @StateVar private var hover = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    func body(content: Content) -> some View {
        content
            .scaleEffect(hover && !reduceMotion ? 1.012 : 1)
            .brightness(hover ? 0.02 : 0)
            .animation(reduceMotion ? nil : .spring(response: 0.3, dampingFraction: 0.8), value: hover)
            .onHover { hover = $0 }
    }
}
extension View { func hoverLift() -> some View { modifier(HoverLift()) } }

// MARK: - Hero shield with a slow breathing glow (only when protected, only while visible, never under Reduce Motion)

struct ShieldHero: View {
    let symbol: String
    let tint: Color
    var breathe: Bool = false
    var size: CGFloat = 150
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    private let gate = AnimationGate.shared

    var body: some View {
        let animate = breathe && gate.live && !reduceMotion
        ZStack {
            Circle().strokeBorder(tint.opacity(0.24), lineWidth: 1).frame(width: size * 0.78, height: size * 0.78)
            Circle().strokeBorder(tint.opacity(0.12), lineWidth: 1).frame(width: size * 0.96, height: size * 0.96)
            Image(systemName: symbol)
                .font(.system(size: size * 0.42, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(LinearGradient(colors: [tint, tint.opacity(0.7)], startPoint: .top, endPoint: .bottom))
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

// MARK: - Charts

struct DayStat: Identifiable, Hashable {
    var id: Date { day }
    let day: Date
    var filesChecked: Int
    var sitesBlocked: Int
    var threats: Int
}

struct Sparkline: View {
    let values: [Double]
    var tint: Color = .rampartTeal
    var body: some View {
        Chart {
            ForEach(Array(values.enumerated()), id: \.offset) { i, v in
                AreaMark(x: .value("i", i), y: .value("v", v))
                    .interpolationMethod(.catmullRom)
                    .foregroundStyle(LinearGradient(colors: [tint.opacity(0.35), tint.opacity(0)], startPoint: .top, endPoint: .bottom))
                LineMark(x: .value("i", i), y: .value("v", v))
                    .interpolationMethod(.catmullRom)
                    .foregroundStyle(tint)
                    .lineStyle(StrokeStyle(lineWidth: 2, lineCap: .round))
            }
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .chartLegend(.hidden)
        .accessibilityHidden(true)
    }
}

struct MiniBars: View {
    let values: [Double]
    var tint: Color = .rampartTeal
    var body: some View {
        Chart {
            ForEach(Array(values.enumerated()), id: \.offset) { i, v in
                BarMark(x: .value("i", String(i)), y: .value("v", v), width: .ratio(0.62))
                    .foregroundStyle(LinearGradient(colors: [tint, tint.opacity(0.45)], startPoint: .top, endPoint: .bottom))
                    .cornerRadius(3)
            }
        }
        .chartXAxis(.hidden)
        .chartYAxis(.hidden)
        .accessibilityHidden(true)
    }
}

// MARK: - Buttons

/// Primary action button: teal gradient capsule with a soft glow. Keeps its colour in inactive windows.
struct GlowButtonStyle: ButtonStyle {
    var tint: Color = .rampartTeal
    func makeBody(configuration: Configuration) -> some View { GlowButtonBody(configuration: configuration, tint: tint) }

    struct GlowButtonBody: View {
        let configuration: Configuration
        let tint: Color
        @Environment(\.isEnabled) private var enabled
        @Environment(\.controlSize) private var controlSize
        @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
        @StateVar private var hover = false
        var body: some View {
            let large = controlSize == .large || controlSize == .extraLarge
            configuration.label
                .font(large ? .body.weight(.semibold) : .callout.weight(.semibold))
                .padding(.horizontal, large ? 18 : 12).padding(.vertical, large ? 8 : 4)
                .foregroundStyle(.white)
                .background {
                    Capsule().fill(LinearGradient(colors: [tint.opacity(hover ? 1 : 0.95), tint.opacity(0.75)], startPoint: .top, endPoint: .bottom))
                }
                .overlay { Capsule().strokeBorder(Color.white.opacity(0.28), lineWidth: 1) }
                .shadow(color: reduceTransparency ? .clear : tint.opacity(hover ? 0.5 : 0.32), radius: hover ? 10 : 6, y: 2)
                .opacity(enabled ? (configuration.isPressed ? 0.85 : 1) : 0.45)
                .scaleEffect(configuration.isPressed ? 0.98 : 1)
                .contentShape(Capsule())
                .onHover { hover = $0 }
                .animation(.easeOut(duration: 0.15), value: hover)
        }
    }
}
