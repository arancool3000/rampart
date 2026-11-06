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
                MeshGradient(width: 3, height: 3,
                             points: [[0, 0], [0.5, 0], [1, 0], [0, 0.5], [0.58, 0.46], [1, 0.42], [0, 1], [0.45, 1], [1, 1]],
                             colors: scheme == .dark ? dark : light)
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

// MARK: - Cards

struct CardModifier: ViewModifier {
    var padding: CGFloat = Spacing.l
    var tint: Color? = nil
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency

    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        let isDark = scheme == .dark
        content
            .padding(padding)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background {
                ZStack {
                    if reduceTransparency {
                        shape.fill(Color(nsColor: .controlBackgroundColor))
                    } else {
                        shape.fill(isDark ? Color.white.opacity(0.055) : Color.white.opacity(0.78))
                        if let tint {
                            shape.fill(LinearGradient(colors: [tint.opacity(isDark ? 0.22 : 0.14), tint.opacity(0)], startPoint: .topLeading, endPoint: .bottomTrailing))
                        }
                    }
                }
                .shadow(color: isDark ? .clear : Color.black.opacity(0.06), radius: 10, y: 3)
            }
            .overlay {
                shape.strokeBorder(
                    LinearGradient(colors: isDark ? [Color.white.opacity(0.16), Color.white.opacity(0.04)]
                                                  : [Color.white.opacity(0.9), Color.black.opacity(0.06)],
                                   startPoint: .top, endPoint: .bottom),
                    lineWidth: 1)
            }
    }
}

extension View {
    func card(padding: CGFloat = Spacing.l, tint: Color? = nil) -> some View { modifier(CardModifier(padding: padding, tint: tint)) }
    func roundedDesign() -> some View { self.fontDesign(.rounded) }
}

/// Rounded-square gradient icon (tiles, scan cards, onboarding).
struct IconBadge: View {
    let symbol: String
    var tint: Color = .rampartTeal
    var size: CGFloat = 36
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .fill(LinearGradient(colors: [tint, tint.opacity(0.62)], startPoint: .topLeading, endPoint: .bottomTrailing))
            RoundedRectangle(cornerRadius: size * 0.28, style: .continuous)
                .strokeBorder(Color.white.opacity(0.25), lineWidth: 1)
            Image(systemName: symbol)
                .font(.system(size: size * 0.46, weight: .semibold))
                .foregroundStyle(.white)
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
            if !reduceTransparency {
                if Headless.renderDir != nil {
                    // Offscreen rendering can't rasterise layer-hosted views; draw the glow's resting state.
                    Circle().fill(RadialGradient(colors: [tint.opacity(0.42), tint.opacity(0)], center: .center, startRadius: 0, endRadius: size * 0.55))
                } else {
                    GlowPulse(color: NSColor(tint), animate: animate)
                }
            }
            Circle().strokeBorder(tint.opacity(0.24), lineWidth: 1).frame(width: size * 0.78, height: size * 0.78)
            Circle().strokeBorder(tint.opacity(0.12), lineWidth: 1).frame(width: size * 0.96, height: size * 0.96)
            Image(systemName: symbol)
                .font(.system(size: size * 0.42, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(LinearGradient(colors: [tint, tint.opacity(0.7)], startPoint: .top, endPoint: .bottom))
                .shadow(color: reduceTransparency ? .clear : tint.opacity(0.55), radius: size * 0.08)
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
