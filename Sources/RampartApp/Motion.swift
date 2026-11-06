import SwiftUI
import AppKit
import RampartShared

// Motion system. Rules: every animation is finite except the slow shield breath while visible;
// nothing flashes; Reduce Motion turns everything into short fades.

// MARK: - Brand assembly (splash)

private enum Ease {
    static func clamp(_ x: Double) -> Double { min(1, max(0, x)) }
    static func out(_ x: Double) -> Double { 1 - pow(1 - clamp(x), 3) }
    /// Gentle overshoot, settles at 1 (approximates the kit's springs).
    static func back(_ x: Double) -> Double { let t = clamp(x), c = 1.4; return 1 + (c + 1) * pow(t - 1, 3) + c * pow(t - 1, 2) }
}

/// Launch assembly (1.2 s): the shield's two halves slide in from left and right and meet with a spring,
/// one light sweep crosses the shield, then the "RamPart" letters rise in one by one.
/// Animatable: a single `withAnimation` drives every frame, and it ends.
struct BrandAssembly: View, Animatable {
    var progress: Double
    var markSize: CGFloat = 132
    var wordHeight: CGFloat = 58
    @Environment(\.colorScheme) private var scheme
    var animatableData: Double { get { progress } set { progress = newValue } }

    static let duration = 1.2
    private static let letterPaths = BrandPaths.letters.map { SVGPath.parse($0.d) }

    var body: some View {
        let t = progress * Self.duration
        let meet = Ease.back(t / 0.5)                         // halves meet by 0.5 s (gentle overshoot)
        let sweep = (t - 0.45) / 0.35                         // one pass, 0.45–0.8 s
        VStack(spacing: wordHeight * 0.4) {
            RamPartMark(size: markSize, tile: true, split: CGFloat(max(0, 1 - meet)), sweep: sweep > 0 && sweep < 1 ? CGFloat(sweep) : nil,
                        halfOpacity: Ease.clamp(t / 0.2))
                .scaleEffect(0.94 + 0.06 * Ease.out(t / 0.5))
            word(t).frame(width: wordHeight * CGFloat(BrandPaths.wordmarkViewBox.w / BrandPaths.wordmarkViewBox.h), height: wordHeight)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Product.name)
    }

    private func word(_ t: Double) -> some View {
        let dark = scheme == .dark
        let accent = dark ? Color(red: 0.251, green: 0.784, blue: 0.878) : Color(red: 0.039, green: 0.518, blue: 0.627)
        let ink = dark ? Color.white : Color(red: 0.043, green: 0.106, blue: 0.180)
        return Canvas { ctx, size in
            let s = size.height / CGFloat(BrandPaths.wordmarkViewBox.h)
            ctx.scaleBy(x: s, y: s)
            for (i, l) in BrandPaths.letters.enumerated() {
                let k = Ease.out((t - 0.55 - Double(i) * 0.055) / 0.28)
                guard k > 0 else { continue }
                var c = ctx
                c.opacity = k
                if k < 1 { c.addFilter(.blur(radius: (1 - k) * 4)) }
                c.translateBy(x: 0, y: CGFloat(16 * (1 - k)))
                c.fill(Self.letterPaths[i], with: .color(l.accent ? accent : ink))
            }
        }
    }
}

/// Launch splash: once per day, ~2 s, click to skip. Never in headless runs.
struct SplashOverlay: View {
    @AppStorage("splash.lastDay") private var lastDay = ""
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var visible = false
    @StateVar private var progress: Double = 0
    @StateVar private var opacity: Double = 1

    private static var today: String { let f = DateFormatter(); f.dateFormat = "yyyy-MM-dd"; return f.string(from: Date()) }

    var body: some View {
        ZStack {
            if visible {
                ZStack {
                    AppBackdrop()
                    BrandAssembly(progress: progress)
                }
                .opacity(opacity)
                .contentShape(Rectangle())
                .onTapGesture { dismiss(fast: true) }
                .transition(.opacity)
                .accessibilityAddTraits(.isButton)
                .accessibilityHint("Click to skip")
            }
        }
        .onAppear {
            guard !Headless.active, lastDay != Self.today else { return }
            lastDay = Self.today
            visible = true
            if reduceMotion {
                progress = 1; opacity = 0
                withAnimation(.easeIn(duration: 0.2)) { opacity = 1 }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { dismiss(fast: false) }
            } else {
                withAnimation(.linear(duration: BrandAssembly.duration)) { progress = 1 }
                DispatchQueue.main.asyncAfter(deadline: .now() + BrandAssembly.duration + 0.4) { dismiss(fast: false) }
            }
        }
    }

    private func dismiss(fast: Bool) {
        guard visible else { return }
        withAnimation(.easeOut(duration: fast ? 0.15 : 0.35)) { opacity = 0 }
        DispatchQueue.main.asyncAfter(deadline: .now() + (fast ? 0.16 : 0.36)) { visible = false }
    }
}

// MARK: - Per-character text reveal

@available(macOS 15, *)
struct RevealRenderer: TextRenderer, Animatable {
    var progress: Double
    var typewriter = false
    var animatableData: Double { get { progress } set { progress = newValue } }

    func draw(layout: Text.Layout, in ctx: inout GraphicsContext) {
        let slices = layout.flatMap { line in line.flatMap { run in Array(run) } }
        let n = Double(max(slices.count, 1))
        for (i, slice) in slices.enumerated() {
            if typewriter {
                if progress * n >= Double(i) + 0.5 || progress >= 1 { ctx.draw(slice) }
                continue
            }
            let start = Double(i) / n * 0.55
            let k = min(1, max(0, (progress - start) / 0.45))
            if k <= 0 { continue }
            var c = ctx
            c.opacity = k
            if k < 1 { c.addFilter(.blur(radius: (1 - k) * 5)) }
            c.translateBy(x: 0, y: (1 - k) * 8)
            c.draw(slice)
        }
    }
}

/// Staggered blur+rise reveal each time the view appears (or `trigger` changes). Fade under Reduce Motion.
struct RevealModifier<T: Equatable>: ViewModifier {
    var trigger: T
    var typewriter = false
    var duration: Double = 0.7
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var progress: Double = Headless.active ? 1 : 0

    func body(content: Content) -> some View {
        Group {
            if #available(macOS 15, *), !reduceMotion {
                content.textRenderer(RevealRenderer(progress: progress, typewriter: typewriter))
            } else {
                content.opacity(progress > 0 ? 1 : 0).animation(.easeOut(duration: 0.2), value: progress)
            }
        }
        .onAppear { run() }
        .onChange(of: trigger) { _, _ in run() }
    }

    private func run() {
        guard !Headless.active else { progress = 1; return }
        progress = 0
        withAnimation(typewriter ? .linear(duration: duration) : .easeOut(duration: duration)) { progress = 1 }
    }
}

extension View {
    func revealText<T: Equatable>(on trigger: T, typewriter: Bool = false, duration: Double = 0.7) -> some View {
        modifier(RevealModifier(trigger: trigger, typewriter: typewriter, duration: duration))
    }
    func revealText(typewriter: Bool = false, duration: Double = 0.7) -> some View {
        modifier(RevealModifier(trigger: 0, typewriter: typewriter, duration: duration))
    }
}

// MARK: - Section transition: blur crossfade

struct BlurFade: ViewModifier {
    let amount: Double
    func body(content: Content) -> some View { content.blur(radius: amount * 10).opacity(1 - amount) }
}
extension AnyTransition {
    static var blurFade: AnyTransition { .modifier(active: BlurFade(amount: 1), identity: BlurFade(amount: 0)) }
}

// MARK: - Magnetic tilt + glow-following highlight (hover only; costs nothing at rest)

struct MagneticTilt: ViewModifier {
    var maxDegrees: Double = 4
    @StateVar private var point: CGPoint?
    @StateVar private var size: CGSize = .zero
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        let nx = point.map { ($0.x / max(size.width, 1)) - 0.5 } ?? 0
        let ny = point.map { ($0.y / max(size.height, 1)) - 0.5 } ?? 0
        content
            .overlay {
                if let p = point {
                    RoundedRectangle(cornerRadius: 16, style: .continuous)
                        .fill(RadialGradient(colors: [Color.rampartTeal.opacity(0.16), .clear], center: UnitPoint(x: p.x / max(size.width, 1), y: p.y / max(size.height, 1)),
                                             startRadius: 0, endRadius: max(size.width, size.height) * 0.6))
                        .allowsHitTesting(false)
                }
            }
            .rotation3DEffect(.degrees(reduceMotion ? 0 : Double(ny) * -maxDegrees * 2), axis: (x: 1, y: 0, z: 0), perspective: 0.6)
            .rotation3DEffect(.degrees(reduceMotion ? 0 : Double(nx) * maxDegrees * 2), axis: (x: 0, y: 1, z: 0), perspective: 0.6)
            .scaleEffect(point != nil && !reduceMotion ? 1.01 : 1)
            .animation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.75), value: point)
            .onGeometryChange(for: CGSize.self) { $0.size } action: { size = $0 }
            .onContinuousHover { phase in
                switch phase {
                case .active(let p): point = p
                case .ended: point = nil
                }
            }
    }
}

// MARK: - One-shot ripple (scan result)

struct RippleOnce: View {
    var tint: Color
    @StateVar private var go = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        ZStack {
            ForEach(0..<2) { i in
                Circle().strokeBorder(tint.opacity(0.5), lineWidth: 2)
                    .scaleEffect(go ? 2.6 : 0.8)
                    .opacity(go ? 0 : 0.7)
                    .animation(.easeOut(duration: 1.4).delay(Double(i) * 0.25), value: go)
            }
        }
        .allowsHitTesting(false)
        .onAppear { if !reduceMotion && !Headless.active { go = true } }
        .accessibilityHidden(true)
    }
}

// MARK: - Threat: shield locks (calm, no red flashing)

struct ShieldLockAnimation: View {
    var size: CGFloat = 64
    var trigger: UUID?
    @StateVar private var closed: Double = Headless.active ? 1 : 0
    @StateVar private var bounce = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        ZStack {
            Circle().stroke(Color.rampartTeal.opacity(0.15), lineWidth: 3)
            Circle().trim(from: 0, to: closed)
                .stroke(LinearGradient(colors: [Palette.teal, Palette.mint], startPoint: .top, endPoint: .bottom), style: StrokeStyle(lineWidth: 3, lineCap: .round))
                .rotationEffect(.degrees(-90))
            Image(systemName: "lock.shield.fill")
                .font(.system(size: size * 0.46, weight: .semibold))
                .symbolRenderingMode(.hierarchical)
                .foregroundStyle(Color.rampartTeal)
                .symbolEffect(.bounce, value: bounce)
        }
        .frame(width: size, height: size)
        .onAppear { play() }
        .onChange(of: trigger) { _, _ in play() }
        .accessibilityHidden(true)
    }
    private func play() {
        guard !Headless.active else { return }
        if reduceMotion { closed = 1; return }
        closed = 0
        withAnimation(.easeInOut(duration: 0.7)) { closed = 1 }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.65) { bounce += 1 }
    }
}

// MARK: - Scan particles: file names flow from the list into the radar (only while scanning and visible)

struct ScanParticles: View {
    let from: CGPoint
    let to: CGPoint
    let active: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private let gate = AnimationGate.shared
    var body: some View {
        let run = active && !reduceMotion && gate.live
        TimelineView(.animation(minimumInterval: 1.0 / 30, paused: !run)) { tl in
            Canvas { ctx, _ in
                guard run else { return }
                let t = tl.date.timeIntervalSinceReferenceDate
                for i in 0..<14 {
                    let phase = (t * 0.55 + Double(i) / 14).truncatingRemainder(dividingBy: 1)
                    let jitter = sin(Double(i) * 12.9898) * 60
                    let start = CGPoint(x: from.x, y: from.y + CGFloat(jitter))
                    let ctrl = CGPoint(x: (start.x + to.x) / 2, y: min(start.y, to.y) - 80 + CGFloat(jitter * 0.5))
                    let u = CGFloat(phase)
                    let x = (1 - u) * (1 - u) * start.x + 2 * (1 - u) * u * ctrl.x + u * u * to.x
                    let y = (1 - u) * (1 - u) * start.y + 2 * (1 - u) * u * ctrl.y + u * u * to.y
                    let r = 2.5 * (1 - u * 0.6)
                    let o = sin(Double(u) * .pi) * 0.85
                    ctx.fill(Path(ellipseIn: CGRect(x: x - r, y: y - r, width: r * 2, height: r * 2)), with: .color(Palette.mint.opacity(o)))
                }
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}
