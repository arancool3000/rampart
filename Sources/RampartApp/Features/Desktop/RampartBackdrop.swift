import RampartShared
import SwiftUI

/// The custom animated RamPart desktop: a deep-navy night with a receding neon pixel grid, data packets racing along
/// it, a slow radar sweep, a giant faint Pixel Guard watching over the screen (it blinks), drifting pixel dust and
/// a soft CRT shimmer. Drawn in one Canvas at 10 fps (4 on battery) only while the desktop is actually visible; static with
/// Reduce Motion. Pure function of time, so there's no state to leak.
struct RampartAnimatedBackdrop: View {
    var running: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        TimelineView(.animation(minimumInterval: PowerThrottle.shared.factor > 1 ? 1.0 / 4 : 1.0 / 10, paused: !running || reduceMotion)) { tl in
            Canvas(rendersAsynchronously: true) { ctx, size in
                Self.draw(&ctx, size, t: reduceMotion ? 3 : tl.date.timeIntervalSinceReferenceDate)
            }
        }
        .ignoresSafeArea()
        .accessibilityHidden(true)
    }

    // Palette
    static let teal = Color(red: 0.39, green: 0.95, blue: 0.81)
    static let cyan = Color(red: 0.09, green: 0.72, blue: 0.80)
    static let red = Color(red: 1.0, green: 0.35, blue: 0.37)

    static func draw(_ ctx: inout GraphicsContext, _ size: CGSize, t: Double) {
        let w = size.width, h = size.height, horizon = h * 0.58
        let rect = CGRect(origin: .zero, size: size)

        // 1. Sky: navy → midnight, with a teal glow on the horizon.
        ctx.fill(Path(rect), with: .linearGradient(Gradient(colors: [Color(red: 0.012, green: 0.025, blue: 0.06), Color(red: 0.03, green: 0.07, blue: 0.15),
                                                                      Color(red: 0.02, green: 0.16, blue: 0.22)]),
                                                   startPoint: .zero, endPoint: CGPoint(x: 0, y: horizon)))
        ctx.fill(Path(CGRect(x: 0, y: horizon, width: w, height: h - horizon)), with: .color(Color(red: 0.01, green: 0.03, blue: 0.07)))
        let glowPulse = 0.75 + 0.25 * sin(t * 0.6)
        ctx.fill(Path(ellipseIn: CGRect(x: -w * 0.1, y: horizon - h * 0.22, width: w * 1.2, height: h * 0.44)),
                 with: .radialGradient(Gradient(colors: [cyan.opacity(0.28 * glowPulse), .clear]),
                                       center: CGPoint(x: w / 2, y: horizon), startRadius: 0, endRadius: w * 0.55))

        // 2. Stars (pixel dust) twinkling in the sky.
        for i in 0..<90 {
            let x = hash(i, 1) * w, y = hash(i, 2) * horizon * 0.95
            let tw = 0.5 + 0.5 * sin(t * (0.6 + hash(i, 3) * 1.6) + hash(i, 4) * 6.28)
            let s: CGFloat = hash(i, 5) > 0.85 ? 3 : 2
            ctx.fill(Path(CGRect(x: x.rounded(), y: y.rounded(), width: s, height: s)), with: .color(Color.white.opacity(0.15 + 0.55 * tw * tw)))
        }

        // 3. The Pixel Guard: huge, faint, standing behind the horizon. Eyes glow and blink.
        drawGuard(&ctx, w: w, horizon: horizon, h: h, t: t)

        // 4. Perspective grid floor scrolling toward you.
        let vanish = CGPoint(x: w / 2, y: horizon)
        var grid = Path()
        for i in -24...24 {   // rays to the vanishing point
            let xb = w / 2 + CGFloat(i) * w / 14
            grid.move(to: vanish); grid.addLine(to: CGPoint(x: xb, y: h))
        }
        let scroll = (t * 0.35).truncatingRemainder(dividingBy: 1)
        for k in 0..<18 {   // horizontal lines, spaced by depth
            let z = (Double(k) + 1 - scroll) / 18          // 0 near horizon … 1 at the bottom
            let y = horizon + (h - horizon) * CGFloat(z * z)
            grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: w, y: y))
        }
        var floor = ctx
        floor.clip(to: Path(CGRect(x: 0, y: horizon, width: w, height: h - horizon)))
        floor.stroke(grid, with: .linearGradient(Gradient(colors: [cyan.opacity(0.05), cyan.opacity(0.45)]),
                                                 startPoint: CGPoint(x: 0, y: horizon), endPoint: CGPoint(x: 0, y: h)), lineWidth: 1)
        // horizon line
        ctx.fill(Path(CGRect(x: 0, y: horizon - 1, width: w, height: 2)), with: .color(teal.opacity(0.55 * glowPulse)))

        // 5. Data packets racing along the grid rays toward you, with trails.
        for i in 0..<14 {
            let ray = Int(hash(i, 7) * 30) - 15
            let speed = 0.12 + hash(i, 8) * 0.18
            let p = (t * speed + hash(i, 9)).truncatingRemainder(dividingBy: 1)
            let threat = i % 7 == 3                       // the odd red one: caught and stopped by the shield line
            for trail in 0..<6 {
                let q = max(0, p - Double(trail) * 0.012)
                let z = q * q
                let xb = w / 2 + CGFloat(ray) * w / 14
                let x = vanish.x + (xb - vanish.x) * CGFloat(z), y = horizon + (h - horizon) * CGFloat(z)
                let s = max(2, CGFloat(2 + z * 7)).rounded()
                let a = (1 - Double(trail) / 6) * (0.3 + 0.7 * z)
                ctx.fill(Path(CGRect(x: (x - s / 2).rounded(), y: (y - s / 2).rounded(), width: s, height: s)),
                         with: .color((threat ? red : teal).opacity(a)))
            }
        }

        // 6. Radar sweep from the Guard across the sky.
        let ang = Angle(radians: t * 0.5)
        var sweep = ctx
        sweep.clip(to: Path(CGRect(x: 0, y: 0, width: w, height: horizon)))
        sweep.translateBy(x: w / 2, y: horizon)
        sweep.rotate(by: ang)
        var wedge = Path()
        wedge.move(to: .zero)
        wedge.addArc(center: .zero, radius: w, startAngle: .degrees(-24), endAngle: .zero, clockwise: false)
        wedge.closeSubpath()
        sweep.fill(wedge, with: .conicGradient(Gradient(colors: [.clear, teal.opacity(0.0), teal.opacity(0.10)]), center: .zero, angle: .degrees(-24)))

        // 7. CRT shimmer: faint scanlines and one bright band rolling down.
        var lines = Path()
        stride(from: 0.0, to: Double(h), by: 4).forEach { lines.addRect(CGRect(x: 0, y: $0, width: w, height: 1)) }
        ctx.fill(lines, with: .color(Color.black.opacity(0.16)))
        let band = CGFloat((t * 0.08).truncatingRemainder(dividingBy: 1.3) - 0.15) * h
        ctx.fill(Path(CGRect(x: 0, y: band, width: w, height: h * 0.12)),
                 with: .linearGradient(Gradient(colors: [.clear, teal.opacity(0.035), .clear]),
                                       startPoint: CGPoint(x: 0, y: band), endPoint: CGPoint(x: 0, y: band + h * 0.12)))
        // Vignette for widget readability.
        ctx.fill(Path(rect), with: .radialGradient(Gradient(colors: [.clear, Color.black.opacity(0.45)]),
                                                   center: CGPoint(x: w / 2, y: h * 0.45), startRadius: min(w, h) * 0.35, endRadius: max(w, h) * 0.75))
    }

    private static let guardCells = PixelGuard.cells(PixelGuard.chosen, body: false)
    private static let guardRows = PixelGuard.head(PixelGuard.chosen).count

    static func drawGuard(_ ctx: inout GraphicsContext, w: CGFloat, horizon: CGFloat, h: CGFloat, t: Double) {
        let cell = (h * 0.42 / CGFloat(guardRows)).rounded(.down)
        let gw = cell * CGFloat(PixelGuard.cols)
        let bob = CGFloat(sin(t * 0.7)) * cell * 0.25
        let origin = CGPoint(x: ((w - gw) / 2).rounded(), y: (horizon - cell * CGFloat(guardRows) * 0.92 + bob).rounded())
        let blink = t.truncatingRemainder(dividingBy: 5.5) < 0.16
        let scanRow = Int(t * 3) % 3
        for c in guardCells {
            let r = CGRect(x: origin.x + CGFloat(c.x) * cell, y: origin.y + CGFloat(c.y) * cell, width: cell - 1, height: cell - 1)
            let col: Color, a: Double
            switch c.key {
            case "e":
                if blink && c.y == PixelGuard.face(PixelGuard.chosen).eyeL.y { continue }
                col = teal; a = 0.55
            case "R": col = red; a = 0.35 + 0.25 * (0.5 + 0.5 * sin(t * 2))
            case "X": col = cyan; a = 0.16
            case "S", "V": col = Color(red: 0.02, green: 0.05, blue: 0.09); a = 0.55
            default: col = Color(red: 0.18, green: 0.26, blue: 0.34); a = 0.10
            }
            ctx.fill(Path(r), with: .color(col.opacity(a)))
            if c.key == "e" {   // eye glow
                ctx.fill(Path(ellipseIn: r.insetBy(dx: -cell * 1.2, dy: -cell * 1.2)),
                         with: .radialGradient(Gradient(colors: [teal.opacity(0.18), .clear]), center: CGPoint(x: r.midX, y: r.midY), startRadius: 0, endRadius: cell * 1.8))
            }
        }
        // visor scan line
        let f = PixelGuard.face(PixelGuard.chosen)
        let rows = Array(f.screenY)
        let sy = origin.y + CGFloat(rows[scanRow % rows.count]) * cell
        ctx.fill(Path(CGRect(x: origin.x + CGFloat(f.screenX.lowerBound) * cell, y: sy + cell * 0.45, width: CGFloat(f.screenX.count) * cell, height: max(1, cell * 0.1))),
                 with: .color(teal.opacity(0.18)))
    }

    /// Deterministic 0…1 noise.
    static func hash(_ i: Int, _ salt: Int) -> CGFloat {
        var x = UInt64(truncatingIfNeeded: i &* 374_761_393 &+ salt &* 668_265_263)
        x = (x ^ (x >> 13)) &* 1_274_126_177
        x ^= x >> 16
        return CGFloat(x & 0xFFFF) / 65535
    }
}
