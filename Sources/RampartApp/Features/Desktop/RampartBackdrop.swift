import RampartShared
import SwiftUI
import AppKit
import QuartzCore

/// The custom animated RamPart desktop: a deep-navy night with a receding neon pixel grid, data packets racing along
/// it, a slow radar sweep, a giant faint Pixel Guard watching over the screen (it blinks), drifting pixel dust and
/// a soft CRT shimmer. The still parts are rendered once into an image; everything that moves is a Core Animation layer, so
/// motion is smooth (display refresh rate) and runs in the window server, not on RamPart's CPU. Paused when hidden.
struct RampartAnimatedBackdrop: View {
    var running: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        BackdropLayerView(running: running && !reduceMotion)
            .ignoresSafeArea()
        .accessibilityHidden(true)
    }

    // Palette
    static let teal = Color(red: 0.39, green: 0.95, blue: 0.81)
    static let cyan = Color(red: 0.09, green: 0.72, blue: 0.80)
    static let red = Color(red: 1.0, green: 0.35, blue: 0.37)

    /// `still`: draw only the parts that don't move (the Core Animation layer view animates the rest on the GPU).
    static func draw(_ ctx: inout GraphicsContext, _ size: CGSize, t: Double, still: Bool = false) {
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

        // 2b. Aurora: soft teal and violet ribbons high in the sky.
        for (i, c) in [(0, cyan), (1, Color(red: 0.45, green: 0.35, blue: 0.95)), (2, teal)] {
            var band = Path()
            let y0 = horizon * (0.18 + 0.12 * CGFloat(i)), amp = horizon * 0.06
            band.move(to: CGPoint(x: 0, y: y0))
            for k in stride(from: 0, through: 40, by: 1) {
                let x = w * CGFloat(k) / 40
                band.addLine(to: CGPoint(x: x, y: y0 + amp * CGFloat(sin(Double(k) * 0.35 + Double(i) * 1.7))))
            }
            ctx.stroke(band, with: .color(c.opacity(0.07)), style: StrokeStyle(lineWidth: horizon * 0.07, lineCap: .round))
            ctx.stroke(band, with: .color(c.opacity(0.06)), style: StrokeStyle(lineWidth: horizon * 0.02, lineCap: .round))
        }

        // 3. The Pixel Guard standing watch behind the wall. Eyes glow and blink.
        drawGuard(&ctx, w: w, horizon: horizon, h: h, t: t)

        // 3b. The rampart: a pixel fortress wall with crenellations and towers along the horizon.
        drawRampart(&ctx, w: w, horizon: horizon)

        // 4. Perspective grid floor scrolling toward you.
        let vanish = CGPoint(x: w / 2, y: horizon)
        // Floor: fog glowing at the horizon, deep navy near you.
        ctx.fill(Path(CGRect(x: 0, y: horizon, width: w, height: h - horizon)),
                 with: .linearGradient(Gradient(colors: [Color(red: 0.03, green: 0.14, blue: 0.19), Color(red: 0.01, green: 0.03, blue: 0.07), Color(red: 0.005, green: 0.015, blue: 0.04)]),
                                       startPoint: CGPoint(x: 0, y: horizon), endPoint: CGPoint(x: 0, y: h)))
        let road = roadGeometry(w: w, h: h, horizon: horizon)
        var grid = Path()
        for i in -24...24 {   // rays to the vanishing point, leaving the road clear
            let xb = w / 2 + CGFloat(i) * w / 14
            if abs(xb - w / 2) < road.bottomHalf * 1.15 { continue }
            let start = CGPoint(x: w / 2 + (xb - w / 2) * (road.topHalf / road.bottomHalf), y: horizon)
            grid.move(to: start); grid.addLine(to: CGPoint(x: xb, y: h))
        }
        var glowFloor = ctx
        glowFloor.clip(to: Path(CGRect(x: 0, y: horizon, width: w, height: h - horizon)))
        glowFloor.stroke(grid, with: .linearGradient(Gradient(colors: [cyan.opacity(0.0), cyan.opacity(0.10)]),
                                                     startPoint: CGPoint(x: 0, y: horizon), endPoint: CGPoint(x: 0, y: h)), lineWidth: 5)
        let scroll = (t * 0.35).truncatingRemainder(dividingBy: 1)
        for k in 0..<(still ? 0 : 18) {   // horizontal lines, spaced by depth
            let z = (Double(k) + 1 - scroll) / 18          // 0 near horizon … 1 at the bottom
            let y = horizon + (h - horizon) * CGFloat(z * z)
            grid.move(to: CGPoint(x: 0, y: y)); grid.addLine(to: CGPoint(x: w, y: y))
        }
        var floor = ctx
        floor.clip(to: Path(CGRect(x: 0, y: horizon, width: w, height: h - horizon)))
        floor.stroke(grid, with: .linearGradient(Gradient(colors: [cyan.opacity(0.10), cyan.opacity(0.55)]),
                                                 startPoint: CGPoint(x: 0, y: horizon), endPoint: CGPoint(x: 0, y: h)), lineWidth: 1)
        // horizon line
        ctx.fill(Path(CGRect(x: 0, y: horizon - 1, width: w, height: 2)), with: .color(teal.opacity(0.55 * glowPulse)))

        // 5. Data packets racing along the grid rays toward you, with trails.
        for i in 0..<(still ? 0 : 14) {
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
        if !still {
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
        }

        // 7. CRT shimmer: faint scanlines and one bright band rolling down.
        var lines = Path()
        stride(from: 0.0, to: Double(h), by: 4).forEach { lines.addRect(CGRect(x: 0, y: $0, width: w, height: 1)) }
        ctx.fill(lines, with: .color(Color.black.opacity(0.16)))
        if !still {
        let band = CGFloat((t * 0.08).truncatingRemainder(dividingBy: 1.3) - 0.15) * h
        ctx.fill(Path(CGRect(x: 0, y: band, width: w, height: h * 0.12)),
                 with: .linearGradient(Gradient(colors: [.clear, teal.opacity(0.035), .clear]),
                                       startPoint: CGPoint(x: 0, y: band), endPoint: CGPoint(x: 0, y: band + h * 0.12)))
        }
        // Vignette for widget readability.
        ctx.fill(Path(rect), with: .radialGradient(Gradient(colors: [.clear, Color.black.opacity(0.45)]),
                                                   center: CGPoint(x: w / 2, y: h * 0.45), startRadius: min(w, h) * 0.35, endRadius: max(w, h) * 0.75))
    }

    private static let guardCells = PixelGuard.cells(PixelGuard.chosen, body: false)
    private static let guardRows = PixelGuard.head(PixelGuard.chosen).count

    static func drawGuard(_ ctx: inout GraphicsContext, w: CGFloat, horizon: CGFloat, h: CGFloat, t: Double) {
        let cell = (h * 0.30 / CGFloat(guardRows)).rounded(.down)
        let gw = cell * CGFloat(PixelGuard.cols)
        let bob = CGFloat(sin(t * 0.7)) * cell * 0.25
        let origin = CGPoint(x: ((w - gw) / 2).rounded(), y: (horizon - wallHeight(horizon) - cell * CGFloat(guardRows) * 0.78 + bob).rounded())
        let blink = t.truncatingRemainder(dividingBy: 5.5) < 0.16
        let scanRow = Int(t * 3) % 3
        for c in guardCells {
            let r = CGRect(x: origin.x + CGFloat(c.x) * cell, y: origin.y + CGFloat(c.y) * cell, width: cell - 1, height: cell - 1)
            let col: Color, a: Double
            switch c.key {
            case "e":
                let f = PixelGuard.face(PixelGuard.chosen)
                guard (f.eyeL.y..<(f.eyeL.y + f.eyeH)).contains(c.y) else { continue }   // eyes only, no cheeks
                if blink { continue }
                col = teal; a = 0.85
            case "R": col = red; a = 0.35 + 0.25 * (0.5 + 0.5 * sin(t * 2))
            case "X": col = cyan; a = 0.45
            case "S", "V": col = Color(red: 0.01, green: 0.03, blue: 0.06); a = 0.92
            case "E": col = cyan; a = 0.30
            case "d": col = Color(red: 0.10, green: 0.15, blue: 0.21); a = 0.85
            default: col = Color(red: 0.17, green: 0.24, blue: 0.31); a = 0.85
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

    /// The road from the fortress gate to the bottom of the screen.
    struct Road { var topHalf: CGFloat; var bottomHalf: CGFloat }
    static func roadGeometry(w: CGFloat, h: CGFloat, horizon: CGFloat) -> Road {
        let px = max(4, (horizon / 90).rounded())
        return Road(topHalf: px * 7, bottomHalf: w * 0.17)
    }

    static func wallHeight(_ horizon: CGFloat) -> CGFloat { (horizon * 0.075).rounded() }

    /// Pixel fortress silhouette: a crenellated wall with taller towers, lit windows, and a teal rim light on top.
    static func drawRampart(_ ctx: inout GraphicsContext, w: CGFloat, horizon: CGFloat) {
        let px = max(4, (horizon / 90).rounded())
        let wallH = wallHeight(horizon)
        let stone = Color(red: 0.04, green: 0.08, blue: 0.13), rim = teal
        var wall = Path(), rimPath = Path()
        // wall body
        wall.addRect(CGRect(x: 0, y: horizon - wallH, width: w, height: wallH))
        // crenellations
        var x: CGFloat = 0
        while x < w { wall.addRect(CGRect(x: x, y: horizon - wallH - px * 2, width: px * 3, height: px * 2)); rimPath.addRect(CGRect(x: x, y: horizon - wallH - px * 2, width: px * 3, height: 1)); x += px * 6 }
        // towers at fixed fractions, symmetric around the Guard
        for f in [0.06, 0.2, 0.34, 0.66, 0.8, 0.94] as [CGFloat] {
            let tw = px * 8, th = wallH * (f == 0.34 || f == 0.66 ? 2.6 : 1.9)
            let tx = (w * f - tw / 2).rounded()
            wall.addRect(CGRect(x: tx, y: horizon - th, width: tw, height: th))
            for k in 0..<3 { wall.addRect(CGRect(x: tx + CGFloat(k) * px * 3, y: horizon - th - px * 2, width: px * 2, height: px * 2))
                rimPath.addRect(CGRect(x: tx + CGFloat(k) * px * 3, y: horizon - th - px * 2, width: px * 2, height: 1)) }
            // windows
            for r in 0..<2 {
                let wy = horizon - th + px * 3 + CGFloat(r) * px * 4
                ctx.fill(Path(CGRect(x: tx + px * 3, y: wy, width: px * 2, height: px * 2)), with: .color(teal.opacity(hash(Int(f * 100), r) > 0.4 ? 0.55 : 0.12)))
            }
        }
        // gate under the Guard
        let gw = px * 14
        ctx.fill(wall, with: .color(stone))
        ctx.fill(Path(CGRect(x: (w - gw) / 2, y: horizon - wallH * 0.85, width: gw, height: wallH * 0.85)), with: .color(Color(red: 0.01, green: 0.02, blue: 0.04)))
        ctx.fill(rimPath, with: .color(rim.opacity(0.5)))
        ctx.fill(Path(CGRect(x: 0, y: horizon - wallH, width: w, height: 1)), with: .color(rim.opacity(0.18)))
        // brick lines
        var bricks = Path()
        var row: CGFloat = horizon - wallH + px * 2
        var odd = false
        while row < horizon - 1 {
            bricks.addRect(CGRect(x: 0, y: row, width: w, height: 1))
            var bx: CGFloat = odd ? px * 3 : 0
            while bx < w { bricks.addRect(CGRect(x: bx, y: row - px * 2, width: 1, height: px * 2)); bx += px * 6 }
            row += px * 2; odd.toggle()
        }
        ctx.fill(bricks, with: .color(Color.black.opacity(0.35)))
    }

    /// Deterministic 0…1 noise.
    static func hash(_ i: Int, _ salt: Int) -> CGFloat {
        var x = UInt64(truncatingIfNeeded: i &* 374_761_393 &+ salt &* 668_265_263)
        x = (x ^ (x >> 13)) &* 1_274_126_177
        x ^= x >> 16
        return CGFloat(x & 0xFFFF) / 65535
    }
}


// MARK: - Core Animation host

struct BackdropLayerView: NSViewRepresentable {
    var running: Bool
    func makeNSView(context: Context) -> BackdropNSView { BackdropNSView() }
    func updateNSView(_ v: BackdropNSView, context: Context) { v.setRunning(running) }
}

final class BackdropNSView: NSView {
    private var built = CGSize.zero
    private var running = true

    override init(frame: NSRect) { super.init(frame: frame); wantsLayer = true; layer?.backgroundColor = NSColor.black.cgColor }
    required init?(coder: NSCoder) { fatalError() }
    override var isFlipped: Bool { true }

    func setRunning(_ on: Bool) {
        running = on
        guard let l = layer else { return }
        if on, l.speed == 0 {   // resume
            let paused = l.timeOffset
            l.speed = 1; l.timeOffset = 0; l.beginTime = 0
            l.beginTime = l.convertTime(CACurrentMediaTime(), from: nil) - paused
        } else if !on, l.speed != 0 {
            let t = l.convertTime(CACurrentMediaTime(), from: nil)
            l.speed = 0; l.timeOffset = t
        }
    }

    override func layout() {
        super.layout()
        guard bounds.size != built, bounds.width > 10, let root = layer else { return }
        built = bounds.size
        root.sublayers?.forEach { $0.removeFromSuperlayer() }
        build(in: root, size: bounds.size)
        setRunning(running)
    }

    private func cg(_ c: Color) -> CGColor { NSColor(c).cgColor }

    private func build(in root: CALayer, size: CGSize) {
        let w = size.width, h = size.height, horizon = h * 0.58
        let scale = window?.backingScaleFactor ?? NSScreen.main?.backingScaleFactor ?? 2
        typealias B = RampartAnimatedBackdrop

        // 1. Still image: sky, stars, Guard, floor rays, scanlines, vignette.
        let still = ImageRenderer(content: Canvas { ctx, sz in B.draw(&ctx, sz, t: 1, still: true) }.frame(width: w, height: h))
        still.scale = scale
        let base = CALayer()
        base.frame = CGRect(origin: .zero, size: size)
        base.contents = still.cgImage
        base.contentsGravity = .resize
        root.addSublayer(base)

        // 2. Horizon glow pulse.
        let glow = CALayer()
        glow.frame = CGRect(x: 0, y: horizon - 1, width: w, height: 2)
        glow.backgroundColor = cg(B.teal)
        glow.shadowColor = cg(B.teal); glow.shadowRadius = 8; glow.shadowOpacity = 0.9; glow.shadowOffset = .zero
        glow.add(pulse("opacity", from: 0.35, to: 0.75, dur: 5.2), forKey: "p")
        root.addSublayer(glow)

        // 3. Grid lines rushing toward you: each line follows y = horizon + depth² · floor, staggered.
        let floorH = h - horizon, lines = 16, period = 3.2
        let floorClip = CALayer()
        floorClip.frame = CGRect(x: 0, y: horizon, width: w, height: floorH)
        floorClip.masksToBounds = true
        root.addSublayer(floorClip)
        for k in 0..<lines {
            let line = CALayer()
            line.frame = CGRect(x: 0, y: 0, width: w, height: 1.5)
            line.backgroundColor = cg(B.cyan)
            line.shadowColor = cg(B.cyan); line.shadowOpacity = 0.9; line.shadowRadius = 4; line.shadowOffset = .zero
            line.shadowPath = CGPath(rect: line.bounds, transform: nil)
            let steps = 24
            let ys = (0...steps).map { i -> NSNumber in let z = Double(i) / Double(steps); return NSNumber(value: Double(floorH) * z * z) }
            let ops = (0...steps).map { i -> NSNumber in let z = Double(i) / Double(steps); return NSNumber(value: 0.05 + 0.45 * z) }
            let a = CAKeyframeAnimation(keyPath: "position.y"); a.values = ys
            let o = CAKeyframeAnimation(keyPath: "opacity"); o.values = ops
            let g = CAAnimationGroup(); g.animations = [a, o]; g.duration = period; g.repeatCount = .infinity
            g.timeOffset = period * Double(k) / Double(lines)
            line.add(g, forKey: "move")
            floorClip.addSublayer(line)
        }

        // 3b. The road into the gate: dark lane with neon edges, a glow reflected from the Guard,
        //     chasing runway lights along both edges and centre dashes rushing toward you.
        let road = B.roadGeometry(w: w, h: h, horizon: horizon)
        func edgeX(_ side: CGFloat, _ s: CGFloat) -> CGFloat { w / 2 + side * (road.topHalf + (road.bottomHalf - road.topHalf) * s) }
        let lane = CGMutablePath()
        lane.move(to: CGPoint(x: edgeX(-1, 0), y: horizon)); lane.addLine(to: CGPoint(x: edgeX(1, 0), y: horizon))
        lane.addLine(to: CGPoint(x: edgeX(1, 1), y: h)); lane.addLine(to: CGPoint(x: edgeX(-1, 1), y: h)); lane.closeSubpath()
        let laneFill = CAGradientLayer()
        laneFill.frame = CGRect(origin: .zero, size: size)
        laneFill.colors = [NSColor(red: 0.05, green: 0.16, blue: 0.20, alpha: 1).cgColor, NSColor(red: 0.015, green: 0.035, blue: 0.07, alpha: 1).cgColor]
        laneFill.startPoint = CGPoint(x: 0.5, y: horizon / h); laneFill.endPoint = CGPoint(x: 0.5, y: 1)
        let laneMask = CAShapeLayer(); laneMask.path = lane; laneFill.mask = laneMask
        root.addSublayer(laneFill)
        // reflection of the Guard's glow on the road
        let reflect = CAGradientLayer()
        reflect.type = .radial
        reflect.frame = CGRect(x: w / 2 - road.bottomHalf, y: horizon, width: road.bottomHalf * 2, height: (h - horizon) * 0.7)
        reflect.colors = [cg(B.teal.opacity(0.22)), cg(B.teal.opacity(0))]
        reflect.startPoint = CGPoint(x: 0.5, y: 0); reflect.endPoint = CGPoint(x: 1, y: 1)
        let rm = CAShapeLayer(); var t = CGAffineTransform(translationX: -reflect.frame.minX, y: -reflect.frame.minY); rm.path = lane.copy(using: &t); reflect.mask = rm
        reflect.add(pulse("opacity", from: 0.6, to: 1, dur: 3.1), forKey: "p")
        root.addSublayer(reflect)
        // neon edges
        for side: CGFloat in [-1, 1] {
            let e = CAShapeLayer()
            let ep = CGMutablePath(); ep.move(to: CGPoint(x: edgeX(side, 0), y: horizon)); ep.addLine(to: CGPoint(x: edgeX(side, 1), y: h))
            e.path = ep; e.strokeColor = cg(B.teal); e.lineWidth = 2.5; e.fillColor = nil
            e.shadowColor = cg(B.teal); e.shadowOpacity = 1; e.shadowRadius = 10; e.shadowOffset = .zero
            root.addSublayer(e)
        }
        // runway lights chasing toward you
        let lights = 12, chase = 1.8
        for side: CGFloat in [-1, 1] {
            for k in 0..<lights {
                let sDepth = pow(Double(k + 1) / Double(lights + 1), 2)
                let sz = CGFloat(3 + 9 * sDepth)
                let l = CALayer()
                l.bounds = CGRect(x: 0, y: 0, width: sz, height: sz * 0.6)
                l.cornerRadius = sz * 0.3
                l.position = CGPoint(x: edgeX(side, CGFloat(sDepth)) + side * sz, y: horizon + (h - horizon) * CGFloat(sDepth))
                l.backgroundColor = NSColor.white.cgColor
                l.shadowColor = cg(B.teal); l.shadowOpacity = 1; l.shadowRadius = sz; l.shadowOffset = .zero
                let a = CAKeyframeAnimation(keyPath: "opacity")
                a.values = [0.15, 1, 0.15, 0.15]; a.keyTimes = [0, 0.08, 0.3, 1]; a.duration = chase; a.repeatCount = .infinity
                a.timeOffset = chase - chase * Double(k) / Double(lights)
                l.opacity = 0.15
                l.add(a, forKey: "chase")
                root.addSublayer(l)
            }
        }
        // centre dashes rushing toward you
        let dashes = 7, dashPeriod = 1.4, dSteps = 20
        for k in 0..<dashes {
            let d = CALayer()
            d.backgroundColor = cg(B.teal)
            d.shadowColor = cg(B.teal); d.shadowOpacity = 0.9; d.shadowRadius = 6; d.shadowOffset = .zero
            var pos: [NSValue] = [], bnd: [NSValue] = [], op: [NSNumber] = []
            for i in 0...dSteps {
                let q = Double(i) / Double(dSteps), z = CGFloat(q * q)
                pos.append(NSValue(point: CGPoint(x: w / 2, y: horizon + (h - horizon) * z)))
                bnd.append(NSValue(rect: CGRect(x: 0, y: 0, width: max(1, 10 * z), height: max(1, 70 * z))))
                op.append(NSNumber(value: 0.2 + 0.8 * Double(z)))
            }
            let pa = CAKeyframeAnimation(keyPath: "position"); pa.values = pos
            let ba = CAKeyframeAnimation(keyPath: "bounds"); ba.values = bnd
            let oa = CAKeyframeAnimation(keyPath: "opacity"); oa.values = op
            let g = CAAnimationGroup(); g.animations = [pa, ba, oa]; g.duration = dashPeriod * Double(dashes) / 2.5; g.repeatCount = .infinity
            g.timeOffset = g.duration * Double(k) / Double(dashes)
            d.add(g, forKey: "dash")
            root.addSublayer(d)
        }

        // 4. Data packets racing down the rays, with a glow trail; every 7th one is a red threat.
        let vanish = CGPoint(x: w / 2, y: horizon)
        for i in 0..<14 {
            let ray = Int(B.hash(i, 7) * 30) - 15
            let xb = w / 2 + CGFloat(ray) * w / 14
            let threat = i % 7 == 3
            let color = cg(threat ? B.red : B.teal)
            let steps = 20
            var pts: [NSValue] = [], sizes: [NSValue] = [], ops: [NSNumber] = []
            for s in 0...steps {
                let q = Double(s) / Double(steps), z = CGFloat(q * q)
                pts.append(NSValue(point: CGPoint(x: vanish.x + (xb - vanish.x) * z, y: horizon + (h - horizon) * z)))
                let px = max(2, 2 + z * 8)
                sizes.append(NSValue(rect: CGRect(x: 0, y: 0, width: px, height: px)))
                ops.append(NSNumber(value: 0.25 + 0.75 * Double(z)))
            }
            let dur = 1 / (0.12 + Double(B.hash(i, 8)) * 0.18)
            for trail in 0..<4 {
                let p = CALayer()
                p.backgroundColor = color
                p.shadowColor = color; p.shadowRadius = trail == 0 ? 6 : 0; p.shadowOpacity = trail == 0 ? 0.9 : 0; p.shadowOffset = .zero
                let pa = CAKeyframeAnimation(keyPath: "position"); pa.values = pts
                let ba = CAKeyframeAnimation(keyPath: "bounds"); ba.values = sizes
                let oa = CAKeyframeAnimation(keyPath: "opacity"); oa.values = ops.map { NSNumber(value: $0.doubleValue * (1 - Double(trail) / 4)) }
                let g = CAAnimationGroup(); g.animations = [pa, ba, oa]; g.duration = dur; g.repeatCount = .infinity
                g.timeOffset = dur * Double(B.hash(i, 9)) - Double(trail) * dur * 0.025
                p.add(g, forKey: "run")
                root.addSublayer(p)
            }
        }

        // 5. Radar sweep around the Guard, clipped to the sky.
        let skyClip = CALayer()
        skyClip.frame = CGRect(x: 0, y: 0, width: w, height: horizon)
        skyClip.masksToBounds = true
        root.addSublayer(skyClip)
        let radar = CAGradientLayer()
        radar.type = .conic
        let R = max(w, h) * 1.2
        radar.frame = CGRect(x: w / 2 - R, y: horizon - R, width: 2 * R, height: 2 * R)
        radar.startPoint = CGPoint(x: 0.5, y: 0.5); radar.endPoint = CGPoint(x: 0.5, y: 0)
        let clear = cg(B.teal.opacity(0))
        radar.colors = [clear, clear, cg(B.teal.opacity(0.10)), clear]
        radar.locations = [0, 0.86, 0.995, 1]
        let spin = CABasicAnimation(keyPath: "transform.rotation.z")
        spin.fromValue = 0; spin.toValue = Double.pi * 2; spin.duration = 12.5; spin.repeatCount = .infinity
        radar.add(spin, forKey: "spin")
        skyClip.addSublayer(radar)

        // 6. Twinkling bright stars.
        for i in 0..<28 {
            let s = CALayer()
            let px: CGFloat = B.hash(i, 5) > 0.7 ? 3 : 2
            s.frame = CGRect(x: (B.hash(i + 500, 1) * w).rounded(), y: (B.hash(i + 500, 2) * horizon * 0.9).rounded(), width: px, height: px)
            s.backgroundColor = NSColor.white.cgColor
            let a = pulse("opacity", from: 0.1, to: 0.85, dur: 1.2 + Double(B.hash(i, 3)) * 2.4)
            a.timeOffset = Double(B.hash(i, 4)) * 3
            s.add(a, forKey: "tw")
            root.addSublayer(s)
        }

        // 7. The Guard blinks: dark lids flash over its eyes every 5.5 s; its red crest light breathes.
        let rows = CGFloat(PixelGuard.head(PixelGuard.chosen).count)
        let cell = (h * 0.30 / rows).rounded(.down)
        let gw = cell * CGFloat(PixelGuard.cols)
        let origin = CGPoint(x: ((w - gw) / 2).rounded(), y: (horizon - B.wallHeight(horizon) - cell * rows * 0.78).rounded())
        let f = PixelGuard.face(PixelGuard.chosen)
        for eye in [f.eyeL, f.eyeR] {
            let lid = CALayer()
            lid.frame = CGRect(x: origin.x + CGFloat(eye.x) * cell - 2, y: origin.y + CGFloat(eye.y) * cell - 2,
                               width: CGFloat(f.eyeW) * cell + 4, height: CGFloat(f.eyeH) * cell + 4)
            lid.backgroundColor = NSColor(red: 0.02, green: 0.04, blue: 0.08, alpha: 1).cgColor
            let b = CAKeyframeAnimation(keyPath: "opacity")
            b.values = [0, 0, 1, 1, 0]; b.keyTimes = [0, 0.95, 0.955, 0.985, 0.99]; b.duration = 5.5; b.repeatCount = .infinity
            lid.opacity = 0
            lid.add(b, forKey: "blink")
            root.addSublayer(lid)
        }
        let guardCells = PixelGuard.cells(PixelGuard.chosen)
        for c in guardCells where c.key == "R" {
            let r = CALayer()
            r.frame = CGRect(x: origin.x + CGFloat(c.x) * cell, y: origin.y + CGFloat(c.y) * cell, width: cell - 1, height: cell - 1)
            r.backgroundColor = cg(B.red)
            r.add(pulse("opacity", from: 0.2, to: 0.6, dur: 1.6), forKey: "breathe")
            root.addSublayer(r)
        }

        // 7a. Force field: a hex-grid dome over the fortress with a shimmer sweeping across it.
        let domeW = min(w * 0.42, h * 0.95), domeH = horizon * 0.55
        let domeRect = CGRect(x: (w - domeW) / 2, y: horizon - domeH, width: domeW, height: domeH)
        let dome = CGMutablePath()
        dome.move(to: CGPoint(x: domeRect.minX, y: horizon))
        dome.addCurve(to: CGPoint(x: domeRect.maxX, y: horizon),
                      control1: CGPoint(x: domeRect.minX, y: domeRect.minY - domeH * 0.33), control2: CGPoint(x: domeRect.maxX, y: domeRect.minY - domeH * 0.33))
        dome.closeSubpath()
        let hexImg: CGImage? = {
            let sz = CGSize(width: domeRect.width * scale, height: domeRect.height * scale)
            guard let c = CGContext(data: nil, width: Int(sz.width), height: Int(sz.height), bitsPerComponent: 8, bytesPerRow: 0,
                                    space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return nil }
            c.setStrokeColor(NSColor.white.cgColor); c.setLineWidth(1 * scale)
            let r = 14 * scale, hx = r * sqrt(3)
            var row = 0
            var yy: CGFloat = 0
            while yy < sz.height + r {
                var xx: CGFloat = row % 2 == 0 ? 0 : hx / 2
                while xx < sz.width + hx {
                    let p = CGMutablePath()
                    for k in 0..<6 { let a = CGFloat(k) * .pi / 3 + .pi / 6
                        let pt = CGPoint(x: xx + r * cos(a), y: yy + r * sin(a)); k == 0 ? p.move(to: pt) : p.addLine(to: pt) }
                    p.closeSubpath(); c.addPath(p)
                    xx += hx
                }
                yy += r * 1.5; row += 1
            }
            c.strokePath()
            return c.makeImage()
        }()
        let domeLocal = { () -> CGPath in var t = CGAffineTransform(translationX: -domeRect.minX, y: -domeRect.minY); return dome.copy(using: &t)! }()
        let field = CALayer(); field.frame = domeRect
        let fieldMask = CAShapeLayer(); fieldMask.path = domeLocal; field.mask = fieldMask
        let hexLayer = CALayer(); hexLayer.frame = field.bounds; hexLayer.contents = hexImg
        hexLayer.contentsGravity = .resize
        let tint = CALayer(); tint.frame = field.bounds; tint.backgroundColor = cg(B.teal)
        tint.mask = hexLayer; tint.opacity = 0.06
        tint.add(pulse("opacity", from: 0.03, to: 0.09, dur: 4.5), forKey: "breathe")
        field.addSublayer(tint)
        // shimmer: a bright band of hexes sweeping left → right
        let shimmerHex = CALayer(); shimmerHex.frame = field.bounds; shimmerHex.contents = hexImg; shimmerHex.contentsGravity = .resize
        let shimmer = CAGradientLayer(); shimmer.frame = field.bounds
        shimmer.colors = [cg(B.teal.opacity(0)), cg(B.teal.opacity(0.55)), cg(B.teal.opacity(0))]
        shimmer.startPoint = CGPoint(x: 0, y: 0.5); shimmer.endPoint = CGPoint(x: 1, y: 0.5)
        shimmer.locations = [0, 0.05, 0.1]
        let sweep = CABasicAnimation(keyPath: "locations")
        sweep.fromValue = [-0.2, -0.1, 0]; sweep.toValue = [1, 1.1, 1.2]
        sweep.duration = 2.4
        let sweepCycle = CAAnimationGroup(); sweepCycle.animations = [sweep]; sweepCycle.duration = 7; sweepCycle.repeatCount = .infinity
        shimmer.add(sweepCycle, forKey: "sweep")
        shimmer.mask = shimmerHex
        field.addSublayer(shimmer)
        root.addSublayer(field)
        let rim = CAShapeLayer(); rim.frame = domeRect; rim.path = domeLocal
        rim.fillColor = nil; rim.strokeColor = cg(B.teal.opacity(0.45)); rim.lineWidth = 1.5
        rim.shadowColor = cg(B.teal); rim.shadowOpacity = 0.8; rim.shadowRadius = 8; rim.shadowOffset = .zero
        rim.add(pulse("opacity", from: 0.5, to: 1, dur: 4.5), forKey: "breathe")
        root.addSublayer(rim)

        // 7a2. Floor scan beam: a bright line sweeps from the gate toward you every few seconds.
        let beam = CALayer()
        beam.frame = CGRect(x: 0, y: 0, width: w, height: 3)
        beam.backgroundColor = cg(B.teal)
        beam.shadowColor = cg(B.teal); beam.shadowOpacity = 1; beam.shadowRadius = 12; beam.shadowOffset = .zero
        beam.shadowPath = CGPath(rect: beam.bounds, transform: nil)
        let bSteps = 24
        let bys = (0...bSteps).map { i -> NSNumber in let z = Double(i) / Double(bSteps); return NSNumber(value: Double(horizon) + Double(h - horizon) * z * z) }
        let bop = (0...bSteps).map { i -> NSNumber in let z = Double(i) / Double(bSteps); return NSNumber(value: sin(z * .pi) * 0.9) }
        let by = CAKeyframeAnimation(keyPath: "position.y"); by.values = bys; by.duration = 2.2
        let bo = CAKeyframeAnimation(keyPath: "opacity"); bo.values = bop; bo.duration = 2.2
        let beamCycle = CAAnimationGroup(); beamCycle.animations = [by, bo]; beamCycle.duration = 8; beamCycle.repeatCount = .infinity
        beam.opacity = 0
        beam.add(beamCycle, forKey: "scan")
        root.addSublayer(beam)

        // 7b. Shooting stars: a streak crosses the sky now and then.
        for i in 0..<3 {
            let streak = CAGradientLayer()
            streak.colors = [NSColor.white.withAlphaComponent(0).cgColor, NSColor.white.withAlphaComponent(0.9).cgColor]
            streak.startPoint = CGPoint(x: 0, y: 0.5); streak.endPoint = CGPoint(x: 1, y: 0.5)
            streak.bounds = CGRect(x: 0, y: 0, width: 140, height: 2)
            streak.setAffineTransform(CGAffineTransform(rotationAngle: .pi / 7))
            let y0 = horizon * (0.08 + 0.18 * B.hash(i, 31)), x0 = w * (0.1 + 0.5 * B.hash(i, 32))
            let move = CABasicAnimation(keyPath: "position")
            move.fromValue = NSValue(point: CGPoint(x: x0, y: y0)); move.toValue = NSValue(point: CGPoint(x: x0 + w * 0.25, y: y0 + w * 0.25 * 0.48))
            let fade = CAKeyframeAnimation(keyPath: "opacity"); fade.values = [0, 1, 0]; fade.keyTimes = [0, 0.3, 1]
            let shot = CAAnimationGroup(); shot.animations = [move, fade]; shot.duration = 0.9
            let cycle = CAAnimationGroup(); cycle.animations = [shot]; cycle.duration = 9 + Double(i) * 6; cycle.repeatCount = .infinity
            cycle.timeOffset = Double(B.hash(i, 33)) * cycle.duration
            streak.opacity = 0
            streak.add(cycle, forKey: "shoot")
            root.addSublayer(streak)
        }

        // 8. A soft bright band rolling down the screen (CRT shimmer).
        let band = CAGradientLayer()
        band.frame = CGRect(x: 0, y: -h * 0.12, width: w, height: h * 0.12)
        band.colors = [cg(B.teal.opacity(0)), cg(B.teal.opacity(0.04)), cg(B.teal.opacity(0))]
        let roll = CABasicAnimation(keyPath: "position.y")
        roll.fromValue = -h * 0.12; roll.toValue = h * 1.12; roll.duration = 14; roll.repeatCount = .infinity
        band.add(roll, forKey: "roll")
        root.addSublayer(band)
    }

    private func pulse(_ key: String, from: Double, to: Double, dur: Double) -> CABasicAnimation {
        let a = CABasicAnimation(keyPath: key)
        a.fromValue = from; a.toValue = to; a.duration = dur; a.autoreverses = true; a.repeatCount = .infinity
        a.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
        return a
    }
}
