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
        for k in 0..<(still ? 0 : 18) {   // horizontal lines, spaced by depth
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
        let still = ImageRenderer(content: Canvas { ctx, sz in B.draw(&ctx, sz, t: 0, still: true) }.frame(width: w, height: h))
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
            line.frame = CGRect(x: 0, y: 0, width: w, height: 1)
            line.backgroundColor = cg(B.cyan)
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
        let cell = (h * 0.42 / rows).rounded(.down)
        let gw = cell * CGFloat(PixelGuard.cols)
        let origin = CGPoint(x: ((w - gw) / 2).rounded(), y: (horizon - cell * rows * 0.92).rounded())
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
