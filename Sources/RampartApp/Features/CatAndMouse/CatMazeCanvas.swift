import SwiftUI

/// Animated cat-and-maze visual drawn with Canvas. Reduce Motion: a still frame (cat and mouse at rest).
/// Purely decorative; hidden from VoiceOver (the screen text says the same thing).
struct CatMazeCanvas: View {
    var deadEnds: Int
    var caught: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        Group {
            if reduceMotion {
                Canvas { ctx, size in Self.draw(ctx, size, t: 0, deadEnds: deadEnds, caught: caught) }
            } else {
                TimelineView(.animation(minimumInterval: 1.0 / 30)) { tl in
                    Canvas { ctx, size in
                        Self.draw(ctx, size, t: tl.date.timeIntervalSinceReferenceDate, deadEnds: deadEnds, caught: caught)
                    }
                }
            }
        }
        .frame(height: 160)
        .accessibilityHidden(true)
    }

    static let cols = 9, rows = 5
    /// Fixed maze walls (bitmask per cell: 1 = right wall, 2 = bottom wall), generated once from a seed.
    static let walls: [[UInt8]] = {
        var s: UInt64 = 0xCA7
        return (0..<rows).map { _ in (0..<cols).map { _ in s = s &* 6364136223846793005 &+ 1; return UInt8((s >> 40) % 4) } }
    }()
    /// A wandering path through cells for the mouse.
    static let path: [(Int, Int)] = [(0,0),(1,0),(2,0),(2,1),(3,1),(4,1),(4,2),(3,2),(3,3),(4,3),(5,3),(6,3),(6,2),(7,2),(7,1),(8,1),(8,2),(8,3),(7,3),(7,4),(6,4),(5,4),(4,4),(3,4),(2,4),(2,3),(1,3),(1,2),(0,2),(0,1)]

    static func draw(_ ctx: GraphicsContext, _ size: CGSize, t: Double, deadEnds: Int, caught: Bool) {
        let cw = size.width / CGFloat(cols), ch = size.height / CGFloat(rows)
        var wallPath = Path()
        for r in 0..<rows { for c in 0..<cols {
            let x = CGFloat(c) * cw, y = CGFloat(r) * ch
            if walls[r][c] & 1 != 0 { wallPath.move(to: CGPoint(x: x + cw, y: y)); wallPath.addLine(to: CGPoint(x: x + cw, y: y + ch)) }
            if walls[r][c] & 2 != 0 { wallPath.move(to: CGPoint(x: x, y: y + ch)); wallPath.addLine(to: CGPoint(x: x + cw, y: y + ch)) }
        } }
        wallPath.addRoundedRect(in: CGRect(origin: .zero, size: size).insetBy(dx: 1, dy: 1), cornerSize: CGSize(width: 8, height: 8))
        ctx.stroke(wallPath, with: .color(.secondary.opacity(0.45)), style: StrokeStyle(lineWidth: 2, lineCap: .round))

        // Dead-end markers: one small cross per dead end (capped at the cell count).
        let marks = min(deadEnds, cols * rows)
        for i in 0..<marks {
            let c = (i * 7) % cols, r = (i * 3) % rows
            let p = CGPoint(x: (CGFloat(c) + 0.8) * cw, y: (CGFloat(r) + 0.25) * ch)
            var x = Path(); x.move(to: CGPoint(x: p.x - 3, y: p.y - 3)); x.addLine(to: CGPoint(x: p.x + 3, y: p.y + 3))
            x.move(to: CGPoint(x: p.x + 3, y: p.y - 3)); x.addLine(to: CGPoint(x: p.x - 3, y: p.y + 3))
            ctx.stroke(x, with: .color(.orange.opacity(0.7)), lineWidth: 1.5)
        }

        func center(_ cell: (Int, Int)) -> CGPoint { CGPoint(x: (CGFloat(cell.0) + 0.5) * cw, y: (CGFloat(cell.1) + 0.5) * ch) }
        func along(_ phase: Double) -> CGPoint {
            let n = Double(path.count)
            let f = (phase.truncatingRemainder(dividingBy: n) + n).truncatingRemainder(dividingBy: n)
            let i = Int(f), j = (i + 1) % path.count, k = CGFloat(f - Double(i))
            let a = center(path[i]), b = center(path[j])
            return CGPoint(x: a.x + (b.x - a.x) * k, y: a.y + (b.y - a.y) * k)
        }
        let mouse = caught ? center(path[path.count / 2]) : along(t * 1.6)
        let cat = caught ? center(path[path.count / 2 - 1]) : along(t * 1.6 - 3.2)
        let font = Font.system(size: min(cw, ch) * 0.62)
        ctx.draw(Text("🐭").font(font), at: mouse)
        ctx.draw(Text("🐱").font(font), at: cat)
        if caught {
            ctx.stroke(Path(ellipseIn: CGRect(x: mouse.x - cw * 0.45, y: mouse.y - ch * 0.45, width: cw * 0.9, height: ch * 0.9)),
                       with: .color(.red.opacity(0.6)), lineWidth: 2)
        }
    }
}
