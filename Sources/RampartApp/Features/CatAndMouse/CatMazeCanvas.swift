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
    /// A perfect maze (recursive backtracker, fixed seed): walls[r][c] bit 1 = right wall, bit 2 = bottom wall.
    /// `path` is the depth-first tour of that maze, so every step moves between two cells through an opening:
    /// the cat and mouse never pass through a wall.
    static let maze: (walls: [[UInt8]], path: [(Int, Int)]) = {
        var walls = Array(repeating: Array(repeating: UInt8(3), count: cols), count: rows)
        var seen = Array(repeating: Array(repeating: false, count: cols), count: rows)
        var s: UInt64 = 0xCA7
        func rnd(_ n: Int) -> Int { s = s &* 6364136223846793005 &+ 1442695040888963407; return Int((s >> 33) % UInt64(n)) }
        var stack = [(0, 0)], tour = [(0, 0)]
        seen[0][0] = true
        while let top = stack.last {
            let (c, r) = top
            var next: [(Int, Int)] = []
            for (dc, dr) in [(1, 0), (-1, 0), (0, 1), (0, -1)] {
                let nc = c + dc, nr = r + dr
                if nc >= 0, nc < cols, nr >= 0, nr < rows, !seen[nr][nc] { next.append((nc, nr)) }
            }
            if next.isEmpty {
                stack.removeLast()
                if let back = stack.last { tour.append(back) }   // walk back through the same opening
                continue
            }
            let (nc, nr) = next[rnd(next.count)]
            if nc > c { walls[r][c] &= ~1 } else if nc < c { walls[nr][nc] &= ~1 }
            else if nr > r { walls[r][c] &= ~2 } else { walls[nr][nc] &= ~2 }
            seen[nr][nc] = true
            stack.append((nc, nr)); tour.append((nc, nr))
        }
        if tour.count > 1, tour.last! == tour.first! { tour.removeLast() }   // the tour ends back at the start: loop seamlessly
        return (walls, tour)
    }()
    static var walls: [[UInt8]] { maze.walls }
    static var path: [(Int, Int)] { maze.path }

    /// True if two cells are neighbours with no wall between them (used by the selftest-style check below).
    static func open(_ a: (Int, Int), _ b: (Int, Int)) -> Bool {
        let dc = b.0 - a.0, dr = b.1 - a.1
        guard abs(dc) + abs(dr) == 1 else { return false }
        if dc == 1 { return walls[a.1][a.0] & 1 == 0 }
        if dc == -1 { return walls[b.1][b.0] & 1 == 0 }
        if dr == 1 { return walls[a.1][a.0] & 2 == 0 }
        return walls[b.1][b.0] & 2 == 0
    }

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
        let speed = 2.2
        let mouse = caught ? center(path[path.count / 2]) : along(t * speed)
        let cat = caught ? center(path[path.count / 2 - 1]) : along(t * speed - 3)
        let font = Font.system(size: min(cw, ch) * 0.62)
        ctx.draw(Text("🐭").font(font), at: mouse)
        ctx.draw(Text("🐱").font(font), at: cat)
        if caught {
            ctx.stroke(Path(ellipseIn: CGRect(x: mouse.x - cw * 0.45, y: mouse.y - ch * 0.45, width: cw * 0.9, height: ch * 0.9)),
                       with: .color(.red.opacity(0.6)), lineWidth: 2)
        }
    }
}
