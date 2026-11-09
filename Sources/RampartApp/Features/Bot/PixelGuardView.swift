import SwiftUI

extension PixelRGBA {
    var swiftUI: Color { Color(.sRGB, red: r, green: g, blue: b, opacity: a) }
}

private func fill(_ boxes: [PixelDraw], in ctx: inout GraphicsContext) {
    for b in boxes {
        let path = b.radius > 0 ? Path(roundedRect: b.rect, cornerRadius: min(b.radius, b.rect.width / 2), style: .continuous) : Path(b.rect)
        ctx.fill(path, with: .color(b.color.swiftUI))
    }
}

/// The RamPart logo: the Pixel Guard's head, optionally on its dark app tile. Pixel-snapped to the display scale.
/// `scatter` (0…1) pushes the boxes apart (splash assembly); `scanLine` (0…1, nil = none) runs one visor scan.
struct PixelGuardView: View {
    var size: CGFloat
    var expression: PixelGuard.Expression = .neutral
    var tile: Bool = true
    var scatter: CGFloat = 0
    var scanLine: CGFloat? = nil
    var variant: PixelGuard.Variant = PixelGuard.chosen
    @Environment(\.displayScale) private var displayScale

    var body: some View {
        Canvas(rendersAsynchronously: false) { ctx, sz in
            let scale = max(1, displayScale)
            let s = min(sz.width, sz.height)
            var tileRect = CGRect(x: (sz.width - s) / 2, y: (sz.height - s) / 2, width: s, height: s)
            if tile {
                // Same proportions as the icon generator's 824/1024 tile, filling the frame.
                let path = Path(roundedRect: tileRect, cornerRadius: s * 0.225, style: .continuous)
                ctx.fill(path, with: .linearGradient(Gradient(colors: [PixelGuard.Palette.tileTop.swiftUI, PixelGuard.Palette.tileBottom.swiftUI]),
                                                     startPoint: CGPoint(x: tileRect.midX, y: tileRect.minY), endPoint: CGPoint(x: tileRect.midX, y: tileRect.maxY)))
                ctx.stroke(Path(roundedRect: tileRect.insetBy(dx: 0.5, dy: 0.5), cornerRadius: s * 0.22, style: .continuous), with: .color(.white.opacity(0.08)), lineWidth: 1)
                tileRect = tileRect.insetBy(dx: s * 0.11, dy: s * 0.11)
            }
            let rows = CGFloat(PixelGuard.head(variant).count)
            let cols = CGFloat(PixelGuard.cols)
            // Whole device pixels per box keeps it crisp.
            let pitch = max(1, (tileRect.width * scale / cols).rounded(.down)) / scale
            let origin = CGPoint(x: ((tileRect.midX - pitch * cols / 2) * scale).rounded() / scale,
                                 y: ((tileRect.midY - pitch * rows / 2) * scale).rounded() / scale)
            var cells = PixelGuard.cells(variant, expression: expression)
            if scatter > 0 {
                for i in cells.indices {
                    let h = BotAnimator.hash(cells[i].x, cells[i].y)
                    cells[i].dx = (Double(h % 17) - 8) * 0.9 * Double(scatter)
                    cells[i].dy = (Double((h / 17) % 13) - 6) * 0.9 * Double(scatter)
                    cells[i].alpha = 1 - 0.6 * Double(scatter)
                }
            }
            if let p = scanLine, p > 0, p < 1 {
                let f = PixelGuard.face(variant)
                let ys = Array(f.screenY)
                let ry = ys[min(ys.count - 1, Int(Double(p) * Double(ys.count)))]
                for x in f.screenX { cells.append(.init(x: x, y: ry, key: "e", color: PixelGuard.Palette.scanLine)) }
            }
            let boxes = PixelRenderer.layout(cells, cell: pitch, origin: origin, mood: PixelGuard.mood(for: expression), pixelScale: scale)
            fill(boxes, in: &ctx)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

/// The full floating robot (head + boxy body), animated from pixel boxes.
/// Runs at most 30 fps, only while visible and not paused; Reduce Motion shows a static pose for the state.
struct PixelBotView: View {
    var state: BotState
    var stateStarted: Date
    var cell: CGFloat = 4
    var paused = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.displayScale) private var displayScale

    static func size(cell: CGFloat) -> CGSize {
        let rows = PixelGuard.head(PixelGuard.chosen).count + PixelGuard.body.count + BotAnimator.padTop + BotAnimator.padBottom
        return CGSize(width: CGFloat(PixelGuard.cols + 2 * BotAnimator.padX) * cell, height: CGFloat(rows) * cell)
    }

    /// Idle only needs blinks and the occasional visor scan: 12 fps is plenty. Busy states use 30.
    private var interval: Double {
        switch state {
        case .idle, .sleeping: return 1.0 / 12
        default: return 1.0 / 30
        }
    }

    var body: some View {
        TimelineView(.animation(minimumInterval: interval, paused: paused || reduceMotion)) { tl in
            let now = tl.date
            Canvas(rendersAsynchronously: false) { ctx, _ in
                let scale = max(1, displayScale)
                let t = now.timeIntervalSince(stateStarted)
                let clock = now.timeIntervalSinceReferenceDate
                let f = BotAnimator.frame(state, t: reduceMotion ? 10 : t, clock: reduceMotion ? 0 : clock, reduceMotion: reduceMotion)
                let pitch = max(1, (cell * scale).rounded()) / scale
                let origin = CGPoint(x: CGFloat(BotAnimator.padX) * pitch, y: CGFloat(BotAnimator.padTop) * pitch)
                let base = Self.baseCells
                var boxes = PixelRenderer.layout(f.cells, cell: pitch, origin: origin, mood: f.mood, pixelScale: scale, plate: true, plateCells: base)
                if f.plateAlpha < 1 {
                    for i in boxes.indices where boxes[i].color == PixelGuard.Palette.plate { boxes[i].color = boxes[i].color.with(alpha: f.plateAlpha) }
                }
                fill(boxes, in: &ctx)
            }
        }
        .frame(width: Self.size(cell: cell).width, height: Self.size(cell: cell).height)
    }

    private static let baseCells = Set(PixelGuard.cells(PixelGuard.chosen, body: true).map { GridPoint(x: $0.x, y: $0.y) })
}
