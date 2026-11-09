import Foundation
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers

// RamPart Pixel Guard asset generator. Offscreen only (CoreGraphics bitmaps, no windows).
// Build + run through generate-guard.sh, which compiles this with the single source of truth:
// Sources/RampartApp/Features/Bot/PixelGuard.swift and BotLogic.swift.
//   generate-guard.sh                → writes the shipped assets into Resources/Brand
//   generate-guard.sh --previews DIR → variant sheets and bot pose sheets into DIR (nothing shipped changes)

@main
struct GenerateGuard {
    static let cs = CGColorSpace(name: CGColorSpace.sRGB)!

    static func context(_ w: Int, _ h: Int) -> CGContext {
        let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: cs,
                            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
        ctx.translateBy(x: 0, y: CGFloat(h)); ctx.scaleBy(x: 1, y: -1)   // y-down like the renderer
        ctx.interpolationQuality = .none
        ctx.setShouldAntialias(true)
        return ctx
    }

    static func save(_ ctx: CGContext, _ path: String) {
        let url = URL(fileURLWithPath: path)
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        let dest = CGImageDestinationCreateWithURL(url as CFURL, UTType.png.identifier as CFString, 1, nil)!
        CGImageDestinationAddImage(dest, ctx.makeImage()!, nil)
        CGImageDestinationFinalize(dest)
    }

    static func icon(_ px: Int, _ v: PixelGuard.Variant) -> CGContext {
        let ctx = context(px, px)
        PixelRenderer.drawIcon(in: ctx, px: px, variant: v)
        return ctx
    }

    static func main() {
        let args = CommandLine.arguments
        let brand = URL(fileURLWithPath: #filePath).deletingLastPathComponent().path
        if let i = args.firstIndex(of: "--previews"), i + 1 < args.count {
            previews(args[i + 1]); return
        }
        // App icon set (all sizes) + master + menu bar template.
        let iconset = brand + "/AppIcon.iconset"
        try? FileManager.default.removeItem(atPath: iconset)
        for base in [16, 32, 128, 256, 512] {
            save(icon(base, PixelGuard.chosen), "\(iconset)/icon_\(base)x\(base).png")
            save(icon(base * 2, PixelGuard.chosen), "\(iconset)/icon_\(base)x\(base)@2x.png")
        }
        save(icon(1024, PixelGuard.chosen), brand + "/logo-mark-1024.png")
        for (px, name) in [(18, "MenuBarIconTemplate.png"), (36, "MenuBarIconTemplate@2x.png")] {
            let ctx = context(px, px)
            PixelRenderer.drawTemplate(in: ctx, px: px)
            save(ctx, brand + "/" + name)
        }
        for px in [16, 32, 64, 128, 256] { save(icon(px, PixelGuard.chosen), brand + "/previews/icon-\(px).png") }
        print("wrote iconset, logo-mark-1024.png, MenuBarIconTemplate(@2x).png")
    }

    /// Variant sheets (each at 1024, 128, 32, 16 and the menu bar template) and the bot pose sheet.
    static func previews(_ dir: String) {
        for v in PixelGuard.Variant.allCases {
            let w = 1024 + 40 + 256 + 40 + 128, h = 1024
            let ctx = context(w, h)
            ctx.setFillColor(PixelRGBA(0xECEFF3).cgColor); ctx.fill(CGRect(x: 0, y: 0, width: w, height: h))
            PixelRenderer.drawIcon(in: ctx, px: 1024, variant: v)
            var y: CGFloat = 40
            for px in [256, 128, 64, 32, 16] {
                ctx.saveGState(); ctx.translateBy(x: 1064, y: y)
                PixelRenderer.drawIcon(in: ctx, px: px, variant: v); ctx.restoreGState()
                y += CGFloat(px) + 24
            }
            // Menu bar templates on a light and a dark strip.
            for (i, bg) in [PixelRGBA(0xF6F6F6), PixelRGBA(0x1E1E1E)].enumerated() {
                let ox: CGFloat = 1360, oy: CGFloat = 40 + CGFloat(i) * 120
                ctx.setFillColor(bg.cgColor); ctx.fill(CGRect(x: ox, y: oy, width: 100, height: 100))
                let t = context(36, 36); PixelRenderer.drawTemplate(in: t, px: 36, variant: v)
                let t1 = context(18, 18); PixelRenderer.drawTemplate(in: t1, px: 18, variant: v)
                for (img, at, s) in [(t.makeImage()!, CGPoint(x: ox + 10, y: oy + 10), 36), (t1.makeImage()!, CGPoint(x: ox + 60, y: oy + 60), 18)] {
                    ctx.saveGState()
                    let r = CGRect(x: at.x, y: at.y, width: CGFloat(s), height: CGFloat(s))
                    ctx.translateBy(x: 0, y: r.minY * 2 + r.height); ctx.scaleBy(x: 1, y: -1)
                    ctx.clip(to: r, mask: img)
                    ctx.setFillColor((i == 0 ? PixelRGBA(0x000000, 0.85) : PixelRGBA(0xFFFFFF, 0.9)).cgColor); ctx.fill(r)
                    ctx.restoreGState()
                }
            }
            save(ctx, "\(dir)/variant-\(v.rawValue + 1)-\(v.name.replacingOccurrences(of: " ", with: "-").lowercased()).png")
        }
        // Bot poses (full robot, 8 px per box) on light and dark desktops.
        let states: [(BotState, Double)] = [(.idle, 1), (.scanning, 0.4), (.alert, 0.1), (.celebrating, 0.55), (.sleeping, 0.8),
                                            (.happy, 0.5), (.thinking, 0.3), (.talking, 0.2), (.assembling, 0.45)]
        let pitch: CGFloat = 8
        let rows = PixelGuard.head(PixelGuard.chosen).count + PixelGuard.body.count
        let cw = CGFloat(PixelGuard.cols + 2 * BotAnimator.padX) * pitch
        let ch = CGFloat(rows + BotAnimator.padTop + BotAnimator.padBottom) * pitch
        let ctx = context(Int(cw) * states.count, Int(ch) * 2)
        for (row, bg) in [PixelRGBA(0xE9EEF4), PixelRGBA(0x1B1F27)].enumerated() {
            ctx.setFillColor(bg.cgColor); ctx.fill(CGRect(x: 0, y: CGFloat(row) * ch, width: cw * CGFloat(states.count), height: ch))
            for (i, (s, t)) in states.enumerated() {
                let f = BotAnimator.frame(s, t: t, clock: t + 0.2, reduceMotion: false)
                let origin = CGPoint(x: CGFloat(i) * cw + CGFloat(BotAnimator.padX) * pitch, y: CGFloat(row) * ch + CGFloat(BotAnimator.padTop) * pitch)
                let base = Set(PixelGuard.cells(PixelGuard.chosen, body: true).map { GridPoint(x: $0.x, y: $0.y) })
                var boxes = PixelRenderer.layout(f.cells, cell: pitch, origin: origin, mood: f.mood, plate: true, plateCells: base)
                for j in boxes.indices where boxes[j].color == PixelGuard.Palette.plate { boxes[j].color = boxes[j].color.with(alpha: f.plateAlpha) }
                PixelRenderer.draw(boxes, in: ctx)
            }
        }
        save(ctx, "\(dir)/bot-poses.png")
        print("wrote previews to \(dir)")
    }
}
