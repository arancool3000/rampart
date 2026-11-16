import Foundation
import CoreGraphics

// RamPart "Pixel Guard": the single source of truth for the brand mark and the floating bot.
// The logo is the guard's HEAD; the floating bot is the head plus a small boxy body. Everything is drawn as
// pixel boxes (slightly rounded squares with a small gap), pixel-snapped, no blur.
// Foundation + CoreGraphics only: the selftest (symlink) and Resources/Brand/generate-guard.swift compile this file
// directly. SwiftUI views live in PixelGuardView.swift.

/// An sRGB colour (0…1).
struct PixelRGBA: Equatable {
    var r: Double, g: Double, b: Double, a: Double = 1
    init(_ hex: UInt32, _ a: Double = 1) {
        r = Double((hex >> 16) & 0xFF) / 255; g = Double((hex >> 8) & 0xFF) / 255; b = Double(hex & 0xFF) / 255; self.a = a
    }
    init(r: Double, g: Double, b: Double, a: Double = 1) { self.r = r; self.g = g; self.b = b; self.a = a }
    var cgColor: CGColor { CGColor(srgbRed: r, green: g, blue: b, alpha: a) }
    func with(alpha: Double) -> PixelRGBA { PixelRGBA(r: r, g: g, b: b, a: a * alpha) }
}

enum PixelGuard {
    static let cols = 16

    /// Three head designs explored; `chosen` is the shipped mark.
    enum Variant: Int, CaseIterable {
        case capGuard, visorSentinel, beaconBot, cyberSentinel
        var name: String { ["Cap Guard", "Visor Sentinel", "Beacon Bot", "Cyber Sentinel"][rawValue] }
    }
    /// The user found the friendly Cap Guard too cute: the shipped mark is the armoured Cyber Sentinel.
    static let chosen: Variant = .cyberSentinel

    // Keys: L beacon light · s antenna stalk · C cap/helmet · G gold shield badge · B brim · H head shell ·
    // E ear guard · S face screen · T uniform · A arm · h glove · K belt · P leg · F boot. "." is empty.
    static func head(_ v: Variant) -> [String] {
        switch v {
        case .capGuard: return [
            ".......LL.......",
            ".......LL.......",
            ".......ss.......",
            "....CCCCCCCC....",
            "...CCCGGGGCCC...",
            "..CCCCCGGCCCCC..",
            ".BBBBBBBBBBBBBB.",
            "..HHHHHHHHHHHH..",
            ".EHSSSSSSSSSSHE.",
            "EEHSSSSSSSSSSHEE",
            "EEHSSSSSSSSSSHEE",
            ".EHSSSSSSSSSSHE.",
            "..HHHHHHHHHHHH..",
            "...HHHHHHHHHH...",
        ]
        case .visorSentinel: return [
            ".......LL.......",
            "......CCCC......",
            "....HHCCCCHH....",
            "...HHHHHHHHHH...",
            "..HHHHHGGHHHHH..",
            "..HHHHHHHHHHHH..",
            "EEHSSSSSSSSSSHEE",
            "EEHSSSSSSSSSSHEE",
            "EEHSSSSSSSSSSHEE",
            "..HHHHHHHHHHHH..",
            "..HHHHHHHHHHHH..",
            "...HHHHHHHHHH...",
            "....CCCCCCCC....",
        ]
        // Cyber Sentinel keys: X cyan armour edge/crest · D gunmetal armour · d dark vents · R red sensor.
        case .cyberSentinel: return [
            "......XRRX......",
            ".......XX.......",
            "....DDDXXDDD....",
            "...DDDDDDDDDD...",
            "..DDDDDGGDDDDD..",
            ".XDDDDDDDDDDDDX.",
            "EXSSSSSSSSSSSSXE",
            "EXSSSSSSSSSSSSXE",
            "EXSSSSSSSSSSSSXE",
            "EXSSSSSSSSSSSSXE",
            "EXVVVVVVVVVVVVXE",
            ".XDDDDDDDDDDDDX.",
            ".DDdDdDDDDdDdDD.",
            "..DDdDdDDdDdDD..",
            "...DDDDDDDDDD...",
            "....dddddddd....",
        ]
        case .beaconBot: return [
            ".....LLLLLL.....",
            "....BBBBBBBB....",
            "..HHHHHHHHHHHH..",
            ".HHHHHHHHHHHHHH.",
            ".HSSSSSSSSSSSSH.",
            "EHSSSSSSSSSSSSHE",
            "EHSSSSSSSSSSSSHE",
            "EHSSSSSSSSSSSSHE",
            ".HSSSSSSSSSSSSH.",
            ".HHHHHHHHHHHHHH.",
            ".HHHHHGGGGHHHHH.",
            "..HHHHHGGHHHHH..",
            "...HHHHHHHHHH...",
        ]
        }
    }

    /// The boxy body under the head (floating bot only).
    static var body: [String] { chosen == .cyberSentinel ? cyberBody : guardBody }

    /// Armoured torso with cyan-edged pauldrons and a red core light.
    static let cyberBody: [String] = [
        "....dDDDDDDd....",
        "..XXDDDGGDDDXX..",
        ".aaXDDDDDDDDXaa.",
        ".aa.DDDRRDDD.aa.",
        ".aa.DDDDDDDD.aa.",
        ".hh.dddddddd.hh.",
        "....DDD..DDD....",
        "...FFFF..FFFF...",
    ]

    static let guardBody: [String] = [
        ".....TTTTTT.....",
        "...TTTTTTTTTT...",
        ".AATTTGGGGTTTAA.",
        ".AATTTTGGTTTTAA.",
        ".AATTTTTTTTTTAA.",
        ".hh.KKKGGKKK.hh.",
        "....PPP..PPP....",
        "...FFFF..FFFF...",
    ]

    /// Where the face lives on each head (grid coordinates, y down).
    struct Face {
        var eyeL: (x: Int, y: Int), eyeR: (x: Int, y: Int)
        var eyeW: Int, eyeH: Int
        var screenX: ClosedRange<Int>, screenY: ClosedRange<Int>
        var mouthY: Int?
        var blush: [(x: Int, y: Int)]
    }
    static func face(_ v: Variant) -> Face {
        switch v {
        case .capGuard: return Face(eyeL: (4, 9), eyeR: (10, 9), eyeW: 2, eyeH: 2, screenX: 3...12, screenY: 8...11, mouthY: 11, blush: [(3, 11), (12, 11)])
        case .visorSentinel: return Face(eyeL: (4, 7), eyeR: (9, 7), eyeW: 3, eyeH: 1, screenX: 3...12, screenY: 6...8, mouthY: nil, blush: [])
        case .cyberSentinel: return Face(eyeL: (4, 7), eyeR: (10, 7), eyeW: 2, eyeH: 2, screenX: 2...13, screenY: 6...9, mouthY: 9, blush: [(3, 9), (12, 9)])
        case .beaconBot: return Face(eyeL: (4, 5), eyeR: (10, 5), eyeW: 2, eyeH: 2, screenX: 2...13, screenY: 4...8, mouthY: 8, blush: [(3, 8), (12, 8)])
        }
    }

    enum Expression: Equatable {
        case neutral, blink, happy, alert, sleeping, thinking, listening
        case talking(Int), scanning(Int), typing(Int)
    }

    /// Colour mood: beacon and eyes follow it.
    enum Mood { case calm, scanning, alert, asleep, celebrate }

    struct Cell: Equatable {
        var x: Int, y: Int
        var key: Character
        var dx = 0.0, dy = 0.0, alpha = 1.0, scale = 1.0
        var color: PixelRGBA? = nil     // explicit colour (eyes, particles); otherwise from the palette
    }

    // MARK: Palette (two-tone: the right half of the shell, cap and uniform is a shade darker)

    enum Palette {
        static let tileTop = PixelRGBA(0x172131), tileBottom = PixelRGBA(0x080D17)
        static let plate = PixelRGBA(0x0A111D)              // dark plate behind the floating bot (reads on any desktop)
        static let screen = PixelRGBA(0x0A1522), screenAlert = PixelRGBA(0x2A0C12)
        static let eye = PixelRGBA(0x63F2CF), eyeAlert = PixelRGBA(0xFF5A5F), eyeDim = PixelRGBA(0x2E7C6E)
        static let blush = PixelRGBA(0xF27C9C, 0.85)
        static let scanLine = PixelRGBA(0x63F2CF, 0.22)
        static let gold = PixelRGBA(0xFFC53D), goldShade = PixelRGBA(0xE5A626)
        static let beaconCalm = PixelRGBA(0x63F2CF), beaconScan = PixelRGBA(0xFFC53D), beaconAlert = PixelRGBA(0xFF4D57), beaconOff = PixelRGBA(0x4A5568)

        static func color(_ key: Character, rightHalf: Bool, mood: Mood = .calm) -> PixelRGBA {
            switch key {
            case "L":
                switch mood {
                case .calm, .celebrate: return beaconCalm
                case .scanning: return beaconScan
                case .alert: return beaconAlert
                case .asleep: return beaconOff
                }
            case "s", "E", "P", "h": return rightHalf ? PixelRGBA(0x7A889C) : PixelRGBA(0x95A3B6)
            case "C", "T": return rightHalf ? PixelRGBA(0x1696A8) : PixelRGBA(0x1FB4C8)
            case "B", "K": return rightHalf ? PixelRGBA(0x0B5866) : PixelRGBA(0x0E6876)
            case "G": return rightHalf ? goldShade : gold
            case "H", "A": return rightHalf ? PixelRGBA(0xD3DCE6) : PixelRGBA(0xF5F8FB)
            case "S": return mood == .alert ? screenAlert : screen
            case "F": return rightHalf ? PixelRGBA(0x2E3746) : PixelRGBA(0x3A4556)
            case "D": return rightHalf ? PixelRGBA(0x3A4558) : PixelRGBA(0x4B586E)
            case "V": return mood == .alert ? PixelRGBA(0xFF4D57, 0.55) : PixelRGBA(0x22D3EE, mood == .asleep ? 0.15 : 0.45)
            case "d": return rightHalf ? PixelRGBA(0x121822) : PixelRGBA(0x18202C)
            case "X": return rightHalf ? PixelRGBA(0x14A8C0) : PixelRGBA(0x22D3EE)
            case "R": return mood == .asleep ? PixelRGBA(0x5A2A30) : PixelRGBA(0xFF3B4E)
            case "a": return rightHalf ? PixelRGBA(0x2E3746) : PixelRGBA(0x3A4556)
            default: return PixelRGBA(0xFF00FF)
            }
        }
    }

    // MARK: Matrix helpers

    static func matrix(_ v: Variant, body withBody: Bool) -> [String] { withBody ? head(v) + body : head(v) }

    /// Static cells for a pose: the matrix plus the face drawn for `expression`.
    static func cells(_ v: Variant = chosen, expression: Expression = .neutral, body withBody: Bool = false) -> [Cell] {
        let m = matrix(v, body: withBody)
        var out: [Cell] = []
        for (y, row) in m.enumerated() {
            for (x, ch) in row.enumerated() where ch != "." { out.append(Cell(x: x, y: y, key: ch)) }
        }
        out += faceCells(v, expression)
        return out
    }

    static func mood(for e: Expression) -> Mood {
        switch e {
        case .alert: return .alert
        case .sleeping: return .asleep
        case .scanning: return .scanning
        case .happy: return .celebrate
        default: return .calm
        }
    }

    /// Eyes, blush, mouth and scan line drawn over the screen (key "e").
    static func faceCells(_ v: Variant, _ e: Expression) -> [Cell] {
        let f = face(v)
        var out: [Cell] = []
        func lit(_ x: Int, _ y: Int, _ c: PixelRGBA) {
            guard f.screenX.contains(x), f.screenY.contains(y) else { return }
            out.append(Cell(x: x, y: y, key: "e", color: c))
        }
        func eyes(dx: Int = 0, dy: Int = 0, h: Int? = nil, rowOffset: Int = 0, _ c: PixelRGBA = Palette.eye) {
            for eye in [f.eyeL, f.eyeR] {
                for i in 0..<f.eyeW { for j in 0..<(h ?? f.eyeH) { lit(eye.x + i + dx, eye.y + j + dy + rowOffset, c) } }
            }
        }
        func blush() { for b in f.blush { lit(b.x, b.y, Palette.blush) } }
        let bottom = f.eyeH - 1
        switch e {
        case .neutral: eyes(); blush()
        case .blink: eyes(h: 1, rowOffset: bottom); blush()
        case .listening:
            eyes(); blush()
            if let my = f.mouthY { lit(7, my, Palette.eye.with(alpha: 0.7)); lit(8, my, Palette.eye.with(alpha: 0.7)) }
        case .happy:
            // ^ ^ : a raised middle with the outer corners one row lower.
            for eye in [f.eyeL, f.eyeR] {
                for i in 0..<f.eyeW { lit(eye.x + i, eye.y, Palette.eye) }
                lit(eye.x - 1, eye.y + 1, Palette.eye); lit(eye.x + f.eyeW, eye.y + 1, Palette.eye)
            }
            blush()
        case .alert:
            // Narrowed, slanted red eyes ("angry brows" in pixels).
            let r = Palette.eyeAlert
            for i in 0..<f.eyeW { lit(f.eyeL.x + i, f.eyeL.y + bottom, r); lit(f.eyeR.x + i, f.eyeR.y + bottom, r) }
            if f.eyeH > 1 { lit(f.eyeL.x + f.eyeW - 1, f.eyeL.y, r); lit(f.eyeR.x, f.eyeR.y, r) }
        case .sleeping:
            for i in 0..<f.eyeW { lit(f.eyeL.x + i, f.eyeL.y + bottom, Palette.eyeDim); lit(f.eyeR.x + i, f.eyeR.y + bottom, Palette.eyeDim) }
        case .thinking:
            eyes(dx: 1, dy: -1); blush()
        case .talking(let phase):
            eyes(); blush()
            if let my = f.mouthY {
                let wide = phase % 2 == 0
                for x in (wide ? 6...9 : 7...8) { lit(x, my, Palette.eye.with(alpha: 0.85)) }
            }
        case .typing(let phase):
            eyes(dx: phase % 4 < 2 ? 0 : 1, dy: -1); blush()
            if let my = f.mouthY {
                for (i, x) in [6, 8, 10].enumerated() where f.screenX.contains(x) {
                    lit(x - 1, my, Palette.eye.with(alpha: i == phase % 3 ? 1 : 0.3))
                }
            }
        case .scanning(let phase):
            // Eyes sweep left/right; a dim scan line runs down the screen.
            let sweep = [0, 1, 1, 0, -1, -1][abs(phase) % 6]
            eyes(dx: sweep)
            let rows = Array(f.screenY)
            let ry = rows[abs(phase) % rows.count]
            for x in f.screenX where !out.contains(where: { $0.x == x && $0.y == ry }) { lit(x, ry, Palette.scanLine) }
        }
        return out
    }

    /// Filled grid positions of a matrix.
    static func filled(_ m: [String]) -> Set<GridPoint> {
        var s = Set<GridPoint>()
        for (y, row) in m.enumerated() { for (x, ch) in row.enumerated() where ch != "." { s.insert(GridPoint(x: x, y: y)) } }
        return s
    }

    /// True when every row mirrors around the vertical centre line (shape, not colour shade).
    static func isSymmetric(_ m: [String]) -> Bool {
        m.allSatisfy { String($0.reversed()) == $0 }
    }
}

struct GridPoint: Hashable { var x: Int, y: Int }

/// One box to draw (y down, points or pixels depending on the caller).
struct PixelDraw {
    var rect: CGRect
    var radius: CGFloat
    var color: PixelRGBA
}

/// Turns cells into pixel-snapped boxes. Shared by the SwiftUI canvas and the CoreGraphics icon generator.
enum PixelRenderer {
    /// - Parameters:
    ///   - cell: box pitch in device pixels (or points × scale). Whole numbers keep it crisp.
    ///   - origin: top-left of grid cell (0,0), y down.
    ///   - pixelScale: device pixels per unit, for snapping.
    ///   - plate: draw a dark silhouette plate (filled cells + 1 cell outline) behind the boxes.
    static func layout(_ cells: [PixelGuard.Cell], cell: CGFloat, origin: CGPoint, mood: PixelGuard.Mood = .calm,
                       pixelScale: CGFloat = 1, plate: Bool = false, plateCells: Set<GridPoint>? = nil,
                       monochrome: PixelRGBA? = nil) -> [PixelDraw] {
        func snap(_ v: CGFloat) -> CGFloat { (v * pixelScale).rounded() / pixelScale }
        let devicePitch = cell * pixelScale
        // Gaps and rounding appear only when a box is big enough to show them crisply.
        let gap: CGFloat = devicePitch >= 6 ? max(1, (devicePitch * 0.12).rounded()) / pixelScale : 0
        let radius: CGFloat = devicePitch >= 6 ? cell * 0.24 : 0
        var out: [PixelDraw] = []
        let half = CGFloat(PixelGuard.cols) / 2
        if plate {
            let base = plateCells ?? Set(cells.map { GridPoint(x: $0.x, y: $0.y) })
            var grown = base
            for p in base { for dx in -1...1 { for dy in -1...1 { grown.insert(GridPoint(x: p.x + dx, y: p.y + dy)) } } }
            for p in grown {
                let r = CGRect(x: snap(origin.x + CGFloat(p.x) * cell), y: snap(origin.y + CGFloat(p.y) * cell), width: snap(cell) + 0.02, height: snap(cell) + 0.02)
                out.append(PixelDraw(rect: r, radius: 0, color: PixelGuard.Palette.plate))
            }
        }
        // Base boxes first, face overlays ("e") on top.
        for c in cells.sorted(by: { ($0.key == "e" ? 1 : 0) < ($1.key == "e" ? 1 : 0) }) where c.alpha > 0.01 {
            var color = c.color ?? PixelGuard.Palette.color(c.key, rightHalf: CGFloat(c.x) >= half, mood: mood)
            if let m = monochrome { color = m }
            color = color.with(alpha: c.alpha)
            let size = (cell - gap) * CGFloat(c.scale)
            let cx = origin.x + (CGFloat(c.x) + 0.5 + CGFloat(c.dx)) * cell
            let cy = origin.y + (CGFloat(c.y) + 0.5 + CGFloat(c.dy)) * cell
            let s = max(1 / pixelScale, snap(size))
            let r = CGRect(x: snap(cx - s / 2), y: snap(cy - s / 2), width: s, height: s)
            out.append(PixelDraw(rect: r, radius: radius * CGFloat(c.scale), color: color))
        }
        return out
    }

    /// Draws boxes into a y-down CoreGraphics context (flip first for bitmap contexts).
    static func draw(_ boxes: [PixelDraw], in ctx: CGContext) {
        for b in boxes {
            ctx.setFillColor(b.color.cgColor)
            if b.radius > 0 {
                ctx.addPath(CGPath(roundedRect: b.rect, cornerWidth: min(b.radius, b.rect.width / 2), cornerHeight: min(b.radius, b.rect.height / 2), transform: nil))
                ctx.fillPath()
            } else {
                ctx.fill(b.rect)
            }
        }
    }

    /// The app tile: dark rounded square (continuous-ish corners), subtle top-to-bottom gradient. y-down rect.
    static func drawTile(in ctx: CGContext, rect: CGRect) {
        let path = CGPath(roundedRect: rect, cornerWidth: rect.width * 0.225, cornerHeight: rect.width * 0.225, transform: nil)
        ctx.saveGState()
        ctx.addPath(path); ctx.clip()
        let cs = CGColorSpace(name: CGColorSpace.sRGB)!
        let g = CGGradient(colorsSpace: cs, colors: [PixelGuard.Palette.tileTop.cgColor, PixelGuard.Palette.tileBottom.cgColor] as CFArray, locations: [0, 1])!
        ctx.drawLinearGradient(g, start: CGPoint(x: rect.midX, y: rect.minY), end: CGPoint(x: rect.midX, y: rect.maxY), options: [])
        // A hairline inner rim so the tile edge reads on dark backgrounds.
        ctx.addPath(CGPath(roundedRect: rect.insetBy(dx: rect.width * 0.004, dy: rect.width * 0.004), cornerWidth: rect.width * 0.22, cornerHeight: rect.width * 0.22, transform: nil))
        ctx.setStrokeColor(PixelRGBA(0xFFFFFF, 0.08).cgColor); ctx.setLineWidth(max(1, rect.width * 0.006)); ctx.strokePath()
        ctx.restoreGState()
    }

    /// Full app icon / logo tile at `px` pixels, drawn into a y-down context.
    /// Small sizes (≤ 32 px) go full-bleed so each box lands on whole pixels; larger ones use the macOS 824/1024 grid.
    static func drawIcon(in ctx: CGContext, px: Int, variant: PixelGuard.Variant = PixelGuard.chosen) {
        let size = CGFloat(px)
        let tile: CGRect = px <= 32 ? CGRect(x: 0, y: 0, width: size, height: size)
                                    : CGRect(x: size * 100 / 1024, y: size * 100 / 1024, width: size * 824 / 1024, height: size * 824 / 1024)
        drawTile(in: ctx, rect: tile)
        let m = PixelGuard.head(variant)
        let rows = CGFloat(m.count)
        let cols = CGFloat(PixelGuard.cols)
        let usable = px <= 32 ? tile.width : tile.width * 0.78
        let pitch = max(1, (usable / cols).rounded(.down))
        let w = pitch * cols, h = pitch * rows
        let origin = CGPoint(x: (tile.midX - w / 2).rounded(), y: (tile.midY - h / 2).rounded())
        draw(layout(PixelGuard.cells(variant), cell: pitch, origin: origin), in: ctx)
    }

    /// Monochrome menu bar template: shell in black, screen cut out, eyes black. y-down context, `px` square.
    static func drawTemplate(in ctx: CGContext, px: Int, variant: PixelGuard.Variant = PixelGuard.chosen) {
        let m = PixelGuard.head(variant)
        let pitch = max(1, (CGFloat(px) / CGFloat(PixelGuard.cols + 1)).rounded(.down))
        let w = pitch * CGFloat(PixelGuard.cols), h = pitch * CGFloat(m.count)
        let origin = CGPoint(x: ((CGFloat(px) - w) / 2).rounded(), y: ((CGFloat(px) - h) / 2).rounded())
        let black = PixelRGBA(0x000000)
        // Solid parts: everything except the screen and the badge (cut-outs keep the face and badge readable).
        let cells = PixelGuard.cells(variant).filter { $0.key != "S" && $0.key != "G" && $0.key != "e" }
        let eyes = PixelGuard.faceCells(variant, .neutral).filter { $0.color == PixelGuard.Palette.eye }
        draw(layout(cells + eyes, cell: pitch, origin: origin, monochrome: black), in: ctx)
    }
}
