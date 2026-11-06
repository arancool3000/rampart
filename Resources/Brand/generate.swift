// RamPart brand asset generator.
// Run from anywhere:  swift Resources/Brand/generate.swift [outputDir]
// Default outputDir is the directory containing this script. Renders offscreen only (no windows).
//
// Source of truth for the mark is the SVG path data in `MarkGeometry` below (1024 x 1024 canvas,
// y-down, same as SVG). Everything else (PNGs, iconset, icns, menu-bar template, SVGs, animation.json,
// storyboard frames) is derived from it.

import AppKit
import CoreGraphics
import CoreText
import Foundation
import ImageIO
import UniformTypeIdentifiers

// MARK: - Output

let scriptDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
let outDir = CommandLine.arguments.count > 1 ? URL(fileURLWithPath: CommandLine.arguments[1]) : scriptDir
let fm = FileManager.default
try? fm.createDirectory(at: outDir, withIntermediateDirectories: true)
func url(_ name: String) -> URL { outDir.appendingPathComponent(name) }

// MARK: - Palette

struct RGB { let hex: UInt32; var alpha: CGFloat = 1
    var cg: CGColor { CGColor(srgbRed: CGFloat((hex >> 16) & 0xff) / 255, green: CGFloat((hex >> 8) & 0xff) / 255, blue: CGFloat(hex & 0xff) / 255, alpha: alpha) }
    var css: String { String(format: "#%06X", hex) }
    func a(_ v: CGFloat) -> RGB { RGB(hex: hex, alpha: v) }
}
enum Brand {
    static let navy = RGB(hex: 0x070D1C)        // Palette.navy
    static let midnight = RGB(hex: 0x0A2840)
    static let deepTeal = RGB(hex: 0x0F5466)
    static let teal = RGB(hex: 0x17B8CC)        // Palette.teal
    static let mint = RGB(hex: 0x54E6C2)        // Palette.mint
    static let accentLight = RGB(hex: 0x0A84A0) // rampartTeal, light appearance
    static let accentDark = RGB(hex: 0x40C8E0)  // rampartTeal, dark appearance
    static let ink = RGB(hex: 0x0B1B2E)         // wordmark on light
    static let frost = RGB(hex: 0xC4EEF4)       // bottom of the white mark gradient
    static let white = RGB(hex: 0xFFFFFF)
}

// MARK: - Mark geometry (hand-written SVG path data, 1024 canvas, y-down)
//
// The "Keep R": an R whose stem is a tower (it rises above the bowl and is crowned with a crenel,
// two merlons), whose bowl is a solid rampart block, and whose leg is a teal stride.
// The three pieces sit 22 units apart like dressed stones, which also gives the animation its parts.

enum MarkGeometry {
    // Body of the macOS icon grid: 824 x 824 at (100,100) on a 1024 canvas.
    static let tileRect = CGRect(x: 100, y: 100, width: 824, height: 824)
    static let stem = "M300 222H340V276H388V222H428V802H300Z"
    static let bowl = "M450 254H550A174 174 0 0 1 550 602H450V482H550A54 54 0 0 0 550 374H450Z"
    static let leg = "M508 624H640L734 802H580Z"
    /// Assembly order for animation (part-1 ... part-3); the tile is part-0.
    static let parts: [(id: String, name: String, d: String)] = [
        ("part-1", "stem (tower)", stem), ("part-2", "bowl (rampart block)", bowl), ("part-3", "leg (stride)", leg)]
    static let markBox = CGRect(x: 300, y: 222, width: 434, height: 580)
}

// MARK: - Minimal SVG path parser (M L H V Z, and A for semicircles only, which is all the mark uses)

func parseSVGPath(_ d: String) -> CGPath {
    var tokens: [String] = []; var cur = ""
    for ch in d {
        if ch.isLetter { if !cur.isEmpty { tokens.append(cur); cur = "" }; tokens.append(String(ch)) }
        else if ch == " " || ch == "," { if !cur.isEmpty { tokens.append(cur); cur = "" } }
        else if ch == "-" && !cur.isEmpty { tokens.append(cur); cur = "-" }
        else { cur.append(ch) }
    }
    if !cur.isEmpty { tokens.append(cur) }
    let p = CGMutablePath(); var i = 0; var pt = CGPoint.zero; var cmd = ""
    func num() -> CGFloat { defer { i += 1 }; return CGFloat(Double(tokens[i])!) }
    while i < tokens.count {
        if tokens[i].first!.isLetter { cmd = tokens[i]; i += 1 }
        switch cmd {
        case "M": pt = CGPoint(x: num(), y: num()); p.move(to: pt); cmd = "L"
        case "L": pt = CGPoint(x: num(), y: num()); p.addLine(to: pt)
        case "H": pt.x = num(); p.addLine(to: pt)
        case "V": pt.y = num(); p.addLine(to: pt)
        case "Z": p.closeSubpath()
        case "A":
            let r = num(); _ = num(); _ = num(); _ = num(); let sweep = num()
            let end = CGPoint(x: num(), y: num())
            let c = CGPoint(x: (pt.x + end.x) / 2, y: (pt.y + end.y) / 2)
            precondition(abs(hypot(end.x - pt.x, end.y - pt.y) - 2 * r) < 0.5, "only semicircle arcs supported")
            let a0 = atan2(pt.y - c.y, pt.x - c.x), a1 = atan2(end.y - c.y, end.x - c.x)
            // SVG sweep=1 is clockwise on screen (y-down) == increasing angle in y-down math.
            p.addArc(center: c, radius: r, startAngle: a0, endAngle: a1, clockwise: sweep == 0)
            pt = end
        default: fatalError("unsupported command \(cmd)")
        }
    }
    return p
}

func svgD(_ path: CGPath, transform t: CGAffineTransform = .identity) -> String {
    var s = ""
    func f(_ v: CGFloat) -> String { let r = (v * 10).rounded() / 10; return r == r.rounded() ? String(Int(r)) : String(format: "%.1f", r) }
    func p(_ q: CGPoint) -> String { let a = q.applying(t); return "\(f(a.x)) \(f(a.y))" }
    path.applyWithBlock { e in
        let el = e.pointee
        switch el.type {
        case .moveToPoint: s += "M" + p(el.points[0])
        case .addLineToPoint: s += "L" + p(el.points[0])
        case .addQuadCurveToPoint: s += "Q" + p(el.points[0]) + " " + p(el.points[1])
        case .addCurveToPoint: s += "C" + p(el.points[0]) + " " + p(el.points[1]) + " " + p(el.points[2])
        case .closeSubpath: s += "Z"
        @unknown default: break
        }
    }
    return s
}

// MARK: - Squircle (Apple-style continuous-corner superellipse)

func squircle(_ r: CGRect, n: CGFloat = 5, steps: Int = 720) -> CGPath {
    let p = CGMutablePath(); let a = r.width / 2, b = r.height / 2
    for i in 0..<steps {
        let t = CGFloat(i) / CGFloat(steps) * 2 * .pi; let c = cos(t), s = sin(t)
        let q = CGPoint(x: r.midX + a * (c < 0 ? -1 : 1) * pow(abs(c), 2 / n), y: r.midY + b * (s < 0 ? -1 : 1) * pow(abs(s), 2 / n))
        i == 0 ? p.move(to: q) : p.addLine(to: q)
    }
    p.closeSubpath(); return p
}
func squircleSVG(_ r: CGRect) -> String {
    // Same n=5 superellipse as the bitmap, sampled at 128 points (sub-unit error at 1024).
    svgD(squircle(r, steps: 128))
}

// MARK: - Bitmap helpers

func bitmap(_ w: Int, _ h: Int) -> CGContext {
    let ctx = CGContext(data: nil, width: w, height: h, bitsPerComponent: 8, bytesPerRow: 0, space: CGColorSpace(name: CGColorSpace.sRGB)!,
                        bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    // Flip to y-down so SVG coordinates can be used directly.
    ctx.translateBy(x: 0, y: CGFloat(h)); ctx.scaleBy(x: 1, y: -1)
    ctx.interpolationQuality = .high; ctx.setShouldAntialias(true)
    return ctx
}
func savePNG(_ ctx: CGContext, _ u: URL) {
    let d = CGImageDestinationCreateWithURL(u as CFURL, UTType.png.identifier as CFString, 1, nil)!
    CGImageDestinationAddImage(d, ctx.makeImage()!, nil); CGImageDestinationFinalize(d)
}
func gradient(_ cs: [RGB], _ locs: [CGFloat]? = nil) -> CGGradient {
    CGGradient(colorsSpace: CGColorSpace(name: CGColorSpace.sRGB), colors: cs.map(\.cg) as CFArray, locations: locs)!
}
/// Shadows are specified in y-down units; CG shadow offsets ignore the CTM flip, so negate y.
func shadow(_ ctx: CGContext, dy: CGFloat, blur: CGFloat, alpha: CGFloat, scale: CGFloat) {
    ctx.setShadow(offset: CGSize(width: 0, height: -dy * scale), blur: blur * scale, color: RGB(hex: 0, alpha: alpha).cg)
}

// MARK: - Icon drawing

struct PartState { var alpha: CGFloat = 1; var transform: CGAffineTransform = .identity }
struct IconState { var tile = PartState(); var parts = [PartState(), PartState(), PartState()]; var glow: CGFloat = 1 }

/// Draws the icon into a 1024-unit space. `px` is the final pixel size (for small-size tuning).
func drawIcon(_ ctx: CGContext, px: CGFloat, state: IconState = IconState(), tile: Bool = true) {
    let s = px / 1024
    let small = px <= 64
    let body = MarkGeometry.tileRect, sq = squircle(body)
    if tile && state.tile.alpha > 0 {
        ctx.saveGState(); ctx.setAlpha(state.tile.alpha); ctx.concatenate(state.tile.transform)
        // drop shadow under the tile (macOS grid: shadow lives in the 100-unit margin)
        ctx.saveGState(); shadow(ctx, dy: 10, blur: 22, alpha: small ? 0.25 : 0.32, scale: s)
        ctx.addPath(sq); ctx.setFillColor(Brand.navy.cg); ctx.fillPath(); ctx.restoreGState()
        ctx.saveGState(); ctx.addPath(sq); ctx.clip()
        ctx.drawLinearGradient(gradient([Brand.deepTeal, Brand.midnight, Brand.navy], [0, 0.55, 1]),
                               start: CGPoint(x: body.minX, y: body.minY), end: CGPoint(x: body.maxX, y: body.maxY), options: [])
        // soft teal glow behind the mark
        let gc = CGPoint(x: 512, y: 470)
        ctx.drawRadialGradient(gradient([Brand.teal.a(0.30 * state.glow), Brand.teal.a(0)]), startCenter: gc, startRadius: 0, endCenter: gc, endRadius: 470, options: [])
        // top sheen + hairline rim (depth without skeuomorphism)
        ctx.drawLinearGradient(gradient([Brand.white.a(0.10), Brand.white.a(0)]), start: CGPoint(x: 0, y: body.minY), end: CGPoint(x: 0, y: body.minY + 300), options: [])
        ctx.addPath(sq); ctx.setStrokeColor(Brand.white.a(0.16).cg); ctx.setLineWidth(small ? 0 : 4); ctx.strokePath()
        ctx.restoreGState()
        ctx.restoreGState()
    }
    let fills: [(RGB, RGB)] = [(Brand.white, Brand.frost), (Brand.white, Brand.frost), (Brand.mint, Brand.teal)]
    for (i, part) in MarkGeometry.parts.enumerated() {
        let st = state.parts[i]; if st.alpha <= 0 { continue }
        let path = parseSVGPath(part.d)
        ctx.saveGState(); ctx.setAlpha(st.alpha); ctx.concatenate(st.transform)
        ctx.saveGState(); shadow(ctx, dy: 8, blur: small ? 6 : 18, alpha: 0.38, scale: s)
        ctx.addPath(path); ctx.setFillColor(fills[i].0.cg); ctx.fillPath(); ctx.restoreGState()
        ctx.saveGState(); ctx.addPath(path); ctx.clip()
        ctx.drawLinearGradient(gradient([fills[i].0, fills[i].1]), start: CGPoint(x: 0, y: 222), end: CGPoint(x: 0, y: 802), options: [])
        ctx.restoreGState()
        ctx.restoreGState()
    }
}

func renderIconPNG(_ px: Int, to u: URL) {
    let ctx = bitmap(px, px); ctx.scaleBy(x: CGFloat(px) / 1024, y: CGFloat(px) / 1024)
    drawIcon(ctx, px: CGFloat(px)); savePNG(ctx, u)
}

// MARK: - Wordmark

let wordmark = "RamPart"
let wordFontSize: CGFloat = 200
let wordTracking: CGFloat = -0.025 // em
func wordFont(_ size: CGFloat) -> CTFont {
    let base = NSFont.systemFont(ofSize: size, weight: .bold)
    let rounded = base.fontDescriptor.withDesign(.rounded) ?? base.fontDescriptor
    return (NSFont(descriptor: rounded, size: size) ?? base) as CTFont
}
struct Letter { let ch: String; let id: String; let path: CGPath; let advanceX: CGFloat }
/// Glyph outlines in a y-down space whose baseline is y = 0.
func wordLetters() -> [Letter] {
    let font = wordFont(wordFontSize)
    let attr = NSAttributedString(string: wordmark, attributes: [
        NSAttributedString.Key(kCTFontAttributeName as String): font,
        NSAttributedString.Key(kCTKernAttributeName as String): wordTracking * wordFontSize])
    let line = CTLineCreateWithAttributedString(attr)
    var out: [Letter] = []; var seen: [String: Int] = [:]
    for run in CTLineGetGlyphRuns(line) as! [CTRun] {
        let n = CTRunGetGlyphCount(run)
        var g = [CGGlyph](repeating: 0, count: n), pos = [CGPoint](repeating: .zero, count: n), idx = [CFIndex](repeating: 0, count: n)
        CTRunGetGlyphs(run, CFRange(location: 0, length: n), &g); CTRunGetPositions(run, CFRange(location: 0, length: n), &pos)
        CTRunGetStringIndices(run, CFRange(location: 0, length: n), &idx)
        for k in 0..<n {
            let ch = String(Array(wordmark)[idx[k]])
            seen[ch, default: 0] += 1
            let id = seen[ch]! == 1 ? "letter-\(ch)" : "letter-\(ch)-\(seen[ch]!)"
            var t = CGAffineTransform(a: 1, b: 0, c: 0, d: -1, tx: pos[k].x, ty: 0) // flip to y-down
            let gp = CTFontCreatePathForGlyph(font, g[k], nil).flatMap { $0.copy(using: &t) } ?? CGMutablePath()
            out.append(Letter(ch: ch, id: id, path: gp, advanceX: pos[k].x))
        }
    }
    return out
}
let letters = wordLetters()
let wordBox: CGRect = letters.reduce(CGRect.null) { $0.union($1.path.boundingBoxOfPath) }
let wordPad: CGFloat = 24
/// Translation that moves glyphs into the SVG viewBox.
let wordT = CGAffineTransform(translationX: wordPad - wordBox.minX, y: wordPad - wordBox.minY)
let wordSize = CGSize(width: (wordBox.width + 2 * wordPad).rounded(.up), height: (wordBox.height + 2 * wordPad).rounded(.up))
/// "Ram" and "Part" share one ink; the capitals R and P carry the accent so the name reads "Ram Part".
func letterColor(_ i: Int, dark: Bool) -> RGB {
    let accent = dark ? Brand.accentDark : Brand.accentLight
    let ink = dark ? Brand.white : Brand.ink
    return (i == 0 || i == 3) ? accent : ink
}

// MARK: - SVG writers

func writeText(_ s: String, _ name: String) { try! s.write(to: url(name), atomically: true, encoding: .utf8) }

func markSVG() -> String {
    """
    <?xml version="1.0" encoding="UTF-8"?>
    <!-- RamPart mark ("Keep R"): crenellated tower stem, rampart bowl, teal stride leg. 1024 grid, macOS icon body 824 @ 100. -->
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" width="1024" height="1024">
      <title>RamPart</title>
      <defs>
        <linearGradient id="tile" x1="100" y1="100" x2="924" y2="924" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="\(Brand.deepTeal.css)"/><stop offset="0.55" stop-color="\(Brand.midnight.css)"/><stop offset="1" stop-color="\(Brand.navy.css)"/>
        </linearGradient>
        <radialGradient id="glow" cx="512" cy="470" r="470" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="\(Brand.teal.css)" stop-opacity="0.30"/><stop offset="1" stop-color="\(Brand.teal.css)" stop-opacity="0"/>
        </radialGradient>
        <linearGradient id="stone" x1="0" y1="222" x2="0" y2="802" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="#FFFFFF"/><stop offset="1" stop-color="\(Brand.frost.css)"/>
        </linearGradient>
        <linearGradient id="stride" x1="0" y1="624" x2="0" y2="802" gradientUnits="userSpaceOnUse">
          <stop offset="0" stop-color="\(Brand.mint.css)"/><stop offset="1" stop-color="\(Brand.teal.css)"/>
        </linearGradient>
        <filter id="lift" x="-20%" y="-20%" width="140%" height="140%">
          <feDropShadow dx="0" dy="8" stdDeviation="9" flood-color="#000" flood-opacity="0.38"/>
        </filter>
      </defs>
      <g id="part-0" data-name="tile">
        <path d="\(squircleSVG(MarkGeometry.tileRect))" fill="url(#tile)"/>
        <path d="\(squircleSVG(MarkGeometry.tileRect))" fill="url(#glow)"/>
      </g>
      <g filter="url(#lift)">
        <path id="part-1" data-name="stem" d="\(MarkGeometry.stem)" fill="url(#stone)"/>
        <path id="part-2" data-name="bowl" d="\(MarkGeometry.bowl)" fill="url(#stone)"/>
        <path id="part-3" data-name="leg" d="\(MarkGeometry.leg)" fill="url(#stride)"/>
      </g>
    </svg>

    """
}

func glyphOnlySVG(color: String, accent: String) -> String {
    // The bare R (no tile), cropped to the mark with 1/4 stem clear space. For use on any background.
    let pad: CGFloat = 32, b = MarkGeometry.markBox
    return """
    <?xml version="1.0" encoding="UTF-8"?>
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="\(Int(b.minX - pad)) \(Int(b.minY - pad)) \(Int(b.width + 2 * pad)) \(Int(b.height + 2 * pad))">
      <title>RamPart</title>
      <path id="part-1" d="\(MarkGeometry.stem)" fill="\(color)"/>
      <path id="part-2" d="\(MarkGeometry.bowl)" fill="\(color)"/>
      <path id="part-3" d="\(MarkGeometry.leg)" fill="\(accent)"/>
    </svg>

    """
}

func wordmarkSVG(dark: Bool) -> String {
    var body = ""
    for (i, l) in letters.enumerated() {
        body += "  <path id=\"\(l.id)\" data-index=\"\(i)\" d=\"\(svgD(l.path, transform: wordT))\" fill=\"\(letterColor(i, dark: dark).css)\"/>\n"
    }
    return """
    <?xml version="1.0" encoding="UTF-8"?>
    <!-- RamPart wordmark, \(dark ? "for dark backgrounds" : "for light backgrounds"). SF Pro Rounded Bold, tracking \(wordTracking)em, outlined. -->
    <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 \(Int(wordSize.width)) \(Int(wordSize.height))" width="\(Int(wordSize.width))" height="\(Int(wordSize.height))">
      <title>RamPart</title>
    \(body)</svg>

    """
}

// MARK: - Animation spec

struct Anim { let id: String; let delay: Double; let duration: Double; let from: [String: Double]; let easing: String }
let markAnims: [Anim] = [
    Anim(id: "part-0", delay: 0.00, duration: 0.35, from: ["opacity": 0, "scale": 0.86], easing: "spring(response:0.45,damping:0.8)"),
    Anim(id: "part-1", delay: 0.15, duration: 0.35, from: ["opacity": 0, "scaleY": 0, "anchorY": 802], easing: "easeOut"),
    Anim(id: "part-2", delay: 0.38, duration: 0.35, from: ["opacity": 0, "translateX": 120], easing: "spring(response:0.4,damping:0.75)"),
    Anim(id: "part-3", delay: 0.58, duration: 0.32, from: ["opacity": 0, "translateY": -90, "translateX": -40], easing: "spring(response:0.35,damping:0.7)")]
let letterStart = 0.45, letterStagger = 0.06, letterDuration = 0.30
let totalDuration = 1.2

func ease(_ t: Double) -> CGFloat { let x = min(max(t, 0), 1); return CGFloat(1 - pow(1 - x, 3)) }
func easeBack(_ t: Double) -> CGFloat { let x = min(max(t, 0), 1); let c1 = 1.70158, c3 = c1 + 1; return CGFloat(1 + c3 * pow(x - 1, 3) + c1 * pow(x - 1, 2)) }
func progress(_ a: Anim, _ time: Double) -> Double { (time - a.delay) / a.duration }

func iconState(at time: Double) -> IconState {
    var st = IconState()
    func p(_ i: Int) -> Double { progress(markAnims[i], time) }
    // tile
    let t0 = easeBack(p(0)), sc = 0.86 + 0.14 * t0
    st.tile.alpha = ease(p(0) * 1.5)
    st.tile.transform = CGAffineTransform(translationX: 512, y: 512).scaledBy(x: sc, y: sc).translatedBy(x: -512, y: -512)
    st.glow = ease((time - 0.7) / 0.5) * 0.6 + 0.4
    // stem grows from baseline
    let t1 = ease(p(1)); st.parts[0].alpha = ease(p(1) * 2)
    st.parts[0].transform = CGAffineTransform(translationX: 0, y: 802).scaledBy(x: 1, y: max(t1, 0.001)).translatedBy(x: 0, y: -802)
    // bowl slides in from the right
    let t2 = easeBack(p(2)); st.parts[1].alpha = ease(p(2) * 2)
    st.parts[1].transform = CGAffineTransform(translationX: 120 * (1 - t2), y: 0)
    // leg strides down into place
    let t3 = easeBack(p(3)); st.parts[2].alpha = ease(p(3) * 2)
    st.parts[2].transform = CGAffineTransform(translationX: -40 * (1 - t3), y: -90 * (1 - t3))
    return st
}

func animationJSON() -> String {
    func esc(_ s: String) -> String { s.replacingOccurrences(of: "\"", with: "\\\"") }
    func from(_ d: [String: Double]) -> String { "{" + d.sorted { $0.key < $1.key }.map { "\"\($0.key)\": \($0.value)" }.joined(separator: ", ") + "}" }
    var mark: [String] = []
    let markD = [squircleSVG(MarkGeometry.tileRect), MarkGeometry.stem, MarkGeometry.bowl, MarkGeometry.leg]
    let markNames = ["tile", "stem", "bowl", "leg"]
    let markFill = ["linear \(Brand.deepTeal.css) -> \(Brand.midnight.css) -> \(Brand.navy.css) (top-left to bottom-right)", "linear #FFFFFF -> \(Brand.frost.css) (top to bottom)", "linear #FFFFFF -> \(Brand.frost.css) (top to bottom)", "linear \(Brand.mint.css) -> \(Brand.teal.css) (top to bottom)"]
    for (i, a) in markAnims.enumerated() {
        mark.append("""
              {"id": "\(a.id)", "name": "\(markNames[i])", "order": \(i), "d": "\(esc(markD[i]))", "fill": "\(markFill[i])", "delay": \(a.delay), "duration": \(a.duration), "from": \(from(a.from)), "easing": "\(a.easing)"}
        """)
    }
    var lets: [String] = []
    for (i, l) in letters.enumerated() {
        let delay = ((letterStart + Double(i) * letterStagger) * 1000).rounded() / 1000
        lets.append("""
              {"id": "\(l.id)", "char": "\(l.ch)", "order": \(i), "d": "\(svgD(l.path, transform: wordT))", "fillLight": "\(letterColor(i, dark: false).css)", "fillDark": "\(letterColor(i, dark: true).css)", "delay": \(delay), "duration": \(letterDuration), "from": {"opacity": 0, "translateY": 18, "blur": 6}, "easing": "spring(response:0.35,damping:0.8)"}
        """)
    }
    return """
    {
      "name": "RamPart brand assembly",
      "totalDuration": \(totalDuration),
      "notes": "Times in seconds. 'from' gives the starting value of each property; animate to identity (opacity 1, scale 1, translate 0, blur 0). Mark coordinates are a 1024x1024 y-down canvas (same as logo-mark.svg). Letter coordinates match logo-wordmark-*.svg viewBox. scaleY on the stem is anchored at its baseline (anchorY). Under Reduce Motion, skip transforms and cross-fade everything in 0.2 s.",
      "mark": {
        "viewBox": "0 0 1024 1024",
        "parts": [
    \(mark.joined(separator: ",\n"))
        ]
      },
      "wordmark": {
        "viewBox": "0 0 \(Int(wordSize.width)) \(Int(wordSize.height))",
        "font": "SF Pro Rounded Bold, \(Int(wordFontSize)) pt, tracking \(wordTracking) em",
        "stagger": \(letterStagger),
        "letters": [
    \(lets.joined(separator: ",\n"))
        ]
      }
    }

    """
}

// MARK: - Wordmark & storyboard rendering

func drawWordmark(_ ctx: CGContext, dark: Bool, time: Double = 10) {
    for (i, l) in letters.enumerated() {
        let delay = letterStart + Double(i) * letterStagger
        let p = (time - delay) / letterDuration
        let a = ease(p * 1.4); if a <= 0 { continue }
        let dy = 18 * (1 - easeBack(p))
        ctx.saveGState(); ctx.setAlpha(a); ctx.translateBy(x: 0, y: dy)
        ctx.concatenate(wordT); ctx.addPath(l.path); ctx.setFillColor(letterColor(i, dark: dark).cg); ctx.fillPath()
        ctx.restoreGState()
    }
}

func renderWordmarkPNG(dark: Bool, scale: CGFloat, to u: URL) {
    let w = Int(wordSize.width * scale), h = Int(wordSize.height * scale)
    let ctx = bitmap(w, h); ctx.scaleBy(x: scale, y: scale)
    drawWordmark(ctx, dark: dark); savePNG(ctx, u)
}

/// Lockup frame: icon at left, wordmark at right, on the app's dark navy background.
func renderStoryboard(time: Double, to u: URL) {
    let W = 1600, H = 560
    let ctx = bitmap(W, H)
    ctx.drawLinearGradient(gradient([RGB(hex: 0x0A172E), Brand.navy]), start: .zero, end: CGPoint(x: 0, y: H), options: [])
    ctx.saveGState(); ctx.translateBy(x: 60, y: 40); ctx.scaleBy(x: 480 / 1024, y: 480 / 1024)
    drawIcon(ctx, px: 480, state: iconState(at: time)); ctx.restoreGState()
    let ws: CGFloat = min(1.2, 940 / wordSize.width)
    ctx.saveGState(); ctx.translateBy(x: 580, y: CGFloat(H) / 2 - wordSize.height * ws / 2); ctx.scaleBy(x: ws, y: ws)
    drawWordmark(ctx, dark: true, time: time); ctx.restoreGState()
    // timeline caption
    let label = String(format: "t = %.2f  (%.2f s)", time / totalDuration, time) as NSString
    let attrs: [NSAttributedString.Key: Any] = [.font: NSFont.monospacedSystemFont(ofSize: 22, weight: .medium), .foregroundColor: NSColor(white: 1, alpha: 0.5)]
    ctx.saveGState(); ctx.translateBy(x: 0, y: CGFloat(H)); ctx.scaleBy(x: 1, y: -1)
    NSGraphicsContext.saveGraphicsState(); NSGraphicsContext.current = NSGraphicsContext(cgContext: ctx, flipped: false)
    label.draw(at: NSPoint(x: 60, y: 14), withAttributes: attrs)
    NSGraphicsContext.restoreGraphicsState(); ctx.restoreGState()
    savePNG(ctx, u)
}

// MARK: - Menu bar template (monochrome R, black + alpha)

func drawTemplate(_ ctx: CGContext, pt: CGFloat, scale: CGFloat) {
    // Fit the mark box into an 18 pt square with 1 pt padding; snap scale so the stem is a whole pixel count.
    let b = MarkGeometry.markBox, avail = (pt - 2) * scale
    let k = avail / b.height
    ctx.translateBy(x: (pt * scale - b.width * k) / 2 - b.minX * k, y: (pt * scale - b.height * k) / 2 - b.minY * k)
    ctx.scaleBy(x: k, y: k)
    ctx.setFillColor(CGColor(gray: 0, alpha: 1))
    for part in MarkGeometry.parts { ctx.addPath(parseSVGPath(part.d)) }
    ctx.fillPath()
}

// MARK: - Run

writeText(markSVG(), "logo-mark.svg")
writeText(glyphOnlySVG(color: Brand.ink.css, accent: Brand.accentLight.css), "logo-glyph-light.svg")
writeText(glyphOnlySVG(color: "#FFFFFF", accent: Brand.accentDark.css), "logo-glyph-dark.svg")
writeText(wordmarkSVG(dark: false), "logo-wordmark-light.svg")
writeText(wordmarkSVG(dark: true), "logo-wordmark-dark.svg")
writeText(animationJSON(), "animation.json")

renderIconPNG(1024, to: url("logo-mark-1024.png"))
let preview = url("previews"); try? fm.createDirectory(at: preview, withIntermediateDirectories: true)
for px in [16, 32, 64, 128, 256] { renderIconPNG(px, to: preview.appendingPathComponent("icon-\(px).png")) }
renderWordmarkPNG(dark: false, scale: 1, to: preview.appendingPathComponent("wordmark-light.png"))
renderWordmarkPNG(dark: true, scale: 1, to: preview.appendingPathComponent("wordmark-dark.png"))

let iconset = url("AppIcon.iconset")
try? fm.removeItem(at: iconset); try! fm.createDirectory(at: iconset, withIntermediateDirectories: true)
for base in [16, 32, 128, 256, 512] {
    renderIconPNG(base, to: iconset.appendingPathComponent("icon_\(base)x\(base).png"))
    renderIconPNG(base * 2, to: iconset.appendingPathComponent("icon_\(base)x\(base)@2x.png"))
}
let iconutil = Process(); iconutil.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
iconutil.arguments = ["-c", "icns", iconset.path, "-o", url("AppIcon.icns").path]
try! iconutil.run(); iconutil.waitUntilExit()
precondition(iconutil.terminationStatus == 0, "iconutil failed")

for (scale, suffix) in [(CGFloat(1), ""), (2, "@2x")] {
    let px = Int(18 * scale); let ctx = bitmap(px, px)
    drawTemplate(ctx, pt: 18, scale: scale); savePNG(ctx, url("MenuBarIconTemplate\(suffix).png"))
}
do { // vector PDF template, 18 x 18 pt
    var box = CGRect(x: 0, y: 0, width: 18, height: 18)
    let pdf = CGContext(url("MenuBarIcon.pdf") as CFURL, mediaBox: &box, nil)!
    pdf.beginPDFPage(nil); pdf.translateBy(x: 0, y: 18); pdf.scaleBy(x: 1, y: -1)
    drawTemplate(pdf, pt: 18, scale: 1); pdf.endPDFPage(); pdf.closePDF()
}

let frames = url("storyboard"); try? fm.createDirectory(at: frames, withIntermediateDirectories: true)
for t in [0.0, 0.25, 0.5, 0.75, 1.0] {
    renderStoryboard(time: t * totalDuration, to: frames.appendingPathComponent(String(format: "frame-t%03d.png", Int(t * 100))))
}
print("RamPart brand assets written to \(outDir.path)")
