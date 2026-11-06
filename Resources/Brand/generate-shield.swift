import AppKit
let cs = CGColorSpace(name: CGColorSpace.sRGB)!
// RamPart's own shield: peaked top with a softened apex, sloped shoulders, rounded shoulder corners,
// straight sides, then a curved taper to a softened point. Drawn from scratch (not an SF Symbol).
func shield(_ c: CGPoint, _ W: CGFloat, crenel: Bool = false) -> CGPath {
    let H = W*1.21, x0 = c.x - W/2, yTop = c.y + H/2, yBot = c.y - H/2
    func P(_ a: CGFloat, _ b: CGFloat) -> CGPoint { CGPoint(x: x0 + W*a, y: yBot + H*b) }
    let p = CGMutablePath()
    if crenel {
        // apex becomes a small battlement: centre merlon flanked by two notches
        p.move(to: P(0.5, 0.995))
        p.addLine(to: P(0.535, 0.995)); p.addLine(to: P(0.535, 0.965)); p.addLine(to: P(0.575, 0.965)); p.addLine(to: P(0.575, 0.987)); p.addLine(to: P(0.60, 0.979))
    } else {
        p.move(to: P(0.5, 1.0))
        p.addQuadCurve(to: P(0.58, 0.985), control: P(0.535, 1.0))           // soft apex (right)
    }
    p.addLine(to: P(0.93, 0.875))                                         // right shoulder slope
    p.addQuadCurve(to: P(1.0, 0.80), control: P(1.0, 0.86))              // rounded shoulder
    p.addLine(to: P(1.0, 0.42))                                           // straight right side
    p.addCurve(to: P(0.56, 0.015), control1: P(1.0, 0.20), control2: P(0.80, 0.11))
    p.addQuadCurve(to: P(0.44, 0.015), control: P(0.5, -0.012))          // soft point
    p.addCurve(to: P(0.0, 0.42), control1: P(0.20, 0.11), control2: P(0.0, 0.20))
    p.addLine(to: P(0.0, 0.80))
    p.addQuadCurve(to: P(0.07, 0.875), control: P(0.0, 0.86))
    if crenel {
        p.addLine(to: P(0.40, 0.979)); p.addLine(to: P(0.425, 0.987)); p.addLine(to: P(0.425, 0.965)); p.addLine(to: P(0.465, 0.965)); p.addLine(to: P(0.465, 0.995)); p.addLine(to: P(0.5, 0.995))
    } else {
        p.addLine(to: P(0.42, 0.985))
        p.addQuadCurve(to: P(0.5, 1.0), control: P(0.465, 1.0))
    }
    p.closeSubpath(); return p
}
func keyhole(_ c: CGPoint, _ W: CGFloat) -> CGPath {
    let p = CGMutablePath(); let r = W*0.075
    let cy = c.y + W*0.10
    p.addEllipse(in: CGRect(x: c.x - r, y: cy - r, width: 2*r, height: 2*r))
    p.move(to: CGPoint(x: c.x - r*0.55, y: cy - r*0.4)); p.closeSubpath(); p.move(to: CGPoint(x: c.x - r*0.55, y: cy - r*0.4)); p.addLine(to: CGPoint(x: c.x + r*0.55, y: cy - r*0.4))
    p.addLine(to: CGPoint(x: c.x + r*0.85, y: cy - r*3.2)); p.addLine(to: CGPoint(x: c.x - r*0.85, y: cy - r*3.2)); p.closeSubpath()
    return p
}
func render(variant: Int, size: Int, name: String) {
    let s = CGFloat(size)
    let ctx = CGContext(data: nil, width: size, height: size, bitsPerComponent: 8, bytesPerRow: 0, space: cs, bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue)!
    let tr = CGRect(x: s*0.0977, y: s*0.0977, width: s*0.8047, height: s*0.8047)
    ctx.addPath(CGPath(roundedRect: tr, cornerWidth: s*0.18, cornerHeight: s*0.18, transform: nil)); ctx.clip()
    let bg = CGGradient(colorsSpace: cs, colors: [CGColor(gray: 0.13, alpha: 1), CGColor(gray: 0.06, alpha: 1)] as CFArray, locations: [0,1])!
    ctx.drawLinearGradient(bg, start: CGPoint(x: 0, y: s), end: CGPoint(x: 0, y: 0), options: [])
    let W = s*0.441, c = CGPoint(x: s/2, y: s/2)
    ctx.saveGState()
    ctx.addPath(shield(c, W, crenel: variant == 1)); ctx.clip()
    ctx.setFillColor(CGColor(gray: 1, alpha: 1)); ctx.fill(CGRect(x: 0, y: 0, width: s, height: s))
    ctx.setFillColor(CGColor(gray: 0.89, alpha: 1)); ctx.fill(CGRect(x: s/2, y: 0, width: s/2, height: s))
    ctx.restoreGState()
    if variant == 2 {
        ctx.saveGState(); ctx.setFillColor(CGColor(gray: 0.10, alpha: 1))
        let r = W*0.075, cy = c.y + W*0.10
        ctx.fillEllipse(in: CGRect(x: c.x - r, y: cy - r, width: 2*r, height: 2*r))
        let slot = CGMutablePath()
        slot.move(to: CGPoint(x: c.x - r*0.55, y: cy)); slot.addLine(to: CGPoint(x: c.x + r*0.55, y: cy))
        slot.addLine(to: CGPoint(x: c.x + r*0.85, y: cy - r*3.2)); slot.addLine(to: CGPoint(x: c.x - r*0.85, y: cy - r*3.2)); slot.closeSubpath()
        ctx.addPath(slot); ctx.fillPath()
        ctx.restoreGState()
    }
    try! NSBitmapImageRep(cgImage: ctx.makeImage()!).representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: name))
}
let labels = ["A: bigger", "B: battlement top", "C: keyhole seam"]
for v in 0...2 { render(variant: v, size: 512, name: "fin-\(v).png"); render(variant: v, size: 32, name: "fin-\(v)-32.png") }
let sheet = NSImage(size: NSSize(width: 1620, height: 560)); sheet.lockFocus()
NSColor(white: 0.94, alpha: 1).setFill(); NSRect(x: 0, y: 0, width: 1620, height: 560).fill()
for v in 0...2 {
    NSImage(contentsOfFile: "fin-\(v).png")!.draw(in: NSRect(x: 20 + v*535, y: 40, width: 500, height: 500))
    NSImage(contentsOfFile: "fin-\(v)-32.png")!.draw(in: NSRect(x: 20 + v*535 + 450, y: 500, width: 32, height: 32))
    (labels[v] as NSString).draw(at: NSPoint(x: 30 + v*535, y: 10), withAttributes: [.font: NSFont.systemFont(ofSize: 16, weight: .semibold)])
}
sheet.unlockFocus()
try! NSBitmapImageRep(data: sheet.tiffRepresentation!)!.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: "compare-final.png"))
