// Renders the placeholder 1024x1024 Rampart icon (teal rounded square + shield). Usage: swift make-icon-png.swift out.png
import AppKit
let size = 1024
let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: size, pixelsHigh: size, bitsPerSample: 8, samplesPerPixel: 4,
                           hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB, bytesPerRow: 0, bitsPerPixel: 0)!
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
let r = NSRect(x: 100, y: 100, width: 824, height: 824)
let path = NSBezierPath(roundedRect: r, xRadius: 185, yRadius: 185)
NSGradient(starting: NSColor(calibratedRed: 0.05, green: 0.55, blue: 0.55, alpha: 1),
           ending: NSColor(calibratedRed: 0.02, green: 0.33, blue: 0.40, alpha: 1))!.draw(in: path, angle: -90)
if let sym = NSImage(systemSymbolName: "checkmark.shield.fill", accessibilityDescription: nil)?
    .withSymbolConfiguration(.init(pointSize: 500, weight: .semibold).applying(.init(paletteColors: [.white]))) {
    let s = sym.size
    sym.draw(in: NSRect(x: (1024 - s.width) / 2, y: (1024 - s.height) / 2, width: s.width, height: s.height))
}
NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: CommandLine.arguments[1]))
