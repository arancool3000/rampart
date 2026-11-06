import SwiftUI
import AppKit
import RampartShared

/// The RamPart "Two-Part Shield" (Resources/Brand/generate-shield.swift, variant 0): peaked top, sloped
/// shoulders, soft point. Fits a 1 : 1.21 box centred in the rect. No keyhole, no glow.
struct RamPartShield: Shape {
    func path(in rect: CGRect) -> Path {
        let H = min(rect.height, rect.width * 1.21), W = H / 1.21
        let x0 = rect.midX - W / 2, yBot = rect.midY + H / 2   // SwiftUI is y-down: b = 0 is the bottom
        func P(_ a: CGFloat, _ b: CGFloat) -> CGPoint { CGPoint(x: x0 + W * a, y: yBot - H * b) }
        var p = Path()
        p.move(to: P(0.5, 1.0))
        p.addQuadCurve(to: P(0.58, 0.985), control: P(0.535, 1.0))
        p.addLine(to: P(0.93, 0.875))
        p.addQuadCurve(to: P(1.0, 0.80), control: P(1.0, 0.86))
        p.addLine(to: P(1.0, 0.42))
        p.addCurve(to: P(0.56, 0.015), control1: P(1.0, 0.20), control2: P(0.80, 0.11))
        p.addQuadCurve(to: P(0.44, 0.015), control: P(0.5, -0.012))
        p.addCurve(to: P(0.0, 0.42), control1: P(0.20, 0.11), control2: P(0.0, 0.20))
        p.addLine(to: P(0.0, 0.80))
        p.addQuadCurve(to: P(0.07, 0.875), control: P(0.0, 0.86))
        p.addLine(to: P(0.42, 0.985))
        p.addQuadCurve(to: P(0.5, 1.0), control: P(0.465, 1.0))
        p.closeSubpath()
        return p
    }
}

/// The mark: white shield, right half 11% darker (gray 0.89), optionally on the near-black squircle tile.
/// `split` (0…1) pulls the halves apart horizontally (splash); `sweep` (0…1, nil = none) runs one light band across.
struct RamPartMark: View {
    var size: CGFloat = 64
    var tile: Bool = true
    var split: CGFloat = 0
    var sweep: CGFloat? = nil
    var halfOpacity: Double = 1

    var body: some View {
        let shieldW = tile ? size * 0.441 / 0.8047 : size / 1.21   // tile proportions from generate-shield.swift
        let shieldH = shieldW * 1.21
        ZStack {
            if tile {
                RoundedRectangle(cornerRadius: size * 0.18 / 0.8047, style: .continuous)
                    .fill(LinearGradient(colors: [Color(white: 0.13), Color(white: 0.06)], startPoint: .top, endPoint: .bottom))
            }
            ZStack {
                // Left half (white) and right half (gray 0.89), each clipped from the same shield.
                RamPartShield().fill(Color.white)
                    .mask(HStack(spacing: 0) { Rectangle(); Color.clear })
                    .offset(x: -split * shieldW * 0.9)
                RamPartShield().fill(Color(white: 0.89))
                    .mask(HStack(spacing: 0) { Color.clear; Rectangle() })
                    .offset(x: split * shieldW * 0.9)
                if let s = sweep, s > 0, s < 1 {
                    RamPartShield()
                        .fill(LinearGradient(colors: [.white.opacity(0), .white.opacity(0.85), .white.opacity(0)],
                                             startPoint: UnitPoint(x: s * 1.6 - 0.5, y: 0), endPoint: UnitPoint(x: s * 1.6 - 0.2, y: 1)))
                        .blendMode(.plusLighter)
                        .opacity(0.35)
                }
            }
            .frame(width: shieldW, height: shieldH)
            .opacity(halfOpacity)
        }
        .frame(width: size, height: tile ? size : shieldH)
        .accessibilityHidden(true)
    }
}

/// Mark with a small status badge (status is never conveyed by the logo alone).
struct StatusMark: View {
    var size: CGFloat
    var badge: String          // SF Symbol for the status
    var tint: Color
    var dimmed = false
    var body: some View {
        ZStack(alignment: .bottomTrailing) {
            RamPartMark(size: size, tile: true)
                .saturation(dimmed ? 0 : 1)
                .opacity(dimmed ? 0.55 : 1)
            Image(systemName: badge)
                .font(.system(size: size * 0.26, weight: .bold))
                .symbolRenderingMode(.palette)
                .foregroundStyle(.white, tint)
                .background(Circle().fill(Color(nsColor: .windowBackgroundColor)).padding(-2))
                .offset(x: size * 0.04, y: size * 0.04)
        }
        .frame(width: size, height: size)
        .accessibilityHidden(true)
    }
}

enum BrandImages {
    /// Menu bar template icon: Resources/Brand/MenuBarIconTemplate.png when bundled, else drawn from the same path.
    @MainActor static let menuBarTemplate: NSImage = {
        for name in ["MenuBarIconTemplate"] {
            if let url = Bundle.main.url(forResource: name, withExtension: "png"), let img = NSImage(contentsOf: url) {
                img.size = NSSize(width: 18, height: 18); img.isTemplate = true; return img
            }
        }
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { rect in
            let shieldRect = rect.insetBy(dx: 2.5, dy: 1)
            let path = RamPartShield().path(in: shieldRect).cgPath
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            ctx.addPath(path); ctx.setFillColor(NSColor.black.cgColor); ctx.fillPath()
            // The two parts: a hairline gap down the middle keeps the "two-part" read at 18 pt.
            ctx.setBlendMode(.clear); ctx.fill(CGRect(x: rect.midX - 0.5, y: 0, width: 1, height: rect.height))
            return true
        }
        img.isTemplate = true
        return img
    }()

    /// About panel / large uses.
    @MainActor static func mark(size: CGFloat) -> NSImage {
        let r = ImageRenderer(content: RamPartMark(size: size, tile: true))
        r.scale = 2
        return r.nsImage ?? NSImage()
    }
}
