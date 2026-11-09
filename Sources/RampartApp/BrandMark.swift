import SwiftUI
import AppKit
import RampartShared

/// The RamPart mark: the Pixel Guard's head (Features/Bot/PixelGuard.swift is the single source of truth),
/// optionally on its dark rounded tile. Replaces the old two-part shield.
/// `split` (0…1) scatters the boxes (splash assembly); `sweep` (0…1, nil = none) runs one visor scan line.
struct RamPartMark: View {
    var size: CGFloat = 64
    var tile: Bool = true
    var split: CGFloat = 0
    var sweep: CGFloat? = nil
    var halfOpacity: Double = 1
    var expression: PixelGuard.Expression = .neutral

    var body: some View {
        PixelGuardView(size: size, expression: expression, tile: tile, scatter: split, scanLine: sweep)
            .opacity(halfOpacity)
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
            RamPartMark(size: size, tile: true, expression: dimmed ? .sleeping : .neutral)
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
    /// Menu bar template icon (18 pt): Resources/Brand/MenuBarIconTemplate.png when bundled, else drawn from the matrix.
    @MainActor static let menuBarTemplate: NSImage = {
        if let url = Bundle.main.url(forResource: "MenuBarIconTemplate", withExtension: "png"), let img = NSImage(contentsOf: url) {
            if let url2 = Bundle.main.url(forResource: "MenuBarIconTemplate@2x", withExtension: "png"),
               let rep2 = NSImage(contentsOf: url2)?.representations.first {
                img.addRepresentation(rep2)
            }
            img.size = NSSize(width: 18, height: 18); img.isTemplate = true; return img
        }
        let img = NSImage(size: NSSize(width: 18, height: 18), flipped: true) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            let px = Int(rect.width)
            PixelRenderer.drawTemplate(in: ctx, px: px)
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
