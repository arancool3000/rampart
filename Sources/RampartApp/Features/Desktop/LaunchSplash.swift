import SwiftUI
import AppKit
import RampartShared

/// Launch moment (1.3 s): the Pixel Guard's boxes drift in from a loose cloud and lock into the logo,
/// one visor scan line passes, then the "RamPart" letters rise in. Ease-out only: nothing overshoots or bounces.
/// Animatable: a single `withAnimation` drives every frame, and it ends.
struct PixelLaunchAssembly: View, Animatable {
    var progress: Double
    var markSize: CGFloat = 140
    var wordHeight: CGFloat = 54
    @Environment(\.colorScheme) private var scheme
    var animatableData: Double { get { progress } set { progress = newValue } }

    static let duration = 1.3
    private static let letterPaths = BrandPaths.letters.map { SVGPath.parse($0.d) }

    private static func clamp(_ x: Double) -> Double { min(1, max(0, x)) }
    private static func out(_ x: Double) -> Double { 1 - pow(1 - clamp(x), 3) }

    var body: some View {
        let t = progress * Self.duration
        let gather = Self.out(t / 0.65)                       // boxes settle by 0.65 s
        let scan = (t - 0.62) / 0.36                           // one visor pass, 0.62–0.98 s
        VStack(spacing: wordHeight * 0.45) {
            PixelGuardView(size: markSize, tile: true, scatter: CGFloat(1.5 * (1 - gather)),
                           scanLine: scan > 0 && scan < 1 ? CGFloat(scan) : nil)
                .opacity(Self.clamp(t / 0.18))
                .scaleEffect(0.95 + 0.05 * gather)
            word(t).frame(width: wordHeight * CGFloat(BrandPaths.wordmarkViewBox.w / BrandPaths.wordmarkViewBox.h), height: wordHeight)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(Product.name)
    }

    private func word(_ t: Double) -> some View {
        let dark = scheme == .dark
        let accent = dark ? Color(red: 0.251, green: 0.784, blue: 0.878) : Color(red: 0.039, green: 0.518, blue: 0.627)
        let ink = dark ? Color.white : Color(red: 0.043, green: 0.106, blue: 0.180)
        return Canvas { ctx, size in
            let s = size.height / CGFloat(BrandPaths.wordmarkViewBox.h)
            ctx.scaleBy(x: s, y: s)
            for (i, l) in BrandPaths.letters.enumerated() {
                let k = Self.out((t - 0.7 - Double(i) * 0.05) / 0.3)
                guard k > 0 else { continue }
                var c = ctx
                c.opacity = k
                if k < 1 { c.addFilter(.blur(radius: (1 - k) * 4)) }
                c.translateBy(x: 0, y: CGFloat(14 * (1 - k)))
                c.fill(Self.letterPaths[i], with: .color(l.accent ? accent : ink))
            }
        }
    }
}
