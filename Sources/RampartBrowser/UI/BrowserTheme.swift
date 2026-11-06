import SwiftUI
import AppKit

/// The CLT toolchain ships no SwiftUIMacros plugin, so `@State` cannot be used. Use `@StateVar`.
typealias StateVar = SwiftUI.State

/// RamPart palette (mirrors Sources/RampartApp/Design.swift; the browser is a separate executable and
/// cannot import the app target).
enum BPalette {
    static let navy = Color(red: 0.027, green: 0.051, blue: 0.110)
    static let midnight = Color(red: 0.039, green: 0.090, blue: 0.180)
    static let abyss = Color(red: 0.020, green: 0.130, blue: 0.200)
    static let deepTeal = Color(red: 0.016, green: 0.235, blue: 0.290)
    static let teal = Color(red: 0.090, green: 0.720, blue: 0.800)
    static let mint = Color(red: 0.330, green: 0.900, blue: 0.760)
    static let amber = Color(red: 1.000, green: 0.760, blue: 0.250)
    static let coral = Color(red: 1.000, green: 0.420, blue: 0.380)
    static let rampartTeal = Color(nsColor: NSColor(name: "RampartTeal") { a in
        a.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
            ? NSColor(srgbRed: 0x40 / 255, green: 0xC8 / 255, blue: 0xE0 / 255, alpha: 1)
            : NSColor(srgbRed: 0x0A / 255, green: 0x84 / 255, blue: 0xA0 / 255, alpha: 1)
    })
}

enum Headless {
    /// `--render <dir>`: offscreen PNGs of the chrome, never a visible window, never a page load.
    static var renderDir: URL? {
        let a = CommandLine.arguments
        guard let i = a.firstIndex(of: "--render"), i + 1 < a.count else { return nil }
        return URL(fileURLWithPath: a[i + 1])
    }
    static var active: Bool { renderDir != nil }
}

/// Glass toolbar backdrop: Liquid Glass on macOS 26+, material before, and a plain fill when rendering
/// offscreen (materials cannot be rasterised without a window server backdrop).
struct ToolbarGlass: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    func body(content: Content) -> some View {
        if #available(macOS 26, *), !Headless.active {
            content.background(.ultraThinMaterial).glassEffect(.regular, in: Rectangle())
        } else if Headless.active {
            content.background(scheme == .dark ? Color.white.opacity(0.06) : Color.white.opacity(0.7))
        } else {
            content.background(.ultraThinMaterial)
        }
    }
}

struct BrowserBackdrop: View {
    @Environment(\.colorScheme) private var scheme
    var body: some View {
        Group {
            if scheme == .dark {
                LinearGradient(colors: [BPalette.navy, BPalette.midnight, BPalette.abyss], startPoint: .topLeading, endPoint: .bottomTrailing)
            } else {
                LinearGradient(colors: [Color(red: 0.965, green: 0.975, blue: 0.990), Color(red: 0.90, green: 0.955, blue: 0.965)], startPoint: .topLeading, endPoint: .bottomTrailing)
            }
        }
        .ignoresSafeArea()
    }
}

struct BCard: ViewModifier {
    @Environment(\.colorScheme) private var scheme
    var tint: Color?
    func body(content: Content) -> some View {
        let shape = RoundedRectangle(cornerRadius: 16, style: .continuous)
        content.padding(16)
            .background {
                ZStack {
                    shape.fill(scheme == .dark ? Color.white.opacity(0.055) : Color.white.opacity(0.78))
                    if let tint { shape.fill(LinearGradient(colors: [tint.opacity(scheme == .dark ? 0.22 : 0.14), .clear], startPoint: .topLeading, endPoint: .bottomTrailing)) }
                }
            }
            .overlay { shape.strokeBorder(LinearGradient(colors: scheme == .dark ? [.white.opacity(0.16), .white.opacity(0.04)] : [.white.opacity(0.9), .black.opacity(0.06)], startPoint: .top, endPoint: .bottom), lineWidth: 1) }
    }
}
extension View {
    func bcard(tint: Color? = nil) -> some View { modifier(BCard(tint: tint)) }
    func toolbarGlass() -> some View { modifier(ToolbarGlass()) }
}

struct GlowButton: ButtonStyle {
    var tint: Color = BPalette.rampartTeal
    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .padding(.horizontal, 18).padding(.vertical, 8)
            .foregroundStyle(.white)
            .background(Capsule().fill(LinearGradient(colors: [tint.opacity(0.95), tint.opacity(0.75)], startPoint: .top, endPoint: .bottom)))
            .overlay(Capsule().strokeBorder(Color.white.opacity(0.28), lineWidth: 1))
            .shadow(color: tint.opacity(0.32), radius: 6, y: 2)
            .opacity(configuration.isPressed ? 0.85 : 1)
    }
}

struct ToolbarIconButton: View {
    let symbol: String
    let help: String
    var enabled = true
    let action: () -> Void
    @StateVar private var hover = false
    var body: some View {
        Button(action: action) {
            Image(systemName: symbol)
                .font(.system(size: 13, weight: .semibold))
                .frame(width: 28, height: 26)
                .background(RoundedRectangle(cornerRadius: 7, style: .continuous).fill(hover ? Color.primary.opacity(0.08) : .clear))
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .disabled(!enabled)
        .opacity(enabled ? 1 : 0.35)
        .onHover { hover = $0 }
        .help(help)
        .accessibilityLabel(help)
    }
}
