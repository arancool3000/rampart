import SwiftUI
import AppKit
import RampartShared

/// The CLT toolchain ships no SwiftUIMacros plugin, so `@State` cannot be used. Use `@StateVar`.
typealias StateVar = SwiftUI.State

extension Color {
    /// Rampart Teal: light #0A84A0, dark #40C8E0.
    static let rampartTeal = Color(nsColor: NSColor(name: "RampartTeal") { appearance in
        if appearance.bestMatch(from: [.darkAqua, .aqua]) == .darkAqua {
            return NSColor(srgbRed: 0x40 / 255, green: 0xC8 / 255, blue: 0xE0 / 255, alpha: 1)
        }
        return NSColor(srgbRed: 0x0A / 255, green: 0x84 / 255, blue: 0xA0 / 255, alpha: 1)
    })
    static let statusProtected = Color.green
    static let statusAttention = Color.yellow
    static let statusAction = Color.red
    static let statusInfo = Color.blue
    static let statusQuarantined = Color.secondary
}

enum Spacing {
    static let xs: CGFloat = 4, s: CGFloat = 8, m: CGFloat = 12, l: CGFloat = 16, xl: CGFloat = 24, xxl: CGFloat = 32
}

extension View {

    /// Primary action: glass prominent on macOS 26+, bordered prominent before.
    @ViewBuilder func primaryActionStyle() -> some View {
        if #available(macOS 26, *), !Headless.active { self.buttonStyle(.glassProminent) } else { self.buttonStyle(.borderedProminent) }
    }
    /// Secondary toolbar/chrome action.
    @ViewBuilder func secondaryActionStyle() -> some View {
        // Offscreen (headless) rendering can't rasterise Liquid Glass backdrops; use bordered there.
        if #available(macOS 26, *), !Headless.active { self.buttonStyle(.glass) } else { self.buttonStyle(.bordered) }
    }
    /// Floating control bar (navigation/control layer only, never content).
    @ViewBuilder func floatingGlassBar() -> some View {
        if #available(macOS 26, *), !Headless.active {
            self.glassEffect(.regular.interactive(), in: Capsule())
        } else {
            self.background(.regularMaterial, in: Capsule())
        }
    }

    /// Centered content column with the spec's max width.
    func contentColumn() -> some View {
        self.frame(maxWidth: 880).frame(maxWidth: .infinity).padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.xl)
    }
}

/// Section header used inside detail screens.
struct SectionHeader: View {
    let title: String
    var trailing: AnyView? = nil
    init(_ title: String, trailing: AnyView? = nil) { self.title = title; self.trailing = trailing }
    var body: some View {
        HStack {
            Text(title).font(.title3.weight(.semibold)).fontDesign(.rounded)
                .revealText(on: title)
            Spacer()
            if let trailing { trailing }
        }
        .accessibilityAddTraits(.isHeader)
    }
}

/// Symbol + text + colour: status is never colour alone.
struct StatusLabel: View {
    let text: String
    let symbol: String
    let tint: Color
    var body: some View {
        Label {
            Text(text).foregroundStyle(.primary)
        } icon: {
            Image(systemName: symbol).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
        }
    }
}

struct Badge: View {
    let text: String
    var tint: Color = .secondary
    var body: some View {
        Text(text)
            .font(.caption.weight(.medium))
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(tint.opacity(0.15), in: Capsule())
            .foregroundStyle(.primary)
    }
}

enum Fmt {
    static let relative: RelativeDateTimeFormatter = {
        let f = RelativeDateTimeFormatter(); f.unitsStyle = .full; return f
    }()
    static func ago(_ d: Date?) -> String {
        guard let d else { return "Never" }
        if abs(d.timeIntervalSinceNow) < 60 { return "Just now" }
        return relative.localizedString(for: d, relativeTo: Date())
    }
    static func dayTime(_ d: Date) -> String {
        let cal = Calendar.current
        let time = d.formatted(date: .omitted, time: .shortened)
        if cal.isDateInToday(d) { return "Today, \(time)" }
        if cal.isDateInYesterday(d) { return "Yesterday, \(time)" }
        return d.formatted(.dateTime.month(.abbreviated).day().hour().minute())
    }
    static func count(_ n: Int) -> String { n.formatted(.number) }
    static func bytes(_ n: UInt64) -> String { ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file) }
    static func duration(_ s: Double) -> String {
        let f = DateComponentsFormatter()
        f.allowedUnits = s >= 3600 ? [.hour, .minute] : (s >= 60 ? [.minute, .second] : [.second])
        f.unitsStyle = .abbreviated
        return f.string(from: max(1, s)) ?? "\(Int(s)) s"
    }
}

extension ThreatCategory {
    var label: String {
        switch self {
        case .malware: return "Malware"
        case .infostealer: return "Infostealer"
        case .adware: return "Adware"
        case .pua: return "Potentially unwanted"
        case .ransomware: return "Ransomware"
        case .backdoor: return "Backdoor"
        case .miner: return "Cryptominer"
        case .persistence: return "Suspicious login item"
        case .phishing: return "Phishing"
        case .test: return "Test file"
        case .suspicious: return "Suspicious behavior"
        }
    }
}

extension DetectionSource {
    var label: String {
        switch self {
        case .hash: return "signature (file fingerprint)"
        case .yara: return "YARA rule"
        case .xprotect: return "Apple XProtect rule"
        case .signing: return "code-signing check"
        case .heuristic: return "heuristics"
        case .behaviour: return "behavior monitoring"
        case .network: return "web protection"
        case .persistence: return "startup item monitoring"
        case .posture: return "security check"
        }
    }
    var symbol: String {
        switch self {
        case .hash: return "number"
        case .yara, .xprotect: return "doc.text.magnifyingglass"
        case .signing: return "signature"
        case .heuristic: return "wand.and.stars"
        case .behaviour: return "waveform.path.ecg"
        case .network: return "globe"
        case .persistence: return "power"
        case .posture: return "checkmark.shield"
        }
    }
}

extension Severity {
    var symbol: String {
        switch self {
        case .critical, .high: return "exclamationmark.triangle.fill"
        case .medium: return "exclamationmark.circle.fill"
        case .low, .info: return "info.circle.fill"
        }
    }
    var tint: Color {
        switch self {
        case .critical, .high: return .orange
        case .medium: return .yellow
        case .low, .info: return .blue
        }
    }
}

// MARK: - Design system tokens (dashboard, desktop mode, shared cards)

/// One scale for spacing, radii and type so screens line up. `Spacing` stays as the older alias.
enum DS {
    enum Space {
        static let xs: CGFloat = 4, s: CGFloat = 8, m: CGFloat = 12, l: CGFloat = 16, xl: CGFloat = 24, xxl: CGFloat = 32, xxxl: CGFloat = 48
    }
    enum Radius {
        static let control: CGFloat = 10, tile: CGFloat = 14, card: CGFloat = 16, panel: CGFloat = 22, hero: CGFloat = 28
    }
    /// Type scale: display 40 · title 22 · headline 17 · body 14 · callout 13 · caption 11.5 · eyebrow 11 (caps).
    enum Font {
        static let display = SwiftUI.Font.system(size: 40, weight: .bold, design: .rounded)
        static let title = SwiftUI.Font.system(size: 22, weight: .semibold, design: .rounded)
        static let headline = SwiftUI.Font.system(size: 17, weight: .semibold, design: .rounded)
        static let body = SwiftUI.Font.system(size: 14)
        static let callout = SwiftUI.Font.system(size: 13)
        static let caption = SwiftUI.Font.system(size: 11.5)
        static let eyebrow = SwiftUI.Font.system(size: 11, weight: .semibold, design: .rounded)
        static let metric = SwiftUI.Font.system(size: 30, weight: .bold, design: .rounded)
    }
    /// Space the floating RamPart bot (bottom-right corner) needs kept clear on full-window layouts.
    static let botClearance: CGFloat = 170
}
