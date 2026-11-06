import SwiftUI
import RampartShared

struct RootView: View {
    @Environment(AppModel.self) private var model
    @AppStorage("onboarding.done") private var onboardingDone = false
    @StateVar private var showOnboarding = false

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                ForEach(SidebarItem.allCases) { item in
                    NavigationLink(value: item) {
                        Label(item.title, systemImage: item.symbol)
                            .badge(item == .threats && !model.openDetections.isEmpty ? model.openDetections.count : 0)
                    }
                    .accessibilityHint("Command \(SidebarItem.allCases.firstIndex(of: item)! + 1)")
                }
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 236, max: 260)
            .safeAreaInset(edge: .top) { SidebarBrand() }
            .safeAreaInset(edge: .bottom) { SidebarFooter() }
        } detail: {
            VStack(spacing: 0) {
                if model.isDemo { DemoBanner() }
                if let err = model.lastError, !model.isDemo { ErrorBanner(message: err) }
                detail
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .background(AppBackdrop())
        }
        .sheet(isPresented: $showOnboarding) {
            OnboardingView { onboardingDone = true; showOnboarding = false }
                .environment(model)
                .tint(.rampartTeal)
        }
        .onAppear {
            let args = ProcessInfo.processInfo.arguments
            if args.contains("--onboarding") { showOnboarding = true }
            else if !onboardingDone && !args.contains("--skip-onboarding") && !Headless.active { showOnboarding = true }
            if let i = args.firstIndex(of: "--section"), i + 1 < args.count, let s = SidebarItem(rawValue: args[i + 1]) { model.selection = s }
        }
        .onReceive(NotificationCenter.default.publisher(for: .rampartShowOnboarding)) { _ in showOnboarding = true }
        .onAppear { AnimationGate.shared.start() }
    }

    @ViewBuilder private var detail: some View {
        switch model.selection ?? .dashboard {
        case .dashboard: DashboardView()
        case .scan: ScanView()
        case .threats: ThreatsView()
        case .activity: ActivityView()
        case .network: NetworkView()
        case .posture: PostureView()
        case .rules: RulesView()
        case .settings: SettingsView(standalone: false)
        }
    }
}

extension Notification.Name {
    static let rampartShowOnboarding = Notification.Name("app.rampart.showOnboarding")
}

struct SidebarFooter: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 6) {
                Image(systemName: footerSymbol).foregroundStyle(footerTint).symbolRenderingMode(.hierarchical)
                Text(footerTitle).font(.callout.weight(.medium))
            }
            Text("Definitions updated \(Fmt.ago(model.definitionsUpdated).lowercased())")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.m)
        .accessibilityElement(children: .combine)
    }
    private var footerTitle: String {
        switch model.overall {
        case .threat: return "Needs attention"
        case .off: return "Protection off"
        case .paused: return "Protection paused"
        case .limited: return "Limited protection"
        default: return "Protected"
        }
    }
    private var footerSymbol: String {
        switch model.overall {
        case .threat, .off: return "xmark.shield.fill"
        case .paused: return "pause.circle.fill"
        case .limited: return "exclamationmark.shield.fill"
        default: return "checkmark.shield.fill"
        }
    }
    private var footerTint: Color {
        switch model.overall {
        case .threat, .off: return .statusAction
        case .paused: return .secondary
        case .limited: return .statusAttention
        default: return .statusProtected
        }
    }
}

struct DemoBanner: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: Spacing.s) {
            Label("Demo mode", systemImage: "sparkles.rectangle.stack")
                .font(.callout.weight(.semibold))
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(Color.statusInfo.opacity(0.18), in: Capsule())
                .foregroundStyle(.primary)
            Text("Sample data. The Rampart background service isn't running, so nothing on this Mac is being changed.")
                .font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            Spacer()
            Button("Retry Connection") { Task { await model.connect() } }
                .controlSize(.small)
        }
        .padding(.horizontal, Spacing.l).padding(.vertical, 7)
        .background(.bar)
        .overlay(alignment: .bottom) { Divider() }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Demo mode. Showing sample data because the background service isn't running.")
    }
}

struct SidebarBrand: View {
    var body: some View {
        HStack(spacing: 10) {
            IconBadge(symbol: "shield.lefthalf.filled", tint: .rampartTeal, size: 30)
            VStack(alignment: .leading, spacing: 0) {
                Text("Rampart").font(.title3.weight(.bold)).fontDesign(.rounded)
                Text("Mac security").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
        }
        .padding(.horizontal, Spacing.l).padding(.top, Spacing.xs).padding(.bottom, Spacing.s)
        .accessibilityElement(children: .combine)
    }
}

struct ErrorBanner: View {
    let message: String
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack {
            Image(systemName: "exclamationmark.circle").foregroundStyle(.secondary)
            Text(message).font(.callout)
            Spacer()
            Button("Dismiss") { model.lastError = nil }.controlSize(.small)
        }
        .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s)
        .background(.background.secondary)
    }
}

/// Score ring: angular gradient with a soft glow; the label text always appears next to it.
struct ScoreRing: View {
    let score: Int
    var size: CGFloat = 120
    var lineWidth: CGFloat = 12
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    @StateVar private var shown: Double = -1

    var body: some View {
        let colors = Palette.gradient(for: score)
        let value = shown < 0 ? (reduceMotion ? Double(score) : 0) : shown
        ZStack {
            Circle().stroke(colors[0].opacity(0.14), lineWidth: lineWidth)
            Circle()
                .trim(from: 0, to: max(0.001, value / 100))
                .stroke(AngularGradient(gradient: Gradient(colors: [colors[0].opacity(0.7), colors[0], colors[1]]),
                                        center: .center, startAngle: .degrees(0), endAngle: .degrees(360 * max(0.01, value / 100))),
                        style: StrokeStyle(lineWidth: lineWidth, lineCap: .round))
                .rotationEffect(.degrees(-90))
                .shadow(color: reduceTransparency ? .clear : colors[1].opacity(0.45), radius: lineWidth * 0.8)
            VStack(spacing: 0) {
                Text("\(score)")
                    .font(.system(size: size * 0.34, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                if size >= 80 { Text("of 100").font(.caption).foregroundStyle(.secondary) }
            }
        }
        .frame(width: size, height: size)
        .onAppear { if reduceMotion || Headless.active { shown = Double(score) } else { withAnimation(.easeOut(duration: 0.9)) { shown = Double(score) } } }
        .onChange(of: score) { _, new in withAnimation(reduceMotion ? nil : .easeOut(duration: 0.5)) { shown = Double(new) } }
    }
}

struct EmptyStateView: View {
    let symbol: String
    let title: String
    let detail: String
    var body: some View {
        VStack(spacing: Spacing.m) {
            Image(systemName: symbol).font(.system(size: 44)).foregroundStyle(.secondary).symbolRenderingMode(.hierarchical)
            Text(title).font(.title3.weight(.medium))
            Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 380)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Spacing.xxl)
        .accessibilityElement(children: .combine)
    }
}

extension Notification.Name {
    static let rampartOnboardingAdvance = Notification.Name("app.rampart.onboardingAdvance")
}
