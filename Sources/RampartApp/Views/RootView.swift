import SwiftUI
import RampartShared

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("onboarding.done") private var onboardingDone = false
    @StateVar private var showOnboarding = false

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            List(selection: $model.selection) {
                Section {
                    ForEach(SidebarItem.core) { item in
                        NavigationLink(value: item) { SidebarRow(item: item) }
                            .accessibilityHint("Command \(SidebarItem.core.firstIndex(of: item)! + 1)")
                    }
                }
                Section("Tools") {
                    ForEach(SidebarItem.tools) { item in
                        NavigationLink(value: item) { SidebarRow(item: item) }
                    }
                }
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 236, max: 260)
            .safeAreaInset(edge: .top) { SidebarBrand() }
            .safeAreaInset(edge: .bottom) { SidebarFooter() }
        } detail: {
            VStack(spacing: 0) {
                if model.isDemo { DemoBanner() }
                if model.isOffline { OfflineBanner() }
                else if let err = model.lastError, model.mode == .live { ErrorBanner(message: err) }
                detail
                    .id(model.selection)
                    .transition(reduceMotion ? .opacity : .blurFade)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .background(AppBackdrop())
            .animation(.easeInOut(duration: reduceMotion ? 0.15 : 0.28), value: model.selection)
        }
        .overlay { SplashOverlay() }
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
        // Tools: see FeatureRouter (one line per feature).
        case .scamCheck, .passwords, .networkScan, .aiAssistant, .remoteAccess: FeatureRouter.view(for: model.selection ?? .dashboard)
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
            if model.hasData {
                Text("Definitions updated \(Fmt.ago(model.definitionsUpdated).lowercased())")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.m)
        .accessibilityElement(children: .combine)
    }
    private var footerTitle: String {
        switch model.overall {
        case .threat: return "Needs attention"
        case .serviceDown: return "Service not running"
        case .starting: return "Starting protection…"
        case .off: return "Protection off"
        case .paused: return "Protection paused"
        case .limited: return "Limited protection"
        default:
            if model.mode == .live && model.source == .basic { return "Basic protection" }
            if model.mode == .connecting { return "Starting protection…" }
            return "Protected"
        }
    }
    private var footerSymbol: String {
        switch model.overall {
        case .threat, .off, .serviceDown: return "xmark.shield.fill"
        case .starting: return "shield.lefthalf.filled"
        case .paused: return "pause.circle.fill"
        case .limited: return "exclamationmark.shield.fill"
        default: return "checkmark.shield.fill"
        }
    }
    private var footerTint: Color {
        switch model.overall {
        case .threat, .off, .serviceDown: return .statusAction
        case .starting: return .secondary
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
            Label("Developer demo", systemImage: "sparkles.rectangle.stack")
                .font(.callout.weight(.semibold))
                .padding(.horizontal, 9).padding(.vertical, 3)
                .background(Color.statusInfo.opacity(0.18), in: Capsule())
                .foregroundStyle(.primary)
            Text("Sample data from --demo. Nothing on this Mac is being checked or changed.")
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

struct OfflineBanner: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: Spacing.s) {
            Image(systemName: "shield.slash").foregroundStyle(Color.statusAction)
            Text("Protection service isn't running.").font(.callout.weight(.semibold))
            Text(model.lastError ?? "Nothing is being checked right now.").font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.tail)
            Spacer()
            Button("Retry") { Task { await model.retry() } }.controlSize(.small)
        }
        .padding(.horizontal, Spacing.l).padding(.vertical, 7)
        .background(.bar)
        .overlay(alignment: .bottom) { Divider() }
        .accessibilityElement(children: .combine)
    }
}

struct SidebarBrand: View {
    var body: some View {
        HStack(spacing: 10) {
            RamPartMark(size: 30)
            VStack(alignment: .leading, spacing: 0) {
                Text("\(Product.name)").font(.title3.weight(.bold)).fontDesign(.rounded)
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
    @StateVar private var drawing = false

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
            // Comet head: a bright point riding the end of the arc, with a soft glow tail.
            if value > 0.5 {
                Circle()
                    .fill(Color.white)
                    .frame(width: lineWidth * 0.7, height: lineWidth * 0.7)
                    .shadow(color: colors[1], radius: lineWidth * (drawing ? 1.2 : 0.6))
                    .shadow(color: colors[1].opacity(0.6), radius: lineWidth * (drawing ? 2.2 : 0.9))
                    .offset(y: -size / 2)
                    .rotationEffect(.degrees(360 * value / 100))
                    .opacity(reduceTransparency ? 0 : 1)
            }
            VStack(spacing: 0) {
                Text("\(score)")
                    .font(.system(size: size * 0.34, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .contentTransition(.numericText())
                if size >= 80 { Text("of 100").font(.caption).foregroundStyle(.secondary) }
            }
        }
        .frame(width: size, height: size)
        .onAppear {
            if reduceMotion || Headless.active { shown = Double(score) }
            else {
                drawing = true
                withAnimation(.easeOut(duration: 1.1)) { shown = Double(score) }
                DispatchQueue.main.asyncAfter(deadline: .now() + 1.1) { withAnimation(.easeOut(duration: 0.4)) { drawing = false } }
            }
        }
        .onChange(of: score) { _, new in withAnimation(reduceMotion ? nil : .easeOut(duration: 0.5)) { shown = Double(new) } }
    }
}

struct EmptyStateView: View {
    let symbol: String
    let title: String
    let detail: String
    var brand = false
    var body: some View {
        VStack(spacing: Spacing.m) {
            if brand {
                StatusMark(size: 64, badge: "checkmark.circle.fill", tint: .statusProtected)
            } else {
                Image(systemName: symbol).font(.system(size: 44)).foregroundStyle(.secondary).symbolRenderingMode(.hierarchical)
            }
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

struct SidebarRow: View {
    let item: SidebarItem
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        Label {
            Text(item.title)
        } icon: {
            Image(systemName: item.symbol)
                .symbolEffect(.bounce, value: reduceMotion ? false : model.selection == item)
        }
        .badge(item == .threats && !model.openDetections.isEmpty ? model.openDetections.count : 0)
    }
}

/// Placeholder for a tool whose screen is being built by its owner (Features/<Name>/).
struct FeaturePlaceholderView: View {
    let item: SidebarItem
    var body: some View {
        VStack(spacing: Spacing.l) {
            RamPartMark(size: 64)
            Text(item.title).font(.largeTitle.weight(.bold)).fontDesign(.rounded)
            Text("This tool is on its way. It will appear here in a future update.")
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .navigationTitle(item.title)
    }
}
