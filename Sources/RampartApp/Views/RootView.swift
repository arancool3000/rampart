import SwiftUI
import RampartShared

struct RootView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("onboarding.done") private var onboardingDone = false
    @StateVar private var showOnboarding = false
    @AppStorage("sidebar.toolsExpanded") private var toolsExpanded = true

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
                Section(isExpanded: $toolsExpanded) {
                    ForEach(SidebarItem.tools) { item in
                        NavigationLink(value: item) { SidebarRow(item: item) }
                    }
                } header: {
                    Text("Tools")
                        .help(toolsExpanded ? "Hide tools" : "Show tools")
                        .accessibilityHint(toolsExpanded ? "Collapses the tools list" : "Expands the tools list")
                }
            }
            .navigationSplitViewColumnWidth(min: 210, ideal: 236, max: 260)
            .safeAreaInset(edge: .top) { SidebarBrand() }
            .safeAreaInset(edge: .bottom) { SidebarFooter() }
        } detail: {
            VStack(spacing: 0) {
                Group {
                if model.isDemo { DemoBanner() }
                if model.isOffline { OfflineBanner() }
                else if let err = model.lastError, model.mode == .live { ErrorBanner(message: err) }
                }
                .transition(.move(edge: .top).combined(with: .opacity))
                detail
                    .id(model.selection)
                    .transition(reduceMotion ? .opacity : .blurFade)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .background(AppBackdrop())
            .animation(.easeInOut(duration: reduceMotion ? 0.15 : 0.28), value: model.selection)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.22), value: model.isOffline)
            .animation(reduceMotion ? nil : .easeOut(duration: 0.22), value: model.lastError)
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
        VStack(alignment: .leading, spacing: 4) {
            Button { model.selection = destination } label: {
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Image(systemName: footerSymbol).foregroundStyle(footerTint).symbolRenderingMode(.hierarchical)
                        Text(footerTitle).font(.callout.weight(.medium))
                    }
                    if let detail = footerDetail {
                        Text(detail).font(.caption).foregroundStyle(.secondary)
                    }
                    if model.hasData, model.definitionsUpdated != nil {
                        Text("Definitions updated \(Fmt.ago(model.definitionsUpdated).lowercased())")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .help(destination == .threats ? "Review the items in Threats & Quarantine" : "Open the overview")
            .accessibilityHint(destination == .threats ? "Opens Threats and Quarantine" : "Opens the overview")

            if model.hasData && model.definitionsUpdated == nil {
                Button {
                    Task { await model.updateDefinitions() }
                } label: {
                    if model.isUpdatingDefinitions {
                        HStack(spacing: 4) { ProgressView().controlSize(.mini); Text("Updating definitions…") }
                    } else {
                        Label("Update definitions", systemImage: "arrow.down.circle")
                    }
                }
                .buttonStyle(.link).font(.caption)
                .disabled(model.isUpdatingDefinitions)
                .help("Definitions haven't been downloaded yet. This fetches the latest public threat lists.")
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.m)
        .overlay(alignment: .top) { Divider().opacity(0.5).padding(.horizontal, Spacing.l) }
    }
    private var destination: SidebarItem {
        if case .threat = model.overall { return .threats }
        return .dashboard
    }
    private var footerDetail: String? {
        switch model.overall {
        case .threat(let n): return n == 1 ? "1 item to review" : "\(n) items to review"
        case .limited: return "Needs Full Disk Access"
        case .recommendations(let n): return n == 1 ? "1 setting to review" : "\(n) settings to review"
        default: return nil
        }
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

/// Shared chrome so every banner above the detail pane looks and behaves the same.
private struct BannerChrome: ViewModifier {
    func body(content: Content) -> some View {
        content
            .padding(.horizontal, Spacing.l).padding(.vertical, 7)
            .frame(minHeight: 34)
            .background(.bar)
            .overlay(alignment: .bottom) { Divider() }
    }
}

private extension View { func bannerChrome() -> some View { modifier(BannerChrome()) } }

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
                .help("Try to reach the background service again")
        }
        .bannerChrome()
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
                .help(model.lastError ?? "Nothing is being checked right now.")
            Spacer()
            Button("Retry") { Task { await model.retry() } }
                .controlSize(.small)
                .help("Try to start the protection service again")
        }
        .bannerChrome()
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
        HStack(spacing: Spacing.s) {
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Color.statusAttention)
                .symbolRenderingMode(.hierarchical)
            Text(message).font(.callout).lineLimit(2).truncationMode(.tail)
                .textSelection(.enabled)
                .help(message)
            Spacer()
            Button("Dismiss") { model.lastError = nil }
                .controlSize(.small)
                .help("Hide this message")
        }
        .bannerChrome()
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Notice: \(message)")
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
                // Counts up in step with the ring as it draws (interpolated by SwiftUI's animation).
                CountingNumber(value: value)
                    .font(.system(size: size * 0.34, weight: .bold, design: .rounded))
                    .monospacedDigit()
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

/// A number that SwiftUI can animate: each animation frame gets the interpolated value.
struct CountingNumber: View, Animatable {
    var value: Double
    var animatableData: Double {
        get { value }
        set { value = newValue }
    }
    var body: some View { Text("\(Int(value.rounded()))") }
}

struct EmptyStateView: View {
    let symbol: String
    let title: String
    let detail: String
    var brand = false
    var actionTitle: String? = nil
    var action: (() -> Void)? = nil
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var appeared = false
    var body: some View {
        VStack(spacing: Spacing.m) {
            if brand {
                StatusMark(size: 64, badge: "checkmark.circle.fill", tint: .statusProtected)
            } else {
                Image(systemName: symbol).font(.system(size: 44)).foregroundStyle(.secondary).symbolRenderingMode(.hierarchical)
            }
            Text(title).font(.title3.weight(.medium))
            Text(detail).foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 380)
                .fixedSize(horizontal: false, vertical: true)
            if let actionTitle, let action {
                Button(actionTitle, action: action)
                    .controlSize(.regular)
                    .padding(.top, Spacing.xs)
            }
        }
        .opacity(appeared ? 1 : 0)
        .offset(y: appeared || reduceMotion ? 0 : 6)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .padding(Spacing.xxl)
        .accessibilityElement(children: actionTitle == nil ? .combine : .contain)
        .onAppear {
            if reduceMotion || Headless.active { appeared = true }
            else { withAnimation(.easeOut(duration: 0.3)) { appeared = true } }
        }
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
        .help(item == .threats && !model.openDetections.isEmpty
              ? "\(item.title): \(model.openDetections.count) open"
              : item.title)
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
