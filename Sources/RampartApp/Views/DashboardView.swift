import SwiftUI
import RampartShared

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var showScoreInfo = false
    @StateVar private var confirmOff = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                hero
                tiles
                if !model.recommendations.isEmpty { recommendations }
                recentActivity
            }
            .contentColumn()
        }
        .navigationTitle("Overview")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { model.selection = .scan; model.startScan(.quick) } label: {
                    Label("Quick Scan", systemImage: "bolt")
                }
                .primaryActionStyle()
                .disabled(model.isScanning)
                .help("Run a Quick Scan (⌘R)")
            }
        }
        .confirmationDialog("Turn off real-time protection?", isPresented: $confirmOff) {
            Button("For 15 minutes") { model.setRealtime(false, pauseFor: 15) }
            Button("For 1 hour") { model.setRealtime(false, pauseFor: 60) }
            Button("Until I turn it on", role: .destructive) { model.setRealtime(false) }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Files won't be checked as they open. Choose how long:")
        }
    }

    // MARK: Hero

    private struct HeroContent { let symbol: String; let tint: Color; let title: String; let detail: String; let button: String; let prominent: Bool }

    private var heroContent: HeroContent {
        switch model.overall {
        case .protected:
            return .init(symbol: "checkmark.shield.fill", tint: .statusProtected, title: "Your Mac is protected",
                         detail: "Real-time protection is on. Last scan found nothing.", button: "Run Quick Scan", prominent: false)
        case .recommendations(let n):
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, title: "Your Mac is protected",
                         detail: "\(n) setting\(n == 1 ? "" : "s") could make your Mac more secure.", button: "Review", prominent: false)
        case .threat(let n):
            return .init(symbol: "xmark.shield.fill", tint: .statusAction, title: n == 1 ? "1 item needs your attention" : "\(n) items need your attention",
                         detail: "Rampart stopped it. Choose what to do next.", button: "Review Item", prominent: true)
        case .off:
            return .init(symbol: "shield.slash", tint: .statusAction, title: "Real-time protection is off",
                         detail: "Files aren't being checked as they open.", button: "Turn On", prominent: true)
        case .limited:
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, title: "Protection is limited",
                         detail: "Rampart can't check some folders without Full Disk Access.", button: "Grant Access…", prominent: true)
        case .paused(let until):
            return .init(symbol: "pause.circle.fill", tint: .secondary, title: "Protection paused",
                         detail: "Resumes automatically at \(until.formatted(date: .omitted, time: .shortened)).", button: "Resume Now", prominent: true)
        }
    }

    private func heroAction() {
        switch model.overall {
        case .protected: model.selection = .scan; model.startScan(.quick)
        case .recommendations: model.selection = .posture
        case .threat: model.selection = .threats
        case .off, .paused: model.setRealtime(true)
        case .limited: openURL(FDAProbe.settingsURL)
        }
    }

    private var hero: some View {
        let h = heroContent
        let score = model.securityScore
        return HStack(alignment: .center, spacing: Spacing.xl) {
            VStack(alignment: .leading, spacing: Spacing.m) {
                Image(systemName: h.symbol)
                    .font(.system(size: 56))
                    .symbolRenderingMode(.hierarchical)
                    .foregroundStyle(h.tint)
                    .accessibilityHidden(true)
                Text(h.title).font(.largeTitle).fontWeight(.semibold)
                Text(h.detail).font(.title3).foregroundStyle(.secondary)
                Group {
                    if h.prominent {
                        Button(h.button, action: heroAction).buttonStyle(.borderedProminent)
                    } else {
                        Button(h.button, action: heroAction).buttonStyle(.bordered)
                    }
                }
                .controlSize(.large)
                .padding(.top, Spacing.xs)
            }
            .accessibilityElement(children: .contain)
            Spacer(minLength: Spacing.l)
            VStack(spacing: Spacing.s) {
                ScoreRing(score: score)
                HStack(spacing: 4) {
                    Text("Security Score").font(.headline)
                    Button { showScoreInfo = true } label: { Image(systemName: "info.circle") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("How is this calculated?")
                        .popover(isPresented: $showScoreInfo, arrowEdge: .bottom) { ScoreExplainer() }
                }
                Text(AppModel.scoreLabel(score)).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Security score \(score) out of 100, \(AppModel.scoreLabel(score)). \(model.recommendations.count) recommendations.")
            .accessibilityAction(named: "How is this calculated?") { showScoreInfo = true }
        }
        .card(padding: Spacing.xl)
    }

    // MARK: Tiles

    private var tiles: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: Spacing.l) { tileViews }
            VStack(spacing: Spacing.l) { tileViews }
        }
    }

    @ViewBuilder private var tileViews: some View {
        @Bindable var model = model
        StatusTile(symbol: model.status.realtimeOn && model.pausedUntil == nil ? "checkmark.shield" : "shield.slash",
                   tint: model.status.realtimeOn && model.pausedUntil == nil ? .statusProtected : .statusAction,
                   title: "Real-time protection",
                   value: model.pausedUntil != nil ? "Paused" : (model.status.realtimeOn ? "On" : "Off")) {
            Toggle("Real-time protection", isOn: Binding(
                get: { model.status.realtimeOn && model.pausedUntil == nil },
                set: { on in if on { model.setRealtime(true) } else { confirmOff = true } }))
                .toggleStyle(.switch).labelsHidden().controlSize(.small)
                .disabled(model.mode == .live)
                .help(model.mode == .live ? "Real-time protection is managed by the background service." : "")
        }
        StatusTile(symbol: "magnifyingglass", tint: .statusInfo, title: "Last scan",
                   value: lastScanText) {
            Button("Scan Now") { model.selection = .scan; model.startScan(.quick) }
                .buttonStyle(.link).disabled(model.isScanning)
        }
        StatusTile(symbol: "arrow.triangle.2.circlepath", tint: .statusInfo, title: "Definitions",
                   value: "Up to date · \(Fmt.ago(model.definitionsUpdated))") {
            if model.isUpdatingDefinitions { ProgressView().controlSize(.small) }
            else { Button("Check Now") { Task { await model.updateDefinitions() } }.buttonStyle(.link) }
        }
    }

    private var lastScanText: String {
        if let r = model.scanHistory.first {
            return "\(Fmt.dayTime(r.date)) · \(r.found == 0 ? "No threats found" : "\(r.found) found")"
        }
        if let d = model.status.lastScan { return Fmt.dayTime(d) }
        return "Not yet"
    }

    // MARK: Recommendations

    private var recommendations: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Recommendations", trailing: AnyView(
                Button("See all in Privacy & Posture") { model.selection = .posture }.buttonStyle(.link)))
            VStack(spacing: 0) {
                ForEach(Array(model.recommendations.prefix(3).enumerated()), id: \.element.id) { idx, c in
                    if idx > 0 { Divider() }
                    RecommendationRow(check: c)
                }
            }
            .card(padding: Spacing.s)
        }
    }

    // MARK: Activity

    private var recentActivity: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Recent activity", trailing: AnyView(
                Button("Show All") { model.selection = .activity }.buttonStyle(.link)))
            VStack(spacing: 0) {
                if model.activity.isEmpty {
                    Text("Nothing yet. Rampart will list what it checks and blocks here.")
                        .foregroundStyle(.secondary).padding(Spacing.m)
                }
                ForEach(Array(model.activity.prefix(5).enumerated()), id: \.element.id) { idx, a in
                    if idx > 0 { Divider() }
                    ActivityRow(item: a).padding(.vertical, Spacing.s).padding(.horizontal, Spacing.s)
                }
            }
            .card(padding: Spacing.s)
        }
    }
}

struct StatusTile<Accessory: View>: View {
    let symbol: String
    let tint: Color
    let title: String
    let value: String
    @ViewBuilder var accessory: Accessory
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack {
                Image(systemName: symbol).foregroundStyle(tint).symbolRenderingMode(.hierarchical).font(.title2)
                Spacer()
                accessory
            }
            Text(title).font(.callout).foregroundStyle(.secondary)
            Text(value).font(.title3.weight(.medium)).lineLimit(2).fixedSize(horizontal: false, vertical: true)
        }
        .frame(minWidth: 200, maxWidth: .infinity, minHeight: 96, alignment: .topLeading)
        .card()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)")
    }
}

struct RecommendationRow: View {
    let check: PostureCheck
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: PostureView.symbol(for: check)).foregroundStyle(Color.statusAttention)
                .symbolRenderingMode(.hierarchical).font(.title3).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(check.title).font(.body.weight(.medium))
                Text(check.detail).font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if model.fixingChecks.contains(check.id) {
                ProgressView().controlSize(.small)
            } else if check.fixable {
                Button("Fix") { Task { await model.fix(check) } }
            } else {
                Button("How to Fix") { model.selection = .posture }
            }
            Menu {
                Button("Ignore this recommendation") { model.ignoredChecks.insert(check.id) }
                Button("Hide from Overview") { model.dismissedRecommendations.insert(check.id) }
            } label: { Image(systemName: "xmark") }
                .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                .accessibilityLabel("Dismiss \(check.title)")
        }
        .padding(Spacing.s)
    }
}

struct ScoreExplainer: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("How is this calculated?").font(.headline)
            Text("Your score reflects settings you can change on this Mac. It never depends on what you've bought.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Divider()
            ForEach(model.scoreBreakdown) { item in
                HStack(spacing: Spacing.s) {
                    Image(systemName: item.earned ? "checkmark.circle.fill" : "circle")
                        .foregroundStyle(item.earned ? Color.statusProtected : Color.secondary)
                    Text(item.title)
                    Spacer()
                    if item.earned {
                        Text("+\(item.weight)").monospacedDigit().foregroundStyle(.secondary)
                    } else {
                        Button("Fix (+\(item.weight))") { model.selection = item.target }.buttonStyle(.link)
                    }
                }
                .font(.callout)
                .accessibilityElement(children: .combine)
            }
        }
        .padding(Spacing.l)
        .frame(width: 400)
    }
}

struct ActivityRow: View {
    let item: ActivityItem
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: item.kind.symbol).foregroundStyle(.secondary).frame(width: 22)
            Text(item.title).lineLimit(1).truncationMode(.middle)
            Spacer()
            Text(item.outcome).font(.callout).foregroundStyle(.secondary)
            Text(Fmt.ago(item.date)).font(.callout).foregroundStyle(.tertiary).frame(minWidth: 90, alignment: .trailing)
        }
        .accessibilityElement(children: .combine)
    }
}
