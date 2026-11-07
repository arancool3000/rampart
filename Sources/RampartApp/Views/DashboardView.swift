import SwiftUI
import Charts
import RampartShared

struct DashboardView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var showScoreInfo = false
    @StateVar private var confirmOff = false
    @StateVar private var showInstall = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("dashboard.basicCardDismissed") private var basicCardDismissed = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                hero
                if model.mode == .live && model.source == .basic && !basicCardDismissed { basicCard }
                if model.hasData {
                    tiles
                    if !model.daily.isEmpty && model.daily.contains(where: { $0.sitesBlocked + $0.threats > 0 }) { weekChart }
                }
                if model.hasData {
                    if !model.recommendations.isEmpty { recommendations }
                    recentActivity
                }
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
                         detail: model.source == .basic && model.mode == .live
                             ? "Basic protection is on. \(Product.name) checks new files and startup items without installing anything."
                             : (model.scanHistory.first.map { $0.found == 0 ? "Real-time protection is on. Your last scan found nothing." : "Real-time protection is on." } ?? "Real-time protection is on. Run a Quick Scan anytime for a full check."),
                         button: "Run Quick Scan", prominent: false)
        case .recommendations(let n):
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, title: "Your Mac is protected",
                         detail: "\(n) setting\(n == 1 ? "" : "s") could make your Mac more secure.", button: "Review", prominent: false)
        case .threat(let n):
            return .init(symbol: "xmark.shield.fill", tint: .statusAction, title: n == 1 ? "1 item needs your attention" : "\(n) items need your attention",
                         detail: "\(Product.name) stopped it. Choose what to do next.", button: "Review Item", prominent: true)
        case .off:
            return .init(symbol: "shield.slash", tint: .statusAction, title: "Real-time protection is off",
                         detail: "Files aren't being checked as they open.", button: "Turn On", prominent: true)
        case .limited:
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, title: "Protection is limited",
                         detail: "\(Product.name) can't check some folders without Full Disk Access.", button: "Grant Access…", prominent: true)
        case .starting:
            return .init(symbol: "shield.lefthalf.filled", tint: .rampartTeal, title: "Starting protection…",
                         detail: "\(Product.name) is starting its background checker. This takes a moment.", button: "Retry", prominent: false)
        case .serviceDown:
            return .init(symbol: "shield.slash", tint: .statusAction, title: "Protection service isn't running",
                         detail: model.lastError ?? "\(Product.name) couldn't start its background checker, so nothing is being checked right now.",
                         button: "Retry", prominent: true)
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
        case .limited: FullDiskAccessRequest.start()
        case .starting, .serviceDown: Task { await model.retry() }
        }
    }

    private var hero: some View {
        let h = heroContent
        let score = model.securityScore
        let isProtected: Bool = { if case .protected = model.overall { return true }; if case .recommendations = model.overall { return true }; return false }()
        return HStack(alignment: .center, spacing: Spacing.xl) {
            Group {
                if isProtected {
                    StatusMark(size: 118, badge: "checkmark.circle.fill", tint: .statusProtected)
                } else if case .serviceDown = model.overall {
                    StatusMark(size: 118, badge: "xmark.circle.fill", tint: .statusAction, dimmed: true)
                } else if case .starting = model.overall {
                    RamPartMark(size: 118)
                } else {
                    ShieldHero(symbol: h.symbol, tint: h.tint == .secondary ? .gray : h.tint, breathe: false, size: 132)
                }
            }
            .frame(width: 132, height: 132)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text(h.title)
                    .font(.largeTitle.weight(.bold)).fontDesign(.rounded)
                    .revealText(on: h.title, duration: 0.8)
                    .fixedSize(horizontal: false, vertical: true)
                Text(h.detail).font(.title3).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: Spacing.m) {
                    Group {
                        if h.prominent {
                            Button(h.button, action: heroAction).buttonStyle(GlowButtonStyle())
                        } else {
                            Button(h.button, action: heroAction).buttonStyle(.bordered)
                        }
                    }
                    .controlSize(.large)
                    if case .serviceDown = model.overall, DaemonLauncher.shared.helperMissing {
                        ReinstallButton().controlSize(.large)
                    }
                    Text("Definitions \(model.status.signatureVersion == "0" ? "" : model.status.signatureVersion + " · ")updated \(Fmt.ago(model.definitionsUpdated).lowercased())")
                        .font(.callout).foregroundStyle(.secondary)
                        .help(model.definitionsUpdated.map { "Definitions last updated \($0.formatted(date: .abbreviated, time: .shortened))" } ?? "Definitions haven't been updated yet")
                }
                .padding(.top, Spacing.s)
            }
            .accessibilityElement(children: .contain)
            Spacer(minLength: Spacing.l)
            if model.hasData {
            VStack(spacing: Spacing.s) {
                ScoreRing(score: score, size: 136, lineWidth: 13)
                HStack(spacing: 4) {
                    Text("Security Score").font(.headline).fontDesign(.rounded)
                    Button { showScoreInfo = true } label: { Image(systemName: "info.circle") }
                        .buttonStyle(.borderless)
                        .accessibilityLabel("How is this calculated?")
                        .popover(isPresented: $showScoreInfo, arrowEdge: .bottom) { ScoreExplainer() }
                }
                Text(AppModel.scoreLabel(score)).font(.callout.weight(.medium)).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel("Security score \(score) out of 100, \(AppModel.scoreLabel(score)). \(model.recommendations.count) recommendations.")
            .accessibilityAction(named: "How is this calculated?") { showScoreInfo = true }
            }
        }
        .card(padding: Spacing.xl, tint: h.tint == .secondary ? .gray : h.tint)
    }

    private var basicCard: some View {
        HStack(spacing: Spacing.l) {
            RamPartMark(size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text("Basic protection (no install)").font(.headline).fontDesign(.rounded)
                Text("\(Product.name) is checking files and startup items from your account. The optional system service adds web protection and system-wide monitoring.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            Button("Enable Full Protection…") { showInstall = true }.buttonStyle(GlowButtonStyle())
            Button { withAnimation(reduceMotion ? nil : .easeOut(duration: 0.2)) { basicCardDismissed = true } } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless).accessibilityLabel("Hide this card")
                .help("Hide this card. You can install full protection later from Settings.")
        }
        .card(tint: .rampartTeal)
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
    }

    // MARK: Tiles

    private var tiles: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: Spacing.l) { tileViews }.fixedSize(horizontal: false, vertical: true)
            VStack(spacing: Spacing.l) { tileViews }
        }
    }

    @ViewBuilder private var tileViews: some View {
        let rtOn = model.status.realtimeOn && model.pausedUntil == nil
        StatusTile(symbol: rtOn ? "checkmark.shield.fill" : "shield.slash", tint: rtOn ? .statusProtected : .statusAction,
                   title: "Real-time protection",
                   value: model.pausedUntil != nil ? "Paused" : (rtOn ? "On" : "Off"),
                   caption: model.daily.last.map { "\(Fmt.count($0.filesChecked)) files checked today" }) {
            Toggle("Real-time protection", isOn: Binding(
                get: { model.status.realtimeOn && model.pausedUntil == nil },
                set: { on in if on { model.setRealtime(true) } else { confirmOff = true } }))
                .toggleStyle(.switch).labelsHidden().controlSize(.small)
                .help(rtOn ? "Turn real-time protection off (asks first)" : "Turn real-time protection on")
        } chart: {
            if model.filesLast14.contains(where: { $0 > 0 }) { Sparkline(values: model.filesLast14, tint: .statusProtected) }
        }
        StatusTile(symbol: "magnifyingglass", tint: .rampartTeal, title: "Last scan", value: lastScanText,
                   caption: model.scanHistory.first.map { "\(Fmt.count($0.scanned)) files in \(Fmt.duration($0.seconds))" }) {
            Button(model.isScanning ? "Scanning…" : "Scan Now") { model.selection = .scan; model.startScan(.quick) }
                .buttonStyle(.link).disabled(model.isScanning)
                .help("Run a Quick Scan (⌘R)")
        } chart: {
            if !model.scanHistory.isEmpty {
                // One pill per recent scan, oldest to newest: green = clean, grey = items found and contained.
                HStack(spacing: 5) {
                    ForEach(Array(model.scanHistory.prefix(8).reversed())) { r in
                        Capsule().fill(r.found == 0 ? Color.statusProtected.opacity(0.85) : Color.gray.opacity(0.6))
                            .frame(height: 10)
                    }
                }
                .frame(maxHeight: .infinity, alignment: .bottom)
                .accessibilityHidden(true)
            }
        }
        StatusTile(symbol: "globe", tint: .statusInfo, title: "Web protection",
                   value: model.status.webProtectionOn ? "\(model.blockedThisMonth) blocked this month" : "Off",
                   caption: model.status.webProtectionOn ? "\(model.blockedToday) today" : nil) {
            Button("Details") { model.selection = .network }.buttonStyle(.link)
                .help("Open Network to see blocked sites")
        } chart: {
            if model.blockedLast7.contains(where: { $0 > 0 }) { MiniBars(values: model.blockedLast7, tint: .statusInfo) }
        }
    }

    private var weekChart: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Last 14 days")
            VStack(alignment: .leading, spacing: Spacing.m) {
                Chart {
                    ForEach(model.daily) { d in
                        BarMark(x: .value("Day", d.day, unit: .day), y: .value("Count", d.sitesBlocked))
                            .foregroundStyle(by: .value("Kind", "Dangerous sites blocked"))
                        BarMark(x: .value("Day", d.day, unit: .day), y: .value("Count", d.threats))
                            .foregroundStyle(by: .value("Kind", "Threats stopped"))
                    }
                }
                .chartForegroundStyleScale(["Dangerous sites blocked": Color.rampartTeal, "Threats stopped": Palette.amber])
                .chartLegend(position: .top, alignment: .leading)
                .chartXAxis { AxisMarks(values: .stride(by: .day, count: 2)) { _ in AxisValueLabel(format: .dateTime.weekday(.abbreviated)) } }
                .chartYAxis { AxisMarks(position: .trailing, values: .automatic(desiredCount: 3)) }
                .frame(height: 150)
                .accessibilityLabel("Chart of dangerous sites blocked and threats stopped over the last 14 days")
            }
            .card()
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
                    HStack(spacing: Spacing.m) {
                        Image(systemName: "list.bullet.rectangle").foregroundStyle(.tertiary).font(.title3)
                            .accessibilityHidden(true)
                        Text(model.mode == .live ? "Nothing yet. Run a Quick Scan and \(Product.name) will list what it checks here." : "Nothing yet. \(Product.name) will list what it checks and blocks here.")
                            .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                        if model.mode == .live {
                            Button("Run Quick Scan") { model.selection = .scan; model.startScan(.quick) }
                                .disabled(model.isScanning)
                        }
                    }
                    .padding(Spacing.m)
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

struct StatusTile<Accessory: View, ChartContent: View>: View {
    let symbol: String
    let tint: Color
    let title: String
    let value: String
    var caption: String? = nil
    @ViewBuilder var accessory: Accessory
    @ViewBuilder var chart: ChartContent
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack {
                IconBadge(symbol: symbol, tint: tint, size: 34)
                Spacer()
                accessory
            }
            Text(title).font(.callout.weight(.medium)).foregroundStyle(.secondary).padding(.top, 2)
            Text(value).font(.title3.weight(.semibold)).fontDesign(.rounded)
                .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            if let caption { Text(caption).font(.caption).foregroundStyle(.secondary).monospacedDigit() }
            Spacer(minLength: 0)
            chart.frame(height: 34)
        }
        .frame(minWidth: 200, maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
        .card()
        .modifier(MagneticTilt())
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(title): \(value)\(caption.map { ". " + $0 } ?? "")")
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
    @StateVar private var hovering = false
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: item.kind.symbol).foregroundStyle(.secondary).frame(width: 22)
            Text(item.title).lineLimit(1).truncationMode(.middle)
            Spacer()
            Text(item.outcome).font(.callout).foregroundStyle(.secondary)
            Text(Fmt.ago(item.date)).font(.callout).foregroundStyle(.tertiary).frame(minWidth: 90, alignment: .trailing)
                .help(item.date.formatted(date: .abbreviated, time: .standard))
        }
        .contentShape(Rectangle())
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(hovering ? 0.04 : 0)).padding(-4))
        .onHover { hovering = $0 }
        .help(item.title)
        .accessibilityElement(children: .combine)
    }
}
