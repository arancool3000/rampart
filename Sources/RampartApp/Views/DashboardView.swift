import SwiftUI
import Charts
import RampartShared

/// Overview. Order of attention: the hero (am I safe?), "Needs you" (what should I do?), live numbers,
/// then every tool as a tile. Motion is limited to counting numbers, a text reveal and hover highlights:
/// nothing bounces, nothing tilts (3D tilt once made tiles unclickable).
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
            VStack(alignment: .leading, spacing: DS.Space.xl) {
                hero
                if model.hasData { needsYou }
                if model.mode == .live && model.source == .basic && !basicCardDismissed { basicCard }
                DesktopInviteCard()
                if model.hasData { tiles }
                featureGrid
                if model.hasData {
                    if !model.daily.isEmpty && model.daily.contains(where: { $0.sitesBlocked + $0.threats > 0 }) { weekChart }
                    recentActivity
                }
                if model.mode == .live { ProtectEverythingView() }
            }
            .frame(maxWidth: 980).frame(maxWidth: .infinity)
            .padding(.horizontal, DS.Space.xl).padding(.vertical, DS.Space.xl)
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

    private struct HeroContent { let symbol: String; let tint: Color; let eyebrow: String; let title: String; let detail: String; let button: String; let prominent: Bool }

    private var heroContent: HeroContent {
        switch model.overall {
        case .protected:
            return .init(symbol: "checkmark.shield.fill", tint: .statusProtected, eyebrow: "All clear", title: "Your Mac is protected",
                         detail: model.source == .basic && model.mode == .live
                             ? "Basic protection is on. \(Product.name) checks new files and startup items without installing anything."
                             : (model.scanHistory.first.map { $0.found == 0 ? "Real-time protection is on. Your last scan found nothing." : "Real-time protection is on." } ?? "Real-time protection is on. Run a Quick Scan anytime for a full check."),
                         button: "Run Quick Scan", prominent: false)
        case .recommendations(let n):
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, eyebrow: "Protected", title: "Your Mac is protected",
                         detail: "\(n) setting\(n == 1 ? "" : "s") could make your Mac more secure.", button: "Review", prominent: false)
        case .threat(let n):
            return .init(symbol: "xmark.shield.fill", tint: .statusAction, eyebrow: "Needs you", title: n == 1 ? "1 item needs your attention" : "\(n) items need your attention",
                         detail: "\(Product.name) stopped it. Choose what to do next.", button: "Review Item", prominent: true)
        case .off:
            return .init(symbol: "shield.slash", tint: .statusAction, eyebrow: "Protection off", title: "Real-time protection is off",
                         detail: "Files aren't being checked as they open.", button: "Turn On", prominent: true)
        case .limited:
            return .init(symbol: "exclamationmark.shield.fill", tint: .statusAttention, eyebrow: "Limited", title: "Limited scanning",
                         detail: "\(Product.name) needs Full Disk Access to scan everything, including inside apps and your Library. Turn on the switch next to \(Product.name).", button: "Grant Full Disk Access…", prominent: true)
        case .starting:
            return .init(symbol: "shield.lefthalf.filled", tint: .rampartTeal, eyebrow: "Starting", title: "Starting protection…",
                         detail: "\(Product.name) is starting its background checker. This takes a moment.", button: "Retry", prominent: false)
        case .serviceDown:
            return .init(symbol: "shield.slash", tint: .statusAction, eyebrow: "Not running", title: "Protection service isn't running",
                         detail: model.lastError ?? "\(Product.name) couldn't start its background checker, so nothing is being checked right now.",
                         button: "Retry", prominent: true)
        case .paused(let until):
            return .init(symbol: "pause.circle.fill", tint: .secondary, eyebrow: "Paused", title: "Protection paused",
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
        let tint = h.tint == .secondary ? Color.gray : h.tint
        let score = model.securityScore
        let isProtected: Bool = { if case .protected = model.overall { return true }; if case .recommendations = model.overall { return true }; return false }()
        return VStack(alignment: .leading, spacing: DS.Space.l) {
            HStack(alignment: .center, spacing: DS.Space.xl) {
                Group {
                    if isProtected {
                        StatusMark(size: 118, badge: "checkmark.circle.fill", tint: .statusProtected)
                    } else if case .serviceDown = model.overall {
                        StatusMark(size: 118, badge: "xmark.circle.fill", tint: .statusAction, dimmed: true)
                    } else if case .starting = model.overall {
                        RamPartMark(size: 118)
                    } else {
                        ShieldHero(symbol: h.symbol, tint: tint, breathe: false, size: 132)
                    }
                }
                .frame(width: 132, height: 132)
                VStack(alignment: .leading, spacing: DS.Space.s) {
                    Text(h.eyebrow.uppercased()).font(DS.Font.eyebrow).tracking(1.4).foregroundStyle(tint)
                    Text(h.title)
                        .font(DS.Font.display)
                        .revealText(on: h.title, duration: 0.8)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(h.detail).font(.title3).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack(spacing: DS.Space.m) {
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
                    }
                    .padding(.top, DS.Space.xs)
                }
                .accessibilityElement(children: .contain)
                Spacer(minLength: DS.Space.l)
                if model.hasData {
                    VStack(spacing: DS.Space.s) {
                        ScoreRing(score: score, size: 140, lineWidth: 13)
                        HStack(spacing: 4) {
                            Text("Security Score").font(DS.Font.headline)
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
            heroChips
        }
        .padding(DS.Space.xl)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background { HeroGlow(tint: tint) }
        .card(padding: 0, tint: tint)
    }

    /// One line of facts under the hero: protection, web, last scan, definitions.
    private var heroChips: some View {
        let rtOn = model.status.realtimeOn && model.pausedUntil == nil
        return ViewThatFits(in: .horizontal) {
            HStack(spacing: DS.Space.s) { chipViews(rtOn: rtOn); Spacer(minLength: 0) }
            VStack(alignment: .leading, spacing: DS.Space.s) { chipViews(rtOn: rtOn) }
        }
    }

    @ViewBuilder private func chipViews(rtOn: Bool) -> some View {
        if model.hasData {
            HeroChip(symbol: rtOn ? "bolt.shield.fill" : "shield.slash", text: model.pausedUntil != nil ? "Real-time paused" : (rtOn ? "Real-time on" : "Real-time off"), tint: rtOn ? .statusProtected : .statusAction)
            HeroChip(symbol: "globe", text: model.status.webProtectionOn ? "Web protection on" : "Web protection off", tint: model.status.webProtectionOn ? .statusProtected : .secondary)
            HeroChip(symbol: "magnifyingglass", text: "Last scan " + (model.scanHistory.first.map { Fmt.ago($0.date).lowercased() } ?? (model.status.lastScan.map { Fmt.ago($0).lowercased() } ?? "never")), tint: .rampartTeal)
        }
        HeroChip(symbol: "arrow.triangle.2.circlepath", text: "Definitions \(model.status.signatureVersion == "0" ? "" : model.status.signatureVersion + " · ")updated \(Fmt.ago(model.definitionsUpdated).lowercased())", tint: .secondary)
            .help(model.definitionsUpdated.map { "Definitions last updated \($0.formatted(date: .abbreviated, time: .shortened))" } ?? "Definitions haven't been updated yet")
    }

    private var basicCard: some View {
        HStack(spacing: DS.Space.l) {
            RamPartMark(size: 40)
            VStack(alignment: .leading, spacing: 2) {
                Text("Basic protection (no install)").font(DS.Font.headline)
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

    // MARK: Needs you

    private var needsYou: some View {
        let threats = Array(model.openDetections.prefix(3))
        let recs = Array(model.recommendations.prefix(3))
        let total = model.needsYouCount + model.recommendations.count
        return VStack(alignment: .leading, spacing: DS.Space.m) {
            SectionHeader("Needs you", trailing: AnyView(HStack(spacing: DS.Space.m) {
                if total > 0 { Badge(text: "\(total)", tint: model.needsYouCount > 0 ? .statusAction : .statusAttention) }
                if model.recommendations.count > 0 {
                    Button("See all in Privacy & Posture") { model.selection = .posture }.buttonStyle(.link)
                }
            }))
            if threats.isEmpty && recs.isEmpty {
                HStack(spacing: DS.Space.m) {
                    Image(systemName: "checkmark.seal.fill").font(.title2).foregroundStyle(Color.statusProtected).symbolRenderingMode(.hierarchical)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Nothing needs you right now").font(DS.Font.headline)
                        Text("\(Product.name) keeps watching in the background and will tell you if something changes.").font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer(minLength: 0)
                }
                .card()
            } else {
                VStack(spacing: 0) {
                    ForEach(Array(threats.enumerated()), id: \.element.id) { idx, d in
                        if idx > 0 { Divider() }
                        NeedsYouThreatRow(detection: d)
                    }
                    if !threats.isEmpty && !recs.isEmpty { Divider() }
                    ForEach(Array(recs.enumerated()), id: \.element.id) { idx, c in
                        if idx > 0 { Divider() }
                        RecommendationRow(check: c)
                    }
                }
                .card(padding: DS.Space.s, tint: threats.isEmpty ? nil : .statusAction)
            }
        }
    }

    // MARK: Tiles

    private var tiles: some View {
        ViewThatFits(in: .horizontal) {
            HStack(alignment: .top, spacing: DS.Space.l) { tileViews }.fixedSize(horizontal: false, vertical: true)
            VStack(spacing: DS.Space.l) { tileViews }
        }
    }

    @ViewBuilder private var tileViews: some View {
        let rtOn = model.status.realtimeOn && model.pausedUntil == nil
        StatusTile(symbol: rtOn ? "checkmark.shield.fill" : "shield.slash", tint: rtOn ? .statusProtected : .statusAction,
                   title: "Real-time protection",
                   value: model.pausedUntil != nil ? "Paused" : (rtOn ? "On" : "Off"),
                   caption: model.daily.last.map { "\(Fmt.count($0.filesChecked)) files checked today" },
                   number: model.daily.last?.filesChecked, unit: "files checked today") {
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
                   caption: model.status.webProtectionOn ? "\(model.blockedToday) today" : nil,
                   number: model.status.webProtectionOn ? model.blockedThisMonth : nil, unit: "blocked this month") {
            Button("Details") { model.selection = .network }.buttonStyle(.link)
                .help("Open Network to see blocked sites")
        } chart: {
            if model.blockedLast7.contains(where: { $0 > 0 }) { MiniBars(values: model.blockedLast7, tint: .statusInfo) }
        }
    }

    // MARK: Feature tiles

    private struct Feature: Identifiable { let item: SidebarItem; let subtitle: String; let tint: Color; var id: String { item.rawValue } }
    private static let features: [Feature] = [
        Feature(item: .emergency, subtitle: "Lockdown and the Super Kill Switch", tint: Palette.coral),
        Feature(item: .catAndMouse, subtitle: "Decoys that catch snoops", tint: Palette.amber),
        Feature(item: .scamCheck, subtitle: "Is this link or message a scam?", tint: .orange),
        Feature(item: .passwords, subtitle: "Your encrypted password vault", tint: Palette.teal),
        Feature(item: .authenticator, subtitle: "Two-factor codes", tint: Palette.mint),
        Feature(item: .passwordChecker, subtitle: "Strength and breach check", tint: .green),
        Feature(item: .networkScan, subtitle: "Devices on your network", tint: .blue),
        Feature(item: .aiAssistant, subtitle: "Ask about your Mac's security", tint: .purple),
        Feature(item: .remoteAccess, subtitle: "Who can control this Mac", tint: .indigo),
        Feature(item: .refreshSmart, subtitle: "Clean up and speed up", tint: Color(red: 0.55, green: 0.55, blue: 1.0)),
    ]

    private var featureGrid: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            SectionHeader("Tools")
            LazyVGrid(columns: [GridItem(.adaptive(minimum: 200), spacing: DS.Space.m)], spacing: DS.Space.m) {
                ForEach(Self.features) { f in
                    FeatureTile(id: f.item.rawValue, symbol: f.item == .refreshSmart ? "sparkles.rectangle.stack" : f.item.symbol, tint: f.tint,
                                title: f.item == .refreshSmart ? "Refresh" : f.item.title, subtitle: f.subtitle) { model.selection = f.item }
                }
                FeatureTile(id: "desktopMode", symbol: "menubar.dock.rectangle", tint: .rampartTeal,
                            title: DesktopMode.shared.isOn ? "Desktop Mode · On" : "Desktop Mode",
                            subtitle: DesktopMode.shared.isOn ? "Click to turn off (\(DesktopMode.shortcutLabel))" : "Your desktop as a command centre") {
                    DesktopMode.shared.toggle()
                }
            }
        }
    }

    private var weekChart: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            SectionHeader("Last 14 days")
            VStack(alignment: .leading, spacing: DS.Space.m) {
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

    // MARK: Activity

    private var recentActivity: some View {
        VStack(alignment: .leading, spacing: DS.Space.m) {
            SectionHeader("Recent activity", trailing: AnyView(
                Button("Show All") { model.selection = .activity }.buttonStyle(.link)))
            VStack(spacing: 0) {
                if model.activity.isEmpty {
                    HStack(spacing: DS.Space.m) {
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
                    .padding(DS.Space.m)
                }
                ForEach(Array(model.activity.prefix(5).enumerated()), id: \.element.id) { idx, a in
                    if idx > 0 { Divider() }
                    ActivityRow(item: a).padding(.vertical, DS.Space.s).padding(.horizontal, DS.Space.s)
                }
            }
            .card(padding: DS.Space.s)
        }
    }
}

/// Soft colour wash behind the hero (static; costs nothing at idle).
struct HeroGlow: View {
    let tint: Color
    @Environment(\.colorScheme) private var scheme
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    var body: some View {
        if !reduceTransparency {
            ZStack {
                RadialGradient(colors: [tint.opacity(scheme == .dark ? 0.30 : 0.18), .clear], center: UnitPoint(x: 0.08, y: 0.3), startRadius: 0, endRadius: 360)
                RadialGradient(colors: [Palette.teal.opacity(scheme == .dark ? 0.18 : 0.10), .clear], center: UnitPoint(x: 0.92, y: 0.2), startRadius: 0, endRadius: 300)
            }
            .clipShape(RoundedRectangle(cornerRadius: DS.Radius.card, style: .continuous))
            .allowsHitTesting(false)
            .accessibilityHidden(true)
        }
    }
}

struct HeroChip: View {
    let symbol: String
    let text: String
    let tint: Color
    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
            Text(text).foregroundStyle(.primary).lineLimit(1)
        }
        .font(.callout)
        .padding(.horizontal, 10).padding(.vertical, 5)
        .background(Color.primary.opacity(0.05), in: Capsule())
        .overlay(Capsule().strokeBorder(Color.primary.opacity(0.08)))
        .accessibilityElement(children: .combine)
    }
}

/// A threat that needs the user, with one clear next step.
struct NeedsYouThreatRow: View {
    let detection: Detection
    @Environment(AppModel.self) private var model
    var body: some View {
        HStack(spacing: DS.Space.m) {
            Image(systemName: detection.severity.symbol).foregroundStyle(detection.severity.tint)
                .symbolRenderingMode(.hierarchical).font(.title3).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                Text(detection.name).font(.body.weight(.medium)).lineLimit(1)
                Text((detection.path.map { ($0 as NSString).lastPathComponent + " · " } ?? "") + detection.category.label)
                    .font(.callout).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Text(Fmt.ago(detection.date)).font(.callout).foregroundStyle(.tertiary)
            Button("Review") { model.selection = .threats }.buttonStyle(GlowButtonStyle(tint: .statusAction))
        }
        .padding(DS.Space.s)
        .accessibilityElement(children: .combine)
    }
}

/// A whole-tile button for a feature. Hover brightens the border; press dims. No tilt, no bounce, and the
/// entire rounded rectangle is the hit area.
struct FeatureTile: View {
    let id: String
    let symbol: String
    let tint: Color
    let title: String
    let subtitle: String
    let action: () -> Void
    var body: some View {
        Button(action: action) {
            HStack(spacing: DS.Space.m) {
                IconBadge(symbol: symbol, tint: tint, size: 38)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(.body.weight(.semibold)).fontDesign(.monospaced).lineLimit(1)
                    Text(subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(2).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
                Image(systemName: "chevron.right").font(.caption.weight(.semibold)).foregroundStyle(.tertiary)
            }
            .frame(maxWidth: .infinity, minHeight: 48, alignment: .leading)
            .card(padding: DS.Space.m)
            .contentShape(RoundedRectangle(cornerRadius: DS.Radius.card, style: .continuous))
        }
        .buttonStyle(FeatureTileStyle())
        .accessibilityLabel(title)
        .accessibilityHint(subtitle)
        .background(HitProbe.Reporter(id: id))
    }
}

struct FeatureTileStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { TileBody(configuration: configuration) }
    struct TileBody: View {
        let configuration: Configuration
        @StateVar private var hover = false
        @Environment(\.accessibilityReduceMotion) private var reduceMotion
        var body: some View {
            configuration.label
                .overlay {
                    RoundedRectangle(cornerRadius: DS.Radius.card, style: .continuous)
                        .strokeBorder(Color.rampartTeal.opacity(hover ? 0.55 : 0), lineWidth: 1.5)
                        .allowsHitTesting(false)
                }
                .brightness(hover ? 0.02 : 0)
                .opacity(configuration.isPressed ? 0.8 : 1)
                .onHover { hover = $0 }
                .animation(reduceMotion ? nil : .easeOut(duration: 0.15), value: hover)
        }
    }
}

struct StatusTile<Accessory: View, ChartContent: View>: View {
    let symbol: String
    let tint: Color
    let title: String
    let value: String
    var caption: String? = nil
    /// When set, the value is shown as a number that counts up, followed by `unit`.
    var number: Int? = nil
    var unit: String = ""
    @ViewBuilder var accessory: Accessory
    @ViewBuilder var chart: ChartContent
    var body: some View {
        VStack(alignment: .leading, spacing: DS.Space.s) {
            HStack {
                IconBadge(symbol: symbol, tint: tint, size: 34)
                Spacer()
                accessory
            }
            Text(title).font(.callout.weight(.medium)).foregroundStyle(.secondary).padding(.top, 2)
            if let number {
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    CountUpNumber(value: number).font(DS.Font.metric)
                    Text(unit).font(.callout).foregroundStyle(.secondary).lineLimit(1)
                }
                if value == "On" || value == "Off" || value == "Paused" { Text(value).font(.caption.weight(.semibold)).foregroundStyle(tint) }
            } else {
                Text(value).font(.title3.weight(.semibold)).fontDesign(.monospaced)
                    .lineLimit(2).fixedSize(horizontal: false, vertical: true)
            }
            if let caption, number == nil || !caption.contains(unit) { Text(caption).font(.caption).foregroundStyle(.secondary).monospacedDigit() }
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
