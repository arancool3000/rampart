import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RampartShared

struct ScanView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var choice: ScanKind = .quick
    @StateVar private var customPaths: [String] = []
    @StateVar private var dropTargeted = false

    var body: some View {
        Group {
            switch model.scanPhase {
            case .idle: idle
            case .running(let p): RunningScanView(progress: p)
            case .finished(let rec, let found): ScanResultView(record: rec, found: found)
            }
        }
        .navigationTitle("Scan")
    }

    private var idle: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 220), spacing: Spacing.l)], spacing: Spacing.l) {
                    ForEach(ScanKind.allCases) { kind in
                        ScanChoiceCard(kind: kind, selected: choice == kind, targeted: kind == .custom && dropTargeted,
                                       subtitle: kind == .custom && !customPaths.isEmpty ? customSummary : nil)
                            .onTapGesture { choice = kind; if kind == .custom && customPaths.isEmpty { pickFolders() } }
                            .accessibilityAddTraits(choice == kind ? [.isButton, .isSelected] : .isButton)
                            .accessibilityAction { choice = kind }
                    }
                }

                HStack(spacing: Spacing.m) {
                    Button { start() } label: {
                        Label("Start \(choice.title)", systemImage: "play.fill").frame(minWidth: 160)
                    }
                    .buttonStyle(GlowButtonStyle()).controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                    .disabled(choice == .custom && customPaths.isEmpty)
                    if choice == .custom {
                        Button("Choose…") { pickFolders() }.controlSize(.large)
                            .help("Pick files, folders or drives to check")
                        if !customPaths.isEmpty {
                            Button("Clear") { withAnimation(.easeOut(duration: 0.15)) { customPaths = [] } }
                                .buttonStyle(.link)
                                .help("Remove the chosen items")
                        }
                    }
                    Spacer()
                    if choice == .custom {
                        Text("Tip: drop files or folders anywhere in this window.")
                            .font(.caption).foregroundStyle(.tertiary)
                    }
                }

                HStack(spacing: Spacing.s) {
                    Image(systemName: "calendar").foregroundStyle(.secondary)
                    Text("Scheduled scans: Quick Scan daily at 12:00").foregroundStyle(.secondary)
                    Button("Edit…") { model.selection = .settings }.buttonStyle(.link)
                }
                .font(.callout)

                VStack(alignment: .leading, spacing: Spacing.m) {
                    SectionHeader("Recent scans")
                    if model.scanHistory.isEmpty {
                        Text("No scans yet.").foregroundStyle(.secondary).card()
                    } else {
                        VStack(spacing: 0) {
                            ForEach(Array(model.scanHistory.prefix(5).enumerated()), id: \.element.id) { i, r in
                                if i > 0 { Divider() }
                                ScanHistoryRow(record: r).padding(Spacing.s)
                            }
                        }
                        .card(padding: Spacing.s)
                    }
                }
            }
            .contentColumn()
        }
        .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
            loadDrop(providers); return !providers.isEmpty
        }
        .overlay { if dropTargeted { DropHintOverlay().transition(.opacity) } }
        .animation(.easeOut(duration: 0.15), value: dropTargeted)
    }

    private var customSummary: String {
        customPaths.count == 1 ? (customPaths[0] as NSString).abbreviatingWithTildeInPath : "\(customPaths.count) items selected"
    }

    private func start() {
        model.startScan(choice, paths: customPaths)
    }

    private func pickFolders() {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true; panel.canChooseDirectories = true; panel.allowsMultipleSelection = true
        panel.prompt = "Choose"
        panel.message = "Choose files, folders or drives to check."
        if panel.runModal() == .OK { customPaths = panel.urls.map(\.path); choice = .custom }
    }

    private func loadDrop(_ providers: [NSItemProvider]) {
        for p in providers {
            _ = p.loadObject(ofClass: URL.self) { url, _ in
                guard let url else { return }
                DispatchQueue.main.async {
                    if !customPaths.contains(url.path) { customPaths.append(url.path) }
                    choice = .custom
                }
            }
        }
    }
}

/// Shown while files are dragged over the Scan screen.
private struct DropHintOverlay: View {
    @Environment(\.accessibilityReduceTransparency) private var reduceTransparency
    var body: some View {
        ZStack {
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .fill(reduceTransparency ? AnyShapeStyle(Color(nsColor: .windowBackgroundColor)) : AnyShapeStyle(.ultraThinMaterial))
            RoundedRectangle(cornerRadius: 20, style: .continuous)
                .strokeBorder(Color.rampartTeal.opacity(0.8), style: StrokeStyle(lineWidth: 2, dash: [8, 6]))
            VStack(spacing: Spacing.s) {
                Image(systemName: "arrow.down.doc").font(.system(size: 40, weight: .semibold)).foregroundStyle(Color.rampartTeal)
                Text("Drop to scan").font(.title2.weight(.semibold)).fontDesign(.rounded)
                Text("Files and folders are added to a Custom Scan.").font(.callout).foregroundStyle(.secondary)
            }
        }
        .padding(Spacing.l)
        .allowsHitTesting(false)
        .accessibilityElement(children: .combine)
    }
}

struct ScanChoiceCard: View {
    let kind: ScanKind
    let selected: Bool
    var targeted = false
    var subtitle: String?
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack {
                IconBadge(symbol: kind.symbol, tint: selected ? .rampartTeal : .gray, size: 42)
                Spacer()
                Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                    .font(.title3).foregroundStyle(selected ? Color.rampartTeal : Color.secondary.opacity(0.5))
            }
            Text(kind.title).font(.title3.weight(.semibold)).fontDesign(.rounded).padding(.top, 4)
            Text(kind.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let subtitle {
                Text(subtitle).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            } else if kind == .custom {
                Text("Or drop files here").font(.caption).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, minHeight: 170, alignment: .topLeading)
        .card(tint: selected ? .rampartTeal : nil)
        .overlay(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .strokeBorder(selected || targeted ? Color.rampartTeal.opacity(0.9) : Color.clear, lineWidth: 1.5)
        )
        .modifier(MagneticTilt())
        .contentShape(Rectangle())
        .accessibilityElement(children: .combine)
    }
}

struct ScanHistoryRow: View {
    let record: ScanRecord
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: record.kind.symbol).foregroundStyle(.secondary).frame(width: 22)
            VStack(alignment: .leading, spacing: 2) {
                Text(record.kind.title).font(.body.weight(.medium))
                Text("\(Fmt.count(record.scanned)) files in \(Fmt.duration(record.seconds))").font(.callout).foregroundStyle(.secondary).monospacedDigit()
            }
            Spacer()
            if record.found == 0 {
                StatusLabel(text: "No threats", symbol: "checkmark.circle.fill", tint: .statusProtected).font(.callout)
            } else {
                StatusLabel(text: "\(record.found) found", symbol: "archivebox.fill", tint: .statusQuarantined).font(.callout)
            }
            Text(Fmt.dayTime(record.date)).font(.callout).foregroundStyle(.tertiary).frame(minWidth: 130, alignment: .trailing)
        }
        .accessibilityElement(children: .combine)
    }
}

/// Radar sweep: concentric rings, a rotating conic sweep and blips that light up as the sweep passes.
/// Animates only while visible and not paused; under Reduce Motion it is a static determinate ring.
struct RadarView: View {
    let fraction: Double?
    let paused: Bool
    var size: CGFloat = 280
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private let gate = AnimationGate.shared

    var body: some View {
        let tint = Color.rampartTeal
        let animate = !paused && !reduceMotion && gate.live
        ZStack {
            Circle().fill(RadialGradient(colors: [tint.opacity(0.16), tint.opacity(0.02)], center: .center, startRadius: 0, endRadius: size / 2))
            ForEach(1..<5) { i in
                Circle().strokeBorder(tint.opacity(0.18), lineWidth: 1).frame(width: size * CGFloat(i) / 4.4, height: size * CGFloat(i) / 4.4)
            }
            Rectangle().fill(tint.opacity(0.12)).frame(width: 1, height: size * 0.9)
            Rectangle().fill(tint.opacity(0.12)).frame(width: size * 0.9, height: 1)
            if !reduceMotion {
                if Headless.renderDir != nil {
                    // Offscreen still: a fixed sweep wedge.
                    Circle()
                        .fill(AngularGradient(gradient: Gradient(stops: [
                            .init(color: tint.opacity(0), location: 0), .init(color: tint.opacity(0), location: 0.72),
                            .init(color: tint.opacity(0.5), location: 1)]), center: .center))
                        .frame(width: size * 0.9, height: size * 0.9)
                        .rotationEffect(.degrees(130))
                } else {
                    RadarSweep(color: NSColor(tint), blipColor: NSColor(Palette.mint), animate: animate)
                        .frame(width: size * 0.9, height: size * 0.9)
                }
            }
            Circle().stroke(tint.opacity(0.15), lineWidth: 6).frame(width: size, height: size)
            if let f = fraction {
                Circle().trim(from: 0, to: f)
                    .stroke(LinearGradient(colors: [Palette.teal, Palette.mint], startPoint: .top, endPoint: .bottom),
                            style: StrokeStyle(lineWidth: 6, lineCap: .round))
                    .rotationEffect(.degrees(-90))
                    .frame(width: size, height: size)
            }
            VStack(spacing: 0) {
                if let f = fraction {
                    Text("\(Int(f * 100))%")
                        .font(.system(size: size * 0.17, weight: .bold, design: .rounded)).monospacedDigit()
                        .contentTransition(.numericText())
                } else {
                    Image(systemName: "magnifyingglass").font(.system(size: size * 0.12, weight: .semibold))
                }
                if size >= 120 {
                    Text(paused ? "Paused" : (fraction == nil ? "Finding files" : "Scanning"))
                        .font(.caption.weight(.medium)).foregroundStyle(.secondary).textCase(.uppercase).tracking(1.2)
                }
            }
            .padding(Spacing.m)
            .background(Circle().fill(.background.opacity(0.55)).blur(radius: 8))
        }
        .frame(width: size, height: size)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("Scan progress")
        .accessibilityValue(fraction.map { "\(Int($0 * 10) * 10) percent" } ?? "Finding files")
    }
}

struct RunningScanView: View {
    let progress: ScanProgress
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("scan.lowImpact") private var lowImpact = false

    var body: some View {
        ZStack(alignment: .bottom) {
            HStack(alignment: .center, spacing: 48) {
                RadarView(fraction: progress.fraction, paused: progress.paused)
                    .anchorPreference(key: RadarCenterKey.self, value: .center) { $0 }
                VStack(alignment: .leading, spacing: Spacing.m) {
                    Label(progress.kind.title, systemImage: progress.kind.symbol)
                        .font(.headline).foregroundStyle(Color.rampartTeal)
                    if progress.walkFinished && progress.total > 0 {
                        (Text(Fmt.count(progress.scanned)).foregroundStyle(.primary) + Text(" of \(Fmt.count(progress.total)) files").foregroundStyle(.secondary))
                            .font(.title.weight(.bold)).fontDesign(.rounded).monospacedDigit()
                            .contentTransition(.numericText())
                    } else {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Finding files…").font(.title.weight(.bold)).fontDesign(.rounded)
                            if progress.total > 0 {
                                Text("\(Fmt.count(progress.total)) found so far, \(Fmt.count(progress.scanned)) checked")
                                    .font(.title3).foregroundStyle(.secondary).monospacedDigit()
                                    .contentTransition(.numericText())
                            }
                        }
                        .help("\(Product.name) checks files while it looks for them. A percentage and time estimate appear once it knows how many there are.")
                    }
                    HStack(spacing: Spacing.l) {
                        Label(Fmt.duration(Date().timeIntervalSince(progress.started)), systemImage: "timer")
                        if let eta = progress.etaSeconds { Label("About \(Fmt.duration(eta)) left", systemImage: "hourglass") }
                        Label("\(progress.found) item\(progress.found == 1 ? "" : "s") found", systemImage: "ladybug")
                    }
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()

                    VStack(alignment: .leading, spacing: 5) {
                        ForEach(Array(model.recentScanPaths.enumerated()), id: \.element) { i, p in
                            HStack(spacing: 6) {
                                Image(systemName: i == 0 ? "doc.text.magnifyingglass" : "checkmark")
                                    .font(.caption2.weight(.bold))
                                    .foregroundStyle(i == 0 ? Color.rampartTeal : Color.statusProtected)
                                    .frame(width: 14)
                                Text(p.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                                    .font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                            }
                            .opacity(1 - Double(i) * 0.13)
                            .transition(reduceMotion ? .identity : .move(edge: .top).combined(with: .opacity))
                        }
                    }
                    .animation(reduceMotion ? nil : .easeOut(duration: 0.18), value: model.recentScanPaths)
                    .frame(maxWidth: 420, minHeight: 150, alignment: .topLeading)
                    .card(padding: Spacing.m)
                    .anchorPreference(key: FileListLeadingKey.self, value: .leading) { $0 }
                    .accessibilityHidden(true)
                }
                .frame(maxWidth: 440, alignment: .leading)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .padding(.bottom, 70)
            .overlayPreferenceValue(RadarCenterKey.self) { radar in
                GeometryReader { geo in
                    if let radar {
                        FileFlowOverlay(radar: geo[radar], active: !progress.paused)
                    }
                }
            }

            HStack(spacing: Spacing.l) {
                if model.mode != .live {
                    Button { model.togglePause() } label: {
                        Label(progress.paused ? "Resume" : "Pause", systemImage: progress.paused ? "play.fill" : "pause.fill")
                    }
                }
                Button(role: .destructive) { model.stopScan() } label: { Label("Stop", systemImage: "stop.fill") }
                Divider().frame(height: 18)
                Toggle(isOn: $lowImpact) { Label("Low impact", systemImage: "tortoise") }
                    .toggleStyle(.switch).controlSize(.small)
                    .help("Lowers disk and CPU priority so the scan stays out of your way.")
            }
            .buttonStyle(.borderless)
            .padding(.horizontal, Spacing.xl).padding(.vertical, Spacing.m)
            .floatingGlassBar()
            .padding(.bottom, Spacing.xl)
        }
        .toolbar {
            ToolbarItem(placement: .status) {
                Text("\(progress.kind.title) · \(progress.fraction.map { "\(Int($0 * 100))%" } ?? "Finding files…")")
                    .foregroundStyle(.secondary).monospacedDigit()
            }
        }
    }
}

struct ScanResultView: View {
    let record: ScanRecord
    let found: [Detection]
    @Environment(AppModel.self) private var model
    @StateVar private var bounce = 0
    @StateVar private var showSkipped = false

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.l) {
                Spacer(minLength: Spacing.xxl)
                if found.isEmpty {
                    ZStack {
                        RippleOnce(tint: .statusProtected).frame(width: 150, height: 150)
                        StatusMark(size: 130, badge: "checkmark.circle.fill", tint: .statusProtected)
                    }
                    Text("All clear").font(.system(size: 44, weight: .bold, design: .rounded))
                        .revealText(duration: 0.9)
                    Text("No threats found").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text("Scanned \(Fmt.count(record.scanned)) files in \(Fmt.duration(record.seconds)).")
                        .font(.title3).foregroundStyle(.secondary)
                } else {
                    Image(systemName: "archivebox.fill").font(.system(size: 64)).foregroundStyle(.secondary)
                    Text(found.count == 1 ? "1 item found" : "\(found.count) items found").font(.largeTitle.weight(.bold)).fontDesign(.rounded)
                        .revealText(duration: 0.9)
                    Text("They've been moved to quarantine and can't run.").font(.title3).foregroundStyle(.secondary)
                    VStack(spacing: 0) {
                        ForEach(found) { d in DetectionRowSummary(detection: d).padding(Spacing.s) }
                    }
                    .card(padding: Spacing.s).frame(maxWidth: 600)
                }
                if record.skipped > 0 {
                    DisclosureGroup(isExpanded: $showSkipped) {
                        Text("Some files were in use, protected by macOS, or couldn't be read without Full Disk Access. They aren't a sign of a problem. Granting Full Disk Access lets \(Product.name) check more of them.")
                            .font(.callout).foregroundStyle(.secondary).padding(.top, Spacing.xs)
                    } label: {
                        Text("\(Fmt.count(record.skipped)) files couldn't be scanned. Why?").font(.callout)
                    }
                    .frame(maxWidth: 520)
                }
                HStack {
                    if found.isEmpty {
                        Button("Done") { model.scanPhase = .idle }.buttonStyle(GlowButtonStyle()).keyboardShortcut(.defaultAction)
                        Button("View Activity") { model.scanPhase = .idle; model.selection = .activity }
                    } else {
                        Button("Review Items") { model.scanPhase = .idle; model.selection = .threats }.buttonStyle(GlowButtonStyle())
                        Button("Done") { model.scanPhase = .idle }
                    }
                }
                .controlSize(.large)
                Spacer()
            }
            .contentColumn()
        }
    }
}

struct DetectionRowSummary: View {
    let detection: Detection
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: detection.severity.symbol).foregroundStyle(detection.severity.tint)
            VStack(alignment: .leading) {
                Text(detection.name).font(.body.weight(.medium))
                Text(detection.path ?? "—").font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
            Spacer()
            Badge(text: detection.category.label)
        }
    }
}

struct RadarCenterKey: PreferenceKey {
    static var defaultValue: Anchor<CGPoint>? = nil
    static func reduce(value: inout Anchor<CGPoint>?, nextValue: () -> Anchor<CGPoint>?) { value = value ?? nextValue() }
}
struct FileListLeadingKey: PreferenceKey {
    static var defaultValue: Anchor<CGPoint>? = nil
    static func reduce(value: inout Anchor<CGPoint>?, nextValue: () -> Anchor<CGPoint>?) { value = value ?? nextValue() }
}
/// Particles flow from the file list (right) into the radar centre while scanning.
struct FileFlowOverlay: View {
    let radar: CGPoint
    let active: Bool
    var body: some View {
        GeometryReader { geo in
            ScanParticles(from: CGPoint(x: min(geo.size.width - 40, radar.x + 360), y: radar.y), to: radar, active: active)
        }
    }
}
