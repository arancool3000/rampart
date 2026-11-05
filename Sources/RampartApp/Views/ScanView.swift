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
                .onDrop(of: [.fileURL], isTargeted: $dropTargeted) { providers in
                    loadDrop(providers); return true
                }

                HStack(spacing: Spacing.m) {
                    Button { start() } label: {
                        Label("Start \(choice.title)", systemImage: "play.fill").frame(minWidth: 160)
                    }
                    .buttonStyle(.borderedProminent).controlSize(.large)
                    .keyboardShortcut(.defaultAction)
                    .disabled(choice == .custom && customPaths.isEmpty)
                    if choice == .custom {
                        Button("Choose…") { pickFolders() }.controlSize(.large)
                    }
                    Spacer()
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

struct ScanChoiceCard: View {
    let kind: ScanKind
    let selected: Bool
    var targeted = false
    var subtitle: String?
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Image(systemName: kind.symbol).font(.title).foregroundStyle(selected ? Color.rampartTeal : .secondary)
                .frame(height: 34)
            Text(kind.title).font(.title3.weight(.medium))
            Text(kind.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if let subtitle {
                Text(subtitle).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            } else if kind == .custom {
                Text("Or drop files here").font(.caption).foregroundStyle(.tertiary)
            }
            Spacer(minLength: 0)
        }
        .frame(maxWidth: .infinity, minHeight: 150, alignment: .topLeading)
        .card()
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(selected || targeted ? Color.rampartTeal : Color.clear, lineWidth: 2)
        )
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

struct RunningScanView: View {
    let progress: ScanProgress
    @Environment(AppModel.self) private var model
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @AppStorage("scan.lowImpact") private var lowImpact = false
    @StateVar private var spin = false

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: Spacing.l) {
                Spacer()
                ZStack {
                    Circle().stroke(Color.secondary.opacity(0.15), lineWidth: 14)
                    if let f = progress.fraction {
                        Circle().trim(from: 0, to: f)
                            .stroke(Color.rampartTeal, style: StrokeStyle(lineWidth: 14, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .animation(reduceMotion ? nil : .linear(duration: 0.1), value: f)
                        Text("\(Int(f * 100))%")
                            .font(.system(size: 44, weight: .semibold, design: .rounded)).monospacedDigit()
                            .contentTransition(.numericText())
                    } else {
                        Circle().trim(from: 0, to: 0.25)
                            .stroke(AngularGradient(colors: [Color.rampartTeal.opacity(0), Color.rampartTeal], center: .center),
                                    style: StrokeStyle(lineWidth: 14, lineCap: .round))
                            .rotationEffect(.degrees(spin ? 360 : 0))
                            .animation(reduceMotion ? nil : .linear(duration: 1.2).repeatForever(autoreverses: false), value: spin)
                            .onAppear { spin = true }
                        Image(systemName: "magnifyingglass").font(.largeTitle).foregroundStyle(.secondary)
                    }
                }
                .frame(width: 200, height: 200)
                .accessibilityElement(children: .ignore)
                .accessibilityLabel("\(progress.kind.title) progress")
                .accessibilityValue(progress.fraction.map { "\(Int($0 * 10) * 10) percent" } ?? "Estimating")

                Text(progress.paused ? "Paused" : (progress.total > 0
                     ? "Scanning… \(Fmt.count(progress.scanned)) of \(Fmt.count(progress.total)) files"
                     : "Estimating files…"))
                    .font(.title3.weight(.medium)).monospacedDigit()
                Text(progress.current)
                    .font(.callout.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).truncationMode(.middle).frame(maxWidth: 520)
                HStack(spacing: Spacing.l) {
                    Text("Elapsed \(Fmt.duration(Date().timeIntervalSince(progress.started)))")
                    if let eta = progress.etaSeconds { Text("About \(Fmt.duration(eta)) left") }
                    Text("\(progress.found) item\(progress.found == 1 ? "" : "s") found")
                }
                .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                Spacer()
                Spacer().frame(height: 60)
            }
            .frame(maxWidth: .infinity)

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
                Text("\(progress.kind.title) · \(progress.fraction.map { "\(Int($0 * 100))%" } ?? "Starting")")
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
                    Image(systemName: "checkmark.shield.fill").font(.system(size: 72))
                        .foregroundStyle(Color.statusProtected).symbolRenderingMode(.hierarchical)
                        .symbolEffect(.bounce, value: bounce)
                        .onAppear { bounce += 1 }
                    Text("No threats found").font(.largeTitle.weight(.semibold))
                    Text("Scanned \(Fmt.count(record.scanned)) files in \(Fmt.duration(record.seconds)).")
                        .font(.title3).foregroundStyle(.secondary)
                } else {
                    Image(systemName: "archivebox.fill").font(.system(size: 64)).foregroundStyle(.secondary)
                    Text(found.count == 1 ? "Found 1 item" : "Found \(found.count) items").font(.largeTitle.weight(.semibold))
                    Text("They've been moved to quarantine and can't run.").font(.title3).foregroundStyle(.secondary)
                    VStack(spacing: 0) {
                        ForEach(found) { d in DetectionRowSummary(detection: d).padding(Spacing.s) }
                    }
                    .card(padding: Spacing.s).frame(maxWidth: 600)
                }
                if record.skipped > 0 {
                    DisclosureGroup(isExpanded: $showSkipped) {
                        Text("Some files were in use, protected by macOS, or couldn't be read without Full Disk Access. They aren't a sign of a problem. Granting Full Disk Access lets Rampart check more of them.")
                            .font(.callout).foregroundStyle(.secondary).padding(.top, Spacing.xs)
                    } label: {
                        Text("\(Fmt.count(record.skipped)) files couldn't be scanned. Why?").font(.callout)
                    }
                    .frame(maxWidth: 520)
                }
                HStack {
                    if found.isEmpty {
                        Button("Done") { model.scanPhase = .idle }.buttonStyle(.borderedProminent).keyboardShortcut(.defaultAction)
                        Button("View Activity") { model.scanPhase = .idle; model.selection = .activity }
                    } else {
                        Button("Review Items") { model.scanPhase = .idle; model.selection = .threats }.buttonStyle(.borderedProminent)
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
