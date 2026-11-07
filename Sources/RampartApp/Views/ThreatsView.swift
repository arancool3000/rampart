import SwiftUI
import AppKit
import RampartShared

struct ThreatsView: View {
    enum Segment: String, CaseIterable, Identifiable { case detections = "Detections", quarantine = "Quarantine"; var id: String { rawValue } }
    @Environment(AppModel.self) private var model
    @StateVar private var segment: Segment = .detections
    @StateVar private var selectedDetection: Detection.ID?
    @StateVar private var selectedQuarantine: QuarantineRecord.ID?
    @StateVar private var showInspector = true
    @StateVar private var sortOrder = [KeyPathComparator(\Detection.date, order: .reverse)]
    /// Records the user deleted but whose permanent delete hasn't run yet (undo window).
    @StateVar private var pendingDeletes: Set<QuarantineRecord.ID> = []
    @StateVar private var undo: UndoNote?
    @StateVar private var undoTask: Task<Void, Never>?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    struct UndoNote: Identifiable {
        let id = UUID()
        let text: String
        let undo: @MainActor () async -> Void
        let commit: (@MainActor () async -> Void)?
    }

    private var visibleQuarantine: [QuarantineRecord] { model.quarantine.filter { !pendingDeletes.contains($0.id) } }

    var body: some View {
        VStack(spacing: 0) {
            switch segment {
            case .detections: detectionsTable
            case .quarantine: quarantineTable
            }
        }
        .overlay(alignment: .bottom) {
            if let undo {
                UndoBanner(text: undo.text) { performUndo() } dismiss: { finishUndo(commit: true) }
                    .id(undo.id)
                    .padding(Spacing.m)
                    .transition(reduceMotion ? .opacity : .move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(reduceMotion ? nil : .spring(response: 0.35, dampingFraction: 0.9), value: undo?.id)
        .onDisappear { finishUndo(commit: true) }
        .navigationTitle("Threats & Quarantine")
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("View", selection: $segment) {
                    ForEach(Segment.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 240)
            }
            ToolbarItem(placement: .automatic) {
                Button { model.selection = .rules } label: { Label("Allowed Items", systemImage: "checkmark.seal") }
                    .help("Files, developers and folders you've allowed are in Rules")
            }
            ToolbarItem(placement: .primaryAction) {
                Button { showInspector.toggle() } label: { Label("Inspector", systemImage: "sidebar.trailing") }
                    .help("Show or hide details")
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if segment == .detections, let id = selectedDetection, let d = model.detections.first(where: { $0.id == id }) {
                    DetectionInspector(detection: d, record: record(for: d), onDelete: scheduleDelete, onRestored: offerReQuarantine)
                } else if segment == .quarantine, let id = selectedQuarantine, let r = visibleQuarantine.first(where: { $0.id == id }) {
                    DetectionInspector(detection: detection(for: r), record: r, onDelete: scheduleDelete, onRestored: offerReQuarantine)
                } else {
                    EmptyStateView(symbol: "info.circle", title: "Select an item", detail: "You'll see why \(Product.name) flagged it and what you can do.")
                }
            }
            .inspectorColumnWidth(min: 340, ideal: 400, max: 520)
        }
        .onAppear {
            if selectedDetection == nil { selectedDetection = model.openDetections.first?.id ?? model.detections.first?.id }
            if selectedQuarantine == nil { selectedQuarantine = model.quarantine.first?.id }
        }
    }

    // MARK: Undo

    /// Hides the record at once and deletes it for real only after a short grace period.
    private func scheduleDelete(_ r: QuarantineRecord) {
        finishUndo(commit: true)
        pendingDeletes.insert(r.id)
        if selectedQuarantine == r.id { selectedQuarantine = visibleQuarantine.first?.id }
        let name = (r.originalPath as NSString).lastPathComponent
        present(UndoNote(text: "Deleted \u{201C}\(name)\u{201D}", undo: { pendingDeletes.remove(r.id); selectedQuarantine = r.id },
                         commit: { await model.delete(r); pendingDeletes.remove(r.id) }))
    }

    /// After a restore, offers to put the file straight back in quarantine.
    private func offerReQuarantine(_ r: QuarantineRecord, _ d: Detection?) {
        finishUndo(commit: true)
        let name = (r.originalPath as NSString).lastPathComponent
        guard let d, d.path != nil else { return }
        present(UndoNote(text: "Restored \u{201C}\(name)\u{201D}", undo: { await model.quarantine(d) }, commit: nil))
    }

    private func present(_ note: UndoNote) {
        undo = note
        let id = note.id
        undoTask = Task { @MainActor in
            try? await Task.sleep(for: .seconds(6))
            guard !Task.isCancelled, undo?.id == id else { return }
            finishUndo(commit: true)
        }
    }

    private func performUndo() {
        guard let note = undo else { return }
        undoTask?.cancel(); undoTask = nil; undo = nil
        Task { @MainActor in await note.undo() }
    }

    private func finishUndo(commit: Bool) {
        guard let note = undo else { return }
        undoTask?.cancel(); undoTask = nil; undo = nil
        if commit, let c = note.commit { Task { @MainActor in await c() } }
    }

    private func record(for d: Detection) -> QuarantineRecord? {
        visibleQuarantine.first { $0.sha256 == d.sha256 && d.sha256 != nil } ?? visibleQuarantine.first { $0.originalPath == d.path }
    }
    private func detection(for r: QuarantineRecord) -> Detection? {
        model.detections.first { $0.sha256 == r.sha256 } ?? model.detections.first { $0.path == r.originalPath }
            ?? model.detections.first { $0.name == r.detectionName }
    }

    private var sortedDetections: [Detection] { model.detections.sorted(using: sortOrder) }

    @ViewBuilder private var detectionsTable: some View {
        if model.detections.isEmpty {
            EmptyStateView(symbol: "checkmark.shield", title: "No threats found",
                           detail: model.mode == .live
                               ? "\(Product.name) checks new and changed files as they arrive. If it ever finds something, it will appear here with a plain explanation of why."
                               : "When \(Product.name) finds something, it will appear here with an explanation.", brand: true)
        } else {
            Table(sortedDetections, selection: $selectedDetection, sortOrder: $sortOrder) {
                TableColumn("Item", value: \.name) { d in
                    HStack(spacing: Spacing.s) {
                        FileIcon(path: d.path)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(d.path.map { ($0 as NSString).lastPathComponent } ?? d.name).lineLimit(1)
                            Text(d.path.map { ($0 as NSString).abbreviatingWithTildeInPath } ?? "—")
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                        }
                    }
                }
                .width(min: 220, ideal: 300)
                TableColumn("Type") { d in Badge(text: d.category.label) }.width(min: 110, ideal: 150)
                TableColumn("Severity", value: \.severity.rawValue) { d in
                    Label { Text(d.severity.label) } icon: { Image(systemName: d.severity.symbol).foregroundStyle(d.severity.tint) }
                }
                .width(min: 80, ideal: 90)
                TableColumn("Status") { d in DetectionStatus(detection: d, quarantined: record(for: d) != nil) }.width(min: 110, ideal: 130)
                TableColumn("Detected", value: \.date) { d in Text(Fmt.ago(d.date)).foregroundStyle(.secondary) }.width(min: 90, ideal: 110)
            }
            .scrollContentBackground(.hidden)
            .contextMenu(forSelectionType: Detection.ID.self) { ids in
                if let id = ids.first, let d = model.detections.first(where: { $0.id == id }), let p = d.path {
                    if FileManager.default.fileExists(atPath: p) {
                        Button("Reveal in Finder") { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") }
                        Divider()
                    }
                    Button("Copy Path") { copy(p) }
                    if let h = d.sha256 { Button("Copy SHA-256") { copy(h) } }
                }
            }
        }
    }

    @ViewBuilder private var quarantineTable: some View {
        if visibleQuarantine.isEmpty {
            EmptyStateView(symbol: "archivebox", title: "Quarantine is empty",
                           detail: "Files \(Product.name) isolates will appear here. They can't run while they're here.")
        } else {
            VStack(spacing: 0) {
                Table(visibleQuarantine, selection: $selectedQuarantine) {
                    TableColumn("Item") { r in
                        HStack(spacing: Spacing.s) {
                            Image(systemName: "lock.square.stack").foregroundStyle(Color.statusQuarantined).font(.title3).frame(width: 24)
                            VStack(alignment: .leading, spacing: 1) {
                                Text((r.originalPath as NSString).lastPathComponent).lineLimit(1)
                                Text(r.detectionName).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                    .width(min: 200, ideal: 240)
                    TableColumn("Original location") { r in
                        Text((r.originalPath as NSString).deletingLastPathComponent.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                            .font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                    TableColumn("Quarantined") { r in Text(Fmt.dayTime(r.date)).foregroundStyle(.secondary) }.width(min: 110, ideal: 130)
                    TableColumn("Size") { r in Text(Fmt.bytes(r.size)).monospacedDigit().foregroundStyle(.secondary) }.width(min: 60, ideal: 70)
                    TableColumn("Auto-delete") { r in
                        Text(r.date.addingTimeInterval(30 * 86_400).formatted(date: .abbreviated, time: .omitted)).foregroundStyle(.secondary)
                    }
                    .width(min: 90, ideal: 100)
                }
                .scrollContentBackground(.hidden)
                .contextMenu(forSelectionType: QuarantineRecord.ID.self) { ids in
                    if let id = ids.first, let r = visibleQuarantine.first(where: { $0.id == id }) {
                        Button("Copy Original Path") { copy(r.originalPath) }
                        if !r.sha256.isEmpty { Button("Copy SHA-256") { copy(r.sha256) } }
                        Divider()
                        Button("Delete Permanently", role: .destructive) { scheduleDelete(r) }
                    }
                }
                HStack {
                    Image(systemName: "info.circle").foregroundStyle(.secondary)
                    Text("Deleted automatically after 30 days.").foregroundStyle(.secondary)
                    Button("Change in Settings") { model.selection = .settings }.buttonStyle(.link)
                    Spacer()
                }
                .font(.callout).padding(Spacing.m)
            }
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string)
    }
}

struct DetectionStatus: View {
    let detection: Detection
    let quarantined: Bool
    var body: some View {
        if quarantined {
            StatusLabel(text: "Quarantined", symbol: "archivebox.fill", tint: .statusQuarantined)
        } else if detection.resolved {
            StatusLabel(text: "Resolved", symbol: "checkmark.circle.fill", tint: .statusProtected)
        } else {
            StatusLabel(text: "Needs decision", symbol: "exclamationmark.circle.fill", tint: .statusAction)
        }
    }
}

struct FileIcon: View {
    let path: String?
    var body: some View {
        Group {
            if let path, FileManager.default.fileExists(atPath: path) {
                Image(nsImage: NSWorkspace.shared.icon(forFile: path)).resizable()
            } else {
                Image(systemName: "doc.questionmark").resizable().scaledToFit().foregroundStyle(.secondary).padding(3)
            }
        }
        .frame(width: 24, height: 24)
        .accessibilityHidden(true)
    }
}

// MARK: - Inspector: "Why was this flagged?"

struct DetectionInspector: View {
    let detection: Detection?
    let record: QuarantineRecord?
    var onDelete: (QuarantineRecord) -> Void = { _ in }
    var onRestored: (QuarantineRecord, Detection?) -> Void = { _, _ in }
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var whyExpanded = true
    @StateVar private var showRestore = false
    @StateVar private var showDelete = false
    @StateVar private var showReport = false
    @StateVar private var showAllow = false

    private var displayName: String {
        if let p = detection?.path ?? record?.originalPath { return (p as NSString).lastPathComponent }
        return detection?.name ?? record?.detectionName ?? "Item"
    }
    private var sha: String? { detection?.sha256 ?? record?.sha256 }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.l) {
                    header
                    if let d = detection { why(d) }
                    whatWeDid
                    details
                    links
                }
                .padding(Spacing.l)
            }
            Divider()
            actions
                .padding(Spacing.m)
        }
        .sheet(isPresented: $showRestore) {
            if let record { RestoreSheet(record: record, detection: detection, onRestored: onRestored) }
        }
        .sheet(isPresented: $showReport) { ReportSheet(name: displayName) }
        .sheet(isPresented: $showAllow) { if let detection { AllowSheet(detection: detection) } }
        .confirmationDialog("Delete \"\(displayName)\" permanently?", isPresented: $showDelete) {
            Button("Delete", role: .destructive) { if let record { onDelete(record) } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("You'll have a few seconds to undo. After that, the file is gone for good.") }
    }

    private var header: some View {
        HStack(spacing: Spacing.m) {
            if let d = detection, !d.resolved {
                ShieldLockAnimation(size: 52, trigger: d.id)
            } else {
                FileIcon(path: detection?.path).frame(width: 40, height: 40).scaleEffect(1.5)
            }
            VStack(alignment: .leading, spacing: 4) {
                Text(displayName).font(.title3.weight(.semibold)).lineLimit(2)
                HStack(spacing: 6) {
                    if let d = detection { Badge(text: d.category.label) }
                    if record != nil { Badge(text: "Quarantined", tint: .gray) }
                }
            }
        }
    }

    private func why(_ d: Detection) -> some View {
        let primary = d.evidence.max { $0.score < $1.score }
        return DisclosureGroup(isExpanded: $whyExpanded) {
            VStack(alignment: .leading, spacing: Spacing.m) {
                (Text("Detected as ") + Text(d.name).bold() + Text(" by ") + Text(primary?.source.label ?? "\(Product.name)").bold() + Text("."))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Array(d.evidence.sorted { $0.score > $1.score }.enumerated()), id: \.element) { idx, e in
                    HStack(alignment: .top, spacing: Spacing.s) {
                        Image(systemName: e.source.symbol).foregroundStyle(Color.rampartTeal).frame(width: 20)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(alignment: .firstTextBaseline, spacing: Spacing.s) {
                                Text(e.title).font(.body.weight(.medium))
                                Spacer(minLength: 0)
                                SignalStrength(score: e.score)
                            }
                            EvidenceDetail(detail: e.detail)
                            Text(e.source.label).font(.caption).foregroundStyle(.tertiary)
                        }
                    }
                    .padding(Spacing.s)
                    .background(Color.primary.opacity(e == primary ? 0.06 : 0.03), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    .accessibilityElement(children: .combine)
                    .modifier(Cascade(index: idx, trigger: d.id))
                }
                confidence(d.confidence)
            }
            .padding(.top, Spacing.s)
        } label: {
            Label("Why was this flagged?", systemImage: "questionmark.bubble").font(.headline)
        }
    }

    private func confidence(_ c: Int) -> some View {
        let text: String
        switch c {
        case 90...: text = "High confidence (\(c)%)"
        case 60..<90: text = "Medium confidence (\(c)%): this may be a false positive."
        default: text = "Low confidence (\(c)%): logged for your review."
        }
        return HStack(spacing: Spacing.s) {
            Gauge(value: Double(c), in: 0...100) { EmptyView() }
                .gaugeStyle(.accessoryLinearCapacity).tint(Color.rampartTeal).frame(width: 80)
            Text(text).font(.callout)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
    }

    @ViewBuilder private var whatWeDid: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Text("What \(Product.name) did").font(.headline)
            if let r = record {
                Text("Moved to quarantine on \(r.date.formatted(date: .abbreviated, time: .shortened)). The file is encrypted and can't run.")
            } else if detection?.resolved == true {
                Text("This item was resolved and is no longer flagged.")
            } else {
                if processStopped {
                    Text("\(Product.name) stopped the process. The file is still in place. Choose what to do next.")
                } else {
                    Text("\(Product.name) hasn't changed anything yet. The file is still in place. Choose what to do next.")
                }
            }
        }
        .font(.callout)
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Details").font(.headline)
            Grid(alignment: .leading, horizontalSpacing: Spacing.m, verticalSpacing: 6) {
                if let p = detection?.path ?? record?.originalPath { row("Location", (p as NSString).abbreviatingWithTildeInPath, mono: true) }
                if let d = detection { row("First seen", d.date.formatted(date: .abbreviated, time: .shortened)) }
                if let pid = detection?.pid { row("Process ID", String(pid), mono: true) }
                if let r = record { row("Size", Fmt.bytes(r.size)) }
                if let sha {
                    GridRow {
                        Text("SHA-256").foregroundStyle(.secondary).font(.callout)
                        HStack(alignment: .top, spacing: 6) {
                            Text(sha).font(.callout.monospaced()).textSelection(.enabled).lineLimit(3).truncationMode(.middle)
                            CopyHashButton(value: sha)
                        }
                    }
                }
            }
        }
    }

    private func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary).font(.callout)
            Text(v).font(mono ? .callout.monospaced() : .callout).textSelection(.enabled).lineLimit(k == "Location" ? 1 : 3).truncationMode(.middle).help(k == "Location" ? v : "")
        }
    }

    private var links: some View {
        HStack(spacing: Spacing.l) {
            if let sha, let url = URL(string: "https://www.virustotal.com/gui/file/\(sha)") {
                Button("Look up on VirusTotal") { openURL(url) }.buttonStyle(.link)
                    .help("Opens your browser with the file's fingerprint only. Nothing is uploaded.")
            }
            Button("Copy Details") { copyDetails() }.buttonStyle(.link)
            if let d = detection {
                Button { AppFeatures.explain(d) } label: { Label("Explain", systemImage: "sparkles") }.buttonStyle(.link)
                    .help("Ask the AI Assistant to explain this in plain language")
            }
        }
        .font(.callout)
    }

    /// True only when the evidence records that a process stop actually succeeded.
    private var processStopped: Bool {
        guard let d = detection else { return false }
        return d.evidence.contains { e in
            let t = (e.title + " " + e.detail).lowercased()
            let said = ["stopped", "terminated", "killed"].contains { t.contains($0) }
            let failed = ["failed", "couldn't", "could not", "unable", "not stopped"].contains { t.contains($0) }
            return said && !failed
        }
    }

    /// Never truncates: full labels, then short labels, then two rows.
    private var actions: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.s) { primaryButtons(short: false); Spacer(minLength: Spacing.s); reportButton(short: false) }
            HStack(spacing: Spacing.s) { primaryButtons(short: true); Spacer(minLength: Spacing.s); reportButton(short: true) }
            VStack(alignment: .leading, spacing: Spacing.s) {
                HStack(spacing: Spacing.s) { primaryButtons(short: true) }
                reportButton(short: true)
            }
        }
        .controlSize(.regular)
    }

    @ViewBuilder private func primaryButtons(short: Bool) -> some View {
        if record != nil {
            Button(role: .destructive) { showDelete = true } label: { Label("Delete", systemImage: "trash").fixedSize() }
            Button { showRestore = true } label: { Label(short ? "Restore" : "Restore…", systemImage: "arrow.uturn.backward").fixedSize() }
        } else if let d = detection, !d.resolved {
            Button { Task { await model.quarantine(d) } } label: { Label("Quarantine", systemImage: "archivebox").fixedSize() }
                .buttonStyle(GlowButtonStyle())
            Button { showAllow = true } label: { Label(short ? "Allow" : "Allow…", systemImage: "checkmark.seal").fixedSize() }
        } else if let p = detection?.path {
            Button { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") } label: {
                Label(short ? "Reveal" : "Reveal in Finder", systemImage: "folder").fixedSize()
            }
            .help("Reveal in Finder")
        }
    }

    private func reportButton(short: Bool) -> some View {
        Button { showReport = true } label: { Label(short ? "Report Safe" : "Report as Safe…", systemImage: "flag").fixedSize() }
            .help("Tell the \(Product.name) lab this file is safe")
    }

    private func copyDetails() {
        var s = "\(Product.name) detection\nName: \(detection?.name ?? record?.detectionName ?? "")\n"
        if let p = detection?.path ?? record?.originalPath { s += "Path: \(p)\n" }
        if let sha { s += "SHA-256: \(sha)\n" }
        if let d = detection {
            s += "Confidence: \(d.confidence)%\n"
            for e in d.evidence { s += "- [\(e.source.rawValue)] \(e.title): \(e.detail) (\(e.score))\n" }
        }
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string)
    }
}

struct RestoreSheet: View {
    enum Choice: Hashable { case allowFile, allowDeveloper, once }
    let record: QuarantineRecord
    let detection: Detection?
    var onRestored: (QuarantineRecord, Detection?) -> Void = { _, _ in }
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var choice: Choice = .once

    var body: some View {
        let name = (record.originalPath as NSString).lastPathComponent
        let conf = (detection?.confidence ?? 0) >= 90 ? "high" : "medium"
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Restore \"\(name)\"?").font(.title2.weight(.semibold))
            Text("\(Product.name) flagged this as \(detection?.category.label ?? record.detectionName) (\(conf) confidence). Restore it only if you trust where it came from.")
                .fixedSize(horizontal: false, vertical: true)
            Picker("", selection: $choice) {
                Text("Restore and always allow this file").tag(Choice.allowFile)
                Text("Restore and allow everything from this developer").tag(Choice.allowDeveloper)
                Text("Restore once (scan again next time)").tag(Choice.once)
            }
            .pickerStyle(.radioGroup).labelsHidden()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).keyboardShortcut(.defaultAction)
                Button("Restore") {
                    Task {
                        if choice == .allowDeveloper, let d = detection { await model.allow(d, scope: .developer) }
                        await model.restore(record, allow: choice != .once)
                        if choice == .once { onRestored(record, detection) }
                    }
                    dismiss()
                }
            }
        }
        .padding(Spacing.xl)
        .frame(width: 460)
    }
}

struct AllowSheet: View {
    let detection: Detection
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var scope: AllowRuleSpec.Scope = .fileHash

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Allow \"\(detection.path.map { ($0 as NSString).lastPathComponent } ?? detection.name)\"?").font(.title2.weight(.semibold))
            Text("\(Product.name) won't flag it again. You can remove this rule anytime in Rules.")
                .foregroundStyle(.secondary)
            Picker("", selection: $scope) {
                Text("This file only (by fingerprint)").tag(AllowRuleSpec.Scope.fileHash)
                Text("This developer").tag(AllowRuleSpec.Scope.developer)
                Text("This folder").tag(AllowRuleSpec.Scope.folder)
            }
            .pickerStyle(.radioGroup).labelsHidden()
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Allow") { Task { await model.allow(detection, scope: scope) }; dismiss() }
            }
        }
        .padding(Spacing.xl).frame(width: 440)
    }
}

struct ReportSheet: View {
    let name: String
    @Environment(\.dismiss) private var dismiss
    @StateVar private var includeFile = false
    @StateVar private var note = ""
    @StateVar private var sent = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Report as safe").font(.title2.weight(.semibold))
            if sent {
                Label("Thanks — we'll review this within 2 business days.", systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.primary)
                HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
            } else {
                Text("We'll send the file's fingerprint and detection details to the \(Product.name) lab. We won't send the file itself unless you choose to.")
                    .fixedSize(horizontal: false, vertical: true)
                Toggle("Include the file to help us review it faster", isOn: $includeFile)
                TextField("Anything we should know? (optional)", text: $note, axis: .vertical).lineLimit(3...5)
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button("Send Report") { sent = true }.keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(Spacing.xl).frame(width: 460)
    }
}

/// Evidence rows cascade in, 60 ms apart (fade only under Reduce Motion).
struct Cascade: ViewModifier {
    let index: Int
    let trigger: UUID
    @StateVar private var shown = Headless.active
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    func body(content: Content) -> some View {
        content
            .opacity(shown ? 1 : 0)
            .offset(y: shown || reduceMotion ? 0 : 10)
            .onAppear { play() }
            .onChange(of: trigger) { _, _ in shown = false; play() }
    }
    private func play() {
        guard !Headless.active else { shown = true; return }
        withAnimation(.spring(response: 0.4, dampingFraction: 0.85).delay(0.15 + Double(index) * 0.06)) { shown = true }
    }
}

/// How much one piece of evidence contributed, in words rather than raw numbers.
struct SignalStrength: View {
    let score: Int
    private var label: String { score >= 70 ? "Strong signal" : score >= 40 ? "Moderate signal" : "Weak signal" }
    private var bars: Int { score >= 70 ? 3 : score >= 40 ? 2 : 1 }
    var body: some View {
        HStack(spacing: 4) {
            HStack(alignment: .bottom, spacing: 2) {
                ForEach(0..<3, id: \.self) { i in
                    Capsule().fill(i < bars ? Color.rampartTeal : Color.secondary.opacity(0.25))
                        .frame(width: 3, height: CGFloat(5 + i * 3))
                }
            }
            Text(label).font(.caption).foregroundStyle(.secondary)
        }
        .fixedSize()
        .help("Contributed \(score) points to this detection")
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(label)
    }
}

/// Small copy button that confirms with a checkmark for a moment.
struct CopyHashButton: View {
    let value: String
    @StateVar private var copied = false
    var body: some View {
        Button {
            NSPasteboard.general.clearContents(); NSPasteboard.general.setString(value, forType: .string)
            copied = true
            Task { @MainActor in try? await Task.sleep(for: .seconds(1.5)); copied = false }
        } label: {
            Image(systemName: copied ? "checkmark" : "doc.on.doc")
                .foregroundStyle(copied ? Color.statusProtected : Color.secondary)
                .contentTransition(.symbolEffect(.replace))
                .frame(width: 16, height: 16)
        }
        .buttonStyle(.borderless)
        .help(copied ? "Copied" : "Copy SHA-256")
        .accessibilityLabel(copied ? "Copied" : "Copy SHA-256")
    }
}

/// Bottom banner offering a few seconds to undo the last action.
struct UndoBanner: View {
    let text: String
    let undo: () -> Void
    let dismiss: () -> Void
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: "arrow.uturn.backward.circle").foregroundStyle(.secondary)
            Text(text).lineLimit(1).truncationMode(.middle)
            Button("Undo", action: undo).keyboardShortcut("z", modifiers: .command)
            Button(action: dismiss) { Image(systemName: "xmark") }
                .buttonStyle(.borderless).foregroundStyle(.secondary).accessibilityLabel("Dismiss")
        }
        .font(.callout)
        .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
        .background(.regularMaterial, in: Capsule())
        .overlay(Capsule().strokeBorder(Color.primary.opacity(0.08)))
        .shadow(color: .black.opacity(0.12), radius: 8, y: 2)
        .accessibilityElement(children: .contain)
    }
}

/// Evidence text made readable: long pid lists collapse to a count with a disclosure,
/// and long paths truncate in the middle with the full text as a tooltip.
struct EvidenceDetail: View {
    let detail: String
    @StateVar private var showPIDs = false

    private var split: (text: String, pids: [String])? {
        guard let r = detail.range(of: #"pids?\s*[:=]?\s*\d+(\s*,\s*\d+)+"#, options: [.regularExpression, .caseInsensitive]) else { return nil }
        let pids = detail[r].components(separatedBy: CharacterSet.decimalDigits.inverted).filter { !$0.isEmpty }
        guard pids.count > 3 else { return nil }
        var text = detail.replacingCharacters(in: r, with: "\(pids.count) processes")
        text = text.trimmingCharacters(in: CharacterSet(charactersIn: " ;,"))
        return (text, pids)
    }

    var body: some View {
        if let s = split {
            VStack(alignment: .leading, spacing: 2) {
                line(s.text)
                DisclosureGroup(isExpanded: $showPIDs) {
                    Text(s.pids.joined(separator: ", ")).font(.caption.monospaced()).foregroundStyle(.secondary)
                        .textSelection(.enabled).fixedSize(horizontal: false, vertical: true)
                } label: {
                    Text("Process IDs").font(.caption).foregroundStyle(.secondary)
                }
            }
        } else {
            line(detail)
        }
    }

    private func line(_ t: String) -> some View {
        let pathy = t.count > 60 && t.contains("/") && !t.contains(" ")
        return Text(t).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            .lineLimit(pathy ? 1 : nil).truncationMode(.middle)
            .fixedSize(horizontal: false, vertical: !pathy)
            .help(t.count > 60 ? t : "")
    }
}
