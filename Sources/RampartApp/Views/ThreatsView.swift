import SwiftUI
import AppKit
import RampartShared

struct ThreatsView: View {
    enum Segment: String, CaseIterable, Identifiable { case detections = "Detections", quarantine = "Quarantine"; var id: String { rawValue } }
    @Environment(AppModel.self) private var model
    @StateVar private var segment: Segment = .detections
    @StateVar private var selectedDetections: Set<Detection.ID> = []
    private var selectedDetection: Detection.ID? {
        get { selectedDetections.count == 1 ? selectedDetections.first : nil }
        nonmutating set { selectedDetections = newValue.map { [$0] } ?? [] }
    }
    /// Detections the "Not a threat" sheet acts on (one, a selection, or a triage group).
    @StateVar private var teaching: TeachRequest?
    @StateVar private var showTriage = false
    @StateVar private var selectedQuarantine: Set<QuarantineRecord.ID> = []
    @StateVar private var notesExpanded = false
    @StateVar private var notesFilter = ""
    /// Notes the user dismissed (per-viewer convenience; comma-separated UUIDs).
    @AppStorage("threats.dismissedNotes") private var dismissedNotesRaw = ""
    @StateVar private var showInspector = true
    @StateVar private var handledExpanded = false
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
                    DetectionInspector(detection: d, record: record(for: d), related: group(for: d)?.members.filter { $0.id != d.id } ?? [],
                                       onDelete: scheduleDelete, onRestored: offerReQuarantine)
                } else if segment == .quarantine, selectedQuarantine.count == 1, let id = selectedQuarantine.first,
                          let r = visibleQuarantine.first(where: { $0.id == id }) {
                    DetectionInspector(detection: detection(for: r), record: r, onDelete: scheduleDelete, onRestored: offerReQuarantine)
                } else if segment == .detections, selectedDetections.count > 1 {
                    let picked = model.detections.filter { selectedDetections.contains($0.id) && !$0.resolved }
                    VStack(spacing: Spacing.m) {
                        EmptyStateView(symbol: "checklist", title: "\(selectedDetections.count) items selected",
                                       detail: "Teach \(Product.name) that these are not threats. Matching findings are resolved at once.")
                        Button { teaching = TeachRequest(detections: picked) } label: { Label("Not a Threat…", systemImage: "hand.thumbsup") }
                            .disabled(picked.isEmpty)
                    }
                } else {
                    EmptyStateView(symbol: "info.circle", title: segment == .quarantine && selectedQuarantine.count > 1 ? "\(selectedQuarantine.count) items selected" : "Select an item",
                                   detail: segment == .quarantine && selectedQuarantine.count > 1
                                       ? "Use Restore or Delete above to act on all of them."
                                       : "You'll see why \(Product.name) flagged it and what you can do.")
                }
            }
            .inspectorColumnWidth(min: 340, ideal: 400, max: 520)
        }
        .sheet(item: $teaching) { req in TeachSheet(request: req) }
        .sheet(isPresented: $showTriage) { NotesTriageSheet(notes: notes) { teaching = TeachRequest(detections: $0) } }
        .onAppear {
            if selectedDetection == nil { selectedDetection = needsYou(tierGroups).first?.primary.id }
            if selectedQuarantine.isEmpty, let f = model.quarantine.first?.id { selectedQuarantine = [f] }
        }
    }

    // MARK: Undo

    /// Hides the record at once and deletes it for real only after a short grace period.
    private func scheduleDelete(_ r: QuarantineRecord) { scheduleDelete([r]) }

    private func scheduleDelete(_ rs: [QuarantineRecord]) {
        guard !rs.isEmpty else { return }
        finishUndo(commit: true)
        let ids = Set(rs.map(\.id))
        pendingDeletes.formUnion(ids)
        selectedQuarantine.subtract(ids)
        let text = rs.count == 1 ? "Deleted \u{201C}\((rs[0].originalPath as NSString).lastPathComponent)\u{201D}" : "Deleted \(rs.count) items"
        present(UndoNote(text: text, undo: { pendingDeletes.subtract(ids); selectedQuarantine = ids },
                         commit: { for r in rs { await model.delete(r) }; pendingDeletes.subtract(ids) }))
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

    // MARK: Tiers: Needs you / Handled automatically / FYI

    /// One row per file, process or login item, in three tiers (see `DetectionPolicy`).
    private var tierGroups: [DetectionTier: [DetectionGroup]] {
        DetectionPolicy.groups(model.detections, quarantined: { record(for: $0) != nil })
    }
    private var dismissedNotes: Set<UUID> { Set(dismissedNotesRaw.split(separator: ",").compactMap { UUID(uuidString: String($0)) }) }
    private func needsYou(_ g: [DetectionTier: [DetectionGroup]]) -> [DetectionGroup] { g[.needsYou] ?? [] }
    private func handled(_ g: [DetectionTier: [DetectionGroup]]) -> [DetectionGroup] { g[.handled] ?? [] }
    private func fyi(_ g: [DetectionTier: [DetectionGroup]]) -> [DetectionGroup] {
        let gone = dismissedNotes
        return (g[.fyi] ?? []).filter { !gone.contains($0.primary.id) }
    }
    /// FYI detections (for "Review All Notes").
    private var notes: [Detection] { fyi(tierGroups).flatMap(\.members) }
    private func filtered(_ gs: [DetectionGroup]) -> [DetectionGroup] {
        let q = notesFilter.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return gs }
        return gs.filter { g in g.members.contains { d in
            [d.name, d.path ?? "", Self.tag(for: d, note: true)].contains { $0.lowercased().contains(q) }
                || d.evidence.contains { $0.title.lowercased().contains(q) }
        } }
    }
    /// The group a detection belongs to (for the inspector's "All signals on this item").
    private func group(for d: Detection) -> DetectionGroup? {
        tierGroups.values.lazy.flatMap { $0 }.first { g in g.members.contains { $0.id == d.id } }
    }

    private func dismissAllNotes() {
        var ids = dismissedNotes.union(fyi(tierGroups).map(\.primary.id))
        let live = Set(model.detections.map(\.id))
        ids = ids.intersection(live)            // forget ids that no longer exist
        dismissedNotesRaw = ids.prefix(3000).map(\.uuidString).joined(separator: ",")
        if let s = selectedDetection, ids.contains(s) { selectedDetection = needsYou(tierGroups).first?.primary.id }
    }

    /// Calm, accurate tag. FYI items say what they are; generic "suspicious" items name what was actually seen.
    static func tag(for d: Detection, note: Bool) -> String {
        if note {
            if d.category == .test { return "Test file" }
            if d.category == .persistence || d.name.hasPrefix("New login item") || d.name.hasPrefix("Login item") { return "New login item" }
            return DetectionPolicy.level(d) == .possible ? "Possible" : "Note"
        }
        guard d.category == .suspicious else { return d.category.label }
        switch d.evidence.max(by: { $0.score < $1.score })?.source {
        case .signing?: return "Code signing"
        case .behaviour?: return "Unusual activity"
        case .persistence?: return "Login item"
        case .network?: return "Network activity"
        case .heuristic?: return "Heuristic match"
        case .hash?, .yara?, .xprotect?: return "Known signature"
        default: return "Needs review"
        }
    }

    private func itemCell(_ g: DetectionGroup) -> some View {
        let d = g.primary
        return HStack(spacing: Spacing.s) {
            FileIcon(path: d.path)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 4) {
                    Text(SafeText.line(d.path.map { ($0 as NSString).lastPathComponent }.flatMap { $0.hasPrefix("btm:") ? nil : $0 } ?? d.name)).lineLimit(1)
                    if g.count > 1 {
                        Text("×\(g.count)").font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                            .help("Seen \(g.count) times, first \(Fmt.ago(g.firstSeen)), last \(Fmt.ago(g.lastSeen))")
                    }
                    if g.members.count > 1 {
                        Text("\(g.members.count) signals").font(.caption).foregroundStyle(.secondary)
                    }
                }
                Text(d.path.map { SafeText.path(($0 as NSString).abbreviatingWithTildeInPath) } ?? "—")
                    .font(.caption).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            }
        }
    }

    @ViewBuilder private var detectionsTable: some View {
        let g = tierGroups
        let needs = needsYou(g), done = handled(g), info = fyi(g)
        if model.detections.isEmpty {
            EmptyStateView(symbol: "checkmark.shield", title: "No threats found",
                           detail: model.mode == .live
                               ? "\(Product.name) checks new and changed files as they arrive. If it ever finds something, it will appear here with a plain explanation of why."
                               : "When \(Product.name) finds something, it will appear here with an explanation.", brand: true)
        } else {
            VStack(spacing: 0) {
                if needs.isEmpty {
                    HStack(spacing: Spacing.m) {
                        Image(systemName: "checkmark.shield").font(.title2).foregroundStyle(Color.statusProtected).accessibilityHidden(true)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Nothing needs you").font(.headline)
                            Text(done.isEmpty && info.isEmpty ? "No open findings."
                                 : "Everything below was handled automatically or is for your information only.")
                                .font(.callout).foregroundStyle(.secondary)
                        }
                        Spacer()
                    }
                    .padding(Spacing.l)
                    if !handledExpanded && !notesExpanded { Spacer() }
                } else {
                    HStack(spacing: Spacing.s) {
                        Text("Needs you (\(needs.count))").font(.headline)
                        Text("likely or confirmed threats, most serious first").font(.callout).foregroundStyle(.secondary)
                        Spacer()
                    }
                    .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
                    Table(needs.map(\.primary), selection: $selectedDetections) {
                        TableColumn("Item") { d in rowCell(d, in: needs) }
                            .width(min: 220, ideal: 300)
                        TableColumn("Type") { d in Badge(text: Self.tag(for: d, note: false)) }.width(min: 110, ideal: 150)
                        TableColumn("Confidence") { d in ConfidenceTag(level: DetectionPolicy.level(d), confidence: d.confidence) }
                            .width(min: 90, ideal: 110)
                        TableColumn("Severity") { d in
                            Label { Text(d.severity.label) } icon: { Image(systemName: d.severity.symbol).foregroundStyle(d.severity.tint) }
                        }
                        .width(min: 80, ideal: 90)
                        TableColumn("Status") { d in DetectionStatus(detection: d, quarantined: record(for: d) != nil) }.width(min: 110, ideal: 130)
                        TableColumn("Last seen") { d in Text(Fmt.ago(d.lastSeen ?? d.date)).foregroundStyle(.secondary) }.width(min: 90, ideal: 110)
                    }
                    .scrollContentBackground(.hidden)
                    .contextMenu(forSelectionType: Detection.ID.self) { ids in detectionMenu(ids) }
                }
                if !done.isEmpty { handledSection(done, roomy: needs.isEmpty) }
                if !info.isEmpty { fyiSection(info, roomy: needs.isEmpty) }
            }
        }
    }

    private func rowCell(_ d: Detection, in gs: [DetectionGroup]) -> some View {
        Group {
            if let g = gs.first(where: { $0.primary.id == d.id }) { itemCell(g) }
            else { itemCell(DetectionGroup(id: d.id.uuidString, tier: .fyi, primary: d, members: [d])) }
        }
    }

    @ViewBuilder private func detectionMenu(_ ids: Set<Detection.ID>) -> some View {
        if let id = ids.first, let d = model.detections.first(where: { $0.id == id }), let p = d.path, p.hasPrefix("/") {
            if FileManager.default.fileExists(atPath: p) {
                Button("Reveal in Finder") { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") }
                Divider()
            }
            Button("Copy Path") { copy(p) }
            if let h = d.sha256 { Button("Copy SHA-256") { copy(h) } }
        }
        // A grouped row acts on every open signal about that item.
        let rows = model.detections.filter { ids.contains($0.id) }
        let picked = rows.flatMap { d in group(for: d)?.members ?? [d] }.filter { !$0.resolved }
        if !picked.isEmpty {
            Divider()
            Button(picked.count == 1 ? "Not a Threat…" : "Not a Threat (\(picked.count) items)…") { teaching = TeachRequest(detections: picked) }
        }
    }

    private func sectionHeader(_ title: String, count: Int, subtitle: String, help: String, expanded: Bool, toggle: @escaping () -> Void) -> some View {
        Button {
            withAnimation(reduceMotion ? nil : .easeInOut(duration: 0.2)) { toggle() }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: "chevron.right").rotationEffect(.degrees(expanded ? 90 : 0)).font(.caption.weight(.semibold))
                    .foregroundStyle(.secondary)
                Text("\(title) (\(count))").font(.headline)
                Text(subtitle).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityLabel("\(title), \(count), \(subtitle)")
        .accessibilityValue(expanded ? "Expanded" : "Collapsed")
        .help(help)
    }

    private func handledSection(_ gs: [DetectionGroup], roomy: Bool) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Divider()
            HStack(spacing: Spacing.s) {
                sectionHeader("Handled automatically", count: gs.count, subtitle: "quarantined, blocked or resolved",
                              help: "Already dealt with. Quarantined files stay in Quarantine until you delete them.",
                              expanded: handledExpanded) { handledExpanded.toggle() }
                Spacer()
            }
            .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
            if handledExpanded {
                Table(gs.map(\.primary), selection: $selectedDetections) {
                    TableColumn("Item") { d in rowCell(d, in: gs) }.width(min: 220, ideal: 300)
                    TableColumn("What happened") { d in
                        Text(SafeText.line(record(for: d) != nil ? "Quarantined" : d.resolution ?? "Resolved"))
                            .foregroundStyle(.secondary).lineLimit(1)
                    }
                    .width(min: 160, ideal: 260)
                    TableColumn("When") { d in Text(Fmt.ago(d.lastSeen ?? d.date)).foregroundStyle(.secondary) }.width(min: 90, ideal: 110)
                }
                .scrollContentBackground(.hidden)
                .frame(minHeight: 140, idealHeight: roomy ? 300 : 200, maxHeight: roomy ? .infinity : 240)
                .contextMenu(forSelectionType: Detection.ID.self) { ids in detectionMenu(ids) }
                .transition(.opacity)
            }
        }
        .background(Color.primary.opacity(0.02))
    }

    private func fyiSection(_ all: [DetectionGroup], roomy: Bool) -> some View {
        let gs = filtered(all)
        return VStack(alignment: .leading, spacing: 0) {
            Divider()
            HStack(spacing: Spacing.s) {
                sectionHeader("FYI", count: all.count, subtitle: "possible findings and notes, no action needed",
                              help: "Single warning signs with nothing to confirm them, new login items, test files and status notes. Kept for reference; nothing was changed and they don't count as threats.",
                              expanded: notesExpanded) { notesExpanded.toggle() }
                Spacer()
                if notesExpanded {
                    TextField("Filter", text: $notesFilter).textFieldStyle(.roundedBorder).frame(maxWidth: 180).controlSize(.small)
                }
                Button("Review All…") { showTriage = true }.controlSize(.small)
                    .help("Groups similar items (for example developer builds) so you can trust each group at once")
                Button("Dismiss All") { dismissAllNotes() }.controlSize(.small)
                    .help("Hide these. New ones will still appear here.")
            }
            .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
            if notesExpanded {
                Table(gs.map(\.primary), selection: $selectedDetections) {
                    TableColumn("Item") { d in rowCell(d, in: gs) }.width(min: 220, ideal: 300)
                    TableColumn("Observation") { d in
                        Text(SafeText.line(d.evidence.filter { !DetectionPolicy.isContextOnly($0) }.max(by: { $0.score < $1.score })?.title ?? d.name))
                            .foregroundStyle(.secondary).lineLimit(1)
                    }
                    .width(min: 140, ideal: 200)
                    TableColumn("Type") { d in Badge(text: Self.tag(for: d, note: true)) }.width(min: 70, ideal: 100)
                    TableColumn("Last seen") { d in Text(Fmt.ago(d.lastSeen ?? d.date)).foregroundStyle(.secondary) }.width(min: 90, ideal: 110)
                }
                .scrollContentBackground(.hidden)
                .frame(minHeight: 160, idealHeight: roomy ? 400 : 220, maxHeight: roomy ? .infinity : 260)
                .contextMenu(forSelectionType: Detection.ID.self) { ids in detectionMenu(ids) }
                .transition(.opacity)
            }
        }
        .background(Color.primary.opacity(0.02))
    }

    private var quarantineTable: some View {
        QuarantineManagerView(records: visibleQuarantine, selection: $selectedQuarantine, showInspector: $showInspector,
                              detection: { detection(for: $0) }, onDelete: { scheduleDelete($0) })
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
    /// Other signals about the same file, process or login item (grouped into one row).
    var related: [Detection] = []
    var onDelete: (QuarantineRecord) -> Void = { _ in }
    var onRestored: (QuarantineRecord, Detection?) -> Void = { _, _ in }
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var whyExpanded = true
    @StateVar private var showRestore = false
    @StateVar private var showDelete = false
    @StateVar private var teaching: TeachRequest?

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
                    if !related.isEmpty { relatedSignals }
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
        .sheet(item: $teaching) { req in TeachSheet(request: req) }
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
                Text(SafeText.line(displayName, max: 160)).font(.title3.weight(.semibold)).lineLimit(2)
                HStack(spacing: 6) {
                    if let d = detection { Badge(text: ThreatsView.tag(for: d, note: DetectionPolicy.tier(d, quarantined: record != nil) == .fyi)) }
                    if record != nil { Badge(text: "Quarantined", tint: .gray) }
                }
            }
        }
    }

    private func why(_ d: Detection) -> some View {
        let primary = d.evidence.max { $0.score < $1.score }
        return DisclosureGroup(isExpanded: $whyExpanded) {
            VStack(alignment: .leading, spacing: Spacing.m) {
                (Text("Detected as ") + Text(SafeText.line(d.name)).bold() + Text(" by ") + Text(primary?.source.label ?? "\(Product.name)").bold() + Text("."))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(Array(d.evidence.sorted { $0.score > $1.score }.enumerated()), id: \.element) { idx, e in
                    HStack(alignment: .top, spacing: Spacing.s) {
                        Image(systemName: e.source.symbol).foregroundStyle(Color.rampartTeal).frame(width: 20)
                        VStack(alignment: .leading, spacing: 3) {
                            HStack(alignment: .firstTextBaseline, spacing: Spacing.s) {
                                Text(SafeText.line(e.title)).font(.body.weight(.medium))
                                Spacer(minLength: 0)
                                SignalStrength(score: e.score, definitive: DetectionPolicy.isDefinitive(e), context: DetectionPolicy.isContextOnly(e))
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
                confidence(d)
            }
            .padding(.top, Spacing.s)
        } label: {
            Label("Why was this flagged?", systemImage: "questionmark.bubble").font(.headline)
        }
    }

    /// Honest wording: Confirmed only for definitive evidence; heuristics say Likely / Possible.
    private func confidence(_ d: Detection) -> some View {
        let c = d.confidence
        let level = DetectionPolicy.level(d)
        let text: String
        switch level {
        case .confirmed: text = "Confirmed (\(c)%): matched a known threat."
        case .likely: text = "Likely (\(c)%): several warning signs, or one strong one. It could still be a false positive."
        case .possible: text = "Possible (\(c)%): a single warning sign with nothing to confirm it. Often harmless."
        case .informational: text = d.category == .test ? "Test file: harmless by design." : "Informational (\(c)%): logged for reference."
        }
        return HStack(spacing: Spacing.s) {
            Gauge(value: Double(c), in: 0...100) { EmptyView() }
                .gaugeStyle(.accessoryLinearCapacity).tint(Color.rampartTeal).frame(width: 80)
            Text(text).font(.callout)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
    }

    /// Every other signal RamPart has about this item (one row per subject in the list).
    private var relatedSignals: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Other signals on this item (\(related.count))").font(.headline)
            ForEach(related) { r in
                HStack(alignment: .firstTextBaseline, spacing: Spacing.s) {
                    ConfidenceTag(level: DetectionPolicy.level(r), confidence: r.confidence)
                    Text(SafeText.line(r.name)).lineLimit(2)
                    Spacer(minLength: 0)
                    Text(Fmt.ago(r.lastSeen ?? r.date)).font(.caption).foregroundStyle(.secondary)
                }
                .font(.callout)
            }
        }
    }

    @ViewBuilder private var whatWeDid: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Text("What \(Product.name) did").font(.headline)
            if let r = record {
                Text("Moved to quarantine on \(r.date.formatted(date: .abbreviated, time: .shortened)). The file is encrypted and can't run.")
            } else if detection?.resolved == true {
                Text(detection?.resolution.map { "\($0)." } ?? "This item was resolved and is no longer flagged.")
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
                if let d = detection {
                    row("First seen", (d.firstSeen ?? d.date).formatted(date: .abbreviated, time: .shortened))
                    if let n = d.count, n > 1 {
                        row("Last seen", (d.lastSeen ?? d.date).formatted(date: .abbreviated, time: .shortened))
                        row("Times seen", String(n))
                    }
                }
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
            Text(k == "Location" ? SafeText.path(v) : SafeText.line(v, max: 400)).font(mono ? .callout.monospaced() : .callout).textSelection(.enabled).lineLimit(k == "Location" ? 1 : 3).truncationMode(.middle).help(k == "Location" ? v : "")
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

    /// True only when the evidence records that RamPart's own process stop actually succeeded
    /// (the daemon's remediation result, e.g. "killed 2 process(es)"). Detector wording such as
    /// "stopped" in a rule description is not proof, so it doesn't count.
    private var processStopped: Bool {
        guard let d = detection else { return false }
        return d.evidence.contains { e in
            let t = (e.title + " " + e.detail).lowercased()
            if ["not killed", "failed", "couldn't", "could not", "unable", "already gone"].contains(where: { t.contains($0) }) { return false }
            return t.range(of: #"\bkilled [1-9][0-9]* process"#, options: .regularExpression) != nil
                || t.range(of: #"\b(process|processes) (was |were )?(stopped|terminated) by "#, options: .regularExpression) != nil
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
        } else if let p = detection?.path {
            Button { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") } label: {
                Label(short ? "Reveal" : "Reveal in Finder", systemImage: "folder").fixedSize()
            }
            .help("Reveal in Finder")
        }
    }

    @ViewBuilder private func reportButton(short: Bool) -> some View {
        if let d = detection, !d.resolved, record == nil {
            Button { teaching = TeachRequest(detections: [d]) } label: { Label(short ? "Not a Threat" : "Not a Threat…", systemImage: "hand.thumbsup").fixedSize() }
                .help("Trust this file, its app's developer, or its folder. Stays on this Mac; nothing is sent anywhere.")
        }
    }

    private func copyDetails() {
        var s = "\(Product.name) detection\nName: \(detection?.name ?? record?.detectionName ?? "")\n"
        if let p = detection?.path ?? record?.originalPath { s += "Path: \(p)\n" }
        if let sha { s += "SHA-256: \(sha)\n" }
        if let d = detection {
            s += "Confidence: \(DetectionPolicy.level(d).label) (\(d.confidence)%)\n"
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
        let conf = detection.map { DetectionPolicy.level($0).label.lowercased() } ?? "unknown"
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Restore \"\(SafeText.line(name))\"?").font(.title2.weight(.semibold))
            Text("\(Product.name) flagged this as \(detection?.category.label ?? record.detectionName) (confidence: \(conf)). Restore it only if you trust where it came from.")
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

/// Detections a "Not a threat" decision applies to.
struct TeachRequest: Identifiable {
    let id = UUID()
    let detections: [Detection]
}

/// Where a finding lives, for suggesting what to trust. Local only: everything becomes an allow rule on this Mac.
enum TeachTarget {
    /// Outermost .app bundle containing the path.
    static func app(_ path: String) -> String? {
        guard let r = path.range(of: ".app/") ?? (path.hasSuffix(".app") ? path.range(of: ".app", options: .backwards) : nil) else { return nil }
        return String(path[..<r.upperBound]).trimmingCharacters(in: CharacterSet(charactersIn: "/")).withSlash
    }

    /// The folder worth trusting: the build dir, agent workspace, app bundle, Application Support folder, or the parent folder.
    static func folder(_ path: String) -> String {
        let home = NSHomeDirectory()
        for m in ["/.build/", "/DerivedData/", "/node_modules/", "/target/"] {
            if let r = path.range(of: m) { return String(path[..<r.upperBound].dropLast()) }
        }
        if let r = path.range(of: "/.build-"), let end = path[r.upperBound...].firstIndex(of: "/") { return String(path[..<end]) }
        if path.hasPrefix("/private/tmp/claude-") || path.hasPrefix("/tmp/claude-") {
            let parts = path.split(separator: "/")
            let n = path.hasPrefix("/private/") ? 3 : 2
            return "/" + parts.prefix(n).joined(separator: "/")
        }
        if let a = app(path) { return a }
        for base in [home + "/Library/Application Support/", "/Library/Application Support/"] where path.hasPrefix(base) {
            if let f = path.dropFirst(base.count).split(separator: "/").first { return base + f }
        }
        return (path as NSString).deletingLastPathComponent
    }

    static func groupLabel(_ folder: String, sample: Detection) -> String {
        let f = (folder as NSString).abbreviatingWithTildeInPath
        if ["/.build", "/DerivedData", "/node_modules", "/target"].contains(where: { folder.hasSuffix($0) }) || folder.contains("/.build-")
            || folder.hasPrefix("/private/tmp/claude-") { return "Developer builds in \(f)" }
        if folder.hasSuffix(".app") { return "Files inside \((folder as NSString).lastPathComponent)" }
        if folder.contains("/Application Support/") { return "App data in \(f)" }
        return "\(sample.evidence.max(by: { $0.score < $1.score })?.title ?? sample.name) in \(f)"
    }
}

private extension String { var withSlash: String { hasPrefix("/") ? self : "/" + self } }

/// "Not a threat": trust the file, its app's developer (Team ID), the app bundle, or the folder.
/// Creates local allow rules through the daemon, which resolves every matching open finding at once
/// and suppresses future matches.
struct TeachSheet: View {
    enum Choice: Hashable { case file, developer, app, folder }
    let request: TeachRequest
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var choice: Choice = .folder
    @StateVar private var working = false
    @StateVar private var error: String?

    private var items: [Detection] { request.detections }
    private var paths: [String] { items.compactMap(\.path) }
    private var apps: [String] { Array(Set(paths.compactMap(TeachTarget.app))).sorted() }
    private var folders: [String] { Array(Set(paths.map(TeachTarget.folder))).sorted() }
    private var canFile: Bool { items.contains { $0.sha256 != nil } }
    private var title: String {
        items.count == 1 ? "\"\(items[0].path.map { ($0 as NSString).lastPathComponent } ?? items[0].name)\" is not a threat" : "\(items.count) items are not threats"
    }
    /// Open findings a folder choice would also resolve (preview; the daemon does the real matching).
    private var alsoResolved: Int {
        let fs = choice == .folder ? folders : choice == .app ? apps : []
        guard !fs.isEmpty else { return 0 }
        let mine = Set(items.map(\.id))
        return model.detections.filter { d in
            !d.resolved && !mine.contains(d.id) && d.path.map { p in fs.contains { p == $0 || p.hasPrefix($0 + "/") } } == true
        }.count
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text(SafeText.line(title, max: 160)).font(.title2.weight(.semibold)).lineLimit(2)
            Text("\(Product.name) will remember this on this Mac and stop flagging matching items. You can remove the rule anytime in Rules. Nothing is sent anywhere.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Picker("", selection: $choice) {
                Text(items.count == 1 ? "Trust this file (by fingerprint)" : "Trust these files (by fingerprint)").tag(Choice.file).disabled(!canFile)
                Text(apps.isEmpty ? "Trust this developer (Team ID)" : "Trust the developer of \(apps.map { ($0 as NSString).lastPathComponent }.joined(separator: ", ")) (Team ID)")
                    .tag(Choice.developer)
                if !apps.isEmpty {
                    Text("Trust \(apps.count == 1 ? (apps[0] as NSString).lastPathComponent : "these \(apps.count) apps") (everything inside)").tag(Choice.app)
                }
                Text(folders.count == 1 ? "Trust this folder: \((folders[0] as NSString).abbreviatingWithTildeInPath)" : "Trust these \(folders.count) folders")
                    .tag(Choice.folder)
            }
            .pickerStyle(.radioGroup).labelsHidden()
            if choice == .developer {
                Text("Works only for code signed by a registered developer. Ad-hoc or unsigned code has no Team ID; trust the app or folder instead.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if alsoResolved > 0 {
                Label("Also resolves \(alsoResolved) other open finding\(alsoResolved == 1 ? "" : "s") in the same place.", systemImage: "checkmark.circle")
                    .font(.callout)
            }
            if let error { Label(error, systemImage: "exclamationmark.triangle").foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true) }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Not a Threat") { Task { await apply() } }.keyboardShortcut(.defaultAction).disabled(working)
            }
        }
        .padding(Spacing.xl).frame(width: 500)
        .onAppear { if items.count == 1, canFile, TeachTarget.app(paths.first ?? "") == nil { choice = .file } }
    }

    private func rules() -> [AllowRuleSpec] {
        switch choice {
        case .file:
            return Array(Set(items.compactMap(\.sha256))).map { h in
                AllowRuleSpec(scope: .fileHash, value: h.lowercased(), name: items.first { $0.sha256 == h }?.path.map { ($0 as NSString).lastPathComponent } ?? "File")
            }
        case .developer:
            // The daemon reads the Team ID from the signature of this path (or its app); the app never guesses it.
            let targets = apps.isEmpty ? Array(Set(paths)) : apps
            return targets.map { AllowRuleSpec(scope: .developer, value: $0, name: ($0 as NSString).lastPathComponent) }
        case .app: return apps.map { AllowRuleSpec(scope: .folder, value: $0, name: ($0 as NSString).lastPathComponent) }
        case .folder: return folders.map { AllowRuleSpec(scope: .folder, value: $0, name: ($0 as NSString).lastPathComponent) }
        }
    }

    private func apply() async {
        working = true; defer { working = false }
        model.lastError = nil
        var failed: [String] = []
        for r in rules() where !(await model.addAllowRule(r)) { failed.append(model.lastError ?? r.value) }
        await model.refresh(heavy: false)
        if failed.isEmpty { dismiss() } else { error = failed.joined(separator: "\n") }
    }
}

/// "Review all notes": groups similar notes by where they live ("64 developer builds: trust all?").
struct NotesTriageSheet: View {
    let notes: [Detection]
    var teach: ([Detection]) -> Void
    @Environment(\.dismiss) private var dismiss

    private struct Group: Identifiable { let id: String; let label: String; let items: [Detection] }
    private var groups: [Group] {
        let by = Dictionary(grouping: notes.filter { !$0.resolved && $0.path != nil }) { TeachTarget.folder($0.path!) }
        return by.map { Group(id: $0.key, label: TeachTarget.groupLabel($0.key, sample: $0.value[0]), items: $0.value) }
            .sorted { $0.items.count != $1.items.count ? $0.items.count > $1.items.count : $0.label < $1.label }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Review notes").font(.title2.weight(.semibold))
            Text("Similar notes are grouped. Trust a group to resolve all of it and stop future matches, or leave it as a note.")
                .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            if groups.isEmpty {
                Text("No open notes.").foregroundStyle(.secondary)
            } else {
                List(groups) { g in
                    HStack(spacing: Spacing.s) {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("\(g.items.count) · \(SafeText.line(g.label))").lineLimit(2)
                            Text(SafeText.line(Set(g.items.compactMap { $0.evidence.max(by: { $0.score < $1.score })?.title }).sorted().joined(separator: ", "), max: 300))
                                .font(.caption).foregroundStyle(.secondary).lineLimit(1)
                        }
                        Spacer()
                        Button(g.items.count == 1 ? "Not a Threat…" : "Trust All \(g.items.count)…") {
                            let items = g.items
                            dismiss()
                            DispatchQueue.main.async { teach(items) }
                        }
                    }
                    .padding(.vertical, 2)
                }
                .frame(minHeight: 260)
            }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl).frame(width: 560)
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
/// Per-evidence strength. "Definitive" only for a known-threat match; a heuristic is at most a "Warning sign".
struct SignalStrength: View {
    let score: Int
    var definitive = false
    var context = false
    private var label: String { context ? "Context" : definitive ? "Definitive" : score >= 60 ? "Warning sign" : "Weak sign" }
    private var bars: Int { context ? 0 : definitive ? 3 : score >= 60 ? 2 : 1 }
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
            Text(SafeText.line(text, max: 300)).lineLimit(1).truncationMode(.middle)
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
        let t = SafeText.line(t, max: 1000)   // hx8: evidence text is attacker-influenced
        let pathy = t.count > 60 && t.contains("/") && !t.contains(" ")
        return Text(t).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
            .lineLimit(pathy ? 1 : nil).truncationMode(.middle)
            .fixedSize(horizontal: false, vertical: !pathy)
            .help(t.count > 60 ? t : "")
    }
}

/// "Confirmed 98%", "Likely 70%", "Possible 45%", "Info".
struct ConfidenceTag: View {
    let level: ConfidenceLevel
    let confidence: Int
    var body: some View {
        let text = level == .informational ? "Info" : "\(level.label) \(confidence)%"
        Text(text).font(.callout.monospacedDigit())
            .foregroundStyle(level == .confirmed ? Color.statusAction : level == .likely ? Color.statusAttention : Color.secondary)
            .help(level.explanation)
            .accessibilityLabel("\(level.label), \(confidence) percent")
    }
}
