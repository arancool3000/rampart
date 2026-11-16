import SwiftUI
import AppKit
import Charts
import RampartShared
import RampartRefresh

/// "Refresh": storage and speed. Honest by design: everything goes to the Trash with an undo, nothing is
/// removed without a preview, and there is no fake "RAM cleaning".
struct RefreshView: View {
    @StateVar private var model = RefreshModel.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                switch model.tab {
                case .storage: RefreshStorageSection(model: model)
                case .map: RefreshDiskMapSection(model: model)
                case .speed: RefreshSpeedSection(model: model)
                }
            }
            .contentColumn()
        }
        .navigationTitle("Refresh")
        .sheet(isPresented: $model.showPreview) { RefreshPreviewSheet(model: model) }
    }

    private var header: some View {
        HStack(alignment: .center, spacing: Spacing.l) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Refresh").font(.title2.weight(.semibold)).fontDesign(.monospaced)
                Text("Free up space safely and see what's slowing your Mac down. Everything goes to the Trash first, so you can put it back.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            Picker("Section", selection: $model.tab) {
                ForEach(RefreshModel.Tab.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            .frame(width: 260)
        }
    }
}

// MARK: - Risk styling

extension RefreshRisk {
    var tint: Color {
        switch self {
        case .safe: return Palette.mint
        case .low: return .rampartTeal
        case .review: return Palette.amber
        case .infoOnly: return .secondary
        }
    }
    var symbol: String {
        switch self {
        case .safe: return "checkmark.seal.fill"
        case .low: return "checkmark.circle"
        case .review: return "eye"
        case .infoOnly: return "info.circle"
        }
    }
}

extension RefreshCategory {
    var chartTint: Color {
        switch self {
        case .appCaches: return .rampartTeal
        case .oldLogs, .crashReports: return Palette.mint
        case .xcode, .projectBuilds: return .indigo
        case .packageCaches, .homebrew: return .purple
        case .oldDownloads: return Palette.amber
        case .duplicates, .largeOldFiles: return .orange
        case .leftovers: return Palette.coral
        default: return .gray
        }
    }
}

// MARK: - Storage

struct RefreshStorageSection: View {
    @Bindable var model: RefreshModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            hero
            if let o = model.lastOutcome, model.phase == .done { RefreshResultsCard(model: model, outcome: o) }
            if let msg = model.undoMessage {
                StatusLabel(text: msg, symbol: "arrow.uturn.backward.circle.fill", tint: .rampartTeal).font(.callout)
            }
            if !model.results.isEmpty {
                SectionHeader("What can go", trailing: AnyView(
                    Button("Reset to smart selection") { model.resetToSmartSelection() }.buttonStyle(.link).font(.callout)
                        .help("Select only the items RamPart considers safe")))
                ForEach(model.actionable.filter { !$0.items.isEmpty || $0.note != nil }) { r in
                    RefreshCategoryCard(model: model, result: r)
                }
                let empty = model.actionable.filter { $0.items.isEmpty && $0.note == nil }
                if !empty.isEmpty {
                    Text("Nothing to clean in: " + empty.map(\.category.title).joined(separator: ", ") + ".")
                        .font(.caption).foregroundStyle(.secondary)
                }
                SectionHeader("For your information")
                ForEach(model.infoOnly) { r in RefreshInfoCard(model: model, result: r) }
            } else if model.phase == .idle {
                intro
            }
        }
    }

    private var hero: some View {
        HStack(spacing: Spacing.xl) {
            RefreshRing(model: model).frame(width: 190, height: 190)
            VStack(alignment: .leading, spacing: Spacing.m) {
                switch model.phase {
                case .scanning(let what):
                    Text("Looking for space…").font(.title3.weight(.semibold)).fontDesign(.monospaced)
                    HStack(spacing: 8) { ProgressView().controlSize(.small); Text(SafeText.line(what)).font(.callout).foregroundStyle(.secondary).contentTransition(.opacity) }
                    Button("Stop") { model.cancelScan() }.secondaryActionStyle()
                case .cleaning:
                    Text("Moving to the Trash…").font(.title3.weight(.semibold)).fontDesign(.monospaced)
                    ProgressView().controlSize(.small)
                default:
                    if model.results.isEmpty {
                        Text("Smart Refresh").font(.title3.weight(.semibold)).fontDesign(.monospaced)
                        Text("RamPart looks for caches, old logs, build leftovers and more, explains each one and pre-selects only what is safe.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    } else {
                        Text("\(model.selectedBytes.refreshFormatted) selected").font(.title2.weight(.semibold)).fontDesign(.monospaced)
                            .contentTransition(.numericText())
                        Text("\(model.reclaimableBytes.refreshFormatted) found in \(model.actionable.filter { !$0.items.isEmpty }.count) categories. Only safe items are selected; review the rest below.")
                            .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                    }
                    HStack(spacing: Spacing.m) {
                        Button {
                            model.smartRefresh()
                        } label: {
                            Label(model.results.isEmpty ? "Smart Refresh" : "Review & Refresh", systemImage: "sparkles")
                        }
                        .buttonStyle(GlowButtonStyle()).controlSize(.large)
                        .disabled(!model.results.isEmpty && model.selectedItems.isEmpty)
                        .keyboardShortcut(.defaultAction)
                        if !model.results.isEmpty {
                            Button("Scan again") { model.scan() }.secondaryActionStyle()
                        }
                    }
                    Toggle("Include personal folders (Downloads, duplicates, large old files)", isOn: $model.includePersonal)
                        .toggleStyle(.checkbox).font(.callout)
                        .help("macOS may ask once for permission to read these folders. Nothing in them is ever pre-selected except old installers.")
                }
                if let v = model.volume {
                    Text("\(v.available.refreshFormatted) free of \(v.total.refreshFormatted)" + (v.purgeable > 0 ? " · \(v.purgeable.refreshFormatted) more that macOS can free on its own (purgeable)" : ""))
                        .font(.caption).foregroundStyle(.secondary)
                        .help("Purgeable space is held by iCloud files that can be downloaded again, local snapshots and caches macOS manages. macOS frees it automatically when needed.")
                }
            }
            Spacer(minLength: 0)
        }
        .card(padding: Spacing.xl, tint: .rampartTeal)
        .animation(reduceMotion ? nil : .snappy(duration: 0.25), value: model.phase)
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("How Refresh keeps you safe")
            ForEach([
                ("trash", "Everything goes to the Trash first, with one-click undo. Emptying the Trash always asks."),
                ("lock.shield", "macOS system files, app contents, keychains, iCloud Drive and files that are open are refused, even if selected."),
                ("doc.richtext", "Documents, photos, Desktop and Documents are never pre-selected."),
                ("memorychip", "No fake “RAM cleaning”: macOS manages memory well. Speed shows only real actions."),
            ], id: \.0) { s, t in
                HStack(alignment: .top, spacing: Spacing.m) {
                    Image(systemName: s).foregroundStyle(Color.rampartTeal).frame(width: 22)
                    Text(t).font(.callout)
                }
            }
        }
        .card()
    }
}

/// Ring chart of reclaimable space by category; the centre shows what's selected.
struct RefreshRing: View {
    @Bindable var model: RefreshModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        let data = model.actionable.filter { $0.totalBytes > 0 }
        ZStack {
            if data.isEmpty {
                Circle().stroke(Color.rampartTeal.opacity(0.18), lineWidth: 18).padding(9)
            } else {
                Chart(data) { r in
                    SectorMark(angle: .value("Bytes", Double(r.totalBytes)), innerRadius: .ratio(0.74), angularInset: 1.5)
                        .cornerRadius(3)
                        .foregroundStyle(r.category.chartTint.opacity(r.selectedBytes > 0 ? 1 : 0.35))
                }
                .chartLegend(.hidden)
                .animation(reduceMotion ? nil : .smooth(duration: 0.5), value: model.selectedBytes)
            }
            VStack(spacing: 2) {
                if model.isScanning { ProgressView().controlSize(.small) }
                Text(model.results.isEmpty ? "—" : model.selectedBytes.refreshFormatted)
                    .font(.title3.weight(.semibold)).fontDesign(.monospaced).monospacedDigit()
                Text(model.results.isEmpty ? "not scanned" : "to free").font(.caption).foregroundStyle(.secondary)
            }
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(model.results.isEmpty ? "Not scanned yet" : "\(model.selectedBytes.refreshFormatted) selected of \(model.reclaimableBytes.refreshFormatted) found")
    }
}

struct RefreshCategoryCard: View {
    @Bindable var model: RefreshModel
    let result: RefreshCategoryResult
    @StateVar private var expanded = false

    var body: some View {
        let c = result.category
        VStack(alignment: .leading, spacing: Spacing.m) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: c.symbol, tint: c.chartTint, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: 6) {
                        Text(c.title).font(.headline)
                        Badge(text: c.risk.label, tint: c.risk.tint)
                    }
                    Text(c.explanation).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 2) {
                    Text(result.totalBytes.refreshFormatted).font(.headline.monospacedDigit())
                    if result.selectedBytes > 0 { Text("\(result.selectedBytes.refreshFormatted) selected").font(.caption).foregroundStyle(.secondary) }
                }
                if !result.items.isEmpty {
                    Toggle("", isOn: Binding(get: { model.categoryState(result) ?? true }, set: { model.toggle(c, on: $0) }))
                        .toggleStyle(.switch).labelsHidden().controlSize(.small)
                        .accessibilityLabel("Select all \(c.title)")
                }
            }
            if let note = result.note { Text(SafeText.line(note, max: 240)).font(.caption).foregroundStyle(.secondary) }
            if !result.items.isEmpty {
                DisclosureGroup(isExpanded: $expanded) {
                    LazyVStack(alignment: .leading, spacing: 4) {
                        ForEach(result.items.prefix(300)) { it in RefreshItemRow(model: model, item: it) }
                        if result.items.count > 300 { Text("and \(result.items.count - 300) more").font(.caption).foregroundStyle(.secondary) }
                    }
                } label: {
                    Text("\(result.items.count) item\(result.items.count == 1 ? "" : "s")").font(.callout)
                }
                .disclosureGroupStyle(FullRowDisclosureStyle())
            }
        }
        .card()
    }
}

struct RefreshItemRow: View {
    @Bindable var model: RefreshModel
    let item: RefreshItem
    @StateVar private var hover = false

    var body: some View {
        HStack(alignment: .top, spacing: Spacing.s) {
            Toggle("", isOn: Binding(get: { item.selected }, set: { _ in model.toggle(item: item) }))
                .toggleStyle(.checkbox).labelsHidden()
                .accessibilityLabel("Select \(SafeText.line(item.name))")
            VStack(alignment: .leading, spacing: 1) {
                Text(SafeText.line(item.name)).font(.callout).lineLimit(1).truncationMode(.middle)
                Text(SafeText.path(item.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")))
                    .font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
                if !item.reason.isEmpty { Text(SafeText.line(item.reason, max: 240)).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 1) {
                Text(item.bytes.refreshFormatted).font(.callout.monospacedDigit())
                if item.sharedBytes > 0 { Text("+\(item.sharedBytes.refreshFormatted) shared").font(.caption2).foregroundStyle(.secondary).help("Shared with an APFS clone: removing this may not free that part.") }
                if let d = item.lastOpened ?? item.modified { Text(Fmt.ago(d)).font(.caption2).foregroundStyle(.tertiary) }
            }
        }
        .padding(.vertical, 3).padding(.horizontal, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(hover ? 0.05 : 0)))
        .onHover { hover = $0 }
        .contentShape(Rectangle())
        .onTapGesture { model.toggle(item: item) }
        .contextMenu {
            Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: item.path)]) }
            if AIChatModel.shared.enabled { Button("Ask the AI Assistant about this") { model.askAI(about: item) } }
        }
    }
}

struct RefreshInfoCard: View {
    @Bindable var model: RefreshModel
    let result: RefreshCategoryResult
    @StateVar private var expanded = false

    var body: some View {
        let c = result.category
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: c.symbol, tint: .gray, size: 30)
                VStack(alignment: .leading, spacing: 2) {
                    Text(c.title).font(.headline)
                    Text(c.explanation).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                if result.totalBytes > 0 { Text(result.totalBytes.refreshFormatted).font(.headline.monospacedDigit()) }
            }
            if let n = result.note { Text(SafeText.line(n, max: 240)).font(.caption).foregroundStyle(.secondary) }
            if c == .trash, model.trashBytes > 0 {
                if model.confirmEmptyTrash {
                    HStack {
                        Text("Permanently delete \(model.trashBytes.refreshFormatted) in the Trash? This can't be undone.").font(.callout)
                        Spacer()
                        Button("Cancel") { model.confirmEmptyTrash = false }.secondaryActionStyle()
                        Button("Empty Trash", role: .destructive) { model.emptyTrash() }.buttonStyle(.borderedProminent).tint(Palette.coral)
                    }
                    .padding(Spacing.s).background(Palette.coral.opacity(0.1), in: RoundedRectangle(cornerRadius: 8))
                } else {
                    Button("Empty Trash…") { model.confirmEmptyTrash = true }.secondaryActionStyle()
                }
            }
            if !result.items.isEmpty, c != .trash {
                DisclosureGroup(isExpanded: $expanded) {
                    ForEach(result.items.prefix(50)) { it in
                        HStack {
                            Text(SafeText.line(it.name)).font(.callout).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(it.bytes.refreshFormatted).font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                        }
                        .contextMenu { Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: it.path)]) } }
                    }
                } label: { Text("\(result.items.count) item\(result.items.count == 1 ? "" : "s")").font(.callout) }
                .disclosureGroupStyle(FullRowDisclosureStyle())
            }
        }
        .card(padding: Spacing.m)
    }
}

// MARK: - Preview & results

struct RefreshPreviewSheet: View {
    @Bindable var model: RefreshModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        let items = model.selectedItems
        let refused = Set(model.previewRefused.map(\.0.path))
        let ok = items.filter { !refused.contains($0.path) }
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: "trash", tint: .rampartTeal, size: 40)
                VStack(alignment: .leading) {
                    Text("Move \(ok.count) item\(ok.count == 1 ? "" : "s") to the Trash?").font(.title2.weight(.semibold))
                    Text("Frees about \(ok.reduce(0) { $0 + $1.bytes }.refreshFormatted) once the Trash is emptied. You can undo this from the results screen.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            if RefreshModel.dryRun { Badge(text: "Dry run: nothing will be moved", tint: Palette.amber) }
            List {
                Section("Will move to the Trash") {
                    ForEach(ok) { it in
                        HStack {
                            Image(systemName: it.category.symbol).foregroundStyle(it.category.chartTint).frame(width: 18)
                            Text(SafeText.path(it.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
                            Spacer()
                            Text(it.bytes.refreshFormatted).font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                        }
                    }
                }
                if !model.previewRefused.isEmpty {
                    Section("Skipped for safety") {
                        ForEach(model.previewRefused, id: \.0.path) { it, why in
                            VStack(alignment: .leading) {
                                Text(SafeText.line(it.name)).font(.callout)
                                Text(why.explanation).font(.caption).foregroundStyle(.secondary)
                            }
                        }
                    }
                }
            }
            .frame(minHeight: 260)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Move to Trash") { model.confirmClean() }.buttonStyle(GlowButtonStyle()).keyboardShortcut(.defaultAction).disabled(ok.isEmpty)
            }
        }
        .padding(Spacing.xl)
        .frame(width: 620, height: 520)
    }
}

struct RefreshResultsCard: View {
    @Bindable var model: RefreshModel
    let outcome: RefreshOutcome
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var appeared = false

    var body: some View {
        HStack(spacing: Spacing.l) {
            Image(systemName: "checkmark.circle.fill").font(.system(size: 40)).foregroundStyle(Palette.mint)
                .scaleEffect(appeared || reduceMotion ? 1 : 0.6).opacity(appeared ? 1 : 0)
            VStack(alignment: .leading, spacing: 4) {
                Text(outcome.dryRun ? "Dry run: \(outcome.freedBytes.refreshFormatted) would be freed" : "\(outcome.freedBytes.refreshFormatted) moved to the Trash")
                    .font(.title3.weight(.semibold)).fontDesign(.monospaced)
                Text(summary).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            if !model.lastUndo.isEmpty && !outcome.dryRun {
                Button { model.undoLast() } label: { Label("Undo", systemImage: "arrow.uturn.backward") }
                    .secondaryActionStyle().keyboardShortcut("z", modifiers: .command)
            }
        }
        .card(tint: Palette.mint)
        .onAppear { withAnimation(reduceMotion ? .easeOut(duration: 0.15) : .spring(response: 0.45, dampingFraction: 0.7)) { appeared = true } }
    }

    private var summary: String {
        var parts = ["\(outcome.trashed.count) item\(outcome.trashed.count == 1 ? "" : "s")"]
        if !outcome.refused.isEmpty { parts.append("\(outcome.refused.count) skipped for safety") }
        if !outcome.failed.isEmpty { parts.append("\(outcome.failed.count) couldn't be moved") }
        return parts.joined(separator: " · ") + ". The space is freed when you empty the Trash; until then you can undo."
    }
}
