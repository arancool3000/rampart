import SwiftUI
import RampartShared
import AppKit
import UniformTypeIdentifiers
import Charts

/// Protection Activity: every protective decision and state change, newest first, in plain English.
/// Rows open an inspector with the full explanation and the actions that really work for that event.
struct ActivityView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var filter: ActivityCategory? = nil
    @StateVar private var search = ""
    @StateVar private var selected: UUID?
    @StateVar private var showInspector = false
    @StateVar private var expanded: Set<UUID> = []

    private var items: [ActivityItem] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        if filter == nil && q.isEmpty { return model.activity }
        let words = q.split(separator: " ").map(String.init)
        return model.activity.filter { a in
            (filter == nil || a.presentation.category == filter) && words.allSatisfy { a.searchText.contains($0) }
        }
    }

    /// Day sections, each a list of rows (single events or bursts of identical events).
    private func sections(_ list: [ActivityItem]) -> [(day: Date, label: String, rows: [ActivityGroup])] {
        let byID = Dictionary(list.map { ($0.id, $0.presentation.groupKey) }, uniquingKeysWith: { a, _ in a })
        let cal = Calendar.current
        var out: [(Date, String, [ActivityGroup])] = []
        var current: [ActivityEntry] = []
        var day: Date?
        func flush() {
            guard let d = day, !current.isEmpty else { return }
            let label = cal.isDateInToday(d) ? "Today" : cal.isDateInYesterday(d) ? "Yesterday" : d.formatted(.dateTime.weekday(.wide).month().day())
            out.append((d, label, ActivityGrouping.group(current, keys: byID)))
        }
        for a in list {
            let d = cal.startOfDay(for: a.date)
            if d != day { flush(); current = []; day = d }
            current.append(a.entry)
        }
        flush()
        return out
    }

    private var itemByID: [UUID: ActivityItem] { Dictionary(model.activity.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a }) }

    var body: some View {
        let lookup = itemByID
        let list = items
        ScrollView {
            LazyVStack(alignment: .leading, spacing: Spacing.l) {
                HStack {
                    Picker("Show", selection: $filter) {
                        Text("All").tag(ActivityCategory?.none)
                        ForEach(ActivityCategory.allCases) { c in Text(c.title).tag(ActivityCategory?.some(c)) }
                    }
                    .pickerStyle(.menu).fixedSize()
                    Spacer()
                    Text("\(Fmt.count(list.count)) events · kept for 90 days").font(.callout).foregroundStyle(.secondary)
                }
                if filter == nil && search.isEmpty && !model.daily.isEmpty { tiles }
                if list.isEmpty {
                    EmptyStateView(symbol: "clock.arrow.circlepath", title: search.isEmpty ? "No activity" : "No matches",
                                   detail: search.isEmpty ? "Scans, blocked sites, threats and changes you make will appear here." : "Try a file name, website, program or rule.")
                        .frame(height: 300)
                }
                ForEach(sections(list), id: \.day) { section in
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        Text(section.label).font(.headline)
                        LazyVStack(spacing: 0) {
                            ForEach(Array(section.rows.enumerated()), id: \.element.id) { i, group in
                                rowView(group, lookup: lookup, isLast: i == section.rows.count - 1)
                            }
                        }
                        .card(padding: Spacing.m)
                    }
                }
            }
            .contentColumn()
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search activity, files, sites, programs")
        .navigationTitle("Protection Activity")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Export as CSV…") { export(csv: true) }
                    Button("Export as JSON…") { export(csv: false) }
                } label: { Label("Export", systemImage: "square.and.arrow.up") }
            }
            ToolbarItem(placement: .primaryAction) {
                Button { showInspector.toggle() } label: { Label("Details", systemImage: "sidebar.right") }
                    .help("Show or hide details")
            }
        }
        .inspector(isPresented: $showInspector) {
            Group {
                if let id = selected, let item = lookup[id] {
                    ActivityInspector(item: item)
                } else {
                    EmptyStateView(symbol: "info.circle", title: "Select an event",
                                   detail: "You'll see what happened, why, what \(Product.name) did and what you can do.")
                }
            }
            .inspectorColumnWidth(min: 340, ideal: 400, max: 520)
        }
    }

    private var tiles: some View {
        HStack(spacing: Spacing.l) {
            ActivityStat(title: "Files checked", value: model.daily.reduce(0) { $0 + $1.filesChecked }, symbol: "doc.text.magnifyingglass", tint: .rampartTeal,
                         values: model.daily.map { Double($0.filesChecked) })
            ActivityStat(title: "Sites & links blocked", value: model.daily.reduce(0) { $0 + $1.sitesBlocked }, symbol: "hand.raised.fill", tint: .statusInfo,
                         values: model.daily.map { Double($0.sitesBlocked) })
            ActivityStat(title: "Threats stopped", value: model.daily.reduce(0) { $0 + $1.threats }, symbol: "ladybug.fill", tint: Palette.amber,
                         values: model.daily.map { Double($0.threats) })
        }
        .fixedSize(horizontal: false, vertical: true)
    }

    @ViewBuilder private func rowView(_ g: ActivityGroup, lookup: [UUID: ActivityItem], isLast: Bool) -> some View {
        if let first = lookup[g.newest.id] {
            if g.isBurst {
                let open = expanded.contains(g.id)
                VStack(spacing: 0) {
                    TimelineRow(item: first, isLast: isLast && !open, burst: g, isExpanded: open, isSelected: false) {
                        if open { expanded.remove(g.id) } else { expanded.insert(g.id) }
                    }
                    if open {
                        ForEach(Array(g.entries.enumerated()), id: \.element.id) { i, e in
                            if let it = lookup[e.id] {
                                TimelineRow(item: it, isLast: isLast && i == g.entries.count - 1, indent: true, isSelected: selected == e.id) { select(e.id) }
                            }
                        }
                    }
                }
            } else {
                TimelineRow(item: first, isLast: isLast, isSelected: selected == first.id) { select(first.id) }
            }
        }
    }

    private func select(_ id: UUID) { selected = id; showInspector = true }

    private func export(csv: Bool) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(Product.name) Activity.\(csv ? "csv" : "json")"
        panel.allowedContentTypes = [csv ? .commaSeparatedText : .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let iso = ISO8601DateFormatter()
        let text: String
        if csv {
            func q(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
            text = "time,category,event,details,outcome\n" + items.map {
                "\(iso.string(from: $0.date)),\(q($0.presentation.category.title)),\(q($0.title)),\(q($0.presentation.subtitle)),\(q($0.outcome))"
            }.joined(separator: "\n")
        } else {
            let arr: [[String: Any]] = items.map { a in
                var d: [String: Any] = ["time": iso.string(from: a.date), "category": a.presentation.category.title, "event": a.title,
                                        "details": a.presentation.subtitle, "outcome": a.outcome, "whatHappened": a.presentation.whatHappened,
                                        "whatRamPartDid": a.presentation.whatWeDid]
                d["facts"] = Dictionary(a.presentation.facts.map { ($0.label, $0.value) }, uniquingKeysWith: { x, _ in x })
                return d
            }
            text = (try? String(data: JSONSerialization.data(withJSONObject: arr, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)) ?? "[]"
        }
        try? text.write(to: url, atomically: true, encoding: .utf8)
    }
}

extension ActivityTone {
    var color: Color {
        switch self {
        case .good: return .statusProtected
        case .info: return .rampartTeal
        case .attention: return .orange
        case .danger: return .statusAction
        case .neutral: return .secondary
        }
    }
}

struct TimelineRow: View {
    let item: ActivityItem
    let isLast: Bool
    var burst: ActivityGroup? = nil
    var isExpanded = false
    var indent = false
    var isSelected = false
    var action: () -> Void = {}
    @StateVar private var hovering = false

    private var p: ActivityPresentation { item.presentation }

    var body: some View {
        Button(action: action) {
            HStack(alignment: .top, spacing: Spacing.m) {
                Text(item.date.formatted(date: .omitted, time: .shortened))
                    .font(.callout).monospacedDigit().foregroundStyle(.secondary).frame(width: 64, alignment: .trailing)
                VStack(spacing: 0) {
                    ZStack {
                        Circle().fill(p.tone.color.opacity(0.15)).frame(width: indent ? 20 : 28, height: indent ? 20 : 28)
                        Image(systemName: p.symbol).font((indent ? Font.caption2 : .caption).weight(.semibold)).foregroundStyle(p.tone.color)
                    }
                    if !isLast { Rectangle().fill(Color.secondary.opacity(0.25)).frame(width: 1.5).frame(minHeight: 18) }
                }
                .frame(width: 28)
                VStack(alignment: .leading, spacing: 2) {
                    HStack(spacing: Spacing.s) {
                        Text(burst?.burstTitle ?? item.title).fontWeight(burst == nil ? .regular : .medium)
                            .fixedSize(horizontal: false, vertical: true).multilineTextAlignment(.leading)
                        if !p.status.isEmpty { Badge(text: SafeText.line(p.status, max: 40), tint: p.tone.color) }
                    }
                    Text(SafeText.line(burst.map { _ in item.title + (p.subtitle.isEmpty ? "" : " · " + p.subtitle) } ?? p.subtitle, max: 220))
                        .font(.callout).foregroundStyle(.secondary).lineLimit(2).multilineTextAlignment(.leading)
                }
                .padding(.top, indent ? 1 : 4)
                Spacer(minLength: Spacing.s)
                Image(systemName: burst != nil ? (isExpanded ? "chevron.down" : "chevron.right") : "info.circle")
                    .font(.caption).foregroundStyle(.tertiary).padding(.top, 6)
                    .opacity(burst != nil || hovering || isSelected ? 1 : 0)
            }
            .padding(.leading, indent ? 24 : 0)
            .padding(.vertical, 2)
            .contentShape(Rectangle())
            .background(RoundedRectangle(cornerRadius: 6).fill(Color.accentColor.opacity(isSelected ? 0.12 : 0))
                .overlay(RoundedRectangle(cornerRadius: 6).fill(Color.primary.opacity(hovering && !isSelected ? 0.04 : 0))).padding(-4))
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .padding(.bottom, isLast ? 0 : 2)
        .accessibilityElement(children: .combine)
        .accessibilityHint(burst != nil ? (isExpanded ? "Collapses the group" : "Shows each event") : "Shows details")
    }
}

struct ActivityStat: View {
    let title: String
    let value: Int
    let symbol: String
    let tint: Color
    let values: [Double]
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            HStack {
                IconBadge(symbol: symbol, tint: tint, size: 28)
                Text(title).font(.callout.weight(.medium)).foregroundStyle(.secondary)
                Spacer()
            }
            Text(Fmt.count(value)).font(.title.weight(.bold)).fontDesign(.monospaced).monospacedDigit()
            Text("Last 14 days").font(.caption).foregroundStyle(.secondary)
            Sparkline(values: values, tint: tint).frame(height: 36)
        }
        .card()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title): \(value) in the last 14 days")
    }
}

// MARK: - Inspector

/// Full plain-English explanation of one event, with only the actions that really work for it.
struct ActivityInspector: View {
    let item: ActivityItem
    @Environment(AppModel.self) private var model
    @StateVar private var showThreat = false
    @StateVar private var teaching: TeachRequest?
    @StateVar private var restoring: QuarantineRecord?
    @StateVar private var copied = false
    @StateVar private var working = false

    private var e: ActivityEntry { item.entry }
    private var p: ActivityPresentation { item.presentation }

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.l) {
                    header
                    section("What happened", p.whatHappened, symbol: "text.bubble")
                    if let why = p.why, !why.isEmpty { section("Why", why, symbol: "questionmark.bubble") }
                    section("What \(Product.name) did", p.whatWeDid, symbol: "shield.lefthalf.filled")
                    section("What you can do", p.whatYouCanDo, symbol: "hand.point.right")
                    details
                }
                .padding(Spacing.l)
            }
            Divider()
            actions.padding(Spacing.m)
        }
        .sheet(isPresented: $showThreat) {
            if let d = detection {
                VStack(spacing: 0) {
                    DetectionInspector(detection: d, record: quarantineRecord, onDelete: { r in Task { await model.delete(r) } })
                    Divider()
                    HStack { Spacer(); Button("Done") { showThreat = false }.keyboardShortcut(.defaultAction) }.padding(Spacing.m)
                }
                .frame(width: 460, height: 600)
            }
        }
        .sheet(item: $teaching) { req in TeachSheet(request: req) }
        .sheet(item: $restoring) { r in RestoreSheet(record: r, detection: detection) }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            IconBadge(symbol: p.symbol, tint: p.tone.color, size: 40)
            VStack(alignment: .leading, spacing: 4) {
                Text(SafeText.line(p.title, max: 200)).font(.title3.weight(.semibold)).fixedSize(horizontal: false, vertical: true)
                if !p.subtitle.isEmpty {
                    Text(SafeText.line(p.subtitle, max: 300)).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                HStack(spacing: Spacing.s) {
                    if !p.status.isEmpty { Badge(text: SafeText.line(p.status, max: 40), tint: p.tone.color) }
                    Badge(text: p.category.title)
                    Text(e.date.formatted(date: .abbreviated, time: .standard)).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
    }

    private func section(_ title: String, _ text: String, symbol: String) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            Label(title, systemImage: symbol).font(.headline)
            Text(SafeText.line(text, max: 1200)).font(.callout).fixedSize(horizontal: false, vertical: true).textSelection(.enabled)
        }
    }

    private var details: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Details").font(.headline)
            Grid(alignment: .leading, horizontalSpacing: Spacing.m, verticalSpacing: 6) {
                ForEach(p.facts, id: \.self) { f in
                    GridRow(alignment: .top) {
                        Text(f.label).foregroundStyle(.secondary).font(.callout)
                        Text(f.mono ? SafeText.path(f.value, max: 600) : SafeText.line(f.value, max: 600))
                            .font(f.mono ? .callout.monospaced() : .callout).textSelection(.enabled)
                            .lineLimit(f.label == "SHA-256" ? 3 : 4).truncationMode(.middle).help(f.value)
                    }
                }
            }
        }
    }

    // MARK: related objects

    private var detection: Detection? {
        guard let id = e.detectionID else { return nil }
        return model.detections.first { $0.id == id }
    }
    private var quarantineRecord: QuarantineRecord? {
        if let r = e.refID.flatMap(UUID.init(uuidString:)), let q = model.quarantine.first(where: { $0.id == r }) { return q }
        guard [.quarantined, .detection].contains(p.event) else { return nil }
        if let h = e.sha256, let t = e.target, let q = model.quarantine.first(where: { $0.sha256 == h && $0.originalPath == t }) { return q }
        return nil
    }
    private var revealPath: String? {
        for c in [e.target, e.process?.path] {
            if let c, c.hasPrefix("/"), FileManager.default.fileExists(atPath: c) { return c }
        }
        return nil
    }
    private var allowRule: AllowRuleSpec? {
        guard p.event == .allowRuleAdded, let id = e.refID.flatMap(UUID.init(uuidString:)) else { return nil }
        return model.allowRules.first { $0.id == id }
    }
    private var toggledSetting: String? {
        guard p.event == .protectionToggled, e.facts?["value"] == "off" || e.outcome.lowercased() == "off" else { return nil }
        let s = e.facts?["setting"] ?? (e.title.lowercased().hasPrefix("web") ? "Web protection" : "Real-time protection")
        if s == "Web protection", !model.status.webProtectionOn, model.webProtectionAvailable { return s }
        if s == "Real-time protection", !model.status.realtimeOn { return s }
        return nil
    }
    private var isLatestCleanup: Bool {
        guard p.event == .refreshCleanup, e.title.hasPrefix("Cleaned up"), !RefreshModel.shared.lastUndo.isEmpty else { return false }
        return model.activity.first { $0.presentation.event == .refreshCleanup || $0.presentation.event == .refreshUndo }?.id == e.id
    }

    // MARK: actions

    private var actions: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: Spacing.s) { buttons; Spacer(minLength: 0) }
            VStack(alignment: .leading, spacing: Spacing.s) { buttons }
        }
        .controlSize(.regular)
        .disabled(working)
    }

    @ViewBuilder private var buttons: some View {
        if detection != nil {
            Button { showThreat = true } label: { Label("Open Threat", systemImage: "ladybug").fixedSize() }
                .help("See the full evidence and quarantine, restore or delete it")
        }
        if let d = detection, !d.resolved, d.path != nil || d.sha256 != nil {
            Button { teaching = TeachRequest(detections: [d]) } label: { Label("Not a Threat…", systemImage: "hand.thumbsup").fixedSize() }
        }
        if let r = quarantineRecord {
            Button { restoring = r } label: { Label("Undo: Restore…", systemImage: "arrow.uturn.backward").fixedSize() }
        }
        if let rule = allowRule {
            Button { run { await model.removeAllowRule(rule) } } label: { Label("Undo: Stop Allowing", systemImage: "arrow.uturn.backward").fixedSize() }
        }
        if let s = toggledSetting, model.mode == .live || model.isDemo {
            Button { run { if s == "Web protection" { await model.setWebProtection(true) } else { model.setRealtime(true) } } } label: {
                Label("Turn Back On", systemImage: "shield.lefthalf.filled").fixedSize()
            }
        }
        if p.event == .protectionPaused, model.pausedUntil.map({ $0 > Date() }) == true {
            Button { model.setRealtime(true) } label: { Label("Resume Now", systemImage: "play.fill").fixedSize() }
        }
        if p.event == .remoteAccessAllowed, let id = e.refID, model.mode == .live {
            Button { run { _ = await RemoteAccessBridge.revoke(client: model.client, toolID: id) } } label: {
                Label("Undo: Remove Permission", systemImage: "arrow.uturn.backward").fixedSize()
            }
        }
        if p.event == .remoteLockdownChanged, !(e.facts?["value"] == "on" || e.outcome.lowercased() == "on"), model.mode == .live {
            Button { run { _ = await RemoteAccessBridge.setLockdown(client: model.client, on: true) } } label: {
                Label("Turn Lockdown Back On", systemImage: "lock.fill").fixedSize()
            }
        }
        if isLatestCleanup {
            Button { RefreshModel.shared.undoLast() } label: { Label("Undo Clean-up", systemImage: "arrow.uturn.backward").fixedSize() }
        }
        if let path = revealPath {
            Button { NSWorkspace.shared.selectFile(path, inFileViewerRootedAtPath: "") } label: { Label("Reveal in Finder", systemImage: "folder").fixedSize() }
        }
        Button { copyDetails() } label: { Label(copied ? "Copied" : "Copy Details", systemImage: copied ? "checkmark" : "doc.on.doc").fixedSize() }
    }

    private func run(_ work: @escaping () async -> Void) {
        working = true
        Task { await work(); working = false; await model.fetchActivity(full: false) }
    }

    private func copyDetails() {
        let text = "\(Product.name) Protection Activity\n" + ActivityPresenter.fullText(e)
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(text, forType: .string)
        copied = true
        Task { try? await Task.sleep(nanoseconds: 1_500_000_000); copied = false }
    }
}
