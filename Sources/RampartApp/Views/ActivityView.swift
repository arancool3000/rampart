import SwiftUI
import RampartShared
import AppKit
import UniformTypeIdentifiers
import Charts

struct ActivityView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var filter: ActivityItem.Kind? = nil
    @StateVar private var search = ""

    private var items: [ActivityItem] {
        model.activity.filter { a in
            (filter == nil || a.kind == filter) &&
            (search.isEmpty || a.title.localizedCaseInsensitiveContains(search) || a.outcome.localizedCaseInsensitiveContains(search))
        }
    }

    private var grouped: [(String, [ActivityItem])] {
        let cal = Calendar.current
        let groups = Dictionary(grouping: items) { cal.startOfDay(for: $0.date) }
        return groups.keys.sorted(by: >).map { day in
            let label = cal.isDateInToday(day) ? "Today" : cal.isDateInYesterday(day) ? "Yesterday" : day.formatted(.dateTime.weekday(.wide).month().day())
            return (label, groups[day]!.sorted { $0.date > $1.date })
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.l) {
                HStack {
                    Picker("Show", selection: $filter) {
                        Text("All").tag(ActivityItem.Kind?.none)
                        ForEach(ActivityItem.Kind.allCases) { k in Text(k.filterTitle).tag(ActivityItem.Kind?.some(k)) }
                    }
                    .pickerStyle(.menu).fixedSize()
                    Spacer()
                    Text("\(items.count) events · kept for 90 days").font(.callout).foregroundStyle(.secondary)
                }
                if !model.daily.isEmpty && filter == nil && search.isEmpty {
                    HStack(spacing: Spacing.l) {
                        ActivityStat(title: "Files checked", value: model.daily.reduce(0) { $0 + $1.filesChecked }, symbol: "doc.text.magnifyingglass", tint: .rampartTeal,
                                     values: model.daily.map { Double($0.filesChecked) })
                        ActivityStat(title: "Sites blocked", value: model.daily.reduce(0) { $0 + $1.sitesBlocked }, symbol: "hand.raised.fill", tint: .statusInfo,
                                     values: model.daily.map { Double($0.sitesBlocked) })
                        ActivityStat(title: "Threats stopped", value: model.daily.reduce(0) { $0 + $1.threats }, symbol: "ladybug.fill", tint: Palette.amber,
                                     values: model.daily.map { Double($0.threats) })
                    }
                    .fixedSize(horizontal: false, vertical: true)
                }
                if items.isEmpty {
                    EmptyStateView(symbol: "clock.arrow.circlepath", title: "No activity", detail: "Scans, blocked connections and changes you make will appear here.")
                        .frame(height: 300)
                }
                ForEach(grouped, id: \.0) { day, list in
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        Text(day).font(.headline)
                        VStack(spacing: 0) {
                            ForEach(Array(list.enumerated()), id: \.element.id) { i, a in
                                TimelineRow(item: a, isLast: i == list.count - 1)
                            }
                        }
                        .card(padding: Spacing.m)
                    }
                }
            }
            .contentColumn()
        }
        .searchable(text: $search, placement: .toolbar, prompt: "Search activity")
        .navigationTitle("Protection Activity")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Menu {
                    Button("Export as CSV…") { export(csv: true) }
                    Button("Export as JSON…") { export(csv: false) }
                } label: { Label("Export", systemImage: "square.and.arrow.up") }
            }
        }
    }

    private func export(csv: Bool) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(Product.name) Activity.\(csv ? "csv" : "json")"
        panel.allowedContentTypes = [csv ? .commaSeparatedText : .json]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        let iso = ISO8601DateFormatter()
        let text: String
        if csv {
            func q(_ s: String) -> String { "\"" + s.replacingOccurrences(of: "\"", with: "\"\"") + "\"" }
            text = "time,category,event,outcome\n" + items.map { "\(iso.string(from: $0.date)),\($0.kind.rawValue),\(q($0.title)),\(q($0.outcome))" }.joined(separator: "\n")
        } else {
            let arr = items.map { ["time": iso.string(from: $0.date), "category": $0.kind.rawValue, "event": $0.title, "outcome": $0.outcome] }
            text = (try? String(data: JSONSerialization.data(withJSONObject: arr, options: [.prettyPrinted, .sortedKeys]), encoding: .utf8)) ?? "[]"
        }
        try? text.write(to: url, atomically: true, encoding: .utf8)
    }
}

struct TimelineRow: View {
    let item: ActivityItem
    let isLast: Bool
    private var tint: Color {
        switch item.kind {
        case .threat: return item.outcome == "Needs decision" ? .statusAction : .statusQuarantined
        case .network: return .orange
        case .scan, .protection: return .rampartTeal
        case .update: return .statusInfo
        case .settings: return .secondary
        }
    }
    var body: some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            Text(item.date.formatted(date: .omitted, time: .shortened))
                .font(.callout).monospacedDigit().foregroundStyle(.secondary).frame(width: 64, alignment: .trailing)
            VStack(spacing: 0) {
                ZStack {
                    Circle().fill(tint.opacity(0.15)).frame(width: 28, height: 28)
                    Image(systemName: item.kind.symbol).font(.caption.weight(.semibold)).foregroundStyle(tint)
                }
                if !isLast { Rectangle().fill(Color.secondary.opacity(0.25)).frame(width: 1.5).frame(minHeight: 18) }
            }
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title).fixedSize(horizontal: false, vertical: true)
                Text(item.outcome).font(.callout).foregroundStyle(.secondary)
            }
            .padding(.top, 4)
            Spacer()
        }
        .padding(.bottom, isLast ? 0 : 2)
        .accessibilityElement(children: .combine)
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
            Text(Fmt.count(value)).font(.title.weight(.bold)).fontDesign(.rounded).monospacedDigit()
            Text("Last 14 days").font(.caption).foregroundStyle(.secondary)
            Sparkline(values: values, tint: tint).frame(height: 36)
        }
        .card()
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(title): \(value) in the last 14 days")
    }
}
