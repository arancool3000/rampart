import SwiftUI
import AppKit
import RampartShared

struct ThreatsView: View {
    enum Segment: String, CaseIterable, Identifiable { case detections = "Detections", quarantine = "Quarantine", allowed = "Allowed"; var id: String { rawValue } }
    @Environment(AppModel.self) private var model
    @StateVar private var segment: Segment = .detections
    @StateVar private var selectedDetection: Detection.ID?
    @StateVar private var selectedQuarantine: QuarantineRecord.ID?
    @StateVar private var showInspector = true
    @StateVar private var sortOrder = [KeyPathComparator(\Detection.date, order: .reverse)]

    var body: some View {
        VStack(spacing: 0) {
            switch segment {
            case .detections: detectionsTable
            case .quarantine: quarantineTable
            case .allowed: allowedList
            }
        }
        .navigationTitle("Threats & Quarantine")
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("View", selection: $segment) {
                    ForEach(Segment.allCases) { Text($0.rawValue).tag($0) }
                }
                .pickerStyle(.segmented).labelsHidden().frame(width: 320)
            }
            ToolbarItem(placement: .primaryAction) {
                Button { showInspector.toggle() } label: { Label("Inspector", systemImage: "sidebar.trailing") }
                    .help("Show or hide details")
            }
        }
        .inspector(isPresented: Binding(get: { showInspector && segment != .allowed }, set: { showInspector = $0 })) {
            Group {
                if segment == .detections, let id = selectedDetection, let d = model.detections.first(where: { $0.id == id }) {
                    DetectionInspector(detection: d, record: record(for: d))
                } else if segment == .quarantine, let id = selectedQuarantine, let r = model.quarantine.first(where: { $0.id == id }) {
                    DetectionInspector(detection: detection(for: r), record: r)
                } else {
                    EmptyStateView(symbol: "info.circle", title: "Select an item", detail: "You'll see why Rampart flagged it and what you can do.")
                }
            }
            .inspectorColumnWidth(min: 320, ideal: 380, max: 480)
        }
        .onAppear {
            if selectedDetection == nil { selectedDetection = model.openDetections.first?.id ?? model.detections.first?.id }
            if selectedQuarantine == nil { selectedQuarantine = model.quarantine.first?.id }
        }
    }

    private func record(for d: Detection) -> QuarantineRecord? {
        model.quarantine.first { $0.sha256 == d.sha256 && d.sha256 != nil } ?? model.quarantine.first { $0.originalPath == d.path }
    }
    private func detection(for r: QuarantineRecord) -> Detection? {
        model.detections.first { $0.sha256 == r.sha256 } ?? model.detections.first { $0.path == r.originalPath }
            ?? model.detections.first { $0.name == r.detectionName }
    }

    private var sortedDetections: [Detection] { model.detections.sorted(using: sortOrder) }

    @ViewBuilder private var detectionsTable: some View {
        if model.detections.isEmpty {
            EmptyStateView(symbol: "checkmark.shield", title: "No threats found", detail: "When Rampart finds something, it will appear here with an explanation.")
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
            .contextMenu(forSelectionType: Detection.ID.self) { ids in
                if let id = ids.first, let d = model.detections.first(where: { $0.id == id }), let p = d.path {
                    Button("Copy Path") { copy(p) }
                    if let h = d.sha256 { Button("Copy SHA-256") { copy(h) } }
                }
            }
        }
    }

    @ViewBuilder private var quarantineTable: some View {
        if model.quarantine.isEmpty {
            EmptyStateView(symbol: "archivebox", title: "Quarantine is empty",
                           detail: "Files Rampart isolates will appear here. They can't run while they're here.")
        } else {
            VStack(spacing: 0) {
                Table(model.quarantine, selection: $selectedQuarantine) {
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

    @ViewBuilder private var allowedList: some View {
        @Bindable var model = model
        if model.allowRules.isEmpty {
            EmptyStateView(symbol: "checkmark.seal", title: "Nothing allowed yet", detail: "Files, developers or folders you allow will be listed here. Rampart won't flag them.")
        } else {
            Table(model.allowRules) {
                TableColumn("Allowed") { r in
                    VStack(alignment: .leading, spacing: 1) {
                        Text(r.name)
                        Text(r.value).font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    }
                }
                TableColumn("Scope") { r in Badge(text: r.scope.rawValue, tint: .rampartTeal) }.width(min: 110, ideal: 130)
                TableColumn("Created") { r in Text(Fmt.dayTime(r.created)).foregroundStyle(.secondary) }.width(min: 110, ideal: 130)
                TableColumn("Expires") { r in Text(r.expires.map { $0.formatted(date: .abbreviated, time: .omitted) } ?? "Never").foregroundStyle(.secondary) }.width(80)
                TableColumn("") { r in
                    Button("Remove") { model.allowRules.removeAll { $0.id == r.id } }.controlSize(.small)
                }
                .width(80)
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
            if let record { RestoreSheet(record: record, detection: detection) }
        }
        .sheet(isPresented: $showReport) { ReportSheet(name: displayName) }
        .sheet(isPresented: $showAllow) { if let detection { AllowSheet(detection: detection) } }
        .confirmationDialog("Delete \"\(displayName)\" permanently?", isPresented: $showDelete) {
            Button("Delete", role: .destructive) { if let record { Task { await model.delete(record) } } }
            Button("Cancel", role: .cancel) {}
        } message: { Text("This can't be undone.") }
    }

    private var header: some View {
        HStack(spacing: Spacing.m) {
            FileIcon(path: detection?.path).frame(width: 40, height: 40).scaleEffect(1.5)
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
                (Text("Detected as ") + Text(d.name).bold() + Text(" by ") + Text(primary?.source.label ?? "Rampart").bold() + Text("."))
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(d.evidence.sorted { $0.score > $1.score }, id: \.self) { e in
                    HStack(alignment: .top, spacing: Spacing.s) {
                        Image(systemName: e.source.symbol).foregroundStyle(Color.rampartTeal).frame(width: 20)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(e.title).font(.body.weight(.medium))
                            Text(e.detail).font(.callout).foregroundStyle(.secondary).textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                    .accessibilityElement(children: .combine)
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
            Text("What Rampart did").font(.headline)
            if let r = record {
                Text("Moved to quarantine on \(r.date.formatted(date: .abbreviated, time: .shortened)). The file is encrypted and can't run.")
            } else if detection?.resolved == true {
                Text("This item was resolved and is no longer flagged.")
            } else {
                Text("Rampart stopped the process. The file is still in place. Choose what to do next.")
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
                if let sha { row("SHA-256", sha, mono: true) }
            }
        }
    }

    private func row(_ k: String, _ v: String, mono: Bool = false) -> some View {
        GridRow {
            Text(k).foregroundStyle(.secondary).font(.callout)
            Text(v).font(mono ? .callout.monospaced() : .callout).textSelection(.enabled).lineLimit(3).truncationMode(.middle)
        }
    }

    private var links: some View {
        HStack(spacing: Spacing.l) {
            if let sha, let url = URL(string: "https://www.virustotal.com/gui/file/\(sha)") {
                Button("Look up on VirusTotal") { openURL(url) }.buttonStyle(.link)
                    .help("Opens your browser with the file's fingerprint only. Nothing is uploaded.")
            }
            Button("Copy Details") { copyDetails() }.buttonStyle(.link)
        }
        .font(.callout)
    }

    private var actions: some View {
        HStack(spacing: Spacing.s) {
            if record != nil {
                Button(role: .destructive) { showDelete = true } label: { Label("Delete", systemImage: "trash") }
                Button { showRestore = true } label: { Label("Restore…", systemImage: "arrow.uturn.backward") }
            } else if let d = detection, !d.resolved {
                Button { Task { await model.quarantine(d) } } label: { Label("Quarantine", systemImage: "archivebox") }
                    .buttonStyle(.borderedProminent)
                Button { showAllow = true } label: { Label("Allow…", systemImage: "checkmark.seal") }
            } else if let p = detection?.path {
                Button { NSWorkspace.shared.selectFile(p, inFileViewerRootedAtPath: "") } label: { Label("Show in Finder", systemImage: "folder") }
            }
            Spacer()
            Button { showReport = true } label: { Label("Report as Safe…", systemImage: "flag") }
        }
        .controlSize(.regular)
    }

    private func copyDetails() {
        var s = "Rampart detection\nName: \(detection?.name ?? record?.detectionName ?? "")\n"
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
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var choice: Choice = .once

    var body: some View {
        let name = (record.originalPath as NSString).lastPathComponent
        let conf = (detection?.confidence ?? 0) >= 90 ? "high" : "medium"
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Restore \"\(name)\"?").font(.title2.weight(.semibold))
            Text("Rampart flagged this as \(detection?.category.label ?? record.detectionName) (\(conf) confidence). Restore it only if you trust where it came from.")
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
    @StateVar private var scope: AllowRule.Scope = .file

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Allow \"\(detection.path.map { ($0 as NSString).lastPathComponent } ?? detection.name)\"?").font(.title2.weight(.semibold))
            Text("Rampart won't flag it again. You can remove this rule anytime from Threats › Allowed.")
                .foregroundStyle(.secondary)
            Picker("", selection: $scope) {
                Text("This file only (by fingerprint)").tag(AllowRule.Scope.file)
                Text("This developer").tag(AllowRule.Scope.developer)
                Text("This folder").tag(AllowRule.Scope.folder)
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
                Text("We'll send the file's fingerprint and detection details to the Rampart lab. We won't send the file itself unless you choose to.")
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
