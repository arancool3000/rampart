import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RampartShared

/// Mirror of rampartd's SandboxReport (Sources/rampartd/Core/SandboxProfile.swift). Keep fields in sync.
struct SandboxReport: Codable, Sendable {
    struct Violation: Codable, Hashable, Sendable {
        var process: String
        var pid: Int32
        var operation: String
        var target: String
    }
    var itemName: String
    var sha256: String
    var command: [String]
    var startedAt: Date
    var seconds: Double
    var exitStatus: Int32?
    var timedOut: Bool
    var killedProcesses: Int
    var stdout: String
    var stderr: String
    var outputTruncated: Bool
    var violations: [Violation]
    var touchedPaths: [String]
    var notes: [String]
    var profile: String
}

/// File names and item output are attacker-controlled. Strip control and bidirectional-override characters (a
/// right-to-left override can make "gpj.app" read as "ppa.jpg") and cap length before showing them in RamPart's UI.
enum QuarantineText {
    static func clean(_ s: String) -> String {
        // o8: same character rules as SafeText (also drops U+2028/2029 line separators, zero-width and tag
        // characters), keeping only real line breaks and tabs.
        String(String.UnicodeScalarView(s.unicodeScalars.filter { c in c == "\n" || c == "\t" || !SafeText.isUnsafeScalar(c) }))
    }
    static func name(_ path: String, max: Int = 60) -> String {
        let n = SafeText.line((path as NSString).lastPathComponent, max: Int.max - 1)
        guard n.count > max else { return n }
        return String(n.prefix(max - 12)) + "\u{2026}" + String(n.suffix(11))
    }
}

/// The Quarantine tab: every isolated item, with restore, delete, export and sandbox actions. Multi-select for bulk work.
struct QuarantineManagerView: View {
    let records: [QuarantineRecord]
    @Binding var selection: Set<QuarantineRecord.ID>
    @Binding var showInspector: Bool
    var detection: (QuarantineRecord) -> Detection?
    var onDelete: ([QuarantineRecord]) -> Void
    @Environment(AppModel.self) private var model
    @StateVar private var sortOrder = [KeyPathComparator(\QuarantineRecord.date, order: .reverse)]
    @StateVar private var pendingRestore: RestorePlan?
    @StateVar private var pendingDelete: [QuarantineRecord] = []
    @StateVar private var showDeleteConfirm = false
    @StateVar private var sandboxTarget: QuarantineRecord?
    @StateVar private var notice: String?
    @StateVar private var busy = false

    struct RestorePlan: Identifiable {
        let id = UUID()
        var records: [QuarantineRecord]
        var destination: String?   // nil = original location
        var allow: Bool
    }

    private var selected: [QuarantineRecord] { records.filter { selection.contains($0.id) } }
    private var sorted: [QuarantineRecord] { records.sorted(using: sortOrder) }

    var body: some View {
        if records.isEmpty {
            EmptyStateView(symbol: "archivebox", title: "Quarantine is empty",
                           detail: "Files \(Product.name) isolates will appear here. They're encrypted and can't run while they're here.")
        } else {
            VStack(spacing: 0) {
                toolbar
                Divider()
                table
                footer
            }
            .confirmationDialog(restoreTitle, isPresented: Binding(get: { pendingRestore != nil }, set: { if !$0 { pendingRestore = nil } }),
                                titleVisibility: .visible, presenting: pendingRestore) { plan in
                Button(plan.allow ? "Restore and Allow" : "Restore") { perform(plan) }
                Button("Cancel", role: .cancel) {}
            } message: { plan in
                Text(restoreMessage(plan))
            }
            .confirmationDialog(deleteTitle, isPresented: $showDeleteConfirm, titleVisibility: .visible) {
                Button("Delete Permanently", role: .destructive) { onDelete(pendingDelete); selection.subtract(pendingDelete.map(\.id)); pendingDelete = [] }
                Button("Cancel", role: .cancel) { pendingDelete = [] }
            } message: { Text("You'll have a few seconds to undo. After that, the encrypted copy is destroyed for good.") }
            .sheet(item: $sandboxTarget) { r in SandboxRunSheet(record: r, detection: detection(r)) }
        }
    }

    // MARK: Pieces

    private var toolbar: some View {
        HStack(spacing: Spacing.s) {
            Text(selection.isEmpty ? "\(records.count) item\(records.count == 1 ? "" : "s")" : "\(selection.count) selected")
                .font(.callout).foregroundStyle(.secondary).monospacedDigit()
            Spacer()
            Button { askRestore(selected, destination: nil, allow: false) } label: { Label("Restore…", systemImage: "arrow.uturn.backward") }
                .disabled(selected.isEmpty || busy)
                .help("Put the selected items back where they were (asks first)")
            Button(role: .destructive) { askDelete(selected) } label: { Label("Delete…", systemImage: "trash") }
                .disabled(selected.isEmpty || busy)
                .help("Destroy the encrypted copies (asks first)")
            Menu {
                if let r = single { singleActions(r) } else { Text("Select one item for more actions") }
            } label: { Label("More", systemImage: "ellipsis.circle") }
                .menuStyle(.borderlessButton).fixedSize()
                .disabled(single == nil || busy)
        }
        .controlSize(.small)
        .padding(.horizontal, Spacing.m).padding(.vertical, Spacing.s)
    }

    private var single: QuarantineRecord? { selected.count == 1 ? selected.first : nil }

    private var table: some View {
        Table(sorted, selection: $selection, sortOrder: $sortOrder) {
            TableColumn("Name", value: \.originalPath) { r in
                HStack(spacing: Spacing.s) {
                    Image(systemName: "lock.square.stack").foregroundStyle(Color.statusQuarantined).font(.title3).frame(width: 24)
                        .accessibilityHidden(true)
                    Text(QuarantineText.name(r.originalPath, max: 120)).lineLimit(1)
                }
            }
            .width(min: 160, ideal: 220)
            TableColumn("Original path") { r in
                Text(SafeText.path((r.originalPath as NSString).abbreviatingWithTildeInPath))
                    .font(.callout.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .help(r.originalPath)
            }
            .width(min: 160, ideal: 260)
            TableColumn("Date", value: \.date) { r in Text(Fmt.dayTime(r.date)).foregroundStyle(.secondary) }.width(min: 100, ideal: 120)
            TableColumn("Detection", value: \.detectionName) { r in Text(SafeText.line(r.detectionName)).lineLimit(1).help(SafeText.line(r.detectionName, max: 300)) }.width(min: 120, ideal: 170)
            TableColumn("Size", value: \.size) { r in Text(Fmt.bytes(r.size)).monospacedDigit().foregroundStyle(.secondary) }.width(min: 60, ideal: 70)
        }
        .scrollContentBackground(.hidden)
        .contextMenu(forSelectionType: QuarantineRecord.ID.self) { ids in
            let rs = records.filter { ids.contains($0.id) }
            if rs.count == 1, let r = rs.first {
                singleActions(r)
            } else if rs.count > 1 {
                Button("Restore \(rs.count) Items…") { askRestore(rs, destination: nil, allow: false) }
                Button("Restore and Allow \(rs.count) Items…") { askRestore(rs, destination: nil, allow: true) }
                Divider()
                Button("Delete \(rs.count) Items Permanently…", role: .destructive) { askDelete(rs) }
            }
        } primaryAction: { ids in
            selection = ids; showInspector = true
        }
        .onDeleteCommand { askDelete(selected) }
    }

    @ViewBuilder private func singleActions(_ r: QuarantineRecord) -> some View {
        Button("Restore to Original Location…") { askRestore([r], destination: nil, allow: false) }
        Button("Restore To…") { chooseRestoreDestination(r) }
        Button("Restore and Allow…") { askRestore([r], destination: nil, allow: true) }
        Divider()
        Button("Show Details and Evidence") { selection = [r.id]; showInspector = true }
        if !r.sha256.isEmpty { Button("Copy SHA-256") { copy(r.sha256) } }
        Button("Copy Original Path") { copy(r.originalPath) }
        Button("Export Encrypted Copy…") { export(r) }
        Divider()
        Button("Run in Sandbox…") { sandboxTarget = r }
        Divider()
        Button("Delete Permanently…", role: .destructive) { askDelete([r]) }
    }

    private var footer: some View {
        HStack(spacing: Spacing.s) {
            if busy { ProgressView().controlSize(.small) }
            if let notice {
                Image(systemName: "checkmark.circle").foregroundStyle(Color.statusProtected).accessibilityHidden(true)
                Text(notice).textSelection(.enabled).lineLimit(2)
                Button { self.notice = nil } label: { Image(systemName: "xmark") }.buttonStyle(.borderless)
                    .foregroundStyle(.secondary).accessibilityLabel("Dismiss")
            } else {
                Image(systemName: "info.circle").foregroundStyle(.secondary).accessibilityHidden(true)
                Text("Deleted automatically after 30 days. Select several items to restore or delete them together.").foregroundStyle(.secondary)
                Button("Change in Settings") { model.selection = .settings }.buttonStyle(.link)
            }
            Spacer()
        }
        .font(.callout).padding(Spacing.m)
    }

    // MARK: Actions

    private var restoreTitle: String {
        guard let p = pendingRestore else { return "" }
        let what = p.records.count == 1 ? "\u{201C}\(QuarantineText.name(p.records[0].originalPath))\u{201D}" : "\(p.records.count) items"
        return p.allow ? "Restore and allow \(what)?" : "Restore \(what)?"
    }

    private func restoreMessage(_ p: RestorePlan) -> String {
        let place = p.destination.map { "to \(($0 as NSString).abbreviatingWithTildeInPath)" } ?? "to \(p.records.count == 1 ? "its original location" : "their original locations")"
        let allow = p.allow ? " \(Product.name) will also stop flagging \(p.records.count == 1 ? "this file" : "these files") (you can undo this in Rules)." : " \(Product.name) will scan \(p.records.count == 1 ? "it" : "them") again next time."
        return "\(Product.name) flagged \(p.records.count == 1 ? "this item" : "these items"). Restore only what you trust. It will be restored \(place).\(allow)"
    }

    private var deleteTitle: String {
        pendingDelete.count == 1 ? "Delete \u{201C}\(QuarantineText.name(pendingDelete[0].originalPath))\u{201D} permanently?"
            : "Delete \(pendingDelete.count) items permanently?"
    }

    private func askRestore(_ rs: [QuarantineRecord], destination: String?, allow: Bool) {
        guard !rs.isEmpty else { return }
        pendingRestore = RestorePlan(records: rs, destination: destination, allow: allow)
    }

    private func askDelete(_ rs: [QuarantineRecord]) {
        guard !rs.isEmpty else { return }
        pendingDelete = rs; showDeleteConfirm = true
    }

    private func chooseRestoreDestination(_ r: QuarantineRecord) {
        let panel = NSSavePanel()
        panel.title = "Restore To"
        panel.prompt = "Choose"
        panel.message = "Choose where to put the restored copy. You'll confirm before anything is restored."
        panel.nameFieldStringValue = (r.originalPath as NSString).lastPathComponent
        panel.canCreateDirectories = true
        panel.directoryURL = URL(fileURLWithPath: NSHomeDirectory())
        guard panel.runModal() == .OK, let url = panel.url else { return }
        askRestore([r], destination: url.path, allow: false)
    }

    private func perform(_ plan: RestorePlan) {
        busy = true
        Task { @MainActor in
            defer { busy = false }
            var done = 0
            for r in plan.records {
                if let dest = plan.destination {
                    guard model.mode == .live else { notice = "Restoring to another place needs the \(Product.name) service."; return }
                    do {
                        let resp = try await model.client.request(.restoreQuarantinedTo(id: r.id, path: dest, allow: plan.allow), timeout: 60)
                        if case .error(let e) = resp { model.lastError = e; continue }
                        done += 1
                    } catch { model.lastError = error.localizedDescription }
                } else {
                    await model.restore(r, allow: plan.allow)
                    done += 1
                }
            }
            selection.subtract(plan.records.map(\.id))
            await model.refresh(heavy: false)
            if done > 0 { notice = "Restored \(done) item\(done == 1 ? "" : "s")\(plan.allow ? " and allowed \(done == 1 ? "it" : "them")" : "")." }
        }
    }

    private func export(_ r: QuarantineRecord) {
        guard model.mode == .live else { notice = "Exporting needs the \(Product.name) service."; return }
        let panel = NSSavePanel()
        panel.title = "Export Encrypted Copy"
        panel.message = "Saves a password-protected zip (password \u{201C}infected\u{201D}, the convention for sharing samples with security labs)."
        panel.nameFieldStringValue = (r.originalPath as NSString).lastPathComponent + ".zip"
        panel.allowedContentTypes = [.zip]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        Task { @MainActor in
            defer { busy = false }
            do {
                switch try await model.client.request(.exportQuarantined(id: r.id, path: url.path), timeout: 180) {
                case .exported(let path, let password):
                    notice = "Saved encrypted copy to \((path as NSString).abbreviatingWithTildeInPath). Password: \(password)"
                case .error(let e): model.lastError = e
                default: model.lastError = "Unexpected reply from the service"
                }
            } catch { model.lastError = error.localizedDescription }
        }
    }

    private func copy(_ s: String) {
        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(s, forType: .string)
        notice = "Copied."
    }
}

// MARK: - Run in sandbox

struct SandboxRunSheet: View {
    let record: QuarantineRecord
    let detection: Detection?
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var typed = ""
    @StateVar private var understood = false
    @StateVar private var running = false
    @StateVar private var report: SandboxReport?
    @StateVar private var error: String?
    @StateVar private var startedAt: Date?

    private var confidence: Int? { detection?.confidence }
    private var needsTyped: Bool { (confidence ?? 100) >= 90 }
    private var canRun: Bool { understood && !running && (!needsTyped || typed == "RUN") && model.mode == .live }
    private var name: String { QuarantineText.name(record.originalPath) }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text(report == nil ? "Run \u{201C}\(SafeText.line(name))\u{201D} in a sandbox?" : "Sandbox report: \(SafeText.line(name))").font(.title2.weight(.semibold))
            if let report { SandboxReportView(report: report) } else { setup }
            HStack {
                if running, let s = startedAt {
                    ProgressView().controlSize(.small)
                    TimelineView(.periodic(from: s, by: 1)) { ctx in
                        Text("Running… \(min(60, Int(ctx.date.timeIntervalSince(s))))s of 60s").monospacedDigit().foregroundStyle(.secondary)
                    }
                }
                Spacer()
                if report != nil {
                    Button("Done") { dismiss() }.keyboardShortcut(.defaultAction)
                } else {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction).disabled(running)
                    Button("Run in Sandbox") { run() }.disabled(!canRun)
                }
            }
        }
        .padding(Spacing.xl)
        .frame(width: 560)
        .frame(minHeight: 340)
        .interactiveDismissDisabled(running)
    }

    private var setup: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Label {
                Text("This runs the item for real. ") + Text("Apple has deprecated sandbox-exec").bold()
                    + Text(", and this is best-effort containment, not a virtual machine. A determined program might escape it. Only do this if you need to see what the item does.")
            } icon: { Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusAction) }
            .fixedSize(horizontal: false, vertical: true)
            VStack(alignment: .leading, spacing: 4) {
                Text("What \(Product.name) does").font(.headline)
                bullet("Copies the item to a private temporary folder (never its original location).")
                bullet("Blocks network access, writing anywhere outside that folder, starting other programs (scripts can't run commands, so many stop early), talking to system services, and reading anything in your home folder, other users' folders or external drives. It can still read macOS's own files.")
                bullet("Removes links inside the item that point outside that folder, and stops it if it writes more than 256 MB.")
                bullet("Stops it after 60 seconds, then deletes the folder.")
                bullet("Shows its output and the files it tried to touch.")
            }
            .font(.callout)
            if let c = confidence { Text("Detection confidence: \(c)%").font(.callout).foregroundStyle(.secondary) }
            Toggle("I understand this runs the item on this Mac", isOn: $understood)
            if needsTyped {
                VStack(alignment: .leading, spacing: 4) {
                    Text(confidence == nil ? "\(Product.name) can't tell how risky this is. Type RUN to confirm."
                                           : "This is a high-confidence detection. Type RUN to confirm.").font(.callout)
                    TextField("RUN", text: $typed).textFieldStyle(.roundedBorder).frame(width: 120)
                        .accessibilityLabel("Type RUN to confirm")
                }
            }
            if model.mode != .live {
                Text("Sandbox runs need the \(Product.name) service running in your session.").font(.callout).foregroundStyle(.secondary)
            }
            if let error {
                Label(error, systemImage: "xmark.octagon").foregroundStyle(.red).font(.callout).textSelection(.enabled)
            }
        }
    }

    private func bullet(_ s: String) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 6) { Text("•").foregroundStyle(.secondary); Text(s).fixedSize(horizontal: false, vertical: true) }
    }

    private func run() {
        running = true; error = nil; startedAt = Date()
        let confirmation = needsTyped ? typed : "confirmed"
        Task { @MainActor in
            defer { running = false }
            do {
                switch try await model.client.request(.sandboxRun(id: record.id, confirmation: confirmation), timeout: 150) {
                case .sandboxReport(let data):
                    report = try JSONDecoder.rampart.decode(SandboxReport.self, from: data)
                case .error(let e): error = e
                default: error = "Unexpected reply from the service"
                }
            } catch let e { error = e.localizedDescription }
        }
    }
}

struct SandboxReportView: View {
    let report: SandboxReport
    @StateVar private var showProfile = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.m) {
                Grid(alignment: .leading, horizontalSpacing: Spacing.m, verticalSpacing: 4) {
                    row("Result", report.timedOut ? "Stopped at the 60-second limit" : "Exited with status \(report.exitStatus.map(String.init) ?? "unknown")")
                    row("Ran for", String(format: "%.1f s", report.seconds))
                    row("Command", report.command.joined(separator: " "))
                    row("Blocked actions", "\(report.violations.count)")
                }
                .font(.callout)
                if !report.touchedPaths.isEmpty {
                    section("Files it tried to touch") {
                        Text(QuarantineText.clean(report.touchedPaths.joined(separator: "\n"))).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                let other = report.violations.filter { !$0.operation.hasPrefix("file-") }
                if !other.isEmpty {
                    section("Other blocked actions") {
                        Text(QuarantineText.clean(other.prefix(200).map { "\($0.operation) \($0.target)" }.joined(separator: "\n")))
                            .font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
                // hx3: this text comes from the item, not from RamPart; label it so and strip spoofing characters.
                section("Output printed by the item (not from \(Product.name))") {
                    Text(report.stdout.isEmpty ? "(none)" : QuarantineText.clean(report.stdout)).font(.caption.monospaced()).textSelection(.enabled)
                }
                if !report.stderr.isEmpty {
                    section("Error output printed by the item") { Text(QuarantineText.clean(report.stderr)).font(.caption.monospaced()).textSelection(.enabled) }
                }
                if report.outputTruncated { Text("Output was cut at 64 KB.").font(.caption).foregroundStyle(.secondary) }
                ForEach(report.notes, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) }
                Text("An empty list doesn't prove the item is safe: it may wait, detect the sandbox, or need things that were blocked.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                DisclosureGroup("Sandbox profile", isExpanded: $showProfile) {
                    Text(report.profile).font(.caption2.monospaced()).textSelection(.enabled)
                }
                .font(.callout)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(maxHeight: 420)
    }

    private func row(_ k: String, _ v: String) -> some View {
        GridRow { Text(k).foregroundStyle(.secondary); Text(v).textSelection(.enabled).lineLimit(2) }
    }

    private func section<C: View>(_ title: String, @ViewBuilder _ content: () -> C) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(title).font(.headline)
            content()
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(Spacing.s)
                .background(Color.primary.opacity(0.04), in: RoundedRectangle(cornerRadius: 6, style: .continuous))
        }
    }
}
