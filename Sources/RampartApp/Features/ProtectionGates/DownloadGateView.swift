import SwiftUI
import RampartShared
import RampartGuard

typealias GateStateVar = SwiftUI.State

/// "Download Gate": every new download is checked within about a second; unsigned programs wait for the user.
struct DownloadGateView: View {
    @Bindable var model = DownloadGateModel.shared
    @GateStateVar private var confirmDelete: GateItem?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                if model.unsupported {
                    Label("The RamPart helper doesn't run Download Gate yet. Update RamPart, or start protection in your session.", systemImage: "info.circle")
                        .foregroundStyle(.secondary).card(padding: Spacing.m)
                }
                if let e = model.error { Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                toggle
                section("Held for your review", items: model.held, empty: "Nothing is waiting for you.", actions: true)
                section("Blocked", items: model.blocked, empty: "No dangerous downloads so far.", actions: false)
                section("Cleared", items: Array(model.cleared.prefix(50)), empty: "New downloads appear here once checked.", actions: false)
                limits
            }
            .contentColumn()
        }
        .task {
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
        .confirmationDialog("Move \"\(confirmDelete.map { SafeText.line($0.name, max: 60) } ?? "")\" to the Trash?",
                            isPresented: Binding(get: { confirmDelete != nil }, set: { if !$0 { confirmDelete = nil } })) {
            Button("Move to Trash", role: .destructive) {
                if let i = confirmDelete { Task { await model.decide(i.id, allow: false) } }
                confirmDelete = nil
            }
        } message: {
            Text("You can get it back from the Trash if you change your mind.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Download Gate").font(.largeTitle.weight(.bold)).fontDesign(.rounded)
            Text(model.held.isEmpty ? "New downloads are checked before you open them." : "\(model.held.count) download\(model.held.count == 1 ? " is" : "s are") waiting for you.")
                .font(.title3).foregroundStyle(.secondary)
            Text("RamPart checks each new download within about a second of it finishing: it scans it, makes sure macOS Gatekeeper will check it, and keeps unsigned programs from running until you decide.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private var toggle: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Toggle(isOn: Binding(get: { model.status?.enabled ?? true }, set: { v in Task { await model.setEnabled(v) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Check new downloads").font(.headline)
                    Text("Downloads, Desktop, Mail and Messages attachments, AirDrop and your browser's download folder.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.switch)
            .disabled(model.busy || model.unsupported)
            if let s = model.status, s.enabled && !s.running {
                Label(s.lastError ?? "Starting…", systemImage: "hourglass").font(.caption).foregroundStyle(.secondary)
            }
        }
        .card(padding: Spacing.m)
    }

    @ViewBuilder
    private func section(_ title: String, items: [GateItem], empty: String, actions: Bool) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text(title).font(.title3.weight(.semibold))
            if items.isEmpty {
                Text(empty).font(.callout).foregroundStyle(.secondary)
            } else {
                ForEach(items) { i in row(i, actions: actions) }
            }
        }
        .card(padding: Spacing.m)
    }

    private func row(_ i: GateItem, actions: Bool) -> some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            Image(systemName: symbol(i)).font(.title2).foregroundStyle(color(i)).frame(width: 28)
            VStack(alignment: .leading, spacing: 3) {
                Text(SafeText.line(i.name, max: 80)).font(.headline).lineLimit(1).truncationMode(.middle)
                Text("\(i.kind.label) · \(i.folder) · \(i.verdict.label) · checked \(String(format: "%.1f", i.secondsToCheck)) s after it arrived")
                    .font(.caption).foregroundStyle(.secondary)
                Text(i.reason).font(.callout).fixedSize(horizontal: false, vertical: true)
                if i.quarantineFlagAdded {
                    Text("RamPart added the macOS quarantine flag, so Gatekeeper checks it when it's first opened.").font(.caption).foregroundStyle(.secondary)
                }
            }
            Spacer(minLength: 0)
            if actions {
                VStack(spacing: Spacing.s) {
                    Button("Allow") { Task { await model.decide(i.id, allow: true) } }
                        .help("Give it back its permission to run")
                    Button("Delete", role: .destructive) { confirmDelete = i }
                        .help("Move it to the Trash")
                }
                .disabled(model.busy)
            }
        }
        .padding(.vertical, 4)
    }

    private func symbol(_ i: GateItem) -> String {
        switch i.verdict {
        case .held: return "hand.raised.fill"; case .blocked: return "xmark.shield.fill"; case .deleted: return "trash"
        case .allowed: return "checkmark.circle"; case .cleared: return "checkmark.shield"
        }
    }
    private func color(_ i: GateItem) -> Color {
        switch i.verdict { case .held: return .orange; case .blocked: return .red; default: return .green }
    }

    private var limits: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Label("What Download Gate can and can't do", systemImage: "info.circle").font(.headline)
            Text(model.status?.honesty ?? DownloadGateService.honesty).font(.callout).foregroundStyle(.secondary)
            Text("Apps you drag out of a disk image to Applications are outside these folders; macOS Gatekeeper still checks them because the quarantine flag travels with them. Developer folders (git repositories, build folders, Homebrew, ~/Code) are never touched.")
                .font(.callout).foregroundStyle(.secondary)
        }
        .card(padding: Spacing.m)
    }
}
