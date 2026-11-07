import SwiftUI
import RampartShared
import RampartRefresh

/// Refresh mode: one sidebar destination per tool, all reusing the existing Refresh views and the shared model.
struct RefreshDestinationView: View {
    let item: SidebarItem
    @StateVar private var model = RefreshModel.shared

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                content
            }
            .contentColumn()
        }
        .navigationTitle(item.title)
        .sheet(isPresented: $model.showPreview) { RefreshPreviewSheet(model: model) }
    }

    private var subtitle: String {
        switch item {
        case .refreshSmart: return "Free up space safely. Everything goes to the Trash first, so you can put it back."
        case .refreshStorage: return "Caches, logs, build leftovers and more, each explained, with only safe items pre-selected."
        case .refreshMap: return "See what takes up space on your Mac."
        case .refreshSpeed: return "Real memory pressure and the apps using the most. No fake “RAM cleaning”."
        case .refreshStartup: return "Apps and helpers that start when you log in."
        case .refreshLargeOld: return "Big files you haven't opened in a long time. Never pre-selected."
        case .refreshDuplicates: return "Identical copies of the same file. Never pre-selected."
        case .refreshLeftovers: return "Support files left behind by apps you've deleted."
        default: return "How Refresh works on this Mac."
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(item.title).font(.title2.weight(.semibold)).fontDesign(.rounded)
            Text(subtitle).font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var content: some View {
        switch item {
        case .refreshMap: RefreshDiskMapSection(model: model)
        case .refreshSpeed: RefreshSpeedSection(model: model, parts: [.memory, .apps])
        case .refreshStartup: RefreshSpeedSection(model: model, parts: [.startup])
        case .refreshLargeOld: category(.largeOldFiles)
        case .refreshDuplicates: category(.duplicates)
        case .refreshLeftovers: category(.leftovers)
        case .refreshSettings: settings
        default: RefreshStorageSection(model: model)   // Smart Refresh and Storage Cleanup share the full storage flow
        }
    }

    /// One category from the storage scan (scanning first if there are no results yet).
    @ViewBuilder private func category(_ c: RefreshCategory) -> some View {
        if let r = model.results.first(where: { $0.category == c }) {
            if r.items.isEmpty && r.note == nil {
                Text("Nothing found in \(c.title).").foregroundStyle(.secondary).card()
            } else {
                RefreshCategoryCard(model: model, result: r)
            }
        } else if model.isScanning {
            HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Looking…").foregroundStyle(.secondary) }.card()
        } else {
            VStack(alignment: .leading, spacing: Spacing.m) {
                Text("Run a scan to see \(c.title.lowercased()).").font(.callout)
                if !model.includePersonal && [.largeOldFiles, .duplicates].contains(c) {
                    Text("This needs “Include personal folders” (Refresh Settings), because these files live in Downloads and your other folders.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button { model.scan() } label: { Label("Scan", systemImage: "magnifyingglass") }.buttonStyle(GlowButtonStyle())
            }
            .card()
        }
        if !model.selectedItems.isEmpty {
            Button { model.preparePreview() } label: { Label("Review & move \(model.selectedBytes.refreshFormatted) to the Trash", systemImage: "trash") }
                .secondaryActionStyle()
        }
    }

    private var settings: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Toggle("Include personal folders (Downloads, duplicates, large old files)", isOn: $model.includePersonal)
                .toggleStyle(.switch)
            Text("macOS may ask once for permission to read these folders. Nothing in them is ever pre-selected except old installers.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            ForEach([
                ("trash", "Everything goes to the Trash first, with one-click undo. Emptying the Trash always asks."),
                ("lock.shield", "macOS system files, app contents, keychains, iCloud Drive and open files are refused, even if selected."),
                ("memorychip", "No fake “RAM cleaning”: macOS manages memory well."),
            ], id: \.0) { s, t in
                HStack(alignment: .top, spacing: Spacing.m) { Image(systemName: s).foregroundStyle(Color.rampartTeal).frame(width: 22); Text(t).font(.callout) }
            }
        }
        .card()
    }
}
