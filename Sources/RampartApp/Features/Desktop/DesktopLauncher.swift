import SwiftUI
import AppKit
import RampartShared

// MARK: - Launcher grid

struct DesktopLauncher: View {
    private let launcher = LauncherModel.shared
    @StateVar private var dropTarget: String?

    var body: some View {
        let a = launcher.arranged
        VStack(alignment: .leading, spacing: DS.Space.m) {
            DesktopSectionTitle(title: "Favourites", symbol: "star.fill", trailing: AnyView(
                Text("Drag to reorder · right-click to pin").font(.system(size: 10.5)).foregroundStyle(.white.opacity(0.4))))
            ScrollView(.horizontal, showsIndicators: false) {
                HStack(spacing: DS.Space.s) {
                    ForEach(a.favorites) { app in tile(app, size: 58, favorite: true) }
                    if a.favorites.isEmpty {
                        Text("Right-click any app below and choose Pin to Favourites.")
                            .font(DS.Font.caption).foregroundStyle(.white.opacity(0.55)).frame(height: 84)
                    }
                }
                .padding(.vertical, 2)
            }
            .frame(minHeight: 96)
            .dropDestination(for: String.self) { items, _ in
                guard let p = items.first else { return false }
                launcher.move(p, before: nil, inFavorites: true); return true
            }
            Divider().overlay(Color.white.opacity(0.08))
            DesktopSectionTitle(title: "All apps", symbol: "square.grid.3x3.fill", trailing: AnyView(
                Text(launcher.loaded ? "\(a.others.count + a.favorites.count)" : "").font(DS.Font.caption).foregroundStyle(.white.opacity(0.4)).monospacedDigit()))
            ScrollView {
                LazyVGrid(columns: [GridItem(.adaptive(minimum: 86, maximum: 110), spacing: DS.Space.s)], spacing: DS.Space.m) {
                    ForEach(a.others) { app in tile(app, size: 46, favorite: false) }
                }
                .padding(.bottom, DS.Space.s)
            }
            .scrollIndicators(.never)
            .dropDestination(for: String.self) { items, _ in
                guard let p = items.first else { return false }
                launcher.move(p, before: nil, inFavorites: false); return true
            }
            if !launcher.loaded { ProgressView().controlSize(.small).frame(maxWidth: .infinity) }
        }
        .frame(maxHeight: .infinity, alignment: .top)
        .desktopCard()
        .onAppear { if !launcher.loaded { Headless.active ? launcher.loadNow() : launcher.refreshIfStale() } }
    }

    private func tile(_ app: LauncherApp, size: CGFloat, favorite: Bool) -> some View {
        Button { launcher.launch(app) } label: {
            VStack(spacing: 6) {
                Image(nsImage: launcher.icon(app)).resizable().interpolation(.high).frame(width: size, height: size)
                    .shadow(color: .black.opacity(0.3), radius: 4, y: 2)
                Text(app.name).font(.system(size: 11, weight: .medium)).lineLimit(1).truncationMode(.tail)
                    .frame(maxWidth: favorite ? 74 : 92)
            }
            .padding(.vertical, 6).padding(.horizontal, 4)
            .frame(width: favorite ? 82 : nil)
            .background(RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous)
                .fill(Color.white.opacity(dropTarget == app.path ? 0.16 : 0)))
            .contentShape(RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous))
        }
        .buttonStyle(LauncherTileStyle())
        .help(app.name)
        .accessibilityLabel("Open \(app.name)")
        .draggable(app.path) {
            Image(nsImage: launcher.icon(app)).resizable().frame(width: size, height: size)
        }
        .dropDestination(for: String.self) { items, _ in
            guard let p = items.first, p != app.path else { return false }
            launcher.move(p, before: app.path, inFavorites: favorite); return true
        } isTargeted: { on in dropTarget = on ? app.path : (dropTarget == app.path ? nil : dropTarget) }
        .contextMenu {
            Button(launcher.layout.isFavorite(app.path) ? "Unpin from Favourites" : "Pin to Favourites") { launcher.togglePin(app) }
            Button("Show in Finder") { launcher.reveal(app) }
        }
    }
}

/// Hover brightens the tile; press dims it a touch. No bounce.
struct LauncherTileStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View { TileBody(configuration: configuration) }
    struct TileBody: View {
        let configuration: Configuration
        @StateVar private var hover = false
        var body: some View {
            configuration.label
                .background(RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous).fill(Color.white.opacity(hover ? 0.08 : 0)))
                .opacity(configuration.isPressed ? 0.7 : 1)
                .onHover { hover = $0 }
                .animation(.easeOut(duration: 0.12), value: hover)
        }
    }
}

// MARK: - Search

struct DesktopSearchBar: View {
    private let launcher = LauncherModel.shared
    @StateVar private var query = ""
    @FocusState private var focused: Bool

    var body: some View {
        let results = query.isEmpty ? [] : DesktopSearch.rank(query, in: DesktopCatalog.items(apps: launcher.apps), limit: 7)
        VStack(spacing: 0) {
            HStack(spacing: DS.Space.s) {
                Image(systemName: "magnifyingglass").foregroundStyle(.white.opacity(0.6))
                TextField("Search apps and \(Product.name)…", text: $query)
                    .textFieldStyle(.plain)
                    .font(.system(size: 16, weight: .regular, design: .monospaced))
                    .focused($focused)
                    .onSubmit { if let f = results.first { open(f) } }
                    .onExitCommand { query = ""; focused = false; DesktopMode.shared.launcherOpen = false }
                    .onChange(of: focused) { _, f in if f { withAnimation(.easeOut(duration: 0.2)) { DesktopMode.shared.launcherOpen = true } } }
                Button {
                    withAnimation(.easeOut(duration: 0.2)) { DesktopMode.shared.launcherOpen.toggle() }
                } label: {
                    Image(systemName: DesktopMode.shared.launcherOpen ? "chevron.up" : "square.grid.2x2")
                        .foregroundStyle(.white.opacity(0.7))
                }
                .buttonStyle(.plain)
                .help(DesktopMode.shared.launcherOpen ? "Hide apps" : "Show apps")
                .accessibilityLabel(DesktopMode.shared.launcherOpen ? "Hide apps" : "Show apps")
                if !query.isEmpty {
                    Button { query = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.white.opacity(0.5)) }
                        .buttonStyle(.plain).accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, DS.Space.l).padding(.vertical, DS.Space.m)
            if !results.isEmpty {
                Divider().overlay(Color.white.opacity(0.1))
                VStack(spacing: 2) {
                    ForEach(Array(results.enumerated()), id: \.element.id) { i, r in
                        Button { open(r) } label: {
                            HStack(spacing: DS.Space.m) {
                                resultIcon(r).frame(width: 24, height: 24)
                                Text(r.title).font(DS.Font.body)
                                Spacer()
                                Text(r.kind == .app ? "App" : (r.kind == .action ? "Action" : Product.name))
                                    .font(DS.Font.caption).foregroundStyle(.white.opacity(0.45))
                                if i == 0 { Image(systemName: "return").font(.caption).foregroundStyle(.white.opacity(0.45)) }
                            }
                            .padding(.horizontal, DS.Space.m).padding(.vertical, 7)
                            .background(Color.white.opacity(i == 0 ? 0.08 : 0), in: RoundedRectangle(cornerRadius: DS.Radius.control, style: .continuous))
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(LauncherTileStyle())
                    }
                }
                .padding(DS.Space.s)
            } else if !query.isEmpty {
                Text("No apps or \(Product.name) features match “\(query)”.").font(DS.Font.caption).foregroundStyle(.white.opacity(0.55))
                    .padding(DS.Space.m)
            }
        }
        .desktopCard(padding: 0)
    }

    private func open(_ r: DesktopSearchItem) {
        DesktopCatalog.open(r)
        query = ""; focused = false
    }

    @ViewBuilder private func resultIcon(_ r: DesktopSearchItem) -> some View {
        if r.kind == .app, let a = launcher.apps.first(where: { "app:" + $0.path == r.id }) {
            Image(nsImage: launcher.icon(a)).resizable()
        } else {
            Image(systemName: DesktopCatalog.symbol(for: r)).foregroundStyle(Palette.teal)
        }
    }
}
