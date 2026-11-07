import SwiftUI
import AppKit
import RampartShared
import RampartRefresh

// MARK: - Disk map (squarified treemap, click to drill in)

struct RefreshDiskMapSection: View {
    @Bindable var model: RefreshModel
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack {
                breadcrumbs
                Spacer()
                if model.mapping {
                    ProgressView().controlSize(.small)
                    Button("Stop") { model.cancelMap() }.secondaryActionStyle()
                } else {
                    Button(model.mapRoot == nil ? "Map my home folder" : "Map again") { model.buildMap() }.buttonStyle(GlowButtonStyle())
                }
            }
            if let node = model.mapStack.last {
                RefreshTreemap(node: node) { child in
                    guard !child.children.isEmpty else { return }
                    withAnimation(reduceMotion ? nil : .snappy(duration: 0.25)) { model.mapStack.append(child) }
                }
                .frame(height: 420)
                .card(padding: Spacing.s)
                legend(node)
            } else {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("See where your space goes").font(.headline)
                    Text("Sizes are what's really on disk: sparse files count only the blocks they use, hard links count once, and space shared with APFS clones is shown separately because removing one copy doesn't free it. Folders macOS protects (Desktop, Documents, Mail…) are measured only when “Include personal folders” is on in Storage.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                .card()
            }
        }
    }

    private var breadcrumbs: some View {
        HStack(spacing: 4) {
            ForEach(Array(model.mapStack.enumerated()), id: \.element.id) { i, n in
                if i > 0 { Image(systemName: "chevron.right").font(.caption).foregroundStyle(.tertiary) }
                Button(i == 0 ? "Home" : SafeText.line(n.name, max: 60)) { model.mapStack = Array(model.mapStack.prefix(i + 1)) }
                    .buttonStyle(.link).font(.callout.weight(i == model.mapStack.count - 1 ? .semibold : .regular))
            }
        }
    }

    private func legend(_ node: DiskMapper.Node) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text("\(node.bytes.refreshFormatted) on disk" + (node.sharedBytes > 0 ? " · \(node.sharedBytes.refreshFormatted) shared with clones" : ""))
                .font(.callout.weight(.medium))
            let skipped = node.children.filter { $0.skippedReason != nil }
            if !skipped.isEmpty {
                Text("Not measured (protected by macOS): " + SafeText.line(skipped.map(\.name).joined(separator: ", "), max: 400))
                    .font(.caption).foregroundStyle(.secondary)
            }
            if let v = model.volume, v.purgeable > 0 {
                Text("Purgeable on this disk: \(v.purgeable.refreshFormatted). macOS frees it automatically when space is needed.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
    }
}

struct RefreshTreemap: View {
    let node: DiskMapper.Node
    let onOpen: (DiskMapper.Node) -> Void

    var body: some View {
        GeometryReader { geo in
            let kids = node.children.filter { $0.bytes + $0.sharedBytes > 0 }.prefix(60)
            let rects = RefreshSquarify.layout(kids.map { Double($0.bytes + $0.sharedBytes) }, in: CGRect(origin: .zero, size: geo.size))
            ZStack(alignment: .topLeading) {
                ForEach(Array(zip(kids.indices, rects)), id: \.0) { i, r in
                    RefreshTreemapTile(node: kids[i], index: i, onOpen: onOpen)
                        .frame(width: max(0, r.width - 2), height: max(0, r.height - 2))
                        .offset(x: r.minX + 1, y: r.minY + 1)
                }
            }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Disk map of \(SafeText.line(node.name))")
    }
}

struct RefreshTreemapTile: View {
    let node: DiskMapper.Node
    let index: Int
    let onOpen: (DiskMapper.Node) -> Void
    @StateVar private var hover = false
    static let tints: [Color] = [.rampartTeal, .indigo, Palette.mint, .purple, Palette.amber, .blue, Palette.coral, .teal, .orange, .pink]

    var body: some View {
        let t = Self.tints[index % Self.tints.count]
        GeometryReader { g in
            ZStack(alignment: .topLeading) {
                RoundedRectangle(cornerRadius: 6, style: .continuous)
                    .fill(LinearGradient(colors: [t.opacity(hover ? 0.95 : 0.8), t.opacity(0.55)], startPoint: .topLeading, endPoint: .bottomTrailing))
                if g.size.width > 60 && g.size.height > 30 {
                    VStack(alignment: .leading, spacing: 1) {
                        Text(SafeText.line(node.name)).font(.caption.weight(.semibold)).lineLimit(1)
                        Text((node.bytes + node.sharedBytes).refreshFormatted).font(.caption2.monospacedDigit()).opacity(0.85)
                    }
                    .foregroundStyle(.white).padding(6)
                }
            }
        }
        .contentShape(Rectangle())
        .onHover { hover = $0 }
        .onTapGesture { onOpen(node) }
        .help("\(SafeText.path(node.path.replacingOccurrences(of: NSHomeDirectory(), with: "~"))) · \(node.bytes.refreshFormatted)" + (node.sharedBytes > 0 ? " + \(node.sharedBytes.refreshFormatted) shared" : "") + (node.children.isEmpty ? "" : " · click to open"))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(SafeText.line(node.name)), \((node.bytes + node.sharedBytes).refreshFormatted)")
        .accessibilityAddTraits(node.children.isEmpty ? [] : .isButton)
        .contextMenu { Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: node.path)]) } }
    }
}

/// Squarified treemap layout (Bruls, Huizing, van Wijk). Values must be sorted largest first.
enum RefreshSquarify {
    static func layout(_ values: [Double], in rect: CGRect) -> [CGRect] {
        let total = values.reduce(0, +)
        guard total > 0, rect.width > 0, rect.height > 0 else { return values.map { _ in .zero } }
        let scale = Double(rect.width * rect.height) / total
        var areas = values.map { $0 * scale }
        var out: [CGRect] = []
        var r = rect
        while !areas.isEmpty {
            let side = Double(min(r.width, r.height))
            var row: [Double] = []
            func worst(_ row: [Double]) -> Double {
                let s = row.reduce(0, +); guard s > 0, let mx = row.max(), let mn = row.min() else { return .infinity }
                return max(side * side * mx / (s * s), (s * s) / (side * side * mn))
            }
            while let a = areas.first, row.isEmpty || worst(row + [a]) <= worst(row) { row.append(a); areas.removeFirst() }
            let s = row.reduce(0, +)
            if r.width >= r.height {
                let w = CGFloat(s / Double(r.height)); var y = r.minY
                for a in row { let h = CGFloat(a) / w; out.append(CGRect(x: r.minX, y: y, width: w, height: h)); y += h }
                r = CGRect(x: r.minX + w, y: r.minY, width: max(0, r.width - w), height: r.height)
            } else {
                let h = CGFloat(s / Double(r.width)); var x = r.minX
                for a in row { let w = CGFloat(a) / h; out.append(CGRect(x: x, y: r.minY, width: w, height: h)); x += w }
                r = CGRect(x: r.minX, y: r.minY + h, width: r.width, height: max(0, r.height - h))
            }
        }
        return out
    }
}

// MARK: - Speed

struct RefreshSpeedSection: View {
    @Bindable var model: RefreshModel
    @Environment(AppModel.self) private var app
    @StateVar private var removing: PersistenceItem?
    enum Part: Hashable { case memory, apps, startup }
    /// Which cards to show (the Refresh sidebar splits Speed & Memory from Startup Items).
    var parts: Set<Part> = [.memory, .apps, .startup]

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            if parts.contains(.memory) { memoryCard }
            if parts.contains(.apps) { appsCard }
            if parts.contains(.startup) { startupCard }
        }
        .onAppear { model.sample() }
        .sheet(item: $removing) { RemediationSheet(item: $0) }
    }

    private var memoryCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            HStack {
                SectionHeader("Memory")
                Spacer()
                Button { model.sample() } label: { Label("Refresh", systemImage: "arrow.clockwise") }
                    .secondaryActionStyle().disabled(model.sampling)
            }
            if let m = model.memory {
                let tint: Color = m.pressure == .critical ? Palette.coral : (m.pressure == .warning ? Palette.amber : Palette.mint)
                HStack(spacing: Spacing.xl) {
                    StatusLabel(text: "Memory pressure: \(m.pressure.label)", symbol: m.pressure == .normal ? "checkmark.circle.fill" : "exclamationmark.circle.fill", tint: tint)
                        .font(.headline)
                    Spacer()
                    Text("\(m.used.refreshFormatted) used of \(m.total.refreshFormatted)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                }
                GeometryReader { g in
                    let total = Double(max(1, m.total))
                    HStack(spacing: 1) {
                        bar(Double(m.wired) / total, .indigo, g.size.width)
                        bar(Double(m.active) / total, .rampartTeal, g.size.width)
                        bar(Double(m.compressed) / total, Palette.amber, g.size.width)
                        bar(Double(m.cached) / total, Color.secondary.opacity(0.35), g.size.width)
                        Spacer(minLength: 0)
                    }
                }
                .frame(height: 12).clipShape(Capsule())
                .accessibilityHidden(true)
                HStack(spacing: Spacing.l) {
                    legendDot(.indigo, "System \(m.wired.refreshFormatted)")
                    legendDot(.rampartTeal, "Apps \(m.active.refreshFormatted)")
                    legendDot(Palette.amber, "Compressed \(m.compressed.refreshFormatted)")
                    legendDot(.secondary, "Cached \(m.cached.refreshFormatted)")
                    if m.swapUsed > 0 { Text("Swap \(m.swapUsed.refreshFormatted)").font(.caption).foregroundStyle(.secondary) }
                }
                Text(m.pressure == .normal
                     ? "Your Mac has enough memory for what you're doing. Unused memory is used as cache on purpose, which makes things faster; “RAM cleaners” only empty that cache and slow your Mac down, so RamPart doesn't offer one."
                     : "Memory is tight. The real fix is quitting apps you're not using (below). RamPart doesn't “clean RAM”: macOS already frees cached memory instantly when an app needs it.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            } else {
                ProgressView().controlSize(.small)
            }
        }
        .card()
    }

    private func bar(_ f: Double, _ c: Color, _ w: CGFloat) -> some View {
        Rectangle().fill(c).frame(width: max(0, CGFloat(f) * w))
    }
    private func legendDot(_ c: Color, _ t: String) -> some View {
        HStack(spacing: 4) { Circle().fill(c).frame(width: 8, height: 8); Text(t).font(.caption).foregroundStyle(.secondary) }
    }

    private var appsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("Apps using the most")
            Text("Memory and CPU over the last second, with helper processes counted under their app. Quit asks the app to close normally, so it can save your work.")
                .font(.caption).foregroundStyle(.secondary)
            ForEach(model.topApps) { u in appRow(u) }
            if model.topApps.isEmpty && !model.sampling { Text("No data yet.").font(.callout).foregroundStyle(.secondary) }
        }
        .card()
    }

    private func appRow(_ u: SpeedMonitor.AppUsage) -> some View {
        let running = model.runningApp(for: u)
        return HStack(spacing: Spacing.m) {
            if let icon = running?.icon { Image(nsImage: icon).resizable().frame(width: 22, height: 22) }
            else { Image(systemName: "gearshape.2").frame(width: 22, height: 22).foregroundStyle(.secondary) }
            VStack(alignment: .leading, spacing: 1) {
                Text(SafeText.line(running?.localizedName ?? u.name, max: 80)).font(.callout)
                if u.pids.count > 1 { Text("\(u.pids.count) processes").font(.caption2).foregroundStyle(.tertiary) }
            }
            Spacer()
            Text(u.memory.refreshFormatted).font(.callout.monospacedDigit()).frame(width: 80, alignment: .trailing)
            Text(String(format: "%.0f%% CPU", u.cpuPercent)).font(.callout.monospacedDigit()).foregroundStyle(.secondary).frame(width: 70, alignment: .trailing)
            if let r = running, r.processIdentifier != getpid(), r.activationPolicy == .regular {
                if model.forceQuitCandidate?.key == u.key {
                    Button("Force Quit", role: .destructive) { model.forceQuit(u) }.buttonStyle(.borderedProminent).tint(Palette.coral)
                        .help("Unsaved work in \(SafeText.line(r.localizedName ?? u.name, max: 80)) will be lost.")
                    Button("Cancel") { model.forceQuitCandidate = nil }.secondaryActionStyle()
                } else if model.quitRequested.contains(u.key) && !r.isTerminated {
                    Button("Force Quit…") { model.forceQuitCandidate = u }.secondaryActionStyle()
                        .help("The app hasn't quit. It may be asking about unsaved changes; check it first.")
                } else {
                    Button("Quit") { model.quit(u) }.secondaryActionStyle()
                }
            }
        }
        .padding(.vertical, 2)
    }

    private var startupItems: [PersistenceItem] {
        app.persistence.filter { [.launchAgent, .loginItem, .btm].contains($0.kind) && !$0.location.hasPrefix("/System") }
    }

    private var startupCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("Starts with your Mac")
            Text("Items that launch at login use memory and slow startup. Turning one off goes through \(Product.name)'s usual preview, and you can undo it.")
                .font(.caption).foregroundStyle(.secondary)
            if !startupItems.isEmpty {
                ForEach(startupItems) { p in
                    HStack {
                        Image(systemName: "power").foregroundStyle(.secondary).frame(width: 20)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(SafeText.line(p.label)).font(.callout).lineLimit(1)
                            Text(SafeText.path(p.location.replacingOccurrences(of: NSHomeDirectory(), with: "~"))).font(.caption2.monospaced()).foregroundStyle(.tertiary).lineLimit(1).truncationMode(.middle)
                        }
                        Spacer()
                        Button("Turn off…") { removing = p }.secondaryActionStyle()
                    }
                }
            } else {
                let agents = SpeedMonitor.userLaunchAgents()
                if agents.isEmpty { Text("No login agents in your Library.").font(.callout).foregroundStyle(.secondary) }
                ForEach(agents) { a in
                    HStack {
                        Image(systemName: "power").foregroundStyle(.secondary).frame(width: 20)
                        VStack(alignment: .leading, spacing: 1) {
                            Text(SafeText.line(a.label)).font(.callout).lineLimit(1)
                            if a.targetMissing { Text("Its program is missing: safe to turn off.").font(.caption2).foregroundStyle(Palette.amber) }
                        }
                        Spacer()
                        Badge(text: "Impact: \(a.impact)", tint: a.impact == "High" ? Palette.amber : .secondary)
                        Button("Turn off…") { removing = PersistenceItem(kind: .launchAgent, label: a.label, location: a.path, target: a.program) }
                            .secondaryActionStyle()
                    }
                }
            }
        }
        .card()
    }
}
