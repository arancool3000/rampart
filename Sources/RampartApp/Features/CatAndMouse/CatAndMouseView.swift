import SwiftUI
import RampartShared
import RampartGuard

typealias CatMouseStateVar = SwiftUI.State

/// "Cat & Mouse" screen: decoys, maze, tarpit, timeline of catches. Playful by default, "Serious" on request.
/// Real threats keep their normal serious alerts and Emergency Lockdown; this screen never downgrades severity.
struct CatAndMouseView: View {
    @Bindable var model = CatAndMouseModel.shared
    @CatMouseStateVar private var confirmRemove = false
    @CatMouseStateVar private var expanded: UUID?

    private var serious: Bool { model.tone == .serious }
    private var cfg: DeceptionConfig { model.status?.config ?? DeceptionConfig() }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                if model.unsupported { unsupportedNote }
                if let e = model.error { Label(e, systemImage: "exclamationmark.triangle").foregroundStyle(.orange) }
                if model.notificationsDenied {
                    HStack {
                        Label("Turn on notifications to hear when the cat catches something", systemImage: "bell.slash")
                        Spacer()
                        Button("Turn on…") { Task { await model.turnOnNotifications() } }
                    }
                    .card(padding: Spacing.m)
                }
                ZStack(alignment: .topTrailing) {
                    CatMazeCanvas(deadEnds: model.deadEnds, caught: model.caughtRecently)
                    if model.caughtRecently {
                        Text(serious ? "Caught" : "Caught! 🐭")
                            .font(.caption.weight(.bold)).padding(.horizontal, 8).padding(.vertical, 3)
                            .background(Color.statusAction.opacity(0.25), in: Capsule())
                            .accessibilityLabel("A decoy was touched recently")
                    }
                }
                .card(padding: Spacing.m)
                toggles
                timeline
                decoyList
                limits
            }
            .contentColumn()
        }
        .task {
            // Live while the screen is open: catches and lure attempts appear within a few seconds.
            while !Task.isCancelled {
                await model.refresh()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
        .confirmationDialog(serious ? "Remove all decoy files and folders?" : "Send the cat home and remove every decoy?",
                            isPresented: $confirmRemove) {
            Button("Remove all decoys", role: .destructive) { Task { await model.removeAll() } }
        } message: {
            Text("Only files RamPart created and that are unchanged are removed. Anything edited is left in place and listed.")
        }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Cat & Mouse").font(.largeTitle.weight(.bold)).fontDesign(.monospaced)
            Text(model.headline()).font(.title3).foregroundStyle(.secondary)
            Text(serious
                 ? "Decoy files and folders that no legitimate app opens. If something reads them, RamPart treats it as a high-confidence threat."
                 : "Tempting fake files only a thief would open. They're full of jokes and fake keys; whoever sniffs them gets caught.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private var unsupportedNote: some View {
        Label("The RamPart helper doesn't support Cat & Mouse yet. Nothing has been planted.", systemImage: "info.circle")
            .foregroundStyle(.secondary).card(padding: Spacing.m)
    }

    private var toggles: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Switches")
            Toggle(isOn: Binding(get: { cfg.decoysEnabled }, set: { v in Task { await model.setDecoys(v) } })) {
                VStack(alignment: .leading) {
                    Text("Decoy files")
                    Text("Documents, Desktop, ~/.ssh, ~/.aws and a decoy browser profile. Hidden in Finder, never synced to iCloud, excluded from Time Machine.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Toggle(isOn: Binding(get: { cfg.mazeEnabled }, set: { v in Task { await model.setMaze(v) } })) {
                VStack(alignment: .leading) {
                    Text(serious ? "Decoy folder maze" : "The maze")
                    Text("Documents/Private: nested dead ends and notes that point to more dead ends. Spotlight and RamPart's scanner skip it.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }.disabled(!cfg.decoysEnabled)
            Toggle(isOn: Binding(get: { cfg.tarpitEnabled }, set: { v in Task { await model.setTarpit(v) } })) {
                VStack(alignment: .leading) {
                    Text(serious ? "Network lure (opt-in)" : "Network lure: a juicy fake \"Backup NAS\"")
                    Text("A fake NAS login on port \(cfg.tarpitPort) that answers slowly with jokes and records every attempt. Opt-in: any listening port slightly increases attack surface, so it runs boxed in by 10 separate containment layers.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            if cfg.tarpitEnabled, let err = model.status?.tarpitError {
                Label(err, systemImage: "exclamationmark.triangle.fill").foregroundStyle(.orange).font(.callout)
            } else if cfg.tarpitEnabled, model.status?.tarpitListening == true {
                Label("Listening on port \(cfg.tarpitPort).", systemImage: "dot.radiowaves.left.and.right").font(.callout)
            }
            if cfg.tarpitEnabled {
                // Reaching the lure from other devices needs the boxed-in helper (rampart-lure), its packet-filter
                // anchor and launchd job, which only the RamPart system service may install. That isn't wired up yet,
                // so only "This Mac" is offered and the network option says so honestly.
                Label("Reachable from this Mac only.", systemImage: "laptopcomputer")
                    .font(.callout)
                Text("Coming soon: letting other devices on your local network reach the lure. It needs the RamPart system service to set up its packet filter and sandboxed helper.")
                    .font(.caption).foregroundStyle(.secondary)
                DisclosureGroup("The 10 containment layers") {
                    VStack(alignment: .leading, spacing: 4) {
                        ForEach(LureContainment.layers) { l in
                            Text("\(l.id). \(l.name): ").font(.caption.weight(.semibold)) + Text(l.detail).font(.caption)
                        }
                    }.padding(.top, 4)
                }.font(.callout)
            }
            Toggle(isOn: Binding(get: { cfg.decoysVisible }, set: { v in Task { await model.setDecoysVisible(v) } })) {
                VStack(alignment: .leading) {
                    Text("Show decoys in Finder")
                    Text(cfg.decoysVisible ? "Decoys are visible in Finder." : "Decoys are hidden in Finder so you don't open them by accident. If you do, RamPart just tells you it's bait.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }.disabled(!cfg.decoysEnabled)
            Picker("Tone", selection: Binding(get: { model.tone }, set: { t in Task { await model.setTone(t) } })) {
                Text("Playful").tag(DeceptionTone.playful)
                Text("Serious").tag(DeceptionTone.serious)
            }.pickerStyle(.segmented).frame(maxWidth: 260)
            Button(role: .destructive) { confirmRemove = true } label: { Label("Remove all decoys", systemImage: "trash") }
                .disabled(model.busy || (model.status?.decoys.isEmpty ?? true))
        }
        .disabled(model.busy || model.unsupported)
        .card()
    }

    private var timeline: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader(serious ? "Decoy access timeline" : "Catches")
            if model.catches.isEmpty {
                Text(serious ? "Nothing has touched a decoy." : "No mice yet. The cat is patient.").foregroundStyle(.secondary)
            }
            ForEach(model.catches.prefix(50)) { c in catchRow(c) }
            ForEach(model.status?.tarpitAttempts.suffix(10).reversed() ?? []) { a in
                let m = DeceptionVoice.tarpit(a, tone: model.tone)
                VStack(alignment: .leading, spacing: 2) {
                    Text(m.title).font(.headline)
                    Text(m.body).font(.callout).foregroundStyle(.secondary)
                    if a.credentialAttempts > 0 {
                        Text("\(a.credentialAttempts) password guess\(a.credentialAttempts == 1 ? "" : "es") (never stored)").font(.caption)
                    }
                    if let r = a.replies, !r.isEmpty {
                        Text((serious ? "Lure replied: " : "What the cat said: ") + r.suffix(4).joined(separator: " / "))
                            .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(3)
                    }
                }
            }
        }
        .card()
    }

    @ViewBuilder private func catchRow(_ c: DeceptionCatch) -> some View {
        let m = c.userOpened ? DeceptionVoice.userOpened(c, tone: model.tone)
            : c.contained ? DeceptionVoice.contained(c, tone: model.tone) : DeceptionVoice.caught(c, tone: model.tone)
        VStack(alignment: .leading, spacing: Spacing.xs) {
            HStack {
                Text(m.title).font(.headline)
                Spacer()
                Text(m.severity.label).font(.caption.weight(.semibold))
                    .padding(.horizontal, 6).padding(.vertical, 2)
                    .background((m.severity >= .critical ? Color.statusAction : m.severity >= .medium ? Color.statusAttention : Color.statusInfo).opacity(0.2), in: Capsule())
            }
            Text(m.body).font(.callout)
            Text("\(c.processPath.isEmpty ? "program unknown" : c.processPath) · \(Fmt.dayTime(c.date))").font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
            if !c.userOpened && !c.isUnattributed { HStack {
                Button(expanded == c.id ? "Hide evidence" : "Show evidence") {
                    expanded = expanded == c.id ? nil : c.id
                    if expanded == c.id { Task { await model.loadEvidence(c) } }
                }
                if c.pid > 1 && !c.contained && kill(c.pid, 0) == 0 {
                    Button(serious ? "Stop this program" : "Contain it") { Task { await model.contain(catchID: c.id) } }
                }
                if c.quarantineID != nil {
                    Button(serious ? "Study it in the sandbox" : "Study it in the sandbox 🔬") {
                        AppModel.shared.selection = .threats   // the Threats screen owns the sandbox flow
                    }
                } else {
                    Text("Sandbox study is available once it's quarantined.").font(.caption).foregroundStyle(.secondary)
                }
            }.buttonStyle(.link) }
            if expanded == c.id, let e = model.evidence[c.id] {
                VStack(alignment: .leading, spacing: 2) {
                    Text(DeceptionVoice.verdictLine(e.verdict, tone: model.tone)).font(.callout.weight(.semibold))
                    Text("Signed: \(e.signing)").font(.caption)
                    Text("Parent chain: " + e.processTree.map { ($0.path as NSString).lastPathComponent }.joined(separator: " ← ")).font(.caption)
                    if !e.network.isEmpty { Text("Network: " + e.network.prefix(5).joined(separator: ", ")).font(.caption) }
                    if !e.filesTouched.isEmpty { Text("Also touched: " + e.filesTouched.prefix(5).joined(separator: ", ")).font(.caption).lineLimit(3) }
                }.padding(.leading, Spacing.s)
            }
        }
        .padding(.vertical, Spacing.xs)
        .accessibilityElement(children: .combine)
    }

    private var decoyList: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("Decoys")
            let files = (model.status?.decoys ?? []).filter { $0.kind.isFile && $0.kind != .mazeNote }
            let mazeCount = (model.status?.decoys ?? []).filter { !$0.kind.isFile || $0.kind == .mazeNote }.count
            if files.isEmpty && mazeCount == 0 { Text("No decoys planted.").foregroundStyle(.secondary) }
            ForEach(files) { d in
                HStack {
                    Image(systemName: "doc.text.magnifyingglass").foregroundStyle(Color.rampartTeal)
                    Text(d.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")).font(.callout.monospaced()).lineLimit(1).truncationMode(.middle)
                }
            }
            if mazeCount > 0 { Text("Maze: \(mazeCount) folders, notes and loops in ~/Documents/Private").font(.callout) }
        }
        .card()
    }

    private var limits: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            SectionHeader("What this can and can't do")
            ForEach(model.status?.notes ?? [
                "Decoys are a tripwire: RamPart sees a touch right after it happens and then responds; it cannot block the read itself.",
            ], id: \.self) { Text("• " + $0).font(.caption).foregroundStyle(.secondary) }
            Text("• Real threats always get RamPart's normal alerts and Emergency Lockdown, whatever the tone.").font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }
}
