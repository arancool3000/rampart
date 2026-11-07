import SwiftUI
import AppKit
import RampartShared

struct PostureView: View {
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var showIgnored = false
    @StateVar private var removing: PersistenceItem?
    @StateVar private var showFixAllPreview = false
    @StateVar private var fixingAll = false
    @StateVar private var scoreChange: (from: Int, to: Int, fixed: Int)?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Keys mirror AppModel.scoreBreakdown so the shown impact matches the real score.
    private static let scoreKeys: [String: [String]] = [
        "filevault": ["filevault"],
        "firewall": ["firewall"],
        "updates": ["autoupdate", "auto-update", "automatic update", "softwareupdate"],
        "gk": ["gatekeeper", "sip", "integrity"],
    ]

    /// Points the score would gain if this one check were fixed (0 if it doesn't move the score on its own).
    static func scoreImpact(of c: PostureCheck, in model: AppModel) -> Int {
        guard c.state == .fail, !model.ignoredChecks.contains(c.id) else { return 0 }
        func matches(_ x: PostureCheck, _ keys: [String]) -> Bool {
            keys.contains { x.id.lowercased().contains($0) || x.title.lowercased().contains($0) }
        }
        var total = 0
        for item in model.scoreBreakdown where !item.earned {
            guard let keys = scoreKeys[item.id], matches(c, keys) else { continue }
            let others = model.failingChecks.filter { $0.id != c.id && matches($0, keys) }
            if others.isEmpty { total += item.weight }
        }
        return total
    }

    private var safeFixes: [PostureCheck] { model.failingChecks.filter(\.fixable) }

    static func symbol(for c: PostureCheck) -> String {
        let id = c.id.lowercased()
        if id.contains("filevault") { return "lock.laptopcomputer" }
        if id.contains("firewall") { return "shield.checkered" }
        if id.contains("gatekeeper") || id.contains("sip") { return "checkmark.shield" }
        if id.contains("update") || id.contains("outdated") { return "arrow.down.circle" }
        if id.contains("lockdown") { return "lock.shield" }
        if id.contains("screen") { return "lock.display" }
        if id.contains("ssh") || id.contains("sharing") { return "rectangle.connected.to.line.below" }
        if id.contains("airdrop") { return "airplayaudio" }
        if id.contains("guest") || id.contains("admin") { return "person.2" }
        return "gearshape"
    }

    private var active: [PostureCheck] { model.posture.filter { !model.ignoredChecks.contains($0.id) } }
    private var ignored: [PostureCheck] { model.posture.filter { model.ignoredChecks.contains($0.id) } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                summary
                if let change = scoreChange { scoreChangeBanner(change) }
                if showFixAllPreview && !safeFixes.isEmpty { fixAllPreview }
                group("macOS protections", active)
                startupItems
                if !ignored.isEmpty {
                    DisclosureGroup("Ignored (\(ignored.count))", isExpanded: $showIgnored) {
                        Text("Ignored items don't count toward your score.").font(.callout).foregroundStyle(.secondary)
                        ForEach(ignored) { c in
                            HStack {
                                Text(c.title)
                                Spacer()
                                Button("Stop Ignoring") { model.ignoredChecks.remove(c.id) }.controlSize(.small)
                            }
                            .padding(.vertical, 4)
                        }
                    }
                    .card()
                }
            }
            .contentColumn()
        }
        .navigationTitle("Privacy & Posture")
        .task { await model.refreshPosture() }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button { Task { await model.refreshPosture() } } label: { Label("Check Again", systemImage: "arrow.clockwise") }
            }
        }
    }

    private var summary: some View {
        let score = model.securityScore
        let failing = model.failingChecks.count
        return HStack(spacing: Spacing.xl) {
            ScoreRing(score: score, size: 88, lineWidth: 9)
            VStack(alignment: .leading, spacing: 4) {
                Text(failing == 0 ? "Your Mac's settings look good" : "\(failing) setting\(failing == 1 ? "" : "s") could make your Mac more secure")
                    .font(.title2.weight(.semibold))
                Text("Your score reflects settings you can change on this Mac. It never depends on what you've bought.")
                    .foregroundStyle(.secondary)
            }
            Spacer()
            if safeFixes.count > 1 && !showFixAllPreview {
                Button("Fix All Safe Items…") { withAnimation(anim) { showFixAllPreview = true } }
                    .buttonStyle(GlowButtonStyle())
                    .disabled(fixingAll)
                    .help("Review the one-click fixes first. Nothing changes until you confirm.")
            }
        }
        .card(padding: Spacing.xl)
        .accessibilityElement(children: .contain)
    }

    private var anim: Animation? { reduceMotion ? nil : .easeInOut(duration: 0.25) }

    private var fixAllPreview: some View {
        let items = safeFixes
        let gain = min(100 - model.securityScore, items.reduce(0) { $0 + Self.scoreImpact(of: $1, in: model) })
        return VStack(alignment: .leading, spacing: Spacing.m) {
            Text("\(Product.name) will turn on:").font(.headline)
            ForEach(items) { c in
                HStack(spacing: Spacing.s) {
                    Image(systemName: PostureView.symbol(for: c)).foregroundStyle(.secondary).frame(width: 20)
                    VStack(alignment: .leading, spacing: 1) {
                        Text(c.title)
                        if !c.fixHint.isEmpty { Text(c.fixHint).font(.caption).foregroundStyle(.secondary) }
                    }
                    Spacer()
                    if model.fixingChecks.contains(c.id) { ProgressView().controlSize(.small) }
                    else if let impact = Optional(Self.scoreImpact(of: c, in: model)), impact > 0 {
                        Text("+\(impact)").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
                    }
                }
                .accessibilityElement(children: .combine)
            }
            Text("Only settings with a built-in one-click fix are included. Anything that needs System Settings stays for you to decide.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            HStack {
                if gain > 0 { Text("Score: \(model.securityScore) → \(model.securityScore + gain)").font(.callout.monospacedDigit()).foregroundStyle(.secondary) }
                Spacer()
                Button("Cancel") { withAnimation(anim) { showFixAllPreview = false } }
                    .keyboardShortcut(.cancelAction).disabled(fixingAll)
                Button(fixingAll ? "Fixing…" : "Fix \(items.count) Items") { fixAll(items) }
                    .buttonStyle(GlowButtonStyle()).keyboardShortcut(.defaultAction).disabled(fixingAll)
            }
        }
        .card()
        .transition(.opacity)
    }

    private func fixAll(_ items: [PostureCheck]) {
        fixingAll = true
        let before = model.securityScore
        Task {
            for c in items { await model.fix(c) }
            await model.refreshPosture()
            let fixed = items.filter { c in model.posture.first { $0.id == c.id }?.state == .pass }.count
            withAnimation(anim) {
                fixingAll = false
                showFixAllPreview = false
                scoreChange = (before, model.securityScore, fixed)
            }
        }
    }

    private func scoreChangeBanner(_ c: (from: Int, to: Int, fixed: Int)) -> some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: c.to > c.from ? "arrow.up.circle.fill" : "checkmark.circle.fill").foregroundStyle(Color.statusProtected)
            Text(c.to > c.from
                 ? "Fixed \(c.fixed) setting\(c.fixed == 1 ? "" : "s"). Your score went from \(c.from) to \(c.to)."
                 : "Fixed \(c.fixed) setting\(c.fixed == 1 ? "" : "s"). Your score is \(c.to).")
            Spacer()
            Button { withAnimation(anim) { scoreChange = nil } } label: { Image(systemName: "xmark") }
                .buttonStyle(.borderless).accessibilityLabel("Dismiss")
        }
        .card(padding: Spacing.m)
        .transition(.opacity)
        .accessibilityElement(children: .combine)
    }

    private func group(_ title: String, _ checks: [PostureCheck]) -> some View {
        let order: [PostureCheck.State: Int] = [.fail: 0, .unknown: 1, .pass: 2, .notApplicable: 3]
        let sorted = checks.sorted { (order[$0.state] ?? 9, -$0.weight) < (order[$1.state] ?? 9, -$1.weight) }
        return VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader(title)
            VStack(spacing: 0) {
                ForEach(Array(sorted.enumerated()), id: \.element.id) { i, c in
                    if i > 0 { Divider() }
                    PostureRow(check: c)
                }
            }
            .card(padding: Spacing.s)
        }
    }

    private var startupItems: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Startup & background items", trailing: AnyView(
                Text("\(model.persistence.count) item\(model.persistence.count == 1 ? "" : "s")").font(.callout).foregroundStyle(.secondary)))
            if model.persistence.isEmpty {
                RuleEmptyRow(symbol: "power", text: model.mode == .live
                             ? "Nothing starts automatically except macOS itself. \(Product.name) will tell you if something new appears."
                             : "Login items and launch agents will be listed when the background service reports them.")
                    .card(padding: Spacing.s)
            }
            ForEach(StartupGroup.groups(model.persistence)) { g in
                VStack(alignment: .leading, spacing: Spacing.s) {
                    HStack(spacing: 6) {
                        Label(g.title, systemImage: g.symbol).font(.headline).foregroundStyle(.secondary)
                        Text("\(g.items.count)").font(.callout.monospacedDigit()).foregroundStyle(.tertiary)
                        let look = g.items.filter { StartupGroup.risk($0) <= 1 }.count
                        if look > 0 { Text("· \(look) worth a look").font(.callout).foregroundStyle(.secondary) }
                    }
                    .accessibilityElement(children: .combine)
                    VStack(spacing: 0) {
                        ForEach(Array(g.items.enumerated()), id: \.element.id) { i, p in
                            if i > 0 { Divider().padding(.leading, 44) }
                            StartupItemRow(item: p) { removing = p }
                        }
                    }
                    .card(padding: Spacing.s)
                }
            }
        }
        .sheet(item: $removing) { RemediationSheet(item: $0) }
    }
}

struct PostureRow: View {
    let check: PostureCheck
    @Environment(AppModel.self) private var model
    @Environment(\.openURL) private var openURL
    @StateVar private var justFixed: String?

    private func fixOne() {
        let before = model.securityScore
        Task {
            await model.fix(check)
            let after = model.securityScore
            justFixed = after > before ? "Fixed. Score \(before) → \(after)" : (model.posture.first { $0.id == check.id }?.state == .pass ? "Fixed" : nil)
        }
    }

    private var stateInfo: (String, String, Color) {
        switch check.state {
        case .pass: return ("checkmark.circle.fill", "Good", .statusProtected)
        case .fail: return ("exclamationmark.circle.fill", "Recommended", .statusAttention)
        case .unknown: return ("questionmark.circle", "Couldn't check", .secondary)
        case .notApplicable: return ("minus.circle", "Info", .secondary)
        }
    }

    var body: some View {
        let (sym, label, tint) = stateInfo
        HStack(spacing: Spacing.m) {
            Image(systemName: PostureView.symbol(for: check)).font(.title3).foregroundStyle(.secondary).frame(width: 28)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(check.title).font(.body.weight(.medium))
                    let impact = PostureView.scoreImpact(of: check, in: model)
                    if impact > 0 {
                        Text("+\(impact) pts").font(.caption.weight(.medium).monospacedDigit()).foregroundStyle(.secondary)
                            .padding(.horizontal, 6).padding(.vertical, 1)
                            .background(.quaternary, in: Capsule())
                            .help("Fixing this raises your score by \(impact).")
                            .accessibilityLabel("Raises score by \(impact) points")
                    }
                }
                if let j = justFixed {
                    Label(j, systemImage: "checkmark").font(.caption).foregroundStyle(Color.statusProtected).transition(.opacity)
                }
                Text(check.detail).font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            Spacer()
            StatusLabel(text: label, symbol: sym, tint: tint).font(.callout).frame(minWidth: 120, alignment: .leading)
            Group {
                if check.state == .fail {
                    if model.fixingChecks.contains(check.id) {
                        ProgressView().controlSize(.small)
                    } else if check.fixable {
                        Button("Fix") { fixOne() }.buttonStyle(GlowButtonStyle())
                            .help(check.fixHint)
                    } else {
                        Button("Open Settings") { openSettings() }.help(check.fixHint)
                    }
                } else { Color.clear }
            }
            .frame(width: 120, alignment: .trailing)
            if check.state == .fail {
                Menu {
                    Button("Ignore") { model.ignoredChecks.insert(check.id) }
                } label: { Image(systemName: "ellipsis") }
                    .menuStyle(.borderlessButton).menuIndicator(.hidden).fixedSize()
                    .accessibilityLabel("More options for \(check.title)")
            } else {
                Color.clear.frame(width: 16)
            }
        }
        .padding(Spacing.s)
        .accessibilityElement(children: .contain)
    }

    private func openSettings() {
        let id = check.id.lowercased()
        let url: String
        if id.contains("outdated") { url = "macappstore://showUpdatesPage" }
        else if id.contains("update") { url = "x-apple.systempreferences:com.apple.Software-Update-Settings.extension" }
        else if id.contains("sharing") || id.contains("ssh") { url = "x-apple.systempreferences:com.apple.Sharing-Settings.extension" }
        else { url = "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension" }
        if let u = URL(string: url) { openURL(u) }
    }
}

struct StartupGroup: Identifiable {
    let id: String
    let title: String
    let symbol: String
    let items: [PersistenceItem]

    static func title(_ k: PersistenceItem.Kind) -> (String, String) {
        switch k {
        case .loginItem, .btm: return ("Login items", "person.crop.circle")
        case .launchAgent: return ("Launch agents (your account)", "gearshape.2")
        case .launchDaemon: return ("Launch daemons (system)", "gearshape.2.fill")
        case .browserExtension: return ("Browser extensions", "puzzlepiece.extension")
        case .profile: return ("Configuration profiles", "doc.badge.gearshape")
        case .systemExtension: return ("System extensions", "cpu")
        case .cron, .periodic: return ("Scheduled jobs", "calendar.badge.clock")
        case .shellRC: return ("Shell startup files", "terminal")
        case .sshKey: return ("SSH authorized keys", "key")
        case .other: return ("Other", "ellipsis.circle")
        }
    }

    static func groups(_ items: [PersistenceItem]) -> [StartupGroup] {
        let order: [PersistenceItem.Kind] = [.loginItem, .btm, .launchAgent, .launchDaemon, .browserExtension, .systemExtension, .profile, .cron, .periodic, .shellRC, .sshKey, .other]
        var byTitle: [String: (String, [PersistenceItem], Int)] = [:]
        for it in items {
            let (t, sym) = title(it.kind)
            let rank = order.firstIndex(of: it.kind) ?? 99
            var e = byTitle[t] ?? (sym, [], rank)
            e.1.append(it); e.2 = min(e.2, rank)
            byTitle[t] = e
        }
        return byTitle.map { t, e in
            // Unsigned and ad-hoc items first: those are the ones worth a look.
            let sorted = e.1.sorted { (risk($0), $0.label.lowercased()) < (risk($1), $1.label.lowercased()) }
            return StartupGroup(id: t, title: t, symbol: e.0, items: sorted)
        }
        .sorted { (byTitle[$0.title]?.2 ?? 99) < (byTitle[$1.title]?.2 ?? 99) }
    }

    static func risk(_ p: PersistenceItem) -> Int {
        switch p.signing?.status {
        case .invalid?, .revoked?: return 0
        case .unsigned?, .adHoc?: return 1
        case nil, .unknown?: return 2
        default: return 3
        }
    }
}

struct StartupItemRow: View {
    let item: PersistenceItem
    let onRemove: () -> Void
    @StateVar private var hover = false
    private var unusual: Bool { StartupGroup.risk(item) <= 1 }
    var body: some View {
        HStack(spacing: Spacing.m) {
            Group {
                if let t = item.target, FileManager.default.fileExists(atPath: t) {
                    Image(nsImage: NSWorkspace.shared.icon(forFile: AppModel.bundlePath(forExecutable: t) ?? t)).resizable()
                } else {
                    Image(systemName: "gearshape").resizable().scaledToFit().foregroundStyle(.secondary).padding(4)
                }
            }
            .frame(width: 28, height: 28)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(item.label).font(.body.weight(.medium)).lineLimit(1)
                    if unusual { Badge(text: "Worth a look", tint: .yellow) }
                }
                Text((item.target ?? item.location).replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                    .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                    .textSelection(.enabled)
            }
            Spacer()
            if let sig = item.signing { SigningBadge(status: sig.status, notarized: sig.notarized) } else { Badge(text: "Not checked") }
            if let team = item.signing?.teamID { Text(team).font(.caption.monospaced()).foregroundStyle(.tertiary) }
            Button("Turn Off…", action: onRemove)
                .controlSize(.small)
                .opacity(hover || unusual ? 1 : 0.6)
                .accessibilityLabel("Turn off \(item.label)")
        }
        .padding(Spacing.s)
        .onHover { hover = $0 }
        .accessibilityElement(children: .combine)
    }
}

/// Shows exactly what turning off a startup item will do (from the daemon) before doing it.
struct RemediationSheet: View {
    let item: PersistenceItem
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var preview: RemediationPreview?
    @StateVar private var error: String?
    @StateVar private var applying = false
    @StateVar private var done = false
    @StateVar private var showCommands = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: "power", tint: .rampartTeal, size: 40)
                VStack(alignment: .leading) {
                    Text(preview?.title ?? "Turn off \(item.label)?").font(.title2.weight(.semibold))
                    Text(item.location.replacingOccurrences(of: NSHomeDirectory(), with: "~"))
                        .font(.caption.monospaced()).foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
            }
            if done {
                Label("Done. \(item.label) won't start automatically anymore.\(preview?.undoable == true ? " You can undo this from Protection Activity." : "")",
                      systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.primary)
                HStack { Spacer(); Button("Close") { dismiss() }.keyboardShortcut(.defaultAction) }
            } else if let p = preview {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("\(Product.name) will:").font(.headline)
                    ForEach(Array(p.steps.enumerated()), id: \.offset) { i, step in
                        Label(step, systemImage: "\(i + 1).circle").fixedSize(horizontal: false, vertical: true)
                    }
                }
                if !p.commands.isEmpty {
                    DisclosureGroup("Show exact commands", isExpanded: $showCommands) {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(p.commands, id: \.self) { Text($0).font(.caption.monospaced()).textSelection(.enabled) }
                        }
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    }
                }
                Label(p.undoable ? "You can undo this later." : "This can't be undone automatically.",
                      systemImage: p.undoable ? "arrow.uturn.backward.circle" : "exclamationmark.circle")
                    .font(.callout).foregroundStyle(.secondary)
                if p.requiresRoot && model.source != .systemService {
                    Label("This item belongs to the system, so removing it needs the full system service.", systemImage: "lock")
                        .font(.callout).foregroundStyle(.secondary)
                }
                if let error { Text(error).font(.callout).foregroundStyle(.red) }
                HStack {
                    Spacer()
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                    Button(applying ? "Turning Off…" : "Turn Off") {
                        applying = true
                        Task {
                            error = await model.remediate(item)
                            applying = false
                            if error == nil { done = true }
                        }
                    }
                    .buttonStyle(GlowButtonStyle())
                    .disabled(applying || (p.requiresRoot && model.source != .systemService && model.mode == .live))
                }
            } else if let error {
                Text(error).foregroundStyle(.secondary)
                HStack { Spacer(); Button("Close") { dismiss() } }
            } else {
                HStack(spacing: Spacing.s) { ProgressView().controlSize(.small); Text("Checking what this would change…").foregroundStyle(.secondary) }
            }
        }
        .padding(Spacing.xl)
        .frame(width: 540)
        .task {
            switch await model.previewRemediation(item) {
            case .success(let p): preview = p
            case .failure(let e): error = "\(Product.name) couldn't prepare this change: \(e.localizedDescription)"
            }
        }
    }
}
