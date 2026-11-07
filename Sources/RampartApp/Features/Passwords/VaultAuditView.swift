import SwiftUI
import RampartVault

/// Watchtower: breached, weak, reused, old, missing 2FA and passkey-ready logins, each with a one-click fix.
struct VaultAuditView: View {
    @Bindable private var model = PasswordsModel.shared

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            let audit = model.audit ?? VaultAudit.run(items: model.items)
            HStack(spacing: Spacing.xl) {
                ScoreRing(score: audit.score, size: 96, lineWidth: 10)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Watchtower").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text(summary(audit)).foregroundStyle(.secondary)
                    HStack {
                        if model.meta.settings.breachCheckEnabled {
                            Button {
                                Task { await model.runAudit(checkBreaches: true) }
                            } label: {
                                HStack { if model.breachSweepRunning { ProgressView().controlSize(.small) }; Text(model.breachSweepRunning ? "Checking…" : "Check Now") }
                            }
                            .buttonStyle(GlowButtonStyle()).disabled(model.breachSweepRunning)
                            .help("Re-check every password against known breaches now")
                        } else {
                            Toggle("Check passwords against known breaches automatically", isOn: Binding(get: { model.meta.settings.breachCheckEnabled },
                                                                                set: { v in model.updateSettings { $0.breachCheckEnabled = v } }))
                                .toggleStyle(.switch).controlSize(.small)
                        }
                    }
                    if let n = model.auditNote { Text(n).font(.caption).foregroundStyle(.orange) }
                }
                Spacer()
            }
            .card(padding: Spacing.xl)

            LazyVGrid(columns: [GridItem(.adaptive(minimum: 130), spacing: Spacing.m)], spacing: Spacing.m) {
                ForEach(VaultAudit.Issue.allCases) { issue in tile(issue, audit.items(issue).count) }
            }

            ForEach(VaultAudit.Issue.allCases) { issue in
                let ids = audit.items(issue)
                if !ids.isEmpty { section(issue, ids, audit) }
            }
            if audit.loginCount > 0 && audit.problemItemCount == 0 {
                StatusLabel(text: "No problems found in \(audit.loginCount) logins.", symbol: "checkmark.seal.fill", tint: .green).card()
            }
            Text("Breach monitoring uses Have I Been Pwned's Pwned Passwords service: only the first 5 characters of a scrambled fingerprint of each password leave this Mac, never the password itself. Each password is re-checked at most once a day; results are stored hashed inside the encrypted vault. Turn it off in Settings. Two-factor and passkey suggestions use a small built-in list of sites, which may be out of date.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func tile(_ issue: VaultAudit.Issue, _ n: Int) -> some View {
        let bad = n > 0 && issue != .passkey
        return VStack(alignment: .leading, spacing: 4) {
            Image(systemName: issue.symbol).foregroundStyle(bad ? (issue == .breached ? Palette.coral : .orange) : .secondary)
            Text("\(n)").font(.title2.weight(.semibold).monospacedDigit())
            Text(issue.title).font(.caption).foregroundStyle(.secondary).lineLimit(2)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .card()
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(issue.title): \(n)")
    }

    private func summary(_ a: VaultAudit) -> String {
        if a.loginCount == 0 { return "Add logins to see how healthy your passwords are." }
        let n = a.problemItemCount
        let breach: String
        if !model.meta.settings.breachCheckEnabled { breach = " Breach monitoring is off." }
        else if model.breachSweepRunning { breach = " Checking against known breaches…" }
        else if let d = model.lastBreachSweep { breach = " Checked for breaches \(Fmt.ago(d))." }
        else { breach = a.checkedBreaches ? " Monitored for breaches daily." : "" }
        return (n == 0 ? "All \(a.loginCount) logins look healthy." : "\(n) of \(a.loginCount) logins need attention.") + breach
    }

    private func section(_ issue: VaultAudit.Issue, _ ids: [UUID], _ audit: VaultAudit) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            HStack {
                Label(issue.title, systemImage: issue.symbol).font(.headline).foregroundStyle(issue == .breached ? Palette.coral : .primary)
                Spacer()
                Badge(text: "\(ids.count)", tint: issue.weight >= 0.7 ? .orange : .secondary)
            }
            Text(issue.advice).font(.callout).foregroundStyle(.secondary)
            VStack(spacing: 0) {
                ForEach(Array(ids.compactMap { id in model.items.first { $0.id == id } }.enumerated()), id: \.element.id) { i, item in
                    if i > 0 { Divider() }
                    HStack {
                        ItemRow(item: item)
                        if issue == .breached, let c = audit.breachCounts[item.id], c > 0 {
                            Text("seen \(c.formatted()) times").font(.caption).foregroundStyle(Palette.coral)
                        }
                        switch issue {
                        case .no2FA, .passkey:
                            Button("Open") { model.tab = .vault; model.selection = item.id; model.editing = nil }.controlSize(.small)
                        default:
                            Button { model.regenerate(item) } label: { Label("Generate a New Password", systemImage: "wand.and.stars") }
                                .controlSize(.small).help("Opens the editor with a new generated password. The old one is kept in the item's history.")
                        }
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .card()
    }
}

/// Live, debounced breach status for a password being typed or generated.
struct BreachBadge: View {
    let password: String
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var state: PasswordsModel.LiveBreach = .off

    var body: some View {
        Group {
            switch state {
            case .off: EmptyView()
            case .checking: Label("Checking known breaches…", systemImage: "hourglass").foregroundStyle(.secondary)
            case .found(let n): Label(BreachMonitor.describe(count: n), systemImage: "exclamationmark.octagon.fill").foregroundStyle(Palette.coral)
            case .clean: Label(BreachMonitor.describe(count: 0), systemImage: "checkmark.shield.fill").foregroundStyle(.green)
            case .failed: Label("Couldn't check breaches right now", systemImage: "wifi.exclamationmark").foregroundStyle(.secondary)
            }
        }
        .font(.caption)
        .help("Only the first 5 characters of a scrambled fingerprint leave your Mac. Your password is never sent.")
        .task(id: password) {
            guard model.meta.settings.breachCheckEnabled, !password.isEmpty else { state = .off; return }
            try? await Task.sleep(for: .milliseconds(700))
            guard !Task.isCancelled else { return }
            state = .checking
            let r = await model.liveBreach(password)
            if !Task.isCancelled { state = r }
        }
    }
}
