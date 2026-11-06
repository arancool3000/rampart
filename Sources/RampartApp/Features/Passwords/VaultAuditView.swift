import SwiftUI
import RampartVault

struct VaultAuditView: View {
    @Bindable private var model = PasswordsModel.shared

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            let audit = model.audit ?? VaultAudit.run(items: model.items)
            HStack(spacing: Spacing.xl) {
                ScoreRing(score: audit.score, size: 96, lineWidth: 10)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Vault health").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text(summary(audit)).foregroundStyle(.secondary)
                    HStack {
                        Button {
                            Task { await model.runAudit(checkBreaches: true) }
                        } label: {
                            HStack { if model.auditRunning { ProgressView().controlSize(.small) }; Text(model.meta.settings.breachCheckEnabled ? "Check for Breaches" : "Run Audit") }
                        }
                        .buttonStyle(GlowButtonStyle()).disabled(model.auditRunning)
                        if !model.meta.settings.breachCheckEnabled {
                            Toggle("Check against known breaches", isOn: Binding(get: { model.meta.settings.breachCheckEnabled },
                                                                                set: { v in model.updateSettings { $0.breachCheckEnabled = v } }))
                                .toggleStyle(.switch).controlSize(.small)
                        }
                    }
                    if let n = model.auditNote { Text(n).font(.caption).foregroundStyle(.orange) }
                }
                Spacer()
            }
            .card(padding: Spacing.xl)

            ForEach(VaultAudit.Issue.allCases) { issue in
                let ids = audit.items(issue)
                if !ids.isEmpty { section(issue, ids, audit) }
            }
            if audit.loginCount > 0 && VaultAudit.Issue.allCases.allSatisfy({ audit.items($0).isEmpty }) {
                StatusLabel(text: "No problems found in \(audit.loginCount) logins.", symbol: "checkmark.seal.fill", tint: .green).card()
            }
            Text("The breach check is opt-in. It uses Have I Been Pwned's k-anonymity range API: only the first 5 characters of each password's SHA-1 hash leave this Mac, never the password or the full hash. Two-factor suggestions use a built-in list of sites known to support it.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    private func summary(_ a: VaultAudit) -> String {
        if a.loginCount == 0 { return "Add logins to see how healthy your passwords are." }
        let n = Set(a.findings.values.flatMap { $0 }).count
        let breach = a.checkedBreaches ? " Checked against known breaches." : ""
        return n == 0 ? "All \(a.loginCount) logins look healthy.\(breach)" : "\(n) of \(a.loginCount) logins need attention.\(breach)"
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
                        if let c = audit.breachCounts[item.id], c > 0, issue == .breached {
                            Text("seen \(c.formatted()) times").font(.caption).foregroundStyle(Palette.coral)
                        }
                        Button("Fix") { model.tab = .vault; model.selection = item.id; model.editing = item }.controlSize(.small)
                    }
                    .padding(.vertical, 4)
                }
            }
        }
        .card()
    }
}
