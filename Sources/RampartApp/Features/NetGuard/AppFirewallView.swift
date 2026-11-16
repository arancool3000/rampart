import SwiftUI
import RampartShared
import RampartNetwork

/// "App Firewall": live per-app connections, first-connection prompts for unknown untrusted apps, block by destination.
struct AppFirewallView: View {
    @StateVar private var model = NetGuardModel.shared
    @StateVar private var expanded: Set<String> = []
    @StateVar private var confirmBlock: AppTraffic?

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                limitsCard
                if !model.prompts.isEmpty { promptsCard }
                if let e = model.error { Label(SafeText.line(e, max: 300), systemImage: "exclamationmark.triangle").foregroundStyle(.secondary) }
                if model.unsupported { Text("This RamPart service is older than the App Firewall. Update RamPart to use it.").foregroundStyle(.secondary) }
                if let st = model.status { appsCard(st.firewall); rulesCard(st.firewall) }
                else if !model.unsupported && model.error == nil { ProgressView("Reading connections…") }
            }
            .contentColumn()
        }
        .navigationTitle("App Firewall")
        .onAppear { model.startPolling() }
        .onDisappear { model.stopPolling() }
        .sheet(item: $confirmBlock) { app in BlockSheet(app: app, model: model) { confirmBlock = nil } }
    }

    private var header: some View {
        HStack(spacing: Spacing.l) {
            IconBadge(symbol: "flame", tint: Palette.coral, size: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text("App Firewall").font(.title2.weight(.semibold)).fontDesign(.monospaced)
                Text("Which apps are talking to the internet, who signed them, and where they connect.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
        }
    }

    private var limitsCard: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label("How blocking works", systemImage: "info.circle").font(.headline)
            Text(AppFirewallStatus.limitation)
            Text("RamPart adds firewall (pf) rules for the addresses an app uses and blocks the names it looked up in RamPart's DNS filter. Open connections are cut. Addresses shared with other apps and local-network addresses are left alone, and RamPart says which.")
                .foregroundStyle(.secondary)
            Text(AppFirewallStatus.countryNote).foregroundStyle(.secondary)
            if let st = model.status, !st.firewall.enforcing {
                Label(st.firewall.note ?? "Preview mode: needs the RamPart system service to load firewall rules.", systemImage: "eye")
                    .foregroundStyle(Palette.amber)
            }
        }
        .font(.callout)
        .card(tint: .rampartTeal)
    }

    private var promptsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("New apps on the internet")
            ForEach(model.prompts) { p in
                HStack(alignment: .top, spacing: Spacing.m) {
                    Image(systemName: "questionmark.app.dashed").font(.title2).foregroundStyle(Palette.amber)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(SafeText.line(p.name, max: 80)).font(.headline)
                        Text("\(p.signerLabel) · first connection to \(SafeText.line(p.host ?? p.address, max: 80)):\(p.port)")
                            .font(.callout).foregroundStyle(.secondary)
                        if let path = p.path { Text(SafeText.line(path, max: 200)).font(.caption.monospaced()).foregroundStyle(.tertiary) }
                    }
                    Spacer()
                    Button("Allow") { Task { await model.decide(p.key, .allow) } }
                    Button("Block") { Task { await model.decide(p.key, .block) } }.tint(Palette.coral)
                    Button("Ask later") { Task { await model.decide(p.key, .askLater) } }
                }
            }
        }
        .card(tint: Palette.amber)
    }

    private func appsCard(_ fw: AppFirewallStatus) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("Apps with open connections (\(fw.apps.count))")
            if fw.apps.isEmpty { Text("No app has an open internet connection right now.").foregroundStyle(.secondary) }
            ForEach(fw.apps) { app in
                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: Spacing.m) {
                        Button { toggle(app.key) } label: {
                            Image(systemName: expanded.contains(app.key) ? "chevron.down" : "chevron.right").frame(width: 14)
                        }.buttonStyle(.plain)
                        VStack(alignment: .leading, spacing: 1) {
                            HStack(spacing: 6) {
                                Text(SafeText.line(app.name, max: 60)).font(.body.weight(.medium))
                                if app.untrusted { Badge(text: "Untrusted", tint: Palette.amber) }
                                if app.decision == .block { Badge(text: "Blocked", tint: Palette.coral) }
                                if app.decision == .allow { Badge(text: "Allowed", tint: .green) }
                            }
                            Text("\(app.signerLabel) · \(app.endpoints.count) connection\(app.endpoints.count == 1 ? "" : "s") · ↓ \(Fmt.bytes(app.bytesIn)) ↑ \(Fmt.bytes(app.bytesOut))")
                                .font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        if app.decision == .block {
                            Button("Unblock") { Task { await model.decide(app.key, .allow) } }
                        } else if AppFirewall.protectedKey(app.key) == nil {
                            Button("Block internet…") { confirmBlock = app; Task { await model.plan(app.key) } }
                        }
                    }
                    if expanded.contains(app.key) {
                        ForEach(app.endpoints, id: \.self) { ep in
                            HStack {
                                Text(ep.proto.uppercased()).font(.caption.monospaced()).frame(width: 34, alignment: .leading)
                                Text(SafeText.line(ep.host ?? ep.remoteAddress, max: 80)).font(.caption)
                                if ep.host != nil { Text(ep.remoteAddress).font(.caption.monospaced()).foregroundStyle(.tertiary) }
                                Spacer()
                                Text("port \(ep.remotePort)").font(.caption.monospaced()).foregroundStyle(.secondary)
                                if let s = ep.state { Text(s).font(.caption2).foregroundStyle(.tertiary) }
                            }
                            .padding(.leading, 26)
                        }
                    }
                }
                .padding(.vertical, 4)
                Divider()
            }
        }
        .card()
    }

    private func rulesCard(_ fw: AppFirewallStatus) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("Your decisions")
            if fw.rules.isEmpty { Text("No app has been allowed or blocked yet.").foregroundStyle(.secondary) }
            ForEach(fw.rules, id: \.key) { r in
                VStack(alignment: .leading, spacing: 2) {
                    HStack {
                        Text(SafeText.line(r.name, max: 60)).font(.body.weight(.medium))
                        Text(r.decision == .askLater ? "Ask later\(r.until.map { " (after \(Fmt.dayTime($0)))" } ?? "")" : r.decision.rawValue.capitalized)
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        Button("Remove rule") { Task { await model.forget(r.key) } }.buttonStyle(.link)
                    }
                    if r.decision == .block {
                        Text("Blocking \(r.blockedAddresses.count) address\(r.blockedAddresses.count == 1 ? "" : "es") and \(r.blockedDomains.count) name\(r.blockedDomains.count == 1 ? "" : "s")")
                            .font(.caption).foregroundStyle(.secondary)
                        ForEach(r.notes.prefix(6), id: \.self) { Text($0).font(.caption2).foregroundStyle(.tertiary) }
                    }
                }
                Divider()
            }
            if !fw.lastCommands.isEmpty {
                DisclosureGroup("Firewall commands") {
                    ForEach(fw.lastCommands, id: \.self) { Text($0).font(.caption.monospaced()).textSelection(.enabled) }
                }.font(.callout)
            }
        }
        .card()
    }

    private func toggle(_ k: String) { if expanded.contains(k) { expanded.remove(k) } else { expanded.insert(k) } }
}

/// Confirmation with the exact plan (what will and won't be blocked). In-app sheet, never a system dialog.
private struct BlockSheet: View {
    let app: AppTraffic
    let model: NetGuardModel
    let done: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Block \(SafeText.line(app.name, max: 60))'s internet?").font(.title3.weight(.semibold))
            Text(AppFirewallStatus.limitation).font(.callout).foregroundStyle(.secondary)
            if let p = model.lastPlan, p.key == app.key {
                Text("Blocks \(p.addresses.count) address\(p.addresses.count == 1 ? "" : "es") and \(p.domains.count) name\(p.domains.count == 1 ? "" : "s"); cuts \(p.killCommands.count) open connection\(p.killCommands.count == 1 ? "" : "s").")
                if !p.sharedAddresses.isEmpty || !p.sharedDomains.isEmpty {
                    Text("Not blocked because other apps use them too: \((p.sharedDomains + p.sharedAddresses).prefix(8).joined(separator: ", "))")
                        .font(.callout).foregroundStyle(Palette.amber)
                }
                if !p.localAddresses.isEmpty { Text("Local-network addresses are never blocked.").font(.callout).foregroundStyle(.secondary) }
            } else { ProgressView().controlSize(.small) }
            HStack {
                Spacer()
                Button("Cancel", role: .cancel) { done() }
                Button("Block") { Task { await model.decide(app.key, .block); done() } }.primaryActionStyle()
            }
        }
        .padding(Spacing.xl)
        .frame(width: 460)
    }
}
