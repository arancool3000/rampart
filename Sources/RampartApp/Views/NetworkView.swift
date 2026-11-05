import SwiftUI
import AppKit
import CryptoKit

struct NetworkView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var onlyBlocked = false
    @StateVar private var filter = ""
    @AppStorage("network.blockTrackers") private var blockTrackers = false
    @AppStorage("network.firewallMode") private var firewallMode = "silent"

    private var filteredConnections: [AppConnections] {
        model.connections.compactMap { c in
            var c = c
            c.destinations = c.destinations.filter { (!onlyBlocked || $0.blocked) && (filter.isEmpty || $0.host.localizedCaseInsensitiveContains(filter) || c.app.localizedCaseInsensitiveContains(filter)) }
            return c.destinations.isEmpty ? nil : c
        }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                wifiCard
                webProtection
                connections
                BreachCheckCard()
            }
            .contentColumn()
        }
        .navigationTitle("Network")
    }

    @ViewBuilder private var wifiCard: some View {
        HStack(spacing: Spacing.m) {
            if let w = model.wifi {
                Image(systemName: w.encrypted && !w.gatewayChanged ? "wifi" : "wifi.exclamationmark")
                    .font(.title).foregroundStyle(w.encrypted && !w.gatewayChanged ? Color.statusProtected : Color.statusAttention)
                VStack(alignment: .leading, spacing: 2) {
                    (Text("Connected to ") + Text(w.ssid).bold() + Text(" · \(w.security)"))
                    if !w.encrypted {
                        Text("This network doesn't use encryption. Avoid entering passwords until you're on a trusted network.").foregroundStyle(.secondary)
                    } else if w.gatewayChanged {
                        Text("The router's hardware address changed. If you didn't replace your router, use a trusted network.").foregroundStyle(.secondary)
                    } else {
                        Text("No issues found").foregroundStyle(.secondary)
                    }
                }
            } else {
                Image(systemName: "wifi").font(.title).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Wi-Fi checks")
                    Text("Wi-Fi details will appear when the background service reports them.").foregroundStyle(.secondary)
                }
            }
            Spacer()
        }
        .card()
        .accessibilityElement(children: .combine)
    }

    private var webProtection: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Web protection")
            VStack(alignment: .leading, spacing: Spacing.m) {
                HStack(spacing: Spacing.m) {
                    Image(systemName: "globe").font(.title2).foregroundStyle(model.status.webProtectionOn ? Color.rampartTeal : .secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Block known malicious and phishing sites").font(.body.weight(.medium))
                        Text("Checks every website and app connection against threat lists. Your browsing isn't recorded.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Web protection", isOn: Binding(get: { model.status.webProtectionOn },
                                                           set: { v in Task { await model.setWebProtection(v) } }))
                        .toggleStyle(.switch).labelsHidden()
                }
                Divider()
                HStack(spacing: Spacing.m) {
                    Image(systemName: "eye.slash").font(.title2).foregroundStyle(.secondary)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Block trackers").font(.body.weight(.medium))
                        Text("Privacy, not security. Some sites may not work as expected.").font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Block trackers", isOn: $blockTrackers).toggleStyle(.switch).labelsHidden()
                }
                Divider()
                HStack(spacing: Spacing.xxl) {
                    Stat(value: model.blockedThisMonth, label: "dangerous sites blocked this month")
                    Stat(value: model.blockedToday, label: "blocked today")
                    Spacer()
                    Picker("Firewall mode", selection: $firewallMode) {
                        Text("Silent (recommended)").tag("silent")
                        Text("Ask me for new apps").tag("ask")
                        Text("Block all new apps").tag("block")
                    }
                    .fixedSize()
                }
            }
            .card()
        }
    }

    private var connections: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Connections", trailing: AnyView(HStack {
                TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).frame(width: 160)
                Toggle("Only show blocked", isOn: $onlyBlocked).toggleStyle(.checkbox)
            }))
            VStack(spacing: 0) {
                if filteredConnections.isEmpty {
                    Text(model.connections.isEmpty ? "Connection details will appear when the background service reports them." : "No matching connections.")
                        .foregroundStyle(.secondary).padding(Spacing.m).frame(maxWidth: .infinity, alignment: .leading)
                }
                ForEach(Array(filteredConnections.enumerated()), id: \.element.id) { i, c in
                    if i > 0 { Divider() }
                    ConnectionGroup(conn: c)
                }
            }
            .card(padding: Spacing.s)
        }
    }
}

struct Stat: View {
    let value: Int
    let label: String
    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("\(value)").font(.title.weight(.semibold)).monospacedDigit().contentTransition(.numericText())
            Text(label).font(.callout).foregroundStyle(.secondary)
        }
        .accessibilityElement(children: .combine)
    }
}

struct ConnectionGroup: View {
    let conn: AppConnections
    @StateVar private var expanded = false
    var body: some View {
        DisclosureGroup(isExpanded: $expanded) {
            VStack(spacing: 4) {
                ForEach(conn.destinations) { d in
                    HStack(spacing: Spacing.m) {
                        Image(systemName: d.blocked ? "hand.raised.fill" : "arrow.up.right.circle")
                            .foregroundStyle(d.blocked ? Color.orange : .secondary).frame(width: 20)
                        Text(d.host).font(.callout.monospaced()).textSelection(.enabled)
                        Spacer()
                        Text("\(d.proto) \(d.port)").font(.callout).foregroundStyle(.secondary).monospacedDigit()
                        Text(d.country).font(.callout).foregroundStyle(.secondary).frame(width: 30)
                        Text(d.blocked ? "Blocked" : "Allowed").font(.callout).frame(width: 60, alignment: .trailing)
                    }
                    .padding(.leading, 36)
                    .accessibilityElement(children: .combine)
                }
            }
            .padding(.vertical, 4)
        } label: {
            HStack(spacing: Spacing.m) {
                Group {
                    if let p = conn.bundlePath, FileManager.default.fileExists(atPath: p) {
                        Image(nsImage: NSWorkspace.shared.icon(forFile: p)).resizable()
                    } else {
                        Image(systemName: "app.dashed").resizable().scaledToFit().foregroundStyle(.secondary)
                    }
                }
                .frame(width: 24, height: 24)
                Text(conn.app).font(.body.weight(.medium))
                Text("\(conn.destinations.count) connection\(conn.destinations.count == 1 ? "" : "s")").foregroundStyle(.secondary)
                Spacer()
                Text("↑ \(Fmt.bytes(UInt64(conn.sentKB) * 1024))  ↓ \(Fmt.bytes(UInt64(conn.receivedKB) * 1024))")
                    .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                if conn.blockedCount > 0 {
                    Label("\(conn.blockedCount) blocked", systemImage: "hand.raised.fill").font(.callout)
                        .labelStyle(.titleAndIcon).foregroundStyle(.primary)
                }
            }
            .contentShape(Rectangle())
            .onTapGesture { withAnimation { expanded.toggle() } }
        }
        .padding(Spacing.s)
    }
}

/// Opt-in password breach check using the Have I Been Pwned k-anonymity range API:
/// only the first 5 hex characters of the SHA-1 leave this Mac. The password is never stored.
struct BreachCheckCard: View {
    enum Result: Equatable { case none, checking, safe, found(Int), error(String) }
    @StateVar private var password = ""
    @StateVar private var result: Result = .none

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Password breach check")
            VStack(alignment: .leading, spacing: Spacing.m) {
                Text("Check whether a password has appeared in a known data breach. Only the first 5 characters of its fingerprint are sent; the password never leaves your Mac.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                HStack {
                    SecureField("Password to check", text: $password).textFieldStyle(.roundedBorder).frame(maxWidth: 320)
                        .onSubmit { check() }
                    Button("Check") { check() }.disabled(password.isEmpty || result == .checking)
                    if result == .checking { ProgressView().controlSize(.small) }
                }
                switch result {
                case .safe:
                    StatusLabel(text: "Not found in known breaches.", symbol: "checkmark.circle.fill", tint: .statusProtected)
                case .found(let n):
                    StatusLabel(text: "Seen \(Fmt.count(n)) times in breaches. Change it wherever you use it — the Passwords app can help.",
                                symbol: "exclamationmark.circle.fill", tint: .statusAttention)
                case .error(let m):
                    StatusLabel(text: m, symbol: "wifi.slash", tint: .secondary)
                default: EmptyView()
                }
            }
            .card()
        }
    }

    private func check() {
        guard !password.isEmpty else { return }
        let digest = Insecure.SHA1.hash(data: Data(password.utf8)).map { String(format: "%02X", $0) }.joined()
        password = ""
        let prefix = String(digest.prefix(5)), suffix = String(digest.dropFirst(5))
        result = .checking
        Task {
            do {
                var req = URLRequest(url: URL(string: "https://api.pwnedpasswords.com/range/\(prefix)")!)
                req.setValue("true", forHTTPHeaderField: "Add-Padding")
                req.setValue("Rampart-macOS", forHTTPHeaderField: "User-Agent")
                req.timeoutInterval = 10
                let (data, resp) = try await URLSession.shared.data(for: req)
                guard (resp as? HTTPURLResponse)?.statusCode == 200, let body = String(data: data, encoding: .utf8),
                      body.contains(":") else {
                    result = .error("Couldn't reach the breach database. Your network may be blocking it."); return
                }
                var count = 0
                for line in body.split(whereSeparator: \.isNewline) {
                    let parts = line.split(separator: ":")
                    if parts.count == 2, parts[0].uppercased() == suffix { count = Int(parts[1].trimmingCharacters(in: .whitespaces)) ?? 0; break }
                }
                result = count > 0 ? .found(count) : .safe
            } catch {
                result = .error("Couldn't reach the breach database. Check your connection and try again.")
            }
        }
    }
}
