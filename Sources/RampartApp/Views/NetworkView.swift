import SwiftUI
import AppKit
import CryptoKit
import Charts
import RampartShared

struct NetworkView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var onlyBlocked = false
    @StateVar private var filter = ""
    @StateVar private var showInstall = false

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
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
        .task {
            // Connections change quickly: refresh every 10 s while this screen is open.
            while !Task.isCancelled && model.mode == .live {
                try? await Task.sleep(nanoseconds: 10_000_000_000)
                await model.refreshConnections()
            }
        }
    }

    @ViewBuilder private var wifiCard: some View {
        HStack(spacing: Spacing.m) {
            if let w = model.wifi {
                IconBadge(symbol: w.encrypted && !w.gatewayChanged ? "wifi" : "wifi.exclamationmark",
                          tint: w.encrypted && !w.gatewayChanged ? .statusProtected : .statusAttention, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    (Text("Connected to ") + Text(w.ssid ?? "your Wi-Fi network").bold() + Text(" · \(w.security)"))
                    if !w.encrypted {
                        Text("This network doesn't use encryption. Avoid entering passwords until you're on a trusted network.").foregroundStyle(.secondary)
                    } else if w.gatewayChanged {
                        Text("The router's hardware address changed. If you didn't replace your router, use a trusted network.").foregroundStyle(.secondary)
                    } else {
                        Text(w.note ?? "No issues found").foregroundStyle(.secondary)
                    }
                }
            } else {
                Image(systemName: "wifi").font(.title).foregroundStyle(.secondary)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Wi-Fi checks")
                    Text(model.mode == .live ? "Not connected to Wi-Fi, or Wi-Fi details aren't available right now." : "Wi-Fi details will appear when the background service reports them.").foregroundStyle(.secondary)
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
                    IconBadge(symbol: "globe", tint: model.status.webProtectionOn ? .rampartTeal : .gray, size: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Block known malicious and phishing sites").font(.body.weight(.medium))
                        Text(model.webProtectionAvailable
                             ? "Checks every website and app connection against threat lists\(model.blocklistDomains > 0 ? " (\(Fmt.count(model.blocklistDomains)) known-bad domains)" : ""). Your browsing isn't recorded."
                             : "Needs the full system service, because it changes how your Mac looks up websites.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.webProtectionAvailable {
                        Toggle("Web protection", isOn: Binding(get: { model.status.webProtectionOn },
                                                               set: { v in model.updateSettings { $0.webProtection = v }; Task { await model.setWebProtection(v) } }))
                            .toggleStyle(.switch).labelsHidden()
                    } else {
                        Button("Enable Full Protection…") { showInstall = true }.buttonStyle(GlowButtonStyle())
                    }
                }
                Divider()
                HStack(spacing: Spacing.m) {
                    IconBadge(symbol: "eye.slash", tint: .gray, size: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Block trackers").font(.body.weight(.medium))
                        Text("Privacy, not security. Some sites may not work as expected.").font(.callout).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Toggle("Block trackers", isOn: model.setting(\.blockTrackers)).toggleStyle(.switch).labelsHidden()
                        .disabled(!model.webProtectionAvailable)
                }
                Divider()
                HStack(alignment: .bottom, spacing: Spacing.xxl) {
                    Stat(value: model.blockedThisMonth, label: "dangerous sites blocked this month")
                    Stat(value: model.blockedToday, label: "blocked today")
                    Spacer()
                }
                if model.daily.contains(where: { $0.sitesBlocked > 0 }) {
                    Chart(model.daily) { d in
                        BarMark(x: .value("Day", d.day, unit: .day), y: .value("Blocked", d.sitesBlocked))
                            .foregroundStyle(LinearGradient(colors: [Color.rampartTeal, Color.rampartTeal.opacity(0.5)], startPoint: .top, endPoint: .bottom))
                            .cornerRadius(3)
                    }
                    .chartXAxis { AxisMarks(values: .stride(by: .day, count: 2)) { _ in AxisValueLabel(format: .dateTime.weekday(.abbreviated)) } }
                    .chartYAxis { AxisMarks(position: .trailing, values: .automatic(desiredCount: 3)) }
                    .frame(height: 110)
                    .accessibilityLabel("Sites blocked per day over the last 14 days")
                }
                if !model.recentBlocks.isEmpty {
                    Divider()
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Recently blocked").font(.callout.weight(.medium)).foregroundStyle(.secondary)
                        ForEach(model.recentBlocks.prefix(6), id: \.self) { host in
                            HStack(spacing: Spacing.s) {
                                Image(systemName: "hand.raised.fill").foregroundStyle(.orange).font(.caption)
                                Text(host).font(.callout.monospaced()).textSelection(.enabled)
                            }
                        }
                    }
                }
            }
            .card()
        }
    }

    private var connections: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Connections", trailing: AnyView(HStack {
                TextField("Filter", text: $filter).textFieldStyle(.roundedBorder).frame(width: 160)
                Toggle("Only show flagged", isOn: $onlyBlocked).toggleStyle(.checkbox)
            }))
            VStack(spacing: 0) {
                if filteredConnections.isEmpty {
                    Text(model.connections.isEmpty
                         ? (model.mode == .live ? "No open connections right now." : "Connection details will appear when the background service reports them.")
                         : "No matching connections.")
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
            Text("\(value)").font(.largeTitle.weight(.bold)).fontDesign(.rounded).monospacedDigit().contentTransition(.numericText())
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
                        if !d.country.isEmpty { Text(d.country).font(.callout).foregroundStyle(.secondary).frame(width: 30) }
                        Text(d.statusLabel).font(.callout).frame(width: 90, alignment: .trailing)
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
                if let sig = conn.signing { SigningBadge(status: sig) }
                Text("\(conn.destinations.count) connection\(conn.destinations.count == 1 ? "" : "s")").foregroundStyle(.secondary)
                Spacer()
                if conn.sentKB + conn.receivedKB > 0 {
                    Text("↑ \(Fmt.bytes(UInt64(conn.sentKB) * 1024))  ↓ \(Fmt.bytes(UInt64(conn.receivedKB) * 1024))")
                        .font(.callout).foregroundStyle(.secondary).monospacedDigit()
                }
                if conn.blockedCount > 0 {
                    Label("\(conn.blockedCount) \(conn.destinations.first(where: \.blocked)?.flaggedOnly == true ? "flagged" : "blocked")", systemImage: "hand.raised.fill").font(.callout)
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
                req.setValue("\(Product.name)-macOS", forHTTPHeaderField: "User-Agent")
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

/// Code-signing badge used for connections and startup items.
struct SigningBadge: View {
    let status: SigningInfo.Status
    var notarized: Bool? = nil
    var body: some View {
        switch status {
        case .apple: Badge(text: "Apple", tint: .green)
        case .appStore: Badge(text: "App Store", tint: .green)
        case .developerID: Badge(text: notarized == false ? "Signed" : "Notarized", tint: .green)
        case .adHoc: Badge(text: "Ad-hoc signed", tint: .yellow)
        case .unsigned: Badge(text: "Not signed", tint: .yellow)
        case .invalid, .revoked: Badge(text: "Invalid signature", tint: .red)
        case .unknown: Badge(text: "Unknown signer")
        }
    }
}
