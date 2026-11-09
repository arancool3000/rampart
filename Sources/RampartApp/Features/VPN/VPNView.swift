import SwiftUI
import AppKit
import UniformTypeIdentifiers
import RampartShared
import RampartVPN

/// RamPart VPN: a WireGuard tunnel to a server the user runs at home (iMac, Raspberry Pi).
struct VPNView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var vpn = VPNModel.shared
    @StateVar private var setupTab = 0
    @StateVar private var host = "imac.local"
    @StateVar private var port = "51820"
    @StateVar private var pasted = ""
    @StateVar private var kitTab = 0
    @StateVar private var confirmRemove = false

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                hero
                if vpn.unsupported { unsupportedCard }
                if let e = vpn.error ?? vpn.status?.error { errorCard(e) }
                if !vpn.warnings.isEmpty { warningsCard }
                honestCard
                if vpn.status?.profile != nil { optionsCard }
                if let k = vpn.kit { kitCard(k) }
                setupCard
                if let p = vpn.status?.profile { profileCard(p) }
                limitsCard
            }
            .contentColumn()
        }
        .navigationTitle("VPN")
        .task {
            while !Task.isCancelled {
                await vpn.refresh(model.client)
                try? await Task.sleep(nanoseconds: 2_000_000_000)
            }
        }
    }

    // MARK: Hero

    private var phase: VPNPhase { vpn.status?.phase ?? .notConfigured }
    private var tint: Color {
        switch phase {
        case .connected: return .statusProtected
        case .connecting, .reconnecting, .suspendedForLockdown: return .statusAttention
        case .failed: return .statusAction
        default: return .statusInfo
        }
    }

    private var hero: some View {
        HStack(alignment: .top, spacing: Spacing.xl) {
            ShieldHero(symbol: phase == .connected ? "lock.shield" : "network.badge.shield.half.filled", tint: tint, breathe: phase == .connected, size: 100)
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("RamPart VPN").font(.title2.weight(.semibold)).fontDesign(.rounded)
                StatusLabel(text: phase.label, symbol: phase == .connected ? "checkmark.circle.fill" : phase == .failed ? "xmark.octagon.fill" : "circle.dashed", tint: tint)
                    .font(.headline)
                if let s = vpn.status, let p = s.profile {
                    Text("Server: \(p.endpointHost):\(String(p.endpointPort))\(s.endpointIP.map { $0 == p.endpointHost ? "" : " (\($0))" } ?? "")")
                        .foregroundStyle(.secondary).textSelection(.enabled)
                    if phase.isActive { statsRow(s) }
                    if let d = s.dnsMode, phase.isActive { Text("DNS: \(d)").font(.callout).foregroundStyle(.secondary) }
                } else {
                    Text("Set up your home server or import a WireGuard configuration below.").foregroundStyle(.secondary)
                }
                HStack(spacing: Spacing.m) {
                    if phase.isActive {
                        Button { Task { await vpn.disconnect(model.client) } } label: { Label("Disconnect", systemImage: "stop.circle") }
                            .secondaryActionStyle()
                    } else {
                        Button { Task { await vpn.connect(model.client) } } label: { Label("Connect", systemImage: "play.circle.fill") }
                            .primaryActionStyle()
                            .disabled(vpn.status?.profile == nil || vpn.busy)
                    }
                    if vpn.busy { ProgressView().controlSize(.small) }
                }
            }
            Spacer()
        }
        .card(padding: Spacing.xl, tint: tint)
    }

    private func statsRow(_ s: VPNStatus) -> some View {
        let age = s.handshakeAge().map { $0 < 5 ? "just now" : "\(Fmt.duration($0)) ago" } ?? "not yet"
        return VStack(alignment: .leading, spacing: 2) {
            Text("Last handshake: \(age)")
            Text("Sent \(Fmt.bytes(s.stats.txBytes)) · Received \(Fmt.bytes(s.stats.rxBytes))")
            if let since = s.connectedSince { Text("Connected \(Fmt.ago(since))") }
            if let i = s.interface { Text("Interface \(i)").font(.caption) }
        }
        .font(.callout.monospacedDigit()).foregroundStyle(.secondary)
    }

    private var unsupportedCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            StatusLabel(text: "The background service needs an update", symbol: "clock", tint: .statusInfo).font(.headline)
            Text("This version of \(Product.name)'s background service doesn't include the VPN yet. Update \(Product.name) and the VPN appears here.")
                .foregroundStyle(.secondary)
        }.card()
    }

    private func errorCard(_ e: String) -> some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            StatusLabel(text: phase == .reconnecting ? "The VPN dropped" : "Something went wrong", symbol: "exclamationmark.triangle.fill", tint: .statusAction).font(.headline)
            Text(SafeText.line(e, max: 500)).textSelection(.enabled)
        }.card(tint: .statusAction)
    }

    private var warningsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            StatusLabel(text: "Imported with notes", symbol: "info.circle", tint: .statusInfo).font(.headline)
            ForEach(vpn.warnings, id: \.self) { Text("• " + SafeText.line($0, max: 200)).foregroundStyle(.secondary) }
        }.card()
    }

    private var honestCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            Text("Your traffic goes through your own home server; \(Product.name) doesn't run VPN servers.")
                .font(.headline)
            Text("On public Wi-Fi, everything this Mac sends is encrypted (WireGuard) and comes out of your home internet connection, so the café or hotel network can't read or change it. Websites see your home's address.")
                .foregroundStyle(.secondary)
            if let s = vpn.status, !s.canRouteTraffic {
                Label("Test mode: \(Product.name)'s system service isn't installed, so Connect only checks the handshake with your server and doesn't route traffic.", systemImage: "testtube.2")
                    .font(.callout).foregroundStyle(.secondary)
            }
            ForEach(vpn.status?.notes ?? [], id: \.self) { Text(SafeText.line($0, max: 300)).font(.callout).foregroundStyle(.secondary) }
        }.card()
    }

    // MARK: Options

    private var optionsCard: some View {
        let opts = vpn.status?.options ?? VPNOptions()
        return VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Options")
            Toggle(isOn: Binding(get: { opts.autoConnect }, set: { v in Task { await vpn.setOptions(model.client, autoConnect: v) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Auto-connect on public or untrusted Wi-Fi")
                    Text("Uses the Wi-Fi guard: connects when you join a network you haven't marked as trusted (after any sign-in page). Turn the VPN off on a network and it stays off there.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }.toggleStyle(.switch)
            if PublicWiFiHost.shared.currentNetworkKey != nil {
                Toggle("Trust the current Wi-Fi network (no auto-connect here)", isOn: Binding(get: { PublicWiFiHost.shared.currentIsTrusted },
                                                                                             set: { PublicWiFiHost.shared.setCurrentTrusted($0) }))
                    .toggleStyle(.checkbox).font(.callout)
            }
            Toggle(isOn: Binding(get: { opts.killSwitch }, set: { v in Task { await vpn.setOptions(model.client, killSwitch: v) } })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Kill switch: block traffic if the VPN drops")
                    Text("While the VPN is on, only the encrypted connection to your server may leave this Mac. Sign-in pages of hotel or café Wi-Fi can't load while it blocks; turn the VPN off to sign in.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }.toggleStyle(.switch)
            if vpn.status?.killSwitchEngaged == true { StatusLabel(text: "Kill switch is active", symbol: "lock.fill", tint: .statusProtected).font(.callout) }
        }.card()
    }

    // MARK: Setup

    private var setupCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Server setup")
            Picker("", selection: $setupTab) {
                Text("Set up my home server").tag(0)
                Text("Import a configuration").tag(1)
            }.pickerStyle(.segmented).labelsHidden()
            if setupTab == 0 {
                Text("\(Product.name) makes new keys for this Mac and for your server, and writes the server's configuration plus the exact commands to install WireGuard on a Raspberry Pi or on a Mac with Homebrew. You run them on the server; \(Product.name) never does.")
                    .foregroundStyle(.secondary)
                HStack {
                    TextField("Server address (e.g. myhome.duckdns.org)", text: $host).textFieldStyle(.roundedBorder)
                    TextField("Port", text: $port).textFieldStyle(.roundedBorder).frame(width: 80)
                }
                if host.hasSuffix(".local") {
                    Label("\(host) only works on your home network. For public Wi-Fi use your home's public address or a dynamic DNS name.", systemImage: "info.circle")
                        .font(.caption).foregroundStyle(.secondary)
                }
                Button {
                    Task { await vpn.setupHome(model.client, host: host, port: UInt16(port) ?? HomeServerSetup.defaultPort) }
                } label: { Label(vpn.status?.profile == nil ? "Create keys and server config" : "Replace with new keys and server config", systemImage: "key.fill") }
                    .primaryActionStyle().disabled(host.isEmpty || vpn.busy)
            } else {
                Text("Paste a wg-quick configuration (the text of a WireGuard QR code works too), or choose a .conf file or a QR code image. This Mac's private key goes to the Keychain; PostUp-style commands in the file are never run.")
                    .foregroundStyle(.secondary)
                TextEditor(text: $pasted).font(.system(.callout, design: .monospaced)).frame(minHeight: 140)
                    .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.secondary.opacity(0.3)))
                HStack {
                    Button("Import") { let t = pasted; Task { await vpn.importText(model.client, t, name: nil); if vpn.error == nil { pasted = "" } } }
                        .primaryActionStyle().disabled(pasted.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty || vpn.busy)
                    Button("Choose File or QR Image…") { chooseFile() }.secondaryActionStyle()
                }
            }
        }.card()
    }

    private func chooseFile() {
        let panel = NSOpenPanel()
        panel.allowsMultipleSelection = false; panel.canChooseDirectories = false
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .plainText, .plainText, .image]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        switch VPNModel.readConfig(from: url) {
        case .success(let t): Task { await vpn.importText(model.client, t, name: url.deletingPathExtension().lastPathComponent) }
        case .failure(let m): vpn.error = m
        }
    }

    private func kitCard(_ k: HomeServerKit) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Your home server")
            ForEach(k.notes, id: \.self) { Text("• " + $0).foregroundStyle(.secondary) }
            Picker("", selection: $kitTab) {
                Text("Raspberry Pi").tag(0)
                Text("Mac (Homebrew)").tag(1)
            }.pickerStyle(.segmented).labelsHidden()
            let config = kitTab == 0 ? k.raspberryPiConfig : k.macConfig
            let commands = kitTab == 0 ? k.raspberryPiCommands : k.macCommands
            Text("1. Install WireGuard").font(.headline)
            codeBlock(commands)
            Text("2. Server configuration (wg0.conf)").font(.headline)
            codeBlock(config)
            Button("Save Server Configuration…") { save(config) }.secondaryActionStyle()
            Text("3. Your router").font(.headline)
            ForEach(k.routerSteps, id: \.self) { Text("• " + $0).foregroundStyle(.secondary) }
            Text("Then press Connect. When the server shows a \"latest handshake\" in `wg show`, it's working.").foregroundStyle(.secondary)
        }.card(tint: .statusInfo)
    }

    private func codeBlock(_ s: String) -> some View {
        ScrollView(.horizontal) {
            Text(s).font(.system(.caption, design: .monospaced)).textSelection(.enabled).fixedSize().padding(Spacing.s)
        }
        .background(Color.secondary.opacity(0.1), in: RoundedRectangle(cornerRadius: 6))
    }

    private func save(_ text: String) {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "wg0.conf"
        guard panel.runModal() == .OK, let url = panel.url else { return }
        do {
            try Data(text.utf8).write(to: url, options: .atomic)
            _ = chmod(url.path, 0o600)
        } catch { vpn.error = "Couldn't save: \(error.localizedDescription)" }
    }

    private func profileCard(_ p: VPNProfile) -> some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            SectionHeader("Configuration")
            Text(p.name).font(.headline)
            Group {
                Text("This Mac's address: \(p.addresses.joined(separator: ", "))")
                Text("Sends through the tunnel: \(p.allowedIPs.joined(separator: ", "))")
                Text("This Mac's public key: \(p.publicKey)").textSelection(.enabled)
                Text("Private key: in the \(vpn.status?.keyStore ?? "Keychain")")
            }.font(.callout).foregroundStyle(.secondary)
            Button("Remove Configuration…", role: .destructive) { confirmRemove = true }
                .secondaryActionStyle().padding(.top, Spacing.s)
                .confirmationDialog("Remove the VPN configuration and its keys?", isPresented: $confirmRemove) {
                    Button("Remove", role: .destructive) { Task { await vpn.remove(model.client) } }
                }
        }.card()
    }

    private var limitsCard: some View {
        VStack(alignment: .leading, spacing: Spacing.xs) {
            SectionHeader("Good to know")
            Group {
                Text("• \(Product.name) has no NetworkExtension permission from Apple, so its system service creates the tunnel itself (a utun interface with routes). macOS's VPN settings won't list it.")
                Text("• The VPN is only as available as your home server and home internet. If either is down, you'll see \"Reconnecting\".")
                Text("• Emergency Lockdown pauses the VPN while it blocks the network; the Super Kill Switch turns it off.")
                Text("• With Web Protection on, its DNS filter keeps working and sends its lookups through the tunnel.")
            }.font(.callout).foregroundStyle(.secondary)
        }.card()
    }
}
