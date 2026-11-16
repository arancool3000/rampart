import SwiftUI
import AppKit
import RampartShared
import RampartNetwork

/// "Network Scan": radar of the home network with the router in the centre, a device list and a detail panel.
struct NetworkScanView: View {
    @StateVar private var model = NetworkScanModel()
    @StateVar private var showConsent = false

    var body: some View {
        HStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: Spacing.xl) {
                    header
                    radarCard
                    if let r = model.report {
                        networkFindings(r)
                        deviceList(r)
                        thisMac(r)
                        if !r.limitations.isEmpty { limitations(r) }
                    } else if model.state == .idle {
                        intro
                    }
                }
                .contentColumn()
            }
            if model.report != nil {
                Divider()
                detailPanel
                    .frame(width: 320)
            }
        }
        .navigationTitle("Network Scan")
        .onAppear { model.refreshCandidates() }
        .alert("Scan your home network?", isPresented: $showConsent) {
            Button("Scan") { model.startScan() }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("RamPart will send a small number of gentle probes (at most 50 per second) to the devices on \(model.eligibleSubnet?.cidr ?? "your network") and listen for Bonjour and UPnP announcements. macOS may ask for Local Network access. Nothing leaves your network.")
        }
    }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: Spacing.l) {
            VStack(alignment: .leading, spacing: 4) {
                Text("Home network").font(.title2.weight(.semibold)).fontDesign(.monospaced)
                if let r = model.report {
                    Text("\(r.subnet.cidr) via \(SafeText.line(r.subnet.interface, max: 32))\(r.wifiSecurity.map { " · \(SafeText.line($0, max: 40))" } ?? "") · scanned \(Fmt.ago(r.date))")
                        .font(.callout).foregroundStyle(.secondary)
                } else if let s = model.eligibleSubnet {
                    Text("Ready to scan \(s.cidr) on \(SafeText.line(s.interface, max: 32)). Only your directly connected network is ever scanned.").font(.callout).foregroundStyle(.secondary)
                } else if let p = model.scopeProblem {
                    Text(SafeText.line(p, max: 240)).font(.callout).foregroundStyle(.secondary)
                }
            }
            Spacer()
            if model.isScanning {
                Button("Stop") { model.cancel() }.secondaryActionStyle()
            } else {
                Button { model.refreshCandidates(); showConsent = true } label: { Label("Scan", systemImage: "dot.radiowaves.left.and.right") }
                    .buttonStyle(GlowButtonStyle()).controlSize(.large)
                    .disabled(model.eligibleSubnet == nil)
                    .keyboardShortcut("r", modifiers: .command)
            }
        }
    }

    private var intro: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("What the scan checks")
            VStack(alignment: .leading, spacing: Spacing.m) {
                introRow("wifi.router", "Your router", "Admin page served over plain HTTP, UPnP port forwarding, the DNS servers your Mac uses, and whether the router's hardware address changed.")
                introRow("rectangle.3.group", "Every device", "Who is on the network (name, maker, type), whether anything new appeared, and a short list of risky services such as Telnet, FTP, RDP, VNC and open cameras.")
                introRow("laptopcomputer", "This Mac", "Which programs accept connections from the network, whether they are signed, and whether the macOS firewall would stop them.")
                Divider()
                Text("Scans run only when you press Scan, stay inside your own network, and send at most 50 small probes per second. Nothing is sent to RamPart.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .card()
        }
    }

    private func introRow(_ symbol: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: Spacing.m) {
            IconBadge(symbol: symbol, size: 34)
            VStack(alignment: .leading, spacing: 2) {
                Text(title).font(.body.weight(.medium))
                Text(text).font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Radar

    private var radarCard: some View {
        HStack(alignment: .center, spacing: Spacing.xl) {
            NetworkRadar(devices: model.devices, selected: $model.selectedDeviceID, scanning: model.isScanning)
                .frame(width: 300, height: 300)
            VStack(alignment: .leading, spacing: Spacing.m) {
                if let r = model.report, !model.isScanning {
                    HStack(alignment: .firstTextBaseline, spacing: 6) {
                        Text("\(r.score)").font(.system(size: 56, weight: .bold, design: .monospaced)).monospacedDigit()
                            .foregroundStyle(LinearGradient(colors: Palette.gradient(for: r.score), startPoint: .top, endPoint: .bottom))
                        Text("/ 100").font(.title3).foregroundStyle(.secondary)
                    }
                    Text(NetScanScoring.label(for: r.score)).font(.title3.weight(.semibold)).fontDesign(.monospaced)
                    HStack(spacing: Spacing.xl) {
                        Stat(value: r.devices.count, label: "devices")
                        Stat(value: r.findings.filter { $0.severity >= .medium }.count, label: "to review")
                            .help("Findings of medium severity or higher, such as an open risky service or an unrecognised new device. Select a device to see what to check.")
                        Stat(value: r.newDevices.filter { !$0.trusted }.count, label: "new")
                    }
                    Text("\(r.probesSent) probes · \(Fmt.duration(r.duration))").font(.caption).foregroundStyle(.secondary)
                } else if let p = model.progress, model.isScanning {
                    Text(SafeText.line(p.message)).font(.body.weight(.medium))
                    ProgressView(value: p.fraction).progressViewStyle(.linear).tint(.rampartTeal)
                    Text("\(p.devicesSoFar) devices so far").font(.callout).foregroundStyle(.secondary)
                    Text("Gentle: at most 50 probes per second, only on your own network.").font(.caption).foregroundStyle(.secondary)
                } else if case .failed(let why) = model.state {
                    StatusLabel(text: "Couldn't scan", symbol: "exclamationmark.triangle.fill", tint: .statusAttention)
                    Text(SafeText.line(why, max: 240)).font(.callout).foregroundStyle(.secondary)
                } else {
                    Text("No scan yet").font(.body.weight(.medium))
                    Text("Press Scan to map your network. The router sits in the middle; every device found is placed around it, coloured by risk.")
                        .font(.callout).foregroundStyle(.secondary)
                }
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .card(tint: model.report.map { Palette.gradient(for: $0.score).first } ?? nil)
    }

    // MARK: Findings

    private func networkFindings(_ r: NetScanReport) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Router and network")
            VStack(alignment: .leading, spacing: 0) {
                if let router = r.router {
                    routerRow("wifi.router", "Router", "\(router.ip)\(router.vendor.map { " · \($0)" } ?? "")", ok: !router.gatewayMACChanged)
                    routerRow("lock", "Admin page", router.adminHTTPOnly ? "Plain HTTP only" : (router.httpsOpen || router.httpRedirectsToHTTPS ? "HTTPS available" : (router.httpOpen ? "HTTP" : "Not reachable on 80/443")), ok: !router.adminHTTPOnly)
                    routerRow("arrow.left.arrow.right", "UPnP port forwarding", router.upnpIGD ? "Enabled (Internet Gateway Device exposed)" : "Not advertised", ok: !router.upnpIGD)
                    routerRow("globe", "DNS servers", router.dnsVerdicts.isEmpty ? "Unknown" : router.dnsVerdicts.map { "\($0.server)\($0.name.map { " (\($0))" } ?? "")" }.joined(separator: ", "),
                              ok: !router.dnsVerdicts.contains { $0.status == .unknown })
                }
                if let w = r.wifiSecurity { routerRow("wifi", "Wi-Fi security", w, ok: !r.wifiWeak) }
                let network = model.networkFindings
                if !network.isEmpty {
                    Divider().padding(.vertical, Spacing.s)
                    ForEach(network) { f in FindingRow(finding: f) }
                } else {
                    Divider().padding(.vertical, Spacing.s)
                    StatusLabel(text: "No router or network issues found", symbol: "checkmark.circle.fill", tint: .statusProtected)
                }
            }
            .card()
        }
    }

    private func routerRow(_ symbol: String, _ title: String, _ value: String, ok: Bool) -> some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: symbol).frame(width: 22).foregroundStyle(.secondary)
            Text(title).frame(width: 150, alignment: .leading)
            Text(SafeText.line(value, max: 240)).foregroundStyle(.secondary).lineLimit(2).textSelection(.enabled)
            Spacer()
            Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.circle.fill").foregroundStyle(ok ? Color.statusProtected : Color.statusAttention)
                .accessibilityLabel(ok ? "OK" : "Needs attention")
        }
        .padding(.vertical, 5)
    }

    // MARK: Device list

    private func deviceList(_ r: NetScanReport) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Devices", trailing: AnyView(Text("\(r.devices.count)").foregroundStyle(.secondary)))
            VStack(spacing: 0) {
                ForEach(r.devices) { d in
                    DeviceRow(device: d, selected: d.id == model.selectedDeviceID)
                        .contentShape(Rectangle())
                        .onTapGesture { model.selectedDeviceID = d.id }
                    if d.id != r.devices.last?.id { Divider() }
                }
            }
            .card(padding: Spacing.s)
        }
    }

    // MARK: This Mac

    private func thisMac(_ r: NetScanReport) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("This Mac")
            VStack(alignment: .leading, spacing: Spacing.s) {
                HStack(spacing: Spacing.m) {
                    IconBadge(symbol: r.firewall.enabled == true ? "checkmark.shield" : "shield.slash", tint: r.firewall.enabled == true ? .statusProtected : .statusAttention, size: 34)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(r.firewall.enabled == true ? "macOS firewall is on\(r.firewall.stealth == true ? " with stealth mode" : "")" : (r.firewall.enabled == false ? "macOS firewall is off" : "Firewall state unknown")).font(.body.weight(.medium))
                        Text("\(r.localListeners.filter { $0.exposure == .network }.count) programs accept connections from the network, \(r.localListeners.filter { $0.exposure == .loopback }.count) only from this Mac.")
                            .font(.callout).foregroundStyle(.secondary)
                    }
                }
                let exposed = r.localListeners.filter { $0.exposure == .network }
                if !exposed.isEmpty {
                    Divider()
                    ForEach(exposed) { l in ListenerRow(listener: l) }
                }
            }
            .card()
        }
    }

    private func limitations(_ r: NetScanReport) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            ForEach(r.limitations, id: \.self) { l in
                Label(SafeText.line(l, max: 240), systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    // MARK: Detail panel

    @ViewBuilder private var detailPanel: some View {
        if let d = model.selectedDevice {
            DeviceDetail(device: d, findings: model.findings(for: d),
                         rename: { model.rename(d.id, to: $0) }, trust: { model.setTrusted(d.id, $0) })
        } else {
            VStack(spacing: Spacing.m) {
                Image(systemName: "hand.tap").font(.largeTitle).foregroundStyle(.secondary)
                Text("Select a device to see what was found and how to fix it.").multilineTextAlignment(.center).foregroundStyle(.secondary)
            }
            .padding(Spacing.xl)
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
    }
}

// MARK: - Rows

struct DeviceRow: View {
    let device: NetDevice
    let selected: Bool
    var body: some View {
        HStack(spacing: Spacing.m) {
            IconBadge(symbol: device.type.symbol, tint: device.worstSeverity >= .medium ? .statusAttention : (device.isGateway ? .rampartTeal : .gray), size: 32)
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    Text(SafeText.line(device.displayName, max: 64)).font(.body.weight(.medium)).lineLimit(1)
                    if device.isNew && !device.trusted { Badge(text: "New", tint: .statusAttention) }
                    if device.trusted && !device.isThisMac { Badge(text: "Trusted", tint: .statusProtected) }
                }
                Text(SafeText.line([device.ip, device.vendor, device.type.label].compactMap { $0 }.joined(separator: " · "))).font(.callout).foregroundStyle(.secondary).lineLimit(1)
            }
            Spacer()
            if !device.openPorts.isEmpty {
                let worst = device.worstSeverity
                Badge(text: worst >= .medium ? "\(device.openPorts.count) risk\(device.openPorts.count == 1 ? "" : "s")" : "\(device.openPorts.count) open", tint: worst >= .high ? .statusAction : (worst == .medium ? .statusAttention : .secondary))
            } else {
                Image(systemName: "checkmark.circle").foregroundStyle(Color.statusProtected).accessibilityLabel("No risky ports")
            }
        }
        .padding(.horizontal, Spacing.s).padding(.vertical, 7)
        .background(selected ? Color.rampartTeal.opacity(0.12) : .clear, in: RoundedRectangle(cornerRadius: 10, style: .continuous))
        .accessibilityElement(children: .combine)
        .accessibilityAddTraits(.isButton)
    }
}

struct FindingRow: View {
    let finding: NetFinding
    @StateVar private var expanded = false
    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: Spacing.m) {
                Image(systemName: finding.severity.symbol).foregroundStyle(finding.severity.tint).symbolRenderingMode(.hierarchical).frame(width: 22)
                VStack(alignment: .leading, spacing: 3) {
                    Text(SafeText.line(finding.title)).font(.body.weight(.medium))
                    Text(SafeText.line(finding.detail, max: 400)).font(.callout).foregroundStyle(.secondary).lineLimit(expanded ? nil : 2)
                    if expanded {
                        Label(SafeText.line(finding.fix, max: 400), systemImage: "wrench.and.screwdriver").font(.callout).padding(.top, 2)
                    }
                }
                Spacer()
                Badge(text: finding.severity.label, tint: finding.severity.tint)
            }
            Button(expanded ? "Hide fix" : "How to fix") { withAnimation(.easeOut(duration: 0.15)) { expanded.toggle() } }
                .buttonStyle(.link).font(.callout).padding(.leading, 34)
        }
        .padding(.vertical, 6)
    }
}

struct ListenerRow: View {
    let listener: LocalListener
    var body: some View {
        HStack(spacing: Spacing.m) {
            Text("\(listener.proto.uppercased()) \(listener.port)").font(.callout.monospaced()).frame(width: 90, alignment: .leading)
            VStack(alignment: .leading, spacing: 1) {
                Text(SafeText.line(listener.service ?? listener.processName, max: 64)).font(.callout.weight(.medium))
                Text("\(SafeText.line(listener.processName, max: 64)) · \(signingLabel)").font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Badge(text: firewallLabel, tint: firewallTint)
        }
        .padding(.vertical, 3)
        .accessibilityElement(children: .combine)
    }
    private var signingLabel: String {
        switch listener.signing {
        case .apple: return "Apple"
        case .developerID: return "Signed (Developer ID)"
        case .appStore: return "App Store"
        case .adHoc: return "Ad-hoc signed"
        case .unsigned: return "Unsigned"
        case .invalid, .revoked: return "Invalid signature"
        case .unknown: return "Signature unknown"
        }
    }
    private var firewallLabel: String {
        switch listener.firewall {
        case .blocked: return "Firewall blocks"
        case .allowed: return "Firewall allows"
        case .allowedBuiltIn: return "Built-in, allowed"
        case .firewallOff: return "Firewall off"
        case .unknown: return "Firewall will ask"
        }
    }
    private var firewallTint: Color {
        switch listener.firewall {
        case .blocked, .allowedBuiltIn: return .statusProtected
        case .allowed, .unknown: return .secondary
        case .firewallOff: return .statusAttention
        }
    }
}

// MARK: - Detail

struct DeviceDetail: View {
    let device: NetDevice
    let findings: [NetFinding]
    let rename: (String) -> Void
    let trust: (Bool) -> Void
    @StateVar private var name = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.l) {
                HStack(spacing: Spacing.m) {
                    IconBadge(symbol: device.type.symbol, tint: device.worstSeverity >= .medium ? .statusAttention : .rampartTeal, size: 48)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(SafeText.line(device.displayName, max: 80)).font(.title3.weight(.semibold)).fontDesign(.monospaced).lineLimit(2)
                        Text(device.type.label).foregroundStyle(.secondary)
                    }
                }
                if !device.isThisMac {
                    VStack(alignment: .leading, spacing: Spacing.s) {
                        TextField("Name this device", text: $name, onCommit: { rename(name) }).textFieldStyle(.roundedBorder)
                        Toggle("I recognise this device", isOn: Binding(get: { device.trusted }, set: { trust($0) }))
                    }
                }
                Group {
                    fact("Address", device.ip)
                    if let m = device.mac { fact("Hardware", m) }
                    if let v = device.vendor { fact("Maker", v) }
                    if let h = device.hostname { fact("Hostname", h) }
                    if let mo = device.model { fact("Model", mo) }
                    if let f = device.firstSeen { fact("First seen", Fmt.dayTime(f)) }
                    if !device.discoveredBy.isEmpty { fact("Found via", device.discoveredBy.joined(separator: ", ")) }
                }
                if !device.services.isEmpty {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Services announced").font(.callout.weight(.medium)).foregroundStyle(.secondary)
                        Text(SafeText.line(device.services.map(friendlyService).joined(separator: ", "), max: 400)).font(.callout)
                    }
                }
                Divider()
                if device.openPorts.isEmpty {
                    StatusLabel(text: device.isThisMac ? "See the “This Mac” section for its open ports." : "None of the risky services are open.", symbol: "checkmark.circle.fill", tint: .statusProtected).font(.callout)
                } else {
                    Text("Open services").font(.callout.weight(.medium)).foregroundStyle(.secondary)
                    ForEach(device.openPorts) { p in
                        VStack(alignment: .leading, spacing: 4) {
                            HStack {
                                Image(systemName: p.severity.symbol).foregroundStyle(p.severity.tint)
                                Text("\(SafeText.line(p.service, max: 48)) · \(p.proto)/\(p.port)").font(.body.weight(.medium))
                                Spacer()
                                Badge(text: p.severity.label, tint: p.severity.tint)
                            }
                            Text(SafeText.line(p.explanation, max: 400)).font(.callout).foregroundStyle(.secondary)
                            Label(SafeText.line(p.fix, max: 400), systemImage: "wrench.and.screwdriver").font(.callout)
                        }
                        .padding(Spacing.m)
                        .background(p.severity.tint.opacity(0.08), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                    }
                }
                if device.isNew && !device.trusted {
                    Label("This device wasn't on the network during the previous scan. If you don't recognise it, change the Wi-Fi password and check the router's device list.", systemImage: "sparkles")
                        .font(.callout).padding(Spacing.m)
                        .background(Color.statusAttention.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
                }
            }
            .padding(Spacing.l)
        }
        .onAppear { name = device.customName ?? "" }
        .onChange(of: device.id) { _, _ in name = device.customName ?? "" }
    }

    private func fact(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).foregroundStyle(.secondary).frame(width: 80, alignment: .leading)
            Text(SafeText.line(v, max: 240)).textSelection(.enabled)
        }
        .font(.callout)
    }

    private func friendlyService(_ s: String) -> String {
        let map = ["_airplay._tcp": "AirPlay", "_raop._tcp": "AirPlay audio", "_companion-link._tcp": "Apple Continuity", "_googlecast._tcp": "Chromecast",
                   "_http._tcp": "Web page", "_https._tcp": "Secure web page", "_ipp._tcp": "Printing", "_ipps._tcp": "Secure printing", "_printer._tcp": "Printing",
                   "_smb._tcp": "File sharing", "_afpovertcp._tcp": "File sharing (AFP)", "_ssh._tcp": "SSH", "_sftp-ssh._tcp": "SFTP", "_rfb._tcp": "Screen sharing",
                   "_hap._tcp": "HomeKit", "_homekit._tcp": "HomeKit", "_spotify-connect._tcp": "Spotify Connect", "_sonos._tcp": "Sonos", "_device-info._tcp": "Device info",
                   "_rdlink._tcp": "Apple Remote", "_sleep-proxy._udp": "Sleep proxy", "_matter._tcp": "Matter", "_hue._tcp": "Philips Hue", "_scanner._tcp": "Scanner",
                   "_adisk._tcp": "Time Machine", "_nfs._tcp": "NFS", "_mqtt._tcp": "MQTT", "_rtsp._tcp": "Video stream", "_workstation._tcp": "Workstation"]
        if let m = map[s] { return m }
        if s.hasPrefix("ssdp:") {
            // "ssdp:urn:schemas-upnp-org:device:MediaRenderer:1" → "UPnP (MediaRenderer)"
            let parts = s.dropFirst(5).split(separator: ":").map(String.init)
            let kind = parts.count >= 4 ? parts[3] : (parts.last ?? "device")
            return "UPnP (\(kind))"
        }
        return s
    }
}

// MARK: - Radar

/// Router in the centre, devices on rings by discovery order, coloured by risk. A sweep rotates only while
/// scanning, only while the window is visible, and never under Reduce Motion.
struct NetworkRadar: View {
    let devices: [NetDevice]
    @Binding var selected: String?
    let scanning: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.colorScheme) private var scheme
    @StateVar private var angle: Double = 0
    private let gate = AnimationGate.shared

    private var others: [NetDevice] { devices.filter { !$0.isGateway } }
    private var center: NetDevice? { devices.first { $0.isGateway } ?? devices.first { $0.isThisMac } }

    var body: some View {
        GeometryReader { geo in
            let size = min(geo.size.width, geo.size.height)
            let c = CGPoint(x: geo.size.width / 2, y: geo.size.height / 2)
            let maxR = size / 2 - 22
            ZStack {
                Canvas { ctx, _ in
                    for ring in 1...3 {
                        let r = maxR * CGFloat(ring) / 3
                        ctx.stroke(Path(ellipseIn: CGRect(x: c.x - r, y: c.y - r, width: 2 * r, height: 2 * r)),
                                   with: .color(Color.rampartTeal.opacity(scheme == .dark ? 0.22 : 0.3)), lineWidth: 1)
                    }
                    for i in 0..<8 {
                        let a = Double(i) * .pi / 4
                        var p = Path(); p.move(to: c); p.addLine(to: CGPoint(x: c.x + cos(a) * maxR, y: c.y + sin(a) * maxR))
                        ctx.stroke(p, with: .color(Color.rampartTeal.opacity(0.08)), lineWidth: 1)
                    }
                    if scanning && !reduceMotion && gate.live {
                        var sweep = Path(); sweep.move(to: c)
                        sweep.addArc(center: c, radius: maxR, startAngle: .degrees(angle - 40), endAngle: .degrees(angle), clockwise: false)
                        sweep.closeSubpath()
                        ctx.fill(sweep, with: .conicGradient(Gradient(colors: [Color.rampartTeal.opacity(0), Color.rampartTeal.opacity(0.35)]), center: c, angle: .degrees(angle - 40)))
                    }
                }
                let spots = NetworkRadar.layout(count: others.count, center: c, maxR: maxR)
                ForEach(Array(others.enumerated()), id: \.element.id) { i, d in
                    let p = spots[i]
                    RadarDot(device: d, selected: d.id == selected)
                        .position(p)
                        .onTapGesture { selected = d.id }
                }
                if let hub = center {
                    ZStack {
                        Circle().fill(Color.rampartTeal.opacity(0.18)).frame(width: 54, height: 54)
                        Circle().strokeBorder(Color.rampartTeal.opacity(0.6), lineWidth: 1.5).frame(width: 54, height: 54)
                        Image(systemName: hub.type.symbol).font(.system(size: 22, weight: .semibold)).foregroundStyle(Color.rampartTeal).symbolRenderingMode(.hierarchical)
                    }
                    .position(c)
                    .onTapGesture { selected = hub.id }
                    .accessibilityLabel("Router \(SafeText.line(hub.displayName, max: 64))")
                } else if devices.isEmpty {
                    Image(systemName: "wifi.router").font(.system(size: 26)).foregroundStyle(.secondary).position(c)
                }
            }
        }
        .onChange(of: scanning) { _, on in
            if on && !reduceMotion { withAnimation(.linear(duration: 2.4).repeatForever(autoreverses: false)) { angle = 360 } }
            else { withAnimation(nil) { angle = 0 } }
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Network map with \(devices.count) devices")
    }

    /// Size reserved for one dot plus its label, used to keep labels from overlapping.
    static let slot = CGSize(width: 74, height: 50)

    /// Deterministic, overlap-free placement. Devices fill the middle ring first, then the outer and inner
    /// rings, each ring holding only as many as fit around its circumference. Rings are offset in angle so
    /// neighbours on adjacent rings don't line up, and a final pass nudges any remaining collisions apart.
    static func layout(count: Int, center c: CGPoint, maxR: CGFloat) -> [CGPoint] {
        guard count > 0 else { return [] }
        let radii: [CGFloat] = [maxR * 2 / 3 - 6, maxR - 6, maxR / 3 + 4]       // middle, outer, inner
        let offsets: [Double] = [-.pi / 2, -.pi / 2 + 0.35, -.pi / 2 + 0.7]
        let capacities = radii.map { r in max(1, Int((2 * .pi * r) / slot.width)) }
        var perRing = [0, 0, 0]
        var left = count
        for k in 0..<3 where left > 0 { let n = min(left, capacities[k]); perRing[k] = n; left -= n }
        // More devices than fit: spread the overflow over all rings (labels will be tight but still nudged apart).
        var k = 0
        while left > 0 { perRing[k % 3] += 1; left -= 1; k += 1 }

        var points: [CGPoint] = []
        for ring in 0..<3 where perRing[ring] > 0 {
            let n = perRing[ring]
            for j in 0..<n {
                let a = offsets[ring] + Double(j) * 2 * .pi / Double(n)
                points.append(CGPoint(x: c.x + cos(a) * radii[ring], y: c.y + sin(a) * radii[ring]))
            }
        }
        // Collision pass: push overlapping label boxes apart (also away from the hub in the centre).
        let w = slot.width, h = slot.height
        for _ in 0..<12 {
            var moved = false
            for i in points.indices {
                for j in points.indices where j > i {
                    let dx = points[j].x - points[i].x, dy = points[j].y - points[i].y
                    let ox = w - abs(dx), oy = h - abs(dy)
                    guard ox > 0, oy > 0 else { continue }
                    moved = true
                    if ox < oy {
                        let push = ox / 2 * (dx >= 0 ? 1 : -1)
                        points[i].x -= push; points[j].x += push
                    } else {
                        let push = oy / 2 * (dy >= 0 ? 1 : -1)
                        points[i].y -= push; points[j].y += push
                    }
                }
            }
            if !moved { break }
        }
        return points
    }
}

struct RadarDot: View {
    let device: NetDevice
    let selected: Bool
    /// About 12 characters, so labels never run into their neighbours; the full name is the tooltip.
    private var shortName: String {
        let n = SafeText.line(device.displayName, max: 64)
        return n.count > 12 ? String(n.prefix(11)) + "…" : n
    }
    private var tint: Color {
        if device.isThisMac { return .rampartTeal }
        switch device.worstSeverity {
        case .critical, .high: return .statusAction
        case .medium: return .statusAttention
        default: return device.isNew && !device.trusted ? .statusAttention : .statusProtected
        }
    }
    var body: some View {
        VStack(spacing: 2) {
            ZStack {
                Circle().fill(tint.opacity(0.2)).frame(width: selected ? 38 : 30, height: selected ? 38 : 30)
                Circle().strokeBorder(tint.opacity(selected ? 1 : 0.55), lineWidth: selected ? 2 : 1).frame(width: selected ? 38 : 30, height: selected ? 38 : 30)
                Image(systemName: device.type.symbol).font(.system(size: 13, weight: .medium)).foregroundStyle(tint).symbolRenderingMode(.hierarchical)
            }
            Text(shortName).font(.system(size: 9)).lineLimit(1).fixedSize().foregroundStyle(.secondary)
        }
        .frame(width: NetworkRadar.slot.width)
        .help(SafeText.line(device.displayName, max: 64))
        .animation(.spring(response: 0.3, dampingFraction: 0.8), value: selected)
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(SafeText.line(device.displayName, max: 64)), \(device.type.label)\(device.openPorts.isEmpty ? "" : ", \(device.openPorts.count) open services")")
        .accessibilityAddTraits(.isButton)
    }
}
