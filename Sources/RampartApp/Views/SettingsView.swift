import SwiftUI
import AppKit
import RampartShared

enum SettingsTab: String, CaseIterable, Identifiable {
    case general = "General", protection = "Protection", scans = "Scans", network = "Network", notifications = "Notifications",
         updates = "Updates", privacy = "Privacy", account = "Account", advanced = "Advanced"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .general: return "gearshape"; case .protection: return "shield.lefthalf.filled"; case .scans: return "magnifyingglass"
        case .network: return "network"; case .notifications: return "bell.badge"; case .updates: return "arrow.down.circle"
        case .privacy: return "hand.raised"; case .account: return "person.crop.circle"; case .advanced: return "wrench.and.screwdriver"
        }
    }
}

struct SettingsView: View {
    let standalone: Bool
    @StateVar private var tab: SettingsTab = .protection

    var body: some View {
        if standalone {
            TabView(selection: $tab) {
                ForEach(SettingsTab.allCases) { t in
                    SettingsPane(tab: t).background(AppBackdrop()).tabItem { Label(t.rawValue, systemImage: t.symbol) }.tag(t)
                }
            }
        } else {
            HStack(spacing: 0) {
                List(SettingsTab.allCases, selection: Binding(get: { Optional(tab) }, set: { if let t = $0 { tab = t } })) { t in
                    Label(t.rawValue, systemImage: t.symbol).tag(t)
                }
                .listStyle(.sidebar)
                .scrollContentBackground(.hidden)
                .frame(width: 200)
                Divider()
                SettingsPane(tab: tab).frame(maxWidth: .infinity, maxHeight: .infinity)
            }
            .navigationTitle("Settings")
        }
    }
}

/// Binding into the daemon-owned settings; writes go through `setSettings`.
extension AppModel {
    func setting<T: Equatable>(_ kp: WritableKeyPath<RampartSettings, T>) -> Binding<T> {
        Binding(get: { self.settings[keyPath: kp] }, set: { v in self.updateSettings { $0[keyPath: kp] = v } })
    }
}

struct SettingsPane: View {
    let tab: SettingsTab
    @Environment(AppModel.self) private var model
    var body: some View {
        Group {
            switch tab {
            case .general: GeneralSettings()
            case .protection: ProtectionSettings()
            case .scans: ScanSettings()
            case .network: NetworkSettings()
            case .notifications: NotificationSettings()
            case .updates: UpdateSettings()
            case .privacy: PrivacySettings()
            case .account: AccountSettings()
            case .advanced: AdvancedSettings()
            }
        }
        .formStyle(.grouped)
        .scrollContentBackground(.hidden)
    }
}

/// Footer shown where a setting is held by the background service.
struct ServiceFooter: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        switch model.mode {
        case .live: Text("Saved by the Rampart background service.").foregroundStyle(.secondary)
        case .demo: Text("Demo mode: changes here aren't saved.").foregroundStyle(.secondary)
        case .connecting: Text("Connecting to the background service…").foregroundStyle(.secondary)
        }
    }
}

struct GeneralSettings: View {
    @AppStorage("general.launchAtLogin") private var launchAtLogin = true
    @AppStorage("general.showDock") private var showDock = true
    @AppStorage(DaemonLauncher.keepRunningKey) private var keepProtecting = true
    @AppStorage("general.textSize") private var textSize = "default"
    var body: some View {
        Form {
            Section {
                Toggle("Open Rampart at login", isOn: $launchAtLogin)
                Toggle("Keep protecting when Rampart is closed", isOn: $keepProtecting)
                Toggle("Show in menu bar", isOn: Binding(get: { ChromeState.shared.menuBarInserted },
                                                          set: { ChromeState.shared.setMenuBarInserted($0) }))
                Toggle("Show Dock icon", isOn: $showDock)
                    .onChange(of: showDock) { _, v in if !Headless.active { NSApp.setActivationPolicy(v ? .regular : .accessory) } }
            } footer: {
                Text("With basic protection, closing Rampart leaves checking running in the background unless you turn that off here.")
                    .foregroundStyle(.secondary)
            }
            Section {
                Picker("Text size", selection: $textSize) {
                    Text("Default").tag("default"); Text("Large").tag("large"); Text("Larger").tag("larger")
                }
                Button("Show Welcome Guide Again") { NotificationCenter.default.post(name: .rampartShowOnboarding, object: nil) }
            }
        }
    }
}

struct ProtectionSettings: View {
    @Environment(AppModel.self) private var model
    @StateVar private var confirmOff = false

    var body: some View {
        Form {
            Section {
                Toggle("Real-time protection", isOn: Binding(get: { model.settings.realtimeOn && model.pausedUntil == nil },
                                                             set: { v in if v { model.setRealtime(true) } else { confirmOff = true } }))
                Toggle("Move threats to quarantine automatically", isOn: model.setting(\.autoQuarantine))
                Toggle("Scan inside archives and disk images", isOn: model.setting(\.scanArchives))
                Toggle("Ransomware early warning (decoy files)", isOn: model.setting(\.ransomwareCanaries))
            } header: { Text("Real-time") } footer: { ServiceFooter() }
            Section {
                Toggle("Learn quietly for the first 48 hours", isOn: model.setting(\.learningMode))
            } footer: {
                Text("While learning, Rampart records how your apps normally behave and only interrupts you for clear threats.").foregroundStyle(.secondary)
            }
            Section {
                LabeledContent("Not scanned") {
                    Text(model.settings.exclusions.isEmpty ? "Nothing excluded" : "\(model.settings.exclusions.count) folder\(model.settings.exclusions.count == 1 ? "" : "s")")
                        .foregroundStyle(.secondary)
                }
                Button("Edit in Rules…") { model.selection = .rules }
            } header: { Text("Exclusions") } footer: {
                Label("Excluded items aren't checked. Only exclude things you trust.", systemImage: "info.circle").foregroundStyle(.secondary)
            }
        }
        .confirmationDialog("Turn off real-time protection?", isPresented: $confirmOff) {
            Button("For 15 minutes") { model.setRealtime(false, pauseFor: 15) }
            Button("For 1 hour") { model.setRealtime(false, pauseFor: 60) }
            Button("Until I turn it on", role: .destructive) { model.setRealtime(false) }
        } message: { Text("Files won't be checked as they open. Choose how long:") }
    }
}

struct ScanSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Form {
            Section {
                Toggle("Run a Quick Scan every day", isOn: model.setting(\.scheduledQuickScan))
                Picker("Time", selection: model.setting(\.scheduledScanHour)) {
                    ForEach(0..<24, id: \.self) { Text(String(format: "%02d:00", $0)).tag($0) }
                }
                .disabled(!model.settings.scheduledQuickScan)
            } header: { Text("Scheduled scan") } footer: { ServiceFooter() }
        }
    }
}

struct NetworkSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Form {
            Section {
                Toggle("Block known malicious and phishing sites", isOn: Binding(get: { model.settings.webProtection },
                                                                              set: { v in model.updateSettings { $0.webProtection = v }; Task { await model.setWebProtection(v) } }))
                    .disabled(!model.webProtectionAvailable)
                Toggle("Block trackers (privacy, not security)", isOn: model.setting(\.blockTrackers))
                    .disabled(!model.webProtectionAvailable)
            } header: { Text("Web protection") } footer: {
                if !model.webProtectionAvailable {
                    Text("Web protection needs the full system service, because it changes how your Mac looks up websites.").foregroundStyle(.secondary)
                } else { ServiceFooter() }
            }
        }
    }
}

struct NotificationSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("notif.sounds") private var sounds = false
    @StateVar private var authorized: Bool? = Notifier.shared.authorized
    var body: some View {
        Form {
            if authorized == false {
                Section {
                    HStack {
                        Label("Notifications are off for Rampart in System Settings.", systemImage: "bell.slash")
                        Spacer()
                        Button("Allow…") { Task { authorized = await Notifier.shared.requestAuthorization() } }
                    }
                }
            }
            Section {
                Toggle("Threats Rampart blocks", isOn: model.setting(\.notifyThreats))
                Toggle("Finished scans and updates", isOn: model.setting(\.notifyInfo))
                Toggle("Play sounds", isOn: $sounds)
            } header: { Text("Notify me about") } footer: {
                Text("Everything other than threats is limited to one notification per hour.").foregroundStyle(.secondary)
            }
        }
    }
}

struct UpdateSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Form {
            Section {
                Toggle("Update definitions automatically", isOn: model.setting(\.autoUpdate))
            } footer: { ServiceFooter() }
            Section {
                LabeledContent("Definitions", value: model.status.signatureVersion == "0" ? "—" : model.status.signatureVersion)
                LabeledContent("Apple XProtect", value: model.status.xprotectVersion ?? "—")
                if model.blocklistDomains > 0 { LabeledContent("Blocked domains", value: Fmt.count(model.blocklistDomains)) }
                LabeledContent("App version", value: Product.version)
                HStack {
                    Text("Last checked \(Fmt.ago(model.definitionsUpdated).lowercased())").foregroundStyle(.secondary)
                    Spacer()
                    if model.isUpdatingDefinitions { ProgressView().controlSize(.small) }
                    Button("Check Now") { Task { await model.updateDefinitions() } }.disabled(model.isUpdatingDefinitions)
                }
            }
        }
    }
}

struct PrivacySettings: View {
    var body: some View {
        Form {
            Section {
                Label("Rampart doesn't collect usage statistics.", systemImage: "chart.bar.xaxis")
                Label("Scanning happens on this Mac. Your files are never uploaded.", systemImage: "internaldrive")
                Label("Definition updates download public threat lists; nothing about you is sent.", systemImage: "arrow.down.circle")
                Label("The password breach check sends only the first 5 characters of a fingerprint.", systemImage: "key")
            } header: { Text("What leaves your Mac") }
        }
    }
}

/// The only place in the app where plans or pricing appear.
struct AccountSettings: View {
    @Environment(\.openURL) private var openURL
    var body: some View {
        Form {
            Section("Plan") {
                LabeledContent("Plan", value: "Rampart Personal")
                LabeledContent("Price", value: "$29.99 per year")
                LabeledContent("Renews", value: Calendar.current.date(byAdding: .month, value: 10, to: Date())!.formatted(date: .long, time: .omitted))
                LabeledContent("Devices", value: "1 of 3 Macs")
            }
            Section {
                Button("Manage Subscription…") { openURL(URL(string: "https://rampart.app/account")!) }
                Button("Turn Off Auto-Renew…") { openURL(URL(string: "https://rampart.app/account/renewal")!) }
            } footer: {
                Text("Your protection and Security Score never depend on your plan.").foregroundStyle(.secondary)
            }
        }
    }
}

struct AdvancedSettings: View {
    @Environment(AppModel.self) private var model
    @StateVar private var confirmReset = false
    @StateVar private var showUninstall = false
    @StateVar private var showInstall = false
    var body: some View {
        Form {
            Section("Protection service") {
                LabeledContent("Running as") { ProtectionSourceLabel() }
                if model.source == .basic {
                    Button("Install Full Protection…") { showInstall = true }
                }
            }
            HealthPanel()
            Section {
                Toggle("Developer mode (fewer alerts for build tools)", isOn: model.setting(\.developerMode))
            } footer: { ServiceFooter() }
            Section("Diagnostics") {
                Button("Open Logs Folder") {
                    let dir = model.source == .basic ? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Rampart") : URL(fileURLWithPath: "/Library/Logs/Rampart")
                    NSWorkspace.shared.open(dir)
                }
            }
            Section {
                Button("Remove All Allow Rules…", role: .destructive) { confirmReset = true }.disabled(model.allowRules.isEmpty)
                Button("Uninstall Rampart…") { showUninstall = true }
            }
        }
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
        .confirmationDialog("Remove all allow rules?", isPresented: $confirmReset) {
            Button("Remove All", role: .destructive) { Task { for r in model.allowRules { await model.removeAllowRule(r) } } }
        } message: { Text("Every allowed file, developer and folder will be checked normally again. This can't be undone.") }
        .alert("Uninstall Rampart", isPresented: $showUninstall) {
            Button("Cancel", role: .cancel) {}
            Button("Copy Uninstall Command") {
                NSPasteboard.general.clearContents()
                NSPasteboard.general.setString("sudo \"\(Paths.supportRoot.path)/uninstall.sh\"", forType: .string)
            }
        } message: {
            Text("This removes the app, its background protection and your rules. Quarantined files will be deleted. Paste the copied command into Terminal to finish; macOS will ask for your password.")
        }
    }
}

struct ProtectionSourceLabel: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        switch (model.mode, model.source) {
        case (.live, .systemService): StatusLabel(text: "System service (full protection)", symbol: "checkmark.shield.fill", tint: .statusProtected)
        case (.live, _): StatusLabel(text: "Basic protection (no install)", symbol: "shield.lefthalf.filled", tint: .rampartTeal)
        case (.demo, _): StatusLabel(text: "Not running · demo mode", symbol: "sparkles.rectangle.stack", tint: .statusInfo)
        case (.connecting, _): StatusLabel(text: "Starting…", symbol: "hourglass", tint: .secondary)
        }
    }
}

/// The daemon's own resource use, refreshed every 3 s while visible.
struct HealthPanel: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Section("Rampart health") {
            if let h = model.health {
                LabeledContent("Version", value: "\(h.version) · \(h.mode == "user" ? "basic" : "system") mode")
                LabeledContent("Running for", value: Fmt.duration(h.uptimeSeconds))
                LabeledContent("CPU") { meter(h.cpuPercent, max: 100, text: String(format: "%.1f%%", h.cpuPercent)) }
                LabeledContent("Memory") { meter(h.residentMB, max: 500, text: String(format: "%.0f MB", h.residentMB)) }
                ForEach(h.sources.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                    LabeledContent(k) { StatusLabel(text: v ? "Running" : "Not available", symbol: v ? "checkmark.circle.fill" : "minus.circle", tint: v ? .green : .secondary) }
                }
                if !h.lastErrors.isEmpty {
                    DisclosureGroup("Recent problems (\(h.lastErrors.count))") {
                        ForEach(h.lastErrors, id: \.self) { Text($0).font(.caption.monospaced()).foregroundStyle(.secondary).textSelection(.enabled) }
                    }
                }
            } else {
                Text(model.mode == .live ? "This version of the background service doesn't report its health." : "Health appears when the background service is running.")
                    .foregroundStyle(.secondary)
            }
        }
        .task {
            while !Task.isCancelled {
                await model.refreshHealth()
                try? await Task.sleep(nanoseconds: 3_000_000_000)
            }
        }
    }

    private func meter(_ v: Double, max: Double, text: String) -> some View {
        HStack(spacing: Spacing.s) {
            Gauge(value: min(v, max), in: 0...max) { EmptyView() }
                .gaugeStyle(.accessoryLinearCapacity).tint(Color.rampartTeal).frame(width: 90)
            Text(text).monospacedDigit().frame(minWidth: 60, alignment: .trailing)
        }
        .accessibilityElement(children: .ignore)
        .accessibilityLabel(text)
    }
}

/// Calm upgrade path from basic protection to the full system service.
struct InstallFullProtectionSheet: View {
    @Environment(\.dismiss) private var dismiss
    @StateVar private var copied = false
    private var command: String {
        let scripts = Bundle.main.bundleURL.deletingLastPathComponent().appendingPathComponent("scripts/install.sh").path
        return FileManager.default.fileExists(atPath: scripts) ? "sudo \"\(scripts)\"" : "sudo ./scripts/install.sh"
    }
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: "shield.lefthalf.filled", tint: .rampartTeal, size: 44)
                VStack(alignment: .leading) {
                    Text("Install full protection").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text("Optional. Basic protection keeps working either way.").foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("The system service adds:").font(.headline)
                Label("Web protection that blocks malicious and phishing sites for every app", systemImage: "globe")
                Label("System-wide monitoring of new processes and startup items", systemImage: "waveform.path.ecg")
                Label("Protection that starts before you log in", systemImage: "power")
            }
            VStack(alignment: .leading, spacing: Spacing.s) {
                Text("How to install").font(.headline)
                Text("Open Rampart.pkg from the Rampart disk image, or run this in Terminal. macOS will ask for an administrator password; Rampart never sees it.")
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(command).font(.callout.monospaced()).textSelection(.enabled)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    Button(copied ? "Copied" : "Copy") {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(command, forType: .string); copied = true
                    }
                }
            }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl)
        .frame(width: 540)
    }
}
