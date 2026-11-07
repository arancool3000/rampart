import SwiftUI
import AppKit
import UserNotifications
import RampartShared

enum SettingsTab: String, CaseIterable, Identifiable {
    case general = "General", protection = "Protection", scans = "Scans", network = "Network", notifications = "Notifications",
         updates = "Updates", privacy = "Privacy", account = "Account", advanced = "Advanced"
    var id: String { rawValue }
    /// Words people might type when looking for a setting on this tab.
    var keywords: String {
        switch self {
        case .general: return "login launch dock menu bar text size welcome permissions background"
        case .protection: return "real-time realtime quarantine archives disk images ransomware decoy learning exclusions pause"
        case .scans: return "schedule daily quick scan time"
        case .network: return "web phishing malicious sites trackers dns"
        case .notifications: return "alerts sounds threats finished"
        case .updates: return "definitions xprotect version automatic check"
        case .privacy: return "data statistics upload breach"
        case .account: return "account free version about"
        case .advanced: return "developer logs diagnostics health uninstall allow rules data folder finder full protection"
        }
    }
    func matches(_ query: String) -> Bool {
        let q = query.trimmingCharacters(in: .whitespaces)
        return q.isEmpty || rawValue.localizedCaseInsensitiveContains(q) || keywords.localizedCaseInsensitiveContains(q)
    }
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
    @StateVar private var query = ""
    private var visibleTabs: [SettingsTab] { SettingsTab.allCases.filter { $0.matches(query) } }

    var body: some View {
        if standalone {
            TabView(selection: $tab) {
                ForEach(SettingsTab.allCases) { t in
                    SettingsPane(tab: t).background(AppBackdrop()).tabItem { Label(t.rawValue, systemImage: t.symbol) }.tag(t)
                }
            }
        } else {
            HStack(spacing: 0) {
                VStack(spacing: 0) {
                    SettingsSearchField(text: $query)
                        .padding(.horizontal, Spacing.s).padding(.top, Spacing.s)
                        .onChange(of: query) { _, _ in
                            if let first = visibleTabs.first, !visibleTabs.contains(tab) { tab = first }
                        }
                    if visibleTabs.isEmpty {
                        Text("No settings match \u{201C}\(query)\u{201D}.")
                            .font(.callout).foregroundStyle(.secondary).multilineTextAlignment(.center)
                            .padding(Spacing.m).frame(maxHeight: .infinity, alignment: .top)
                    } else {
                        List(visibleTabs, selection: Binding(get: { Optional(tab) }, set: { if let t = $0 { tab = t } })) { t in
                            Label(t.rawValue, systemImage: t.symbol).tag(t)
                        }
                        .listStyle(.sidebar)
                        .scrollContentBackground(.hidden)
                    }
                }
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

/// Compact search field for the settings sidebar.
struct SettingsSearchField: View {
    @Binding var text: String
    var body: some View {
        HStack(spacing: 4) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary).accessibilityHidden(true)
            TextField("Search settings", text: $text).textFieldStyle(.plain)
                .onExitCommand { text = "" }
            if !text.isEmpty {
                Button { text = "" } label: { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                    .buttonStyle(.plain).help("Clear search").accessibilityLabel("Clear search")
            }
        }
        .padding(.horizontal, 7).padding(.vertical, 5)
        .background(.quaternary.opacity(0.6), in: RoundedRectangle(cornerRadius: 7, style: .continuous))
    }
}

/// A toggle with a one-line plain-language explanation underneath.
struct HintToggle: View {
    let title: String
    let hint: String
    @Binding var isOn: Bool
    init(_ title: String, hint: String, isOn: Binding<Bool>) { self.title = title; self.hint = hint; self._isOn = isOn }
    var body: some View {
        Toggle(isOn: $isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                Text(hint).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
        }
        .accessibilityHint(hint)
    }
}

/// Small "Reset to Defaults" control for a section; disabled when nothing differs.
struct ResetSectionButton: View {
    let isDefault: Bool
    let reset: () -> Void
    var body: some View {
        HStack {
            Spacer()
            Button("Reset to Defaults", action: reset)
                .buttonStyle(.link).font(.caption)
                .disabled(isDefault)
                .help(isDefault ? "Already using the recommended settings" : "Restore the recommended settings for this section")
        }
    }
}

extension AppModel {
    /// True when every key path matches a fresh `RampartSettings()`.
    func settingsAreDefault(_ kps: [PartialKeyPath<RampartSettings>]) -> Bool {
        let d = RampartSettings()
        return kps.allSatisfy { kp in
            (settings[keyPath: kp] as? AnyHashable) == (d[keyPath: kp] as? AnyHashable)
        }
    }
    func resetSettings(_ apply: @escaping (inout RampartSettings, RampartSettings) -> Void) {
        let d = RampartSettings()
        updateSettings { apply(&$0, d) }
    }

    /// App-only preferences cleared by "Reset all settings". Onboarding, login-item state and internal
    /// bookkeeping (rate limits, splash) are deliberately left alone.
    static let resettableDefaultsKeys = [
        "general.showDock", "general.textSize", ChromeState.menuBarKey, "notif.sounds", "scan.lowImpact",
        "dashboard.basicCardDismissed", "sidebar.toolsExpanded", "safari.autoReenable", "safari.jsControl",
        PermissionsModel.networkScanEnabledKey, PermissionsModel.safariSetupEnabledKey,
    ]

    /// Sends a fresh `RampartSettings()` to the service and clears app-only preferences.
    func resetAllSettings() {
        updateSettings { $0 = RampartSettings() }
        let d = UserDefaults.standard
        for k in Self.resettableDefaultsKeys { d.removeObject(forKey: k) }
        ChromeState.shared.setMenuBarInserted(true)
        if !Headless.active { NSApp.setActivationPolicy(.regular) }
    }
}

/// Footer shown where a setting is held by the background service.
struct ServiceFooter: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        switch model.mode {
        case .live: Text("Saved by the \(Product.name) background service.").foregroundStyle(.secondary)
        case .demo: Text("Developer demo: changes here aren't saved.").foregroundStyle(.secondary)
        case .offline: Text("The protection service isn't running, so changes can't be saved right now.").foregroundStyle(.secondary)
        case .connecting: Text("Connecting to the background service…").foregroundStyle(.secondary)
        }
    }
}

struct GeneralSettings: View {
    @StateVar private var showPermissions = false
    @AppStorage("general.launchAtLogin") private var launchAtLogin = true
    @AppStorage("general.showDock") private var showDock = true
    @AppStorage(DaemonLauncher.keepRunningKey) private var keepProtecting = true
    @AppStorage("general.textSize") private var textSize = "default"
    var body: some View {
        Form {
            Section {
                HintToggle("Open \(Product.name) at login", hint: "Starts quietly in the background when you log in.", isOn: $launchAtLogin)
                HintToggle("Keep protecting when \(Product.name) is closed", hint: "Checking continues even after you quit the window.", isOn: $keepProtecting)
                HintToggle("Show in menu bar", hint: "A small icon for status and quick actions.",
                           isOn: Binding(get: { ChromeState.shared.menuBarInserted }, set: { ChromeState.shared.setMenuBarInserted($0) }))
                HintToggle("Show Dock icon", hint: "Turn off to keep \(Product.name) out of the Dock and app switcher.", isOn: $showDock)
                    .onChange(of: showDock) { _, v in if !Headless.active { NSApp.setActivationPolicy(v ? .regular : .accessory) } }
            } footer: {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("With basic protection, closing \(Product.name) leaves checking running in the background unless you turn that off here.")
                        .foregroundStyle(.secondary)
                    ResetSectionButton(isDefault: launchAtLogin && keepProtecting && showDock) {
                        launchAtLogin = true; keepProtecting = true; showDock = true
                    }
                }
            }
            Section {
                Picker("Text size", selection: $textSize) {
                    Text("Default").tag("default"); Text("Large").tag("large"); Text("Larger").tag("larger")
                }
                Button("Show Welcome Guide Again") { NotificationCenter.default.post(name: .rampartShowOnboarding, object: nil) }
            }
            Section {
                LabeledContent("Permissions") {
                    Button("Set Up \(Product.name)…") { showPermissions = true }
                }
            } footer: { Text("Grant everything \(Product.name) needs in one place.").foregroundStyle(.secondary) }
        }
        .sheet(isPresented: $showPermissions) { PermissionsSheet() }
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
                HintToggle("Move threats to quarantine automatically", hint: "Threats are set aside safely; you can restore them from Quarantine.", isOn: model.setting(\.autoQuarantine))
                HintToggle("Scan inside archives and disk images", hint: "Checks .zip, .dmg and similar files before you open what's inside.", isOn: model.setting(\.scanArchives))
                HintToggle("Ransomware early warning (decoy files)", hint: "Places hidden decoy files and alerts you if something starts encrypting them.", isOn: model.setting(\.ransomwareCanaries))
            } header: { Text("Real-time") } footer: {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    ServiceFooter()
                    ResetSectionButton(isDefault: model.settingsAreDefault([\.autoQuarantine, \.scanArchives, \.ransomwareCanaries])) {
                        model.resetSettings { $0.autoQuarantine = $1.autoQuarantine; $0.scanArchives = $1.scanArchives; $0.ransomwareCanaries = $1.ransomwareCanaries }
                    }
                }
            }
            Section {
                HintToggle("Learn quietly for the first 48 hours", hint: "Fewer questions while \(Product.name) gets to know your Mac.", isOn: model.setting(\.learningMode))
            } footer: {
                Text("While learning, \(Product.name) records how your apps normally behave and only interrupts you for clear threats.").foregroundStyle(.secondary)
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
                HintToggle("Run a Quick Scan every day", hint: "Checks the places malware usually hides. Takes a minute or two.", isOn: model.setting(\.scheduledQuickScan))
                Picker("Time", selection: model.setting(\.scheduledScanHour)) {
                    ForEach(0..<24, id: \.self) { Text(String(format: "%02d:00", $0)).tag($0) }
                }
                .disabled(!model.settings.scheduledQuickScan)
            } header: { Text("Scheduled scan") } footer: {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    ServiceFooter()
                    ResetSectionButton(isDefault: model.settingsAreDefault([\.scheduledQuickScan, \.scheduledScanHour])) {
                        model.resetSettings { $0.scheduledQuickScan = $1.scheduledQuickScan; $0.scheduledScanHour = $1.scheduledScanHour }
                    }
                }
            }
        }
    }
}

struct NetworkSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Form {
            Section {
                HintToggle("Block known malicious and phishing sites", hint: "Stops pages that try to steal passwords or install malware.", isOn: Binding(get: { model.settings.webProtection },
                                                                              set: { v in model.updateSettings { $0.webProtection = v }; Task { await model.setWebProtection(v) } }))
                    .disabled(!model.webProtectionAvailable)
                HintToggle("Block trackers (privacy, not security)", hint: "Hides known ad and analytics domains. Some sites may behave differently.", isOn: model.setting(\.blockTrackers))
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
                        Label("Notifications are off for \(Product.name) in System Settings.", systemImage: "bell.slash")
                        Spacer()
                        Button("Allow…") { Task { authorized = await Notifier.shared.allowOrOpenSettings() } }
                            .help("Asks macOS for permission, or opens Notifications in System Settings if you turned them off there.")
                    }
                }
            }
            Section {
                HintToggle("Threats \(Product.name) blocks", hint: "A short note whenever something is stopped or quarantined.", isOn: model.setting(\.notifyThreats))
                HintToggle("Finished scans and updates", hint: "Lets you know when routine work is done.", isOn: model.setting(\.notifyInfo))
                HintToggle("Play sounds", hint: "Adds a gentle sound to notifications.", isOn: $sounds)
            } header: { Text("Notify me about") } footer: {
                VStack(alignment: .leading, spacing: Spacing.s) {
                    Text("Everything other than threats is limited to one notification per hour.").foregroundStyle(.secondary)
                    ResetSectionButton(isDefault: !sounds && model.settingsAreDefault([\.notifyThreats, \.notifyInfo])) {
                        sounds = false
                        model.resetSettings { $0.notifyThreats = $1.notifyThreats; $0.notifyInfo = $1.notifyInfo }
                    }
                }
            }
        }
        .task { await refreshAuthorization() }
        .onReceive(NotificationCenter.default.publisher(for: NSApplication.didBecomeActiveNotification)) { _ in
            Task { await refreshAuthorization() }
        }
    }

    private func refreshAuthorization() async {
        guard let st = await Notifier.shared.authorizationStatus() else { return }
        authorized = st == .authorized || st == .provisional
    }
}

struct UpdateSettings: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Form {
            Section {
                HintToggle("Update definitions automatically", hint: "Downloads the latest threat lists in the background. Recommended.", isOn: model.setting(\.autoUpdate))
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
                Label("\(Product.name) doesn't collect usage statistics.", systemImage: "chart.bar.xaxis")
                Label("Scanning happens on this Mac. Your files are never uploaded.", systemImage: "internaldrive")
                Label("Definition updates download public threat lists; nothing about you is sent.", systemImage: "arrow.down.circle")
                Label("The password breach check sends only the first 5 characters of a fingerprint.", systemImage: "key")
                Label("AI tools are off unless you turn them on. Then only what you send (redacted) goes to Google Gemini.", systemImage: "sparkles")
                Label("With web protection on, website lookups go to an encrypted DNS service (Cloudflare or Quad9).", systemImage: "globe")
            } header: { Text("What leaves your Mac") }
        }
    }
}

/// No accounts, plans or prices: RamPart is free while it's in development.
struct AccountSettings: View {
    var body: some View {
        Form {
            Section {
                Label("\(Product.name) is free while in development.", systemImage: "heart")
                Text("There's no account, subscription or sign-in. Every feature is available, and nothing is limited.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            Section("About") {
                LabeledContent("Version", value: Product.version).textSelection(.enabled)
            }
        }
    }
}

struct AdvancedSettings: View {
    @Environment(AppModel.self) private var model
    @StateVar private var confirmReset = false
    @StateVar private var confirmResetAll = false
    @StateVar private var showUninstall = false
    @StateVar private var showInstall = false
    private var dataFolder: URL {
        model.source == .basic
            ? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Rampart")
            : Paths.supportRoot
    }
    var body: some View {
        Form {
            Section("Protection service") {
                LabeledContent("Running as") { ProtectionSourceLabel() }
                if model.source == .basic {
                    Button("Enable Full Protection…") { showInstall = true }.buttonStyle(GlowButtonStyle())
                }
            }
            HealthPanel()
            Section {
                HintToggle("Developer mode (fewer alerts for build tools)", hint: "Trusts compilers and package managers that create many new files.", isOn: model.setting(\.developerMode))
            } footer: { ServiceFooter() }
            Section("Diagnostics") {
                Button("Open Logs Folder") {
                    let dir = model.source == .basic ? FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/Rampart") : URL(fileURLWithPath: "/Library/Logs/Rampart")
                    NSWorkspace.shared.open(dir)
                }
                LabeledContent("Data folder") {
                    HStack(spacing: Spacing.s) {
                        Text(dataFolder.path).font(.caption.monospaced()).foregroundStyle(.secondary)
                            .lineLimit(1).truncationMode(.middle).textSelection(.enabled)
                        Button("Show in Finder") { NSWorkspace.shared.activateFileViewerSelecting([dataFolder]) }
                            .buttonStyle(.link)
                            .help("Reveal where \(Product.name) keeps its definitions, rules and quarantine")
                    }
                }
            }
            Section {
                Button("Reset All Settings to Defaults…") { confirmResetAll = true }
                    .help("Puts every setting back the way it was when you installed \(Product.name). Your rules, quarantine and history are kept.")
                Button("Remove All Allow Rules…", role: .destructive) { confirmReset = true }.disabled(model.allowRules.isEmpty)
                Button("Uninstall \(Product.name)…") { showUninstall = true }
            }
        }
        .sheet(isPresented: $showInstall) { InstallFullProtectionSheet() }
        .confirmationDialog("Reset all settings to defaults?", isPresented: $confirmResetAll) {
            Button("Reset All Settings", role: .destructive) { model.resetAllSettings() }
        } message: {
            Text("Protection, scan, notification, network and app settings go back to their defaults, and scan exclusions are cleared. Allow rules, quarantined items and history are kept.")
        }
        .confirmationDialog("Remove all allow rules?", isPresented: $confirmReset) {
            Button("Remove All", role: .destructive) { Task { for r in model.allowRules { await model.removeAllowRule(r) } } }
        } message: { Text("Every allowed file, developer and folder will be checked normally again. This can't be undone.") }
        .alert("Uninstall \(Product.name)", isPresented: $showUninstall) {
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
        case (.demo, _): StatusLabel(text: "Developer demo", symbol: "sparkles.rectangle.stack", tint: .statusInfo)
        case (.offline, _): StatusLabel(text: "Not running", symbol: "shield.slash", tint: .statusAction)
        case (.connecting, _): StatusLabel(text: "Starting…", symbol: "hourglass", tint: .secondary)
        }
    }
}

/// The daemon's own resource use, refreshed every 3 s while visible.
struct HealthPanel: View {
    @Environment(AppModel.self) private var model
    var body: some View {
        Section("\(Product.name) health") {
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

/// Calm upgrade path from basic protection to the full system service: one password prompt, once.
struct InstallFullProtectionSheet: View {
    @Environment(\.dismiss) private var dismiss
    private let installer = FullProtectionInstaller.shared
    @StateVar private var showManual = false
    @StateVar private var copied = false
    private var command: String { "sudo \"\(installer.cliURL.path)\" install" }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: "lock.shield", tint: .rampartTeal, size: 44)
                VStack(alignment: .leading) {
                    Text("Enable full protection").font(.title2.weight(.semibold)).fontDesign(.rounded)
                    Text("Optional. Basic protection keeps working either way.").foregroundStyle(.secondary)
                }
            }
            VStack(alignment: .leading, spacing: Spacing.s) {
                Label("Web protection that blocks malicious and phishing sites for every app", systemImage: "globe")
                Label("System-wide monitoring of new processes and startup items", systemImage: "waveform.path.ecg")
                Label("Protection that starts before you log in", systemImage: "power")
            }
            Text("macOS will ask for your password once. After that \(Product.name) handles protection without asking again.")
                .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)

            switch installer.phase {
            case .idle:
                EmptyView()
            case .waitingForPassword:
                progress("Waiting for your password…")
            case .installing:
                progress("Installing the system service…")
            case .connecting:
                progress("Connecting to the new service…")
            case .done:
                Label("Full protection is on.", systemImage: "checkmark.shield.fill").foregroundStyle(.primary).font(.headline)
            case .failed(let why):
                Label(why, systemImage: "exclamationmark.circle").foregroundStyle(.secondary)
            }

            if let reason = installer.unavailableReason {
                Label(reason, systemImage: "info.circle").font(.callout).foregroundStyle(.secondary)
            }

            DisclosureGroup("Prefer Terminal?", isExpanded: $showManual) {
                HStack {
                    Text(command).font(.callout.monospaced()).textSelection(.enabled)
                        .padding(8).frame(maxWidth: .infinity, alignment: .leading)
                        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8, style: .continuous))
                    Button(copied ? "Copied" : "Copy") {
                        NSPasteboard.general.clearContents(); NSPasteboard.general.setString(command, forType: .string); copied = true
                    }
                }
            }
            .font(.callout)

            HStack {
                Spacer()
                Button(installer.phase == .done ? "Done" : "Not Now") { dismiss() }.keyboardShortcut(.cancelAction)
                if installer.phase != .done {
                    Button("Enable Full Protection") { installer.run() }
                        .buttonStyle(GlowButtonStyle()).controlSize(.large)
                        .disabled(installer.unavailableReason != nil || [.waitingForPassword, .installing, .connecting].contains(installer.phase))
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(Spacing.xl)
        .frame(width: 540)
    }

    private func progress(_ text: String) -> some View {
        HStack(spacing: Spacing.s) { ProgressView().controlSize(.small); Text(text).foregroundStyle(.secondary) }
    }
}
