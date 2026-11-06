import SwiftUI
import AppKit
import RampartShared

enum SettingsTab: String, CaseIterable, Identifiable {
    case general = "General", protection = "Protection", scans = "Scans", notifications = "Notifications", updates = "Updates", privacy = "Privacy", account = "Account", advanced = "Advanced"
    var id: String { rawValue }
    var symbol: String {
        switch self {
        case .general: return "gearshape"; case .protection: return "shield.lefthalf.filled"; case .scans: return "magnifyingglass"
        case .notifications: return "bell.badge"; case .updates: return "arrow.down.circle"; case .privacy: return "hand.raised"
        case .account: return "person.crop.circle"; case .advanced: return "wrench.and.screwdriver"
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

struct SettingsPane: View {
    let tab: SettingsTab
    var body: some View {
        Group {
            switch tab {
            case .general: GeneralSettings()
            case .protection: ProtectionSettings()
            case .scans: ScanSettings()
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

struct GeneralSettings: View {
    @AppStorage("general.launchAtLogin") private var launchAtLogin = true
    @AppStorage("general.showDock") private var showDock = true
    @AppStorage("general.textSize") private var textSize = "default"
    var body: some View {
        Form {
            Section {
                Toggle("Launch Rampart at login", isOn: $launchAtLogin)
                Toggle("Show in menu bar", isOn: Binding(get: { ChromeState.shared.menuBarInserted },
                                                          set: { ChromeState.shared.setMenuBarInserted($0) }))
                Toggle("Show Dock icon", isOn: $showDock)
                    .onChange(of: showDock) { _, v in NSApp.setActivationPolicy(v ? .regular : .accessory) }
            } footer: {
                Text("When the Dock icon is hidden, open Rampart from the menu bar.").foregroundStyle(.secondary)
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
    @AppStorage("prot.onOpen") private var onOpen = true
    @AppStorage("prot.onDownload") private var onDownload = true
    @AppStorage("prot.onMount") private var onMount = true
    @AppStorage("prot.behaviour") private var behaviour = true
    @AppStorage("prot.ransomware") private var ransomware = true
    @AppStorage("prot.pup") private var pup = true
    @AppStorage("prot.adware") private var adware = true
    @AppStorage("prot.archives") private var archives = true
    @AppStorage("prot.archiveDepth") private var archiveDepth = 3
    @AppStorage("prot.quarantineDays") private var quarantineDays = 30
    @AppStorage("prot.exclusions") private var exclusionsRaw = ""
    @StateVar private var selectedExclusion: String?
    @StateVar private var confirmOff = false

    private var exclusions: [String] { exclusionsRaw.split(separator: "\n").map(String.init) }

    var body: some View {
        Form {
            Section {
                Toggle("Real-time protection", isOn: Binding(get: { model.status.realtimeOn && model.pausedUntil == nil },
                                                             set: { v in if v { model.setRealtime(true) } else { confirmOff = true } }))
                    .disabled(model.mode == .live)
                Toggle("Scan files when they open", isOn: $onOpen)
                Toggle("Scan downloads", isOn: $onDownload)
                Toggle("Scan USB and external drives when connected", isOn: $onMount)
                Toggle("Behavior monitoring", isOn: $behaviour)
                Toggle("Ransomware guard", isOn: $ransomware)
            } header: { Text("Real-time") }
            Section("Detection") {
                Toggle("Detect potentially unwanted programs", isOn: $pup)
                Toggle("Detect adware", isOn: $adware)
                Toggle("Scan inside archives and disk images", isOn: $archives)
                Stepper("Maximum archive depth: \(archiveDepth)", value: $archiveDepth, in: 1...8).disabled(!archives)
            }
            Section {
                List(selection: $selectedExclusion) {
                    ForEach(exclusions, id: \.self) { e in
                        Label((e as NSString).abbreviatingWithTildeInPath, systemImage: "folder").tag(e)
                    }
                }
                .frame(minHeight: 90)
                .overlay { if exclusions.isEmpty { Text("No exclusions").foregroundStyle(.secondary) } }
                HStack {
                    Button("Add…") { addExclusion() }
                    Button("Remove") {
                        if let s = selectedExclusion { exclusionsRaw = exclusions.filter { $0 != s }.joined(separator: "\n"); selectedExclusion = nil }
                    }
                    .disabled(selectedExclusion == nil)
                }
            } header: { Text("Exclusions") } footer: {
                Label("Excluded items aren't checked. Only exclude things you trust.", systemImage: "info.circle").foregroundStyle(.secondary)
            }
            Section("Quarantine") {
                Picker("Delete quarantined files automatically after", selection: $quarantineDays) {
                    Text("7 days").tag(7); Text("30 days").tag(30); Text("90 days").tag(90); Text("Never").tag(0)
                }
            }
        }
        .confirmationDialog("Turn off real-time protection?", isPresented: $confirmOff) {
            Button("For 15 minutes") { model.setRealtime(false, pauseFor: 15) }
            Button("For 1 hour") { model.setRealtime(false, pauseFor: 60) }
            Button("Until I turn it on", role: .destructive) { model.setRealtime(false) }
        } message: { Text("Files won't be checked as they open. Choose how long:") }
    }

    private func addExclusion() {
        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = true; p.allowsMultipleSelection = true
        p.message = "Excluded items aren't checked. Only exclude things you trust."
        guard p.runModal() == .OK else { return }
        let new = Array(Set(exclusions + p.urls.map(\.path))).sorted()
        exclusionsRaw = new.joined(separator: "\n")
        for u in p.urls {
            model.activity.insert(ActivityItem(date: Date(), kind: .settings, title: "Excluded \((u.path as NSString).abbreviatingWithTildeInPath) from scans", outcome: "Rule added"), at: 0)
        }
    }
}

struct ScanSettings: View {
    @AppStorage("scan.schedule") private var schedule = "daily"
    @AppStorage("scan.scheduleType") private var scheduleType = "quick"
    @AppStorage("scan.scheduleHour") private var hour = 12
    @AppStorage("scan.pauseBattery") private var pauseBattery = true
    @AppStorage("scan.pauseLowPower") private var pauseLowPower = true
    @AppStorage("scan.pauseFullscreen") private var pauseFullscreen = true
    @AppStorage("scan.priority") private var priority = "balanced"
    var body: some View {
        Form {
            Section("Scheduled scan") {
                Picker("Repeat", selection: $schedule) { Text("Off").tag("off"); Text("Daily").tag("daily"); Text("Weekly").tag("weekly") }
                Picker("Type", selection: $scheduleType) { Text("Quick Scan").tag("quick"); Text("Full Scan").tag("full") }.disabled(schedule == "off")
                Picker("Time", selection: $hour) { ForEach(0..<24, id: \.self) { Text(String(format: "%02d:00", $0)).tag($0) } }.disabled(schedule == "off")
            }
            Section("Performance") {
                Toggle("Pause scans on battery", isOn: $pauseBattery)
                Toggle("Pause during Low Power Mode", isOn: $pauseLowPower)
                Toggle("Pause during video calls or full-screen apps", isOn: $pauseFullscreen)
                Picker("Scan priority", selection: $priority) { Text("Low impact").tag("low"); Text("Balanced").tag("balanced"); Text("Fast").tag("fast") }
            }
        }
    }
}

struct NotificationSettings: View {
    @AppStorage("notif.threatStyle") private var threatStyle = "banner"
    @AppStorage("notif.scanFinished") private var scanFinished = false
    @AppStorage("notif.blocked") private var blocked = false
    @AppStorage("notif.weekly") private var weekly = true
    @AppStorage("notif.updates") private var updates = false
    @AppStorage("notif.recommendations") private var recommendations = "weekly"
    @AppStorage("notif.focus") private var focus = true
    @AppStorage("notif.fullscreen") private var fullscreen = true
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
                LabeledContent("Threats") {
                    Picker("", selection: $threatStyle) { Text("Banner").tag("banner"); Text("Alert").tag("alert") }.labelsHidden().fixedSize()
                }
                Toggle("Scan finished", isOn: $scanFinished)
                Toggle("Blocked connections", isOn: $blocked)
                Toggle("Weekly summary", isOn: $weekly)
                Toggle("Updates", isOn: $updates)
                Picker("Recommendations", selection: $recommendations) { Text("Off").tag("off"); Text("Weekly digest").tag("weekly") }
            } header: { Text("Notify me about") } footer: {
                Text("Threat notifications are always on. Other notifications are limited to one per hour.").foregroundStyle(.secondary)
            }
            Section("Quiet Mode") {
                Toggle("Follow macOS Focus", isOn: $focus)
                Toggle("Stay quiet during full-screen apps", isOn: $fullscreen)
                Toggle("Play sounds", isOn: $sounds)
            }
        }
    }
}

struct UpdateSettings: View {
    @Environment(AppModel.self) private var model
    @AppStorage("upd.definitions") private var defs = true
    @AppStorage("upd.app") private var app = true
    @AppStorage("upd.beta") private var beta = false
    var body: some View {
        Form {
            Section {
                Toggle("Update definitions automatically (hourly)", isOn: $defs)
                Toggle("Update Rampart automatically", isOn: $app)
                Toggle("Beta updates", isOn: $beta)
            }
            Section {
                LabeledContent("Definitions", value: model.status.signatureVersion == "0" ? "—" : model.status.signatureVersion)
                LabeledContent("Apple XProtect", value: model.status.xprotectVersion ?? "—")
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
    @AppStorage("priv.analytics") private var analytics = false
    @AppStorage("priv.crash") private var crash = "ask"
    @AppStorage("priv.reputation") private var reputation = true
    @AppStorage("priv.samples") private var samples = false
    var body: some View {
        Form {
            Section {
                Toggle("Share anonymous usage statistics", isOn: $analytics)
                Picker("Crash reports", selection: $crash) { Text("Ask each time").tag("ask"); Text("Always send").tag("always"); Text("Never send").tag("never") }
                Toggle("Cloud reputation lookups", isOn: $reputation)
                Toggle("Automatically submit samples of new threats", isOn: $samples)
            } footer: {
                Text("Reputation lookups send file fingerprints (SHA-256) only, never file contents or names.").foregroundStyle(.secondary)
            }
            Section {
                Button("View What Rampart Sends") {
                    NSWorkspace.shared.open(Paths.userRoot.appendingPathComponent("Telemetry"))
                }
            }
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
    @AppStorage("adv.adminToDisable") private var adminToDisable = false
    @AppStorage("adv.touchID") private var touchID = false
    @StateVar private var confirmReset = false
    @StateVar private var showUninstall = false
    var body: some View {
        Form {
            Section {
                Toggle("Require an administrator password to turn off protection", isOn: $adminToDisable)
                Toggle("Lock settings with Touch ID", isOn: $touchID)
            }
            Section("Diagnostics") {
                LabeledContent("Background service") {
                    Text(model.mode == .live ? "Connected (\(model.client.connectedPath ?? ""))" : "Not running · demo mode")
                        .foregroundStyle(.secondary).lineLimit(1).truncationMode(.middle)
                }
                ForEach(model.status.sources.sorted(by: { $0.key < $1.key }), id: \.key) { k, v in
                    LabeledContent(k) { StatusLabel(text: v ? "Running" : "Stopped", symbol: v ? "checkmark.circle.fill" : "minus.circle", tint: v ? .green : .secondary) }
                }
                Button("Open Logs Folder") { NSWorkspace.shared.open(URL(fileURLWithPath: "/Library/Logs/Rampart")) }
            }
            Section {
                Button("Reset All Rules…", role: .destructive) { confirmReset = true }
                Button("Uninstall Rampart…") { showUninstall = true }
            }
        }
        .confirmationDialog("Reset all rules?", isPresented: $confirmReset) {
            Button("Reset", role: .destructive) { model.allowRules.removeAll(); model.ignoredChecks.removeAll() }
        } message: { Text("Every allowed file, developer and folder will be removed. This can't be undone.") }
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
