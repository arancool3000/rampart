import SwiftUI
import AppKit
import RampartShared

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        if Headless.active {
            NSApp.setActivationPolicy(.prohibited)
            HeadlessRunner.installWindowGuard()
        }
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if Headless.active {
            NSApp.setActivationPolicy(.prohibited)
            for w in NSApp.windows { HeadlessRunner.hide(w) }
            AppModel.shared.start()
            Task { await HeadlessRunner.run() }
            return
        }
        // The login LaunchAgent starts the app with --background: menu bar only, no window, no focus change.
        let background = CommandLine.arguments.contains("--background")
        let showDock = UserDefaults.standard.object(forKey: "general.showDock") as? Bool ?? true
        NSApp.setActivationPolicy(showDock && !background ? .regular : .accessory)
        Notifier.shared.configure()
        AppModel.shared.start()
        AppFeatures.startBackgroundServices()
        if background {
            DispatchQueue.main.async {
                for window in NSApp.windows where window.identifier?.rawValue.contains("main") == true || window.title == Product.name {
                    window.close()
                }
            }
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }
    func applicationWillTerminate(_ notification: Notification) { DaemonLauncher.shared.appWillTerminate() }

    /// Dropping files or folders on the Dock icon starts a Custom Scan.
    func application(_ application: NSApplication, open urls: [URL]) {
        let paths = urls.filter(\.isFileURL).map(\.path)
        guard !paths.isEmpty else { return }
        AppModel.shared.selection = .scan
        AppModel.shared.startScan(.custom, paths: paths)
    }
}

@main
struct RampartApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) var delegate
    let model = AppModel.shared
    let chrome = ChromeState.shared

    var body: some Scene {
        mainWindow
        settingsAndMenuBar
    }

    private var mainWindow: some Scene {
        Window(Product.name, id: "main") {
            RootView()
                .background(HeadlessWindowHider())
                .environment(model)
                .tint(.rampartTeal)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1100, height: 740)
        .commands { RampartCommands() }
    }

    @SceneBuilder private var settingsAndMenuBar: some Scene {
        Settings {
            SettingsView(standalone: true)
                .environment(model)
                .tint(.rampartTeal)
                .frame(width: 680, height: 560)
        }

        MenuBarExtra(isInserted: chrome.menuBarBinding) {
            MenuBarView()
                .environment(model)
                .tint(.rampartTeal)
        } label: {
            MenuBarLabel()
        }
        .menuBarExtraStyle(.window)
    }
}

/// Reads only ChromeState (changes on scan start/stop), never the full model, so menus aren't rebuilt per tick.
struct RampartCommands: Commands {
    let chrome = ChromeState.shared
    var body: some Commands {
        CommandGroup(replacing: .appInfo) {
            Button("About \(Product.name)") {
                NSApp.orderFrontStandardAboutPanel(options: [
                    .applicationIcon: BrandImages.mark(size: 128),
                    .applicationName: Product.name,
                    .applicationVersion: Product.version,
                ])
            }
        }
        CommandGroup(after: .sidebar) {
            Button("Overview") { AppModel.shared.selection = .dashboard }.keyboardShortcut("1", modifiers: .command)
            Button("Scan") { AppModel.shared.selection = .scan }.keyboardShortcut("2", modifiers: .command)
            Button("Threats & Quarantine") { AppModel.shared.selection = .threats }.keyboardShortcut("3", modifiers: .command)
            Button("Protection Activity") { AppModel.shared.selection = .activity }.keyboardShortcut("4", modifiers: .command)
            Button("Network") { AppModel.shared.selection = .network }.keyboardShortcut("5", modifiers: .command)
            Button("Privacy & Posture") { AppModel.shared.selection = .posture }.keyboardShortcut("6", modifiers: .command)
            Button("Rules") { AppModel.shared.selection = .rules }.keyboardShortcut("7", modifiers: .command)
            Button("Settings") { AppModel.shared.selection = .settings }.keyboardShortcut("8", modifiers: .command)
        }
        CommandMenu("Scan") {
            Button("Quick Scan") { AppModel.shared.selection = .scan; AppModel.shared.startScan(.quick) }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(chrome.isScanning)
            Button("Full Scan") { AppModel.shared.selection = .scan; AppModel.shared.startScan(.full) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(chrome.isScanning)
            Divider()
            Button("Stop Scan") { AppModel.shared.stopScan() }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(!chrome.isScanning)
            Divider()
            Button("Update Definitions") { Task { await AppModel.shared.updateDefinitions() } }
        }
    }
}
