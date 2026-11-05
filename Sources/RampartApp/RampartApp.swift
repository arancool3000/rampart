import SwiftUI
import AppKit
import RampartShared

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    func applicationDidFinishLaunching(_ notification: Notification) {
        // The login LaunchAgent starts the app with --background: menu bar only, no window, no focus change.
        let background = CommandLine.arguments.contains("--background")
        let showDock = UserDefaults.standard.object(forKey: "general.showDock") as? Bool ?? true
        NSApp.setActivationPolicy(showDock && !background ? .regular : .accessory)
        Notifier.shared.configure()
        AppModel.shared.start()
        if background {
            DispatchQueue.main.async {
                for window in NSApp.windows where window.identifier?.rawValue.contains("main") == true || window.title == "Rampart" {
                    window.close()
                }
            }
        } else {
            NSApp.activate(ignoringOtherApps: true)
        }
        Snapshotter.runIfRequested()
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

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
    @AppStorage("general.showMenuBar") var showMenuBar = true
    let model = AppModel.shared

    var body: some Scene {
        Window("Rampart", id: "main") {
            RootView()
                .environment(model)
                .tint(.rampartTeal)
                .frame(minWidth: 900, minHeight: 600)
        }
        .defaultSize(width: 1100, height: 740)
        .commands { RampartCommands(model: model) }

        Settings {
            SettingsView(standalone: true)
                .environment(model)
                .tint(.rampartTeal)
                .frame(width: 680, height: 560)
        }

        MenuBarExtra(isInserted: $showMenuBar) {
            MenuBarView()
                .environment(model)
                .tint(.rampartTeal)
        } label: {
            Image(systemName: model.openDetections.isEmpty ? "shield.lefthalf.filled" : "exclamationmark.shield")
                .accessibilityLabel(model.openDetections.isEmpty ? "Rampart: protected" : "Rampart: item needs attention")
        }
        .menuBarExtraStyle(.window)
    }
}

struct RampartCommands: Commands {
    let model: AppModel
    var body: some Commands {
        CommandGroup(after: .sidebar) {
            ForEach(SidebarItem.allCases) { item in
                Button(item.title) { model.selection = item }
                    .keyboardShortcut(item.shortcut, modifiers: .command)
            }
        }
        CommandMenu("Scan") {
            Button("Quick Scan") { model.selection = .scan; model.startScan(.quick) }
                .keyboardShortcut("r", modifiers: .command)
                .disabled(model.isScanning)
            Button("Full Scan") { model.selection = .scan; model.startScan(.full) }
                .keyboardShortcut("r", modifiers: [.command, .shift])
                .disabled(model.isScanning)
            Divider()
            Button("Stop Scan") { model.stopScan() }
                .keyboardShortcut(".", modifiers: .command)
                .disabled(!model.isScanning)
            Divider()
            Button("Update Definitions") { Task { await model.updateDefinitions() } }
        }
    }
}
