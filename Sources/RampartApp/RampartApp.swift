import SwiftUI
import AppKit
import Security
import RampartShared

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    /// Set when another copy was already running and this one is quitting; skips all startup work.
    private var isDuplicate = false
    static let revealNotification = Notification.Name("app.rampart.app.reveal")

    func applicationWillFinishLaunching(_ notification: Notification) {
        if Headless.active {
            NSApp.setActivationPolicy(.prohibited)
            HeadlessRunner.installWindowGuard()
            return
        }
        // Single instance: two copies would mean two menu bar icons and two background checkers.
        if let other = Self.otherRunningInstance() {
            isDuplicate = true
            NSApp.setActivationPolicy(.prohibited)
            if !CommandLine.arguments.contains("--background") {
                DistributedNotificationCenter.default().postNotificationName(Self.revealNotification, object: nil, userInfo: nil, deliverImmediately: true)
                other.activate()
            }
            // Nothing has started yet (no daemon child, no menu bar item), so quitting here is clean.
            exit(0)
        }
        // hx8: any process can post a distributed notification, so this only ever brings our own window
        // forward (it can't change state) and is rate-limited so it can't be used to keep stealing focus.
        DistributedNotificationCenter.default().addObserver(forName: Self.revealNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated {
                guard RevealLimiter.shared.allow() else { return }
                AppDelegate.revealMainWindow()
            }
        }
    }

    /// Another running copy of RamPart (any copy, wherever it was launched from).
    /// hx8: a bundle ID is just a string any app can claim, so a look-alike could otherwise make RamPart quit
    /// on every launch. The other process must be signed like us (our designated requirement, i.e. the same
    /// certificate, or for ad-hoc builds the same binary) or run from this very bundle path.
    static func otherRunningInstance() -> NSRunningApplication? {
        guard let id = Bundle.main.bundleIdentifier else { return nil }   // `swift run` builds have no bundle
        let me = ProcessInfo.processInfo.processIdentifier
        return NSRunningApplication.runningApplications(withBundleIdentifier: id)
            .first { $0.processIdentifier != me && !$0.isTerminated && isGenuineSibling($0) }
    }

    static func isGenuineSibling(_ app: NSRunningApplication) -> Bool {
        if let u = app.bundleURL?.resolvingSymlinksInPath().path,
           u == Bundle.main.bundleURL.resolvingSymlinksInPath().path { return true }
        var me: SecCode?, req: SecRequirement?, other: SecCode?
        guard SecCodeCopySelf([], &me) == errSecSuccess, let me,
              SecCodeCopyDesignatedRequirement(unsafeBitCast(me, to: SecStaticCode.self), [], &req) == errSecSuccess, let req else { return false }
        let attrs = [kSecGuestAttributePid: app.processIdentifier] as CFDictionary
        guard SecCodeCopyGuestWithAttributes(nil, attrs, [], &other) == errSecSuccess, let other else { return false }
        return SecCodeCheckValidity(other, [], req) == errSecSuccess
    }

    /// A second launch asked us to come forward: show the main window if it exists.
    static func revealMainWindow() {
        let showDock = UserDefaults.standard.object(forKey: "general.showDock") as? Bool ?? true
        if showDock { NSApp.setActivationPolicy(.regular) }
        NSApp.activate(ignoringOtherApps: true)
        if let w = NSApp.windows.first(where: { $0.identifier?.rawValue.contains("main") == true || $0.title == Product.name }) {
            w.makeKeyAndOrderFront(nil)
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if isDuplicate { return false }
        // Desktop Mode's layer windows count as "visible", which made the Dock icon do nothing. Always bring the app up.
        if DesktopMode.shared.isOn { DesktopMode.shared.openMain(); return false }
        return true
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        if isDuplicate { return }
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
    func applicationWillTerminate(_ notification: Notification) { if !isDuplicate { DaemonLauncher.shared.appWillTerminate() } }

    /// Dropping files or folders on the Dock icon starts a Custom Scan.
    /// hx8: other apps can send this too (`open -a`). Only existing local files, at most 64, and never while a
    /// scan runs: it can't be used to restart scans in a loop or smuggle non-file URLs in.
    func application(_ application: NSApplication, open urls: [URL]) {
        let paths = Self.droppedScanPaths(urls)
        guard !paths.isEmpty, !AppModel.shared.isScanning else { return }
        AppModel.shared.selection = .scan
        AppModel.shared.startScan(.custom, paths: paths)
    }
}

extension AppDelegate {
    static let maxDroppedPaths = 64
    static func droppedScanPaths(_ urls: [URL]) -> [String] {
        var seen = Set<String>(), out: [String] = []
        for u in urls where u.isFileURL {
            let p = u.standardizedFileURL.path
            guard !p.isEmpty, p.utf8.count < Int(PATH_MAX), !p.contains("\0"),
                  FileManager.default.fileExists(atPath: p), seen.insert(p).inserted else { continue }
            out.append(p)
            if out.count == maxDroppedPaths { break }
        }
        return out
    }
}

/// hx8: at most one reveal per 2 seconds from distributed notifications.
@MainActor
final class RevealLimiter {
    static let shared = RevealLimiter()
    private var last: Date = .distantPast
    func allow(now: Date = Date()) -> Bool {
        guard now.timeIntervalSince(last) >= 2 else { return false }
        last = now; return true
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
                .disclosureGroupStyle(FullRowDisclosureStyle())
                .environment(model)
                .tint(.rampartTeal)
                .frame(width: 680, height: 560)
        }

        MenuBarExtra(isInserted: chrome.menuBarBinding) {
            MenuBarView()
                .disclosureGroupStyle(FullRowDisclosureStyle())
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
            // ⌘1–⌘9 apply within the current sidebar mode (Protection or Refresh).
            let items = AppModel.shared.sidebarMode.shortcutItems
            ForEach(Array(items.prefix(9).enumerated()), id: \.offset) { i, item in
                Button(item.title) { AppModel.shared.selectShortcut(i) }
                    .keyboardShortcut(KeyEquivalent(Character(String(i + 1))), modifiers: .command)
            }
            Divider()
            Button("Protection") { AppModel.shared.switchMode(.protection) }.keyboardShortcut("1", modifiers: [.command, .option])
            Button("Refresh") { AppModel.shared.switchMode(.refresh) }.keyboardShortcut("2", modifiers: [.command, .option])
            Divider()
            // ⌃⌥⌘D is a global hot key (DesktopMode), so it isn't bound here too (it would toggle twice).
            Button("Toggle Desktop Mode (\(DesktopMode.shortcutLabel))") { DesktopMode.shared.toggle() }
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
