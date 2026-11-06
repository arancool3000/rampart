import SwiftUI
import AppKit
import RampartShared

@MainActor
final class BrowserAppDelegate: NSObject, NSApplicationDelegate {
    func applicationWillFinishLaunching(_ notification: Notification) {
        if Headless.active { NSApp.setActivationPolicy(.prohibited) }
    }
    func applicationDidFinishLaunching(_ notification: Notification) {
        if let dir = Headless.renderDir {
            NSApp.setActivationPolicy(.prohibited)
            for w in NSApp.windows { OffscreenRender.hide(w) }
            Task { await OffscreenRender.renderAll(to: dir); exit(0) }
            return
        }
        let model = BrowserModel.shared
        model.start()
        if model.tabs.isEmpty {
            let args = CommandLine.arguments.dropFirst().filter { !$0.hasPrefix("-") }
            if let first = args.first, let u = URLDecisionPolicy.resolveTyped(first) { model.newTab(url: u) } else { model.newTab() }
        }
        NSApp.activate(ignoringOtherApps: true)
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { !Headless.active }
    func application(_ application: NSApplication, open urls: [URL]) {
        for u in urls where !u.isFileURL { BrowserModel.shared.newTab(url: u) }
    }
}

/// Entry point. `--selftest` runs the pure-logic suites and exits before AppKit starts: no window, no WebKit.
@main
enum BrowserMain {
    static func main() {
        if CommandLine.arguments.contains("--selftest") {
            exit(BrowserSelfTests.run() ? 0 : 1)
        }
        if CommandLine.arguments.contains("--help") {
            print("RamPart Secure Browser\n  [url]            open url\n  --selftest       run logic self-tests\n  --render <dir>   offscreen PNGs of the chrome (no window)\n  --developer      show 'visit anyway' on blocked pages\n  --socket <path>  rampartd socket")
            exit(0)
        }
        SecureBrowserApp.main()
    }
}

struct SecureBrowserApp: App {
    @NSApplicationDelegateAdaptor(BrowserAppDelegate.self) var delegate
    let model = BrowserModel.shared

    var body: some Scene {
        Window("RamPart Secure Browser", id: "browser") {
            BrowserWindowView(model: model)
                .background(WindowConfigurator())
        }
        .defaultSize(width: 1180, height: 780)
        .windowStyle(.hiddenTitleBar)
        .commands { BrowserCommands(model: model) }
    }
}

/// Keyboard-first command set. Menu items so shortcuts are discoverable and work with any focus.
struct BrowserCommands: Commands {
    let model: BrowserModel
    var body: some Commands {
        CommandGroup(replacing: .newItem) {
            Button("New Tab") { model.newTab() }.keyboardShortcut("t")
            Button("Close Tab") { model.closeSelected() }.keyboardShortcut("w")
            Button("Open Location…") { model.addressFocusToken += 1 }.keyboardShortcut("l")
        }
        CommandMenu("View") {
            Button("Reload Page") { model.selectedTab?.reload() }.keyboardShortcut("r")
            Button("Stop") { model.selectedTab?.stop() }.keyboardShortcut(".")
            Divider()
            Button("Find in Page…") { model.showFind = true }.keyboardShortcut("f")
            Button("Next Tab") { model.selectNext(1) }.keyboardShortcut("]", modifiers: [.command, .shift])
            Button("Previous Tab") { model.selectNext(-1) }.keyboardShortcut("[", modifiers: [.command, .shift])
            Divider()
            Button("Downloads") { model.showDownloads.toggle() }.keyboardShortcut("j", modifiers: [.command, .shift])
            Button("Site Identity") { model.showIdentity.toggle() }.keyboardShortcut("i", modifiers: [.command, .shift])
        }
        CommandMenu("History") {
            Button("Back") { model.selectedTab?.goBack() }.keyboardShortcut("[")
            Button("Forward") { model.selectedTab?.goForward() }.keyboardShortcut("]")
        }
        CommandMenu("Privacy") {
            Toggle("Banking Mode", isOn: Binding(get: { model.bankingMode }, set: { _ in model.toggleBankingMode() }))
        }
    }
}

/// Titlebar styling without a toolbar: transparent title bar so the glass tab strip reaches the top.
struct WindowConfigurator: NSViewRepresentable {
    func makeNSView(context: Context) -> NSView {
        let v = NSView()
        DispatchQueue.main.async {
            guard let w = v.window else { return }
            w.titlebarAppearsTransparent = true
            w.titleVisibility = .hidden
            w.styleMask.insert(.fullSizeContentView)
            w.isMovableByWindowBackground = true
        }
        return v
    }
    func updateNSView(_ nsView: NSView, context: Context) {}
}
