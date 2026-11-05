import SwiftUI
import AppKit

/// Developer aid for visual QA: `RampartApp --snapshot-dir <dir>` visits every screen and writes PNGs, then quits.
/// Uses `screencapture -l <windowID>`; falls back to rendering the window's view hierarchy.
@MainActor
enum Snapshotter {
    static func runIfRequested() {
        let args = ProcessInfo.processInfo.arguments
        guard let i = args.firstIndex(of: "--snapshot-dir"), i + 1 < args.count else { return }
        let dir = URL(fileURLWithPath: args[i + 1])
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        Task { await run(dir) }
    }

    private static func sleep(_ s: Double) async { try? await Task.sleep(nanoseconds: UInt64(s * 1_000_000_000)) }

    private static var mainWindow: NSWindow? {
        NSApp.windows.first { $0.identifier?.rawValue.contains("main") == true }
            ?? NSApp.windows.first { !($0 is NSPanel) && $0.sheetParent == nil && $0.frame.width > 600 }
    }

    static func capture(_ window: NSWindow, to url: URL) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        p.arguments = ["-x", "-o", "-l", String(window.windowNumber), url.path]
        try? p.run(); p.waitUntilExit()
        FileHandle.standardError.write("snapshot \(url.lastPathComponent) window=\(window.windowNumber) status=\(p.terminationStatus)\n".data(using: .utf8)!)
        if FileManager.default.fileExists(atPath: url.path) { return }
        // Fallback: render the view hierarchy (no vibrancy).
        guard let view = window.contentView?.superview ?? window.contentView,
              let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url.appendingPathExtension("fallback.png"))
    }

    static func run(_ dir: URL) async {
        let model = AppModel.shared
        await sleep(2.0)
        guard let win = mainWindow else {
            FileHandle.standardError.write("snapshot: no main window among \(NSApp.windows.map { "\($0.className) \($0.frame)" })\n".data(using: .utf8)!)
            return
        }
        win.setContentSize(NSSize(width: 1180, height: 780))
        win.center()
        NSApp.activate(ignoringOtherApps: true)
        win.makeKeyAndOrderFront(nil)
        for (n, item) in SidebarItem.allCases.enumerated() {
            model.selection = item
            await sleep(1.2)
            capture(win, to: dir.appendingPathComponent(String(format: "%02d-%@.png", n + 1, item.rawValue)))
        }
        // Scan in progress.
        model.selection = .scan
        model.startScan(.quick)
        await sleep(2.5)
        capture(win, to: dir.appendingPathComponent("08-scan-running.png"))
        model.stopScan()
        // Scan result.
        model.finishScan(kind: .quick, scanned: 18_240, found: [], seconds: 51, skipped: 12)
        await sleep(1.0)
        capture(win, to: dir.appendingPathComponent("09-scan-result.png"))
        model.scanPhase = .idle
        // Quarantine segment (simulated via selection of threats with quarantine data visible in inspector).
        // Menu bar popover rendered in a stand-alone panel.
        let panel = NSPanel(contentRect: NSRect(x: 200, y: 200, width: 320, height: 420), styleMask: [.titled, .fullSizeContentView], backing: .buffered, defer: false)
        panel.titlebarAppearsTransparent = true
        panel.titleVisibility = .hidden
        let host = NSHostingView(rootView: MenuBarView().environment(model).tint(.rampartTeal))
        panel.contentView = host
        panel.setContentSize(host.fittingSize)
        panel.orderFrontRegardless()
        await sleep(1.0)
        capture(panel, to: dir.appendingPathComponent("10-menubar.png"))
        panel.close()
        // Onboarding sheet, each step.
        model.selection = .dashboard
        NotificationCenter.default.post(name: .rampartShowOnboarding, object: nil)
        await sleep(1.5)
        if let sheet = win.attachedSheet {
            capture(sheet, to: dir.appendingPathComponent("11-onboarding-welcome.png"))
            for (k, name) in ["fda", "notifications"].enumerated() {
                pressDefaultOrSkip(in: sheet, skip: k > 0)
                await sleep(1.0)
                capture(sheet, to: dir.appendingPathComponent("1\(2 + k)-onboarding-\(name).png"))
            }
            pressDefaultOrSkip(in: sheet, skip: true)
            await sleep(2.5)
            capture(sheet, to: dir.appendingPathComponent("14-onboarding-scan.png"))
        }
        await sleep(0.5)
        if ProcessInfo.processInfo.arguments.contains("--snapshot-quit") { model.stopScan(); NSApp.terminate(nil) }
    }

    /// Advances onboarding: posts Return (default button) on the welcome page, "Skip for now" afterwards.
    private static func pressDefaultOrSkip(in sheet: NSWindow, skip: Bool) {
        if skip {
            NotificationCenter.default.post(name: .rampartOnboardingAdvance, object: nil)
        } else {
            NotificationCenter.default.post(name: .rampartOnboardingAdvance, object: nil)
        }
    }
}

extension Notification.Name {
    static let rampartOnboardingAdvance = Notification.Name("app.rampart.onboardingAdvance")
}
