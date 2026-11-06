import SwiftUI
import AppKit
import RampartShared

/// Offscreen visual QA for `--headless-check N --render-ui <dir>`: hosts views in windows that are never
/// ordered onscreen and rasterises them with cacheDisplay. No screen capture of any kind.
@MainActor
enum UIRenderer {
    static func sleep(_ s: Double) async { try? await Task.sleep(nanoseconds: UInt64(s * 1e9)) }

    static func snapshot(_ view: NSView, to url: URL) {
        view.layoutSubtreeIfNeeded()
        guard let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) else { return }
        view.cacheDisplay(in: view.bounds, to: rep)
        try? rep.representation(using: .png, properties: [:])?.write(to: url)
    }

    static func render<V: View>(_ v: V, size: NSSize, dark: Bool, name: String, dir: URL, settle: Double = 0.8) async {
        let (w, hv) = HeadlessRunner.host(v.environment(\.colorScheme, dark ? .dark : .light).environment(\.controlActiveState, .key), size: size, dark: dark)
        await sleep(settle)
        snapshot(hv, to: dir.appendingPathComponent("\(name)-\(dark ? "dark" : "light").png"))
        w.contentView = nil
        w.close()
    }

    static func renderAll(to dir: URL) async {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = AppModel.shared
        // Wait for demo/live data.
        for _ in 0..<40 where model.mode == .connecting { await sleep(0.1) }
        let size = NSSize(width: 1180, height: 780)
        for dark in [false, true] {
            for (i, item) in SidebarItem.allCases.enumerated() {
                model.selection = item
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark,
                             name: String(format: "%02d-%@", i + 1, item.rawValue), dir: dir)
            }
            // Scan running.
            model.selection = .scan
            model.startScan(.quick)
            await sleep(2.0)
            await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "08-scan-running", dir: dir, settle: 1.2)
            model.stopScan()
            model.finishScan(kind: .quick, scanned: 18_240, found: [], seconds: 51, skipped: 12)
            await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "09-scan-result", dir: dir)
            model.scanPhase = .idle
            model.selection = .dashboard
            await render(NavigationStack { MenuBarView() }.environment(model).tint(.rampartTeal), size: NSSize(width: 330, height: 470), dark: dark, name: "10-menubar", dir: dir)
            if CommandLine.arguments.contains("--render-debug") {
                await render(AppBackdrop(), size: NSSize(width: 200, height: 120), dark: dark, name: "dbg-backdrop", dir: dir)
                await render(ShieldHero(symbol: "checkmark.shield.fill", tint: .green, size: 80), size: NSSize(width: 120, height: 120), dark: dark, name: "dbg-shield", dir: dir)
                await render(Text("Card text").card(), size: NSSize(width: 200, height: 120), dark: dark, name: "dbg-card", dir: dir)
                await render(VStack { Text("Plain"); Text("Card").card() }.padding().background(AppBackdrop()), size: NSSize(width: 200, height: 160), dark: dark, name: "dbg-combo", dir: dir)
                await render(VStack { Text("With menu").card(); Menu("Menu") { Button("A") {} }.menuStyle(.borderlessButton) }.padding().background(AppBackdrop()), size: NSSize(width: 200, height: 160), dark: dark, name: "dbg-menu", dir: dir)
            }
            for step in OnboardingView.Step.allCases where step != .firstScan {
                await render(OnboardingView(onFinish: {}, initialStep: step).environment(model).tint(.rampartTeal),
                             size: NSSize(width: 640, height: 520), dark: dark, name: "11-onboarding-\(step.rawValue)", dir: dir)
            }
        }
        HeadlessRunner.log("render-ui: wrote PNGs to \(dir.path)")
    }
}
