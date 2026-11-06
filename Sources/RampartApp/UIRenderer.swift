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

    static func render<V: View>(_ v: V, size: NSSize, dark: Bool, name: String, dir: URL, settle: Double = 0.5) async {
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
        for dark in [true, false] {
            for p in [0.1, 0.25, 0.4, 0.55, 0.7, 0.85, 1.0] {
                await render(ZStack { AppBackdrop(); BrandAssembly(progress: p) }, size: NSSize(width: 520, height: 340), dark: dark,
                             name: String(format: "12-splash-t%03d", Int(p * 100)), dir: dir, settle: 0.2)
            }
            await render(HStack(spacing: 24) {
                Image(nsImage: BrandImages.menuBarTemplate).renderingMode(.template).resizable().frame(width: 72, height: 72)
                RamPartMark(size: 96)
                RamPartMark(size: 96, tile: false)
                StatusMark(size: 96, badge: "checkmark.circle.fill", tint: .statusProtected)
            }.padding(24).background(AppBackdrop()), size: NSSize(width: 520, height: 160), dark: dark, name: "13-marks", dir: dir, settle: 0.2)
        }
        if CommandLine.arguments.contains("--render-wordmark-only") { HeadlessRunner.log("render-ui: wrote PNGs to \(dir.path)"); return }
        let size = NSSize(width: 1180, height: 780)
        for dark in [false, true] {
            for (i, item) in (SidebarItem.core + [.scamCheck]).enumerated() {
                model.selection = item
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark,
                             name: String(format: "%02d-%@", i + 1, item.rawValue), dir: dir)
            }
            // Scan running.
            model.selection = .scan
            if model.mode == .demo {
                model.startScan(.quick)
                await sleep(2.0)
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "08-scan-running", dir: dir, settle: 1.2)
                model.stopScan()
                model.finishScan(kind: .quick, scanned: 18_240, found: [], seconds: 51, skipped: 12)
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "09-scan-result", dir: dir)
            } else if model.mode == .live, let p = Headless.scanPath {
                // Live: a real scan of the scratch fixture folder only.
                model.startScan(.custom, paths: [p])
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "08-scan-running", dir: dir, settle: 0.3)
                for _ in 0..<100 where model.isScanning { await sleep(0.1) }
                await render(RootView().environment(model).tint(.rampartTeal), size: size, dark: dark, name: "09-scan-result", dir: dir)
            }
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
                             size: NSSize(width: 680, height: 600), dark: dark, name: "11-onboarding-\(step.rawValue)", dir: dir)
            }
        }
        HeadlessRunner.log("render-ui: wrote PNGs to \(dir.path)")
    }
}
