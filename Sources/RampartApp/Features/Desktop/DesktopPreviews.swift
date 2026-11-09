import SwiftUI
import AppKit
import RampartShared

/// Records clickable tiles' frames in headless runs so the preview harness can click them for real.
@MainActor
enum HitProbe {
    static var frames: [String: CGRect] = [:]

    struct Reporter: View {
        let id: String
        var body: some View {
            if Headless.active {
                GeometryReader { g in
                    Color.clear
                        .onAppear { HitProbe.frames[id] = g.frame(in: .global) }
                        .onChange(of: g.frame(in: .global)) { _, f in HitProbe.frames[id] = f }
                }
                .allowsHitTesting(false)
            }
        }
    }
}

/// `--headless-check N --demo --render-ui <dir> --render-desktop`: offscreen PNGs of Desktop Mode, the new
/// Overview and the launch moment, plus a real click test on every Overview tool tile. Never touches the screen.
@MainActor
enum DesktopPreviews {
    static func renderAll(to dir: URL) async {
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let model = AppModel.shared
        for _ in 0..<40 where model.mode == .connecting { await UIRenderer.sleep(0.1) }
        if CommandLine.arguments.contains("--click-only") { await clickTest(); return }

        // System samplers: two samples so CPU / network have a delta.
        DesktopInfo.shared.sample()
        await UIRenderer.sleep(1.0)
        DesktopInfo.shared.sample()
        LauncherModel.shared.loadNow()

        let desk = NSSize(width: 1512, height: 900)
        for (style, welcome) in [(DesktopBackdropStyle.tinted, false), (.glass, false), (.full, false), (.tinted, true)] {
            DesktopMode.shared.backdrop = style
            await UIRenderer.render(layer(primary: true, welcome: welcome), size: desk, dark: true,
                                    name: "desktop-\(style.rawValue)\(welcome ? "-welcome" : "")", dir: dir, settle: 1.0)
        }
        DesktopMode.shared.backdrop = .tinted
        await UIRenderer.render(layer(primary: false, welcome: false), size: NSSize(width: 1100, height: 760), dark: true,
                                name: "desktop-secondary", dir: dir, settle: 0.8)

        for p in [0.0, 0.2, 0.4, 0.55, 0.7, 0.85, 1.0] {
            await UIRenderer.render(ZStack { AppBackdrop(); PixelLaunchAssembly(progress: p) }, size: NSSize(width: 520, height: 360), dark: true,
                                    name: String(format: "splash-t%03d", Int(p * 100)), dir: dir, settle: 0.15)
        }

        model.selection = .dashboard
        for dark in [false, true] {
            await UIRenderer.render(RootView().environment(model).tint(.rampartTeal), size: NSSize(width: 1240, height: 1500), dark: dark,
                                    name: "dashboard", dir: dir, settle: 1.6)
        }
        await clickTest()
        HeadlessRunner.log("render-desktop: wrote PNGs to \(dir.path)")
    }

    private static func layer(primary: Bool, welcome: Bool) -> some View {
        ZStack {
            FakeWallpaper()
            DesktopBackdropView()
            DesktopLayerView(screenNumber: 0, primary: primary, welcomeOverride: welcome)
        }
        .environment(AppModel.shared)
        .environment(DesktopMode.shared)
        .environment(\.colorScheme, .dark)
        .tint(.rampartTeal)
    }

    /// Clicks the centre of every Overview tool tile (synthetic mouse down/up sent to the offscreen window)
    /// and checks the tile's action ran. Catches tiles that render but don't take clicks.
    static func clickTest() async {
        // Control: a plain SwiftUI button in the same kind of window must take a synthetic click,
        // otherwise the harness itself can't deliver clicks and the tile result means nothing.
        var controlHit = false
        do {
            let (w, _) = HeadlessRunner.host(Button { controlHit = true } label: { Color.gray.frame(width: 200, height: 100) }.buttonStyle(.plain),
                                             size: NSSize(width: 200, height: 100), dark: true)
            await UIRenderer.sleep(0.4)
            await click(w, NSPoint(x: 100, y: 50))
            HeadlessRunner.log("render-desktop: control button click \(controlHit ? "delivered" : "NOT delivered")")
            w.contentView = nil; w.close()
        }
        let model = AppModel.shared
        model.selection = .dashboard
        HitProbe.frames = [:]
        let size = NSSize(width: 1000, height: 1600)
        let (w, hv) = HeadlessRunner.host(DashboardView().environment(model).tint(.rampartTeal).frame(width: size.width, height: size.height),
                                          size: size, dark: true)
        await UIRenderer.sleep(1.2)
        hv.layoutSubtreeIfNeeded()
        var ok = 0, bad: [String] = []
        for (id, f) in HitProbe.frames.sorted(by: { $0.key < $1.key }) {
            guard let item = SidebarItem(rawValue: id) else { continue }   // Desktop Mode tile only toggles; skipped headless
            model.selection = .dashboard
            await UIRenderer.sleep(0.05)
            await click(w, NSPoint(x: f.midX, y: size.height - f.midY))
            await UIRenderer.sleep(0.05)
            if model.selection == item { ok += 1 } else { bad.append(id) }
        }
        model.selection = .dashboard
        HeadlessRunner.log("render-desktop: tile click test \(ok)/\(ok + bad.count) tiles respond\(bad.isEmpty ? "" : "; NOT clickable: \(bad.joined(separator: ", "))")")
        w.contentView = nil
        w.close()
    }

    /// Synthetic click delivered straight to the view AppKit hit-tests at `p` (the window is never on screen,
    /// so the window server can't route it). This exercises SwiftUI's own hit-testing inside the hosting view.
    private static func click(_ w: NSWindow, _ p: NSPoint) async {
        w.ignoresMouseEvents = false
        guard let root = w.contentView, let target = root.hitTest(root.convert(p, from: nil)) else { return }
        for type in [NSEvent.EventType.leftMouseDown, .leftMouseUp] {
            if let e = NSEvent.mouseEvent(with: type, location: p, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime,
                                          windowNumber: w.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: type == .leftMouseDown ? 1 : 0) {
                type == .leftMouseDown ? target.mouseDown(with: e) : target.mouseUp(with: e)
            }
            await UIRenderer.sleep(0.05)
        }
    }
}

/// A stand-in wallpaper for previews (the real one is whatever the user has).
private struct FakeWallpaper: View {
    var body: some View {
        ZStack {
            LinearGradient(colors: [Color(red: 0.30, green: 0.22, blue: 0.55), Color(red: 0.95, green: 0.45, blue: 0.40), Color(red: 0.98, green: 0.75, blue: 0.45)],
                           startPoint: .topLeading, endPoint: .bottomTrailing)
            Circle().fill(Color(red: 0.2, green: 0.6, blue: 0.9).opacity(0.55)).frame(width: 700).blur(radius: 120).offset(x: -300, y: 250)
            Circle().fill(Color.white.opacity(0.25)).frame(width: 500).blur(radius: 100).offset(x: 420, y: -260)
        }
        .ignoresSafeArea()
    }
}
