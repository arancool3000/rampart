import SwiftUI
import AppKit
import Darwin

/// `--headless-check [seconds]` runs the real app/scene graph invisibly and reports CPU and memory, then exits.
/// No activation, no Dock icon, no menu bar item, no visible window, never key.
/// `--render-ui <dir>` (with --headless-check) also renders every screen to PNG offscreen.
enum Headless {
    static let active = CommandLine.arguments.contains("--headless-check")
    static var seconds: Double {
        let a = CommandLine.arguments
        if let i = a.firstIndex(of: "--headless-check"), i + 1 < a.count, let s = Double(a[i + 1]) { return s }
        return 30
    }
    static var renderDir: URL? {
        let a = CommandLine.arguments
        guard let i = a.firstIndex(of: "--render-ui"), i + 1 < a.count else { return nil }
        return URL(fileURLWithPath: a[i + 1])
    }
}

enum ProcStats {
    /// User + system CPU seconds of this process.
    static func cpuSeconds() -> Double {
        var u = rusage(); getrusage(RUSAGE_SELF, &u)
        return Double(u.ru_utime.tv_sec) + Double(u.ru_utime.tv_usec) / 1e6 + Double(u.ru_stime.tv_sec) + Double(u.ru_stime.tv_usec) / 1e6
    }
    /// Peak resident set size, MB (ru_maxrss is bytes on macOS).
    static func peakRSSMB() -> Double { var u = rusage(); getrusage(RUSAGE_SELF, &u); return Double(u.ru_maxrss) / 1_048_576 }
    /// Current physical footprint, MB.
    static func footprintMB() -> Double {
        var info = task_vm_info_data_t()
        var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
        }
        return kr == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : 0
    }
}

@MainActor
enum HeadlessRunner {
    private static var hostWindows: [NSWindow] = []

    /// Window-server metadata only (no pixels): proves nothing of ours is on screen.
    static func logOnscreenWindows() {
        let pid = ProcessInfo.processInfo.processIdentifier
        let list = (CGWindowListCopyWindowInfo([.optionOnScreenOnly], kCGNullWindowID) as? [[String: Any]]) ?? []
        let mine = list.filter { ($0[kCGWindowOwnerPID as String] as? Int32) == pid }
        let desc = mine.map { w -> String in
            let b = w[kCGWindowBounds as String] as? [String: Any] ?? [:]
            return "#\(w[kCGWindowNumber as String] ?? 0) layer=\(w[kCGWindowLayer as String] ?? 0) alpha=\(w[kCGWindowAlpha as String] ?? 0) \(b["X"] ?? 0),\(b["Y"] ?? 0) \(b["Width"] ?? 0)x\(b["Height"] ?? 0)"
        }
        let ns = NSApp.windows.filter(\.isVisible).map { "\($0.windowNumber):\(type(of: $0)) alpha=\($0.alphaValue)" }
        log("headless-check: onscreen windows owned by this process: \(mine.count) \(desc) visibleNSWindows=\(ns); activation policy=\(NSApp.activationPolicy().rawValue) active=\(NSApp.isActive)")
    }

    static func log(_ s: String) { FileHandle.standardOutput.write((s + "\n").data(using: .utf8)!) }

    /// Keeps any window SwiftUI creates invisible, offscreen and non-key.
    static func hide(_ w: NSWindow) {
        w.alphaValue = 0
        w.ignoresMouseEvents = true
        w.setFrameOrigin(NSPoint(x: -30_000, y: -30_000))
        w.orderOut(nil)
    }

    static func installWindowGuard() {
        for name in [NSWindow.didUpdateNotification, NSWindow.didBecomeKeyNotification, NSWindow.didBecomeMainNotification, NSWindow.didChangeOcclusionStateNotification] {
            NotificationCenter.default.addObserver(forName: name, object: nil, queue: .main) { n in
                MainActor.assumeIsolated {
                    if let w = n.object as? NSWindow, !hostWindows.contains(where: { $0 === w }), w.alphaValue != 0 || w.isVisible { hide(w) }
                }
            }
        }
    }

    /// Hosts a view in a borderless window that is never ordered onscreen.
    static func host<V: View>(_ view: V, size: NSSize, dark: Bool? = nil) -> (NSWindow, NSView) {
        let w = NSWindow(contentRect: NSRect(origin: NSPoint(x: -30_000, y: -30_000), size: size), styleMask: [.borderless], backing: .buffered, defer: false)
        w.alphaValue = 0
        w.ignoresMouseEvents = true
        w.isReleasedWhenClosed = false
        if let dark { w.appearance = NSAppearance(named: dark ? .darkAqua : .aqua) }
        let hv = NSHostingView(rootView: view)
        hv.frame = NSRect(origin: .zero, size: size)
        if let dark { hv.appearance = NSAppearance(named: dark ? .darkAqua : .aqua) }
        w.contentView = hv
        hostWindows.append(w)
        return (w, hv)
    }

    static func run() async {
        let model = AppModel.shared
        for w in NSApp.windows where !hostWindows.contains(where: { $0 === w }) { hide(w) }
        let total = Headless.seconds
        let t0 = Date(), c0 = ProcStats.cpuSeconds()
        log("headless-check: start, \(Int(total)) s, mode=\(model.mode), footprint=\(String(format: "%.1f", ProcStats.footprintMB())) MB")
        // The real main view tree, hosted offscreen so it reacts to model changes like the real window would.
        let (_, _) = host(MenuBarView().environment(model).tint(.rampartTeal), size: NSSize(width: 340, height: 480))

        if let dir = Headless.renderDir { await UIRenderer.renderAll(to: dir) }
        logOnscreenWindows()

        func sleep(_ s: Double) async { try? await Task.sleep(nanoseconds: UInt64(s * 1e9)) }
        var samples: [(t: Double, cpu: Double, mb: Double)] = []
        var scanDone = false
        var scanEndedAt: Double?
        var lastC = ProcStats.cpuSeconds(), lastT = Date()
        while Date().timeIntervalSince(t0) < total {
            await sleep(1)
            let el = Date().timeIntervalSince(t0)
            if el >= 3, !scanDone, !model.isScanning, model.scanHistory.count < 50 {
                if case .idle = model.scanPhase { log("headless-check: starting simulated Quick Scan at \(Int(el)) s"); model.selection = .scan; model.startScan(.quick) }
                scanDone = true
            }
            if scanEndedAt == nil, scanDone, !model.isScanning { scanEndedAt = el }
            if case .finished = model.scanPhase, el > 12 {
                model.scanPhase = .idle; model.selection = .dashboard
                // Worst-case run: resolve the demo threat so the hero shows its calm, breathing state.
                if AnimationGate.shared.forced { for i in model.detections.indices { model.detections[i].resolved = true } }
            }
            let c = ProcStats.cpuSeconds(), now = Date()
            let pct = (c - lastC) / now.timeIntervalSince(lastT) * 100
            lastC = c; lastT = now
            let mb = ProcStats.footprintMB()
            samples.append((el, pct, mb))
            log(String(format: "  t=%5.1fs cpu=%6.1f%% footprint=%7.1f MB%@", el, pct, mb, model.isScanning ? " (scanning)" : ""))
        }
        let elapsed = Date().timeIntervalSince(t0)
        let cpuTotal = ProcStats.cpuSeconds() - c0
        let idle = samples.filter { $0.t >= min(14, total * 0.5) }
        let idleCPU = idle.isEmpty ? 0 : idle.map(\.cpu).reduce(0, +) / Double(idle.count)
        func median(_ v: [Double]) -> Double { let s = v.sorted(); return s.isEmpty ? 0 : s[s.count / 2] }
        // Memory: settled footprint (median of the last 5 s) vs the median just after the demo scan ends
        // (5 s window), so scan churn and its release don't count as growth.
        let end = scanEndedAt ?? 0
        let mbFirst = median(samples.filter { $0.t >= end && $0.t < end + 5 }.map(\.mb))
        let mbLast = median(samples.filter { $0.t > (samples.last?.t ?? 0) - 5 }.map(\.mb))
        let settledGrowth = mbLast - mbFirst
        log(String(format: "headless-check: elapsed=%.1fs cpu_time=%.2fs avg_cpu=%.1f%% idle_cpu=%.2f%% peak_rss=%.1f MB footprint median after scan %.1f MB → settled %.1f MB",
                   elapsed, cpuTotal, cpuTotal / elapsed * 100, idleCPU, ProcStats.peakRSSMB(), mbFirst, mbLast))
        DaemonLauncher.shared.stopChild()
        let ok = idleCPU < 3 && settledGrowth < 15
        logOnscreenWindows()
        log("headless-check: \(ok ? "PASS" : "FAIL")")
        exit(ok ? 0 : 1)
    }
}

/// In headless mode, hides the hosting window the moment the view is installed, before SwiftUI orders it front.
struct HeadlessWindowHider: NSViewRepresentable {
    final class V: NSView {
        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            guard Headless.active, let w = window else { return }
            MainActor.assumeIsolated {
                HeadlessRunner.hide(w)
                DispatchQueue.main.async { HeadlessRunner.hide(w) }
            }
        }
    }
    func makeNSView(context: Context) -> V { V() }
    func updateNSView(_ nsView: V, context: Context) {}
}
