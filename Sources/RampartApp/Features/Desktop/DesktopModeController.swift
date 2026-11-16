import SwiftUI
import AppKit
import Carbon.HIToolbox
import RampartShared

/// How much of the wallpaper Desktop Mode keeps.
enum DesktopBackdropStyle: String, CaseIterable, Identifiable {
    case glass, tinted, full
    var id: String { rawValue }
    var title: String {
        switch self { case .glass: return "Wallpaper"; case .tinted: return "Tinted"; case .full: return "\(Product.name) backdrop" }
    }
}

/// Desktop Mode: a full-screen RamPart layer at desktop level (above the wallpaper, below every app window),
/// on every Space and every display.
///
/// Two windows per display:
/// - a **backdrop** just above the wallpaper and *below* Finder's desktop icons (never takes clicks), and
/// - a **widget layer** just above the desktop icons. It ignores the mouse everywhere except over a widget,
///   so clicking empty desktop space reaches Finder (icons, selection rectangles, right-click) as usual.
///   Icons that sit under a widget are covered; the welcome card and Settings say so.
///
/// Nothing here asks macOS for anything: no Accessibility, no Apple Events, no system dialog. The shortcut is a
/// Carbon hot key (no permission needed) and mouse tracking uses mouse-move monitors (no permission needed).
@MainActor
@Observable
final class DesktopMode {
    static let shared = DesktopMode()

    static let enabledKey = "desktop.enabled"
    static let askedKey = "desktop.asked"
    static let welcomeKey = "desktop.welcomeSeen"
    static let backdropKey = "desktop.backdrop"
    static let allDisplaysKey = "desktop.allDisplays"
    static let shortcutLabel = "⌃⌥⌘D"

    private(set) var isOn: Bool
    /// True while at least one layer is on screen, not fully covered, and the displays are awake.
    private(set) var visible = false
    var backdrop: DesktopBackdropStyle {
        didSet { if !Headless.active { UserDefaults.standard.set(backdrop.rawValue, forKey: Self.backdropKey) } }
    }
    var allDisplays: Bool {
        didSet { if !Headless.active { UserDefaults.standard.set(allDisplays, forKey: Self.allDisplaysKey) }; if isOn { rebuild() } }
    }
    var welcomeSeen: Bool {
        didSet {
            if !Headless.active { UserDefaults.standard.set(welcomeSeen, forKey: Self.welcomeKey) }
            if welcomeSeen { closeWelcome() }
        }
    }
    @ObservationIgnored private var welcomePanel: NSPanel?

    /// Set by a SwiftUI view that has `openWindow` (RootView / menu bar), so the desktop can bring the main window back.
    @ObservationIgnored var openMainHandler: (() -> Void)?

    @ObservationIgnored private var layers: [Layer] = []
    @ObservationIgnored private var monitors: [Any] = []
    /// The apps panel stays hidden so the backdrop shows; the search bar or its Apps button opens it.
    var launcherOpen = false
    /// Stage Manager keeps recent windows in a strip on the left; widgets move right so they don't sit under it.
    var stageManagerOn = false
    static func readStageManager() -> Bool {
        CFPreferencesCopyAppValue("GloballyEnabled" as CFString, "com.apple.WindowManager" as CFString) as? Bool ?? false
    }
    @ObservationIgnored private var observers: [NSObjectProtocol] = []
    @ObservationIgnored private var displaysAwake = true
    @ObservationIgnored private var hotKey: EventHotKeyRef?
    @ObservationIgnored private var started = false

    private init() {
        let d = UserDefaults.standard
        isOn = !Headless.active && d.bool(forKey: Self.enabledKey)
        backdrop = DesktopBackdropStyle(rawValue: d.string(forKey: Self.backdropKey) ?? "") ?? .full
        allDisplays = d.object(forKey: Self.allDisplaysKey) as? Bool ?? true
        welcomeSeen = d.bool(forKey: Self.welcomeKey)
    }

    // MARK: Public

    /// App launch: registers the shortcut and restores the layer if the user left it on.
    func start() {
        guard !started, !Headless.active else { return }
        started = true
        registerHotKey()
        if isOn { show() } else { DesktopCleaner.restoreIfNeeded() }   // RamPart quit while Desktop Mode was on
        NotificationCenter.default.addObserver(forName: NSApplication.willTerminateNotification, object: nil, queue: .main) { _ in
            DesktopCleaner.restoreIfNeeded()
        }
    }

    func toggle() { setOn(!isOn) }

    func setOn(_ on: Bool) {
        guard !Headless.active else { return }
        UserDefaults.standard.set(true, forKey: Self.askedKey)
        UserDefaults.standard.set(on, forKey: Self.enabledKey)
        guard on != isOn else { return }
        isOn = on
        on ? show() : hide()
    }

    /// Brings the main RamPart window forward on `item` (quick actions, features from search).
    func openMain(_ item: SidebarItem? = nil) {
        if let item { AppModel.shared.selection = item }
        guard !Headless.active else { return }
        let showDock = UserDefaults.standard.object(forKey: "general.showDock") as? Bool ?? true
        if showDock { NSApp.setActivationPolicy(.regular) }
        if let h = openMainHandler { h(); NSApp.activate(ignoringOtherApps: true) } else { AppDelegate.revealMainWindow() }
    }

    /// Widget frames (top-left coordinates inside the layer) reported by the SwiftUI layout.
    func setHitRects(_ rects: [CGRect], for screen: Int) {
        layers.first { $0.screenNumber == screen }?.rects = rects
    }

    // MARK: Windows

    private final class Layer {
        let screenNumber: Int
        let backdrop: NSWindow
        let widgets: DesktopPanel
        var rects: [CGRect] = []
        init(screenNumber: Int, backdrop: NSWindow, widgets: DesktopPanel) { self.screenNumber = screenNumber; self.backdrop = backdrop; self.widgets = widgets }
    }

    static let backdropLevel = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.desktopWindow)) + 1)
    static let widgetLevel = NSWindow.Level(rawValue: Int(CGWindowLevelForKey(.desktopIconWindow)) + 1)

    private func show() {
        stageManagerOn = Self.readStageManager()
        DesktopCleaner.apply()   // hide Finder's desktop files and macOS widgets: only RamPart's layer shows
        rebuild()
        installTracking()
        recomputeVisible()
    }

    private func hide() {
        DesktopCleaner.restoreIfNeeded()
        for l in layers { l.widgets.orderOut(nil); l.backdrop.orderOut(nil); l.widgets.contentView = nil; l.backdrop.contentView = nil }
        layers = []
        closeWelcome()
        for m in monitors { NSEvent.removeMonitor(m) }
        monitors = []
        for o in observers { NotificationCenter.default.removeObserver(o); NSWorkspace.shared.notificationCenter.removeObserver(o) }
        observers = []
        recomputeVisible()
    }

    private func rebuild() {
        for l in layers { l.widgets.orderOut(nil); l.backdrop.orderOut(nil) }
        layers = []
        guard isOn else { return }
        let screens = allDisplays ? NSScreen.screens : Array(NSScreen.screens.prefix(1))
        for (i, s) in screens.enumerated() {
            let num = (s.deviceDescription[NSDeviceDescriptionKey("NSScreenNumber")] as? NSNumber)?.intValue ?? i
            let primary = i == 0
            let back = NSWindow(contentRect: s.frame, styleMask: [.borderless], backing: .buffered, defer: false)
            configure(back, level: Self.backdropLevel)
            back.ignoresMouseEvents = true
            back.contentView = NSHostingView(rootView: DesktopBackdropView().environment(self))
            back.setFrame(s.frame, display: false)

            // The widget layer avoids the menu bar and the Dock.
            let panel = DesktopPanel(contentRect: s.visibleFrame, styleMask: [.borderless, .nonactivatingPanel], backing: .buffered, defer: false)
            configure(panel, level: Self.widgetLevel)
            panel.ignoresMouseEvents = true
            panel.acceptsMouseMovedEvents = true
            panel.becomesKeyOnlyIfNeeded = true
            let root = DesktopLayerView(screenNumber: num, primary: primary)
                .environment(AppModel.shared)
                .environment(self)
                .environment(\.colorScheme, .dark)
                .tint(.rampartTeal)
            panel.contentView = FirstMouseHostingView(rootView: root)
            panel.setFrame(s.visibleFrame, display: false)
            back.orderFront(nil)
            panel.orderFront(nil)
            layers.append(Layer(screenNumber: num, backdrop: back, widgets: panel))
        }
        if !welcomeSeen { showWelcome() }
    }

    /// The welcome card gets its own normal-level window, centred on the main screen: inside the desktop layer it
    /// sat below macOS's own desktop widgets (Calendar, Clock…), which covered half of it.
    private func showWelcome() {
        guard welcomePanel == nil, !Headless.active, let screen = NSScreen.main ?? NSScreen.screens.first else { return }
        // Margin so the card's soft shadow isn't clipped into a hard rectangle at the window edge.
        let host = FirstMouseHostingView(rootView: DesktopWelcomeCard().frame(width: 560).padding(40).environment(self)
            .environment(\.colorScheme, .dark).tint(.rampartTeal))
        host.wantsLayer = true; host.layer?.backgroundColor = .clear
        let size = host.fittingSize
        let vf = screen.visibleFrame
        let p = NSPanel(contentRect: NSRect(x: vf.midX - size.width / 2, y: vf.midY - size.height / 2, width: size.width, height: size.height),
                        styleMask: [.borderless], backing: .buffered, defer: false)
        p.isOpaque = false; p.backgroundColor = .clear; p.hasShadow = false
        p.isReleasedWhenClosed = false; p.level = .normal; p.isMovableByWindowBackground = true
        p.collectionBehavior = [.moveToActiveSpace, .fullScreenNone]
        p.contentView = host
        p.orderFrontRegardless()
        welcomePanel = p
    }
    private func closeWelcome() { welcomePanel?.orderOut(nil); welcomePanel = nil }

    private func configure(_ w: NSWindow, level: NSWindow.Level) {
        w.level = level
        w.isOpaque = false
        w.backgroundColor = .clear
        w.hasShadow = false
        w.isReleasedWhenClosed = false
        w.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle, .fullScreenNone]
        w.animationBehavior = .none
        w.identifier = NSUserInterfaceItemIdentifier("rampart.desktop")
    }

    // MARK: Click-through, visibility

    private func installTracking() {
        guard monitors.isEmpty else { return }
        let types: NSEvent.EventTypeMask = [.mouseMoved, .leftMouseDragged, .rightMouseDragged]
        if let g = NSEvent.addGlobalMonitorForEvents(matching: types, handler: { _ in
            MainActor.assumeIsolated { DesktopMode.shared.updatePassThrough() }
        }) { monitors.append(g) }
        if let l = NSEvent.addLocalMonitorForEvents(matching: types, handler: { e in
            MainActor.assumeIsolated { DesktopMode.shared.updatePassThrough() }
            return e
        }) { monitors.append(l) }

        let nc = NotificationCenter.default, ws = NSWorkspace.shared.notificationCenter
        observers.append(nc.addObserver(forName: NSApplication.didChangeScreenParametersNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { DesktopMode.shared.rebuild(); DesktopMode.shared.recomputeVisible() }
        })
        observers.append(nc.addObserver(forName: NSWindow.didChangeOcclusionStateNotification, object: nil, queue: .main) { _ in
            MainActor.assumeIsolated { DesktopMode.shared.recomputeVisible() }
        })
        for (name, awake) in [(NSWorkspace.screensDidSleepNotification, false), (NSWorkspace.screensDidWakeNotification, true),
                              (NSWorkspace.sessionDidResignActiveNotification, false), (NSWorkspace.sessionDidBecomeActiveNotification, true)] {
            observers.append(ws.addObserver(forName: name, object: nil, queue: .main) { _ in
                MainActor.assumeIsolated { DesktopMode.shared.displaysAwake = awake; DesktopMode.shared.recomputeVisible() }
            })
        }
    }

    private func updatePassThrough() {
        let p = NSEvent.mouseLocation
        for l in layers {
            let f = l.widgets.frame
            let accept = f.contains(p) && DesktopHitRegions.accepts(DesktopHitRegions.toTopLeft(p, frame: f), in: l.rects)
            if l.widgets.ignoresMouseEvents == accept { l.widgets.ignoresMouseEvents = !accept }
        }
    }

    private func recomputeVisible() {
        let v = isOn && displaysAwake && layers.contains { $0.widgets.isVisible && $0.widgets.occlusionState.contains(.visible) }
        if v != visible { visible = v }
        DesktopInfo.shared.setActive(v)
        if v { LauncherModel.shared.refreshIfStale() }
    }

    // MARK: Shortcut (⌃⌥⌘D, Carbon hot key: works while another app is in front, needs no permission)

    nonisolated static let hotKeySignature = OSType(0x52_4D_50_44)   // 'RMPD'

    private func registerHotKey() {
        var spec = EventTypeSpec(eventClass: OSType(kEventClassKeyboard), eventKind: UInt32(kEventHotKeyPressed))
        InstallEventHandler(GetApplicationEventTarget(), { _, event, _ in
            var hk = EventHotKeyID()
            GetEventParameter(event, EventParamName(kEventParamDirectObject), EventParamType(typeEventHotKeyID), nil,
                              MemoryLayout<EventHotKeyID>.size, nil, &hk)
            guard hk.signature == DesktopMode.hotKeySignature else { return OSStatus(eventNotHandledErr) }   // someone else's hot key
            DispatchQueue.main.async { MainActor.assumeIsolated { DesktopMode.shared.toggle() } }
            return noErr
        }, 1, &spec, nil, nil)
        let id = EventHotKeyID(signature: Self.hotKeySignature, id: 1)
        RegisterEventHotKey(UInt32(kVK_ANSI_D), UInt32(controlKey | optionKey | cmdKey), id, GetApplicationEventTarget(), 0, &hotKey)
    }
}

/// Borderless, non-activating panel that can still take typing (the search field) without bringing
/// RamPart's other windows forward.
final class DesktopPanel: NSPanel {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { false }
}

/// The first click on a widget acts immediately (no "click once to focus").
final class FirstMouseHostingView<Content: View>: NSHostingView<Content> {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}
