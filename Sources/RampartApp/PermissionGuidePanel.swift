import SwiftUI
import AppKit
import RampartShared

/// A small floating hint shown beside System Settings after we open Full Disk Access.
/// Non-activating, joins all spaces, ignores the mouse except for its own buttons.
/// Never shown in headless/test runs (ZERO POP-UPS RULE). Closes itself once access is detected.
@MainActor
final class PermissionGuidePanel {
    static let shared = PermissionGuidePanel()
    private var panel: NSPanel?
    private let state = GuideState()

    @MainActor @Observable final class GuideState { var done = false }

    var isShowing: Bool { panel != nil }

    func show() {
        guard !Headless.active, Bundle.main.bundleIdentifier != nil else { return }
        state.done = false
        if panel == nil {
            let p = NSPanel(contentRect: NSRect(x: 0, y: 0, width: 320, height: 250),
                            styleMask: [.nonactivatingPanel, .borderless], backing: .buffered, defer: true)
            p.level = .floating
            p.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
            p.isFloatingPanel = true
            p.hidesOnDeactivate = false
            p.becomesKeyOnlyIfNeeded = true
            p.isOpaque = false
            p.backgroundColor = .clear
            p.hasShadow = true
            p.isReleasedWhenClosed = false
            let host = NSHostingView(rootView: PermissionGuideView(state: state,
                                                                   close: { [weak self] in self?.close() },
                                                                   reveal: { NSWorkspace.shared.activateFileViewerSelecting([Bundle.main.bundleURL]) }))
            p.contentView = host
            p.setContentSize(host.fittingSize)
            panel = p
        }
        position()
        panel?.orderFrontRegardless()
        // System Settings may take a moment to open; re-place once it has.
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in self?.position() }
    }

    /// Called when access is detected: show a tick briefly, then close.
    func finish() {
        guard panel != nil, !state.done else { return }
        state.done = true
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.6) { [weak self] in self?.close() }
    }

    func close() { panel?.orderOut(nil); panel = nil }

    private func position() {
        guard let panel else { return }
        let size = panel.frame.size
        let screen = NSScreen.main ?? NSScreen.screens.first
        let primaryHeight = NSScreen.screens.first?.frame.height ?? 0
        var origin: NSPoint?
        // Window bounds (not contents) are readable without Screen Recording permission.
        if let list = CGWindowListCopyWindowInfo([.optionOnScreenOnly, .excludeDesktopElements], kCGNullWindowID) as? [[String: Any]],
           let w = list.first(where: { ($0[kCGWindowOwnerName as String] as? String) == "System Settings" && ($0[kCGWindowLayer as String] as? Int) == 0 }),
           let b = w[kCGWindowBounds as String] as? [String: CGFloat],
           let x = b["X"], let y = b["Y"], let width = b["Width"], let h = b["Height"] {
            let flippedY = primaryHeight - y - h       // CG is top-left origin; AppKit is bottom-left
            var px = x + width + 12
            if let vf = screen?.visibleFrame, px + size.width > vf.maxX { px = x - size.width - 12 }
            origin = NSPoint(x: px, y: flippedY + h - size.height - 60)
        }
        if origin == nil, let vf = screen?.visibleFrame {
            origin = NSPoint(x: vf.maxX - size.width - 24, y: vf.maxY - size.height - 24)
        }
        if let origin { panel.setFrameOrigin(origin) }
    }
}

private struct PermissionGuideView: View {
    let state: PermissionGuidePanel.GuideState
    let close: () -> Void
    let reveal: () -> Void
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @StateVar private var nudge = false
    @StateVar private var toggleOn = false

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 28, height: 28)
                Text(state.done ? "All set" : "Turn on Full Disk Access").font(.headline)
                Spacer()
                Button(action: close) { Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary) }
                    .buttonStyle(.plain).help("Close").accessibilityLabel("Close")
            }
            if state.done {
                HStack(spacing: 8) {
                    Image(systemName: "checkmark.circle.fill").font(.title).foregroundStyle(Color.statusProtected)
                    Text("\(Product.name) now has Full Disk Access.").font(.callout)
                }
                .transition(.opacity)
            } else {
                HStack(spacing: 6) {
                    Image(systemName: "arrow.left").font(.title2.weight(.bold)).foregroundStyle(Color.rampartTeal)
                        .offset(x: nudge ? -6 : 0)
                        .accessibilityHidden(true)
                    Text("Find \(Product.name) in the list (it's in alphabetical order, under R) and turn on its switch.")
                        .font(.callout).fixedSize(horizontal: false, vertical: true)
                }
                row
                Divider()
                Text("Not listed? Click + and choose \(Product.name) from Applications.")
                    .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                Button("Show \(Product.name) in Finder", action: reveal).controlSize(.small)
                    .help("Reveals the app so you can drag it into the list")
            }
        }
        .padding(14)
        .frame(width: 300)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 12))
        .overlay(RoundedRectangle(cornerRadius: 12).stroke(.quaternary))
        .animation(reduceMotion ? nil : .easeInOut(duration: 0.25), value: state.done)
        .onAppear {
            guard !reduceMotion else { toggleOn = true; return }
            // Finite loops only: a few nudges and one toggle animation.
            withAnimation(.easeInOut(duration: 0.5).repeatCount(6, autoreverses: true)) { nudge = true }
            withAnimation(.spring(response: 0.4, dampingFraction: 0.7).delay(0.6)) { toggleOn = true }
        }
    }

    private var row: some View {
        HStack(spacing: 8) {
            Image(nsImage: NSApp.applicationIconImage).resizable().frame(width: 18, height: 18)
            Text(Product.name).font(.callout)
            Spacer()
            Capsule().fill(toggleOn ? Color.accentColor : Color.secondary.opacity(0.35))
                .frame(width: 30, height: 17)
                .overlay(alignment: toggleOn ? .trailing : .leading) {
                    Circle().fill(.white).frame(width: 15, height: 15).padding(1).shadow(radius: 0.5)
                }
        }
        .padding(.horizontal, 8).padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 6).fill(.quaternary.opacity(0.6)))
        .overlay(RoundedRectangle(cornerRadius: 6).stroke(Color.rampartTeal, lineWidth: 1.5))
        .accessibilityElement(children: .ignore)
        .accessibilityLabel("\(Product.name) row with its switch turned on")
    }
}

/// One click: open System Settings › Full Disk Access, show the floating guide, and close it automatically
/// (with a tick) as soon as RamPart has access. macOS does not allow any app to grant itself Full Disk Access;
/// this gets the user to the single switch they need to turn on.
@MainActor
enum FullDiskAccessRequest {
    private static var timer: Timer?
    static func start() {
        guard !Headless.active else { return }
        if FDAProbe.check() { return }
        NSWorkspace.shared.open(FDAProbe.settingsURL)
        PermissionGuidePanel.shared.show()
        timer?.invalidate()
        var ticks = 0
        timer = Timer.scheduledTimer(withTimeInterval: 1, repeats: true) { t in
            MainActor.assumeIsolated {
                ticks += 1
                if FDAProbe.check() {
                    t.invalidate(); timer = nil
                    AppModel.shared.hasFullDiskAccess = true
                    PermissionGuidePanel.shared.finish()
                } else if ticks > 300 {
                    t.invalidate(); timer = nil
                    PermissionGuidePanel.shared.close()
                }
            }
        }
    }
}
