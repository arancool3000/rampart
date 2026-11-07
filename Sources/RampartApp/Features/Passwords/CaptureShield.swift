import SwiftUI
import AppKit

/// Asks macOS to keep a window out of screenshots, screen recordings and screen sharing while it shows
/// secrets (`NSWindow.sharingType = .none`), and restores it when the last secret view on that window goes away.
///
/// Honest limit: this is a request to the window server. Legacy capture APIs and most screen-sharing tools honour
/// it; recent versions of macOS do not apply it to every ScreenCaptureKit capture, and nothing stops a camera
/// pointed at the display. It reduces accidental leaks (a shared screen in a meeting, a screenshot tool), it is
/// not a guarantee.
@MainActor
enum CaptureShield {
    private static var counts: [ObjectIdentifier: (window: NSWindow, count: Int, original: NSWindow.SharingType)] = [:]

    static func retain(_ w: NSWindow) {
        let id = ObjectIdentifier(w)
        if var e = counts[id] { e.count += 1; counts[id] = e; return }
        counts[id] = (w, 1, w.sharingType)
        w.sharingType = .none
    }

    static func release(_ w: NSWindow) {
        let id = ObjectIdentifier(w)
        guard var e = counts[id] else { return }
        e.count -= 1
        if e.count <= 0 { w.sharingType = e.original == .none ? .readOnly : e.original; counts[id] = nil } else { counts[id] = e }
    }

    static func isShielded(_ w: NSWindow) -> Bool { counts[ObjectIdentifier(w)] != nil }
}

private final class CaptureShieldView: NSView {
    var active = true { didSet { update() } }
    private weak var shielded: NSWindow?

    override func viewDidMoveToWindow() { super.viewDidMoveToWindow(); update() }

    func update() {
        let target = active ? window : nil
        guard target !== shielded else { return }
        if let old = shielded { CaptureShield.release(old) }
        shielded = target
        if let new = target { CaptureShield.retain(new) }
    }

    func tearDown() { if let old = shielded { CaptureShield.release(old) }; shielded = nil }
}

private struct CaptureShieldRepresentable: NSViewRepresentable {
    var active: Bool
    func makeNSView(context: Context) -> CaptureShieldView { let v = CaptureShieldView(); v.active = active; return v }
    func updateNSView(_ v: CaptureShieldView, context: Context) { v.active = active }
    static func dismantleNSView(_ v: CaptureShieldView, coordinator: ()) { v.tearDown() }
}

extension View {
    /// Keeps the hosting window (including a sheet's own window) out of screen capture while `active`.
    func protectedFromCapture(_ active: Bool = true) -> some View {
        background(CaptureShieldRepresentable(active: active).frame(width: 0, height: 0).allowsHitTesting(false))
    }
}
