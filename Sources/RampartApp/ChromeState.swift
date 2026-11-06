import SwiftUI
import Observation

/// The only state the App scene body and Commands are allowed to read.
/// Every property changes only on real transitions (never on every scan tick or KVO echo), and nothing
/// here is ever written during view, menu or scene evaluation.
///
/// Hang fix: `MenuBarExtra(isInserted:)` used to be bound to `@AppStorage`. SwiftUI's MenuBarExtraController
/// KVO-observes the status item and writes the binding back; the write invalidated App.body, which rebuilt the
/// main menu and re-configured the status item, which fired KVO again: an endless app-graph update loop.
@MainActor
@Observable
final class ChromeState {
    static let shared = ChromeState()

    private(set) var menuBarInserted: Bool
    private(set) var hasThreat = false
    private(set) var isScanning = false

    private init() {
        menuBarInserted = Headless.active ? false : (UserDefaults.standard.object(forKey: Self.menuBarKey) as? Bool ?? true)
    }

    static let menuBarKey = "general.showMenuBar"

    /// User preference change from Settings. Writes UserDefaults only when the value really changes.
    func setMenuBarInserted(_ on: Bool) {
        guard !Headless.active, on != menuBarInserted else { return }
        menuBarInserted = on
        UserDefaults.standard.set(on, forKey: Self.menuBarKey)
    }

    func update(hasThreat t: Bool, isScanning s: Bool) {
        if t != hasThreat { hasThreat = t }
        if s != isScanning { isScanning = s }
    }

    /// Binding for MenuBarExtra. System-driven writes (KVO echoes) are ignored on purpose: they must not
    /// feed back into the scene graph. The user's preference is changed only through Settings.
    var menuBarBinding: Binding<Bool> {
        Binding(get: { ChromeState.shared.menuBarInserted }, set: { _ in })
    }
}

/// Menu bar label as its own view, so model changes re-render only this label, not the App scene.
struct MenuBarLabel: View {
    let chrome = ChromeState.shared
    var body: some View {
        Image(systemName: chrome.hasThreat ? "exclamationmark.shield" : "shield.lefthalf.filled")
            .accessibilityLabel(chrome.hasThreat ? "Rampart: item needs attention" : "Rampart: protected")
    }
}
