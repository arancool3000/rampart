import SwiftUI
import RampartShared
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
    /// Lockdown in the menu bar: nil = off; "" = on (internet on or kept blocked); "9m" = automatic block countdown.
    /// Read only by MenuBarLabel; changes at most once a minute.
    private(set) var lockdownBadge: String?

    func setLockdownBadge(_ b: String?) { if b != lockdownBadge { lockdownBadge = b } }

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
        HStack(spacing: 2) {
            if let b = chrome.lockdownBadge {
                // Red, not a template image: the lockdown must be visible at a glance.
                HStack(spacing: 2) {
                    Image(nsImage: Self.redLock)
                    if !b.isEmpty { Text(b) }
                }
            } else if chrome.hasThreat { Image(systemName: "exclamationmark.shield") } else { Image(nsImage: BrandImages.menuBarTemplate) }
            MediaInUseBadge()   // live camera / microphone indicator (Camera & Mic)
        }
            .accessibilityLabel(chrome.lockdownBadge != nil ? "\(Product.name): emergency lockdown on" : chrome.hasThreat ? "\(Product.name): item needs attention" : "\(Product.name): protected")
    }

    static let redLock: NSImage = {
        let cfg = NSImage.SymbolConfiguration(paletteColors: [.systemRed])
        let img = NSImage(systemSymbolName: "lock.shield.fill", accessibilityDescription: "Lockdown")?.withSymbolConfiguration(cfg) ?? NSImage()
        img.isTemplate = false
        return img
    }()
}

/// PasteGuard's status, published by PasteGuardHost (which lives with the AI/behaviour modules) and read by
/// the permissions screen. Kept dependency-free so screens don't need those modules.
@MainActor
@Observable
final class PasteGuardStatusBox {
    static let shared = PasteGuardStatusBox()
    enum Status { case active, needsPermission, denied, stopped }
    var status: Status?
}
