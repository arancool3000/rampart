import SwiftUI
import AppKit
import RampartShared

/// Settings › General: Desktop Mode on/off, background, displays.
struct DesktopModeSettingsSection: View {
    private let desktop = DesktopMode.shared
    var body: some View {
        @Bindable var desktop = desktop
        Section {
            HintToggle("Desktop Mode", hint: "Turns your desktop into a \(Product.name) command centre: status, apps, Mac info and quick actions behind your windows. \(DesktopMode.shortcutLabel) toggles it.",
                       isOn: Binding(get: { desktop.isOn }, set: { desktop.setOn($0) }))
            Picker("Background", selection: $desktop.backdrop) {
                ForEach(DesktopBackdropStyle.allCases) { Text($0.title).tag($0) }
            }
            .disabled(!desktop.isOn)
            Toggle("Show on every display", isOn: $desktop.allDisplays).disabled(!desktop.isOn)
        } footer: {
            Text("Desktop icons keep working: clicks on empty space go to Finder. Icons under a widget are covered; to hide all desktop icons, turn off “Show Items on Desktop” in System Settings › Desktop & Dock. Widgets refresh every 2–5 seconds only while you can see them.")
                .foregroundStyle(.secondary)
        }
    }
}

/// One-time in-app invitation on the Overview (never a system pop-up).
struct DesktopInviteCard: View {
    @AppStorage(DesktopMode.askedKey) private var asked = false
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    var body: some View {
        if !asked && !DesktopMode.shared.isOn && !Headless.active {
            HStack(spacing: DS.Space.l) {
                IconBadge(symbol: "menubar.dock.rectangle", tint: .rampartTeal, size: 44)
                VStack(alignment: .leading, spacing: 2) {
                    Text("New: Desktop Mode").font(DS.Font.headline)
                    Text("Make your desktop a \(Product.name) command centre: protection status, your apps, Mac info and quick actions, right behind your windows. Desktop icons keep working.")
                        .font(DS.Font.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: DS.Space.s)
                Button("Not Now") { withAnimation(reduceMotion ? nil : .easeOut(duration: 0.2)) { asked = true } }.buttonStyle(.bordered)
                Button("Try Desktop Mode") { asked = true; DesktopMode.shared.setOn(true) }.buttonStyle(GlowButtonStyle())
            }
            .card(tint: .rampartTeal)
        }
    }
}

/// Menu bar popover row.
struct DesktopMenuRow: View {
    private let desktop = DesktopMode.shared
    var body: some View {
        MenuRowButton(title: desktop.isOn ? "Hide Desktop Mode" : "Desktop Mode", shortcut: DesktopMode.shortcutLabel) { desktop.toggle() }
    }
}

/// Lets the desktop layer bring the main window back after it was closed (needs SwiftUI's `openWindow`).
struct DesktopOpenWindowBridge: View {
    @Environment(\.openWindow) private var openWindow
    var body: some View {
        Color.clear.frame(width: 0, height: 0)
            .onAppear {
                let open = openWindow
                DesktopMode.shared.openMainHandler = { open(id: "main") }
            }
            .accessibilityHidden(true)
    }
}
