import SwiftUI
import AppKit
import RampartShared
import RampartWeb

// Card for Settings / Network: one-button Safari setup, the relaunch toggle, and the optional
// lower-security "Safari JavaScript control" mode with an honest explanation of its guard.
// Drop `SafariSetupCard()` into any screen; it owns its model.

struct SafariSetupCard: View {
    @StateVar private var model = SafariSetupModel()
    @StateVar private var showAdvancedConfirm = false
    @StateVar private var showGuardDetails = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            HStack(spacing: Spacing.m) {
                IconBadge(symbol: "safari", tint: .rampartTeal, size: 34)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Safari protection").font(.body.weight(.medium))
                    Text("Safari only loads extensions from Apple-signed apps. RamPart is self-signed, so Safari needs its “Allow Unsigned Extensions” developer setting, which resets every time Safari quits. The button does all the clicks for you.")
                        .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Spacer()
                Button { model.start() } label: { Label(buttonTitle, systemImage: "wand.and.stars") }
                    .buttonStyle(GlowButtonStyle()).disabled(model.phase.isActive)
            }
            statusLine
            if case .needsAccessibility = model.phase {
                HStack(spacing: Spacing.m) {
                    Image(systemName: "hand.raised.square").foregroundStyle(Color.statusAttention)
                    Text("RamPart needs Accessibility permission to press Safari's menu items. System Settings › Privacy & Security › Accessibility › turn on RamPart, then press the button again.").font(.callout)
                    Spacer()
                    Button("Open Accessibility settings") { model.requestAccessibility() }.secondaryActionStyle()
                }
                .padding(Spacing.m).background(Color.statusAttention.opacity(0.1), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
            }
            if !model.planNotes.isEmpty { ForEach(model.planNotes, id: \.self) { Text($0).font(.caption).foregroundStyle(.secondary) } }
            Divider()
            Toggle(isOn: Binding(get: { model.autoReenable }, set: { model.setAutoReenable($0) })) {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Re-enable automatically when Safari starts")
                    Text("Each time Safari launches, RamPart re-applies “Allow Unsigned Extensions”. macOS will ask for your password each time; RamPart never types it.").font(.caption).foregroundStyle(.secondary)
                }
            }.toggleStyle(.switch)
            Divider()
            DisclosureGroup(isExpanded: $showGuardDetails) {
                advanced
            } label: {
                HStack { Text("Advanced: Safari JavaScript control (lower security)").font(.callout.weight(.medium)); Spacer(); Badge(text: model.jsControlEnabled ? "On" : "Off", tint: model.jsControlEnabled ? .statusAttention : .secondary) }
            }
            Text("What stays honest: without an Apple Developer ID the Safari extension is “unsigned”, and nothing RamPart does changes what Safari itself blocks. Chrome, Brave, Edge and Arc don't need any of this.")
                .font(.caption).foregroundStyle(.tertiary).fixedSize(horizontal: false, vertical: true)
        }
        .card()
        .sheet(isPresented: $showAdvancedConfirm) { AdvancedModeConfirm(onEnable: { model.setJSControl(true); showAdvancedConfirm = false }, onCancel: { showAdvancedConfirm = false }) }
    }

    private var buttonTitle: String {
        switch model.phase { case .launching, .running, .waitingForPassword: return "Setting up…"; case .done: return "Set up again"; default: return "Set up Safari protection" }
    }

    @ViewBuilder private var statusLine: some View {
        switch model.phase {
        case .idle: EmptyView()
        case .needsAccessibility: EmptyView()
        case .launching: StatusLabel(text: "Opening Safari… don't touch the mouse or keyboard.", symbol: "safari", tint: .rampartTeal)
        case .running(let step, let i, let n): StatusLabel(text: "Step \(i) of \(n): \(step)", symbol: "cursorarrow.click", tint: .rampartTeal)
        case .waitingForPassword: StatusLabel(text: "Waiting for you to enter your password in Safari's dialog.", symbol: "lock", tint: .statusAttention)
        case .done(let s): StatusLabel(text: s, symbol: "checkmark.circle.fill", tint: .statusProtected)
        case .failed(let m): StatusLabel(text: m, symbol: "exclamationmark.triangle.fill", tint: .statusAction)
        case .cancelled: StatusLabel(text: "Cancelled. Nothing else was changed.", symbol: "xmark.circle", tint: .secondary)
        }
    }

    private var advanced: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("If the Safari extension can't be loaded, RamPart can still scan Safari pages by sending its scanner script to Safari through “Develop › Allow JavaScript from Apple Events”.")
                .font(.callout).fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .top, spacing: Spacing.s) {
                Image(systemName: "exclamationmark.triangle.fill").foregroundStyle(Color.statusAttention)
                Text("Why it's lower security: with that setting on, ANY app you've ever allowed to automate Safari can run script inside every page, including your bank. Real macOS stealers abuse exactly this. RamPart can't inspect scripts other apps send; it can only police who is allowed to send them.")
                    .font(.callout).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            VStack(alignment: .leading, spacing: 6) {
                Text("How RamPart reduces the risk while it's on (reduced, not zero):").font(.callout.weight(.medium))
                guardRow("person.badge.key", "Sender control", "Reads which apps hold Automation permission over Safari (needs Full Disk Access) and watches the system log for new requests. Any app other than RamPart triggers a detection, the mode turns itself off, and you can revoke that app with one click.")
                guardRow("terminal", "Process watch", "Flags any osascript/JXA run that sends “do JavaScript” to Safari, and script files that do, unless RamPart launched it. Unsigned senders count as malicious.")
                guardRow("doc.text.magnifyingglass", "In-page tamper detection", "RamPart's scanner installs a MutationObserver and API traps (new scripts or inline handlers after load, overridden fetch/XMLHttpRequest/form submit/clipboard/input getters, hidden iframes, keystroke listeners on password fields). It only raises alarms on sign-in or payment pages, or together with a foreign sender, to avoid false positives.")
            }
            HStack {
                if model.jsControlEnabled {
                    Button("Turn off now") { model.setJSControl(false) }.buttonStyle(GlowButtonStyle(tint: .statusAction))
                    Text(model.jsControl.lastVerdict.isEmpty ? "Scanning the front tab…" : "Last: \(model.jsControl.lastVerdict) · \(model.jsControl.pagesScanned) pages").font(.caption).foregroundStyle(.secondary)
                } else {
                    Button("Enable lower-security mode…") { showAdvancedConfirm = true }.secondaryActionStyle()
                }
                Spacer()
            }
            if let m = model.jsControl.lastGuardMessage { StatusLabel(text: m, symbol: "exclamationmark.shield.fill", tint: .statusAction) }
            ForEach(model.jsControl.findings) { f in
                HStack(alignment: .top, spacing: Spacing.s) {
                    Image(systemName: "xmark.shield.fill").foregroundStyle(Color.statusAction)
                    VStack(alignment: .leading, spacing: 2) {
                        Text(f.finding.detail).font(.callout)
                        Text(Fmt.dayTime(f.date)).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    if f.finding.bundleID != nil {
                        Button(f.revoked ? "Revoked" : "Revoke its Safari access") { model.jsControl.revoke(f) }.disabled(f.revoked)
                    }
                }
                .padding(Spacing.s).background(Color.statusAction.opacity(0.08), in: RoundedRectangle(cornerRadius: 8, style: .continuous))
            }
        }
        .padding(.top, Spacing.s)
    }

    private func guardRow(_ symbol: String, _ title: String, _ text: String) -> some View {
        HStack(alignment: .top, spacing: Spacing.s) {
            Image(systemName: symbol).foregroundStyle(Color.rampartTeal).frame(width: 18)
            VStack(alignment: .leading, spacing: 1) { Text(title).font(.callout.weight(.medium)); Text(text).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true) }
        }
    }
}

struct AdvancedModeConfirm: View {
    let onEnable: () -> Void, onCancel: () -> Void
    @StateVar private var understood = false
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            HStack(spacing: Spacing.m) { IconBadge(symbol: "exclamationmark.triangle.fill", tint: .statusAttention, size: 40); Text("Enable lower-security Safari mode?").font(.title3.weight(.semibold)) }
            Text("RamPart will turn on Safari › Develop › “Allow JavaScript from Apple Events” and ask macOS for permission to control Safari. While it's on, any other app with Automation permission over Safari could run script in your pages. RamPart's guard watches for that and switches the mode off, but it can't make it risk-free.")
                .fixedSize(horizontal: false, vertical: true)
            Text("Prefer the regular Safari extension whenever it can be loaded. You can turn this off with one click at any time.").font(.callout).foregroundStyle(.secondary)
            Toggle("I understand this lowers Safari's security while it's on", isOn: $understood)
            HStack { Spacer(); Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction); Button("Enable", action: onEnable).buttonStyle(GlowButtonStyle(tint: .statusAttention)).disabled(!understood) }
        }
        .padding(Spacing.xl).frame(width: 520)
    }
}
