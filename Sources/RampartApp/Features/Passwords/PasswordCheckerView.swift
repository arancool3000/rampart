import SwiftUI
import RampartVault

/// Checks any password without unlocking the vault. Nothing typed here is stored or logged, and the field
/// is cleared when the view disappears. The leak check uses the k-anonymity range API.
struct PasswordCheckerView: View {
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var password = ""
    @StateVar private var reveal = false
    @StateVar private var strength: PasswordStrength?
    @StateVar private var leak: PasswordsModel.LiveBreach = .off
    @StateVar private var checking = false

    /// Automatic when breach monitoring is on (defaults to on when no vault is unlocked).
    private var autoCheck: Bool { model.phase == .unlocked ? model.meta.settings.breachCheckEnabled : true }

    var body: some View { secretContent.protectedFromCapture(reveal) }

    @ViewBuilder private var secretContent: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.l) {
                SectionHeader("Password checker")
                Text("See how strong a password is and whether it has appeared in a known data breach. You don't need to unlock your vault.")
                    .foregroundStyle(.secondary)
                HStack {
                    Image(systemName: "key.fill").foregroundStyle(.secondary)
                    Group {
                        if reveal { TextField("Type or paste a password", text: $password) } else { SecureField("Type or paste a password", text: $password) }
                    }
                    .textFieldStyle(.plain).font(.body.monospaced())
                    Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                        .buttonStyle(.borderless).help(reveal ? "Hide" : "Show")
                }
                .padding(10)
                .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))

                if let s = strength, !password.isEmpty {
                    StrengthMeter(strength: s, compact: false).card(tint: StrengthMeter.tint(s.level))
                }

                HStack {
                    Button { Task { await checkLeaks() } } label: {
                        HStack { if checking { ProgressView().controlSize(.small) }; Text("Check for Leaks") }
                    }
                    .disabled(password.isEmpty || checking)
                    leakLabel
                    Spacer()
                    Button { password = PasswordGenerator.random(model.meta.settings.generator).password; reveal = true } label: {
                        Label("Generate a Strong One Instead", systemImage: "wand.and.stars")
                    }
                }
                Text("Only the first 5 characters of a scrambled fingerprint leave your Mac. Your password is never sent or saved.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .contentColumn()
        }
        .task(id: password) {
            leak = .off
            guard !password.isEmpty else { strength = nil; return }
            try? await Task.sleep(for: .milliseconds(700))
            guard !Task.isCancelled else { return }
            strength = PasswordStrength.evaluate(password)
            if autoCheck { await checkLeaks() }
        }
        .onDisappear { password = ""; strength = nil; leak = .off; reveal = false }
    }

    @ViewBuilder private var leakLabel: some View {
        switch leak {
        case .found(let n): Label("Found in known breaches, seen \(n.formatted()) time\(n == 1 ? "" : "s")", systemImage: "exclamationmark.octagon.fill").foregroundStyle(Palette.coral)
        case .clean: Label("Not found in known breaches", systemImage: "checkmark.shield.fill").foregroundStyle(.green)
        case .failed: Label("Couldn't reach the breach service", systemImage: "wifi.exclamationmark").foregroundStyle(.secondary)
        case .checking: Text("Checking…").foregroundStyle(.secondary)
        case .off: EmptyView()
        }
    }

    private func checkLeaks() async {
        let pw = password
        guard !pw.isEmpty, !Headless.active else { return }
        checking = true; leak = .checking
        let r: PasswordsModel.LiveBreach
        do { let c = try await model.breachChecker.breachCount(for: pw); r = c > 0 ? .found(c) : .clean }
        catch { r = .failed(error.localizedDescription) }
        checking = false
        if pw == password { leak = r }
    }
}
