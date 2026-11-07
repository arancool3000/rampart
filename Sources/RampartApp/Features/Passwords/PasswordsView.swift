import SwiftUI
import AppKit
import RampartVault
import RampartShared

/// Root of the "Passwords" sidebar section: create / lock screen, then the vault with its tabs.
struct PasswordsView: View {
    @Bindable private var model = PasswordsModel.shared

    var body: some View {
        Group {
            switch model.phase {
            case .noVault, .locked: lockedTabs
            case .unlocked: unlocked
            }
        }
        .navigationTitle("Passwords")
        .overlay(alignment: .bottom) {
            if let t = model.toast {
                Label(t, systemImage: "checkmark.circle.fill")
                    .font(.callout.weight(.medium))
                    .padding(.horizontal, 14).padding(.vertical, 8)
                    .floatingGlassBar()
                    .padding(.bottom, Spacing.l)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .animation(.spring(response: 0.35, dampingFraction: 0.85), value: model.toast)
        .onAppear { model.refreshPhase() }
    }

    @StateVar private var lockedTab = 0

    /// While locked: the lock screen, plus the password checker that works without unlocking.
    private var lockedTabs: some View {
        VStack(spacing: 0) {
            if lockedTab == 0 { VaultLockScreen(creating: model.phase == .noVault) } else { PasswordCheckerView() }
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Section", selection: $lockedTab) {
                    Label(model.phase == .noVault ? "Create Vault" : "Unlock", systemImage: "lock.fill").tag(0)
                    Label("Password Checker", systemImage: "checkmark.shield").tag(1)
                }
                .pickerStyle(.segmented).labelsHidden()
            }
        }
    }

    private var unlocked: some View {
        VStack(spacing: 0) {
            if model.offerTouchID { TouchIDOfferBanner() }
            if let e = model.error {
                HStack {
                    StatusLabel(text: e, symbol: "exclamationmark.triangle.fill", tint: .orange)
                    Spacer()
                    Button("Dismiss") { model.error = nil }.controlSize(.small)
                }
                .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s)
                .background(Color.orange.opacity(0.12))
            }
            switch model.tab {
            case .vault: VaultBrowserView()
            case .generator: ScrollView { GeneratorPanel(onUse: nil).contentColumn() }
            case .audit: ScrollView { VaultAuditView().contentColumn() }
            case .settings: ScrollView { VaultSettingsView().contentColumn() }
            }
        }
        .toolbar {
            ToolbarItem(placement: .principal) {
                Picker("Section", selection: $model.tab) {
                    ForEach(PasswordsModel.Tab.allCases) { t in Label(t.rawValue, systemImage: t.symbol).tag(t) }
                }
                .pickerStyle(.segmented)
                .labelsHidden()
            }
            ToolbarItem(placement: .primaryAction) {
                Button { model.lock() } label: { Label("Lock Vault", systemImage: "lock.fill") }
                    .help("Lock now (⌘L)")
                    .keyboardShortcut("l", modifiers: [.command])
            }
        }
    }
}

// MARK: - Lock / create screen

/// Plain-language explanation of how the vault is protected (no algorithm names, on purpose).
struct VaultProtectionSheet: View {
    @Environment(\.dismiss) private var dismiss
    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("How is my vault protected?").font(.title2.weight(.semibold))
            ForEach([
                ("lock.fill", "Your passwords are scrambled with strong, modern encryption before they're saved. The file on disk is unreadable without your master password."),
                ("hourglass", "Turning your master password into the key is deliberately slow, so guessing it is very expensive for an attacker."),
                ("checkmark.seal", "The vault detects tampering: if the file is changed or damaged, it refuses to open instead of showing wrong data."),
                ("touchid", "With Touch ID on, the key is protected by your Mac's security chip and needs your current fingerprint."),
                ("internaldrive", "Everything stays on this Mac. Nothing is uploaded, and locking wipes the decrypted items from memory."),
                ("exclamationmark.triangle", "\(Product.name) can't recover a forgotten master password. Keep it somewhere safe."),
            ], id: \.1) { symbol, text in
                Label { Text(text).fixedSize(horizontal: false, vertical: true) } icon: { Image(systemName: symbol).foregroundStyle(Color.rampartTeal) }
            }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl).frame(width: 460)
    }
}

/// Offered right after a master-password unlock when Touch ID is available but off.
struct TouchIDOfferBanner: View {
    @Bindable private var model = PasswordsModel.shared
    var body: some View {
        HStack {
            Image(systemName: "touchid").foregroundStyle(Color.rampartTeal)
            Text("Unlock faster next time with \(model.availability.biometryName)?")
            Spacer()
            Button("Not Now") { model.touchIDOfferDismissed = true }.controlSize(.small)
            Button("Turn On") { model.setTouchID(true); model.touchIDOfferDismissed = true }.controlSize(.small).buttonStyle(GlowButtonStyle())
        }
        .padding(.horizontal, Spacing.l).padding(.vertical, Spacing.s)
        .background(Color.rampartTeal.opacity(0.1))
    }
}

struct VaultLockScreen: View {
    let creating: Bool
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var password = ""
    @StateVar private var confirm = ""
    @StateVar private var reveal = false
    @FocusState private var focused: Bool
    @StateVar private var showProtection = false

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.xl) {
                Spacer(minLength: Spacing.xl)
                ShieldHero(symbol: creating ? "key.viewfinder" : "lock.shield.fill", tint: .rampartTeal, breathe: false, size: 130)
                VStack(spacing: 6) {
                    Text(creating ? "Create your password vault" : "Your vault is locked")
                        .font(.largeTitle.weight(.semibold)).fontDesign(.rounded)
                    if creating {
                        Text("Everything is encrypted on this Mac. Only your master password, or your fingerprint once you turn on Touch ID, can open it. \(Product.name) can't recover a forgotten master password.")
                            .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                    }
                    Button("How is my vault protected?") { showProtection = true }
                        .buttonStyle(.link).font(.callout)
                }
                form.frame(maxWidth: 380)
                Spacer(minLength: Spacing.xl)
            }
            .frame(maxWidth: .infinity)
            .padding(Spacing.xl)
        }
        .sheet(isPresented: $showProtection) { VaultProtectionSheet() }
        .onAppear {
            // Load the vault and Touch ID enrolment state before the button is drawn (first screen after launch).
            model.refreshPhase()
            focused = true
        }
        .task {
            // Offer Touch ID once on first appear, only if it's on and RamPart is frontmost. At launch the app may
            // not be active yet when this screen appears, so wait (briefly) for it to become active.
            guard !creating, !Headless.active, !PasswordsModel.didAutoPromptTouchID else { return }
            model.refreshPhase()
            guard model.touchIDEnabled else { return }
            for _ in 0..<20 where !NSApp.isActive { try? await Task.sleep(for: .milliseconds(250)) }
            guard NSApp.isActive, model.phase == .locked, !Task.isCancelled else { return }
            PasswordsModel.didAutoPromptTouchID = true
            await model.unlockWithTouchID()
        }
    }

    @ViewBuilder private var form: some View {
        VStack(spacing: Spacing.m) {
            if !creating && model.touchIDEnabled {
                Button { Task { await model.unlockWithTouchID() } } label: {
                    Label("Unlock with \(model.availability.biometryName)", systemImage: "touchid").frame(maxWidth: .infinity)
                }
                .buttonStyle(GlowButtonStyle()).controlSize(.large)
                if let r = model.availability.reason { Text(r).font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center) }
                HStack { line; Text("or").font(.caption).foregroundStyle(.secondary); line }
            } else if !creating && model.availability.biometryAvailable {
                Label("\(model.availability.biometryName) unlock is off. Unlock once with your master password and you can turn it on.", systemImage: "touchid")
                    .font(.caption).foregroundStyle(.secondary)
            }
            field("Master password", text: $password)
                .onSubmit(submit)
            if creating {
                field("Confirm master password", text: $confirm).onSubmit(submit)
                StrengthMeter(strength: PasswordStrength.evaluate(password), compact: false)
            }
            if let e = model.error {
                StatusLabel(text: e, symbol: "exclamationmark.triangle.fill", tint: .orange).font(.callout)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            Button(action: submit) {
                HStack {
                    if model.busy { ProgressView().controlSize(.small) }
                    Text(creating ? "Create Vault" : "Unlock")
                }.frame(maxWidth: .infinity)
            }
            .buttonStyle(GlowButtonStyle()).controlSize(.large)
            .disabled(!canSubmit || model.busy)
            .keyboardShortcut(.defaultAction)
            if creating {
                Text("Use at least 10 characters. A passphrase of four or more random words is easy to remember and hard to guess.")
                    .font(.caption).foregroundStyle(.secondary).multilineTextAlignment(.center)
            }
        }
        .card(padding: Spacing.xl)
    }

    private var line: some View { Rectangle().fill(.quaternary).frame(height: 1) }

    private func field(_ title: String, text: Binding<String>) -> some View {
        HStack {
            Image(systemName: "key.fill").foregroundStyle(.secondary)
            Group {
                if reveal { TextField(title, text: text) } else { SecureField(title, text: text) }
            }
            .textFieldStyle(.plain).focused($focused)
            Button { reveal.toggle() } label: { Image(systemName: reveal ? "eye.slash" : "eye") }
                .buttonStyle(.borderless).help(reveal ? "Hide" : "Show")
        }
        .padding(10)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10, style: .continuous))
    }

    private var canSubmit: Bool {
        creating ? (VaultStore.isAcceptableMaster(password) && password == confirm) : !password.isEmpty
    }

    private func submit() {
        guard canSubmit, !model.busy else { return }
        let pw = password
        Task {
            if creating { await model.create(master: pw) } else { await model.unlock(master: pw) }
            if model.phase == .unlocked { password = ""; confirm = "" }
        }
    }
}

// MARK: - Strength meter

struct StrengthMeter: View {
    let strength: PasswordStrength
    var compact = true

    static func tint(_ l: PasswordStrength.Level) -> Color {
        switch l { case .veryWeak: return Palette.coral; case .weak: return .orange; case .fair: return Palette.amber; case .strong: return Palette.teal; case .veryStrong: return Palette.mint }
    }

    var body: some View {
        let tint = Self.tint(strength.level)
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 4) {
                ForEach(0..<5) { i in
                    Capsule().fill(i <= strength.level.rawValue ? AnyShapeStyle(LinearGradient(colors: [tint, tint.opacity(0.7)], startPoint: .leading, endPoint: .trailing)) : AnyShapeStyle(.quaternary))
                        .frame(height: 6)
                }
            }
            HStack {
                Text(strength.level.label).font(.callout.weight(.semibold)).foregroundStyle(tint)
                Spacer()
                Text("\(Int(strength.entropyBits.rounded())) bits").font(.callout.monospacedDigit()).foregroundStyle(.secondary)
            }
            if strength.entropyBits > 0 {
                Text(strength.crackTimeSentence).font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            }
            if !compact {
                Grid(alignment: .leading, horizontalSpacing: Spacing.m, verticalSpacing: 3) {
                    GridRow { Text("Online attack (10/s)").foregroundStyle(.secondary); Text(PasswordStrength.describe(seconds: strength.onlineSeconds)) }
                    GridRow { Text("Offline, slow hash (10k/s)").foregroundStyle(.secondary); Text(PasswordStrength.describe(seconds: strength.offlineSlowSeconds)) }
                    GridRow { Text("Offline, fast hash (10B/s)").foregroundStyle(.secondary); Text(PasswordStrength.describe(seconds: strength.offlineFastSeconds)) }
                }
                .font(.caption)
                if let w = strength.warning { Label(w, systemImage: "exclamationmark.triangle.fill").font(.caption).foregroundStyle(.orange) }
                ForEach(strength.suggestions, id: \.self) { s in Label(s, systemImage: "lightbulb").font(.caption).foregroundStyle(.secondary) }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Strength \(strength.level.label), \(Int(strength.entropyBits)) bits")
        .animation(.easeOut(duration: 0.2), value: strength.level)
    }
}
