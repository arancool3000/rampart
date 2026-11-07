import SwiftUI
import AppKit
import RampartVault

/// Root of the "Passwords" sidebar section: create / lock screen, then the vault with its tabs.
struct PasswordsView: View {
    @Bindable private var model = PasswordsModel.shared

    var body: some View {
        Group {
            switch model.phase {
            case .noVault: VaultLockScreen(creating: true)
            case .locked: VaultLockScreen(creating: false)
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

    private var unlocked: some View {
        VStack(spacing: 0) {
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

struct VaultLockScreen: View {
    let creating: Bool
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var password = ""
    @StateVar private var confirm = ""
    @StateVar private var reveal = false
    @FocusState private var focused: Bool

    var body: some View {
        ScrollView {
            VStack(spacing: Spacing.xl) {
                Spacer(minLength: Spacing.xl)
                ShieldHero(symbol: creating ? "key.viewfinder" : "lock.shield.fill", tint: .rampartTeal, breathe: false, size: 130)
                VStack(spacing: 6) {
                    Text(creating ? "Create your password vault" : "Your vault is locked")
                        .font(.largeTitle.weight(.semibold)).fontDesign(.rounded)
                    Text(creating
                         ? "Everything is encrypted on this Mac with AES-256. Only your master password, or your fingerprint once you turn on Touch ID, can open it. RamPart can't recover a forgotten master password."
                         : "Encrypted at rest with AES-256-GCM. Unlock with Touch ID or your master password.")
                        .foregroundStyle(.secondary).multilineTextAlignment(.center).frame(maxWidth: 460)
                }
                form.frame(maxWidth: 380)
                Spacer(minLength: Spacing.xl)
            }
            .frame(maxWidth: .infinity)
            .padding(Spacing.xl)
        }
        .onAppear {
            focused = true
            // Offer Touch ID straight away, but only when the user can see the window.
            if !creating && model.touchIDEnabled && !Headless.active && NSApp.isActive { Task { await model.unlockWithTouchID() } }
        }
    }

    @ViewBuilder private var form: some View {
        VStack(spacing: Spacing.m) {
            if !creating && model.touchIDEnabled {
                Button { Task { await model.unlockWithTouchID() } } label: {
                    Label("Unlock with \(model.availability.biometryName)", systemImage: "touchid").frame(maxWidth: .infinity)
                }
                .buttonStyle(GlowButtonStyle()).controlSize(.large)
                HStack { line; Text("or").font(.caption).foregroundStyle(.secondary); line }
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
