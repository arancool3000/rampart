import SwiftUI
import RampartVault
import RampartShared

struct VaultSettingsView: View {
    @Bindable private var model = PasswordsModel.shared
    @StateVar private var showKeychain = false
    @StateVar private var exportPassword = ""
    @StateVar private var importPassword = ""
    @StateVar private var currentMaster = ""
    @StateVar private var newMaster = ""

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.xl) {
            touchID
            breachMonitoring
            locking
            importExport
            security
        }
        .sheet(isPresented: $showKeychain) { KeychainImportSheet() }
    }

    private var touchID: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("\(model.availability.biometryName) unlock")
            Toggle(isOn: Binding(get: { model.touchIDEnabled }, set: { model.setTouchID($0) })) {
                Text("Unlock the vault with \(model.availability.biometryName)")
            }
            .toggleStyle(.switch)
            .disabled(!model.availability.biometryAvailable && !model.touchIDEnabled)
            if let r = model.availability.reason { StatusLabel(text: r, symbol: "info.circle.fill", tint: .blue).font(.callout) }
            Group {
                if model.touchIDMode == .keychainGated {
                    Text("Compatibility mode (this Mac's security chip couldn't be used): the vault key is stored in your login keychain and RamPart asks for Touch ID before reading it. That check is enforced by RamPart, not by hardware, so it is weaker than the master password: an app you allow to access the keychain item could read the key without Touch ID.")
                } else {
                    Text("Hardware-protected: the vault key is locked by a key that lives inside this Mac's security chip and can only be used after a Touch ID match with your current fingerprints. Adding or removing a fingerprint switches Touch ID off until you unlock once with your master password. Nothing is stored in the keychain. Anyone who can pass Touch ID on this Mac can open the vault, and your master password always works.")
                }
            }
            .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    private var breachMonitoring: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Breach monitoring")
            Toggle("Check passwords against known breaches automatically", isOn: Binding(get: { model.meta.settings.breachCheckEnabled },
                                                                            set: { v in model.updateSettings { $0.breachCheckEnabled = v } }))
                .toggleStyle(.switch)
            Text("When on, \(Product.name) checks each password when you save it, after you unlock (at most once a day per password), and as you type or generate one. Privacy: it uses Have I Been Pwned's Pwned Passwords service. Only the first 5 characters of a scrambled fingerprint of the password leave this Mac; the password never does, and the service can't tell which of the hundreds of matching fingerprints was yours. Results are kept scrambled inside the encrypted vault.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    private var locking: some View {
        let s = model.meta.settings
        return VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Automatic locking")
            Picker("Lock after inactivity", selection: Binding(get: { s.autoLockMinutes }, set: { v in model.updateSettings { $0.autoLockMinutes = v } })) {
                Text("1 minute").tag(1); Text("5 minutes").tag(5); Text("15 minutes").tag(15); Text("1 hour").tag(60)
            }
            Toggle("Lock when the Mac sleeps", isOn: Binding(get: { s.lockOnSleep }, set: { v in model.updateSettings { $0.lockOnSleep = v } }))
            Toggle("Lock when the screen locks or the screensaver starts", isOn: Binding(get: { s.lockOnScreenLock }, set: { v in model.updateSettings { $0.lockOnScreenLock = v } }))
            Picker("Clear copied passwords after", selection: Binding(get: { s.clipboardClearSeconds }, set: { v in model.updateSettings { $0.clipboardClearSeconds = v } })) {
                Text("15 seconds").tag(15); Text("30 seconds").tag(30); Text("90 seconds").tag(90)
            }
            Text("The vault file is always encrypted; locking also wipes the key and decrypted items from memory. Copied secrets are marked as concealed so clipboard managers that respect it skip them.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    private var importExport: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Import and export")
            HStack {
                Button { model.importCSV() } label: { Label("Import CSV…", systemImage: "square.and.arrow.down") }
                Button { showKeychain = true } label: { Label("Import from Keychain…", systemImage: "key") }
            }
            Text("CSV exports from Chrome, Edge, Brave, Firefox, Safari, Bitwarden and 1Password are recognised. Delete the CSV afterwards: it isn't encrypted.")
                .font(.caption).foregroundStyle(.secondary)
            Divider()
            HStack {
                SecureField("Export password", text: $exportPassword).frame(maxWidth: 220)
                Button { let p = exportPassword; Task { await model.exportEncrypted(password: p); exportPassword = "" } } label: { Label("Export Encrypted…", systemImage: "square.and.arrow.up") }
                    .disabled(exportPassword.count < 10 || model.busy)
            }
            HStack {
                SecureField("Export file password", text: $importPassword).frame(maxWidth: 220)
                Button { let p = importPassword; Task { await model.importEncrypted(password: p); importPassword = "" } } label: { Label("Import RamPart Export…", systemImage: "tray.and.arrow.down") }
                    .disabled(importPassword.isEmpty || model.busy)
            }
        }
        .card()
    }

    private var security: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Master password and backups")
            HStack {
                SecureField("Current", text: $currentMaster).frame(maxWidth: 180)
                SecureField("New", text: $newMaster).frame(maxWidth: 180)
                Button("Change") {
                    let c = currentMaster, n = newMaster, store = model.store
                    model.busy = true
                    Task {
                        let err: Error? = await Task.detached { () -> Error? in
                            do { try store.changeMasterPassword(current: c, new: n); return nil } catch { return error }
                        }.value
                        model.busy = false
                        if let err { model.error = err.localizedDescription } else { model.flash("Master password changed."); currentMaster = ""; newMaster = "" }
                    }
                }
                .disabled(currentMaster.isEmpty || !VaultStore.isAcceptableMaster(newMaster) || model.busy)
            }
            if !newMaster.isEmpty { StrengthMeter(strength: PasswordStrength.evaluate(newMaster)) }
            Text("Encrypted backups: \(model.store.backups().count) of the last \(VaultStore.maxBackups) kept in \(model.store.backupDirectory.path(percentEncoded: false)). Each opens with the master password that was current when it was made.")
                .font(.caption).foregroundStyle(.secondary)
            Text("Each item is encrypted separately, the whole file is checked for tampering, and your master password is stretched so guessing it is slow.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }
}

/// Lists login-keychain entries by name only. Each password is read only when the user clicks Import on
/// that row, which shows macOS's own permission prompt for entries RamPart didn't create.
struct KeychainImportSheet: View {
    @Bindable private var model = PasswordsModel.shared
    @Environment(\.dismiss) private var dismiss
    @StateVar private var entries: [KeychainEntry] = []
    @StateVar private var showAll = false
    @StateVar private var imported: Set<Data> = []
    @StateVar private var loaded = false

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            Text("Import from your login keychain").font(.title2.weight(.semibold))
            Text("Choose entries one at a time. macOS asks for your permission each time RamPart reads a password it didn't save; RamPart never reads them in bulk.")
                .font(.callout).foregroundStyle(.secondary)
            Toggle("Show app and system entries", isOn: $showAll).controlSize(.small)
            List(entries.filter { showAll || $0.looksLikeUserPassword }) { e in
                HStack {
                    Image(systemName: e.kind == .internet ? "globe" : "key").foregroundStyle(.secondary)
                    VStack(alignment: .leading) {
                        Text(e.label).lineLimit(1)
                        Text([e.account, e.server].filter { !$0.isEmpty }.joined(separator: " · ")).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                    Spacer()
                    if imported.contains(e.persistentRef) {
                        Image(systemName: "checkmark.circle.fill").foregroundStyle(.green)
                    } else {
                        Button("Import") { importOne(e) }.controlSize(.small)
                    }
                }
            }
            .frame(minHeight: 320)
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.defaultAction) }
        }
        .padding(Spacing.xl)
        .frame(width: 560, height: 520)
        .onAppear {
            guard !loaded, !Headless.active else { return }
            loaded = true
            entries = LoginKeychain.listEntries()
        }
    }

    private func importOne(_ e: KeychainEntry) {
        do {
            let pw = try LoginKeychain.readPassword(e)
            let item = LoginKeychain.makeItem(from: e, password: pw)
            model.perform { try model.store.upsert(item) }
            imported.insert(e.persistentRef)
        } catch VaultError.cancelled {
        } catch { model.error = error.localizedDescription }
    }
}
