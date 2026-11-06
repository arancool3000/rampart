import SwiftUI
import AppKit
import Observation
import UniformTypeIdentifiers
import RampartVault

/// State for the Passwords screen. One shared instance so the lock state survives sidebar navigation.
/// Never logs secrets; decrypted items live only while unlocked and are dropped on lock.
@MainActor
@Observable
final class PasswordsModel {
    static let shared = PasswordsModel()

    enum Phase { case noVault, locked, unlocked }
    enum Tab: String, CaseIterable, Identifiable {
        case vault = "Vault", generator = "Generator", audit = "Security Audit", settings = "Settings"
        var id: String { rawValue }
        var symbol: String {
            switch self { case .vault: return "lock.rectangle.stack"; case .generator: return "wand.and.stars"; case .audit: return "checkmark.shield"; case .settings: return "gearshape" }
        }
    }
    enum Filter: Hashable {
        case all, favourites, kind(VaultItemKind), folder(UUID), tag(String)
    }

    let store: VaultStore
    let touchID: TouchIDUnlock
    @ObservationIgnored private var autoLock: AutoLock?

    var phase: Phase = .noVault
    var tab: Tab = .vault
    var items: [VaultItem] = []
    var meta = VaultMeta()
    var filter: Filter = .all
    var search = ""
    var selection: UUID?
    var editing: VaultItem?
    var busy = false
    var error: String?
    var toast: String?
    var touchIDEnabled = false
    var touchIDMode: TouchIDUnlock.Mode?
    var availability = TouchIDUnlock.availability()
    var audit: VaultAudit?
    var auditRunning = false
    var auditNote: String?

    init(store: VaultStore = VaultStore()) {
        self.store = store
        touchID = TouchIDUnlock(store: store)
        refreshPhase()
    }

    func refreshPhase() {
        phase = !store.exists ? .noVault : (store.isUnlocked ? .unlocked : .locked)
        touchIDEnabled = touchID.isEnabled
        touchIDMode = touchID.mode
    }

    // MARK: Lock / unlock

    func create(master: String) async {
        busy = true; error = nil
        let store = store
        let result: Error? = await Task.detached { () -> Error? in
            do { try store.create(masterPassword: master); return nil } catch { return error }
        }.value
        busy = false
        if let result { error = result.localizedDescription; return }
        didUnlock()
    }

    func unlock(master: String) async {
        busy = true; error = nil
        let store = store
        let result: Error? = await Task.detached { () -> Error? in
            do { try store.unlock(masterPassword: master); return nil } catch { return error }
        }.value
        busy = false
        if let result { error = result.localizedDescription; return }
        didUnlock()
    }

    func unlockWithTouchID() async {
        guard !Headless.active else { return }
        error = nil
        do { try await touchID.unlock(); didUnlock() }
        catch VaultError.cancelled { }
        catch { self.error = error.localizedDescription; refreshPhase() }
    }

    private func didUnlock() {
        reload()
        phase = .unlocked
        startAutoLock()
        refreshPhase()
    }

    func lock() {
        autoLock?.stop(); autoLock = nil
        ClipboardGuard.shared.clearIfOurs()
        store.lock()
        items = []; editing = nil; selection = nil; audit = nil; search = ""
        meta = VaultMeta()
        refreshPhase()
    }

    private func startAutoLock() {
        let s = meta.settings
        let a = autoLock ?? AutoLock(onLock: { [weak self] in self?.lock() })
        a.idleMinutes = s.autoLockMinutes; a.lockOnSleep = s.lockOnSleep; a.lockOnScreenLock = s.lockOnScreenLock
        autoLock = a
        a.start()
    }

    func reload() {
        items = store.items.sorted { $0.title.localizedCaseInsensitiveCompare($1.title) == .orderedAscending }
        meta = store.meta
    }

    // MARK: Browsing

    static func matches(_ i: VaultItem, _ f: Filter) -> Bool {
        switch f {
        case .all: return true
        case .favourites: return i.favourite
        case .kind(let k): return i.kind == k
        case .folder(let id): return i.folderID == id
        case .tag(let t): return i.tags.contains(t)
        }
    }

    var visibleItems: [VaultItem] {
        let q = search.lowercased().trimmingCharacters(in: .whitespaces)
        return items.filter { Self.matches($0, filter) && (q.isEmpty || $0.searchText.contains(q)) }
    }

    var allTags: [String] { Array(Set(items.flatMap(\.tags))).sorted() }
    func count(_ f: Filter) -> Int { items.lazy.filter { Self.matches($0, f) }.count }

    var selectedItem: VaultItem? { selection.flatMap { id in items.first { $0.id == id } } }

    // MARK: Editing

    func newItem(_ kind: VaultItemKind) {
        var i = VaultItem(kind: kind, title: "")
        if case .folder(let f) = filter { i.folderID = f }
        if kind == .login { i.password = PasswordGenerator.random(meta.settings.generator).password }
        editing = i
        selection = nil
    }

    func save(_ item: VaultItem) {
        var item = item
        if item.title.trimmingCharacters(in: .whitespaces).isEmpty { item.title = item.primaryDomain ?? item.kind.label }
        perform { try self.store.upsert(item) }
        selection = item.id
        editing = nil
    }

    func delete(_ id: UUID) {
        perform { try self.store.delete(id) }
        if selection == id { selection = nil }
        editing = nil
    }

    func toggleFavourite(_ item: VaultItem) {
        var i = item; i.favourite.toggle()
        perform { try self.store.upsert(i) }
    }

    func addFolder(_ name: String) {
        let n = name.trimmingCharacters(in: .whitespaces); guard !n.isEmpty else { return }
        perform { try self.store.updateMeta { $0.folders.append(VaultFolder(name: n)) } }
    }

    func deleteFolder(_ id: UUID) {
        perform { try self.store.updateMeta { $0.folders.removeAll { $0.id == id } } }
        if filter == .folder(id) { filter = .all }
    }

    func updateSettings(_ change: @escaping (inout VaultSettings) -> Void) {
        perform { try self.store.updateMeta { change(&$0.settings) } }
        if phase == .unlocked { startAutoLock() }
    }

    func perform(_ body: () throws -> Void) {
        do { try body(); error = nil } catch { self.error = error.localizedDescription }
        reload()
    }

    func copy(_ secret: String, label: String) {
        guard !Headless.active else { return }
        let secs = meta.settings.clipboardClearSeconds
        ClipboardGuard.shared.copy(secret, clearAfter: secs)
        flash(secs > 0 ? "\(label) copied. Clipboard clears in \(secs) s." : "\(label) copied.")
    }

    func flash(_ text: String) {
        toast = text
        Task { try? await Task.sleep(for: .seconds(2.5)); if toast == text { toast = nil } }
    }

    // MARK: Touch ID

    func setTouchID(_ on: Bool) {
        if on {
            do {
                let mode = try touchID.enable()
                flash(mode == .secureEnclave ? "Touch ID is on, protected by the Secure Enclave." : "Touch ID is on (keychain mode).")
            } catch { self.error = error.localizedDescription }
        } else {
            touchID.disable()
        }
        refreshPhase()
    }

    // MARK: Audit

    func runAudit(checkBreaches: Bool) async {
        auditRunning = true; auditNote = nil
        if checkBreaches && meta.settings.breachCheckEnabled {
            let (a, failure) = await VaultAudit.runWithBreachCheck(items: items)
            audit = a
            auditNote = failure.map { "Breach check incomplete: \($0)" }
        } else {
            audit = VaultAudit.run(items: items)
        }
        auditRunning = false
    }

    // MARK: Import / export

    func importCSV() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.commaSeparatedText, .plainText]
        panel.message = "Choose a CSV exported from Chrome, Firefox, Safari, Bitwarden or 1Password."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        guard let data = try? Data(contentsOf: url) else { error = "Couldn't read that file."; return }
        let result = CSVImporter.parse(String(decoding: data, as: UTF8.self))
        var newMeta = meta
        let items = CSVImporter.applyFolders(result, into: &newMeta)
        perform {
            try self.store.updateMeta { $0.folders = newMeta.folders }
            try self.store.insert(items)
        }
        flash("Imported \(items.count) item\(items.count == 1 ? "" : "s") from \(result.source.rawValue)\(result.skipped > 0 ? " (\(result.skipped) empty rows skipped)" : "").")
        if error == nil {
            toast = (toast ?? "") + " Delete the CSV file now: it holds your passwords in plain text."
        }
    }

    func exportEncrypted(password: String) async {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "RamPart Passwords.rpexport"
        panel.message = "The export is encrypted with the password you chose (AES-256-GCM, PBKDF2)."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        let items = items, folders = meta.folders
        let result: Result<Data, Error> = await Task.detached { Result { try EncryptedExport.export(items: items, folders: folders, password: password) } }.value
        busy = false
        switch result {
        case .success(let d):
            do { try d.write(to: url, options: .atomic); flash("Exported \(items.count) items, encrypted.") } catch { self.error = error.localizedDescription }
        case .failure(let e): error = e.localizedDescription
        }
    }

    func importEncrypted(password: String) async {
        let panel = NSOpenPanel()
        panel.message = "Choose a RamPart export (.rpexport)."
        guard panel.runModal() == .OK, let url = panel.url, let data = try? Data(contentsOf: url) else { return }
        busy = true
        let result: Result<(items: [VaultItem], folders: [VaultFolder]), Error> = await Task.detached { Result { try EncryptedExport.import(data, password: password) } }.value
        busy = false
        switch result {
        case .success(let r):
            perform {
                try self.store.updateMeta { m in for f in r.folders where !m.folders.contains(where: { $0.id == f.id }) { m.folders.append(f) } }
                try self.store.insert(r.items)
            }
            flash("Imported \(r.items.count) items.")
        case .failure(let e): error = e.localizedDescription
        }
    }

    func saveToKeychain(_ item: VaultItem) {
        do { try LoginKeychain.save(item); flash("Saved to your login keychain.") }
        catch VaultError.cancelled { }
        catch { self.error = error.localizedDescription }
    }
}
