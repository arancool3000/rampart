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
        case vault = "Vault", generator = "Generator", audit = "Watchtower", settings = "Settings"
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
    var breachSweepRunning = false
    /// Last 10 generated passwords, memory only; cleared on lock.
    var generatorHistory = GeneratorHistory()
    /// When the copied secret will be cleared from the clipboard (drives the countdown).
    var clipboardDeadline: Date?
    var lastBreachSweep: Date?
    @ObservationIgnored let breachChecker = BreachChecker()
    @ObservationIgnored private var sweepTask: Task<Void, Never>?

    enum LiveBreach: Equatable { case off, checking, found(Int), clean, failed(String) }

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
        startBreachSweep(force: false)
    }

    func lock() {
        autoLock?.stop(); autoLock = nil
        sweepTask?.cancel(); sweepTask = nil; breachSweepRunning = false
        breachChecker.clearCache()
        generatorHistory.clear(); clipboardDeadline = nil
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
        audit = VaultAudit.run(items: items, breachCounts: BreachMonitor.counts(items: items, cache: meta.breachCache),
                               checkedBreaches: meta.settings.breachCheckEnabled && !meta.breachCache.entries.isEmpty)
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
        let old = store.item(item.id)?.password
        perform { try self.store.upsert(item) }
        selection = item.id
        editing = nil
        if !item.password.isEmpty, item.password != old { checkSaved(item.password, title: item.title) }
    }

    // MARK: Breach monitoring (k-anonymity: only 5 hex chars of the SHA-1 leave the Mac)

    /// Checks every stored password not checked in the last day (or all, when `force`).
    func startBreachSweep(force: Bool) {
        guard meta.settings.breachCheckEnabled, phase == .unlocked, !Headless.active, sweepTask == nil else { return }
        let passwords = BreachMonitor.passwords(in: items), cache = meta.breachCache, checker = breachChecker
        guard force || !BreachMonitor.due(passwords, cache: cache).isEmpty else { return }
        breachSweepRunning = true; auditNote = nil
        sweepTask = Task { [weak self] in
            let r = await BreachMonitor.sweep(passwords, cache: cache, checker: checker, force: force)
            guard let self else { return }
            self.sweepTask = nil; self.breachSweepRunning = false
            guard !Task.isCancelled, self.phase == .unlocked else { return }
            self.mergeBreachResults(r.updates)
            self.lastBreachSweep = Date()
            if let f = r.failure { self.auditNote = "Breach check incomplete: \(f)" }
            else if r.found > 0 { self.flash("\(r.found) password\(r.found == 1 ? " was" : "s were") found in known breaches. See Watchtower.") }
        }
    }

    private func mergeBreachResults(_ updates: [String: BreachCache.Entry]) {
        guard !updates.isEmpty, store.isUnlocked else { return }
        let keep = BreachMonitor.passwords(in: store.items)
        perform {
            try self.store.updateMeta { m in
                for (k, v) in updates { m.breachCache.entries[k] = v }
                m.breachCache.prune(keeping: keep)
            }
        }
    }

    private func checkSaved(_ password: String, title: String) {
        guard meta.settings.breachCheckEnabled, !Headless.active, !meta.breachCache.isFresh(password) else { return }
        let checker = breachChecker, cache = meta.breachCache
        Task { [weak self] in
            guard let c = try? await checker.breachCount(for: password), let self, self.phase == .unlocked else { return }
            self.mergeBreachResults([cache.key(password): .init(count: c, checked: Date())])
            if c > 0 { self.flash("“\(title)”: \(BreachMonitor.describe(count: c)). Consider changing it.") }
        }
    }

    /// Live check while typing. Callers debounce; uses the cache first, never stores the result.
    func liveBreach(_ password: String) async -> LiveBreach {
        guard meta.settings.breachCheckEnabled else { return .off }
        guard !password.isEmpty, !Headless.active else { return .off }
        if meta.breachCache.isFresh(password), let e = meta.breachCache.result(for: password) { return e.count > 0 ? .found(e.count) : .clean }
        do { let c = try await breachChecker.breachCount(for: password); return c > 0 ? .found(c) : .clean }
        catch { return .failed(error.localizedDescription) }
    }

    /// One-click fix from Watchtower: open the editor with a freshly generated password.
    func regenerate(_ item: VaultItem) {
        var i = item
        i.password = PasswordGenerator.random(meta.settings.generator).password
        tab = .vault; selection = item.id; editing = i
        flash("New password generated. Change it on the website too, then Save.")
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
        let wasOn = meta.settings.breachCheckEnabled
        perform { try self.store.updateMeta { change(&$0.settings) } }
        if phase == .unlocked { startAutoLock() }
        if !meta.settings.breachCheckEnabled { sweepTask?.cancel(); sweepTask = nil; breachSweepRunning = false }
        else if !wasOn { startBreachSweep(force: false) }
    }

    func perform(_ body: () throws -> Void) {
        do { try body(); error = nil } catch { self.error = error.localizedDescription }
        reload()
    }

    func copy(_ secret: String, label: String) {
        guard !Headless.active else { return }
        let secs = meta.settings.clipboardClearSeconds
        ClipboardGuard.shared.copy(secret, clearAfter: secs)
        let deadline: Date? = secs > 0 ? Date().addingTimeInterval(Double(secs)) : nil
        clipboardDeadline = deadline
        if let deadline {
            Task { try? await Task.sleep(for: .seconds(secs)); if clipboardDeadline == deadline { clipboardDeadline = nil } }
        }
        flash(secs > 0 ? "\(label) copied. Clipboard clears in \(secs) s." : "\(label) copied.")
    }

    func clearClipboardNow() {
        guard !Headless.active else { return }
        ClipboardGuard.shared.clearIfOurs(); clipboardDeadline = nil
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
        reload()
        if checkBreaches { startBreachSweep(force: true) }
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
