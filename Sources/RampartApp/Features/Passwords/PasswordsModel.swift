import SwiftUI
import AppKit
import Observation
import UniformTypeIdentifiers
import RampartVault
import RampartShared
import LocalAuthentication

/// State for the Passwords screen. One shared instance so the lock state survives sidebar navigation.
/// Never logs secrets; decrypted items live only while unlocked and are dropped on lock.
@MainActor
@Observable
final class PasswordsModel {
    static let shared = PasswordsModel()
    /// The lock screen auto-offers Touch ID once per launch.
    static var didAutoPromptTouchID = false

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
    /// Set after a master-password unlock while Touch ID is available but off (cleared by "Not Now").
    var touchIDOfferDismissed = false
    @ObservationIgnored private var unlockedWithMaster = false
    /// Touch ID passed but the security-chip key failed: switch to compatibility mode after the next master unlock.
    @ObservationIgnored private var touchIDNeedsRepair = false
    /// A fresh security-chip key also failed: offer compatibility mode, but only as the user's explicit choice
    /// (switching automatically would let anyone who can corrupt touchid.json downgrade Touch ID).
    var touchIDCompatSuggested = false
    static let touchIDRepairKey = "rampart.vault.touchIDRepairAttempts"
    /// The vault file is older than the anti-rollback mark; the user may tick "Open anyway".
    var rollbackPending = false
    var acceptRollback = false
    var offerTouchID: Bool { phase == .unlocked && unlockedWithMaster && !touchIDEnabled && availability.biometryAvailable && !touchIDOfferDismissed && !Headless.active }
    var audit: VaultAudit?
    var auditRunning = false
    var auditNote: String?
    var breachSweepRunning = false
    /// Last 10 generated passwords, memory only; cleared on lock.
    var generatorHistory = GeneratorHistory()
    /// When the copied secret will be cleared from the clipboard (drives the countdown).
    var clipboardDeadline: Date?
    /// The one locked item currently revealed (re-locks on navigation, hide, minimise or 60 s idle).
    var revealedItem: UUID?
    var itemUnlockError: String?
    @ObservationIgnored private var revealTimer: Timer?
    @ObservationIgnored private var revealObservers: [NSObjectProtocol] = []
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
        // Re-check each time (lid closed, keyboard connected, fingers enrolled since launch). No prompt.
        if !Headless.active { availability = TouchIDUnlock.availability() }
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
        let accept = rollbackPending && acceptRollback
        let result: Error? = await Task.detached { () -> Error? in
            do { try store.unlock(masterPassword: master, acceptRollback: accept); return nil } catch { return error }
        }.value
        busy = false
        if let result {
            if case VaultError.rolledBack = result { rollbackPending = true }
            error = result.localizedDescription; return
        }
        rollbackPending = false; acceptRollback = false
        unlockedWithMaster = true
        didUnlock()
        repairTouchIDIfNeeded()
    }

    /// After the security chip refused the key, re-enrol Touch ID in compatibility (keychain) mode.
    private func repairTouchIDIfNeeded() {
        guard touchIDNeedsRepair, !Headless.active else { return }
        touchIDNeedsRepair = false
        let defaults = UserDefaults.standard
        if defaults.integer(forKey: Self.touchIDRepairKey) == 0 {
            // First failure: re-enrol with a FRESH security-chip key (a corrupted or swapped touchid.json is fixed
            // this way without weakening anything).
            defaults.set(1, forKey: Self.touchIDRepairKey)
            do {
                let mode = try touchID.enable(forceMode: .secureEnclave)
                flash(mode == .secureEnclave ? "Touch ID was set up again with a new security-chip key." : "Touch ID is on (compatibility mode).")
            } catch { self.error = "Touch ID couldn't be set up: \(error.localizedDescription)" }
        } else {
            touchIDCompatSuggested = true
            self.error = "Touch ID still can't use this Mac's security chip. You can choose compatibility mode in Passwords › Settings; it is weaker, see the note there."
        }
        refreshPhase()
    }

    /// The user's explicit choice after the security chip kept failing.
    func useTouchIDCompatibilityMode() {
        guard !Headless.active else { return }
        do {
            _ = try touchID.enable(forceMode: .keychainGated)
            touchIDCompatSuggested = false
            UserDefaults.standard.removeObject(forKey: Self.touchIDRepairKey)
            flash("Touch ID is on (compatibility mode).")
        } catch { self.error = error.localizedDescription }
        refreshPhase()
    }

    func unlockWithTouchID() async {
        guard !Headless.active else { return }
        error = nil
        do {
            try await touchID.unlock(); unlockedWithMaster = false
            UserDefaults.standard.removeObject(forKey: Self.touchIDRepairKey)
            didUnlock()
        }
        catch VaultError.cancelled { }
        catch VaultError.secureEnclaveFailed(let why) {
            touchIDNeedsRepair = true
            self.error = "Touch ID recognised you, but this Mac's security chip couldn't open the vault key (\(why)). Unlock with your master password once and \(Product.name) will fix Touch ID automatically."
            refreshPhase()
        }
        catch {
            if case VaultError.rolledBack = error { rollbackPending = true }
            self.error = error.localizedDescription; refreshPhase()
        }
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
        relockItem()
        breachChecker.clearCache()
        generatorHistory.clear(); clipboardDeadline = nil
        ClipboardGuard.shared.clearIfOurs()
        store.lock()
        items = []; editing = nil; selection = nil; audit = nil; search = ""; unlockedWithMaster = false
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
        let secs = min(ClipboardGuard.clearRange.upperBound, max(ClipboardGuard.clearRange.lowerBound, meta.settings.clipboardClearSeconds))
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
            UserDefaults.standard.removeObject(forKey: Self.touchIDRepairKey); touchIDCompatSuggested = false
            do {
                let mode = try touchID.enable()
                flash(mode == .secureEnclave ? "Touch ID is on, protected by your Mac's security chip." : "Touch ID is on (compatibility mode).")
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

    // MARK: Per-item lock (secure notes and "Require Touch ID to view")

    func isItemHidden(_ item: VaultItem) -> Bool { meta.requiresItemUnlock(item) && revealedItem != item.id }

    func setItemLock(_ id: UUID, _ on: Bool) {
        perform { try self.store.updateMeta { m in m.lockedItems.removeAll { $0 == id }; if on { m.lockedItems.append(id) } } }
    }

    /// Touch ID (falling back to the Mac's login password). Never called during development or headless.
    func unlockItem(_ item: VaultItem) async {
        guard !Headless.active else { return }
        itemUnlockError = nil
        let ctx = LAContext()
        ctx.localizedFallbackTitle = "Use Password"
        var err: NSError?
        guard ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &err) else {
            itemUnlockError = "Touch ID isn't available. Enter your master password instead."; return
        }
        do {
            let ok = try await ctx.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: "show “\(item.title)”")
            if ok { reveal(item.id) }
        } catch let e as LAError where e.code == .userCancel || e.code == .appCancel || e.code == .systemCancel {
        } catch { itemUnlockError = error.localizedDescription }
    }

    func unlockItem(_ item: VaultItem, master: String) async {
        if await verifyMaster(master) { reveal(item.id) } else { itemUnlockError = "That master password is not correct." }
    }

    private func reveal(_ id: UUID) {
        relockItem()
        revealedItem = id
        let nc = NotificationCenter.default
        for name in [NSApplication.didHideNotification, NSApplication.didResignActiveNotification, NSWindow.didMiniaturizeNotification] {
            revealObservers.append(nc.addObserver(forName: name, object: nil, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated { self?.relockItem() }
            })
        }
        revealTimer = Timer.scheduledTimer(withTimeInterval: 5, repeats: true) { [weak self] _ in
            MainActor.assumeIsolated { if AutoLock.systemIdleSeconds >= 60 { self?.relockItem() } }
        }
    }

    /// Hides the revealed item again and stops watching. Views never keep their own copy of the content.
    func relockItem() {
        revealTimer?.invalidate(); revealTimer = nil
        for o in revealObservers { NotificationCenter.default.removeObserver(o) }
        revealObservers = []
        if revealedItem != nil { revealedItem = nil }
    }

    // MARK: Authenticator (accounts are .totp vault items; secrets stay inside the encrypted vault)

    var authenticatorItems: [VaultItem] {
        let auth = items.filter { $0.kind == .totp && $0.totp != nil }
        let order = Dictionary(meta.authenticatorOrder.enumerated().map { ($1, $0) }, uniquingKeysWith: { a, _ in a })
        return auth.sorted { a, b in
            if a.favourite != b.favourite { return a.favourite }
            let oa = order[a.id] ?? Int.max, ob = order[b.id] ?? Int.max
            return oa != ob ? oa < ob : a.title.localizedCaseInsensitiveCompare(b.title) == .orderedAscending
        }
    }

    /// Adds accounts, skipping duplicates. Returns (added, duplicates).
    @discardableResult
    func addAuthenticatorAccounts(_ accounts: [TOTP]) -> (Int, Int) {
        let existing = items.compactMap(\.totp)
        let (kept, dup) = Authenticator.dedupe(accounts, against: existing)
        if !kept.isEmpty { perform { try self.store.insert(kept.map(Authenticator.makeItem)) } }
        flash("Added \(kept.count) account\(kept.count == 1 ? "" : "s")\(dup > 0 ? ", skipped \(dup) duplicate\(dup == 1 ? "" : "s")" : "").")
        return (kept.count, dup)
    }

    func moveAuthenticator(from: IndexSet, to: Int) {
        var ids = authenticatorItems.map(\.id)
        ids.move(fromOffsets: from, toOffset: to)
        perform { try self.store.updateMeta { $0.authenticatorOrder = ids } }
    }

    /// HOTP: advance the counter (shows the next code) and save.
    func advanceHOTP(_ item: VaultItem) {
        guard var t = item.totp, t.kind == .hotp else { return }
        t.counter += 1
        var i = item; i.totpSecret = t.uri
        perform { try self.store.upsert(i) }
    }

    func verifyMaster(_ pw: String) async -> Bool {
        let store = store
        return await Task.detached { store.verifyMasterPassword(pw) }.value
    }

    func exportAuthenticator(password: String) async {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "RamPart Authenticator.rpexport"
        panel.message = "The export is encrypted with the password you chose."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        let auth = authenticatorItems
        let result: Result<Data, Error> = await Task.detached { Result { try EncryptedExport.export(items: auth, folders: [], password: password) } }.value
        busy = false
        switch result {
        case .success(let d):
            do { try Self.writePrivate(d, to: url); flash("Exported \(auth.count) accounts, encrypted.") } catch { self.error = error.localizedDescription }
        case .failure(let e): error = e.localizedDescription
        }
    }

    // MARK: Import / export

    func importCSV() {
        let panel = NSOpenPanel()
        panel.allowedContentTypes = [.commaSeparatedText, .plainText]
        panel.message = "Choose a CSV exported from Chrome, Firefox, Safari, Bitwarden or 1Password."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > CSVImporter.maxBytes {
            error = "That file is too large to be a password export."; return
        }
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
        panel.message = "The export is encrypted with the password you chose."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        busy = true
        let items = items, folders = meta.folders
        let result: Result<Data, Error> = await Task.detached { Result { try EncryptedExport.export(items: items, folders: folders, password: password) } }.value
        busy = false
        switch result {
        case .success(let d):
            do { try Self.writePrivate(d, to: url); flash("Exported \(items.count) items, encrypted.") } catch { self.error = error.localizedDescription }
        case .failure(let e): error = e.localizedDescription
        }
    }

    func importEncrypted(password: String) async {
        let panel = NSOpenPanel()
        panel.message = "Choose a RamPart export (.rpexport)."
        guard panel.runModal() == .OK, let url = panel.url else { return }
        if let size = (try? url.resourceValues(forKeys: [.fileSizeKey]))?.fileSize, size > 512 * 1_048_576 {
            error = "That file is too large to be a RamPart export."; return
        }
        guard let data = try? Data(contentsOf: url) else { return }
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

    /// Writes a file only the user can read (0600), atomically. Used for exports and saved attachments.
    nonisolated static func writePrivate(_ data: Data, to url: URL) throws {
        try data.write(to: url, options: [.atomic])
        try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }

    func saveToKeychain(_ item: VaultItem) {
        do { try LoginKeychain.save(item); flash("Saved to your login keychain.") }
        catch VaultError.cancelled { }
        catch { self.error = error.localizedDescription }
    }
}
