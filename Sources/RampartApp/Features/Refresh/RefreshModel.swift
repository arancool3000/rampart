import SwiftUI
import AppKit
import Observation
import RampartShared
import RampartRefresh

/// State for RamPart Refresh. Scans run off the main thread; cleaning always goes through a preview first.
@MainActor
@Observable
final class RefreshModel {
    static let shared = RefreshModel()

    enum Phase: Equatable { case idle, scanning(String), ready, cleaning, done }
    enum Tab: String, CaseIterable, Identifiable { case storage = "Storage", map = "Disk Map", speed = "Speed"; var id: String { rawValue } }

    var tab: Tab = .storage
    var phase: Phase = .idle
    var results: [RefreshCategoryResult] = []
    var includePersonal = UserDefaults.standard.bool(forKey: "refresh.includePersonal") {
        didSet { UserDefaults.standard.set(includePersonal, forKey: "refresh.includePersonal") }
    }
    var volume: DiskSizer.VolumeInfo? = DiskSizer.volume()
    var lastOutcome: RefreshOutcome?
    var lastUndo: [RefreshUndoEntry] = []
    var undoMessage: String?
    var showPreview = false
    var previewRefused: [(RefreshItem, RefreshRefusal)] = []
    var trashBytes: UInt64 = 0
    var confirmEmptyTrash = false

    // Disk map
    var mapRoot: DiskMapper.Node?
    var mapStack: [DiskMapper.Node] = []
    var mapping = false
    @ObservationIgnored private var mapper: DiskMapper?

    // Speed
    var memory: SpeedMonitor.Memory?
    var topApps: [SpeedMonitor.AppUsage] = []
    var sampling = false
    var quitRequested: Set<String> = []
    var forceQuitCandidate: SpeedMonitor.AppUsage?

    @ObservationIgnored private var scanner: RefreshScanner?
    /// Cat & Mouse decoys and the maze are on the safety policy's skip list, so Refresh never "cleans them up".
    /// Falls back to every decoy path in the last status when the helper predates `exclusions`.
    var cleaner: RefreshCleaner {
        let st = CatAndMouseModel.shared.status
        return RefreshCleaner(policy: RefreshSafetyPolicy(decoyPaths: st?.exclusions ?? st?.decoys.map(\.path) ?? []))
    }

    // MARK: Derived

    var actionable: [RefreshCategoryResult] { results.filter { $0.category.actionable && $0.category != .trash } }
    var infoOnly: [RefreshCategoryResult] { results.filter { !$0.category.actionable || $0.category == .trash } }
    var selectedItems: [RefreshItem] { actionable.flatMap { $0.items.filter(\.selected) } }
    var selectedBytes: UInt64 { selectedItems.reduce(0) { $0 + $1.bytes } }
    var reclaimableBytes: UInt64 { actionable.reduce(0) { $0 + $1.totalBytes } }
    var isScanning: Bool { if case .scanning = phase { return true }; return false }

    // MARK: Scan

    func scan() {
        guard !isScanning else { return }
        phase = .scanning("Getting ready…")
        lastOutcome = nil
        let running = Set(NSWorkspace.shared.runningApplications.compactMap(\.bundleIdentifier))
        let env = RefreshScanner.Environment(runningBundleIDs: running, includePersonal: includePersonal)
        let s = RefreshScanner(env: env)
        scanner = s
        Task.detached(priority: .utility) {
            let r = s.scan { c in Task { @MainActor in RefreshModel.shared.phase = .scanning(c.title) } }
            await MainActor.run {
                let m = RefreshModel.shared
                guard m.scanner === s else { return }
                m.results = r
                m.trashBytes = r.first { $0.category == .trash }?.totalBytes ?? 0
                m.volume = DiskSizer.volume()
                m.phase = s.cancelled ? .idle : .ready
            }
        }
    }

    func cancelScan() { scanner?.cancel(); scanner = nil; phase = results.isEmpty ? .idle : .ready }

    // MARK: Selection

    func toggle(_ c: RefreshCategory, on: Bool) {
        guard let i = results.firstIndex(where: { $0.category == c }), c.actionable else { return }
        for j in results[i].items.indices { results[i].items[j].selected = on }
    }
    func toggle(item: RefreshItem) {
        guard let i = results.firstIndex(where: { $0.category == item.category }),
              let j = results[i].items.firstIndex(where: { $0.path == item.path }) else { return }
        results[i].items[j].selected.toggle()
    }
    func categoryState(_ r: RefreshCategoryResult) -> Bool? {
        let n = r.items.filter(\.selected).count
        return n == 0 ? false : (n == r.items.count ? true : nil)
    }
    func resetToSmartSelection() {
        let scorer = RefreshScorer()
        for i in results.indices { for j in results[i].items.indices { results[i].items[j].reason = ""; scorer.score(&results[i].items[j]) } }
    }

    // MARK: Clean

    /// Smart Refresh: scan if needed, then show the preview. Nothing is moved until the user confirms in the preview.
    func smartRefresh() {
        if results.isEmpty { scan(); return }
        preparePreview()
    }

    func preparePreview() {
        let items = selectedItems
        Task {
            // Fresh decoy list first (the user may never have opened Cat & Mouse this session).
            await CatAndMouseModel.shared.refresh()
            let c = cleaner
            let p = await Task.detached(priority: .userInitiated) { c.preview(items) }.value
            RefreshModel.shared.previewRefused = p.refused
            RefreshModel.shared.showPreview = true
        }
    }

    func confirmClean() {
        showPreview = false
        let items = selectedItems
        phase = .cleaning
        let c = cleaner
        Task.detached(priority: .userInitiated) {
            let out = c.clean(items, dryRun: RefreshModel.dryRun)
            await MainActor.run {
                let m = RefreshModel.shared
                m.lastOutcome = out
                m.lastUndo = out.trashed
                let freed = ByteCountFormatter.string(fromByteCount: Int64(out.freedBytes), countStyle: .file)
                AppModel.shared.recordActivity(ActivityEntry(kind: .refresh, title: "Cleaned up \(freed)", outcome: "cleaned", event: .refreshCleanup, actor: .user,
                    action: RefreshModel.dryRun ? "Practice run: nothing was moved." : "Moved the items to the Bin so this can be undone.",
                    count: out.trashed.count, found: out.failed.count,
                    facts: ["freed": freed, "skipped for safety": out.refused.isEmpty ? "" : String(out.refused.count),
                            "couldn't be removed": out.failed.isEmpty ? "" : String(out.failed.count)]))
                let gone = Set(out.trashed.map(\.original))
                for i in m.results.indices { m.results[i].items.removeAll { gone.contains($0.path) } }
                m.volume = DiskSizer.volume()
                m.phase = .done
            }
        }
    }

    func undoLast() {
        let entries = lastUndo
        let c = cleaner
        Task.detached {
            let r = c.undo(entries)
            await MainActor.run {
                let m = RefreshModel.shared
                m.undoMessage = r.skipped.isEmpty ? "Put back \(r.restored.count) item\(r.restored.count == 1 ? "" : "s")."
                    : "Put back \(r.restored.count); \(r.skipped.count) couldn't be restored (already moved or replaced)."
                AppModel.shared.recordActivity(ActivityEntry(kind: .refresh, title: "Undid the last clean-up", outcome: "undone", event: .refreshUndo, actor: .user,
                    count: r.restored.count, facts: ["couldn't be restored": r.skipped.isEmpty ? "" : String(r.skipped.count)]))
                m.lastUndo = []
                m.results = []
                m.phase = .idle
                m.scan()
            }
        }
    }

    func emptyTrash() {
        confirmEmptyTrash = false
        let c = cleaner
        Task.detached {
            _ = try? c.emptyTrash(confirmed: true, dryRun: RefreshModel.dryRun)
            await MainActor.run {
                let m = RefreshModel.shared
                let freed = ByteCountFormatter.string(fromByteCount: Int64(m.trashBytes), countStyle: .file)
                AppModel.shared.recordActivity(ActivityEntry(kind: .refresh, title: "Emptied the Bin", outcome: "cleaned", event: .refreshCleanup, actor: .user,
                    action: "Deleted the Bin's contents permanently.", facts: ["freed": freed]))
                m.trashBytes = 0
                m.results.removeAll { $0.category == .trash }
                m.volume = DiskSizer.volume()
            }
        }
    }

    /// `--refresh-dry-run` (or RAMPART_REFRESH_DRY_RUN=1) makes every clean a dry run, for development.
    nonisolated static let dryRun = CommandLine.arguments.contains("--refresh-dry-run") || ProcessInfo.processInfo.environment["RAMPART_REFRESH_DRY_RUN"] == "1"

    // MARK: Disk map

    func buildMap() {
        mapper?.cancel()
        let m = DiskMapper(includeProtected: includePersonal, maxDepth: 3)
        mapper = m
        mapping = true
        Task.detached(priority: .utility) {
            let root = m.map(NSHomeDirectory())
            await MainActor.run {
                let s = RefreshModel.shared
                guard s.mapper === m else { return }
                s.mapRoot = root; s.mapStack = [root]; s.mapping = false
            }
        }
    }
    func cancelMap() { mapper?.cancel(); mapping = false }

    // MARK: Speed

    func sample() {
        guard !sampling else { return }
        sampling = true
        Task.detached(priority: .utility) {
            let a = SpeedMonitor.sampleProcesses()
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            let b = SpeedMonitor.sampleProcesses()
            let usage = SpeedMonitor.usage(before: a, after: b, interval: 1)
            let mem = SpeedMonitor.memory()
            await MainActor.run {
                let s = RefreshModel.shared
                s.topApps = Array(usage.prefix(12)); s.memory = mem; s.sampling = false
            }
        }
    }

    func runningApp(for u: SpeedMonitor.AppUsage) -> NSRunningApplication? {
        guard let path = u.appPath else { return nil }
        return NSWorkspace.shared.runningApplications.first { $0.bundleURL?.path == path }
    }

    /// Asks the app to quit normally (it can save work or ask about unsaved documents). Never force-quits.
    func quit(_ u: SpeedMonitor.AppUsage) {
        guard let app = runningApp(for: u), app.processIdentifier != getpid() else { return }
        quitRequested.insert(u.key)
        app.terminate()
        Task { try? await Task.sleep(nanoseconds: 2_500_000_000); sample() }
    }

    /// Only after the user explicitly confirmed force quitting (unsaved work is lost).
    func forceQuit(_ u: SpeedMonitor.AppUsage) {
        forceQuitCandidate = nil
        guard let app = runningApp(for: u), app.processIdentifier != getpid() else { return }
        app.forceTerminate()
        Task { try? await Task.sleep(nanoseconds: 1_500_000_000); sample() }
    }

    // MARK: AI hook

    /// Optional: ask RamPart's AI assistant (only when the user turned it on) to explain an item. Sends only the
    /// category, size, age and path with the home folder replaced by "~".
    func askAI(about item: RefreshItem) {
        let ai = AIChatModel.shared
        guard ai.enabled else { return }
        let path = item.path.replacingOccurrences(of: NSHomeDirectory(), with: "~")
        ai.newChat()
        ai.draft = "Is it safe to remove this from my Mac? Category: \(item.category.title). Path: \(path). Size: \(item.bytes.refreshFormatted). \(item.reason)"
        AppModel.shared.selection = .aiAssistant
    }
}
