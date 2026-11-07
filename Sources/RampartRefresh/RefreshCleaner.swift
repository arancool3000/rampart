import Foundation

/// Moves items to the Trash (never deletes), re-checking the safety policy for every path at the moment of cleaning,
/// and journals each move so it can be undone. `dryRun` reports what would happen without touching anything.
public final class RefreshCleaner: @unchecked Sendable {
    public typealias Trasher = (URL) throws -> URL?
    public let policy: RefreshSafetyPolicy
    public let journalURL: URL
    let trasher: Trasher
    let fm = FileManager.default

    public static var defaultJournal: URL {
        URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support/Rampart/Refresh/undo.json")
    }

    /// `trasher` defaults to FileManager.trashItem; tests pass one that moves into a scratch folder.
    public init(policy: RefreshSafetyPolicy = RefreshSafetyPolicy(), journalURL: URL = RefreshCleaner.defaultJournal, trasher: Trasher? = nil) {
        self.policy = policy
        self.journalURL = journalURL
        self.trasher = trasher ?? { url in
            var out: NSURL?
            try FileManager.default.trashItem(at: url, resultingItemURL: &out)
            return out as URL?
        }
    }

    /// Preview: which items would be refused and why (same checks the real run makes).
    public func preview(_ items: [RefreshItem]) -> (ok: [RefreshItem], refused: [(RefreshItem, RefreshRefusal)]) {
        let openNow = policy.openFilesOverride ?? OpenFiles.snapshot()
        var p = policy; p.openFilesOverride = openNow
        var ok: [RefreshItem] = [], refused: [(RefreshItem, RefreshRefusal)] = []
        for it in items {
            if !it.category.actionable { refused.append((it, .systemPath)); continue }
            if let r = p.refusal(it.path) { refused.append((it, r)) } else { ok.append(it) }
        }
        return (ok, refused)
    }

    public func clean(_ items: [RefreshItem], dryRun: Bool) -> RefreshOutcome {
        var outcome = RefreshOutcome(dryRun: dryRun)
        var p = policy
        p.openFilesOverride = policy.openFilesOverride ?? OpenFiles.snapshot()   // one snapshot per run
        // Never trash a parent and its child in the same run (the child would already be gone).
        let paths = Set(items.map(\.path))
        for it in items.sorted(by: { $0.path < $1.path }) {
            if paths.contains(where: { it.path.hasPrefix($0 + "/") }) { continue }
            guard it.category.actionable else { outcome.refused.append((it.path, .systemPath)); continue }
            if let r = p.refusal(it.path) { outcome.refused.append((it.path, r)); continue }
            if dryRun {
                outcome.trashed.append(RefreshUndoEntry(original: it.path, trashed: "", bytes: it.bytes, date: Date()))
                continue
            }
            do {
                let dest = try trasher(URL(fileURLWithPath: it.path))
                outcome.trashed.append(RefreshUndoEntry(original: it.path, trashed: dest?.path ?? "", bytes: it.bytes, date: Date()))
            } catch {
                outcome.failed.append((it.path, error.localizedDescription))
            }
        }
        if !dryRun, !outcome.trashed.isEmpty { appendJournal(outcome.trashed) }
        return outcome
    }

    // MARK: Undo

    public func journal() -> [RefreshUndoEntry] {
        guard let d = try? Data(contentsOf: journalURL) else { return [] }
        return (try? JSONDecoder().decode([RefreshUndoEntry].self, from: d)) ?? []
    }

    func appendJournal(_ e: [RefreshUndoEntry]) {
        var all = journal() + e
        let cutoff = Date().addingTimeInterval(-30 * 86400)
        all.removeAll { $0.date < cutoff }
        try? fm.createDirectory(at: journalURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let d = try? JSONEncoder().encode(all) { try? d.write(to: journalURL, options: .atomic) }
    }

    /// Puts trashed items back where they were. Never overwrites: if something now exists at the original path, it's skipped.
    @discardableResult
    public func undo(_ entries: [RefreshUndoEntry]) -> (restored: [String], skipped: [String]) {
        var restored: [String] = [], skipped: [String] = []
        for e in entries {
            guard !e.trashed.isEmpty, fm.fileExists(atPath: e.trashed), !fm.fileExists(atPath: e.original) else { skipped.append(e.original); continue }
            do {
                try fm.createDirectory(atPath: (e.original as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
                try fm.moveItem(atPath: e.trashed, toPath: e.original)
                restored.append(e.original)
            } catch { skipped.append(e.original) }
        }
        let done = Set(restored)
        let remaining = journal().filter { !done.contains($0.original) }
        if let d = try? JSONEncoder().encode(remaining) { try? d.write(to: journalURL, options: .atomic) }
        return (restored, skipped)
    }

    // MARK: Emptying the Trash (the only permanent action; requires explicit confirmation)

    public enum EmptyTrashError: Error { case notConfirmed }

    /// Permanently removes everything in `trashDir` (default ~/.Trash). `confirmed` must come from an explicit user confirmation.
    public func emptyTrash(confirmed: Bool, trashDir: String = NSHomeDirectory() + "/.Trash", dryRun: Bool) throws -> UInt64 {
        guard confirmed else { throw EmptyTrashError.notConfirmed }
        var freed: UInt64 = 0
        for n in (try? fm.contentsOfDirectory(atPath: trashDir)) ?? [] {
            let p = trashDir + "/" + n
            freed += DiskSizer.measure(p).total
            if !dryRun { try? fm.removeItem(atPath: p) }
        }
        return freed
    }
}
