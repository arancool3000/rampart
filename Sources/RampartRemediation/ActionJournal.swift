import Foundation
import RampartShared

/// How to reverse a completed action.
public enum UndoStep: Codable, Hashable, Sendable {
    case restoreQuarantine(id: UUID, originalPath: String)
    case runCommands([PrivilegedCommand])
    case restoreBackups([FileBackup])
    case composite([UndoStep])
    /// Not automatically reversible; text tells the user what to do.
    case manual(String)
    case notReversible(String)
}

public enum JournalPhase: String, Codable, Sendable {
    case pending, done, failed, undone, undoFailed, interrupted
    /// Written before an undo runs (hx3): a crash mid-undo leaves this, and the action is never undone a second time
    /// automatically (replaying e.g. an old crontab over newer edits would be data loss).
    case undoPending
}

/// One append-only line. The latest line per `actionID` gives the action's state.
public struct JournalRecord: Codable, Sendable {
    public var actionID: UUID
    public var transactionID: UUID
    public var seq: Int
    public var date: Date
    public var phase: JournalPhase
    public var action: RemediationAction
    public var beforeState: [String: String]
    public var undo: UndoStep?
    public var message: String?
    public init(actionID: UUID, transactionID: UUID, seq: Int, date: Date = Date(), phase: JournalPhase, action: RemediationAction,
                beforeState: [String: String] = [:], undo: UndoStep? = nil, message: String? = nil) {
        self.actionID = actionID; self.transactionID = transactionID; self.seq = seq; self.date = date; self.phase = phase
        self.action = action; self.beforeState = beforeState; self.undo = undo; self.message = message
    }
}

public struct JournalActionState: Sendable {
    public var actionID: UUID
    public var transactionID: UUID
    public var seq: Int
    public var action: RemediationAction
    public var phase: JournalPhase
    public var beforeState: [String: String]
    public var undo: UndoStep?
    public var history: [JournalRecord]
}

/// Append-only JSON-lines journal (`journal.jsonl`). Each state change is a new fsync'd line, so a crash
/// leaves at worst a truncated final line, which is ignored on replay. Actions written as `pending` but never
/// completed are reported by `recoverInterrupted()`.
public final class ActionJournal: @unchecked Sendable {
    public let directory: URL
    public var fileURL: URL { directory.appendingPathComponent("journal.jsonl") }
    public var backupsDir: URL { directory.appendingPathComponent("backups") }
    private let lock = NSLock()

    public static var defaultDirectory: URL { Paths.effectiveRoot.appendingPathComponent("Journal") }

    public init(directory: URL = ActionJournal.defaultDirectory) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        chmod(directory.path, 0o700)
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            let fd = open(fileURL.path, O_WRONLY | O_CREAT | O_EXCL, 0o600); if fd >= 0 { close(fd) }
        }
    }

    public func append(_ r: JournalRecord) throws {
        lock.lock(); defer { lock.unlock() }
        var line = try JSONEncoder.rampartSorted.encode(r)
        line.append(0x0A)
        let fd = open(fileURL.path, O_WRONLY | O_APPEND | O_CREAT, 0o600)
        guard fd >= 0 else { throw RemediationError.ioError("open journal: \(String(cString: strerror(errno)))") }
        defer { close(fd) }
        // If the previous writer crashed mid-line, start on a fresh line.
        var st = stat()
        if fstat(fd, &st) == 0, st.st_size > 0 {
            let rfd = open(fileURL.path, O_RDONLY); var last: UInt8 = 0x0A
            if rfd >= 0 { _ = pread(rfd, &last, 1, st.st_size - 1); close(rfd) }
            if last != 0x0A { line.insert(0x0A, at: 0) }
        }
        let ok = line.withUnsafeBytes { write(fd, $0.baseAddress, line.count) } == line.count
        fsync(fd)
        guard ok else { throw RemediationError.ioError("journal write") }
    }

    /// All parsable records in order; corrupt/truncated lines are skipped.
    public func records() -> [JournalRecord] {
        lock.lock(); defer { lock.unlock() }
        guard let d = FileManager.default.contents(atPath: fileURL.path) else { return [] }
        let dec = JSONDecoder.rampart
        return d.split(separator: 0x0A).compactMap { try? dec.decode(JournalRecord.self, from: Data($0)) }
    }

    public func states() -> [JournalActionState] {
        var order: [UUID] = []
        var map: [UUID: JournalActionState] = [:]
        for r in records() {
            if var s = map[r.actionID] {
                s.phase = r.phase; s.history.append(r)
                if !r.beforeState.isEmpty { s.beforeState = r.beforeState }
                if r.undo != nil { s.undo = r.undo }
                map[r.actionID] = s
            } else {
                order.append(r.actionID)
                map[r.actionID] = JournalActionState(actionID: r.actionID, transactionID: r.transactionID, seq: r.seq, action: r.action,
                                                     phase: r.phase, beforeState: r.beforeState, undo: r.undo, history: [r])
            }
        }
        return order.compactMap { map[$0] }
    }

    public func transaction(_ id: UUID) -> [JournalActionState] {
        states().filter { $0.transactionID == id }.sorted { $0.seq < $1.seq }
    }

    public func transactionIDs() -> [UUID] {
        var seen = Set<UUID>(); var out: [UUID] = []
        for s in states() where seen.insert(s.transactionID).inserted { out.append(s.transactionID) }
        return out
    }

    /// Actions left `pending` by a crash. Marks them `interrupted` and returns them so the caller can
    /// re-verify the system state (e.g. does the file still exist? is the job still loaded?).
    @discardableResult
    public func recoverInterrupted() -> [JournalActionState] {
        let stuck = states().filter { $0.phase == .pending || $0.phase == .undoPending }
        for s in stuck {
            try? append(JournalRecord(actionID: s.actionID, transactionID: s.transactionID, seq: s.seq, date: Date(), phase: .interrupted,
                                      action: s.action, beforeState: [:], undo: nil, message: "recovered after crash; verify state"))
        }
        return stuck
    }
}
