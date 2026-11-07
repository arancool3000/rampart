import Foundation
import RampartShared

/// A typed remediation action. The daemon accepts only these, never raw shell.
public enum RemediationAction: Codable, Hashable, Sendable {
    case quarantineFile(path: String, detectionName: String)
    case killProcessTree(pid: Int32, startTime: UInt64)
    case launchdJob(LaunchdJob)
    case removeLoginItem(name: String, path: String?)
    case removeProfile(identifier: String)
    case removeBrowserExtension(browser: String, profilePath: String, extensionID: String)
    case removeCronLines(user: String?, containing: [String])

    public var title: String {
        switch self {
        case .quarantineFile(let p, let n): return "Quarantine \(p) (\(n))"
        case .killProcessTree(let pid, _): return "Stop process \(pid) and its children"
        case .launchdJob(let j): return "Stop and disable launch job \(j.serviceTarget)"
        case .removeLoginItem(let n, _): return "Remove login item \(n)"
        case .removeProfile(let id): return "Remove configuration profile \(id)"
        case .removeBrowserExtension(let b, let p, let e): return "Remove \(b) extension \(e) (\((p as NSString).lastPathComponent))"
        case .removeCronLines(let u, let c): return "Remove cron lines for \(u ?? "current user") matching \(c.joined(separator: ", "))"
        }
    }
    public var reversible: Bool {
        switch self {
        case .killProcessTree, .removeProfile: return false
        case .removeLoginItem(_, let path): return path != nil
        default: return true
        }
    }
}

public struct PlannedStep: Codable, Sendable {
    public var action: RemediationAction
    public var commands: [PrivilegedCommand]
    public var reversible: Bool
    public var notes: [String]
}

/// Ordered list of actions run as one journaled transaction: plan -> preview -> apply -> (undo).
public struct RemediationPlan: Codable, Sendable {
    public var id: UUID
    public var title: String
    public var actions: [RemediationAction]
    public init(id: UUID = UUID(), title: String, actions: [RemediationAction]) {
        self.id = id; self.title = title; self.actions = actions
    }

    /// Recommended order: kill processes, unload jobs, then remove persistence, then quarantine files.
    public func ordered() -> RemediationPlan {
        func rank(_ a: RemediationAction) -> Int {
            switch a {
            case .launchdJob: return 0
            case .killProcessTree: return 1
            case .removeLoginItem, .removeProfile, .removeCronLines, .removeBrowserExtension: return 2
            case .quarantineFile: return 3
            }
        }
        var p = self
        p.actions = actions.enumerated().sorted { (rank($0.element), $0.offset) < (rank($1.element), $1.offset) }.map(\.element)
        return p
    }
}

public struct StepResult: Codable, Sendable {
    public var actionID: UUID
    public var action: RemediationAction
    public var success: Bool
    public var message: String
    public var undo: UndoStep?
}

public struct PlanResult: Codable, Sendable {
    public var transactionID: UUID
    public var dryRun: Bool
    public var steps: [StepResult]
    public var allSucceeded: Bool { steps.allSatisfy(\.success) }
}

/// Runs plans against the remediation components and journals every step.
public final class RemediationExecutor: @unchecked Sendable {
    public let vault: QuarantineVault
    public let journal: ActionJournal
    public let killer: ProcessKiller
    public let launchd: LaunchdRemediator
    public let loginItems: LoginItemCleaner
    public let profiles: ProfileCleaner
    public let cron: CronCleaner
    public let browsers: BrowserExtensionCleaner
    public let runner: CommandRunner

    public init(vault: QuarantineVault, journal: ActionJournal, runner: CommandRunner = ProcessCommandRunner(),
                killer: ProcessKiller = ProcessKiller(), browsers: BrowserExtensionCleaner = BrowserExtensionCleaner()) {
        self.vault = vault; self.journal = journal; self.runner = runner; self.killer = killer
        self.launchd = LaunchdRemediator(runner: runner)
        self.loginItems = LoginItemCleaner(runner: runner)
        self.profiles = ProfileCleaner(runner: runner)
        self.cron = CronCleaner(runner: runner)
        self.browsers = browsers
    }

    // MARK: Preview

    public func preview(_ plan: RemediationPlan) -> [PlannedStep] {
        plan.actions.map { a in
            var cmds: [PrivilegedCommand] = []
            var notes: [String] = []
            switch a {
            case .quarantineFile(let p, _):
                if ProtectedPaths.isProtected(p) { notes.append("REFUSED: protected path") }
                if !FileManager.default.fileExists(atPath: p) { notes.append("file not found") }
                notes.append("encrypted into vault; restorable until purge")
            case .killProcessTree(let pid, let start):
                let r = killer.killTree(ProcessIdentity(pid: pid, startTime: start), dryRun: true)
                notes.append("will stop \(r.plan.count) process(es): " + r.plan.map { "\($0.identity.pid) \(($0.path as NSString).lastPathComponent)" }.joined(separator: ", "))
                notes += r.skipped
                notes.append("not reversible; restoring files/jobs lets it start again")
            case .launchdJob(let j):
                cmds = launchd.commands(for: j)
                if j.domain.requiresRoot { notes.append("requires root") }
            case .removeLoginItem(let n, let path):
                cmds = [loginItems.removeCommand(name: n)]
                notes.append("needs Automation permission for System Events")
                if path == nil { notes.append("undo is manual (path unknown)") }
            case .removeProfile(let id):
                cmds = [profiles.exportCommand(), profiles.removeCommand(identifier: id)]
                notes.append("undo is manual: profiles cannot be reinstalled from the CLI")
            case .removeBrowserExtension(let b, let prof, let ext):
                if let spec = BrowserSpec.named(b) {
                    if browsers.isRunning(spec) { notes.append("\(b) is running: close it first") }
                    if let o = try? browsers.remove(browser: spec, profile: URL(fileURLWithPath: prof), extensionID: ext, backupDir: journal.backupsDir, dryRun: true) {
                        notes.append("moves: " + (o.beforeState["moved"] ?? "")); notes.append("edits: " + (o.beforeState["edited"] ?? ""))
                    } else { notes.append("extension not found") }
                } else { notes.append("unknown browser \(b)") }
            case .removeCronLines(let u, let c):
                if let o = try? cron.remove(user: u, containing: c, dryRun: true) {
                    cmds = o.commands; notes.append("lines: " + (o.beforeState["removed"] ?? ""))
                }
            }
            return PlannedStep(action: a, commands: cmds, reversible: a.reversible, notes: notes)
        }
    }

    public func previewText(_ plan: RemediationPlan) -> String {
        var s = "Plan: \(plan.title)\n"
        for (i, step) in preview(plan).enumerated() {
            s += "\(i + 1). \(step.action.title)\(step.reversible ? "" : " [not reversible]")\n"
            for c in step.commands { s += "     $ \(c)\(c.requiresRoot ? "   (root)" : "")\n" }
            for n in step.notes { s += "     - \(n)\n" }
        }
        return s
    }

    // MARK: Apply

    /// Runs the plan. In dry-run nothing is changed or journaled. `stopOnFailure` keeps partial state
    /// for the caller to decide: roll back (`undo(transaction:)`) or keep.
    public func run(_ plan: RemediationPlan, dryRun: Bool = true, stopOnFailure: Bool = true) -> PlanResult {
        var result = PlanResult(transactionID: plan.id, dryRun: dryRun, steps: [])
        if dryRun {
            for step in preview(plan) {
                result.steps.append(StepResult(actionID: UUID(), action: step.action, success: !step.notes.contains { $0.hasPrefix("REFUSED") },
                                               message: (step.commands.map(\.description) + step.notes).joined(separator: "; "), undo: nil))
            }
            return result
        }
        for (seq, a) in plan.actions.enumerated() {
            let aid = UUID()
            try? journal.append(JournalRecord(actionID: aid, transactionID: plan.id, seq: seq, date: Date(), phase: .pending,
                                              action: a, beforeState: [:], undo: nil, message: nil))
            do {
                let (before, undo, msg) = try apply(a, actionID: aid)
                try? journal.append(JournalRecord(actionID: aid, transactionID: plan.id, seq: seq, date: Date(), phase: .done,
                                                  action: a, beforeState: before, undo: undo, message: msg))
                result.steps.append(StepResult(actionID: aid, action: a, success: true, message: msg, undo: undo))
            } catch {
                try? journal.append(JournalRecord(actionID: aid, transactionID: plan.id, seq: seq, date: Date(), phase: .failed,
                                                  action: a, beforeState: [:], undo: nil, message: "\(error)"))
                result.steps.append(StepResult(actionID: aid, action: a, success: false, message: "\(error)", undo: nil))
                if stopOnFailure { break }
            }
        }
        return result
    }

    private func apply(_ a: RemediationAction, actionID: UUID) throws -> ([String: String], UndoStep, String) {
        let bdir = journal.backupsDir.appendingPathComponent(actionID.uuidString)
        switch a {
        case .quarantineFile(let p, let name):
            let r = try vault.quarantine(path: p, detectionName: name)
            return (["path": p, "sha256": r.sha256, "vaultID": r.id.uuidString, "mode": String(r.mode, radix: 8)],
                    .restoreQuarantine(id: r.id, originalPath: p), "quarantined as \(r.id)")
        case .killProcessTree(let pid, let start):
            let r = killer.killTree(ProcessIdentity(pid: pid, startTime: start), dryRun: false)
            if r.plan.isEmpty { throw RemediationError.notFound("process \(pid): " + r.skipped.joined(separator: "; ")) }
            let before = ["processes": r.plan.map { "\($0.identity.pid):\($0.path)" }.joined(separator: "\n")]
            if !r.survivors.isEmpty { throw RemediationError.commandFailed("survivors: \(r.survivors)") }
            return (before, .notReversible("killed processes cannot be restarted by undo"), "killed \(r.killed.count)")
        case .launchdJob(let j):
            var before: [String: String] = ["label": j.label, "domain": j.domain.description, "plist": j.plistPath ?? ""]
            if let p = j.plistPath, let d = FileManager.default.contents(atPath: p) { before["plistBase64"] = d.base64EncodedString() }
            let r = launchd.remediate(j, dryRun: false)
            if let w = r.wasDisabled { before["wasDisabled"] = String(w) }
            if !r.errors.isEmpty { throw RemediationError.commandFailed(r.errors.joined(separator: "; ")) }
            return (before, .runCommands(r.undoCommands), "booted out and disabled \(j.serviceTarget)")
        case .removeLoginItem(let n, let path):
            let o = try loginItems.remove(name: n, path: path, dryRun: false)
            return (o.beforeState, o.undoCommands.isEmpty ? .manual(o.manualUndo ?? "") : .runCommands(o.undoCommands), o.summary)
        case .removeProfile(let id):
            let o = try profiles.remove(identifier: id, backupDir: bdir, dryRun: false)
            return (o.beforeState, .manual(o.manualUndo ?? ""), o.summary)
        case .removeBrowserExtension(let b, let prof, let ext):
            guard let spec = BrowserSpec.named(b) else { throw RemediationError.unsupported("browser \(b)") }
            let o = try browsers.remove(browser: spec, profile: URL(fileURLWithPath: prof), extensionID: ext, backupDir: bdir, dryRun: false)
            return (o.beforeState, .restoreBackups(o.backups), o.summary)
        case .removeCronLines(let u, let c):
            let o = try cron.remove(user: u, containing: c, dryRun: false)
            return (o.beforeState, .runCommands(o.undoCommands), o.summary)
        }
    }

    // MARK: Undo

    /// Reverts completed steps of a transaction in reverse order.
    public func undo(transaction id: UUID) -> [StepResult] {
        journal.transaction(id).filter { $0.phase == .done }.reversed().map { undoAction($0) }
    }

    public func undoAction(_ s: JournalActionState) -> StepResult {
        guard let u = s.undo else { return StepResult(actionID: s.actionID, action: s.action, success: false, message: "no undo recorded", undo: nil) }
        // hx3: undo only what the journal says is done right now (a stale state passed in twice is refused), and mark it
        // in progress first so a crash can't lead to a second replay.
        guard let current = journal.states().first(where: { $0.actionID == s.actionID }), current.phase == .done else {
            return StepResult(actionID: s.actionID, action: s.action, success: false, message: "already undone or not complete", undo: nil)
        }
        do {
            try journal.append(JournalRecord(actionID: s.actionID, transactionID: s.transactionID, seq: s.seq, date: Date(), phase: .undoPending,
                                             action: s.action, beforeState: [:], undo: nil, message: nil))
        } catch {
            return StepResult(actionID: s.actionID, action: s.action, success: false, message: "journal not writable: \(error)", undo: nil)
        }
        do {
            let msg = try perform(u)
            try? journal.append(JournalRecord(actionID: s.actionID, transactionID: s.transactionID, seq: s.seq, date: Date(), phase: .undone,
                                              action: s.action, beforeState: [:], undo: nil, message: msg))
            return StepResult(actionID: s.actionID, action: s.action, success: true, message: msg, undo: nil)
        } catch {
            try? journal.append(JournalRecord(actionID: s.actionID, transactionID: s.transactionID, seq: s.seq, date: Date(), phase: .undoFailed,
                                              action: s.action, beforeState: [:], undo: nil, message: "\(error)"))
            return StepResult(actionID: s.actionID, action: s.action, success: false, message: "\(error)", undo: nil)
        }
    }

    private func perform(_ u: UndoStep) throws -> String {
        switch u {
        case .restoreQuarantine(let id, _):
            return "restored to " + (try vault.restore(id: id))
        case .runCommands(let cmds):
            for c in cmds {
                let r = runner.run(c)
                if !r.succeeded { throw RemediationError.commandFailed("\(c): \(r.stderr)") }
            }
            return "ran \(cmds.count) command(s)"
        case .restoreBackups(let bs):
            for b in bs.reversed() { try BackupIO.restore(b) }
            return "restored \(bs.count) file(s)"
        case .composite(let steps):
            return try steps.reversed().map { try perform($0) }.joined(separator: "; ")
        case .manual(let s): throw RemediationError.unsupported("manual undo: \(s)")
        case .notReversible(let s): throw RemediationError.unsupported(s)
        }
    }
}
