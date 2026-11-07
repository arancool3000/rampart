import Foundation
import RampartShared

/// Protection Activity entries for features that run in the app process (PasteGuard, Wi-Fi guard, vault,
/// authenticator, Refresh, network scan, Protect Everything, and actions taken while the service is offline).
/// JSON lines in ~/Library/Application Support/Rampart/app-activity.jsonl (0600), kept for 90 days.
/// Never written in headless checks. Never holds secrets: callers pass counts and names only.
@MainActor
final class AppActivityLog {
    static let retention: TimeInterval = 90 * 86_400
    static let keep = 20_000

    private(set) var entries: [ActivityEntry] = []
    private let url: URL?
    private var bytes = 0
    /// Who did what, for daemon entries the app caused (AI-approved changes, "in Settings").
    private(set) var annotations: [UUID: Annotation] = [:]
    private let annotationsURL: URL?
    private var notes: [Note] = []

    struct Annotation: Codable, Hashable { var actor: ActivityActor; var place: String?; var date: Date? }
    private struct Note { var date: Date; var actor: ActivityActor; var place: String?; var events: Set<ActivityEvent> }

    init(directory: URL? = AppActivityLog.defaultDirectory) {
        if let directory {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
            url = directory.appendingPathComponent("app-activity.jsonl")
            annotationsURL = directory.appendingPathComponent("app-activity-annotations.json")
        } else { url = nil; annotationsURL = nil }
        load()
    }

    nonisolated static var defaultDirectory: URL? {
        if Headless.active { return nil }
        return FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Application Support/Rampart")
    }

    private func load() {
        guard let url, let d = try? Data(contentsOf: url) else { return }
        bytes = d.count
        let dec = JSONDecoder.rampart
        let cutoff = Date().addingTimeInterval(-Self.retention)
        for line in d.split(separator: 0x0a) {
            if let e = try? dec.decode(ActivityEntry.self, from: Data(line)), e.date >= cutoff { entries.append(e) }
        }
        if entries.count > Self.keep { entries.removeFirst(entries.count - Self.keep) }
        if let au = annotationsURL, let a = try? Data(contentsOf: au),
           let m = try? JSONDecoder.rampart.decode([String: Annotation].self, from: a) {
            for (k, v) in m { if let id = UUID(uuidString: k) { annotations[id] = v } }
        }
    }

    func add(_ e: ActivityEntry) {
        var e = e
        e.title = SafeText.line(e.title, max: 200); e.detail = SafeText.line(e.detail, max: 2000); e.outcome = SafeText.line(e.outcome, max: 120)
        e.reason = e.reason.map { SafeText.line($0, max: 1000) }; e.target = e.target.map { SafeText.line($0, max: 600) }
        e.action = e.action.map { SafeText.line($0, max: 600) }
        entries.append(e)
        if entries.count > Self.keep { entries.removeFirst(entries.count - Self.keep) }
        guard let url, var line = try? JSONEncoder.rampart.encode(e) else { return }
        line.append(0x0a)
        bytes += line.count
        if bytes > 24 << 20 { rewrite(); return }
        let fd = open(url.path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { return }
        defer { close(fd) }
        _ = line.withUnsafeBytes { Darwin.write(fd, $0.baseAddress!, $0.count) }
    }

    private func rewrite() {
        guard let url else { return }
        let cutoff = Date().addingTimeInterval(-Self.retention)
        entries.removeAll { $0.date < cutoff }
        let enc = JSONEncoder.rampart
        var out = Data()
        for e in entries { if let l = try? enc.encode(e) { out.append(l); out.append(0x0a) } }
        try? out.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        bytes = out.count
    }

    // MARK: who did it

    /// The app is about to ask the service for a change: daemon entries of these types that arrive within a few
    /// seconds are attributed to `actor` (and `place`, e.g. "Settings").
    func note(_ actor: ActivityActor, place: String? = nil, events: Set<ActivityEvent>) {
        notes.append(Note(date: Date(), actor: actor, place: place, events: events))
        let cutoff = Date().addingTimeInterval(-120)
        notes.removeAll { $0.date < cutoff }
    }

    /// Applies notes and saved annotations to daemon entries.
    func annotate(_ e: ActivityEntry) -> ActivityEntry {
        var e = e
        if let a = annotations[e.id] {
            e.actor = a.actor
            if let p = a.place { var f = e.facts ?? [:]; f["where"] = p; e.facts = f }
            return e
        }
        guard !notes.isEmpty else { return e }
        let ev = ActivityPresenter.event(for: e)
        // Newest matching note wins (an AI action wraps the app's own Settings call).
        if let n = notes.last(where: { $0.events.contains(ev) && e.date >= $0.date.addingTimeInterval(-2) && e.date <= $0.date.addingTimeInterval(30) }) {
            let a = Annotation(actor: n.actor, place: n.place, date: e.date)
            annotations[e.id] = a
            if annotations.count > 5000 {
                let cutoff = Date().addingTimeInterval(-Self.retention)
                annotations = annotations.filter { ($0.value.date ?? .distantPast) >= cutoff }
            }
            saveAnnotations()
            e.actor = a.actor
            if let p = a.place { var f = e.facts ?? [:]; f["where"] = p; e.facts = f }
        }
        return e
    }

    private func saveAnnotations() {
        guard let au = annotationsURL else { return }
        let m = Dictionary(uniqueKeysWithValues: annotations.map { ($0.key.uuidString, $0.value) })
        if let d = try? JSONEncoder.rampart.encode(m) {
            try? d.write(to: au, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: au.path)
        }
    }
}

/// Settings-type events a note can attribute.
extension ActivityEvent {
    static let attributable: Set<ActivityEvent> = [
        .settingsChanged, .protectionToggled, .protectionPaused, .protectionResumed, .allowRuleAdded, .allowRuleRemoved,
        .postureFixed, .postureFixFailed, .remoteLockdownChanged, .remoteAccessAllowed, .remoteAccessRevoked,
        .scanStarted, .scanFinished, .scanCancelled, .definitionsUpdated, .definitionsFailed, .quarantined, .restored, .deleted,
        .startupItemRemoved, .lockdownStarted, .lockdownLifted,
    ]
}
