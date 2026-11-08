import Foundation
import RampartShared

/// One macOS notification the app (menu bar process) should post for Cat & Mouse. Produced by the session
/// daemon for every catch and every lure attempt that wasn't refused; pushed to the app over the
/// `subscribeEvents` stream (as `.deception(JSON of this)`) and kept in `DeceptionStatus.alerts` so an app that
/// starts later still posts what it missed.
public struct CatMouseAlert: Codable, Hashable, Sendable, Identifiable {
    public var id: UUID = UUID()               // this emission (the app posts each id once)
    public var date: Date
    /// Notification request identifier: the same story keeps the same identifier, so a burst replaces one
    /// notification (with a growing count) instead of stacking many.
    public var identifier: String
    public var title: String
    public var body: String
    public var severity: Severity
    public var timeSensitive: Bool
    /// How many touches this story has had so far.
    public var count: Int
    public var catchID: UUID?
    /// The program to offer "Contain it" for (only when known; the app checks it is still running).
    public var pid: Int32?
    public var processPath: String?
    public var calm: Bool = false              // the user opened a bait file: info only, never time-sensitive
}

/// Groups bursts into stories: touches within `window` seconds of the previous one in the same story share one
/// notification whose body carries the count. Tone follows the user's choice; facts and severity never change.
public struct CatMouseAlertPlanner: Sendable {
    public var window: TimeInterval = 120
    private var catchStory: (id: String, last: Date, count: Int, first: String)?
    private var lureStory: (id: String, last: Date, count: Int)?
    public init(window: TimeInterval = 120) { self.window = window }

    static func q(_ s: String) -> String { DeceptionVoice.q(s) }

    /// "'cat'", "probably 'cat'", or "Something".
    static func who(_ c: DeceptionCatch) -> String {
        switch c.attribution {
        case .unknown?: return "Something"
        case .commandLine?: return "Probably " + q(c.processName)
        default: return q(c.processName)
        }
    }

    public mutating func alert(for c: DeceptionCatch, tone: DeceptionTone, now: Date = Date()) -> CatMouseAlert {
        if c.userOpened {
            let m = DeceptionVoice.userOpened(c, tone: tone)
            return CatMouseAlert(date: now, identifier: "catmouse.calm.\(c.id)", title: m.title, body: m.body, severity: .info,
                                 timeSensitive: false, count: 1, catchID: c.id, calm: true)
        }
        let file = Self.q((c.decoyPath as NSString).lastPathComponent)
        let sevMsg = DeceptionVoice.caught(c, tone: tone)
        let what: String
        switch c.access {
        case .mazeWalk: what = tone == .playful ? "is lost in the maze (\(c.mazeDeadEnds) dead end\(c.mazeDeadEnds == 1 ? "" : "s"))" : "searched the decoy folder maze (\(c.mazeDeadEnds) folder\(c.mazeDeadEnds == 1 ? "" : "s"))"
        case .read, .copy, .rename: what = (tone == .playful ? "grabbed " : (c.access == .read ? "read " : c.access == .copy ? "copied " : "moved ")) + file
        case .write: what = "changed " + file
        case .delete: what = "deleted " + file
        case .xattr: what = "changed the attributes of " + file
        }
        let limit = c.attribution == .unknown ? " (\(DeceptionVoice.unattributedLimit).)" : ""
        var story = catchStory
        if let s = story, now.timeIntervalSince(s.last) < window { story = (s.id, now, s.count + 1, s.first) }
        else { story = ("catmouse.story.\(UUID().uuidString)", now, 1, file) }
        catchStory = story
        let count = story!.count
        let more = count > 1 ? " \(count) bait touches in this burst so far." : ""
        let title = tone == .playful ? (count > 1 ? "🐱 The cat caught a mouse! (\(count))" : "🐱 The cat caught a mouse!")
                                     : (count > 1 ? "Decoy files accessed (\(count))" : "Decoy file accessed")
        let body = "\(Self.who(c)) \(what).\(limit)\(more) Severity: \(sevMsg.severity.label)."
        return CatMouseAlert(date: now, identifier: story!.id, title: title, body: body, severity: sevMsg.severity,
                             timeSensitive: sevMsg.severity >= .high, count: count, catchID: c.id,
                             pid: c.pid > 1 ? c.pid : nil, processPath: c.processPath.isEmpty ? nil : c.processPath)
    }

    public mutating func alert(for a: TarpitAttempt, tone: DeceptionTone, now: Date = Date()) -> CatMouseAlert {
        let m = DeceptionVoice.tarpit(a, tone: tone)
        var story = lureStory
        if let s = story, now.timeIntervalSince(s.last) < window { story = (s.id, now, s.count + 1) }
        else { story = ("catmouse.lure.\(UUID().uuidString)", now, 1) }
        lureStory = story
        let n = story!.count
        let creds = a.credentialAttempts > 0 ? " It tried \(a.credentialAttempts) password\(a.credentialAttempts == 1 ? "" : "s") (never stored)." : ""
        return CatMouseAlert(date: now, identifier: story!.id, title: n > 1 ? m.title + " (\(n))" : m.title,
                             body: m.body.replacingOccurrences(of: " Severity:", with: "\(creds)\(n > 1 ? " \(n) knocks in this burst." : "") Severity:"),
                             severity: m.severity, timeSensitive: true, count: n, catchID: nil)
    }
}
