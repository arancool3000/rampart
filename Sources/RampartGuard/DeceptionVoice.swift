import Foundation
import RampartShared

/// Every Cat & Mouse sentence, in both tones. Rule: the playful line always carries the same facts and the same
/// severity word as the serious one; humour never hides severity. Attacker-controlled names are sanitised and quoted.
public struct DeceptionMessage: Codable, Hashable, Sendable {
    public var title: String
    public var body: String
    public var severity: Severity
}

public enum DeceptionVoice {
    static func q(_ s: String) -> String { "'" + SafeText.line(s, max: 60).replacingOccurrences(of: "'", with: "’") + "'" }

    static func decoyLabel(_ k: DecoyKind) -> String {
        switch k {
        case .passwordsSheet: return "fake passwords file"
        case .cryptoSeed: return "fake crypto wallet seed"
        case .sshKey: return "fake SSH key"
        case .awsCredentials: return "fake cloud credentials"
        case .browserLoginData: return "fake browser logins"
        case .mazeNote, .mazeDir, .mazeLink: return "decoy maze"
        }
    }

    /// The exact honest limit, shown whenever RamPart couldn't identify the program.
    public static let unattributedLimit = "RamPart couldn't see which program without Full Disk Access / the system service"

    static func verb(_ a: DeceptionAccess) -> String {
        switch a {
        case .read: return "read"
        case .write: return "changed"
        case .rename: return "moved"
        case .delete: return "deleted"
        case .xattr: return "changed the attributes of"
        case .copy: return "copied"
        case .mazeWalk: return "searched"
        }
    }

    public static func caught(_ c: DeceptionCatch, tone: DeceptionTone) -> DeceptionMessage {
        if c.attribution == .unknown || c.attribution == .commandLine { return caughtUnsure(c, tone: tone) }
        let sev: Severity = c.access == .mazeWalk && c.mazeDeadEnds < 10 ? .high : .critical
        let who = q(c.processName)
        switch (tone, c.access) {
        case (.playful, .mazeWalk):
            return .init(title: "🐱 The cat is playing with the mouse",
                         body: "\(who) is lost in the maze (\(c.mazeDeadEnds) dead ends so far). Severity: \(sev.label).", severity: sev)
        case (.serious, .mazeWalk):
            return .init(title: "Decoy folders are being searched",
                         body: "\(who) (pid \(c.pid)) has opened \(c.mazeDeadEnds) decoy folders. This looks like automated data theft. Severity: \(sev.label).", severity: sev)
        case (.playful, _):
            let verb = c.access == .rename || c.access == .copy ? "tried to run off with" : "sniffed"
            return .init(title: "🐱 The cat caught a mouse",
                         body: "\(who) \(verb) your \(decoyLabel(c.decoyKind)). Severity: \(sev.label).", severity: sev)
        case (.serious, _):
            return .init(title: "Decoy file accessed",
                         body: "\(who) (pid \(c.pid)) accessed a RamPart \(decoyLabel(c.decoyKind)). No legitimate app does this. Severity: \(sev.label).", severity: sev)
        }
    }

    /// No actor (user mode without the system service), or only a likely one from a command line. Same facts in
    /// both tones; severity High (it is still a real touch of a file nobody legitimate opens).
    static func caughtUnsure(_ c: DeceptionCatch, tone: DeceptionTone) -> DeceptionMessage {
        let sev: Severity = .high
        let file = q((c.decoyPath as NSString).lastPathComponent)
        let what = c.access == .mazeWalk ? "searched the decoy folder maze (\(c.mazeDeadEnds) folder\(c.mazeDeadEnds == 1 ? "" : "s") so far)"
            : "\(verb(c.access)) your \(decoyLabel(c.decoyKind)) \(file)"
        let dest = c.destPath.map { " It ended up at \(q(($0 as NSString).lastPathComponent))." } ?? ""
        let when = c.note.map { " (\($0))" } ?? ""
        if c.attribution == .commandLine {
            let who = q(c.processName)
            switch tone {
            case .playful:
                return .init(title: "🐱 The cat caught a mouse (probably \(who))",
                             body: "Something \(what)\(when). Probably \(who): its command line named the file.\(dest) Severity: \(sev.label).", severity: sev)
            case .serious:
                return .init(title: "Decoy file accessed, probably by \(who)",
                             body: "Something \(what)\(when). Likely \(who) (pid \(c.pid)): its command line named the file.\(dest) Severity: \(sev.label).", severity: sev)
            }
        }
        switch tone {
        case .playful:
            return .init(title: "🐱 Something touched a bait file",
                         body: "Something \(what)\(when). \(unattributedLimit).\(dest) Severity: \(sev.label).", severity: sev)
        case .serious:
            return .init(title: "Decoy file accessed (program unknown)",
                         body: "Something \(what)\(when). \(unattributedLimit).\(dest) No legitimate app does this. Severity: \(sev.label).", severity: sev)
        }
    }

    /// Calm note when the user opened a bait file themselves. Info severity, no alert sound, no detection.
    public static func userOpened(_ c: DeceptionCatch, tone: DeceptionTone) -> DeceptionMessage {
        let file = q((c.decoyPath as NSString).lastPathComponent)
        switch tone {
        case .playful: return .init(title: "🐱 That's one of our bait files", body: "You opened \(file) with \(q(c.processName)). Nothing's wrong: it's RamPart's decoy, full of jokes. The cat says hi.", severity: .info)
        case .serious: return .init(title: "You opened a RamPart bait file", body: "\(file) is a decoy RamPart placed to catch data thieves. You opened it with \(q(c.processName)); nothing's wrong.", severity: .info)
        }
    }

    public static func contained(_ c: DeceptionCatch, tone: DeceptionTone) -> DeceptionMessage {
        switch tone {
        case .playful: return .init(title: "🐭 Mouse contained", body: "RamPart froze \(q(c.processName)) and moved it to quarantine.", severity: .critical)
        case .serious: return .init(title: "Threat contained", body: "RamPart stopped \(q(c.processName)) (pid \(c.pid)) and quarantined it.", severity: .critical)
        }
    }

    public static func tarpit(_ a: TarpitAttempt, tone: DeceptionTone) -> DeceptionMessage {
        switch tone {
        case .playful: return .init(title: "🐱 A mouse knocked on port \(a.port)",
                                    body: "\(SafeText.line(a.remote, max: 60)) got the slow treatment for \(Int(a.seconds)) s and a few bad jokes. Severity: High.", severity: .high)
        case .serious: return .init(title: "Blocked connection recorded",
                                    body: "An unapproved connection from \(SafeText.line(a.remote, max: 60)) to port \(a.port) was held by the honeypot for \(Int(a.seconds)) s and logged. Severity: High.", severity: .high)
        }
    }

    public static func verdictLine(_ v: DeceptionVerdict, tone: DeceptionTone) -> String {
        switch (tone, v.level) {
        case (.playful, .dangerous): return "This mouse has sharp teeth: \(v.summary)"
        case (.playful, .suspicious): return "Shifty mouse. \(v.summary)"
        case (.playful, .likelyBenign): return "Probably a lost house mouse. \(v.summary)"
        case (.serious, _): return "\(v.level.label): \(v.summary)"
        }
    }
}
