import Foundation
import CoreGraphics

// Floating bot logic with no UI dependencies (the selftest compiles this file through a symlink):
// the state machine, speech-bubble text (sanitised), edge snapping and the pixel-box animator.

// MARK: State machine

enum BotState: String, Equatable, CaseIterable {
    case assembling, idle, scanning, alert, celebrating, sleeping, happy, thinking, talking, listening
}

enum BotEvent: Equatable {
    case assembled
    case scanStarted, scanFinished(threats: Int)
    case threatFound, threatsCleared
    case catCaught
    case lockdownOn, lockdownOff
    case wifiWarning
    case protectionPaused, protectionResumed
    case chatThinking, chatAnswered, chatEnded
    case voiceListening, voiceStopped
    case transientElapsed
}

struct BotStateMachine: Equatable {
    private(set) var state: BotState = .assembling
    private(set) var threats = false
    private(set) var lockdown = false
    private(set) var paused = false
    private(set) var scanning = false

    init(state: BotState = .assembling) { self.state = state }

    /// The resting state the flags imply. Alert outranks everything; a paused guard sleeps unless it is scanning.
    var base: BotState {
        if threats || lockdown { return .alert }
        if scanning { return .scanning }
        if paused { return .sleeping }
        return .idle
    }

    /// States that end by themselves (the controller sends `.transientElapsed` after `duration`).
    static func duration(_ s: BotState) -> TimeInterval? {
        switch s {
        case .celebrating: return 2.6
        case .happy: return 2.2
        case .talking: return 3.0
        case .alert: return 3.0      // only a Wi-Fi warning makes alert transient; sticky alerts re-enter via `base`
        default: return nil
        }
    }

    private var inChat: Bool { state == .thinking || state == .talking || state == .listening }

    @discardableResult
    mutating func handle(_ e: BotEvent) -> BotState {
        let assembling = state == .assembling
        switch e {
        case .assembled: if assembling { state = base }; return state
        case .scanStarted: scanning = true
        case .scanFinished(let n): scanning = false; if n > 0 { threats = true }
        case .threatFound: threats = true
        case .threatsCleared: threats = false
        case .lockdownOn: lockdown = true
        case .lockdownOff: lockdown = false
        case .protectionPaused: paused = true
        case .protectionResumed: paused = false
        default: break
        }
        guard !assembling else { return state }
        switch e {
        case .scanStarted: if !inChat && state != .alert { state = .scanning }
        case .scanFinished(let n): if !inChat { state = n > 0 ? .alert : (base == .alert ? .alert : .happy) }
        case .threatFound, .lockdownOn: if !inChat { state = .alert }
        case .threatsCleared, .lockdownOff: if state == .alert { state = base == .alert ? .alert : .happy }
        case .catCaught: if !inChat { state = .celebrating }
        case .wifiWarning: if !inChat && state != .alert { state = .alert }
        case .protectionPaused, .protectionResumed: if !inChat && state != .celebrating { state = base }
        case .chatThinking: state = .thinking
        case .chatAnswered: state = .talking
        case .chatEnded: if inChat { state = base }
        case .voiceListening: state = .listening
        case .voiceStopped: if state == .listening { state = base }
        case .transientElapsed: if Self.duration(state) != nil { state = base }
        case .assembled: break
        }
        return state
    }
}

// MARK: Speech bubbles

/// Short, fixed-template bubble lines. Only names (file, app, network) are interpolated, and they pass through
/// `sanitize`. Never the AI prompt, a reply body, a path with the user name, or anything that looks like a secret.
enum BotBubble {
    static let maxLength = 90

    static func scanDone(threats: Int) -> String {
        threats == 0 ? "Scan done. All clear!" : "Scan done. Found \(threats) thing\(threats == 1 ? "" : "s") to look at."
    }
    static func threat(_ name: String?) -> String {
        guard let n = name.map({ sanitize($0, max: 40) }), !n.isEmpty else { return "Threat found. I'm on it." }
        return sanitize("Threat found: \(n)")
    }
    static func catCaught(_ actor: String?) -> String {
        guard let a = actor.map({ sanitize($0, max: 36) }), !a.isEmpty else { return "Caught one! A program took the bait." }
        return sanitize("Caught one! \(a) took the bait.")
    }
    static func lockdown(_ on: Bool) -> String { on ? "Lockdown on. I've sealed things up." : "Lockdown lifted. Back to normal." }
    static func wifi(_ ssid: String?) -> String {
        guard let s = ssid.map({ sanitize($0, max: 32) }), !s.isEmpty else { return "Careful: this Wi-Fi isn't secure." }
        return sanitize("Careful: \"\(s)\" isn't secure.")
    }
    static let paused = "Protection paused. Napping…"
    static let resumed = "Back on guard."
    static let answerReady = "I've answered in the chat."

    /// Strips control and invisible characters, collapses whitespace, hides secrets and home paths, caps length.
    static func sanitize(_ input: String, max: Int = maxLength) -> String {
        var scalars = String.UnicodeScalarView()
        for u in input.unicodeScalars {
            switch u.properties.generalCategory {
            case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned: scalars.append(" ")
            default: scalars.append(u)
            }
        }
        var s = String(scalars)
        // Home paths → "~" so the account name never shows; long paths → last component.
        s = s.replacingOccurrences(of: #"/Users/[^/\s]+"#, with: "~", options: .regularExpression)
        s = s.replacingOccurrences(of: #"(?:~|/)[^\s"]*/([^/\s"]+)"#, with: "$1", options: .regularExpression)
        // Secrets: API keys, bearer tokens, long mixed alphanumeric runs, emails, "password: …".
        let secretPatterns = [
            #"AIza[0-9A-Za-z_\-]{20,}"#,
            #"\b(?:sk|pk|ghp|gho|xox[abp])[-_][0-9A-Za-z_\-]{10,}"#,
            #"(?i)\b(?:password|passcode|pin|token|secret|api[ _-]?key)\s*[:=]\s*\S+"#,
            #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#,
            #"\b(?=[A-Za-z0-9+/_\-]*[0-9])(?=[A-Za-z0-9+/_\-]*[A-Za-z])[A-Za-z0-9+/_\-]{24,}={0,2}"#,
        ]
        for p in secretPatterns { s = s.replacingOccurrences(of: p, with: "•••", options: .regularExpression) }
        s = s.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
        if s.count > max { s = String(s.prefix(Swift.max(1, max - 1))).trimmingCharacters(in: .whitespaces) + "…" }
        return s
    }
}

// MARK: Geometry

enum BotGeometry {
    /// Keeps the bot on screen and snaps it flush to an edge when it is dropped within `threshold` of one.
    static func snapped(_ frame: CGRect, in visible: CGRect, threshold: CGFloat = 32, margin: CGFloat = 4) -> CGPoint {
        var x = min(max(frame.minX, visible.minX + margin), visible.maxX - frame.width - margin)
        var y = min(max(frame.minY, visible.minY + margin), visible.maxY - frame.height - margin)
        if x - visible.minX < threshold + margin { x = visible.minX + margin }
        else if visible.maxX - (x + frame.width) < threshold + margin { x = visible.maxX - frame.width - margin }
        if y - visible.minY < threshold + margin { y = visible.minY + margin }
        else if visible.maxY - (y + frame.height) < threshold + margin { y = visible.maxY - frame.height - margin }
        return CGPoint(x: x, y: y)
    }

    /// Default spot: bottom-right corner of the visible frame.
    static func defaultOrigin(size: CGSize, in visible: CGRect, margin: CGFloat = 24) -> CGPoint {
        CGPoint(x: visible.maxX - size.width - margin, y: visible.minY + margin)
    }

    /// Which side of the bot a popover / bubble should open on (the side with more room).
    static func opensLeft(_ frame: CGRect, in visible: CGRect) -> Bool { frame.midX > visible.midX }
}

// MARK: Animator

/// Builds the animated cell list for a state. Cheap (a few hundred cells), deterministic in time.
enum BotAnimator {
    static let padX = 4, padTop = 6, padBottom = 1

    struct Frame {
        var cells: [PixelGuard.Cell]
        var mood: PixelGuard.Mood
        var plateAlpha: Double
        var rows: Int
    }

    static func frame(_ state: BotState, t: Double, clock: Double, reduceMotion: Bool,
                      variant: PixelGuard.Variant = PixelGuard.chosen) -> Frame {
        let head = PixelGuard.head(variant)
        let rows = head.count + PixelGuard.body.count
        let rm = reduceMotion
        var expr: PixelGuard.Expression = .neutral
        switch state {
        case .assembling, .idle: expr = (!rm && clock.truncatingRemainder(dividingBy: 4.3) < 0.14) ? .blink : .neutral
        case .scanning: expr = .scanning(rm ? 0 : Int(clock * 6))
        case .alert: expr = .alert
        case .celebrating, .happy: expr = .happy
        case .sleeping: expr = .sleeping
        case .thinking: expr = .typing(rm ? 0 : Int(clock * 5))
        case .talking: expr = .talking(rm ? 0 : Int(clock * 8))
        case .listening: expr = .listening
        }
        var cells = PixelGuard.cells(variant, expression: expr, body: true)
        let mood = PixelGuard.mood(for: expr)
        var plate = 1.0

        // Idle visor scan: one dim line sweeps the screen every 7 s.
        if state == .idle && !rm {
            let c = clock.truncatingRemainder(dividingBy: 7)
            if c < 0.9 {
                let f = PixelGuard.face(variant)
                let ys = Array(f.screenY)
                let ry = ys[min(ys.count - 1, Int(c / 0.9 * Double(ys.count)))]
                for x in f.screenX where !cells.contains(where: { $0.key == "e" && $0.x == x && $0.y == ry }) {
                    cells.append(.init(x: x, y: ry, key: "e", color: PixelGuard.Palette.scanLine))
                }
            }
        }

        let cx = Double(PixelGuard.cols) / 2 - 0.5, cy = Double(rows) / 2
        let rightArm: (PixelGuard.Cell) -> Bool = { ($0.key == "A" || $0.key == "h") && $0.x >= 13 }
        let wave = { (amount: Double) in
            for i in cells.indices where rightArm(cells[i]) {
                cells[i].dy -= 2 * amount
                cells[i].dx += rm ? 0 : sin(clock * 14) * 0.35 * amount
            }
        }

        if !rm {
            switch state {
            case .assembling:
                // Boxes fly in from scattered spots, top row first.
                for i in cells.indices {
                    let c = cells[i]
                    let h = hash(c.x, c.y)
                    let sx = (Double(h % 17) - 8) * 1.1, sy = (Double((h / 17) % 13) - 9) * 1.0
                    let delay = Double(c.y) / Double(rows) * 0.55
                    let p = clamp((t - delay) / 0.65)
                    let e = easeOutBack(p)
                    cells[i].dx = sx * (1 - e); cells[i].dy = sy * (1 - e)
                    cells[i].alpha = clamp(p * 2.5); cells[i].scale = 0.6 + 0.4 * clamp(p * 1.4)
                }
                plate = clamp((t - 1.05) / 0.3)
            case .scanning:
                for i in cells.indices {
                    let d = hypot(Double(cells[i].x) - cx, Double(cells[i].y) - cy)
                    cells[i].scale = 1 - 0.24 * max(0, sin(clock * 6 - d * 0.55))
                }
            case .alert:
                let phase = clock.truncatingRemainder(dividingBy: 2.5)
                let shake = phase < 0.7 ? sin(clock * 45) * 0.35 * (1 - phase / 0.7) : 0
                let blinkOff = Int(clock * 4) % 2 == 1
                for i in cells.indices {
                    cells[i].dx += shake
                    if cells[i].key == "L" && blinkOff { cells[i].alpha = 0.35 }
                }
            case .celebrating:
                wave(1)
                let bounce = t < 1.4 ? -abs(sin(t * 7)) * 0.7 : 0
                for i in cells.indices { cells[i].dy += bounce }
                cells += burst(t: t, rows: rows)
            case .happy:
                wave(t < 1.6 ? 1 : 0)
            case .sleeping:
                cells += zzz(clock: clock)
            case .thinking, .listening:
                let pulse = 0.55 + 0.45 * (0.5 + 0.5 * sin(clock * 5))
                for i in cells.indices where cells[i].key == "L" { cells[i].alpha = pulse }
            default: break
            }
        } else if state == .sleeping {
            cells += zzz(clock: 0)
        }
        return Frame(cells: cells, mood: mood, plateAlpha: plate, rows: rows)
    }

    /// "Cat caught a mouse": gold, mint and pink boxes burst out of the beacon and fade (1.4 s, finite).
    static func burst(t: Double, rows: Int) -> [PixelGuard.Cell] {
        guard t < 1.6 else { return [] }
        let colors = [PixelGuard.Palette.gold, PixelGuard.Palette.eye, PixelGuard.Palette.blush.with(alpha: 1 / 0.85)]
        var out: [PixelGuard.Cell] = []
        let n = 20
        for i in 0..<n {
            let a = Double(i) / Double(n) * 2 * .pi + 0.3
            let speed = 5.5 + Double(hash(i, 7) % 5)
            let p = easeOut(clamp(t / 1.4))
            let x = 7.5 + cos(a) * speed * p
            let y = 1 + sin(a) * speed * p * 0.85 + 2 * p * p
            var c = PixelGuard.Cell(x: 0, y: 0, key: "*", color: colors[i % colors.count])
            c.dx = x; c.dy = y
            c.alpha = 1 - clamp((t - 0.7) / 0.8); c.scale = 0.75
            out.append(c)
        }
        return out
    }

    /// Three small pixel "z"s drifting up from the beacon (cheap loop).
    static func zzz(clock: Double) -> [PixelGuard.Cell] {
        let z = [(0, 0), (1, 0), (2, 0), (1, 1), (0, 2), (1, 2), (2, 2)]
        var out: [PixelGuard.Cell] = []
        for k in 0..<2 {
            let p = (clock / 2.4 + Double(k) * 0.5).truncatingRemainder(dividingBy: 1)
            let baseX = 11 + p * 2, baseY = -1 - p * 4
            for (zx, zy) in z {
                var c = PixelGuard.Cell(x: 0, y: 0, key: "*", color: PixelRGBA(0xBFD3FF))
                c.dx = baseX + Double(zx) * 0.5; c.dy = baseY + Double(zy) * 0.5
                c.scale = 0.45; c.alpha = sin(p * .pi)
                out.append(c)
            }
        }
        return out
    }

    static func hash(_ a: Int, _ b: Int) -> Int { abs((a &* 73_856_093) ^ (b &* 19_349_663)) % 10_007 }
    static func clamp(_ v: Double) -> Double { min(1, max(0, v)) }
    static func easeOut(_ p: Double) -> Double { 1 - pow(1 - p, 3) }
    static func easeOutBack(_ p: Double) -> Double { let c = 1.4; return 1 + (c + 1) * pow(p - 1, 3) + c * pow(p - 1, 2) }
}
