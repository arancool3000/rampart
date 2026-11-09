import Foundation
import CoreGraphics

// Pixel Guard brand + floating bot: matrix shape and symmetry, face placement, state machine transitions,
// bubble text sanitising, edge snapping and the animator's bounds (PixelGuard.swift / BotLogic.swift are symlinked).
extension SelfTest {
    static func botChecks() {
        // Matrix shape: every row is exactly 16 boxes, only known keys, mirror-symmetric, strong silhouette.
        let keys = Set(".LsCGBHESTAhKPF")
        for v in PixelGuard.Variant.allCases {
            let h = PixelGuard.head(v)
            check(h.allSatisfy { $0.count == PixelGuard.cols }, "bot: \(v.name) rows are 16 wide")
            check(h.count >= 12 && h.count <= 16, "bot: \(v.name) head fits a 16x16 grid")
            check(h.allSatisfy { $0.allSatisfy { keys.contains($0) } }, "bot: \(v.name) uses known keys only")
            check(PixelGuard.isSymmetric(h), "bot: \(v.name) head is mirror-symmetric")
            check(PixelGuard.filled(h).count >= 100, "bot: \(v.name) head has a solid silhouette")
            check(h.first?.contains(where: { $0 != "." }) == true && h.last?.contains(where: { $0 != "." }) == true, "bot: \(v.name) no empty top/bottom rows")
            let f = PixelGuard.face(v)
            let screen = Set(h.enumerated().flatMap { y, row in row.enumerated().compactMap { x, c in c == "S" ? GridPoint(x: x, y: y) : nil } })
            for e in PixelGuard.faceCells(v, .neutral) {
                check(screen.contains(GridPoint(x: e.x, y: e.y)), "bot: \(v.name) eye/blush (\(e.x),\(e.y)) sits on the screen")
            }
            let eyes = PixelGuard.faceCells(v, .neutral).filter { $0.color == PixelGuard.Palette.eye }
            check(eyes.count == 2 * f.eyeW * f.eyeH, "bot: \(v.name) neutral face has two whole eyes")
            check(Set(eyes.map { $0.x }).map { PixelGuard.cols - 1 - $0 }.allSatisfy { x in eyes.contains { $0.x == x } }, "bot: \(v.name) eyes are symmetric")
            for e in [PixelGuard.Expression.blink, .happy, .alert, .sleeping, .thinking, .listening, .talking(1), .scanning(3), .typing(2)] {
                check(PixelGuard.faceCells(v, e).allSatisfy { f.screenX.contains($0.x) && f.screenY.contains($0.y) }, "bot: \(v.name) \(e) stays on the screen")
            }
        }
        check(PixelGuard.body.allSatisfy { $0.count == PixelGuard.cols } && PixelGuard.isSymmetric(PixelGuard.body), "bot: body is 16 wide and symmetric")
        check(PixelGuard.chosen == .capGuard, "bot: shipped mark is the Cap Guard")
        // Two-tone: right half is darker than the left for the shell.
        let l = PixelGuard.Palette.color("H", rightHalf: false), r = PixelGuard.Palette.color("H", rightHalf: true)
        check(l.r + l.g + l.b > r.r + r.g + r.b, "bot: right half is the shade side")
        check(PixelGuard.Palette.color("L", rightHalf: false, mood: .alert) == PixelGuard.Palette.beaconAlert, "bot: alert beacon is red")

        // Renderer: crisp at small sizes (no gaps, whole pixels), boxes with gaps when big.
        let small = PixelRenderer.layout(PixelGuard.cells(), cell: 1, origin: .zero)
        check(small.allSatisfy { $0.rect.width == 1 && $0.rect.minX == $0.rect.minX.rounded() && $0.radius == 0 }, "bot: 16 px boxes are whole pixels, no rounding")
        let big = PixelRenderer.layout(PixelGuard.cells(), cell: 40, origin: .zero)
        check(big.allSatisfy { $0.rect.width < 40 && $0.rect.width >= 34 && $0.radius > 0 }, "bot: large boxes are rounded with a small gap")
        check(big.allSatisfy { $0.rect.minX == $0.rect.minX.rounded() && $0.rect.minY == $0.rect.minY.rounded() }, "bot: large boxes are pixel-snapped")

        // State machine.
        var m = BotStateMachine()
        check(m.state == .assembling, "bot: starts assembling")
        m.handle(.threatFound)
        check(m.state == .assembling, "bot: events during assembly only set flags")
        m.handle(.assembled)
        check(m.state == .alert, "bot: assembles into alert when a threat is open")
        m.handle(.threatsCleared)
        check(m.state == .happy, "bot: all clear after threats are cleared")
        m.handle(.transientElapsed)
        check(m.state == .idle, "bot: happy fades back to idle")
        m.handle(.scanStarted)
        check(m.state == .scanning, "bot: scanning")
        m.handle(.scanFinished(threats: 0))
        check(m.state == .happy, "bot: clean scan is happy")
        m.handle(.scanStarted); m.handle(.scanFinished(threats: 2))
        check(m.state == .alert, "bot: scan with findings alerts")
        m.handle(.transientElapsed)
        check(m.state == .alert, "bot: a real threat keeps the alert")
        m.handle(.catCaught)
        check(m.state == .celebrating, "bot: Cat & Mouse catch celebrates")
        m.handle(.transientElapsed)
        check(m.state == .alert, "bot: back to alert after the celebration while threats are open")
        m.handle(.threatsCleared); m.handle(.transientElapsed)
        m.handle(.protectionPaused)
        check(m.state == .sleeping, "bot: paused protection sleeps")
        m.handle(.chatThinking)
        check(m.state == .thinking, "bot: chat request thinks")
        m.handle(.scanStarted)
        check(m.state == .thinking, "bot: background events don't interrupt the chat face")
        m.handle(.chatAnswered)
        check(m.state == .talking, "bot: answer talks")
        m.handle(.transientElapsed)
        check(m.state == .scanning, "bot: after talking, back to the base state (scanning outranks sleeping)")
        m.handle(.scanFinished(threats: 0)); m.handle(.transientElapsed)
        check(m.state == .sleeping, "bot: still asleep while paused")
        m.handle(.protectionResumed)
        check(m.state == .idle, "bot: resumes to idle")
        m.handle(.wifiWarning)
        check(m.state == .alert, "bot: Wi-Fi warning alerts")
        m.handle(.transientElapsed)
        check(m.state == .idle, "bot: Wi-Fi alert is transient")
        m.handle(.lockdownOn); m.handle(.transientElapsed)
        check(m.state == .alert, "bot: lockdown alert is sticky")
        m.handle(.lockdownOff)
        check(m.state == .happy, "bot: lockdown lifted is happy")
        m.handle(.voiceListening)
        check(m.state == .listening, "bot: listening")
        m.handle(.voiceStopped)
        check(m.state == .idle, "bot: stops listening")
        // Every state reachable and every state has a frame that stays near the grid.
        for s in BotState.allCases {
            for t in stride(from: 0.0, through: 3.0, by: 0.25) {
                let f = BotAnimator.frame(s, t: t, clock: t * 3.7, reduceMotion: false)
                let ok = f.cells.allSatisfy { Double($0.x) + $0.dx >= -Double(BotAnimator.padX) - 9 && Double($0.x) + $0.dx <= 16 + Double(BotAnimator.padX) + 9 }
                check(ok && f.cells.count > 150, "bot: \(s) frame at t=\(t) is bounded")
            }
            let still = BotAnimator.frame(s, t: 10, clock: 0, reduceMotion: true)
            check(still.cells.allSatisfy { $0.dx == 0 && $0.dy == 0 || $0.key == "*" } && still.plateAlpha == 1, "bot: \(s) reduce-motion pose is static")
        }
        check(BotAnimator.burst(t: 2, rows: 22).isEmpty, "bot: celebration burst is finite")

        // Bubble text sanitising.
        check(BotBubble.sanitize("Hi\u{202E}there\u{0007}\nfriend") == "Hi there friend", "bot: bubble strips control / bidi characters")
        check(!BotBubble.sanitize("key AIzaSyA1234567890abcdefghijklmnopqrstu").contains("AIza"), "bot: bubble hides Gemini keys")
        check(!BotBubble.sanitize("password: hunter2 ok").contains("hunter2"), "bot: bubble hides passwords")
        check(!BotBubble.sanitize("mail me at a.person@example.com").contains("@"), "bot: bubble hides email addresses")
        check(!BotBubble.sanitize("token 9f8e7d6c5b4a39281706f5e4d3c2b1a0ffee").contains("9f8e7d6c"), "bot: bubble hides long tokens")
        let p = BotBubble.threat("/Users/alice/Downloads/evil.app")
        check(!p.contains("alice") && p.contains("evil.app"), "bot: bubble shows the file name, never the home path")
        check(BotBubble.sanitize(String(repeating: "word ", count: 60)).count <= BotBubble.maxLength, "bot: bubble length is capped")
        check(BotBubble.scanDone(threats: 0) == "Scan done. All clear!", "bot: clean scan bubble")
        check(BotBubble.catCaught(nil).hasPrefix("Caught one!"), "bot: catch bubble")
        check(!BotBubble.wifi("Free\u{200F}WiFi").unicodeScalars.contains("\u{200F}"), "bot: Wi-Fi name is cleaned")

        // Edge snapping.
        let vis = CGRect(x: 0, y: 25, width: 1440, height: 850)
        let near = BotGeometry.snapped(CGRect(x: 1320, y: 300, width: 96, height: 150), in: vis)
        check(near.x == vis.maxX - 96 - 4, "bot: snaps to the right edge")
        let off = BotGeometry.snapped(CGRect(x: -500, y: 2000, width: 96, height: 150), in: vis)
        check(off.x == 4 && off.y == vis.maxY - 150 - 4, "bot: dragged off-screen comes back inside")
        let mid = BotGeometry.snapped(CGRect(x: 600, y: 400, width: 96, height: 150), in: vis)
        check(mid == CGPoint(x: 600, y: 400), "bot: no snap in the middle")
        check(BotGeometry.opensLeft(CGRect(x: 1300, y: 40, width: 96, height: 150), in: vis), "bot: popover opens toward the room")
    }
}
