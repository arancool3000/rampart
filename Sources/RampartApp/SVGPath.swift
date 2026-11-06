import SwiftUI

/// Minimal SVG path-data parser (M L H V Q C A Z, absolute and relative) for the brand kit's outlines.
enum SVGPath {
    static func parse(_ d: String) -> Path {
        var path = Path()
        var tokens: [String] = []
        var cur = ""
        func flush() { if !cur.isEmpty { tokens.append(cur); cur = "" } }
        for ch in d {
            if ch.isLetter && ch != "e" && ch != "E" { flush(); tokens.append(String(ch)) }
            else if ch == "," || ch == " " || ch == "\n" { flush() }
            else if ch == "-" && !cur.isEmpty && !(cur.last == "e" || cur.last == "E") { flush(); cur = "-" }
            else if ch == "." && cur.contains(".") { flush(); cur = "." }
            else { cur.append(ch) }
        }
        flush()
        var i = 0
        var cmd: Character = "M"
        var p = CGPoint.zero, start = CGPoint.zero
        func num() -> CGFloat { defer { i += 1 }; return CGFloat(Double(tokens[i]) ?? 0) }
        func hasNum() -> Bool { i < tokens.count && !(tokens[i].first?.isLetter ?? false) }
        while i < tokens.count {
            if let c = tokens[i].first, c.isLetter { cmd = c; i += 1 }
            let rel = cmd.isLowercase
            func pt() -> CGPoint { let x = num(), y = num(); return rel ? CGPoint(x: p.x + x, y: p.y + y) : CGPoint(x: x, y: y) }
            switch cmd.uppercased().first! {
            case "M": p = pt(); start = p; path.move(to: p); cmd = rel ? "l" : "L"
            case "L": p = pt(); path.addLine(to: p)
            case "H": let x = num(); p.x = rel ? p.x + x : x; path.addLine(to: p)
            case "V": let y = num(); p.y = rel ? p.y + y : y; path.addLine(to: p)
            case "Q": let c = pt(); p = pt(); path.addQuadCurve(to: p, control: c)
            case "C": let c1 = pt(); let c2 = pt(); p = pt(); path.addCurve(to: p, control1: c1, control2: c2)
            case "A":
                let rx = num(), ry = num(), rot = num(), large = num() != 0, sweep = num() != 0
                let end = pt()
                addArc(&path, from: p, to: end, rx: rx, ry: ry, xRot: rot, large: large, sweep: sweep)
                p = end
            case "Z": path.closeSubpath(); p = start
            default: i += 1
            }
            if cmd.uppercased() == "Z" { continue }
            if !hasNum() { continue }
        }
        return path
    }

    /// SVG endpoint arc → centre parameterisation, emitted as cubic segments.
    private static func addArc(_ path: inout Path, from p0: CGPoint, to p1: CGPoint, rx rxIn: CGFloat, ry ryIn: CGFloat, xRot: CGFloat, large: Bool, sweep: Bool) {
        var rx = abs(rxIn), ry = abs(ryIn)
        if rx == 0 || ry == 0 { path.addLine(to: p1); return }
        let phi = xRot * .pi / 180, cosP = cos(phi), sinP = sin(phi)
        let dx = (p0.x - p1.x) / 2, dy = (p0.y - p1.y) / 2
        let x1 = cosP * dx + sinP * dy, y1 = -sinP * dx + cosP * dy
        let lambda = (x1 * x1) / (rx * rx) + (y1 * y1) / (ry * ry)
        if lambda > 1 { rx *= sqrt(lambda); ry *= sqrt(lambda) }
        let num = rx * rx * ry * ry - rx * rx * y1 * y1 - ry * ry * x1 * x1
        let den = rx * rx * y1 * y1 + ry * ry * x1 * x1
        var coef = sqrt(max(0, num / den))
        if large == sweep { coef = -coef }
        let cx1 = coef * rx * y1 / ry, cy1 = -coef * ry * x1 / rx
        let cx = cosP * cx1 - sinP * cy1 + (p0.x + p1.x) / 2
        let cy = sinP * cx1 + cosP * cy1 + (p0.y + p1.y) / 2
        func angle(_ ux: CGFloat, _ uy: CGFloat, _ vx: CGFloat, _ vy: CGFloat) -> CGFloat {
            let a = atan2(ux * vy - uy * vx, ux * vx + uy * vy); return a
        }
        let theta1 = angle(1, 0, (x1 - cx1) / rx, (y1 - cy1) / ry)
        var dTheta = angle((x1 - cx1) / rx, (y1 - cy1) / ry, (-x1 - cx1) / rx, (-y1 - cy1) / ry)
        if !sweep && dTheta > 0 { dTheta -= 2 * .pi } else if sweep && dTheta < 0 { dTheta += 2 * .pi }
        let segs = Int(ceil(abs(dTheta) / (.pi / 2)))
        let delta = dTheta / CGFloat(segs)
        let t = 4.0 / 3.0 * tan(delta / 4)
        var th = theta1
        for _ in 0..<segs {
            let c1 = cos(th), s1 = sin(th), c2 = cos(th + delta), s2 = sin(th + delta)
            func map(_ x: CGFloat, _ y: CGFloat) -> CGPoint { CGPoint(x: cx + rx * x * cosP - ry * y * sinP, y: cy + rx * x * sinP + ry * y * cosP) }
            path.addCurve(to: map(c2, s2), control1: map(c1 - t * s1, s1 + t * c1), control2: map(c2 + t * s2, s2 - t * c2))
            th += delta
        }
    }
}
