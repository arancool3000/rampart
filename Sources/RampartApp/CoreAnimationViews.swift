import SwiftUI
import AppKit
import QuartzCore

/// Continuous motion runs as Core Animation layer animations (render server), not per-frame SwiftUI updates,
/// so a visible, idle window costs ~0% app CPU. Animations are attached only while `animate` is true.

/// Slow "breathing" radial glow behind the hero shield.
struct GlowPulse: NSViewRepresentable {
    let color: NSColor
    let animate: Bool

    final class V: NSView {
        let glow = CAGradientLayer()
        override init(frame: NSRect) {
            super.init(frame: frame)
            wantsLayer = true
            layer = CALayer()
            glow.type = .radial
            glow.startPoint = CGPoint(x: 0.5, y: 0.5)
            glow.endPoint = CGPoint(x: 1, y: 1)
            layer?.addSublayer(glow)
        }
        required init?(coder: NSCoder) { fatalError() }
        override func layout() {
            super.layout()
            CATransaction.begin(); CATransaction.setDisableActions(true)
            glow.frame = bounds
            CATransaction.commit()
        }
        func configure(color: NSColor, animate: Bool) {
            glow.colors = [color.withAlphaComponent(0.42).cgColor, color.withAlphaComponent(0).cgColor]
            let running = glow.animation(forKey: "breathe") != nil
            if animate && !running {
                let scale = CABasicAnimation(keyPath: "transform.scale")
                scale.fromValue = 0.88; scale.toValue = 1.04
                let fade = CABasicAnimation(keyPath: "opacity")
                fade.fromValue = 0.55; fade.toValue = 1.0
                let g = CAAnimationGroup()
                g.animations = [scale, fade]
                g.duration = 2.5
                g.autoreverses = true
                g.repeatCount = .infinity
                g.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
                glow.add(g, forKey: "breathe")
            } else if !animate && running {
                glow.removeAnimation(forKey: "breathe")
            }
            glow.opacity = animate ? 1 : 0.8
        }
    }

    func makeNSView(context: Context) -> V { let v = V(); v.configure(color: color, animate: animate); return v }
    func updateNSView(_ v: V, context: Context) { v.configure(color: color, animate: animate) }
}

/// Radar sweep (rotating conic gradient) plus blips that twinkle as the sweep passes them.
struct RadarSweep: NSViewRepresentable {
    let color: NSColor
    let blipColor: NSColor
    let animate: Bool
    static let period: CFTimeInterval = 3.2
    static let blips: [(r: Double, a: Double)] = [(0.32, 40), (0.62, 115), (0.48, 200), (0.78, 260), (0.25, 310), (0.7, 20), (0.55, 160)]

    final class V: NSView {
        let sweep = CAGradientLayer()
        let mask = CAShapeLayer()
        var blipLayers: [CALayer] = []
        override init(frame: NSRect) {
            super.init(frame: frame)
            wantsLayer = true
            layer = CALayer()
            sweep.type = .conic
            sweep.startPoint = CGPoint(x: 0.5, y: 0.5)
            sweep.endPoint = CGPoint(x: 0.5, y: 0)
            sweep.locations = [0, 0.72, 1]
            sweep.mask = mask
            layer?.addSublayer(sweep)
            for _ in RadarSweep.blips {
                let b = CALayer()
                b.cornerRadius = 3.5
                b.shadowOpacity = 1
                b.shadowRadius = 4
                b.shadowOffset = .zero
                b.opacity = 0
                layer?.addSublayer(b)
                blipLayers.append(b)
            }
        }
        required init?(coder: NSCoder) { fatalError() }
        override func layout() {
            super.layout()
            CATransaction.begin(); CATransaction.setDisableActions(true)
            sweep.frame = bounds
            mask.path = CGPath(ellipseIn: bounds, transform: nil)
            let c = CGPoint(x: bounds.midX, y: bounds.midY), radius = min(bounds.width, bounds.height) / 2
            for (i, b) in blipLayers.enumerated() {
                let bl = RadarSweep.blips[i]
                let rad = (90 - bl.a) * .pi / 180   // clockwise from 12 o'clock, AppKit y-up
                b.frame = CGRect(x: c.x + cos(rad) * radius * bl.r - 3.5, y: c.y + sin(rad) * radius * bl.r - 3.5, width: 7, height: 7)
            }
            CATransaction.commit()
        }
        func configure(color: NSColor, blip: NSColor, animate: Bool) {
            sweep.colors = [color.withAlphaComponent(0).cgColor, color.withAlphaComponent(0).cgColor, color.withAlphaComponent(0.5).cgColor]
            for b in blipLayers { b.backgroundColor = blip.cgColor; b.shadowColor = blip.cgColor }
            let running = sweep.animation(forKey: "spin") != nil
            if animate && !running {
                let now = CACurrentMediaTime()
                let spin = CABasicAnimation(keyPath: "transform.rotation.z")
                spin.fromValue = 0; spin.toValue = -2 * Double.pi   // clockwise
                spin.duration = RadarSweep.period
                spin.repeatCount = .infinity
                spin.beginTime = now
                sweep.add(spin, forKey: "spin")
                for (i, b) in blipLayers.enumerated() {
                    let a = CAKeyframeAnimation(keyPath: "opacity")
                    a.values = [1, 0, 0]
                    a.keyTimes = [0, 0.66, 1]
                    a.duration = RadarSweep.period
                    a.repeatCount = .infinity
                    // Peak when the sweep's leading edge passes the blip's angle.
                    a.beginTime = now + RadarSweep.period * (RadarSweep.blips[i].a / 360)
                    a.fillMode = .backwards
                    b.add(a, forKey: "twinkle")
                }
            } else if !animate && running {
                sweep.removeAnimation(forKey: "spin")
                for b in blipLayers { b.removeAnimation(forKey: "twinkle") }
            }
            sweep.opacity = animate ? 1 : 0
        }
    }

    func makeNSView(context: Context) -> V { let v = V(); v.configure(color: color, blip: blipColor, animate: animate); return v }
    func updateNSView(_ v: V, context: Context) { v.configure(color: color, blip: blipColor, animate: animate) }
}
