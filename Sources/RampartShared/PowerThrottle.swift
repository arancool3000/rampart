import Foundation
import IOKit.ps

/// Battery-aware pacing for periodic background work. Timers keep their base interval but skip ticks:
/// on AC every tick runs; on battery 1 in 3; in Low Power Mode 1 in 6. The power state is cached for 30 s.
public final class PowerThrottle: @unchecked Sendable {
    public static let shared = PowerThrottle()
    private let lock = NSLock()
    private var checkedAt = Date.distantPast
    private var cachedFactor = 1

    /// 1 on AC, 3 on battery, 6 in Low Power Mode.
    public var factor: Int {
        lock.lock(); defer { lock.unlock() }
        if Date().timeIntervalSince(checkedAt) > 30 {
            checkedAt = Date()
            cachedFactor = ProcessInfo.processInfo.isLowPowerModeEnabled ? 6 : (Self.onBattery() ? 3 : 1)
        }
        return cachedFactor
    }

    /// True when tick `n` should do work.
    public func shouldRun(tick n: Int) -> Bool { n % factor == 0 }

    static func onBattery() -> Bool {
        guard let info = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
              let type = IOPSGetProvidingPowerSourceType(info)?.takeUnretainedValue() as String? else { return false }
        return type == kIOPSBatteryPowerValue
    }
}
