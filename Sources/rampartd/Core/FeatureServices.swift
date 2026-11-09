import Foundation
import RampartShared
import RampartGuard

/// Download Gate and Camera & Microphone Guard. Both act on the logged-in user's own folders and apps, so they run in
/// the user-session daemon only (like Cat & Mouse); the root daemon answers their requests with "unavailable".
enum FeatureServices {
    static var downloadGate: DownloadGateService?
    static var mediaGuard: MediaGuardService?

    static func start(_ p: Protection) {
        let runtime = p.runtime
        guard runtime.userMode, getuid() != 0 else { return }
        let dir = runtime.root.appendingPathComponent("protection-features")

        // Download Gate. Online notarization lookups are skipped in development (RAMPART_NO_PRIVILEGED_TOOLS=1).
        let gate = DownloadGateService(directory: dir, signer: SecDownloadGateSigning(allowNetwork: !Privileged.noPrivilegedTools))
        gate.extraSkipPrefixes = runtime.ownDataRoots
        gate.scan = { [weak p] path in p?.services.scanner.scanFile(path) }
        gate.quarantine = { [weak p] path, d in
            guard let p else { return nil }
            var d = d
            d.path = path
            guard let stored = p.handle(d) else { return nil }   // records it; auto-quarantines when the policy allows
            if stored.resolved || !FileManager.default.fileExists(atPath: path) { return stored.id }
            // The gate quarantines malware it caught on arrival even when automatic quarantine is off for scans.
            do {
                _ = try p.services.quarantine.quarantine(path: path, detection: stored)
                _ = p.store.update(stored.id) { $0.resolved = true }
                return stored.id
            } catch {
                logWarn("download gate: quarantine failed for \(path): \(error.localizedDescription)")
                return nil
            }
        }
        gate.onDecision = { [weak p, weak gate] item in
            guard let p else { return }
            let (title, outcome, sev): (String, String, Severity) = {
                switch item.verdict {
                case .blocked: return ("Download Gate blocked \(item.name)", "blocked", .high)
                case .held: return ("Download Gate held \(item.name) for your review", "held", .medium)
                case .allowed: return ("You allowed \(item.name)", "allowed", .info)
                case .deleted: return ("\(item.name) moved to the Trash", "deleted", .info)
                case .cleared: return ("Download Gate cleared \(item.name)", "cleared", .info)
                }
            }()
            var facts = ["folder": item.folder, "type": item.kind.label, "checked in": String(format: "%.1f s", item.secondsToCheck)]
            if let s = item.signature { facts["signature"] = s.summary }
            if item.quarantineFlagAdded { facts["Gatekeeper flag"] = "Added by RamPart" }
            if !item.strippedModes.isEmpty { facts["permission to run"] = item.verdict == .held || item.verdict == .blocked ? "Removed" : "Restored" }
            p.activity.add(.realtime, title, detail: item.path, outcome: outcome, severity: sev, detectionID: item.detectionID,
                           event: .downloadGate, actor: item.verdict == .allowed || item.verdict == .deleted ? .user : .system,
                           target: item.path, reason: item.reason, facts: facts)
            if let st = gate?.status(), let d = try? JSONEncoder.rampart.encode(st) { p.push(.downloadGate(d)) }
        }
        gate.start()
        downloadGate = gate

        // Camera & Microphone Guard. The device-state fallback is never used in development.
        let media = MediaGuardService(directory: dir)
        media.onAlert = { [weak p] a in
            guard let p, let d = try? JSONEncoder.rampart.encode(a) else { return }
            p.push(.mediaGuardAlert(d))
            if p.subscriberCount == 0 { AgentWake.wake() }
        }
        media.onSessionEnded = { [weak p] s in
            guard let p else { return }
            let secs = Int(s.duration().rounded())
            let dur = secs < 60 ? "\(secs) s" : secs < 3600 ? "\(secs / 60) min \(secs % 60) s" : "\(secs / 3600) h \(secs % 3600 / 60) min"
            var facts = ["app": s.appName, "app id": s.appID, "device": s.device.label, "duration": dur,
                         "trusted app": s.system ? "macOS component" : (s.trusted ? "Yes" : "No")]
            if s.whileLocked { facts["screen"] = "Locked" } else if s.whileIdle { facts["screen"] = "You were away" }
            p.activity.add(.realtime, "\(s.appName) used the \(s.device.label) for \(dur)", detail: s.appPath ?? s.appID,
                           outcome: s.alerted ? "alerted" : "logged", severity: s.alerted ? .medium : .info,
                           event: .cameraMicUsed, actor: .system, target: s.appID, facts: facts)
        }
        media.onChange = { [weak p] st in
            guard let p, let d = try? JSONEncoder.rampart.encode(st) else { return }
            p.push(.mediaGuard(d))
        }
        media.start(allowDeviceProbe: !Privileged.noPrivilegedTools)
        mediaGuard = media
        p.services.wiring.append("features: download gate (\(gate.roots.count) folders), camera & microphone guard (sensor log)")
    }

    static func gate() throws -> DownloadGateService {
        guard let g = downloadGate else { throw ServiceError.unavailable("Download Gate (it runs in your session's protection service)") }
        return g
    }
    static func media() throws -> MediaGuardService {
        guard let m = mediaGuard else { throw ServiceError.unavailable("Camera & Microphone Guard (it runs in your session's protection service)") }
        return m
    }
}
