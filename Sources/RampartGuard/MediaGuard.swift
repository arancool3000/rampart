import Foundation
import Darwin
import CoreGraphics
import IOKit
import CoreAudio
import CoreMediaIO
import RampartShared

// Camera & Microphone Guard: who turned the camera or microphone on, with no prompts.
//
// Source (verified on macOS 27 by reading the unified log only): Control Center's sensor-indicator log, the same
// data behind the green/orange menu-bar dots:
//   [com.apple.controlcenter:sensor-indicators] Active activity attributions changed to ["mic:com.apple.CoreSpeech", "loc:…"]
// Every line is the complete set of active uses ("cam:", "mic:", "scr:" screen recording, "loc:" location), so
// diffing consecutive lines gives on / off per app. `log stream` reads it without any permission prompt.
// Fallback when `log stream` isn't available: CoreAudio / CoreMediaIO "device is running somewhere" (which device,
// not which app). Neither path opens the camera or microphone.

public enum MediaDevice: String, Codable, Sendable, CaseIterable {
    case camera, microphone
    public var label: String { self == .camera ? "camera" : "microphone" }
    public var symbol: String { self == .camera ? "video.fill" : "mic.fill" }
    init?(prefix: String) {
        switch prefix { case "cam": self = .camera; case "mic": self = .microphone; default: return nil }
    }
}

/// One app using one device (from a Control Center attribution).
public struct MediaUse: Hashable, Sendable {
    public var device: MediaDevice
    public var appID: String
    public init(device: MediaDevice, appID: String) { self.device = device; self.appID = appID }
}

public struct MediaSession: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var device: MediaDevice
    public var appID: String
    public var appName: String
    public var appPath: String?
    public var pid: Int32?
    public var start: Date
    public var end: Date?
    public var trusted: Bool
    /// An Apple system component (Siri, dictation, FaceTime …): logged, never alerted, never stopped.
    public var system: Bool
    public var whileLocked: Bool
    public var whileIdle: Bool
    public var alerted: Bool
    /// The app wasn't named (device-state fallback).
    public var unattributed: Bool = false
    public func duration(now: Date = Date()) -> TimeInterval { (end ?? now).timeIntervalSince(start) }
}

public struct MediaGuardAlert: Codable, Hashable, Sendable, Identifiable {
    public var id = UUID()
    public var date: Date
    /// One notification per app + device (a repeat replaces it).
    public var identifier: String
    public var title: String
    public var body: String
    public var severity: Severity
    public var timeSensitive: Bool
    public var device: MediaDevice
    public var appID: String
    public var appName: String
    public var sessionID: UUID
    /// Offer "Stop it" (an app RamPart may terminate, still running).
    public var canStop: Bool
}

public struct MediaGuardConfig: Codable, Hashable, Sendable {
    public var enabled = true
    public var trusted: [String] = []
    public var tone: DeceptionTone = .playful
    public var alertWhenAway = true
    public var idleSeconds: Double = 300
    public init() {}
}

public struct MediaGuardStatus: Codable, Hashable, Sendable {
    public var enabled: Bool
    public var source: String
    public var sourceError: String?
    public var active: [MediaSession]
    public var recent: [MediaSession]
    public var alerts: [MediaGuardAlert]
    public var config: MediaGuardConfig
    public var honesty: String
    public var cameraOn: Bool { active.contains { $0.device == .camera } }
    public var micOn: Bool { active.contains { $0.device == .microphone } }
}

public enum MediaGuardError: Error, LocalizedError {
    case systemProcess(String), notRunning(String), invalid
    public var errorDescription: String? {
        switch self {
        case .systemProcess(let n): return "\(n) is part of macOS, so RamPart won't stop it."
        case .notRunning(let n): return "\(n) isn't running any more."
        case .invalid: return "That isn't an app RamPart can act on."
        }
    }
}

// MARK: - parsing

public enum MediaLogParser {
    static let marker = "Active activity attributions changed to "
    static let systemMarker = "SystemStatus attributed attribution to "

    /// The full set of active camera / microphone uses in a sensor-indicator line (nil = not such a line).
    /// Accepts plain text or a `log stream --style ndjson` record.
    public static func activeUses(in line: String) -> Set<MediaUse>? {
        let msg = message(line)
        guard let r = msg.range(of: marker) else { return nil }
        let list = msg[r.upperBound...]
        guard let open = list.firstIndex(of: "["), let close = list.lastIndex(of: "]"), open < close else { return nil }
        var out = Set<MediaUse>()
        for raw in list[list.index(after: open)..<close].split(separator: ",") {
            let item = raw.trimmingCharacters(in: CharacterSet(charactersIn: " \"'\t"))
            guard let colon = item.firstIndex(of: ":") else { continue }
            let prefix = String(item[..<colon]), id = String(item[item.index(after: colon)...])
            guard let dev = MediaDevice(prefix: prefix), isValidAppID(id) else { continue }
            out.insert(MediaUse(device: dev, appID: id))
        }
        return out
    }

    /// "SystemStatus attributed attribution to com.apple.x, … isSystemExecutable: true" → ("com.apple.x", true).
    public static func systemFlag(in line: String) -> (appID: String, system: Bool)? {
        let msg = message(line)
        guard let r = msg.range(of: systemMarker) else { return nil }
        let rest = msg[r.upperBound...]
        let id = String(rest.prefix { $0 != "," && $0 != " " })
        guard isValidAppID(id) else { return nil }
        return (id, rest.contains("isSystemExecutable: true"))
    }

    static func message(_ line: String) -> String {
        if line.hasPrefix("{"), let d = line.data(using: .utf8),
           let j = try? JSONSerialization.jsonObject(with: d) as? [String: Any], let m = j["eventMessage"] as? String { return m }
        return line
    }

    /// Bundle-identifier-like: short, printable, no quotes or path separators.
    public static func isValidAppID(_ s: String) -> Bool {
        !s.isEmpty && s.utf8.count <= 200 && s.unicodeScalars.allSatisfy {
            $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "._-".unicodeScalars.contains($0))
        }
    }

    public static let predicate = #"subsystem == "com.apple.controlcenter" AND category == "sensor-indicators" AND (eventMessage BEGINSWITH "Active activity attributions changed" OR eventMessage BEGINSWITH "SystemStatus attributed attribution")"#
}

// MARK: - service

public final class MediaGuardService: @unchecked Sendable {
    public static let honesty = "RamPart reads the same signal macOS uses for the green and orange dots in the menu bar, so it knows which app turned the camera or microphone on, usually within a second. It never opens the camera or microphone itself and can't block an app before it starts recording; it tells you, and can stop the app."

    public struct App: Sendable {
        public var pid: Int32?; public var path: String?; public var name: String
        public init(pid: Int32?, path: String?, name: String) { self.pid = pid; self.path = path; self.name = name }
    }

    public let directory: URL
    /// (screen locked, seconds since the last keyboard / mouse input).
    public var screenState: () -> (locked: Bool, idle: Double) = { (ScreenState.isLocked(), ScreenState.idleSeconds()) }
    public var resolve: (String) -> App? = { AppResolver.app(bundleID: $0) }
    public var kill: KillHook = { pid, sig in Darwin.kill(pid, sig) == 0 }
    public var isAlive: (Int32) -> Bool = { $0 > 0 && Darwin.kill($0, 0) == 0 }
    public var onAlert: ((MediaGuardAlert) -> Void)?
    /// A use ended (for Protection Activity: app, device, duration, trusted).
    public var onSessionEnded: ((MediaSession) -> Void)?
    /// Anything the live indicator shows changed.
    public var onChange: ((MediaGuardStatus) -> Void)?

    private let queue = DispatchQueue(label: "rampart.mediaguard")
    private var config = MediaGuardConfig()
    private var active: [MediaUse: MediaSession] = [:]
    private var recent: [MediaSession] = []
    private var alerts: [MediaGuardAlert] = []
    private var systemIDs = Set<String>()
    private var source = "off"
    private var sourceError: String?
    private var logRunner: LogStreamRunner?
    private var devicePoll: DispatchSourceTimer?

    public init(directory: URL) {
        self.directory = directory
        try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        if let d = try? Data(contentsOf: configURL), let c = try? JSONDecoder.rampart.decode(MediaGuardConfig.self, from: d) { config = c }
        if let d = try? Data(contentsOf: historyURL), let h = try? JSONDecoder.rampart.decode([MediaSession].self, from: d) { recent = h }
    }
    private var configURL: URL { directory.appendingPathComponent("media-guard-config.json") }
    private var historyURL: URL { directory.appendingPathComponent("media-guard-history.json") }

    // MARK: lifecycle

    /// Starts `log stream` on the sensor-indicator log (no prompts). `allowDeviceProbe`: when the log can't be read,
    /// poll CoreAudio / CoreMediaIO device state instead (the daemon turns this off in development).
    public func start(allowDeviceProbe: Bool = true) {
        queue.async {
            guard self.config.enabled, self.logRunner == nil else { return }
            let r = LogStreamRunner(predicate: MediaLogParser.predicate, queue: self.queue)
            r.onLine = { [weak self] l in self?.ingestLocked(l, now: Date()) }
            r.onFailure = { [weak self] why in
                guard let self else { return }
                self.sourceError = why
                if allowDeviceProbe, self.devicePoll == nil { self.startDevicePollLocked() }
            }
            self.logRunner = r
            self.source = "Control Center sensor log"
            r.start()
        }
    }

    public func stop() {
        queue.sync {
            logRunner?.stop(); logRunner = nil
            devicePoll?.cancel(); devicePoll = nil
            for (_, s) in active { endLocked(s, now: Date()) }
            active.removeAll()
            source = "off"
        }
    }

    // MARK: settings

    public func setEnabled(_ on: Bool) -> MediaGuardStatus {
        queue.sync { config.enabled = on; saveConfigLocked() }
        if on { start() } else { stop() }
        return status()
    }
    public func setTrusted(_ appID: String, trusted: Bool) throws -> MediaGuardStatus {
        guard MediaLogParser.isValidAppID(appID) else { throw MediaGuardError.invalid }
        queue.sync {
            config.trusted.removeAll { $0 == appID }
            if trusted { config.trusted.append(appID); config.trusted.sort() }
            for (k, var s) in active where s.appID == appID { s.trusted = trusted; active[k] = s }
            saveConfigLocked()
        }
        let st = status(); onChange?(st); return st
    }
    public func setTone(serious: Bool) -> MediaGuardStatus {
        queue.sync { config.tone = serious ? .serious : .playful; saveConfigLocked() }
        return status()
    }
    public func setAlertWhenAway(_ on: Bool) -> MediaGuardStatus {
        queue.sync { config.alertWhenAway = on; saveConfigLocked() }
        return status()
    }
    private func saveConfigLocked() {
        if let d = try? JSONEncoder.rampart.encode(config) { try? d.write(to: configURL, options: .atomic) }
    }

    public func status() -> MediaGuardStatus { queue.sync { statusLocked() } }
    private func statusLocked() -> MediaGuardStatus {
        MediaGuardStatus(enabled: config.enabled, source: source, sourceError: sourceError,
                         active: active.values.sorted { $0.start < $1.start }, recent: recent, alerts: alerts,
                         config: config, honesty: Self.honesty)
    }

    // MARK: events

    /// One unified-log line (or a simulated one in tests).
    public func ingest(_ line: String, now: Date = Date()) { queue.sync { ingestLocked(line, now: now) } }

    private func ingestLocked(_ line: String, now: Date) {
        if let f = MediaLogParser.systemFlag(in: line), f.system { systemIDs.insert(f.appID) }
        guard let uses = MediaLogParser.activeUses(in: line) else { return }
        applyLocked(uses, now: now)
    }

    /// The complete set of current uses: starts new sessions, ends missing ones.
    public func apply(_ uses: Set<MediaUse>, now: Date = Date()) { queue.sync { applyLocked(uses, now: now) } }

    private func applyLocked(_ uses: Set<MediaUse>, now: Date) {
        var changed = false
        for (k, s) in active where !uses.contains(k) { endLocked(s, now: now); active[k] = nil; changed = true }
        for u in uses where active[u] == nil {
            active[u] = beginLocked(u, now: now, unattributed: false); changed = true
        }
        if changed { onChange?(statusLocked()) }
    }

    public func isSystem(_ appID: String, path: String? = nil) -> Bool {
        if appID.hasPrefix("com.apple.") || systemIDs.contains(appID) { return true }
        guard let p = path else { return false }
        return ["/System/", "/usr/", "/bin/", "/sbin/", "/Library/Apple/"].contains { p.hasPrefix($0) }
    }

    private func beginLocked(_ u: MediaUse, now: Date, unattributed: Bool) -> MediaSession {
        let app = unattributed ? nil : resolve(u.appID)
        let (locked, idle) = screenState()
        let idleNow = idle >= config.idleSeconds
        var s = MediaSession(device: u.device, appID: u.appID, appName: unattributed ? "An app macOS didn't name" : (app?.name ?? u.appID),
                             appPath: app?.path, pid: app?.pid, start: now, end: nil,
                             trusted: config.trusted.contains(u.appID), system: !unattributed && isSystem(u.appID, path: app?.path),
                             whileLocked: locked, whileIdle: idleNow, alerted: false, unattributed: unattributed)
        let untrusted = !s.trusted && !s.system && !unattributed
        let away = config.alertWhenAway && (locked || idleNow) && !s.system
        if untrusted || away {
            s.alerted = true
            let a = Self.alert(for: s, tone: config.tone, canStop: canStop(s), now: now)
            alerts.insert(a, at: 0)
            if alerts.count > 50 { alerts = Array(alerts.prefix(50)) }
            onAlert?(a)
        }
        return s
    }

    private func endLocked(_ s: MediaSession, now: Date) {
        var s = s
        s.end = now
        recent.insert(s, at: 0)
        if recent.count > 200 { recent = Array(recent.prefix(200)) }
        if let d = try? JSONEncoder.rampart.encode(recent) { try? d.write(to: historyURL, options: .atomic) }
        onSessionEnded?(s)
    }

    func canStop(_ s: MediaSession) -> Bool {
        guard !s.system, !s.unattributed, let pid = s.pid, pid > 1, pid != getpid() else { return false }
        if s.appID.hasPrefix(Product.bundlePrefix) { return false }
        return isAlive(pid)
    }

    // MARK: actions

    /// "Stop it": terminate the app using the camera / microphone (the app asked the user to confirm first).
    /// Never system processes, never RamPart, only processes owned by this user.
    public func stopApp(_ appID: String) throws -> MediaGuardStatus {
        guard MediaLogParser.isValidAppID(appID) else { throw MediaGuardError.invalid }
        let app = resolve(appID)
        let name = app?.name ?? appID
        if isSystem(appID, path: app?.path) || appID.hasPrefix(Product.bundlePrefix) { throw MediaGuardError.systemProcess(name) }
        guard let pid = app?.pid, pid > 1, pid != getpid(), isAlive(pid) else { throw MediaGuardError.notRunning(name) }
        if getuid() != 0, let owner = GuardProc.info(pid)?.uid, owner != getuid() { throw MediaGuardError.systemProcess(name) }
        _ = kill(pid, SIGTERM)
        let k = kill, alive = isAlive
        DispatchQueue.global().asyncAfter(deadline: .now() + 3) { if alive(pid) { _ = k(pid, SIGKILL) } }
        return status()
    }

    // MARK: alerts

    public static func alert(for s: MediaSession, tone: DeceptionTone, canStop: Bool, now: Date = Date()) -> MediaGuardAlert {
        let app = "'" + SafeText.line(s.appName, max: 60) + "'"
        let dev = s.device.label
        let away = s.whileLocked ? "while your Mac is locked" : (s.whileIdle ? "while you're away from your Mac" : nil)
        let title: String, body: String
        let reason = s.trusted ? "" : " It isn't on your trusted list."
        let ask = canStop ? " Stop it, or trust it if that was you." : (s.trusted ? "" : " Trust it if that was you.")
        if tone == .playful {
            if let away {
                title = s.device == .camera ? "🌙 Someone switched on the camera" : "🌙 Someone's listening"
                body = "\(app) turned on your \(dev) \(away).\(reason)\(ask)"
            } else {
                title = s.device == .camera ? "📷 Who's peeking?" : "🎙️ Who's listening?"
                body = "\(app) just turned on your \(dev).\(reason)\(ask)"
            }
        } else {
            title = "\(s.device == .camera ? "Camera" : "Microphone") turned on" + (away != nil ? " while you were away" : " by an untrusted app")
            body = "\(app) (\(s.appID)) started using the \(dev)\(away.map { " " + $0 } ?? "").\(reason)\(ask)"
        }
        return MediaGuardAlert(date: now, identifier: "mediaguard.\(s.appID).\(s.device.rawValue)", title: title, body: body,
                               severity: away != nil ? .high : .medium, timeSensitive: true, device: s.device, appID: s.appID,
                               appName: s.appName, sessionID: s.id, canStop: canStop)
    }

    // MARK: fallback: device state only

    private func startDevicePollLocked() {
        source = "Device state (which app isn't known)"
        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + 1, repeating: 2)
        t.setEventHandler { [weak self] in
            guard let self, self.logRunner?.healthy != true else { return }
            var uses = Set<MediaUse>()
            if DeviceProbe.cameraInUse() { uses.insert(MediaUse(device: .camera, appID: "unknown")) }
            if DeviceProbe.microphoneInUse() { uses.insert(MediaUse(device: .microphone, appID: "unknown")) }
            var changed = false
            for (k, s) in self.active where k.appID == "unknown" && !uses.contains(k) { self.endLocked(s, now: Date()); self.active[k] = nil; changed = true }
            for u in uses where self.active[u] == nil { self.active[u] = self.beginLocked(u, now: Date(), unattributed: true); changed = true }
            if changed { self.onChange?(self.statusLocked()) }
        }
        t.resume(); devicePoll = t
    }
}

// MARK: - helpers

/// `log stream --style ndjson` with a predicate; restarts with back-off when it exits.
final class LogStreamRunner {
    let predicate: String
    let queue: DispatchQueue
    var onLine: ((String) -> Void)?
    var onFailure: ((String) -> Void)?
    private var process: Process?
    private var stopped = false
    private var backoff: TimeInterval = 2
    private var buffer = Data()
    private(set) var healthy = false

    init(predicate: String, queue: DispatchQueue) { self.predicate = predicate; self.queue = queue }

    func start() {
        guard !stopped else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        p.arguments = ["stream", "--style", "ndjson", "--level", "info", "--predicate", predicate]
        let out = Pipe(), err = Pipe()
        p.standardOutput = out; p.standardError = err; p.standardInput = FileHandle.nullDevice
        let started = Date()
        out.fileHandleForReading.readabilityHandler = { [weak self] h in
            let d = h.availableData
            guard let self, !d.isEmpty else { return }
            self.queue.async { self.consume(d) }
        }
        p.terminationHandler = { [weak self] proc in
            let e = String(decoding: err.fileHandleForReading.availableData, as: UTF8.self)
            out.fileHandleForReading.readabilityHandler = nil
            guard let self else { return }
            self.queue.async {
                self.healthy = false
                guard !self.stopped else { return }
                let quick = Date().timeIntervalSince(started) < 5
                if quick { self.onFailure?(e.isEmpty ? "log stream exited (\(proc.terminationStatus))" : SafeText.line(e, max: 200)) }
                self.backoff = quick ? min(self.backoff * 2, 120) : 2
                self.queue.asyncAfter(deadline: .now() + self.backoff) { self.start() }
            }
        }
        do { try p.run(); process = p; healthy = true } catch { onFailure?("couldn't start log stream: \(error.localizedDescription)") }
    }

    private func consume(_ d: Data) {
        buffer.append(d)
        while let nl = buffer.firstIndex(of: 0x0a) {
            let line = String(decoding: buffer[buffer.startIndex..<nl], as: UTF8.self)
            buffer.removeSubrange(buffer.startIndex...nl)
            if !line.isEmpty { onLine?(line) }
        }
        if buffer.count > 1 << 20 { buffer.removeAll() }
    }

    func stop() { stopped = true; process?.terminate(); process = nil }
}

/// Lock state and idle time of this login session (no permission needed).
public enum ScreenState {
    public static func isLocked() -> Bool {
        guard let d = CGSessionCopyCurrentDictionary() as? [String: Any] else { return false }
        return (d["CGSSessionScreenIsLocked"] as? Bool) ?? ((d["CGSSessionScreenIsLocked"] as? NSNumber)?.boolValue ?? false)
    }
    /// Seconds since the last keyboard / mouse input (IOHIDSystem HIDIdleTime).
    public static func idleSeconds() -> Double {
        let svc = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOHIDSystem"))
        guard svc != 0 else { return 0 }
        defer { IOObjectRelease(svc) }
        guard let v = IORegistryEntryCreateCFProperty(svc, "HIDIdleTime" as CFString, kCFAllocatorDefault, 0)?.takeRetainedValue() as? NSNumber else { return 0 }
        return v.doubleValue / 1e9
    }
}

/// Running app for a bundle identifier (libproc + the bundle's Info.plist; cached per bundle path).
public enum AppResolver {
    nonisolated(unsafe) private static var cache: [String: (id: String?, name: String)] = [:]
    private static let lock = NSLock()

    public static func bundle(ofExecutable path: String) -> String? {
        guard let r = path.range(of: ".app/Contents/", options: .backwards) else { return nil }
        return String(path[..<r.lowerBound]) + ".app"
    }

    static func info(bundle: String) -> (id: String?, name: String) {
        lock.lock(); defer { lock.unlock() }
        if let c = cache[bundle] { return c }
        let plist = NSDictionary(contentsOfFile: bundle + "/Contents/Info.plist") as? [String: Any]
        let name = (plist?["CFBundleDisplayName"] as? String) ?? (plist?["CFBundleName"] as? String)
            ?? ((bundle as NSString).lastPathComponent as NSString).deletingPathExtension
        let v = (plist?["CFBundleIdentifier"] as? String, name)
        if cache.count > 2000 { cache.removeAll() }
        cache[bundle] = v
        return v
    }

    public static func app(bundleID: String) -> MediaGuardService.App? {
        var best: MediaGuardService.App?
        for p in GuardProc.processes() {
            // The outermost .app (helpers live inside the main bundle).
            guard let first = p.path.range(of: ".app/") else { continue }
            let outer = String(p.path[..<first.lowerBound]) + ".app"
            let inner = bundle(ofExecutable: p.path) ?? outer
            for b in Set([inner, outer]) where info(bundle: b).id == bundleID {
                let cand = MediaGuardService.App(pid: p.pid, path: p.path, name: info(bundle: outer).name)
                if b == outer && p.path.hasPrefix(outer + "/Contents/MacOS/") { return cand }   // main executable
                if best == nil { best = cand }
            }
        }
        return best
    }
}

/// "Is this device running somewhere?" for every camera (CoreMediaIO) and microphone (CoreAudio). Property reads
/// only: no stream is opened, so no camera / microphone permission is involved.
public enum DeviceProbe {
    public static func microphoneInUse() -> Bool {
        var addr = AudioObjectPropertyAddress(mSelector: kAudioHardwarePropertyDevices, mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
        var size: UInt32 = 0
        guard AudioObjectGetPropertyDataSize(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size) == noErr, size > 0 else { return false }
        var ids = [AudioObjectID](repeating: 0, count: Int(size) / MemoryLayout<AudioObjectID>.size)
        guard AudioObjectGetPropertyData(AudioObjectID(kAudioObjectSystemObject), &addr, 0, nil, &size, &ids) == noErr else { return false }
        for id in ids {
            var inAddr = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyStreams, mScope: kAudioObjectPropertyScopeInput, mElement: kAudioObjectPropertyElementMain)
            var sz: UInt32 = 0
            guard AudioObjectGetPropertyDataSize(id, &inAddr, 0, nil, &sz) == noErr, sz > 0 else { continue }   // not an input device
            var runAddr = AudioObjectPropertyAddress(mSelector: kAudioDevicePropertyDeviceIsRunningSomewhere, mScope: kAudioObjectPropertyScopeGlobal, mElement: kAudioObjectPropertyElementMain)
            var running: UInt32 = 0, rs = UInt32(MemoryLayout<UInt32>.size)
            if AudioObjectGetPropertyData(id, &runAddr, 0, nil, &rs, &running) == noErr, running != 0 { return true }
        }
        return false
    }

    public static func cameraInUse() -> Bool {
        var addr = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIOHardwarePropertyDevices),
                                             mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeGlobal),
                                             mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementMain))
        var size: UInt32 = 0
        let sys = CMIOObjectID(kCMIOObjectSystemObject)
        guard CMIOObjectGetPropertyDataSize(sys, &addr, 0, nil, &size) == 0, size > 0 else { return false }
        var ids = [CMIOObjectID](repeating: 0, count: Int(size) / MemoryLayout<CMIOObjectID>.size)
        var used: UInt32 = 0
        guard CMIOObjectGetPropertyData(sys, &addr, 0, nil, size, &used, &ids) == 0 else { return false }
        for id in ids {
            var runAddr = CMIOObjectPropertyAddress(mSelector: CMIOObjectPropertySelector(kCMIODevicePropertyDeviceIsRunningSomewhere),
                                                    mScope: CMIOObjectPropertyScope(kCMIOObjectPropertyScopeWildcard),
                                                    mElement: CMIOObjectPropertyElement(kCMIOObjectPropertyElementWildcard))
            var running: UInt32 = 0, u: UInt32 = 0
            if CMIOObjectGetPropertyData(id, &runAddr, 0, nil, UInt32(MemoryLayout<UInt32>.size), &u, &running) == 0, running != 0 { return true }
        }
        return false
    }
}
