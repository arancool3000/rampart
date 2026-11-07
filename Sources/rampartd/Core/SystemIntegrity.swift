import Foundation
import Security
import RampartShared

/// Quick and Full scans also verify Apple's own apps: /System/Applications/*.app (and its Utilities) plus
/// /Applications/Safari.app must carry a valid Apple-anchored signature. Apple's built-in apps live on a sealed,
/// read-only system volume (the posture check "Sealed system volume" reports the seal); this is the per-app check.
/// Read-only Security.framework calls: no prompts, no child processes.
enum SystemIntegrity {
    static let roots = ["/System/Applications", "/System/Applications/Utilities"]
    static let extraApps = ["/Applications/Safari.app"]
    private static let appleAnchor: SecRequirement? = {
        var r: SecRequirement?
        return SecRequirementCreateWithString("anchor apple" as CFString, [], &r) == errSecSuccess ? r : nil
    }()

    static func appleApps() -> [String] {
        var out: [String] = []
        for root in roots {
            for name in (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? [] where name.hasSuffix(".app") {
                out.append(root + "/" + name)
            }
        }
        for a in extraApps where FileManager.default.fileExists(atPath: a) { out.append(a) }
        return out
    }

    /// nil = genuine; otherwise why it failed. Strict validation of the code (resources are covered by the volume seal).
    static func problem(_ path: String) -> String? {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            return "its signature can't be read"
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSDoNotValidateResources)
        let st = SecStaticCodeCheckValidity(code, flags, appleAnchor)
        if st == errSecSuccess { return nil }
        if st == errSecCSReqFailed { return "it is not signed by Apple" }
        return "its signature is not valid (\(st))"
    }

    /// Detections (critical) for every Apple app that fails. Runs the checks in parallel.
    static func verifyAppleApps() -> [Detection] {
        let apps = appleApps()
        let lock = NSLock(); var bad: [(String, String)] = []
        DispatchQueue.concurrentPerform(iterations: apps.count) { i in
            if let why = problem(apps[i]) { lock.lock(); bad.append((apps[i], why)); lock.unlock() }
        }
        return bad.sorted { $0.0 < $1.0 }.map { path, why in
            let name = (path as NSString).lastPathComponent
            let ev = Evidence(source: .signing, title: "Apple app failed its signature check",
                              detail: "\(name) should be signed by Apple, but \(why). Apple's built-in apps live on a sealed, read-only system volume, so this means the system was modified.",
                              score: 95)
            return Detection(path: path, name: "System integrity: \(name) is not genuine", category: .suspicious,
                             severity: .critical, confidence: 95, evidence: [ev])
        }
    }
}
