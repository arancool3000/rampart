import Foundation
import RampartShared

/// Signing / provenance / Mach-O structure heuristics for executables.
///
/// Rules (ARCHITECTURE.md): Apple platform code, App Store code and notarized Developer ID code produce no
/// evidence; nothing fires for Apple-signed code in /usr/bin, /System, /Applications; developer locations
/// (Homebrew, DerivedData, .build, ~/Developer...) stay silent for ad-hoc/unsigned; and the combined
/// confidence of everything this detector returns never exceeds 50 (`maxCombined`).
public struct SigningHeuristicDetector: FileDetector {
    public let name = "signing-heuristics"
    public static let maxCombined = 50

    public init() {}

    public func inspect(_ facts: FileFacts) -> [Evidence] {
        let path = facts.path
        let isBundle = facts.kind == .appBundle
        var exePath = path
        if isBundle {
            guard let e = Bundle(path: path)?.executablePath else { return [] }
            exePath = e
        } else {
            switch facts.kind {
            case .machO, .fatMachO: break
            case .other, .document, .script:
                guard facts.isExecutable, MachOFile.looksLikeMachO(path: path) else { return [] }
            default: return []
            }
        }
        let macho = try? MachOFile(path: exePath)
        // Object files, dSYMs and kexts aren't directly runnable by users; skip noise.
        if let ft = macho?.primaryFileType, ![MachOFile.MH_EXECUTE, MachOFile.MH_DYLIB, MachOFile.MH_BUNDLE].contains(ft) { return [] }

        let report: SigningReport
        if let s = facts.signing, s.status != .unknown {
            report = SigningReport(path: path, info: s, cdhash: nil, isPlatformBinary: s.status == .apple, codeFlags: 0,
                                   certificateChain: [], validationError: 0, bundleIdentifier: nil, otherCertificate: false)
        } else {
            report = SigningInspector.inspectCached(path: path)
        }
        let prov = Provenance.read(path: path)
        return Self.evaluate(path: path, report: report, macho: macho, provenance: prov,
                             isExecutable: facts.isExecutable || isBundle || macho?.primaryFileType == MachOFile.MH_EXECUTE)
    }

    /// Pure scoring function (no I/O) so it can be tested on synthetic inputs.
    public static func evaluate(path: String, report: SigningReport, macho: MachOFile?, provenance: Provenance,
                                isExecutable: Bool) -> [Evidence] {
        if report.isTrusted || report.isPlatformBinary { return [] }
        let cls = PathClass.classify(path)
        if cls == .system { return [] }          // SIP-protected; non-Apple code can't normally live here
        let s = report.info
        var ev: [Evidence] = []
        func add(_ title: String, _ detail: String, _ score: Int) {
            ev.append(Evidence(source: .signing, title: title, detail: detail, score: score))
        }
        let locWord: String = {
            switch cls {
            case .temp: return "a temporary or shared folder"
            case .userWritable: return "a user-writable folder"
            case .applications: return "Applications"
            case .developer: return "a developer folder"
            default: return "this location"
            }
        }()
        let dev = cls == .developer

        switch s.status {
        case .revoked:
            add("Apple revoked this signature", "Apple has revoked the certificate or notarization for this code, which usually means it was found to be malicious.", 50)
        case .invalid:
            add("Broken code signature", "The code signature does not validate (error \(report.validationError)); the file was modified after signing.", dev ? 15 : 40)
        case .unsigned:
            if !dev {
                let sc = cls == .temp ? 35 : cls == .userWritable ? 25 : cls == .applications ? 15 : 10
                add("Unsigned program", "This program has no code signature and is in \(locWord).", sc)
            }
        case .adHoc:
            if !dev {
                let sc = cls == .temp ? 30 : cls == .userWritable ? 20 : cls == .applications ? 10 : 5
                add("Ad-hoc signed program", "Signed without a developer identity (no Team ID) and located in \(locWord).", sc)
            }
        case .developerID:
            if s.notarized == false && provenance.isQuarantined && !dev {
                add("Not notarized", "Signed by developer \(s.teamID ?? "?") but not notarized by Apple, and downloaded from the internet.", 15)
            }
        case .unknown:
            if report.otherCertificate && !dev {
                add("Untrusted certificate", "Signed with a certificate that is not issued by Apple.", cls == .temp ? 20 : 10)
            }
        case .apple, .appStore: break
        }

        let weakSig = [.unsigned, .adHoc, .invalid, .unknown].contains(s.status)

        // Provenance
        if provenance.quarantineLikelyStripped && isExecutable {
            add("Quarantine flag removed", "The file was downloaded (from \(provenance.whereFroms.first ?? "the internet")) but its quarantine flag was removed, which bypasses Gatekeeper.", weakSig ? 30 : 15)
        } else if provenance.quarantine == nil && PathClass.isInDownloads(path) && weakSig && isExecutable {
            add("Downloaded program without quarantine", "An unsigned or ad-hoc program in Downloads has no quarantine flag, so Gatekeeper never checked it.", 10)
        }
        if let q = provenance.quarantine, weakSig, !dev, s.status != .invalid {
            add("Downloaded unsigned code", "Downloaded by \(q.agentName ?? "an app")\(provenance.whereFroms.first.map { " from \($0)" } ?? "") and has no trusted signature.", 15)
        }
        if PathClass.isHidden(path) && weakSig {
            add("Hidden location", "The program is in a hidden file or folder, a common way to hide persistent malware.", 20)
        }

        // Entitlements (only meaningful when the code isn't Apple-vetted, which is already the case here)
        let risky = report.riskyEntitlements
        if !dev && !risky.isEmpty && s.status != .unsigned {
            let dangerous = risky.filter { $0.hasSuffix("disable-library-validation") || $0.hasSuffix("allow-dyld-environment-variables") }
            if !dangerous.isEmpty {
                add("Weakened runtime protections", "Entitlements allow injecting code: \(dangerous.joined(separator: ", ")).", 10)
            }
        }
        if report.identifierMismatch && !dev {
            add("Signature identifier mismatch", "Signing ID \(s.signingID ?? "?") differs from bundle ID \(report.bundleIdentifier ?? "?"); the app may have been repackaged.", 10)
        }

        // Mach-O structure
        if let m = macho {
            if !m.slices.flatMap(\.dyldEnvironment).isEmpty {
                add("Embedded dyld environment", "The binary sets DYLD_* variables via LC_DYLD_ENVIRONMENT, a code-injection technique.", 20)
            }
            if !dev && !PathClass.isUserWritable(path) {
                let uw = m.userWritableDylibs + m.userWritableRpaths
                if !uw.isEmpty {
                    add("Loads libraries from user-writable folders", "Links \(uw.prefix(3).joined(separator: ", ")); anyone who can write there can hijack it.", 15)
                }
            }
            if m.anySliceUnsigned && s.status != .unsigned && weakSig && !dev {
                add("Partly unsigned universal binary", "At least one architecture slice has no code signature.", 10)
            }
        }
        return capCombined(ev, max: maxCombined)
    }

    /// combined = 100·(1 − Π(1 − s/100)). Scales scores down until combined ≤ `max`.
    public static func combined(_ scores: [Int]) -> Int {
        let p = scores.reduce(1.0) { $0 * (1 - Double(min(max($1, 0), 100)) / 100) }
        return Int((100 * (1 - p)).rounded())
    }

    public static func capCombined(_ ev: [Evidence], max cap: Int) -> [Evidence] {
        guard combined(ev.map(\.score)) > cap else { return ev }
        var lo = 0.0, hi = 1.0
        for _ in 0..<30 {
            let mid = (lo + hi) / 2
            if combined(ev.map { Int((Double($0.score) * mid).rounded(.down)) }) <= cap { lo = mid } else { hi = mid }
        }
        return ev.map { var e = $0; e.score = Int((Double($0.score) * lo).rounded(.down)); return e }
    }
}
