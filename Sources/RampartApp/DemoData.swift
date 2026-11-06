import Foundation
import RampartShared

/// Realistic sample data used when no daemon is reachable. Clearly labelled "Demo mode" in the UI.
/// All names are fictional; no real malware sample or indicator is referenced.
@MainActor
enum DemoData {
    static func populate(_ m: AppModel) {
        let now = Date()
        func ago(_ minutes: Double) -> Date { now.addingTimeInterval(-minutes * 60) }
        let home = NSHomeDirectory()

        m.status = ProtectionStatus(realtimeOn: true,
                                    sources: ["eslogger": true, "fsevents": true, "procsweep": true, "unifiedlog": true],
                                    webProtectionOn: true, fullDiskAccess: true, lastScan: ago(312),
                                    signatureVersion: "2026.11.05.1", xprotectVersion: "5321", securityScore: nil, openDetections: 1)
        m.definitionsUpdated = ago(12)

        let stealer = Detection(date: ago(26), path: home + "/Downloads/ScreenRecorderPro.app/Contents/MacOS/ScreenRecorderPro",
                                pid: 48_213, sha256: "4f9c2a6e1b7d03c58e2f94a1d6b0c3e7a85f1290de4b6c7a3e18f05d92b4c6a1",
                                name: "OSX.Stealer.Generic", category: .infostealer, severity: .high, confidence: 94,
                                evidence: [
                                    Evidence(source: .behaviour, title: "Read saved browser passwords",
                                             detail: "Opened ~/Library/Application Support/Google/Chrome/Default/Login Data at 9:41:07", score: 70),
                                    Evidence(source: .behaviour, title: "Asked for your password with a fake dialog",
                                             detail: "Ran osascript 'display dialog … with hidden answer' from a downloaded app", score: 60),
                                    Evidence(source: .yara, title: "Matched rule Rampart_Stealer_Structure",
                                             detail: "4 of 5 structural indicators (keychain path list, archive-and-upload routine)", score: 65),
                                    Evidence(source: .signing, title: "Not signed",
                                             detail: "No Developer ID signature · Notarized: No · Quarantine flag was removed before launch", score: 40),
                                ])
        let adware = Detection(date: ago(60 * 26), path: home + "/Library/LaunchAgents/com.searchbaron.update.plist",
                               sha256: "b1d07e3a9c4f62e8d5a0173bc94e6f28a1c3d5e7f90b2468ace13579bdf02468",
                               name: "Adware.SearchHijack", category: .adware, severity: .medium, confidence: 82,
                               evidence: [
                                   Evidence(source: .persistence, title: "New launch agent pointing at a temporary folder",
                                            detail: "ProgramArguments → /private/tmp/.sbupd/updater (unsigned)", score: 55),
                                   Evidence(source: .heuristic, title: "Changes your browser's search engine",
                                            detail: "Writes Safari and Chrome default-search preferences every hour", score: 50),
                               ], resolved: true)
        let eicar = Detection(date: ago(60 * 24 * 3), path: home + "/Downloads/eicar-test.com",
                              sha256: "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                              name: "EICAR-Test-File", category: .test, severity: .low, confidence: 100,
                              evidence: [Evidence(source: .hash, title: "Matched the EICAR antivirus test string",
                                                  detail: "This is a harmless industry-standard test file, not malware.", score: 100)],
                              resolved: true)
        m.detections = [stealer, adware, eicar]

        m.quarantine = [
            QuarantineRecord(date: adware.date, originalPath: adware.path!, sha256: adware.sha256!, size: 1_284,
                             detectionName: adware.name, ownerUID: 501, mode: 0o644),
            QuarantineRecord(date: ago(60 * 26 - 1), originalPath: "/private/tmp/.sbupd/updater",
                             sha256: "9a8b7c6d5e4f30211f2e3d4c5b6a79880f1e2d3c4b5a69788796a5b4c3d2e1f0", size: 412_336,
                             detectionName: adware.name, ownerUID: 501, mode: 0o755),
            QuarantineRecord(date: eicar.date, originalPath: eicar.path!, sha256: eicar.sha256!, size: 68,
                             detectionName: eicar.name, ownerUID: 501, mode: 0o644),
        ]

        m.posture = [
            PostureCheck(id: "filevault", title: "FileVault disk encryption", state: .pass, weight: 10, detail: "Your startup disk is encrypted.", fixable: false, fixHint: "System Settings › Privacy & Security › FileVault"),
            PostureCheck(id: "firewall", title: "macOS firewall", state: .fail, weight: 5, detail: "Incoming connections to apps aren't filtered.", fixable: true, fixHint: "Turn on the application firewall"),
            PostureCheck(id: "firewall.stealth", title: "Stealth mode", state: .fail, weight: 2, detail: "Your Mac answers ping and port probes on public networks.", fixable: true, fixHint: "Turn on stealth mode"),
            PostureCheck(id: "gatekeeper", title: "Gatekeeper", state: .pass, weight: 5, detail: "Only apps from the App Store and identified developers can open.", fixable: false, fixHint: ""),
            PostureCheck(id: "sip", title: "System Integrity Protection", state: .pass, weight: 5, detail: "System files are protected from modification.", fixable: false, fixHint: ""),
            PostureCheck(id: "autoupdate", title: "Automatic macOS updates", state: .fail, weight: 5, detail: "Security responses and system files aren't installed automatically.", fixable: true, fixHint: "Turn on automatic security updates"),
            PostureCheck(id: "lockdown", title: "Lockdown Mode", state: .notApplicable, weight: 0, detail: "Off. Only needed if you may be personally targeted.", fixable: false, fixHint: ""),
            PostureCheck(id: "screenlock", title: "Require password after sleep", state: .pass, weight: 3, detail: "Password required immediately.", fixable: false, fixHint: ""),
            PostureCheck(id: "guest", title: "Guest account", state: .pass, weight: 2, detail: "The guest account is off.", fixable: false, fixHint: ""),
            PostureCheck(id: "ssh", title: "Remote Login (SSH)", state: .pass, weight: 3, detail: "Off.", fixable: false, fixHint: ""),
            PostureCheck(id: "screensharing", title: "Screen Sharing", state: .unknown, weight: 3, detail: "Couldn't check without Full Disk Access.", fixable: false, fixHint: "System Settings › General › Sharing"),
            PostureCheck(id: "airdrop", title: "AirDrop", state: .pass, weight: 1, detail: "Contacts Only.", fixable: false, fixHint: ""),
            PostureCheck(id: "admins", title: "Administrator accounts", state: .pass, weight: 2, detail: "1 administrator account.", fixable: false, fixHint: ""),
            PostureCheck(id: "outdated", title: "Outdated apps", state: .fail, weight: 2, detail: "2 apps have security updates available: Zoom, VLC.", fixable: false, fixHint: "Open App Store › Updates"),
        ]

        m.persistence = [
            PersistenceItem(kind: .launchAgent, label: "com.google.keystone.agent", location: home + "/Library/LaunchAgents/com.google.keystone.agent.plist",
                            target: home + "/Library/Google/GoogleSoftwareUpdate/GoogleSoftwareUpdate.bundle", signing: SigningInfo(status: .developerID, teamID: "EQHXZ8M8AV", notarized: true)),
            PersistenceItem(kind: .loginItem, label: "Dropbox", location: "/Applications/Dropbox.app", target: "/Applications/Dropbox.app",
                            signing: SigningInfo(status: .developerID, teamID: "G7HH3F8CAK", notarized: true)),
            PersistenceItem(kind: .launchDaemon, label: "com.docker.vmnetd", location: "/Library/LaunchDaemons/com.docker.vmnetd.plist",
                            target: "/Library/PrivilegedHelperTools/com.docker.vmnetd", signing: SigningInfo(status: .developerID, teamID: "9BNSXJN65R", notarized: true)),
            PersistenceItem(kind: .browserExtension, label: "uBlock Origin Lite (Chrome)", location: "Chrome › Default › Extensions", target: nil, signing: nil),
        ]

        m.activity = [
            ActivityItem(date: ago(3), kind: .network, title: "Blocked Helper (Chrome) from reaching tracker-cdn.example", outcome: "Blocked"),
            ActivityItem(date: ago(12), kind: .update, title: "Definitions updated to 2026.11.05.1", outcome: "Up to date"),
            ActivityItem(date: ago(26), kind: .threat, title: "OSX.Stealer.Generic stopped in ScreenRecorderPro", outcome: "Needs decision"),
            ActivityItem(date: ago(41), kind: .network, title: "Blocked Safari from opening login-verify.example (phishing)", outcome: "Blocked"),
            ActivityItem(date: ago(95), kind: .protection, title: "Checked Zoom.pkg on download", outcome: "Safe"),
            ActivityItem(date: ago(312), kind: .scan, title: "Scheduled Quick Scan checked 18,204 files", outcome: "No threats"),
            ActivityItem(date: ago(60 * 9), kind: .settings, title: "Excluded ~/Developer/build from scans", outcome: "Rule added"),
            ActivityItem(date: ago(60 * 26), kind: .threat, title: "Moved Adware.SearchHijack to quarantine", outcome: "Contained"),
            ActivityItem(date: ago(60 * 26 + 1), kind: .protection, title: "New launch agent com.searchbaron.update appeared", outcome: "Flagged"),
            ActivityItem(date: ago(60 * 30), kind: .scan, title: "Full Scan checked 612,880 files", outcome: "1 found"),
            ActivityItem(date: ago(60 * 72), kind: .threat, title: "EICAR test file found in Downloads", outcome: "Contained"),
        ]

        m.scanHistory = [
            ScanRecord(kind: .quick, date: ago(312), scanned: 18_204, seconds: 52, found: 0, skipped: 0),
            ScanRecord(kind: .full, date: ago(60 * 30), scanned: 612_880, seconds: 1_384, found: 1, skipped: 312),
            ScanRecord(kind: .quick, date: ago(60 * 48), scanned: 17_998, seconds: 49, found: 0, skipped: 0),
            ScanRecord(kind: .custom, date: ago(60 * 72), scanned: 1_204, seconds: 6, found: 1, skipped: 0),
        ]

        m.connections = [
            AppConnections(app: "Safari", bundlePath: "/Applications/Safari.app", sentKB: 1_840, receivedKB: 48_210, destinations: [
                .init(host: "www.apple.com", port: 443, proto: "TCP", country: "US", blocked: false),
                .init(host: "news.example.org", port: 443, proto: "QUIC", country: "GB", blocked: false),
                .init(host: "login-verify.example", port: 443, proto: "TCP", country: "—", blocked: true)]),
            AppConnections(app: "Google Chrome", bundlePath: "/Applications/Google Chrome.app", sentKB: 3_022, receivedKB: 91_400, destinations: [
                .init(host: "www.google.com", port: 443, proto: "QUIC", country: "US", blocked: false),
                .init(host: "tracker-cdn.example", port: 443, proto: "TCP", country: "NL", blocked: true)]),
            AppConnections(app: "Mail", bundlePath: "/System/Applications/Mail.app", sentKB: 220, receivedKB: 4_810, destinations: [
                .init(host: "imap.mail.me.com", port: 993, proto: "TCP", country: "US", blocked: false)]),
            AppConnections(app: "Dropbox", bundlePath: "/Applications/Dropbox.app", sentKB: 12_400, receivedKB: 2_100, destinations: [
                .init(host: "client.dropbox.com", port: 443, proto: "TCP", country: "US", blocked: false),
                .init(host: "bolt.dropbox.com", port: 443, proto: "TCP", country: "US", blocked: false)]),
            AppConnections(app: "ScreenRecorderPro", bundlePath: nil, sentKB: 0, receivedKB: 0, destinations: [
                .init(host: "185.0.2.44", port: 8443, proto: "TCP", country: "—", blocked: true)]),
        ]
        m.wifi = WiFiInfo(ssid: "HomeNet", security: "WPA3 Personal", encrypted: true, gatewayChanged: false)
        m.blockedThisMonth = 14
        m.blockedToday = 3

        let cal = Calendar.current
        let today = cal.startOfDay(for: now)
        let files = [16_900, 18_204, 17_350, 21_480, 19_020, 8_410, 7_960, 18_640, 20_110, 19_870, 22_340, 18_990, 9_120, 14_380]
        let blocked = [1, 0, 2, 1, 0, 0, 1, 3, 1, 0, 2, 1, 2, 3]
        let threats = [0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1]
        m.daily = (0..<14).map { i in
            DayStat(day: cal.date(byAdding: .day, value: i - 13, to: today)!, filesChecked: files[i], sitesBlocked: blocked[i], threats: threats[i])
        }

        m.allowRules = [
            AllowRule(name: "build-tools", scope: .folder, value: home + "/Developer/build", created: ago(60 * 9), expires: nil),
            AllowRule(name: "Homebrew", scope: .developer, value: "Homebrew (team 927JGANW46)", created: ago(60 * 24 * 12), expires: nil),
        ]
    }

    /// Simulated scan with realistic pacing so the progress UI is exercised.
    static func runScan(_ m: AppModel, kind: ScanKind, paths: [String]) {
        let total: Int = kind == .quick ? 18_240 : (kind == .full ? 118_904 : 2_400)
        let perTick: Int = kind == .quick ? 420 : (kind == .full ? 1_350 : 160)
        let home = NSHomeDirectory()
        let sample = [home + "/Downloads", home + "/Desktop", home + "/Library/LaunchAgents", "/Applications/Safari.app/Contents",
                      "/Applications/Utilities", home + "/Library/Application Support", "/Library/LaunchDaemons", "/usr/local/bin"]
        let names = ["Info.plist", "main.js", "libswiftCore.dylib", "Resources/en.lproj", "installer.pkg", "setup.sh", "README.md", "icon.icns", "Frameworks/Sparkle.framework"]
        var scanned = 0
        var tick = 0
        let t = Timer.scheduledTimer(withTimeInterval: 0.1, repeats: true) { timer in
            MainActor.assumeIsolated {
                guard case .running(var p) = m.scanPhase else { timer.invalidate(); return }
                if p.paused { return }
                tick += 1
                if tick < 6 { p.current = "Estimating files…"; m.scanPhase = .running(p); return }
                scanned = min(total, scanned + perTick + Int.random(in: -40...40))
                p.total = total
                p.scanned = scanned
                let base = kind == .custom ? (paths.first ?? home) : sample[(tick / 4) % sample.count]
                p.current = base + "/" + names[tick % names.count]
                m.scanPhase = .running(p)
                m.noteScanPath(p.current)
                if scanned >= total {
                    timer.invalidate()
                    m.finishScan(kind: kind, scanned: total, found: [], seconds: Date().timeIntervalSince(p.started), skipped: kind == .full ? 312 : 0)
                }
            }
        }
        m.setDemoTimer(t)
    }
}
