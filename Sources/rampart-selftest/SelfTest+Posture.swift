import Foundation
import SQLite3
import RampartShared
import RampartPosture

// Owned by the posture build agent. Add checks with check(cond, "name").

/// Fake runner keyed by "exe arg1 arg2"; unknown commands fail to launch.
private struct FakeRunner: CommandRunning {
    var table: [String: CommandResult]
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult {
        table(([executable] + arguments).joined(separator: " "))
    }
    func table(_ key: String) -> CommandResult { table[key] ?? .failedToLaunch }
}

extension SelfTest {
    static func posture() {
        postureParsers()
        postureScoreAndFixer()
        postureTCC()
        postureBrowsers()
        postureFakeScan()
        postureLiveScan()
    }

    private static func st(_ o: ParseOutcome) -> PostureCheck.State { o.state }

    static func postureParsers() {
        typealias P = PostureParsers
        // FileVault (doc 07 [tested]: "FileVault is On.")
        check(st(P.fileVault("FileVault is On.\n")) == .pass, "fv on")
        check(st(P.fileVault("FileVault is Off.\n")) == .fail, "fv off")
        check(st(P.fileVault("FileVault is Off, but will be enabled after the next restart.\nDeferred enablement appears to be active for user 'x'.")) == .fail, "fv deferred")
        check(st(P.fileVault("FileVault is On.\nEncryption in progress: Percent completed = 34")) == .pass, "fv encrypting")
        check(st(P.fileVault("FileVault is On.\nDecryption in progress: Percent completed = 10")) == .fail, "fv decrypting")
        check(st(P.fileVault("")) == .unknown, "fv empty unknown")
        // SIP
        check(st(P.sip("System Integrity Protection status: enabled.\n")) == .pass, "sip on")
        check(st(P.sip("System Integrity Protection status: disabled.\n")) == .fail, "sip off")
        check(st(P.sip("System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled\n\tKext Signing: disabled\n")) == .fail, "sip custom")
        check(st(P.sip("csrutil: failed")) == .unknown, "sip garbage")
        // Gatekeeper
        check(st(P.gatekeeper("assessments enabled\n")) == .pass, "gk on")
        check(st(P.gatekeeper("assessments enabled\ndeveloper id enabled\n")) == .pass, "gk verbose")
        check(st(P.gatekeeper("assessments disabled\n")) == .fail, "gk off")
        // Firewall (doc 07 [tested]: "Firewall is disabled. (State = 0)")
        check(st(P.firewall("Firewall is disabled. (State = 0)\n")) == .fail, "fw off")
        check(st(P.firewall("Firewall is enabled. (State = 1)\n")) == .pass, "fw on")
        check(st(P.firewall("Firewall is blocking all non-essential incoming connections. (State = 2)")) == .pass, "fw blockall")
        check(st(P.firewall("Firewall is enabled.")) == .pass, "fw no state")
        check(st(P.firewall("")) == .unknown, "fw unknown")
        // Stealth (this Mac: "Firewall stealth mode is off")
        check(st(P.stealthMode("Firewall stealth mode is off\n")) == .fail, "stealth off")
        check(st(P.stealthMode("Firewall stealth mode is on\n")) == .pass, "stealth on")
        check(st(P.stealthMode("Stealth mode enabled\n")) == .pass, "stealth legacy on")
        check(st(P.stealthMode("Stealth mode disabled\n")) == .fail, "stealth legacy off")
        // Software Update plist (fixture mirrors this Mac: 27.0.1 with 27.2 + CLT pending)
        let suXML = """
        <?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
        <key>AutomaticDownload</key><true/><key>AutomaticallyInstallMacOSUpdates</key><true/>
        <key>ConfigDataInstall</key><true/><key>CriticalUpdateInstall</key><true/>
        <key>LastSuccessfulDate</key><date>2026-11-05T13:17:06Z</date>
        <key>RecommendedUpdates</key><array>
          <dict><key>Display Name</key><string>Command Line Tools for Xcode 27.2</string><key>Display Version</key><string>27.2</string><key>Identifier</key><string>Command Line Tools for Xcode 27.2</string></dict>
          <dict><key>Display Name</key><string>macOS 27.2</string><key>Display Version</key><string>27.2</string><key>Identifier</key><string>MSU_UPDATE_26B123_patch_27.2_minor</string><key>MobileSoftwareUpdate</key><true/></dict>
        </array></dict></plist>
        """
        let su = P.plistDictionary(Data(suXML.utf8))
        check(su != nil, "su plist parsed")
        check(st(P.autoUpdates(softwareUpdate: su, appStoreAutoUpdate: "1")) == .pass, "auto updates on (missing AutomaticCheckEnabled = default on)")
        var suOff = su ?? [:]; suOff["CriticalUpdateInstall"] = false
        let offO = P.autoUpdates(softwareUpdate: suOff, appStoreAutoUpdate: "0")
        check(offO.state == .fail && offO.detail.contains("security responses") && offO.detail.contains("App Store"), "auto updates off detail")
        check(st(P.autoUpdates(softwareUpdate: nil, appStoreAutoUpdate: nil)) == .unknown, "auto updates unknown")
        check(P.productVersion(swVers: "ProductName:\t\tmacOS\nProductVersion:\t\t27.0.1\nBuildVersion:\t\t26A434\n") == "27.0.1", "sw_vers")
        let osO = P.osUpToDate(softwareUpdate: su, currentVersion: "27.0.1")
        check(osO.state == .fail && osO.detail.contains("macOS 27.2") && !osO.detail.contains("Command Line"), "os update pending")
        var suMajor = su ?? [:]
        suMajor["RecommendedUpdates"] = [["Display Name": "macOS 28", "Display Version": "28.0", "Identifier": "MSU_UPDATE_x_major"]]
        check(st(P.osUpToDate(softwareUpdate: suMajor, currentVersion: "27.0.1")) == .pass, "major upgrade optional")
        var suNone = su ?? [:]; suNone["RecommendedUpdates"] = [[String: Any]]()
        check(st(P.osUpToDate(softwareUpdate: suNone, currentVersion: "27.0.1")) == .pass, "os up to date")
        // XProtect
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        check(st(P.xprotectFreshness(bundles: [("5371", now.addingTimeInterval(-6 * 86_400))], now: now)) == .pass, "xp fresh")
        check(st(P.xprotectFreshness(bundles: [("5000", now.addingTimeInterval(-60 * 86_400)), (nil, nil)], now: now)) == .fail, "xp stale")
        check(st(P.xprotectFreshness(bundles: [], now: now)) == .unknown, "xp missing")
        // Screen lock (doc 07 [tested]: NSLog prefix on stderr)
        check(st(P.screenLock("2026-11-05 16:53:32.080 sysadminctl[12789:175746] screenLock delay is 300 seconds")) == .pass, "screenlock 300")
        check(st(P.screenLock("2026-11-05 sysadminctl[1:2] screenLock delay is immediate")) == .pass, "screenlock immediate")
        check(st(P.screenLock("sysadminctl[1:2] screenLock delay is 3600 seconds")) == .fail, "screenlock 1h")
        check(st(P.screenLock("sysadminctl[1:2] screenLock is off")) == .fail, "screenlock off")
        check(st(P.screenLock("")) == .unknown, "screenlock unknown")
        // Guest
        check(st(P.guestAccount(sysadminctl: "2026-11-05 sysadminctl[1:2] Guest account disabled.", guestEnabledDefault: nil)) == .pass, "guest off")
        check(st(P.guestAccount(sysadminctl: "sysadminctl[1:2] Guest account enabled.", guestEnabledDefault: "0")) == .fail, "guest on")
        check(st(P.guestAccount(sysadminctl: nil, guestEnabledDefault: "0")) == .pass, "guest defaults fallback")
        check(st(P.guestAccount(sysadminctl: nil, guestEnabledDefault: nil)) == .unknown, "guest unknown")
        // launchd
        let notFound = "Bad request.\nCould not find service \"com.openssh.sshd\" in domain for system\n"
        check(P.launchdService(notFound) == .notLoaded, "launchd not found")
        let loaded = "system/com.openssh.sshd = {\n\tactive count = 0\n\tpath = /System/Library/LaunchDaemons/ssh.plist\n\ttype = LaunchDaemon\n\tstate = not running\n}"
        check(P.launchdService(loaded) == .loaded(running: false), "launchd loaded")
        check(P.launchdService("state = running\n") == .loaded(running: true), "launchd running")
        check(st(P.remoteLogin(service: notFound, disabled: [:])) == .pass, "ssh off")
        check(st(P.remoteLogin(service: loaded, disabled: [:])) == .fail, "ssh on")
        let dis = P.disabledServices("disabled services = {\n\t\"com.openssh.sshd\" => disabled\n\t\"com.apple.ftpd\" => true\n\t\"com.apple.x\" => enabled\n}")
        check(dis["com.openssh.sshd"] == true && dis["com.apple.ftpd"] == true && dis["com.apple.x"] == false, "print-disabled parse")
        check(st(P.remoteLogin(service: "weird", disabled: dis)) == .pass, "ssh disabled fallback")
        check(st(P.remoteLogin(service: nil, disabled: [:])) == .unknown, "ssh unknown")
        check(st(P.screenSharing(service: notFound, remoteManagementFlagExists: false)) == .pass, "screensharing off")
        check(st(P.screenSharing(service: notFound, remoteManagementFlagExists: true)) == .fail, "ARD on")
        check(st(P.screenSharing(service: loaded, remoteManagementFlagExists: false)) == .fail, "screensharing on")
        check(st(P.fileSharing(service: notFound)) == .pass, "smb off")
        check(st(P.fileSharing(service: loaded)) == .fail, "smb on")
        // Other sharing (this Mac: all off, nat domain missing)
        let cups = "_debug_logging=0\n_remote_admin=0\n_remote_any=0\n_share_printers=0\n_user_cancel_any=0\n"
        let acmu = "Content caching status:\n    Activated: false\n    Active: false\n"
        check(st(P.sharingServices(remoteAppleEvents: notFound, natPlist: nil, natPlistMissing: true, cupsctl: cups, mediaSharing: "0", contentCaching: acmu)) == .pass, "sharing off")
        let shOn = P.sharingServices(remoteAppleEvents: loaded, natPlist: ["NAT": ["Enabled": 1]], natPlistMissing: false,
                                     cupsctl: cups.replacingOccurrences(of: "_share_printers=0", with: "_share_printers=1"),
                                     mediaSharing: "1", contentCaching: "Activated: true")
        check(shOn.state == .fail && shOn.detail.contains("Internet Sharing") && shOn.detail.contains("Printer") && shOn.detail.contains("Content Caching") && shOn.detail.contains("Remote Apple Events"), "sharing on")
        check(st(P.sharingServices(remoteAppleEvents: nil, natPlist: nil, natPlistMissing: false, cupsctl: nil, mediaSharing: nil, contentCaching: nil)) == .unknown, "sharing unknown")
        // AirDrop (this Mac: "Contacts Only")
        check(st(P.airDrop("Contacts Only\n")) == .pass, "airdrop contacts")
        check(st(P.airDrop("Everyone")) == .fail, "airdrop everyone")
        check(st(P.airDrop("Off")) == .pass, "airdrop off")
        check(st(P.airDrop(nil)) == .pass, "airdrop default")
        // Lockdown (this Mac: key missing)
        check(st(P.lockdownMode(nil)) == .notApplicable, "lockdown off not penalised")
        check(st(P.lockdownMode("1")) == .pass, "lockdown on")
        // Admins (doc 07 [tested]: root arankeyhan _mbsetupuser)
        check(P.adminMembers("GroupMembership: root arankeyhan _mbsetupuser\n") == ["arankeyhan"], "admin filter")
        check(st(P.adminCount("GroupMembership: root arankeyhan _mbsetupuser")) == .pass, "one admin")
        check(st(P.adminCount("GroupMembership: root alice bob")) == .fail, "two admins")
        check(st(P.adminCount("No such key: GroupMembership")) == .unknown, "admin unknown")
        // Terminal secure keyboard (this Mac: 0)
        check(st(P.secureKeyboardEntry("0")) == .fail && st(P.secureKeyboardEntry("1")) == .pass, "secure keyboard")
        // Rosetta (this Mac: oahd running)
        check(st(P.rosetta(pgrepStatus: 0, oahDirExists: true, isAppleSilicon: true)) == .notApplicable, "rosetta info only")
        // Secure boot
        check(st(P.secureBoot("Local Policy:\n  Security Mode: Full Security\n")) == .pass, "bputil full")
        check(st(P.secureBoot("Security Mode: Reduced Security")) == .fail, "bputil reduced")
        check(st(P.secureBoot("Security Mode: Permissive Security")) == .fail, "bputil permissive")
        // Profiles (this Mac: one Screen Time profile)
        let prof = "arankeyhan[1] attribute: profileIdentifier: com.apple.ManagedSettings.macOS.7BE22211-B222-4C33-9D44-110000000055\nThere are 1 user configuration profiles installed for 'arankeyhan'\n"
        check(P.profileIdentifiers(prof).count == 1, "profile ids")
        check(st(P.profiles(prof)) == .pass, "screen time profile benign")
        check(st(P.profiles("There are no configuration profiles installed\n")) == .pass, "no profiles")
        let bad = P.profiles("_computerlevel[1] attribute: profileIdentifier: com.searchbaron.policy\n" + prof)
        check(bad.state == .fail && bad.detail.contains("com.searchbaron.policy"), "unknown profile flagged")
        // Trust settings (this Mac: Securly web-filter cert)
        let trust = "Number of trusted certs = 1\nCert 0: *.securly.com\n   Number of trust settings : 0\n"
        check(P.trustedCertNames(trust) == ["*.securly.com"], "trust names")
        check(st(P.trustedRoots(trust)) == .pass, "org filter cert passes")
        check(st(P.trustedRoots("Number of trusted certs = 1\nCert 0: Totally Legit Root CA\n")) == .fail, "unknown root flagged")
        check(st(P.trustedRoots("SecTrustSettingsCopyCertificates: No Trust Settings were found.\n")) == .pass, "no trust settings")
        // Firmware password
        check(st(P.firmwarePassword("Password Enabled: Yes")) == .pass && st(P.firmwarePassword("Password Enabled: No")) == .fail, "firmwarepasswd")
    }

    static func postureScoreAndFixer() {
        func c(_ id: String, _ s: PostureCheck.State, _ w: Int) -> PostureCheck {
            PostureCheck(id: id, title: id, state: s, weight: w, detail: "", fixable: false, fixHint: "")
        }
        let all = SecurityScore.compute([c("a", .pass, 50), c("b", .pass, 50)])
        check(all.value == 100 && all.label == .excellent, "score 100")
        let half = SecurityScore.compute([c("a", .pass, 50), c("b", .fail, 50), c("u", .unknown, 50)])
        check(half.value == 50 && half.label == .fair && half.unknownCount == 1 && half.failedCount == 1, "unknown never counts as fail")
        check(SecurityScore.compute([c("a", .pass, 50), c("b", .fail, 50)], ignoring: ["b"]).value == 100, "ignored excluded")
        check(SecurityScore.compute([c("a", .pass, 49), c("b", .fail, 51), c("lockdownMode", .pass, 2)]).value == 51, "lockdown bonus")
        check(SecurityScore.compute([c("a", .pass, 90), c("b", .fail, 10), c("lockdownMode", .notApplicable, 2)]).value == 90, "lockdown off no penalty")
        check(SecurityScore.label(for: 89) == .good && SecurityScore.label(for: 75) == .good && SecurityScore.label(for: 74) == .fair
              && SecurityScore.label(for: 49) == .needsAttention, "label bands")
        let labels = [0, 10, 49, 50, 74, 75, 89, 90, 100].map { SecurityScore.label(for: $0).rawValue }
        check(!labels.contains { $0.lowercased().contains("risk") }, "never At risk")
        check(PostureChecks.all.count == 26 && Set(PostureChecks.all.map(\.id)).count == 26, "26 unique checks (25 + sealed system volume)")
        check(PostureChecks.all.filter { $0.id != "lockdownMode" }.reduce(0) { $0 + $1.weight } == 122, "weights match doc 07 table (112) plus sealed system volume (10); score renormalises")

        let fw = PostureFixer.fix(for: "firewall")
        check(fw?.commands == [["/usr/libexec/ApplicationFirewall/socketfilterfw", "--setglobalstate", "on"]] && fw?.dryRun == true, "fix firewall")
        check(PostureFixer.fix(for: "stealthMode")?.commands.first == [PostureFixer.socketfilterfw, "--setstealthmode", "on"], "fix stealth")
        check(PostureFixer.fix(for: "guestAccount")?.commands.first == ["/usr/sbin/sysadminctl", "-guestAccount", "off"], "fix guest")
        check(PostureFixer.fix(for: "remoteLogin")?.commands.first == ["/usr/sbin/systemsetup", "-f", "-setremotelogin", "off"], "fix ssh")
        let au = PostureFixer.fix(for: "autoUpdates", dryRun: false)
        check(au?.dryRun == false && au?.commands.count == 6 && au?.commands.allSatisfy { $0.first == "/usr/bin/defaults" && $0.last == "true" } == true, "fix autoupdates")
        check(["fileVault", "sip", "lockdownMode", "secureBoot", "gatekeeper"].allSatisfy { PostureFixer.fix(for: $0) == nil }, "no unsafe fixes")
        check(PostureFixer.fix(for: "firewall")?.commands.allSatisfy { $0.first?.hasPrefix("/") == true } == true, "absolute paths only")
    }

    static func postureTCC() {
        let tmp = NSTemporaryDirectory() + "com.rampart.test.posture-\(getpid())"
        try? FileManager.default.createDirectory(atPath: tmp, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: tmp) }
        let dbPath = tmp + "/TCC.db"
        var db: OpaquePointer?
        sqlite3_open(dbPath, &db)
        sqlite3_exec(db, """
            CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, auth_reason INTEGER, auth_version INTEGER, last_modified INTEGER);
            INSERT INTO access VALUES ('kTCCServiceScreenCapture','com.example.app',0,2,2,1,1700000000);
            INSERT INTO access VALUES ('kTCCServiceAccessibility','/tmp/com.rampart.test.gone',1,2,4,1,1700000001);
            INSERT INTO access VALUES ('kTCCServiceMicrophone','com.example.denied',0,0,2,1,1700000002);
            """, nil, nil, nil)
        sqlite3_close(db)
        let (status, grants, _) = TCCReview.readGrants(dbPath: dbPath, database: .user)
        check(status == .ok && grants.count == 3, "tcc read fixture db")
        check(grants.first?.allowed == true && grants.first?.serviceName == "Screen Recording", "tcc grant fields")
        let findings = TCCReview.classify(grants, pathExists: { _ in false })
        check(findings.count == 1 && findings[0].grant.client == "/tmp/com.rampart.test.gone", "tcc missing-binary finding")
        let r = TCCReview.review(home: tmp, userDB: dbPath, systemDB: tmp + "/none.db", pathExists: { _ in false })
        check(r.status == .ok && r.findings.count == 1, "tcc review ok with fixture")
        // Legacy schema (pre-11: `allowed` column) still parses.
        let oldPath = tmp + "/old.db"
        sqlite3_open(oldPath, &db)
        sqlite3_exec(db, "CREATE TABLE access (service TEXT, client TEXT, client_type INTEGER, allowed INTEGER); INSERT INTO access VALUES ('kTCCServiceAccessibility','com.x',0,1);", nil, nil, nil)
        sqlite3_close(db)
        let (os, og, _) = TCCReview.readGrants(dbPath: oldPath, database: .system)
        check(os == .ok && og.first?.allowed == true, "tcc legacy schema")
        // Live: on this Mac without FDA it must report needs-FDA, never crash.
        let live = TCCReview.review()
        print("  live TCC review: \(live.status.rawValue) — \(live.message)")
        check([.ok, .needsFullDiskAccess].contains(live.status), "tcc live status sane")
    }

    static func postureBrowsers() {
        typealias B = BrowserHijackAudit
        check(B.classifySearchURL("https://www.google.com/search?q={searchTerms}").0 == .ok, "google ok")
        check(B.classifySearchURL("https://duckduckgo.com/?q={searchTerms}").0 == .ok, "ddg ok")
        check(B.classifySearchURL("https://search.yahoo.com/yhs/search?hspart=adk&type=x&p={searchTerms}").0 == .suspicious, "yhs suspicious")
        check(B.classifySearchURL("https://searchbaron.com/?q={searchTerms}").0 == .suspicious, "searchbaron suspicious")
        check(B.classifySearchURL("https://search.example.net/?q={searchTerms}").0 == .unrecognized, "unknown engine")
        let chrome = """
        {"default_search_provider_data":{"template_url_data":{"short_name":"Search Baron","keyword":"sb","url":"https://searchbaron.com/search?q={searchTerms}"}},
         "homepage":"https://www.apple.com","homepage_is_newtabpage":false,
         "session":{"restore_on_startup":4,"startup_urls":["https://search.myway.com/start"]}}
        """
        let cf = B.chromiumSettings(preferences: Data(chrome.utf8), browser: "Chrome", profile: "Default", source: "fixture")
        check(cf.count == 3, "chrome findings count")
        check(cf.first { $0.kind == .searchEngine }?.verdict == .suspicious, "chrome hijacked search")
        check(cf.first { $0.kind == .homepage }?.verdict == .ok, "chrome normal homepage")
        check(cf.first { $0.kind == .startupPage }?.verdict == .suspicious, "chrome hijacked startup")
        check(B.chromiumSettings(preferences: Data("{\"homepage\":\"https://x\"}".utf8), browser: "Chrome", profile: "D", source: "f").isEmpty, "chrome defaults no findings")
        let pol = B.policySettings(["DefaultSearchProviderSearchURL": "https://www.bing.com/search?q={searchTerms}",
                                    "ExtensionInstallForcelist": ["abcdefghijklmnopabcdefghijklmnop;https://x/update.xml"]],
                                   browser: "Chrome", source: "/Library/Preferences/com.google.Chrome.plist", managedByOrganization: false)
        check(pol.count == 2 && pol.allSatisfy { $0.verdict == .unrecognized }, "unmanaged policy flagged")
        // Firefox
        let ini = "[Install4F96D1932A9F858E]\nDefault=Profiles/abc.default-release\n\n[Profile0]\nName=default-release\nIsRelative=1\nPath=Profiles/abc.default-release\n\n[Profile1]\nName=x\nIsRelative=0\nPath=/Users/x/ff\n"
        check(B.firefoxProfilePaths(profilesINI: ini, firefoxRoot: "/R") == ["/R/Profiles/abc.default-release", "/Users/x/ff"], "profiles.ini")
        let prefs = """
        // Mozilla User Preferences
        user_pref("browser.startup.homepage", "https://search.handy-tab.com/home|https://www.mozilla.org");
        user_pref("browser.startup.page", 1);
        user_pref("app.update.lastUpdateTime", 123);
        """
        let pm = B.firefoxPrefs(prefs)
        check(pm["browser.startup.page"] == "1" && pm["browser.startup.homepage"]?.contains("|") == true, "prefs.js parse")
        let ff = B.firefoxPrefSettings(pm, profile: "p", source: "f")
        check(ff.count == 2 && ff[0].verdict == .suspicious && ff[1].verdict == .ok, "firefox homepage verdicts")
        // LZ4 block: literals "abc" + match(offset 3, len 6) => "abcabcabc"; then trailing literal "!"
        let block: [UInt8] = [0x32, 0x61, 0x62, 0x63, 0x03, 0x00, 0x10, 0x21]
        check(B.lz4BlockDecode(block, expectedSize: 10).map { String(decoding: $0, as: UTF8.self) } == "abcabcabc!", "lz4 decode")
        let json = #"{"version":6,"engines":[{"id":"e1","_name":"Bad","_loadPath":"[user]","_urls":[{"template":"https://searchmarquis.com/?q={searchTerms}"}]},{"id":"google","_name":"Google","_loadPath":"[app]google"}],"metaData":{"defaultEngineId":"e1"}}"#
        var moz = Array("mozLz40".utf8) + [0]
        let raw = Array(json.utf8)
        moz += [UInt8(raw.count & 0xff), UInt8(raw.count >> 8 & 0xff), 0, 0]
        // literal-only LZ4 block: token 0xF0 + length extension bytes
        var lit = raw.count - 15
        moz.append(0xF0)
        while lit >= 255 { moz.append(255); lit -= 255 }
        moz.append(UInt8(lit)); moz += raw
        let dec = B.decodeMozLz4(Data(moz))
        check(dec.map { String(decoding: $0, as: UTF8.self) } == json, "mozlz4 container decode")
        let fs = dec.map { B.firefoxSearchSettings(searchJSON: $0, profile: "p", source: "f") } ?? []
        check(fs.count == 1 && fs[0].verdict == .suspicious, "firefox search hijack")
        check(B.decodeMozLz4(Data("notmozlz4data".utf8)) == nil, "mozlz4 bad magic")
        let fpol = B.firefoxPolicySettings(policiesJSON: Data(#"{"policies":{"Homepage":{"URL":"https://www.example.org"},"SearchEngines":{"Default":"X"}}}"#.utf8), source: "f")
        check(fpol.count == 2 && fpol.allSatisfy { $0.verdict != .ok }, "firefox policies flagged")
        // Safari
        let sf = B.safariSettings(["HomePage": "https://www.apple.com/startpage/", "SearchProviderShortName": "DuckDuckGo"], source: "f")
        check(sf.count == 2 && sf.allSatisfy { $0.verdict == .ok }, "safari settings")
        // End-to-end on a fixture home folder.
        let home = NSTemporaryDirectory() + "com.rampart.test.home-\(getpid())"
        let prof = home + "/Library/Application Support/Google/Chrome/Default"
        try? FileManager.default.createDirectory(atPath: prof, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: home) }
        try? Data(chrome.utf8).write(to: URL(fileURLWithPath: prof + "/Preferences"))
        let r = B.audit(home: home, userName: "nobody", systemRoot: home)
        check(r.browsersChecked == ["Chrome"] && r.suspicious.count == 2, "audit fixture home")
        // Live (read-only) audit of this Mac.
        let live = B.audit()
        print("  live browser audit: checked \(live.browsersChecked), unreadable \(live.unreadable), flagged \(live.flagged.map { "\($0.browser) \($0.kind.rawValue): \($0.value)" })")
    }

    static func postureFakeScan() {
        let fw = PostureFixer.socketfilterfw
        let notFound = CommandResult(status: 113, stdout: "Bad request.\nCould not find service \"x\" in domain for system\n")
        let table: [String: CommandResult] = [
            "/usr/bin/fdesetup status": .init(stdout: "FileVault is On.\n"),
            "/usr/bin/csrutil status": .init(stdout: "System Integrity Protection status: enabled.\n"),
            "/usr/sbin/spctl --status": .init(stdout: "assessments enabled\n"),
            "\(fw) --getglobalstate": .init(stdout: "Firewall is disabled. (State = 0)\n"),
            "\(fw) --getstealthmode": .init(stdout: "Firewall stealth mode is off\n"),
            "/usr/sbin/sysadminctl -screenLock status": .init(stderr: "2026 sysadminctl[1:2] screenLock delay is 300 seconds\n"),
            "/usr/sbin/sysadminctl -guestAccount status": .init(stderr: "2026 sysadminctl[1:2] Guest account disabled.\n"),
            "/bin/launchctl print system/com.openssh.sshd": notFound,
            "/bin/launchctl print system/com.apple.screensharing": notFound,
            "/bin/launchctl print system/com.apple.smbd": notFound,
            "/bin/launchctl print system/com.apple.AEServer": notFound,
            "/usr/bin/dscl . -read /Groups/admin GroupMembership": .init(stdout: "GroupMembership: root arankeyhan _mbsetupuser\n"),
            "/usr/bin/profiles list": .init(stdout: "There are no configuration profiles installed\n"),
            "/usr/bin/security dump-trust-settings -d": .init(stdout: "SecTrustSettingsCopyCertificates: No Trust Settings were found.\n"),
            "/usr/bin/fdesetup slow": .init(timedOut: true),
        ]
        let env = PostureEnvironment(isRoot: false, isAppleSilicon: true, home: "/nonexistent", userName: "t",
                                     fileExists: { _ in false }, readFile: { _ in nil }, modificationDate: { _ in nil })
        let s = PostureScanner(runner: FakeRunner(table: table), environment: env)
        s.hasFullDiskAccess = false
        let r = s.scan()
        let byID = Dictionary(uniqueKeysWithValues: r.checks.map { ($0.id, $0) })
        check(r.checks.count == 26, "fake scan 26 checks")
        check(byID["firewall"]?.state == .fail && byID["firewall"]?.fixable == true, "fake firewall fail+fixable")
        check(byID["fileVault"]?.state == .pass && byID["fileVault"]?.fixable == false, "fake filevault pass")
        check(byID["secureBoot"]?.state == .unknown && r.needsPermission.contains("secureBoot"), "fake secure boot needs admin")
        check(byID["autoUpdates"]?.state == .unknown, "unreadable plist -> unknown")
        check(byID["firmwarePassword"]?.state == .notApplicable, "firmware n/a on arm")
        // Known: fv12 sip12 gk8 fw8 stealth3 screen6 guest3 ssh5 ss5 smb3 airdrop2 admin4 securekbd1 profiles3 roots2 + sharing(3, AE known)
        check(r.score.value == Int((Double(12+12+8+6+3+5+5+3+2+4+3+2+3) * 100 / Double(12+12+8+8+3+6+3+5+5+3+2+4+1+3+2+3)).rounded()), "fake score math")
        check(r.score.unknownCount > 0, "unknowns counted separately")
    }

    static func postureLiveScan() {
        let start = Date()
        let report = PostureScanner().scan()
        let secs = Date().timeIntervalSince(start)
        print(String(format: "  live posture scan: %.2fs, score %d (%@), %d failed, %d unknown, root=%@, FDA=%@",
                     secs, report.score.value, report.score.label.rawValue, report.score.failedCount, report.score.unknownCount,
                     "\(report.isRoot)", "\(report.hasFullDiskAccess)"))
        for c in report.checks {
            print("    [\(c.state.rawValue)] \(c.id) (w\(c.weight))\(c.fixable ? " [fix]" : ""): \(c.detail)")
        }
        check(secs < 10, "live scan under 10 s")
        check(report.checks.count == 26, "live 26 checks")
        check((0...100).contains(report.score.value), "live score in range")
        // Expected on this Mac (doc 07): firewall and stealth mode are off.
        let byID = Dictionary(uniqueKeysWithValues: report.checks.map { ($0.id, $0) })
        check(byID["firewall"]?.state != .unknown && byID["stealthMode"]?.state != .unknown, "live firewall/stealth readable")
        if byID["firewall"]?.state == .fail { check(byID["firewall"]?.fixable == true, "live firewall fixable") }
        check(byID["sip"]?.state == .pass && byID["gatekeeper"]?.state == .pass, "live SIP + Gatekeeper on")
        let data = try? JSONEncoder.rampart.encode(report.checks)
        check(data != nil, "checks encode for IPC")
    }
}
