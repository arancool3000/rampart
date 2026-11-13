import Foundation
import Darwin
import RampartShared
import RampartRefresh

// WMS o8: the app process and the Refresh cleaner. Everything runs in a scratch "home"; nothing real is moved,
// no app is launched. Trash moves go to a scratch Trash folder.
extension SelfTest {
    static func wmsO8Checks() {
        let fm = FileManager.default
        let base = ProcessInfo.processInfo.environment["RAMPART_SCRATCH"] ?? NSTemporaryDirectory()
        let raw = (base as NSString).appendingPathComponent("wms-o8-\(getpid())")
        try? fm.createDirectory(atPath: raw, withIntermediateDirectories: true)
        let root = RefreshSafetyPolicy.realPath(raw) ?? raw
        defer { try? fm.removeItem(atPath: root) }
        let home = root + "/home", trash = root + "/Trash"
        func write(_ p: String, _ text: String = "x") {
            try? fm.createDirectory(atPath: (p as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
            fm.createFile(atPath: p, contents: Data(text.utf8))
        }
        try? fm.createDirectory(atPath: trash, withIntermediateDirectories: true)
        let pol = RefreshSafetyPolicy(home: home, openFilesOverride: [])

        // 1. Case-insensitive path rules (APFS is usually case-insensitive).
        check(pol.pathRefusal(home + "/documents") == .protectedUserFolder, "o8.refresh.caseInsensitivePersonalFolder")
        check(pol.pathRefusal(home + "/library/mobile documents/com~apple~CloudDocs/a.txt") == .iCloud, "o8.refresh.caseInsensitiveICloud")
        check(pol.pathRefusal(home + "/library/application support/RAMPART/vault.db") == .rampartData, "o8.refresh.caseInsensitiveRampartData")
        check(pol.pathRefusal(home + "/LIBRARY/KEYCHAINS/x.db") == .keychain, "o8.refresh.caseInsensitiveKeychain")
        check(pol.pathRefusal(home.uppercased()) == .homeItself || pol.pathRefusal(home.uppercased()) == .systemPath, "o8.refresh.caseInsensitiveHome")
        check(pol.pathRefusal("/private") == .systemPath && pol.pathRefusal("/Volumes") == .systemPath, "o8.refresh.topLevelSystemFolders")

        // 2. Cloud storage and placeholders.
        check(pol.pathRefusal(home + "/Library/CloudStorage/Dropbox/a.pdf") == .iCloud, "o8.refresh.cloudStorageProviders")
        check(pol.pathRefusal(home + "/Library/Caches/x/.Report.pdf.icloud") == .cloudPlaceholder, "o8.refresh.icloudStubFile")
        write(home + "/Library/Caches/com.example.stubs/.thesis.docx.icloud")
        check(pol.refusal(home + "/Library/Caches/com.example.stubs") == .cloudPlaceholder, "o8.refresh.folderWithIcloudStub")

        // 3. Category allowlist: a tampered `brew cleanup -n` naming a document.
        let doc = home + "/Documents/thesis.docx"
        write(doc, "my thesis")
        check(pol.categoryRefusal(doc, .homebrew) == .outsideCategory, "o8.refresh.categoryHomebrewNotDocuments")
        check(pol.categoryRefusal(doc, .appCaches) == .outsideCategory, "o8.refresh.categoryCachesNotDocuments")
        check(pol.categoryRefusal(doc, .duplicates) == nil, "o8.refresh.categoryDuplicatesInDocumentsOK")
        check(pol.categoryRefusal(home + "/Library/Caches/Homebrew/foo.tar.gz", .homebrew) == nil, "o8.refresh.categoryHomebrewCacheOK")
        check(pol.categoryRefusal(home + "/Code/App/node_modules", .projectBuilds) == nil, "o8.refresh.categoryProjectBuildOK")
        check(pol.categoryRefusal(home + "/Library/Caches/pip", .packageCaches) == nil && pol.categoryRefusal(home + "/.Trash", .trash) == .outsideCategory
              && pol.categoryRefusal(home + "/Downloads", .oldDownloads) == .outsideCategory, "o8.refresh.categoryRootsOnlyForPackageCaches")
        check(pol.categoryRefusal(home + "/Code/App/src", .projectBuilds) == .outsideCategory, "o8.refresh.categoryProjectBuildNameOnly")
        check(pol.categoryRefusal(home + "/Library/Foo/node_modules", .projectBuilds) == .outsideCategory, "o8.refresh.categoryProjectBuildNotLibrary")
        check(pol.categoryRefusal(home + "/Documents/../Library/Caches/x", .appCaches) == nil
              && pol.categoryRefusal(home + "/Library/Caches/../../Documents/x", .appCaches) == .outsideCategory, "o8.refresh.categoryDotDot")
        let env = RefreshScanner.Environment(home: home, includePersonal: false, brewDryRunOutput: "Would remove: \(doc) (1KB)\n",
                                             runBrew: false, runSystemTools: false, lastUsed: { _ in nil })
        let brew = RefreshScanner(env: env, policy: pol).scan([.homebrew]).first?.items ?? []
        check(brew.isEmpty, "o8.refresh.scannerDropsTamperedBrewPath")
        let cleaner = RefreshCleaner(policy: pol, journalURL: URL(fileURLWithPath: root + "/undo.json"), trashDirectory: trash)
        let forged = cleaner.clean([RefreshItem(path: doc, category: .homebrew, bytes: 1, regenerable: true)], dryRun: false)
        check(forged.trashed.isEmpty && forged.refused.first?.reason == .outsideCategory && fm.fileExists(atPath: doc), "o8.refresh.cleanerRefusesForgedCategory")

        // 4. Secure move + undo (the default mover, into a scratch Trash).
        let cache = home + "/Library/Caches/com.example.o8/data.bin"
        write(cache, "cache")
        let ok = cleaner.clean([RefreshItem(path: home + "/Library/Caches/com.example.o8", category: .appCaches, bytes: 5, regenerable: true)], dryRun: false)
        check(ok.trashed.count == 1 && !fm.fileExists(atPath: cache) && ok.trashed.first.map { $0.trashed.hasPrefix(trash + "/") } == true,
              "o8.refresh.secureMoveToTrash (\(ok.refused) \(ok.failed))")
        let undone = cleaner.undo(ok.trashed)
        check(undone.restored.count == 1 && fm.fileExists(atPath: cache), "o8.refresh.undoAfterSecureMove")
        // Same name already in the Trash: no overwrite, a numbered copy.
        write(trash + "/com.example.o8", "older")
        let again = cleaner.clean([RefreshItem(path: home + "/Library/Caches/com.example.o8", category: .appCaches, bytes: 5, regenerable: true)], dryRun: false)
        check(again.trashed.first?.trashed == trash + "/com.example 1.o8"
              && (try? String(contentsOfFile: trash + "/com.example.o8", encoding: .utf8)) == "older", "o8.refresh.trashNameCollisionNoOverwrite")
        check(cleaner.undo(again.trashed).restored.count == 1, "o8.refresh.undoNumberedCopy")

        // 5. TOCTOU: the cache folder is swapped for a symlink to Documents after the check.
        let victim = home + "/Documents/data.bin"
        write(victim, "precious")
        let swap = home + "/Library/Caches/com.example.swap"
        write(swap + "/data.bin", "cache")
        var racer = RefreshCleaner(policy: pol, journalURL: URL(fileURLWithPath: root + "/undo2.json"), trashDirectory: trash)
        racer.beforeMove = { _ in
            _ = rename(swap, swap + ".old")
            _ = symlink(home + "/Documents", swap)
        }
        let raced = racer.clean([RefreshItem(path: swap + "/data.bin", category: .appCaches, bytes: 5, regenerable: true)], dryRun: false)
        check((try? String(contentsOfFile: victim, encoding: .utf8)) == "precious", "o8.refresh.toctouParentSwapKeepsDocument")
        check(raced.trashed.isEmpty && raced.refused.first?.reason == .changedDuringClean, "o8.refresh.toctouParentSwapRefused (\(raced.refused))")
        // A symlinked parent present from the start: the verified location is Documents, outside the category.
        let linked = cleaner.clean([RefreshItem(path: swap + "/data.bin", category: .appCaches, bytes: 5, regenerable: true)], dryRun: false)
        check(linked.trashed.isEmpty && fm.fileExists(atPath: victim), "o8.refresh.symlinkedParentIntoDocumentsRefused (\(linked.refused))")
        // The item itself replaced after the check.
        let swapped = home + "/Library/Caches/com.example.replace"
        write(swapped, "cache")
        var replacer = RefreshCleaner(policy: pol, journalURL: URL(fileURLWithPath: root + "/undo3.json"), trashDirectory: trash)
        replacer.beforeMove = { p in try? fm.removeItem(atPath: p); write(p, "different object") }
        let rep = replacer.clean([RefreshItem(path: swapped, category: .appCaches, bytes: 5, regenerable: true)], dryRun: false)
        check(rep.trashed.isEmpty && rep.refused.first?.reason == .changedDuringClean && fm.fileExists(atPath: swapped), "o8.refresh.toctouItemReplacedRefused")

        // 6. Tampered undo log can't move documents around.
        let evil = RefreshUndoEntry(original: root + "/exfil/thesis.docx", trashed: doc, bytes: 1, date: Date())
        check(!cleaner.undoAllowed(evil), "o8.refresh.undoRejectsNonTrashSource")
        let r6 = cleaner.undo([evil])
        check(r6.restored.isEmpty && fm.fileExists(atPath: doc), "o8.refresh.undoTamperKeepsDocument")
        let evil2 = RefreshUndoEntry(original: "/Library/LaunchAgents/x.plist", trashed: trash + "/x.plist", bytes: 1, date: Date())
        check(!cleaner.undoAllowed(evil2), "o8.refresh.undoRejectsDestinationOutsideHome")

        // 7. Empty Trash refuses a Trash folder that is a symlink.
        let fakeDocs = root + "/Docs"
        write(fakeDocs + "/keep.txt", "keep")
        _ = symlink(fakeDocs, root + "/LinkedTrash")
        var threw = false
        do { _ = try cleaner.emptyTrash(confirmed: true, trashDir: root + "/LinkedTrash", dryRun: false) } catch { threw = true }
        check(threw && fm.fileExists(atPath: fakeDocs + "/keep.txt"), "o8.refresh.emptyTrashRefusesSymlinkedTrash")

        // 8. Decoys when the Cat & Mouse status is unavailable.
        write(home + "/Library/Application Support/RamPart/deception/decoys.json",
              "[{\"path\":\"\(home)/Desktop/Passwords.xlsx\",\"kind\":\"file\"}]")
        let fb = RefreshSafetyPolicy.fallbackDecoyPaths(home: home)
        check(fb.contains(home + "/Documents/Private") && fb.contains(home + "/Desktop/Passwords.xlsx"), "o8.refresh.fallbackDecoys")
        let dp = RefreshSafetyPolicy(home: home, openFilesOverride: [], decoyPaths: fb)
        check(dp.pathRefusal(home + "/Desktop/Passwords.xlsx") == .rampartDecoy && dp.pathRefusal(home + "/documents/private/a") == .rampartDecoy,
              "o8.refresh.fallbackDecoysRefused")

        // 9. Desktop launcher: look-alikes, symlinked bundles, spoofed names, swapped bundles.
        func makeApp(_ path: String, id: String) {
            try? fm.createDirectory(atPath: path + "/Contents", withIntermediateDirectories: true)
            (["CFBundleIdentifier": id] as NSDictionary).write(toFile: path + "/Contents/Info.plist", atomically: true)
        }
        let sys = root + "/System/Applications", apps = root + "/Applications", user = root + "/home/Applications"
        makeApp(sys + "/Mail.app", id: "com.apple.mail")
        makeApp(apps + "/Zed.app", id: "dev.zed.Zed")
        makeApp(user + "/Safari.app", id: "com.evil.safari")                     // well-known name, wrong ID
        makeApp(user + "/S\u{0443}stem Settings.app", id: "com.evil.settings")   // Cyrillic у
        makeApp(user + "/RamPart.app", id: "com.evil.rampart")
        makeApp(user + "/\u{202E}gpj.Notes.app", id: "com.example.notes")         // bidi override in the name
        makeApp(root + "/elsewhere/Tool.app", id: "com.example.tool")
        _ = symlink(root + "/elsewhere/Tool.app", user + "/Tool.app")             // symlink out of the app folders
        let found = LauncherCatalog.discover(roots: [apps, user], extras: [])
        let names = found.map(\.name)
        check(!names.contains("Safari") && !names.contains { LauncherCatalog.skeleton($0) == "systemsettings" } && !names.contains("RamPart"),
              "o8.desktop.lookAlikesDropped (\(names))")
        check(!names.contains("Tool"), "o8.desktop.symlinkedBundleOutsideRootsSkipped")
        check(names.contains("Zed") && names.contains("gpj.Notes") && !names.contains { $0.unicodeScalars.contains { SafeText.isUnsafeScalar($0) } },
              "o8.desktop.namesCleaned (\(names))")
        check(LauncherCatalog.skeleton("S\u{0430}far\u{0456}") == "safari" && LauncherCatalog.skeleton("Ma\u{00ED}l") == "mail", "o8.desktop.skeleton")
        // A /System reference makes a same-name app elsewhere with another ID a look-alike.
        let withSys = LauncherCatalog.dropLookAlikes([LauncherApp(path: "/System/Applications/Mail.app", name: "Mail", bundleID: "com.apple.mail"),
                                                      LauncherApp(path: user + "/Mail.app", name: "Mail", bundleID: "com.evil.mail"),
                                                      LauncherApp(path: "/Applications/RamPart.app", name: "RamPart", bundleID: "app.rampart.app")])
        check(withSys.map(\.path) == ["/System/Applications/Mail.app", "/Applications/RamPart.app"], "o8.desktop.systemReferenceAndRealRampartKept")
        check(LauncherCatalog.defaultRoots.first == "/System/Applications", "o8.desktop.systemRootWinsBundleIDTie")
        // Swapped after discovery: other bundle ID, or replaced by a symlink elsewhere.
        if let zed = found.first(where: { $0.name == "Zed" }) {
            check(LauncherCatalog.stillSame(zed, roots: [apps, user], extras: []), "o8.desktop.stillSameUnchanged")
            makeApp(apps + "/Zed.app", id: "com.evil.zed")
            check(!LauncherCatalog.stillSame(zed, roots: [apps, user], extras: []), "o8.desktop.swappedBundleIDNotLaunched")
            try? fm.removeItem(atPath: apps + "/Zed.app")
            _ = symlink(root + "/elsewhere/Tool.app", apps + "/Zed.app")
            check(!LauncherCatalog.stillSame(zed, roots: [apps, user], extras: []), "o8.desktop.swappedToSymlinkNotLaunched")
        } else { check(false, "o8.desktop.zedFixture") }

        // 10. Untrusted text: a fake "All clear" second line or bidi reorder can't survive SafeText.
        let spoof = "evil.app\u{2028}RamPart: All clear \u{2014} no threats\nfound\u{202E}fdp.exe"
        let line = SafeText.line(spoof, max: 200)
        check(!line.contains("\n") && !line.unicodeScalars.contains { $0.value == 0x2028 || $0.value == 0x202E }, "o8.text.noLineOrBidiInjection")
    }
}
