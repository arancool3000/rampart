import Foundation
import CryptoKit
import RampartShared
import RampartEngine
import RampartNetwork

// wms-fc: supply chain and integrity (docs/security/wms-fc.md). Signed feed manifests (FeedSigning), the hardened
// hash-feed and blocklist downloaders (mock URLProtocol only, no network), and the root shell scripts in --dry-run
// (environment injection, internal daemon source, links in the source bundle, pf anchor names, env -i wrappers).
// Nothing is installed, nothing runs privileged, no dialog can appear.

/// Routes requests to canned answers; records every URL asked for. `huge` streams `chunks` x 64 KB.
final class FcMockFeeds: URLProtocol, @unchecked Sendable {
    struct Answer { var status: Int; var body: Data; var headers: [String: String] = ["Content-Type": "text/plain"]; var redirectTo: URL? = nil; var chunks: Int = 0 }
    nonisolated(unsafe) static var routes: [String: Answer] = [:]
    nonisolated(unsafe) static var seen: [String] = []
    private static let lock = NSLock()
    static func reset() { lock.lock(); routes = [:]; seen = []; lock.unlock() }
    static func set(_ url: URL, _ a: Answer) { lock.lock(); routes[url.absoluteString] = a; lock.unlock() }
    static func sawHost(_ h: String) -> Bool { lock.lock(); defer { lock.unlock() }; return seen.contains { $0.contains(h) } }
    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func startLoading() {
        let url = request.url!
        Self.lock.lock(); Self.seen.append(url.absoluteString); let a = Self.routes[url.absoluteString]; Self.lock.unlock()
        guard let a else {
            client?.urlProtocol(self, didReceive: HTTPURLResponse(url: url, statusCode: 404, httpVersion: "HTTP/1.1", headerFields: [:])!, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self); return
        }
        if let to = a.redirectTo {
            let r = HTTPURLResponse(url: url, statusCode: 302, httpVersion: "HTTP/1.1", headerFields: ["Location": to.absoluteString])!
            var next = request; next.url = to
            client?.urlProtocol(self, wasRedirectedTo: next, redirectResponse: r)
            client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
            client?.urlProtocolDidFinishLoading(self); return
        }
        let r = HTTPURLResponse(url: url, statusCode: a.status, httpVersion: "HTTP/1.1", headerFields: a.headers)!
        client?.urlProtocol(self, didReceive: r, cacheStoragePolicy: .notAllowed)
        if a.chunks > 0 {
            let chunk = Data(repeating: 0x61, count: 65_536)
            for _ in 0..<a.chunks { client?.urlProtocol(self, didLoad: chunk) }
        } else { client?.urlProtocol(self, didLoad: a.body) }
        client?.urlProtocolDidFinishLoading(self)
    }
    override func stopLoading() {}
}

extension SelfTest {
    static func wmsFcChecks() {
        let fm = FileManager.default
        let repo = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().path
        let scratch = NSTemporaryDirectory() + "rampart-wmsfc-\(getpid())"
        try? fm.removeItem(atPath: scratch)
        try? fm.createDirectory(atPath: scratch, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: scratch) }

        func wait<T>(_ body: @escaping @Sendable () async -> T) -> T {
            let sem = DispatchSemaphore(value: 0); let box = FcBox<T>()
            Task { box.value = await body(); sem.signal() }
            sem.wait(); return box.value!
        }

        // ---- FeedSigning: signed manifests for RamPart's own feeds ------------------------------------------------
        // TEST KEY ONLY: fresh per run, never written anywhere. The production key is the lead's (FeedSigning hook).
        let (privB64, pubB64) = FeedSigning.generateKeyPair()
        let priv = Data(base64Encoded: privB64)!
        let body = Data((0..<20).map { String(format: "%064x", $0 + 1) }.joined(separator: "\n").utf8)
        let now = Date()
        func signed(feed: String = "rampart-test", version: Int = 2, body b: Data = body, created: Date = now, expires: Date? = nil, key: Data = priv) -> Data {
            (try? FeedSigning.sign(FeedSigning.manifest(feed: feed, version: version, body: b, created: created, expires: expires), privateKeyRaw: key)) ?? Data()
        }
        let good = signed()
        check(!good.isEmpty && good.count <= FeedSigning.maxManifestBytes, "wmsfc: signed manifest is small")
        if case .success(let m) = FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) {
            check(m.version == 2 && m.sha256 == FeedSigning.sha256Hex(body) && m.size == body.count, "wmsfc: manifest round-trips")
        } else { check(false, "wmsfc: valid manifest verifies") }
        check(FeedSigning.verify(signed: good, body: body + Data("x".utf8), feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.sizeMismatch), "wmsfc: body size change refused")
        var flipped = body; flipped[0] = flipped[0] == 0x30 ? 0x31 : 0x30
        check(FeedSigning.verify(signed: good, body: flipped, feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.hashMismatch), "wmsfc: body byte flip refused")
        check(FeedSigning.verify(signed: good, body: body, feed: "other", publicKeyBase64: pubB64, now: now) == .failure(.wrongFeed("rampart-test")), "wmsfc: manifest for another feed refused")
        let otherPub = FeedSigning.generateKeyPair().publicKeyBase64
        check(FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: otherPub, now: now) == .failure(.badSignature), "wmsfc: another key's manifest refused")
        check(FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: "AAAA", now: now) == .failure(.badKey), "wmsfc: malformed public key refused")
        var tamperedSig = good
        if var obj = try? JSONSerialization.jsonObject(with: good) as? [String: String] {
            obj["signature"] = Data(repeating: 0, count: 64).base64EncodedString()
            tamperedSig = (try? JSONSerialization.data(withJSONObject: obj)) ?? good
        }
        check(FeedSigning.verify(signed: tamperedSig, body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.badSignature), "wmsfc: edited signature refused")
        check(FeedSigning.verify(signed: Data("{\"manifest\":\"notbase64!\"}".utf8), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.malformed), "wmsfc: malformed envelope refused")
        check(FeedSigning.verify(signed: Data(repeating: 0x20, count: FeedSigning.maxManifestBytes + 1), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.tooLarge), "wmsfc: oversized manifest refused before parsing")
        check(FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: pubB64, previous: .init(version: 3), now: now) == .failure(.rollback(have: 2, previous: 3)), "wmsfc: version rollback refused")
        check(FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: pubB64, previous: .init(version: 2, sha256: "ab"), now: now) == .failure(.sameVersionDifferentBody), "wmsfc: same version with a different body refused")
        check({ if case .success = FeedSigning.verify(signed: good, body: body, feed: "rampart-test", publicKeyBase64: pubB64, previous: .init(version: 1), now: now) { return true }; return false }(), "wmsfc: newer version accepted")
        check({ if case .failure(.stale) = FeedSigning.verify(signed: signed(created: now.addingTimeInterval(-60 * 86_400)), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) { return true }; return false }(), "wmsfc: stale (replayed) manifest refused")
        check({ if case .failure(.future) = FeedSigning.verify(signed: signed(created: now.addingTimeInterval(3 * 86_400)), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) { return true }; return false }(), "wmsfc: manifest from the future refused")
        check({ if case .failure(.expired) = FeedSigning.verify(signed: signed(expires: now.addingTimeInterval(-1)), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) { return true }; return false }(), "wmsfc: expired manifest refused")
        check(FeedSigning.verify(signed: signed(version: 0), body: body, feed: "rampart-test", publicKeyBase64: pubB64, now: now) == .failure(.badVersion), "wmsfc: version 0 refused")
        // The hook: no production key yet, so no "RamPart feed" can be configured; with a key, the factories work.
        check(FeedSigning.productionPublicKeyBase64 == nil || FeedSigning.keyID(publicKeyBase64: FeedSigning.productionPublicKeyBase64!) != nil, "wmsfc: production key hook is nil or a valid key")
        let feedURL = URL(string: "https://feeds.rampart.test/hashes.txt")!
        check(HashFeed.rampartSigned(name: "x", url: feedURL, source: "rampart", publicKey: nil) == nil, "wmsfc: hash feed factory refuses to build an unsigned RamPart feed")
        check(HashFeed.rampartSigned(name: "x", url: feedURL, source: "rampart", publicKey: "junk") == nil, "wmsfc: hash feed factory refuses a bad key")
        check(HashFeed.rampartSigned(name: "x", url: feedURL, source: "rampart", publicKey: pubB64)?.effectiveManifestURL.absoluteString == feedURL.absoluteString + ".manifest.json", "wmsfc: hash feed factory with a key points at <url>.manifest.json")
        check(BlocklistUpdater.Source.rampartSigned(id: "rampart-domains", url: feedURL, format: .plain, minimumEntries: 1, publicKey: nil) == nil, "wmsfc: blocklist factory refuses an unsigned RamPart list")
        check(BlocklistUpdater.Source.rampartSigned(id: "rampart-domains", url: feedURL, format: .plain, minimumEntries: 1, publicKey: pubB64)?.manifestURL != nil, "wmsfc: blocklist factory with a key uses a signed manifest")

        // ---- HashFeedUpdater: pinned transport, streamed size cap, signed manifests, last known good ----------------
        if let db = try? HashDatabase.inMemory() {
            let up = HashFeedUpdater(database: db, timeout: 5, protocolClasses: [FcMockFeeds.self])
            up.maxBytes = 200_000
            FcMockFeeds.reset()
            // Unsigned feed off the pinned host: refused before any request.
            let rogue = HashFeed(name: "rogue", url: URL(string: "https://bazaar.abuse.ch.evil.test/x")!, source: "rogue")
            check(HashFeedUpdater.sourceRefusal(rogue) != nil, "wmsfc: unsigned hash feed from a non-pinned host refused")
            let r0 = wait { () -> Bool in (try? await up.update(rogue)) == nil }
            check(r0 && !FcMockFeeds.sawHost("evil.test"), "wmsfc: no request is sent to a non-pinned host")
            check(HashFeedUpdater.sourceRefusal(HashFeed(name: "http", url: URL(string: "http://bazaar.abuse.ch/x")!, source: "p")) != nil, "wmsfc: plain-http hash feed refused")
            check(HashFeedUpdater.sourceRefusal(HashFeed(name: "cred", url: URL(string: "https://user:pw@bazaar.abuse.ch/x")!, source: "p")) != nil, "wmsfc: hash feed URL with credentials refused")
            check(HashFeedUpdater.sourceRefusal(.malwareBazaarRecent()) == nil, "wmsfc: the MalwareBazaar default stays allowed")
            // Oversized body: streamed, abandoned, database untouched.
            let bazaar = HashFeed.malwareBazaarRecent()
            FcMockFeeds.set(bazaar.url, .init(status: 200, body: Data(), chunks: 6))   // 384 KB > 200 KB cap
            let big = wait { () -> String in do { _ = try await up.update(bazaar); return "accepted" } catch { return "\(error)" } }
            check(big.contains("too large") && db.knownBadCount() == 0, "wmsfc: oversized hash feed is refused while streaming (\(big))")
            // Redirect off the pinned host is not followed.
            FcMockFeeds.set(bazaar.url, .init(status: 200, body: Data(), redirectTo: URL(string: "https://collector.evil.test/feed")!))
            let red = wait { () -> String in do { _ = try await up.update(bazaar); return "accepted" } catch { return "\(error)" } }
            check(red != "accepted" && !FcMockFeeds.sawHost("collector.evil.test"), "wmsfc: hash feed redirect to another host is refused and never requested")
            // HTML block page refused.
            FcMockFeeds.set(bazaar.url, .init(status: 200, body: Data("<html>login</html>".utf8), headers: ["Content-Type": "text/html"]))
            check(wait { (try? await up.update(bazaar)) == nil } && db.knownBadCount() == 0, "wmsfc: HTML answer on the hash feed is refused")
            // A good unsigned fetch still works.
            FcMockFeeds.set(bazaar.url, .init(status: 200, body: body))
            check(wait { (try? await up.update(bazaar))?.stored == 20 } && db.knownBadCount() == 20, "wmsfc: valid hash feed imports")

            // Signed RamPart feed (test key only).
            guard let own = HashFeed.rampartSigned(name: "RamPart hashes", url: feedURL, source: "rampart", publicKey: pubB64) else { check(false, "wmsfc: signed feed fixture"); return }
            let manifestURL = own.effectiveManifestURL
            FcMockFeeds.set(feedURL, .init(status: 200, body: body))
            check(wait { (try? await up.update(own)) == nil } && db.knownBadCount(source: "rampart") == 0, "wmsfc: signed feed without a manifest is refused")
            FcMockFeeds.set(manifestURL, .init(status: 200, body: signed(feed: "rampart", version: 2), headers: ["Content-Type": "application/json"]))
            let ok = wait { () -> Int? in (try? await up.update(own))?.manifestVersion }
            check(ok == 2 && db.knownBadCount(source: "rampart") == 20 && db.meta("feed.rampart.version") == "2", "wmsfc: signed feed imports and records its version")
            // Rollback: an older signed manifest with its matching (older) body.
            let oldBody = Data((0..<15).map { String(format: "%064x", $0 + 500) }.joined(separator: "\n").utf8)
            FcMockFeeds.set(feedURL, .init(status: 200, body: oldBody))
            FcMockFeeds.set(manifestURL, .init(status: 200, body: signed(feed: "rampart", version: 1, body: oldBody), headers: ["Content-Type": "application/json"]))
            let rb = wait { () -> String in do { _ = try await up.update(own); return "accepted" } catch { return "\(error)" } }
            check(rb.contains("rollback") && db.knownBadCount(source: "rampart") == 20 && db.meta("feed.rampart.version") == "2", "wmsfc: signed feed rollback refused, last known good kept (\(rb))")
            // Tampered body under a valid manifest (mirror/MITM edit).
            FcMockFeeds.set(feedURL, .init(status: 200, body: flipped))
            FcMockFeeds.set(manifestURL, .init(status: 200, body: signed(feed: "rampart", version: 3), headers: ["Content-Type": "application/json"]))
            let tp = wait { () -> String in do { _ = try await up.update(own); return "accepted" } catch { return "\(error)" } }
            check(tp.contains("SHA-256") && db.meta("feed.rampart.version") == "2", "wmsfc: signed feed with an edited body refused (\(tp))")
            // Manifest signed by someone else.
            FcMockFeeds.set(feedURL, .init(status: 200, body: body))
            FcMockFeeds.set(manifestURL, .init(status: 200, body: signed(feed: "rampart", version: 3, key: Data(base64Encoded: FeedSigning.generateKeyPair().privateKeyBase64)!), headers: ["Content-Type": "application/json"]))
            check(wait { (try? await up.update(own)) == nil } && db.meta("feed.rampart.version") == "2", "wmsfc: signed feed with a foreign signature refused")
        } else { check(false, "wmsfc: in-memory hash database") }

        // ---- BlocklistUpdater: signed manifest path with rollback + last known good on disk -------------------------
        do {
            let dir = URL(fileURLWithPath: scratch + "/Blocklists")
            let listURL = URL(string: "https://feeds.rampart.test/domains.txt")!
            guard let src = BlocklistUpdater.Source.rampartSigned(id: "rampart-domains", url: listURL, format: .plain, minimumEntries: 3, publicKey: pubB64) else { check(false, "wmsfc: blocklist fixture"); return }
            let bl = BlocklistUpdater(sources: [src], directory: dir, timeout: 5, protocolClasses: [FcMockFeeds.self])
            let v2 = Data("bad1.test\nbad2.test\nbad3.test\nbad4.test\n".utf8)
            FcMockFeeds.reset()
            FcMockFeeds.set(listURL, .init(status: 200, body: v2))
            let noMan = wait { await bl.update(src, force: true) }
            check(!noMan.isSuccess && !fm.fileExists(atPath: dir.appendingPathComponent("rampart-domains.txt").path), "wmsfc: signed blocklist without a manifest is not stored (\(noMan))")
            FcMockFeeds.set(src.manifestURL!, .init(status: 200, body: signed(feed: "rampart-domains", version: 2, body: v2), headers: ["Content-Type": "application/json"]))
            let acc = wait { await bl.update(src, force: true) }
            check(acc.isSuccess && fm.contents(atPath: dir.appendingPathComponent("rampart-domains.txt").path) == v2, "wmsfc: signed blocklist accepted and stored (\(acc))")
            let v1 = Data("old1.test\nold2.test\nold3.test\n".utf8)
            FcMockFeeds.set(listURL, .init(status: 200, body: v1))
            FcMockFeeds.set(src.manifestURL!, .init(status: 200, body: signed(feed: "rampart-domains", version: 1, body: v1), headers: ["Content-Type": "application/json"]))
            let roll = wait { await bl.update(src, force: true) }
            check(!roll.isSuccess && "\(roll)".contains("rollback") && fm.contents(atPath: dir.appendingPathComponent("rampart-domains.txt").path) == v2, "wmsfc: blocklist rollback refused, last known good kept on disk (\(roll))")
            var edited = v2; edited.append(Data("extra.test\n".utf8))
            FcMockFeeds.set(listURL, .init(status: 200, body: edited))
            FcMockFeeds.set(src.manifestURL!, .init(status: 200, body: signed(feed: "rampart-domains", version: 3, body: v2), headers: ["Content-Type": "application/json"]))
            let ed = wait { await bl.update(src, force: true) }
            check(!ed.isSuccess && fm.contents(atPath: dir.appendingPathComponent("rampart-domains.txt").path) == v2, "wmsfc: blocklist body edited after signing refused (\(ed))")
            // Old-style detached-signature sources are unchanged: an unsigned source on a pinned host still works.
            check(BlocklistUpdater.hostAllowed(BlocklistUpdater.hageziTIF) && BlocklistUpdater.hostAllowed(BlocklistUpdater.urlhausHosts), "wmsfc: default pinned blocklist hosts unchanged")
        }

        // ---- Root shell scripts (dry runs only) ----------------------------------------------------------------------
        let setup = repo + "/Packaging/rampart-setup.sh"
        func run(_ exe: String, _ args: [String], env: [String: String]? = nil, extra: [String: String] = [:]) -> (Int32, String) {
            let p = Process(); p.executableURL = URL(fileURLWithPath: exe); p.arguments = args
            var e = env ?? ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": NSHomeDirectory(), "TMPDIR": NSTemporaryDirectory()]
            e["RAMPART_NO_PRIVILEGED_TOOLS"] = "1"
            for (k, v) in extra { e[k] = v }
            p.environment = e
            let pipe = Pipe(); p.standardOutput = pipe; p.standardError = pipe
            do { try p.run() } catch { return (-1, "\(error)") }
            let d = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
            return (p.terminationStatus, String(decoding: d, as: UTF8.self))
        }
        for f in ["Packaging/rampart-setup.sh", "scripts/install.sh", "scripts/uninstall.sh", "scripts/build.sh", "Packaging/scripts/postinstall", "Packaging/scripts/preinstall"] {
            check(run("/bin/bash", ["-n", repo + "/" + f]).0 == 0, "wmsfc: \(f) parses")
        }
        check(run("/bin/sh", ["-n", repo + "/Packaging/killswitch.sh"]).0 == 0, "wmsfc: killswitch.sh parses")
        let setupSrc = (try? String(contentsOfFile: setup, encoding: .utf8)) ?? ""
        check(setupSrc.contains("\nset -euo pipefail\n") && setupSrc.contains("PATH=/usr/bin:/bin:/usr/sbin:/sbin; export PATH"), "wmsfc: rampart-setup.sh uses set -euo pipefail and a fixed PATH")
        check(setupSrc.contains("unset RAMPART_DAEMON_SRC") && !setupSrc.contains("${RAMPART_DAEMON_SRC"), "wmsfc: the helper source is never taken from the environment")
        for f in ["scripts/install.sh", "scripts/uninstall.sh", "Packaging/scripts/postinstall"] {
            check(((try? String(contentsOfFile: repo + "/" + f, encoding: .utf8)) ?? "").contains("/usr/bin/env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin"), "wmsfc: \(f) starts the root script under env -i")
        }
        let ks = (try? String(contentsOfFile: repo + "/Packaging/killswitch.sh", encoding: .utf8)) ?? ""
        check(ks.contains("\nset -u\n") && ks.contains("unset RAMPART_KS_ANCHORS RAMPART_KS_SERVICES RAMPART_KS_ROOT"), "wmsfc: killswitch.sh ignores fixture variables outside dry runs")

        // Fixture bundle (ad-hoc signed copies of /usr/bin/true).
        func makeApp(_ path: String) -> Bool {
            try? fm.removeItem(atPath: path)
            for d in ["MacOS", "Resources", "Helpers"] { try? fm.createDirectory(atPath: path + "/Contents/" + d, withIntermediateDirectories: true) }
            let info: [String: Any] = ["CFBundleExecutable": "Rampart", "CFBundleIdentifier": "app.rampart.app", "CFBundlePackageType": "APPL",
                                       "CFBundleShortVersionString": "0.1.0", "CFBundleVersion": "202611131200"]
            guard let d = try? PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0) else { return false }
            fm.createFile(atPath: path + "/Contents/Info.plist", contents: d)
            try? fm.copyItem(atPath: "/usr/bin/true", toPath: path + "/Contents/MacOS/Rampart")
            try? fm.copyItem(atPath: "/usr/bin/true", toPath: path + "/Contents/MacOS/rampartd")
            try? fm.copyItem(atPath: setup, toPath: path + "/Contents/Resources/rampart-setup.sh")
            guard run("/usr/bin/codesign", ["-f", "-s", "-", "--identifier", "app.rampart.daemon", path + "/Contents/MacOS/rampartd"]).0 == 0 else { return false }
            return run("/usr/bin/codesign", ["-f", "-s", "-", path]).0 == 0
        }
        let app = scratch + "/Good.app"
        guard makeApp(app) else { check(false, "wmsfc: fixture bundle signs"); return }

        // Environment injection into the .pkg path (`install`): hostile PATH/IFS/DYLD/RAMPART_DAEMON_SRC change nothing.
        let hostile: [String: String] = ["PATH": "/nonexistent", "IFS": ":", "DYLD_INSERT_LIBRARIES": "/tmp/evil.dylib", "LD_PRELOAD": "/tmp/evil.so",
                                         "CDPATH": "/tmp", "GLOBIGNORE": "*", "RAMPART_DAEMON_SRC": "/private/tmp/evil-rampartd", "RAMPART_APP": app]
        let (irc, iout) = run("/bin/bash", [setup, "install", "--dry-run"], env: hostile)
        check(irc == 0 && iout.contains("Contents/MacOS/rampartd") && iout.contains("open "), "wmsfc: install dry run succeeds with a hostile environment (rc \(irc))")
        check(!iout.contains("evil-rampartd"), "wmsfc: RAMPART_DAEMON_SRC from the environment is ignored")
        // BASH_ENV: the wrapper may source it, the root script under env -i must not.
        let marker = scratch + "/bashenv.log", hook = scratch + "/bashenv.sh"
        fm.createFile(atPath: hook, contents: Data("echo \"$0 $*\" >> \(marker)\n".utf8))
        let (wrc, wout) = run("/bin/bash", [repo + "/scripts/install.sh", "--dry-run", app], extra: ["BASH_ENV": hook])
        let lines = (fm.contents(atPath: marker).map { String(decoding: $0, as: UTF8.self) } ?? "").split(separator: "\n")
        check(wrc == 0 && wout.contains("[dry-run]"), "wmsfc: install.sh dry run via the wrapper works (rc \(wrc))")
        check(lines.count <= 1 && !lines.contains { $0.contains("rampart-setup.sh") }, "wmsfc: BASH_ENV never reaches the root script (\(lines.count) sourced)")
        let users = scratch + "/Users"
        try? fm.createDirectory(atPath: users + "/good/Library/Application Support/Rampart", withIntermediateDirectories: true)
        let (urc, uout) = run("/bin/bash", [repo + "/scripts/uninstall.sh", "--dry-run"], extra: ["RAMPART_TEST_USERS_DIR": users, "BASH_ENV": hook])
        check(urc == 0 && uout.contains("good/Library/Application\\ Support/Rampart"), "wmsfc: uninstall.sh dry run passes fixture roots through env -i (rc \(urc))")

        // Links in the source bundle (root later runs ditto/chown -R/chmod -R on it): refused.
        let linked = scratch + "/Linked.app"
        _ = makeApp(linked)
        try? fm.createSymbolicLink(atPath: linked + "/Contents/Resources/hosts", withDestinationPath: "/etc/hosts")
        let (lrc, lout) = run("/bin/bash", [setup, "install-from", linked, "/Applications/Rampart.app", "--dry-run"])
        check(lrc != 0 && lout.contains("symlink or hard link"), "wmsfc: install-from refuses a bundle containing a symlink")
        let hard = scratch + "/Hard.app"
        _ = makeApp(hard)
        let outside = scratch + "/outside.txt"; fm.createFile(atPath: outside, contents: Data("x".utf8))
        if link(outside, hard + "/Contents/Resources/hard") == 0 {
            check(run("/bin/bash", [setup, "install-from", hard, "/Applications/Rampart.app", "--dry-run"]).0 != 0, "wmsfc: install-from refuses a bundle containing a hard link")
        } else { check(true, "wmsfc: hard link fixture unavailable on this volume") }
        check(run("/bin/bash", [setup, "install-from", app, "/Applications/Rampart.app", "--dry-run"]).0 == 0, "wmsfc: install-from still accepts a clean bundle")

        // pf anchor names from a listing are validated, never glob-expanded.
        let anchors = "com.apple/250.Rampart\n  com.apple/evil;rm -rf /rampart\ncom.apple/*rampart*\n$(id)rampart\nother\n"
        let (prc, pout) = run("/bin/bash", [setup, "uninstall", "--dry-run"], extra: ["RAMPART_TEST_PF_ANCHORS": anchors, "RAMPART_TEST_USERS_DIR": users])
        check(prc == 0 && pout.contains("pfctl -a com.apple/250.Rampart -F all"), "wmsfc: uninstall flushes listed RamPart anchors")
        check(!pout.contains("pfctl -a com.apple/\\*rampart") && !pout.contains("pfctl -a com.apple/evil") && !pout.contains("pfctl -a \\$(id)"), "wmsfc: anchor names with shell or glob characters are skipped")
        let (krc, kout) = run("/bin/sh", [repo + "/Packaging/killswitch.sh", "--dry-run"], extra: ["RAMPART_KS_ANCHORS": anchors, "RAMPART_KS_SERVICES": "An asterisk (*) denotes...\nWi-Fi\n", "RAMPART_KS_ROOT": scratch])
        check(krc == 0 && kout.contains("pfctl -a com.apple/250.Rampart -F all") && !kout.contains("pfctl -a com.apple/*rampart*") && !kout.contains("pfctl -a com.apple/evil"), "wmsfc: killswitch.sh skips hostile anchor names")
        check(kout.contains("networksetup -setdnsservers Wi-Fi Empty"), "wmsfc: killswitch.sh dry run still resets DNS")

        // set -e did not break the read-only checks: a record missing its version refuses with a message, not a silent exit.
        let rec = scratch + "/rec.plist"
        let (rrc, recXML) = run("/bin/bash", [setup, "identity-record", app])
        fm.createFile(atPath: rec, contents: Data(recXML.utf8))
        check(rrc == 0 && run("/bin/bash", [setup, "check-update", app, rec]).0 == 0, "wmsfc: identity record round-trips")
        _ = run("/usr/bin/plutil", ["-remove", "version", rec])
        let (crc, cout) = run("/bin/bash", [setup, "check-update", app, rec])
        check(crc != 0 && cout.contains("refused:"), "wmsfc: a record without a version refuses the update with a message")
        check(run("/bin/bash", [setup, "verify-bundle", scratch + "/missing.app"]).0 != 0, "wmsfc: verify-bundle on a missing bundle fails cleanly")
    }
}

private final class FcBox<T>: @unchecked Sendable { var value: T? }
