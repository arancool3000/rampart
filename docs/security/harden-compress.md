# Hardening: compressed and run-time-unpacked payloads (CX1, 2026-11-07)

User concern: "a sophisticated virus could run even when compressed / only when compressed".

## Threat model
- Asset: the scan verdict for anything that arrives packed (download, Mail/Messages attachment, AirDrop, script dropped by another program).
- Attacker: local malware or a lure file the user downloads. Tricks: password-protected zip with the password in the email; formats the scanner
  doesn't open (zstd, rar, odd compressors, zlib blobs); archive bombs and deep nesting to make the scanner give up; corrupt/truncated
  containers that the scanner skips but a lenient unpacker opens; shell / Python / JS / Ruby / Perl / AppleScript droppers that only carry
  a compressed or base64 payload and unpack it at run time; packed Mach-O (UPX-style) whose real code exists only in memory;
  unpacking with a tool that drops the quarantine flag, then running the extracted program (Gatekeeper never sees it).

## Findings
| Sev | Where | Issue | Fix | Status |
|---|---|---|---|---|
| High | ScanCoordinator.swift `scanContainer` | Any unpack failure (encrypted, over limit, corrupt, unknown format) returned no evidence: the archive was reported **clean**. | `ContainerUnreadable` error with reason + listable member names; `ContainerRisk.evidence` turns it into a "Couldn't look inside" note (30, log only) that rises with program-type members (+20), double extension (+15), download/Mail/Messages origin (+10/+15), password-protected download (+5), bomb (base 45). Cap 75, so it can alert but never auto-quarantines. | Fixed |
| High | ScanCoordinator.swift (depth check) | Containers at the nesting limit were silently skipped. | Over-depth containers get a "nested too deep" note (quiet for normal jar/whl/docx nesting). | Fixed |
| High | ScanCoordinator.swift (walk caps) | Member walk stopped silently at the file/byte cap. | Emits a bomb / too-many-files note. | Fixed |
| High | ArchiveUnpacker.swift | Single compressed streams (gzip/bzip2/xz/.Z/zlib) that are not tars were "unpack failed" -> clean; .Z, cpio, lz4, Apple Archive, zlib not sniffed at all. | Format detection by magic (`ArchiveFormat.detect`), single-stream decompression with a hard output cap (gzip/bzip2 tools via `BoundedProcess`; xz/zlib in-process with Compression), compressed tars still go straight to bsdtar, 7z/rar/cpio/xar via bsdtar, .aar/.yaa via `aa`. zstd/lz4 (no Apple tool) are reported as unreadable. | Fixed |
| Med | ArchiveUnpacker.swift (tar) | bsdtar extraction had no size precheck: a tar.gz bomb was written to disk before limits applied. | Bounded `tar -tv` listing first (member count, summed size, ratio). | Fixed |
| Med | ArchiveUnpacker.swift (zip) | Encrypted zips were passed to ditto; reason lost. | zipinfo listing detects encrypted members, lists names for risk scoring. | Fixed |
| Med | ArchiveUnpacker.swift (dmg) | Attaching an encrypted DMG could raise a password dialog (ZERO POP-UPS). | `hdiutil isencrypted` first; encrypted images are reported, never attached. | Fixed |
| Med | ArchiveUnpacker.swift (bsdtar) | Encrypted 7z/rar could make bsdtar prompt on a tty. | Always passes `--passphrase` with a dummy value. | Fixed |
| High | new EmbeddedPayload.swift | Scripts that decode/decompress and run a hidden payload were invisible (`tail -n +N "$0" \| gunzip \| sh`, `base64 -d \| gunzip \| bash`, `eval "$(…)"`, uudecode, `exec(zlib.decompress(b64decode(…)))`, JS `eval(inflateSync(Buffer.from(…)))`, Ruby/Perl/PHP equivalents, AppleScript `do shell script`). | Pattern evidence (45–60, explained), payload extraction (appended after `exit`/`__MARKER__`, `tail -n +N`/`tail -c`, sed/awk markers, base64 blobs, uuencoded blocks), bounded, scanned recursively. Self-extracting installers (payload -> tar, not -> shell) only get a 15-point context note. | Fixed |
| Med | new PackedMachO.swift | Packed Mach-O not recognised. | `PackedMachODetector` (always registered): UPX/MPRESS segment names or `UPX!` after load commands, `__text` entropy ≥ 7.4 with ≤ 2 dylibs and ≤ 16 symbols; 40 alone, 45 unsigned, 60 unsigned in a user-writable folder; notarised/Apple skipped. | Fixed |
| Med | new ExtractionLineage.swift | Nothing linked "archive unpacked" with "extracted file executed". | `ExtractionLineage` tracks extractor execs (Archive Utility, ditto, unzip, tar, aa, gunzip, 7z, …) and their file writes; exec of an extracted file (or a script passed to an interpreter) within 10 min returns a scan request with lineage text; `scanOnExec` scans and attaches it. Downloaded archive + quarantine-dropping tool + unflagged program = "Ran straight out of a downloaded archive without Gatekeeper" (45). | Fixed in engine; **needs owner** to wire (below) |
| Med | selftests (Remediation, Engine, Yara, Daemon, FP2, ScanPerf, Emergency, RedTeam) | EICAR fixtures were written under `/private/tmp/claude-501/…` (Remediation hard-coded the scratchpad; others use `$TMPDIR`, which agent sandboxes point at /private/tmp). The installed RamPart watches/quick-scans /private/tmp, so it detected and quarantined `com.rampart.test.eicar.com` during test runs and kept those detections. Files were deleted by the tests; the detections stayed. | `SelfTest.fixtureTempDir` = confstr Darwin user temp (`/private/var/folders/…/T/`, skipped by real-time protection, not in quick scans). All EICAR-writing suites use it; RedTeam cleanup moved to `defer`. The unpack temp root also moved there (`ArchiveUnpacker.defaultTempRoot`). | Fixed |

## Needs owner (rampartd / RealtimePipeline, I1)
`Sources/rampartd/Core/Realtime.swift`, in `RealtimePipeline`:
```swift
private let lineage = ExtractionLineage()            // RampartEngine
// first line of ingest(_:), before the behaviour hook:
if let req = lineage.observe(ev) {
    let scanner = self.scanner, cb = onDetection, lin = lineage
    scanQ.async {
        var d = scanner.scanFile(req.path)
        let ev = lin.evidence(for: req)
        if d != nil { d!.evidence.append(ev); d!.pid = req.runnerPid }
        else if ev.score > 0 { d = Scoring.makeDetection(path: req.path, sha256: nil, evidence: [ev], pid: req.runnerPid) }
        if let d { cb?(d) }
    }
}
```
(`ExtractionLineage.scanOnExec(_:coordinator:)` does the same when a `ScanCoordinator` is at hand.)
The app's "Why was this flagged?" panel already shows evidence details, so the lineage text appears there without UI changes.

## Remaining limits (honest)
- zstd and lz4 streams, RAR5 solid/encrypted, and password-protected anything can't be opened: they are reported, not checked.
- Raw deflate without a zlib/gzip header, custom XOR/AES "encryption" of payloads, and payloads fetched from the network at run time
  can't be extracted; only the decode-and-run pattern is reported.
- Pattern detection is regex-based: heavily obfuscated scripts (string concatenation, `getattr(__builtins__, …)`) can evade it.
  Behaviour rules and exec-time scanning remain the backstop.
- Packed-binary detection is heuristic; a custom packer with a normal-looking import table and moderate entropy evades it.
- Without the Endpoint Security entitlement RamPart sees an exec right after it happens: the extracted file is scanned on exec,
  not blocked before it.
- Lineage needs exec + file events (eslogger as root, or the process sweep + FSEvents fallback); without them nothing is linked.

## Tests
`rampart-selftest compress` (Sources/rampart-selftest/SelfTest+Compress.swift, Suites line `("compress", SelfTest.compressChecks)`).
