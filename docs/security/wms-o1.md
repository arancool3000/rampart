# wms-o1 — Untrusted-input parsers: mutation fuzzing and DoS hardening (2026-11-13)

Owner: agent O1. Owned area: `Sources/RampartYara/**` (YARA engine and rule parser); in `RampartEngine`, the
FileSniffer, ArchiveUnpacker, EmbeddedPayload and PackedMachO parsers; in `RampartSigning`, the Mach-O,
code-signature and plist parsing.
Regression tests and fuzz harness: `Sources/rampart-selftest/SelfTest+WMSo1.swift`, which runs `SelfTest.wmsO1Checks()`
(suite `wmso1`).

## Threat model

A malicious file only has to stop the scanner from finishing. If it crashes the process (a trap, SIGBUS or
stack overflow), the whole scan dies: every file after it goes unscanned, and real-time scanning restarts in a
loop. If it hangs, it holds a worker for the full per-file deadline. If it blows up memory, jetsam kills the
daemon. Each of these is a scan-evasion DoS. Every byte of a scanned file, every xattr on it and every member
of an archive is attacker-controlled. So is the file's size over time: the attacker can grow or truncate the
file while we read it.

Out of scope: the external tools RamPart spawns (`ditto`, `bsdtar`, `gzip`, `hdiutil`, `pkgutil`, `aa`).
They are bounded by timeouts and output caps, not by RamPart parsing. Also out of scope: the platform limits
(no Endpoint Security AUTH, no NetworkExtension, ad-hoc signing).

## Fuzz harness

`wmso1` is an in-process mutation fuzzer with a SplitMix64 PRNG and deterministic seeds. Its mutations are
bit and byte flips, "interesting" 32-bit and 64-bit integers (both endiannesses), chunk deletion,
duplication and insertion, truncation, and format dictionaries. They are biased toward the hot regions:
headers, load commands and code-signature blobs.

It mutates these fixtures:
- synthetic thin, fat32 and fat64 Mach-O files with dylib, rpath, uuid, symtab, encryption and segment/section
  load commands, plus a full code-signature SuperBlob (CodeDirectory, XML entitlements, CMS);
- `/usr/bin/true` (read-only);
- zip, tar, gzip, zlib and xz archives built at test time;
- a 512-byte dmg `koly` trailer;
- XML and binary plists;
- self-extracting and decode-and-run scripts;
- the YARA fixture rules and `Rules/rampart-generic.yar`.

Fuzz targets: `MachOFile(data:)`, PackedMachO (both slice and path), `FileSniffer` (header, fd and a lying
size), `ArchiveFormat.detect` (zlib trial inflate), `EmbeddedPayload.analyze` (true, larger and smaller sizes),
`Provenance.parseWhereFroms`, YARA rule compile+scan, YARA scan with `macho` module rules, and
`ArchiveUnpacker.unpack` on zip, tar, gz, zlib and xz.

Default budget: the whole suite takes about 50 s. A crash kills the selftest. Any single input that costs more
than its threshold (2 to 3 s of thread CPU time) is reported as a FAIL, and the input is saved. The unpack target
uses 20 s of wall time, because its work happens in subprocesses. CPU time is used so that a heavily loaded
machine doesn't produce false "hangs": during this work the load average was 150 to 210, and wall-clock stalls of
40 to 70 s with about 1 ms of CPU were seen.

Environment variables:
- `RAMPART_FUZZ_SECONDS=N` sets the seconds per target (long mode).
- `RAMPART_FUZZ_SEED` sets the seed.
- `RAMPART_FUZZ_TRACE=1` writes each input to disk before running it, for crash triage.
- `RAMPART_FUZZ_KEEP=dir` keeps slow inputs.

## Findings

| # | Sev | Where | Issue | Fix | Status |
|---|---|---|---|---|---|
| F1 | High | PackedMachO.swift `analyze(path:)` / `analyzeSlice` | A fat64 arch offset above `Int.max` trapped in `Int(UInt64)`. A section/segment file offset plus the slice offset overflowed `UInt64` (trap). Any crafted Mach-O crashed the scan. | `Int(exactly:)` + range check; `addingReportingOverflow` for slice + offset. | Fixed |
| F2 | Med | EmbeddedPayload.swift `analyze` | `totalSize - offset` underflowed (trap) when the file grew between `stat` and `read` (race), or when a caller passed a smaller size. | `totalSize = max(totalSize, head.count)`; `Int(clamping:)`. | Fixed |
| F3 | High | EmbeddedPayload.swift patterns | ICU catastrophic backtracking. One long line of decoder words (`gunzip gunzip …`) against `decoder[^\n]*\|\s*sh`, or many `x = zlib.decompress …` lines against the two-step pattern, took minutes per file. That is a worker DoS, and the thread kept spinning after the watchdog abandoned it. | Pattern matching runs on a copy with lines clipped to 4 KB, under a 1.5 s total budget for each script. `enumerateMatches(.reportProgress)` aborts a running match attempt at the deadline. | Fixed |
| F4 | High | YaraParser.swift / YaraRegex.swift | Unbounded recursion in condition parsing (`((((`, `not not`, `- - -`, `1+1+…` chains). Hex alternatives and regex groups could overflow the 512 KB stack of a scan thread when parsed, evaluated or freed. | Depth limits. Conditions get a 64-point budget: a `(` costs 4, since each parenthesis level re-enters about 15 parser frames (2.8 KB for `parsePrimary` alone in debug), so at most 16 nested; a unary, `not` or chain link costs 1. Hex alternatives are capped at 32, regex groups at 64. Rules over a limit are skipped with a reason. None of the 517 XProtect and bundled rules is affected; a selftest checks this. | Fixed |
| F5 | High | YaraScanner.swift `scanFile`, MachOFile.swift `init(path:)`, OwnData.swift `sameContents` | The file was read through `mmap`. Truncating it while the scan ran raised SIGBUS and killed the scanner: any file could evade by shrinking itself. | YARA reads with `pread` (the file is already capped at 100 MB). MachOFile uses a bounds-checked fd `Reader` with a 64 KB block cache. It never maps the file, and a short read returns nil. OwnData compares in chunks. | Fixed |
| F9 | High | EmbeddedPayload.swift hint scan (pre-existing) | `decoderHints.contains(where: lower.contains)` searched a Swift String Character by Character over up to 4 MB, for each of 35 hints. A crafted 1.3 MB script took 47 to 900 s, and the regex budget can't cut this step off. | ASCII-lowercased bytes + `memmem`. | Fixed |
| F10 | High | YaraParser.swift `HexParser.readInt`, YaraScanner.swift eval | Integer-overflow traps, found by a long fuzz run: a hex jump `[9223372036854775808]`; `Int64.min \ -1` and `% -1`; `for i in (lo..hi)` where `hi - lo` overflows; a huge `N% of them`; `hash.*(off, len)` where `off + len` overflows. One bad rule text, or a condition evaluated against any file, crashed the process. | Saturating parse, overflow-checked span and bounds, guarded division and remainder, clamped percent. | Fixed |
| F6 | Med | ArchiveUnpacker.swift `decompressStream` (.xz/.zlib) | The whole container (up to 2 GB) was read into memory twice. The output (up to a 4 GB cap) was also held in memory, so the scan could run out of memory. A stalled decoder could also spin. | Streaming inflate from file to file in 1 MB pieces, with an output cap, a deadline and stall detection. The in-memory `inflate` gained a stall guard. | Fixed |
| F7 | Med | ArchiveUnpacker.swift `zipListing` | The `unzip -Z` output was read without a bound, then cut down to 4 MB afterward. A zip declaring millions of members would grow memory to the size of that listing. | `BoundedProcess`, capped at `zipListingCap` (4 to 64 MB). A truncated listing is reported as `tooManyFiles` (it is never treated as clean). | Fixed |
| F8 | Med | MachOFile.swift entitlements, Provenance.swift `parseWhereFroms` | CoreFoundation's plist parsers recurse once per nesting level. A deeply nested XML or binary plist could exhaust the stack, through either the entitlements blob or the attacker-set `kMDItemWhereFroms` xattr. | New `PlistGuard`: XML tag depth ≤ 48 and no `<!ENTITY`. For binary plists, an iterative longest-path walk of the object graph that refuses cycles, bad tables and depth over 48. The parse happens only after the check passes. | Fixed |
| — | Info | ScanCoordinator | A per-file watchdog already exists (`perFileDeadline`, `abandonOverdue`). The YARA scanner has its own deadline plus regex and hex budgets. | Not changed. With F3 fixed, the parsers this agent owns return before the deadline, so abandoned threads no longer spin forever. | Existing |

## Residual risks

- Under the EmbeddedPayload regex budget, a script can pad itself with enough costly lines to use up the
  budget before its real decode-and-run line. The pattern is then missed: no crash, but a possible miss.
  Appended or embedded payloads are still extracted and scanned, and YARA and hash checks still run on the
  file itself.
- The external decompressors run as separate processes under a timeout and an output cap. A bug in one of
  them can't crash RamPart, but it can make a container "unreadable", which is reported, not passed as clean.
- Long-mode runs (three seeds at 20 s per target, about 200k inputs) found no further crashes. One unpack input took
  176 s of wall time once. Standalone, `tar` finished on it in under a second, so it was a scheduler stall under a
  load average of about 200. Each subprocess has its own timeout regardless.
- `hdiutil attach` of crafted DMGs was not fuzzed. It would mount images during development, and it is
  bounded by a timeout anyway.
- The watchdog abandons a stuck thread; it can't kill it. Any future parser that loops without a deadline
  would still burn a core.
- Limits of the fuzzing: it is mutation-based, with no coverage feedback and no sanitizers, because the
  Command Line Tools toolchain has no libFuzzer or ASan runtime here. The default runs are short. Use
  `RAMPART_FUZZ_SECONDS=600` for deeper runs.
