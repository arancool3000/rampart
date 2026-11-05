# 04 — Detection Engines, Signature Sources, Hashing and Mach-O Analysis

Status: research, 2026-11-05. Target: Bastion (Swift, SwiftPM only, macOS 27, arm64).
Local checks were read-only (`brew info`, listing the XProtect bundle). Nothing was installed.

---

## 1. Local environment facts (checked on this machine)

| Item | Result |
|---|---|
| `brew info yara` | yara 4.5.8, bottled, BSD-3-Clause. Deps: jansson, libmagic, openssl@4, protobuf-c. Not installed. |
| `brew info yara-x` | yara-x 1.22.1, bottled, BSD-3-Clause. Not installed. The formula runs `cargo cinstall -p yara-x-capi --prefix ... --libdir lib`, so the bottle ships the C library, `yara_x.h` and a pkg-config file next to the `yr` CLI. |
| `brew info clamav` | clamav 1.5.4, bottled, GPL-2.0-or-later. Deps: json-c, openssl@4, pcre2, yara. Not installed. |
| `brew info ssdeep` | ssdeep 2.14.1 (libfuzzy), GPL-2.0-or-later. |
| `brew info tlsh` | No formula. Build from source (github.com/trendmicro/tlsh), or port it. |
| XProtect | `/Library/Apple/System/Library/CoreServices/XProtect.bundle` and `/private/var/protected/xprotect/XProtect.bundle` both exist. `XProtect.yara` is 1.05 MB with 512 rules, plus `XPScripts.yr` (66 KB), `XProtect.plist`, `XProtect.meta.plist`, and `gk.db`. Bundle version 5371. `/usr/bin/xprotect` is present. |
| CPU | 10 cores (relevant to hashing and scan parallelism). |

Note: on this network, `curl` to raw.githubusercontent.com was intercepted by a Securly content filter that returned a login page. Bastion's updater must check HTTP status, content type and signatures, and must never treat a 200 response as valid rule data on its own.

---

## 2. Engine options

### 2.1 YARA (libyara 4.x, C)
- **Licence:** BSD-3-Clause. Fine to embed and ship.
- **Status:** maintenance mode. VirusTotal's new development goes into YARA-X. 4.5.x still gets fixes.
- **Linking from SwiftPM:** use a `.systemLibrary` target with `pkgConfig: "yara"` and `providers: [.brew(["yara"])]`. The API is `yr_initialize`, `yr_compiler_create`, `yr_compiler_add_string`, `yr_compiler_get_rules`, `yr_rules_scan_mem/file/fd` with a C callback. The callback is a `@convention(c)` function, so pass context through `user_data` with `Unmanaged`.
- **Drawbacks:** it pulls in libmagic, jansson, protobuf-c and openssl. Shipping a self-contained .app means vendoring or relocating those dylibs. Its global state (`yr_initialize`) makes thread safety more fiddly than in YARA-X.

### 2.2 YARA-X (Rust rewrite, C API)
- **Licence:** BSD-3-Clause.
- **Status:** 1.x is stable and actively developed (1.22.1 in Homebrew). VirusTotal uses it in production. It is mostly compatible with YARA rule syntax, with stricter parsing and better error messages. Its `macho` module exposes more (entitlements, signature info, dylibs) than YARA 4's.
- **C API (`yara_x.h`, library `yara_x_capi`):** `yrx_compile(src, &rules)` for one-shot compilation, or `yrx_compiler_create` / `yrx_compiler_add_source` / `yrx_compiler_define_global_*` / `yrx_compiler_build`. Scanning uses `yrx_scanner_create(rules, &scanner)`, `yrx_scanner_set_timeout`, `yrx_scanner_set_global_str/int/bool` (for externals such as file path), `yrx_scanner_on_matching_rule(callback, user_data)`, `yrx_scanner_scan(scanner, data, len)`, and then `yrx_scanner_destroy` / `yrx_rules_destroy`. Compiled rules can be serialised (`yrx_rules_serialize` / `yrx_rules_deserialize`), which allows fast startup from a cached blob.
- **Threading:** a compiled `YRX_RULES` can be shared read-only. Create one `YRX_SCANNER` per worker thread.
- **Linking from SwiftPM:** see section 3. The library is a single Rust dylib/static lib with no runtime deps beyond libSystem (openssl only at build time for some modules, depending on features). It is much easier to bundle than libyara.
- **Drawbacks:** the Rust toolchain is needed if we vendor the source instead of using the bottle, and the static lib is large (tens of MB before stripping). There are a few syntax incompatibilities with old community rules (e.g. some regexes, duplicate rule names, `\` escapes), which need a compile-test pass on import.

### 2.3 Shelling out (`yr scan` / `yara` / `clamscan`)
- It is simple and isolates crashes in a child process. It costs process spawn per batch, output parsing, and no streaming callbacks. `yr scan --output-format ndjson` is easy to parse.
- Good for a prototype or as a crash-isolated fallback. Not recommended for on-access scanning. The Endpoint Security file-open path needs in-process, sub-millisecond decisions.

### 2.4 ClamAV (clamd / clamscan / libclamav)
- **Licence:** engine is GPL-2.0-or-later. Linking libclamav into Bastion would make the linked binary GPL. Running `clamd` as a separate process and talking over its socket (INSTREAM / SCAN commands) is the usual way to avoid that. Get legal sign-off either way.
- **Signatures:** `main.cvd`, `daily.cvd` and `bytecode.cvd`, updated by `freshclam`. They need several hundred MB on disk once unpacked, and clamd's resident memory is commonly about 1–1.5 GB with the full database loaded. Startup and reload take tens of seconds. Cisco's CDN enforces rate limits and bans abusive update clients. For fleet use, run a private mirror (`cvdupdate`). Database licensing: the official signatures are distributed by Cisco Talos under its terms. Redistributing them bundled inside a commercial product needs checking. Third-party DBs (e.g. Sanesecurity) have their own terms.
- **macOS efficacy:** ClamAV's coverage of current macOS threats (stealers, Adload variants, Go and Rust backdoors) is noticeably weaker than XProtect plus targeted YARA. Its strengths are archive and document unpacking (zip, rar, 7z, OLE2, PDF, mail) and broad Windows and Linux coverage, which is relevant if users store or forward files to other platforms.
- **Verdict:** optional, user-enabled module (for example "deep archive / cross-platform scan"). It should not be the core engine.

### 2.5 Apple XProtect (rules read in place)
- XProtect already runs on every Mac. Its YARA rules are on disk and world-readable: 512 rules at version 5371 on this machine, plus `XPScripts.yr` for scripts.
- **Plan:** read `/var/protected/xprotect/XProtect.bundle/Contents/Resources/XProtect.yara` (fall back to `/Library/Apple/System/Library/CoreServices/XProtect.bundle/...`) at runtime. Compile it with YARA-X and recompile when the bundle version in `Info.plist` / `XProtect.meta.plist` changes. Watch it with FSEvents or poll on launch.
- **Licence:** Apple-proprietary. Reading the rules at runtime on the user's own machine is fine. Do not copy, redistribute or ship them in the Bastion bundle or over our own update channel.
- **Caveats:**
  - A few rules use YARA 4 features or modules (e.g. `macho`, `hash`). They must compile under YARA-X. Compile per rule and skip and log any that fail rather than rejecting the whole set.
  - Apple updates silently (`xprotect` daemon, `XProtectPayloads`). The value Bastion adds is on-demand scans of arbitrary paths, archives, and files that XProtect doesn't check (it mostly checks at first launch or Gatekeeper assessment, plus periodic XProtect Remediator scans).
  - `xprotect` CLI (`/usr/bin/xprotect`) can report the version and trigger an update check. Only use it read-only.

---

## 3. Linking YARA-X from SwiftPM (no Xcode)

```
Bastion/
  Package.swift
  Sources/CYaraX/module.modulemap
  Sources/CYaraX/shim.h          // #include <yara_x.h>
  Sources/DetectionEngine/...     // Swift wrapper
```

`Sources/CYaraX/module.modulemap`:
```
module CYaraX [system] {
    header "shim.h"
    link "yara_x_capi"
    export *
}
```

`Package.swift` (excerpt):
```swift
.systemLibrary(
    name: "CYaraX",
    path: "Sources/CYaraX",
    pkgConfig: "yara_x_capi",
    providers: [.brew(["yara-x"])]
),
.target(name: "DetectionEngine", dependencies: ["CYaraX"]),
```

Notes:
- pkg-config resolves `-I/opt/homebrew/include -L/opt/homebrew/lib`. To build a distributable app, link the static `libyara_x_capi.a`, or copy the dylib into `Contents/Frameworks` and fix `install_name` with `install_name_tool`, so end users don't need Homebrew. For reproducible builds, a later step can build `yara-x-capi` from a pinned tag with `cargo cinstall` into `vendor/` and point an `unsafeFlags`-free `linkerSettings` / modulemap at it, or ship an XCFramework `.binaryTarget`.
- Swift wrapper shape: `final class YaraRules: @unchecked Sendable` owns `OpaquePointer` (YRX_RULES). `struct YaraScanner` is per-thread and owns YRX_SCANNER. The callback is `@convention(c) (OpaquePointer?, UnsafeMutableRawPointer?) -> Void`, and it collects rule identifiers via `yrx_rule_identifier` / `yrx_rule_namespace` into a `Box` passed as `user_data`.
- Scan by memory-mapping the file (`Data(contentsOf:options: .alwaysMapped)` or `mmap`) and calling `yrx_scanner_scan`. Set a per-file timeout (e.g. 5 s) and a size cap (e.g. skip YARA above 256 MB, hash only).
- Use `yrx_rules_serialize` to cache compiled XProtect plus Bastion rules in `~/Library/Application Support/Bastion/rules.bin`, keyed by the XProtect version and the Bastion rule-pack version.

Fallback for the prototype: `Process` running `/opt/homebrew/bin/yr scan --output-format ndjson <rules> <path>`.

---

## 4. Signature and intel sources — licences and update mechanics

| Source | What | Access / update | Licence / commercial use |
|---|---|---|---|
| **abuse.ch MalwareBazaar** | Malware sample SHA-256/MD5/SHA-1 hashes, tags, signatures | Free Auth-Key from auth.abuse.ch (required since 2024). API `mb-api.abuse.ch/api/v1/`. Bulk exports: recent-additions CSV (hourly) and full dump (daily zip). | abuse.ch fair-use terms (updated 2025-11-04): free for not-for-profit use. **Commercial use requires a paid Spamhaus subscription** (Spamhaus is the primary licensee). Fine for a free, non-commercial Bastion. Must be revisited before charging. |
| **URLhaus** | Malicious URLs / hosts | CSV / hostfile / API exports, updated every 5 minutes | Same abuse.ch / Spamhaus terms. |
| **ThreatFox** | IOCs (IP:port, domains, URLs, hashes) with malware family | API + JSON/CSV exports | Same abuse.ch / Spamhaus terms. |
| **Feodo Tracker** | Botnet C2 IP blocklist | Plain-text / JSON blocklists, updated every 5 minutes | Same abuse.ch / Spamhaus terms. |
| **Apple XProtect** | ~500 YARA rules, macOS-specific, high quality | Updated by Apple. Read in place. | Apple-proprietary: use locally only, never redistribute. |
| **Yara-Rules/rules** (GitHub) | Large community rule set, mostly Windows, stale | git | GPL-2.0. Copyleft for the rule files themselves. Mostly low value for macOS. |
| **Neo23x0 signature-base** | Florian Roth's YARA + IOCs, includes some macOS | git | **Detection Rule License (DRL) 1.1**: commercial use allowed with attribution. Some rules use THOR-only externals (`filename`, `filepath`, `extension`), so define those globals. |
| **ReversingLabs reversinglabs-yara-rules** | Well-tested rules, low FP, some macOS | git | **MIT**. |
| **Elastic protections-artifacts** | Endpoint YARA rules incl. many `MacOS_*` | git (auto-generated; no PRs) | **Elastic License 2.0**: allows use and redistribution but forbids offering as a managed service and removing licence notices. Needs legal review for a commercial product. Rules were written for Elastic Endpoint, so a few need adaptation. |
| **Objective-See** | Malware sample collection (objective-see.org/malware.html) and open-source tools (KnockKnock, BlockBlock, LuLu, etc.) | Website / GitHub | Tools are mostly GPL-3.0, so use them for ideas, not code. Samples are for testing; no rule feed. |
| **VirusTotal API v3** | Hash reputation | Free key | Public API: **4 req/min, 500/day, 15.5k/month, non-commercial only**. Premium is required for commercial use and higher volume. Use it only for user-initiated "look up this file" with the user's own key, or skip it. |
| **Google Safe Browsing** | URL reputation | v4 Lookup/Update API; v5 (hash-prefix, local DB) | **Non-commercial use only.** Commercial products must use **Google Web Risk API** (paid, with a free tier). Use the Update API / local hash-prefix list for privacy. |
| **Have I Been Pwned** | Breach monitoring | Breached-account search needs a **paid key** (subscription tiers from a few US$/month, rate-limited by tier). **Pwned Passwords** range API (`api.pwnedpasswords.com/range/{5-hex}`) is free, keyless, k-anonymity. | Attribution required (CC BY 4.0). Domain search requires verifying domain ownership. |
| **PhishTank** | Phishing URLs | New registrations have effectively been closed for years and the feed is unreliable | Free with an app key if you can get one. Don't depend on it. |
| **OpenPhish** | Phishing URLs | Community feed (plain text, ~12 h refresh) | Community feed is free for non-commercial use. Premium is paid. |
| **ClamAV DBs** | main/daily/bytecode | freshclam / cvdupdate | Cisco Talos terms; check before redistributing. |

**Update mechanism:**
- Bastion runs its own update job (a launchd agent every 1–6 h):
  - Downloads abuse.ch exports with the Auth-Key.
  - Verifies the HTTP status, content type and expected format (CSV header / JSON schema), which guards against captive portals and filters like the one observed here.
  - Builds compact local stores:
    - SHA-256 set: a sorted binary file of 32-byte entries searched with binary search, or a SQLite table. A Bloom filter in front is optional.
    - URL/domain set for the network module.
  - Swaps the stores in atomically (write temp, then `rename`).
- Bastion's own rule pack (generic and EICAR rules) is signed. Verify it with an Ed25519 signature via CryptoKit before loading.
- XProtect needs no download: watch its bundle.

---

## 5. Generic rules Bastion ships (instead of malware-family rules)

The rule set is deliberately generic. Family coverage comes from XProtect (read in place) and from abuse.ch hashes. Signature and code-signing checks are done in Swift (section 7), because YARA can't evaluate trust. The YARA rules below catch the test file and structural traits, and they take externals that the Swift layer sets per file with `yrx_scanner_set_global_*`.

```yara
// Externals: set per file by Bastion before each scan.
// filepath (str), is_user_writable (bool), is_quarantined (bool),
// sig_state (str: "unsigned" | "adhoc" | "devid" | "appstore" | "apple" | "invalid")

private rule Bastion_MachO_Thin {
    condition:
        uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface   // MH_MAGIC_64 / MH_MAGIC (LE)
}

private rule Bastion_MachO_Fat {
    condition:
        (uint32be(0) == 0xcafebabe or uint32be(0) == 0xcafebabf)  // FAT_MAGIC / FAT_MAGIC_64
        and uint32be(4) > 0 and uint32be(4) < 20                  // nfat_arch sanity (excludes Java .class)
}

private rule Bastion_MachO {
    condition: Bastion_MachO_Thin or Bastion_MachO_Fat
}

rule Bastion_EICAR_Test_File {
    meta:
        description = "EICAR anti-malware test file (harmless)"
        severity = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar at 0 and filesize < 128
}

rule Bastion_Unsigned_MachO_In_User_Writable_Path {
    meta:
        description = "Unsigned Mach-O executable in a user-writable location"
        severity = "medium"
    condition:
        Bastion_MachO and sig_state == "unsigned" and is_user_writable
}

rule Bastion_AdHoc_MachO_In_User_Writable_Path {
    meta:
        description = "Ad-hoc signed Mach-O (no Team ID) in a user-writable location"
        severity = "low"     // common for dev tools/Homebrew builds; raise if combined with persistence
    condition:
        Bastion_MachO and sig_state == "adhoc" and is_user_writable
}

rule Bastion_Invalid_Signature_MachO {
    meta:
        description = "Mach-O whose code signature fails validation (tampered)"
        severity = "high"
    condition:
        Bastion_MachO and sig_state == "invalid"
}

rule Bastion_MachO_In_Temp_Or_Shared {
    meta:
        description = "Executable placed in /tmp, /private/var/tmp or /Users/Shared"
        severity = "low"
    condition:
        Bastion_MachO and (
            filepath matches /^\/(private\/)?tmp\// or
            filepath matches /^\/(private\/)?var\/tmp\// or
            filepath matches /^\/Users\/Shared\//
        )
}

rule Bastion_Hidden_MachO_In_Library {
    meta:
        description = "Mach-O inside a dot-directory under ~/Library (common hiding spot)"
        severity = "medium"
    condition:
        Bastion_MachO and filepath matches /^\/Users\/[^\/]+\/Library\/(.*\/)?\.[^\/]+\//
}

rule Bastion_LaunchItem_Targets_User_Writable_Binary {
    meta:
        description = "LaunchAgent/Daemon plist whose program lives in tmp/Shared/hidden dir"
        severity = "medium"
    strings:
        $plist = "<plist" ascii
        $k1 = "<key>ProgramArguments</key>" ascii
        $k2 = "<key>Program</key>" ascii
        $p1 = /<string>\/(private\/)?tmp\// ascii
        $p2 = /<string>\/Users\/Shared\// ascii
        $p3 = /<string>[^<]*\/\.[A-Za-z0-9_\-]+\/[^<]*<\/string>/ ascii
    condition:
        filepath matches /\/Library\/Launch(Agents|Daemons)\/[^\/]+\.plist$/
        and $plist and ($k1 or $k2) and any of ($p*)
}

rule Bastion_Script_Pipes_Download_To_Shell {
    meta:
        description = "Script that downloads and pipes content directly into a shell"
        severity = "low"
    strings:
        $a = /curl\s+[^|\n]{0,200}\|\s*(ba|z)?sh\b/ ascii
        $b = /base64\s+(-d|--decode|-D)\s*\|\s*(ba|z)?sh\b/ ascii
    condition:
        filesize < 1MB and not Bastion_MachO and any of them
}

rule Bastion_Strips_Quarantine_Attribute {
    meta:
        description = "Script/binary that removes com.apple.quarantine (Gatekeeper bypass)"
        severity = "low"
    strings:
        $a = /xattr\s+(-[rcd]+\s+)*(-d\s+)?com\.apple\.quarantine/ ascii
        $b = /xattr\s+-c[r]?\s/ ascii
    condition:
        filesize < 5MB and any of them
}
```

**Severity policy:** the structural rules are signals, not verdicts. Bastion combines them, e.g. `adhoc + user_writable + referenced by LaunchAgent` means alert, and an ad-hoc binary in `~/Developer` alone stays silent. Allowlist paths under Homebrew, Xcode and the user's dev directories. Only XProtect matches, abuse.ch hash hits, `invalid` signatures and EICAR are high-confidence enough to quarantine automatically.

---

## 6. Fast hashing

- **CryptoKit `SHA256`:** hardware-accelerated on Apple silicon, and typically well above 1.5 GB/s per core. In practice disk I/O and per-file syscall overhead dominate. Stream the file in 1–4 MB chunks (`FileHandle.read(upToCount:)`, or `read(2)` into a reusable buffer) with `hasher.update(bufferPointer:)`. Avoid `Data(contentsOf:)` for large files. For files under ~64 MB, `mmap` with `.alwaysMapped` is fine.
- **Alternative:** `CC_SHA256` (CommonCrypto) has similar speed and a C API. CryptoKit is the cleaner choice.
- **Large directories:**
  - Enumerate with `FileManager.enumerator(at:includingPropertiesForKeys: [.isRegularFileKey, .fileSizeKey, .contentModificationDateKey, .fileResourceIdentifierKey], options: [.skipsPackageDescendants?])`. For maximum speed use `fts(3)` or `getattrlistbulk(2)`, which is far faster than per-file `stat` on APFS.
  - Run a bounded `TaskGroup` / `DispatchQueue.concurrentPerform` with about `activeProcessorCount` workers for CPU, fewer on HDD/network volumes.
  - **Cache:** key = (device, inode / `fileResourceIdentifier`, size, mtime, ctime). Value = SHA-256 plus the verdict and rule-pack version. Store in SQLite (WAL). Rescans then touch only changed files, so a home folder rescan drops from minutes to seconds.
  - Skip or deprioritise: dataless iCloud files (don't trigger downloads; check `URLResourceKey.ubiquitousItemDownloadingStatusKey`), `/System` (SSV-sealed), sparse VM images above a size cap, and files with `SF_DATALESS`.
  - Use `F_NOCACHE` (`fcntl`) on bulk scans to avoid evicting the user's page cache.
- **Pipeline per file:** hash, then hash-set lookup (abuse.ch). If no hit and the file type warrants it, run YARA. If it is a Mach-O, run signature checks. Results go to the cache.

---

## 7. Mach-O parsing in Swift

**Do it ourselves, read-only, bounds-checked.** The `<mach-o/loader.h>` / `<mach-o/fat.h>` structs are importable from Swift via `import MachO` (`mach_header_64`, `load_command`, `segment_command_64`, `linkedit_data_command`, `fat_header`, `fat_arch`). Parse from a mapped `Data` / `UnsafeRawBufferPointer`. Validate every offset and size against the file length. Malware deliberately ships malformed headers, so never trust `ncmds` / `sizeofcmds`.

1. **Magic:**
   - `MH_MAGIC_64` (0xfeedfacf) / `MH_MAGIC` means thin.
   - `MH_CIGAM*` means byte-swapped.
   - `FAT_MAGIC` / `FAT_MAGIC_64` (big-endian) means universal: iterate `fat_arch` entries (`cputype` `CPU_TYPE_ARM64` / `CPU_TYPE_X86_64`, offset, size) and parse each slice. Disambiguate from Java `.class` (also 0xcafebabe) with an `nfat_arch` sanity check.
2. **Header:** `filetype` (`MH_EXECUTE`, `MH_DYLIB`, `MH_BUNDLE`, `MH_KEXT_BUNDLE`), `flags` (`MH_PIE`, etc.).
3. **Load commands of interest:**
   - `LC_SEGMENT_64`: names, sizes, and protections. Flag RWX segments and unusual segment names.
   - `LC_LOAD_DYLIB` / `LC_LOAD_WEAK_DYLIB` / `LC_REEXPORT_DYLIB`: linked libraries. Flag dylibs with `@rpath` or `@executable_path` relative paths, which can enable hijacking.
   - `LC_RPATH`.
   - `LC_CODE_SIGNATURE`: a `linkedit_data_command` giving `dataoff` / `datasize` into `__LINKEDIT`.
   - `LC_ENCRYPTION_INFO_64`, `LC_MAIN`, `LC_BUILD_VERSION` (platform, minos, sdk), `LC_UUID`.
4. **Code signature blob** (big-endian, at `dataoff`). It is a `CS_SuperBlob` (magic 0xfade0cc0) with an index of blobs:
   - `CS_CodeDirectory` (0xfade0c02, slot 0): `flags` (`CS_ADHOC` 0x2, `CS_RUNTIME` 0x10000 for hardened runtime, `CS_LINKER_SIGNED` 0x20000), `hashType`, `teamOffset`, which gives the **Team ID**, and `identOffset`, which gives the signing identifier.
   - Requirements (0xfade0c01).
   - Entitlements XML (0xfade7171, slot 5), parsed with `PropertyListSerialization`.
   - DER entitlements (0xfade7172, slot 7).
   - CMS signature (0xfade0b01, slot 0x10000). If it is empty or missing, the binary is ad-hoc.
5. **Classification:**
   - **No `LC_CODE_SIGNATURE`:** unsigned. Rare on arm64, because the kernel refuses to run unsigned arm64 code, so the linker auto-ad-hoc-signs. Unsigned x86_64 slices are more meaningful.
   - **`CS_ADHOC` or `CS_LINKER_SIGNED`, with no CMS blob and no Team ID:** ad-hoc.
   - **Has a CMS blob and a Team ID:** Developer ID or App Store. Confirm with Security.framework.
6. **Authoritative validation (use Security.framework, not our parser):**
   - Call `SecStaticCodeCreateWithPath` and then `SecStaticCodeCheckValidity` with flags `kSecCSCheckAllArchitectures | kSecCSStrictValidate | kSecCSCheckNestedCode` (for bundles).
   - Use `SecCodeCopySigningInformation` with `kSecCSSigningInformation` to read the Team ID, certificate chain, flags, entitlements and `kSecCodeInfoNotarized`-related data, via `SecStaticCodeCheckValidity` against the requirement `notarized` (`SecRequirementCreateWithString("notarized")`).
   - Use `SecRequirementCreateWithString("anchor apple")` to recognise Apple platform binaries.
   - Our own parser is for speed (fast triage without Security.framework cost), for malformed files Security.framework rejects, and for feature extraction (dylibs, entitlements of interest such as `com.apple.security.cs.disable-library-validation`, `com.apple.security.get-task-allow`, and `com.apple.security.cs.allow-dyld-environment-variables`).
7. **Swift packages:** there is no dominant SwiftPM Mach-O library with a compatible licence and active maintenance. Options include `p-x9/MachOKit` (MIT, actively maintained, parses headers, load commands, code signature and fat). It is a reasonable dependency to evaluate. Otherwise write about 600 lines of our own. Recommendation: start with our own minimal parser (header, fat, load commands, CodeDirectory flags, Team ID, entitlements), and evaluate MachOKit if scope grows.

---

## 8. Fuzzy hashing (ssdeep / TLSH)

| | ssdeep (CTPH) | TLSH |
|---|---|---|
| Licence | GPL-2.0 (libfuzzy). Linking it makes the binary GPL, so shell out or reimplement from the paper (the algorithm is not patented). | Apache-2.0 / BSD-3 dual licence. Fine to embed. |
| Availability | `brew install ssdeep` | No Homebrew formula. Vendor the C++ source as a SwiftPM C++ target (SwiftPM builds C++ natively), or port it to Swift (~500 lines). |
| Behaviour | Good for near-identical files. Weak when sizes differ greatly. Comparisons are not a metric. | Distance score (0 = identical; under ~50–100 means similar). Needs at least 50 bytes (256 recommended), plus some variance. Better robustness and indexable. MalwareBazaar publishes TLSH for samples. |
| Use in Bastion | Skip. | Phase 2: compute TLSH for unknown Mach-Os and compare against TLSH values from MalwareBazaar (filtered to macOS tags) to flag variants. |

Fuzzy hashing has a real false-positive cost on shared runtimes. All Go binaries and all Electron apps look alike, so use it only as a scoring input, never as a sole verdict.

---

## 9. Recommendation

**Engine stack:**
1. **Hash layer (always on):**
   - CryptoKit SHA-256, streamed, with an inode/mtime-keyed SQLite cache.
   - Lookup against a local SHA-256 set built from **MalwareBazaar** (filtered by `macos`/`osx`/Mach-O/DMG/pkg tags, plus the full recent feed), and **ThreatFox** hash IOCs.
   - Plus a Bastion-maintained allowlist of known-good hashes (Apple platform binaries are recognised via `anchor apple`, not hashes).
2. **YARA-X (in-process via C API, SwiftPM `.systemLibrary` + pkg-config `yara_x_capi`):**
   - Rules: **XProtect.yara read in place** from `/var/protected/xprotect/XProtect.bundle/Contents/Resources/` (fallback `/Library/Apple/System/Library/CoreServices/XProtect.bundle/...`), compiled per rule with failures skipped, and recompiled on version change. Apple's file is never redistributed.
   - Plus the Bastion generic rule pack (section 5: EICAR plus structural rules, driven by externals), signed with Ed25519.
   - Optionally later, ReversingLabs (MIT) and selected signature-base rules (DRL 1.1, with attribution).
3. **Swift Mach-O analyser plus Security.framework:** classifies files as unsigned, ad-hoc, invalid, Developer ID, notarized or Apple, and extracts Team ID, entitlements and dylibs. This feeds the `sig_state` / `is_user_writable` externals and the scoring.
4. **Scoring layer:**
   - **Quarantine automatically:** hash hit, XProtect match, invalid signature, EICAR.
   - **Alert:** combinations of structural signals plus persistence (from the persistence scanner module).
   - **Log only:** single weak signals.
5. **URL / network intel (separate module):** URLhaus, ThreatFox, Feodo Tracker and the OpenPhish community feed, loaded into local sets. Safe Browsing v5 local list only while Bastion is non-commercial; switch to Web Risk if it ever becomes commercial.
6. **Breach monitoring:** HIBP Pwned Passwords range API (free, k-anonymity) now. Account breach search only with a paid HIBP key, ideally user-supplied.
7. **Optional later:**
   - TLSH similarity against MalwareBazaar TLSH values.
   - A ClamAV `clamd` sidecar (separate process, user opt-in) for archives and Windows malware.
   - VirusTotal lookups using a user-supplied key.

**Pros:**
- **Licences:** BSD-3 core (YARA-X); no GPL in the main binary; Apple rules used without redistribution.
- **macOS coverage:** XProtect is the best-maintained macOS-specific rule set and costs nothing. abuse.ch adds fast-moving hash coverage.
- **Performance:**
  - YARA-X scanners are per-thread with shared compiled rules, and serialised rules give fast startup.
  - Hash caching makes rescans cheap.
  - The memory footprint is tens of MB, versus about 1 GB for clamd.
- **Build:** pure SwiftPM. The Homebrew `yara-x` bottle already ships the C API and pkg-config file, and it can later be vendored as a static lib for distribution.

**Cons / risks:**
- **abuse.ch commercial terms:** free only for not-for-profit use. Bastion must either stay non-commercial or buy a Spamhaus subscription before monetising. Same for Safe Browsing (switch to Web Risk) and the VirusTotal public API.
- **XProtect dependency:**
  - Apple can move, encrypt or restructure the bundle. The path already changed once, to `/var/protected/xprotect`.
  - Bastion's detections then partly duplicate what XProtect already blocks at launch. The value added is on-demand, archive and arbitrary-path scanning plus the scoring and UI.
- **YARA-X compatibility:** some XProtect and community rules may fail to compile. This is handled per rule, but it is a monitoring item: count skipped rules in telemetry/logs.
- **Generic structural rules are noisy:** they need allowlists (Homebrew, Xcode/DerivedData, `~/Developer`, `~/.cargo`, `~/go`, `node_modules`) and combined scoring to stay quiet.
- **No archive unpacking** in YARA-X itself. DMG, pkg and zip extraction must be implemented (`hdiutil attach -readonly -nobrowse`, `pkgutil --expand`, libarchive via `/usr/lib/libarchive.dylib`), or delegated to the optional clamd sidecar.

**First implementation steps:**
1. `CYaraX` system library target and a Swift wrapper, with a unit test compiling the EICAR rule and matching the EICAR string in memory.
2. XProtect loader with per-rule compile and a skip log.
3. Streaming SHA-256 hasher with the SQLite cache.
4. Minimal Mach-O and code-signature classifier, plus Security.framework validation.
5. abuse.ch feed updater (Auth-Key in Keychain, response validation, atomic swap).
