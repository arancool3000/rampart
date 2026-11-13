// Rampart generic rules: EICAR test file and structural traits only. No malware-family strings.
// Family coverage comes from Apple's XProtect rules (read in place) and hash feeds.
// Meta keys used by Rampart: detection (name), category (ThreatCategory raw value), score (0-100 evidence score).
// Externals set per file by YaraEngine: filepath, filename, extension, is_executable, sig_state.

private rule Rampart_MachO_Thin
{
    condition:
        uint32(0) == 0xfeedfacf or uint32(0) == 0xfeedface or uint32(0) == 0xcffaedfe or uint32(0) == 0xcefaedfe
}

private rule Rampart_MachO_Fat
{
    condition:
        (uint32be(0) == 0xcafebabe or uint32be(0) == 0xcafebabf) and uint32be(4) > 0 and uint32be(4) < 20
}

private rule Rampart_MachO
{
    condition:
        Rampart_MachO_Thin or Rampart_MachO_Fat
}

rule Rampart_EICAR_Test_File
{
    meta:
        description = "EICAR anti-malware test file (harmless)"
        detection = "EICAR-Test-File"
        category = "test"
        score = 100
    strings:
        // The 68-byte EICAR string, written as hex so this file is not itself a test file.
        $eicar = { 58 35 4F 21 50 25 40 41 50 5B 34 5C 50 5A 58 35 34 28 50 5E 29 37 43 43 29 37 7D 24
                   45 49 43 41 52 2D 53 54 41 4E 44 41 52 44 2D 41 4E 54 49 56 49 52 55 53 2D 54 45 53 54 2D
                   46 49 4C 45 21 24 48 2B 48 2A }
    condition:
        $eicar at 0 and filesize <= 128
}

rule Rampart_MachO_UPX_Packed
{
    meta:
        description = "Mach-O packed with UPX (packing is uncommon for legitimate macOS software)"
        detection = "Packed-MachO-UPX"
        category = "suspicious"
        score = 40
    strings:
        $xhdr = "__XHDR" ascii
        $upx = "UPX!" ascii
    condition:
        Rampart_MachO and $xhdr in (0 .. 8192) and #upx >= 2
}

rule Rampart_MachO_Fat_Truncated
{
    meta:
        description = "Universal Mach-O whose slice table points past the end of the file (truncated or malformed)"
        detection = "Malformed-Universal-MachO"
        category = "suspicious"
        score = 30
    condition:
        uint32be(0) == 0xcafebabe and uint32be(4) > 0 and uint32be(4) < 8 and
        for any i in (0 .. uint32be(4) - 1) : (
            uint32be(8 + i * 20 + 8) + uint32be(8 + i * 20 + 12) > filesize
        )
}

rule Rampart_MachO_Disguised_As_Document
{
    meta:
        description = "Mach-O executable with a document or media file extension"
        detection = "Disguised-Executable"
        category = "suspicious"
        score = 60
    condition:
        Rampart_MachO and filename matches /\.(pdf|docx?|xlsx?|pptx?|rtf|txt|jpe?g|png|gif|heic|mp3|mp4|mov|csv)$/i
}

rule Rampart_Script_Disguised_As_Document
{
    meta:
        description = "Shell script (#!) with a document or media file extension"
        detection = "Disguised-Script"
        category = "suspicious"
        score = 45
    condition:
        uint16(0) == 0x2123 and filename matches /\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|heic|mp3|mp4|mov)$/i
}

// wms-o10: persistence traits in XML launchd plists (LaunchAgents/LaunchDaemons only; binary plists are covered by
// the persistence scanner, which parses them). No family strings.
rule Rampart_LaunchPlist_Download_Exec
{
    meta:
        description = "Launch agent/daemon whose command pipes a download or a decoded blob into a shell"
        detection = "Persistence-LaunchItem-DownloadExec"
        category = "suspicious"
        score = 70
    strings:
        $args = "<key>ProgramArguments</key>" ascii
        $curl = "curl " ascii
        $wget = "wget " ascii
        $b64a = "base64 -d" ascii
        $b64b = "base64 -D" ascii
        $b64c = "base64 --decode" ascii
        $p1 = "| sh" ascii
        $p2 = "|sh" ascii
        $p3 = "| bash" ascii
        $p4 = "|bash" ascii
        $p5 = "| zsh" ascii
        $p6 = "| /bin/sh" ascii
        $p7 = "| /bin/bash" ascii
        $p8 = "| /bin/zsh" ascii
    condition:
        filesize < 262144 and filepath matches /\/Launch(Agents|Daemons)\/[^\/]+\.plist$/ and $args and any of ($curl, $wget, $b64*) and any of ($p*)
}

rule Rampart_LaunchPlist_DYLD_Insert
{
    meta:
        description = "Launch agent/daemon that injects a dylib with DYLD_INSERT_LIBRARIES"
        detection = "Persistence-LaunchItem-DylibInjection"
        category = "suspicious"
        score = 70
    strings:
        $env = "<key>EnvironmentVariables</key>" ascii
        $dyld = "<key>DYLD_INSERT_LIBRARIES</key>" ascii
    condition:
        filesize < 262144 and filepath matches /\/Launch(Agents|Daemons)\/[^\/]+\.plist$/ and $env and $dyld
}
