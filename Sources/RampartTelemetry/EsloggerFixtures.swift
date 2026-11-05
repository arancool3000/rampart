import Foundation

/// Hand-written eslogger JSON lines modelled on eslogger's documented output (schema_version 1,
/// es_message_t field names). Harmless: they describe Apple binaries and `com.rampart.test.*` paths only.
/// Used by the self-test and available to other modules for replay tests.
public enum EsloggerFixtures {
    static func proc(pid: Int, ppid: Int, path: String, signingID: String, team: String?, platform: Bool, euid: Int = 501) -> String {
        let teamJSON = team.map { "\"\($0)\"" } ?? "null"
        return """
        {"audit_token":{"asid":100004,"auid":501,"egid":20,"euid":\(euid),"pid":\(pid),"pidversion":\(pid * 3),"rgid":20,"ruid":\(euid)},\
        "cdhash":"5f1c2a4b9d7e0c3a8b6f4e2d1c0b9a8f7e6d5c4b","codesigning_flags":570522385,"executable":{"path":"\(path)","path_truncated":false,\
        "stat":{"st_atimespec":"2026-11-05T09:00:00.000000000Z","st_blksize":4096,"st_blocks":200,"st_dev":16777234,"st_flags":0,"st_gen":0,\
        "st_gid":0,"st_ino":1152921500312,"st_mode":33261,"st_nlink":1,"st_rdev":0,"st_size":100000,"st_uid":0}},\
        "group_id":\(pid),"is_es_client":false,"is_platform_binary":\(platform),"original_ppid":\(ppid),"ppid":\(ppid),\
        "responsible_audit_token":{"asid":100004,"auid":501,"egid":20,"euid":501,"pid":612,"pidversion":1836,"rgid":20,"ruid":501},\
        "session_id":\(ppid),"signing_id":"\(signingID)","start_time":"2026-11-05T10:00:00.000000Z","team_id":\(teamJSON),\
        "tty":{"path":"/dev/ttys001","path_truncated":false}}
        """
    }

    static func file(_ path: String) -> String {
        "{\"path\":\"\(path)\",\"path_truncated\":false,\"stat\":{\"st_mode\":33188,\"st_size\":12,\"st_uid\":501}}"
    }

    static func envelope(seq: Int, version: Int = 9, schema: Int = 1, eventType: Int, process: String, event: String) -> String {
        "{\"action\":{\"result\":{\"result\":{\"auth\":0},\"result_type\":0}},\"action_type\":1,\"event\":\(event),\"event_type\":\(eventType)," +
        "\"global_seq_num\":\(seq),\"mach_time\":\(900000000 + seq),\"process\":\(process),\"schema_version\":\(schema),\"seq_num\":\(seq)," +
        "\"thread\":{\"thread_id\":\(7000 + seq)},\"time\":\"2026-11-05T10:15:3\(seq % 10).123456789Z\",\"version\":\(version)}"
    }

    public static let zsh = proc(pid: 4242, ppid: 612, path: "/bin/zsh", signingID: "com.apple.zsh", team: nil, platform: true)
    public static let curlPrev = proc(pid: 4243, ppid: 4242, path: "/bin/zsh", signingID: "com.apple.zsh", team: nil, platform: true)
    public static let curl = proc(pid: 4243, ppid: 4242, path: "/usr/bin/curl", signingID: "com.apple.curl", team: nil, platform: true)
    public static let helper = proc(pid: 5150, ppid: 1, path: "/Users/Shared/com.rampart.test.helper", signingID: "com.rampart.test.helper",
                                    team: nil, platform: false)

    /// exec of /usr/bin/curl from zsh with argv.
    public static let exec = envelope(seq: 1, eventType: 9, process: curlPrev, event:
        "{\"exec\":{\"args\":[\"curl\",\"-fsSL\",\"https://example.com/com.rampart.test.txt\",\"-o\",\"/tmp/com.rampart.test.txt\"]," +
        "\"cwd\":\(file("/Users/tester")),\"dyld_exec_path\":\"/usr/bin/curl\",\"env\":[\"PATH=/usr/bin:/bin\"],\"fds\":[]," +
        "\"image_cpusubtype\":-2147483646,\"image_cputype\":16777228,\"last_fd\":2,\"script\":null,\"target\":\(curl)}}")

    /// create of a new file (new_path destination form).
    public static let createNew = envelope(seq: 2, eventType: 13, process: curl, event:
        "{\"create\":{\"acl\":null,\"destination\":{\"new_path\":{\"dir\":\(file("/private/tmp")),\"filename\":\"com.rampart.test.txt\",\"mode\":420}},\"destination_type\":1}}")

    /// close with modified=true.
    public static let closeModified = envelope(seq: 3, eventType: 12, process: curl, event:
        "{\"close\":{\"modified\":true,\"target\":\(file("/private/tmp/com.rampart.test.txt")),\"was_mapped_writable\":false}}")

    /// close with modified=false (dropped by default).
    public static let closeUnmodified = envelope(seq: 4, eventType: 12, process: zsh, event:
        "{\"close\":{\"modified\":false,\"target\":\(file("/etc/zshrc")),\"was_mapped_writable\":false}}")

    /// rename into an existing-dir new path.
    public static let rename = envelope(seq: 5, eventType: 25, process: helper, event:
        "{\"rename\":{\"destination\":{\"new_path\":{\"dir\":\(file("/Users/tester/Library/LaunchAgents")),\"filename\":\"com.rampart.test.agent.plist\"}}," +
        "\"destination_type\":1,\"source\":\(file("/private/tmp/com.rampart.test.agent.plist"))}}")

    /// quarantine xattr removal.
    public static let deleteXattr = envelope(seq: 6, eventType: 47, process: helper, event:
        "{\"deleteextattr\":{\"extattr\":\"com.apple.quarantine\",\"target\":\(file("/Users/Shared/com.rampart.test.helper"))}}")

    /// BTM launch item add (macOS 13+).
    public static let btmAdd = envelope(seq: 7, eventType: 124, process: proc(pid: 380, ppid: 1, path: "/System/Library/PrivateFrameworks/BackgroundTaskManagement.framework/Versions/A/Resources/backgroundtaskmanagementd", signingID: "com.apple.backgroundtaskmanagementd", team: nil, platform: true, euid: 0), event:
        "{\"btm_launch_item_add\":{\"app\":null,\"executable_path\":\"/Users/Shared/com.rampart.test.helper\",\"instigator\":\(helper)," +
        "\"item\":{\"app_url\":null,\"item_type\":3,\"item_url\":\"file:///Users/tester/Library/LaunchAgents/com.rampart.test.agent.plist\",\"legacy\":true,\"managed\":false,\"uid\":501}}}")

    /// XProtect detection (fixture identifier, not a real family).
    public static let xpDetected = envelope(seq: 8, eventType: 128, process: proc(pid: 901, ppid: 1, path: "/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/MacOS/XProtect", signingID: "com.apple.XProtectFramework.XProtect", team: nil, platform: true, euid: 0), event:
        "{\"xp_malware_detected\":{\"detected_path\":\"/Users/Shared/com.rampart.test.helper\",\"incident_identifier\":\"0F3C2A1B-0000-4000-8000-000000000001\"," +
        "\"malware_identifier\":\"com.rampart.test.signature\",\"signature_version\":\"5333\"}}")

    /// A line from a hypothetical future eslogger with schema_version 2 and an unknown event.
    public static let futureSchema = envelope(seq: 9, version: 12, schema: 2, eventType: 999, process: zsh, event:
        "{\"quantum_flux\":{\"target\":\(file("/private/tmp/com.rampart.test.flux"))}}")

    /// Garbage and truncated lines that must not crash the parser.
    public static let malformed: [String] = [
        "", "not json", "{\"schema_version\":1,\"event\":", "[1,2,3]", "{\"schema_version\":1}",
        "{\"schema_version\":1,\"event\":{\"exec\":{\"target\":{}}},\"process\":{}}",
    ]

    public static let all: [String] = [exec, createNew, closeModified, closeUnmodified, rename, deleteXattr, btmAdd, xpDetected, futureSchema]
}
