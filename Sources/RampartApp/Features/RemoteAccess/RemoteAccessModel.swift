import Foundation
import Observation
import RampartShared

// Remote Access screen model. The app depends only on RampartShared, so these types mirror the JSON shape of
// RampartGuard.RemoteAccessReport / RemoteToolFinding / SharingServiceState / RemoteAllowance one-to-one
// (same field names). Once the lead adds the IPC cases listed in RemoteAccessBridge, `fetch` decodes real data.

struct RemoteToolFindingDTO: Codable, Hashable, Identifiable {
    var id: String { toolID }
    var toolID: String
    var name: String
    var isAppleService: Bool
    var pids: [Int32]
    var paths: [String]
    var launchItems: [String]
    var listeningPorts: [Int]
    var inboundSessions: Int
    var matchedBy: [String]
    var serviceEnabled: Bool?
    var allowed: Bool
    var allowedUntil: Date?
    var scamContext: Bool
    var scamReason: String
    var severity: Severity
    var active: Bool { !pids.isEmpty || !listeningPorts.isEmpty || serviceEnabled == true || inboundSessions > 0 }
}

struct SharingServiceStateDTO: Codable, Hashable {
    var screenSharing: Bool?
    var remoteManagement: Bool?
    var remoteLogin: Bool?
    var remoteAppleEvents: Bool?
}

struct ListeningPortDTO: Codable, Hashable {
    var port: Int; var proto: String; var pid: Int32?; var process: String
}

struct RemoteAccessReportDTO: Codable, Hashable {
    var generatedAt: Date
    var lockdownEnabled: Bool
    var findings: [RemoteToolFindingDTO]
    var sharing: SharingServiceStateDTO
    var inbound: [ConnectionInfo]
    var unknownListeners: [ListeningPortDTO]
    var blockedPorts: [Int]
    var note: String
    var activeUnapproved: [RemoteToolFindingDTO] { findings.filter { $0.active && !$0.allowed } }
}

/// IPC needed from the lead (RampartShared.IPCRequest / IPCResponse):
///   case remoteAccessReport                              -> .remoteAccess(Data)   // JSON of RampartGuard.RemoteAccessReport
///   case allowRemoteTool(id: String, minutes: Int?)      -> .remoteAccess(Data)   // privileged (admin peer)
///   case revokeRemoteTool(id: String)                    -> .remoteAccess(Data)   // privileged
///   case setRemoteLockdown(on: Bool)                     -> .remoteAccess(Data)   // privileged
/// Carrying the report as `Data` keeps RampartShared free of Guard types; the DTOs above decode it.
enum RemoteAccessBridge {
    enum Outcome { case report(RemoteAccessReportDTO), unsupported, error(String) }

    static func decode(_ data: Data) -> Outcome {
        do { return .report(try JSONDecoder.rampart.decode(RemoteAccessReportDTO.self, from: data)) }
        catch { return .error("Could not read the remote-access report: \(error.localizedDescription)") }
    }

    static func fetch(client: DaemonClient) async -> Outcome {
        // Switch-over point once the IPC case exists:
        //   if case .remoteAccess(let data)? = try? await client.request(.remoteAccessReport) { return decode(data) }
        return .unsupported
    }
    static func allow(client: DaemonClient, toolID: String, minutes: Int?) async -> Outcome {
        //   if case .remoteAccess(let data)? = try? await client.request(.allowRemoteTool(id: toolID, minutes: minutes)) { return decode(data) }
        return .unsupported
    }
    static func revoke(client: DaemonClient, toolID: String) async -> Outcome {
        //   if case .remoteAccess(let data)? = try? await client.request(.revokeRemoteTool(id: toolID)) { return decode(data) }
        return .unsupported
    }
    static func setLockdown(client: DaemonClient, on: Bool) async -> Outcome {
        //   if case .remoteAccess(let data)? = try? await client.request(.setRemoteLockdown(on: on)) { return decode(data) }
        return .unsupported
    }
}

@MainActor
@Observable
final class RemoteAccessScreenModel {
    var report: RemoteAccessReportDTO?
    var loading = false
    var unsupported = false
    var error: String?
    var busyTool: String?

    private func apply(_ o: RemoteAccessBridge.Outcome) {
        switch o {
        case .report(let r): report = r; unsupported = false; error = nil
        case .unsupported: unsupported = true
        case .error(let e): error = e
        }
    }

    func refresh(client: DaemonClient) async {
        loading = true; defer { loading = false }
        apply(await RemoteAccessBridge.fetch(client: client))
    }
    func allow(_ f: RemoteToolFindingDTO, minutes: Int?, client: DaemonClient) async {
        busyTool = f.toolID; defer { busyTool = nil }
        apply(await RemoteAccessBridge.allow(client: client, toolID: f.toolID, minutes: minutes))
    }
    func revoke(_ f: RemoteToolFindingDTO, client: DaemonClient) async {
        busyTool = f.toolID; defer { busyTool = nil }
        apply(await RemoteAccessBridge.revoke(client: client, toolID: f.toolID))
    }
    func setLockdown(_ on: Bool, client: DaemonClient) async {
        apply(await RemoteAccessBridge.setLockdown(client: client, on: on))
    }
}

/// Copy shared with RampartGuard.TamperCopy / ProtectionDisableFlow.honestLimitCopy (kept in sync by hand; the app
/// cannot import RampartGuard).
enum RemoteAccessCopy {
    static let headline = "Remote access is blocked until you allow it"
    static let body = "Screen Sharing, Remote Login, Remote Management and remote-control apps like TeamViewer or AnyDesk stay off " +
        "unless you approve them here. Approvals can be for one hour, so a one-off support session doesn't leave a door open."
    static let scam = "Tech-support scammers ask you to install a remote-control app while you're on their web page. " +
        "\(Product.name) treats a remote tool that starts while a browser is in front, or just after a scam page, as critical."
    static let limit = "How far this goes: \(Product.name) stops unapproved tools after they start, disables their launch items and " +
        "drops inbound connections on their ports with the macOS firewall. Without Apple's Endpoint Security entitlement it cannot " +
        "prevent a launch before it happens, and a person with your administrator password can always re-enable sharing in System Settings."
    static let tamper = "Scripts and malware running as your user can't turn \(Product.name) off: protection can only be paused or removed " +
        "with your administrator password through \(Product.name) itself. Attempts to stop, unload, delete or edit it, even by admin-level " +
        "scripts, are detected, undone from sealed backups, and reported to you. No antivirus can stop a person who deliberately restarts " +
        "into Recovery Mode and removes it."
}
