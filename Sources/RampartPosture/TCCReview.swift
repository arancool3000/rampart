import Foundation
import SQLite3

/// One row of the TCC `access` table.
public struct TCCGrant: Codable, Hashable, Sendable {
    public enum Database: String, Codable, Sendable { case user, system }
    public var database: Database
    public var service: String          // e.g. kTCCServiceScreenCapture
    public var client: String           // bundle ID (client_type 0) or absolute path (1)
    public var clientType: Int
    public var authValue: Int           // 0 denied, 1 unknown, 2 allowed, 3 limited
    public var authReason: Int?
    public var lastModified: Date?
    public var allowed: Bool { authValue == 2 || authValue == 3 }
    public var isSensitive: Bool { TCCReview.sensitiveServices[service] != nil }
    public var serviceName: String { TCCReview.friendlyName(service) }
    public init(database: Database, service: String, client: String, clientType: Int, authValue: Int,
                authReason: Int? = nil, lastModified: Date? = nil) {
        self.database = database; self.service = service; self.client = client; self.clientType = clientType
        self.authValue = authValue; self.authReason = authReason; self.lastModified = lastModified
    }
}

/// A grant worth showing the user, with the reason.
public struct TCCFinding: Codable, Hashable, Sendable {
    public var grant: TCCGrant
    public var reason: String
}

public struct TCCReviewResult: Codable, Sendable {
    public enum Status: String, Codable, Sendable { case ok, needsFullDiskAccess, notFound, error }
    public var status: Status
    public var userDB: Status
    public var systemDB: Status
    public var grants: [TCCGrant]
    public var findings: [TCCFinding]
    public var message: String
}

/// Read-only review of TCC grants. Never writes TCC.db (it's SIP-protected anyway); revoking is done
/// by deep-linking to System Settings > Privacy & Security.
public enum TCCReview {
    public static let systemDBPath = "/Library/Application Support/com.apple.TCC/TCC.db"
    public static func userDBPath(home: String) -> String { home + "/Library/Application Support/com.apple.TCC/TCC.db" }

    public static let sensitiveServices: [String: String] = [
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceListenEvent": "Input Monitoring",
        "kTCCServicePostEvent": "Keyboard/mouse control",
        "kTCCServiceDeveloperTool": "Developer Tools",
        "kTCCServiceEndpointSecurityClient": "Endpoint Security",
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceSystemPolicyAppBundles": "App Management",
    ]

    public static func friendlyName(_ service: String) -> String {
        if let n = sensitiveServices[service] { return n }
        return service.hasPrefix("kTCCService") ? String(service.dropFirst("kTCCService".count)) : service
    }

    /// Services where any grant to an app that no longer exists, or to a loose binary in a temp/download folder,
    /// deserves a look. Pure: the existence check is injected.
    public static let highRiskServices: Set<String> = ["kTCCServiceAccessibility", "kTCCServiceScreenCapture",
        "kTCCServiceSystemPolicyAllFiles", "kTCCServiceListenEvent", "kTCCServicePostEvent",
        "kTCCServiceDeveloperTool", "kTCCServiceEndpointSecurityClient"]

    public static func classify(_ grants: [TCCGrant], pathExists: (String) -> Bool) -> [TCCFinding] {
        var out: [TCCFinding] = []
        for g in grants where g.allowed && highRiskServices.contains(g.service) {
            if g.clientType == 1 {
                let p = g.client
                if !pathExists(p) {
                    out.append(TCCFinding(grant: g, reason: "\(g.serviceName) is granted to \(p), which no longer exists."))
                } else if p.hasPrefix("/tmp/") || p.hasPrefix("/private/tmp/") || p.hasPrefix("/private/var/folders/")
                            || p.contains("/Downloads/") || p.contains("/.Trash/") || p.hasPrefix("/Users/Shared/") {
                    out.append(TCCFinding(grant: g, reason: "\(g.serviceName) is granted to a program in an unusual place: \(p)."))
                }
            }
        }
        return out
    }

    public enum OpenResult { case ok(OpaquePointer), needsFDA, notFound, error(String) }

    static func openReadOnly(_ path: String) -> OpenResult {
        let fd = open(path, O_RDONLY)
        if fd < 0 {
            let e = errno
            if e == ENOENT {
                // Without FDA the parent folder may also be hidden; treat "missing" as unknown permission for the user DB.
                return .notFound
            }
            return (e == EPERM || e == EACCES) ? .needsFDA : .error(String(cString: strerror(e)))
        }
        close(fd)
        var db: OpaquePointer?
        if sqlite3_open_v2(path, &db, SQLITE_OPEN_READONLY, nil) != SQLITE_OK {
            let msg = db.map { String(cString: sqlite3_errmsg($0)) } ?? "open failed"
            sqlite3_close(db)
            return msg.lowercased().contains("authoriz") ? .needsFDA : .error(msg)
        }
        return .ok(db!)
    }

    /// Reads the `access` table; probes columns because the schema varies across macOS versions.
    public static func readGrants(dbPath: String, database: TCCGrant.Database) -> (TCCReviewResult.Status, [TCCGrant], String?) {
        switch openReadOnly(dbPath) {
        case .needsFDA: return (.needsFullDiskAccess, [], nil)
        case .notFound: return (.notFound, [], nil)
        case .error(let m): return (.error, [], m)
        case .ok(let db):
            defer { sqlite3_close(db) }
            var cols = Set<String>()
            var st: OpaquePointer?
            if sqlite3_prepare_v2(db, "PRAGMA table_info(access)", -1, &st, nil) == SQLITE_OK {
                while sqlite3_step(st) == SQLITE_ROW { if let c = sqlite3_column_text(st, 1) { cols.insert(String(cString: c)) } }
            }
            sqlite3_finalize(st)
            if cols.isEmpty {
                let msg = String(cString: sqlite3_errmsg(db))
                return (msg.lowercased().contains("authoriz") ? .needsFullDiskAccess : .error, [], msg)
            }
            guard cols.contains("service"), cols.contains("client") else { return (.error, [], "unexpected TCC schema") }
            func col(_ name: String, _ fallback: String) -> String { cols.contains(name) ? name : fallback }
            // Old schema (pre-11) had `allowed` instead of `auth_value`.
            let authExpr = cols.contains("auth_value") ? "auth_value" : (cols.contains("allowed") ? "allowed*2" : "1")
            let sql = "SELECT service, client, \(col("client_type", "0")), \(authExpr), \(col("auth_reason", "NULL")), \(col("last_modified", "NULL")) FROM access"
            var rows: [TCCGrant] = []
            st = nil
            guard sqlite3_prepare_v2(db, sql, -1, &st, nil) == SQLITE_OK else {
                return (.error, [], String(cString: sqlite3_errmsg(db)))
            }
            defer { sqlite3_finalize(st) }
            while sqlite3_step(st) == SQLITE_ROW {
                let service = sqlite3_column_text(st, 0).map { String(cString: $0) } ?? ""
                let client = sqlite3_column_text(st, 1).map { String(cString: $0) } ?? ""
                let reason: Int? = sqlite3_column_type(st, 4) == SQLITE_NULL ? nil : Int(sqlite3_column_int64(st, 4))
                let mod: Date? = sqlite3_column_type(st, 5) == SQLITE_NULL ? nil
                    : Date(timeIntervalSince1970: TimeInterval(sqlite3_column_int64(st, 5)))
                rows.append(TCCGrant(database: database, service: service, client: client,
                                     clientType: Int(sqlite3_column_int64(st, 2)), authValue: Int(sqlite3_column_int64(st, 3)),
                                     authReason: reason, lastModified: mod))
            }
            return (.ok, rows, nil)
        }
    }

    /// Reviews the user and system TCC databases. Without Full Disk Access the result is `needsFullDiskAccess`.
    public static func review(home: String = FileManager.default.homeDirectoryForCurrentUser.path,
                              userDB: String? = nil, systemDB: String? = nil,
                              pathExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }) -> TCCReviewResult {
        let (us, ug, ue) = readGrants(dbPath: userDB ?? userDBPath(home: home), database: .user)
        let (ss, sg, se) = readGrants(dbPath: systemDB ?? systemDBPath, database: .system)
        let grants = ug + sg
        let findings = classify(grants, pathExists: pathExists)
        // The user DB always exists once the user has used the Mac, so "not found" for it without FDA means hidden.
        let anyOK = us == .ok || ss == .ok
        let status: TCCReviewResult.Status
        if anyOK { status = .ok }
        else if us == .needsFullDiskAccess || ss == .needsFullDiskAccess || (us == .notFound && !FullDiskAccess.isGranted(home: home)) {
            status = .needsFullDiskAccess
        } else if us == .notFound && ss == .notFound { status = .notFound }
        else { status = .error }
        let message: String
        switch status {
        case .ok:
            let sens = grants.filter { $0.allowed && $0.isSensitive }.count
            message = findings.isEmpty ? "\(sens) sensitive permission\(sens == 1 ? "" : "s") granted; nothing unusual."
                                       : "\(findings.count) permission\(findings.count == 1 ? "" : "s") to review."
        case .needsFullDiskAccess: message = "Needs Full Disk Access to review app permissions."
        case .notFound: message = "No permission database found."
        case .error: message = "Couldn't read app permissions: \(ue ?? se ?? "unknown error")."
        }
        return TCCReviewResult(status: status, userDB: us, systemDB: ss, grants: grants, findings: findings, message: message)
    }
}
