import Foundation

/// hx6: validates what Safari hands the extension handler before it reaches WebVerdictService.
/// The JSON comes from the extension's background script, which relays content-script data that a
/// hostile page shaped. Foundation only, so it can be compiled into a scratch harness and fuzzed.
enum SafariMessageValidator {
    static let maxPayloadBytes = 2 * 1024 * 1024
    static let allowedTypes: Set<String> = ["ping", "checkURL", "checkPage", "checkText", "checkClipboard", "allowHost", "reportDecision", "status", "countTrackers"]
    static let allowedDecisions: Set<String> = ["continued", "wentBack", "dismissedBanner"]

    enum Failure: Error, Equatable { case notAnObject, tooLarge, badType, badField(String) }

    /// Returns a cleaned copy of the payload (unknown keys dropped, strings capped) or a failure.
    static func validate(_ raw: Any?) -> Result<[String: Any], Failure> {
        guard let payload = raw as? [String: Any] else { return .failure(.notAnObject) }
        guard JSONSerialization.isValidJSONObject(payload),
              let data = try? JSONSerialization.data(withJSONObject: payload) else { return .failure(.notAnObject) }
        guard data.count <= maxPayloadBytes else { return .failure(.tooLarge) }
        guard let type = payload["type"] as? String, allowedTypes.contains(type) else { return .failure(.badType) }
        var out: [String: Any] = ["type": type]
        if let id = responseID(payload["id"]) { out["id"] = id }

        if let u = payload["url"] {
            guard let s = u as? String, s.utf8.count <= 8192, isWebURL(s) else { return .failure(.badField("url")) }
            out["url"] = s
        }
        if let t = payload["text"] {
            guard let s = t as? String else { return .failure(.badField("text")) }
            out["text"] = String(s.prefix(20_000))
        }
        if let h = payload["html"] {
            guard let s = h as? String else { return .failure(.badField("html")) }
            out["html"] = String(s.prefix(1_000_000))
        }
        if let h = payload["host"] {
            guard let s = h as? String, isHostname(s) else { return .failure(.badField("host")) }
            out["host"] = s.lowercased()
        }
        if let d = payload["decision"] {
            guard let s = d as? String, allowedDecisions.contains(s) else { return .failure(.badField("decision")) }
            out["decision"] = s
        }
        if let t = payload["tamper"] {
            guard let arr = t as? [Any] else { return .failure(.badField("tamper")) }
            out["tamper"] = arr.prefix(40).compactMap { $0 as? String }.map { String($0.prefix(300)) }
        }
        if let hs = payload["hosts"] {   // wms-o3: countTrackers (was dropped, so Safari never got tracker counts)
            guard let arr = hs as? [Any] else { return .failure(.badField("hosts")) }
            out["hosts"] = arr.prefix(300).compactMap { $0 as? String }.map { $0.lowercased() }.filter { (1...253).contains($0.utf8.count) && $0.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" || $0 == "." } }
        }
        if let sig = payload["signals"] {
            guard let d = sig as? [String: Any] else { return .failure(.badField("signals")) }
            out["signals"] = d    // shape is enforced by PageSignals' Decodable conformance
        }
        switch type {
        case "checkURL", "checkPage": if out["url"] == nil { return .failure(.badField("url")) }
        case "checkText", "checkClipboard": if out["text"] == nil { return .failure(.badField("text")) }
        case "countTrackers": if (out["hosts"] as? [String])?.isEmpty ?? true { return .failure(.badField("hosts")) }
        case "allowHost": if out["host"] == nil { return .failure(.badField("host")) }
        default: break
        }
        return .success(out)
    }

    /// The id echoed back: a short string or a number (as a string). Anything else is dropped, so a
    /// caller can't make the reply carry an arbitrary object.
    static func responseID(_ v: Any?) -> String? {
        if let s = v as? String { return s.utf8.count <= 64 ? s : nil }
        if let n = v as? NSNumber, CFGetTypeID(n) != CFBooleanGetTypeID() { return n.stringValue }
        return nil
    }

    static func isWebURL(_ s: String) -> Bool {
        guard let c = URLComponents(string: s), let scheme = c.scheme?.lowercased(), scheme == "https" || scheme == "http",
              let host = c.host, !host.isEmpty else { return false }
        return true
    }

    /// Plain DNS hostname: ASCII letters, digits, hyphen and dots; at least two labels; no empty label,
    /// no newline (the allowlist file is line-based), no wildcard, at most 253 characters.
    static func isHostname(_ s: String) -> Bool {
        let h = s.lowercased()
        guard (4...253).contains(h.utf8.count), h.contains("."), !h.hasPrefix("."), !h.hasSuffix("."), !h.contains("..") else { return false }
        guard h.unicodeScalars.allSatisfy({ ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "-" || $0 == "." }) else { return false }
        return h.split(separator: ".").allSatisfy { !$0.hasPrefix("-") && !$0.hasSuffix("-") && $0.count <= 63 }
    }
}
