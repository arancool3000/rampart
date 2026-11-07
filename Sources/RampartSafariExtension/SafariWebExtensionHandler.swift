import Foundation
import SafariServices
import RampartShared
import RampartWeb

// Principal class of RamPartSafari.appex (NSExtensionPrincipalClass in its Info.plist).
// Safari delivers `browser.runtime.sendNativeMessage(...)` calls here as NSExtensionItems whose
// userInfo[SFExtensionMessageKey] is the JSON object the extension sent. We answer with the same
// NMRequest/NMResponse contract rampart-nmh uses, via WebVerdictService (local engine + rampartd).
@objc(SafariWebExtensionHandler)
final class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    private static let service = WebVerdictService(bridge: IPCDaemonBridge())

    func beginRequest(with context: NSExtensionContext) {
        let item = context.inputItems.first as? NSExtensionItem
        let payload = (item?.userInfo?[SFExtensionMessageKey] as? [String: Any]) ?? [:]   // validated in respond(to:)
        let response = SafariWebExtensionHandler.respond(to: payload)
        let out = NSExtensionItem()
        out.userInfo = [SFExtensionMessageKey: response]
        context.completeRequest(returningItems: [out], completionHandler: nil)
    }

    /// Pure helper so the mapping can be exercised without Safari.
    static func respond(to payload: [String: Any]) -> [String: Any] {
        // hx6: validate and clean before decoding. Size cap, type whitelist, http(s)-only URLs, hostname-only
        // allowHost (no newline, no wildcard, never a bare public suffix like "co.uk" or "github.io", which
        // the suffix-matching allowlist would otherwise turn into "trust every site under it"), and the id
        // echoed back only when it is a short string or a number.
        let echoID: Any = SafariMessageValidator.responseID(payload["id"]) ?? NSNull()
        let clean: [String: Any]
        switch SafariMessageValidator.validate(payload) {
        case .success(let c): clean = c
        case .failure: return ["ok": false, "error": "bad request", "id": echoID]
        }
        if let host = clean["host"] as? String {
            guard let split = PublicSuffix.split(host), host != split.suffix else {
                return ["ok": false, "error": "bad request", "id": echoID]
            }
        }
        guard let data = try? JSONSerialization.data(withJSONObject: clean),
              let req = try? JSONDecoder().decode(NMRequest.self, from: data) else {
            return ["ok": false, "error": "bad request", "id": echoID]
        }
        let resp = service.handle(req)
        guard let enc = try? JSONEncoder().encode(resp), let obj = try? JSONSerialization.jsonObject(with: enc) as? [String: Any] else {
            return ["ok": false, "error": "encode failed", "id": req.id ?? NSNull()]
        }
        return obj
    }
}
