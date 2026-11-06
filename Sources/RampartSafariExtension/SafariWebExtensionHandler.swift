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
        let payload = (item?.userInfo?[SFExtensionMessageKey] as? [String: Any]) ?? [:]
        let response = SafariWebExtensionHandler.respond(to: payload)
        let out = NSExtensionItem()
        out.userInfo = [SFExtensionMessageKey: response]
        context.completeRequest(returningItems: [out], completionHandler: nil)
    }

    /// Pure helper so the mapping can be exercised without Safari.
    static func respond(to payload: [String: Any]) -> [String: Any] {
        guard let data = try? JSONSerialization.data(withJSONObject: payload),
              let req = try? JSONDecoder().decode(NMRequest.self, from: data) else {
            return ["ok": false, "error": "bad request", "id": payload["id"] ?? NSNull()]
        }
        let resp = service.handle(req)
        guard let enc = try? JSONEncoder().encode(resp), let obj = try? JSONSerialization.jsonObject(with: enc) as? [String: Any] else {
            return ["ok": false, "error": "encode failed", "id": req.id ?? NSNull()]
        }
        return obj
    }
}
