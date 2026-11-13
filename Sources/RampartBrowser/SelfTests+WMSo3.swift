import Foundation
import RampartWeb

/// wms-o3: browser attack-surface regressions (fingerprinting, schemes the Download Gate relies on).
extension BrowserSelfTests {
    static func wmsO3() {
        // User agent looks like Safari, and a hostile version string never reaches it.
        check(UserAgentPolicy.applicationName(safariVersion: "18.2") == "Version/18.2 Safari/605.1.15", "wms-o3 UA mirrors installed Safari")
        check(UserAgentPolicy.applicationName(safariVersion: nil) == "Version/18.0 Safari/605.1.15", "wms-o3 UA fallback")
        for bad in ["18.2) evil", "18..2", "", "１８.0", "18.0\nX-Header: 1", String(repeating: "9", count: 40)] {
            check(UserAgentPolicy.applicationName(safariVersion: bad) == "Version/18.0 Safari/605.1.15", "wms-o3 UA rejects \(bad.debugDescription)")
        }
        // Local files and script URLs never load (no file:// access from pages or popups), in any frame.
        let p = URLDecisionPolicy()
        for s in ["file:///Users/x/.ssh/id_rsa", "FILE:///etc/hosts", "blob:https://a.test/1", "data:text/html,<script>1</script>", "javascript:void(0)"] {
            guard let u = URL(string: s) else { continue }
            check(!p.decide(url: u, facts: URLFacts(), isMainFrame: true).isAllowed && !p.decide(url: u, facts: URLFacts(), isMainFrame: false).isAllowed, "wms-o3 \(s.prefix(12)) blocked in every frame")
        }
    }
}
