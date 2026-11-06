import Foundation
import WebKit

/// Curated tracker / malvertising / crypto-miner hosts compiled into a WKContentRuleList. Short on
/// purpose: these are the networks that follow people between shops and banks, plus script hosts
/// seen in ClickFix and drainer kits. The daemon's DNS filter (when on) covers the long tail.
enum ContentRules {
    static let identifier = "rampart-secure-browser-v1"

    static let trackerHosts: [String] = [
        // Ad / analytics networks
        "doubleclick.net", "googlesyndication.com", "googleadservices.com", "google-analytics.com", "googletagmanager.com", "googletagservices.com",
        "adnxs.com", "adsrvr.org", "rubiconproject.com", "pubmatic.com", "openx.net", "criteo.com", "criteo.net", "taboola.com", "outbrain.com",
        "scorecardresearch.com", "quantserve.com", "moatads.com", "amazon-adsystem.com", "casalemedia.com", "bluekai.com", "demdex.net",
        "everesttech.net", "mathtag.com", "yieldmo.com", "sharethrough.com", "33across.com", "bidswitch.net", "smartadserver.com", "teads.tv",
        "connect.facebook.net", "pixel.facebook.com", "ads.linkedin.com", "snap.licdn.com", "analytics.tiktok.com", "ads.tiktok.com",
        "bat.bing.com", "clarity.ms", "hotjar.com", "mouseflow.com", "fullstory.com", "luckyorange.com", "crazyegg.com", "inspectlet.com",
        "mixpanel.com", "segment.io", "segment.com", "amplitude.com", "heapanalytics.com", "kissmetrics.com", "chartbeat.com", "parsely.com",
        "newrelic.com", "nr-data.net", "bugsnag.com", "optimizely.com", "branch.io", "adjust.com", "appsflyer.com", "braze.com",
        "cxense.com", "exelator.com", "eyeota.net", "tapad.com", "rlcdn.com", "liadm.com", "id5-sync.com", "agkn.com", "crwdcntrl.net", "krxd.net",
        "adform.net", "adroll.com", "zemanta.com", "revcontent.com", "mgid.com", "popads.net", "propellerads.com", "adsterra.com", "exoclick.com",
        "trafficjunky.net", "juicyads.com", "hilltopads.net", "clickadu.com", "adcash.com", "a-ads.com",
        // Crypto-miner script hosts
        "coinhive.com", "coin-hive.com", "crypto-loot.com", "cryptoloot.pro", "webminepool.com", "minero.cc", "coinimp.com", "jsecoin.com", "webmine.cz",
        "monerominer.rocks", "cryptonoter.com", "authedmine.com", "2giga.link", "ppoi.org", "coinblind.com", "cloudcoins.co",
        // Fake-update / scareware / clickfix kit hosts seen in public reports
        "ssl-prod.me", "browser-update.cc", "pushwelcome.com", "pushnotification.ro", "fastclick.net", "notix.co", "sendpulse.com", "onesignal-push.com",
    ]

    /// Resources we never want from third parties in a banking session: fonts and media are fine, but
    /// third-party scripts that fingerprint are not worth it. Kept to known fingerprinters.
    static let fingerprintHosts: [String] = [
        "fingerprintjs.com", "fpjs.io", "fingerprint.com", "seon.io", "sift.com", "siftscience.com", "threatmetrix.com", "online-metrix.net",
        "iovation.com", "iesnare.com", "forter.com", "signifyd.com", "perimeterx.net", "px-cloud.net", "datadome.co", "imperva.com", "distilnetworks.com",
    ]

    /// WKContentRuleList JSON. `if-domain` is not used so a tracker is blocked on every site; `load-type`
    /// third-party keeps first-party analytics on a shop working (they would see the visit anyway).
    static func json(trackers: [String] = trackerHosts, fingerprinters: [String] = fingerprintHosts, blockFingerprinters: Bool = true) -> String {
        var rules: [[String: Any]] = []
        func block(_ host: String, resourceTypes: [String]? = nil) {
            var trigger: [String: Any] = ["url-filter": "^https?://([a-z0-9-]+\\.)*" + NSRegularExpression.escapedPattern(for: host) + "[/:]?", "load-type": ["third-party"]]
            if let r = resourceTypes { trigger["resource-type"] = r }
            rules.append(["trigger": trigger, "action": ["type": "block"]])
        }
        for h in trackers { block(h) }
        if blockFingerprinters { for h in fingerprinters { block(h, resourceTypes: ["script", "raw", "fetch"]) } }
        // Strip third-party cookies at the rule level too (belt and braces with the data store policy).
        rules.append(["trigger": ["url-filter": ".*", "load-type": ["third-party"]], "action": ["type": "block-cookies"]])
        // Upgrade stray http subresources on https pages.
        rules.append(["trigger": ["url-filter": "^http://.*", "resource-type": ["image", "style-sheet", "script", "font", "media", "fetch", "raw"]],
                      "action": ["type": "make-https"]])
        let data = try! JSONSerialization.data(withJSONObject: rules, options: [])
        return String(decoding: data, as: UTF8.self)
    }

    static var ruleCount: Int { trackerHosts.count + fingerprintHosts.count + 2 }

    /// Compiles (or fetches the cached) rule list. Never throws into the UI: on failure the browser
    /// still works, just without tracker blocking, and says so in the shield menu.
    static func compile() async -> WKContentRuleList? {
        guard let store = WKContentRuleListStore.default() else { return nil }
        return await withCheckedContinuation { cont in
            store.compileContentRuleList(forIdentifier: identifier, encodedContentRuleList: json()) { list, error in
                if let error { NSLog("RamPart Browser: content rules failed: \(error.localizedDescription)") }
                cont.resume(returning: list)
            }
        }
    }
}
