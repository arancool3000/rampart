import Foundation

// Protection Activity presentation: turns any ActivityEntry (new structured ones and older free-text ones) into a
// plain-English title, subtitle and full explanation. Pure and shared, so rampart-selftest can check that every
// ActivityEvent has a human mapping and that no raw internal strings ("fileTamper", "likelyScam (93)", "off",
// "needs review") reach the screen.

public enum ActivityCategory: String, CaseIterable, Identifiable, Sendable {
    case threats, web, scans, protection, network, settings, updates, privacy, maintenance
    public var id: String { rawValue }
    public var title: String {
        switch self {
        case .threats: return "Threats"; case .web: return "Web & scam blocks"; case .scans: return "Scans"
        case .protection: return "Protection"; case .network: return "Network & Wi-Fi"; case .settings: return "Settings changes"
        case .updates: return "Updates"; case .privacy: return "Passwords & codes"; case .maintenance: return "Clean-ups"
        }
    }
    public var symbol: String {
        switch self {
        case .threats: return "ladybug"; case .web: return "hand.raised"; case .scans: return "magnifyingglass"
        case .protection: return "shield.lefthalf.filled"; case .network: return "wifi"; case .settings: return "gearshape"
        case .updates: return "arrow.triangle.2.circlepath"; case .privacy: return "key"; case .maintenance: return "sparkles"
        }
    }
}

public enum ActivityTone: String, Sendable { case good, info, attention, danger, neutral }

public struct ActivityFact: Hashable, Sendable {
    public var label: String
    public var value: String
    /// Monospaced, selectable (paths, hashes, ids).
    public var mono: Bool
    public init(_ label: String, _ value: String, mono: Bool = false) { self.label = label; self.value = value; self.mono = mono }
}

public struct ActivityPresentation: Hashable, Sendable {
    public var event: ActivityEvent
    public var category: ActivityCategory
    public var tone: ActivityTone
    public var symbol: String
    public var title: String
    public var subtitle: String
    /// Short human outcome ("Blocked", "Needs your review").
    public var status: String
    public var whatHappened: String
    public var why: String?
    public var whatWeDid: String
    public var whatYouCanDo: String
    public var facts: [ActivityFact]
    /// Same key + close in time = one burst row.
    public var groupKey: String
    /// Plural noun for a burst ("tamper attempts").
    public var burstNoun: String
}

public enum ActivityPresenter {

    // MARK: event inference

    /// The decision type. Entries written before `event` existed are inferred from kind and wording.
    public static func event(for e: ActivityEntry) -> ActivityEvent {
        if let ev = e.event { return ev }
        let t = e.title.lowercased(), o = e.outcome.lowercased(), d = e.detail.lowercased()
        switch e.kind {
        case .scan:
            if t.contains("cancel") || t.contains("stopped") { return .scanCancelled }
            if t.contains("fail") || t.contains("error") { return .scanFailed }
            if t.contains("paused") { return .scanPaused }
            if t.contains("resumed") { return .scanResumed }
            if t.contains("started") { return .scanStarted }
            return .scanFinished
        case .detection:
            if isTamperName(e.title) { return .tamper }
            if isRemoteName(e.title) { return .remoteAccessAttempt }
            if t.hasPrefix("pasteguard") || t.contains("pasted command") || t.contains("clipboard") { return .pasteGuardWarned }
            return .detection
        case .quarantine:
            if t.hasPrefix("exported") { return .exported }
            if t.hasPrefix("sandbox run") { return .sandboxRun }
            if t.hasPrefix("deleted") { return .deleted }
            if o.contains("fail") { return .quarantineFailed }
            return .quarantined
        case .restore: return .restored
        case .persistence:
            if t.hasPrefix("could not remove") { return .startupItemRemoveFailed }
            if t.hasPrefix("removed ") || t.hasPrefix("turned off") { return .startupItemRemoved }
            if t.contains("removed") { return .persistenceRemoved }
            return .persistenceAdded
        case .webBlock:
            if d.hasPrefix("listed in") || (t.hasPrefix("blocked ") && o == "blocked") { return .dnsBlocked }
            let (verdict, score) = parseVerdict(e.outcome)
            if verdict == "likelyscam" || (score ?? 0) >= 60 { return .scamBlocked }
            if verdict != nil || t.hasPrefix("web warning") { return .webWarning }
            return .webBlocked
        case .posture: return t.hasPrefix("could not") || o.contains("fail") ? .postureFixFailed : .postureFixed
        case .update: return o.contains("retry") || o.contains("fail") || t.contains("partly") ? .definitionsFailed : .definitionsUpdated
        case .settings:
            if t.hasPrefix("allowed remote tool") { return .remoteAccessAllowed }
            if t.hasPrefix("revoked remote tool") { return .remoteAccessRevoked }
            if t.hasPrefix("remote-access lockdown") { return .remoteLockdownChanged }
            if t.hasPrefix("administrator confirmed") { return .adminSession }
            if t.hasPrefix("protect everything") { return .protectEverything }
            if t.hasPrefix("web protection") || t.hasPrefix("real-time protection") {
                return t.contains("paused") ? .protectionPaused : .protectionToggled
            }
            if t.hasPrefix("protection paused") { return .protectionPaused }
            if t.hasPrefix("protection resumed") { return .protectionResumed }
            if t.hasPrefix("allowed ") || o == "allow rule added" || o == "rule added" { return .allowRuleAdded }
            if t.hasPrefix("removed an allow rule") || t.hasPrefix("removed rule") { return .allowRuleRemoved }
            if t.hasPrefix("restored") { return .restored }
            if t.hasPrefix("fixed") { return .postureFixed }
            return .settingsChanged
        case .system:
            if t.hasPrefix("emergency lockdown lifted") { return .lockdownLifted }
            if t.hasPrefix("emergency lockdown") { return .lockdownStarted }
            if t.hasSuffix("protection started") { return .serviceStarted }
            if t.hasSuffix("protection stopped") { return .serviceStopped }
            if t.hasPrefix("resolved") { return .alertsResolved }
            if t.hasPrefix("uninstall") { return .uninstall }
            return .other
        case .tamper: return .tamper
        case .realtime: return .realtimeBlock
        case .remoteAccess: return .remoteAccessAttempt
        case .pasteGuard: return .pasteGuardWarned
        case .lockdown: return .lockdownStarted
        case .wifi: return .wifiWarning
        case .vault: return .vaultEvent
        case .refresh: return .refreshCleanup
        case .networkScan: return .networkScan
        }
    }

    static func isTamperName(_ s: String) -> Bool { s.hasPrefix("Tampering with ") || s.hasPrefix("Self-defence:") }
    static func isRemoteName(_ s: String) -> Bool {
        s.hasPrefix("Unapproved remote access") || s.contains("remote-access port") || s.contains("accepting outside connections")
    }

    /// The category an event belongs to (filter menu, icon).
    public static func category(_ ev: ActivityEvent) -> ActivityCategory {
        switch ev {
        case .scanStarted, .scanFinished, .scanCancelled, .scanFailed, .scanPaused, .scanResumed: return .scans
        case .detection, .quarantined, .quarantineFailed, .restored, .deleted, .exported, .sandboxRun, .alertsResolved,
             .realtimeBlock, .processStopped, .tamper, .pasteGuardBlocked, .pasteGuardWarned, .persistenceAdded,
             .persistenceRemoved, .startupItemRemoved, .startupItemRemoveFailed: return .threats
        case .webBlocked, .dnsBlocked, .scamBlocked, .webWarning: return .web
        case .remoteAccessAttempt, .remoteAccessAllowed, .remoteAccessRevoked, .remoteLockdownChanged,
             .wifiWarning, .wifiDisconnected, .wifiStayedConnected, .wifiTrustChanged, .networkScan: return .network
        case .lockdownStarted, .lockdownLifted, .serviceStarted, .serviceStopped, .uninstall, .protectEverything: return .protection
        case .settingsChanged, .protectionToggled, .protectionPaused, .protectionResumed, .allowRuleAdded, .allowRuleRemoved,
             .adminSession, .postureFixed, .postureFixFailed: return .settings
        case .definitionsUpdated, .definitionsFailed: return .updates
        case .vaultEvent, .authenticatorEvent: return .privacy
        case .refreshCleanup, .refreshUndo: return .maintenance
        case .other: return .protection
        }
    }

    // MARK: presentation

    public static func present(_ e: ActivityEntry) -> ActivityPresentation {
        let ev = event(for: e)
        var p = ActivityPresentation(event: ev, category: category(ev), tone: .neutral, symbol: category(ev).symbol,
                                     title: "", subtitle: "", status: humanOutcome(e.outcome), whatHappened: "", why: nil,
                                     whatWeDid: "", whatYouCanDo: "No action is needed.", facts: [],
                                     groupKey: ev.rawValue + "|" + (e.rule ?? ""), burstNoun: "similar events")
        let target = targetOf(e)
        let file = target.flatMap { $0.hasPrefix("/") || $0.hasPrefix("~") ? $0 : nil }
        let fileName = file.map { ($0 as NSString).lastPathComponent }
        let host = target.flatMap(hostOf)
        let proc = processLine(e.process)
        let who = actorPhrase(e.actor)
        let reason = e.reason.flatMap { $0.isEmpty ? nil : $0 }
        let scoreText = e.score.map { "\($0) out of 100" }

        switch ev {
        // scans
        case .scanStarted:
            p.tone = .info; p.symbol = "magnifyingglass"
            p.title = (e.facts?["scanType"].map { "\($0) started" }) ?? (e.title.isEmpty ? "Scan started" : cleanTitle(e.title))
            p.subtitle = who.map { "Started \($0)" } ?? (e.detail.isEmpty ? "Checking your files" : "Checking \(shortList(e.detail))")
            p.status = "Started"
            p.whatHappened = "\(Product.name) began checking files for malware\(e.detail.isEmpty ? "" : " in \(e.detail)")."
            p.whatWeDid = "Every file is fingerprinted and checked against \(Product.name)'s definitions, YARA rules and Apple's XProtect. Nothing is changed by scanning."
            p.burstNoun = "scans started"
        case .scanFinished, .scanCancelled, .scanFailed:
            let files = filesScanned(e) ?? 0
            let found = e.found ?? parseFound(e.outcome) ?? 0
            let kind = e.facts?["scanType"] ?? (e.title.lowercased().contains("quick") ? "Quick scan" : "Scan")
            switch ev {
            case .scanCancelled: p.title = "\(kind) cancelled"; p.status = "Cancelled"; p.tone = .neutral
            case .scanFailed: p.title = "\(kind) couldn't finish"; p.status = "Didn't finish"; p.tone = .attention
            default: p.title = "\(kind) finished"; p.status = found == 0 ? "No threats" : "\(found) found"; p.tone = found == 0 ? .good : .danger
            }
            var parts = ["Checked \(fmt(files)) file\(files == 1 ? "" : "s")"]
            if let s = e.facts?["seconds"] ?? parseSeconds(e.detail) { parts[0] += " in \(s) s" }
            parts.append(found == 0 ? "no threats found" : "\(found) threat\(found == 1 ? "" : "s") found")
            p.subtitle = parts.joined(separator: " · ")
            p.symbol = found == 0 ? "checkmark.shield" : "exclamationmark.shield"
            p.whatHappened = ev == .scanFailed ? "The scan stopped early because of an error\(reason.map { ": \($0)" } ?? ".")"
                : ev == .scanCancelled ? "The scan was stopped before it finished, after checking \(fmt(files)) files."
                : "\(kind) checked \(fmt(files)) files."
            p.whatWeDid = found == 0 ? "Nothing needed attention." : "\(found) item\(found == 1 ? " was" : "s were") flagged. Each one is listed in Threats & Quarantine with the reason it was flagged."
            p.whatYouCanDo = found == 0 ? (ev == .scanFinished ? "No action is needed." : "You can start the scan again from the Scan screen.")
                : "Open Threats & Quarantine to review what was found."
            p.burstNoun = "scans"
        case .scanPaused, .scanResumed:
            p.title = ev == .scanPaused ? "Scan paused" : "Scan resumed"; p.subtitle = who.map { "\($0.prefix(1).uppercased())\($0.dropFirst())" } ?? "From the Scan screen"
            p.status = ev == .scanPaused ? "Paused" : "Running"
            p.whatHappened = ev == .scanPaused ? "The running scan was paused." : "The paused scan carried on."
            p.whatWeDid = ev == .scanPaused ? "Files are not being checked until the scan resumes. Real-time protection keeps running." : "Scanning continued where it left off."

        // threats
        case .detection:
            let name = threatName(e)
            p.tone = e.outcome.lowercased() == "contained" ? .attention : (e.severity >= .medium ? .danger : .attention)
            p.symbol = "ladybug.fill"
            p.title = "\(name) found" + (fileName.map { " in \($0)" } ?? "")
            p.subtitle = [file.map(tilde), proc].compactMap { $0 }.joined(separator: " · ")
            if p.subtitle.isEmpty { p.subtitle = "Severity: \(e.severity.label)" }
            p.whatHappened = "\(Product.name) flagged \(fileName ?? proc ?? "an item") as \(name)."
            p.why = reason ?? e.rule.map { "The rule “\($0)” matched." }
            p.whatWeDid = outcomeSentence(e.outcome, default: e.action ?? "Logged it for your review. Nothing was changed.")
            p.whatYouCanDo = "Open the threat to see the full evidence, then quarantine it or mark it as not a threat."
            p.burstNoun = "detections"
        case .quarantined, .quarantineFailed:
            let name = threatName(e)
            p.tone = ev == .quarantined ? .good : .danger; p.symbol = "archivebox.fill"
            p.title = ev == .quarantined ? "Moved \(fileName ?? name) to quarantine" : "Couldn't quarantine \(fileName ?? name)"
            p.subtitle = [name == fileName ? nil : name, file.map(tilde)].compactMap { $0 }.joined(separator: " · ")
            p.status = ev == .quarantined ? "Contained" : "Didn't work"
            p.whatHappened = ev == .quarantined ? "\(fileName ?? "The file") was identified as \(name) and moved out of harm's way." : "\(Product.name) tried to quarantine \(fileName ?? "the file") but couldn't."
            p.why = reason
            p.whatWeDid = ev == .quarantined ? "The file is encrypted inside \(Product.name)'s quarantine, so it can't run. It can be restored." : (e.action ?? "The file is still in place.")
            p.whatYouCanDo = ev == .quarantined ? "Nothing, unless you're sure it's safe: then restore it from Threats & Quarantine." : "Open the threat and try again, or delete the file yourself."
            p.burstNoun = "files quarantined"
        case .restored:
            p.tone = .info; p.symbol = "arrow.uturn.backward"
            p.title = "Restored \(fileName ?? threatName(e))"
            let trusted = e.outcome.lowercased().contains("trust") || e.title.lowercased().contains("allowed it")
            p.subtitle = (file.map { "Back at \(tilde($0))" } ?? "Put back") + (trusted ? " · now allowed" : "") + (who.map { " · \($0)" } ?? "")
            p.status = trusted ? "Restored and allowed" : "Restored"
            p.whatHappened = "A quarantined item was put back\(file.map { " at \(tilde($0))" } ?? "")."
            p.whatWeDid = trusted ? "\(Product.name) restored it and won't flag this exact file again." : "\(Product.name) restored it once. If its content is unchanged it won't be re-quarantined."
            p.whatYouCanDo = "If you restored it by mistake, run a scan of the file or move it to the Bin."
        case .deleted:
            p.tone = .neutral; p.symbol = "trash"
            p.title = "Deleted \(fileName ?? threatName(e)) permanently"
            p.subtitle = "From quarantine" + (who.map { " · \($0)" } ?? "")
            p.status = "Deleted"
            p.whatHappened = "A quarantined item was deleted for good."
            p.whatWeDid = "The encrypted copy was erased. This can't be undone."
        case .exported:
            p.tone = .info; p.symbol = "square.and.arrow.up"
            p.title = "Exported an encrypted copy of \(threatName(e))"
            p.subtitle = file.map { "Saved to \(tilde($0))" } ?? ""
            p.status = "Exported"
            p.whatHappened = "A quarantined item was exported as an encrypted, password-less archive for analysis."
            p.whatWeDid = "The copy stays encrypted, so it can't run by accident."
        case .sandboxRun:
            p.tone = .info; p.symbol = "shippingbox"
            p.title = (e.outcome.lowercased() == "started" ? "Started a sandboxed test run of " : "Sandboxed test run of ") + threatName(e)
            p.subtitle = humanOutcome(e.outcome) + (fileName.map { " · \($0)" } ?? "")
            p.whatHappened = "A quarantined item was run inside a locked-down sandbox to see what it does."
            p.whatWeDid = "The sandbox has no network, no access to your files and is stopped after a short time."
            p.why = reason
        case .alertsResolved:
            p.tone = .good; p.symbol = "checkmark.circle"
            let n = e.count ?? Int(e.title.components(separatedBy: CharacterSet.decimalDigits.inverted).first { !$0.isEmpty } ?? "") ?? 0
            p.title = n > 0 ? "Cleared \(n) earlier alert\(n == 1 ? "" : "s")" : "Cleared earlier alerts"
            p.subtitle = "No longer flagged after the protection update"
            p.status = "Resolved"
            p.whatHappened = "After updating its definitions \(Product.name) re-checked earlier alerts and these no longer match."
            p.whatWeDid = "They were marked resolved. Nothing on your Mac was changed."
        case .realtimeBlock, .processStopped:
            p.tone = .good; p.symbol = "hand.raised.fill"
            let name = threatName(e)
            p.title = ev == .processStopped ? "Stopped \(e.process?.name ?? name)" : "Blocked \(e.process?.name ?? fileName ?? name) as it ran"
            p.subtitle = [name == e.process?.name ? nil : name, file.map(tilde)].compactMap { $0 }.joined(separator: " · ")
            p.status = ev == .processStopped ? "Stopped" : "Blocked"
            p.whatHappened = "Real-time protection caught \(proc ?? fileName ?? "a program") behaving like \(name)."
            p.why = reason
            p.whatWeDid = e.action ?? "\(Product.name) stopped the process."
            p.whatYouCanDo = "Open the threat to quarantine the file or mark it as not a threat."
            p.burstNoun = "programs stopped"
        case .tamper:
            let kind = tamperKind(e)
            p.tone = .danger; p.symbol = "lock.trianglebadge.exclamationmark"
            p.title = tamperTitle(kind)
            p.subtitle = [file.map(tilde), proc.map { "by \($0)" }].compactMap { $0 }.joined(separator: " · ")
            if p.subtitle.isEmpty { p.subtitle = "Something outside \(Product.name) did this" }
            p.whatHappened = tamperExplanation(kind)
            p.why = reason ?? "Malware and tech-support scammers often turn security software off before they act."
            p.whatWeDid = e.action ?? (e.outcome.lowercased() == "contained" ? "\(Product.name) undid the change and kept protecting your Mac." : "\(Product.name) recorded it and kept protecting your Mac. It restores its own files and settings if they change.")
            p.whatYouCanDo = "If you weren't updating or removing \(Product.name) yourself, open the alert and run a full scan. If it keeps happening, turn on Emergency Lockdown."
            p.groupKey = "tamper"; p.burstNoun = "tamper attempts"
        case .pasteGuardBlocked, .pasteGuardWarned:
            p.tone = ev == .pasteGuardBlocked ? .good : .attention; p.symbol = "doc.on.clipboard"
            let src = e.facts?["sourceApp"] ?? e.process?.name
            p.title = ev == .pasteGuardBlocked ? "Stopped a dangerous pasted command" : "Warned about a copied command"
            p.subtitle = [src.map { "Copied from \($0)" }, reason].compactMap { $0 }.joined(separator: " · ")
            if p.subtitle.isEmpty { p.subtitle = cleanTitle(e.title) }
            p.status = ev == .pasteGuardBlocked ? "Stopped" : "Warned"
            p.whatHappened = "A command that could take over your Mac was copied to the clipboard\(src.map { " from \($0)" } ?? "")."
            p.why = reason ?? e.rule.map { "It matched “\($0)”, a pattern used by fake “verify you're human” and support scams." }
            p.whatWeDid = e.action ?? "\(Product.name) warned you before it could be pasted into Terminal. The command text isn't kept."
            p.whatYouCanDo = "Never paste commands a website or caller asks you to run. If you already ran it, run a full scan."
            p.burstNoun = "paste warnings"

        // web
        case .webBlocked, .dnsBlocked:
            p.tone = .good; p.symbol = "hand.raised.fill"
            let h = host ?? e.title.replacingOccurrences(of: "Blocked ", with: "")
            let list = e.rule ?? listName(e.detail)
            p.title = ev == .dnsBlocked ? "Blocked a connection to \(h)" : "Blocked \(h)"
            p.subtitle = [list.map { "On the \($0) blocklist" }, proc].compactMap { $0 }.joined(separator: " · ")
            if p.subtitle.isEmpty { p.subtitle = "Known dangerous site" }
            p.status = "Blocked"
            p.whatHappened = "\(proc ?? "Something on your Mac") tried to reach \(h)."
            p.why = list.map { "\(h) is listed on \($0), a list of sites known for malware, scams or tracking." } ?? reason
            p.whatWeDid = "\(Product.name)'s web protection answered with “no such site”, so nothing was loaded."
            p.whatYouCanDo = "If this is a site you trust, allow it under Rules. Otherwise no action is needed."
            p.groupKey = ev.rawValue + "|" + h; p.burstNoun = "blocks"
        case .scamBlocked, .webWarning:
            let (_, parsedScore) = parseVerdict(e.outcome)
            let score = e.score ?? parsedScore
            let h = host ?? e.title.replacingOccurrences(of: "Web warning: ", with: "")
            let brand = e.facts?["brand"]
            p.symbol = ev == .scamBlocked ? "xmark.shield.fill" : "exclamationmark.triangle.fill"
            p.tone = ev == .scamBlocked ? .good : .attention
            if ev == .scamBlocked {
                p.title = "Scam link blocked: " + (brand.map { "\($0) lookalike" } ?? h)
            } else {
                p.title = "Warned about a suspicious site: \(h)"
            }
            let headline = e.title.lowercased().hasPrefix("web warning") ? "" : e.title
            p.subtitle = [brand == nil ? nil : h, headline.isEmpty ? nil : headline, score.map { "risk \($0)/100" }].compactMap { $0 }.joined(separator: " · ")
            p.status = ev == .scamBlocked ? "Blocked" : "Warned"
            p.whatHappened = "\(proc ?? "Your browser") opened \(h)\(brand.map { ", a site made to look like \($0)" } ?? "")."
            p.why = reason ?? (headline.isEmpty ? "The address and page have the hallmarks of a scam." : headline + ".")
            if let s = score { p.why = (p.why ?? "") + " Risk score \(s) out of 100." }
            p.whatWeDid = ev == .scamBlocked ? "\(Product.name) stopped the page and showed a warning instead. Nothing you typed was sent." : "\(Product.name) showed a warning on the page. It was not blocked."
            p.whatYouCanDo = ev == .scamBlocked ? "Close the tab. If you entered a password there, change it now." : "Check the address carefully before typing anything."
            p.groupKey = ev.rawValue + "|" + h; p.burstNoun = ev == .scamBlocked ? "scam links blocked" : "warnings"

        // remote access
        case .remoteAccessAttempt:
            p.tone = .danger; p.symbol = "display.2"
            let tool = e.facts?["tool"] ?? e.title.replacingOccurrences(of: "Unapproved remote access: ", with: "")
            p.title = isRemoteName(e.title) && e.title.hasPrefix("Unapproved") || e.facts?["tool"] != nil ? "Remote-control app running without your approval: \(tool)" : cleanTitle(e.title)
            p.subtitle = [proc, file.map(tilde)].compactMap { $0 }.joined(separator: " · ")
            if p.subtitle.isEmpty { p.subtitle = humanOutcome(e.outcome) }
            p.whatHappened = "A program that lets someone control your Mac from elsewhere is active."
            p.why = reason ?? "Scammers often ask people to install remote-control apps such as AnyDesk or TeamViewer."
            p.whatWeDid = e.action ?? outcomeSentence(e.outcome, default: "\(Product.name) alerted you. With remote-access lockdown on, it also suspends the app.")
            p.whatYouCanDo = "If you didn't start a support session yourself, quit the app and open Remote Access to keep it blocked. If you did, allow it there."
            p.groupKey = ev.rawValue + "|" + tool; p.burstNoun = "remote access attempts"
        case .remoteAccessAllowed, .remoteAccessRevoked:
            let tool = e.facts?["tool"] ?? e.title.replacingOccurrences(of: "Allowed remote tool ", with: "").replacingOccurrences(of: "Revoked remote tool ", with: "")
            p.tone = .info; p.symbol = "display.2"
            p.title = ev == .remoteAccessAllowed ? "Allowed remote control by \(tool)" : "Removed permission for \(tool)"
            p.subtitle = (ev == .remoteAccessAllowed ? (e.detail.isEmpty ? "" : e.detail.replacingOccurrences(of: "min", with: "minutes")) : "") + (who.map { (ev == .remoteAccessAllowed && !e.detail.isEmpty ? " · " : "") + $0 } ?? "")
            p.status = ev == .remoteAccessAllowed ? "Allowed" : "Removed"
            p.whatHappened = ev == .remoteAccessAllowed ? "\(tool) was allowed to control this Mac." : "\(tool) is no longer allowed to control this Mac."
            p.whatWeDid = ev == .remoteAccessAllowed ? "\(Product.name) won't alert on or suspend \(tool) while the permission lasts." : "\(Product.name) alerts on, and with lockdown on suspends, \(tool) again."
            p.whatYouCanDo = ev == .remoteAccessAllowed ? "Remove the permission in Remote Access as soon as your session ends." : "No action is needed."
        case .remoteLockdownChanged:
            let on = isOn(e)
            p.tone = on ? .good : .attention; p.symbol = "display.2"
            p.title = "Remote-access lockdown turned \(on ? "on" : "off")" + (who.map { " (\($0))" } ?? "")
            p.subtitle = on ? "Unapproved remote-control apps are suspended" : "Remote-control apps are only reported"
            p.status = on ? "On" : "Off"
            p.whatHappened = p.title + "."
            p.whatWeDid = p.subtitle + "."

        // lockdown
        case .lockdownStarted:
            p.tone = .danger; p.symbol = "lock.shield.fill"
            p.title = "Emergency Lockdown started" + (who.map { " (\($0))" } ?? "")
            p.subtitle = reason ?? (e.detail.isEmpty ? "Protecting your Mac from an active threat" : e.detail)
            p.status = e.outcome.lowercased().contains("dry run") ? "Practice run" : "Locked down"
            p.whatHappened = "\(Product.name) detected signs of an active attack\(reason.map { ": \($0)" } ?? (e.detail.isEmpty ? "" : ": \(e.detail)"))."
            p.whatWeDid = e.action ?? "Network access for untrusted apps, remote control and risky settings were locked down until the checks pass."
            p.whatYouCanDo = "Follow the steps in Emergency. Lift the lockdown when every check passes."
        case .lockdownLifted:
            p.tone = .good; p.symbol = "lock.open"
            p.title = "Emergency Lockdown lifted" + (who.map { " (\($0))" } ?? "")
            p.subtitle = e.detail.isEmpty ? "Normal protection resumed" : e.detail.prefix(1).uppercased() + e.detail.dropFirst()
            p.status = "Lifted"
            p.whatHappened = "The emergency lockdown ended."
            p.whatWeDid = "Network, remote control and settings went back to how they were before."
            p.whatYouCanDo = e.detail.contains("before every check") ? "Some checks hadn't passed. Run a full scan to be safe." : "No action is needed."

        // Wi-Fi
        case .wifiWarning, .wifiDisconnected, .wifiStayedConnected, .wifiTrustChanged:
            let net = e.facts?["network"] ?? target ?? "this Wi-Fi network"
            p.symbol = "wifi.exclamationmark"
            switch ev {
            case .wifiDisconnected: p.title = "Disconnected from \(net)"; p.tone = .good; p.status = "Disconnected"
                p.whatWeDid = "\(Product.name) disconnected so your traffic couldn't be watched."
            case .wifiStayedConnected: p.title = "Stayed connected to \(net)" + (who.map { " (\($0))" } ?? ""); p.tone = .attention; p.status = "Stayed connected"
                p.whatWeDid = "\(Product.name) kept the connection because you asked it to."
            case .wifiTrustChanged: let t = isOn(e); p.title = "\(net) marked as \(t ? "trusted" : "not trusted")" + (who.map { " (\($0))" } ?? ""); p.tone = .info; p.status = t ? "Trusted" : "Not trusted"; p.symbol = "wifi"
                p.whatWeDid = t ? "\(Product.name) won't warn about this network again." : "\(Product.name) will check this network each time you join."
            default: p.title = "Risky Wi-Fi: \(net)"; p.tone = .attention; p.status = humanOutcome(e.outcome).isEmpty ? "Warned" : humanOutcome(e.outcome)
                p.whatWeDid = e.action ?? "\(Product.name) warned you."
            }
            p.subtitle = reason ?? (e.detail.isEmpty ? "Wi-Fi guard" : e.detail)
            p.whatHappened = ev == .wifiTrustChanged ? "You changed how \(Product.name) treats \(net)." : "\(Product.name) checked the Wi-Fi network \(net)."
            p.why = reason
            p.whatYouCanDo = ev == .wifiWarning ? "Avoid signing in to anything important on this network, or use a VPN." : "No action is needed."
            p.groupKey = ev.rawValue + "|" + net; p.burstNoun = "Wi-Fi warnings"

        // persistence and posture
        case .persistenceAdded:
            p.tone = .info; p.symbol = "arrow.right.circle"
            let label = e.facts?["label"] ?? cleanTitle(e.title.replacingOccurrences(of: "New ", with: ""))
            p.title = "New startup item: \(label)"
            p.subtitle = file.map(tilde) ?? e.detail
            p.status = "Noted"
            p.whatHappened = "A program set itself up to start automatically\(file.map { " (\(tilde($0)))" } ?? "")."
            p.whatWeDid = "\(Product.name) recorded it and checked it. Risky items appear as separate alerts."
            p.whatYouCanDo = "If you don't recognise it, review it under Startup Items."
            p.burstNoun = "new startup items"
        case .persistenceRemoved:
            p.title = cleanTitle(e.title).replacingOccurrences(of: "persistence item(s)", with: "startup item(s)"); p.subtitle = "Startup items"
            p.status = "Noted"; p.whatHappened = "Startup items were removed from your Mac."; p.whatWeDid = "\(Product.name) updated its list."
        case .startupItemRemoved, .startupItemRemoveFailed:
            let label = e.facts?["label"] ?? cleanTitle(e.title.replacingOccurrences(of: "Removed ", with: "").replacingOccurrences(of: "Could not remove ", with: "").replacingOccurrences(of: "Turned off startup item ", with: ""))
            p.tone = ev == .startupItemRemoved ? .good : .danger; p.symbol = "power"
            p.title = ev == .startupItemRemoved ? "Turned off startup item \(label)" : "Couldn't turn off \(label)"
            p.subtitle = (file.map(tilde) ?? "") + (who.map { (file == nil ? "" : " · ") + $0 } ?? "")
            p.status = ev == .startupItemRemoved ? "Removed" : "Didn't work"
            p.whatHappened = ev == .startupItemRemoved ? "\(label) no longer starts automatically." : "\(Product.name) couldn't turn off \(label)."
            p.why = reason ?? (ev == .startupItemRemoveFailed && !e.detail.isEmpty ? e.detail : nil)
            p.whatWeDid = ev == .startupItemRemoved ? (e.detail.isEmpty ? "It was stopped, disabled and its file moved to quarantine so this can be undone." : e.detail) : "Nothing was changed."
        case .postureFixed, .postureFixFailed:
            let check = e.facts?["check"] ?? cleanTitle(e.title.replacingOccurrences(of: "Fixed: ", with: "").replacingOccurrences(of: "Fixed ", with: "").replacingOccurrences(of: "Could not fix ", with: ""))
            p.tone = ev == .postureFixed ? .good : .attention; p.symbol = "checkmark.seal"
            p.title = ev == .postureFixed ? "Fixed: \(check)" : "Couldn't fix: \(check)"
            p.subtitle = (ev == .postureFixFailed ? (reason ?? e.detail) : "Security Score") + (who.map { " · \($0)" } ?? "")
            p.status = ev == .postureFixed ? "Fixed" : "Didn't work"
            p.whatHappened = ev == .postureFixed ? "A Mac security setting was turned on." : "\(Product.name) tried to fix a Mac security setting."
            p.why = ev == .postureFixFailed ? (reason ?? (e.detail.isEmpty ? nil : e.detail)) : nil
            p.whatWeDid = ev == .postureFixed ? (e.detail.isEmpty ? "The setting was changed." : e.detail) : "Nothing was changed."

        // settings
        case .settingsChanged:
            p.tone = .neutral; p.symbol = "gearshape"
            let changes = e.facts?["changes"] ?? (e.detail == "no effective change" ? "" : e.detail)
            p.title = "Settings changed" + (who.map { " (\($0))" } ?? "")
            p.subtitle = changes.isEmpty ? "No effective change" : humanizeChanges(changes)
            p.status = "Saved"
            p.whatHappened = changes.isEmpty ? "Settings were saved without changes." : "These settings changed: \(humanizeChanges(changes))."
            p.whatWeDid = "\(Product.name) saved and applied the new settings."
            p.whatYouCanDo = "Change them back in Settings if this wasn't you."
        case .protectionToggled:
            let on = isOn(e)
            let setting = e.facts?["setting"] ?? (e.title.lowercased().hasPrefix("web") ? "Web protection" : "Real-time protection")
            p.tone = on ? .good : .attention; p.symbol = on ? "shield.lefthalf.filled" : "shield.slash"
            let place = e.facts?["where"].map { ", in \($0)" } ?? ""
            p.title = "\(setting) turned \(on ? "on" : "off")" + (who.map { " (\($0)\(place))" } ?? "")
            p.subtitle = on ? "Protection is active" : "Your Mac is less protected until it's turned back on"
            p.status = on ? "On" : "Off"
            p.whatHappened = "\(setting) was turned \(on ? "on" : "off")."
            p.whatWeDid = on ? "\(Product.name) is checking again." : "\(Product.name) stopped this layer of protection."
            p.whatYouCanDo = on ? "No action is needed." : "Turn it back on when you're done."
        case .protectionPaused:
            p.tone = .attention; p.symbol = "pause.circle"
            let m = e.count ?? Int(e.title.components(separatedBy: CharacterSet.decimalDigits.inverted).first { !$0.isEmpty } ?? "")
            p.title = "Protection paused" + (m.map { " for \(minutesText($0))" } ?? "") + (who.map { " (\($0))" } ?? "")
            p.subtitle = "It turns itself back on automatically"; p.status = "Paused"
            p.whatHappened = "Real-time protection was paused."
            p.whatWeDid = "\(Product.name) stopped checking new files and programs for the pause and will resume on its own."
            p.whatYouCanDo = "Resume it sooner from the menu bar or Settings."
        case .protectionResumed:
            p.tone = .good; p.symbol = "play.circle"; p.title = "Protection resumed" + (who.map { " (\($0))" } ?? "")
            p.subtitle = "Real-time protection is on again"; p.status = "On"
            p.whatHappened = "The pause ended."; p.whatWeDid = "Real-time protection is checking again."
        case .allowRuleAdded, .allowRuleRemoved:
            let name = e.facts?["name"] ?? cleanTitle(e.title.replacingOccurrences(of: "Allowed ", with: "").replacingOccurrences(of: "Removed rule for ", with: ""))
            let scope = e.facts?["scope"].map(scopeLabel)
            p.tone = .neutral; p.symbol = "checkmark.seal"
            if ev == .allowRuleAdded {
                p.title = "Allowed \(name)" + (scope.map { " (\($0))" } ?? "")
                p.subtitle = "Marked as not a threat" + (who.map { " · \($0)" } ?? "")
                p.status = "Allowed"
                p.whatHappened = "\(name) was added to the allowed items."
                p.whatWeDid = "\(Product.name) won't flag it again\(scope.map { " (matched by \($0.lowercased()))" } ?? "")."
                p.whatYouCanDo = "Undo this if you allowed it by mistake."
            } else {
                p.title = e.facts?["name"] != nil || e.title.hasPrefix("Removed rule for") ? "Stopped allowing \(name)" : "Removed an allowed item"
                p.subtitle = "Allowed items" + (who.map { " · \($0)" } ?? ""); p.status = "Removed"
                p.whatHappened = "An allowed item was removed."; p.whatWeDid = "\(Product.name) checks it normally again."
            }
        case .adminSession:
            p.tone = .info; p.symbol = "person.badge.key"
            p.title = "Administrator approved changing protected settings"
            p.subtitle = "For 10 minutes"; p.status = "Approved"
            p.whatHappened = "An administrator password was entered to change settings that lower protection."
            p.whatWeDid = "\(Product.name) allowed protected changes for 10 minutes."
            p.whatYouCanDo = "If this wasn't you, change your Mac password."
        case .protectEverything:
            let on = isOn(e) || e.title.lowercased().contains("turned on")
            p.tone = on ? .good : .neutral; p.symbol = "shield.checkered"
            p.title = "Protect Everything turned \(on ? "on" : "off")" + (who.map { " (\($0))" } ?? "")
            p.subtitle = e.detail.isEmpty ? humanOutcome(e.outcome) : e.detail; p.status = on ? "On" : "Off"
            p.whatHappened = p.title + "."; p.whatWeDid = on ? "Every protection layer that can run was turned on." : "Your previous settings were restored."

        // updates
        case .definitionsUpdated:
            p.tone = .good; p.symbol = "arrow.triangle.2.circlepath"
            p.title = "Protection definitions updated" + (who.map { " (\($0))" } ?? "")
            p.subtitle = e.detail.isEmpty ? "Up to date" : shortList(e.detail); p.status = "Up to date"
            p.whatHappened = "\(Product.name) downloaded the latest malware and scam definitions."
            p.whatWeDid = e.detail.isEmpty ? "The new definitions are in use." : e.detail
        case .definitionsFailed:
            p.tone = .attention; p.symbol = "exclamationmark.arrow.triangle.2.circlepath"
            p.title = "Couldn't update all protection definitions"
            p.subtitle = (e.detail.isEmpty ? "" : shortList(e.detail) + " · ") + "will retry"; p.status = "Will retry"
            p.whatHappened = "Some definitions couldn't be downloaded\(e.detail.isEmpty ? "" : ": \(e.detail)")."
            p.why = reason ?? "Usually the Mac was offline or a download server didn't answer."
            p.whatWeDid = "\(Product.name) kept using the definitions it already has and will try again automatically."
            p.whatYouCanDo = "Check your internet connection, or update now from the Dashboard."

        // privacy features
        case .vaultEvent, .authenticatorEvent:
            p.tone = e.severity >= .medium ? .attention : .info; p.symbol = ev == .vaultEvent ? "lock.rectangle" : "number.square"
            p.title = cleanTitle(e.title)
            p.subtitle = e.detail
            p.whatHappened = cleanTitle(e.title) + "."
            p.why = reason
            p.whatWeDid = e.action ?? (e.detail.isEmpty ? "Recorded for your security history. No passwords or codes are kept in this log." : e.detail)
            p.whatYouCanDo = e.severity >= .medium ? "If this wasn't you, change your vault's main password." : "No action is needed."
            p.burstNoun = ev == .vaultEvent ? "vault events" : "authenticator events"

        // maintenance
        case .refreshCleanup, .refreshUndo:
            p.tone = .good; p.symbol = "sparkles"
            let n = e.count ?? 0
            p.title = ev == .refreshUndo ? "Undid the last clean-up" : (e.facts?["freed"].map { "Cleaned up \($0)" } ?? cleanTitle(e.title))
            p.subtitle = (n > 0 ? "\(fmt(n)) item\(n == 1 ? "" : "s")" : "") + (e.detail.isEmpty ? "" : (n > 0 ? " · " : "") + e.detail)
            p.status = ev == .refreshUndo ? "Undone" : "Cleaned"
            p.whatHappened = ev == .refreshUndo ? "The items from the last clean-up were put back." : "Refresh removed items you selected."
            p.whatWeDid = ev == .refreshUndo ? "They were restored from \(Product.name)'s backup." : (e.action ?? "Items were moved to the Bin or a backup so the clean-up can be undone.")
            p.whatYouCanDo = ev == .refreshUndo ? "No action is needed." : "Undo it from the Refresh screen if something is missing."
        case .networkScan:
            let n = e.count ?? 0, f = e.found ?? 0
            p.tone = f > 0 ? .attention : .good; p.symbol = "network"
            p.title = "Network scan found \(n) device\(n == 1 ? "" : "s")"
            p.subtitle = (f == 0 ? "No problems" : "\(f) issue\(f == 1 ? "" : "s") to review") + (target.map { " · \($0)" } ?? "")
            p.status = f == 0 ? "No problems" : "\(f) to review"
            p.whatHappened = "\(Product.name) checked the devices on your local network\(target.map { " (\($0))" } ?? "")."
            p.whatWeDid = "Each device was identified and checked for open, risky services. Nothing was changed."
            p.whatYouCanDo = f == 0 ? "No action is needed." : "Open Network Scan to see which devices need attention."

        // service
        case .serviceStarted, .serviceStopped:
            p.tone = ev == .serviceStarted ? .good : .attention; p.symbol = ev == .serviceStarted ? "power" : "power.dotted"
            p.title = "\(Product.name) protection \(ev == .serviceStarted ? "started" : "stopped")"
            p.subtitle = e.detail.isEmpty ? (ev == .serviceStarted ? "Background service running" : "Background service ended") : e.detail
            p.status = ev == .serviceStarted ? "Running" : "Stopped"
            p.whatHappened = ev == .serviceStarted ? "\(Product.name)'s background protection service started." : "\(Product.name)'s background protection service stopped\(e.detail.isEmpty ? "" : ": \(e.detail)")."
            p.whatWeDid = ev == .serviceStarted ? "Real-time, web and tamper protection are active." : "Protection pauses until the service runs again; macOS restarts it automatically."
            p.whatYouCanDo = ev == .serviceStopped && !e.detail.lowercased().contains("shut") ? "If it doesn't come back within a minute, restart your Mac." : "No action is needed."
        case .uninstall:
            p.tone = .attention; p.symbol = "trash"; p.title = "\(Product.name) uninstall started" + (who.map { " (\($0))" } ?? "")
            p.subtitle = "Approved with an administrator password"; p.status = "Uninstalling"
            p.whatHappened = "Someone asked to remove \(Product.name)."; p.whatWeDid = "Protection is being removed."
            p.whatYouCanDo = "If this wasn't you, reinstall \(Product.name) and change your Mac password."
        case .other:
            p.title = cleanTitle(e.title); p.subtitle = e.detail
            p.whatHappened = cleanTitle(e.title) + "."; p.whatWeDid = outcomeSentence(e.outcome, default: "Recorded.")
        }

        if p.title.isEmpty { p.title = cleanTitle(e.title) }
        if p.status.isEmpty { p.status = humanOutcome(e.outcome) }
        p.facts = facts(e, p, target: target, scoreText: scoreText)
        return p
    }

    // MARK: facts

    static func facts(_ e: ActivityEntry, _ p: ActivityPresentation, target: String?, scoreText: String?) -> [ActivityFact] {
        var out: [ActivityFact] = [ActivityFact("When", e.date.formatted(date: .complete, time: .standard))]
        if let pr = e.process, !pr.isEmpty {
            if let n = pr.name { out.append(ActivityFact("Process", n)) }
            if let path = pr.path { out.append(ActivityFact("Process path", path, mono: true)) }
            if let s = pr.signer { out.append(ActivityFact("Signed by", s)) }
            if let pid = pr.pid { out.append(ActivityFact("Process ID", String(pid), mono: true)) }
            if let pp = pr.parentPID { out.append(ActivityFact("Started by", (pr.parentName.map { "\($0) " } ?? "") + "(pid \(pp))")) }
        }
        if let t = target {
            let label = t.hasPrefix("/") || t.hasPrefix("~") ? "File" : t.contains("://") ? "Website" : "Address"
            out.append(ActivityFact(label, t, mono: label == "File"))
        }
        if let r = e.rule, !r.isEmpty, p.event != .dnsBlocked, p.event != .webBlocked { out.append(ActivityFact("Rule", r, mono: true)) }
        else if let r = e.rule, !r.isEmpty { out.append(ActivityFact("Blocklist", r)) }
        if let s = scoreText { out.append(ActivityFact(p.event == .detection || p.event == .tamper ? "Confidence" : "Score", s)) }
        if e.severity > .info { out.append(ActivityFact("Severity", e.severity.label)) }
        if let a = e.actor { out.append(ActivityFact("Done by", actorLabel(a))) }
        if let c = e.count, [.scanFinished, .scanCancelled, .scanFailed].contains(p.event) { out.append(ActivityFact("Files checked", fmt(c))) }
        for (k, v) in (e.facts ?? [:]).sorted(by: { $0.key < $1.key }) where !hiddenFactKeys.contains(k) && !v.isEmpty {
            out.append(ActivityFact(factLabel(k), k == "changes" ? humanizeChanges(v) : v))
        }
        if let h = e.sha256, !h.isEmpty { out.append(ActivityFact("SHA-256", h, mono: true)) }
        if !e.outcome.isEmpty { out.append(ActivityFact("Result", humanOutcome(e.outcome))) }
        return out
    }
    static let hiddenFactKeys: Set<String> = ["scanType", "seconds", "where"]
    static func factLabel(_ k: String) -> String {
        switch k {
        case "setting": return "Setting"; case "value": return "New value"; case "tool": return "Remote tool"; case "brand": return "Imitating"
        case "network": return "Wi-Fi network"; case "sourceApp": return "Copied from"; case "label": return "Startup item"
        case "check": return "Check"; case "name": return "Item"; case "scope": return "Matched by"; case "changes": return "Changes"
        case "freed": return "Space freed"; case "subnet": return "Network"; case "list": return "Blocklist"; case "verdict": return "Verdict"
        default: return splitCamel(k).prefix(1).uppercased() + splitCamel(k).dropFirst()
        }
    }

    /// Everything about the entry as plain text (search, Copy details, export). No secrets are ever stored.
    public static func fullText(_ e: ActivityEntry) -> String {
        let p = present(e)
        var lines = [p.title]
        if !p.subtitle.isEmpty { lines.append(p.subtitle) }
        lines.append("")
        lines.append("What happened: " + p.whatHappened)
        if let w = p.why { lines.append("Why: " + w) }
        lines.append("What \(Product.name) did: " + p.whatWeDid)
        lines.append("What you can do: " + p.whatYouCanDo)
        lines.append("")
        for f in p.facts { lines.append("\(f.label): \(f.value)") }
        return lines.joined(separator: "\n")
    }

    // MARK: wording helpers

    /// Maps raw outcome codes ("needs review", "off", "likelyScam (93)", "allow rule added") to plain English.
    public static func humanOutcome(_ raw: String) -> String {
        let s = raw.trimmingCharacters(in: .whitespaces)
        if s.isEmpty { return "" }
        let (verdict, score) = parseVerdict(s)
        if let v = verdict {
            let name: String = v == "likelyscam" ? "Likely scam" : v == "suspicious" ? "Suspicious" : v == "likelysafe" ? "Looks safe" : splitCamel(v)
            return name + (score.map { " · risk \($0)/100" } ?? "")
        }
        let map: [String: String] = [
            "needs review": "Needs your review", "needs decision": "Needs your review", "contained": "Contained", "logged": "Logged for review",
            "blocked": "Blocked", "on": "On", "off": "Off", "allow rule added": "Allowed", "rule added": "Allowed",
            "allow rule removed": "Removed", "rule removed": "Removed", "quarantined": "Moved to quarantine", "restored": "Restored",
            "restored and trusted": "Restored and allowed", "restored elsewhere": "Restored to a new place",
            "restored elsewhere and trusted": "Restored to a new place and allowed", "will retry": "Will retry automatically",
            "ok": "Up to date", "recorded": "Noted", "fixed": "Fixed", "failed": "Didn't work", "resolved": "Resolved",
            "saved": "Saved", "paused": "Paused", "uninstalling": "Uninstalling", "lifted": "Lifted", "locked down": "Locked down",
            "locked down (dry run)": "Practice run (nothing locked)", "exported": "Exported", "started": "Started", "no threats": "No threats",
            "allowed": "Allowed", "revoked": "Removed", "removed": "Removed", "changed": "Changed", "done": "Done",
            "settings session (10 min)": "Approved for 10 minutes", "completed": "Completed", "stopped": "Stopped", "deleted": "Deleted",
            "warned": "Warned", "disconnected": "Disconnected", "suspended": "Suspended", "killed": "Stopped",
        ]
        if let m = map[s.lowercased()] { return m }
        if let n = parseFound(s) { return n == 0 ? "No threats" : "\(n) threat\(n == 1 ? "" : "s") found" }
        let cleaned = splitCamel(s)
        return cleaned.prefix(1).uppercased() + cleaned.dropFirst()
    }

    static func outcomeSentence(_ raw: String, default d: String) -> String {
        switch raw.lowercased() {
        case "contained", "quarantined": return "\(Product.name) contained it: the file was moved to quarantine or the process was stopped."
        case "needs review", "needs decision": return "\(Product.name) hasn't changed anything. It's waiting for you to decide."
        case "logged": return "Logged for your review. The confidence was too low to act on its own."
        case "blocked": return "\(Product.name) blocked it."
        case "suspended": return "\(Product.name) suspended it."
        default: return d
        }
    }

    public static func tamperKind(_ e: ActivityEntry) -> String {
        if let r = e.rule, !r.isEmpty { return r }
        for prefix in ["Tampering with \(Product.name): ", "Self-defence: "] where e.title.hasPrefix(prefix) {
            return String(e.title.dropFirst(prefix.count))
        }
        return ""
    }

    public static func tamperTitle(_ kind: String) -> String {
        switch kind {
        case "unloadAttempt": return "Something tried to stop \(Product.name)'s background service"
        case "killAttempt": return "Something tried to shut \(Product.name) down"
        case "fileTamper": return "Something tried to change \(Product.name)'s files"
        case "plistTamper": return "Something tried to change how \(Product.name) starts"
        case "binaryTamper": return "\(Product.name)'s program file was changed"
        case "configTamper": return "\(Product.name)'s settings were changed from outside the app"
        case "exclusionOfSelf": return "Something tried to hide \(Product.name)'s own files from scanning"
        case "launchItemRemoved": return "\(Product.name)'s startup item was removed"
        case "clockTamper": return "The Mac's clock was changed"
        default: return "Something tried to interfere with \(Product.name)"
        }
    }

    static func tamperExplanation(_ kind: String) -> String {
        switch kind {
        case "unloadAttempt": return "A program asked macOS to unload \(Product.name)'s protection service."
        case "killAttempt": return "A program tried to force-quit \(Product.name)'s protection service."
        case "fileTamper": return "A program wrote to, renamed or deleted a file inside \(Product.name)'s installation."
        case "plistTamper": return "\(Product.name)'s launch settings, which make it start with your Mac, were edited or removed."
        case "binaryTamper": return "\(Product.name)'s installed program no longer matches the copy that was installed."
        case "configTamper": return "\(Product.name)'s sealed settings or allowed items were edited outside the app."
        case "exclusionOfSelf": return "Someone tried to add \(Product.name)'s own folders to the scan exclusions."
        case "launchItemRemoved": return "macOS reported that \(Product.name)'s login item was removed."
        case "clockTamper": return "The system clock jumped. That can make time-limited permissions expire early or last too long."
        default: return "Something acted on \(Product.name) itself."
        }
    }

    static func actorPhrase(_ a: ActivityActor?) -> String? {
        switch a {
        case .user?: return "by you"
        case .ai?: return "by the AI assistant, approved by you"
        case .system?: return "automatically"
        case .schedule?: return "on schedule"
        case .commandLine?: return "from the command line"
        case nil: return nil
        }
    }
    static func actorLabel(_ a: ActivityActor) -> String {
        switch a {
        case .user: return "You"; case .ai: return "AI assistant (you approved it)"; case .system: return "\(Product.name), automatically"
        case .schedule: return "Scheduled task"; case .commandLine: return "Command line"
        }
    }

    static func isOn(_ e: ActivityEntry) -> Bool {
        if let v = e.facts?["value"]?.lowercased() { return v == "on" || v == "true" || v == "trusted" }
        let o = e.outcome.lowercased(), t = e.title.lowercased()
        if o == "on" { return true }
        if o == "off" { return false }
        return t.hasSuffix(" on") || t.contains("turned on")
    }

    static func threatName(_ e: ActivityEntry) -> String {
        var n = e.facts?["threat"] ?? e.title
        for prefix in ["Quarantined ", "Restored ", "Exported encrypted copy of ", "Sandbox run finished: ", "Sandbox run of ", "Moved ", "Deleted "] where n.hasPrefix(prefix) {
            n = String(n.dropFirst(prefix.count))
        }
        if n.hasSuffix(" to quarantine") { n = String(n.dropLast(" to quarantine".count)) }
        return n.isEmpty ? "item" : n
    }

    static func targetOf(_ e: ActivityEntry) -> String? {
        if let t = e.target, !t.isEmpty { return t }
        let d = e.detail.trimmingCharacters(in: .whitespaces)
        if d.hasPrefix("/") && !d.contains(", ") { return d }
        if d.hasPrefix("http://") || d.hasPrefix("https://") { return d }
        if e.kind == .webBlock, e.title.hasPrefix("Blocked ") { return String(e.title.dropFirst("Blocked ".count)) }
        return nil
    }

    static func hostOf(_ t: String) -> String? {
        if t.hasPrefix("/") || t.hasPrefix("~") { return nil }
        if t.contains("://") { return URL(string: t)?.host ?? t }
        return t
    }

    static func processLine(_ p: ActivityProcess?) -> String? {
        guard let p, !p.isEmpty else { return nil }
        let name = p.name ?? p.path.map { ($0 as NSString).lastPathComponent } ?? "process"
        return name + (p.pid.map { " (pid \($0))" } ?? "")
    }

    static func tilde(_ p: String) -> String { (p as NSString).abbreviatingWithTildeInPath }

    static func listName(_ detail: String) -> String? {
        guard detail.hasPrefix("Listed in ") else { return nil }
        let s = String(detail.dropFirst("Listed in ".count)); return s.isEmpty ? nil : s
    }

    static func shortList(_ s: String) -> String { s.count > 140 ? String(s.prefix(139)) + "…" : s }

    static func minutesText(_ m: Int) -> String {
        m >= 60 && m % 60 == 0 ? "\(m / 60) hour\(m == 60 ? "" : "s")" : "\(m) minute\(m == 1 ? "" : "s")"
    }

    static func scopeLabel(_ raw: String) -> String {
        switch raw { case "fileHash": return "This exact file"; case "developer": return "Developer"; case "signingID": return "App identity"; case "folder": return "Folder"; default: return splitCamel(raw) }
    }

    /// "realtimeOn: true → false; scanHour: 2 → 3" → "Real-time protection: on → off; Scan hour: 2 → 3".
    static func humanizeChanges(_ s: String) -> String {
        s.components(separatedBy: "; ").map { part -> String in
            guard let r = part.range(of: ": ") else { return part }
            let key = String(part[..<r.lowerBound]), val = String(part[r.upperBound...])
            let k = settingLabels[key] ?? (splitCamel(key).prefix(1).uppercased() + splitCamel(key).dropFirst())
            let v = val.replacingOccurrences(of: "true", with: "on").replacingOccurrences(of: "false", with: "off")
            return "\(k): \(v)"
        }.joined(separator: "; ")
    }
    static let settingLabels: [String: String] = [
        "realtimeOn": "Real-time protection", "webProtection": "Web protection", "autoQuarantine": "Automatic quarantine",
        "scanHour": "Daily scan time", "exclusions": "Scan exclusions", "killMaliciousProcesses": "Stop malicious programs",
        "autoUpdate": "Automatic updates", "scanArchives": "Scan inside archives", "pua": "Potentially unwanted apps",
    ]

    /// Splits camelCase into words and lowercases them ("fileTamper" → "file tamper").
    public static func splitCamel(_ s: String) -> String {
        var out = ""
        var prevLower = false
        for ch in s {
            if ch.isUppercase && prevLower { out.append(" "); out.append(Character(ch.lowercased())) } else { out.append(ch) }
            prevLower = ch.isLowercase
        }
        return out
    }

    /// Removes internal codes from free-text titles: camelCase tokens and the "Tampering with X: kind" form.
    static func cleanTitle(_ s: String) -> String {
        if isTamperName(s) { return tamperTitle(String(s.split(separator: ":").last ?? "").trimmingCharacters(in: .whitespaces)) }
        let words = s.split(separator: " ", omittingEmptySubsequences: false).map { w -> String in
            let t = String(w)
            if t.contains("/") || t.contains(".") || t.contains("_") { return t }   // paths, hosts, identifiers stay intact
            return splitCamel(t)
        }
        return words.joined(separator: " ")
    }

    /// "likelyScam (93)" → ("likelyscam", 93).
    static func parseVerdict(_ s: String) -> (String?, Int?) {
        let lower = s.lowercased()
        let known = ["likelyscam", "suspicious", "likelysafe"]
        guard let v = known.first(where: { lower.hasPrefix($0) }) else { return (nil, nil) }
        var score: Int?
        if let o = lower.firstIndex(of: "("), let c = lower.firstIndex(of: ")"), o < c { score = Int(lower[lower.index(after: o)..<c]) }
        return (v, score)
    }

    static func parseFound(_ s: String) -> Int? {
        let l = s.lowercased()
        if l == "no threats" { return 0 }
        guard l.hasSuffix(" found"), let n = Int(l.dropLast(" found".count)) else { return nil }
        return n
    }

    static func parseSeconds(_ s: String) -> String? {
        guard let r = s.range(of: #"in ([0-9.]+) s"#, options: .regularExpression) else { return nil }
        return String(s[r]).replacingOccurrences(of: "in ", with: "").replacingOccurrences(of: " s", with: "")
    }

    /// Files checked by a scan entry (structured count, or "18204 files in 42.0 s" in older details).
    public static func filesScanned(_ e: ActivityEntry) -> Int? {
        if let c = e.count { return c }
        let src = e.detail.isEmpty ? e.title : e.detail
        guard let r = src.range(of: #"([0-9][0-9,]*) files"#, options: .regularExpression) else { return nil }
        return Int(src[r].replacingOccurrences(of: " files", with: "").replacingOccurrences(of: ",", with: ""))
    }

    static func fmt(_ n: Int) -> String {
        let f = NumberFormatter(); f.numberStyle = .decimal
        return f.string(from: NSNumber(value: n)) ?? String(n)
    }
}

// MARK: - Stats and grouping

public struct ActivityDayTally: Hashable, Sendable {
    public var day: Date
    public var filesChecked = 0
    /// Web, scam-link and blocklist blocks recorded in the log (DNS blocks are also counted by the DNS stats).
    public var webBlocks = 0
    public var dnsBlocks = 0
    public var threatsStopped = 0
}

public enum ActivityStats {
    /// Per-day tallies, oldest first, for the last `days` days.
    public static func daily(_ entries: [ActivityEntry], days: Int = 14, now: Date = Date(), calendar: Calendar = .current) -> [ActivityDayTally] {
        let today = calendar.startOfDay(for: now)
        var out = (0..<days).reversed().map { ActivityDayTally(day: calendar.date(byAdding: .day, value: -$0, to: today)!) }
        let first = out.first?.day ?? today
        var stopped = Set<String>()
        for e in entries where e.date >= first {
            let idx = calendar.dateComponents([.day], from: first, to: calendar.startOfDay(for: e.date)).day ?? -1
            guard out.indices.contains(idx) else { continue }
            let ev = ActivityPresenter.event(for: e)
            switch ev {
            case .scanFinished, .scanCancelled, .scanFailed: out[idx].filesChecked += ActivityPresenter.filesScanned(e) ?? 0
            case .webBlocked, .scamBlocked: out[idx].webBlocks += 1
            case .dnsBlocked: out[idx].dnsBlocks += 1
            case .quarantined, .realtimeBlock, .processStopped, .pasteGuardBlocked:
                if stopped.insert(e.detectionID?.uuidString ?? e.id.uuidString).inserted { out[idx].threatsStopped += 1 }
            case .detection, .tamper, .remoteAccessAttempt:
                if e.outcome.lowercased() == "contained" || e.outcome.lowercased() == "suspended",
                   stopped.insert(e.detectionID?.uuidString ?? e.id.uuidString).inserted { out[idx].threatsStopped += 1 }
            default: break
            }
        }
        return out
    }
}

/// One timeline row: a single entry, or a burst of identical events close together.
public struct ActivityGroup: Identifiable, Hashable, Sendable {
    public var id: UUID { entries[0].id }
    public var entries: [ActivityEntry]   // newest first
    public var isBurst: Bool { entries.count > 1 }
    public var newest: ActivityEntry { entries[0] }
    public var oldest: ActivityEntry { entries[entries.count - 1] }

    /// "3 tamper attempts in 1 minute".
    public var burstTitle: String {
        let p = ActivityPresenter.present(newest)
        let span = newest.date.timeIntervalSince(oldest.date)
        let mins = max(1, Int((span / 60).rounded(.up)))
        return "\(entries.count) \(p.burstNoun) in \(mins == 1 ? "1 minute" : "\(mins) minutes")"
    }
}

public enum ActivityGrouping {
    /// Groups consecutive entries with the same group key, each within `window` seconds of the previous one.
    /// `entries` must be sorted newest first.
    public static func group(_ entries: [ActivityEntry], window: TimeInterval = 60, keys: [UUID: String]? = nil) -> [ActivityGroup] {
        var out: [ActivityGroup] = []
        var lastKey = ""
        for e in entries {
            let k = keys?[e.id] ?? ActivityPresenter.present(e).groupKey
            if var g = out.last, k == lastKey, let prev = g.entries.last, prev.date.timeIntervalSince(e.date) <= window,
               !ActivityGrouping.neverGroup.contains(ActivityPresenter.event(for: e)) {
                g.entries.append(e); out[out.count - 1] = g
            } else {
                out.append(ActivityGroup(entries: [e])); lastKey = k
            }
        }
        return out
    }
    /// Distinct user decisions stay separate rows even when close together.
    static let neverGroup: Set<ActivityEvent> = [.scanStarted, .scanFinished, .scanCancelled, .settingsChanged, .protectionToggled,
                                                 .lockdownStarted, .lockdownLifted, .serviceStarted, .serviceStopped]
}
