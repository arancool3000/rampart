import SwiftUI
import RampartShared
import RampartNetwork

/// "Filters & Privacy": content filter categories with schedules, SafeSearch, the privacy report and breach monitoring.
struct PrivacyFiltersView: View {
    @StateVar private var model = NetGuardModel.shared
    @StateVar private var breach = BreachWatch.shared
    @StateVar private var draft: ContentFilterConfig?
    @StateVar private var newEmail = ""
    @StateVar private var newKey = ""

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                header
                if let e = model.error { Label(SafeText.line(e, max: 300), systemImage: "exclamationmark.triangle").foregroundStyle(.secondary) }
                if let st = model.status {
                    filterCard(st)
                    safeSearchCard
                    reportCard(st.report)
                    limitsCard(st)
                } else if model.unsupported {
                    Text("This RamPart service is older than the content filter. Update RamPart to use it.").foregroundStyle(.secondary)
                } else { ProgressView() }
                breachCard
            }
            .contentColumn()
        }
        .navigationTitle("Filters & Privacy")
        .onAppear { model.startPolling(); breach.start() }
        .onDisappear { model.stopPolling() }
        .onChange(of: model.status?.filter) { _, f in if draft == nil || !model.busy { draft = f } }
    }

    private var cfg: ContentFilterConfig { draft ?? model.status?.filter ?? .defaults }
    private func apply(_ change: (inout ContentFilterConfig) -> Void) {
        var c = cfg; change(&c); draft = c
        Task { await model.setFilter(c) }
    }

    private var header: some View {
        HStack(spacing: Spacing.l) {
            IconBadge(symbol: "line.3.horizontal.decrease.circle", tint: .rampartTeal, size: 44)
            VStack(alignment: .leading, spacing: 4) {
                Text("Filters & Privacy").font(.title2.weight(.semibold)).fontDesign(.monospaced)
                Text("Choose what this Mac can reach, set quiet hours, and see who tried to track you.").font(.callout).foregroundStyle(.secondary)
            }
            Spacer()
            if model.busy { ProgressView().controlSize(.small) }
        }
    }

    // MARK: Content filter

    private func filterCard(_ st: NetGuardStatus) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Content filter")
            ForEach(ContentCategory.allCases, id: \.self) { c in
                let rule = cfg.rule(c)
                VStack(alignment: .leading, spacing: 4) {
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: 6) {
                                Text(c.title).font(.body.weight(.medium))
                                if st.activeNow.contains(c.rawValue) { Badge(text: "Blocking now", tint: .green) }
                            }
                            Text(c.detail).font(.caption).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Picker("", selection: Binding(get: { rule.mode }, set: { m in
                            apply { var r = $0.rule(c); r.mode = m
                                if m == .scheduled && r.windows.isEmpty { r.windows = [FilterWindow((22, 0), (7, 0))] }
                                $0.rules[c.rawValue] = r }
                        })) {
                            Text("Off").tag(CategoryRule.Mode.off)
                            Text("Always").tag(CategoryRule.Mode.always)
                            Text("On a schedule").tag(CategoryRule.Mode.scheduled)
                        }
                        .labelsHidden().frame(width: 150)
                    }
                    if rule.mode == .scheduled {
                        ForEach(Array(rule.windows.enumerated()), id: \.offset) { i, w in
                            HStack(spacing: 6) {
                                Text("Blocked").font(.caption).foregroundStyle(.secondary)
                                hourPicker(w.start) { v in apply { var r = $0.rule(c); r.windows[i].start = v; $0.rules[c.rawValue] = r } }
                                Text("to").font(.caption).foregroundStyle(.secondary)
                                hourPicker(w.end) { v in apply { var r = $0.rule(c); r.windows[i].end = v; $0.rules[c.rawValue] = r } }
                                Text(w.weekdays.isEmpty ? "every day" : w.label).font(.caption).foregroundStyle(.secondary)
                                Spacer()
                                if rule.windows.count > 1 {
                                    Button { apply { var r = $0.rule(c); r.windows.remove(at: i); $0.rules[c.rawValue] = r } } label: { Image(systemName: "minus.circle") }.buttonStyle(.plain)
                                }
                            }
                        }
                        Button("Add time window") { apply { var r = $0.rule(c); r.windows.append(FilterWindow((12, 0), (13, 0))); $0.rules[c.rawValue] = r } }
                            .buttonStyle(.link).font(.caption)
                    }
                }
                Divider()
            }
            Text("Lists: HaGeZi DNS blocklists (free, open source), downloaded when a category is first switched on and refreshed every 12 hours. \(Fmt.count(st.categoryDomains)) category domains loaded.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    private func hourPicker(_ minutes: Int, set: @escaping (Int) -> Void) -> some View {
        Picker("", selection: Binding(get: { (minutes / 30) * 30 }, set: set)) {
            ForEach(Array(stride(from: 0, to: 1440, by: 30)), id: \.self) { m in Text(String(format: "%02d:%02d", m / 60, m % 60)).tag(m) }
        }
        .labelsHidden().frame(width: 84)
    }

    private var safeSearchCard: some View {
        VStack(alignment: .leading, spacing: Spacing.s) {
            SectionHeader("SafeSearch")
            Toggle("Force SafeSearch on Google, Bing and DuckDuckGo, and YouTube Restricted Mode",
                   isOn: Binding(get: { cfg.safeSearch }, set: { v in apply { $0.safeSearch = v } }))
            Toggle("Strict YouTube Restricted Mode (instead of moderate)",
                   isOn: Binding(get: { cfg.youtubeStrict }, set: { v in apply { $0.youtubeStrict = v } }))
                .disabled(!cfg.safeSearch)
            Text("Enforced by DNS: these sites are answered with their own safe-search servers, so it can't be switched off in the browser's settings.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .card()
    }

    // MARK: Privacy report

    private func reportCard(_ r: PrivacyReport) -> some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Privacy report · last \(r.days) days")
            HStack(spacing: Spacing.xl) {
                stat(r.trackerBlockingOn ? "Trackers blocked" : "Trackers contacted", r.trackerBlockingOn ? r.trackersBlocked : r.trackersSeen)
                stat("Category blocks", r.categoryBlocks.reduce(0) { $0 + $1.count })
                stat("SafeSearch answers", r.safeSearchRewrites)
            }
            if r.trackersByDay.contains(where: { $0 > 0 }) {
                MiniBars(values: r.trackersByDay.map(Double.init)).frame(height: 36)
            }
            if let n = r.note { Text(n).font(.callout).foregroundStyle(.secondary) }
            HStack(alignment: .top, spacing: Spacing.xl) {
                list("Top trackers", r.topTrackers)
                list("Companies", r.topCompanies)
                list("Apps talking to trackers", r.appsContactingTrackers)
            }
            if !r.categoryBlocks.isEmpty { list("Blocked by category", r.categoryBlocks) }
        }
        .card(tint: .rampartTeal)
    }

    private func stat(_ title: String, _ v: Int) -> some View {
        VStack(alignment: .leading) {
            Text(Fmt.count(v)).font(.title.weight(.semibold)).fontDesign(.monospaced)
            Text(title).font(.caption).foregroundStyle(.secondary)
        }
    }

    private func list(_ title: String, _ items: [PrivacyReport.Item]) -> some View {
        VStack(alignment: .leading, spacing: 3) {
            Text(title).font(.subheadline.weight(.semibold))
            if items.isEmpty { Text("Nothing yet").font(.caption).foregroundStyle(.tertiary) }
            ForEach(items.prefix(8), id: \.self) { i in
                HStack { Text(SafeText.line(i.name, max: 48)).font(.caption).lineLimit(1); Spacer(); Text(Fmt.count(i.count)).font(.caption.monospacedDigit()).foregroundStyle(.secondary) }
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func limitsCard(_ st: NetGuardStatus) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Label("Limits", systemImage: "info.circle").font(.headline)
            ForEach(st.limitations, id: \.self) { Text("• " + $0).font(.callout).foregroundStyle(.secondary) }
        }
        .card()
    }

    // MARK: Breach monitoring

    private var breachCard: some View {
        VStack(alignment: .leading, spacing: Spacing.m) {
            SectionHeader("Breach monitoring")
            Label("Saved passwords: checked automatically every 6 hours while your vault is unlocked (and on unlock). Only the first 5 characters of each password's SHA-1 hash leave this Mac (Have I Been Pwned k-anonymity, free).",
                  systemImage: "key.horizontal").font(.callout)
            Divider()
            Text("Email addresses").font(.headline)
            Text(HIBPEmailClient.caveat).font(.caption).foregroundStyle(.secondary)
            if breach.hasKey {
                HStack {
                    Label("Your API key is saved in your login Keychain.", systemImage: "checkmark.seal").font(.callout)
                    Spacer()
                    Button("Remove key") { breach.removeKey() }.buttonStyle(.link)
                }
                HStack {
                    TextField("you@example.com", text: $newEmail).textFieldStyle(.roundedBorder).frame(maxWidth: 280)
                    Button("Watch address") { breach.add(newEmail); newEmail = "" }.disabled(newEmail.isEmpty)
                    Spacer()
                    Button(breach.checking ? "Checking…" : "Check now") { Task { await breach.checkEmails(force: true) } }
                        .disabled(breach.checking || breach.emails.isEmpty)
                }
                ForEach(breach.emails, id: \.self) { e in
                    let r = breach.results[e]
                    VStack(alignment: .leading, spacing: 2) {
                        HStack {
                            Text(e).font(.body.weight(.medium))
                            if let r, r.error == nil {
                                Badge(text: r.breaches.isEmpty ? "No breaches" : "\(r.breaches.count) breach\(r.breaches.count == 1 ? "" : "es")",
                                      tint: r.breaches.isEmpty ? .green : Palette.coral)
                            }
                            Spacer()
                            if let r { Text("checked \(Fmt.ago(r.checked))").font(.caption).foregroundStyle(.secondary) }
                            Button { breach.remove(e) } label: { Image(systemName: "trash") }.buttonStyle(.plain)
                        }
                        if let err = r?.error { Text(err).font(.caption).foregroundStyle(Palette.amber) }
                        ForEach(r?.breaches.prefix(6) ?? [], id: \.name) { b in
                            Text("\(b.title) (\(b.breachDate)): \(b.dataClasses.prefix(4).joined(separator: ", "))").font(.caption).foregroundStyle(.secondary)
                        }
                    }
                }
            } else {
                HStack {
                    SecureField("Your Have I Been Pwned API key", text: $newKey).textFieldStyle(.roundedBorder).frame(maxWidth: 320)
                    Button("Save key") { breach.setKey(newKey); newKey = "" }.disabled(newKey.isEmpty)
                }
            }
            if let m = breach.message { Text(m).font(.caption).foregroundStyle(.secondary) }
        }
        .card()
    }
}
