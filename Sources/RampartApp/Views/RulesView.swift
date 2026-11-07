import SwiftUI
import AppKit
import RampartShared

/// Every decision the user has made, as readable sentences: allow rules (daemon-owned) and scan exclusions.
struct RulesView: View {
    @Environment(AppModel.self) private var model
    @StateVar private var search = ""
    @StateVar private var showAdd = false
    @StateVar private var pendingRemoval: AllowRuleSpec?

    private var rules: [AllowRuleSpec] {
        model.allowRules.filter { search.isEmpty || $0.sentence.localizedCaseInsensitiveContains(search) || $0.value.localizedCaseInsensitiveContains(search) }
    }
    private var exclusions: [String] {
        model.settings.exclusions.filter { search.isEmpty || $0.localizedCaseInsensitiveContains(search) }
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: Spacing.xl) {
                Text("Every choice you've made about what \(Product.name) allows or skips. Rules apply right away and you can change them anytime.")
                    .foregroundStyle(.secondary)

                VStack(alignment: .leading, spacing: Spacing.m) {
                    SectionHeader("Allowed", trailing: AnyView(
                        Button { showAdd = true } label: { Label("Add Rule…", systemImage: "plus") }))
                    VStack(spacing: 0) {
                        if rules.isEmpty {
                            RuleEmptyRow(symbol: "checkmark.seal",
                                         text: search.isEmpty ? "Nothing allowed yet. When you restore or allow something, the rule shows up here." : "No allowed items match \"\(search)\".")
                        }
                        ForEach(Array(rules.enumerated()), id: \.element.id) { i, r in
                            if i > 0 { Divider().padding(.leading, 52) }
                            RuleRow(symbol: symbol(for: r.scope), tint: .statusProtected, sentence: r.sentence,
                                    meta: "\(r.scope.label) · added \(Fmt.dayTime(r.created))\(r.expires.map { " · expires \($0.formatted(date: .abbreviated, time: .omitted))" } ?? "")") {
                                pendingRemoval = r
                            }
                        }
                    }
                    .card(padding: Spacing.s)
                }

                VStack(alignment: .leading, spacing: Spacing.m) {
                    SectionHeader("Not scanned", trailing: AnyView(
                        Button { addExclusion() } label: { Label("Add Folder…", systemImage: "plus") }))
                    VStack(spacing: 0) {
                        if exclusions.isEmpty {
                            RuleEmptyRow(symbol: "folder", text: search.isEmpty ? "\(Product.name) checks everything it can reach. Add a folder here only if you trust everything in it." : "No exclusions match \"\(search)\".")
                        }
                        ForEach(Array(exclusions.enumerated()), id: \.element) { i, e in
                            if i > 0 { Divider().padding(.leading, 52) }
                            RuleRow(symbol: "folder.badge.minus", tint: .secondary,
                                    sentence: "\(Product.name) doesn't scan \((e as NSString).abbreviatingWithTildeInPath).",
                                    meta: "Exclusion") {
                                model.updateSettings { $0.exclusions.removeAll { $0 == e } }
                            }
                        }
                    }
                    .card(padding: Spacing.s)
                    Label("Excluded items aren't checked. Only exclude things you trust.", systemImage: "info.circle")
                        .font(.callout).foregroundStyle(.secondary)
                }
            }
            .contentColumn()
        }
        .navigationTitle("Rules")
        .searchable(text: $search, placement: .toolbar, prompt: "Search rules")
        .sheet(isPresented: $showAdd) { AddRuleSheet() }
        .confirmationDialog("Remove this rule?", isPresented: Binding(get: { pendingRemoval != nil }, set: { if !$0 { pendingRemoval = nil } }), presenting: pendingRemoval) { r in
            Button("Remove Rule", role: .destructive) { Task { await model.removeAllowRule(r) } }
        } message: { r in
            Text("\(Product.name) will check \(SafeText.line(r.name, max: 80)) normally again.")
        }
    }

    private func symbol(for s: AllowRuleSpec.Scope) -> String {
        switch s { case .fileHash: return "number"; case .developer: return "person.badge.shield.checkmark"; case .folder: return "folder"; case .signingID: return "app.badge.checkmark" }
    }

    private func addExclusion() {
        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = true; p.allowsMultipleSelection = true
        p.prompt = "Exclude"
        p.message = "Excluded items aren't checked. Only exclude things you trust."
        guard p.runModal() == .OK else { return }
        let new = p.urls.map(\.path)
        model.updateSettings { s in s.exclusions = Array(Set(s.exclusions + new)).sorted() }
    }
}

struct RuleRow: View {
    let symbol: String
    let tint: Color
    let sentence: String
    let meta: String
    let onRemove: () -> Void
    @StateVar private var hover = false
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: symbol).font(.title3).foregroundStyle(tint).frame(width: 32)
            VStack(alignment: .leading, spacing: 2) {
                Text(sentence).fixedSize(horizontal: false, vertical: true)
                Text(meta).font(.caption).foregroundStyle(.secondary)
            }
            Spacer()
            Button("Remove", action: onRemove)
                .controlSize(.small)
                .opacity(hover ? 1 : 0.55)
                .accessibilityLabel("Remove: \(sentence)")
        }
        .padding(Spacing.s)
        .onHover { hover = $0 }
        .accessibilityElement(children: .combine)
    }
}

struct RuleEmptyRow: View {
    let symbol: String
    let text: String
    var body: some View {
        HStack(spacing: Spacing.m) {
            Image(systemName: symbol).font(.title3).foregroundStyle(.tertiary).frame(width: 32)
            Text(text).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Spacer()
        }
        .padding(Spacing.s)
    }
}

struct AddRuleSheet: View {
    @Environment(AppModel.self) private var model
    @Environment(\.dismiss) private var dismiss
    @StateVar private var scope: AllowRuleSpec.Scope = .folder
    @StateVar private var value = ""
    @StateVar private var name = ""

    private var prompt: String {
        switch scope {
        case .fileHash: return "SHA-256 fingerprint"
        case .developer: return "Team ID (for example 927JGANW46)"
        case .folder: return "Folder path"
        case .signingID: return "Signing identifier (for example com.example.app)"
        }
    }
    private var preview: String {
        AllowRuleSpec(scope: scope, value: value.isEmpty ? "…" : value, name: name.isEmpty ? (scope == .folder ? (value as NSString).lastPathComponent : "This item") : name).sentence
    }
    private var valid: Bool {
        let v = value.trimmingCharacters(in: .whitespaces)
        switch scope {
        case .fileHash: return v.count == 64 && v.allSatisfy(\.isHexDigit)
        case .developer: return v.count == 10 && v.allSatisfy { $0.isLetter || $0.isNumber }
        case .folder: return v.hasPrefix("/") || v.hasPrefix("~")
        case .signingID: return v.contains(".")
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: Spacing.l) {
            Text("Add an allow rule").font(.title2.weight(.semibold))
            Text("\(Product.name) won't flag anything this rule covers. Allow only things you trust.").foregroundStyle(.secondary)
            Picker("Allow", selection: $scope) {
                Text("A folder").tag(AllowRuleSpec.Scope.folder)
                Text("A developer").tag(AllowRuleSpec.Scope.developer)
                Text("An app").tag(AllowRuleSpec.Scope.signingID)
                Text("One file").tag(AllowRuleSpec.Scope.fileHash)
            }
            .pickerStyle(.segmented)
            HStack {
                TextField(prompt, text: $value).textFieldStyle(.roundedBorder).font(.body.monospaced())
                if scope == .folder {
                    Button("Choose…") {
                        let p = NSOpenPanel(); p.canChooseDirectories = true; p.canChooseFiles = false
                        if p.runModal() == .OK, let u = p.url { value = u.path }
                    }
                }
            }
            TextField("Name shown in the list (optional)", text: $name).textFieldStyle(.roundedBorder)
            Label(preview, systemImage: "text.quote").font(.callout).foregroundStyle(.secondary)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Add Rule") {
                    let v = (value.trimmingCharacters(in: .whitespaces) as NSString).expandingTildeInPath
                    let n = name.isEmpty ? (scope == .folder ? (v as NSString).lastPathComponent : v) : name
                    Task { await model.addAllowRule(AllowRuleSpec(scope: scope, value: v, name: n)) }
                    dismiss()
                }
                .buttonStyle(GlowButtonStyle())
                .disabled(!valid)
                .keyboardShortcut(.defaultAction)
            }
        }
        .padding(Spacing.xl)
        .frame(width: 520)
    }
}
